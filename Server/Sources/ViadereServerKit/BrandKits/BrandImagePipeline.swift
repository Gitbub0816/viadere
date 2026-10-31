import Crypto
import Foundation
import JPEG
import PNG
import ViadereCore

/// The brand asset ingestion pipeline (WP-2.2, ADR-0017, SECURITY.md §2.93 "Assets"). Pure function of the uploaded bytes: nothing is stored
/// and nothing touches disk until it returns a clean PNG.
///
/// 1. `BrandAssetPolicy.precheck`: size cap, declared type and magic bytes agree, SVG and markup refused.
/// 2. A strict structural front end written here (not the codec): PNG chunks with CRCs, a single well-formed `IHDR`, no `CgBI`, no APNG
///    chunks, nothing after `IEND`; JPEG segments with lengths, exactly one supported `SOF`, nothing after `EOI`. The declared dimensions are
///    checked **before** the codec allocates a pixel buffer (decompression-bomb guard).
/// 3. The codec sees a **rebuilt** stream that contains only the chunks or segments needed for pixels (PNG: `IHDR`, `PLTE`, `tRNS`, `IDAT`,
///    `IEND`; JPEG: tables, frame, scans): metadata (EXIF/GPS, ICC, text, XMP, comments, compressed text chunks) never reaches a parser.
/// 4. Decode with the pure-Swift codecs (swift-png, swift-jpeg), resize to the slot (area average, premultiplied alpha, never upscale), and
///    encode a **fresh** PNG with no metadata. The output is re-checked by the same front end and must contain exactly `IHDR`, `IDAT`, `IEND`.
enum BrandImagePipeline {
    struct Output: Sendable, Equatable {
        var png: Data
        /// Lowercase hex SHA-256 of `png`.
        var sha256: String
        var width: Int
        var height: Int
    }

    typealias Rejection = BrandAssetPolicy.Rejection

    /// Most chunks or segments a file may have (a real logo has a handful; this bounds parsing work on hostile input).
    static let maxParts = 4096
    /// PNG compression level for the output (swift-png 0…13).
    static let outputLevel = 7

    static func process(_ data: Data, declaredContentType: String, slot: BrandAssetSlot) -> Result<Output, Rejection> {
        let format: BrandAssetPolicy.DetectedFormat
        switch BrandAssetPolicy.precheck(declaredContentType: declaredContentType, byteCount: data.count, prefix: data.prefix(64)) {
        case .failure(let rejection): return .failure(rejection)
        case .success(let detected): format = detected
        }
        let bytes = [UInt8](data)
        let decoded: Result<Pixels, Rejection>
        switch format {
        case .png: decoded = decodePNG(bytes)
        case .jpeg: decoded = decodeJPEG(bytes)
        default: return .failure(.unsupportedFormat)
        }
        switch decoded {
        case .failure(let rejection): return .failure(rejection)
        case .success(let pixels):
            let target = BrandAssetPolicy.targetSize(width: pixels.width, height: pixels.height, slot: slot)
            let resized = pixels.resized(to: target)
            guard let png = encodePNG(resized) else { return .failure(.decodeFailed) }
            guard png.count <= slot.maxStoredBytes else { return .failure(.outputTooLarge) }
            // Defense in depth: our own output must pass our own front end and carry nothing but pixels.
            guard case .success(let parsed) = PNGStructure.parse([UInt8](png)), parsed.chunkTypes.allSatisfy({ ["IHDR", "IDAT", "IEND"].contains($0) }),
                  parsed.width == resized.width, parsed.height == resized.height else { return .failure(.decodeFailed) }
            return .success(Output(png: png, sha256: Hex.encode(Data(SHA256.hash(data: png))), width: resized.width, height: resized.height))
        }
    }

    // MARK: Pixels

    /// 8-bit RGBA, row-major, straight (not premultiplied) alpha.
    struct Pixels {
        var width: Int
        var height: Int
        var rgba: [UInt8]

        var isOpaque: Bool { stride(from: 3, to: rgba.count, by: 4).allSatisfy { rgba[$0] == 255 } }

        /// Area-average downscale with premultiplied alpha (so transparent pixels do not bleed color). Returns `self` when the size is unchanged.
        func resized(to target: (width: Int, height: Int)) -> Pixels {
            guard target.width != width || target.height != height, target.width >= 1, target.height >= 1 else { return self }
            var out = [UInt8](repeating: 0, count: target.width * target.height * 4)
            for ty in 0..<target.height {
                let y0 = ty * height / target.height, y1 = max(y0 + 1, (ty + 1) * height / target.height)
                for tx in 0..<target.width {
                    let x0 = tx * width / target.width, x1 = max(x0 + 1, (tx + 1) * width / target.width)
                    var r = 0, g = 0, b = 0, a = 0
                    for y in y0..<y1 {
                        var i = (y * width + x0) * 4
                        for _ in x0..<x1 {
                            let alpha = Int(rgba[i + 3])
                            r += Int(rgba[i]) * alpha
                            g += Int(rgba[i + 1]) * alpha
                            b += Int(rgba[i + 2]) * alpha
                            a += alpha
                            i += 4
                        }
                    }
                    let count = (y1 - y0) * (x1 - x0)
                    let o = (ty * target.width + tx) * 4
                    if a > 0 {
                        out[o] = UInt8(min(255, (r + a / 2) / a))
                        out[o + 1] = UInt8(min(255, (g + a / 2) / a))
                        out[o + 2] = UInt8(min(255, (b + a / 2) / a))
                    }
                    out[o + 3] = UInt8(min(255, (a + count / 2) / count))
                }
            }
            return Pixels(width: target.width, height: target.height, rgba: out)
        }
    }

    // MARK: PNG

    static func decodePNG(_ bytes: [UInt8]) -> Result<Pixels, Rejection> {
        let structure: PNGStructure
        switch PNGStructure.parse(bytes) {
        case .failure(let r): return .failure(r)
        case .success(let s): structure = s
        }
        if let r = BrandAssetPolicy.checkSourceDimensions(width: structure.width, height: structure.height) { return .failure(r) }
        var source = ByteSource(bytes: structure.pixelStream)
        guard let image = try? PNG.Image.decompress(stream: &source), image.size.x == structure.width, image.size.y == structure.height else {
            return .failure(.decodeFailed)
        }
        let pixels = image.unpack(as: PNG.RGBA<UInt8>.self)
        guard pixels.count == structure.width * structure.height else { return .failure(.decodeFailed) }
        var rgba = [UInt8]()
        rgba.reserveCapacity(pixels.count * 4)
        for p in pixels { rgba.append(p.r); rgba.append(p.g); rgba.append(p.b); rgba.append(p.a) }
        return .success(Pixels(width: structure.width, height: structure.height, rgba: rgba))
    }

    static func encodePNG(_ pixels: Pixels) -> Data? {
        let image: PNG.Image
        if pixels.isOpaque {
            var rgb = [PNG.RGBA<UInt8>]()
            rgb.reserveCapacity(pixels.width * pixels.height)
            for i in stride(from: 0, to: pixels.rgba.count, by: 4) { rgb.append(PNG.RGBA(pixels.rgba[i], pixels.rgba[i + 1], pixels.rgba[i + 2], 255)) }
            image = PNG.Image(packing: rgb, size: (pixels.width, pixels.height), layout: PNG.Layout(format: .rgb8(palette: [], fill: nil, key: nil)))
        } else {
            var rgba = [PNG.RGBA<UInt8>]()
            rgba.reserveCapacity(pixels.width * pixels.height)
            for i in stride(from: 0, to: pixels.rgba.count, by: 4) { rgba.append(PNG.RGBA(pixels.rgba[i], pixels.rgba[i + 1], pixels.rgba[i + 2], pixels.rgba[i + 3])) }
            image = PNG.Image(packing: rgba, size: (pixels.width, pixels.height), layout: PNG.Layout(format: .rgba8(palette: [], fill: nil)))
        }
        var sink = ByteSink()
        guard (try? image.compress(stream: &sink, level: outputLevel)) != nil else { return nil }
        return Data(sink.bytes)
    }

    // MARK: JPEG

    static func decodeJPEG(_ bytes: [UInt8]) -> Result<Pixels, Rejection> {
        let structure: JPEGStructure
        switch JPEGStructure.parse(bytes) {
        case .failure(let r): return .failure(r)
        case .success(let s): structure = s
        }
        if let r = BrandAssetPolicy.checkSourceDimensions(width: structure.width, height: structure.height) { return .failure(r) }
        var source = ByteSource(bytes: structure.pixelStream)
        guard let image = try? JPEG.Data.Rectangular<JPEG.Common>.decompress(stream: &source),
              image.size.x == structure.width, image.size.y == structure.height else { return .failure(.decodeFailed) }
        let pixels = image.unpack(as: JPEG.RGB.self)
        guard pixels.count == structure.width * structure.height else { return .failure(.decodeFailed) }
        var rgba = [UInt8]()
        rgba.reserveCapacity(pixels.count * 4)
        for p in pixels { rgba.append(p.r); rgba.append(p.g); rgba.append(p.b); rgba.append(255) }
        return .success(Pixels(width: structure.width, height: structure.height, rgba: rgba))
    }
}

// MARK: - Byte streams for the codecs

struct ByteSource: PNG.BytestreamSource, JPEG.Bytestream.Source {
    let bytes: [UInt8]
    var offset = 0

    init(bytes: [UInt8]) { self.bytes = bytes }

    mutating func read(count: Int) -> [UInt8]? {
        guard count >= 0, count <= bytes.count - offset else { return nil }
        defer { offset += count }
        return Array(bytes[offset..<(offset + count)])
    }
}

struct ByteSink: PNG.BytestreamDestination {
    var bytes: [UInt8] = []
    mutating func write(_ buffer: [UInt8]) -> Void? {
        bytes.append(contentsOf: buffer)
        return ()
    }
}

// MARK: - PNG structure (front end)

/// Strict PNG container check (ISO/IEC 15948): signature, chunk lengths within the file, ASCII-letter chunk types, CRC-32 of every chunk,
/// `IHDR` first with legal values, `PLTE` only before `IDAT`, consecutive `IDAT`, `IEND` last with nothing after it.
struct PNGStructure {
    var width: Int
    var height: Int
    var chunkTypes: [String]
    /// Signature + `IHDR`, `PLTE`, `tRNS`, `IDAT`…, `IEND`: everything the codec needs and nothing else.
    var pixelStream: [UInt8]

    static let signature: [UInt8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
    static let animationChunks: Set<String> = ["acTL", "fcTL", "fdAT"]
    static let kept: Set<String> = ["IHDR", "PLTE", "tRNS", "IDAT", "IEND"]

    static func parse(_ b: [UInt8]) -> Result<PNGStructure, BrandAssetPolicy.Rejection> {
        guard b.count >= 8 else { return .failure(.truncated) }
        guard Array(b[0..<8]) == signature else { return .failure(.malformed) }
        var offset = 8
        var types: [String] = []
        var stream = signature
        var width = 0, height = 0, colorType = -1
        var sawIDAT = false, idatEnded = false, sawPLTE = false
        while true {
            guard types.count < BrandImagePipeline.maxParts else { return .failure(.malformed) }
            guard b.count - offset >= 12 else { return .failure(.truncated) }
            let length = Int(b[offset]) << 24 | Int(b[offset + 1]) << 16 | Int(b[offset + 2]) << 8 | Int(b[offset + 3])
            guard length <= 0x7FFF_FFFF else { return .failure(.malformed) }
            guard b.count - offset - 12 >= length else { return .failure(.truncated) }
            let typeBytes = Array(b[(offset + 4)..<(offset + 8)])
            guard typeBytes.allSatisfy({ (0x41...0x5A).contains($0) || (0x61...0x7A).contains($0) }) else { return .failure(.malformed) }
            let type = String(decoding: typeBytes, as: UTF8.self)
            let dataRange = (offset + 8)..<(offset + 8 + length)
            let crcAt = offset + 8 + length
            let stored = UInt32(b[crcAt]) << 24 | UInt32(b[crcAt + 1]) << 16 | UInt32(b[crcAt + 2]) << 8 | UInt32(b[crcAt + 3])
            guard CRC32.checksum(b[(offset + 4)..<crcAt]) == stored else { return .failure(.malformed) }
            if types.isEmpty, type != "IHDR" { return .failure(.malformed) }
            if animationChunks.contains(type) { return .failure(.animated) }
            switch type {
            case "IHDR":
                guard types.isEmpty, length == 13 else { return .failure(.malformed) }
                let d = Array(b[dataRange])
                width = Int(d[0]) << 24 | Int(d[1]) << 16 | Int(d[2]) << 8 | Int(d[3])
                height = Int(d[4]) << 24 | Int(d[5]) << 16 | Int(d[6]) << 8 | Int(d[7])
                let depth = Int(d[8])
                colorType = Int(d[9])
                let legal: [Int: Set<Int>] = [0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16]]
                guard legal[colorType]?.contains(depth) == true, d[10] == 0, d[11] == 0, d[12] <= 1 else { return .failure(.malformed) }
                // A zero or absurd size is refused here, before anything allocates.
                if let r = BrandAssetPolicy.checkSourceDimensions(width: width, height: height) { return .failure(r) }
            case "PLTE":
                guard !sawIDAT, !sawPLTE, length > 0, length % 3 == 0, length <= 768 else { return .failure(.malformed) }
                sawPLTE = true
            case "IDAT":
                guard !idatEnded else { return .failure(.malformed) }
                sawIDAT = true
            case "IEND":
                guard length == 0, sawIDAT else { return .failure(.malformed) }
                if colorType == 3, !sawPLTE { return .failure(.malformed) }
                types.append(type)
                stream += b[offset..<(crcAt + 4)]
                guard crcAt + 4 == b.count else { return .failure(.trailingData) }
                return .success(PNGStructure(width: width, height: height, chunkTypes: types, pixelStream: stream))
            case "CgBI":
                return .failure(.malformed) // Apple's non-standard PNG variant
            default:
                // Unknown critical chunks (upper-case first letter) cannot be skipped safely.
                if (0x41...0x5A).contains(typeBytes[0]) { return .failure(.malformed) }
            }
            if sawIDAT, type != "IDAT" { idatEnded = true }
            types.append(type)
            if kept.contains(type) { stream += b[offset..<(crcAt + 4)] }
            offset = crcAt + 4
        }
    }
}

// MARK: - JPEG structure (front end)

/// Strict JPEG marker walk (ITU-T T.81): `SOI`, length-prefixed segments within the file, exactly one frame header of a supported process
/// (baseline, extended sequential or progressive Huffman, 8-bit, 1 or 3 components) before the first scan, entropy-coded data scanned to the
/// next real marker, `EOI` last with nothing after it. `APPn` (JFIF, EXIF/GPS, XMP, ICC, Adobe) and `COM` segments are dropped.
struct JPEGStructure {
    var width: Int
    var height: Int
    var pixelStream: [UInt8]

    static func parse(_ b: [UInt8]) -> Result<JPEGStructure, BrandAssetPolicy.Rejection> {
        guard b.count >= 4 else { return .failure(.truncated) }
        guard b[0] == 0xFF, b[1] == 0xD8 else { return .failure(.malformed) }
        var out: [UInt8] = [0xFF, 0xD8]
        var offset = 2
        var parts = 0
        var width = 0, height = 0, sawFrame = false, sawScan = false
        while true {
            parts += 1
            guard parts < BrandImagePipeline.maxParts else { return .failure(.malformed) }
            guard b.count - offset >= 2 else { return .failure(.truncated) }
            guard b[offset] == 0xFF else { return .failure(.malformed) }
            // Fill bytes (0xFF padding) before a marker are legal.
            var markerAt = offset + 1
            while markerAt < b.count, b[markerAt] == 0xFF { markerAt += 1 }
            guard markerAt < b.count else { return .failure(.truncated) }
            let marker = b[markerAt]
            offset = markerAt + 1
            switch marker {
            case 0xD9: // EOI
                guard sawFrame, sawScan else { return .failure(.malformed) }
                out += [0xFF, 0xD9]
                guard offset == b.count else { return .failure(.trailingData) }
                return .success(JPEGStructure(width: width, height: height, pixelStream: out))
            case 0xD8, 0x01, 0xD0...0xD7, 0x00:
                return .failure(.malformed) // a second SOI, TEM, a stray RST or a stuffed zero outside scan data
            default:
                break
            }
            guard b.count - offset >= 2 else { return .failure(.truncated) }
            let length = Int(b[offset]) << 8 | Int(b[offset + 1])
            guard length >= 2 else { return .failure(.malformed) }
            guard b.count - offset >= length else { return .failure(.truncated) }
            let segment = b[(offset - 2)..<(offset + length)] // marker + length + payload
            let payload = Array(b[(offset + 2)..<(offset + length)])
            offset += length
            switch marker {
            case 0xC0, 0xC1, 0xC2: // SOF0 baseline, SOF1 extended sequential, SOF2 progressive (Huffman)
                guard !sawFrame, payload.count >= 6 else { return .failure(.malformed) }
                let precision = Int(payload[0])
                height = Int(payload[1]) << 8 | Int(payload[2])
                width = Int(payload[3]) << 8 | Int(payload[4])
                let components = Int(payload[5])
                guard precision == 8, components == 1 || components == 3, payload.count == 6 + 3 * components else { return .failure(.malformed) }
                // Height 0 (defined later by DNL) is refused; size is checked before the codec allocates anything.
                if let r = BrandAssetPolicy.checkSourceDimensions(width: width, height: height) { return .failure(r) }
                sawFrame = true
                out += segment
            case 0xC3, 0xC5...0xC7, 0xC9...0xCB, 0xCD...0xCF:
                return .failure(.malformed) // lossless, hierarchical and arithmetic-coded processes are not accepted
            case 0xC4, 0xDB, 0xDD: // DHT, DQT, DRI
                out += segment
            case 0xDC: // DNL
                return .failure(.malformed)
            case 0xE0...0xEF, 0xFE: // APPn and COM: metadata, dropped
                break
            case 0xDA: // SOS, then entropy-coded data up to the next marker that is not a stuffed zero or a restart
                guard sawFrame else { return .failure(.malformed) }
                sawScan = true
                out += segment
                let start = offset
                while true {
                    guard offset < b.count - 1 else { return .failure(.truncated) }
                    if b[offset] == 0xFF {
                        let next = b[offset + 1]
                        if next == 0x00 || (0xD0...0xD7).contains(next) || next == 0xFF {
                            offset += next == 0xFF ? 1 : 2
                            continue
                        }
                        break
                    }
                    offset += 1
                }
                out += b[start..<offset]
            default:
                return .failure(.malformed)
            }
        }
    }
}
