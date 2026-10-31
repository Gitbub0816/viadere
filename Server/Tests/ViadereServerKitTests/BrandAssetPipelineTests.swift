import Crypto
import Foundation
import JPEG
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// D3.T5 "Malicious asset uploads" (plan 5.4, WP-2.2, ADR-0017): a corpus generated here (truncated, polyglot, decompression bomb, EXIF/GPS,
/// ICC, text chunks, animated, mislabeled MIME, SVG, HTML-as-PNG, unsupported codecs) plus seeded mutation fuzzing. Every file is either refused
/// with a reason code **before** any pixel buffer is allocated, or re-encoded to a clean PNG with nothing but `IHDR`, `IDAT` and `IEND`.
final class BrandAssetPipelineTests: XCTestCase {
    // MARK: Corpus builders

    /// A chunk with its length and CRC.
    static func chunk(_ type: String, _ data: [UInt8]) -> [UInt8] {
        let typeBytes = Array(type.utf8)
        let length = UInt32(data.count)
        let crc = CRC32.checksum(ArraySlice(typeBytes + data))
        return [UInt8(length >> 24), UInt8(length >> 16 & 0xFF), UInt8(length >> 8 & 0xFF), UInt8(length & 0xFF)] + typeBytes + data
            + [UInt8(crc >> 24), UInt8(crc >> 16 & 0xFF), UInt8(crc >> 8 & 0xFF), UInt8(crc & 0xFF)]
    }

    /// A real PNG produced by the encoder (gradient with transparency).
    static func png(width: Int = 40, height: Int = 30, opaque: Bool = false) -> [UInt8] {
        var rgba = [UInt8]()
        for y in 0..<height {
            for x in 0..<width { rgba += [UInt8(x * 255 / max(1, width - 1)), UInt8(y * 255 / max(1, height - 1)), 128, opaque ? 255 : UInt8((x + y) % 2 == 0 ? 255 : 90)] }
        }
        return [UInt8](BrandImagePipeline.encodePNG(.init(width: width, height: height, rgba: rgba))!)
    }

    /// Splits a PNG into its chunks (type, full chunk bytes).
    static func chunks(_ png: [UInt8]) -> [(String, [UInt8])] {
        var out: [(String, [UInt8])] = []
        var i = 8
        while i + 12 <= png.count {
            let length = Int(png[i]) << 24 | Int(png[i + 1]) << 16 | Int(png[i + 2]) << 8 | Int(png[i + 3])
            out.append((String(decoding: png[(i + 4)..<(i + 8)], as: UTF8.self), Array(png[i..<(i + 12 + length)])))
            i += 12 + length
        }
        return out
    }

    /// Inserts extra chunks right after `IHDR`.
    static func pngWith(_ extra: [[UInt8]], base: [UInt8] = png()) -> [UInt8] {
        let parts = chunks(base)
        return PNGStructure.signature + parts[0].1 + extra.flatMap { $0 } + parts.dropFirst().flatMap(\.1)
    }

    static func ihdr(width: UInt32, height: UInt32, depth: UInt8 = 8, color: UInt8 = 6) -> [UInt8] {
        chunk("IHDR", [UInt8(width >> 24), UInt8(width >> 16 & 0xFF), UInt8(width >> 8 & 0xFF), UInt8(width & 0xFF),
                       UInt8(height >> 24), UInt8(height >> 16 & 0xFF), UInt8(height >> 8 & 0xFF), UInt8(height & 0xFF), depth, color, 0, 0, 0])
    }

    struct Sink: JPEG.Bytestream.Destination {
        var bytes: [UInt8] = []
        mutating func write(_ bytes: [UInt8]) -> Void? { self.bytes += bytes; return () }
    }

    /// A real baseline JPEG produced by swift-jpeg (with a JFIF APP0 segment).
    static func jpeg(width: Int = 24, height: Int = 16) -> [UInt8] {
        let layout = JPEG.Layout<JPEG.Common>(format: .ycc8, process: .baseline,
                                              components: [1: (factor: (2, 2), qi: 0), 2: (factor: (1, 1), qi: 1), 3: (factor: (1, 1), qi: 1)],
                                              scans: [.sequential((1, \.0, \.0), (2, \.1, \.1), (3, \.1, \.1))])
        var pixels: [JPEG.RGB] = []
        for y in 0..<height { for x in 0..<width { pixels.append(JPEG.RGB(UInt8(x * 10 % 256), UInt8(y * 15 % 256), 90)) } }
        let image = JPEG.Data.Rectangular<JPEG.Common>.pack(size: (width, height), layout: layout,
                                                             metadata: [.jfif(JPEG.JFIF(version: .v1_2, density: (72, 72, .inches)))], pixels: pixels)
        var sink = Sink()
        try! image.compress(stream: &sink, quanta: [0: JPEG.CompressionLevel.luminance(0.2).quanta, 1: JPEG.CompressionLevel.chrominance(0.2).quanta])
        return sink.bytes
    }

    static func segment(_ marker: UInt8, _ payload: [UInt8]) -> [UInt8] {
        let length = payload.count + 2
        return [0xFF, marker, UInt8(length >> 8), UInt8(length & 0xFF)] + payload
    }

    /// Inserts segments right after `SOI`.
    static func jpegWith(_ extra: [[UInt8]], base: [UInt8] = jpeg()) -> [UInt8] { Array(base.prefix(2)) + extra.flatMap { $0 } + Array(base.dropFirst(2)) }

    func run(_ bytes: [UInt8], _ type: String, slot: BrandAssetSlot = .logo) -> Result<BrandImagePipeline.Output, BrandAssetPolicy.Rejection> {
        BrandImagePipeline.process(Data(bytes), declaredContentType: type, slot: slot)
    }

    func assertRejected(_ bytes: [UInt8], _ type: String, _ expected: BrandAssetPolicy.Rejection, _ name: String, file: StaticString = #filePath, line: UInt = #line) {
        switch run(bytes, type) {
        case .success: XCTFail("\(name): accepted", file: file, line: line)
        case .failure(let r): XCTAssertEqual(r, expected, name, file: file, line: line)
        }
    }

    /// Accepted outputs are fresh PNGs with only pixel chunks, a matching hash, and none of `forbidden` anywhere in the bytes.
    func assertClean(_ bytes: [UInt8], _ type: String, slot: BrandAssetSlot = .logo, forbidden: [String] = [], _ name: String,
                     file: StaticString = #filePath, line: UInt = #line) -> BrandImagePipeline.Output? {
        guard case .success(let out) = run(bytes, type, slot: slot) else { XCTFail("\(name): rejected", file: file, line: line); return nil }
        let outBytes = [UInt8](out.png)
        XCTAssertEqual(Array(outBytes.prefix(8)), PNGStructure.signature, name, file: file, line: line)
        XCTAssertEqual(Set(Self.chunks(outBytes).map(\.0)), ["IHDR", "IDAT", "IEND"], name, file: file, line: line)
        XCTAssertEqual(out.sha256, Hex.encode(Data(SHA256.hash(data: out.png))), name, file: file, line: line)
        XCTAssertLessThanOrEqual(max(out.width, out.height), slot.maxDimension, name, file: file, line: line)
        for text in forbidden { XCTAssertNil(out.png.range(of: Data(text.utf8)), "\(name): output still contains \(text)", file: file, line: line) }
        return out
    }

    // MARK: Accepted and normalized

    func testPlainPNGAndJPEGAreReencodedToCleanPNG() throws {
        let png = try XCTUnwrap(assertClean(Self.png(), "image/png", "png"))
        XCTAssertEqual(png.width, 40)
        XCTAssertEqual(png.height, 30)
        let jpg = try XCTUnwrap(assertClean(Self.jpeg(), "image/jpeg", forbidden: ["JFIF"], "jpeg"))
        XCTAssertEqual(jpg.width, 24)
        XCTAssertEqual(jpg.height, 16)
        // Content type parameters do not matter; the declared type still has to agree with the bytes.
        _ = assertClean(Self.png(), "image/png; charset=binary", "png with parameter")
        // Re-encoding is deterministic: the same upload gives the same content address.
        XCTAssertEqual(try run(Self.png(), "image/png").get().sha256, png.sha256)
    }

    func testMetadataChunksAndSegmentsAreDroppedNotParsed() throws {
        let exif = Array("Exif\0\0MM\0*GPSLatitude 47.3769N GPSLongitude 8.5417E".utf8)
        let icc = Array("viadere-icc\0".utf8) + [0] + Array(repeating: 0x78, count: 40) // name, method, garbage "compressed" profile
        let hostile = [Self.chunk("tEXt", Array("Comment\0<script>alert(1)</script>".utf8)),
                       Self.chunk("iTXt", Array("XML:com.adobe.xmp\0\0\0\0\0<x:xmpmeta>secret</x:xmpmeta>".utf8)),
                       Self.chunk("zTXt", Array("Bomb\0\0".utf8) + Array(repeating: 0xFF, count: 64)),
                       Self.chunk("eXIf", exif), Self.chunk("iCCP", icc), Self.chunk("gAMA", [0, 0, 0xB1, 0x8F]),
                       Self.chunk("pHYs", [0, 0, 0x0B, 0x13, 0, 0, 0x0B, 0x13, 1])]
        _ = assertClean(Self.pngWith(hostile), "image/png", forbidden: ["<script>", "GPSLatitude", "xmpmeta", "viadere-icc", "tEXt", "eXIf", "iCCP", "zTXt", "iTXt"], "png metadata")
        let app1 = Self.segment(0xE1, exif)
        let app2 = Self.segment(0xE2, Array("ICC_PROFILE\0".utf8) + [1, 1] + Array(repeating: 0x41, count: 128))
        let xmp = Self.segment(0xE1, Array("http://ns.adobe.com/xap/1.0/\0<x:xmpmeta>secret</x:xmpmeta>".utf8))
        let comment = Self.segment(0xFE, Array("<script>alert(1)</script>".utf8))
        _ = assertClean(Self.jpegWith([app1, app2, xmp, comment]), "image/jpeg", forbidden: ["GPSLatitude", "ICC_PROFILE", "xmpmeta", "<script>", "Exif"], "jpeg metadata")
    }

    func testLargeImagesAreResizedToTheirSlotAndNeverUpscaled() throws {
        let wide = try XCTUnwrap(assertClean(Self.png(width: 1200, height: 300, opaque: true), "image/png", slot: .logo, "wide logo"))
        XCTAssertEqual(wide.width, 512)
        XCTAssertEqual(wide.height, 128)
        let mark = try XCTUnwrap(assertClean(Self.png(width: 300, height: 600, opaque: true), "image/png", slot: .mark, "tall mark"))
        XCTAssertEqual(mark.height, 256)
        XCTAssertEqual(mark.width, 128)
        let small = try XCTUnwrap(assertClean(Self.png(width: 20, height: 10), "image/png", slot: .background, "small background"))
        XCTAssertEqual(small.width, 20)
    }

    // MARK: Refused before decoding

    func testFormatsAndMislabeledTypesAreRefused() {
        assertRejected(Array("<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>".utf8), "image/svg+xml", .svgRefused, "svg")
        assertRejected(Array("<svg onload=alert(1)>".utf8), "image/png", .svgRefused, "svg as png")
        assertRejected(Array("<!DOCTYPE html><html><script>alert(1)</script></html>".utf8), "image/png", .markupRefused, "html as png")
        assertRejected(Array("\u{FEFF}  <html><body onload=alert(1)>".utf8), "image/jpeg", .markupRefused, "html with BOM as jpeg")
        assertRejected(Array("<?xml version='1.0'?><root/>".utf8), "image/png", .markupRefused, "xml")
        assertRejected(Self.png(), "image/jpeg", .contentTypeMismatch, "png declared jpeg")
        assertRejected(Self.jpeg(), "image/png", .contentTypeMismatch, "jpeg declared png")
        assertRejected(Self.png(), "text/html", .contentTypeMismatch, "png declared html")
        assertRejected(Self.png(), "", .contentTypeMismatch, "no declared type")
        assertRejected(Array("GIF89a".utf8) + [1, 0, 1, 0, 0, 0, 0], "image/gif", .unsupportedFormat, "gif")
        assertRejected(Array("RIFF".utf8) + [0, 0, 0, 0] + Array("WEBPVP8 ".utf8), "image/webp", .unsupportedFormat, "webp")
        assertRejected(Array("%PDF-1.7\n".utf8), "application/pdf", .unsupportedFormat, "pdf")
        assertRejected([0, 0, 0, 0x18] + Array("ftypheic".utf8) + Array(repeating: 0, count: 16), "image/heic", .unsupportedFormat, "heic")
        assertRejected([], "image/png", .empty, "empty")
        assertRejected(Array(repeating: 0x41, count: BrandAssetPolicy.maxUploadBytes + 1), "image/png", .tooLarge, "over 2 MB")
    }

    func testDecompressionBombsAreRefusedFromTheHeaderAlone() {
        let idat = Self.chunks(Self.png()).first { $0.0 == "IDAT" }!.1
        let end = Self.chunk("IEND", [])
        for (w, h, expected) in [(UInt32(100_000), UInt32(100_000), BrandAssetPolicy.Rejection.dimensionsTooLarge), (8192, 8192, .dimensionsTooLarge),
                                 (9000, 10, .dimensionsTooLarge), (0, 10, .dimensionsInvalid), (0x7FFF_FFFF, 0x7FFF_FFFF, .dimensionsTooLarge)] {
            let bomb = PNGStructure.signature + Self.ihdr(width: w, height: h) + idat + end
            let started = Date()
            assertRejected(bomb, "image/png", expected, "png \(w)x\(h)")
            XCTAssertLessThan(Date().timeIntervalSince(started), 1, "refused without decoding")
        }
        // JPEG frame header claiming 60000 x 60000.
        var jpeg = Self.jpeg()
        let sof = (0..<(jpeg.count - 1)).first { jpeg[$0] == 0xFF && jpeg[$0 + 1] == 0xC0 }!
        jpeg[sof + 5] = 0xEA; jpeg[sof + 6] = 0x60; jpeg[sof + 7] = 0xEA; jpeg[sof + 8] = 0x60
        assertRejected(jpeg, "image/jpeg", .dimensionsTooLarge, "jpeg 60000x60000")
        // Height 0 (deferred to a DNL marker) is refused.
        var dnl = Self.jpeg()
        dnl[sof + 5] = 0; dnl[sof + 6] = 0
        assertRejected(dnl, "image/jpeg", .dimensionsInvalid, "jpeg height 0")
    }

    func testPolyglotsAnimationAndStructuralDamageAreRefused() {
        let png = Self.png()
        assertRejected(png + Array("<html><script>alert(1)</script></html>".utf8), "image/png", .trailingData, "png + html polyglot")
        assertRejected(png + [0x50, 0x4B, 0x03, 0x04] + Array(repeating: 0, count: 26), "image/png", .trailingData, "png + zip polyglot")
        assertRejected(Self.jpeg() + Array("PK\u{3}\u{4}".utf8) + Array(repeating: 0, count: 26), "image/jpeg", .trailingData, "jpeg + zip polyglot")
        assertRejected(Self.jpeg() + Array("<script>alert(1)</script>".utf8), "image/jpeg", .trailingData, "jpeg + script")
        assertRejected(Self.pngWith([Self.chunk("acTL", [0, 0, 0, 2, 0, 0, 0, 0])]), "image/png", .animated, "apng")
        assertRejected(Self.pngWith([Self.chunk("fcTL", Array(repeating: 0, count: 26))]), "image/png", .animated, "apng frame")
        // CRC mismatch, unknown critical chunk, CgBI, IHDR not first, missing IEND.
        var badCRC = png
        badCRC[29] ^= 0xFF
        assertRejected(badCRC, "image/png", .malformed, "bad crc")
        assertRejected(Self.pngWith([Self.chunk("ZZZZ", [1, 2, 3])]), "image/png", .malformed, "unknown critical chunk")
        assertRejected(PNGStructure.signature + Self.chunk("CgBI", [0, 0, 0, 0]) + Array(png.dropFirst(8)), "image/png", .malformed, "CgBI")
        let parts = Self.chunks(png)
        assertRejected(PNGStructure.signature + Self.chunk("tEXt", Array("a\0b".utf8)) + parts.flatMap(\.1), "image/png", .malformed, "IHDR not first")
        assertRejected(Self.jpegWith([Self.segment(0xC9, [8, 0, 16, 0, 16, 1, 1, 0x11, 0])]), "image/jpeg", .malformed, "arithmetic SOF9")
        assertRejected(Self.jpegWith([Self.segment(0xC3, [8, 0, 16, 0, 16, 1, 1, 0x11, 0])]), "image/jpeg", .malformed, "lossless SOF3")
        assertRejected([0xFF, 0xD8, 0xFF, 0xD8] + Array(Self.jpeg().dropFirst(2)), "image/jpeg", .malformed, "double SOI")
    }

    func testTruncatedFilesAreRefusedAtEveryCut() {
        let png = Self.png()
        for cut in [9, 16, 33, png.count / 2, png.count - 13, png.count - 1] {
            switch run(Array(png.prefix(cut)), "image/png") {
            case .success: XCTFail("png cut at \(cut) accepted")
            case .failure(let r): XCTAssertTrue([.truncated, .malformed].contains(r), "png cut at \(cut): \(r)")
            }
        }
        let jpeg = Self.jpeg()
        for cut in [3, 6, 30, jpeg.count / 2, jpeg.count - 2, jpeg.count - 1] {
            switch run(Array(jpeg.prefix(cut)), "image/jpeg") {
            case .success: XCTFail("jpeg cut at \(cut) accepted")
            case .failure(let r): XCTAssertTrue([.truncated, .malformed, .decodeFailed].contains(r), "jpeg cut at \(cut): \(r)")
            }
        }
    }

    // MARK: Mutation fuzzing (seeded, reproducible)

    struct SplitMix64: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
    }

    func testMutatedFilesAreEitherRefusedOrCleanlyReencoded() {
        var rng = SplitMix64(state: 0x5649_4144_4552_4521)
        for (seed, type) in [(Self.png(width: 12, height: 9), "image/png"), (Self.jpeg(width: 16, height: 8), "image/jpeg")] {
            var accepted = 0, refused = 0
            for _ in 0..<300 {
                var bytes = seed
                for _ in 0..<Int.random(in: 1...6, using: &rng) {
                    let index = Int.random(in: 0..<bytes.count, using: &rng)
                    switch Int.random(in: 0..<4, using: &rng) {
                    case 0: bytes[index] = UInt8.random(in: 0...255, using: &rng)
                    case 1: bytes.insert(UInt8.random(in: 0...255, using: &rng), at: index)
                    case 2: if bytes.count > 16 { bytes.remove(at: index) }
                    default: bytes[index] ^= 0x80
                    }
                }
                switch run(bytes, type) {
                case .failure: refused += 1
                case .success(let out):
                    accepted += 1
                    XCTAssertEqual(Set(Self.chunks([UInt8](out.png)).map(\.0)), ["IHDR", "IDAT", "IEND"])
                }
            }
            XCTAssertEqual(accepted + refused, 300)
            XCTAssertGreaterThan(refused, 0, type)
        }
    }
}
