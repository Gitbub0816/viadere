import Foundation

// CKey Profile 0 encoder (Format 0.27.0, standard layout): a line-for-line Swift port of the CKey reference core
// (https://github.com/clearkeysolutions/ckey, tag v0.1.0-build.85, `src/core_internal.inc` and `src/api_codec.inc`).
//
// Why a port and not the C++ core: the server and the business SDK only ever *draw* codes, from text they made themselves, and the
// project keeps C codecs out of the server (CLAUDE.md, ADR-0017). Reading codes from camera frames is the app's job and uses the
// official scan-only CKey package there. `CKeySymbolTests` checks this port against vectors made by the reference build: the same
// codeword, bit for bit, and the same SVG, byte for byte, so a symbol drawn here is the symbol the reference decoder expects.
//
// Portions Copyright (c) 2026 ClearKey Solutions, LLC, MIT License (see `docs/THIRD-PARTY-NOTICES.md`).

/// A CKey optical code (Profile 0): the payload after framing, Reed-Solomon coding and interleaving, ready to draw.
public struct CKeySymbol: Sendable, Equatable {
    /// Error-correction level: about 7, 14, 22 or 30 % of each block can be repaired.
    public enum Level: Int, Sendable, CaseIterable {
        case low = 0, medium = 1, quartile = 2, high = 3
    }

    public enum EncodingError: Error, Sendable, Equatable {
        /// `version` is not 0 (automatic) or 1...31.
        case invalidVersion
        /// The payload does not fit the requested version (or version 31) at this level.
        case payloadTooLong
    }

    public static let versionRange = 1...31

    /// Symbol version 1...31; a higher version has more, smaller marks.
    public let version: Int
    public let level: Level
    public let payloadLength: Int
    /// The interleaved Reed-Solomon codeword, one bit per data site in placement order.
    public let codeword: [UInt8]

    /// The longest payload, in bytes, that `version` holds at `level`.
    public static func capacity(version: Int, level: Level) -> Int {
        guard versionRange.contains(version) else { return 0 }
        let data = dataBytes(codewordBytes: CKeyLayout.standard(version).codewordBytes, level: level)
        return data > overheadBytes ? min(data - overheadBytes, 65_535) : 0
    }

    /// Encodes UTF-8 text. `version` 0 picks the smallest version that fits.
    public static func encode(_ text: String, level: Level = .medium, version: Int = 0) throws -> CKeySymbol {
        try encode(bytes: Array(text.utf8), level: level, version: version)
    }

    /// Encodes bytes. `version` 0 picks the smallest version that fits.
    public static func encode(bytes payload: [UInt8], level: Level = .medium, version: Int = 0) throws -> CKeySymbol {
        guard version == 0 || versionRange.contains(version) else { throw EncodingError.invalidVersion }
        var v = version
        if v == 0 {
            v = 1
            while v <= versionRange.upperBound, capacity(version: v, level: level) < payload.count { v += 1 }
        }
        guard v <= versionRange.upperBound, capacity(version: v, level: level) >= payload.count else { throw EncodingError.payloadTooLong }
        let layout = CKeyLayout.standard(v)
        let blocks = rsBlocks(codewordBytes: layout.codewordBytes, level: level)

        // Frame: magic, format, profile, version, level, length, payload, CRC-32C, then the normative SplitMix32 fill.
        var framed = [UInt8](repeating: 0, count: blocks.reduce(0) { $0 + $1.k })
        framed[0] = 0xC7; framed[1] = 0x4B; framed[2] = CKeyLayout.formatVersion; framed[3] = 0
        framed[4] = UInt8(v); framed[5] = UInt8(level.rawValue)
        framed[6] = UInt8(payload.count >> 8); framed[7] = UInt8(payload.count & 0xFF)
        framed.replaceSubrange(headerBytes..<(headerBytes + payload.count), with: payload)
        let crcIndex = headerBytes + payload.count
        let crc = CKeyMath.crc32c(framed[0..<crcIndex])
        for b in 0..<4 { framed[crcIndex + b] = UInt8((crc >> UInt32(24 - 8 * b)) & 0xFF) }
        var state = CKeyMath.crc32c(framed[0..<(crcIndex + 4)])
        for i in (crcIndex + 4)..<framed.count { framed[i] = CKeyMath.paddingByte(&state) }

        // Reed-Solomon per block, then byte-interleave so local damage spreads over every block.
        var coded: [[UInt8]] = []
        var offset = 0
        for block in blocks {
            var work = [UInt8](repeating: 0, count: block.n)
            work.replaceSubrange(0..<block.k, with: framed[offset..<(offset + block.k)])
            offset += block.k
            CKeyMath.rsEncode(&work, dataBytes: block.k)
            coded.append(work)
        }
        var codeword: [UInt8] = []
        codeword.reserveCapacity(layout.codewordBytes)
        for j in 0..<blocks[0].n {
            for b in 0..<blocks.count where j < blocks[b].n { codeword.append(coded[b][j]) }
        }
        return CKeySymbol(version: v, level: level, payloadLength: payload.count, codeword: codeword)
    }

    /// Whether data site `index` (placement order) is printed: the codeword bit, whitened.
    func siteValue(_ index: Int, layout: CKeyLayout) -> Bool {
        let data = index < layout.codewordBytes * 8 && (codeword[index / 8] >> UInt8(7 - index % 8)) & 1 != 0
        return data != layout.white[index]
    }

    // MARK: Blocks

    static let headerBytes = 8
    static let overheadBytes = 12  // header + CRC-32C
    private static let parityPercent = [14, 28, 44, 60]  // L, M, Q, H

    struct Block: Equatable { let n: Int; let k: Int }

    /// The codeword is split into ceil(C/255) near-equal blocks (longer ones first); each keeps 2*round(pct*n/200) parity bytes.
    static func rsBlocks(codewordBytes: Int, level: Level) -> [Block] {
        let count = (codewordBytes + 254) / 255
        return (0..<count).map { b in
            let n = codewordBytes / count + (b < codewordBytes % count ? 1 : 0)
            let parity = max(2, 2 * ((parityPercent[level.rawValue] * n + 100) / 200))
            return Block(n: n, k: n - min(parity, n - 1))
        }
    }

    static func dataBytes(codewordBytes: Int, level: Level) -> Int {
        rsBlocks(codewordBytes: codewordBytes, level: level).reduce(0) { $0 + $1.k }
    }
}

/// Integer arithmetic of the format: GF(256) Reed-Solomon, CRC-32C, the SplitMix32 fill and the site hash.
enum CKeyMath {
    private static let tables: (exp: [UInt8], log: [UInt8]) = {
        var exp = [UInt8](repeating: 0, count: 512), log = [UInt8](repeating: 0, count: 256)
        var x = 1
        for i in 0..<255 {
            exp[i] = UInt8(x); log[x] = UInt8(i)
            x <<= 1
            if x & 0x100 != 0 { x ^= 0x11D }
        }
        for i in 255..<512 { exp[i] = exp[i - 255] }
        return (exp, log)
    }()

    static func gfMul(_ a: UInt8, _ b: UInt8) -> UInt8 {
        a == 0 || b == 0 ? 0 : tables.exp[Int(tables.log[Int(a)]) + Int(tables.log[Int(b)])]
    }

    /// Systematic RS encode in place: `codeword[dataBytes...]` receives the parity.
    static func rsEncode(_ codeword: inout [UInt8], dataBytes: Int) {
        let parity = codeword.count - dataBytes
        var generator: [UInt8] = [1]
        for root in 0..<parity {
            var next = [UInt8](repeating: 0, count: generator.count + 1)
            for i in 0..<generator.count {
                next[i] ^= generator[i]
                next[i + 1] ^= gfMul(generator[i], tables.exp[root])
            }
            generator = next
        }
        var work = codeword
        for i in 0..<dataBytes {
            let feedback = work[i]
            if feedback == 0 { continue }
            for j in 1...parity { work[i + j] ^= gfMul(generator[j], feedback) }
        }
        codeword.replaceSubrange(dataBytes..., with: work[dataBytes...])
    }

    static func crc32c(_ data: ArraySlice<UInt8>) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            crc ^= UInt32(byte)
            for _ in 0..<8 { crc = (crc >> 1) ^ (0x82F6_3B78 & (0 &- (crc & 1))) }
        }
        return ~crc
    }

    /// SplitMix32: the fill for unused frame bytes and the whitening sequence.
    static func paddingByte(_ state: inout UInt32) -> UInt8 {
        state = state &+ 0x9E37_79B9
        var value = state
        value = (value ^ (value >> 16)) &* 0x85EB_CA6B
        value = (value ^ (value >> 13)) &* 0xC2B2_AE35
        value ^= value >> 16
        return UInt8(value & 0xFF)
    }

    /// lowbias32: a bijection on 32-bit words, so distinct sites never tie.
    static func siteHash(_ input: UInt32) -> UInt32 {
        var x = input
        x ^= x >> 16; x = x &* 0x7FEB_352D; x ^= x >> 15; x = x &* 0x846C_A68B; x ^= x >> 16
        return x
    }
}

/// Where every mark of a version sits (standard family). Built once per version and cached.
final class CKeyLayout: Sendable {
    enum Kind: UInt8, Sendable { case cartesian = 0, dial = 1, ring = 2 }

    struct Node: Sendable {
        let kind: Kind
        let x: Double, y: Double
        let ring: Int, slot: Int
        let id: UInt32
    }

    static let formatVersion: UInt8 = 0x1B  // Format 0.27
    static let center = 14.5
    static let tau = 6.283185307179586476925286766559
    static let ringInner = 3.4, dialInner = 7.6

    private static let grids = [29, 31, 33, 36, 38, 41, 44, 47, 50, 54, 58, 62, 67, 71, 77, 82, 88, 94, 101, 108, 116, 124, 133, 143, 153, 164, 176, 188, 202, 216, 232]
    private static let slots = [72, 80, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 168, 176, 192, 200, 216, 232, 248, 272, 288, 304, 328, 352, 376, 408, 440, 464, 504, 536, 576]
    private static let ringCounts = [3, 3, 3, 4, 4, 5, 5, 6, 6, 7, 8, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 20, 22, 23, 25, 27, 29, 32, 34, 37]
    private static let gridCols = [2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 7, 7, 8, 9, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21, 23]
    private static let gridRows = [10, 12, 13, 14, 15, 16, 17, 18, 20, 21, 23, 25, 27, 28, 31, 33, 35, 38, 41, 44, 47, 50, 54, 58, 62, 67, 72, 77, 83, 88, 95]

    let version: Int
    let grid: Int, rings: Int, col0: Int, row0: Int, dialSlots: Int
    let pitch: Double
    let nodes: [Node]
    let white: [Bool]
    let codewordBytes: Int

    var ringPitch: Double { 0.86 * pitch }
    var dot: Double { 0.2 * pitch }
    var rayWidth: Double { 0.2 * pitch }
    var longRay: Double { 2.2 * pitch }
    var shortRay: Double { 1.0 * pitch }
    var keyRay: Double { 3.4 * pitch }
    var rayKeyHalf: Int { 3 * dialSlots / 4 }        // 9:00, half length
    var rayKeyThree: Int { 3 * dialSlots / 4 - 2 }   // two slots before, 3/4 length
    var ringKeySlot: Int { dialSlots / 4 }           // 3:00, on the outermost ring
    static let ringKeySpan = 16

    func ringRadius(_ k: Int) -> Double { Self.ringInner + ringPitch * Double(k) }
    func reservedRay(_ slot: Int) -> Bool { slot == 0 || slot == rayKeyHalf || slot == rayKeyThree }

    // MARK: Cache

    private final class Cache: @unchecked Sendable {
        let lock = NSLock()
        var layouts: [Int: CKeyLayout] = [:]
    }
    private static let cache = Cache()

    static func standard(_ version: Int) -> CKeyLayout {
        precondition(CKeySymbol.versionRange.contains(version))
        cache.lock.lock()
        defer { cache.lock.unlock() }
        if let layout = cache.layouts[version] { return layout }
        let layout = CKeyLayout(version: version)
        cache.layouts[version] = layout
        return layout
    }

    private init(version v: Int) {
        let i = v - 1
        version = v
        grid = Self.grids[i]; rings = Self.ringCounts[i]; col0 = Self.gridCols[i]; row0 = Self.gridRows[i]; dialSlots = Self.slots[i]
        let p = 29.0 / Double(grid)
        pitch = p
        let geometry = Geometry(col0: col0, row0: row0, pitch: p, slots: dialSlots, rayInkOuter: Self.dialInner + 2.2 * p + 0.2 * p / 2)

        var nodes: [Node] = []
        for row in 0..<grid {
            for col in 0..<grid {
                let x = (Double(col) + 0.5) * p, y = (Double(row) + 0.5) * p
                if geometry.siteMargin(x, y) <= 0.0 { continue }
                nodes.append(Node(kind: .cartesian, x: x, y: y, ring: -1, slot: -1, id: Self.identity(0, UInt32(row), UInt32(col))))
            }
        }
        let rayKeyHalf = 3 * dialSlots / 4, rayKeyThree = 3 * dialSlots / 4 - 2
        let reserved = { (slot: Int) in slot == 0 || slot == rayKeyHalf || slot == rayKeyThree }
        for slot in 0..<dialSlots where !reserved(slot) {
            nodes.append(Node(kind: .dial, x: 0, y: 0, ring: -1, slot: slot, id: Self.identity(1, 0, UInt32(slot))))
        }
        let key = dialSlots / 4
        for ring in 0..<rings {
            for slot in 0..<dialSlots {
                // Ring slots are also cleared on the Ray Key bearings, and the Ring Key owns a span of the outermost ring.
                if reserved(slot) || (ring == rings - 1 && slot >= key && slot < key + Self.ringKeySpan) { continue }
                let r = Self.ringInner + 0.86 * p * Double(ring), a = Self.tau * Double(slot) / Double(dialSlots)
                nodes.append(Node(kind: .ring, x: Self.center + r * sin(a), y: Self.center - r * cos(a), ring: ring, slot: slot,
                                  id: Self.identity(2, UInt32(ring), UInt32(slot))))
            }
        }
        let placement = CKeyMath.siteHash(0x434B_5030 ^ UInt32(v))  // "CKP0"
        nodes.sort { CKeyMath.siteHash($0.id ^ placement) < CKeyMath.siteHash($1.id ^ placement) }
        self.nodes = nodes

        var state: UInt32 = 0x434B_5730 &+ UInt32(v)  // "CKW0"
        var white = [Bool](repeating: false, count: nodes.count)
        var byte: UInt8 = 0
        for n in 0..<nodes.count {
            if n % 8 == 0 { byte = CKeyMath.paddingByte(&state) }
            white[n] = (byte >> UInt8(7 - n % 8)) & 1 != 0
        }
        self.white = white
        codewordBytes = nodes.count / 8
    }

    private static func identity(_ kind: UInt32, _ a: UInt32, _ b: UInt32) -> UInt32 { (kind << 24) | (a << 12) | b }

    /// The structural clearances a Cartesian module must keep: frame, finders, Grid Key, the polar field and the Ray Keys.
    private struct Geometry {
        let frameCenter = 14.5, frameHalf = 14.0, frameRadius = 3.5, frameHalfStroke = 0.325
        let finderInset = 4.0, finderRadius = 2.3, finderHalfStroke = 0.4, side = 29.0
        let clear: Double
        let gridX0: Double, gridY0: Double, gridX1: Double, gridY1: Double, gridClear: Double
        let rayInkOuter: Double, polarClear: Double
        let keyRayR0 = CKeyLayout.dialInner
        let keyRayLength: Double, keyRayHalfWidth: Double
        let keyRayDir: [(Double, Double)]
        let keyRayFraction = [1.0, 0.5, 0.75]
        let moduleHalf: Double

        init(col0: Int, row0: Int, pitch p: Double, slots: Int, rayInkOuter: Double) {
            let a = CKeyLayout.tau * (3.0 * Double(slots) / 4.0 - 2.0) / Double(slots)
            clear = max(0.375, p)
            gridX0 = Double(col0) * p + 0.16 * p; gridY0 = Double(row0) * p + 0.16 * p
            gridX1 = Double(col0 + 2) * p - 0.16 * p; gridY1 = Double(row0 + 2) * p - 0.16 * p
            gridClear = p
            self.rayInkOuter = rayInkOuter; polarClear = p
            keyRayLength = 3.4 * p; keyRayHalfWidth = 0.22 * p
            keyRayDir = [(0.0, -1.0), (-1.0, 0.0), (sin(a), -cos(a))]
            moduleHalf = 0.34 * p
        }

        private func roundedSquareSD(_ x: Double, _ y: Double) -> Double {
            let qx = abs(x - frameCenter) - (frameHalf - frameRadius), qy = abs(y - frameCenter) - (frameHalf - frameRadius)
            let ox = max(qx, 0.0), oy = max(qy, 0.0)
            return (ox * ox + oy * oy).squareRoot() + min(max(qx, qy), 0.0) - frameRadius
        }

        /// Distance to a corner finder's centerline: the quarter circle around (cx, cy) in the symbol's outer corner quadrant.
        private func finderDistance(_ x: Double, _ y: Double, _ cx: Double, _ cy: Double, right: Bool, bottom: Bool) -> Double {
            var dx = x - cx, dy = y - cy
            if right { dx = -dx }
            if bottom { dy = -dy }
            let r = finderRadius
            if dx <= 0 && dy <= 0 { return abs((dx * dx + dy * dy).squareRoot() - r) }
            let ex = dx + r, ey = dy + r
            return min((ex * ex + dy * dy).squareRoot(), (dx * dx + ey * ey).squareRoot())
        }

        private func segmentDistance(_ x: Double, _ y: Double, _ x0: Double, _ y0: Double, _ x1: Double, _ y1: Double) -> Double {
            let vx = x1 - x0, vy = y1 - y0, wx = x - x0, wy = y - y0
            let t = min(max((wx * vx + wy * vy) / (vx * vx + vy * vy), 0.0), 1.0)
            let px = x0 + t * vx - x, py = y0 + t * vy - y
            return (px * px + py * py).squareRoot()
        }

        /// Signed safe-area slack for a module centered at (x, y): positive means every clearance is met.
        func siteMargin(_ x: Double, _ y: Double) -> Double {
            let e = moduleHalf * 1.4142135623730951  // circumscribed disc
            var m = -roundedSquareSD(x, y) - frameHalfStroke - e - clear
            let near = finderInset, far = side - finderInset
            let finderNeed = finderHalfStroke + e + clear
            m = min(m, finderDistance(x, y, near, near, right: false, bottom: false) - finderNeed)
            m = min(m, finderDistance(x, y, far, near, right: true, bottom: false) - finderNeed)
            m = min(m, finderDistance(x, y, near, far, right: false, bottom: true) - finderNeed)
            m = min(m, finderDistance(x, y, far, far, right: true, bottom: true) - finderNeed)
            let gx = max(gridX0 - x, 0.0, x - gridX1), gy = max(gridY0 - y, 0.0, y - gridY1)
            m = min(m, (gx * gx + gy * gy).squareRoot() - e - gridClear)
            let dx = x - CKeyLayout.center, dy = y - CKeyLayout.center
            m = min(m, (dx * dx + dy * dy).squareRoot() - rayInkOuter - e - polarClear)
            for k in 0..<3 {
                let r1 = keyRayR0 + keyRayLength * keyRayFraction[k]
                let (ux, uy) = keyRayDir[k]
                let c = CKeyLayout.center
                m = min(m, segmentDistance(x, y, c + keyRayR0 * ux, c + keyRayR0 * uy, c + r1 * ux, c + r1 * uy) - keyRayHalfWidth - e - polarClear)
            }
            return m
        }
    }
}
