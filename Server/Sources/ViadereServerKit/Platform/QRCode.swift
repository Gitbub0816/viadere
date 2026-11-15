import Foundation

/// A small, dependency-free QR Code (ISO/IEC 18004 Model 2) encoder: byte mode, versions 1–40, all four error
/// correction levels, automatic mask selection with the standard penalty rules. Used to render campaign links as
/// SVG on the server, so no third-party service ever sees a link. Output is verified against independently produced
/// symbols and the specification's Reed–Solomon / format-information test vectors (see `QRCodeTests`).
struct QRCode: Sendable, Equatable {
    enum ErrorCorrection: Int, Sendable, CaseIterable {
        case low = 0, medium, quartile, high

        /// The two format-information bits for the level (L=01, M=00, Q=11, H=10).
        var formatBits: Int {
            switch self {
            case .low: 1
            case .medium: 0
            case .quartile: 3
            case .high: 2
            }
        }
    }

    enum EncodeError: Error, Equatable { case tooLong, invalidMask }

    let version: Int
    let errorCorrection: ErrorCorrection
    let mask: Int
    let size: Int
    /// `modules[y][x]`, `true` = dark.
    let modules: [[Bool]]

    // MARK: Encoding

    /// Encodes UTF-8 text. `boostErrorCorrection` raises the level (up to H) whenever the chosen version has room.
    static func encode(_ text: String, errorCorrection: ErrorCorrection = .medium, minVersion: Int = 1, maxVersion: Int = 40,
                       mask forcedMask: Int? = nil, boostErrorCorrection: Bool = true) throws -> QRCode {
        try encode(bytes: Array(text.utf8), errorCorrection: errorCorrection, minVersion: minVersion, maxVersion: maxVersion,
                   mask: forcedMask, boostErrorCorrection: boostErrorCorrection)
    }

    static func encode(bytes: [UInt8], errorCorrection requested: ErrorCorrection = .medium, minVersion: Int = 1, maxVersion: Int = 40,
                       mask forcedMask: Int? = nil, boostErrorCorrection: Bool = true) throws -> QRCode {
        if let forcedMask, !(0...7).contains(forcedMask) { throw EncodeError.invalidMask }
        var ecc = requested
        var version = minVersion
        var dataUsedBits = 0
        while true {
            let capacity = numDataCodewords(version, ecc) * 8
            let countBits = version <= 9 ? 8 : 16
            if bytes.count < (1 << countBits) {
                dataUsedBits = 4 + countBits + bytes.count * 8
                if dataUsedBits <= capacity { break }
            }
            if version >= maxVersion { throw EncodeError.tooLong }
            version += 1
        }
        if boostErrorCorrection {
            for candidate in [ErrorCorrection.medium, .quartile, .high] where candidate.rawValue > ecc.rawValue {
                if dataUsedBits <= numDataCodewords(version, candidate) * 8 { ecc = candidate }
            }
        }
        // Bit stream: mode (0100), character count, data, terminator, padding.
        var bits: [Bool] = []
        func append(_ value: Int, _ count: Int) { for i in stride(from: count - 1, through: 0, by: -1) { bits.append((value >> i) & 1 == 1) } }
        append(0b0100, 4)
        append(bytes.count, version <= 9 ? 8 : 16)
        for byte in bytes { append(Int(byte), 8) }
        let capacityBits = numDataCodewords(version, ecc) * 8
        append(0, min(4, capacityBits - bits.count))
        append(0, (8 - bits.count % 8) % 8)
        var pad = 0xEC
        while bits.count < capacityBits {
            append(pad, 8)
            pad ^= 0xEC ^ 0x11
        }
        var data = [UInt8](repeating: 0, count: bits.count / 8)
        for (i, bit) in bits.enumerated() where bit { data[i >> 3] |= UInt8(1 << (7 - (i & 7))) }
        return build(version: version, ecc: ecc, data: data, forcedMask: forcedMask)
    }

    // MARK: Capacity tables (ISO/IEC 18004 Table 9; index [ecc][version], index 0 unused)

    private static let eccCodewordsPerBlock: [[Int]] = [
        [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
        [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
        [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
        [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    ]

    private static let errorCorrectionBlocks: [[Int]] = [
        [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
        [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
        [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
        [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
    ]

    /// Modules available for data and error correction (everything except function patterns).
    static func numRawDataModules(_ version: Int) -> Int {
        var result = (16 * version + 128) * version + 64
        if version >= 2 {
            let numAlign = version / 7 + 2
            result -= (25 * numAlign - 10) * numAlign - 55
            if version >= 7 { result -= 36 }
        }
        return result
    }

    static func numDataCodewords(_ version: Int, _ ecc: ErrorCorrection) -> Int {
        numRawDataModules(version) / 8 - eccCodewordsPerBlock[ecc.rawValue][version] * errorCorrectionBlocks[ecc.rawValue][version]
    }

    // MARK: Reed–Solomon over GF(2^8 / 0x11D)

    static func gfMultiply(_ x: UInt8, _ y: UInt8) -> UInt8 {
        var z = 0
        for i in stride(from: 7, through: 0, by: -1) {
            z = (z << 1) ^ ((z >> 7) * 0x11D)
            z ^= ((Int(y) >> i) & 1) * Int(x)
        }
        return UInt8(truncatingIfNeeded: z)
    }

    static func reedSolomonDivisor(degree: Int) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: degree - 1) + [1]
        var root: UInt8 = 1
        for _ in 0..<degree {
            for j in 0..<degree {
                result[j] = gfMultiply(result[j], root)
                if j + 1 < degree { result[j] ^= result[j + 1] }
            }
            root = gfMultiply(root, 0x02)
        }
        return result
    }

    static func reedSolomonRemainder(data: [UInt8], divisor: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: divisor.count)
        for byte in data {
            let factor = byte ^ result.removeFirst()
            result.append(0)
            for i in 0..<divisor.count { result[i] ^= gfMultiply(divisor[i], factor) }
        }
        return result
    }

    /// Splits data into blocks, appends each block's error correction and interleaves (ISO 18004 §7.6).
    static func addErrorCorrectionAndInterleave(_ data: [UInt8], version: Int, ecc: ErrorCorrection) -> [UInt8] {
        let numBlocks = errorCorrectionBlocks[ecc.rawValue][version]
        let blockEccLen = eccCodewordsPerBlock[ecc.rawValue][version]
        let rawCodewords = numRawDataModules(version) / 8
        let numShortBlocks = numBlocks - rawCodewords % numBlocks
        let shortBlockLen = rawCodewords / numBlocks
        var blocks: [[UInt8]] = []
        let divisor = reedSolomonDivisor(degree: blockEccLen)
        var k = 0
        for i in 0..<numBlocks {
            let length = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1)
            var block = Array(data[k..<k + length])
            k += length
            let eccBytes = reedSolomonRemainder(data: block, divisor: divisor)
            if i < numShortBlocks { block.append(0) }
            blocks.append(block + eccBytes)
        }
        var result: [UInt8] = []
        for i in 0..<blocks[0].count {
            for (j, block) in blocks.enumerated() where i != shortBlockLen - blockEccLen || j >= numShortBlocks { result.append(block[i]) }
        }
        return result
    }

    // MARK: Matrix construction

    private struct Builder {
        let version: Int
        let size: Int
        var modules: [[Bool]]
        var isFunction: [[Bool]]

        init(version: Int) {
            self.version = version
            size = version * 4 + 17
            modules = Array(repeating: Array(repeating: false, count: size), count: size)
            isFunction = modules
        }

        mutating func setFunction(_ x: Int, _ y: Int, _ dark: Bool) {
            modules[y][x] = dark
            isFunction[y][x] = true
        }

        static func alignmentPositions(version: Int, size: Int) -> [Int] {
            guard version > 1 else { return [] }
            let numAlign = version / 7 + 2
            let step = version == 32 ? 26 : (version * 4 + numAlign * 2 + 1) / (numAlign * 2 - 2) * 2
            var result = [Int](repeating: 0, count: numAlign)
            result[0] = 6
            var pos = size - 7
            for i in stride(from: numAlign - 1, through: 1, by: -1) {
                result[i] = pos
                pos -= step
            }
            return result
        }

        mutating func drawFunctionPatterns() {
            for i in 0..<size {
                setFunction(6, i, i % 2 == 0)
                setFunction(i, 6, i % 2 == 0)
            }
            drawFinder(3, 3)
            drawFinder(size - 4, 3)
            drawFinder(3, size - 4)
            let positions = Self.alignmentPositions(version: version, size: size)
            let n = positions.count
            for i in 0..<n {
                for j in 0..<n {
                    if (i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0) { continue }
                    drawAlignment(positions[i], positions[j])
                }
            }
            drawFormat(ecc: .low, mask: 0) // reserve; overwritten once the mask is chosen
            drawVersion()
        }

        mutating func drawFinder(_ x: Int, _ y: Int) {
            for dy in -4...4 {
                for dx in -4...4 {
                    let dist = max(abs(dx), abs(dy))
                    let xx = x + dx, yy = y + dy
                    if (0..<size).contains(xx), (0..<size).contains(yy) { setFunction(xx, yy, dist != 2 && dist != 4) }
                }
            }
        }

        mutating func drawAlignment(_ x: Int, _ y: Int) {
            for dy in -2...2 {
                for dx in -2...2 { setFunction(x + dx, y + dy, max(abs(dx), abs(dy)) != 1) }
            }
        }

        static func formatBits(ecc: ErrorCorrection, mask: Int) -> Int {
            let data = (ecc.formatBits << 3) | mask
            var rem = data
            for _ in 0..<10 { rem = (rem << 1) ^ ((rem >> 9) * 0x537) }
            return ((data << 10) | rem) ^ 0x5412
        }

        mutating func drawFormat(ecc: ErrorCorrection, mask: Int) {
            let bits = Self.formatBits(ecc: ecc, mask: mask)
            func bit(_ i: Int) -> Bool { (bits >> i) & 1 == 1 }
            for i in 0...5 { setFunction(8, i, bit(i)) }
            setFunction(8, 7, bit(6))
            setFunction(8, 8, bit(7))
            setFunction(7, 8, bit(8))
            for i in 9..<15 { setFunction(14 - i, 8, bit(i)) }
            for i in 0..<8 { setFunction(size - 1 - i, 8, bit(i)) }
            for i in 8..<15 { setFunction(8, size - 15 + i, bit(i)) }
            setFunction(8, size - 8, true)
        }

        static func versionBits(_ version: Int) -> Int {
            var rem = version
            for _ in 0..<12 { rem = (rem << 1) ^ ((rem >> 11) * 0x1F25) }
            return (version << 12) | rem
        }

        mutating func drawVersion() {
            guard version >= 7 else { return }
            let bits = Self.versionBits(version)
            for i in 0..<18 {
                let bit = (bits >> i) & 1 == 1
                let a = size - 11 + i % 3
                let b = i / 3
                setFunction(a, b, bit)
                setFunction(b, a, bit)
            }
        }

        mutating func drawCodewords(_ data: [UInt8]) {
            var i = 0
            var right = size - 1
            while right >= 1 {
                if right == 6 { right = 5 }
                for vert in 0..<size {
                    for j in 0..<2 {
                        let x = right - j
                        let upward = ((right + 1) & 2) == 0
                        let y = upward ? size - 1 - vert : vert
                        if !isFunction[y][x], i < data.count * 8 {
                            modules[y][x] = (data[i >> 3] >> (7 - UInt8(i & 7))) & 1 == 1
                            i += 1
                        }
                    }
                }
                right -= 2
            }
        }

        mutating func applyMask(_ mask: Int) {
            for y in 0..<size {
                for x in 0..<size {
                    let invert: Bool
                    switch mask {
                    case 0: invert = (x + y) % 2 == 0
                    case 1: invert = y % 2 == 0
                    case 2: invert = x % 3 == 0
                    case 3: invert = (x + y) % 3 == 0
                    case 4: invert = (x / 3 + y / 2) % 2 == 0
                    case 5: invert = x * y % 2 + x * y % 3 == 0
                    case 6: invert = (x * y % 2 + x * y % 3) % 2 == 0
                    default: invert = ((x + y) % 2 + x * y % 3) % 2 == 0
                    }
                    if invert && !isFunction[y][x] { modules[y][x].toggle() }
                }
            }
        }

        // Penalty rules N1–N4 (ISO 18004 §7.8.3).
        func penalty() -> Int {
            var result = 0
            func addHistory(_ run: Int, _ history: inout [Int]) {
                var run = run
                if history[0] == 0 { run += size }
                for i in stride(from: history.count - 1, through: 1, by: -1) { history[i] = history[i - 1] }
                history[0] = run
            }
            func countPatterns(_ h: [Int]) -> Int {
                let n = h[1]
                let core = n > 0 && h[2] == n && h[3] == n * 3 && h[4] == n && h[5] == n
                return (core && h[0] >= n * 4 && h[6] >= n ? 1 : 0) + (core && h[6] >= n * 4 && h[0] >= n ? 1 : 0)
            }
            func terminate(_ color: Bool, _ run: Int, _ history: inout [Int]) -> Int {
                var run = run
                if color {
                    addHistory(run, &history)
                    run = 0
                }
                run += size
                addHistory(run, &history)
                return countPatterns(history)
            }
            func scan(_ get: (Int, Int) -> Bool) {
                for a in 0..<size {
                    var color = false
                    var run = 0
                    var history = [Int](repeating: 0, count: 7)
                    for b in 0..<size {
                        if get(a, b) == color {
                            run += 1
                            if run == 5 { result += 3 } else if run > 5 { result += 1 }
                        } else {
                            addHistory(run, &history)
                            if !color { result += countPatterns(history) * 40 }
                            color = get(a, b)
                            run = 1
                        }
                    }
                    result += terminate(color, run, &history) * 40
                }
            }
            scan { y, x in modules[y][x] }
            scan { x, y in modules[y][x] }
            for y in 0..<(size - 1) {
                for x in 0..<(size - 1) {
                    let c = modules[y][x]
                    if c == modules[y][x + 1], c == modules[y + 1][x], c == modules[y + 1][x + 1] { result += 3 }
                }
            }
            let dark = modules.reduce(0) { $0 + $1.filter { $0 }.count }
            let total = size * size
            let k = (abs(dark * 20 - total * 10) + total - 1) / total - 1
            result += k * 10
            return result
        }
    }

    private static func build(version: Int, ecc: ErrorCorrection, data: [UInt8], forcedMask: Int?) -> QRCode {
        var builder = Builder(version: version)
        builder.drawFunctionPatterns()
        builder.drawCodewords(addErrorCorrectionAndInterleave(data, version: version, ecc: ecc))
        var best = forcedMask ?? 0
        if forcedMask == nil {
            var minPenalty = Int.max
            for candidate in 0..<8 {
                builder.applyMask(candidate)
                builder.drawFormat(ecc: ecc, mask: candidate)
                let p = builder.penalty()
                if p < minPenalty {
                    best = candidate
                    minPenalty = p
                }
                builder.applyMask(candidate) // XOR undoes it
            }
        }
        builder.applyMask(best)
        builder.drawFormat(ecc: ecc, mask: best)
        return QRCode(version: version, errorCorrection: ecc, mask: best, size: builder.size, modules: builder.modules)
    }

    // MARK: Format information (exposed for tests)

    static func formatInformation(ecc: ErrorCorrection, mask: Int) -> Int { Builder.formatBits(ecc: ecc, mask: mask) }
    static func versionInformation(_ version: Int) -> Int { Builder.versionBits(version) }

    // MARK: Rendering

    /// Self-contained SVG: dark modules on a white field with a 4-module quiet zone, merged into horizontal runs.
    func svg(border: Int = 4, dark: String = "#1F1E1C", light: String = "#FFFFFF", title: String? = nil) -> String {
        let total = size + border * 2
        var path = ""
        for y in 0..<size {
            var x = 0
            while x < size {
                if modules[y][x] {
                    var end = x
                    while end < size, modules[y][end] { end += 1 }
                    path += "M\(x + border),\(y + border)h\(end - x)v1h-\(end - x)z"
                    x = end
                } else {
                    x += 1
                }
            }
        }
        let titleTag = title.map { "<title>\(WebRoutes.escape($0))</title>" } ?? ""
        return "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 \(total) \(total)\" role=\"img\" shape-rendering=\"crispEdges\">\(titleTag)"
            + "<rect width=\"\(total)\" height=\"\(total)\" fill=\"\(light)\"/><path d=\"\(path)\" fill=\"\(dark)\"/></svg>"
    }

    /// Row strings of `0`/`1` (for vector tests).
    var rows: [String] { modules.map { String($0.map { $0 ? "1" : "0" }) } }
}
