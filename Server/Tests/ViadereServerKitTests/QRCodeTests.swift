import Foundation
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// QR encoder verification against independent references:
/// * the ISO/IEC 18004 Reed–Solomon example (version 1-M "HELLO WORLD"),
/// * the specification's format- and version-information tables and capacity tables,
/// * complete symbols produced by an independent implementation (segno 1.6.6, byte mode, no error-correction
///   boost, automatic mask), compared module for module (small symbols) or by SHA-256 of the module matrix.
final class QRCodeTests: XCTestCase {
    func testReedSolomonMatchesTheSpecificationExample() {
        let data: [UInt8] = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17]
        let divisor = QRCode.reedSolomonDivisor(degree: 10)
        XCTAssertEqual(QRCode.reedSolomonRemainder(data: data, divisor: divisor), [196, 35, 39, 119, 235, 215, 231, 226, 93, 23])
    }

    func testGaloisFieldMultiplication() {
        XCTAssertEqual(QRCode.gfMultiply(2, 128), 0x1D) // x * x^7 = x^8 = 0x11D mod -> 0x1D
        XCTAssertEqual(QRCode.gfMultiply(0, 77), 0)
        XCTAssertEqual(QRCode.gfMultiply(1, 77), 77)
        XCTAssertEqual(QRCode.gfMultiply(3, 7), 9) // (x+1)(x^2+x+1) = x^3+1... carry-less: 3*7 = 9
    }

    func testFormatAndVersionInformationMatchTheSpecificationTables() {
        XCTAssertEqual(QRCode.formatInformation(ecc: .medium, mask: 0), 0b101010000010010)
        XCTAssertEqual(QRCode.formatInformation(ecc: .low, mask: 0), 0b111011111000100)
        XCTAssertEqual(QRCode.formatInformation(ecc: .quartile, mask: 0), 0b011010101011111)
        XCTAssertEqual(QRCode.formatInformation(ecc: .high, mask: 0), 0b001011010001001)
        XCTAssertEqual(QRCode.versionInformation(7), 0b000111110010010100)
        XCTAssertEqual(QRCode.versionInformation(8), 0b001000010110111100)
        XCTAssertEqual(QRCode.versionInformation(40), 0b101000110001101001)
    }

    func testCapacityTablesMatchTheSpecification() {
        let expected: [(Int, QRCode.ErrorCorrection, Int)] = [
            (1, .low, 19), (1, .medium, 16), (1, .quartile, 13), (1, .high, 9),
            (2, .low, 34), (3, .medium, 44), (5, .quartile, 62), (7, .high, 66),
            (10, .low, 274), (10, .medium, 216), (10, .quartile, 154), (10, .high, 122),
            (40, .low, 2956), (40, .medium, 2334), (40, .quartile, 1666), (40, .high, 1276),
        ]
        for (version, ecc, codewords) in expected {
            XCTAssertEqual(QRCode.numDataCodewords(version, ecc), codewords, "v\(version) \(ecc)")
        }
        // Raw module counts from ISO/IEC 18004 Table 1.
        XCTAssertEqual(QRCode.numRawDataModules(1), 208)
        XCTAssertEqual(QRCode.numRawDataModules(2), 359)
        XCTAssertEqual(QRCode.numRawDataModules(7), 1568)
        XCTAssertEqual(QRCode.numRawDataModules(40), 29648)
        // Every version/level must leave a positive, whole number of codewords per block.
        for version in 1...40 {
            for ecc in QRCode.ErrorCorrection.allCases { XCTAssertGreaterThan(QRCode.numDataCodewords(version, ecc), 0, "v\(version)") }
        }
    }

    /// (text, level, version chosen without boost, SHA-256 prefix of the module matrix for masks 0…7), produced by
    /// segno 1.6.6 in byte mode (raw bytes, no ECI; its pad-to-byte step is patched to the ISO rule, because stock
    /// segno appends a spurious 0x00 byte when the stream is already byte aligned). Comparing every mask proves codeword encoding, Reed–Solomon, block interleaving,
    /// function patterns, mask patterns and format/version information module for module, independent of how a
    /// given implementation scores masks.
    func vectors() -> [(String, QRCode.ErrorCorrection, Int, [String])] {
        [
            ("HELLO WORLD", .medium, 1, ["2cee776cd87923a0", "c7636e44b12237cb", "4a00c00a60fcf7c1", "1e387bd8b7a170bf", "2d21897bf5a7ac60", "ab139df21b793714", "84a0007f0e8c0dba", "0903104ff7b59378"]),
            ("https://viadere.io/c/AF2345", .low, 2, ["ea91d2c2f710d333", "a9286c0574ab74b5", "dd830b45453f3780", "d9d45d849a58ff5b", "ee2b2ea8a06bee02", "f8a4d1a1b956a1f3", "71316ae9feead99d", "714272101fc5e522"]),
            ("https://viadere.io/c/AF2345", .medium, 3, ["e5324977153f6590", "c7e9fc6d8d0cfd46", "ff4fbd663714e538", "e577cc6c6f0195a0", "d8cbd32a1a4ed3fe", "1993151c37f66c1a", "3c36cbc620e03e5d", "c2286c2d006888d9"]),
            ("https://viadere.io/c/AF2345", .quartile, 3, ["20d77ec65a1f79dd", "b62559653cc1a1a1", "d41779c9772c4e03", "5499802776e8b7eb", "94d6ed10c1ad51a5", "74ac77244beb08c3", "616960b8154ae11d", "4e69d2619e3b3905"]),
            ("https://viadere.io/c/AF2345", .high, 4, ["39fd8c3079e8eaac", "0af5322841117549", "f67cad11572b60f0", "2cdc1e09e237a0c1", "d8e8b007f5b9c32a", "9d3fa6f04702be38", "d6c18b16dfcad0ca", "bf09b0078e15f7cc"]),
            ("Viadere ✓ trusted way to connect", .medium, 3, ["17500b4d2f4c3484", "f2f334b2db83ac82", "428d7f70b62464fc", "e1ae7e676530def1", "65e7ace98c1930bb", "0d67efab745461c1", "cc272711f6fb1505", "93ef012d5a909d1f"]),
            (String(repeating: "A", count: 150), .medium, 8, ["0fa359aa8b175d9b", "d0bb5ff6ea02e40c", "bff5d45955555edc", "6083ea84067d0179", "1aa3d7608b0808eb", "c3527c43d767aebf", "70dccfbdbe4df34d", "4eaa42ec7578383a"]),
            ("https://viadere.io/c/AF2345?ctx=eyJhY3QiOiJlbnJvbGxfcmV3YXJkcyIsImNtcCI6InNwcmluZy1mbHllciIsImlhdCI6IjIwMjYtMTAtMjdUMDg6MDA6MDAuMDAwWiJ9&sig=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ0", .medium, 10, ["6e2aa121feceb2c6", "679ae6ddabba4e22", "f15b66b1afc8cb08", "1d548031bef2f271", "8e6fe765821442d3", "659b3ea0c3b0b8c9", "bb8a96e456ff86ad", "93b0f9f871055043"]),
            (String(repeating: "B", count: 400), .quartile, 19, ["dc1cf0dfa4d84732", "8d4106c67e5c8884", "d8f6a7dffbf18ed0", "83111c96f9c0a8fa", "a39144078b25eaaf", "826a064d89da3e5e", "bcd9d92cb149ce39", "c7f621f1ff92bb7b"]),
            (String(repeating: "B", count: 1000), .low, 22, ["ff0c01b972c8f504", "9a8da5c60819e135", "c9d8e1a9f0ea1fde", "a120f4285103bbca", "1e183613a3b82efe", "ddcb1804f0d396cc", "6e5256b59f909e27", "ccdfecb142d542cc"]),
            (String(repeating: "C", count: 2900), .low, 40, ["aa322e75bfa77cd4", "044dc6f45ee6e4ef", "8498664c49b229db", "74c762266538165f", "64e56235ded5dd8f", "a30409bd091bc251", "2b24b5510f800e91", "950522eeb91196af"]),
        ]
    }

    func testSymbolsMatchAnIndependentImplementationModuleForModule() throws {
        for (text, ecc, version, hashes) in vectors() {
            for mask in 0..<8 {
                let qr = try QRCode.encode(text, errorCorrection: ecc, mask: mask, boostErrorCorrection: false)
                XCTAssertEqual(qr.version, version, "version for \(text.prefix(30))")
                XCTAssertEqual(qr.size, version * 4 + 17)
                XCTAssertEqual(String(Self.sha(qr.rows).prefix(16)), hashes[mask], "v\(version) \(ecc) mask \(mask) \(text.prefix(30))")
            }
        }
    }

    func testAutomaticMaskChoiceIsOneOfTheEightAndRoundTripsItsFormatBits() throws {
        for (text, ecc, _, _) in vectors() {
            let qr = try QRCode.encode(text, errorCorrection: ecc, boostErrorCorrection: false)
            XCTAssertTrue((0..<8).contains(qr.mask))
            // The auto-selected symbol is exactly the forced symbol for the mask it chose.
            let forced = try QRCode.encode(text, errorCorrection: ecc, mask: qr.mask, boostErrorCorrection: false)
            XCTAssertEqual(qr, forced)
        }
    }

    func testForcedMasksProduceValidFormatBitsAndDifferentSymbols() throws {
        var seen = Set<String>()
        for mask in 0..<8 {
            let qr = try QRCode.encode("https://viadere.io/c/AF2345", errorCorrection: .medium, mask: mask, boostErrorCorrection: false)
            XCTAssertEqual(qr.mask, mask)
            seen.insert(Self.sha(qr.rows))
            // Read the first format copy back (row 8, columns 0-5,7,8 / column 8 rows 7,5-0) and compare with the table.
            func bit(_ x: Int, _ y: Int) -> Int { qr.modules[y][x] ? 1 : 0 }
            var bits = 0
            for i in 0...5 { bits |= bit(8, i) << i }
            bits |= bit(8, 7) << 6
            bits |= bit(8, 8) << 7
            bits |= bit(7, 8) << 8
            for i in 9..<15 { bits |= bit(14 - i, 8) << i }
            XCTAssertEqual(bits, QRCode.formatInformation(ecc: .medium, mask: mask))
        }
        XCTAssertEqual(seen.count, 8)
    }

    func testBoostRaisesTheLevelOnlyWhenTheVersionAllowsIt() throws {
        let boosted = try QRCode.encode("HELLO", errorCorrection: .low)
        XCTAssertEqual(boosted.errorCorrection, .high)
        let plain = try QRCode.encode("HELLO", errorCorrection: .low, boostErrorCorrection: false)
        XCTAssertEqual(plain.errorCorrection, .low)
        // Same version either way.
        XCTAssertEqual(boosted.version, plain.version)
    }

    func testCapacityBoundariesAndLimits() throws {
        // Version 1-L holds 17 bytes in byte mode, 18 needs version 2.
        XCTAssertEqual(try QRCode.encode(String(repeating: "a", count: 17), errorCorrection: .low, boostErrorCorrection: false).version, 1)
        XCTAssertEqual(try QRCode.encode(String(repeating: "a", count: 18), errorCorrection: .low, boostErrorCorrection: false).version, 2)
        // Version 40-L holds 2953 bytes.
        XCTAssertEqual(try QRCode.encode(String(repeating: "a", count: 2953), errorCorrection: .low, boostErrorCorrection: false).version, 40)
        XCTAssertThrowsError(try QRCode.encode(String(repeating: "a", count: 2954), errorCorrection: .low, boostErrorCorrection: false)) {
            XCTAssertEqual($0 as? QRCode.EncodeError, .tooLong)
        }
        XCTAssertThrowsError(try QRCode.encode("x", mask: 9)) { XCTAssertEqual($0 as? QRCode.EncodeError, .invalidMask) }
    }

    func testStructureOfEverySymbol() throws {
        let qr = try QRCode.encode("https://viadere.io/c/AF2345", errorCorrection: .quartile)
        // Finder patterns: 7x7 rings at three corners; timing patterns alternate on row/column 6; dark module present.
        for (ox, oy) in [(0, 0), (qr.size - 7, 0), (0, qr.size - 7)] {
            for d in 0..<7 {
                XCTAssertTrue(qr.modules[oy][ox + d] && qr.modules[oy + 6][ox + d] && qr.modules[oy + d][ox] && qr.modules[oy + d][ox + 6])
            }
            XCTAssertTrue(qr.modules[oy + 3][ox + 3])
            XCTAssertFalse(qr.modules[oy + 1][ox + 1])
        }
        for i in 8..<(qr.size - 8) { XCTAssertEqual(qr.modules[6][i], i % 2 == 0); XCTAssertEqual(qr.modules[i][6], i % 2 == 0) }
        XCTAssertTrue(qr.modules[qr.size - 8][8])
    }

    func testSVGIsSelfContainedAndEscapesTheTitle() throws {
        let qr = try QRCode.encode("https://viadere.io/c/AF2345")
        let svg = qr.svg(title: "A <b>title</b> & more")
        XCTAssertTrue(svg.hasPrefix("<svg xmlns=\"http://www.w3.org/2000/svg\""))
        XCTAssertTrue(svg.contains("viewBox=\"0 0 \(qr.size + 8) \(qr.size + 8)\""))
        XCTAssertTrue(svg.contains("A &lt;b&gt;title&lt;/b&gt; &amp; more"))
        XCTAssertFalse(svg.contains("<script"))
        XCTAssertFalse(svg.contains("href"))
        XCTAssertFalse(svg.contains("http://") && svg.replacingOccurrences(of: "http://www.w3.org/2000/svg", with: "").contains("http://"))
        // The number of dark modules in the path equals the number of dark modules in the matrix.
        let dark = qr.modules.reduce(0) { $0 + $1.filter { $0 }.count }
        var counted = 0
        for part in svg.components(separatedBy: "M").dropFirst() {
            if let h = part.firstIndex(of: "h"), let v = part.firstIndex(of: "v") { counted += Int(part[part.index(after: h)..<v]) ?? 0 }
        }
        XCTAssertEqual(counted, dark)
    }

    static func sha(_ rows: [String]) -> String { SecureToken.sha256Hex(Data(rows.joined(separator: "\n").utf8)) }
}
