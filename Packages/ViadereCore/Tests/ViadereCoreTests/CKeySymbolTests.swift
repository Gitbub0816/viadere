import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// The CKey port against the reference core (`docs/protocol/vectors/ckey-profile0-v1.json`, made by clearkeysolutions/ckey
/// v0.1.0-build.127, `CKEY_LAYOUT_STANDARD`): the same version choice, the same codeword bit for bit, and the same SVG for both presets.
@Suite struct CKeySymbolTests {
    struct Vectors: Decodable {
        struct Vector: Decodable {
            let name: String, payload: String, requested_version: Int, level: Int, version: Int
            let codeword: String, plain_svg_sha256: String, concept_svg_sha256: String
        }
        let vectors: [Vector]
    }

    static func load() throws -> [Vectors.Vector] {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url.appendingPathComponent("docs/protocol/vectors/ckey-profile0-v1.json"))).vectors
    }

    static func bytes(_ hex: String) -> [UInt8] {
        var out: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            out.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return out
    }

    static func sha256(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    @Test func everyReferenceVectorEncodesToTheSameCodeword() throws {
        let vectors = try Self.load()
        #expect(vectors.count >= 37)
        #expect(Set(vectors.map(\.version)) == Set(1...31))
        for vector in vectors {
            let level = try #require(CKeySymbol.Level(rawValue: vector.level))
            let symbol = try CKeySymbol.encode(bytes: Self.bytes(vector.payload), level: level, version: vector.requested_version)
            #expect(symbol.version == vector.version, "\(vector.name)")
            #expect(symbol.codeword == Self.bytes(vector.codeword), "\(vector.name)")
        }
    }

    // Coordinates are printed to four decimals from sin and cos. The vectors were made with glibc; another libm may round a last digit
    // differently, which moves a mark by a ten-thousandth of a unit and nothing else. The codeword test above is exact everywhere.
    #if os(Linux)
    @Test func everyReferenceVectorRendersTheSameSVG() throws {
        for vector in try Self.load() {
            let symbol = try CKeySymbol.encode(bytes: Self.bytes(vector.payload), level: CKeySymbol.Level(rawValue: vector.level)!, version: vector.requested_version)
            #expect(Self.sha256(symbol.svg(style: .plain)) == vector.plain_svg_sha256, "\(vector.name) plain")
            #expect(Self.sha256(symbol.svg(style: .concept)) == vector.concept_svg_sha256, "\(vector.name) concept")
        }
    }
    #endif

    @Test func aSignInLinkFitsASmallSymbol() throws {
        let link = OIDCChallengeLink.build(challengeId: "ach_AAECAwQFBgcICQoLDA0ODw", domain: .production)
        let symbol = try CKeySymbol.encode(link)
        #expect(symbol.version <= 4)
        #expect(symbol.payloadLength == link.utf8.count)
    }

    @Test func capacityAndLimits() throws {
        #expect(CKeySymbol.capacity(version: 1, level: .medium) == 27)
        #expect(CKeySymbol.capacity(version: 11, level: .medium) == 228)
        #expect(CKeySymbol.capacity(version: 31, level: .medium) == 4619)
        #expect(CKeySymbol.capacity(version: 0, level: .medium) == 0)
        #expect(CKeySymbol.capacity(version: 32, level: .medium) == 0)
        #expect(throws: CKeySymbol.EncodingError.payloadTooLong) { try CKeySymbol.encode(bytes: [UInt8](repeating: 7, count: 28), version: 1) }
        #expect(throws: CKeySymbol.EncodingError.payloadTooLong) { try CKeySymbol.encode(bytes: [UInt8](repeating: 7, count: 4620)) }
        #expect(throws: CKeySymbol.EncodingError.invalidVersion) { try CKeySymbol.encode("x", version: 32) }
        #expect(throws: CKeySymbol.EncodingError.invalidVersion) { try CKeySymbol.encode("x", version: -1) }
    }

    @Test func theAccessibleNameIsEscapedAndNothingElseIsCallerControlled() throws {
        let symbol = try CKeySymbol.encode("https://viadere.com/v/K7QFM2XA")
        let svg = symbol.svg(label: "Sign in \"<script>&'\u{0}\u{7}")
        #expect(svg.contains("aria-label=\"Sign in &quot;&lt;script&gt;&amp;&#39;\""))
        #expect(!svg.contains("<script"))
        #expect(!svg.contains("href"))
        // The payload never appears as text: it exists only as marks.
        #expect(!svg.contains("K7QFM2XA"))
        #expect(svg.hasPrefix("<svg xmlns=\"http://www.w3.org/2000/svg\"") && svg.hasSuffix("</svg>"))
    }
}
