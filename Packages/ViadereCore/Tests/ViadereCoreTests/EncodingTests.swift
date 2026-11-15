import Foundation
import Testing
@testable import ViadereCore

@Suite("Encoding")
struct EncodingTests {
    @Test func base64url() {
        let data = Data([0xFB, 0xFF, 0xBF, 0x00, 0x01])
        let encoded = Base64URL.encode(data)
        #expect(encoded == "-_-_AAE")
        #expect(Base64URL.decode(encoded) == data)
        #expect(Base64URL.decode("+/+/AAE") == nil)
        #expect(Base64URL.decode("a") == nil)
        #expect(Base64URL.decode("") == Data())
        for n in 0..<40 {
            let bytes = Data((0..<n).map { UInt8(truncatingIfNeeded: $0 &* 37) })
            #expect(Base64URL.decode(Base64URL.encode(bytes)) == bytes)
        }
    }

    @Test func hex() {
        #expect(Hex.encode([0x00, 0xAB, 0xFF]) == "00abff")
        #expect(Hex.decode("00ABff") == Data([0x00, 0xAB, 0xFF]))
        #expect(Hex.decode("abc") == nil)
        #expect(Hex.decode("zz") == nil)
    }

    @Test func iso8601Format() throws {
        let date = Date(timeIntervalSince1970: 1_793_109_789.12)
        #expect(ViadereDate.format(date) == "2026-10-27T14:03:09.120Z")
        #expect(ViadereDate.format(Date(timeIntervalSince1970: 0)) == "1970-01-01T00:00:00.000Z")
        #expect(ViadereDate.format(Date(timeIntervalSince1970: -1)) == "1969-12-31T23:59:59.000Z")
        #expect(ViadereDate.format(Date(timeIntervalSince1970: 951_782_400)) == "2000-02-29T00:00:00.000Z")
    }

    @Test func iso8601Parse() throws {
        let expected = Date(timeIntervalSince1970: 1_793_109_789.12)
        #expect(ViadereDate.parse("2026-10-27T14:03:09.120Z") == expected)
        #expect(ViadereDate.parse("2026-10-27T14:03:09.12Z") == expected)
        #expect(ViadereDate.parse("2026-10-27T14:03:09.120999Z") == expected)
        #expect(ViadereDate.parse("2026-10-27T07:03:09.120-07:00") == expected)
        #expect(ViadereDate.parse("2026-10-27T14:03:09Z") == Date(timeIntervalSince1970: 1_793_109_789))
        for bad in ["2026-10-27", "2026-13-01T00:00:00Z", "2026-10-27T14:03:09", "2026-10-27T14:03:09.Z", "x", "2026-10-27T14:03:09Zjunk"] {
            #expect(ViadereDate.parse(bad) == nil)
        }
        for t in stride(from: -86_400_000.0, to: 4_000_000_000, by: 123_456_789.123) {
            let d = ViadereDate.truncatedToMilliseconds(Date(timeIntervalSince1970: t))
            #expect(ViadereDate.parse(ViadereDate.format(d)) == d)
        }
    }

    @Test func sharedJSONDates() throws {
        struct Box: Codable, Equatable { var at: Date }
        let box = Box(at: Date(timeIntervalSince1970: 1_793_109_789))
        let data = try ViadereJSON.encode(box)
        #expect(String(decoding: data, as: UTF8.self) == #"{"at":"2026-10-27T14:03:09.000Z"}"#)
        #expect(try ViadereJSON.decode(Box.self, from: data) == box)
    }

    @Test func canonicalJSON() throws {
        let value = JSONValue.object([
            "b": .integer(-12), "a": .string("x/\"\\\n\u{01}é"), "c": .array([.bool(true), .null]), "A": .object([:]),
        ])
        let s = String(decoding: try CanonicalJSON.serialize(value), as: UTF8.self)
        #expect(s == #"{"A":{},"a":"x/\"\\\n\u0001é","b":-12,"c":[true,null]}"#)
        #expect(throws: CanonicalJSON.Error.floatingPointNotAllowed) { try CanonicalJSON.serialize(.number(1.5)) }
    }

    @Test func constantTime() {
        #expect(ConstantTime.equals(Data([1, 2, 3]), Data([1, 2, 3])))
        #expect(!ConstantTime.equals(Data([1, 2, 3]), Data([1, 2, 4])))
        #expect(!ConstantTime.equals(Data([1, 2, 3]), Data([1, 2])))
        #expect(ConstantTime.equals("abc", "abc"))
        #expect(!ConstantTime.equals("abc", "abd"))
    }
}
