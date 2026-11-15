import Crypto
import Foundation
import Testing
@testable import ViadereCore

@Suite("BusinessCode")
struct BusinessCodeTests {
    @Test("IO3456 and 103456 normalize equivalently (spec §19 #2)")
    func ioEquivalence() throws {
        let a = try BusinessCode("IO3456")
        let b = try BusinessCode("103456")
        #expect(a == b)
        #expect(a.canonical == "103456")
        #expect(try BusinessCode("io3456") == b)
        #expect(try BusinessCode("1o3456") == b)
        #expect(try BusinessCode("i03456") == b)
    }

    @Test("L stays distinct from 1 and I")
    func lDistinct() throws {
        let l = try BusinessCode("L03456")
        let one = try BusinessCode("103456")
        #expect(l != one)
        #expect(l.canonical == "L03456")
        #expect(try BusinessCode("l03456") == l)
        #expect(try BusinessCode("I03456") != l)
    }

    @Test("Separators and whitespace are accepted", arguments: ["AF2345", "af2345", "AF-2345", "af 2345", " AF.23-45 ", "a f 2 3 4 5", "AF_2345"])
    func separators(input: String) throws {
        #expect(try BusinessCode(input).canonical == "AF2345")
    }

    @Test func invalidInputs() {
        #expect(throws: BusinessCode.ValidationError.empty) { try BusinessCode("   ") }
        #expect(throws: BusinessCode.ValidationError.invalidLength(5)) { try BusinessCode("AF234") }
        #expect(throws: BusinessCode.ValidationError.invalidLength(7)) { try BusinessCode("AF23456") }
        #expect(throws: BusinessCode.ValidationError.invalidCharacter("*")) { try BusinessCode("AF*345") }
        #expect(throws: BusinessCode.ValidationError.invalidCharacter("А")) { try BusinessCode("АF2345") } // Cyrillic A
        #expect(throws: BusinessCode.ValidationError.invalidCharacter("２")) { try BusinessCode("AF２345") } // full-width 2
        #expect(BusinessCode.isValid("AF2345"))
        #expect(!BusinessCode.isValid("AF@345"))
    }

    @Test func displayRoundTrips() throws {
        let code = try BusinessCode("af2345")
        #expect(code.display == "AF-2345")
        #expect(try BusinessCode(code.display) == code)
    }

    @Test("Generator emits only canonical, unambiguous characters")
    func generator() throws {
        let forbidden: Set<Character> = ["I", "O", "L"]
        for _ in 0..<2000 {
            let code = BusinessCode.generate()
            #expect(code.canonical.count == 6)
            #expect(code.canonical.allSatisfy { !forbidden.contains($0) && BusinessCode.issuanceAlphabet.contains($0) })
            #expect(try BusinessCode(code.canonical) == code)
        }
    }

    @Test("Issuance collision check works on canonical form")
    func collisions() throws {
        var issued: Set<String> = [try BusinessCode("IO3456").canonical]
        #expect(issued.contains(try BusinessCode("103456").canonical))   // collides
        #expect(!issued.contains(try BusinessCode("L03456").canonical))  // distinct
        issued.insert(try BusinessCode("L03456").canonical)
        #expect(issued.count == 2)
    }

    @Test func codable() throws {
        let data = try ViadereJSON.encode(["c": try BusinessCode("io-3456")])
        #expect(String(decoding: data, as: UTF8.self) == #"{"c":"103456"}"#)
        #expect(throws: (any Error).self) { try ViadereJSON.decode([String: BusinessCode].self, from: Data(#"{"c":"bad"}"#.utf8)) }
    }
}

@Suite("BusinessHandle")
struct BusinessHandleTests {
    @Test func parsing() throws {
        #expect(try BusinessHandle("@Amazon").value == "amazon")
        #expect(try BusinessHandle("  starbucks ").display == "@starbucks")
        #expect(try BusinessHandle("@acme_bank2").value == "acme_bank2")
    }

    @Test func structuralRules() {
        #expect(throws: BusinessHandle.ValidationError.empty) { try BusinessHandle("@") }
        #expect(throws: BusinessHandle.ValidationError.tooShort) { try BusinessHandle("ab") }
        #expect(throws: BusinessHandle.ValidationError.tooLong) { try BusinessHandle(String(repeating: "a", count: 31)) }
        #expect(throws: BusinessHandle.ValidationError.mustStartWithLetter) { try BusinessHandle("1shop") }
        #expect(throws: BusinessHandle.ValidationError.invalidUnderscore) { try BusinessHandle("shop_") }
        #expect(throws: BusinessHandle.ValidationError.invalidUnderscore) { try BusinessHandle("sh__op") }
        #expect(throws: BusinessHandle.ValidationError.invalidCharacter("-")) { try BusinessHandle("my-shop") }
        #expect(throws: BusinessHandle.ValidationError.invalidCharacter(".")) { try BusinessHandle("my.shop") }
    }

    @Test("Non-ASCII homoglyphs are rejected", arguments: ["аmazon", "amazοn", "ａmazon", "amazon\u{200B}", "starbucks\u{0301}"])
    func homoglyphs(input: String) {
        #expect(throws: BusinessHandle.ValidationError.nonASCII) { try BusinessHandle(input) }
    }

    @Test("Reserved words cannot be registered", arguments: ["viadere", "admin", "support", "help", "stop", "menu", "back", "start", "myviadere"])
    func reserved(word: String) {
        #expect(throws: BusinessHandle.ValidationError.reserved) { try BusinessHandle.validateForRegistration(word) }
    }

    @Test("Confusables of reserved words are rejected", arguments: ["v1adere", "vlADERE", "adm1n", "supp0rt", "rnenu", "he1p"])
    func confusableReserved(word: String) {
        #expect(throws: (any Error).self) { try BusinessHandle.validateForRegistration(word) }
    }

    @Test func confusableSkeletons() throws {
        let a = try BusinessHandle("amazon")
        #expect(a.isConfusable(with: try BusinessHandle("amaz0n")))
        #expect(a.isConfusable(with: try BusinessHandle("arnazon")))
        #expect(!a.isConfusable(with: try BusinessHandle("amazing")))
        #expect(try BusinessHandle.validateForRegistration("starbucks").value == "starbucks")
    }
}

@Suite("Typed IDs")
struct TypedIDTests {
    @Test func lowercaseWireForm() throws {
        let uuid = try #require(UUID(uuidString: "E621E1F8-C36C-495A-93FC-0C247A3E6E5F"))
        let id = BusinessID(uuid)
        let data = try ViadereJSON.encode([id])
        #expect(String(decoding: data, as: UTF8.self) == #"["e621e1f8-c36c-495a-93fc-0c247a3e6e5f"]"#)
        #expect(try ViadereJSON.decode([BusinessID].self, from: data) == [id])
        #expect(BusinessID("E621E1F8-C36C-495A-93FC-0C247A3E6E5F") == id)
        #expect(BusinessID("nope") == nil)
    }
}

@Suite("ConnectLink")
struct ConnectLinkTests {
    let key = SymmetricKey(data: Data(repeating: 7, count: 32))
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    @Test func plainRoundTrip() throws {
        let link = ConnectLink(code: try BusinessCode("AF2345"))
        #expect(link.urlString == "https://viadere.com/c/AF2345")
        #expect(try ConnectLink.parse(link.urlString) == link)
        #expect(try ConnectLink.parse("https://www.viadere.com/c/af2345/").code.canonical == "AF2345")
        #expect(try ConnectLink.parse("HTTPS://VIADERE.COM/c/io3456").code.canonical == "103456")
    }

    @Test func signedContext() throws {
        let ctx = ConnectContext(campaign: "fall-promo", action: "enroll_rewards", issuedAt: now, expiresAt: now.addingTimeInterval(3600))
        let link = try ConnectLink(code: try BusinessCode("AF2345"), context: ctx, key: key)
        let parsed = try ConnectLink.parse(link.urlString)
        #expect(try parsed.verifiedContext(key: key, now: now) == ctx)
        #expect(throws: ConnectLink.ContextError.expired) { try parsed.verifiedContext(key: key, now: now.addingTimeInterval(3601)) }
        #expect(throws: ConnectLink.ContextError.badSignature) {
            try parsed.verifiedContext(key: SymmetricKey(data: Data(repeating: 8, count: 32)), now: now)
        }
        // Context bound to the code: moving ctx+sig to another code fails.
        let moved = try ConnectLink.parse(link.urlString.replacingOccurrences(of: "/c/AF2345", with: "/c/AF2346"))
        #expect(throws: ConnectLink.ContextError.badSignature) { try moved.verifiedContext(key: key, now: now) }
        #expect(throws: ConnectLink.ContextError.noContext) { try ConnectLink(code: parsed.code).verifiedContext(key: key, now: now) }
    }

    @Test func tamperedContext() throws {
        let ctx = ConnectContext(campaign: "a", issuedAt: now)
        let link = try ConnectLink(code: try BusinessCode("AF2345"), context: ctx, key: key)
        let otherCtx = Base64URL.encode(try ConnectContext(campaign: "b", issuedAt: now).canonicalJSON())
        let tampered = "https://viadere.com/c/AF2345?ctx=\(otherCtx)&sig=\(link.signature ?? "")"
        #expect(throws: ConnectLink.ContextError.badSignature) { try ConnectLink.parse(tampered).verifiedContext(key: key, now: now) }
    }

    @Test("Hostile links are rejected", arguments: [
        "http://viadere.com/c/AF2345",
        "javascript:alert(1)//viadere.com/c/AF2345",
        "https://viadere.com.evil.com/c/AF2345",
        "https://evil.com/c/AF2345",
        "https://evilviadere.com/c/AF2345",
        "https://viadere.com@evil.com/c/AF2345",
        "https://user:pw@viadere.com/c/AF2345",
        "https://viadere.com:8443/c/AF2345",
        "https://viadere.com/c/AF2345#https://evil.com",
        "https://viadere.com/c/AF2345?next=https://evil.com",
        "https://viadere.com/c/AF2345?redirect=//evil.com",
        "https://viadere.com/c/AF2345?ctx=a&ctx=b&sig=c",
        "https://viadere.com/c/AF2345?ctx=abc",
        "https://viadere.com/c/AF2345/extra",
        "https://viadere.com/c/AF%2F2345",
        "https://viadere.com/c/../c/AF2345",
        "https://viadere.com//evil.com/c/AF2345",
        "https://viadere.com\\@evil.com/c/AF2345",
        "https://viadere.com/c/AF 2345",
        "https://viadere.com/x/AF2345",
        "https://viadere.com/c/AF234",
        "https://viadere.com/c/AF*345",
        "https://vіadere.com/c/AF2345",
        "",
    ])
    func hostile(input: String) {
        #expect(throws: (any Error).self) { try ConnectLink.parse(input) }
    }
}
