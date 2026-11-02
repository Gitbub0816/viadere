import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// Number-match allocation (ADR-0020 section 2a): collision-free, prefix-free, 3 digits from 30 open requests, exhaustion, and the lockout bound.
@Suite("Match group allocation")
struct MatchGroupTests {
    typealias Open = MatchGroupPolicy.Open
    /// A tag is just the code here (the HMAC is a bijection for a fixed subject).
    static func open(_ code: String) -> Open { Open(tag: code, prefixTag: code.count == 3 ? String(code.prefix(2)) : nil) }
    static func decide(_ code: String, _ open: [Open]) -> MatchGroupDecision { MatchGroupPolicy.evaluate(new: (code, code.count == 3 ? String(code.prefix(2)) : nil), open: open) }

    @Test func tagsAreKeyedPerSubjectAndPrefixTagMatchesTheTwoDigitTag() {
        let key = SymmetricKey(size: .bits256)
        let a = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 1, count: 32)))!
        let b = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 2, count: 32)))!
        let three = AuthMatchTags.tags(key: key, subjectRef: a, code: "123")!
        let two = AuthMatchTags.tags(key: key, subjectRef: a, code: "12")!
        #expect(three.prefixTag == two.tag && two.prefixTag == nil)
        #expect(AuthMatchTags.tags(key: key, subjectRef: b, code: "123")!.tag != three.tag)
        #expect(AuthMatchTags.isValidTag(three.tag) && AuthMatchTags.tags(key: key, subjectRef: a, code: "05") == nil && AuthMatchTags.tags(key: key, subjectRef: a, code: "1234") == nil)
    }

    @Test func codesInOneGroupAreCollisionFreeAndPrefixFree() {
        let open = [Self.open("42"), Self.open("517")]
        #expect(Self.decide("42", open) == .inUse)
        #expect(Self.decide("421", open) == .inUse)         // an open 2-digit code is its prefix
        #expect(Self.decide("517", open) == .inUse)
        #expect(Self.decide("51", open) == .inUse)          // it is the prefix of an open 3-digit code
        #expect(Self.decide("518", open) == .accepted)      // shares a prefix with another 3-digit code: allowed
        #expect(Self.decide("43", open) == .accepted)
        #expect(Self.decide("42", []) == .accepted)
    }

    @Test func threeDigitsAreRequiredFromThirtyOpenRequests() {
        let open29 = (10..<39).map { Self.open(String($0)) }
        #expect(open29.count == 29 && Self.decide("90", open29) == .accepted)
        let open30 = open29 + [Self.open("39")]
        #expect(Self.decide("90", open30) == .digitsRequired)
        #expect(Self.decide("901", open30) == .accepted)
    }

    @Test func exhaustionIsReportedWhenNoFreeCodeCanExist() {
        var open = ["10", "11", "12"].map(Self.open)          // 30 occupied 3-digit slots
        var count = 0
        outer: for a in 13...99 { for c in 0...9 { open.append(Self.open("\(a)\(c)")); count += 1; if count == 870 { break outer } } }
        #expect(open.count == 873)
        #expect(Self.decide("999", open) == .exhausted)
        #expect(Self.decide("99", open) == .digitsRequired)
        #expect(Self.decide("999", Array(open.dropLast())) != .exhausted)
    }

    /// The documented bound: the least number of requests that locks a person out is 639 (29 two-digit codes before 3 digits are forced, then 610 three-digit codes
    /// outside their prefixes). A per-initiator cap is deliberately absent (carrier NAT).
    @Test func lockoutNeedsAtLeastSixHundredThirtyNineAttackerRequests() {
        var open: [Open] = (10..<39).map { Self.open(String($0)) }          // 29 two-digit codes: the most the attacker can use
        var attempts = 29
        outer: for prefix in 39...99 {
            for last in 0...9 {
                if Self.decide("100", open) == .exhausted { break outer }
                open.append(Self.open("\(prefix)\(last)")); attempts += 1
            }
        }
        #expect(Self.decide("100", open) == .exhausted)
        #expect(attempts >= 600 && attempts == 639)
        #expect(Self.decide("100", Array(open.dropLast())) != .exhausted)
        #expect(MatchGroupPolicy.pressureThreshold == 10)
    }

    @Test func tagMembersFollowNumberMatch() {
        let t = Base64URL.encode(Data(repeating: 9, count: 32))
        #expect(AuthMatchTagMembers(matchTag: nil, matchPrefixTag: nil).validate(hasNumberMatch: false, threeDigit: false) == nil)
        #expect(AuthMatchTagMembers(matchTag: t, matchPrefixTag: nil).validate(hasNumberMatch: false, threeDigit: false) != nil)
        #expect(AuthMatchTagMembers(matchTag: t, matchPrefixTag: nil).validate(hasNumberMatch: true, threeDigit: false) == nil)
        #expect(AuthMatchTagMembers(matchTag: t, matchPrefixTag: nil).validate(hasNumberMatch: true, threeDigit: true) != nil)
        #expect(AuthMatchTagMembers(matchTag: t, matchPrefixTag: t).validate(hasNumberMatch: true, threeDigit: true) == nil)
        #expect(AuthMatchTagMembers(matchTag: "short", matchPrefixTag: nil).validate(hasNumberMatch: true, threeDigit: false) != nil)
    }
}
