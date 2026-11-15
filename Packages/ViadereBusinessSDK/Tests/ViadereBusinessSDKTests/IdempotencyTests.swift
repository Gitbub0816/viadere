import Foundation
import Testing
import ViadereCore
@testable import ViadereBusinessSDK

@Suite("Idempotency keys")
struct IdempotencyTests {
    @Test func generatedKeysAreValidUniqueAndHighEntropy() {
        var seen = Set<String>()
        for _ in 0..<500 {
            let key = IdempotencyKey.generate()
            #expect(IdempotencyKey.isValid(key))
            #expect(key.count == 22, "128 bits as base64url")
            #expect(seen.insert(key).inserted)
        }
        let prefixed = IdempotencyKey.generate(prefix: "order refund!")
        #expect(prefixed.hasPrefix("orderrefund-"))
        #expect(IdempotencyKey.isValid(prefixed))
        #expect(IdempotencyKey.isValid(IdempotencyKey.generate(prefix: String(repeating: "p", count: 500))))
        #expect(IdempotencyKey.isValid(IdempotencyKey.generate(prefix: "😀😀")))
    }

    @Test func deterministicKeysAreStableDistinctAndUnambiguous() {
        let a = IdempotencyKey.deterministic(namespace: "refund", ["order-1042", "line-3"])
        #expect(a == IdempotencyKey.deterministic(namespace: "refund", ["order-1042", "line-3"]))
        #expect(a != IdempotencyKey.deterministic(namespace: "refund", ["order-1042", "line-4"]))
        #expect(a != IdempotencyKey.deterministic(namespace: "approve", ["order-1042", "line-3"]))
        #expect(IdempotencyKey.deterministic(namespace: "n", ["ab", "c"]) != IdempotencyKey.deterministic(namespace: "n", ["a", "bc"]))
        #expect(IdempotencyKey.deterministic(namespace: "n", ["a"]) != IdempotencyKey.deterministic(namespace: "n", ["a", ""]))
        #expect(IdempotencyKey.isValid(a))
        #expect(a.hasPrefix("refund-"))
        #expect(a.count <= IdempotencyKey.maxLength)
        // Hostile input cannot produce an invalid key.
        #expect(IdempotencyKey.isValid(IdempotencyKey.deterministic(namespace: "💥 bad ns", ["x\ny", String(repeating: "é", count: 1000)])))
    }

    @Test func validityRulesMatchTheServer() {
        for ok in ["a", "order_1042.confirm:v2", "A-b_c.d:e", String(repeating: "a", count: 128)] { #expect(IdempotencyKey.isValid(ok), "\(ok)") }
        for bad in ["", " ", "a b", "a/b", "é", "a\u{0}b", String(repeating: "a", count: 129)] { #expect(!IdempotencyKey.isValid(bad), "\(bad)") }
        // The same rule ViadereCore validates interactions with.
        let request = Fixtures.confirm(key: "order_1042.confirm:v2")
        let interaction = Fixtures.interaction(from: request)
        #expect(!InteractionValidation.issues(in: interaction, now: Fixtures.now).contains { $0.field == "idempotencyKey" })
    }

    @Test func aRetriedLogicalOperationReusesItsKeyAndBodyExactly() throws {
        let key = IdempotencyKey.deterministic(namespace: "confirm", ["order-1042"])
        let first = try ViadereJSON.encode(Fixtures.confirm(key: key))
        let second = try ViadereJSON.encode(Fixtures.confirm(key: key))
        #expect(first == second, "identical bodies hash identically on the server, so a retry returns the original")
    }
}
