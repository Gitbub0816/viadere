import Foundation
import Testing
@testable import ViadereCore

/// Webhook signature v2 (ADR-0025): the cross-language vectors (`docs/protocol/vectors/webhook-v2.json`, computed independently in Python), what the
/// MAC covers (ST-WH-01), two entries and malformed headers (ST-WH-07), and the dedup horizon constant (ST-WH-06).
@Suite("Webhook signature v2")
struct WebhookSignatureV2Tests {
    struct Vector: Decodable {
        var name: String, secret: String, kid: String, t: Int64, method: String, host: String
        var pathAndQuery: String, eventId: String, tenantId: String, body: String, contentDigest: String, stringToSign: String, v2: String
        enum CodingKeys: String, CodingKey {
            case name, secret, kid, t, method, host, pathAndQuery = "path_and_query", eventId = "event_id", tenantId = "tenant_id", body
            case contentDigest = "content_digest", stringToSign = "string_to_sign", v2
        }
    }
    struct Vectors: Decodable { var cases: [Vector] }

    static func vectors() throws -> [Vector] {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url.appendingPathComponent("docs/protocol/vectors/webhook-v2.json"))).cases
    }

    static func context(_ v: Vector) -> WebhookSignatureV2.Context {
        .init(host: v.host, pathAndQuery: v.pathAndQuery, eventId: v.eventId, tenantId: v.tenantId)
    }

    @Test func vectorsReproduceByteForByte() throws {
        let all = try Self.vectors()
        #expect(all.count >= 3)
        for v in all {
            let body = Data(v.body.utf8)
            #expect(WebhookSignatureV2.stringToSign(Self.context(v), timestamp: v.t, kid: v.kid, body: body) == v.stringToSign, "\(v.name)")
            #expect(WebhookSignatureV2.mac(secret: v.secret, context: Self.context(v), timestamp: v.t, kid: v.kid, body: body).map { v.kid + ":" + $0 } == v.v2, "\(v.name)")
            #expect(WebhookSignatureV2.contentDigest(body) == v.contentDigest, "\(v.name)")
        }
    }

    static var base: Vector { try! vectors()[0] }
    static let now = Date(timeIntervalSince1970: 1_793_620_800)

    static func header(_ v: Vector = base, extra: [String] = [], t: Int64? = nil) -> String {
        (["t=\(t ?? v.t)", "v2=\(v.v2)"] + extra).joined(separator: ",")
    }

    static func verify(_ v: Vector = base, header: String? = nil, body: String? = nil, digest: String? = nil, context: WebhookSignatureV2.Context? = nil,
                       tenant: String? = nil, keys: [String: String]? = nil, at: Date = now) -> WebhookSignatureV2.Error? {
        do {
            try WebhookSignatureV2.verify(header: header ?? Self.header(v), body: Data((body ?? v.body).utf8), contentDigestHeader: digest ?? v.contentDigest, context: context ?? Self.context(v),
                                          expectedTenant: tenant ?? v.tenantId, keys: keys ?? [v.kid: v.secret], now: at)
            return nil
        } catch { return error }
    }

    @Test func aValidDeliveryVerifiesAndThenEachSignedFieldBreaksIt() {
        #expect(Self.verify() == nil)
        let v = Self.base
        // ST-WH-01: method, host, path, timestamp, event id, tenant, key id and body each change the MAC.
        var c = Self.context(v)
        c.method = "PUT"; #expect(Self.verify(context: c) == .noMatchingSignature)
        c = Self.context(v); c.host = "evil.example.com"; #expect(Self.verify(context: c) == .noMatchingSignature)
        c = Self.context(v); c.pathAndQuery = "/other"; #expect(Self.verify(context: c) == .noMatchingSignature)
        c = Self.context(v); c.eventId = "evt_" + String(repeating: "9", count: 32); #expect(Self.verify(context: c) == .noMatchingSignature)
        c = Self.context(v); c.tenantId = "ten_other"; #expect(Self.verify(context: c, tenant: "ten_other") == .noMatchingSignature)
        #expect(Self.verify(header: Self.header(t: v.t + 1)) == .noMatchingSignature)
        #expect(Self.verify(header: "t=\(v.t),v2=whk_1a2b3c4d_v9:" + String(v.v2.split(separator: ":")[1]), keys: ["whk_1a2b3c4d_v9": v.secret]) == .noMatchingSignature)
        let tamperedBody = v.body.replacingOccurrences(of: "opened", with: "failed")
        #expect(Self.verify(body: tamperedBody) == .digestMismatch)
    }

    @Test func tenantDigestAndWindowAreChecked() {
        let v = Self.base
        // Cross-tenant / cross-endpoint replay: the tenant in the delivery is not the receiver's own.
        #expect(Self.verify(tenant: "ten_somebody_else") == .tenantMismatch)
        #expect(Self.verify(digest: "sha-256=:AAAA:") == .digestMismatch)
        #expect(Self.verify(at: Self.now.addingTimeInterval(301)) == .timestampOutsideTolerance)
        #expect(Self.verify(at: Self.now.addingTimeInterval(-301)) == .timestampOutsideTolerance)
        #expect(Self.verify(at: Self.now.addingTimeInterval(300)) == nil)
        // A v2 verifier never accepts a v1 entry alone.
        #expect(Self.verify(header: "t=\(v.t),v1=" + String(repeating: "a", count: 64)) == .malformedHeader)
        // Unknown schemes are ignored next to a valid v2 entry.
        #expect(Self.verify(header: Self.header(extra: ["v9=zzz", "v1=" + String(repeating: "0", count: 64)])) == nil)
    }

    /// ST-WH-07: two entries verify each with its own secret; duplicate kid, two `t=`, LF in any field are malformed.
    @Test func rotationEntriesDuplicateKidsTwoTimestampsAndLineFeeds() throws {
        let all = try Self.vectors()
        let current = all[0], previous = all[1]
        let two = "t=\(current.t),v2=\(current.v2),v2=\(previous.v2)"
        #expect(Self.verify(header: two, keys: [current.kid: current.secret, previous.kid: previous.secret]) == nil)
        // Each entry verifies with its own secret: only the previous secret held, still verifies; neither held, fails.
        #expect(Self.verify(header: two, keys: [previous.kid: previous.secret]) == nil)
        #expect(Self.verify(header: two, keys: [previous.kid: "whsec_wrong"]) == .noMatchingSignature)
        // A MAC cannot be re-bound to another kid (the kid is inside the string to sign).
        let swapped = "t=\(current.t),v2=\(previous.kid):" + String(current.v2.split(separator: ":")[1])
        #expect(Self.verify(header: swapped, keys: [previous.kid: previous.secret]) == .noMatchingSignature)
        // Malformed.
        #expect(Self.verify(header: "t=\(current.t),v2=\(current.v2),v2=\(current.v2)") == .malformedHeader)
        #expect(Self.verify(header: "t=\(current.t),t=\(current.t),v2=\(current.v2)") == .malformedHeader)
        #expect(Self.verify(header: "t=\(current.t),v2=\(current.v2)\n") == .malformedHeader)
        #expect(Self.verify(header: "t=\(current.t),v2=\(current.kid):short") == .malformedHeader)
        for broken in [{ (c: inout WebhookSignatureV2.Context) in c.eventId += "\n" }, { $0.tenantId += "\n" }, { $0.host += "\n" }, { $0.pathAndQuery += "\nX" }, { $0.method = "PO\nST" }] {
            var c = Self.context(current)
            broken(&c)
            #expect(Self.verify(context: c, tenant: c.tenantId.trimmingCharacters(in: .newlines)) == .malformedHeader)
        }
        // The header can be built with two entries and verifies.
        let built = WebhookSignatureV2.header(secrets: [(current.kid, current.secret), (previous.kid, previous.secret)], context: Self.context(current), body: Data(current.body.utf8),
                                              now: Date(timeIntervalSince1970: TimeInterval(current.t)))
        #expect(built?.hasPrefix("t=\(current.t),v2=") == true && built?.contains("v1=") == false)
    }

    @Test func authEventsNeverCarryALegacyEntryAndMigrationAddsOneOnlyOnRequest() throws {
        let v = Self.base
        let migrating = WebhookSignatureV2.header(secrets: [(v.kid, v.secret)], context: Self.context(v), body: Data(v.body.utf8), now: Date(timeIntervalSince1970: TimeInterval(v.t)),
                                                  legacySecret: v.secret)
        #expect(migrating?.contains(",v1=") == true && migrating?.contains(",v2=") == true)
        let authOnly = WebhookSignatureV2.header(secrets: [(v.kid, v.secret)], context: Self.context(v), body: Data(v.body.utf8), now: Date(timeIntervalSince1970: TimeInterval(v.t)))
        #expect(authOnly?.contains("v1=") == false)
        // A legacy v1 verifier still verifies the dual-signed header (the migration promise).
        let legacy = try #require(migrating)
        #expect((try? WebhookSignature.verify(header: legacy, body: Data(v.body.utf8), secrets: [v.secret], now: Self.now)) != nil)
    }

    @Test func endpointContextUsesTheRegisteredUrl() throws {
        let c = try #require(WebhookSignatureV2.Context(endpoint: URL(string: "https://Hooks.Example.com/a/b?x=1&y=%20")!, eventId: "evt_1", tenantId: "ten_1"))
        #expect(c.host == "hooks.example.com" && c.pathAndQuery == "/a/b?x=1&y=%20")
        let port = try #require(WebhookSignatureV2.Context(endpoint: URL(string: "https://hooks.example.com:8443")!, eventId: "evt_1", tenantId: "ten_1"))
        #expect(port.host == "hooks.example.com:8443" && port.pathAndQuery == "/")
        let standard = try #require(WebhookSignatureV2.Context(endpoint: URL(string: "https://hooks.example.com:443/x")!, eventId: "evt_1", tenantId: "ten_1"))
        #expect(standard.host == "hooks.example.com")
    }

    /// ST-WH-06 (contract half): the dedup horizon is derived from the sender's backoff table, and the written-down constant matches it.
    @Test func dedupHorizonFollowsTheBackoffTable() {
        #expect(WebhookRetrySchedule.backoff.count == WebhookRetrySchedule.maxAttempts - 1)
        #expect(WebhookRetrySchedule.maxHorizon == 155_550)
        #expect(WebhookRetrySchedule.dedupHorizon == WebhookRetrySchedule.documentedDedupHorizon)
        #expect(WebhookRetrySchedule.documentedMinimumRetention >= WebhookRetrySchedule.dedupHorizon)
        // An event delivered at the final retry offset (first receipt at t0, last retry at maxHorizon) is still inside the horizon.
        #expect(WebhookRetrySchedule.maxHorizon + WebhookSignature.defaultTolerance <= WebhookRetrySchedule.dedupHorizon)
    }
}
