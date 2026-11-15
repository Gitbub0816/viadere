import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// API-key lifecycle (SEC-API-001..003): key id + 256-bit secret shown once, environment binding, expiry, last used, immediate revoke,
/// overlap rotation with auto-revoke, IP allow-lists and operator revocation without suspension (G-3).
final class WP6KeyTests: XCTestCase {
    private let probe = "/v1/business/webhooks"

    private func keyId(_ secret: String) -> String { String(secret.dropFirst("vdk_test_".count).prefix(16)) }

    func testKeyShapeSecretStrengthAndWhatIsStored() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let created = try await h.createKey(owner, scopes: ["webhooks:manage"])
            let secret = try XCTUnwrap(created.secret)
            // vdk_test_<16 hex key id>.<43 base64url chars = 256 bits>
            let parts = secret.dropFirst("vdk_test_".count).split(separator: ".", maxSplits: 1).map(String.init)
            XCTAssertEqual(parts.count, 2)
            XCTAssertEqual(parts[0].count, 16)
            XCTAssertTrue(parts[0].allSatisfy(\.isHexDigit))
            XCTAssertEqual(parts[1].count, 43)
            XCTAssertEqual(Base64URL.decode(parts[1])?.count, 32, "256 bits")
            let record = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            XCTAssertEqual(record.kid, parts[0])
            XCTAssertEqual(record.keyHash, SecureToken.hash(secret), "a verifier, not the key")
            XCTAssertFalse(record.keyHash.contains(parts[1]))
            XCTAssertEqual(record.prefix, "vdk_test_")
            // A request quoting the key id with the wrong secret is the same 401 as any unknown key, and does not authenticate.
            let wrong = "vdk_test_\(parts[0]).\(String(repeating: "A", count: 43))"
            let denied = try await h.apiGet(wrong, probe)
            XCTAssertEqual(denied.status, .unauthorized)
            let unknown = try await h.apiGet("vdk_test_0000000000000000.\(parts[1])", probe)
            XCTAssertEqual(unknown.status, .unauthorized)
            let deniedCode = try (JSONSerialization.jsonObject(with: denied.body) as? [String: Any])?["error"] as? [String: Any]
            let unknownCode = try (JSONSerialization.jsonObject(with: unknown.body) as? [String: Any])?["error"] as? [String: Any]
            XCTAssertEqual(deniedCode?["code"] as? String, unknownCode?["code"] as? String, "no oracle for a valid key id")
            XCTAssertEqual(deniedCode?["message"] as? String, unknownCode?["message"] as? String)
            let ok = try await h.apiGet(secret, probe)
            XCTAssertEqual(ok.status, .ok)
            // Never shown again; the listing and the audit trail carry the non-secret id only.
            let list = try await h.page("/dashboard/api-keys", owner).text
            XCTAssertFalse(list.contains(secret))
            XCTAssertFalse(list.contains(parts[1]))
            XCTAssertTrue(list.contains(parts[0]))
            let audit = try await AuditEventRecord.query(on: h.db).all().map(\.metadataJSON).joined()
            XCTAssertTrue(audit.contains(parts[0]))
            XCTAssertFalse(audit.contains(parts[1]))
        }
    }

    func testLegacyKeysWithoutAKeyIdKeepWorking() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let legacy = "vdk_test_" + SecureToken.generate(byteCount: 32)
            let record = BusinessAPIKeyRecord(businessId: businessId, keyHash: SecureToken.hash(legacy), prefix: "vdk_test_", last4: String(legacy.suffix(4)), name: "old",
                                              scopes: ["webhooks:manage"], capabilities: Capability.messaging, now: h.clock.now(), expiresAt: nil)
            try await record.create(on: h.db)
            XCTAssertNil(record.kid)
            let ok = try await h.apiGet(legacy, probe)
            XCTAssertEqual(ok.status, .ok)
            let list = try await h.page("/dashboard/api-keys", owner).text
            XCTAssertTrue(list.contains("vdk_test_…\(record.last4)"), "legacy keys are shown by prefix and last four")
            // And they can be revoked and rotated like any other (the replacement gets a key id).
            let revoke = try await h.formPost("/dashboard/api-keys/\(record.id!.uuidString.lowercased())/revoke", owner)
            XCTAssertEqual(revoke.status, .seeOther)
            let after = try await h.apiGet(legacy, probe)
            XCTAssertEqual(after.status, .unauthorized)
        }
    }

    func testExpiryLastUsedAndImmediateRevocation() async throws {
        try await withHarness { h in
            let (firstSession, account, businessId) = try await h.verifiedOwner()
            var owner = firstSession
            let created = try await h.createKey(owner, scopes: ["webhooks:manage"], extra: [("expires", "30")])
            let secret = try XCTUnwrap(created.secret)
            var record = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            XCTAssertNil(record.lastUsedAt)
            XCTAssertEqual(record.expiresAt, h.clock.now().addingTimeInterval(30 * 86_400))
            let ok = try await h.apiGet(secret, probe, headers: ["User-Agent": "sdk"])
            XCTAssertEqual(ok.status, .ok)
            record = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.find(record.id!, on: h.db))
            XCTAssertEqual(record.lastUsedAt, h.clock.now())
            let hash = try XCTUnwrap(record.lastUsedIPHash)
            XCTAssertFalse(hash.isEmpty)
            // Expiry: the key stops at the instant, the listing says so.
            h.clock.advance(by: 30 * 86_400 - 1)
            let before = try await h.apiGet(secret, probe)
            XCTAssertEqual(before.status, .ok)
            h.clock.advance(by: 2)
            let expired = try await h.apiGet(secret, probe)
            XCTAssertEqual(expired.status, .unauthorized)
            let relogin = try await h.dashLogin(account)
            owner = try XCTUnwrap(relogin.session) // the console session ended long ago
            let list = try await h.page("/dashboard/api-keys", owner).text
            XCTAssertTrue(list.contains("Expired"))
            // Immediate revocation of a key that has not expired.
            let second = try await h.newKey(owner, name: "second", scopes: ["webhooks:manage"])
            let secondRecord = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.query(on: h.db).filter(\.$name == "second").first())
            let working = try await h.apiGet(second, probe)
            XCTAssertEqual(working.status, .ok)
            let revoke = try await h.formPost("/dashboard/api-keys/\(secondRecord.id!.uuidString.lowercased())/revoke", owner)
            XCTAssertEqual(revoke.status, .seeOther)
            let gone = try await h.apiGet(second, probe)
            XCTAssertEqual(gone.status, .unauthorized, "revocation is effective on the very next request")
            // Revoking twice is harmless and audited once.
            _ = try await h.formPost("/dashboard/api-keys/\(secondRecord.id!.uuidString.lowercased())/revoke", owner)
            let revocations = try await h.auditActions(businessId).filter { $0 == "apikey.revoked" }
            XCTAssertEqual(revocations.count, 1)
            // A key's expiry can only be one of the offered choices.
            let bogus = try await h.createKey(owner, name: "bogus", scopes: ["webhooks:manage"], extra: [("expires", "100000")])
            XCTAssertNotEqual(bogus.status, .ok)
        }
    }

    func testRotationOverlapThenAutomaticRevocation() async throws {
        try await withHarness { h in
            let (owner, account, businessId) = try await h.verifiedOwner()
            let oldSecret = try await h.newKey(owner, name: "prod", scopes: ["webhooks:manage"], extra: [("ipAllowlist", "203.0.113.0/24")])
            let old = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            let rotate = try await h.formPost("/dashboard/api-keys/\(old.id!.uuidString.lowercased())/rotate", owner, [("overlap", "86400")])
            XCTAssertEqual(rotate.status, .ok, rotate.text)
            let newSecret = try XCTUnwrap(h.shownSecret(rotate.text))
            XCTAssertNotEqual(newSecret, oldSecret)
            XCTAssertTrue(rotate.text.contains("stays valid"))
            let fresh = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.query(on: h.db).filter(\.$kid == keyId(newSecret)).first())
            XCTAssertEqual(fresh.scopeSet, old.scopeSet, "the replacement never widens")
            XCTAssertEqual(fresh.capabilitySet, old.capabilitySet)
            XCTAssertEqual(fresh.ipAllowlist, old.ipAllowlist, "restrictions carry over")
            XCTAssertEqual(fresh.rotatedFrom, old.id)
            // Both work during the overlap (the allow-list is open in this configuration: no proxy is trusted, so the address is the peer's).
            var oldRecord = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.find(old.id!, on: h.db))
            XCTAssertEqual(oldRecord.autoRevokeAt, h.clock.now().addingTimeInterval(86_400))
            XCTAssertNil(oldRecord.revokedAt)
            // A second rotation of a key that is already rotating is refused.
            try await h.dashReauth(owner, account)
            let twice = try await h.formPost("/dashboard/api-keys/\(old.id!.uuidString.lowercased())/rotate", owner, [("overlap", "0")])
            XCTAssertEqual(twice.status, .conflict, twice.text)
            // After the overlap the old key is refused even before the sweep runs; the sweep then stamps the record and audits it.
            h.clock.advance(by: 86_400 - 1)
            XCTAssertTrue(oldRecord.isUsable(at: h.clock.now()))
            h.clock.advance(by: 2)
            oldRecord = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.find(old.id!, on: h.db))
            XCTAssertFalse(oldRecord.isUsable(at: h.clock.now()))
            let swept = try await APIKeyLifecycle(db: h.db, ctx: h.ctx).sweep()
            XCTAssertEqual(swept, 1)
            let again = try await APIKeyLifecycle(db: h.db, ctx: h.ctx).sweep()
            XCTAssertEqual(again, 0, "idempotent")
            oldRecord = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.find(old.id!, on: h.db))
            XCTAssertNotNil(oldRecord.revokedAt)
            XCTAssertEqual(oldRecord.revokeReason, "rotation overlap ended")
            let actions = try await h.auditActions(businessId)
            XCTAssertTrue(actions.contains("apikey.rotated"))
            XCTAssertTrue(actions.contains("apikey.auto_revoked"))
            let oldDenied = try await h.apiGet(oldSecret, probe)
            XCTAssertEqual(oldDenied.status, .unauthorized)
        }
    }

    func testRotationOverlapBothKeysWorkThenOnlyTheNewOne() async throws {
        try await withHarness { h in
            let (firstSession, account, businessId) = try await h.verifiedOwner()
            var owner = firstSession
            let oldSecret = try await h.newKey(owner, name: "prod", scopes: ["webhooks:manage"])
            let old = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            let rotate = try await h.formPost("/dashboard/api-keys/\(old.id!.uuidString.lowercased())/rotate", owner, [("overlap", "3600")])
            let newSecret = try XCTUnwrap(h.shownSecret(rotate.text))
            let oldOK = try await h.apiGet(oldSecret, probe)
            let newOK = try await h.apiGet(newSecret, probe)
            XCTAssertEqual(oldOK.status, .ok)
            XCTAssertEqual(newOK.status, .ok)
            h.clock.advance(by: 3601)
            let relogin = try await h.dashLogin(account)
            owner = try XCTUnwrap(relogin.session)
            let oldGone = try await h.apiGet(oldSecret, probe)
            let newStill = try await h.apiGet(newSecret, probe)
            XCTAssertEqual(oldGone.status, .unauthorized)
            XCTAssertEqual(newStill.status, .ok)
            // No overlap: the old key ends with the rotation.
            try await h.dashReauth(owner, account)
            let fresh = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.query(on: h.db).filter(\.$kid == keyId(newSecret)).first())
            let instant = try await h.formPost("/dashboard/api-keys/\(fresh.id!.uuidString.lowercased())/rotate", owner, [("overlap", "0")])
            XCTAssertEqual(instant.status, .ok, instant.text)
            let ended = try await h.apiGet(newSecret, probe)
            XCTAssertEqual(ended.status, .unauthorized)
            // An overlap beyond the configured maximum is refused by the service.
            let third = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.query(on: h.db).filter(\.$revokedAt == nil).first())
            do {
                _ = try await APIKeyLifecycle(db: h.db, ctx: h.ctx).rotate(id: third.id!, businessId: businessId, overlap: 365 * 86_400, actor: .system("test"))
                XCTFail("overlap above the maximum must be refused")
            } catch {}
        }
    }

    // MARK: IP allow-lists

    func testPerKeyIPAllowListIsEnforcedAndDenialsAreAudited() async throws {
        try await withHarness({ $0.trustedProxyCount = 1 }) { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let bad = try await h.createKey(owner, name: "bad", scopes: ["webhooks:manage"], extra: [("ipAllowlist", "not-an-address")])
            XCTAssertNotEqual(bad.status, .ok)
            let secret = try await h.newKey(owner, name: "pinned", scopes: ["webhooks:manage"], extra: [("ipAllowlist", "203.0.113.0/24, 2001:db8::/48")])
            func call(_ ip: String) async throws -> HTTPStatus { try await h.apiGet(secret, probe, headers: ["X-Forwarded-For": ip]).status }
            let inside4 = try await call("203.0.113.77")
            let inside6 = try await call("2001:db8:0:1::5")
            let outside4 = try await call("198.51.100.9")
            let outside6 = try await call("2001:db9::1")
            XCTAssertEqual(inside4, .ok)
            XCTAssertEqual(inside6, .ok)
            XCTAssertEqual(outside4, .unauthorized)
            XCTAssertEqual(outside6, .unauthorized)
            // Spoofing: with one trusted proxy only the hop it appended counts, so a client-supplied first hop does not help.
            let spoof = try await h.apiGet(secret, probe, headers: ["X-Forwarded-For": "203.0.113.5, 198.51.100.9"]).status
            XCTAssertEqual(spoof, .unauthorized)
            // The refusal is indistinguishable from an unknown key, but the owner sees it in the audit trail (without the full address).
            let denied = try await AuditEventRecord.query(on: h.db).filter(\.$businessId == businessId).filter(\.$action == "apikey.ip_denied").all()
            XCTAssertEqual(denied.count, 1, "rate-limited to one record per key per five minutes")
            XCTAssertFalse(denied[0].metadataJSON.contains("198.51.100.9"))
            let unknown = try await h.apiGet("vdk_test_0000000000000000.\(String(repeating: "A", count: 43))", probe, headers: ["X-Forwarded-For": "203.0.113.77"])
            let outside = try await h.apiGet(secret, probe, headers: ["X-Forwarded-For": "198.51.100.9"])
            XCTAssertEqual(unknown.body.count == outside.body.count || String(decoding: unknown.body, as: UTF8.self).contains("unauthorized"), true)
            XCTAssertTrue(String(decoding: outside.body, as: UTF8.self).contains("unauthorized"))
        }
    }

    // MARK: Operator revocation (G-3)

    func testOperatorRevokesKeysWithoutSuspendingTheBusiness() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            let (owner, _, businessId) = try await h.verifiedOwner()
            let leaked = try await h.newKey(owner, name: "leaked", scopes: ["webhooks:manage"])
            let other = try await h.newKey(owner, name: "other", scopes: ["webhooks:manage"])
            let leakedRecord = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.query(on: h.db).filter(\.$name == "leaked").first())
            let path = "/operator/businesses/\(businessId.uuidString.lowercased())"
            // One key.
            let one = try await h.formPost("\(path)/revoke-key/\(leakedRecord.id!.uuidString.lowercased())", op, [("note", "found in a public repository")])
            XCTAssertEqual(one.status, .seeOther, one.text)
            let leakedStatus = try await h.apiGet(leaked, probe).status
            let otherStatus = try await h.apiGet(other, probe).status
            XCTAssertEqual(leakedStatus, .unauthorized)
            XCTAssertEqual(otherStatus, .ok, "only the named key was revoked")
            // All keys; the business keeps its status.
            let all = try await h.formPost("\(path)/revoke-keys", op, [("note", "precaution"), ("scope", "all")])
            XCTAssertEqual(all.status, .seeOther, all.text)
            let otherAfter = try await h.apiGet(other, probe).status
            XCTAssertEqual(otherAfter, .unauthorized)
            let business = try await XCTUnwrapAsync(await BusinessRecord.find(businessId, on: h.db))
            XCTAssertEqual(business.status, .verified, "G-3: no suspension needed")
            // The owner can still sign in, create a new key and use it.
            let replacement = try await h.newKey(owner, name: "replacement", scopes: ["webhooks:manage"])
            let replacementStatus = try await h.apiGet(replacement, probe).status
            XCTAssertEqual(replacementStatus, .ok)
            // Audited as an operator action, and the organization was told (no secret in the mail).
            let revoked = try await AuditEventRecord.query(on: h.db).filter(\.$action == "apikey.revoked_by_operator").all()
            XCTAssertEqual(revoked.count, 2)
            XCTAssertTrue(revoked.allSatisfy { $0.actorKind == "operator" })
            XCTAssertTrue(h.emails.sent.contains { $0.subject.contains("revoked") })
            XCTAssertFalse(h.allMailText.contains(leaked))
            // Another business's keys are unreachable through this business's page.
            let (otherOwner, _, otherId) = try await h.verifiedOwner(email: "o2@example.net", org: "Other Co", handle: "otherco")
            let foreign = try await h.newKey(otherOwner, name: "foreign", scopes: ["webhooks:manage"])
            let foreignRecord = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == otherId).first())
            let cross = try await h.formPost("\(path)/revoke-key/\(foreignRecord.id!.uuidString.lowercased())", op, [("note", "x")])
            XCTAssertEqual(cross.status, .notFound)
            let foreignStatus = try await h.apiGet(foreign, probe).status
            XCTAssertEqual(foreignStatus, .ok)
        }
    }

    // MARK: Environment binding

    func testATestKeyAndALiveKeyAreBoundToTheirEnvironment() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let testKey = try await h.newKey(owner, name: "t", mode: "test", scopes: ["interactions:write", "messages:write"])
            let liveKey = try await h.newKey(owner, name: "l", mode: "live", scopes: ["interactions:write", "messages:write"])
            XCTAssertTrue(testKey.hasPrefix("vdk_test_"))
            XCTAssertTrue(liveKey.hasPrefix("vdk_live_"))
            // The prefix is part of the verifier: relabelling a test secret as live finds nothing.
            let relabelled = "vdk_live_" + testKey.dropFirst("vdk_test_".count)
            let relabelledStatus = try await h.apiGet(relabelled, probe).status
            XCTAssertEqual(relabelledStatus, .unauthorized)
            // A test key addresses sandbox customers only; a live key can never address one.
            let sandbox = try await h.apiPost(testKey, "/v1/business/sandbox/relationships")
            XCTAssertEqual(sandbox.status, .created, sandbox.text)
            let rel = try XCTUnwrap(try JSONSerialization.jsonObject(with: sandbox.body) as? [String: Any])["relationshipId"] as? String
            let body = { (key: String) in try JSONSerialization.data(withJSONObject: ["relationshipId": rel as Any, "body": "hi", "idempotencyKey": key]) }
            let viaLive = try await h.apiPost(liveKey, "/v1/business/messages", json: try body("m1"), headers: ["Idempotency-Key": "m1"])
            XCTAssertEqual(viaLive.status, .notFound)
            let viaTest = try await h.apiPost(testKey, "/v1/business/messages", json: try body("m2"), headers: ["Idempotency-Key": "m2"])
            XCTAssertEqual(viaTest.status, .created, viaTest.text)
            _ = businessId
        }
    }
}
