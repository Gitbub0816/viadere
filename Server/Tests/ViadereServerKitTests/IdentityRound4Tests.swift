import Fluent
import Foundation
import NIOHTTP1
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Identity round 4: pending device replacement, device-signed refresh, and idempotent business operations.
final class IdentityRound4Tests: XCTestCase {
    // MARK: Helpers

    func notices(_ h: TestHarness, _ consumer: TestConsumer) async throws -> [SecurityNotice] {
        try await h.signed(consumer, .GET, "/v1/security-notices").json([SecurityNotice].self)
    }

    func registerPush(_ h: TestHarness, _ consumer: TestConsumer) async throws {
        let response = try await h.signedPost(consumer, "/v1/push/apns-token",
                                              APNsTokenRegistration(token: String(repeating: "ab", count: 32), environment: .sandbox, bundleId: "com.viadere.app"))
        XCTAssertEqual(response.status, .ok, response.text)
    }

    /// The new device after a pending replacement: the session the server minted for it, and its keys.
    func newDeviceConsumer(_ owner: TestConsumer, _ device: Device, _ keys: [DeviceKeyPurpose: SoftwareP256SigningKey]) throws -> TestConsumer {
        var consumer = owner
        consumer.session = try XCTUnwrap(device.replacementSession)
        consumer.device = TestDevice(id: device.id, requestKey: keys[.request]!, passcodeKey: keys[.approvalUserPresence]!, biometricKey: keys[.approvalBiometric]!)
        return consumer
    }

    func confirm(_ h: TestHarness, by confirmer: TestConsumer, device target: DeviceID) async throws -> HTTPResult {
        let proof = try await ConfirmationProof.sign(subject: .device, subjectId: target.description, deviceId: confirmer.device!.id, assurance: .biometric,
                                                     key: confirmer.device!.biometricKey, now: h.clock.now())
        return try await h.signedPost(confirmer, "/v1/devices/\(target)/confirm", ConfirmationRequest(proof: proof))
    }

    // MARK: Set up again can no longer swap out a live device

    func testReplacingALiveDeviceDoesNotRevokeItAndTheOwnerCanCancel() async throws {
        try await withHarness { h in
            let owner = try await h.readyConsumer()
            try await registerPush(h, owner)
            let oldId = owner.device!.id
            // Exploit (before): a thief with the owner's session bound to the old device plus the passkey replaced it, revoking it at once.
            let (response, keys) = try await h.enrollRaw(owner, replaces: oldId)
            XCTAssertEqual(response.status, .created, response.text)
            let replacement = try response.json(Device.self)
            let old = try await XCTUnwrapAsync(try await DeviceRecord.find(oldId.uuid, on: h.db))
            XCTAssertNil(old.revokedAt, "a live device is not revoked by a replacement request")
            XCTAssertEqual(old.pendingReplacementBy, replacement.id.uuid)
            XCTAssertEqual(replacement.approvalsLockedUntil, h.clock.now().addingTimeInterval(24 * 3600), "the new device gets the normal cool-down")
            XCTAssertNotNil(replacement.replacementSession, "the new device gets its own session")

            // The old device keeps working, and sees the pending replacement.
            let listed = try await h.signed(owner, .GET, "/v1/devices")
            XCTAssertEqual(listed.status, .ok, listed.text)
            let devices = try listed.json([Device].self)
            let shown = try XCTUnwrap(devices.first { $0.id == oldId })
            XCTAssertEqual(shown.pendingReplacementBy, replacement.id)
            XCTAssertEqual(shown.pendingReplacementAt, replacement.approvalsLockedUntil)
            XCTAssertNil(shown.revokedAt)
            // ...and is told, with a "Not you? Cancel" action that targets the new device.
            let ownerNotices = try await notices(h, owner)
            let notice = try XCTUnwrap(ownerNotices.first { $0.kind == .devicePendingReplacement })
            XCTAssertEqual(notice.action, .cancelDeviceReplacement)
            XCTAssertEqual(notice.subjectId, replacement.id.description)
            XCTAssertTrue(h.push.sent.contains { $0.body.contains("about to replace") && $0.category == "viadere.security.cancel" }, "a push goes to the old device")

            // The new device works but is not trusted: it can neither cancel its own replacement nor remove the old device.
            let newcomer = try newDeviceConsumer(owner, replacement, keys)
            try await eq(try await h.signed(newcomer, .GET, "/v1/devices").status, .ok)
            let selfCancel = try await h.signed(newcomer, .POST, "/v1/devices/\(replacement.id)/cancel-replacement")
            XCTAssertEqual(selfCancel.status, .forbidden, selfCancel.text)
            let removeOld = try await h.signed(newcomer, .DELETE, "/v1/devices/\(oldId)")
            XCTAssertEqual(removeOld.errorCode, .deviceCoolDown)
            try await isNil(try await DeviceRecord.find(oldId.uuid, on: h.db)?.revokedAt)

            // The owner cancels from the old device: the NEW device and its session go, the old one is untouched.
            let cancel = try await h.signed(owner, .POST, "/v1/devices/\(replacement.id)/cancel-replacement")
            XCTAssertEqual(cancel.status, .ok, cancel.text)
            try await notNil(try await DeviceRecord.find(replacement.id.uuid, on: h.db)?.revokedAt)
            try await eq(try await h.signed(newcomer, .GET, "/v1/devices").status, .unauthorized)
            let afterOld = try await XCTUnwrapAsync(try await DeviceRecord.find(oldId.uuid, on: h.db))
            XCTAssertNil(afterOld.revokedAt)
            XCTAssertNil(afterOld.pendingReplacementBy)
            try await eq(try await h.signed(owner, .GET, "/v1/devices").status, .ok, "the old device and its session still work")
            let events = try await AuditEventRecord.query(on: h.db).all().map(\.action)
            XCTAssertTrue(events.contains("device.replacement_pending") && events.contains("device.replacement_cancelled"))
            // Cancelling again, or something that is not pending, is refused.
            try await eq(try await h.signed(owner, .POST, "/v1/devices/\(replacement.id)/cancel-replacement").status, .notFound)
            try await eq(try await h.signed(owner, .POST, "/v1/devices/\(oldId)/cancel-replacement").status, .forbidden, "not the caller's own device")
        }
    }

    func testTheReplacementCompletesWhenTheNewDeviceIsConfirmed() async throws {
        try await withHarness { h in
            let owner = try await h.readyConsumer()
            let oldId = owner.device!.id
            let (response, keys) = try await h.enrollRaw(owner, replaces: oldId)
            let replacement = try response.json(Device.self)
            XCTAssertEqual(response.status, .created, response.text)
            let confirmed = try await confirm(h, by: owner, device: replacement.id)
            XCTAssertEqual(confirmed.status, .ok, confirmed.text)
            try await notNil(try await DeviceRecord.find(oldId.uuid, on: h.db)?.revokedAt, "confirmation completes the replacement")
            // The old device is told it was replaced; its sessions end; the new device is now trusted and works.
            let stale = try await h.signed(owner, .GET, "/v1/devices")
            XCTAssertEqual(stale.status, .unauthorized)
            let newcomer = try newDeviceConsumer(owner, replacement, keys)
            let ok = try await h.signed(newcomer, .GET, "/v1/devices")
            XCTAssertEqual(ok.status, .ok, ok.text)
            let list = try ok.json([Device].self)
            XCTAssertNil(list.first { $0.id == replacement.id }?.approvalsLockedUntil)
            XCTAssertNil(list.first { $0.id == oldId }?.pendingReplacementBy)
            let replaced = try await AuditEventRecord.query(on: h.db).filter(\.$action == "device.replaced").all()
            XCTAssertEqual(replaced.count, 1)
            XCTAssertTrue(replaced[0].metadataJSON.contains("pending_completed"))
        }
    }

    func testTheReplacementCompletesWhenTheCoolDownEndsByJobOrByTheNextRequest() async throws {
        try await withHarness { h in
            let owner = try await h.readyConsumer()
            let oldId = owner.device!.id
            let (response, keys) = try await h.enrollRaw(owner, replaces: oldId)
            let replacement = try response.json(Device.self)
            XCTAssertEqual(response.status, .created, response.text)
            h.clock.advance(by: 24 * 3600 - 60)
            try await h.runJobs()
            try await isNil(try await DeviceRecord.find(oldId.uuid, on: h.db)?.revokedAt, "still cooling down")
            h.clock.advance(by: 120)
            // The old device's next request completes the swap on its own (its access token is refreshed first, as the app does).
            var refreshedOwner = owner
            refreshedOwner.session = try await h.refresh(owner).json(AuthSession.self)
            let lazy = try await h.signed(refreshedOwner, .GET, "/v1/devices")
            XCTAssertEqual(lazy.status, .unauthorized, lazy.text)
            try await notNil(try await DeviceRecord.find(oldId.uuid, on: h.db)?.revokedAt)
            var newcomer = try newDeviceConsumer(owner, replacement, keys)
            newcomer.session = try await h.refresh(newcomer).json(AuthSession.self)
            try await eq(try await h.signed(newcomer, .GET, "/v1/devices").status, .ok)
        }
        // And the background job does it without any request.
        try await withHarness { h in
            let owner = try await h.readyConsumer()
            let oldId = owner.device!.id
            let (response, _) = try await h.enrollRaw(owner, replaces: oldId)
            XCTAssertEqual(response.status, .created, response.text)
            h.clock.advance(by: 24 * 3600 + 1)
            try await h.runJobs()
            try await notNil(try await DeviceRecord.find(oldId.uuid, on: h.db)?.revokedAt)
            try await isNil(try await DeviceRecord.find(oldId.uuid, on: h.db)?.pendingReplacementBy)
        }
    }

    func testAReplacementWhoseNewDeviceWasRemovedIsAbandonedAndOnlyOneCanBePending() async throws {
        try await withHarness { h in
            let owner = try await h.readyConsumer()
            let oldId = owner.device!.id
            let (first, _) = try await h.enrollRaw(owner, replaces: oldId)
            XCTAssertEqual(first.status, .created, first.text)
            let replacement = try first.json(Device.self)
            // A second replacement of the same device while one is pending is refused.
            let again = try await h.enrollRaw(owner, replaces: oldId)
            XCTAssertEqual(again.0.status, .conflict, again.0.text)
            // The owner removes the new device the ordinary way: nothing is left to complete.
            try await eq(try await h.signed(owner, .DELETE, "/v1/devices/\(replacement.id)").status, .ok)
            h.clock.advance(by: 25 * 3600)
            try await h.runJobs()
            let old = try await XCTUnwrapAsync(try await DeviceRecord.find(oldId.uuid, on: h.db))
            XCTAssertNil(old.revokedAt, "the old device stays")
            XCTAssertNil(old.pendingReplacementBy)
            var refreshed = owner
            refreshed.session = try await h.refresh(owner).json(AuthSession.self)
            try await eq(try await h.signed(refreshed, .GET, "/v1/devices").status, .ok)
        }
    }

    // MARK: Refresh needs the bound device's signature

    func testACopiedRefreshTokenIsUselessWithoutTheBoundDevice() async throws {
        try await withHarness { h in
            let user = try await h.readyConsumer()
            let other = try await h.enrollDevice(user)           // the same account's second phone (its own session)
            let token = try XCTUnwrap(user.session.refreshToken)
            // Exploit (before): the token alone obtained a fresh pair, and inside the grace window even the same pair.
            let bare = try await h.refresh(user, signed: false)
            XCTAssertEqual(bare.status, .unauthorized)
            XCTAssertEqual(bare.errorCode, .signatureInvalid)
            // A signature from another device of the account, or the bound device id with the wrong key, is no better.
            var crossed = user
            crossed.device = other.device
            let wrongDevice = try await h.refresh(crossed, token: token)
            XCTAssertEqual(wrongDevice.errorCode, .signatureInvalid)
            let wrongKey = try await h.refresh(user, token: token, signWith: other.device!.requestKey)
            XCTAssertEqual(wrongKey.errorCode, .signatureInvalid)
            let stale = try await h.refresh(user, token: token, at: h.clock.now().addingTimeInterval(-3600))
            XCTAssertEqual(stale.errorCode, .clockSkew)
            // None of those consumed the token or touched the session.
            let denied = try await AuditEventRecord.query(on: h.db).filter(\.$action == "auth.refresh_unsigned").count()
            XCTAssertGreaterThanOrEqual(denied, 3)
            let nonce = SecureToken.generate(byteCount: 16)
            let good = try await h.refresh(user, nonce: nonce)
            XCTAssertEqual(good.status, .ok, good.text)
            let pair = try good.json(AuthSession.self)
            // The same signed request is a replay.
            let replay = try await h.refresh(user, nonce: nonce)
            XCTAssertEqual(replay.errorCode, .replayDetected)
            // The grace window: the legitimate device gets the same pair again, a thief with the copied token gets nothing.
            h.clock.advance(by: 5)
            let thief = try await h.refresh(user, token: token, signed: false)
            XCTAssertEqual(thief.status, .unauthorized, "the grace replay needs the device signature too")
            let again = try await h.refresh(user, token: token)
            XCTAssertEqual(again.status, .ok, again.text)
            XCTAssertEqual(try again.json(AuthSession.self).refreshToken, pair.refreshToken)
            try await isNil(try await TokenFamilyRecord.query(on: h.db).first()?.revokedAt)
        }
    }

    func testSessionsThatHaveNoDeviceYetStillRefreshUntilTheyBind() async throws {
        try await withHarness { h in
            // A fresh passkey sign-in (no device yet) and a legacy family refresh without a signature.
            var user = try await h.registerConsumer()
            let first = try await h.refresh(user, signed: false)
            XCTAssertEqual(first.status, .ok, first.text)
            user.session = try first.json(AuthSession.self)
            // Once the family binds to a device (its first signed request), unsigned refresh stops working.
            var enrolled = try await h.enrollDevice(user)
            enrolled.session = try await h.login(enrolled).session   // a second session of the same device, unbound
            let beforeBinding = try await h.refresh(enrolled, signed: false)
            XCTAssertEqual(beforeBinding.status, .ok, "an unbound family keeps working")
            enrolled.session = try beforeBinding.json(AuthSession.self)
            try await eq(try await h.signed(enrolled, .GET, "/v1/devices").status, .ok)     // binds the family to the device
            let afterBinding = try await h.refresh(enrolled, signed: false)
            XCTAssertEqual(afterBinding.errorCode, .signatureInvalid)
            try await eq(try await h.refresh(enrolled).status, .ok)
        }
    }

    // MARK: Business idempotency

    func request(_ h: TestHarness, _ b: TestBusiness, _ method: NIOHTTP1.HTTPMethod, _ path: String, body: Data? = nil, key: String?) async throws -> HTTPResult {
        var headers = ["Authorization": "Bearer \(b.key)"]
        if let key { headers["Idempotency-Key"] = key }
        return try await h.request(method, path, headers: headers, body: body)
    }

    func testWebhookCreateIsIdempotent() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let body = try ViadereJSON.encode(CreateWebhookRequest(url: URL(string: "https://hooks.example.com/a")!, events: [.interactionDecided]))
            // Required, like on issue.
            let missing = try await request(h, b, .POST, "/v1/business/webhooks", body: body, key: nil)
            XCTAssertEqual(missing.status, .unprocessableEntity, missing.text)
            let invalid = try await request(h, b, .POST, "/v1/business/webhooks", body: body, key: "bad key!")
            XCTAssertEqual(invalid.status, .unprocessableEntity)
            let first = try await request(h, b, .POST, "/v1/business/webhooks", body: body, key: "create-1")
            XCTAssertEqual(first.status, .created, first.text)
            let created = try first.json(WebhookSecretResponse.self)
            // Exploit (before): a retry after a lost response created a second endpoint with a second secret.
            let retry = try await request(h, b, .POST, "/v1/business/webhooks", body: body, key: "create-1")
            XCTAssertEqual(retry.status, .ok, retry.text)
            let replay = try retry.json(WebhookSecretResponse.self)
            XCTAssertEqual(replay.subscription.id, created.subscription.id)
            XCTAssertEqual(replay.secret, created.secret)
            try await eq(try await WebhookSubscriptionRecord.query(on: h.db).count(), 1)
            // The secret is never stored in the clear next to the key.
            let row = try await XCTUnwrapAsync(try await BusinessIdempotencyRecord.query(on: h.db).first())
            XCTAssertFalse(try XCTUnwrap(row.resultSealed).contains(created.secret))
            // Same key, different request: conflict. A new key: a new endpoint.
            let other = try ViadereJSON.encode(CreateWebhookRequest(url: URL(string: "https://hooks.example.com/b")!, events: [.interactionDecided]))
            let conflict = try await request(h, b, .POST, "/v1/business/webhooks", body: other, key: "create-1")
            XCTAssertEqual(conflict.status, .conflict)
            XCTAssertEqual(conflict.errorCode, .idempotencyConflict)
            let second = try await request(h, b, .POST, "/v1/business/webhooks", body: other, key: "create-2")
            XCTAssertEqual(second.status, .created)
            try await eq(try await WebhookSubscriptionRecord.query(on: h.db).count(), 2)
            // Keys are per business.
            let c = try await h.makeBusiness(name: "Contoso", handle: "contosohq")
            let foreign = try await request(h, c, .POST, "/v1/business/webhooks", body: body, key: "create-1")
            XCTAssertEqual(foreign.status, .created)
            try await eq(try await WebhookSubscriptionRecord.query(on: h.db).count(), 3)
            // The one-time secret is wiped after 24 h: a late replay is gone, not a new secret.
            h.clock.advance(by: 25 * 3600)
            try await h.runJobs()
            let late = try await request(h, b, .POST, "/v1/business/webhooks", body: body, key: "create-1")
            XCTAssertEqual(late.status, .gone, late.text)
            try await eq(try await WebhookSubscriptionRecord.query(on: h.db).count(), 3)
        }
    }

    func testWebhookSecretRotationIsIdempotent() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let created = try await request(h, b, .POST, "/v1/business/webhooks", body: try ViadereJSON.encode(CreateWebhookRequest(
                url: URL(string: "https://hooks.example.com/a")!, events: [.interactionDecided])), key: "c").json(WebhookSecretResponse.self)
            let id = created.subscription.id
            let missing = try await request(h, b, .POST, "/v1/business/webhooks/\(id)/rotate-secret", key: nil)
            XCTAssertEqual(missing.status, .unprocessableEntity)
            let first = try await request(h, b, .POST, "/v1/business/webhooks/\(id)/rotate-secret", key: "rot-1")
            XCTAssertEqual(first.status, .ok, first.text)
            let rotated = try first.json(WebhookSecretResponse.self)
            XCTAssertNotEqual(rotated.secret, created.secret)
            // Exploit (before): a retry rotated again and the first new secret was lost.
            let retry = try await request(h, b, .POST, "/v1/business/webhooks/\(id)/rotate-secret", key: "rot-1")
            XCTAssertEqual(retry.status, .ok)
            XCTAssertEqual(try retry.json(WebhookSecretResponse.self).secret, rotated.secret)
            let record = try await XCTUnwrapAsync(try await WebhookSubscriptionRecord.find(id.uuid, on: h.db))
            XCTAssertEqual(try h.ctx.cipher.openString(record.secretCiphertext, context: "webhook_subscriptions.secret", rowId: id.uuid), rotated.secret)
            XCTAssertEqual(try h.ctx.cipher.openString(try XCTUnwrap(record.previousSecretCiphertext), context: "webhook_subscriptions.secret", rowId: id.uuid), created.secret,
                           "rotated once: the previous secret is still the original")
            // A new key rotates again; the same key on another webhook is a conflict.
            let next = try await request(h, b, .POST, "/v1/business/webhooks/\(id)/rotate-secret", key: "rot-2")
            XCTAssertNotEqual(try next.json(WebhookSecretResponse.self).secret, rotated.secret)
            let second = try await request(h, b, .POST, "/v1/business/webhooks", body: try ViadereJSON.encode(CreateWebhookRequest(
                url: URL(string: "https://hooks.example.com/b")!, events: [.interactionDecided])), key: "c2").json(WebhookSecretResponse.self)
            let conflict = try await request(h, b, .POST, "/v1/business/webhooks/\(second.subscription.id)/rotate-secret", key: "rot-1")
            XCTAssertEqual(conflict.errorCode, .idempotencyConflict)
            // Another business cannot rotate (or learn about) it.
            let c = try await h.makeBusiness(name: "Contoso", handle: "contosohq")
            try await eq(try await request(h, c, .POST, "/v1/business/webhooks/\(id)/rotate-secret", key: "rot-9").status, .notFound)
        }
    }

    func testInteractionCancelIsIdempotent() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            let one = try await h.issue(b, relationship: rel, payload: .authorize(.sample())).json(Interaction.self)
            let two = try await h.issue(b, relationship: rel, payload: .authorize(.sample())).json(Interaction.self)
            let missing = try await request(h, b, .POST, "/v1/business/interactions/\(one.id)/cancel", key: nil)
            XCTAssertEqual(missing.status, .unprocessableEntity, missing.text)
            let first = try await request(h, b, .POST, "/v1/business/interactions/\(one.id)/cancel", key: "cancel-1")
            XCTAssertEqual(first.status, .ok, first.text)
            XCTAssertEqual(try first.json(InteractionOutcome.self).status, .cancelled)
            let retry = try await request(h, b, .POST, "/v1/business/interactions/\(one.id)/cancel", key: "cancel-1")
            XCTAssertEqual(retry.status, .ok)
            XCTAssertEqual(try retry.json(InteractionOutcome.self).status, .cancelled)
            // The same key for another interaction is a conflict (it must not silently cancel nothing, or the wrong thing).
            let conflict = try await request(h, b, .POST, "/v1/business/interactions/\(two.id)/cancel", key: "cancel-1")
            XCTAssertEqual(conflict.errorCode, .idempotencyConflict)
            let stillPending = try await XCTUnwrapAsync(try await InteractionRecord.find(two.id.uuid, on: h.db))
            XCTAssertEqual(stillPending.statusValue, .pending)
            let ok = try await request(h, b, .POST, "/v1/business/interactions/\(two.id)/cancel", key: "cancel-2")
            XCTAssertEqual(ok.status, .ok)
            // One cancelled webhook event per interaction, whatever the retries.
            try await eq(try await BusinessIdempotencyRecord.query(on: h.db).filter(\.$operation == "interaction.cancel").count(), 2)
            // Another business gets a plain 404 and no key is recorded for it.
            let c = try await h.makeBusiness(name: "Contoso", handle: "contosohq")
            try await eq(try await request(h, c, .POST, "/v1/business/interactions/\(one.id)/cancel", key: "x").status, .notFound)
            try await eq(try await BusinessIdempotencyRecord.query(on: h.db).count(), 2)
        }
    }
}
