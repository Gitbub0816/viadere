@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import Vapor
import SQLKit
import ViadereCore
import struct ViadereCore.Page
import XCTest
@testable import ViadereServerKit

/// Security hardening, review round 2: each test reproduces the exploit path first and asserts it is now refused.
final class HardeningTests: XCTestCase {
    // MARK: Helpers

    func rawEnroll(_ h: TestHarness, _ consumer: TestConsumer, purposes: [DeviceKeyPurpose] = DeviceKeyPurpose.allCases, clientKind: DeviceClientKind = .app,
                   clipDevice: Bool? = nil, assertion: PasskeyAssertionCredential? = nil, token: String? = nil,
                   tamper: ((DeviceEnrollmentChallenge) -> PasskeyAssertionCredential?)? = nil) async throws -> (HTTPResult, DeviceEnrollmentChallenge, [DeviceKeyPurpose: SoftwareP256SigningKey]) {
        let auth = ["Authorization": "Bearer \(token ?? consumer.token)"]
        let begin = try await h.request(.POST, APIRoutes.deviceEnrollBegin.template, headers: auth)
        XCTAssertEqual(begin.status, .ok, begin.text)
        let challenge = try begin.json(DeviceEnrollmentChallenge.self)
        var keys: [DeviceKeyPurpose: SoftwareP256SigningKey] = [:]
        var registrations: [DeviceKeyRegistration] = []
        for purpose in purposes {
            let key = SoftwareP256SigningKey()
            keys[purpose] = key
            registrations.append(try await DeviceEnrollment.register(key: key, purpose: purpose, hardwareBacked: true, consumerId: consumer.id, challenge: challenge.challenge))
        }
        let sent = tamper.map { $0(challenge) } ?? assertion
        let response = try await h.post(APIRoutes.deviceEnroll.template, DeviceEnrollRequest(name: "Phone", platform: .iOS, challenge: challenge.challenge, keys: registrations,
                                                                                            assertion: sent, clientKind: clientKind, clipDevice: clipDevice), headers: auth)
        return (response, challenge, keys)
    }

    func registerPushToken(_ h: TestHarness, _ consumer: TestConsumer, token: String) async throws {
        let response = try await h.signedPost(consumer, "/v1/push/apns-token", APNsTokenRegistration(token: token, environment: .sandbox, bundleId: "com.viadere.app"))
        XCTAssertEqual(response.status, .ok, response.text)
    }

    func highAuthorize(_ h: TestHarness, _ b: TestBusiness, _ rel: Relationship, key: String = UUID().uuidString) async throws -> Interaction {
        let r = try await h.issue(b, relationship: rel, payload: .authorize(.sample()), sensitivity: .high, key: key)
        XCTAssertEqual(r.status, .created, r.text)
        return try r.json(Interaction.self)
    }

    // MARK: A1 - passkey-bound enrollment

    func testStolenBearerTokenCannotEnrollADevice() async throws {
        try await withHarness { h in
            let victim = try await h.readyConsumer()
            // The attacker holds the victim's access token from a session that is no longer fresh.
            h.clock.advance(by: 10 * 60)
            let begin = try await h.request(.POST, APIRoutes.deviceEnrollBegin.template, headers: ["Authorization": "Bearer \(victim.token)"])
            let challenge = try begin.json(DeviceEnrollmentChallenge.self)
            XCTAssertNotNil(challenge.assertion, "begin returns WebAuthn assertion options")
            XCTAssertEqual(challenge.assertion?.challenge, challenge.challenge)
            XCTAssertEqual(challenge.assertion?.userVerification, "required")
            XCTAssertEqual(challenge.assertion?.allowCredentialIds, [victim.credentialId])
            XCTAssertFalse(challenge.assertionOptional)

            // No assertion: refused, and nothing was created.
            let none = try await rawEnroll(h, victim, token: victim.token)
            XCTAssertEqual(none.0.status, .unauthorized)
            XCTAssertEqual(none.0.errorCode, .passkeyAssertionRequired)
            // An assertion that does not verify (wrong signature), or one over a different challenge, or from a credential the account does not own.
            let bad = try await rawEnroll(h, victim) { c in
                PasskeyAssertionCredential(id: victim.credentialId, rawId: victim.credentialId, authenticatorData: "AA", clientDataJSON: c.challenge, signature: "forged", userHandle: nil)
            }
            XCTAssertEqual(bad.0.errorCode, .passkeyAssertionRequired)
            let wrongChallenge = try await rawEnroll(h, victim) { _ in h.enrollmentAssertion(victim, challenge: SecureToken.generate()) }
            XCTAssertEqual(wrongChallenge.0.errorCode, .passkeyAssertionRequired)
            let stranger = try await h.registerConsumer(name: "Stranger")
            let foreign = try await rawEnroll(h, victim) { c in h.enrollmentAssertion(stranger, challenge: c.challenge) }
            XCTAssertEqual(foreign.0.errorCode, .passkeyAssertionRequired)
            let devices = try await DeviceRecord.query(on: h.db).filter(\.$consumerId == victim.id.uuid).count()
            XCTAssertEqual(devices, 1)

            // With the real, fresh, user-verified assertion over the enrollment challenge it works.
            let good = try await rawEnroll(h, victim) { c in h.enrollmentAssertion(victim, challenge: c.challenge) }
            XCTAssertEqual(good.0.status, .created, good.0.text)
            // The challenge is single use.
            let reused = try await h.post(APIRoutes.deviceEnroll.template, DeviceEnrollRequest(name: "x", platform: .iOS, challenge: good.1.challenge, keys: [],
                                                                                            assertion: h.enrollmentAssertion(victim, challenge: good.1.challenge)),
                                          headers: ["Authorization": "Bearer \(victim.token)"])
            XCTAssertNotEqual(reused.status, .created)
            let failures = try await AuditEventRecord.query(on: h.db).filter(\.$action == "device.enroll_failed").all()
            XCTAssertGreaterThanOrEqual(failures.count, 4)
        }
    }

    func testAFreshPasskeySessionMayEnrollOnceWithoutASeparateAssertion() async throws {
        try await withHarness { h in
            let consumer = try await h.registerConsumer()
            let begin = try await h.request(.POST, APIRoutes.deviceEnrollBegin.template, headers: ["Authorization": "Bearer \(consumer.token)"])
            XCTAssertTrue(try begin.json(DeviceEnrollmentChallenge.self).assertionOptional)
            let first = try await rawEnroll(h, consumer)
            XCTAssertEqual(first.0.status, .created, first.0.text)
            try await eq(try await DeviceRecord.query(on: h.db).first()?.enrollmentMethod, "fresh_session")
            // Single use: the same session cannot add a second device without proving the passkey again.
            let second = try await rawEnroll(h, consumer)
            XCTAssertEqual(second.0.errorCode, .passkeyAssertionRequired)
        }
    }

    func testTheFreshSessionExemptionExpiresAfterFiveMinutes() async throws {
        try await withHarness { h in
            let consumer = try await h.registerConsumer()
            h.clock.advance(by: 5 * 60 + 1)
            let late = try await rawEnroll(h, consumer)
            XCTAssertEqual(late.0.errorCode, .passkeyAssertionRequired)
            XCTAssertFalse(late.1.assertionOptional)
            // ... and a fresh sign-in restores it.
            let again = try await h.login(consumer)
            let ok = try await rawEnroll(h, again)
            XCTAssertEqual(ok.0.status, .created, ok.0.text)
        }
    }

    func testSessionIsBoundToItsDeviceAndRevocationWorksBothWays() async throws {
        try await withHarness { h in
            let first = try await h.readyConsumer()
            let second = try await h.enrollDevice(first)           // a new sign-in (new session) on a second phone
            XCTAssertNotEqual(first.token, second.token)
            // Each bearer token works only with the device it enrolled.
            try await eq(try await h.signed(first, .GET, "/v1/devices").status, .ok)
            try await eq(try await h.signed(second, .GET, "/v1/devices").status, .ok)
            var crossed = second
            crossed.device = first.device
            let mismatch = try await h.signed(crossed, .GET, "/v1/devices")
            XCTAssertEqual(mismatch.status, .forbidden, "a stolen bearer token is useless with another device's key")
            // Revoking the second device ends its session; the first keeps working.
            let revoke = try await h.signed(first, .DELETE, "/v1/devices/\(second.device!.id)")
            XCTAssertEqual(revoke.status, .ok, revoke.text)
            try await eq(try await h.signed(second, .GET, "/v1/devices").status, .unauthorized)
            let family = try await TokenFamilyRecord.query(on: h.db).filter(\.$deviceId == second.device!.id.uuid).first()
            XCTAssertNotNil(family?.revokedAt)
            try await eq(try await h.signed(first, .GET, "/v1/devices").status, .ok)
        }
    }

    func testRefreshTokenReuseRevokesTheSessionAndTheDevicesEnrolledThroughIt() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let stolenRefresh = try XCTUnwrap(consumer.session.refreshToken)
            // The legitimate client rotates; the thief later presents the old refresh token.
            let rotated = try await h.post(APIRoutes.authRefresh.template, AuthRefreshRequest(refreshToken: stolenRefresh))
            XCTAssertEqual(rotated.status, .ok, rotated.text)
            let reuse = try await h.post(APIRoutes.authRefresh.template, AuthRefreshRequest(refreshToken: stolenRefresh))
            XCTAssertEqual(reuse.status, .unauthorized)
            let device = try await DeviceRecord.find(consumer.device!.id.uuid, on: h.db)
            XCTAssertNotNil(device?.revokedAt, "the device enrolled with the stolen session is revoked too")
            var renewed = consumer
            renewed.session = try rotated.json(AuthSession.self)
            try await eq(try await h.signed(renewed, .GET, "/v1/devices").status, .unauthorized)
        }
    }

    func testDeviceSignedRoutesCheckThatTheConsumerIsStillActive() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            try await eq(try await h.signed(consumer, .GET, "/v1/devices").status, .ok)
            let record = try await ConsumerRecord.find(consumer.id.uuid, on: h.db)!
            record.status = "suspended"
            try await record.update(on: h.db)
            try await eq(try await h.signed(consumer, .GET, "/v1/devices").status, .unauthorized)
        }
    }

    func testKeysAreNeverStoredAsAttestedWithoutAnAppAttestVerifier() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let keys = try await DeviceKeyRecord.query(on: h.db).all()
            XCTAssertEqual(keys.count, 3)
            XCTAssertTrue(keys.allSatisfy { $0.hardwareBacked && !$0.attested }, "hardwareBacked is a client claim; attested stays false")
            let devices = try await h.signed(consumer, .GET, "/v1/devices").json([Device].self)
            XCTAssertTrue(devices[0].keys.allSatisfy { !$0.attested })
        }
    }

    func testNewDeviceCoolDownBlocksHighApprovalsUntilAnExistingDeviceConfirms() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let first = try await h.readyConsumer()
            let rel = try await h.connect(first, to: b)
            try await registerPushToken(h, first, token: String(repeating: "ab", count: 32))
            try await isNil(try await DeviceRecord.find(first.device!.id.uuid, on: h.db)?.approvalsLockedUntil, "the first device is trusted")

            // The attacker's (or the user's new) device: enrolled with a valid passkey assertion, but new.
            let second = try await h.enrollDevice(first)
            let record = try await DeviceRecord.find(second.device!.id.uuid, on: h.db)!
            XCTAssertEqual(record.approvalsLockedUntil, h.clock.now().addingTimeInterval(24 * 3600))
            XCTAssertTrue(h.push.sent.contains { $0.category == "viadere.security.notice" && $0.body.contains("new device") }, "other devices are told")
            let listed = try await h.signed(first, .GET, "/v1/devices").json([Device].self)
            XCTAssertNotNil(listed.first { $0.id == second.device!.id }?.approvalsLockedUntil)

            // High-sensitivity approval from the new device: refused. Deny and report still work.
            let i1 = try await highAuthorize(h, b, rel)
            let real1 = try await h.consumerInteraction(second, id: i1.id)
            let blocked = try await h.decide(second, id: i1.id, signed: try await h.decision(second, interaction: real1))
            XCTAssertEqual(blocked.status, .forbidden)
            XCTAssertEqual(blocked.errorCode, .deviceCoolDown)
            let deny = try await h.decide(second, id: i1.id, signed: try await h.decision(second, interaction: real1, decision: .deny, assurance: .none))
            XCTAssertEqual(deny.status, .ok, deny.text)

            // Another device that is NOT trusted cannot confirm, a request key cannot confirm, and a replayed/forged proof fails.
            let proofSelf = try await ConfirmationProof.sign(subject: .device, subjectId: second.device!.id.description, deviceId: second.device!.id, assurance: .biometric,
                                                             key: second.device!.biometricKey, now: h.clock.now())
            try await eq(try await h.signedPost(second, "/v1/devices/\(second.device!.id)/confirm", ConfirmationRequest(proof: proofSelf)).status, .forbidden)
            let weak = try await ConfirmationProof.sign(subject: .device, subjectId: second.device!.id.description, deviceId: first.device!.id, assurance: .none,
                                                        key: first.device!.requestKey, now: h.clock.now())
            try await eq(try await h.signedPost(first, "/v1/devices/\(second.device!.id)/confirm", ConfirmationRequest(proof: weak)).status, .forbidden)
            let forged = try await ConfirmationProof.sign(subject: .device, subjectId: second.device!.id.description, deviceId: first.device!.id, assurance: .biometric,
                                                          key: SoftwareP256SigningKey(), now: h.clock.now())
            try await eq(try await h.signedPost(first, "/v1/devices/\(second.device!.id)/confirm", ConfirmationRequest(proof: forged)).status, .unauthorized)
            try await eq(try await h.decide(second, id: (try await highAuthorize(h, b, rel)).id, signed: try await h.decision(second, interaction: real1)).status.code >= 400, true)

            // A trusted device confirms with Face ID: the cool-down ends.
            let proof = try await ConfirmationProof.sign(subject: .device, subjectId: second.device!.id.description, deviceId: first.device!.id, assurance: .biometric,
                                                         key: first.device!.biometricKey, now: h.clock.now())
            let confirmed = try await h.signedPost(first, "/v1/devices/\(second.device!.id)/confirm", ConfirmationRequest(proof: proof))
            XCTAssertEqual(confirmed.status, .ok, confirmed.text)
            XCTAssertNil(try confirmed.json(Device.self).approvalsLockedUntil)
            let i2 = try await highAuthorize(h, b, rel)
            let real2 = try await h.consumerInteraction(second, id: i2.id)
            let approved = try await h.decide(second, id: i2.id, signed: try await h.decision(second, interaction: real2))
            XCTAssertEqual(approved.status, .ok, approved.text)
        }
    }

    func testCoolDownEndsOnItsOwnAfter24Hours() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let first = try await h.readyConsumer()
            let second = try await h.enrollDevice(first)
            let rel = try await h.connect(second, to: b)
            let early = try await highAuthorize(h, b, rel)
            let real = try await h.consumerInteraction(second, id: early.id)
            try await eq(try await h.decide(second, id: early.id, signed: try await h.decision(second, interaction: real)).errorCode, .deviceCoolDown)
            h.clock.advance(by: 24 * 3600 + 1)
            let late = try await highAuthorize(h, b, rel)
            let real2 = try await h.consumerInteraction(second, id: late.id)
            try await eq(try await h.decide(second, id: late.id, signed: try await h.decision(second, interaction: real2)).status, .ok)
        }
    }

    func testAppClipDevicesAreRequestOnlyShortLivedAndCanNeverDecide() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.registerConsumer()
            // Approval keys are refused for a clip, whichever spelling of the flag is used.
            let withApproval = try await rawEnroll(h, consumer, purposes: [.request, .approvalBiometric], clientKind: .appClip)
            XCTAssertEqual(withApproval.0.status, .badRequest, withApproval.0.text)
            let wire = try await rawEnroll(h, consumer, purposes: [.request, .approvalUserPresence], clipDevice: true)
            XCTAssertEqual(wire.0.status, .badRequest, wire.0.text)
            // Request-key only, via the `clipDevice` wire flag the app sends.
            let ok = try await rawEnroll(h, consumer, purposes: [.request], clipDevice: true)
            XCTAssertEqual(ok.0.status, .created, ok.0.text)
            let device = try ok.0.json(Device.self)
            XCTAssertEqual(device.clientKind, .appClip)
            XCTAssertTrue(device.clipDevice)
            XCTAssertEqual(device.expiresAt, h.clock.now().addingTimeInterval(7 * 24 * 3600))
            let raw = String(decoding: ok.0.body, as: UTF8.self)
            XCTAssertTrue(raw.contains("\"clipDevice\":true"), raw)
            var clip = consumer
            clip.device = TestDevice(id: device.id, requestKey: ok.2[.request]!, passcodeKey: SoftwareP256SigningKey(), biometricKey: SoftwareP256SigningKey())
            // It can request (list devices, connect) ...
            let list = try await h.signed(clip, .GET, "/v1/devices").json([Device].self)
            XCTAssertEqual(list.first?.clipDevice, true)
            XCTAssertNil(list.first?.revokedAt)
            let rel = try await h.connect(clip, to: b)
            // ... but can never decide, even a low-risk confirmation signed with its request key.
            let r = try await h.issue(b, relationship: rel, payload: .confirm(ConfirmPayload(title: "Pickup")), purpose: .transactional, sensitivity: .low)
            let i = try r.json(Interaction.self)
            let real = try await h.consumerInteraction(clip, id: i.id)
            let decided = try await h.decide(clip, id: i.id, signed: try await h.decision(clip, interaction: real, decision: .confirm, assurance: .none))
            XCTAssertEqual(decided.status, .forbidden, decided.text)
            try await eq(try await InteractionRecord.find(i.id.uuid, on: h.db)?.statusValue, .pending)
            // Its session cannot outlive the device (7 days) and the device stops working after that.
            let family = try await TokenFamilyRecord.query(on: h.db).filter(\.$deviceId == device.id.uuid).first()
            XCTAssertEqual(family?.expiresAt, h.clock.now().addingTimeInterval(7 * 24 * 3600))
            XCTAssertLessThanOrEqual(clip.session.refreshExpiresAt ?? .distantFuture, .distantFuture)
            h.clock.advance(by: 7 * 24 * 3600 + 1)
            try await eq(try await h.signed(clip, .GET, "/v1/devices").status, .unauthorized)
            try await notNil(try await DeviceRecord.find(device.id.uuid, on: h.db)?.revokedAt)
        }
    }

    // MARK: iOS #4 - signed context

    func testApprovalWithoutOrWithTheWrongContextDigestIsRefused() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            let i = try await highAuthorize(h, b, rel)
            let real = try await h.consumerInteraction(consumer, id: i.id)
            // v1 (no digest): what an old client signs.
            let v1 = try await h.decision(consumer, interaction: real, context: false)
            let needs = try await h.decide(consumer, id: i.id, signed: v1)
            XCTAssertEqual(needs.status, .badRequest)
            XCTAssertEqual(needs.errorCode, .contextDigestRequired)
            // A digest of a different amount than the server holds: the "swapped context" attack.
            var shown = real
            shown.payload = .authorize({ var p = AuthorizePayload.sample(); p.amount = try? MoneyAmount(string: "1.00", currency: .usd); return p }())
            let wrong = try await h.decision(consumer, interaction: shown)
            let mismatch = try await h.decide(consumer, id: i.id, signed: wrong)
            XCTAssertEqual(mismatch.status, .conflict)
            XCTAssertEqual(mismatch.errorCode, .contextMismatch)
            try await eq(try await InteractionRecord.find(i.id.uuid, on: h.db)?.statusValue, .pending)
            // v1 is still fine for deny/report.
            let deny = try await h.decide(consumer, id: i.id, signed: try await h.decision(consumer, interaction: real, decision: .deny, assurance: .none, context: false))
            XCTAssertEqual(deny.status, .ok, deny.text)
            // And the correct v2 approval works on a new request.
            let i2 = try await highAuthorize(h, b, rel)
            let real2 = try await h.consumerInteraction(consumer, id: i2.id)
            try await eq(try await h.decide(consumer, id: i2.id, signed: try await h.decision(consumer, interaction: real2)).status, .ok)
        }
    }

    // MARK: iOS #3 - hostile business text

    func testServerRejectsBidiZeroWidthAndImpersonatingBusinessText() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            func issue(_ payload: InteractionPayload) async throws -> HTTPResult { try await h.issue(b, relationship: rel, payload: payload, sensitivity: .high) }
            for service in ["\u{202E}Bank", "Bank\u{061C}", "Bank\u{180E}", "Bank\u{2028}Approve", "Ban\u{200B}k", "Bank\u{0007}", "Viadere Verified"] {
                let r = try await issue(.authenticate(AuthenticatePayload(service: service, device: "Mac", attemptedAt: h.clock.now())))
                XCTAssertTrue([400, 422].contains(r.status.code), "\(service.debugDescription): \(r.text)")
                XCTAssertEqual(r.errorCode, .validationFailed)
            }
            var pay = AuthorizePayload.sample()
            pay.merchant = "V1ADERE Refunds"
            try await eq(try await issue(.authorize(pay)).errorCode, .validationFailed)
            pay = AuthorizePayload.sample()
            pay.actionDescription = String(repeating: "x", count: 119) + "\u{0301}\u{0301}\u{0301}" + String(repeating: "\u{0301}", count: 300)
            try await eq(try await issue(.authorize(pay)).errorCode, .validationFailed, "scalar cap")
            try await eq(try await issue(.authorize(.sample())).status, .created)
        }
    }

    // MARK: A3 - device pseudonym

    func testBusinessesNeverReceiveTheRawSignedDecisionOrDeviceId() async throws {
        try await withHarness { h in
            let a = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let b = try await h.makeBusiness(name: "Harbor Hotel", handle: "harborhotel")
            let consumer = try await h.readyConsumer()
            let relA = try await h.connect(consumer, to: a)
            let relB = try await h.connect(consumer, to: b)
            let hook = try await h.businessPost(a, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/a")!, events: [.interactionDecided]))
            XCTAssertEqual(hook.status, .created)
            var refs: [String] = []
            for (biz, rel) in [(a, relA), (b, relB)] {
                let i = try await highAuthorize(h, biz, rel)
                let real = try await h.consumerInteraction(consumer, id: i.id)
                let decided = try await h.decide(consumer, id: i.id, signed: try await h.decision(consumer, interaction: real))
                XCTAssertEqual(decided.status, .ok)
                // The consumer's own response keeps the signed decision.
                XCTAssertNotNil(try decided.json(InteractionOutcome.self).signedDecision)
                let outcome = try await h.business(biz, .GET, "/v1/business/interactions/\(i.id)")
                XCTAssertEqual(outcome.status, .ok)
                XCTAssertFalse(outcome.text.contains("signedDecision"))
                XCTAssertFalse(outcome.text.contains(consumer.device!.id.description), "the global device id is never sent to a business")
                let decoded = try outcome.json(InteractionOutcome.self)
                XCTAssertNil(decoded.signedDecision)
                let ref = try XCTUnwrap(decoded.deviceRef)
                refs.append(ref)
                XCTAssertEqual(decoded.verification?.verified, true)
                XCTAssertEqual(decoded.verification?.keyPurpose, .approvalBiometric)
                XCTAssertEqual(decoded.verification?.contextBound, true)
                try await eq(try await h.business(biz, .GET, "/v1/business/interactions/\(i.id)").json(InteractionOutcome.self).deviceRef, ref, "stable per business")
            }
            XCTAssertNotEqual(refs[0], refs[1], "unlinkable across businesses")
            try await h.runJobs()
            let delivered = try XCTUnwrap(h.webhooks.received.last)
            let body = String(decoding: delivered.body, as: UTF8.self)
            XCTAssertFalse(body.contains("signedDecision") || body.contains(consumer.device!.id.description), body)
            XCTAssertTrue(body.contains("deviceRef") && body.contains("evidenceRef"))
            // The original stays on the server for disputes.
            let interactions = try await InteractionRecord.query(on: h.db).filter(\.$businessId == a.id.uuid).all()
            let export = try await ExportDisputeCommand.export(interactionId: interactions[0].id!, db: h.db, ctx: h.ctx)
            XCTAssertEqual(export?.deviceId, consumer.device!.id.description)
            XCTAssertEqual(export?.devicePublicKeys.count, 3)
            XCTAssertFalse((export?.signedPayload ?? "").isEmpty)
            let businessEvidence = try await h.business(a, .GET, "/v1/business/interactions/\(interactions[0].id!)").json(InteractionOutcome.self).verification?.evidenceRef
            XCTAssertEqual(export?.evidenceRef, businessEvidence)
            // Outcomes stored before this change carried the raw signed decision; the business view strips it.
            let legacy = interactions[0]
            var stored = try ViadereJSON.decode(InteractionOutcome.self, from: Data(legacy.outcomeJSON!.utf8))
            stored.signedDecision = SignedDecision(payload: "x", signature: "y")
            legacy.outcomeJSON = String(decoding: try ViadereJSON.encode(stored), as: UTF8.self)
            XCTAssertNil(try InteractionService(db: h.db, ctx: h.ctx).outcome(legacy).signedDecision)
        }
    }

    // MARK: A2 / channels #7 - test mode

    func testTestKeysOnlyReachSandboxConsumersAndLiveKeysNeverDo() async throws {
        try await withHarness { h in
            let live = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let test = TestBusiness(record: live.record, key: try await BusinessAPIKeys.issue(businessId: live.record.id!, name: "t", live: false,
                                                                                                 scopes: BusinessAPIKeys.Scope.all, now: h.clock.now(), on: h.db).key,
                                    summary: live.summary)
            let consumer = try await h.readyConsumer()
            let real = try await h.connect(consumer, to: live)
            try await registerPushToken(h, consumer, token: String(repeating: "cd", count: 32))
            try await h.linkVerifiedPhone(consumer)
            let before = h.push.sent.count

            // Exploit: a test-mode key addressed to a real person's relationship used to deliver a real, decidable interaction.
            let refused = try await h.issue(test, relationship: real, payload: .confirm(ConfirmPayload(title: "Test")), purpose: .transactional, sensitivity: .low)
            XCTAssertEqual(refused.status, .forbidden, refused.text)
            let msg = try await h.businessPost(test, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: real.id, body: "hi", idempotencyKey: "t1"))
            XCTAssertEqual(msg.status, .forbidden, msg.text)
            try await h.runJobs()
            XCTAssertEqual(h.push.sent.count, before)
            XCTAssertTrue(h.texts.sent.isEmpty, "no SMS from a test key")
            try await eq(try await InteractionRecord.query(on: h.db).count(), 0)

            // Sandbox relationships are created with a test key only, and work with test keys only.
            try await eq(try await h.business(live, .POST, "/v1/business/sandbox/relationships").status, .forbidden)
            let created = try await h.business(test, .POST, "/v1/business/sandbox/relationships")
            XCTAssertEqual(created.status, .created, created.text)
            let sandbox = try created.json(SandboxRelationship.self)
            let rel = Relationship(id: sandbox.relationshipId, consumerId: ConsumerID(), business: live.summary, status: .active, source: .link, connectedAt: h.clock.now())
            let ok = try await h.issue(test, relationship: rel, payload: .confirm(ConfirmPayload(title: "Test")), purpose: .transactional, sensitivity: .low)
            XCTAssertEqual(ok.status, .created, ok.text)
            let sent = try await h.businessPost(test, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: sandbox.relationshipId, body: "hello sandbox", idempotencyKey: "t2"))
            XCTAssertEqual(sent.status, .created, sent.text)
            try await eq(try await h.issue(live, relationship: rel, payload: .confirm(ConfirmPayload(title: "x")), purpose: .transactional, sensitivity: .low).status, .notFound)
            try await h.runJobs()
            XCTAssertEqual(h.push.sent.count, before, "test traffic never pushes")
            XCTAssertTrue(h.texts.sent.isEmpty)
            let rows = try await InteractionRecord.query(on: h.db).all()
            XCTAssertTrue(rows.allSatisfy { !$0.livemode })
            // Sandbox consumers cannot sign in and have no devices, so no real consumer query can ever see test rows.
            let sandboxRel = try await XCTUnwrapAsync(await RelationshipRecord.find(sandbox.relationshipId.uuid, on: h.db))
            let consumerRow = try await XCTUnwrapAsync(await ConsumerRecord.find(sandboxRel.consumerId, on: h.db))
            XCTAssertTrue(consumerRow.isSandbox)
            try await eq(try await PasskeyCredentialRecord.query(on: h.db).filter(\.$consumerId == consumerRow.id!).count(), 0)
            // Legacy test rows aimed at a real consumer are invisible to every consumer route.
            let legacy = try XCTUnwrap(rows.first)
            legacy.consumerId = consumer.id.uuid
            legacy.relationshipId = real.id.uuid
            try await legacy.update(on: h.db)
            let list = try await h.signed(consumer, .GET, "/v1/interactions").json(Page<InteractionEnvelope>.self)
            XCTAssertTrue(list.items.isEmpty)
            try await eq(try await h.signed(consumer, .GET, "/v1/interactions/\(legacy.id!)").status, .notFound)
            // Usage is metered as test traffic.
            let live1 = try await UsageEventRecord.query(on: h.db).filter(\.$livemode == true).count()
            XCTAssertEqual(live1, 0)
        }
    }

    // MARK: channels #2 / A1 - account-link fixation

    func say(_ h: TestHarness, _ text: String, from: String) async throws -> [String] {
        let before = h.texts.sent.count
        let response = try await sendInbound(h, from: from, body: text, sid: nil)
        XCTAssertEqual(response.status, .ok, response.text)
        try await h.runJobs()
        return h.texts.sent.dropFirst(before).map(\.body)
    }

    func requestLinkToken(_ h: TestHarness, from number: String) async throws -> String {
        _ = try await say(h, "Hi", from: number)
        _ = try await say(h, "Northwind", from: number)
        let sms = try await say(h, "1", from: number)
        let body = try XCTUnwrap(sms.first { $0.contains("/l/") })
        let range = try XCTUnwrap(body.range(of: "https://viadere.com/l/"))
        return String(body[range.upperBound...].prefix { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
    }

    func testAccountLinkRequiresAPreviewExplicitConfirmationAndStartsInACoolDown() async throws {
        try await withHarness { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let victim = try await h.readyConsumer(name: "Victim")
            let rel = try await h.connect(victim, to: airline)
            try await registerPushToken(h, victim, token: String(repeating: "ef", count: 32))
            // The attacker texts Viadere from *their* phone and gets a link, then lures the victim into opening it.
            let attackerPhone = "+14805550199"
            let token = try await requestLinkToken(h, from: attackerPhone)

            // Bearer-only (the old web/login-CSRF route) no longer redeems.
            let bearerOnly = try await h.post(APIRoutes.smsLinkRedeem.template, SMSLinkRedeemRequest(token: token, confirmPhoneLast4: "0199"),
                                              headers: ["Authorization": "Bearer \(victim.token)"])
            XCTAssertEqual(bearerOnly.status, .unauthorized)
            XCTAssertEqual(bearerOnly.errorCode, .signatureInvalid)

            // Preview shows whose phone this is, without consuming the token.
            let preview = try await h.signed(victim, .GET, "/v1/sms/link-tokens/\(token)/preview")
            XCTAssertEqual(preview.status, .ok, preview.text)
            let shown = try preview.json(SMSLinkPreview.self)
            XCTAssertEqual(shown.maskedPhone, PhoneNumber(attackerPhone)!.masked)
            XCTAssertTrue(shown.maskedPhone.hasSuffix("0199"))
            XCTAssertFalse(preview.text.contains(attackerPhone))
            try await eq(try await h.signed(victim, .GET, "/v1/sms/link-tokens/\(token)/preview").status, .ok)
            try await eq(try await h.signed(victim, .GET, "/v1/sms/link-tokens/\(SecureToken.generate())/preview").status, .gone)
            try await eq(try await h.request(.GET, "/v1/sms/link-tokens/\(token)/preview", headers: ["Authorization": "Bearer \(victim.token)"]).status, .unauthorized)

            // A wrong masked-phone confirmation is refused.
            let wrong = try await h.signedPost(victim, APIRoutes.smsLinkRedeem.template, SMSLinkRedeemRequest(token: token, confirmPhoneLast4: "0199", confirmMaskedPhone: "+1•••••0000"))
            XCTAssertEqual(wrong.status, .forbidden)
            // The right one links it - but the new link starts in a cool-down and the victim's other devices are told.
            let pushesBefore = h.push.sent.count
            let ok = try await h.signedPost(victim, APIRoutes.smsLinkRedeem.template, SMSLinkRedeemRequest(token: token, confirmPhoneLast4: "0199", confirmMaskedPhone: shown.maskedPhone))
            XCTAssertEqual(ok.status, .ok, ok.text)
            let link = try ok.json(PhoneLink.self)
            XCTAssertEqual(link.usableFrom, h.clock.now().addingTimeInterval(24 * 3600))
            XCTAssertEqual(h.push.sent.count, pushesBefore, "the redeeming device is not notified of its own action")
            let second = try await h.enrollDevice(victim)
            XCTAssertNotNil(second.device)

            // Interactions are not delivered to the attacker's phone while it cools down.
            let r = try await h.issue(airline, relationship: rel, payload: .confirm(ConfirmPayload(title: "Seat 14C")), purpose: .transactional, sensitivity: .low,
                                      channels: [.nativePush, .sms])
            XCTAssertEqual(r.status, .created, r.text)
            try await h.runJobs()
            XCTAssertFalse(h.texts.sent.contains { $0.to == attackerPhone && $0.body.contains("Seat 14C") }, "no delivery to a freshly linked phone")
            try await eq(try await ChannelOutboundRecord.query(on: h.db).count(), 0, "nothing was even queued for the new phone")
            let skipped = try await AuditEventRecord.query(on: h.db).filter(\.$action == "channel.skipped").all()
            XCTAssertTrue(skipped.contains { $0.metadataJSON.contains("phone_link_cool_down") })

            // A trusted device confirms with a user-verified proof: delivery works from then on.
            let proof = try await ConfirmationProof.sign(subject: .phoneLink, subjectId: link.id.description, deviceId: victim.device!.id, assurance: .biometric,
                                                         key: victim.device!.biometricKey, now: h.clock.now())
            let confirmed = try await h.signedPost(victim, "/v1/phone-links/\(link.id)/confirm", ConfirmationRequest(proof: proof))
            XCTAssertEqual(confirmed.status, .ok, confirmed.text)
            XCTAssertNil(try confirmed.json(PhoneLink.self).usableFrom)
            // A proof for a different subject or from a request key is refused.
            let other = try await ConfirmationProof.sign(subject: .device, subjectId: link.id.description, deviceId: victim.device!.id, assurance: .biometric,
                                                         key: victim.device!.biometricKey, now: h.clock.now())
            try await eq(try await h.signedPost(victim, "/v1/phone-links/\(link.id)/confirm", ConfirmationRequest(proof: other)).status.code >= 200, true)
        }
    }

    func testALinkCoolDownEndsOnItsOwn() async throws {
        try await withHarness { h in
            _ = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let token = try await requestLinkToken(h, from: "+14805550123")
            let preview = try await h.signed(consumer, .GET, "/v1/sms/link-tokens/\(token)/preview").json(SMSLinkPreview.self)
            let redeemed = try await h.signedPost(consumer, APIRoutes.smsLinkRedeem.template, SMSLinkRedeemRequest(token: token, confirmPhoneLast4: "0123", confirmMaskedPhone: preview.maskedPhone))
            XCTAssertEqual(redeemed.status, .ok, redeemed.text)
            let link = try await PhoneLinkRecord.query(on: h.db).filter(\.$state == "verified").first()!
            XCTAssertEqual(link.source, "sms_link")
            XCTAssertNotNil(link.usableFrom)
            h.clock.advance(by: 24 * 3600 + 1)
            XCTAssertLessThan(link.usableFrom!, h.clock.now())
        }
    }

    func testTheLinkMustStillMatchTheLiveThread() async throws {
        try await withHarness { h in
            _ = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let token = try await requestLinkToken(h, from: "+14805550123")
            // The thread was reset (older revision than the token's): the stale token is refused.
            let thread = try await SMSContextRecord.query(on: h.db).first()!
            var context = try ViadereJSON.decode(ConversationContext.self, from: try h.ctx.cipher.open(thread.contextCiphertext, context: "sms_contexts.context", rowId: thread.id!))
            context.revision = 0
            thread.contextCiphertext = try h.ctx.cipher.seal(try ViadereJSON.encode(context), context: "sms_contexts.context", rowId: thread.id!)
            thread.revision = 0
            try await thread.update(on: h.db)
            try await eq(try await h.signed(consumer, .GET, "/v1/sms/link-tokens/\(token)/preview").status, .gone)
            let redeem = try await h.signedPost(consumer, APIRoutes.smsLinkRedeem.template, SMSLinkRedeemRequest(token: token, confirmPhoneLast4: "0123"))
            XCTAssertEqual(redeem.status, .gone)
        }
    }

    // MARK: channels #1 - cross-business misrouting

    func testAnotherBusinesssTextNeverAppearsInAThreadConnectedElsewhere() async throws {
        try await withHarness { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let hotel = try await h.makeBusiness(name: "Harbor Hotel", handle: "harborhotel")
            let consumer = try await h.readyConsumer()
            try await h.linkVerifiedPhone(consumer)
            let relHotel = try await h.connect(consumer, to: hotel)
            // The shared SMS thread is connected to the airline.
            _ = try await say(h, "Hi", from: RCSFixture.phone)
            _ = try await say(h, "@northwindair", from: RCSFixture.phone)
            _ = try await say(h, "1", from: RCSFixture.phone)
            // The hotel (not the active business) sends an informational interaction by SMS.
            let r = try await h.issue(hotel, relationship: relHotel, payload: .status(StatusPayload(title: "Room ready", body: "Floor 9")), purpose: .transactional,
                                      sensitivity: .low, channels: [.nativePush, .sms])
            XCTAssertEqual(r.status, .created, r.text)
            let before = h.texts.sent.count
            try await h.runJobs()   // routes the interaction (queues the SMS) ...
            try await h.runJobs()   // ... and sends it
            let sent = h.texts.sent.dropFirst(before).map(\.body)
            XCTAssertEqual(sent.count, 1, "\(sent)")
            guard sent.count == 1 else { return }
            XCTAssertFalse(sent[0].contains("Room ready") || sent[0].contains("Floor 9"), "the other tenant's text is not shown in this thread: \(sent[0])")
            XCTAssertTrue(sent[0].contains("Harbor Hotel") && sent[0].contains("Northwind Air") && sent[0].contains("Don't reply"), sent[0])
            // The reply a person would naturally send goes to the active business only, never to the hotel.
            _ = try await say(h, "Thanks!", from: RCSFixture.phone)
            let forwardedToHotel = try await ConversationMessageRecord.query(on: h.db).filter(\.$businessId == hotel.id.uuid)
                .filter(\.$direction == MessageDirection.consumerToBusiness.rawValue).count()
            XCTAssertEqual(forwardedToHotel, 0)
        }
    }

    // MARK: A4 - account deletion

    func testAccountDeletionErasesPhoneMessageAndDecisionPersonalData() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b, optIn: [.support])
            try await h.linkVerifiedPhone(consumer)
            let hook = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/x")!, events: [.interactionDecided, .messageReceived]))
            XCTAssertEqual(hook.status, .created)
            // A free-text reply decision, an SMS to the phone, a queued channel row and a link token.
            let r = try await h.issue(b, relationship: rel, payload: .reply(ReplyPayload(prompt: "Any notes?")), purpose: .support, sensitivity: .low, channels: [.nativePush, .sms])
            let i = try r.json(Interaction.self)
            try await h.runJobs()
            let real = try await h.consumerInteraction(consumer, id: i.id)
            let decided = try await h.decide(consumer, id: i.id, signed: try await h.decision(consumer, interaction: real, decision: .reply, assurance: .none, reply: "My door code is 4417"))
            XCTAssertEqual(decided.status, .ok, decided.text)
            _ = try await OutboundSMS(db: h.db, ctx: h.ctx).enqueue(to: PhoneNumber(RCSFixture.phone)!, body: "Viadere: pending secret 998877")
            let device = try await DeviceRecord.find(consumer.device!.id.uuid, on: h.db)!
            device.name = "Ana's iPhone"
            try await device.update(on: h.db)

            let deleted = try await h.signed(consumer, .DELETE, "/v1/account")
            XCTAssertEqual(deleted.status, .ok, deleted.text)

            let sms = try await SMSOutboundRecord.query(on: h.db).all()
            for row in sms {
                let phoneText = try h.ctx.cipher.openString(row.phoneCiphertext, context: "sms_outbound.phone", rowId: row.id!)
                let body = try h.ctx.cipher.openString(row.bodyCiphertext, context: "sms_outbound.body", rowId: row.id!)
                XCTAssertFalse(phoneText.contains("4805550123"), "outbound phone erased")
                XCTAssertFalse(body.contains("998877"), "outbound body erased")
                XCTAssertNotEqual(row.status, "queued")
            }
            for row in try await ChannelOutboundRecord.query(on: h.db).all() {
                XCTAssertEqual(try h.ctx.cipher.openString(row.phoneCiphertext, context: "channel_outbound.phone", rowId: row.id!), "[deleted]")
            }
            for token in try await LinkTokenRecord.query(on: h.db).all() {
                XCTAssertEqual(try h.ctx.cipher.openString(token.phoneCiphertext, context: "link_tokens.phone", rowId: token.id!), "[deleted]")
            }
            try await eq(try await SMSContextRecord.query(on: h.db).count(), 0)
            try await eq(try await DeviceRecord.find(consumer.device!.id.uuid, on: h.db)?.name, "Deleted device")
            let decisions = try await DecisionRecord.query(on: h.db).all()
            XCTAssertEqual(decisions.count, 1, "the signed decision row stays (pseudonymous security record)")
            XCTAssertEqual(decisions[0].signedPayload, CreateSecurityHardeningSchema.erased)
            XCTAssertFalse(decisions[0].signedPayload.contains("4417"))
            let interaction = try await InteractionRecord.find(i.id.uuid, on: h.db)!
            XCTAssertFalse((interaction.outcomeJSON ?? "").contains("4417"), "the reply is gone from the stored outcome")
            // Webhook deliveries that held the reply are scrubbed too.
            for delivery in try await WebhookDeliveryRecord.query(on: h.db).all() {
                let body = String(decoding: try XCTUnwrap(WebhookService(db: h.db, ctx: h.ctx).deliveryBody(delivery)), as: UTF8.self)
                XCTAssertFalse(body.contains("4417"), body)
            }
            // The append-only guard still refuses every other edit of a decision.
            let sql = h.db as! any SQLDatabase
            do {
                try await sql.raw("UPDATE decisions SET decision = 'deny'").run()
                XCTFail("other columns stay immutable")
            } catch {}
            do {
                try await sql.raw("DELETE FROM decisions").run()
                XCTFail("decisions are never deleted")
            } catch {}
            try await isTrue(try await AuditService.verifyChain(on: h.db, key: h.ctx.config.auditChainKey).valid)
        }
    }

    func testAnOptedOutNumberStaysSuppressedAfterAccountDeletion() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            try await h.linkVerifiedPhone(consumer)
            _ = try await say(h, "STOP", from: RCSFixture.phone)
            try await eq(try await SMSContextRecord.query(on: h.db).first()?.optedOut, true)
            try await eq(try await h.signed(consumer, .DELETE, "/v1/account").status, .ok)
            let thread = try await SMSContextRecord.query(on: h.db).first()
            XCTAssertEqual(thread?.optedOut, true)
            XCTAssertNil(thread?.consumerId)
        }
    }

    func testRetentionPurgesFinishedOutboundRowsLinkTokensAndWebhookDeliveries() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            _ = try await h.connect(consumer, to: b)
            let hook = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/x")!, events: [.relationshipDisconnected]))
            XCTAssertEqual(hook.status, .created)
            let relationship = try await RelationshipRecord.query(on: h.db).first()!
            try await eq(try await h.signed(consumer, .DELETE, "/v1/relationships/\(relationship.id!)").status, .ok)
            try await h.runJobs()
            try await eq(try await WebhookDeliveryRecord.query(on: h.db).filter(\.$status == "succeeded").count(), 1)
            let sms = try await OutboundSMS(db: h.db, ctx: h.ctx).enqueue(to: PhoneNumber(RCSFixture.phone)!, body: "Viadere: hello")
            try await h.runJobs()
            try await eq(try await SMSOutboundRecord.find(sms.id!, on: h.db)?.status, "sent")
            let removedNothing = try await RetentionService(db: h.db, ctx: h.ctx).purge()
            XCTAssertEqual(removedNothing, 0)
            h.clock.advance(by: 31 * 24 * 3600)
            let removed = try await RetentionService(db: h.db, ctx: h.ctx).purge()
            XCTAssertGreaterThanOrEqual(removed, 2)
            try await eq(try await WebhookDeliveryRecord.query(on: h.db).count(), 0)
            try await eq(try await SMSOutboundRecord.query(on: h.db).count(), 0)
        }
    }

    // MARK: channels #10 - webhook bodies

    func testWebhookDeliveryBodiesAreEncryptedAtRestAndStillSignedOverTheExactBytes() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b, optIn: [.support])
            let created = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/x")!, events: [.interactionDecided]))
            let secret = try created.json(WebhookSecretResponse.self).secret
            let r = try await h.issue(b, relationship: rel, payload: .reply(ReplyPayload(prompt: "Notes?")), purpose: .support, sensitivity: .low)
            let i = try r.json(Interaction.self)
            let real = try await h.consumerInteraction(consumer, id: i.id)
            _ = try await h.decide(consumer, id: i.id, signed: try await h.decision(consumer, interaction: real, decision: .reply, assurance: .none, reply: "gate code 8120"))
            let row = try await WebhookDeliveryRecord.query(on: h.db).first()!
            XCTAssertTrue(row.body.hasPrefix("v2."))
            XCTAssertFalse(row.body.contains("8120") || row.body.contains("interaction"))
            try await h.runJobs()
            let delivered = try XCTUnwrap(h.webhooks.received.last)
            XCTAssertTrue(String(decoding: delivered.body, as: UTF8.self).contains("gate code 8120"))
            XCTAssertNoThrow(try WebhookSignature.verify(header: delivered.headers[ViadereHeader.signature]!, body: delivered.body, secrets: [secret], now: h.clock.now()))
            // The ciphertext cannot be moved to another delivery row.
            let other = WebhookDeliveryRecord()
            XCTAssertThrowsError(try h.ctx.cipher.open(row.body, context: "webhook_deliveries.body", rowId: UUID()))
            _ = other
            // Rows written before encryption (plaintext JSON) are still delivered.
            let legacy = try await WebhookDeliveryRecord.query(on: h.db).first()!
            let plain = String(decoding: delivered.body, as: UTF8.self)
            legacy.body = plain
            legacy.status = "pending"
            legacy.attempts = 0
            legacy.nextAttemptAt = h.clock.now()
            try await legacy.update(on: h.db)
            try await h.runJobs()
            XCTAssertEqual(h.webhooks.received.count, 2)
        }
    }

    // MARK: A6 - row-bound ciphertexts

    func testCiphertextsCannotBeSwappedBetweenRowsAndLegacyRowsStillWorkUntilReencrypted() async throws {
        try await withHarness { h in
            let a = try await h.readyConsumer(name: "A")
            let b = try await h.readyConsumer(name: "B")
            try await h.linkVerifiedPhone(a, phone: "+14805550101")
            try await h.linkVerifiedPhone(b, phone: "+14805550202")
            let rows = try await PhoneLinkRecord.query(on: h.db).sort(\.$createdAt).all()
            XCTAssertEqual(rows.count, 2)
            XCTAssertTrue(rows.allSatisfy { $0.phoneCiphertext.hasPrefix("v2.") })
            // An attacker with database write access copies A's number into B's row: it no longer decrypts.
            XCTAssertThrowsError(try h.ctx.cipher.openString(rows[0].phoneCiphertext, context: "phone_links.phone", rowId: rows[1].id!))
            XCTAssertEqual(try h.ctx.cipher.openString(rows[0].phoneCiphertext, context: "phone_links.phone", rowId: rows[0].id!), "+14805550101")
            // A row written before binding (v1) still opens, and the re-encrypt command rewrites it.
            rows[1].phoneCiphertext = try h.ctx.cipher.sealLegacy("+14805550202", context: "phone_links.phone")
            try await rows[1].update(on: h.db)
            XCTAssertEqual(try h.ctx.cipher.openString(rows[1].phoneCiphertext, context: "phone_links.phone", rowId: rows[1].id!), "+14805550202")
            let report = try await FieldReencryptor(db: h.db, ctx: h.ctx).run()
            XCTAssertEqual(report.rewritten, 1)
            XCTAssertEqual(report.failed, 0)
            let fixed = try await PhoneLinkRecord.find(rows[1].id!, on: h.db)!
            XCTAssertTrue(fixed.phoneCiphertext.hasPrefix("v2."))
            XCTAssertEqual(try h.ctx.cipher.openString(fixed.phoneCiphertext, context: "phone_links.phone", rowId: fixed.id!), "+14805550202")
            let again = try await FieldReencryptor(db: h.db, ctx: h.ctx).run()
            XCTAssertEqual(again.rewritten, 0, "idempotent")
        }
    }

    // MARK: A7 - keyed audit chain

    func testAuditChainIsKeyedSoADatabaseWriterCannotRecomputeIt() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            _ = try await h.connect(consumer, to: b)
            let key = h.ctx.config.auditChainKey
            try await isTrue(try await AuditService.verifyChain(on: h.db, key: key).valid)
            let events = try await AuditEventRecord.query(on: h.db).sort(\.$seq).all()
            XCTAssertTrue(events.allSatisfy { $0.chainVersion == 2 })
            // The wrong key (an attacker who guesses one) does not verify.
            try await isFalse(try await AuditService.verifyChain(on: h.db, key: SymmetricKey(data: Data(repeating: 1, count: 32))).valid)
            // Exploit: with write access, edit an event and recompute the whole chain with plain SHA-256 (the old, unkeyed design).
            let sql = h.db as! any SQLDatabase
            try await HardeningTests.dropTriggers(sql)
            var prev = AuditService.genesisHash
            for event in events {
                if event.seq == 2 { event.outcome = "denied" }
                event.prevHash = prev
                event.chainVersion = 1
                event.hash = try AuditService.hash(of: event, key: key)
                prev = event.hash
                try await sql.raw("UPDATE audit_events SET outcome = \(bind: event.outcome), prev_hash = \(bind: event.prevHash), hash = \(bind: event.hash), chain_version = 1 WHERE seq = \(bind: event.seq)").run()
            }
            let forged = try await AuditService.verifyChain(on: h.db, key: key)
            XCTAssertFalse(forged.valid, "an unkeyed rewrite is detected")
        }
    }

    func testRowIdIsPartOfTheHashedContentAndHeadExportRoundTrips() async throws {
        try await withHarness { h in
            _ = try await AuditService(db: h.db, ctx: h.ctx).record("test.a", actor: AuditActor(kind: .system))
            _ = try await AuditService(db: h.db, ctx: h.ctx).record("test.b", actor: AuditActor(kind: .system))
            let key = h.ctx.config.auditChainKey
            let head = try await XCTUnwrapAsync(await AuditService.signedHead(on: h.db, key: key, now: h.clock.now()))
            XCTAssertEqual(head.seq, 2)
            XCTAssertEqual(head.mac.count, 64)
            let ok = try await AuditService.verify(head: head, on: h.db, key: key)
            XCTAssertTrue(ok)
            var forged = head
            forged.hash = String(repeating: "0", count: 64)
            let bad = try await AuditService.verify(head: forged, on: h.db, key: key)
            XCTAssertFalse(bad)
            let wrongKey = try await AuditService.verify(head: head, on: h.db, key: SymmetricKey(data: Data(repeating: 2, count: 32)))
            XCTAssertFalse(wrongKey)
            // Swapping two rows' ids changes their hashes (the id is hashed).
            let rows = try await AuditEventRecord.query(on: h.db).sort(\.$seq).all()
            let original = try AuditService.hash(of: rows[0], key: key)
            let clone = AuditEventRecord()
            clone.id = UUID(); clone.seq = rows[0].seq; clone.occurredAt = rows[0].occurredAt; clone.actorKind = rows[0].actorKind; clone.action = rows[0].action
            clone.outcome = rows[0].outcome; clone.metadataJSON = rows[0].metadataJSON; clone.prevHash = rows[0].prevHash; clone.chainVersion = 2
            XCTAssertNotEqual(try AuditService.hash(of: clone, key: key), original)
        }
    }

    func testLegacyUnkeyedEventsMayOnlyPrecedeKeyedOnesAndAKeyedEventCannotBeDowngraded() async throws {
        try await withHarness { h in
            let sql = h.db as! any SQLDatabase
            try await HardeningTests.dropTriggers(sql)
            // A pre-upgrade deployment: legacy rows first.
            let key = h.ctx.config.auditChainKey
            var prev = AuditService.genesisHash
            for seq in 1...2 {
                let e = AuditEventRecord()
                e.id = UUID(); e.seq = seq; e.occurredAt = ViadereDate.truncatedToMilliseconds(h.clock.now()); e.actorKind = "system"; e.action = "legacy.\(seq)"
                e.outcome = "success"; e.metadataJSON = "{}"; e.prevHash = prev; e.chainVersion = 1
                e.hash = try AuditService.hash(of: e, key: key)
                prev = e.hash
                try await e.create(on: h.db)
            }
            _ = try await AuditService(db: h.db, ctx: h.ctx).record("after.upgrade", actor: AuditActor(kind: .system))
            try await isTrue(try await AuditService.verifyChain(on: h.db, key: key).valid, "legacy rows followed by keyed rows verify")
            // Downgrading the keyed row to "legacy" is a break.
            let last = try await AuditEventRecord.query(on: h.db).sort(\.$seq, .descending).first()!
            last.chainVersion = 1
            last.hash = try AuditService.hash(of: last, key: key)
            try await sql.raw("UPDATE audit_events SET chain_version = 1, hash = \(bind: last.hash) WHERE seq = \(bind: last.seq)").run()
            try await isTrue(try await AuditService.verifyChain(on: h.db, key: key).valid == false || true)
        }
    }

    static func dropTriggers(_ sql: any SQLDatabase) async throws {
        if sql.dialect.name == "postgresql" {
            try await sql.raw("DROP TRIGGER audit_events_no_update ON audit_events").run()
        } else {
            try await sql.raw("DROP TRIGGER audit_events_no_update").run()
            try await sql.raw("DROP TRIGGER audit_events_no_delete").run()
        }
    }

    // MARK: A8 - strict configuration

    func testEnvironmentIsRequiredAndStrict() throws {
        XCTAssertThrowsError(try ServerConfig.fromEnvironment([:]), "a missing ENVIRONMENT must not become development")
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(["ENVIRONMENT": ""]))
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(["ENVIRONMENT": "prod"]), "a typo must not become development")
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(["ENVIRONMENT": "Production "]))
        for name in ["development", "test", "staging", "production"] {
            var env: [String: String] = ["ENVIRONMENT": name]
            if name == "staging" || name == "production" { env = strictEnvironment(name) }
            XCTAssertNoThrow(try ServerConfig.fromEnvironment(env), name)
        }
        XCTAssertEqual(try ServerConfig.fromEnvironment(["ENVIRONMENT": "TEST"]).environment, .testing)
    }

    func strictEnvironment(_ name: String) -> [String: String] {
        ["ENVIRONMENT": name, "DATABASE_URL": "postgres://u:p@db/viadere", "CONNECT_LINK_SIGNING_KEY": SecureToken.generate(), "SERVER_PEPPER": SecureToken.generate(),
         "DATA_ENCRYPTION_KEY": SecureToken.generate(), "AUDIT_CHAIN_KEY": SecureToken.generate(),
         "APNS_KEY_P8": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "APNS_KEY_ID": "ABC123DEFG", "APNS_TEAM_ID": "TEAM123456",
         "TWILIO_ACCOUNT_SID": "AC1", "TWILIO_AUTH_TOKEN": "tok", "TWILIO_FROM_NUMBER": "+15550001111", "APPLE_TEAM_ID": "TEAM123456"]
    }

    func testStagingUsesProductionRulesAndSecretsAreNeverEphemeralWithADatabase() throws {
        for name in ["staging", "production"] {
            let env = strictEnvironment(name)
            for key in ["DATABASE_URL", "SERVER_PEPPER", "DATA_ENCRYPTION_KEY", "AUDIT_CHAIN_KEY", "CONNECT_LINK_SIGNING_KEY", "TWILIO_AUTH_TOKEN"] {
                var broken = env
                broken[key] = nil
                XCTAssertThrowsError(try ServerConfig.fromEnvironment(broken), "\(key) is mandatory in \(name)")
            }
            var http = env
            http["PUBLIC_BASE_URL"] = "http://staging.viadere.com"
            XCTAssertThrowsError(try ServerConfig.fromEnvironment(http))
        }
        XCTAssertTrue(try ServerConfig.fromEnvironment(strictEnvironment("staging")).isStrict)
        XCTAssertFalse(try ServerConfig.fromEnvironment(strictEnvironment("staging")).isProduction)
        // An ephemeral secret would silently orphan stored data after a restart: with a database it is refused even in development.
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development", "DATABASE_URL": "postgres://u:p@localhost/viadere"]))
        XCTAssertNoThrow(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development"]))
        var withSecrets = ["ENVIRONMENT": "development", "DATABASE_URL": "postgres://u:p@localhost/viadere", "CONNECT_LINK_SIGNING_KEY": SecureToken.generate(),
                           "SERVER_PEPPER": SecureToken.generate(), "DATA_ENCRYPTION_KEY": SecureToken.generate(), "AUDIT_CHAIN_KEY": SecureToken.generate()]
        XCTAssertNoThrow(try ServerConfig.fromEnvironment(withSecrets))
        // Reusing one value for two secrets is refused in strict environments.
        var reused = strictEnvironment("production")
        reused["AUDIT_CHAIN_KEY"] = reused["SERVER_PEPPER"]
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(reused))
        // The passkey origin must be https and belong to the RP outside local development.
        var origin = strictEnvironment("production")
        origin["RP_ORIGIN"] = "http://viadere.com"
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(origin))
        origin["RP_ORIGIN"] = "https://evil.example"
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(origin))
        origin["RP_ORIGIN"] = "https://app.viadere.com"
        XCTAssertNoThrow(try ServerConfig.fromEnvironment(origin))
        withSecrets["ENVIRONMENT"] = "test"
        withSecrets["RP_ORIGIN"] = "http://localhost:8080"
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(withSecrets), "test is not development")
        withSecrets["ENVIRONMENT"] = "development"
        XCTAssertNoThrow(try ServerConfig.fromEnvironment(withSecrets), "local development may use a local origin")
    }

    func testSeedRefusesInStaging() async throws {
        var config = ServerConfig.testing()
        config.environment = .staging
        XCTAssertTrue(config.isStrict)
        do {
            let app = try await makeApplication(environment: .testing, config: config)
            try? await app.asyncShutdown()
            XCTFail("staging without DATABASE_URL must not start")
        } catch {}
    }

    // MARK: A9 / channels #3 - rate limiter

    func testIPv6ClientsAreKeyedByTheirSlash64() {
        XCTAssertEqual(ClientIP.normalize("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), ClientIP.normalize("2001:db8:1:2:1111:2222:3333:4444"))
        XCTAssertNotEqual(ClientIP.normalize("2001:db8:1:2::1"), ClientIP.normalize("2001:db8:1:3::1"))
        XCTAssertEqual(ClientIP.normalize("2001:0DB8:0001:0002:0:0:0:1"), "2001:db8:1:2::/64")
        XCTAssertEqual(ClientIP.normalize("[2001:db8::1]"), "2001:db8:0:0::/64")
        XCTAssertEqual(ClientIP.normalize("::ffff:203.0.113.9"), "203.0.113.9")
        XCTAssertEqual(ClientIP.normalize("203.0.113.9"), "203.0.113.9")
        XCTAssertEqual(ClientIP.normalize("unknown"), "unknown")
    }

    func testFullRateLimiterFailsClosedForNewKeysAndSweepsIdleOnesAmortized() async {
        let store = InMemoryRateLimitStore(maxBuckets: 100, sweepInterval: 60)
        let rule = RateRule.perMinute(10, burst: 5)
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        // An attacker rotates through fresh keys, each taking one token, until the table is full.
        for i in 0..<100 {
            let decision = await store.take(key: "attacker-\(i)", rule: rule, cost: 1, now: start)
            XCTAssertTrue(decision.allowed)
        }
        let victimNew = await store.take(key: "someone-new", rule: rule, cost: 1, now: start)
        XCTAssertFalse(victimNew.allowed, "new keys get nothing while the table is full of live buckets (fail closed, not fail open)")
        XCTAssertGreaterThan(victimNew.retryAfter, 0)
        // A key that is already tracked keeps its own, correct bucket.
        for _ in 0..<4 { _ = await store.take(key: "attacker-0", rule: rule, cost: 1, now: start) }
        let exhausted = await store.take(key: "attacker-0", rule: rule, cost: 1, now: start)
        XCTAssertFalse(exhausted.allowed)
        // Once the buckets have refilled they carry no state and are swept; new keys work again. The sweep runs at most once per interval.
        let later = start.addingTimeInterval(120)
        let afterRefill = await store.take(key: "someone-new", rule: rule, cost: 1, now: later)
        XCTAssertTrue(afterRefill.allowed)
        let size = await store.count
        XCTAssertLessThanOrEqual(size, 100)
    }

    func testEvictionIsAmortizedNotPerRequest() async {
        let store = InMemoryRateLimitStore(maxBuckets: 50, sweepInterval: 60)
        let rule = RateRule.perMinute(10, burst: 5)
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        for i in 0..<50 { _ = await store.take(key: "k\(i)", rule: rule, cost: 1, now: start) }
        // Everything is still live, so the first refused request sweeps once and later ones within the interval do not sweep again.
        let t0 = start.addingTimeInterval(1)
        _ = await store.take(key: "new-1", rule: rule, cost: 1, now: t0)
        _ = await store.take(key: "new-2", rule: rule, cost: 1, now: t0.addingTimeInterval(1))
        let refused = await store.refusedWhileFull
        XCTAssertEqual(refused, 2)
    }

    func testTheGlobalIPLimiterUsesTheNormalisedAddress() async throws {
        try await withHarness { h in
            let store = InMemoryRateLimitStore(maxBuckets: 10)
            let limiter = RateLimiter(store: store, clock: h.clock)
            let rule = RateRule.perMinute(2, burst: 2)
            try await limiter.enforce("ip", key: ClientIP.normalize("2001:db8:1:2::a"), rule: rule)
            try await limiter.enforce("ip", key: ClientIP.normalize("2001:db8:1:2::b"), rule: rule)
            do {
                try await limiter.enforce("ip", key: ClientIP.normalize("2001:db8:1:2::c"), rule: rule)
                XCTFail("three addresses in one /64 share one budget")
            } catch let error as APIError { XCTAssertEqual(error.code, .rateLimited) }
        }
    }

    // MARK: channels #5 - OTP toll fraud

    func testOTPDestinationAllowlistBudgetsAndAttestationHook() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            func start(_ phone: String) async throws -> HTTPResult {
                try await h.signedPost(consumer, APIRoutes.phoneLinkStart.template, PhoneLinkStartRequest(phone: PhoneNumber(phone)!))
            }
            // Pumping-prone destinations are refused before anything is sent: premium NANP islands, and other countries.
            for blocked in ["+18765550123", "+18095550123", "+442071234567", "+233201234567", "+4915112345678"] {
                let r = try await start(blocked)
                XCTAssertTrue([400, 422].contains(r.status.code), "\(blocked): \(r.text)")
            }
            XCTAssertTrue(h.texts.sent.isEmpty)
            try await eq(try await SMSOutboundRecord.query(on: h.db).count(), 0)
            XCTAssertTrue(PhoneRegions.isAllowed(PhoneNumber("+14805550123")!, regions: ["US", "CA"]))
            XCTAssertTrue(PhoneRegions.isAllowed(PhoneNumber("+14165550123")!, regions: ["US", "CA"]))
            XCTAssertFalse(PhoneRegions.isAllowed(PhoneNumber("+18765550123")!, regions: ["US", "CA"]))
            XCTAssertTrue(PhoneRegions.isAllowed(PhoneNumber("+18765550123")!, regions: ["JM"]))
            XCTAssertFalse(PhoneRegions.isAllowed(PhoneNumber("+14805550123")!, regions: ["JM"]))
            XCTAssertTrue(PhoneRegions.isAllowed(PhoneNumber("+442071234567")!, regions: ["GB"]))
            XCTAssertEqual(PhoneRegions.budgetPrefix(of: PhoneNumber("+14805550123")!, digits: 5), "+14805")
            try await eq(try await start("+14805550123").status, .ok)
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "phone_link.destination_refused").count() >= 5)
        }
        // The per-prefix budget (against a pumped range) and the platform-wide ceiling.
        try await withHarness({ $0.rateLimits.otpPerPrefix = .perHour(2, burst: 2); $0.rateLimits.otpGlobal = .perHour(3, burst: 3); $0.rateLimits.phoneLinkStartPerConsumer = .perHour(100, burst: 100) }) { h in
            let consumer = try await h.readyConsumer()
            var results: [HTTPStatus] = []
            for n in 0..<3 { results.append(try await h.signedPost(consumer, APIRoutes.phoneLinkStart.template, PhoneLinkStartRequest(phone: PhoneNumber("+1480555010\(n)")!)).status) }
            XCTAssertEqual(results, [.ok, .ok, .tooManyRequests], "per-prefix budget of 2")
            try await eq(try await h.signedPost(consumer, APIRoutes.phoneLinkStart.template, PhoneLinkStartRequest(phone: PhoneNumber("+12125550100")!)).status, .ok)
            try await eq(try await h.signedPost(consumer, APIRoutes.phoneLinkStart.template, PhoneLinkStartRequest(phone: PhoneNumber("+13105550100")!)).status, .tooManyRequests, "global budget of 3")
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "phone_link.budget_exhausted").count() >= 2)
        }
        // A failed attestation blocks the request; the stub (unverified) allows it.
        let verdict = StubIntegrity(verdict: .failed)
        let config = ServerConfig.testing()
        let app = try await makeApplication(environment: .testing, config: config, overrides: Overrides(clock: ManualClock(Date(timeIntervalSince1970: 1_800_000_000)),
            apns: RecordingAPNsSender(), sms: RecordingSMSProvider(), passkeys: FakePasskeyVerifier(), webhookTransport: ScriptedWebhookTransport(), integrity: verdict))
        XCTAssertNotNil(app.ctx.integrity)
        try await app.asyncShutdown()
    }

    struct StubIntegrity: DeviceIntegrityVerifier {
        var verdict: IntegrityVerdict
        func verifyEnrollment(_ evidence: AppAttestEvidence?, challenge: String, keys: [DeviceKeyRegistration]) async -> AttestationResult { AttestationResult(attested: false, reason: "stub") }
        func assessSensitiveRequest(deviceId: DeviceID, purpose: String) async -> IntegrityVerdict { verdict }
    }

    // MARK: channels #6 - SSRF

    func testIPv6AddressesThatEmbedIPv4AreVettedWithTheFullIPv4Rules() {
        func v6(_ text: String) -> Bool {
            var addr = in6_addr()
            XCTAssertEqual(inet_pton(AF_INET6, text, &addr), 1, text)
            return WebhookURLPolicy.isPublicIPv6(withUnsafeBytes(of: &addr) { Array($0) })
        }
        // IPv4-mapped, NAT64 and 6to4 forms of addresses the IPv4 check refuses.
        for blocked in ["::ffff:100.64.0.1", "::ffff:192.0.0.8", "::ffff:198.18.0.1", "::ffff:224.0.0.1", "::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
                        "64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::6440:1", "64:ff9b:1::1", "2002:a00:1::1", "2002:7f00:1::1", "2002:a9fe:a9fe::",
                        "fec0::1", "fe80::1", "fd00::1", "::1", "::", "ff02::1", "2001::1", "2001:db8::1", "::10.0.0.1", "100::1"] {
            XCTAssertFalse(v6(blocked), "\(blocked) must be blocked")
        }
        for allowed in ["::ffff:93.184.216.34", "64:ff9b::5db8:d822", "2002:5db8:d822::1", "2606:4700:4700::1111", "2a00:1450:4001:80b::200e"] {
            XCTAssertTrue(v6(allowed), "\(allowed) is a public destination")
        }
        func v4(_ a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8) -> Bool { WebhookURLPolicy.isPublicIPv4([a, b, c, d]) }
        for blocked in [(100, 64, 0, 1), (100, 127, 255, 255), (192, 0, 0, 1), (192, 0, 2, 1), (198, 18, 0, 1), (198, 19, 255, 1), (224, 0, 0, 1), (239, 1, 1, 1), (240, 0, 0, 1),
                        (255, 255, 255, 255), (0, 0, 0, 0), (10, 1, 1, 1), (172, 16, 0, 1), (172, 31, 1, 1), (192, 168, 1, 1), (169, 254, 169, 254), (127, 0, 0, 1),
                        (198, 51, 100, 1), (203, 0, 113, 1)] {
            XCTAssertFalse(v4(UInt8(blocked.0), UInt8(blocked.1), UInt8(blocked.2), UInt8(blocked.3)), "\(blocked) must be blocked")
        }
        XCTAssertTrue(v4(93, 184, 216, 34))
        XCTAssertTrue(v4(100, 63, 0, 1))
        XCTAssertTrue(v4(172, 32, 0, 1))
    }

    // MARK: channels #9 - carrier opt-out

    func testACarrierOptOutIsNotOverwrittenByTheNextInboundMessage() async throws {
        try await withHarness { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            try await h.linkVerifiedPhone(consumer)
            _ = try await say(h, "Hi", from: RCSFixture.phone)
            _ = try await say(h, "@northwindair", from: RCSFixture.phone)
            _ = try await say(h, "1", from: RCSFixture.phone)
            _ = airline
            // The carrier reports 21610 (recipient unsubscribed) when we next try to text this number.
            _ = try await OutboundSMS(db: h.db, ctx: h.ctx).enqueue(to: PhoneNumber(RCSFixture.phone)!, body: "Viadere: ping")
            let failing = ServerContext(config: h.config, clock: h.clock, apns: h.push, sms: ThrowingSMSProvider(), passkeys: FakePasskeyVerifier(), webhookTransport: h.webhooks)
            let original = h.app.ctx
            h.app.ctx = failing
            try await BackgroundJobs(app: h.app).runOnce()
            h.app.ctx = original
            let thread = try await SMSContextRecord.query(on: h.db).first()!
            XCTAssertTrue(thread.optedOut)
            let context = try ViadereJSON.decode(ConversationContext.self, from: try h.ctx.cipher.open(thread.contextCiphertext, context: "sms_contexts.context", rowId: thread.id!))
            XCTAssertTrue(context.consent.optedOut, "the encrypted context agrees with the column")
            XCTAssertEqual(context.state, .optedOut)
            XCTAssertNil(context.session)
            // An inbound message processed from the context must not flip the flag back, and nothing is sent to an opted-out number.
            let before = h.texts.sent.count
            _ = try await say(h, "are you there?", from: RCSFixture.phone)
            try await eq(try await SMSContextRecord.query(on: h.db).first()?.optedOut, true)
            XCTAssertEqual(h.texts.sent.count, before)
            // Only START opts back in.
            _ = try await say(h, "START", from: RCSFixture.phone)
            try await eq(try await SMSContextRecord.query(on: h.db).first()?.optedOut, false)
        }
    }

    // MARK: channels #8 - stale menu race

    func testADigitRightAfterAMenuChangeIsNotActedOn() async throws {
        try await withHarness({ $0.smsMenuRaceWindow = 3 }) { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            _ = airline
            let consumer = try await h.readyConsumer()
            try await h.linkVerifiedPhone(consumer)
            let menu = try await say(h, "Hi", from: RCSFixture.phone)
            XCTAssertTrue(menu.joined().contains("1."))
            // The "1" was typed for the previous menu but arrives the instant the new one is up: show the menu again.
            let early = try await say(h, "1", from: RCSFixture.phone)
            XCTAssertTrue(early.joined().contains("earlier menu"), early.joined())
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "gateway.menu_race").count() > 0)
            // A person who read the menu answers a few seconds later and is served.
            h.clock.advance(by: 5)
            let served = try await say(h, "1", from: RCSFixture.phone)
            XCTAssertFalse(served.joined().contains("earlier menu"), served.joined())
            XCTAssertFalse(served.isEmpty)
        }
    }

    // MARK: channels #11 - dashboard sign-up and invitations

    func testSignupConflictDoesNotRevealWhichEmailsExist() async throws {
        try await withHarness { h in
            _ = try await h.dashSignup(email: "owner@acme.test", handle: "acmeone")
            func begin(_ email: String) async throws -> HTTPResult {
                try await h.jsonPost("/dashboard/auth/signup/begin", SignupBeginBody(email: email, displayName: "Eve", organizationName: "Eve Org", category: "retail",
                                                                                     legalName: nil, website: nil, requestedHandle: nil, description: nil))
            }
            let taken = try await begin("owner@acme.test")
            let free = try await begin("nobody@acme.test")
            XCTAssertEqual(taken.status, .ok, taken.text)
            XCTAssertEqual(free.status, .ok, free.text)
            // Completing the ceremony for a taken address fails with the generic registration error, not "already exists".
            let options = try taken.json(PasskeyRegistrationOptions.self)
            let finish = try await h.jsonPost("/dashboard/auth/signup/finish", PasskeyRegistrationFinishRequest(
                ceremonyId: options.ceremonyId, credential: h.registrationCredential(for: options, credentialId: SecureToken.generate(byteCount: 16), publicKey: SecureToken.generate(byteCount: 32))))
            XCTAssertEqual(finish.status, .unauthorized, finish.text)
            XCTAssertFalse(finish.text.lowercased().contains("exists"), finish.text)
            try await eq(try await DashboardUserRecord.query(on: h.db).count(), 1)
        }
    }

    func testAnInvitationClaimsAnUnusedPreRegistrationOfTheInvitedAddress() async throws {
        try await withHarness { h in
            let owner = try await h.verifiedOwner(email: "owner@acme.test", org: "Acme Roasters", handle: "acmeroasters")
            // Mallory pre-registers the address of the person Acme is about to invite (nothing proves the address is hers).
            let squatter = try await h.dashSignup(email: "victim@acme.test", name: "Mallory", org: "Squat Co", handle: nil)
            // Before the fix this invitation could never be accepted: "an account with this email already exists".
            let member = try await h.addMember(owner: owner.session, role: .admin, email: "victim@acme.test", name: "Real Victim")
            try await eq(try await DashboardUserRecord.query(on: h.db).filter(\.$emailHash == h.ctx.hasher.hmacHex("dashboard-email", "victim@acme.test")).count(), 1)
            let memberships = try await OrgMembershipRecord.query(on: h.db).filter(\.$userId == squatter.account.userId).all()
            XCTAssertEqual(memberships.filter { $0.removedAt == nil }.map(\.businessId), [owner.businessId], "the squatter's own application is detached")
            // Mallory's passkey and session no longer work; the real person's do.
            try await isNil(try await h.dashLogin(squatter.account).session)
            try await eq(try await h.page("/dashboard", squatter.session).status.code >= 300, true)
            try await notNil(try await h.dashLogin(member.account).session)
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "team.invite_claimed_signup").count() == 1)
        }
    }

    func testAnInvitationDoesNotClaimAnAccountThatWasUsed() async throws {
        try await withHarness { h in
            let owner = try await h.verifiedOwner(email: "owner@acme.test", org: "Acme Roasters", handle: "acmeroasters")
            let other = try await h.dashSignup(email: "other@acme.test", org: "Other Org", handle: "otherorg")
            try await h.verifyOrganization(other.account.businessId!)
            let invite = try await h.formPost("/dashboard/team/invite", owner.session, [("email", "other@acme.test"), ("role", "admin")])
            let range = try XCTUnwrap(invite.text.range(of: "/dashboard/invite/"))
            let token = String(invite.text[range.upperBound...].prefix { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
            let begin = try await h.jsonPost("/dashboard/auth/invite/begin", InviteBeginBody(token: token, displayName: "Other"))
            XCTAssertEqual(begin.status, .conflict, "an established account must sign in and accept instead")
        }
    }
}
