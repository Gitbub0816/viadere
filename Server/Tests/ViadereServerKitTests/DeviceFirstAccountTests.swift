@preconcurrency import Crypto
import Fluent
import SQLKit
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// An integrity verifier that would vouch for **any** Apple evidence. Used to prove that other formats never reach the Apple path.
struct AppleAlwaysAttests: DeviceIntegrityVerifier {
    func verifyEnrollment(_ evidence: AppAttestEvidence?, consumerId: ConsumerID, challenge: String, keys: [DeviceKeyRegistration],
                          clientKind: DeviceClientKind) async -> AttestationResult {
        guard evidence != nil else { return AttestationResult(attested: false, reason: "not_provided") }
        return AttestationResult(attested: true, reason: "verified", keyId: SecureToken.sha256Hex(Data(UUID().uuidString.utf8)),
                                 publicKey: Base64URL.encode(P256.Signing.PrivateKey().publicKey.x963Representation), counter: 0, environment: "production")
    }

    func assessSensitiveRequest(deviceId: DeviceID, purpose: String) async -> IntegrityVerdict { .unverified }
}

/// WP-B4 (device-first pseudonymous accounts) and WP-A2 (platform-neutral protocol), server side. Each test names the exploit it closes.
final class DeviceFirstAccountTests: XCTestCase {
    // MARK: Creation

    func testAnAccountIsCreatedFromTheDeviceAloneAndStoresNoPersonalField() async throws {
        try await withHarness { h in
            // A client that sends personal fields anyway: none of them is part of the contract, none is stored.
            let created = try await h.createAccount(extra: ["displayName": "Ana Rivera", "email": "ana@example.com", "phone": "+14805550123",
                                                            "trustTier": "d2", "elevatedBy": "trusted_device_approval"])
            XCTAssertEqual(created.result.status, .created, created.result.text)
            let consumer = try XCTUnwrap(created.consumer)
            let response = try created.result.json(AccountCreateResponse.self)
            XCTAssertEqual(response.accountId, created.begin?.accountId, "the reserved id becomes the account id")
            XCTAssertEqual(response.device.consumerId, response.accountId)
            XCTAssertEqual(response.device.keys.count, 3)
            XCTAssertNil(response.session.recoveryCodes, "recovery credentials are optional and come later")

            let record = try await XCTUnwrapAsync(try await ConsumerRecord.find(consumer.id.uuid, on: h.db))
            XCTAssertNil(record.displayName)
            XCTAssertNil(record.userHandle)
            XCTAssertEqual(record.createdVia, "device")
            XCTAssertEqual(record.policyVersion, TrustTierPolicy.version)
            try await eq(try await PasskeyCredentialRecord.query(on: h.db).filter(\.$consumerId == consumer.id.uuid).count(), 0, "no passkey is needed")
            let raw = try await AuditEventRecord.query(on: h.db).all().map(\.metadataJSON).joined()
            for pii in ["Ana Rivera", "ana@example.com", "4805550123"] { XCTAssertFalse(raw.contains(pii), pii) }

            // The session is bound to the new device: device-signed requests work, an unsigned bearer does not.
            let devices = try await h.signed(consumer, .GET, "/v1/devices")
            XCTAssertEqual(devices.status, .ok, devices.text)
            try await eq(try await h.request(.GET, "/v1/devices", headers: ["Authorization": "Bearer \(consumer.token)"]).status, .unauthorized)
            let device = try await XCTUnwrapAsync(try await DeviceRecord.find(consumer.device!.id.uuid, on: h.db))
            XCTAssertEqual(device.enrollmentMethod, "account_create")
            XCTAssertEqual(device.keyAlgorithm, "ES256")
            XCTAssertNil(device.approvalsLockedUntil, "the first device of a new account has no window")
            // Tier: decided by the server (development harness: integrity is not evaluated, so a UV key makes it D1), never from the body.
            XCTAssertEqual(device.trustTier, "d1")
            XCTAssertEqual(device.elevatedBy, TrustElevation.firstDeviceAttested.rawValue)
            XCTAssertEqual(response.device.trustTier, .d1)
            let audit = try await AuditEventRecord.query(on: h.db).filter(\.$action == "account.created").all()
            XCTAssertEqual(audit.count, 1)
            // The access token refreshes with the device's signature, like any bound session.
            try await eq(try await h.refresh(consumer).status, .ok)
        }
    }

    func testTheCeremonyIsSingleUseAndBoundToItsChallenge() async throws {
        try await withHarness { h in
            let first = try await h.createAccount()
            XCTAssertEqual(first.result.status, .created, first.result.text)
            // Replaying the same ceremony (new keys, same challenge) creates nothing.
            let replay = try await h.createAccount(begin: first.begin)
            XCTAssertEqual(replay.result.status, .unauthorized, replay.result.text)
            // Another ceremony's challenge, or an unknown ceremony: the same 401.
            let opened = try await h.beginAccount().json(AccountEnrollBeginResponse.self)
            let wrongChallenge = try await h.createAccount(begin: opened, mutate: { $0.challenge = first.begin!.challenge })
            XCTAssertEqual(wrongChallenge.result.status, .unauthorized)
            var unknown = opened
            unknown.ceremonyId = CeremonyID(UUID())
            try await eq(try await h.createAccount(begin: unknown).result.status, .unauthorized)
            // A failed attempt did not burn the ceremony (it is consumed only when everything else passed) ...
            let proofsForAnotherAccount = try await h.createAccount(begin: opened, mutate: { request in
                request.keys = request.keys.map { DeviceKeyRegistration(purpose: $0.purpose, publicKey: $0.publicKey, hardwareBacked: true, proof: request.keys[0].proof) }
            })
            XCTAssertEqual(proofsForAnotherAccount.result.status, .unauthorized)
            try await eq(try await h.createAccount(begin: opened).result.status, .created)
            // ... and it expires.
            let late = try await h.beginAccount().json(AccountEnrollBeginResponse.self)
            h.clock.advance(by: 5 * 60 + 1)
            try await eq(try await h.createAccount(begin: late).result.status, .unauthorized)
            try await eq(try await ConsumerRecord.query(on: h.db).count(), 2)
        }
    }

    func testTwoConcurrentCreatesOnOneCeremonyMakeExactlyOneAccount() async throws {
        try await withHarness { h in
            let opened = try await h.beginAccount().json(AccountEnrollBeginResponse.self)
            let statuses = try await withThrowingTaskGroup(of: HTTPStatus.self) { group in
                for _ in 0..<4 { group.addTask { try await h.createAccount(begin: opened).result.status } }
                var out: [HTTPStatus] = []
                for try await status in group { out.append(status) }
                return out
            }
            XCTAssertEqual(statuses.filter { $0 == .created }.count, 1, "\(statuses)")
            XCTAssertTrue(statuses.filter { $0 != .created }.allSatisfy { $0 == .unauthorized || $0 == .conflict }, "\(statuses)")
            try await eq(try await ConsumerRecord.query(on: h.db).count(), 1)
            try await eq(try await DeviceRecord.query(on: h.db).count(), 1)
        }
    }

    func testBeginSaysNothingAboutExistingAccounts() async throws {
        try await withHarness { h in
            let existing = try await h.deviceFirstConsumer()
            let response = try await h.beginAccount()
            XCTAssertEqual(response.status, .ok, response.text)
            let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: response.body) as? [String: Any])
            XCTAssertEqual(Set(object.keys), ["ceremonyId", "accountId", "challenge", "expiresAt", "integrity"])
            let opened = try response.json(AccountEnrollBeginResponse.self)
            XCTAssertNotEqual(opened.accountId, existing.id)
            let reserved = try await ConsumerRecord.find(opened.accountId.uuid, on: h.db)
            XCTAssertNil(reserved, "a reserved id is not an account")
            XCTAssertGreaterThanOrEqual(Base64URL.decode(opened.challenge)?.count ?? 0, 32)
            // Begin takes no input that could name an account.
            let withInput = try await h.request(.POST, APIRoutes.accountEnrollBegin.template, body: Data(#"{"accountId":"\#(existing.id)"}"#.utf8))
            XCTAssertEqual(withInput.status, .ok)
            XCTAssertNotEqual(try withInput.json(AccountEnrollBeginResponse.self).accountId, existing.id)
        }
    }

    func testExpiredCeremoniesArePurged() async throws {
        try await withHarness { h in
            _ = try await h.beginAccount()
            try await eq(try await AccountEnrollCeremonyRecord.query(on: h.db).count(), 1)
            h.clock.advance(by: 2 * 86_400)
            try await IdentityMaintenance(db: h.db, ctx: h.ctx).run()
            try await eq(try await AccountEnrollCeremonyRecord.query(on: h.db).count(), 0)
        }
    }

    // MARK: Abuse budgets and the kill switch

    func testTheGlobalBeginBudgetIsEnforced() async throws {
        try await withHarness({ $0.rateLimits.accountEnrollGlobal = .perHour(2, burst: 2) }) { h in
            try await eq(try await h.beginAccount().status, .ok)
            try await eq(try await h.beginAccount().status, .ok)
            let third = try await h.beginAccount()
            XCTAssertEqual(third.status, .tooManyRequests, third.text)
        }
    }

    func testTheSignupSwitchStopsAccountCreation() async throws {
        try await withHarness { h in
            let opened = try await h.beginAccount().json(AccountEnrollBeginResponse.self)
            try await PlatformFlags(db: h.db, ctx: h.ctx).set(.signupConsumer, value: "on", reason: "Test: stop consumer sign-ups.", actor: .system("test"))
            try await eq(try await h.beginAccount().status, .serviceUnavailable)
            try await eq(try await h.createAccount(begin: opened).result.status, .serviceUnavailable)
            try await eq(try await ConsumerRecord.query(on: h.db).count(), 0)
        }
    }

    func testAccountsPerAttestEnvironmentAndAddressBucketAreLimited() async throws {
        try await withHarness({ config in
            config.rateLimits.accountCreatePerBucket = .perHour(2, burst: 2)
            config.trustedProxyCount = 1
        }) { h in
            let ip = ["X-Forwarded-For": "203.0.113.7"]
            try await eq(try await h.createAccount(headers: ip).result.status, .created)
            // A refused attempt does not use the budget.
            let opened = try await h.beginAccount(headers: ip).json(AccountEnrollBeginResponse.self)
            try await eq(try await h.createAccount(begin: opened, mutate: { $0.challenge = "wrong" }, headers: ip).result.status, .unauthorized)
            try await eq(try await h.createAccount(headers: ip).result.status, .created)
            let third = try await h.createAccount(headers: ip)
            XCTAssertEqual(third.result.status, .tooManyRequests, third.result.text)
            // The same /24 is the same bucket; another network is not.
            try await eq(try await h.createAccount(headers: ["X-Forwarded-For": "203.0.113.200"]).result.status, .tooManyRequests)
            try await eq(try await h.createAccount(headers: ["X-Forwarded-For": "198.51.100.7"]).result.status, .created)
        }
    }

    // MARK: Integrity (App Attest, platform-neutral envelope)

    func testInRequireModeAnAttestationForAnotherChallengeAccountOrKeyListIsRejected() async throws {
        try await withAttestHarness(mode: .require) { h, pki in
            for (what, flawed) in [("another challenge", genuineIntegrity(pki, clock: h.clock, bindTo: { _, account in ("another-challenge", account) })),
                                   ("another account", genuineIntegrity(pki, clock: h.clock, bindTo: { challenge, _ in (challenge, ConsumerID()) })),
                                   ("another key list", genuineIntegrity(pki, clock: h.clock, keysOverride: [
                                       DeviceKeyRegistration(purpose: .request, publicKey: SoftwareP256SigningKey().publicKey, hardwareBacked: true, proof: "x")]))] {
                let refused = try await h.createAccount(integrity: flawed)
                XCTAssertEqual(refused.result.status, .forbidden, "\(what): \(refused.result.text)")
                XCTAssertEqual(refused.result.errorCode, .attestationRequired, what)
            }
            let none = try await h.createAccount()
            XCTAssertEqual(none.result.errorCode, .attestationRequired, "no evidence in require mode")
            try await eq(try await ConsumerRecord.query(on: h.db).count(), 0, "nothing was created")
            let genuine = try await h.createAccount(integrity: genuineIntegrity(pki, clock: h.clock))
            XCTAssertEqual(genuine.result.status, .created, genuine.result.text)
            let device = try genuine.result.json(AccountCreateResponse.self).device
            XCTAssertEqual(device.trustTier, .d1, "attested, user-verified, first device of a new account")
            XCTAssertTrue(device.keys.allSatisfy(\.attested))
            let record = try await XCTUnwrapAsync(try await DeviceRecord.find(device.id.uuid, on: h.db))
            XCTAssertEqual(record.integrityFormat, "apple-app-attest")
            let attestKey = try await AppAttestKeyRecord.query(on: h.db).first()
            XCTAssertEqual(attestKey?.format, "apple-app-attest")
        }
    }

    func testOneAppAttestKeyCannotVouchForASecondAccount() async throws {
        try await withAttestHarness(mode: .require) { h, pki in
            let appAttestKey = P256Key()
            try await eq(try await h.createAccount(integrity: genuineIntegrity(pki, clock: h.clock, key: appAttestKey)).result.status, .created)
            // A farm reusing the attested key: a valid attestation over the second account's own binding, same key.
            let second = try await h.createAccount(integrity: genuineIntegrity(pki, clock: h.clock, key: appAttestKey))
            XCTAssertEqual(second.result.status, .forbidden, second.result.text)
            XCTAssertEqual(second.result.errorCode, .attestationRequired)
            try await eq(try await ConsumerRecord.query(on: h.db).count(), 1)
        }
        try await withAttestHarness(mode: .report) { h, pki in
            let appAttestKey = P256Key()
            try await eq(try await h.createAccount(integrity: genuineIntegrity(pki, clock: h.clock, key: appAttestKey)).result.status, .created)
            let second = try await h.createAccount(integrity: genuineIntegrity(pki, clock: h.clock, key: appAttestKey))
            XCTAssertEqual(second.result.status, .created, second.result.text)
            XCTAssertEqual(try second.result.json(AccountCreateResponse.self).device.trustTier, .d0, "a reused key is unattested: D0")
        }
    }

    func testReportModeUnattestedAccountIsD0AndItsApprovalKeysAreNotHonouredForHighRisk() async throws {
        try await withAttestHarness(mode: .report) { h, _ in
            let created = try await h.createAccount()
            XCTAssertEqual(created.result.status, .created, created.result.text)
            let consumer = try XCTUnwrap(created.consumer)
            XCTAssertEqual(try created.result.json(AccountCreateResponse.self).device.trustTier, .d0)
            let record = try await XCTUnwrapAsync(try await DeviceRecord.find(consumer.device!.id.uuid, on: h.db))
            XCTAssertEqual(record.attestationStatus, "unattested")
            XCTAssertEqual(record.trustTier, "d0")
            let flagged = try await AuditEventRecord.query(on: h.db).filter(\.$action == "account.created").first()
            XCTAssertTrue(flagged?.metadataJSON.contains("unattested") ?? false)

            // Messaging-level use works; a high-risk approval with its (biometric) key does not. Deny stays available.
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let rel = try await h.connect(consumer, to: b)
            let blocked = try await h.highRiskDecision(consumer, business: b, relationship: rel)
            XCTAssertEqual(blocked.status, .forbidden, blocked.text)
            XCTAssertEqual(blocked.errorCode, .deviceCoolDown)
            try await eq(try await h.highRiskDecision(consumer, business: b, relationship: rel, verdict: .deny).status, .ok)
            // No amount of time changes that (within the refresh token's life, so the session itself is still good).
            h.clock.advance(by: 20 * 86_400)
            let later = try await h.renewed(consumer)
            try await eq(try await h.highRiskDecision(later, business: b, relationship: rel).errorCode, .deviceCoolDown)
        }
    }

    func testAndroidAndUnknownEvidenceIsNeverAttested() async throws {
        let android = IntegrityEvidence(androidKeyAttestation: AndroidKeyAttestationEvidence(certificateChain: ["MIIBszCCAVmgAwIBAgIBATAKBggqhkjOPQQDAjA"],
                                                                                             playIntegrityToken: "eyJhbGciOi"))
        // Even a verifier that would vouch for any Apple evidence is never asked about another format.
        let harness = try await TestHarness.make(mode: .require, integrity: { _ in AppleAlwaysAttests() })
        do {
            let refused = try await harness.createAccount(integrity: { _, _, _ in android })
            XCTAssertEqual(refused.result.status, .forbidden, refused.result.text)
            XCTAssertEqual(refused.result.errorCode, .attestationRequired)
            let unknown = try await harness.createAccount(mutate: { request in
                request.integrity = try? ViadereJSON.decode(IntegrityEvidence.self, from: Data(#"{"format":"tpm-2","keyId":"a2V5","attestation":"b2Jq"}"#.utf8))
            })
            XCTAssertEqual(unknown.result.errorCode, .attestationRequired, "an unknown format is unattested, never attested")
            let apple = try await harness.createAccount(integrity: { _, _, _ in IntegrityEvidence(appleAppAttest: AppAttestEvidence(keyId: "a2V5", attestation: "b2Jq")) })
            XCTAssertEqual(apple.result.status, .created, "the Apple path is the only one this verifier answers")
        } catch {
            try? await harness.shutdown()
            throw error
        }
        try await harness.shutdown()

        // The stub itself.
        let stub = await AndroidKeyAttestationVerifier().verify(android.androidKeyAttestation, consumerId: ConsumerID(), challenge: "c", keys: [])
        XCTAssertFalse(stub.attested)

        try await withAttestHarness(mode: .report) { h, _ in
            let created = try await h.createAccount(integrity: { _, _, _ in android })
            XCTAssertEqual(created.result.status, .created, created.result.text)
            let device = try created.result.json(AccountCreateResponse.self).device
            XCTAssertEqual(device.trustTier, .d0)
            XCTAssertFalse(device.keys.contains(where: \.attested))
            let record = try await XCTUnwrapAsync(try await DeviceRecord.find(device.id.uuid, on: h.db))
            XCTAssertEqual(record.integrityFormat, "android-key-attestation")
            XCTAssertEqual(record.attestationStatus, "rejected")
            try await eq(try await AppAttestKeyRecord.query(on: h.db).count(), 0)
        }
    }

    // MARK: Request validation

    func testOnlyES256KeysAreAccepted() async throws {
        try await withHarness { h in
            let created = try await h.createAccount(mutate: { request in
                request.keys = request.keys.map { DeviceKeyRegistration(purpose: $0.purpose, publicKey: $0.publicKey, hardwareBacked: true, proof: $0.proof,
                                                                         algorithm: DeviceKeyAlgorithm(rawValue: $0.purpose == .request ? "EdDSA" : "ES256")) }
            })
            XCTAssertEqual(created.result.status, .badRequest, created.result.text)
            // The same rule on `POST /v1/devices`.
            let consumer = try await h.registerConsumer()
            let begin = try await h.request(.POST, APIRoutes.deviceEnrollBegin.template, headers: ["Authorization": "Bearer \(consumer.token)"])
            let challenge = try begin.json(DeviceEnrollmentChallenge.self).challenge
            let key = SoftwareP256SigningKey()
            var registration = try await DeviceEnrollment.register(key: key, purpose: .request, hardwareBacked: true, consumerId: consumer.id, challenge: challenge)
            registration.algorithm = DeviceKeyAlgorithm(rawValue: "RS256")
            let enroll = try await h.post(APIRoutes.deviceEnroll.template, DeviceEnrollRequest(name: "Phone", platform: .iOS, challenge: challenge, keys: [registration],
                                                                                             assertion: h.enrollmentAssertion(consumer, challenge: challenge)),
                                          headers: ["Authorization": "Bearer \(consumer.token)"])
            XCTAssertEqual(enroll.status, .badRequest, enroll.text)
            // Contradicting evidence fields on `POST /v1/devices` are refused rather than one being picked.
            let fresh = try await h.login(consumer)
            let again = try await h.request(.POST, APIRoutes.deviceEnrollBegin.template, headers: ["Authorization": "Bearer \(fresh.token)"])
            let challenge2 = try again.json(DeviceEnrollmentChallenge.self).challenge
            let ok = try await DeviceEnrollment.register(key: key, purpose: .request, hardwareBacked: true, consumerId: consumer.id, challenge: challenge2)
            let conflicting = try await h.post(APIRoutes.deviceEnroll.template, DeviceEnrollRequest(
                name: "Phone", platform: .iOS, challenge: challenge2, keys: [ok], assertion: h.enrollmentAssertion(consumer, challenge: challenge2),
                appAttest: AppAttestEvidence(keyId: "a", attestation: "b"), integrity: IntegrityEvidence(appleAppAttest: AppAttestEvidence(keyId: "c", attestation: "d"))),
                headers: ["Authorization": "Bearer \(fresh.token)"])
            XCTAssertEqual(conflicting.status, .badRequest, conflicting.text)
        }
    }

    func testAnAppClipCreatesARequestOnlyShortLivedD0Account() async throws {
        try await withHarness { h in
            let withApproval = try await h.createAccount(purposes: [.request, .approvalBiometric], clientKind: .appClip)
            XCTAssertEqual(withApproval.result.status, .unprocessableEntity, withApproval.result.text)
            let missingRequest = try await h.createAccount(purposes: [.approvalBiometric])
            XCTAssertEqual(missingRequest.result.status, .unprocessableEntity)
            let clip = try await h.createAccount(purposes: [.request], clientKind: .appClip, deviceName: nil)
            XCTAssertEqual(clip.result.status, .created, clip.result.text)
            let response = try clip.result.json(AccountCreateResponse.self)
            XCTAssertEqual(response.device.clientKind, .appClip)
            XCTAssertEqual(response.device.trustTier, .d0)
            XCTAssertEqual(response.device.expiresAt, h.clock.now().addingTimeInterval(7 * 86_400))
            XCTAssertLessThanOrEqual(response.session.expiresAt, h.clock.now().addingTimeInterval(7 * 86_400))
            XCTAssertFalse(response.device.name.isEmpty, "a neutral default label")
            // It can connect (a request-key action) ...
            let consumer = try XCTUnwrap(clip.consumer)
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            _ = try await h.connect(consumer, to: b)
        }
    }

    func testLegacyPasskeySignUpNoLongerNeedsAName() async throws {
        try await withHarness { h in
            let begin = try await h.post(APIRoutes.registerBegin.template, PasskeyRegistrationBeginRequest(displayName: nil))
            XCTAssertEqual(begin.status, .ok, begin.text)
            let options = try begin.json(PasskeyRegistrationOptions.self)
            XCTAssertFalse(options.userName.isEmpty, "the passkey sheet gets a neutral label")
            let credential = PasskeyRegistrationCredential(id: "cred-1", rawId: "cred-1", attestationObject: SecureToken.generate(byteCount: 32), clientDataJSON: options.challenge)
            let finish = try await h.post(APIRoutes.registerFinish.template, PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: credential))
            XCTAssertEqual(finish.status, .created, finish.text)
            let session = try finish.json(AuthSession.self)
            let record = try await XCTUnwrapAsync(try await ConsumerRecord.find(session.consumerId.uuid, on: h.db))
            XCTAssertNil(record.displayName)
            XCTAssertEqual(record.createdVia, "passkey")
            XCTAssertNotNil(record.userHandle)
        }
    }

    func testPushRegistrationIsProviderNeutral() async throws {
        try await withHarness { h in
            let consumer = try await h.deviceFirstConsumer()
            let apns = PushRegistration(provider: .apns, token: String(repeating: "ab", count: 32), environment: "sandbox", appId: "com.viadere.app")
            try await eq(try await h.signedPost(consumer, "/v1/push/apns-token", apns).status, .ok)
            try await eq(try await APNsTokenRecord.query(on: h.db).filter(\.$deviceId == consumer.device!.id.uuid).count(), 1)
            // An FCM token is never stored as (or sent through) APNs.
            let fcm = PushRegistration(provider: .fcm, token: "fcm-token-0123456789", environment: nil, appId: "com.viadere.android")
            let refused = try await h.signedPost(consumer, "/v1/push/apns-token", fcm)
            XCTAssertEqual(refused.status, .unprocessableEntity, refused.text)
            try await eq(try await APNsTokenRecord.query(on: h.db).filter(\.$token == "fcm-token-0123456789").count(), 0)
            // The original body still works.
            try await eq(try await h.signedPost(consumer, "/v1/push/apns-token",
                                                APNsTokenRegistration(token: String(repeating: "cd", count: 32), environment: .production, bundleId: "com.viadere.app")).status, .ok)
        }
    }

    // MARK: Audit pseudonym and policy version

    func testAuditEventsCarryAnActorPseudonymAndThePolicyVersionUnderTheChain() async throws {
        try await withHarness { h in
            let consumer = try await h.deviceFirstConsumer()
            _ = try await h.signed(consumer, .DELETE, "/v1/sessions/\(UUID())")
            let created = try await XCTUnwrapAsync(try await AuditEventRecord.query(on: h.db).filter(\.$action == "account.created").first())
            let ref = try XCTUnwrap(created.actorRef)
            XCTAssertTrue(ref.hasPrefix("act_"))
            XCTAssertFalse(ref.lowercased().contains(consumer.id.description), "a pseudonym, not the account id")
            XCTAssertEqual(created.policyVersion, TrustTierPolicy.version)
            XCTAssertEqual(created.chainVersion, 4)
            // The same account always has the same pseudonym; another account another one.
            let other = try await h.deviceFirstConsumer()
            let events = try await AuditEventRecord.query(on: h.db).filter(\.$action == "account.created").all()
            let refs = Set(events.compactMap(\.actorRef))
            XCTAssertEqual(refs.count, 2)
            XCTAssertEqual(AuditPseudonym(ctx: h.ctx).ref(for: consumer.id.uuid), ref)
            XCTAssertNotEqual(AuditPseudonym(ctx: h.ctx).ref(for: other.id.uuid), ref)
            // Both fields are covered by the keyed chain: editing either breaks it.
            let key = h.config.auditChainKey
            try await eq(try await AuditService.verifyChain(on: h.db, key: key).valid, true)
            // Exploit: a database writer (the append-only triggers dropped) relabels who acted, or under which policy.
            let sql = h.db as! any SQLDatabase
            try await HardeningTests.dropTriggers(sql)
            try await sql.raw("UPDATE audit_events SET actor_ref = 'act_forged' WHERE seq = \(bind: created.seq)").run()
            let broken = try await AuditService.verifyChain(on: h.db, key: key)
            XCTAssertFalse(broken.valid)
            XCTAssertEqual(broken.firstBrokenSeq, created.seq)
            try await sql.raw("UPDATE audit_events SET actor_ref = \(bind: ref), policy_version = 99 WHERE seq = \(bind: created.seq)").run()
            try await eq(try await AuditService.verifyChain(on: h.db, key: key).valid, false)
            try await sql.raw("UPDATE audit_events SET policy_version = \(bind: TrustTierPolicy.version) WHERE seq = \(bind: created.seq)").run()
            try await eq(try await AuditService.verifyChain(on: h.db, key: key).valid, true)
        }
    }
}
