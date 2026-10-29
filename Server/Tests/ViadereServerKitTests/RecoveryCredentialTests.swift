import Fluent
import Foundation
import NIOHTTP1
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// "Protect your account" (WP-B4): optional recovery credentials added with a user-verified proof from the device, and the tier rules around them.
final class RecoveryCredentialTests: XCTestCase {
    func beginCodes(_ h: TestHarness, _ consumer: TestConsumer) async throws -> PasskeyAssertionOptions {
        let begin = try await h.signed(consumer, .POST, APIRoutes.recoveryCodesBegin.template)
        XCTAssertEqual(begin.status, .ok, begin.text)
        return try begin.json(PasskeyAssertionOptions.self)
    }

    func regenerate(_ h: TestHarness, _ consumer: TestConsumer, ceremony: CeremonyID, proof: ConfirmationProof) async throws -> HTTPResult {
        try await h.signedPost(consumer, APIRoutes.recoveryCodesRegenerate.template, RecoveryCodesRegenerateRequest(ceremonyId: ceremony, proof: proof))
    }

    func testRecoveryCodesNeedOnlyAUserVerifiedProofFromThisDevice() async throws {
        try await withHarness { h in
            let consumer = try await h.deviceFirstConsumer()
            let options = try await beginCodes(h, consumer)
            XCTAssertTrue(options.allowCredentialIds.isEmpty, "a device-first account has no passkey")
            // A request key never counts; a proof for another ceremony, or claimed for another device, does not either.
            let weak = try await h.recoveryCredentialProof(consumer, ceremonyId: options.ceremonyId, assurance: .none)
            try await eq(try await regenerate(h, consumer, ceremony: options.ceremonyId, proof: weak).status, .forbidden)
            let other = try await h.recoveryCredentialProof(consumer, ceremonyId: CeremonyID(UUID()))
            try await eq(try await regenerate(h, consumer, ceremony: options.ceremonyId, proof: other).status, .unauthorized)
            let forged = try await h.recoveryCredentialProof(consumer, ceremonyId: options.ceremonyId, key: SoftwareP256SigningKey())
            try await eq(try await regenerate(h, consumer, ceremony: options.ceremonyId, proof: forged).status, .unauthorized)
            let deviceProof = try await ConfirmationProof.sign(subject: .device, subjectId: options.ceremonyId.description, deviceId: consumer.device!.id,
                                                               assurance: .biometric, key: consumer.device!.biometricKey, now: h.clock.now())
            try await eq(try await regenerate(h, consumer, ceremony: options.ceremonyId, proof: deviceProof).status, .unauthorized,
                         "a device-confirmation proof is not a recovery-credential proof")
            // The passcode key is enough (the same bar as the passkey assertion it replaces).
            let proof = try await h.recoveryCredentialProof(consumer, ceremonyId: options.ceremonyId, assurance: .devicePasscode)
            let issued = try await regenerate(h, consumer, ceremony: options.ceremonyId, proof: proof)
            XCTAssertEqual(issued.status, .created, issued.text)
            let set = try issued.json(RecoveryCodeSet.self)
            XCTAssertEqual(set.codes.count, 10)
            // Single use: the same proof, or the same ceremony, never again.
            try await eq(try await regenerate(h, consumer, ceremony: options.ceremonyId, proof: proof).status.code >= 400, true)
            let again = try await beginCodes(h, consumer)
            let replayed = try await regenerate(h, consumer, ceremony: again.ceremonyId, proof: proof)
            XCTAssertEqual(replayed.status, .unauthorized, replayed.text)
            let info = try await h.signed(consumer, .GET, APIRoutes.recoveryInfo.template).json(RecoveryInfo.self)
            XCTAssertEqual(info.remainingCodes, 10)
            XCTAssertEqual(info.passkeyCount, 0)
        }
    }

    func testAPasskeyCanBeAddedAsARecoveryCredentialAndThenDiscoversTheAccount() async throws {
        try await withHarness { h in
            var consumer = try await h.deviceFirstConsumer()
            let begin = try await h.signed(consumer, .POST, APIRoutes.recoveryPasskeyBegin.template)
            XCTAssertEqual(begin.status, .ok, begin.text)
            let options = try begin.json(PasskeyRegistrationOptions.self)
            XCTAssertEqual(options.userName, ConsumerRecord.neutralLabel, "no personal name is needed for the passkey sheet")
            let stored = try await XCTUnwrapAsync(try await ConsumerRecord.find(consumer.id.uuid, on: h.db))
            XCTAssertEqual(stored.userHandle, options.userId, "the WebAuthn user handle is assigned on first use")
            let credentialId = SecureToken.generate(byteCount: 16)
            let credential = PasskeyRegistrationCredential(id: credentialId, rawId: credentialId, attestationObject: SecureToken.generate(byteCount: 32),
                                                           clientDataJSON: options.challenge)
            // Without a valid proof from this device nothing is added.
            let forged = try await h.recoveryCredentialProof(consumer, ceremonyId: options.ceremonyId, key: SoftwareP256SigningKey())
            try await eq(try await h.signedPost(consumer, APIRoutes.recoveryPasskeyFinish.template,
                                                RecoveryPasskeyFinishRequest(ceremonyId: options.ceremonyId, credential: credential, proof: forged)).status, .unauthorized)
            let proof = try await h.recoveryCredentialProof(consumer, ceremonyId: options.ceremonyId)
            let added = try await h.signedPost(consumer, APIRoutes.recoveryPasskeyFinish.template,
                                               RecoveryPasskeyFinishRequest(ceremonyId: options.ceremonyId, credential: credential, proof: proof))
            XCTAssertEqual(added.status, .created, added.text)
            XCTAssertEqual(try added.json(RecoveryPasskeyAdded.self).passkeyCount, 1)
            try await eq(try await h.signedPost(consumer, APIRoutes.recoveryPasskeyFinish.template,
                                                RecoveryPasskeyFinishRequest(ceremonyId: options.ceremonyId, credential: credential, proof: proof)).status.code >= 400, true)
            try await eq(try await h.signed(consumer, .GET, APIRoutes.recoveryInfo.template).json(RecoveryInfo.self).passkeyCount, 1)

            // On a new phone the passkey finds the account; the new device is D0 until this one approves it, and this one is told.
            consumer.credentialId = credentialId
            let second = try await h.enrollDevice(consumer)
            try await eq(try await h.tier(of: second, as: consumer), .d0)
            let notices = try await h.signed(consumer, .GET, "/v1/security-notices").json([SecurityNotice].self)
            XCTAssertTrue(notices.contains { $0.topic == .newDevice })
            // The new device cannot add credentials to an account that has a trusted device.
            try await eq(try await h.signed(second, .POST, APIRoutes.recoveryPasskeyBegin.template).errorCode, .deviceCoolDown)
            try await eq(try await h.confirm(second, from: consumer).status, .ok)
            try await eq(try await h.tier(of: second, as: consumer), .d1)
        }
    }

    func testRecoveryWorksForAnAccountThatOnlyHasCodes() async throws {
        try await withHarness { h in
            let consumer = try await h.deviceFirstConsumer()
            let options = try await beginCodes(h, consumer)
            let set = try await regenerate(h, consumer, ceremony: options.ceremonyId,
                                           proof: try await h.recoveryCredentialProof(consumer, ceremonyId: options.ceremonyId)).json(RecoveryCodeSet.self)
            let begin = try await h.post(APIRoutes.recoveryBegin.template, RecoveryBeginRequest(recoveryId: set.recoveryId, code: set.codes[0]))
            XCTAssertEqual(begin.status, .ok, begin.text)
            let recovery = try begin.json(PasskeyRegistrationOptions.self)
            XCTAssertFalse(recovery.userId.isEmpty)
            XCTAssertEqual(recovery.userName, ConsumerRecord.neutralLabel)
        }
    }

    // MARK: Tier rules around the protect step

    func testASoleUnapprovedDeviceCanStillManageItsOwnAccountButNeverApproveHighRisk() async throws {
        try await withAttestHarness(mode: .report) { h, _ in
            // Unattested in report mode: D0, and nobody else could ever approve it. It must not lock the owner out of their own account.
            let created = try await h.createAccount()
            let consumer = try XCTUnwrap(created.consumer)
            try await eq(try await h.tier(of: consumer), .d0)
            let options = try await beginCodes(h, consumer)
            try await eq(try await regenerate(h, consumer, ceremony: options.ceremonyId,
                                              proof: try await h.recoveryCredentialProof(consumer, ceremonyId: options.ceremonyId)).status, .created)
            try await eq(try await h.signed(consumer, .POST, APIRoutes.recoveryPasskeyBegin.template).status, .ok)
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let rel = try await h.connect(consumer, to: b)
            try await eq(try await h.highRiskDecision(consumer, business: b, relationship: rel).errorCode, .deviceCoolDown)
            try await eq(try await h.signed(consumer, .DELETE, "/v1/account").status, .ok)
        }
    }

    func testOnlyAD1DeviceApprovesAnotherAndUnverifiedIntegrityIsNeverElevated() async throws {
        try await withAttestHarness(mode: .report) { h, pki in
            let owner = try await h.registerConsumer()
            let (_, _, attested) = try await h.enrollAttested(owner, login: false, evidence: genuineEvidence(pki, clock: h.clock))
            try await eq(try await h.tier(of: attested), .d1, "a new account's attested first device")
            let (_, _, unattested) = try await h.enrollAttested(attested, evidence: { _, _, _ in nil })
            try await eq(try await h.tier(of: unattested, as: attested), .d0)
            // A D0 device approves nothing.
            let (_, _, third) = try await h.enrollAttested(attested, evidence: genuineEvidence(pki, clock: h.clock))
            try await eq(try await h.confirm(third, from: unattested).status, .forbidden)
            // The D1 device approves both; only the attested one becomes D1.
            let ownerNow = attested
            try await eq(try await h.confirm(unattested, from: ownerNow).status, .ok)
            try await eq(try await h.tier(of: unattested, as: attested), .d0, "integrity is evaluated here and was never verified")
            try await eq(try await h.confirm(third, from: ownerNow).status, .ok)
            try await eq(try await h.tier(of: third, as: attested), .d1)
            let event = try await AuditEventRecord.query(on: h.db).filter(\.$action == "device.confirmed").sort(\.$seq, .descending).first()
            XCTAssertTrue(event?.metadataJSON.contains("\"elevated\":\"true\"") ?? false)
        }
    }
}
