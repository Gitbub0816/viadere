import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// WP-A2 (platform-neutral protocol), WP-B4 (device-first accounts) and WP-B5 (trust tiers): the shared contract.
@Suite("Device-first accounts and trust tiers")
struct DeviceFirstTests {
    // MARK: A2: integrity evidence

    @Test func appleEvidenceRoundTripsAndIsTheOnlyFormatWithAppleFields() throws {
        let evidence = IntegrityEvidence(appleAppAttest: AppAttestEvidence(keyId: "a2V5", attestation: "b2Jq"))
        #expect(evidence.format == .appleAppAttest)
        let json = try ViadereJSON.encode(evidence)
        let object = try #require(try JSONSerialization.jsonObject(with: json) as? [String: Any])
        #expect(object["format"] as? String == "apple-app-attest")
        #expect(object["keyId"] as? String == "a2V5")
        let decoded = try ViadereJSON.decode(IntegrityEvidence.self, from: json)
        #expect(decoded == evidence)
        #expect(decoded.appleAppAttest == AppAttestEvidence(keyId: "a2V5", attestation: "b2Jq"))
    }

    @Test func androidAndUnknownFormatsNeverCarryAppleEvidence() throws {
        let android = try ViadereJSON.decode(IntegrityEvidence.self, from: Data(#"{"format":"android-key-attestation","certificateChain":["MIIB"],"playIntegrityToken":"t","keyId":"x","attestation":"y"}"#.utf8))
        #expect(android.format == .androidKeyAttestation)
        #expect(android.androidKeyAttestation?.certificateChain == ["MIIB"])
        // Apple fields smuggled into another format are ignored: only `format` decides how evidence is read.
        #expect(android.appleAppAttest == nil)
        let unknown = try ViadereJSON.decode(IntegrityEvidence.self, from: Data(#"{"format":"tpm-2","keyId":"x","attestation":"y"}"#.utf8))
        #expect(unknown.format == .unknown)
        #expect(unknown.rawFormat == "tpm-2")
        #expect(unknown.appleAppAttest == nil)
        let none = try ViadereJSON.decode(IntegrityEvidence.self, from: Data(#"{"format":"none"}"#.utf8))
        #expect(none.format == .none)
    }

    @Test func aLegacyEnrollmentStillCarriesItsAppAttestEvidence() throws {
        let key = SoftwareP256SigningKey()
        let registration = DeviceKeyRegistration(purpose: .request, publicKey: key.publicKey, hardwareBacked: true, proof: "p")
        let legacy = DeviceEnrollRequest(name: "Phone", platform: .iOS, challenge: "c", keys: [registration],
                                         appAttest: AppAttestEvidence(keyId: "k", attestation: "a"))
        let decoded = try ViadereJSON.decode(DeviceEnrollRequest.self, from: try ViadereJSON.encode(legacy))
        #expect(decoded.effectiveIntegrity == IntegrityEvidence(appleAppAttest: AppAttestEvidence(keyId: "k", attestation: "a")))
        #expect(!decoded.hasConflictingIntegrity)
        var both = legacy
        both.integrity = IntegrityEvidence(appleAppAttest: AppAttestEvidence(keyId: "other", attestation: "a"))
        #expect(both.hasConflictingIntegrity)
        var neutral = legacy
        neutral.appAttest = nil
        neutral.integrity = IntegrityEvidence(appleAppAttest: AppAttestEvidence(keyId: "k", attestation: "a"))
        #expect(neutral.effectiveIntegrity?.appleAppAttest?.keyId == "k")
    }

    // MARK: A2: key algorithm

    @Test func keyAlgorithmDefaultsToES256AndKeepsUnknownValuesForTheServerToRefuse() throws {
        let key = SoftwareP256SigningKey()
        let registration = DeviceKeyRegistration(purpose: .request, publicKey: key.publicKey, hardwareBacked: true, proof: "p")
        #expect(registration.algorithm == .es256)
        let encoded = try #require(try JSONSerialization.jsonObject(with: try ViadereJSON.encode(registration)) as? [String: Any])
        #expect(encoded["algorithm"] as? String == "ES256")
        // An older client sends no algorithm: ES256.
        let legacy = Data(#"{"purpose":"request","publicKey":"\#(key.publicKey.base64URL)","hardwareBacked":true,"proof":"p"}"#.utf8)
        #expect(try ViadereJSON.decode(DeviceKeyRegistration.self, from: legacy).algorithm == .es256)
        let other = Data(#"{"purpose":"request","publicKey":"\#(key.publicKey.base64URL)","hardwareBacked":true,"proof":"p","algorithm":"EdDSA"}"#.utf8)
        let decoded = try ViadereJSON.decode(DeviceKeyRegistration.self, from: other)
        #expect(decoded.algorithm.rawValue == "EdDSA")
        #expect(!decoded.algorithm.isSupported)
        #expect(DeviceKeyAlgorithm.es256.isSupported)
    }

    // MARK: A2: push registration

    @Test func pushRegistrationNamesItsProvider() throws {
        let apns = APNsTokenRegistration(token: "abcd", environment: .production, bundleId: "com.viadere.app")
        let neutral = PushRegistration(apns)
        #expect(neutral.provider == .apns && neutral.appId == "com.viadere.app" && neutral.environment == "production")
        #expect(neutral.apnsRegistration == apns)
        let fcm = PushRegistration(provider: .fcm, token: "tok", environment: nil, appId: "com.viadere.android")
        #expect(fcm.apnsRegistration == nil)
        let decoded = try ViadereJSON.decode(PushRegistration.self, from: try ViadereJSON.encode(fcm))
        #expect(decoded == fcm)
        let unknown = try ViadereJSON.decode(PushRegistration.self, from: Data(#"{"provider":"carrier-pigeon","token":"t","appId":"x"}"#.utf8))
        #expect(unknown.provider == .unknown)
    }

    // MARK: B5: tiers

    @Test func tiersAreOrderedAndUnknownTiersAreTheLowest() throws {
        #expect(DeviceTrustTier.d0 < .d1 && DeviceTrustTier.d1 < .d2)
        #expect(try ViadereJSON.decode(DeviceTrustTier.self, from: Data(#""d9""#.utf8)) == .d0)
        #expect(try ViadereJSON.decode(DeviceTrustTier.self, from: Data(#""d1""#.utf8)) == .d1)
    }

    func facts(app: Bool = true, revoked: Bool = false, expired: Bool = false, uv: Bool = true, verified: Bool = true, required: Bool = true,
               firstAppDevice: Bool = true, recovered: Bool = false) -> DeviceTrustFacts {
        DeviceTrustFacts(isFullApp: app, revoked: revoked, expired: expired, hasUserVerifiedApprovalKey: uv, integrityVerified: verified,
                         integrityRequired: required, firstAppDeviceOfAccount: firstAppDevice, accountRecovered: recovered)
    }

    @Test func aNewAccountsFirstDeviceIsD1OnlyWithVerifiedIntegrityAndAUserVerifiedKey() {
        #expect(TrustTierPolicy.initialElevation(facts()) == .firstDeviceAttested)
        // Unattested where attestation is evaluated (report mode): D0, no matter what else holds.
        #expect(TrustTierPolicy.initialElevation(facts(verified: false)) == nil)
        // Development (`APP_ATTEST_MODE=off`): integrity is not evaluated, so it is not a condition.
        #expect(TrustTierPolicy.initialElevation(facts(verified: false, required: false)) == .firstDeviceAttested)
        #expect(TrustTierPolicy.initialElevation(facts(uv: false)) == nil)
        #expect(TrustTierPolicy.initialElevation(facts(app: false)) == nil)
        // Every later device, and every device after a recovery, starts at D0.
        #expect(TrustTierPolicy.initialElevation(facts(firstAppDevice: false)) == nil)
        #expect(TrustTierPolicy.initialElevation(facts(recovered: true)) == nil)
    }

    @Test func storedTrustIsCappedByLiveFactsAndD2NeedsD1() {
        #expect(TrustTierPolicy.evaluate(stored: .d1, facts: facts()) == .d1)
        #expect(TrustTierPolicy.evaluate(stored: .d1, facts: facts(revoked: true)) == .d0)
        #expect(TrustTierPolicy.evaluate(stored: .d1, facts: facts(expired: true)) == .d0)
        #expect(TrustTierPolicy.evaluate(stored: .d1, facts: facts(app: false)) == .d0)
        #expect(TrustTierPolicy.evaluate(stored: .d0, facts: facts()) == .d0)
        #expect(TrustTierPolicy.evaluate(stored: .d1, facts: facts(), liveVerifiedClaim: true) == .d2)
        #expect(TrustTierPolicy.evaluate(stored: .d0, facts: facts(), liveVerifiedClaim: true) == .d0)
        // A stored D2 is never trusted as such: D2 is evaluated per claim, from a live verification.
        #expect(TrustTierPolicy.evaluate(stored: .d2, facts: facts()) == .d1)
    }

    @Test func onlyAD1DeviceCanElevateAnotherAndNothingElevatesByTime() {
        #expect(TrustTierPolicy.mayElevate(target: facts(firstAppDevice: false), approverTier: .d1))
        #expect(!TrustTierPolicy.mayElevate(target: facts(firstAppDevice: false), approverTier: .d0))
        #expect(!TrustTierPolicy.mayElevate(target: facts(uv: false, firstAppDevice: false, recovered: true), approverTier: .d1))
        #expect(!TrustTierPolicy.mayElevate(target: facts(verified: false), approverTier: .d1))
        #expect(!TrustTierPolicy.mayElevate(target: facts(revoked: true), approverTier: .d1))
        // The reasons a device may be elevated: none of them is the passing of time.
        #expect(Set(TrustElevation.allCases.map(\.rawValue)) == ["first_device_attested", "trusted_device_approval", "migration_backfill"])
    }

    // MARK: B4: account enrollment DTOs

    @Test func accountCreationCarriesNoPersonalField() throws {
        let key = SoftwareP256SigningKey()
        let request = AccountCreateRequest(ceremonyId: CeremonyID(UUID()), challenge: "c", platform: .iOS, deviceName: nil,
                                           keys: [DeviceKeyRegistration(purpose: .request, publicKey: key.publicKey, hardwareBacked: true, proof: "p")],
                                           integrity: nil, clientKind: .app)
        let object = try #require(try JSONSerialization.jsonObject(with: try ViadereJSON.encode(request)) as? [String: Any])
        #expect(Set(object.keys).isSubset(of: ["ceremonyId", "challenge", "platform", "deviceName", "keys", "integrity", "clientKind"]))
        // Extra personal fields a client might send are not part of the contract (and so never reach storage).
        var withPII = object
        withPII["displayName"] = "Ana Rivera"
        withPII["email"] = "ana@example.com"
        withPII["phone"] = "+14805550123"
        let decoded = try ViadereJSON.decode(AccountCreateRequest.self, from: try JSONSerialization.data(withJSONObject: withPII))
        #expect(decoded == request)
    }

    @Test func accountRoutesArePublicAndCatalogued() {
        #expect(APIRoutes.accountEnrollBegin.descriptor.template == "/v1/accounts/enroll/begin")
        #expect(APIRoutes.accountEnrollBegin.descriptor.auth == .none)
        #expect(APIRoutes.accountCreate.descriptor.template == "/v1/accounts")
        #expect(APIRoutes.accountCreate.descriptor.method == .POST)
        #expect(APIRoutes.recoveryPasskeyBegin.descriptor.auth == .deviceSignedBearer)
        #expect(APIRoutes.recoveryPasskeyFinish.descriptor.auth == .deviceSignedBearer)
        let all = Set(APIRoutes.all.map(\.name))
        for name in ["accounts.enroll.begin", "accounts.create", "recoveryCredentials.passkeys.begin", "recoveryCredentials.passkeys.finish"] {
            #expect(all.contains(name), "\(name)")
        }
    }

    @Test func aRecoveryCredentialProofAcceptsAUserVerifiedKeyAndNothingWeaker() async throws {
        let key = SoftwareP256SigningKey()
        let device = DeviceID()
        let subjectId = UUID().uuidString.lowercased()
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        #expect(ConfirmationProof(subject: .recoveryCredential, subjectId: subjectId, deviceId: device, signedAt: now, assurance: .biometric, signature: "")
            .requiredKeyPurpose == .approvalBiometric)
        #expect(ConfirmationProof(subject: .recoveryCredential, subjectId: subjectId, deviceId: device, signedAt: now, assurance: .devicePasscode, signature: "")
            .requiredKeyPurpose == .approvalUserPresence)
        #expect(ConfirmationProof(subject: .recoveryCredential, subjectId: subjectId, deviceId: device, signedAt: now, assurance: .none, signature: "")
            .requiredKeyPurpose == nil)
        // Confirming a device or a phone is still biometric only.
        #expect(ConfirmationProof(subject: .device, subjectId: subjectId, deviceId: device, signedAt: now, assurance: .devicePasscode, signature: "")
            .requiredKeyPurpose == nil)
        let proof = try await ConfirmationProof.sign(subject: .recoveryCredential, subjectId: subjectId, deviceId: device, assurance: .devicePasscode, key: key, now: now)
        #expect(String(decoding: proof.signingInput(), as: UTF8.self).hasPrefix("VIADERE-CONFIRM-V1\nrecoveryCredential\n\(subjectId)\n"))
        try proof.verify(subject: .recoveryCredential, subjectId: subjectId, publicKey: key.publicKey, now: now)
        #expect(throws: ConfirmationProof.Failure.wrongSubject) {
            try proof.verify(subject: .device, subjectId: subjectId, publicKey: key.publicKey, now: now)
        }
    }

    @Test func deviceDTOCarriesTheServerEvaluatedTier() throws {
        let device = Device(id: DeviceID(), consumerId: ConsumerID(), name: "Phone", platform: .iOS, keys: [], createdAt: Date(timeIntervalSince1970: 1_800_000_000),
                            trustTier: .d1)
        let decoded = try ViadereJSON.decode(Device.self, from: try ViadereJSON.encode(device))
        #expect(decoded.trustTier == .d1)
        // From a server that predates tiers: unknown.
        var object = try #require(try JSONSerialization.jsonObject(with: try ViadereJSON.encode(device)) as? [String: Any])
        object.removeValue(forKey: "trustTier")
        #expect(try ViadereJSON.decode(Device.self, from: try JSONSerialization.data(withJSONObject: object)).trustTier == nil)
    }
}
