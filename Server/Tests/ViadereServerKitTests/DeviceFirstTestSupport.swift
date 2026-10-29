@preconcurrency import Crypto
import Foundation
import NIOHTTP1
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Device-first account creation (§2.5a) the way the app does it: begin, keys with proofs over the reserved id, integrity, create.
extension TestHarness {
    struct AccountCreation {
        var result: HTTPResult
        var consumer: TestConsumer?
        var begin: AccountEnrollBeginResponse?
        var keys: [DeviceKeyPurpose: SoftwareP256SigningKey] = [:]
    }

    func beginAccount(headers: [String: String] = [:]) async throws -> HTTPResult {
        try await request(.POST, APIRoutes.accountEnrollBegin.template, headers: headers, body: Data("{}".utf8))
    }

    /// `integrity(keys, challenge, reservedAccountId)` builds the evidence; `mutate` edits the request; `extra` adds raw JSON fields.
    func createAccount(purposes: [DeviceKeyPurpose] = DeviceKeyPurpose.allCases, clientKind: DeviceClientKind = .app, deviceName: String? = "Test iPhone",
                       begin existing: AccountEnrollBeginResponse? = nil,
                       integrity: ([DeviceKeyRegistration], String, ConsumerID) throws -> IntegrityEvidence? = { _, _, _ in nil },
                       mutate: (inout AccountCreateRequest) -> Void = { _ in }, extra: [String: Any] = [:],
                       headers: [String: String] = [:]) async throws -> AccountCreation {
        let opened: AccountEnrollBeginResponse
        if let existing {
            opened = existing
        } else {
            let response = try await beginAccount(headers: headers)
            guard response.status == .ok else { return AccountCreation(result: response) }
            opened = try response.json(AccountEnrollBeginResponse.self)
        }
        var keyMap: [DeviceKeyPurpose: SoftwareP256SigningKey] = [:]
        var registrations: [DeviceKeyRegistration] = []
        for purpose in purposes {
            let key = SoftwareP256SigningKey()
            keyMap[purpose] = key
            registrations.append(try await DeviceEnrollment.register(key: key, purpose: purpose, hardwareBacked: true, consumerId: opened.accountId,
                                                                    challenge: opened.challenge))
        }
        var request = AccountCreateRequest(ceremonyId: opened.ceremonyId, challenge: opened.challenge, platform: .iOS, deviceName: deviceName,
                                           keys: registrations, integrity: try integrity(registrations, opened.challenge, opened.accountId), clientKind: clientKind)
        mutate(&request)
        var body = try ViadereJSON.encode(request)
        if !extra.isEmpty, var object = try JSONSerialization.jsonObject(with: body) as? [String: Any] {
            for (key, value) in extra { object[key] = value }
            body = try JSONSerialization.data(withJSONObject: object)
        }
        let result = try await self.request(.POST, APIRoutes.accountCreate.template, headers: headers, body: body)
        guard result.status == .created, let created = try? result.json(AccountCreateResponse.self) else {
            return AccountCreation(result: result, begin: opened, keys: keyMap)
        }
        let device = TestDevice(id: created.device.id, requestKey: keyMap[.request]!, passcodeKey: keyMap[.approvalUserPresence] ?? SoftwareP256SigningKey(),
                                biometricKey: keyMap[.approvalBiometric] ?? SoftwareP256SigningKey())
        return AccountCreation(result: result, consumer: TestConsumer(id: created.accountId, session: created.session, device: device), begin: opened, keys: keyMap)
    }

    /// A device-first account, asserting success.
    func deviceFirstConsumer() async throws -> TestConsumer {
        let created = try await createAccount()
        XCTAssertEqual(created.result.status, .created, created.result.text)
        return try XCTUnwrap(created.consumer)
    }

    /// The tier the server reports for `consumer`'s own device.
    func tier(of consumer: TestConsumer, as viewer: TestConsumer? = nil) async throws -> DeviceTrustTier? {
        let list = try await signed(viewer ?? consumer, .GET, "/v1/devices").json([Device].self)
        return list.first { $0.id == consumer.device?.id }?.trustTier
    }

    /// `POST /v1/devices/{target}/confirm` signed by `confirmer`'s biometric key.
    func confirm(_ target: TestConsumer, from confirmer: TestConsumer) async throws -> HTTPResult {
        let proof = try await ConfirmationProof.sign(subject: .device, subjectId: target.device!.id.description, deviceId: confirmer.device!.id,
                                                     assurance: .biometric, key: confirmer.device!.biometricKey, now: clock.now())
        return try await signedPost(confirmer, "/v1/devices/\(target.device!.id)/confirm", ConfirmationRequest(proof: proof))
    }

    /// The `recoveryCredential` proof for `ceremonyId`, signed by `consumer`'s device.
    func recoveryCredentialProof(_ consumer: TestConsumer, ceremonyId: CeremonyID, assurance: DecisionAssurance = .biometric,
                                 key: SoftwareP256SigningKey? = nil, deviceId: DeviceID? = nil) async throws -> ConfirmationProof {
        let device = consumer.device!
        let signer: SoftwareP256SigningKey
        switch assurance {
        case .biometric: signer = key ?? device.biometricKey
        case .devicePasscode: signer = key ?? device.passcodeKey
        case .none: signer = key ?? device.requestKey
        }
        return try await ConfirmationProof.sign(subject: .recoveryCredential, subjectId: ceremonyId.description, deviceId: deviceId ?? device.id,
                                                assurance: assurance, key: signer, now: clock.now())
    }
}

/// App Attest evidence (as the envelope) over the account-creation binding, from a synthetic PKI.
func genuineIntegrity(_ pki: TestAppAttestPKI, clock: any ServerClock, flaws: TestAppAttestPKI.Flaws = .init(), key: P256Key = P256Key(),
                      clientKind: DeviceClientKind = .app, bindTo: ((String, ConsumerID) -> (String, ConsumerID))? = nil,
                      keysOverride: [DeviceKeyRegistration]? = nil) -> ([DeviceKeyRegistration], String, ConsumerID) throws -> IntegrityEvidence? {
    { keys, challenge, account in
        let (boundChallenge, boundAccount) = bindTo?(challenge, account) ?? (challenge, account)
        let made = try pki.attest(clientDataHash: AppAttestBinding.clientDataHash(consumerId: boundAccount, challenge: boundChallenge, keys: keysOverride ?? keys),
                                  clientKind: clientKind, now: clock.now(), flaws: flaws, key: key.key)
        return IntegrityEvidence(appleAppAttest: made.evidence)
    }
}

/// A reusable App Attest key (to reproduce "one App Attest key, two accounts").
final class P256Key: @unchecked Sendable {
    let key: P256.Signing.PrivateKey
    init() { key = .init() }
}

extension TestHarness {
    /// Issues a high-sensitivity `authorize` interaction to `relationship` and answers it from `consumer`'s device.
    func highRiskDecision(_ consumer: TestConsumer, business: TestBusiness, relationship: Relationship, verdict: Decision = .approve) async throws -> HTTPResult {
        let issued = try await issue(business, relationship: relationship, payload: .authorize(.sample()), sensitivity: .high)
        XCTAssertEqual(issued.status, .created, issued.text)
        let interaction = try issued.json(Interaction.self)
        let real = try await consumerInteraction(consumer, id: interaction.id)
        return try await decide(consumer, id: interaction.id,
                                signed: try await decision(consumer, interaction: real, decision: verdict, assurance: verdict == .approve ? .biometric : .none))
    }

    /// A session for `consumer`'s device after the clock moved past its access token (the app refreshes, device-signed).
    func renewed(_ consumer: TestConsumer) async throws -> TestConsumer {
        var renewed = consumer
        let refreshed = try await refresh(consumer)
        XCTAssertEqual(refreshed.status, .ok, refreshed.text)
        renewed.session = try refreshed.json(AuthSession.self)
        return renewed
    }
}
