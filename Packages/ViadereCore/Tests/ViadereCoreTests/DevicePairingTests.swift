import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// Device pairing (WP-D1, SECURITY.md §2.105) against the independently generated vectors `docs/protocol/vectors/device-pairing-v1.json`
/// (`generate_device_pairing_v1.py`, Python standard library + `cryptography`), plus the exploit paths the shared contract closes.
@Suite("Device pairing (VIADERE-PAIR-V1)")
struct DevicePairingTests {
    static var vectors: [String: Any] {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        let data = try! Data(contentsOf: url.appendingPathComponent("docs/protocol/vectors/device-pairing-v1.json"))
        return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    static var pairingId: DevicePairingID { DevicePairingID(vectors["pairingId"] as! String)! }
    static var nonce: String { vectors["nonce"] as! String }

    static func newDeviceKeys() throws -> [DeviceKeyRegistration] {
        try (vectors["newDeviceKeys"] as! [[String: Any]]).map {
            DeviceKeyRegistration(purpose: DeviceKeyPurpose(rawValue: $0["purpose"] as! String)!, publicKey: try DevicePublicKey(base64URL: $0["publicKey"] as! String),
                                  hardwareBacked: true, proof: $0["proof"] as! String)
        }
    }

    static func approval(_ name: String) throws -> (DevicePairingApproval, expect: String, signingInput: String) {
        let item = try #require((vectors["approvals"] as! [[String: Any]]).first { $0["name"] as? String == name })
        let data = try JSONSerialization.data(withJSONObject: item["approval"]!)
        return (try ViadereJSON.decode(DevicePairingApproval.self, from: data), item["expect"] as! String, item["signingInput"] as! String)
    }

    static var approverKey: DevicePublicKey {
        try! DevicePublicKey(base64URL: (vectors["approver"] as! [String: Any])["approvalBiometricPublicKey"] as! String)
    }

    static var now: Date { Date(timeIntervalSince1970: TimeInterval(vectors["now"] as! Int)) }

    // MARK: Vectors

    @Test func theNewDevicesKeyProofsNameThePairingIdAndVerify() throws {
        let keys = try Self.newDeviceKeys()
        #expect(keys.count == 3)
        let begin = DevicePairingBeginResponse(pairingId: Self.pairingId, challenge: Self.vectors["challenge"] as! String, expiresAt: Self.now,
                                               integrity: IntegrityRequirement(required: [], accepted: []))
        for (key, item) in zip(keys, Self.vectors["newDeviceKeys"] as! [[String: Any]]) {
            let message = DeviceEnrollment.proofMessage(consumerId: begin.proofSubject, challenge: begin.challenge, purpose: key.purpose, publicKey: key.publicKey)
            #expect(String(decoding: message, as: UTF8.self) == item["proofMessage"] as! String)
            #expect(DeviceEnrollment.verify(key, consumerId: begin.proofSubject, challenge: begin.challenge))
            // The same proof does not verify for another subject or challenge.
            #expect(!DeviceEnrollment.verify(key, consumerId: ConsumerID(), challenge: begin.challenge))
        }
    }

    @Test func theComparisonDigestAndCodeMatchThePythonReference() throws {
        let keys = try Self.newDeviceKeys()
        let kld = Self.vectors["keyListDigest"] as! String
        #expect(AppAttestBinding.keyListDigest(keys) == kld)
        #expect(DevicePairing.keyListDigest(keys.map { DevicePairingKey(purpose: $0.purpose, publicKey: $0.publicKey) }) == kld)
        let input = DevicePairing.comparisonInput(pairingId: Self.pairingId, nonce: Self.nonce, keyListDigest: kld)
        #expect(String(decoding: input, as: UTF8.self) == Self.vectors["comparisonInput"] as! String)
        let digest = DevicePairing.comparisonDigest(pairingId: Self.pairingId, nonce: Self.nonce, keys: keys)
        #expect(digest == Self.vectors["comparisonDigest"] as! String)
        #expect(DevicePairing.code(comparisonDigest: digest) == (Self.vectors["code"] as? String))
        for item in Self.vectors["decimal6"] as! [[String: Any]] {
            #expect(DevicePairing.code(comparisonDigest: item["digest"] as! String) == item["code"] as? String)
        }
        #expect(DevicePairing.code(comparisonDigest: "abc") == nil)
    }

    @Test func aSubstitutedNewDeviceKeyGivesAnotherDigestAndCode() throws {
        let sub = Self.vectors["substitution"] as! [String: Any]
        let keys = try (sub["keys"] as! [[String: Any]]).map {
            DevicePairingKey(purpose: DeviceKeyPurpose(rawValue: $0["purpose"] as! String)!, publicKey: try DevicePublicKey(base64URL: $0["publicKey"] as! String))
        }
        let kld = DevicePairing.keyListDigest(keys)
        #expect(kld == sub["keyListDigest"] as! String)
        let digest = DevicePairing.comparisonDigest(pairingId: Self.pairingId, nonce: Self.nonce, keyListDigest: kld)
        #expect(digest == sub["comparisonDigest"] as! String)
        #expect(digest != Self.vectors["comparisonDigest"] as! String)
        #expect(DevicePairing.code(comparisonDigest: digest) == sub["code"] as? String)
        #expect(sub["code"] as? String != Self.vectors["code"] as? String)
    }

    @Test func thePairingCodeNormalizesLikeTheRecoveryAlphabet() {
        for item in Self.vectors["pairingCodeNormalization"] as! [[String: Any]] {
            #expect(DevicePairingCode.normalize(item["input"] as! String) == item["normalized"] as? String, "\(item)")
        }
        let generated = DevicePairingCode.generate()
        #expect(generated.count == 14 && DevicePairingCode.normalize(generated) != nil)
        #expect(DevicePairingCode.generate() != generated)
    }

    @Test func everyApprovalVectorHasItsExpectedOutcome() throws {
        let names = (Self.vectors["approvals"] as! [[String: Any]]).map { $0["name"] as! String }
        #expect(names.count >= 10)
        let kld = Self.vectors["keyListDigest"] as! String
        let stored = try Self.approval("valid").0
        for name in names {
            let (approval, expect, input) = try Self.approval(name)
            #expect(String(decoding: approval.signingInput(), as: UTF8.self) == input, "\(name): signing input")
            var outcome = "valid"
            do {
                try approval.verify(registeredKey: Self.approverKey, now: Self.now)
                if !approval.isBound(accountId: stored.accountId, pairingId: Self.pairingId, nonce: Self.nonce, newDeviceKeys: kld, expiresAt: stored.expiresAt) {
                    outcome = "binding_mismatch"
                } else if !approval.matchesCode(of: DevicePairing.comparisonDigest(pairingId: Self.pairingId, nonce: Self.nonce, keyListDigest: kld)) {
                    outcome = "comparison_mismatch"
                }
            } catch DevicePairingApproval.Failure.badSignature { outcome = "bad_signature" }
            catch DevicePairingApproval.Failure.assuranceTooLow { outcome = "assurance_too_low" }
            catch DevicePairingApproval.Failure.malformed { outcome = "malformed" }
            catch { outcome = "\(error)" }
            #expect(outcome == expect, "\(name)")
        }
    }

    // MARK: Exploit paths (shared contract)

    @Test func anApprovalIsFreshAndSignedOnlyByTheRegisteredBiometricKey() throws {
        let (approval, _, _) = try Self.approval("valid")
        #expect(throws: DevicePairingApproval.Failure.tooOld) { try approval.verify(registeredKey: Self.approverKey, now: Self.now.addingTimeInterval(301)) }
        #expect(throws: DevicePairingApproval.Failure.signedInFuture) { try approval.verify(registeredKey: Self.approverKey, now: Self.now.addingTimeInterval(-61)) }
        // A statement naming one key but verified against another registered key (another device of the account) is refused.
        #expect(throws: DevicePairingApproval.Failure.wrongKey) { try approval.verify(registeredKey: SoftwareP256SigningKey().publicKey, now: Self.now) }
    }

    @Test func aRequestWhoseDigestsDoNotFollowFromItsKeysIsNotSigned() async throws {
        let keys = try Self.newDeviceKeys().map { DevicePairingKey(purpose: $0.purpose, publicKey: $0.publicKey) }
        let kld = DevicePairing.keyListDigest(keys)
        var request = DevicePairingRequest(pairingId: Self.pairingId, accountId: ConsumerID(), nonce: Self.nonce, deviceName: "iPhone", platform: .iOS,
                                           keys: keys, newDeviceKeys: kld,
                                           comparisonDigest: DevicePairing.comparisonDigest(pairingId: Self.pairingId, nonce: Self.nonce, keyListDigest: kld),
                                           requestedAt: Self.now, expiresAt: Self.now.addingTimeInterval(300), attemptsRemaining: 3, fatigueWarning: false,
                                           integrityVerified: true)
        #expect(request.isConsistent)
        var swapped = request
        swapped.keys[0] = DevicePairingKey(purpose: keys[0].purpose, publicKey: SoftwareP256SigningKey().publicKey)
        #expect(!swapped.isConsistent, "keys swapped under the server's digests")
        var digest = request
        digest.comparisonDigest = String(repeating: "0", count: 64)
        #expect(!digest.isConsistent)

        // A round trip: what a trusted device signs is bound to exactly this request and verifies.
        let key = SoftwareP256SigningKey()
        let device = DeviceID()
        let signed = try await DevicePairingApproval.sign(request: request, approverDeviceId: device, match: "123456", key: key, now: Self.now)
        try signed.verify(registeredKey: key.publicKey, now: Self.now)
        #expect(signed.isBound(accountId: request.accountId, pairingId: request.pairingId, nonce: request.nonce, newDeviceKeys: kld, expiresAt: request.expiresAt))
        #expect(!signed.isBound(accountId: ConsumerID(), pairingId: request.pairingId, nonce: request.nonce, newDeviceKeys: kld, expiresAt: request.expiresAt))
        #expect(!signed.isBound(accountId: request.accountId, pairingId: DevicePairingID(), nonce: request.nonce, newDeviceKeys: kld, expiresAt: request.expiresAt))
        #expect(!signed.isBound(accountId: request.accountId, pairingId: request.pairingId, nonce: request.nonce, newDeviceKeys: kld,
                                expiresAt: request.expiresAt.addingTimeInterval(60)), "a longer expiry than the server's")
        request.nonce = Base64URL.encode(Data(repeating: 9, count: 32))
        #expect(!signed.isBound(accountId: request.accountId, pairingId: request.pairingId, nonce: request.nonce, newDeviceKeys: kld, expiresAt: request.expiresAt))
        // Wire round trip.
        let decoded = try ViadereJSON.decode(DevicePairingApproval.self, from: try ViadereJSON.encode(signed))
        #expect(decoded == signed)
        try decoded.verify(registeredKey: key.publicKey, now: Self.now)
    }

    @Test func theStartRequestHasNoAccountOrTierField() throws {
        let request = DevicePairingStartRequest(challenge: "c", pairingCode: "ABCD-EFGH-JKMN", platform: .iOS, deviceName: nil, keys: [], integrity: nil)
        let object = try #require(try JSONSerialization.jsonObject(with: try ViadereJSON.encode(request)) as? [String: Any])
        #expect(Set(object.keys).isSubset(of: ["challenge", "pairingCode", "platform", "deviceName", "keys", "integrity"]))
        // Extra members a client adds are not part of the contract.
        let extra = try ViadereJSON.decode(DevicePairingStartRequest.self, from: Data(#"{"challenge":"c","pairingCode":"x","platform":"iOS","keys":[],"trustTier":"d1","accountId":"6f1c2a4e-9b3d-4c5e-8f70-112233445566"}"#.utf8))
        #expect(extra.pairingCode == "x")
        #expect(DevicePairingState(rawValue: "approved") == .approved)
        #expect(try ViadereJSON.decode(DevicePairingState.self, from: Data(#""elevated""#.utf8)) == .unknown)
    }

    @Test func theRoutesAreInTheCatalogWithTheRightAuthentication() {
        let byName = Dictionary(uniqueKeysWithValues: APIRoutes.all.map { ($0.name, $0) })
        #expect(byName["devicePairings.begin"]?.auth == AuthRequirement.none)
        #expect(byName["devicePairings.start"]?.auth == AuthRequirement.none)
        #expect(byName["devicePairings.invite"]?.auth == .deviceSignedBearer)
        #expect(byName["devicePairings.pending"]?.auth == .deviceSignedBearer)
        #expect(byName["devicePairings.approve"]?.auth == .deviceSignedBearer)
        #expect(byName["devicePairings.deny"]?.auth == .deviceSignedBearer)
    }
}
