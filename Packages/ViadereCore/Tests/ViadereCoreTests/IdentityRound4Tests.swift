import Crypto
import Foundation
import Testing
@testable import ViadereCore

@Suite("Identity round 4 contracts")
struct IdentityRound4Tests {
    func registration(_ purpose: DeviceKeyPurpose, key: SoftwareP256SigningKey) -> DeviceKeyRegistration {
        DeviceKeyRegistration(purpose: purpose, publicKey: key.publicKey, hardwareBacked: true, proof: "x")
    }

    @Test func appAttestClientDataBindsChallengeAccountAndEveryKey() {
        let consumer = ConsumerID()
        let a = SoftwareP256SigningKey(), b = SoftwareP256SigningKey(), c = SoftwareP256SigningKey()
        let keys = [registration(.request, key: a), registration(.approvalBiometric, key: b)]
        let data = String(decoding: AppAttestBinding.clientData(consumerId: consumer, challenge: "chal", keys: keys), as: UTF8.self)
        #expect(data.hasPrefix("VIADERE-APPATTEST-ENROLL-V1\n\(consumer)\nchal\n"))
        #expect(data.split(separator: "\n").last.map(String.init) == AppAttestBinding.keyListDigest(keys))
        let base = AppAttestBinding.clientDataHash(consumerId: consumer, challenge: "chal", keys: keys)
        #expect(base.count == 32)
        // Order of the list does not matter, content does.
        #expect(AppAttestBinding.clientDataHash(consumerId: consumer, challenge: "chal", keys: keys.reversed()) == base)
        #expect(AppAttestBinding.clientDataHash(consumerId: consumer, challenge: "other", keys: keys) != base)
        #expect(AppAttestBinding.clientDataHash(consumerId: ConsumerID(), challenge: "chal", keys: keys) != base)
        let swapped = [registration(.request, key: a), registration(.approvalBiometric, key: c)]
        #expect(AppAttestBinding.clientDataHash(consumerId: consumer, challenge: "chal", keys: swapped) != base)
        let extra = keys + [registration(.approvalUserPresence, key: c)]
        #expect(AppAttestBinding.clientDataHash(consumerId: consumer, challenge: "chal", keys: extra) != base)
        // A key moved to another purpose is a different list.
        let moved = [registration(.approvalUserPresence, key: a), registration(.approvalBiometric, key: b)]
        #expect(AppAttestBinding.clientDataHash(consumerId: consumer, challenge: "chal", keys: moved) != base)
    }

    @Test func recoveryCodeFormats() throws {
        for _ in 0..<50 {
            let code = RecoveryCodeFormat.generateCode()
            #expect(code.count == 11 && code.dropFirst(5).first == "-")
            #expect(RecoveryCodeFormat.normalizeCode(code) != nil)
            #expect(RecoveryCodeFormat.normalizeCode(code.lowercased()) == RecoveryCodeFormat.normalizeCode(code))
            let id = RecoveryCodeFormat.generateRecoveryID()
            #expect(id.count == 14)
            #expect(RecoveryCodeFormat.normalizeRecoveryID(id)?.count == 12)
        }
        #expect(RecoveryCodeFormat.normalizeCode("abcde fghjk") == "ABCDEFGHJK")
        #expect(RecoveryCodeFormat.normalizeCode("OIL00-00000") == "01100" + "00000")
        #expect(RecoveryCodeFormat.normalizeCode("ABCDE-FGHJ") == nil)
        #expect(RecoveryCodeFormat.normalizeCode("ABCDE-FGHJU") == nil, "U is not in the alphabet")
        #expect(RecoveryCodeFormat.normalizeCode(String(repeating: "A", count: 100)) == nil)
        #expect(RecoveryCodeFormat.normalizeRecoveryID("ABCD-EFGH-JKM") == nil)
    }

    @Test func newDTOsAreAdditiveAndRoundTrip() throws {
        // An old server's session (no recovery codes) still decodes; a new one carries them.
        let session = AuthSession(consumerId: ConsumerID(), accessToken: "vda_x", expiresAt: Fixtures.now)
        let encoded = try ViadereJSON.encode(session)
        #expect(!String(decoding: encoded, as: UTF8.self).contains("recoveryCodes"))
        var withCodes = session
        withCodes.recoveryCodes = RecoveryCodeSet(recoveryId: "ABCD-EFGH-JKMN", codes: [RecoveryCodeFormat.generateCode()], issuedAt: Fixtures.now)
        let back = try ViadereJSON.decode(AuthSession.self, from: try ViadereJSON.encode(withCodes))
        #expect(back.recoveryCodes?.recoveryId == "ABCD-EFGH-JKMN")
        // Unknown notice kinds / actions decode leniently.
        let json = #"{"id":"\#(UUID().uuidString.lowercased())","kind":"somethingNew","message":"m","createdAt":"2027-01-15T08:00:00.000Z","action":"newAction"}"#
        let notice = try ViadereJSON.decode(SecurityNotice.self, from: Data(json.utf8))
        #expect(notice.kind == .unknown && notice.action == .unknown)
        // Device: pending replacement fields round-trip and are optional.
        let device = Device(id: DeviceID(), consumerId: ConsumerID(), name: "Phone", platform: .iOS, keys: [], createdAt: Fixtures.now,
                            pendingReplacementBy: DeviceID(), pendingReplacementAt: Fixtures.now)
        let decoded = try ViadereJSON.decode(Device.self, from: try ViadereJSON.encode(device))
        #expect(decoded.pendingReplacementBy == device.pendingReplacementBy)
        #expect(APIRoutes.all.contains { $0.name == "recovery.begin" && $0.auth == .none })
        #expect(APIRoutes.all.contains { $0.name == "recovery.codes.regenerate" && $0.auth == .deviceSignedBearer })
        #expect(APIRoutes.all.contains { $0.name == "devices.replacement.cancel" && $0.auth == .deviceSignedBearer })
        #expect(RecoveryPolicy.holdSeconds == 72 * 3600 && RecoveryPolicy.codeCount == 10)
    }
}
