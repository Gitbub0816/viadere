import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// Device pairing on the devices (WP-D1, SECURITY.md §2.105): the new device shows a code from its own keys only, stores nothing unless the
/// added device holds exactly its keys; the trusted device never holds the code, signs only a consistent request of its own account, and keeps
/// Deny / This wasn't me / Add device equal with the safe actions first.
@Suite("Device pairing (Kit)")
@MainActor
struct DevicePairingKitTests {
    struct NewDeviceEnv {
        let api = MockDevicePairingAPI()
        let keys = SoftwareDeviceKeyStore(secrets: InMemorySecretStore())
        let secrets = InMemorySecretStore()
        let records: SecretDeviceRecordStore
        let tokens: SecretTokenStore
        let sessions: SessionManager
        let preferences = InMemoryPreferences()
        let pairing: NewDevicePairing

        init() {
            records = SecretDeviceRecordStore(secrets: secrets)
            tokens = SecretTokenStore(secrets: secrets)
            sessions = SessionManager(store: tokens, refresher: CountingRefresher())
            pairing = NewDevicePairing(api: api, keys: keys, records: records, sessions: sessions, preferences: preferences, skipsAttestationWhenUnsupported: true,
                                       clock: { Date(timeIntervalSince1970: 1_800_000_000) })
        }
    }

    nonisolated static let now = Date(timeIntervalSince1970: 1_800_000_000)

    // MARK: New device

    @Test func theNewDeviceShowsTheCodeOfItsOwnKeysAndSendsNoAccountOrTier() async throws {
        let env = NewDeviceEnv()
        let started = try await env.pairing.start(code: "abcd-efgh-jkmn", deviceName: "  My iPhone  ")
        let sent = try #require(await env.api.startRequests.first)
        #expect(sent.pairingCode == "abcd-efgh-jkmn")
        #expect(sent.deviceName == "My iPhone")
        // Proofs name the pairing id (never an account id).
        for key in sent.keys { #expect(DeviceEnrollment.verify(key, consumerId: ConsumerID(env.api.pairingId.uuid), challenge: env.api.challenge)) }
        let expected = DevicePairing.code(comparisonDigest: DevicePairing.comparisonDigest(pairingId: env.api.pairingId, nonce: await env.api.nonce, keys: sent.keys))
        #expect(started.code == expected)
        let object = try #require(try JSONSerialization.jsonObject(with: try ViadereJSON.encode(sent)) as? [String: Any])
        #expect(object["trustTier"] == nil && object["accountId"] == nil && object["consumerId"] == nil)
    }

    @Test func aMalformedCodeIsRefusedLocallyAndAFailedStartLeavesNoKeys() async throws {
        let env = NewDeviceEnv()
        await #expect(throws: DevicePairingError.invalidCode) { _ = try await env.pairing.start(code: "nope", deviceName: nil) }
        await env.api.set(startError: .noTrustedDevice)
        await #expect(throws: DevicePairingError.noTrustedDevice) { _ = try await env.pairing.start(code: "ABCD-EFGH-JKMN", deviceName: nil) }
        #expect(try await env.keys.existingKey(for: .request) == nil, "keys made for a refused pairing are deleted")
    }

    @Test func theSessionIsStoredOnlyWhenTheAddedDeviceHoldsExactlyThisDevicesKeys() async throws {
        let env = NewDeviceEnv()
        let started = try await env.pairing.start(code: "ABCD-EFGH-JKMN", deviceName: nil)
        let account = ConsumerID()
        let session = AuthSession(consumerId: account, accessToken: "access", expiresAt: Self.now.addingTimeInterval(900), refreshToken: "refresh")
        // A device with someone else's keys (a substituted registration): refused, nothing stored, keys wiped.
        let foreign = Device(id: DeviceID(), consumerId: account, name: "x", platform: .iOS,
                             keys: [DeviceKey(id: DeviceKeyID(), purpose: .request, publicKey: SoftwareP256SigningKey().publicKey, hardwareBacked: true, createdAt: Self.now)],
                             createdAt: Self.now)
        await env.api.set(statuses: [.approved], device: foreign, session: session)
        await #expect(throws: DevicePairingError.mismatch) { _ = try await env.pairing.poll(started) }
        #expect(await env.sessions.tokens() == nil)
        #expect(try await env.records.load() == nil)

        let env2 = NewDeviceEnv()
        let started2 = try await env2.pairing.start(code: "ABCD-EFGH-JKMN", deviceName: nil)
        let own = Device(id: DeviceID(), consumerId: account, name: "New iPhone", platform: .iOS,
                         keys: started2.publicKeys.map { DeviceKey(id: DeviceKeyID(), purpose: $0.key, publicKey: $0.value, hardwareBacked: true, createdAt: Self.now) },
                         createdAt: Self.now, trustTier: .d1)
        await env2.api.set(statuses: [.pending, .approved], device: own, session: session)
        #expect(try await env2.pairing.poll(started2) == .pending)
        #expect(try await env2.pairing.poll(started2) == .approved)
        #expect(await env2.sessions.tokens()?.accessToken == "access")
        let record = try #require(try await env2.records.load())
        #expect(record.deviceId == own.id && record.consumerId == account)
        #expect(Set(record.purposes) == Set(started2.purposes))
    }

    @Test func theNewDeviceViewModelWalksCodeEntryCodeAndResult() async throws {
        let env = NewDeviceEnv()
        let vm = NewDevicePairingViewModel(pairing: env.pairing, now: { Self.now }, sleep: { _ in })
        #expect(vm.phase == .enteringCode && !vm.canContinue)
        vm.edit("ABCD-EFGH-JKMN<script>")
        #expect(vm.entry.isEmpty, "only letters, digits, dashes and spaces")
        vm.edit("abcd-efgh-jkmn")
        #expect(vm.canContinue)
        await vm.start()
        guard case .showing(let code) = vm.phase else { Issue.record("shows the code"); return }
        #expect(code.count == 6)
        #expect(vm.title.contains(DeviceAddCode.display(code)))
        #expect(vm.spokenCode == DeviceAddCode.spoken(code))
        await env.api.set(statuses: [.pending, .denied])
        await vm.waitForResult(interval: .zero)
        #expect(vm.phase == .declined)
        #expect(vm.resultLine == PairingCopy.declined)
    }

    @Test func noTrustedDeviceOffersTheRecoveryPath() async {
        let env = NewDeviceEnv()
        await env.api.set(startError: .noTrustedDevice)
        let vm = NewDevicePairingViewModel(pairing: env.pairing, now: { Self.now }, sleep: { _ in })
        vm.edit("ABCD-EFGH-JKMN")
        await vm.start()
        #expect(vm.phase == .noTrustedDevice)
        #expect(vm.resultLine?.contains("account recovery") == true)
    }

    // MARK: Trusted device

    static func request(account: ConsumerID, expiresAt: Date = Date(timeIntervalSince1970: 1_800_000_300), fatigue: Bool = false) -> DevicePairingRequest {
        let keys = [DevicePairingKey(purpose: .request, publicKey: SoftwareP256SigningKey().publicKey),
                    DevicePairingKey(purpose: .approvalBiometric, publicKey: SoftwareP256SigningKey().publicKey)]
        let id = DevicePairingID()
        let nonce = Base64URL.encode(Data(repeating: 5, count: 32))
        let kld = DevicePairing.keyListDigest(keys)
        return DevicePairingRequest(pairingId: id, accountId: account, nonce: nonce, deviceName: "New\u{202E}iPhone", platform: .iOS, keys: keys,
                                    newDeviceKeys: kld, comparisonDigest: DevicePairing.comparisonDigest(pairingId: id, nonce: nonce, keyListDigest: kld),
                                    requestedAt: now, expiresAt: expiresAt, attemptsRemaining: 3, fatigueWarning: fatigue, integrityVerified: true)
    }

    struct RecordingSigner: PairingApprovalSigning {
        let key = SoftwareP256SigningKey()
        let device = DeviceID()
        func sign(request: DevicePairingRequest, match: String) async throws -> DevicePairingApproval {
            try await DevicePairingApproval.sign(request: request, approverDeviceId: device, match: match, key: key, now: DevicePairingKitTests.now)
        }
    }

    @Test func theApprovingDeviceHasNoCodeAndKeepsEqualButtonsWithTheSafeActionsFirst() async throws {
        let account = ConsumerID()
        let vm = PairingApprovalViewModel(request: Self.request(account: account, fatigue: true), ownAccountId: account, api: MockDevicePairingAPI(),
                                          signer: RecordingSigner(), now: Self.now, timeText: { _ in "10:00" })
        #expect(vm.phase == .entering)
        #expect(vm.buttons.map(\.role) == [.deny, .notMe, .proceed])
        #expect(Set(vm.buttons.map(\.style)).count == 1, "one look for every button")
        #expect(vm.buttons.map(\.isEnabled) == [true, true, false], "Add device disabled, not hidden, until six digits")
        #expect(!vm.nameRow.contains("\u{202E}"), "reported text is sanitized")
        #expect(vm.fatigueWarning == PairingCopy.fatigueWarning)
        #expect(vm.requestedRow == "Requested at 10:00")
        // No member exposes the code: the digest is in the request only to be recomputed, never displayed.
        let code = DevicePairing.code(comparisonDigest: vm.request.comparisonDigest)!
        for text in [vm.title, vm.nameRow, vm.helper, vm.fieldLabel, vm.requestedRow, vm.expiresRow, vm.integrityRow, vm.safeLine] {
            #expect(!text.contains(code))
        }
        vm.edit("1")
        vm.edit("12")
        vm.edit("123456")
        #expect(vm.entry == "12", "paste is refused")
    }

    @Test func aRequestOfAnotherAccountOrWithInconsistentDigestsIsNeverSigned() async throws {
        let account = ConsumerID()
        let api = MockDevicePairingAPI()
        let other = PairingApprovalViewModel(request: Self.request(account: ConsumerID()), ownAccountId: account, api: api, signer: RecordingSigner(), now: Self.now)
        #expect(other.phase == .refused)
        var tampered = Self.request(account: account)
        tampered.keys[0] = DevicePairingKey(purpose: .request, publicKey: SoftwareP256SigningKey().publicKey)
        let swapped = PairingApprovalViewModel(request: tampered, ownAccountId: account, api: api, signer: RecordingSigner(), now: Self.now)
        #expect(swapped.phase == .refused)
        let late = PairingApprovalViewModel(request: Self.request(account: account, expiresAt: Self.now), ownAccountId: account, api: api,
                                            signer: RecordingSigner(), now: Self.now)
        #expect(late.phase == .refused)
        for vm in [other, swapped, late] {
            for digit in "123456" { vm.edit(vm.entry + String(digit)) }
            await vm.add()
        }
        #expect(await api.approvals.isEmpty, "nothing was signed or sent")
    }

    @Test func wrongNumbersCountDownAndTheThirdEndsThePairing() async throws {
        let account = ConsumerID()
        let api = MockDevicePairingAPI()
        await api.set(approveErrors: [.wrongNumber, .wrongNumber, .wrongNumber])
        let vm = PairingApprovalViewModel(request: Self.request(account: account), ownAccountId: account, api: api, signer: RecordingSigner(), now: Self.now)
        for attempt in 1...3 {
            for digit in "654321" { vm.edit(vm.entry + String(digit)) }
            await vm.add()
            if attempt < 3 {
                #expect(vm.phase == .entering && vm.notice == AuthDeliveryCopy.deviceWrongNumber && vm.entry.isEmpty)
            }
        }
        #expect(vm.phase == .ended)
        let approvals = await api.approvals
        #expect(approvals.count == 3)
        #expect(approvals.allSatisfy { $0.match == "654321" && $0.accountId == account && $0.assurance == .biometric })
    }

    @Test func approveDenyAndThisWasntMe() async throws {
        let account = ConsumerID()
        let api = MockDevicePairingAPI()
        let signer = RecordingSigner()
        let request = Self.request(account: account)
        let vm = PairingApprovalViewModel(request: request, ownAccountId: account, api: api, signer: signer, now: Self.now)
        for digit in "012345" { vm.edit(vm.entry + String(digit)) }
        #expect(vm.entry == "012345", "leading zeros are allowed")
        await vm.add()
        #expect(vm.phase == .added)
        let approval = try #require(await api.approvals.first)
        try approval.verify(registeredKey: signer.key.publicKey, now: Self.now)
        #expect(approval.isBound(accountId: account, pairingId: request.pairingId, nonce: request.nonce, newDeviceKeys: request.newDeviceKeys,
                                 expiresAt: request.expiresAt))

        let deny = PairingApprovalViewModel(request: Self.request(account: account), ownAccountId: account, api: api, signer: signer, now: Self.now)
        await deny.deny()
        #expect(deny.phase == .denied)
        let report = PairingApprovalViewModel(request: Self.request(account: account), ownAccountId: account, api: api, signer: signer, now: Self.now)
        await report.thisWasntMe()
        #expect(report.phase == .reported && report.resultLine == PairingCopy.reportedResult)
        #expect(await api.denials.map(\.1) == [false, true])
    }

    @Test func theInviteScreenShowsTheCodeOrTheRecoveryPath() async {
        let api = MockDevicePairingAPI()
        let vm = AddDeviceInviteViewModel(api: api, timeText: { _ in "10:10" })
        await vm.create()
        #expect(vm.phase == .showing(code: "ABCD-EFGH-JKMN", expiresAt: Date(timeIntervalSince1970: 1_800_000_600)))
        #expect(vm.expiryLine == "Works until 10:10. Don't share it with anyone.")
        await api.set(inviteError: .noTrustedDevice)
        let none = AddDeviceInviteViewModel(api: api)
        await none.create()
        #expect(none.phase == .noTrustedDevice)
    }

    @Test func theLiveClientMapsServerErrors() {
        #expect(DevicePairingError.from(APIError.server(status: 409, code: .noTrustedDevice, message: "")) == .noTrustedDevice)
        #expect(DevicePairingError.from(APIError.server(status: 409, code: .comparisonMismatch, message: "")) == .wrongNumber)
        #expect(DevicePairingError.from(APIError.server(status: 409, code: .pairingMismatch, message: "")) == .mismatch)
        #expect(DevicePairingError.from(APIError.server(status: 403, code: .deviceCoolDown, message: "")) == .notTrusted)
        #expect(DevicePairingError.from(APIError.server(status: 410, code: .expired, message: "")) == .expired)
        #expect(DevicePairingError.from(APIError.transport("x")) == .offline)
    }
}
