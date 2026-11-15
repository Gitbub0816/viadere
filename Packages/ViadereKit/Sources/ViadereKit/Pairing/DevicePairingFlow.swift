import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

// Device pairing (WP-D1, SECURITY.md §2.107, UX_COPY S-DEV-03..05 and S-PAIR-01..08).
//
// * Trusted device (A): Settings → Trusted devices → "Add another device" makes a pairing code (`AddDeviceInviteViewModel`); the request then
//   arrives by push and in Alerts and is answered on `PairingApprovalViewModel`, which asks for the number shown on the new device and **never
//   shows or holds the code** (it signs only what the person typed).
// * New device (B): onboarding → "I already use Viadere" (`NewDevicePairingViewModel`). The code it shows comes from its **own** keys, the
//   pairing id and the server's nonce, never from anything else the server says.

public enum PairingCopy {
    public static let inviteTitle = "Add another device"
    public static let inviteBody = "On the new device, open Viadere, choose I already use Viadere and enter this code. It works once."
    public static func inviteExpires(_ time: String) -> String { "Works until \(time). Don't share it with anyone." }
    public static let inviteAction = "Show a code"
    public static let noTrustedDevice = "None of your devices can approve a new one. To get back into your account, use account recovery with your recovery codes."
    public static let recoveryAction = "Use account recovery"
    public static let codeEntryTitle = "Enter the code from your other device"
    public static let codeEntryHelper = "On a device that already uses Viadere, open Settings, then Trusted devices, then Add another device."
    public static let codeFieldLabel = "Code"
    public static let continueAction = "Continue"
    public static let invalidCode = "This code didn't work. Check it on your other device, or make a new one there."
    public static let waiting = "Waiting for your other device…"
    public static let cancelAction = "Cancel"
    public static let added = "This device was added to your account."
    public static let declined = "Your other device didn't add this one. Nothing was added."
    public static let expired = "This request expired and nothing was added. Make a new code on your other device."
    public static let cancelled = "Nothing was added."
    public static let attestation = "This device could not be verified. Update Viadere and try again on a genuine device."
    // Approving device
    public static func requestedAt(_ time: String) -> String { "Requested at \(time)" }
    public static func expiresAt(_ time: String) -> String { "Expires at \(time)" }
    public static let integrityVerified = "Viadere verified this is a genuine Apple device."
    public static let integrityUnverified = "Viadere couldn't verify this device."
    public static let fatigueWarning = "You've had several requests to add a device. Only continue if you're setting one up right now."
    public static let deny = "Deny"
    public static let safeLine = "Deny says no. This wasn't me also reports it."
    public static let deniedResult = "Nothing was added."
    public static let reportedResult = "Nothing was added. Your devices were told."
    public static let addedResult = "The new device was added. Your other devices were told."
    public static let needsFaceID = "Adding a device needs Face ID or Touch ID on this device."
    public static let notTrusted = "Only a device you already trust can add a new one."
    public static let mismatch = "This request doesn't match the new device, so nothing was added. Start again on the new device."
    public static let alertsLine = "A device is asking to join your account."
}

// MARK: - New device (B)

/// The new device's part: keys, proofs, attestation, start, poll; on approval it stores the session and the device record.
public struct NewDevicePairing: Sendable {
    public struct Started: Sendable, Equatable {
        public var pairingId: DevicePairingID
        public var code: String
        public var expiresAt: Date
        public var statusToken: String
        public var purposes: [DeviceKeyPurpose]
        public var publicKeys: [DeviceKeyPurpose: DevicePublicKey]
        public var appAttestKeyId: String?
    }

    let api: any DevicePairingAPI
    let keys: any DeviceKeyStore
    let records: any DeviceRecordStore
    let sessions: SessionManager
    let preferences: any PreferencesStore
    let appAttest: any AppAttestProviding
    let skipsAttestationWhenUnsupported: Bool
    let platform: DevicePlatform
    let clock: @Sendable () -> Date

    public init(api: any DevicePairingAPI, keys: any DeviceKeyStore, records: any DeviceRecordStore, sessions: SessionManager,
                preferences: any PreferencesStore, appAttest: any AppAttestProviding = UnavailableAppAttest(),
                skipsAttestationWhenUnsupported: Bool = AppAttestPolicy.skipsWhenUnsupported, platform: DevicePlatform = .iOS,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.keys = keys
        self.records = records
        self.sessions = sessions
        self.preferences = preferences
        self.appAttest = appAttest
        self.skipsAttestationWhenUnsupported = skipsAttestationWhenUnsupported
        self.platform = platform
        self.clock = clock
    }

    /// Begin, create this device's keys (non-exportable where the hardware allows), prove them over the pairing id, attest, start with `code`.
    public func start(code: String, deviceName: String?) async throws -> Started {
        guard DevicePairingCode.normalize(code) != nil else { throw DevicePairingError.invalidCode }
        let opened = try await api.begin()
        let provisioned: DeviceKeyProvisioner.Result
        do {
            provisioned = try await DeviceKeyProvisioner(store: keys).provision(consumerId: opened.proofSubject, challenge: opened.challenge)
        } catch { throw DevicePairingError.failed }
        let evidence: AppAttestEvidence?
        do {
            evidence = try await EnrollmentAttester(provider: appAttest, skipsWhenUnsupported: skipsAttestationWhenUnsupported)
                .evidence(consumerId: opened.proofSubject, challenge: opened.challenge, keys: provisioned.registrations)
        } catch {
            try? await keys.deleteAllKeys()
            throw DevicePairingError.attestationRequired
        }
        let name = deviceName.map { String($0.trimmingCharacters(in: .whitespacesAndNewlines).prefix(64)) }.flatMap { $0.isEmpty ? nil : $0 }
        let started: DevicePairingStartResponse
        do {
            started = try await api.start(opened.pairingId, DevicePairingStartRequest(
                challenge: opened.challenge, pairingCode: code, platform: platform, deviceName: name, keys: provisioned.registrations,
                integrity: evidence.map(IntegrityEvidence.init(appleAppAttest:))))
        } catch {
            // Nothing was stored for these keys: they are useless now.
            try? await keys.deleteAllKeys()
            throw DevicePairingError.from(error)
        }
        guard started.pairingId == opened.pairingId, DevicePairing.isNonce(started.nonce) else {
            try? await keys.deleteAllKeys()
            throw DevicePairingError.mismatch
        }
        // The code comes from this device's own keys: a server or relay that swapped them cannot make this device show their code.
        let digest = DevicePairing.comparisonDigest(pairingId: opened.pairingId, nonce: started.nonce, keys: provisioned.registrations)
        guard let shown = DevicePairing.code(comparisonDigest: digest) else { throw DevicePairingError.failed }
        return Started(pairingId: opened.pairingId, code: shown, expiresAt: started.expiresAt, statusToken: started.statusToken,
                       purposes: provisioned.registrations.map(\.purpose),
                       publicKeys: Dictionary(uniqueKeysWithValues: provisioned.registrations.map { ($0.purpose, $0.publicKey) }),
                       appAttestKeyId: evidence?.keyId)
    }

    /// One poll. On approval (the first answer that carries the session) the session and the device record are stored, but only if the
    /// device the server added holds exactly this device's keys.
    public func poll(_ started: Started) async throws -> DevicePairingState {
        let status: DevicePairingStatus
        do { status = try await api.status(started.pairingId, token: started.statusToken) } catch { throw DevicePairingError.from(error) }
        switch status.state {
        case .approved:
            guard let session = status.session, let device = status.device else { return .pending }
            let theirs = Dictionary(uniqueKeysWithValues: device.keys.map { ($0.purpose, $0.publicKey) })
            guard theirs == started.publicKeys, session.consumerId == device.consumerId else {
                try? await keys.deleteAllKeys()
                throw DevicePairingError.mismatch
            }
            try await sessions.set(TokenSet(session))
            preferences.setString(session.consumerId.description, for: .lastKnownConsumerId)
            try await records.save(DeviceRecord(deviceId: device.id, consumerId: device.consumerId, name: device.name, purposes: started.purposes,
                                                enrolledAt: clock(), appAttestKeyId: started.appAttestKeyId))
            return .approved
        case .pending:
            return .pending
        default:
            try? await keys.deleteAllKeys()
            return status.state
        }
    }

    public func cancel(_ started: Started) async {
        _ = try? await api.cancel(started.pairingId, token: started.statusToken)
        try? await keys.deleteAllKeys()
    }
}

@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class NewDevicePairingViewModel {
    public enum Phase: Sendable, Equatable {
        case enteringCode
        case starting
        case showing(code: String)
        case added
        case declined
        case expired
        case ended
        case noTrustedDevice
    }

    public private(set) var phase: Phase = .enteringCode
    public private(set) var entry = ""
    public private(set) var notice: String?
    private var started: NewDevicePairing.Started?
    private let pairing: NewDevicePairing
    private let deviceName: String?
    private let sleep: @Sendable (Duration) async -> Void
    private let now: @Sendable () -> Date

    public init(pairing: NewDevicePairing, deviceName: String? = nil, now: @escaping @Sendable () -> Date = { Date() },
                sleep: @escaping @Sendable (Duration) async -> Void = { try? await Task.sleep(for: $0) }) {
        self.pairing = pairing
        self.deviceName = deviceName
        self.now = now
        self.sleep = sleep
    }

    public var title: String {
        if case .showing(let code) = phase { return AuthDeliveryCopy.newDeviceCodeTitle(code: DeviceAddCode.display(code)) }
        return PairingCopy.codeEntryTitle
    }
    public var displayCode: String? { if case .showing(let code) = phase { return DeviceAddCode.display(code) } else { return nil } }
    public var spokenCode: String? { if case .showing(let code) = phase { return DeviceAddCode.spoken(code) } else { return nil } }
    public var canContinue: Bool { phase == .enteringCode && DevicePairingCode.normalize(entry) != nil }

    public var resultLine: String? {
        switch phase {
        case .added: PairingCopy.added
        case .declined: PairingCopy.declined
        case .expired: PairingCopy.expired
        case .ended: AuthDeliveryCopy.deviceWrongNumberFinal
        case .noTrustedDevice: PairingCopy.noTrustedDevice
        default: nil
        }
    }

    /// Letters, digits, spaces and dashes only, at most 14 characters (`XXXX-XXXX-XXXX`).
    public func edit(_ proposed: String) {
        guard phase == .enteringCode, proposed.count <= 14,
              proposed.unicodeScalars.allSatisfy({ ($0.isASCII && ($0.properties.isAlphabetic || ("0"..."9").contains($0))) || $0 == "-" || $0 == " " }) else { return }
        entry = proposed.uppercased()
    }

    public func start() async {
        guard canContinue else { return }
        phase = .starting
        notice = nil
        do {
            let started = try await pairing.start(code: entry, deviceName: deviceName)
            self.started = started
            phase = .showing(code: started.code)
        } catch let error as DevicePairingError {
            switch error {
            case .noTrustedDevice: phase = .noTrustedDevice
            case .attestationRequired: phase = .enteringCode; notice = PairingCopy.attestation
            case .offline: phase = .enteringCode; notice = AuthDeliveryCopy.offline
            case .rateLimited: phase = .enteringCode; notice = "Too many attempts. Please wait a moment."
            default: phase = .enteringCode; notice = PairingCopy.invalidCode
            }
        } catch {
            phase = .enteringCode
            notice = PairingCopy.invalidCode
        }
    }

    /// Polls every 2 seconds until the pairing is answered or expires (no countdown is shown).
    public func waitForResult(interval: Duration = .seconds(2)) async {
        guard let started else { return }
        while case .showing = phase {
            if now() > started.expiresAt.addingTimeInterval(5) { phase = .expired; await pairing.cancel(started); return }
            do {
                switch try await pairing.poll(started) {
                case .pending: break
                case .approved: phase = .added; return
                case .denied: phase = .declined; return
                case .expired: phase = .expired; return
                case .failed: phase = .ended; return
                default: phase = .ended; return
                }
            } catch DevicePairingError.mismatch {
                phase = .ended
                return
            } catch {
                // Offline for a moment: keep showing the code and try again.
            }
            await sleep(interval)
        }
    }

    public func cancel() async {
        guard let started, case .showing = phase else { return }
        await pairing.cancel(started)
        phase = .ended
    }
}

// MARK: - Trusted device (A): the pairing code

@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class AddDeviceInviteViewModel {
    public enum Phase: Sendable, Equatable {
        case idle, creating
        case showing(code: String, expiresAt: Date)
        case noTrustedDevice
        case failed(String)
    }

    public private(set) var phase: Phase = .idle
    private let api: any DevicePairingAPI
    private let timeText: @Sendable (Date) -> String

    public init(api: any DevicePairingAPI, timeText: @escaping @Sendable (Date) -> String = PairingTime.short) {
        self.api = api
        self.timeText = timeText
    }

    public var expiryLine: String? { if case .showing(_, let at) = phase { return PairingCopy.inviteExpires(timeText(at)) } else { return nil } }

    public func create() async {
        guard phase != .creating else { return }
        phase = .creating
        do {
            let invitation = try await api.invite()
            phase = .showing(code: invitation.code, expiresAt: invitation.expiresAt)
        } catch let error as DevicePairingError {
            switch error {
            case .noTrustedDevice: phase = .noTrustedDevice
            case .notTrusted: phase = .failed(PairingCopy.notTrusted)
            case .offline: phase = .failed(AuthDeliveryCopy.offline)
            case .rateLimited: phase = .failed("Too many attempts. Please wait a moment.")
            default: phase = .failed("Something went wrong. Please try again.")
            }
        } catch {
            phase = .failed(AuthDeliveryCopy.offline)
        }
    }
}

public enum PairingTime {
    public static let short: @Sendable (Date) -> String = { date in
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }
}

// MARK: - Trusted device (A): review and approve

/// Signs a `VIADERE-PAIR-V1` approval with this device's biometric key (Face ID / Touch ID appears).
public protocol PairingApprovalSigning: Sendable {
    func sign(request: DevicePairingRequest, match: String) async throws -> DevicePairingApproval
}

public struct BiometricPairingSigner: PairingApprovalSigning {
    let keys: any DeviceKeyStore
    let records: any DeviceRecordStore
    let clock: @Sendable () -> Date

    public init(keys: any DeviceKeyStore, records: any DeviceRecordStore, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.keys = keys
        self.records = records
        self.clock = clock
    }

    public func sign(request: DevicePairingRequest, match: String) async throws -> DevicePairingApproval {
        guard let record = try? await records.load() else { throw DevicePairingError.notTrusted }
        // Only the biometric key approves a device, as for every device confirmation (§2.17): never the passcode or the request key.
        guard record.purposes.contains(.approvalBiometric) else { throw ConfirmationError.cannotConfirm }
        do {
            let key = try await keys.requireKey(for: .approvalBiometric)
            let prompt = SigningPrompt(reason: "Add \(UntrustedText.line(request.deviceName, max: 40)) to your account")
            return try await DevicePairingApproval.sign(request: request, approverDeviceId: record.deviceId, match: match,
                                                        key: PromptBoundKey(key, prompt: prompt), now: clock())
        } catch let error as KeyStoreError {
            switch error {
            case .userCancelled: throw ConfirmationError.userCancelled
            case .keyInvalidated, .keyNotFound: throw ConfirmationError.keyInvalidated
            case .temporarilyUnavailable: throw ConfirmationError.keysUnavailable
            default: throw ConfirmationError.authenticationFailed
            }
        }
    }
}

/// The approving device: facts first (reported name, platform, time, integrity, the fatigue warning), then the number field, then three
/// equal buttons with the safe actions first (Deny, This wasn't me, Add device). **There is no property or method that returns the code.**
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class PairingApprovalViewModel {
    public static let digits = DevicePairing.codeDigits

    public enum Phase: Sendable, Equatable {
        /// Not this account's, internally inconsistent, or expired: nothing is signed.
        case refused
        case entering
        case submitting
        case added
        /// Three wrong numbers: the pairing ended on the server.
        case ended
        case denied
        case reported
        case expired
    }

    public private(set) var phase: Phase
    public private(set) var entry = ""
    public private(set) var notice: String?
    public private(set) var announcement: String?
    public let request: DevicePairingRequest
    private let api: any DevicePairingAPI
    private let signer: any PairingApprovalSigning
    private let timeText: @Sendable (Date) -> String
    private var remaining: Int

    public init(request: DevicePairingRequest, ownAccountId: ConsumerID?, api: any DevicePairingAPI, signer: any PairingApprovalSigning,
                now: Date = Date(), timeText: @escaping @Sendable (Date) -> String = PairingTime.short) {
        self.request = request
        self.api = api
        self.signer = signer
        self.timeText = timeText
        remaining = max(0, request.attemptsRemaining)
        // Only this account's request, only when its digests follow from its own keys, and only while it is live.
        if request.accountId != ownAccountId || !request.isConsistent || request.expiresAt <= now || remaining == 0 { phase = .refused }
        else { phase = .entering }
    }

    public var title: String { AuthDeliveryCopy.existingDeviceTitle }
    public var nameRow: String { AuthDeliveryCopy.existingDeviceName(UntrustedText.line(request.deviceName, max: 40)) }
    public var platformRow: String { request.platform.rawValue }
    public var requestedRow: String { PairingCopy.requestedAt(timeText(request.requestedAt)) }
    public var expiresRow: String { PairingCopy.expiresAt(timeText(request.expiresAt)) }
    public var integrityRow: String { request.integrityVerified ? PairingCopy.integrityVerified : PairingCopy.integrityUnverified }
    public var fatigueWarning: String? { request.fatigueWarning ? PairingCopy.fatigueWarning : nil }
    public var fieldLabel: String { AuthDeliveryCopy.deviceNumberLabel }
    public var helper: String { AuthDeliveryCopy.deviceNumberHelper }
    public var safeLine: String { PairingCopy.safeLine }
    public var refusal: String? { phase == .refused ? AuthDeliveryCopy.deviceChallengeMismatch : nil }
    public var isComplete: Bool { entry.count == Self.digits }

    /// Equal prominence, safe actions first; Add device is disabled (not hidden) until six digits are entered.
    public var buttons: [SafeActionButton] {
        [SafeActionButton(role: .deny, title: PairingCopy.deny, isEnabled: phase == .entering),
         SafeActionButton(role: .notMe, title: AuthDeliveryCopy.notMe, isEnabled: phase == .entering),
         SafeActionButton(role: .proceed, title: AuthDeliveryCopy.addDevice, isEnabled: phase == .entering && isComplete)]
    }

    public var resultLine: String? {
        switch phase {
        case .added: PairingCopy.addedResult
        case .ended: AuthDeliveryCopy.deviceWrongNumberFinal
        case .denied: PairingCopy.deniedResult
        case .reported: PairingCopy.reportedResult
        case .expired: PairingCopy.expired
        default: nil
        }
    }

    /// One ASCII digit at a time (paste, AutoFill and replacement are refused, as on the approval screen); leading zeros are allowed.
    public func edit(_ proposed: String) {
        guard phase == .entering, proposed != entry else { return }
        let deleting = entry.hasPrefix(proposed)
        let appending = proposed.hasPrefix(entry) && proposed.count == entry.count + 1
        guard deleting || appending, proposed.unicodeScalars.allSatisfy({ (0x30...0x39).contains($0.value) }), proposed.count <= Self.digits else { return }
        entry = proposed
    }

    public func add() async {
        guard phase == .entering, isComplete else { return }
        phase = .submitting
        let typed = entry
        do {
            let approval = try await signer.sign(request: request, match: typed)
            _ = try await api.approve(request.pairingId, approval)
            phase = .added
        } catch let error as DevicePairingError {
            switch error {
            case .wrongNumber:
                remaining -= 1
                entry = ""
                if remaining <= 0 { phase = .ended; notice = AuthDeliveryCopy.deviceWrongNumberFinal }
                else { phase = .entering; notice = AuthDeliveryCopy.deviceWrongNumber }
            case .expired: phase = .expired; notice = nil
            case .mismatch: phase = .refused; notice = PairingCopy.mismatch
            case .conflict: phase = .ended; notice = PairingCopy.deniedResult
            case .notTrusted: phase = .entering; notice = PairingCopy.notTrusted
            default: phase = .entering; notice = AuthDeliveryCopy.offline
            }
        } catch ConfirmationError.cannotConfirm {
            phase = .entering
            notice = PairingCopy.needsFaceID
        } catch let error as ConfirmationError {
            phase = .entering
            notice = error.userMessage
        } catch {
            phase = .entering
            notice = AuthDeliveryCopy.offline
        }
        announcement = notice ?? resultLine
    }

    /// Deny and This wasn't me need no Face ID: saying no is always safe.
    public func deny() async { await answer(report: false) }
    public func thisWasntMe() async { await answer(report: true) }

    private func answer(report: Bool) async {
        guard phase == .entering else { return }
        do {
            try await api.deny(request.pairingId, report: report)
            phase = report ? .reported : .denied
            notice = nil
        } catch {
            notice = AuthDeliveryCopy.offline
        }
        announcement = notice ?? resultLine
    }
}

/// Alerts on the trusted device: the account's pending pairings (only a D1 device gets any) as review models.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class PairingRequestsViewModel {
    public private(set) var reviews: [PairingApprovalViewModel] = []
    private let api: any DevicePairingAPI
    private let records: any DeviceRecordStore
    private let signer: any PairingApprovalSigning
    private let now: @Sendable () -> Date

    public init(api: any DevicePairingAPI, records: any DeviceRecordStore, signer: any PairingApprovalSigning, now: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.records = records
        self.signer = signer
        self.now = now
    }

    public var alertsLine: String? { reviews.isEmpty ? nil : PairingCopy.alertsLine }

    public func load() async {
        let account = (try? await records.load())?.consumerId
        guard let requests = try? await api.pending() else { return }
        reviews = requests.map { PairingApprovalViewModel(request: $0, ownAccountId: account, api: api, signer: signer, now: now()) }
            .filter { $0.phase != .refused || $0.request.accountId == account }
    }
}

extension ViadereServices {
    /// The new device's pairing flow (onboarding → "I already use Viadere").
    public var newDevicePairing: NewDevicePairing {
        NewDevicePairing(api: devicePairingAPI, keys: keys, records: records, sessions: sessions, preferences: preferences, appAttest: appAttest, clock: clock)
    }

    public var pairingSigner: BiometricPairingSigner { BiometricPairingSigner(keys: keys, records: records, clock: clock) }
}
