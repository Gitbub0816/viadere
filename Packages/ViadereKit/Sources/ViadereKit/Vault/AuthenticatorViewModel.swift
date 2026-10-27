import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// State and actions behind the Authenticator screens (list of passkeys and codes, add a code, sync, devices, recovery key). All the
/// cryptography stays in `VaultEngine`; this type only holds what the screens show, keeps secrets for as short as it can, and turns errors into
/// plain sentences.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class AuthenticatorViewModel {
    public enum Phase: Equatable, Sendable {
        case loading, empty, locked, ready
        case failed(String)
    }

    public struct Row: Identifiable, Equatable, Sendable {
        public enum Kind: Sendable { case passkey, code }
        public var id: UUID
        public var kind: Kind
        public var title: String
        public var subtitle: String
        /// Present only for codes, and only while the vault is unlocked.
        public var code: String?
        public var secondsRemaining: Int?
        public var period: Int?

        /// "123 456" for six digits, "1234 5678" for eight: easier to read and to copy from.
        public var spacedCode: String? {
            guard let code else { return nil }
            let half = code.count / 2
            return code.count >= 6 ? String(code.prefix(half)) + " " + String(code.dropFirst(half)) : code
        }
    }

    public enum SyncStep: Equatable, Sendable {
        case idle
        /// The recovery key is on screen; the person must confirm they saved it before sync turns on.
        case showingRecoveryKey
        case enabling
    }

    public private(set) var phase: Phase = .loading
    public private(set) var rows: [Row] = []
    public private(set) var syncInfo: VaultEngine.SyncInfo?
    public private(set) var syncAvailable = false
    public private(set) var syncFailure: String?
    public private(set) var devices: [VaultDeviceSummary] = []
    public private(set) var message: String?
    public private(set) var syncStep: SyncStep = .idle
    /// Shown once while `syncStep == .showingRecoveryKey` or after a recovery-key change; released as soon as the screen is done with it.
    public private(set) var recoveryKeyText: String?
    public private(set) var invite: AddDeviceInvite?
    public private(set) var joinPreview: JoinRequestPreview?
    public private(set) var isWorking = false

    private let engine: VaultEngine
    private var pendingRecoveryKey: RecoveryKey?
    private let clock: @Sendable () -> Date

    public init(engine: VaultEngine, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.engine = engine
        self.clock = clock
    }

    // MARK: Loading

    public func load() async {
        do {
            switch try await engine.phase() {
            case .empty: phase = .empty
            case .locked: phase = .locked
            case .unlocked: try await refresh()
            }
            syncAvailable = await engine.syncAvailable()
        } catch {
            phase = .failed(Self.describe(error))
        }
    }

    /// Opens the vault (Face ID / Touch ID / passcode is asked for by the system, inside the key use).
    public func unlock() async {
        do {
            try await engine.unlock()
            try await refresh()
            syncAvailable = await engine.syncAvailable()
        } catch {
            message = Self.describe(error)
            if phase == .loading { phase = .locked }
        }
    }

    public func lock() async {
        await engine.lock()
        rows = []
        devices = []
        invite = nil
        joinPreview = nil
        releaseRecoveryKey()
        phase = (try? await engine.phase()) == .empty ? .empty : .locked
    }

    public func createVault() async {
        do {
            try await engine.create()
            try await refresh()
        } catch {
            message = Self.describe(error)
        }
    }

    private func refresh() async throws {
        let items = try await engine.items()
        let codes = try await engine.liveCodes(at: clock())
        rows = items.compactMap { Self.row($0, codes: codes) }.sorted { ($0.title.lowercased(), $0.subtitle) < ($1.title.lowercased(), $1.subtitle) }
        syncInfo = try await engine.syncInfo()
        phase = .ready
    }

    static func row(_ item: VaultItemPayload, codes: [UUID: VaultEngine.LiveCode]) -> Row? {
        switch item.body {
        case .passkey(let p):
            return Row(id: item.id, kind: .passkey, title: DisplayTextSanitizer.sanitize(p.rpId, maxCharacters: 80),
                       subtitle: DisplayTextSanitizer.sanitize(p.displayName ?? p.userName, maxCharacters: 80))
        case .totp(let t):
            let live = codes[item.id]
            return Row(id: item.id, kind: .code, title: DisplayTextSanitizer.sanitize(t.issuer ?? t.accountName, maxCharacters: 80),
                       subtitle: t.issuer == nil ? "" : DisplayTextSanitizer.sanitize(t.accountName, maxCharacters: 80), code: live?.code,
                       secondsRemaining: live?.secondsRemaining, period: live?.period)
        }
    }

    /// Called every second while the list is visible.
    public func tick() async {
        guard phase == .ready, let codes = try? await engine.liveCodes(at: clock()) else { return }
        rows = rows.map { row in
            guard row.kind == .code, let live = codes[row.id] else { return row }
            var copy = row
            copy.code = live.code
            copy.secondsRemaining = live.secondsRemaining
            copy.period = live.period
            return copy
        }
    }

    // MARK: Items

    /// Adds a code from a scanned or pasted `otpauth://` URI. Anything else is refused with a plain message.
    @discardableResult
    public func addCode(uri: String) async -> Bool {
        do {
            try await engine.addTOTP(uri: uri)
            try await refresh()
            message = nil
            return true
        } catch {
            message = "That isn't a valid authenticator QR code or link. Codes from Authenticator setup screens start with otpauth://."
            return false
        }
    }

    /// Adds a code typed by hand (the "can't scan" path).
    @discardableResult
    public func addCode(issuer: String, account: String, secret: String, algorithm: TOTPAlgorithm = .sha1, digits: Int = 6, period: Int = 30) async -> Bool {
        let cleanIssuer = issuer.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanAccount = account.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let bytes = Base32.decode(secret), !cleanAccount.isEmpty, !DisplayTextSanitizer.containsDisallowedScalars(cleanAccount + cleanIssuer) else {
            message = "Check the setup key: it should be letters and numbers from the site's setup page."
            return false
        }
        do {
            try await engine.addTOTP(TOTPParameters(secret: bytes, algorithm: algorithm, digits: digits, period: period, issuer: cleanIssuer.isEmpty ? nil : cleanIssuer, accountName: cleanAccount))
            try await refresh()
            message = nil
            return true
        } catch {
            message = "That setup key isn't long enough or isn't valid."
            return false
        }
    }

    public func delete(_ id: UUID) async {
        do {
            try await engine.deleteItem(id)
            try await refresh()
        } catch {
            message = Self.describe(error)
        }
    }

    public func clearMessage() { message = nil }

    // MARK: Sync and recovery key

    /// Step 1 of turning sync on: makes the recovery key and shows it. Nothing is uploaded yet.
    public func beginEnablingSync() async {
        let key = await engine.makeRecoveryKey()
        pendingRecoveryKey = key
        recoveryKeyText = key.displayString
        syncStep = .showingRecoveryKey
        syncFailure = nil
    }

    /// Step 2: the person typed the recovery key back. Only then does sync turn on (so a key that was never really saved cannot be the only way in).
    @discardableResult
    public func confirmRecoveryKeyAndEnableSync(typed: String) async -> Bool {
        guard let key = pendingRecoveryKey, let entered = try? RecoveryKey(parsing: typed), entered == key else {
            syncFailure = "That doesn't match the recovery key shown. Check it and try again."
            return false
        }
        syncStep = .enabling
        defer { releaseRecoveryKey() }
        do {
            try await engine.enableSync(recoveryKey: key)
            try await refresh()
            syncStep = .idle
            return true
        } catch {
            syncFailure = Self.describe(error)
            syncStep = .idle
            return false
        }
    }

    public func cancelEnablingSync() {
        releaseRecoveryKey()
        syncStep = .idle
    }

    private func releaseRecoveryKey() {
        pendingRecoveryKey = nil
        recoveryKeyText = nil
    }

    public func syncNow() async {
        isWorking = true
        defer { isWorking = false }
        do {
            _ = try await engine.syncNow()
            syncFailure = nil
            try await refresh()
        } catch {
            syncFailure = Self.describe(error)
        }
    }

    public func turnOffSync(deleteFromServer: Bool) async {
        do {
            try await engine.disableSync(deleteFromServer: deleteFromServer)
            syncInfo = try await engine.syncInfo()
            syncFailure = nil
        } catch {
            syncFailure = Self.describe(error)
        }
    }

    /// "Check my recovery key": compares what was typed with this vault, on this device.
    public func verifyRecoveryKey(_ text: String) async -> Bool {
        (try? await engine.verifyRecoveryKey(text)) ?? false
    }

    /// Replaces the recovery key (shows the new one; confirm with `confirmRecoveryKeyReplacement`).
    public func beginReplacingRecoveryKey() async {
        let key = await engine.makeRecoveryKey()
        pendingRecoveryKey = key
        recoveryKeyText = key.displayString
    }

    @discardableResult
    public func confirmRecoveryKeyReplacement(typed: String, rotateVaultKey: Bool) async -> Bool {
        guard let key = pendingRecoveryKey, let entered = try? RecoveryKey(parsing: typed), entered == key else {
            syncFailure = "That doesn't match the recovery key shown."
            return false
        }
        defer { releaseRecoveryKey() }
        do {
            try await engine.installRecoveryKey(key, rotateVaultKey: rotateVaultKey)
            try await refresh()
            return true
        } catch {
            syncFailure = Self.describe(error)
            return false
        }
    }

    // MARK: Devices

    public func loadDevices() async {
        do {
            let server = (try? await engine.serverDevices()) ?? []
            devices = try await engine.devices(serverInfo: server)
        } catch {
            message = Self.describe(error)
        }
    }

    public func beginAddingDevice() async {
        do {
            invite = try await engine.beginAddingDevice()
            joinPreview = nil
        } catch {
            message = Self.describe(error)
        }
    }

    /// Polled while the pairing code is on screen.
    public func checkForJoinRequest() async {
        guard let invite else { return }
        joinPreview = try? await engine.joinRequest(for: invite)
    }

    public func approveJoin() async -> Bool {
        guard let invite else { return false }
        do {
            try await engine.approveJoin(invite)
            self.invite = nil
            joinPreview = nil
            await loadDevices()
            return true
        } catch {
            message = Self.describe(error)
            return false
        }
    }

    public func cancelAddingDevice() async {
        if let invite { await engine.cancelAddingDevice(invite) }
        invite = nil
        joinPreview = nil
    }

    public func removeDevice(_ memberId: String) async {
        isWorking = true
        defer { isWorking = false }
        do {
            try await engine.removeDevice(memberId)
            await loadDevices()
            try await refresh()
        } catch {
            message = Self.describe(error)
        }
    }

    // MARK: This device joining or restoring

    private var joinHandle: JoinHandle?

    /// The person typed (or scanned) the pairing code shown on the approving device.
    public func requestJoin(code: String) async -> Bool {
        do {
            joinHandle = try await engine.requestJoin(code: code)
            return true
        } catch VaultError.invalidPairingCode {
            message = "That code doesn't look right. Check it against the other device."
            return false
        } catch {
            message = Self.describe(error)
            return false
        }
    }

    /// Polled while "Waiting for approval" is on screen. Returns `true` once the vault is open on this device.
    public func completeJoin() async -> Bool {
        guard let joinHandle else { return false }
        do {
            try await engine.completeJoin(joinHandle)
            self.joinHandle = nil
            try await refresh()
            return true
        } catch VaultEngineError.joinNotApproved {
            return false
        } catch {
            message = Self.describe(error)
            return false
        }
    }

    /// Restoring with the recovery key: first a new recovery key is made and shown; `restore` runs after the person confirms it.
    public func beginRestore() async {
        let key = await engine.makeRecoveryKey()
        pendingRecoveryKey = key
        recoveryKeyText = key.displayString
    }

    @discardableResult
    public func restore(recoveryKey: String, confirmingNewKey typed: String) async -> Bool {
        guard let key = pendingRecoveryKey, let entered = try? RecoveryKey(parsing: typed), entered == key else {
            message = "That doesn't match the new recovery key shown."
            return false
        }
        isWorking = true
        defer { isWorking = false; releaseRecoveryKey() }
        do {
            try await engine.restore(recoveryKey: recoveryKey, newRecoveryKey: key)
            try await refresh()
            return true
        } catch VaultError.invalidRecoveryKey {
            message = "That recovery key doesn't match this vault. Check it and try again."
            return false
        } catch {
            message = Self.describe(error)
            return false
        }
    }

    // MARK: Copy

    /// The text to copy for a code row (the app puts it on the pasteboard with `SensitiveCopyPolicy`: local only, expires).
    public func codeToCopy(_ id: UUID) -> String? { rows.first { $0.id == id }?.code }

    // MARK: Errors

    static func describe(_ error: Error) -> String {
        switch error {
        case VaultEngineError.syncUnavailable: return "Sync isn't available yet."
        case VaultEngineError.remoteVaultExists: return "This account already has a synced vault. Add this device from one that has it, or restore with your recovery key."
        case VaultEngineError.notBound: return "This device isn't part of the synced vault yet."
        case VaultEngineError.removedFromVault: return "This device was removed from the synced vault."
        case VaultEngineError.rollbackDetected: return "The server showed an older version of your vault than this device has already seen, so nothing was changed."
        case VaultEngineError.membershipConflict: return "Devices changed in two places at once. Review the devices list and try again."
        case VaultEngineError.stateTampered: return "The vault on this device doesn't match what it last saw, so it was not opened."
        case VaultEngineError.deviceKeyMissing: return "This device's vault key is gone, so the vault can't be opened here. Restore it with your recovery key."
        case VaultEngineError.locked: return "Unlock the vault first."
        case VaultEngineError.tooManySyncAttempts: return "Sync is busy. Try again in a moment."
        case let error as APIError: return error.userMessage
        default: return "Something went wrong. Please try again."
        }
    }
}
