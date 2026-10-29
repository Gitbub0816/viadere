import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class SecuritySettingsViewModel {
    public struct ConsentHistoryItem: Identifiable, Equatable, Sendable {
        public var id: ConsentGrantID { grant.id }
        public var grant: ConsentGrant
        public var businessName: String
    }

    public private(set) var devices: [Device] = []
    public private(set) var phones: [PhoneLink] = []
    public private(set) var sessions: [ConsumerSession] = []
    public private(set) var consentHistory: [ConsentHistoryItem] = []
    public private(set) var currentDeviceId: DeviceID?
    public private(set) var phonesAvailable = true
    public private(set) var sessionsAvailable = true
    public private(set) var errorMessage: String?
    /// The id of the device or phone currently being confirmed (Face ID is up).
    public private(set) var confirmingId: String?
    /// This device's purposes, to know whether it can confirm others.
    private var thisDevicePurposes: [DeviceKeyPurpose] = []
    public private(set) var appLockMethod: String
    public var appLockEnabled: Bool
    /// Show amounts, places and other details in approval notifications on the lock screen. Off by default: the
    /// lock screen then names only who is asking.
    public var richPreviewsEnabled: Bool
    /// Recovery codes status (`nil` until loaded, or when the server doesn't offer recovery).
    public private(set) var recoveryInfo: RecoveryInfo?
    public private(set) var recoveryAvailable = true
    public private(set) var isRegeneratingCodes = false
    public private(set) var isCancellingRecovery = false
    public private(set) var recoveryMessage: String?
    /// New codes from "Generate new codes", on screen once.
    public private(set) var newRecoveryCodes: RecoveryCodesViewModel?
    private let services: ViadereServices

    public init(services: ViadereServices) {
        self.services = services
        appLockEnabled = services.preferences.bool(.appLockEnabled)
        richPreviewsEnabled = services.preferences.bool(.richNotificationPreviews)
        appLockMethod = services.appLock.methodName
    }

    public func load() async {
        let record = try? await services.records.load()
        currentDeviceId = record?.deviceId
        thisDevicePurposes = record?.purposes ?? []
        await loadRecovery()
        async let d = try? services.api.devices()
        async let relationships = try? services.api.relationships()
        let (deviceList, rels) = await (d, relationships)
        devices = (deviceList ?? []).sorted { ($0.lastSeenAt ?? $0.createdAt) > ($1.lastSeenAt ?? $1.createdAt) }

        do { phones = try await services.api.phoneLinks(); phonesAvailable = true } catch let error as APIError {
            if error.code == .notFound { phonesAvailable = false }
        } catch {}
        do { sessions = try await services.api.sessions(); sessionsAvailable = true } catch let error as APIError {
            if error.code == .notFound { sessionsAvailable = false }
        } catch {}

        var history: [ConsentHistoryItem] = []
        for relationship in rels ?? [] {
            for grant in (try? await services.api.consents(for: relationship.id)) ?? [] {
                history.append(ConsentHistoryItem(grant: grant, businessName: relationship.business.safeName))
            }
        }
        consentHistory = history.sorted { $0.grant.updatedAt > $1.grant.updatedAt }
    }

    // MARK: Recovery codes (§2.26)

    public func loadRecovery() async {
        do { recoveryInfo = try await services.api.recoveryInfo(); recoveryAvailable = true } catch let error as APIError {
            if error.code == .notFound { recoveryAvailable = false }
        } catch {}
    }

    /// Only a trusted device may generate new codes (it must not be cooling down).
    public var canRegenerateRecoveryCodes: Bool { isTrustedDevice }

    /// This iPhone may act on the account's security (the server's rule, §2.5a): it is approved (D1), or it is the account's only
    /// candidate (no approved device exists) and outside its new-device window. Unknown (devices not loaded): the server decides.
    public var isTrustedDevice: Bool {
        guard let device = thisDevice else { return true }
        let now = services.clock()
        guard !device.isRevoked else { return false }
        if device.approvesHighRisk(at: now) { return true }
        guard device.trustTier != nil else { return false }
        let otherApproved = devices.contains { $0.id != device.id && !$0.isRevoked && ($0.trustTier ?? .d0) >= .d1 }
        return !otherApproved && device.clientKind == .app && !device.isCoolingDown(at: now)
    }

    /// This iPhone can't approve high-risk requests yet (not D1): the calm explanation, else `nil`.
    public var thisDeviceTrustNotice: String? {
        guard let device = thisDevice, !device.isRevoked, !device.approvesHighRisk(at: services.clock()) else { return nil }
        return CoolDownPolicy.notApprovedMessage
    }

    /// Every recovery of this account that is waiting out its 72 h hold, from `RecoveryInfo` (the server's own list, not the Home notice).
    public var pendingRecoveries: [PendingRecovery] {
        guard let info = recoveryInfo else { return [] }
        return info.pendingRecoveries.isEmpty ? (info.pending.map { [$0] } ?? []) : info.pendingRecoveries
    }

    /// "Recovery in progress - Cancel": cancels **every** pending recovery (a trusted device; one request each). Needs no Home notice.
    public func cancelPendingRecoveries() async {
        guard !isCancellingRecovery, !pendingRecoveries.isEmpty else { return }
        guard isTrustedDevice else { recoveryMessage = SecurityNoticesViewModel.coolDownActionMessage; return }
        isCancellingRecovery = true
        recoveryMessage = nil
        defer { isCancellingRecovery = false }
        for pending in pendingRecoveries {
            do { _ = try await services.api.cancelRecovery(pending.id) } catch let error as APIError {
                switch error.code {
                case .notFound?, .gone?, .conflict?: continue            // already cancelled, finished or handled elsewhere
                case .deviceCoolDown?: recoveryMessage = SecurityNoticesViewModel.coolDownActionMessage
                default: recoveryMessage = error.userMessage
                }
                await loadRecovery()
                return
            } catch {
                recoveryMessage = "Couldn't cancel the recovery. Try again in a moment."
                await loadRecovery()
                return
            }
        }
        recoveryMessage = SecurityNoticesViewModel.recoveryCancelledMessage
        await loadRecovery()
    }

    /// One calm line about the codes.
    public var recoveryStatusLine: String {
        guard let info = recoveryInfo else { return "Checking…" }
        if !pendingRecoveries.isEmpty { return "Recovery in progress. You can cancel it here." }
        if info.remainingCodes == 0 { return "No codes yet. Generate a set to be able to recover your account." }
        return info.remainingCodes == 1 ? "1 unused code" : "\(info.remainingCodes) unused codes"
    }

    /// New recovery codes: a device that may manage the account **and** this device's Face ID / Touch ID / passcode proof (§2.5a; no
    /// passkey needed). The old codes stop working. The codes are shown once (`newRecoveryCodes`) and never stored.
    public func regenerateRecoveryCodes() async {
        guard !isRegeneratingCodes else { return }
        guard canRegenerateRecoveryCodes else { recoveryMessage = SecurityNoticesViewModel.coolDownActionMessage; return }
        isRegeneratingCodes = true
        recoveryMessage = nil
        defer { isRegeneratingCodes = false }
        do {
            let set = try await services.account.makeRecoveryCodes()
            newRecoveryCodes = RecoveryCodesViewModel(codes: set)
            await loadRecovery()
        } catch let error as ConfirmationError {
            if error != .userCancelled { recoveryMessage = error.userMessage }
        } catch let error as APIError {
            recoveryMessage = error.code == .deviceCoolDown ? SecurityNoticesViewModel.coolDownActionMessage : error.userMessage
        } catch {
            recoveryMessage = "Couldn't generate new codes. Try again in a moment."
        }
    }

    /// The codes screen is done (saved, or dismissed): they are released.
    public func finishRecoveryCodes() {
        newRecoveryCodes?.release()
        newRecoveryCodes = nil
    }

    // MARK: Pending device replacement

    public enum ReplacementState: Equatable, Sendable {
        /// This row is the device being replaced; `thisIPhone` when it is the one in the person's hand.
        case beingReplaced(thisIPhone: Bool, until: Date?)
        /// This row is the new device waiting to take over.
        case pendingReplacement
    }

    public func replacementState(for device: Device) -> ReplacementState? {
        guard !device.isRevoked else { return nil }
        if device.pendingReplacementBy != nil {
            return .beingReplaced(thisIPhone: device.id == currentDeviceId, until: device.pendingReplacementAt)
        }
        if devices.contains(where: { !$0.isRevoked && $0.pendingReplacementBy == device.id }) { return .pendingReplacement }
        return nil
    }

    public func replacementTitle(for state: ReplacementState) -> String {
        switch state {
        case .beingReplaced(let thisIPhone, _): thisIPhone ? "Replacing this iPhone" : "Being replaced"
        case .pendingReplacement: "Pending replacement"
        }
    }

    public func replacementNote(for state: ReplacementState) -> String {
        let now = services.clock()
        switch state {
        case .beingReplaced(let thisIPhone, let until):
            let when = until.map { " It takes over \(CoolDownPolicy.timeText($0, now: now)), unless you cancel." } ?? ""
            return (thisIPhone ? "A new iPhone is set up to replace this one." : "A new iPhone is set up to replace this device.") + when
        case .pendingReplacement:
            return "This iPhone is waiting to replace another device. If that wasn't you, cancel it."
        }
    }

    /// The device a "Cancel" on this row would remove: always the NEW one.
    public func replacementTarget(for device: Device) -> DeviceID? {
        switch replacementState(for: device) {
        case .beingReplaced?: device.pendingReplacementBy
        case .pendingReplacement?: device.id
        case nil: nil
        }
    }

    /// Whether this iPhone may cancel the replacement shown on `device`'s row: it must be trusted and cannot be the new device.
    public func canCancelReplacement(_ device: Device) -> Bool {
        guard let target = replacementTarget(for: device) else { return false }
        return target != currentDeviceId && isTrustedDevice
    }

    public func cancelReplacement(_ device: Device) async {
        guard canCancelReplacement(device), let target = replacementTarget(for: device) else { return }
        do {
            try await services.api.cancelDeviceReplacement(target)
            errorMessage = nil
            await load()
        } catch let error as APIError {
            errorMessage = error.code == .deviceCoolDown ? SecurityNoticesViewModel.coolDownActionMessage : error.userMessage
        } catch {
            errorMessage = "Couldn't cancel that."
        }
    }

    /// Turning the lock on requires a successful authentication first, so a stranger can't enable and lock out the owner.
    public func setAppLock(_ enabled: Bool) async {
        guard enabled != services.preferences.bool(.appLockEnabled) else { return }
        if enabled {
            guard await services.appLock.isAvailable(),
                  await services.appLock.authenticate(reason: "Turn on app lock") else {
                appLockEnabled = false
                return
            }
        }
        services.preferences.setBool(enabled, for: .appLockEnabled)
        appLockEnabled = enabled
    }

    /// Turning detailed previews on needs a successful authentication (it exposes request details to anyone who can
    /// see the lock screen); turning them off never does.
    public func setRichPreviews(_ enabled: Bool) async {
        guard enabled != services.preferences.bool(.richNotificationPreviews) else { return }
        if enabled {
            guard await services.appLock.isAvailable(),
                  await services.appLock.authenticate(reason: "Show request details in notifications") else {
                richPreviewsEnabled = false
                return
            }
        }
        services.preferences.setBool(enabled, for: .richNotificationPreviews)
        richPreviewsEnabled = enabled
    }

    // MARK: New-device cool-down and confirmation

    public var thisDevice: Device? { devices.first { $0.id == currentDeviceId } }

    /// This iPhone is new: high-risk approvals are paused until this time.
    public var thisDeviceLockedUntil: Date? {
        guard let until = thisDevice?.approvalsLockedUntil, CoolDownPolicy.isActive(until: until, now: services.clock()) else { return nil }
        return until
    }

    /// Whether this iPhone may approve another device: it is approved itself (D1) and has a Face ID / Touch ID approval key.
    public var canConfirmOthers: Bool {
        guard let device = thisDevice, !device.isRevoked else { return false }
        return device.approvesHighRisk(at: services.clock()) && thisDevicePurposes.contains(.approvalBiometric)
    }

    /// A device that is not approved yet, as one calm line (`nil` when it is approved).
    public func coolDownNote(for device: Device) -> String? {
        guard !device.isRevoked, device.clientKind == .app, !device.approvesHighRisk(at: services.clock()) else { return nil }
        return "Not approved yet. It can't approve high-risk requests until a trusted device approves it."
    }

    /// Whether the "Approve" action applies to `device`: someone else's device that is not approved yet, from a device that may approve it.
    public func canConfirm(_ device: Device) -> Bool {
        device.id != currentDeviceId && !device.isRevoked && device.clientKind == .app && !device.approvesHighRisk(at: services.clock())
            && canConfirmOthers
    }

    /// "Usable after 3:42 PM" for a phone still in its cool-down, else `nil`.
    public func coolDownNote(for phone: PhoneLink) -> String? {
        let now = services.clock()
        guard let until = phone.usableFrom, until > now else { return nil }
        return "Messages start working \(CoolDownPolicy.timeText(until, now: now)), or confirm it now."
    }

    public func canConfirm(_ phone: PhoneLink) -> Bool {
        guard let until = phone.usableFrom, until > services.clock() else { return false }
        return canConfirmOthers
    }

    /// Lifts another device's cool-down with this iPhone's Face ID / passcode key.
    public func confirm(_ device: Device) async {
        guard confirmingId == nil, canConfirm(device) else { return }
        confirmingId = device.id.description
        defer { confirmingId = nil }
        do {
            let updated = try await services.confirmations.confirm(device: device)
            if let index = devices.firstIndex(where: { $0.id == device.id }) { devices[index] = updated }
            errorMessage = nil
        } catch let error as ConfirmationError {
            if error != .userCancelled { errorMessage = error.userMessage }
        } catch {
            errorMessage = "Couldn't confirm that device."
        }
    }

    /// Makes a newly linked phone usable now.
    public func confirm(_ phone: PhoneLink) async {
        guard confirmingId == nil, canConfirm(phone) else { return }
        confirmingId = phone.id.description
        defer { confirmingId = nil }
        do {
            let updated = try await services.confirmations.confirm(phone: phone)
            if let index = phones.firstIndex(where: { $0.id == phone.id }) { phones[index] = updated }
            errorMessage = nil
        } catch let error as ConfirmationError {
            if error != .userCancelled { errorMessage = error.userMessage }
        } catch {
            errorMessage = "Couldn't confirm that phone."
        }
    }

    public func revoke(_ device: Device) async {
        guard device.id != currentDeviceId else { return }
        do {
            try await services.api.revokeDevice(device.id)
            if let index = devices.firstIndex(where: { $0.id == device.id }) { devices[index].revokedAt = services.clock() }
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't remove that device."
        }
    }

    // MARK: Linking another phone

    public enum AddPhoneStage: Equatable, Sendable { case idle, awaitingCode, failed(String) }
    public private(set) var addPhoneStage: AddPhoneStage = .idle
    private var pendingPhoneLinkId: PhoneLinkID?

    /// Starts linking a number (`PhoneInput` accepts "(480) 555-0123"); an SMS code follows.
    public func startAddPhone(_ raw: String) async {
        guard let phone = PhoneInput.normalize(raw) else { addPhoneStage = .failed("Enter a full mobile number."); return }
        do {
            pendingPhoneLinkId = try await services.api.startPhoneLink(phone: phone).phoneLinkId
            addPhoneStage = .awaitingCode
        } catch {
            addPhoneStage = .failed((error as? APIError)?.userMessage ?? "Couldn't send a code.")
        }
    }

    public func verifyAddPhone(code: String) async {
        guard let id = pendingPhoneLinkId, OTPInput.isComplete(code) else { return }
        do {
            let link = try await services.api.verifyPhoneLink(id: id, code: OTPInput.normalize(code))
            phones.append(link)
            lastLinkedPhone = link
            pendingPhoneLinkId = nil
            addPhoneStage = .idle
        } catch {
            addPhoneStage = .failed((error as? APIError)?.userMessage ?? "That code isn't right.")
        }
    }

    public func cancelAddPhone() { pendingPhoneLinkId = nil; addPhoneStage = .idle }

    // MARK: SMS account link (https://viadere.com/l/{token})

    /// Warning shown on the link confirmation screen. Linking someone else's number lets them message businesses as you.
    public static let accountLinkWarning = "Only continue if you started this from your own phone. Linking someone else's number lets them message businesses as you."

    public enum AccountLinkPhase: Equatable, Sendable {
        case idle, loading
        /// The token is valid; the screen shows the masked number and waits for an explicit "This is my phone".
        case ready(SMSLinkPreview)
        case failed(String)
    }

    public private(set) var accountLinkPhase: AccountLinkPhase = .idle

    /// Fetches what the one-time token would link (masked number and expiry). Read-only: nothing is linked yet.
    public func loadAccountLinkPreview(token: String) async {
        accountLinkPhase = .loading
        do {
            accountLinkPhase = .ready(try await services.api.previewPhoneLink(token: token))
        } catch {
            accountLinkPhase = .failed((error as? APIError)?.userMessage ?? "This link isn't valid anymore.")
        }
    }

    /// The phone the last redemption linked (it may carry `usableFrom`).
    public private(set) var lastLinkedPhone: PhoneLink?

    /// Redeems the token for the number previewed. Refuses unless the person explicitly confirmed "This is my phone"
    /// for a preview that is still valid. Sends both the last four digits and the exact masked number from the preview.
    public func redeemAccountLink(token: String, confirmedOwnPhone: Bool) async -> Bool {
        guard confirmedOwnPhone, case .ready(let preview) = accountLinkPhase, preview.expiresAt > services.clock(),
              let last4 = preview.last4 else { return false }
        do {
            let link = try await services.api.redeemSMSLink(
                SMSLinkRedeemRequest(token: token, confirmPhoneLast4: last4, confirmMaskedPhone: preview.maskedPhone))
            phones.removeAll { $0.id == link.id }
            phones.append(link)
            lastLinkedPhone = link
            accountLinkPhase = .idle
            return true
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "We couldn't link that number."
            return false
        }
    }

    /// What to tell the person after a successful redemption: when the number starts working.
    public var accountLinkResultMessage: String? {
        guard let link = lastLinkedPhone else { return nil }
        let now = services.clock()
        if let until = link.usableFrom, until > now {
            return "\(link.maskedPhone) is linked. For your security it starts working \(CoolDownPolicy.timeText(until, now: now)), or confirm it now from a device you trust."
        }
        return "\(link.maskedPhone) is linked."
    }

    public func resetAccountLink() { accountLinkPhase = .idle }

    public func removePhone(_ phone: PhoneLink) async {
        do { try await services.api.removePhoneLink(phone.id); phones.removeAll { $0.id == phone.id } } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't unlink that number."
        }
    }

    public func revokeSession(_ session: ConsumerSession) async {
        guard !session.isCurrent else { return }
        do { try await services.api.revokeSession(session.id); sessions.removeAll { $0.id == session.id } } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't sign that session out."
        }
    }
}
