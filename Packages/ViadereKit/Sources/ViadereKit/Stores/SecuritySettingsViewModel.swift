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

    /// Whether this iPhone may confirm another device: it is not itself cooling down and has a Face ID or passcode approval key.
    public var canConfirmOthers: Bool {
        thisDeviceLockedUntil == nil && thisDevice?.isRevoked == false
            && (thisDevicePurposes.contains(.approvalBiometric) || thisDevicePurposes.contains(.approvalUserPresence))
    }

    /// Other trusted devices' cool-down, as one calm line (`nil` when the device is trusted).
    public func coolDownNote(for device: Device) -> String? {
        let now = services.clock()
        guard !device.isRevoked, device.isCoolingDown(at: now), let until = device.approvalsLockedUntil else { return nil }
        return "New device. High-risk approvals unlock \(CoolDownPolicy.timeText(until, now: now))."
    }

    /// Whether the "Confirm" action applies to `device`: someone else's cooling-down device, from a device that may confirm.
    public func canConfirm(_ device: Device) -> Bool {
        device.id != currentDeviceId && !device.isRevoked && device.isCoolingDown(at: services.clock()) && canConfirmOthers
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
