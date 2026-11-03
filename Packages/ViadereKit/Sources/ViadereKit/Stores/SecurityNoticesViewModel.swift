import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// The calm "something changed on your account" banner on Home. Loaded when the app opens and returns to the foreground; a failed
/// load never shows an error (the banner is simply absent), because a notice is information, not a task.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class SecurityNoticesViewModel {
    public private(set) var notices: [SecurityNotice] = []
    /// Set when a dismissal was refused because this device is not trusted yet.
    public private(set) var message: String?
    public private(set) var isDismissing = false
    /// A notice's action (Cancel recovery, Cancel replacement) is running.
    public private(set) var isActing = false
    private let services: ViadereServices

    public init(services: ViadereServices) { self.services = services }

    /// The notice the banner shows: the newest one, except that a pending phone transfer always comes first. It is the one notice whose
    /// outcome depends on the person seeing it with its "Keep my number" action (R-1), so a newer notice never hides it.
    public var current: SecurityNotice? { notices.first { $0.action == .keepPhoneNumber } ?? notices.first }
    /// Whether something covers the screen (the app lock): a notice behind it is not shown, so it is not reported as seen.
    public private(set) var isCovered = false
    private var shownNoticeId: UUID?
    private var reportedSeen: Set<UUID> = []
    /// How many more notices wait behind the one shown.
    public var additionalCount: Int { max(0, notices.count - 1) }

    public func load() async {
        guard let list = try? await services.api.securityNotices() else { return }
        notices = list.sorted { $0.createdAt > $1.createdAt }
        if notices.isEmpty { message = nil }
    }

    /// The banner calls this when it appears with `notice`. A notice whose outcome waits for it (a pending phone transfer) is reported to the server
    /// as **seen**, only while nothing covers the screen and only once it was really rendered with its action: loading the list, or having it
    /// behind the lock screen, never counts. A failed report is tried again the next time the banner appears or the lock opens.
    public func noteShown(_ notice: SecurityNotice) async {
        shownNoticeId = notice.id
        await reportShownIfNeeded()
    }

    /// The app lock closed or opened over the banner (`AppModel.lock()` and `unlocked()`).
    public func setCovered(_ covered: Bool) async {
        isCovered = covered
        if !covered { await reportShownIfNeeded() }
    }

    private func reportShownIfNeeded() async {
        guard !isCovered, let id = shownNoticeId, !reportedSeen.contains(id),
              let notice = notices.first(where: { $0.id == id }), notice.action == .keepPhoneNumber, actionTitle(for: notice) != nil else { return }
        do {
            try await services.api.markSecurityNoticeSeen(id)
            reportedSeen.insert(id)
        } catch {
            // Not recorded: the transfer keeps waiting for the owner, which is the safe side. The next appearance tries again.
        }
    }

    public func dismiss(_ notice: SecurityNotice) async {
        guard !isDismissing else { return }
        isDismissing = true
        defer { isDismissing = false }
        do {
            try await services.api.dismissSecurityNotice(notice.id)
            notices.removeAll { $0.id == notice.id }
            message = nil
        } catch let error as APIError {
            switch error.code {
            case .deviceCoolDown?:
                message = Self.coolDownMessage
            case .notFound?, .gone?:
                notices.removeAll { $0.id == notice.id }   // already handled elsewhere
            default:
                message = error.userMessage
            }
        } catch {
            message = "Couldn't update that. Try again in a moment."
        }
    }

    public static let coolDownMessage = "This iPhone hasn't been approved yet, so it can't dismiss this. Use a device you already trust, or review your devices."

    // MARK: Actions ("Not you? Cancel")

    /// The button a notice offers besides "This was me", or `nil` for an informational notice.
    public func actionTitle(for notice: SecurityNotice) -> String? {
        switch notice.action {
        case .cancelRecovery?: "Cancel recovery"
        case .cancelDeviceReplacement?: "Cancel"
        case .cancelVaultRecovery?: "Cancel release"
        case .keepPhoneNumber?: "Keep my number"
        case .unknown?, nil: nil
        }
    }

    /// What the button is called in the accessibility tree (more than "Cancel").
    public func actionHint(for notice: SecurityNotice) -> String? {
        switch notice.action {
        case .cancelRecovery?: "Stops the account recovery that was started"
        case .cancelDeviceReplacement?: "Removes the new iPhone and keeps this one"
        case .cancelVaultRecovery?: "Stops the request to release your vault's recovery key envelope"
        case .keepPhoneNumber?: "Refuses the request to link your number to another account"
        case .unknown?, nil: nil
        }
    }

    /// Runs the notice's action. The cancel actions need a trusted device (`403 device_cool_down` otherwise, said calmly); "Keep my number" works
    /// from any app device of the account. Returns whether it worked.
    @discardableResult
    public func perform(_ notice: SecurityNotice) async -> Bool {
        guard !isActing, let action = notice.action else { return false }
        isActing = true
        defer { isActing = false }
        do {
            switch action {
            case .cancelRecovery:
                guard let id = notice.subjectId.flatMap(RecoveryID.init) else { throw APIError.invalidRequest("id") }
                _ = try await services.api.cancelRecovery(id)
                message = Self.recoveryCancelledMessage
            case .cancelDeviceReplacement:
                guard let id = notice.subjectId.flatMap(DeviceID.init) else { throw APIError.invalidRequest("id") }
                try await services.api.cancelDeviceReplacement(id)
                message = Self.replacementCancelledMessage
            case .cancelVaultRecovery:
                guard let id = notice.subjectId.flatMap(UUID.init(uuidString:)) else { throw APIError.invalidRequest("id") }
                try await services.api.cancelVaultRecoveryRelease(id)
                message = Self.vaultReleaseCancelledMessage
            case .keepPhoneNumber:
                guard let id = notice.subjectId.flatMap(PhoneLinkID.init) else { throw APIError.invalidRequest("id") }
                try await services.api.keepPhoneNumber(id)
                message = Self.phoneKeptMessage
            case .unknown:
                return false
            }
        } catch let error as APIError {
            switch error.code {
            case .deviceCoolDown?:
                message = Self.coolDownActionMessage
            case .notFound?, .gone?, .conflict?:
                // Already cancelled, finished or handled from another device.
                notices.removeAll { $0.id == notice.id }
                message = Self.alreadyHandledMessage
            default:
                message = error.userMessage
            }
            return false
        } catch {
            message = "Couldn't do that. Try again in a moment."
            return false
        }
        notices.removeAll { $0.id == notice.id }
        // The notice has served its purpose; clearing it on the server is best effort.
        try? await services.api.dismissSecurityNotice(notice.id)
        return true
    }

    public static let recoveryCancelledMessage = "Recovery was cancelled. Its recovery codes no longer work, so generate new ones in Settings."
    public static let vaultReleaseCancelledMessage = "The request was cancelled. Nothing was released. If you didn't ask for it, replace your recovery key in Authenticator."
    public static let replacementCancelledMessage = "The new iPhone was removed. This one keeps working."
    public static let coolDownActionMessage = "This iPhone hasn't been approved yet, so it can't do that. Use a device you already trust."
    public static let phoneKeptMessage = "Your number stays linked to this account."
    public static let alreadyHandledMessage = "That was already taken care of."

    // MARK: Copy

    /// The headline, chosen by the notice's `topic` so kinds newer than this app's `SecurityNoticeKind` read properly. Anything the app
    /// doesn't know falls back to the server's plain-text message, then to a generic line.
    public func headline(for notice: SecurityNotice) -> String {
        let when = InteractionPresentation.relative(notice.createdAt, now: services.clock()).lowercased()
        switch notice.topic {
        case .newDevice: return "A new device was added to your account \(when)."
        case .newPhone: return "A new phone number was linked to your account \(when)."
        case .appClip: return "Viadere was opened as an App Clip on your account \(when)."
        case .deviceReplaced: return "A device on your account was set up again \(when)."
        case .devicePendingReplacement: return "A new iPhone is replacing this one."
        case .recoveryStarted: return "Account recovery was started \(when)."
        case .recoveryCancelled: return "An account recovery was cancelled \(when)."
        case .recoveryAttemptsLocked: return "Several wrong recovery codes were entered, so recovery is paused for a day."
        case .recoveryCompleted: return "Your account was recovered \(when). Household access ended and your phone numbers are cooling down."
        case .delegationEnded: return "Household access with another account ended \(when) because that account was recovered."
        case .vaultDeviceAdded: return "A device was added to your synced credential vault \(when)."
        case .vaultDeviceRemoved: return "A device was removed from your synced credential vault \(when)."
        case .vaultDeleted: return "Your synced credential vault was deleted from Viadere's servers \(when)."
        case .vaultRecoveryRequested: return "Someone asked to release your vault's recovery key envelope \(when). Nothing is released for 72 hours."
        case .vaultRecoveryCancelled: return "A request to release your vault's recovery key envelope was cancelled \(when)."
        case .vaultRecoveryReleased: return "Your vault's recovery key envelope is now available to the device that asked for it \(when)."
        case .vaultRecoveryFetched: return "Your vault's recovery key envelope was downloaded \(when)."
        case .vaultRestored: return "Your synced credential vault was restored on a new device with the recovery key \(when)."
        case .approvalKeyEnrolled: return "A business can now ask you to approve requests with a new approval key (\(when))."
        case .approvalKeyRevoked: return "An approval key was removed \(when)."
        case .approvalsFrozen: return "Approvals were frozen \(when)."
        case .approvalsUnfrozen: return "Approvals were unfrozen \(when)."
        case .approvalRequestsPaused: return "A business sent you several approval requests, so Viadere paused it \(when)."
        case .approvalKeyUnconfirmed: return "An approval key was never confirmed by the business, so it was removed \(when)."
        case .recoveryCredentialAdded: return "A passkey was added to your account \(when)."
        case .phoneTransferRequested: return "Someone asked to link your phone number to another Viadere account \(when). If that number is still yours, keep it."
        case .phoneUnlinked: return "Someone texted UNLINK from your phone number, so Viadere paused it. If this wasn't you, link it again in Viadere with a text from that phone. If you remove it instead, the number is free for another account to link."
        case .phoneTransferred: return "Your phone number was moved to another Viadere account \(when) because you did not keep it."
        case .businessLinked: return "A business linked your Viadere account to your account with them \(when)."
        case .businessLinkUnconfirmed: return "A business never confirmed a link you started, so it was ended \(when)."
        case .unknown:
            let text = UntrustedText.paragraphs(notice.message, max: 300)
            return text.isEmpty ? "Something changed on your account \(when)." : "\(text) (\(when))"
        }
    }

    /// The second line under the headline.
    public func prompt(for notice: SecurityNotice) -> String {
        switch notice.action {
        case .cancelRecovery?: return "Not you? Cancel recovery."
        case .cancelDeviceReplacement?: return "Not you? Cancel."
        case .cancelVaultRecovery?: return "Not you? Cancel the release now."
        case .keepPhoneNumber?: return "If you don't keep it, the request goes through after its waiting period."
        case .unknown?, nil: break
        }
        switch notice.topic {
        case .recoveryCancelled, .recoveryAttemptsLocked: return "Your devices were told. You can generate new recovery codes in Settings."
        case .recoveryCompleted: return "Confirm your phone numbers from a device you trust, and share access again if you want to."
        case .delegationEnded: return "Ask them to invite you again if you still want to share."
        case .vaultDeviceAdded: return "Not you? Open Authenticator, remove the device and change the passwords and passkeys stored there."
        case .vaultRecoveryFetched: return "It opens nothing without your recovery key. Not you? Open Authenticator and replace the recovery key."
        case .vaultRestored: return "Not you? Open Authenticator, replace your recovery key and change the passwords and passkeys stored there."
        case .approvalKeyEnrolled: return "Not you? Open Approvals, remove the key and freeze approvals."
        case .approvalsUnfrozen: return "Not you? Open Approvals and freeze them again."
        case .approvalRequestsPaused: return "Don't recognize it? Open Approvals and report the business."
        case .approvalKeyUnconfirmed: return "Didn't just set up approvals? Open Approvals and freeze them."
        case .businessLinked: return "Not you? Disconnect the business in Businesses and contact it."
        case .businessLinkUnconfirmed: return "Didn't just link a business? Review your businesses."
        default: return Self.prompt
        }
    }

    public static let prompt = "Not you? Review your devices."
}
