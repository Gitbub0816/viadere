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

    /// The notice the banner shows: the newest one.
    public var current: SecurityNotice? { notices.first }
    /// How many more notices wait behind the one shown.
    public var additionalCount: Int { max(0, notices.count - 1) }

    public func load() async {
        guard let list = try? await services.api.securityNotices() else { return }
        notices = list.sorted { $0.createdAt > $1.createdAt }
        if notices.isEmpty { message = nil }
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

    public static let coolDownMessage = "This iPhone is new to your account, so it can't dismiss this yet. Use a device you already trust, or review your devices."

    // MARK: Actions ("Not you? Cancel")

    /// The button a notice offers besides "This was me", or `nil` for an informational notice.
    public func actionTitle(for notice: SecurityNotice) -> String? {
        switch notice.action {
        case .cancelRecovery?: "Cancel recovery"
        case .cancelDeviceReplacement?: "Cancel"
        case .unknown?, nil: nil
        }
    }

    /// What the button is called in the accessibility tree (more than "Cancel").
    public func actionHint(for notice: SecurityNotice) -> String? {
        switch notice.action {
        case .cancelRecovery?: "Stops the account recovery that was started"
        case .cancelDeviceReplacement?: "Removes the new iPhone and keeps this one"
        case .unknown?, nil: nil
        }
    }

    /// Runs the notice's action. Both need a trusted device (`403 device_cool_down` otherwise, said calmly). Returns whether it worked.
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
    public static let replacementCancelledMessage = "The new iPhone was removed. This one keeps working."
    public static let coolDownActionMessage = "This iPhone is new to your account, so it can't do that yet. Use a device you already trust."
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
        case .approvalKeyEnrolled: return "A business can now ask you to approve requests with a new approval key (\(when))."
        case .approvalKeyRevoked: return "An approval key was removed \(when)."
        case .approvalsFrozen: return "Approvals were frozen \(when)."
        case .approvalsUnfrozen: return "Approvals were unfrozen \(when)."
        case .approvalRequestsPaused: return "A business sent you several approval requests, so Viadere paused it \(when)."
        case .approvalKeyUnconfirmed: return "An approval key was never confirmed by the business, so it was removed \(when)."
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
        case .unknown?, nil: break
        }
        switch notice.topic {
        case .recoveryCancelled, .recoveryAttemptsLocked: return "Your devices were told. You can generate new recovery codes in Settings."
        case .recoveryCompleted: return "Confirm your phone numbers from a device you trust, and share access again if you want to."
        case .delegationEnded: return "Ask them to invite you again if you still want to share."
        case .vaultDeviceAdded: return "Not you? Open Authenticator, remove the device and change the passwords and passkeys stored there."
        case .approvalKeyEnrolled: return "Not you? Open Approvals, remove the key and freeze approvals."
        case .approvalsUnfrozen: return "Not you? Open Approvals and freeze them again."
        case .approvalRequestsPaused: return "Don't recognize it? Open Approvals and report the business."
        case .approvalKeyUnconfirmed: return "Didn't just set up approvals? Open Approvals and freeze them."
        default: return Self.prompt
        }
    }

    public static let prompt = "Not you? Review your devices."
}
