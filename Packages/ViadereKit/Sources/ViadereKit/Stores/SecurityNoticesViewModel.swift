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

    // MARK: Copy

    /// The headline. Uses the server's plain-text message for kinds this app doesn't know, so new kinds still read sensibly.
    public func headline(for notice: SecurityNotice) -> String {
        let when = InteractionPresentation.relative(notice.createdAt, now: services.clock()).lowercased()
        switch notice.kind {
        case .newDevice: return "A new device was added to your account \(when)."
        case .newPhone: return "A new phone number was linked to your account \(when)."
        case .appClip: return "Viadere was opened as an App Clip on your account \(when)."
        case .deviceReplaced: return "A device on your account was set up again \(when)."
        case .unknown:
            let text = UntrustedText.paragraphs(notice.message, max: 300)
            return text.isEmpty ? "Something changed on your account \(when)." : "\(text) (\(when))"
        }
    }

    public static let prompt = "Not you? Review your devices."
}
