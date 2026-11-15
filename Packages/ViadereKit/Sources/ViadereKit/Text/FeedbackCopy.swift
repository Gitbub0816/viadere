import Foundation

/// What a screen that loads a list should show. One decision for every list screen, so loading, failure, empty and content never
/// overlap: content always wins (a failed refresh keeps what is on screen and says so in a notice), a first load shows the placeholder,
/// a first load that failed shows the error with a retry, and only a successful empty answer shows the empty state.
public enum ScreenLoadState: Equatable, Sendable {
    /// Nothing to show yet and a load is running: placeholder rows.
    case loading
    /// Nothing to show and the load failed: the message with a way to try again.
    case failed(String)
    /// The load answered and there is nothing: the empty state.
    case empty
    /// There is something to show (even if a refresh is running or just failed).
    case content

    public static func resolve(isLoading: Bool, isEmpty: Bool, errorMessage: String?) -> ScreenLoadState {
        guard isEmpty else { return .content }
        if isLoading { return .loading }
        if let errorMessage, !errorMessage.isEmpty { return .failed(errorMessage) }
        return .empty
    }
}

/// The short confirmations shown as a toast after a small, reversible action. One sentence, no exclamation, said once.
public enum FeedbackCopy {
    public static func conversationMuted(_ muted: Bool) -> String {
        muted ? "Conversation muted." : "Conversation unmuted."
    }

    public static func conversationArchived(_ archived: Bool) -> String {
        archived ? "Archived. It's under Archived in Messages." : "Back in Messages."
    }

    public static func favorite(_ favorite: Bool, business: String) -> String {
        favorite ? "\(business) is a favorite." : "\(business) is no longer a favorite."
    }

    public static let copied = "Copied."
    public static let saved = "Saved."

    /// "No match" line for an on-device search. The query is the person's own typing; it is trimmed and capped so a long paste
    /// cannot push the line off the screen.
    public static func noMatch(_ query: String, in what: String) -> String {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        let shown = trimmed.count > maxQueryLength ? String(trimmed.prefix(maxQueryLength)) + "\u{2026}" : trimmed
        return shown.isEmpty ? "No \(what) found." : "No \(what) matches \u{201C}\(shown)\u{201D}."
    }

    public static let maxQueryLength = 40
}
