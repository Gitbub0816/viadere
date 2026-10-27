import Foundation

/// Policy for anything the user copies out of the app (redemption codes, business codes, OTPs).
/// The UI layer applies it to `UIPasteboard` with `.expirationDate` and `.localOnly` (no Universal Clipboard).
public enum SensitiveCopyPolicy {
    /// Seconds a copied sensitive value stays on the pasteboard.
    public static let pasteboardLifetime: TimeInterval = 60

    public static func expiration(from now: Date = Date()) -> Date { now.addingTimeInterval(pasteboardLifetime) }
}
