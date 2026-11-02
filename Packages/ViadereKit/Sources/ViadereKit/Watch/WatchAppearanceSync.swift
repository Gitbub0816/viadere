import Foundation

/// The phone's appearance choice, carried to the watch inside the same WatchConnectivity application context as the pending list
/// (`WatchSync.appearanceKey`). The watch has no light appearance and no app group: it draws the night theme of the chosen pairing and
/// keeps the last received choice in its own defaults. Nothing secret travels: two theme ids, a follow mode and a flag.
extension AppearanceSelection {
    /// The theme the watch draws: the night side of the choice (always, whatever `follow` says), standard contrast.
    public var watchTheme: AppearanceTheme { theme(for: .dark) }
}

extension WatchSync {
    public static let appearanceKey = "appearance.v1"

    public static func encode(_ selection: AppearanceSelection) -> Data? { try? JSONEncoder().encode(selection) }

    /// `nil` when the data is missing or is not a selection (the caller then keeps what it has, or the default).
    public static func decodeAppearance(_ data: Data?) -> AppearanceSelection? {
        guard let data, let value = try? JSONDecoder().decode(AppearanceSelection.self, from: data) else { return nil }
        return value
    }

    /// The application context the phone publishes (latest wins, so it always carries both parts).
    public static func context(items: [WatchPendingItem], appearance: AppearanceSelection) -> [String: Data] {
        var context: [String: Data] = [:]
        if let data = encode(items) { context[contextKey] = data }
        if let data = encode(appearance) { context[appearanceKey] = data }
        return context
    }

    /// Watch side: the choice in a received context, `nil` when the phone has not sent one (an older phone build, or never synced).
    public static func appearance(fromContext context: [String: Any]) -> AppearanceSelection? {
        decodeAppearance(context[appearanceKey] as? Data)
    }

    /// Watch side: what to draw now. The received choice, else the one stored from an earlier sync, else the default pairing.
    public static func resolveWatchAppearance(received: AppearanceSelection?, stored: AppearanceSelection?) -> AppearanceSelection {
        received ?? stored ?? .default
    }
}
