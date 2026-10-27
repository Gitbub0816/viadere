import Foundation
import ViadereCore

/// Local state outside the Keychain that sign-out, account deletion and device revocation must also erase.
/// Abstracted so the **order** (server revocation, then residue, then keys) is unit-testable; the app supplies
/// the UIKit/UserNotifications/ActivityKit/WatchConnectivity implementation.
public protocol LocalResidueCleaner: Sendable {
    /// Removes delivered notifications (they can still show names, amounts and locations in Notification Center).
    func removeDeliveredNotifications() async
    /// Ends every Live Activity (they show business names and order or trip details on the Lock Screen).
    func endLiveActivities() async
    /// Clears the application context shared with the watch (pending requests and their headlines).
    func clearWatchContext() async
    /// Removes the per-interaction dynamic notification categories (`viadere.choose.<id>`), keeping the static ones.
    func removeDynamicNotificationCategories() async
}

/// Does nothing (extensions, tests, previews).
public struct NoLocalResidueCleaner: LocalResidueCleaner {
    public init() {}
    public func removeDeliveredNotifications() async {}
    public func endLiveActivities() async {}
    public func clearWatchContext() async {}
    public func removeDynamicNotificationCategories() async {}
}

extension LocalResidueCleaner {
    /// Runs every cleanup, in a fixed order.
    public func cleanAll() async {
        await removeDeliveredNotifications()
        await endLiveActivities()
        await clearWatchContext()
        await removeDynamicNotificationCategories()
    }
}

/// Lets the networking layer tell the app that the server stopped trusting this device (repeated signature
/// rejection). `AppModel` registers a handler that wipes local state; extensions register none.
public final class DeviceRevocationNotifier: @unchecked Sendable {
    private let lock = NSLock()
    private var handler: (@Sendable () -> Void)?
    private var fired = false

    public init() {}

    /// Registers the single handler (replaces any previous one) and re-arms the notifier.
    public func setHandler(_ handler: (@Sendable () -> Void)?) {
        lock.lock(); defer { lock.unlock() }
        self.handler = handler
        fired = false
    }

    /// Called from the API client. Fires the handler at most once until it is set again.
    public func notify() {
        lock.lock()
        let handler = fired ? nil : self.handler
        if handler != nil { fired = true }
        lock.unlock()
        handler?()
    }
}

/// Kit-side enrollment body: ViadereCore's `DeviceEnrollRequest` plus the App Clip marker.
///
/// `clipDevice: true` tells the server this is a request-key-only, short-lived device created by the App Clip:
/// it may sign API requests but the server refuses approvals from it and expires it (documented in
/// docs/SECURITY.md). The key is omitted entirely for a normal device, so the body is unchanged for the full app.
public struct DeviceEnrollmentPayload: Codable, Sendable, Hashable {
    public var name: String
    public var platform: DevicePlatform
    public var challenge: String
    public var keys: [DeviceKeyRegistration]
    public var clipDevice: Bool?

    public init(name: String, platform: DevicePlatform, challenge: String, keys: [DeviceKeyRegistration], clipDevice: Bool = false) {
        self.name = name
        self.platform = platform
        self.challenge = challenge
        self.keys = keys
        self.clipDevice = clipDevice ? true : nil
    }

    public var isClipDevice: Bool { clipDevice == true }

    /// The body ViadereCore's server model understands (no clip marker).
    public var base: DeviceEnrollRequest { DeviceEnrollRequest(name: name, platform: platform, challenge: challenge, keys: keys) }
}

/// Reads only the fields needed to find App Clip devices in `GET /v1/devices`.
struct DeviceClipFlag: Decodable, Sendable {
    var id: DeviceID
    var clipDevice: Bool?
    var revokedAt: Date?
}
