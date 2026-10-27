import Foundation
import Observation
import ViadereCore
import ViadereKit

/// Which verification request is open, set by a notification tap or by the list in Settings. `MainShell` presents the sheet.
@MainActor
@Observable
final class VerificationCenter {
    var presented: VerificationRequestID?

    func present(_ id: VerificationRequestID) { presented = id }

    /// A tap on the "verification request" notification. The push carries only the opaque request id.
    static func requestId(fromPushUserInfo userInfo: [AnyHashable: Any]) -> VerificationRequestID? {
        (userInfo["iid"] as? String).flatMap { VerificationRequestID($0) }
    }
}
