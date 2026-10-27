import ActivityKit
import Foundation
import ViadereCore

/// Live Activity attributes shared by the app (which starts them) and the widget extension (which draws them).
/// The dynamic part is ViadereCore's `LiveActivityStatus` (order, delivery, flight, appointment), so a status
/// push from the server decodes straight into `ContentState`.
struct ViadereActivityAttributes: ActivityAttributes {
    typealias ContentState = LiveActivityStatus

    /// Verified business display name.
    var businessName: String
    var businessId: String
    var interactionId: String
}
