import ActivityKit
import Foundation
import ViadereCore

/// Live Activity attributes shared by the app (which starts them) and the widget extension (which draws them).
/// The dynamic part is ViadereCore's `LiveActivityStatus` (order, delivery, flight, appointment, or a pending decision), so a
/// push from the server decodes straight into `ContentState`. A decision's pushed state carries no business text; the app adds it
/// on the device (`LiveActivityManager`, docs/SECURITY.md §2.16).
struct ViadereActivityAttributes: ActivityAttributes {
    typealias ContentState = LiveActivityStatus

    /// Verified business display name.
    var businessName: String
    var businessId: String
    var interactionId: String
}
