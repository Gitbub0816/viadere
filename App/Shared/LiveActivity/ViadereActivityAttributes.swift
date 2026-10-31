import ActivityKit
import Foundation
import SwiftUI
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
    /// The Brand Kit accent (`#RRGGBB`) per appearance, set by the app from `BrandSurfacePolicy.liveActivityAccent`: only the kit's
    /// `accent` token, only if the contrast clamp kept it, never for sign-in approvals, payment authorizations or security purposes.
    /// Fixed when the activity starts (no mid-flow change); `nil` = Viadere's champagne. Optional so older activities still decode.
    var accentLight: String? = nil
    var accentDark: String? = nil
}

extension ViadereActivityAttributes {
    /// The accent the widget draws: the kit's (validated hex) or Viadere's own. Title, status, actions and alert colors stay neutral.
    var accent: Color {
        let light = accentLight.flatMap(BrandColor.init)
        let dark = accentDark.flatMap(BrandColor.init)
        guard light != nil || dark != nil else { return ViadereColor.accent }
        return Color(brandLight: light, dark: dark, fallbackLight: 0x8C7550, fallbackDark: 0xCDB993)
    }
}
