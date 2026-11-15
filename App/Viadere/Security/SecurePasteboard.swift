import UIKit
import UniformTypeIdentifiers
import ViadereKit

/// Copies sensitive values (business codes, redemption codes) with an expiry and without Universal Clipboard.
enum SecurePasteboard {
    @MainActor
    static func copy(_ string: String) {
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: string]],
            options: [.localOnly: true, .expirationDate: SensitiveCopyPolicy.expiration()])
    }

    /// A value whose own lifetime may be shorter than the policy's (a delivered one-time code): the item expires at `request.expiresAt`,
    /// which `SensitiveCopy.make` already capped at the policy and at the value's expiry. Always local only.
    @MainActor
    static func copy(_ request: SensitiveCopy) {
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: request.value]],
            options: [.localOnly: request.localOnly, .expirationDate: request.expiresAt])
    }
}
