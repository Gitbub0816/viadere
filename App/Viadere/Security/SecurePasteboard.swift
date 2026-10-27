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
}
