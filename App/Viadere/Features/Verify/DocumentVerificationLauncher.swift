import DiditSDK
import Foundation
import SwiftUI
import UIKit
import ViadereKit

/// Runs Didit's native flow (DiditSDK, Core variant: manual capture, no NFC) with a session token from the Viadere server.
///
/// The SDK renders its own screens, themed for Viadere in the provider console (White Label). Document images, the selfie and the
/// liveness video go from this phone to the provider; Viadere never receives them, and the server deletes the provider session after it
/// has read the one claim it needs. The SDK's own result is advisory: the app asks the server, which re-fetches the decision itself.
@MainActor
final class DocumentVerificationLauncher: DocumentVerificationService {
    static let shared = DocumentVerificationLauncher()

    private var continuation: CheckedContinuation<DocumentFlowResult, Never>?

    /// Called by `DiditResultModifier` when the SDK reports an end.
    func finish(_ result: DocumentFlowResult) {
        continuation?.resume(returning: result)
        continuation = nil
    }

    nonisolated func verify(sessionToken: String) async -> DocumentFlowResult {
        await MainActor.run { Self.shared }.run(sessionToken: sessionToken)
    }

    private func run(sessionToken: String) async -> DocumentFlowResult {
        // One flow at a time: a second request while one is running ends the first as cancelled.
        finish(.cancelled)
        return await withCheckedContinuation { continuation in
            self.continuation = continuation
            DiditSdk.shared.startVerification(token: sessionToken)
        }
    }
}

extension View {
    /// Attach once near the root: `.diditVerification` presents the SDK and reports back to the launcher.
    func viadereDocumentVerification() -> some View {
        diditVerification { result in
            switch result {
            case .completed: DocumentVerificationLauncher.shared.finish(.finished)
            case .cancelled: DocumentVerificationLauncher.shared.finish(.cancelled)
            case .failed: DocumentVerificationLauncher.shared.finish(.failed)
            @unknown default: DocumentVerificationLauncher.shared.finish(.failed)
            }
        }
    }
}
