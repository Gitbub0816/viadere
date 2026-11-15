import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// Why a device is being enrolled. A first enrollment right after sign-up or sign-in may skip the passkey assertion
/// (the server says so with `assertionOptional`); setting a device up **again** never may.
public enum EnrollmentPurpose: Sendable, Equatable {
    case firstDevice
    /// "Set up again" after the biometric key was invalidated: always performs a fresh, user-verified passkey assertion.
    case setUpAgain
}

/// What the person is told **before** the system passkey sheet appears, so the sheet is never a surprise.
public struct PasskeyExplanation: Sendable, Equatable {
    public enum Context: Sendable, Equatable { case addDevice, setUpAgain, appClip }

    public var context: Context
    public var title: String
    public var message: String
    public var points: [String]
    public var continueTitle: String

    public init(context: Context, title: String, message: String, points: [String], continueTitle: String) {
        self.context = context
        self.title = title
        self.message = message
        self.points = points
        self.continueTitle = continueTitle
    }

    public static func make(_ context: Context) -> PasskeyExplanation {
        switch context {
        case .addDevice:
            PasskeyExplanation(
                context: context, title: "Confirm it's you",
                message: "Before this iPhone can approve requests for your account, Viadere checks that you hold your passkey. Your iPhone will ask for Face ID or your passcode next.",
                points: ["It stops anyone who only has a copy of your sign-in from adding their own device.",
                         "Nothing is shared: your passkey only signs a one-time challenge."],
                continueTitle: "Continue with passkey")
        case .setUpAgain:
            PasskeyExplanation(
                context: context, title: "Confirm it's you to set up again",
                message: "The keys that approved requests on this iPhone were retired, so new ones need your passkey. Your iPhone will ask for Face ID or your passcode next.",
                points: ["New keys are created inside this iPhone and can't be copied.",
                         "If you have another trusted device, it may be asked to confirm this one before high-risk approvals work."],
                continueTitle: "Continue with passkey")
        case .appClip:
            PasskeyExplanation(
                context: context, title: "Confirm it's you",
                message: "To connect, Viadere checks that you hold your account's passkey. Your iPhone will ask for Face ID or your passcode next.",
                points: ["This quick connection can never approve purchases or sign-ins."],
                continueTitle: "Continue with passkey")
        }
    }
}

/// Shows the explanation and reports whether the person chose to continue. `false` cancels the enrollment.
public typealias PasskeyExplainer = @Sendable (PasskeyExplanation) async -> Bool

/// Bridges `AccountService` (which needs a yes or no) to a SwiftUI screen (which shows `pending` and calls `resolve`).
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class PasskeyExplanationGate {
    public private(set) var pending: PasskeyExplanation?
    private final class Waiter { var continuation: CheckedContinuation<Bool, Never>? }
    private let waiter = Waiter()

    public init() {}

    /// Suspends until `resolve` is called. A second request cancels the first.
    public func request(_ explanation: PasskeyExplanation) async -> Bool {
        waiter.continuation?.resume(returning: false)
        waiter.continuation = nil
        pending = explanation
        return await withCheckedContinuation { waiter.continuation = $0 }
    }

    public func resolve(_ proceed: Bool) {
        pending = nil
        waiter.continuation?.resume(returning: proceed)
        waiter.continuation = nil
    }

    /// The closure to pass to `AccountService`.
    public nonisolated var explainer: PasskeyExplainer { { [self] explanation in await self.request(explanation) } }
}
