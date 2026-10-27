import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// Formats a server redemption code for reading aloud and typing: "K7M29QXP" -> "K7M2 9QXP".
public enum RedemptionCodeFormat {
    public static func display(_ code: String) -> String {
        var out = ""
        for (index, character) in code.enumerated() {
            if index > 0, index % 4 == 0 { out.append(" ") }
            out.append(character)
        }
        return out
    }

    /// VoiceOver reads characters one at a time.
    public static func spoken(_ code: String) -> String { code.map(String.init).joined(separator: " ") }
}

/// A single redemption: asks the server for a short-lived, single-use code, counts it down, and forgets it.
///
/// Rules (spec §10; SECURITY.md "no caching of sensitive codes"):
/// - the code exists only in this object's memory: never persisted, never in a URL, never in logs, never prefetched;
/// - it disappears at expiry, when the view goes away, when the app backgrounds, and while the screen is recorded;
/// - a screenshot is noted so the screen can warn the person (the code is single-use and short-lived either way).
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class RedemptionViewModel {
    public enum Phase: Equatable, Sendable {
        case idle
        case requesting
        case active
        case expired
        /// The server declined (not eligible any more, limit reached).
        case refused(String)
        case failed(String)
    }

    /// Never show a code for longer than this, whatever the server says (guards against a badly skewed clock).
    public static let maximumDisplayLifetime: TimeInterval = 15 * 60

    public let entry: RewardEntry
    public private(set) var phase: Phase = .idle
    public private(set) var now: Date
    public var isScreenBeingCaptured = false
    public private(set) var screenshotTaken = false
    public let rewardTitle: String
    public let businessName: String

    private var code: String?
    private var expiry: Date?
    private var lifetime: TimeInterval = 1
    private let services: ViadereServices
    private let onFinished: @MainActor () async -> Void

    public init(entry: RewardEntry, services: ViadereServices, onFinished: @escaping @MainActor () async -> Void = {}) {
        self.entry = entry
        self.services = services
        self.onFinished = onFinished
        self.now = services.clock()
        self.rewardTitle = entry.reward.title
        self.businessName = entry.business.displayName
    }

    // MARK: Display state

    /// The code, only while it is valid and the screen isn't being recorded.
    public var visibleCode: String? {
        guard phase == .active, !isScreenBeingCaptured else { return nil }
        return code
    }

    public var displayCode: String? { visibleCode.map(RedemptionCodeFormat.display) }
    public var spokenCode: String? { visibleCode.map(RedemptionCodeFormat.spoken) }

    /// What the QR encodes: the server's code verbatim, for the business's scanner to validate.
    public var qrPayload: String? { visibleCode }

    public var remaining: TimeInterval {
        guard let expiry else { return 0 }
        return max(0, expiry.timeIntervalSince(now))
    }

    /// 1 when fresh, 0 at expiry.
    public var fraction: Double { phase == .active ? min(1, max(0, remaining / lifetime)) : 0 }

    /// "1:42"
    public var countdownLabel: String {
        let seconds = Int(remaining.rounded(.up))
        return String(format: "%d:%02d", seconds / 60, seconds % 60)
    }

    public var spokenCountdown: String {
        let seconds = Int(remaining.rounded(.up))
        return seconds >= 60 ? "Expires in \(seconds / 60) minutes \(seconds % 60) seconds" : "Expires in \(seconds) seconds"
    }

    public var isBusy: Bool { phase == .requesting }
    public var canRequestAgain: Bool { phase == .expired || { if case .failed = phase { return true } else { return false } }() }

    // MARK: Lifecycle

    /// Asks the server for a code (device-signed). The server re-checks eligibility and may refuse.
    public func start() async {
        guard phase == .idle || canRequestAgain, entry.eligibility.state == .eligible, entry.eligibility.nextAction == .redeem else {
            if phase == .idle { phase = .refused("This reward isn't available to use right now.") }
            return
        }
        phase = .requesting
        screenshotTaken = false
        do {
            let redemption = try await services.api.redeemReward(entry.id, RedeemRewardRequest())
            let received = services.clock()
            now = received
            let capped = min(redemption.expiresAt, received.addingTimeInterval(Self.maximumDisplayLifetime))
            guard capped > received else { phase = .expired; return }
            code = redemption.redemptionCode
            expiry = capped
            lifetime = max(1, capped.timeIntervalSince(received))
            phase = .active
        } catch {
            code = nil
            expiry = nil
            phase = RewardErrors.isStaleVerdict(error) ? .refused(RewardErrors.message(for: error)) : .failed(RewardErrors.message(for: error))
            await onFinished()
        }
    }

    /// Call every second while visible.
    public func tick(_ date: Date) {
        now = date
        if phase == .active, let expiry, date >= expiry { expire() }
    }

    private func expire() {
        wipe()
        phase = .expired
        Task { await onFinished() }
    }

    /// Forget the code (view disappeared, app backgrounded, person closed it).
    public func invalidate() {
        let wasActive = phase == .active
        wipe()
        if wasActive { phase = .expired }
    }

    private func wipe() {
        code = nil
        expiry = nil
    }

    public func noteScreenshot() {
        guard phase == .active else { return }
        screenshotTaken = true
    }

    public func dismissScreenshotNotice() { screenshotTaken = false }

    /// Copying is allowed (for typing at a register) but only through the app's secure pasteboard policy.
    public var codeForSecureCopy: String? { visibleCode }
}
