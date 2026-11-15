import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

// A delivered one-time code (flows F5 and F6; UX_COPY §4 C-OTP-01, C-OTP-02, C-OTP-04, C-TOTP-01; ADR-0020 §6).
//
// Viadere only transports the code: the business generated it and the business checks it. The device's duties are about exposure:
// - the sheet opens on who sent it and when it expires, with the code absent; nothing is consumed by looking;
// - the code is requested only by an explicit tap ("Show code"), which is the server's one-time `open`;
// - it lives in this model's memory only, is cleared when it expires (device clock) and when the sheet closes, and is never logged,
//   never put in a notification, a Live Activity, the watch context or the widget snapshot;
// - copying goes through `SensitiveCopy`: local only (no Universal Clipboard), with an expiry that never outlives the code.

/// What "Copy code" puts on the pasteboard, and until when. The App applies it with `UIPasteboard` (`localOnly`, `expirationDate`).
public struct SensitiveCopy: Sendable, Equatable {
    public var value: String
    public var expiresAt: Date
    /// Always true: a sensitive value never travels to other devices through Universal Clipboard.
    public var localOnly: Bool { true }

    /// The pasteboard lifetime is the shorter of the app's policy (`SensitiveCopyPolicy`) and what is left of the value itself.
    /// `nil` when the value is empty or already expired.
    public static func make(_ value: String, validUntil: Date, now: Date) -> SensitiveCopy? {
        guard !value.isEmpty, validUntil > now else { return nil }
        return SensitiveCopy(value: value, expiresAt: min(SensitiveCopyPolicy.expiration(from: now), validUntil))
    }
}

/// The code sheet.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class CodeDeliveryViewModel {
    public enum Phase: Sendable, Equatable {
        case loading
        /// Who and when are on screen; the code is not on the device yet.
        case ready
        /// "Show code" was tapped; the one-time `open` is in flight.
        case revealing
        /// The code is on screen.
        case revealed
        /// C-OTP-02.
        case expired
        /// The code was already handed over once (here or on another device), or the delivery ended: E-03.
        case gone
        /// "This wasn't me" was sent.
        case reported
        /// E-02. Nothing was sent and nothing is queued.
        case offline
        /// The sheet was closed: nothing is kept.
        case closed
    }

    public private(set) var phase: Phase = .loading
    public private(set) var item: AuthDeliveryItem?
    /// The code, present only in `.revealed`.
    public private(set) var code: String?
    public private(set) var codeKind: AuthCodeKind = .otp

    private let deliveryId: UUID
    private let api: any AuthDeliveryAPI
    private let clock: @Sendable () -> Date

    public init(deliveryId: UUID, api: any AuthDeliveryAPI, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.deliveryId = deliveryId
        self.api = api
        self.clock = clock
    }

    // MARK: Presentation

    public var business: String { UntrustedText.name(item?.business ?? "", max: 40, attribution: nil).text }
    public var title: String { AuthDeliveryCopy.codeTitle(business: business) }
    /// C-TOTP-01 for a partner TOTP code; nothing for an ordinary one-time code.
    public var kindLabel: String? { codeKind == .totp ? AuthDeliveryCopy.totpLabel(business: business) : nil }
    public var useOnlyLine: String { AuthDeliveryCopy.codeUseOnly(business: business) }
    public var neverShareLine: String { AuthDeliveryCopy.codeNeverShare(business: business) }
    /// "Expires at {time}": an absolute time, never a running countdown (UX_COPY §0 rule 10).
    public func expiryLine(formatter: (Date) -> String) -> String? { item.map { AuthDeliveryCopy.expiresAt(formatter($0.expiresAt)) } }
    public var expiresAt: Date? { item?.expiresAt }

    /// The code in groups of three or four for reading, e.g. `482 913`. Empty unless revealed.
    public var displayCode: String {
        guard let code else { return "" }
        let characters = Array(code)
        let size = characters.count % 3 == 0 ? 3 : (characters.count % 4 == 0 ? 4 : characters.count)
        return stride(from: 0, to: characters.count, by: size).map { String(characters[$0..<min($0 + size, characters.count)]) }.joined(separator: " ")
    }

    /// What VoiceOver reads: the characters one by one.
    public var spokenCode: String { (code ?? "").map(String.init).joined(separator: " ") }

    public var canReveal: Bool { phase == .ready }
    public var canCopy: Bool { phase == .revealed && code != nil }
    public var canReport: Bool { phase == .ready || phase == .revealed }
    public var offersTryAgain: Bool { phase == .offline }

    /// The line for a phase that is not the code itself.
    public var message: String? {
        switch phase {
        case .loading, .ready, .revealing, .revealed, .closed: return nil
        case .expired: return AuthDeliveryCopy.codeExpired(business: business)
        case .gone: return AuthDeliveryCopy.noLongerActive
        case .reported: return AuthDeliveryCopy.linkReported(business: business)
        case .offline: return AuthDeliveryCopy.offline
        }
    }

    // MARK: Flow

    /// Fetches who and when. Asks for no code and consumes nothing.
    public func load() async {
        clearCode()
        phase = .loading
        let fetched: AuthDeliveryItem
        do { fetched = try await api.item(deliveryId: deliveryId) } catch let error as AuthDeliveryError {
            phase = error == .offline ? .offline : (error == .expired ? .expired : .gone)
            return
        } catch { phase = .gone; return }
        // A link or a notice is not a code: this sheet shows nothing for it and asks for nothing.
        guard case .code(let kind) = fetched.kind, fetched.deliveryId == deliveryId else { phase = .gone; return }
        item = fetched
        codeKind = kind
        switch fetched.state {
        case .expired: phase = .expired
        case .used, .cancelled: phase = .gone
        case .open: phase = fetched.expiresAt > clock() ? .ready : .expired
        }
    }

    public func tryAgain() async {
        guard offersTryAgain else { return }
        await load()
    }

    /// "Show code": the only path that asks the service for the code. One attempt; a failure is shown, never retried silently.
    public func reveal() async {
        guard phase == .ready, let item else { return }
        guard item.expiresAt > clock() else { phase = .expired; return }
        phase = .revealing
        let delivered: DeliveredCode
        do { delivered = try await api.openCode(deliveryId: deliveryId) } catch let error as AuthDeliveryError {
            // The sheet may have been closed while the call was in flight: it stays closed.
            guard phase == .revealing else { return }
            switch error {
            case .offline: phase = .offline
            // The service answers `410` both for an expiry and for a delivery that ended early; the device clock tells them apart.
            case .expired: phase = item.expiresAt > clock() ? .gone : .expired
            default: phase = .gone
            }
            return
        } catch {
            if phase == .revealing { phase = .gone }
            return
        }
        // Closed, or expired while the answer travelled: the code is dropped unseen.
        guard phase == .revealing else { return }
        guard item.expiresAt > clock() else { phase = .expired; return }
        code = delivered.value
        codeKind = delivered.kind
        phase = .revealed
    }

    /// Called by the sheet on a timer and before every action: an expired code leaves the screen and memory.
    public func tick() {
        guard let item, phase == .ready || phase == .revealed || phase == .revealing else { return }
        if item.expiresAt <= clock() {
            clearCode()
            phase = .expired
        }
    }

    /// What "Copy code" may put on the pasteboard right now; `nil` when there is nothing to copy (hidden, expired, closed).
    public func copyRequest() -> SensitiveCopy? {
        tick()
        guard canCopy, let code, let item else { return nil }
        return SensitiveCopy.make(code, validUntil: item.expiresAt, now: clock())
    }

    /// "This wasn't me": a signed, reduce-only report. The code leaves the screen first.
    public func thisWasntMe() async {
        guard canReport else { return }
        clearCode()
        do {
            try await api.reduce(.delivery(deliveryId), action: .report)
            phase = .reported
        } catch let error as AuthDeliveryError {
            phase = error == .offline ? .offline : (error == .expired ? .expired : .gone)
        } catch { phase = .gone }
    }

    /// The sheet closed (dismissed, or the app left the foreground): nothing is kept.
    public func close() {
        clearCode()
        phase = .closed
    }

    private func clearCode() { code = nil }
}
