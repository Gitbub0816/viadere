import Crypto
import Foundation
#if canImport(Observation) && !os(Linux)
import Observation
#endif

// Device-add comparison code (ADR-0033 §4.1, UX_COPY S-DEV-03..05). UI and Kit logic only: the authority side arrives in Stage 6, so every
// entry point is behind `AuthDeliveryFlags.deviceAddComparison` (off in `.shipping`).
//
// The NEW device shows a code derived from the keys it holds; the EXISTING device never shows it and asks the person to type it. Showing it
// on the existing device would let the person copy that device's own screen and would prove nothing.

public enum DeviceAddCode {
    /// `decimal6(SHA-256("VIADERE-DEVICE-ADD-V1\n" ‖ env ‖ "\n" ‖ nonce ‖ "\n" ‖ join("\n", sorted kids)))`: the big-endian unsigned integer
    /// of the first 8 bytes, modulo 1 000 000, written with 6 digits (leading zeros kept). `kids` sort ascending by byte order.
    public static func code(env: String, nonce: String, kids: [String]) -> String {
        let sorted = kids.sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }
        let input = "VIADERE-DEVICE-ADD-V1\n" + env + "\n" + nonce + "\n" + sorted.joined(separator: "\n")
        let digest = SHA256.hash(data: Data(input.utf8))
        var value: UInt64 = 0
        for byte in digest.prefix(8) { value = (value << 8) | UInt64(byte) }
        let number = value % 1_000_000
        let digits = String(number)
        return String(repeating: "0", count: 6 - digits.count) + digits
    }

    /// Two groups of three for reading aloud and copying by eye (S-DEV-03): `123 456`. VoiceOver reads digit by digit.
    public static func display(_ code: String) -> String {
        guard code.count == 6 else { return code }
        return "\(code.prefix(3)) \(code.suffix(3))"
    }

    public static func spoken(_ code: String) -> String { code.map(String.init).joined(separator: ", ") }
}

/// The verified `keylog_device_added` challenge statement, reduced to what the screens need. Built by the (Stage 6) authority client after it
/// verified the signature and the freshness; nothing here is checked against the api.
public struct DeviceAddChallenge: Sendable, Equatable {
    public var env: String
    /// The challenge's base64url nonce (drawn by the authority after the entry's keys were fixed, ADR-0033 §4.1 item 2).
    public var nonce: String
    /// Every key the entry adds.
    public var kids: [String]
    public var accountRef: String
    /// The name the new device sent: reported text, labelled as such, sanitized by the caller (≤ 40 characters).
    public var reportedName: String
    public var expiresAt: Date

    public init(env: String, nonce: String, kids: [String], accountRef: String, reportedName: String, expiresAt: Date) {
        self.env = env
        self.nonce = nonce
        self.kids = kids
        self.accountRef = accountRef
        self.reportedName = reportedName
        self.expiresAt = expiresAt
    }
}

/// The new device (B): shows the comparison code, but only after checking that the signed challenge lists **exactly** its own keys.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class NewDeviceComparisonViewModel {
    public enum Phase: Sendable, Equatable {
        case unavailable
        /// The challenge lists keys that are not exactly this device's (S-DEV-05): no code is shown.
        case refused
        case showing(code: String)
    }

    public private(set) var phase: Phase

    public init(challenge: DeviceAddChallenge, ownKids: [String], flags: AuthDeliveryFlags = .shipping, now: Date = Date()) {
        guard flags.deviceAddComparison else { phase = .unavailable; return }
        let mine = Set(ownKids)
        // Exactly this device's keys: the same set, no extras, no duplicates, none missing, and not expired.
        guard !ownKids.isEmpty, mine.count == ownKids.count, challenge.kids.count == mine.count, Set(challenge.kids) == mine,
              challenge.expiresAt > now else { phase = .refused; return }
        phase = .showing(code: DeviceAddCode.code(env: challenge.env, nonce: challenge.nonce, kids: challenge.kids))
    }

    public var title: String? {
        if case .showing(let code) = phase { return AuthDeliveryCopy.newDeviceCodeTitle(code: DeviceAddCode.display(code)) }
        return nil
    }
    public var detail: String? { if case .showing = phase { return AuthDeliveryCopy.newDeviceCodeDetail } else { return nil } }
    public var refusal: String? { phase == .refused ? AuthDeliveryCopy.deviceChallengeMismatch : nil }
    /// VoiceOver text for the code (digit by digit).
    public var spokenCode: String? { if case .showing(let code) = phase { return DeviceAddCode.spoken(code) } else { return nil } }
}

public enum DeviceAddApprovalResult: Sendable, Equatable {
    case added
    case wrongNumber
    case failed
}

/// Sends the typed digits in the factor JWS `match` member after Face ID (the authority compares them; ADR-0033 §4.1 item 6).
public protocol DeviceAddApproving: Sendable {
    func approve(match: String) async -> DeviceAddApprovalResult
}

/// The existing device (A): asks for the number shown on the new device. **It has no property or method that returns the code.**
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class ExistingDeviceApprovalViewModel {
    public static let digits = 6
    public static let maxWrongEntries = 3

    public enum Phase: Sendable, Equatable {
        case unavailable
        /// The challenge's `account_ref` is not this account's (S2-A2-11 item 4).
        case refused
        case entering
        case submitting
        case added
        /// Three wrong numbers: the entry ended; the new device starts again with new keys.
        case ended
        case reported
    }

    public private(set) var phase: Phase
    public private(set) var entry = ""
    public private(set) var notice: String?
    public private(set) var announcement: String?
    public let reportedName: String
    private let approver: any DeviceAddApproving
    private let reducer: (@Sendable () async -> Void)?
    private var wrong = 0

    public init(challenge: DeviceAddChallenge, ownAccountRef: String, approver: any DeviceAddApproving, flags: AuthDeliveryFlags = .shipping,
                now: Date = Date(), reportNotMe: (@Sendable () async -> Void)? = nil) {
        reportedName = UntrustedText.line(challenge.reportedName, max: 40)
        self.approver = approver
        reducer = reportNotMe
        if !flags.deviceAddComparison { phase = .unavailable }
        else if challenge.accountRef != ownAccountRef || challenge.expiresAt <= now { phase = .refused }
        else { phase = .entering }
    }

    public var title: String { AuthDeliveryCopy.existingDeviceTitle }
    public var nameRow: String { AuthDeliveryCopy.existingDeviceName(reportedName) }
    public var fieldLabel: String { AuthDeliveryCopy.deviceNumberLabel }
    public var helper: String { AuthDeliveryCopy.deviceNumberHelper }
    public var traits: NumberFieldTraits { .required }
    public var refusal: String? { phase == .refused ? AuthDeliveryCopy.deviceChallengeMismatch : nil }

    /// Equal prominence, safe action first; Add device is disabled (not hidden) until six digits are entered.
    public var buttons: [SafeActionButton] {
        [SafeActionButton(role: .notMe, title: AuthDeliveryCopy.notMe, isEnabled: phase == .entering),
         SafeActionButton(role: .proceed, title: AuthDeliveryCopy.addDevice, isEnabled: phase == .entering && isComplete)]
    }

    public var isComplete: Bool { NumberMatcher.isComplete(entry, digits: Self.digits) }

    public var resultLine: String? {
        switch phase {
        case .ended: return AuthDeliveryCopy.deviceWrongNumberFinal
        default: return nil
        }
    }

    /// Paste, AutoFill and replacement are refused, as on the approval screen. Unlike approval codes, a device code may start with 0
    /// (it keeps leading zeros), so the leading-zero rule does not apply: only ASCII digits, one at a time.
    public func edit(_ proposed: String) {
        guard phase == .entering else { return }
        if proposed == entry { return }
        let deleting = entry.hasPrefix(proposed)
        let appending = proposed.hasPrefix(entry) && proposed.count == entry.count + 1
        guard deleting || appending, proposed.unicodeScalars.allSatisfy({ (0x30...0x39).contains($0.value) }), proposed.count <= Self.digits else { return }
        entry = proposed
    }

    /// Add device: the implementation of `DeviceAddApproving` confirms with Face ID and signs. The code is compared by the authority.
    public func add() async {
        guard phase == .entering, isComplete else { return }
        phase = .submitting
        let typed = entry
        switch await approver.approve(match: typed) {
        case .added:
            phase = .added
        case .wrongNumber:
            wrong += 1
            entry = ""
            if wrong >= Self.maxWrongEntries {
                phase = .ended
                notice = AuthDeliveryCopy.deviceWrongNumberFinal
            } else {
                phase = .entering
                notice = AuthDeliveryCopy.deviceWrongNumber
            }
            announcement = notice
        case .failed:
            phase = .entering
            notice = AuthDeliveryCopy.offline
            announcement = notice
        }
    }

    public func thisWasntMe() async {
        guard phase == .entering else { return }
        await reducer?()
        phase = .reported
    }
}
