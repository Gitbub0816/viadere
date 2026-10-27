import Foundation

// MARK: - Account recovery (§2.25)
//
// There are no emails or phone-based sign-ins to fall back on, so an account that loses every device and its passkey is recovered with
// **recovery codes**: 10 single-use codes issued at registration (shown once, stored only as peppered HMACs) together with a
// **recovery ID** that names the account. Recovery is deliberately slow and loud: a new passkey is registered, then the account waits
// 72 hours (`RecoveryPolicy.holdSeconds`) during which every existing device gets a notice and a push and any trusted device can
// cancel. Only after the hold does the new passkey work, all old devices and sessions are revoked, the remaining codes are
// invalidated and 10 new ones are issued.

public enum RecoveryPolicy {
    /// Recovery codes issued per set.
    public static let codeCount = 10
    /// Hold between registering the new passkey and the recovery taking effect.
    public static let holdSeconds: TimeInterval = 72 * 3600
    /// A recovery that registered no passkey within this long after the code was accepted is dropped.
    public static let passkeyWindow: TimeInterval = 10 * 60
    /// A finished recovery's status token stops working this long after activation.
    public static let completionWindow: TimeInterval = 7 * 24 * 3600
}

/// Shared formats for recovery codes and recovery IDs. Alphabet: `0-9 A-Z` without `I`, `L`, `O`, `U` (Crockford base32).
public enum RecoveryCodeFormat {
    static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    /// A recovery code: 50 random bits as `XXXXX-XXXXX`.
    public static func generateCode() -> String {
        let chars = SecureToken.randomBytes(10).map { alphabet[Int($0) & 31] }
        return String(chars[0..<5]) + "-" + String(chars[5..<10])
    }

    /// A recovery account ID: 60 random bits as `XXXX-XXXX-XXXX`.
    public static func generateRecoveryID() -> String {
        let chars = SecureToken.randomBytes(12).map { alphabet[Int($0) & 31] }
        return String(chars[0..<4]) + "-" + String(chars[4..<8]) + "-" + String(chars[8..<12])
    }

    /// Canonical form (upper case, no spaces or dashes, `I`/`L` → `1`, `O` → `0`) or `nil` when it is not `length` characters of the
    /// alphabet.
    private static func normalize(_ raw: String, length: Int) -> String? {
        guard raw.count <= 64 else { return nil }
        let cleaned = raw.uppercased().filter { !$0.isWhitespace && $0 != "-" }
        guard cleaned.count == length else { return nil }
        let mapped = cleaned.map { ch -> Character in
            switch ch {
            case "I", "L": "1"
            case "O": "0"
            default: ch
            }
        }
        guard mapped.allSatisfy({ alphabet.contains($0) }) else { return nil }
        return String(mapped)
    }

    public static func normalizeCode(_ raw: String) -> String? { normalize(raw, length: 10) }
    public static func normalizeRecoveryID(_ raw: String) -> String? { normalize(raw, length: 12) }
}

/// A set of recovery codes, shown **once** (at registration, after a recovery completes, or after regeneration).
public struct RecoveryCodeSet: Codable, Sendable, Hashable {
    /// Names the account in `POST /v1/recovery/begin`. Not secret on its own, but save it with the codes.
    public var recoveryId: String
    /// `RecoveryPolicy.codeCount` codes, `XXXXX-XXXXX`. Each works once.
    public var codes: [String]
    public var issuedAt: Date

    public init(recoveryId: String, codes: [String], issuedAt: Date) {
        self.recoveryId = recoveryId
        self.codes = codes
        self.issuedAt = issuedAt
    }
}

/// `POST /v1/recovery/begin` (public, rate-limited and attempt-capped). One code is spent. Every failure (unknown recovery ID, wrong
/// or used code, locked account) is the same `401 unauthorized`, so the call cannot be used to find accounts. The response is
/// `PasskeyRegistrationOptions` for a NEW passkey: `ceremonyId` is the recovery's id (`RecoveryID`).
public struct RecoveryBeginRequest: Codable, Sendable, Hashable {
    public var recoveryId: String
    public var code: String
    public init(recoveryId: String, code: String) {
        self.recoveryId = recoveryId
        self.code = code
    }
}

/// `POST /v1/recovery/finish` (public): registers the new passkey and starts the 72 h hold. The new passkey cannot sign in yet.
public struct RecoveryFinishRequest: Codable, Sendable, Hashable {
    /// `PasskeyRegistrationOptions.ceremonyId` from `recovery/begin`.
    public var ceremonyId: CeremonyID
    public var credential: PasskeyRegistrationCredential
    public init(ceremonyId: CeremonyID, credential: PasskeyRegistrationCredential) {
        self.ceremonyId = ceremonyId
        self.credential = credential
    }
}

public enum RecoveryState: String, Codable, Sendable, Hashable {
    /// The code was accepted; the new passkey is not registered yet.
    case awaitingPasskey
    /// The hold is running (`activatesAt`). Any trusted device can cancel.
    case holding
    /// The hold passed: the new passkey is the account's passkey, old devices and sessions are revoked. Sign in with the new passkey.
    case activated
    case cancelled
    /// The hold passed but the completion window ended, or no passkey was registered in time.
    case expired
    case unknown

    public init(from decoder: any Decoder) throws {
        self = RecoveryState(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}

/// State of one recovery.
public struct RecoveryStatus: Codable, Sendable, Hashable {
    public var id: RecoveryID
    public var state: RecoveryState
    public var startedAt: Date
    /// When the hold ends (`nil` until the passkey is registered).
    public var activatesAt: Date?
    /// Returned **only** by `recovery/finish`: the secret the recovering client keeps (and sends to `recovery/complete`) to poll and finish.
    public var statusToken: String?
    /// The replacement recovery codes, present **exactly once**: on the first `recovery/complete` after activation.
    public var recoveryCodes: RecoveryCodeSet?

    public init(id: RecoveryID, state: RecoveryState, startedAt: Date, activatesAt: Date? = nil, statusToken: String? = nil,
                recoveryCodes: RecoveryCodeSet? = nil) {
        self.id = id
        self.state = state
        self.startedAt = startedAt
        self.activatesAt = activatesAt
        self.statusToken = statusToken
        self.recoveryCodes = recoveryCodes
    }
}

/// `POST /v1/recovery/complete` (public, rate-limited): polls a recovery with its `statusToken`. Once the hold has passed and nobody
/// cancelled, it activates (if the server's sweep has not already) and returns the replacement codes once.
public struct RecoveryCompleteRequest: Codable, Sendable, Hashable {
    public var recoveryId: RecoveryID
    public var statusToken: String
    public init(recoveryId: RecoveryID, statusToken: String) {
        self.recoveryId = recoveryId
        self.statusToken = statusToken
    }
}

/// A recovery that is holding on this account (`GET /v1/recovery`), for the "Not you? Cancel" screen.
public struct PendingRecovery: Codable, Sendable, Hashable {
    public var id: RecoveryID
    public var startedAt: Date
    public var activatesAt: Date
    public init(id: RecoveryID, startedAt: Date, activatesAt: Date) {
        self.id = id
        self.startedAt = startedAt
        self.activatesAt = activatesAt
    }
}

/// Recovery settings for the signed-in account.
public struct RecoveryInfo: Codable, Sendable, Hashable {
    /// Unused codes left (0 = none issued yet or all used: regenerate).
    public var remainingCodes: Int
    public var issuedAt: Date?
    /// The earliest pending recovery (kept for older clients; `pendingRecoveries` is the complete list).
    public var pending: PendingRecovery?
    /// Every recovery waiting out its 72 h hold, oldest first. The source of truth for "Recovery in progress - Cancel": cancel each one.
    public var pendingRecoveries: [PendingRecovery]
    public init(remainingCodes: Int, issuedAt: Date? = nil, pending: PendingRecovery? = nil, pendingRecoveries: [PendingRecovery]? = nil) {
        self.remainingCodes = remainingCodes
        self.issuedAt = issuedAt
        self.pending = pending ?? pendingRecoveries?.first
        self.pendingRecoveries = pendingRecoveries ?? pending.map { [$0] } ?? []
    }

    private enum CodingKeys: String, CodingKey { case remainingCodes, issuedAt, pending, pendingRecoveries }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        remainingCodes = try container.decode(Int.self, forKey: .remainingCodes)
        issuedAt = try container.decodeIfPresent(Date.self, forKey: .issuedAt)
        let single = try container.decodeIfPresent(PendingRecovery.self, forKey: .pending)
        let all = try container.decodeIfPresent([PendingRecovery].self, forKey: .pendingRecoveries)
        pending = single ?? all?.first
        pendingRecoveries = all ?? single.map { [$0] } ?? []
    }
}

/// `POST /v1/recovery/codes/regenerate` (trusted device + a fresh passkey assertion over the challenge from
/// `POST /v1/recovery/codes/begin`, which returns `PasskeyAssertionOptions`). Invalidates the old codes and returns a new
/// `RecoveryCodeSet` once. Also the way to get codes for an account that predates recovery codes.
public struct RecoveryCodesRegenerateRequest: Codable, Sendable, Hashable {
    public var ceremonyId: CeremonyID
    public var assertion: PasskeyAssertionCredential
    public init(ceremonyId: CeremonyID, assertion: PasskeyAssertionCredential) {
        self.ceremonyId = ceremonyId
        self.assertion = assertion
    }
}
