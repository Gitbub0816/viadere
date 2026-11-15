import Crypto
import Foundation

// Device pairing (implementation plan v3 WP-D1, SECURITY.md §2.107, vectors `docs/protocol/vectors/device-pairing-v1.json`).
//
// A new device (B) joins an account that has no passkey by approval from a trusted device (A, tier D1) of that account:
//
// 1. A (D1) creates a short-lived **pairing code** (`DevicePairingCode`) in Settings → Trusted devices → Add another device. It is the only
//    thing that names the account, and it names it only to the server (B never sends or learns an account id).
// 2. B opens a ceremony, creates its own non-exportable keys, proves possession over `VIADERE-ENROLL-V1` with the pairing id in the subject
//    slot, and starts the pairing with the code. The server draws a fresh 256-bit **nonce** only after B's keys are stored.
// 3. B shows the **comparison code** `DevicePairing.code(comparisonDigest:)`, computed from its *own* keys, the pairing id and the nonce.
// 4. A sees the request only in its own device-signed session, asks the person for the number shown on B (A never shows it), and signs a
//    `VIADERE-PAIR-V1` statement with its biometric approval key. The server compares the typed number with the code of the keys it stored.
//    A substituted B key (a relay starting its own pairing) gives a different code, so the number the person reads off their real B does not
//    match, and nothing is added.

public enum DevicePairing {
    /// Domain separator of A's approval statement.
    public static let statementDomain = "VIADERE-PAIR-V1"
    /// Domain separator of the comparison digest.
    public static let comparisonDomain = "VIADERE-PAIR-CODE-V1"
    /// The push category for a pairing request on the trusted devices (no name, code or number in it; a tap opens Alerts, where the request
    /// is listed in the device-signed session).
    public static let pushCategory = "viadere.security.pairing"

    /// A pairing code lives 10 minutes: long enough to install Viadere on a new phone, short enough that a code seen over a shoulder goes stale.
    public static let invitationTTL: TimeInterval = 10 * 60
    /// B's ceremony (begin → start) lives 5 minutes, like every other enrollment challenge (§2.5).
    public static let ceremonyTTL: TimeInterval = 5 * 60
    /// A started pairing lives **5 minutes**: enough to pick up both devices, read six digits and confirm with Face ID; short enough that a
    /// relayed or forgotten request cannot wait for a moment of inattention. It matches the request-signing window (§2.3, 300 s).
    public static let pairingTTL: TimeInterval = 5 * 60
    /// After approval, B has this long to collect its session; then the sweep revokes the unclaimed device.
    public static let sessionPickupWindow: TimeInterval = 10 * 60
    /// Wrong numbers before the pairing ends (B starts again with new keys), as for the key-log device add (ADR-0033 §4.1 item 3).
    public static let maxWrongEntries = 3
    public static let codeDigits = 6

    /// Lowercase hex `SHA-256("VIADERE-PAIR-CODE-V1\n" ‖ pairingId ‖ "\n" ‖ nonce ‖ "\n" ‖ keyListDigest)`, where `keyListDigest` is
    /// `AppAttestBinding.keyListDigest` of the new device's keys (one `{purpose}:{base64url X9.63}` line per key, sorted, LF-joined, SHA-256 hex).
    public static func comparisonDigest(pairingId: DevicePairingID, nonce: String, keyListDigest: String) -> String {
        SecureToken.sha256Hex(comparisonInput(pairingId: pairingId, nonce: nonce, keyListDigest: keyListDigest))
    }

    public static func comparisonDigest(pairingId: DevicePairingID, nonce: String, keys: [DeviceKeyRegistration]) -> String {
        comparisonDigest(pairingId: pairingId, nonce: nonce, keyListDigest: AppAttestBinding.keyListDigest(keys))
    }

    static func comparisonInput(pairingId: DevicePairingID, nonce: String, keyListDigest: String) -> Data {
        Data([comparisonDomain, pairingId.description, nonce, keyListDigest].joined(separator: "\n").utf8)
    }

    /// `keyListDigest` for keys given as (purpose, public key) pairs, as A receives them.
    public static func keyListDigest(_ keys: [DevicePairingKey]) -> String {
        let lines = keys.map { "\($0.purpose.rawValue):\($0.publicKey.base64URL)" }.sorted()
        return SecureToken.sha256Hex(Data(lines.joined(separator: "\n").utf8))
    }

    /// The 6-digit comparison code: the big-endian unsigned integer of the first 8 bytes of the digest, modulo 1 000 000, with leading zeros
    /// (`decimal6`, the same reduction as the key-log device add, bias below 2^-44). `nil` for a digest that is not 64 hex characters.
    public static func code(comparisonDigest: String) -> String? {
        guard let bytes = hexBytes(comparisonDigest), bytes.count == 32 else { return nil }
        var value: UInt64 = 0
        for byte in bytes.prefix(8) { value = (value << 8) | UInt64(byte) }
        let digits = String(value % 1_000_000)
        return String(repeating: "0", count: codeDigits - digits.count) + digits
    }

    /// Six ASCII digits.
    public static func isWellFormedCode(_ code: String) -> Bool {
        code.utf8.count == codeDigits && code.utf8.allSatisfy { (0x30...0x39).contains($0) }
    }

    /// 64 lowercase hex characters.
    public static func isDigest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }

    /// base64url without padding, 43 characters (256 bits).
    public static func isNonce(_ value: String) -> Bool {
        value.utf8.count == 43 && Base64URL.decode(value)?.count == 32
    }

    static func hexBytes(_ hex: String) -> [UInt8]? {
        guard hex.utf8.count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        var iterator = hex.utf8.makeIterator()
        while let high = iterator.next(), let low = iterator.next() {
            guard let h = nibble(high), let l = nibble(low) else { return nil }
            out.append(h << 4 | l)
        }
        return out
    }

    private static func nibble(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: c - 0x30
        case 0x61...0x66: c - 0x61 + 10
        case 0x41...0x46: c - 0x41 + 10
        default: nil
        }
    }
}

/// The pairing code A shows and B types: 60 random bits as `XXXX-XXXX-XXXX` in the recovery alphabet (`0-9 A-Z` without `I L O U`). It names
/// an account to the server only; it is single use, valid `DevicePairing.invitationTTL`, and stored only as a peppered HMAC.
public enum DevicePairingCode {
    public static func generate() -> String { RecoveryCodeFormat.generateRecoveryID() }

    /// Upper case, no spaces or dashes, `I`/`L` → `1`, `O` → `0`; `nil` unless 12 characters of the alphabet.
    public static func normalize(_ raw: String) -> String? { RecoveryCodeFormat.normalize(raw, length: 12) }
}

/// One key of the new device, as the approving device receives it.
public struct DevicePairingKey: Codable, Sendable, Hashable {
    public var purpose: DeviceKeyPurpose
    public var publicKey: DevicePublicKey

    public init(purpose: DeviceKeyPurpose, publicKey: DevicePublicKey) {
        self.purpose = purpose
        self.publicKey = publicKey
    }
}

/// A's approval (`VIADERE-PAIR-V1`). `signature` = ECDSA P-256/SHA-256 (raw r‖s, base64url, low-S) by A's **biometric** approval key over the
/// UTF-8 of the LF-joined lines (no trailing LF):
///
/// ```
/// VIADERE-PAIR-V1
/// {accountId}            lowercase UUID: the account A belongs to
/// {pairingId}            lowercase UUID
/// {nonce}                the server's 256-bit base64url nonce
/// {newDeviceKeys}        keyListDigest of B's keys
/// {approverDeviceId}     lowercase UUID: A
/// {approverPublicKey}    base64url X9.63 of A's approvalBiometric key
/// {comparisonDigest}     DevicePairing.comparisonDigest
/// {match}                the 6 digits the person typed (read off B)
/// {expiresAt}            the pairing's expiry, ISO-8601 ms UTC
/// {signedAt}             ISO-8601 ms UTC
/// {assurance}            biometric
/// ```
public struct DevicePairingApproval: Codable, Sendable, Hashable {
    public static let maxAge: TimeInterval = 300
    public static let allowedFutureSkew: TimeInterval = 60

    public var accountId: ConsumerID
    public var pairingId: DevicePairingID
    public var nonce: String
    public var newDeviceKeys: String
    public var approverDeviceId: DeviceID
    public var approverPublicKey: DevicePublicKey
    public var comparisonDigest: String
    public var match: String
    public var expiresAt: Date
    public var signedAt: Date
    public var assurance: DecisionAssurance
    public var signature: String

    public init(accountId: ConsumerID, pairingId: DevicePairingID, nonce: String, newDeviceKeys: String, approverDeviceId: DeviceID,
                approverPublicKey: DevicePublicKey, comparisonDigest: String, match: String, expiresAt: Date, signedAt: Date,
                assurance: DecisionAssurance, signature: String) {
        self.accountId = accountId
        self.pairingId = pairingId
        self.nonce = nonce
        self.newDeviceKeys = newDeviceKeys
        self.approverDeviceId = approverDeviceId
        self.approverPublicKey = approverPublicKey
        self.comparisonDigest = comparisonDigest
        self.match = match
        self.expiresAt = ViadereDate.truncatedToMilliseconds(expiresAt)
        self.signedAt = ViadereDate.truncatedToMilliseconds(signedAt)
        self.assurance = assurance
        self.signature = signature
    }

    public func signingInput() -> Data {
        Data([DevicePairing.statementDomain, accountId.description, pairingId.description, nonce, newDeviceKeys, approverDeviceId.description,
              approverPublicKey.base64URL, comparisonDigest, match, ViadereDate.format(expiresAt), ViadereDate.format(signedAt), assurance.rawValue]
            .joined(separator: "\n").utf8)
    }

    /// Content-based replay key (never the signature: `(r, n − s)` encodes the same approval).
    public var replayKey: String { SecureToken.sha256Hex(signingInput()) }

    /// Every field has its canonical shape, so the signed lines cannot be ambiguous (no LF can hide in a field).
    public var isWellFormed: Bool {
        DevicePairing.isNonce(nonce) && DevicePairing.isDigest(newDeviceKeys) && DevicePairing.isDigest(comparisonDigest)
            && DevicePairing.isWellFormedCode(match)
    }

    /// Signs an approval (approving device). `key` is the biometric approval key; the caller binds the Face ID prompt to it.
    public static func sign(request: DevicePairingRequest, approverDeviceId: DeviceID, match: String, key: any DeviceSigningKey,
                            now: Date = Date()) async throws -> DevicePairingApproval {
        var approval = DevicePairingApproval(accountId: request.accountId, pairingId: request.pairingId, nonce: request.nonce,
                                             newDeviceKeys: DevicePairing.keyListDigest(request.keys), approverDeviceId: approverDeviceId,
                                             approverPublicKey: key.publicKey,
                                             comparisonDigest: DevicePairing.comparisonDigest(pairingId: request.pairingId, nonce: request.nonce,
                                                                                              keyListDigest: DevicePairing.keyListDigest(request.keys)),
                                             match: match, expiresAt: request.expiresAt, signedAt: now, assurance: .biometric, signature: "")
        let signature = try await key.signature(for: approval.signingInput())
        approval.signature = ViadereSignatureEncoding.encode(signature)
        return approval
    }

    /// The statement names exactly this pairing as the server stored it: account, pairing, nonce (constant time), the new device's key-list
    /// digest, the expiry, and the comparison digest those give. A relayed or substituted new-device key changes the key-list digest and so the
    /// comparison digest; another account's pairing changes the account or the nonce.
    public func isBound(accountId expectedAccount: ConsumerID, pairingId expectedPairing: DevicePairingID, nonce expectedNonce: String,
                        newDeviceKeys expectedKeys: String, expiresAt expectedExpiry: Date) -> Bool {
        let digest = DevicePairing.comparisonDigest(pairingId: expectedPairing, nonce: expectedNonce, keyListDigest: expectedKeys)
        // Evaluate every comparison (no early exit), then combine.
        let checks = [accountId == expectedAccount, pairingId == expectedPairing, ConstantTime.equals(nonce, expectedNonce),
                      ConstantTime.equals(newDeviceKeys, expectedKeys), ConstantTime.equals(comparisonDigest, digest),
                      ViadereDate.format(expiresAt) == ViadereDate.format(expectedExpiry)]
        return checks.allSatisfy { $0 }
    }

    /// The typed number equals the code of `comparisonDigest` (the server passes the digest it computed itself), in constant time.
    public func matchesCode(of comparisonDigest: String) -> Bool {
        guard let expected = DevicePairing.code(comparisonDigest: comparisonDigest) else { return false }
        return ConstantTime.equals(match, expected)
    }

    public enum Failure: Error, Equatable, Sendable {
        case malformed, assuranceTooLow, wrongKey, signedInFuture, tooOld, badSignature
    }

    /// Shape, assurance (biometric only, as for every device confirmation, §2.17), freshness and the signature by `registeredKey` (A's registered
    /// `approvalBiometric` key, which must equal `approverPublicKey`). Binding to the stored pairing is the server's job.
    public func verify(registeredKey: DevicePublicKey, now: Date) throws {
        guard isWellFormed else { throw Failure.malformed }
        guard assurance == .biometric else { throw Failure.assuranceTooLow }
        guard ConstantTime.equals(approverPublicKey.x963, registeredKey.x963) else { throw Failure.wrongKey }
        guard let decoded = ViadereSignatureEncoding.decode(signature) else { throw Failure.malformed }
        guard signedAt <= now.addingTimeInterval(Self.allowedFutureSkew) else { throw Failure.signedInFuture }
        guard now.timeIntervalSince(signedAt) <= Self.maxAge else { throw Failure.tooOld }
        guard let key = try? registeredKey.signingKey(), key.isValidSignature(decoded, for: signingInput()) else { throw Failure.badSignature }
    }
}
