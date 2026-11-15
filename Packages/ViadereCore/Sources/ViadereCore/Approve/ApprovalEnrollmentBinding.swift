import Crypto
import Foundation

/// The business-held secret of one enrollment (`es`, 256 bits) and everything derived from it (gate finding F1).
///
/// The relay creates the short code, relays the device's statement and sees every request the business makes, so **nothing the relay carries
/// can authenticate the device to the business**. The business generates `es` locally and gives it to the customer on a channel the relay
/// does not see:
///
/// * **Link or QR**: `https://viadere.com/a/{CODE}?rk={root kid}#es={base64url}`. A URL fragment is never sent to a server. The device
///   returns a **binding tag** `HMAC-SHA256(es, "VIADERE-ENROLL-BIND-V1\n" ‖ statement payload)` with its statement; the business verifies
///   it (constant time) before confirming. The relay cannot forge a tag and cannot move one to another statement.
/// * **Typed code** (no fragment): the business also shows a 40-bit **check code** derived from `es`. The person types it into the app
///   (it is never sent) and the app displays a six-digit **SAS** (`HMAC` keyed by the check code over the statement); the person types the
///   SAS into the business's own signed-in session and the SDK compares. Because the check code never leaves the device and the business,
///   the relay cannot compute the SAS of the statement it saw, so it cannot grind a forged statement to match.
public struct ApprovalEnrollmentSecret: Sendable, Hashable {
    public static let byteCount = 32
    static let bindingDomain = "VIADERE-ENROLL-BIND-V1\n"
    static let checkDomain = "VIADERE-ENROLL-CHECK-V1\n"
    static let sasKeyDomain = "VIADERE-ENROLL-SAS-KEY-V1\n"
    static let sasDomain = "VIADERE-ENROLL-SAS-V1\n"

    private let bytes: Data

    /// A fresh secret from the system CSPRNG.
    public init() { bytes = SecureToken.randomBytes(Self.byteCount) }

    /// Strict: exactly 43 unpadded base64url characters that decode to 32 bytes and re-encode identically.
    public init?(base64URL text: String) {
        guard text.utf8.count == 43, let data = Base64URL.decode(text), data.count == Self.byteCount, Base64URL.encode(data) == text else { return nil }
        bytes = data
    }

    public var base64URL: String { Base64URL.encode(bytes) }

    private var key: SymmetricKey { SymmetricKey(data: bytes) }

    /// `base64url(HMAC-SHA256(es, "VIADERE-ENROLL-BIND-V1\n" ‖ payload))`, 43 characters.
    public func bindingTag(for statement: SignedStatement) -> String {
        var message = Data(Self.bindingDomain.utf8)
        message.append(Data(statement.payload.utf8))
        return Base64URL.encode(Data(HMAC<SHA256>.authenticationCode(for: message, using: key)))
    }

    /// Constant-time check of a tag the relay handed over.
    public func verifyBindingTag(_ tag: String, for statement: SignedStatement) -> Bool {
        guard tag.utf8.count == 43 else { return false }
        return ConstantTime.equals(bindingTag(for: statement), tag)
    }

    /// The 40-bit check code the business shows next to the code for the typed path, canonical form (eight alphabet characters).
    public var checkCode: String {
        let mac = Data(HMAC<SHA256>.authenticationCode(for: Data(Self.checkDomain.utf8), using: key))
        // 40 bits = eight 5-bit groups of the first five bytes.
        let b = Array(mac.prefix(5))
        let value = b.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let alphabet = ApprovalEnrollmentCode.alphabet
        return String(decoding: (0..<8).map { alphabet[Int((value >> UInt64(35 - 5 * $0)) & 31)] }, as: UTF8.self)
    }

    /// The SAS the business expects for this statement (see `ApprovalEnrollmentSAS`).
    public func expectedSAS(for statement: SignedStatement) -> String {
        // `checkCode` is always canonical.
        ApprovalEnrollmentSAS.compute(checkCode: checkCode, statement: statement) ?? ""
    }

    /// Whether what the person typed is the SAS of this statement. Whitespace and a hyphen are ignored.
    public func verifySAS(_ typed: String, for statement: SignedStatement) -> Bool {
        guard let normalized = ApprovalEnrollmentSAS.normalize(typed) else { return false }
        return ConstantTime.equals(normalized, expectedSAS(for: statement))
    }
}

/// The six-digit short authentication string of the typed-code path. Computed on the device from the check code the person typed (never
/// sent anywhere) and the statement the device signed; recomputed by the business from `es`.
public enum ApprovalEnrollmentSAS {
    public static let digits = 6

    /// `nil` unless `checkCode` is a valid check code (eight alphabet characters; case and separators ignored).
    public static func compute(checkCode: String, statement: SignedStatement) -> String? {
        guard let canonical = ApprovalEnrollmentCode.canonical(checkCode) else { return nil }
        var keyMaterial = Data(ApprovalEnrollmentSecret.sasKeyDomain.utf8)
        keyMaterial.append(Data(canonical.utf8))
        let key = SymmetricKey(data: Data(SHA256.hash(data: keyMaterial)))
        var message = Data(ApprovalEnrollmentSecret.sasDomain.utf8)
        message.append(Data(statement.payload.utf8))
        let mac = Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
        let value = mac.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let text = String(value % 1_000_000)
        return String(repeating: "0", count: digits - text.count) + text
    }

    /// Six digits, with optional spaces or a hyphen, to the canonical six digits.
    public static func normalize(_ input: String) -> String? {
        let cleaned = input.filter { $0 != " " && $0 != "-" }
        guard cleaned.utf8.count == digits, cleaned.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return nil }
        return cleaned
    }

    /// `123 456`.
    public static func display(_ sas: String) -> String {
        guard sas.count == digits else { return sas }
        return sas.prefix(3) + " " + sas.suffix(3)
    }
}
