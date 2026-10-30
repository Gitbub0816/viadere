import Crypto
import Foundation

/// Domain separators of the business link-session protocol (WP-C1, `docs/SECURITY.md` §2.59). Each signed or MACed object has its own, so a
/// value made for one can never be read as another.
public enum LinkDomainSeparator {
    /// Viadere's signed descriptor of a session (key `link-descriptor`).
    public static let descriptor = "VIADERE-LINK-DESCRIPTOR-V1\n"
    /// The device's statement (signed by the connection key it contains).
    public static let statement = "VIADERE-LINK-V1\n"
    /// The business's confirmation (its directory-published confirmation key).
    public static let confirmation = "VIADERE-LINK-CONFIRM-V1\n"
    /// Viadere's signed result for the business (key `link-descriptor`).
    public static let result = "VIADERE-LINK-RESULT-V1\n"
    static let binding = "VIADERE-LINK-BIND-V1\n"
    static let check = "VIADERE-LINK-CHECK-V1\n"
    static let sasKey = "VIADERE-LINK-SAS-KEY-V1\n"
    static let sas = "VIADERE-LINK-SAS-V1\n"
    static let pseudonym = "VIADERE-LINK-PSEUDONYM-V1\n"
    /// App Attest client data of a link completion (`LinkAppAttest`).
    public static let appAttest = "VIADERE-APPATTEST-LINK-V1\n"
}

/// The short single-use code of a link session: eight characters of the Approve alphabet (40 bits, no look-alikes), shown `ABCD-EFGH`. It is
/// the session reference in the QR (`/k/{CODE}`) and what a person types instead of scanning. Lookup is rationed per account and globally, and
/// the session lives at most five minutes, so the code space cannot be searched; claiming a session also needs the person's SAS comparison in
/// the business's own signed-in session (§2.59), so a guessed code links nothing.
public enum LinkSessionCode {
    public static let length = ApprovalEnrollmentCode.length

    public static func generate() -> String { ApprovalEnrollmentCode.generate() }
    public static func canonical(_ input: String) -> String? { ApprovalEnrollmentCode.canonical(input) }
    public static func display(_ canonical: String) -> String { ApprovalEnrollmentCode.display(canonical) }
}

/// The link a business shows for a link session, **built by the business SDK** (never by the relay): `https://{link domain}/k/{CODE}#es={secret}`.
/// The fragment carries the business-held session secret; a URL fragment is never sent in an HTTP request, so Viadere never sees it.
public enum LinkSessionLink {
    public static func build(code: String, secret: LinkSessionSecret?, domain: LinkDomain = .current) -> String {
        var link = "\(domain.origin)\(APIRoutes.Web.linkSessionPrefix)\(code)"
        if let secret { link += "#es=\(secret.base64URL)" }
        return link
    }

    /// Strict: https, exactly the link domain (no `www.`, no port, no user info), path `/k/{CODE}` with a canonical code, **no query**, and an
    /// optional fragment that is exactly `es=` plus 43 base64url characters. Anything else is `nil`.
    public static func parse(_ link: URL, domain: LinkDomain = .current) -> (code: String, secret: LinkSessionSecret?)? {
        guard link.scheme == "https", domain.matches(link.host), link.host == link.host?.lowercased(), link.user == nil, link.password == nil,
              link.port == nil, let components = URLComponents(url: link, resolvingAgainstBaseURL: false), components.query == nil else { return nil }
        var secret: LinkSessionSecret?
        if let fragment = components.fragment {
            guard fragment.hasPrefix("es="), let parsed = LinkSessionSecret(base64URL: String(fragment.dropFirst(3))) else { return nil }
            secret = parsed
        }
        let parts = components.percentEncodedPath.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3, parts[0].isEmpty, parts[1] == "k", let code = LinkSessionCode.canonical(parts[2]), code == parts[2] else { return nil }
        return (code, secret)
    }
}

/// The business-held secret of one link session (`es`, 256 bits from the business's CSPRNG) and what derives from it.
///
/// Unlike an Approve v2 enrollment, a link session has **no prior relationship**: whoever scans the QR can claim the session, and the same
/// person then also holds `es` (`docs/IMPLEMENTATION-PLAN-v3.md` §2.12). `es` therefore only proves that the statement the business receives came
/// from *an* app that saw the QR or the check code (the relay cannot forge the binding tag or the SAS); it does **not** prove that the app is the
/// customer's. That is the SAS comparison in the business's own signed-in session plus the out-of-band notice (§2.59).
public struct LinkSessionSecret: Sendable, Hashable {
    public static let byteCount = 32
    private let bytes: Data

    public init() { bytes = SecureToken.randomBytes(Self.byteCount) }

    /// Strict: exactly 43 unpadded base64url characters that decode to 32 bytes and re-encode identically.
    public init?(base64URL text: String) {
        guard text.utf8.count == 43, let data = Base64URL.decode(text), data.count == Self.byteCount, Base64URL.encode(data) == text else { return nil }
        bytes = data
    }

    public var base64URL: String { Base64URL.encode(bytes) }
    private var key: SymmetricKey { SymmetricKey(data: bytes) }

    /// `base64url(HMAC-SHA256(es, "VIADERE-LINK-BIND-V1\n" ‖ statement payload))`, 43 characters.
    public func bindingTag(for statement: SignedStatement) -> String {
        Base64URL.encode(Data(HMAC<SHA256>.authenticationCode(for: Data(LinkDomainSeparator.binding.utf8) + Data(statement.payload.utf8), using: key)))
    }

    public func verifyBindingTag(_ tag: String, for statement: SignedStatement) -> Bool {
        guard tag.utf8.count == 43 else { return false }
        return ConstantTime.equals(bindingTag(for: statement), tag)
    }

    /// The 40-bit check code for the typed path (eight alphabet characters, canonical). The person types it into the app with the session code;
    /// it is never sent to Viadere.
    public var checkCode: String {
        let mac = Data(HMAC<SHA256>.authenticationCode(for: Data(LinkDomainSeparator.check.utf8), using: key))
        let value = Array(mac.prefix(5)).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let alphabet = ApprovalEnrollmentCode.alphabet
        return String(decoding: (0..<8).map { alphabet[Int((value >> UInt64(35 - 5 * $0)) & 31)] }, as: UTF8.self)
    }

    /// The SAS the business shows (and expects) for `statement`.
    public func expectedSAS(for statement: SignedStatement) -> String { LinkSAS.compute(checkCode: checkCode, statement: statement) ?? "" }

    /// Whether what the person typed into the business's session is the SAS of this statement (spaces and a hyphen ignored).
    public func verifySAS(_ typed: String, for statement: SignedStatement) -> Bool {
        guard let normalized = ApprovalEnrollmentSAS.normalize(typed) else { return false }
        return ConstantTime.equals(normalized, expectedSAS(for: statement))
    }
}

/// The six-digit short authentication string the app shows after it signed its statement, and the business shows in its signed-in session:
/// `decimal(uint32(HMAC-SHA256(SHA-256("VIADERE-LINK-SAS-KEY-V1\n" ‖ checkCode), "VIADERE-LINK-SAS-V1\n" ‖ statement payload))[0..<4]) mod 10^6`.
/// The app derives the check code from `es` (QR) or takes it as typed (typed path); the relay knows neither, so it cannot make the two sides
/// show the same number for a statement it substituted.
public enum LinkSAS {
    public static func compute(checkCode: String, statement: SignedStatement) -> String? {
        guard let canonical = LinkSessionCode.canonical(checkCode) else { return nil }
        let key = SymmetricKey(data: Data(SHA256.hash(data: Data(LinkDomainSeparator.sasKey.utf8) + Data(canonical.utf8))))
        let mac = Array(HMAC<SHA256>.authenticationCode(for: Data(LinkDomainSeparator.sas.utf8) + Data(statement.payload.utf8), using: key))
        let value = mac.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let text = String(value % 1_000_000)
        return String(repeating: "0", count: 6 - text.count) + text
    }

    public static func display(_ sas: String) -> String { ApprovalEnrollmentSAS.display(sas) }
}

/// The account pseudonym both sides show next to the SAS: eight alphabet characters derived from the pairwise `subject_ref` (so it is different
/// at every business and reveals nothing), `ABCD-EFGH`. The app shows "Your account at {business}: ABCD-EFGH"; the business shows the same value
/// for the `subject_ref` it received. It lets the person see *which* Viadere account is about to be linked.
public enum LinkPseudonym {
    public static func make(_ subject: SubjectRef) -> String {
        let digest = Array(SHA256.hash(data: Data(LinkDomainSeparator.pseudonym.utf8) + Data(subject.rawValue.utf8)))
        let value = digest.prefix(5).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let alphabet = ApprovalEnrollmentCode.alphabet
        return ApprovalEnrollmentCode.display(String(decoding: (0..<8).map { alphabet[Int((value >> UInt64(35 - 5 * $0)) & 31)] }, as: UTF8.self))
    }
}

/// App Attest client data of a link completion (`docs/SECURITY.md` §2.59):
/// `"VIADERE-APPATTEST-LINK-V1\n{session id}\n{hex SHA-256 of the statement payload}"`. The app passes `SHA-256(clientData)` to
/// `generateAssertion`; the server rebuilds the same bytes.
public enum LinkAppAttest {
    public static func clientData(sessionId: UUID, statement: SignedStatement) -> Data {
        Data((LinkDomainSeparator.appAttest + sessionId.uuidString.lowercased() + "\n" + SecureToken.sha256Hex(Data(statement.payload.utf8))).utf8)
    }
}
