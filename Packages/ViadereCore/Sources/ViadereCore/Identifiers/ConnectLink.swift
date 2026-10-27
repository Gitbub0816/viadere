import Crypto
import Foundation

/// Optional, server-signed campaign/action context carried in a connect link.
/// Encoded as base64url(canonical JSON) in the `ctx` query parameter.
public struct ConnectContext: Codable, Sendable, Hashable {
    /// Campaign identifier chosen by the business (≤ 64 chars).
    public var campaign: String?
    /// Requested follow-up action, e.g. `"enroll_rewards"` (≤ 64 chars).
    public var action: String?
    /// Issue time.
    public var issuedAt: Date
    /// Optional expiry; expired contexts are ignored (the plain code still works).
    public var expiresAt: Date?
    /// Id of the server signing key that signed this context (`CONNECT_LINK_SIGNING_KEY_ID`), so a key can be rotated while links signed under
    /// the previous one stay valid. Covered by the signature. `nil` on links signed before key ids existed.
    public var keyId: String?

    public init(campaign: String? = nil, action: String? = nil, issuedAt: Date, expiresAt: Date? = nil, keyId: String? = nil) {
        self.campaign = campaign
        self.action = action
        self.issuedAt = ViadereDate.truncatedToMilliseconds(issuedAt)
        self.expiresAt = expiresAt.map(ViadereDate.truncatedToMilliseconds)
        self.keyId = keyId
    }

    func canonicalJSON() throws -> Data {
        var object: [String: JSONValue] = ["iat": .string(ViadereDate.format(issuedAt))]
        if let campaign { object["cmp"] = .string(campaign) }
        if let action { object["act"] = .string(action) }
        if let expiresAt { object["exp"] = .string(ViadereDate.format(expiresAt)) }
        if let keyId { object["kid"] = .string(keyId) }
        return try CanonicalJSON.serialize(.object(object))
    }

    static func fromCanonicalJSON(_ data: Data) -> ConnectContext? {
        guard case .object(let object)? = try? JSONDecoder().decode(JSONValue.self, from: data),
              let iatString = object["iat"]?.stringValue, let iat = ViadereDate.parse(iatString) else { return nil }
        let allowed: Set<String> = ["iat", "cmp", "act", "exp", "kid"]
        guard Set(object.keys).isSubset(of: allowed) else { return nil }
        var exp: Date?
        if let value = object["exp"] {
            guard let s = value.stringValue, let parsed = ViadereDate.parse(s) else { return nil }
            exp = parsed
        }
        let campaign = object["cmp"]?.stringValue
        let action = object["act"]?.stringValue
        if object["cmp"] != nil && campaign == nil { return nil }
        if object["act"] != nil && action == nil { return nil }
        let keyId = object["kid"]?.stringValue
        if object["kid"] != nil && (keyId == nil || keyId?.isEmpty == true || (keyId?.count ?? 0) > 16) { return nil }
        return ConnectContext(campaign: campaign, action: action, issuedAt: iat, expiresAt: exp, keyId: keyId)
    }
}

/// A `https://viadere.com/c/{CODE}` connect link (QR codes, NFC, buttons, App Clip invocations).
///
/// Optional signed context: `?ctx={base64url canonical JSON}&sig={base64url HMAC}` where
/// `sig = HMAC-SHA256(key, "VIADERE-CTX-V1\n" + canonicalCode + "\n" + ctx)`.
/// The key is a server-only secret; clients parse links but must treat `ctx` as
/// unverified until the server validates it (`verifiedContext`).
///
/// Parsing is strict to block open-redirect and look-alike tricks: scheme `https` only,
/// host exactly one of `allowedHosts`, no userinfo, no port other than 443, no fragment,
/// path exactly `/c/{code}` (optional trailing `/`), only `ctx`/`sig` query items, each at most once,
/// and both or neither.
public struct ConnectLink: Sendable, Hashable {
    /// Hosts accepted when parsing.
    public static let allowedHosts: Set<String> = ["viadere.com", "www.viadere.com"]
    /// Host used when building links.
    public static let canonicalHost = "viadere.com"
    /// Maximum length of the `ctx` parameter.
    public static let maxContextLength = 512
    static let contextDomain = "VIADERE-CTX-V1"

    /// Parse failures.
    public enum ParseError: Error, Sendable, Equatable {
        case malformedURL
        case disallowedScheme
        case disallowedHost
        case userInfoNotAllowed
        case portNotAllowed
        case fragmentNotAllowed
        case invalidPath
        case invalidCode
        case unexpectedQueryItem(String)
        case duplicateQueryItem(String)
        case incompleteSignature
        case contextTooLong
    }

    /// Context verification failures.
    public enum ContextError: Error, Sendable, Equatable {
        case noContext
        case badSignature
        case malformedContext
        case expired
    }

    /// The business code (canonical).
    public let code: BusinessCode
    /// Raw `ctx` parameter (base64url), if present.
    public let context: String?
    /// Raw `sig` parameter (base64url), if present.
    public let signature: String?

    /// A plain link with no context.
    public init(code: BusinessCode) {
        self.code = code
        self.context = nil
        self.signature = nil
    }

    /// Builds a link with signed context (server side).
    public init(code: BusinessCode, context: ConnectContext, key: SymmetricKey) throws {
        let ctx = Base64URL.encode(try context.canonicalJSON())
        self.code = code
        self.context = ctx
        self.signature = Self.sign(code: code, context: ctx, key: key)
    }

    /// The canonical URL string.
    public var urlString: String {
        var s = "https://\(Self.canonicalHost)/c/\(code.canonical)"
        if let context, let signature { s += "?ctx=\(context)&sig=\(signature)" }
        return s
    }

    /// The canonical URL.
    public var url: URL? { URL(string: urlString) }

    /// Strictly parses a link string (see type documentation).
    public static func parse(_ string: String) throws -> ConnectLink {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        // Reject whitespace, backslashes and control chars anywhere: common parser-confusion vectors.
        guard !trimmed.isEmpty, trimmed.count <= 2048,
              !trimmed.unicodeScalars.contains(where: { $0.value < 0x21 || $0 == "\\" || $0.value == 0x7F || !$0.isASCII })
        else { throw ParseError.malformedURL }
        guard let components = URLComponents(string: trimmed) else { throw ParseError.malformedURL }
        guard components.scheme?.lowercased() == "https" else { throw ParseError.disallowedScheme }
        guard components.user == nil, components.password == nil, !trimmed.contains("@") else {
            throw ParseError.userInfoNotAllowed
        }
        guard let host = components.host?.lowercased(), allowedHosts.contains(host) else { throw ParseError.disallowedHost }
        if let port = components.port, port != 443 { throw ParseError.portNotAllowed }
        guard components.fragment == nil else { throw ParseError.fragmentNotAllowed }
        // Use the percent-encoded path so "%2F" tricks cannot alter segmentation.
        var path = Substring(components.percentEncodedPath)
        if path.hasSuffix("/") { path = path.dropLast() }
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0].isEmpty, parts[1] == "c" else { throw ParseError.invalidPath }
        let rawCode = String(parts[2])
        guard rawCode.count == BusinessCode.length,
              rawCode.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }),
              let code = BusinessCode(parsing: rawCode) else { throw ParseError.invalidCode }
        var ctx: String?
        var sig: String?
        for item in components.percentEncodedQueryItems ?? [] {
            switch item.name {
            case "ctx":
                guard ctx == nil else { throw ParseError.duplicateQueryItem("ctx") }
                ctx = item.value ?? ""
            case "sig":
                guard sig == nil else { throw ParseError.duplicateQueryItem("sig") }
                sig = item.value ?? ""
            default:
                throw ParseError.unexpectedQueryItem(item.name)
            }
        }
        if (ctx == nil) != (sig == nil) { throw ParseError.incompleteSignature }
        if let ctx {
            guard ctx.count <= maxContextLength else { throw ParseError.contextTooLong }
            guard Base64URL.isValid(ctx), let sig, Base64URL.isValid(sig, minLength: 43, maxLength: 43) else {
                throw ParseError.incompleteSignature
            }
        }
        return ConnectLink(code: code, context: ctx, signature: sig)
    }

    private init(code: BusinessCode, context: String?, signature: String?) {
        self.code = code
        self.context = context
        self.signature = signature
    }

    /// The key id the (still **unverified**) context names, for choosing which key to verify with. Never trust anything else in it.
    public var claimedKeyId: String? {
        guard let context, let data = Base64URL.decode(context) else { return nil }
        return ConnectContext.fromCanonicalJSON(data)?.keyId
    }

    /// Verifies `sig` with the server key and decodes the context.
    public func verifiedContext(key: SymmetricKey, now: Date) throws -> ConnectContext {
        guard let context, let signature else { throw ContextError.noContext }
        guard let provided = Base64URL.decode(signature) else { throw ContextError.badSignature }
        let message = Data("\(Self.contextDomain)\n\(code.canonical)\n\(context)".utf8)
        guard HMAC<SHA256>.isValidAuthenticationCode(provided, authenticating: message, using: key) else {
            throw ContextError.badSignature
        }
        guard let data = Base64URL.decode(context), let decoded = ConnectContext.fromCanonicalJSON(data) else {
            throw ContextError.malformedContext
        }
        if let expiresAt = decoded.expiresAt, now >= expiresAt { throw ContextError.expired }
        return decoded
    }

    static func sign(code: BusinessCode, context: String, key: SymmetricKey) -> String {
        let message = Data("\(contextDomain)\n\(code.canonical)\n\(context)".utf8)
        return Base64URL.encode(Data(HMAC<SHA256>.authenticationCode(for: message, using: key)))
    }
}
