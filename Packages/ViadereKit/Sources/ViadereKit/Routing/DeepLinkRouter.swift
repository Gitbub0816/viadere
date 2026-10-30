import Foundation
import ViadereCore

/// A destination inside the app. Produced only from strictly validated URLs.
public enum DeepLink: Sendable, Equatable {
    /// `https://{link domain}/c/{CODE}` (QR, NFC, button, App Clip invocation) or `viadere://c/{CODE}`.
    case connect(code: BusinessCode, link: ConnectLink?)
    /// `viadere://b/{handle}`
    case business(BusinessHandle)
    /// `https://{link domain}/l/{token}` (universal link only; no custom-scheme equivalent): finish linking a phone that texted Viadere.
    case accountLink(token: String)
    /// `https://{link domain}/h/{token}`: secure handoff of a request that can't be completed by text.
    case handoff(token: String)
    /// `viadere://i/{interactionId}` (also used by notification taps).
    case interaction(InteractionID)
    /// `viadere://m/{sessionId}`
    case conversation(SessionID)
    case settings
    /// `https://{link domain}/a/{CODE}?rk={root key id}#es={secret}` (QR or button the business shows in its own session): start an Approve enrollment.
    /// The fragment never reaches a server; log nothing of this link.
    case approveEnrollment(code: String, rootKid: String?, secret: ApprovalEnrollmentSecret?)
    /// `https://{link domain}/k/{CODE}#es={secret}` (QR or button a business shows in its own signed-in session, right after it authenticated the
    /// customer): link this app to the business's customer record (WP-C1). The fragment never reaches a server; log nothing of this link.
    case linkSession(code: String, secret: LinkSessionSecret?)
}

/// Strict URL → `DeepLink` mapping for universal links and the custom scheme.
///
/// Anything that is not an exact match yields `nil`: wrong host, userinfo, a port other than 443, a fragment,
/// unexpected query items, extra path segments, or malformed identifiers. Tokens are never logged.
public enum DeepLinkRouter {
    public static let customScheme = "viadere"
    static let tokenLength = 43

    /// `domain` is the build's link domain (`ViadereCore.configureLinkDomain` at launch); a universal link for any other host is refused.
    public static func route(_ url: URL, domain: LinkDomain = .current) -> DeepLink? {
        switch url.scheme?.lowercased() {
        case "https": return routeUniversal(url, domain: domain)
        case customScheme: return routeCustom(url)
        default: return nil
        }
    }

    public static func route(_ string: String, domain: LinkDomain = .current) -> DeepLink? {
        guard let url = URL(string: string.trimmingCharacters(in: .whitespacesAndNewlines)) else { return nil }
        return route(url, domain: domain)
    }

    // MARK: https

    private static func routeUniversal(_ url: URL, domain: LinkDomain) -> DeepLink? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false), let host = components.host?.lowercased(),
              domain.connectHosts.contains(host) else { return nil }
        if components.path.hasPrefix(APIRoutes.Web.connectPrefix) {
            guard let link = try? ConnectLink.parse(url.absoluteString, domain: domain) else { return nil }
            return .connect(code: link.code, link: link)
        }
        if components.path.hasPrefix("/a/") {
            // The fragment (`#es=`, the enrollment secret) is parsed strictly by `ApprovalEnrollmentCode.parse`; anything else in it is refused.
            guard components.user == nil, components.password == nil, components.port == nil || components.port == 443,
                  let parsed = ApprovalEnrollmentCode.parse(link: url, domain: domain) else { return nil }
            return .approveEnrollment(code: parsed.code, rootKid: parsed.rootKid, secret: parsed.secret)
        }
        if components.path.hasPrefix(APIRoutes.Web.linkSessionPrefix) {
            // Strict: the exact link domain, `/k/{CODE}`, no query, and a fragment that is exactly `es=` plus 43 characters (or none).
            guard let parsed = LinkSessionLink.parse(url, domain: domain) else { return nil }
            return .linkSession(code: parsed.code, secret: parsed.secret)
        }
        // `/l/` and `/h/` tokens: the exact link domain only (never the `www.` alias).
        guard domain.matches(host), components.user == nil, components.password == nil, components.fragment == nil,
              components.query == nil, components.port == nil || components.port == 443 else { return nil }
        if let token = token(in: components.percentEncodedPath, prefix: APIRoutes.Web.accountLinkPrefix) { return .accountLink(token: token) }
        if let token = token(in: components.percentEncodedPath, prefix: APIRoutes.Web.handoffPrefix) { return .handoff(token: token) }
        return nil
    }

    private static func token(in path: String, prefix: String) -> String? {
        guard path.hasPrefix(prefix) else { return nil }
        var rest = Substring(path.dropFirst(prefix.count))
        if rest.hasSuffix("/") { rest = rest.dropLast() }
        let token = String(rest)
        guard token.count == tokenLength, Base64URL.isValid(token, minLength: tokenLength, maxLength: tokenLength) else { return nil }
        return token
    }

    // MARK: viadere://

    private static func routeCustom(_ url: URL) -> DeepLink? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false), components.user == nil,
              components.password == nil, components.fragment == nil, components.query == nil,
              let kind = components.host?.lowercased() else { return nil }
        var arg = components.path
        if arg.hasPrefix("/") { arg.removeFirst() }
        if arg.hasSuffix("/") { arg.removeLast() }
        guard !arg.contains("/") else { return nil }
        switch kind {
        case "c":
            guard arg.count == BusinessCode.length, arg.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }),
                  let code = BusinessCode(parsing: arg) else { return nil }
            return .connect(code: code, link: nil)
        case "b":
            guard let handle = BusinessHandle(parsing: arg) else { return nil }
            return .business(handle)
        case "i":
            return InteractionID(arg).map(DeepLink.interaction)
        case "m":
            return SessionID(arg).map(DeepLink.conversation)
        // There is deliberately no `viadere://l/{token}`: any app on the device can open a custom-scheme URL, so a
        // phone-link token is accepted only from the https universal link (`https://{link domain}/l/{token}`), which
        // iOS verifies against the app-site association.
        case "h":
            guard Base64URL.isValid(arg, minLength: tokenLength, maxLength: tokenLength) else { return nil }
            return .handoff(token: arg)
        case "settings":
            return arg.isEmpty ? .settings : nil
        default:
            return nil
        }
    }

    /// The deep link for a tapped notification (`userInfo` carries the interaction id).
    public static func route(notification userInfo: [AnyHashable: Any]) -> DeepLink? {
        PushPayload.interactionId(from: userInfo).map(DeepLink.interaction)
    }
}
