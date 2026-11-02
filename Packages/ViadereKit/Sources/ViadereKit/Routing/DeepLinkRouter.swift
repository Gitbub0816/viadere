import Foundation
import ViadereCore

/// A destination inside the app. Produced only from strictly validated URLs.
public enum DeepLink: Sendable, Equatable {
    /// `https://{link domain}/c/{CODE}` (QR, NFC, button, App Clip invocation) or `viadere://c/{CODE}`.
    case connect(code: BusinessCode, link: ConnectLink?)
    /// `viadere://b/{handle}`
    case business(BusinessHandle)
    /// `https://{link domain}/l/{token}` or `/h/{token}` from a text sent by an older build. Viadere no longer texts links that link a
    /// phone or hand a request over (decision 9, ADR-0027): the app only says so and never reads or redeems the token.
    case retiredLink
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
    /// `https://{link domain}/lp/{loopId}` or `viadere://lp/{loopId}`: a business's Loop install link. Opens the install sheet only
    /// (SECURITY.md §2.98 "Installed Loops"); nothing is installed without the customer's choice.
    case loopInstall(LoopDefinitionID)
    /// Produced only from a tapped authentication-delivery push, never from a URL: the confirm screen for a link delivery (`adl`).
    case authDelivery(UUID)
    /// Produced only from a tapped push, never from a URL: an Approve v2 request (`req`), or `nil` for the list of requests.
    case approveRequest(String?)
    /// `https://{link domain}/v/{CODE}` (a business's "Verify with Viadere" button or its QR): review a verification session. No secret, no query.
    case verificationSession(code: String)
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
        if components.path.hasPrefix(APIRoutes.Web.loopInstallPrefix) {
            return LoopInstallLink.parse(url, domain: domain).map { .loopInstall($0.loopId) }
        }
        if components.path.hasPrefix(APIRoutes.Web.linkSessionPrefix) {
            // Strict: the exact link domain, `/k/{CODE}`, no query, and a fragment that is exactly `es=` plus 43 characters (or none).
            guard let parsed = LinkSessionLink.parse(url, domain: domain) else { return nil }
            return .linkSession(code: parsed.code, secret: parsed.secret)
        }
        if components.path.hasPrefix(APIRoutes.Web.verificationSessionPrefix) {
            // Strict: the exact link domain, `/v/{CODE}`, no query, no fragment.
            guard let code = VerificationSessionLink.parse(url, domain: domain) else { return nil }
            return .verificationSession(code: code)
        }
        // `/l/` and `/h/` tokens: the exact link domain only (never the `www.` alias).
        guard domain.matches(host), components.user == nil, components.password == nil, components.fragment == nil,
              components.query == nil, components.port == nil || components.port == 443 else { return nil }
        if token(in: components.percentEncodedPath, prefix: APIRoutes.Web.accountLinkPrefix) != nil
            || token(in: components.percentEncodedPath, prefix: APIRoutes.Web.handoffPrefix) != nil { return .retiredLink }
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
        // There is no `viadere://l/…` or `viadere://h/…`: those links are retired and a custom scheme is never trusted with a token.
        case "settings":
            return arg.isEmpty ? .settings : nil
        case "lp":
            // Harmless from any app: it only opens the install sheet, which needs the customer's explicit choice.
            return LoopInstallLink.parse(path: APIRoutes.Web.loopInstallPrefix + arg).map { .loopInstall($0.loopId) }
        default:
            return nil
        }
    }

    /// The deep link for a tapped notification (`userInfo` carries the interaction id).
    public static func route(notification userInfo: [AnyHashable: Any]) -> DeepLink? {
        PushPayload.interactionId(from: userInfo).map(DeepLink.interaction)
    }
}
