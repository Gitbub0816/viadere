import Foundation
import ViadereCore

/// A destination inside the app. Produced only from strictly validated URLs.
public enum DeepLink: Sendable, Equatable {
    /// `https://viadere.com/c/{CODE}` (QR, NFC, button, App Clip invocation) or `viadere://c/{CODE}`.
    case connect(code: BusinessCode, link: ConnectLink?)
    /// `viadere://b/{handle}`
    case business(BusinessHandle)
    /// `https://viadere.com/l/{token}`: finish linking a phone that texted Viadere.
    case accountLink(token: String)
    /// `https://viadere.com/h/{token}`: secure handoff of a request that can't be completed by text.
    case handoff(token: String)
    /// `viadere://i/{interactionId}` (also used by notification taps).
    case interaction(InteractionID)
    /// `viadere://m/{sessionId}`
    case conversation(SessionID)
    case settings
}

/// Strict URL → `DeepLink` mapping for universal links and the custom scheme.
///
/// Anything that is not an exact match yields `nil`: wrong host, userinfo, a port other than 443, a fragment,
/// unexpected query items, extra path segments, or malformed identifiers. Tokens are never logged.
public enum DeepLinkRouter {
    public static let customScheme = "viadere"
    static let tokenLength = 43

    public static func route(_ url: URL) -> DeepLink? {
        switch url.scheme?.lowercased() {
        case "https": return routeUniversal(url)
        case customScheme: return routeCustom(url)
        default: return nil
        }
    }

    public static func route(_ string: String) -> DeepLink? {
        guard let url = URL(string: string.trimmingCharacters(in: .whitespacesAndNewlines)) else { return nil }
        return route(url)
    }

    // MARK: https

    private static func routeUniversal(_ url: URL) -> DeepLink? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false), let host = components.host?.lowercased(),
              ConnectLink.allowedHosts.contains(host) else { return nil }
        if components.path.hasPrefix(APIRoutes.Web.connectPrefix) {
            guard let link = try? ConnectLink.parse(url.absoluteString) else { return nil }
            return .connect(code: link.code, link: link)
        }
        guard components.user == nil, components.password == nil, components.fragment == nil,
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
        case "l":
            guard Base64URL.isValid(arg, minLength: tokenLength, maxLength: tokenLength) else { return nil }
            return .accountLink(token: arg)
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
