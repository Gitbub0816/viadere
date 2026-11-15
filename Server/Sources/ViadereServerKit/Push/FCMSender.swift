@preconcurrency import Crypto
import _CryptoExtras
import Foundation
import NIOHTTP1
import ViadereCore

/// The FCM HTTP v1 message (`POST https://fcm.googleapis.com/v1/projects/{project}/messages:send`), **data only** (SECURITY.md §2.114): no
/// `notification`, no title, no body, no business name. `data` carries exactly the opaque ids an iOS push carries at its top level (`iid`,
/// `loopInstanceId`, `adl`, `req`, `ach`), the category as `kind`, and the payload version `v`. The Android app shows its own generic
/// notification and fetches everything else over the authenticated API.
public struct FCMMessage: Sendable, Equatable {
    public var token: String
    public var data: [String: String]
    public var highPriority: Bool
    public var collapseKey: String?
    public var ttlSeconds: Int

    /// Renders a provider-neutral push. The title, body, thread id and interruption level are dropped: they never leave the server for FCM.
    public static func from(_ message: PushMessage, token: String) -> FCMMessage {
        var data = ["v": "1", "kind": message.category]
        if let value = message.interactionId { data["iid"] = value }
        if let value = message.loopInstanceId { data["loopInstanceId"] = value }
        if let value = message.authDeliveryId { data["adl"] = value }
        if let value = message.approveRequestId { data["req"] = value }
        if let value = message.oidcChallengeId { data["ach"] = value }
        return FCMMessage(token: token, data: data, highPriority: message.highPriority, collapseKey: message.collapseID, ttlSeconds: 3600)
    }

    /// The exact request body.
    public func body() throws -> Data {
        var android: [String: Any] = ["priority": highPriority ? "HIGH" : "NORMAL", "ttl": "\(ttlSeconds)s"]
        if let collapseKey { android["collapse_key"] = collapseKey }
        let object: [String: Any] = ["message": ["token": token, "data": data, "android": android] as [String: Any]]
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }
}

/// What an FCM request body may contain. The sender checks every body against it before sending, and the tests check the builders against it.
public enum FCMPushPayloadPolicy {
    public static let dataKeys: Set<String> = ["v", "kind", "iid", "loopInstanceId", "adl", "req", "ach"]
    static let messageKeys: Set<String> = ["token", "data", "android"]
    static let androidKeys: Set<String> = ["priority", "ttl", "collapse_key"]

    /// An opaque identifier: 1 to 128 characters of letters, digits, `-`, `_` and `.` (UUIDs, `loop.<uuid>` collapse keys). Never text.
    static func isOpaque(_ value: String) -> Bool {
        (1...128).contains(value.count) && value.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" || $0 == ".") }
    }

    public static func isAllowed(_ body: Data) -> Bool {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any], Set(root.keys) == ["message"],
              let message = root["message"] as? [String: Any], Set(message.keys).isSubset(of: messageKeys),
              let token = message["token"] as? String, !token.isEmpty,
              let data = message["data"] as? [String: Any], Set(data.keys).isSubset(of: dataKeys), data["v"] as? String == "1",
              let kind = data["kind"] as? String, kind.hasPrefix("viadere."), isOpaque(kind) else { return false }
        for (key, value) in data where key != "v" {
            guard let text = value as? String, isOpaque(text) else { return false }
        }
        if let android = message["android"] {
            guard let android = android as? [String: Any], Set(android.keys).isSubset(of: androidKeys),
                  ["HIGH", "NORMAL"].contains(android["priority"] as? String ?? "HIGH") else { return false }
            if let collapse = android["collapse_key"] { guard let text = collapse as? String, isOpaque(text) else { return false } }
        }
        return true
    }
}

/// OAuth 2.0 access tokens for the service account (the JWT-bearer grant, RFC 7523): an RS256 assertion signed with the account's key, exchanged at
/// Google's token endpoint for a one-hour token with the `firebase.messaging` scope. Cached until a minute before it expires.
actor FCMAccessTokens {
    static let scope = "https://www.googleapis.com/auth/firebase.messaging"
    private let account: FCMServiceAccount
    private let key: _RSA.Signing.PrivateKey
    private let http: any OutboundHTTP
    private let now: @Sendable () -> Date
    private var cached: (token: String, expires: Date)?

    init(account: FCMServiceAccount, http: any OutboundHTTP, now: @escaping @Sendable () -> Date) throws {
        self.account = account
        key = try _RSA.Signing.PrivateKey(pemRepresentation: account.privateKeyPEM)
        self.http = http
        self.now = now
    }

    func invalidate() { cached = nil }

    /// The signed assertion (exposed for tests).
    func assertion(at date: Date) throws -> String {
        var header: [String: String] = ["alg": "RS256", "typ": "JWT"]
        if let kid = account.privateKeyId { header["kid"] = kid }
        let issued = Int(date.timeIntervalSince1970)
        let claims: [String: Any] = ["iss": account.clientEmail, "scope": Self.scope, "aud": FCMServiceAccount.tokenURI, "iat": issued, "exp": issued + 3600]
        let encodedHeader = Base64URL.encode(try JSONSerialization.data(withJSONObject: header, options: [.sortedKeys, .withoutEscapingSlashes]))
        let encodedClaims = Base64URL.encode(try JSONSerialization.data(withJSONObject: claims, options: [.sortedKeys, .withoutEscapingSlashes]))
        let input = Data("\(encodedHeader).\(encodedClaims)".utf8)
        let signature = try key.signature(for: input, padding: .insecurePKCS1v1_5)
        return "\(encodedHeader).\(encodedClaims).\(Base64URL.encode(signature.rawRepresentation))"
    }

    func token() async throws -> String {
        let date = now()
        if let cached, cached.expires > date.addingTimeInterval(60) { return cached.token }
        let form = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=\(try assertion(at: date))"
        let response = try await http.send(method: .POST, url: FCMServiceAccount.tokenURI,
                                           headers: ["Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"], body: Data(form.utf8))
        struct Answer: Decodable { var access_token: String; var expires_in: Int? }
        guard response.status == 200, let answer = try? JSONDecoder().decode(Answer.self, from: response.body), !answer.access_token.isEmpty,
              answer.access_token.count <= 4096 else { throw FCMError.tokenRefused(response.status) }
        cached = (answer.access_token, date.addingTimeInterval(TimeInterval(min(max(answer.expires_in ?? 3600, 120), 3600))))
        return answer.access_token
    }
}

enum FCMError: Error, Equatable { case tokenRefused(Int) }

/// FCM HTTP v1 delivery through the server's outbound client (TLS only, behind the identity-endpoint guard). No Google SDK.
public final class FCMHTTPv1Sender: PushProvider, Sendable {
    public var kind: PushRegistration.Provider { .fcm }
    private let account: FCMServiceAccount
    private let packageName: String
    private let http: any OutboundHTTP
    private let tokens: FCMAccessTokens

    /// Refuses to exist without credentials: a sender is only built from a parsed service account.
    public init(account: FCMServiceAccount, packageName: String, http: any OutboundHTTP, now: @escaping @Sendable () -> Date) throws {
        self.account = account
        self.packageName = packageName
        self.http = http
        tokens = try FCMAccessTokens(account: account, http: http, now: now)
    }

    var endpoint: String { "https://fcm.googleapis.com/v1/projects/\(account.projectId)/messages:send" }

    func assertion(at date: Date) async throws -> String { try await tokens.assertion(at: date) }

    public func deliver(_ message: PushMessage, to target: PushTarget) async -> PushOutcome {
        guard target.provider == .fcm, target.appId == packageName else { return .failed }
        let fcm = FCMMessage.from(message, token: target.token)
        guard let body = try? fcm.body(), FCMPushPayloadPolicy.isAllowed(body) else { return .failed }
        do {
            let bearer = try await tokens.token()
            let response = try await http.send(method: .POST, url: endpoint, headers: ["Authorization": "Bearer \(bearer)", "Content-Type": "application/json"],
                                               body: body)
            switch response.status {
            case 200: return .delivered
            case 404: return .tokenInvalid
            case 400 where Self.errorCode(response.body) == "INVALID_ARGUMENT" && Self.mentionsToken(response.body): return .tokenInvalid
            case 401, 403:
                await tokens.invalidate()
                return .failed
            default:
                return Self.errorCode(response.body) == "UNREGISTERED" ? .tokenInvalid : .failed
            }
        } catch {
            return .failed
        }
    }

    /// `error.details[].errorCode` of an FCM error response (`UNREGISTERED`, `INVALID_ARGUMENT`, ...).
    static func errorCode(_ body: Data) -> String? {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any], let error = root["error"] as? [String: Any] else { return nil }
        for detail in error["details"] as? [[String: Any]] ?? [] {
            if let code = detail["errorCode"] as? String { return code }
        }
        return error["status"] as? String
    }

    private static func mentionsToken(_ body: Data) -> Bool {
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any], let error = root["error"] as? [String: Any],
              let message = error["message"] as? String else { return false }
        return message.lowercased().contains("registration token")
    }
}
