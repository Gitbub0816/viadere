import Foundation

/// `PATCH /v1/business/webhooks/{webhookId}` (ADR-0025 section 3, M1): switch a subscription's signature version. Idempotency required.
public struct UpdateWebhookRequest: Codable, Sendable, Hashable {
    /// `v2` (the only value a subscription can be moved to; there is no way back to `v1`).
    public var signatureVersion: WebhookSignatureVersion
    public init(signatureVersion: WebhookSignatureVersion) { self.signatureVersion = signatureVersion }
    enum CodingKeys: String, CodingKey { case signatureVersion = "signature_version" }
}

/// Which signature a subscription's deliveries carry. `auth.*` events exist only on `v2`.
public enum WebhookSignatureVersion: String, Codable, Sendable, CaseIterable, Hashable {
    case v1, v2
}

/// `POST /v1/business/webhooks/test` (test keys only): a signed sample `auth.*` event with fixed sample ids, so a partner can check signature, tenant,
/// digest and dedup handling (spec 6.1, ADR-0025 section 4).
public struct AuthWebhookTestRequest: Codable, Sendable, Hashable {
    public var webhookId: WebhookSubscriptionID
    public var type: String
    public init(webhookId: WebhookSubscriptionID, type: String) {
        self.webhookId = webhookId
        self.type = type
    }
    enum CodingKeys: String, CodingKey { case webhookId = "webhook_id", type }
}

public struct AuthWebhookTestResponse: Codable, Sendable, Hashable {
    public var eventId: String
    public init(eventId: String) { self.eventId = eventId }
    enum CodingKeys: String, CodingKey { case eventId = "event_id" }
}

extension APIRoutes {
    // MARK: Auth delivery (ADR-0020; behind `AUTH_DELIVERY_ENABLED`, off by default in staging and production)
    /// Creates a `magic_link`, `otp` or `notice` delivery. Scope `auth_deliveries:write`; `Idempotency-Key` required; the tenant is the API key's business.
    public static let businessAuthDeliveryCreate = Endpoint<AuthDeliveryCreateRequest, AuthDeliveryView>(
        "business.authDeliveries.create", .POST, "/v1/business/auth-deliveries", auth: .businessAPIKey)
    /// Status and events. Never a secret.
    public static let businessAuthDeliveryGet = Endpoint<EmptyBody, AuthDeliveryView>(
        "business.authDeliveries.get", .GET, "/v1/business/auth-deliveries/{deliveryId}", auth: .businessAPIKey)
    public static let businessAuthDeliveryCancel = Endpoint<EmptyBody, AuthDeliveryView>(
        "business.authDeliveries.cancel", .POST, "/v1/business/auth-deliveries/{deliveryId}/cancel", auth: .businessAPIKey)
    /// The business reports its own verification outcome. OPENED is never success; only this call completes a delivery.
    public static let businessAuthDeliveryComplete = Endpoint<AuthDeliveryCompleteRequest, AuthDeliveryView>(
        "business.authDeliveries.complete", .POST, "/v1/business/auth-deliveries/{deliveryId}/complete", auth: .businessAPIKey)
    public static let businessWebhookUpdate = Endpoint<UpdateWebhookRequest, WebhookSubscription>(
        "business.webhooks.update", .PATCH, "/v1/business/webhooks/{webhookId}", auth: .businessAPIKey)
    public static let businessAuthWebhookTest = Endpoint<AuthWebhookTestRequest, AuthWebhookTestResponse>(
        "business.authWebhooks.test", .POST, "/v1/business/webhooks/test", auth: .businessAPIKey)

    /// Device: open deliveries for this device's account (inbox). Delegates never see them.
    public static let authDeliveries = Endpoint<EmptyBody, [AuthDeliveryDisplay]>(
        "authDeliveries.list", .GET, "/v1/auth-deliveries", auth: .deviceSignedBearer)
    /// Device: the display object (no secret); the first fetch marks the delivery `delivered`.
    public static let authDeliveryGet = Endpoint<EmptyBody, AuthDeliveryDisplay>(
        "authDeliveries.get", .GET, "/v1/auth-deliveries/{deliveryId}", auth: .deviceSignedBearer)
    /// Device: returns the URL or code **once**, deletes the ciphertext and marks the delivery `opened`.
    public static let authDeliveryOpen = Endpoint<EmptyBody, AuthDeliveryOpenResponse>(
        "authDeliveries.open", .POST, "/v1/auth-deliveries/{deliveryId}/open", auth: .deviceSignedBearer)
    /// Device: Deny or "This wasn't me". Reduce-only.
    public static let authDeliveryDeny = Endpoint<AuthDeliveryDenyRequest, AuthDeliveryView>(
        "authDeliveries.deny", .POST, "/v1/auth-deliveries/{deliveryId}/deny", auth: .deviceSignedBearer)

    /// Appended to `APIRoutes.all`. There is **no route that verifies an OTP or TOTP** (decision 3, ST-OTP-02) and none that delivers by SMS.
    public static let authDeliveryEndpoints: [AnyEndpoint] = [
        businessAuthDeliveryCreate.descriptor, businessAuthDeliveryGet.descriptor, businessAuthDeliveryCancel.descriptor, businessAuthDeliveryComplete.descriptor,
        businessWebhookUpdate.descriptor, businessAuthWebhookTest.descriptor,
        authDeliveries.descriptor, authDeliveryGet.descriptor, authDeliveryOpen.descriptor, authDeliveryDeny.descriptor,
    ]
}

/// What a push for an auth delivery may contain (ADR-0020 section 6.2, ST-PRIV-02): a generic alert, a category, an opaque thread id and the delivery id.
/// No business id or name, no URL, no code, no amount. Used by the server's tests and by the app's notification extension tests.
public enum AuthPushPayloadPolicy {
    public static let allowedCategories: Set<String> = ["viadere.auth.link", "viadere.auth.code", "viadere.auth.notice"]
    /// N-01: the visible text before the extension runs.
    public static let alertTitle = "Viadere"
    public static let alertBody = "You have a new security item."
    /// Top-level members of the APNs payload besides `aps`: only the delivery id.
    public static let customKeys: Set<String> = ["adl"]
    /// Members allowed inside `aps`.
    public static let apsKeys: Set<String> = ["alert", "category", "thread-id", "interruption-level", "mutable-content"]

    public static func category(for method: AuthDeliveryMethod) -> String {
        switch method {
        case .magicLink: "viadere.auth.link"
        case .otp: "viadere.auth.code"
        case .notice: "viadere.auth.notice"
        }
    }

    /// Whether `payload` (the JSON the APNs request carries) obeys the schema.
    public static func isAllowed(_ payload: [String: Any]) -> Bool {
        guard Set(payload.keys).isSubset(of: customKeys.union(["aps"])), let aps = payload["aps"] as? [String: Any], Set(aps.keys).isSubset(of: apsKeys),
              let alert = aps["alert"] as? [String: Any], alert["title"] as? String == alertTitle, alert["body"] as? String == alertBody, Set(alert.keys) == ["title", "body"],
              let category = aps["category"] as? String, allowedCategories.contains(category), aps["interruption-level"] as? String == "active" else { return false }
        if let adl = payload["adl"] as? String, AuthDeliveryID(adl) == nil { return false }
        return true
    }
}
