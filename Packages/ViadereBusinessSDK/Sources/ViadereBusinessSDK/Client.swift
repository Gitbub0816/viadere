import Foundation
import ViadereCore

/// Retry behaviour for transient failures (network errors, `429`, `5xx`). Only requests that are safe to repeat are
/// retried: every `GET`, and every `POST` that carries an idempotency key or is naturally idempotent (cancel).
public struct RetryPolicy: Sendable, Equatable {
    public var maxAttempts: Int
    public var baseDelay: TimeInterval
    public var maxDelay: TimeInterval

    public init(maxAttempts: Int = 3, baseDelay: TimeInterval = 0.5, maxDelay: TimeInterval = 30) {
        self.maxAttempts = max(1, maxAttempts)
        self.baseDelay = baseDelay
        self.maxDelay = maxDelay
    }

    public static let none = RetryPolicy(maxAttempts: 1)
    public static let standard = RetryPolicy()

    /// `Retry-After` wins (capped); otherwise exponential backoff with full jitter.
    func delay(attempt: Int, retryAfter: TimeInterval?) -> TimeInterval {
        if let retryAfter { return min(max(0, retryAfter), maxDelay) }
        let exponential = min(maxDelay, baseDelay * pow(2, Double(attempt - 1)))
        return Double.random(in: 0...exponential)
    }
}

/// Result of issuing an interaction.
public struct IssuedInteraction: Sendable, Equatable {
    public var interaction: Interaction
    /// `false` when the server recognized the idempotency key and returned the original interaction.
    public var wasCreated: Bool
}

/// A typed client for the Viadere business API (`/v1/business/*`) for **server-side** Swift.
///
/// * Authenticates with your API key (`Authorization: Bearer vdk_…`). Keep it on your server: never ship it in an app.
/// * Sets `Idempotency-Key` from the request's `idempotencyKey` so retries are safe.
/// * Retries `429`, `5xx` and network failures with backoff, honouring `Retry-After`.
/// * Never logs or prints the key (`description` is redacted).
public struct ViadereBusinessClient: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public static let userAgent = "ViadereBusinessSDK/1.0 (Swift)"

    private let apiKey: String
    public let baseURL: URL
    private let transport: any BusinessTransport
    public let retry: RetryPolicy
    private let sleep: @Sendable (TimeInterval) async -> Void

    /// - Parameters:
    ///   - apiKey: `vdk_live_…` or `vdk_test_…`.
    ///   - baseURL: defaults to `https://viadere.com`. Must be https (plain http only for loopback development).
    public init(apiKey: String, baseURL: URL = URL(string: "https://\(ViadereCore.domain)")!, transport: any BusinessTransport = URLSessionTransport(),
                retry: RetryPolicy = .standard, sleep: @escaping @Sendable (TimeInterval) async -> Void = { try? await Task.sleep(nanoseconds: UInt64($0 * 1_000_000_000)) }) throws {
        guard (apiKey.hasPrefix("vdk_live_") || apiKey.hasPrefix("vdk_test_")), apiKey.count >= 20, apiKey.count <= 80,
              apiKey.unicodeScalars.allSatisfy({ $0.isASCII && $0.value > 0x20 && $0.value < 0x7F }) else { throw ViadereSDKError.invalidAPIKey }
        let loopback = ["localhost", "127.0.0.1", "::1"].contains(baseURL.host ?? "")
        guard baseURL.scheme == "https" || (baseURL.scheme == "http" && loopback), baseURL.host != nil, baseURL.user == nil else {
            throw ViadereSDKError.insecureBaseURL
        }
        self.apiKey = apiKey
        self.baseURL = baseURL
        self.transport = transport
        self.retry = retry
        self.sleep = sleep
    }

    /// Whether this client uses a live key (real customers) or a test key.
    public var isLive: Bool { apiKey.hasPrefix("vdk_live_") }

    public var description: String { "ViadereBusinessClient(\(isLive ? "live" : "test") key •••\(apiKey.suffix(4)), \(baseURL.absoluteString))" }
    public var debugDescription: String { description }

    // MARK: Interactions

    /// Issues an interaction (`POST /v1/business/interactions`, scope `interactions:write`). Idempotent on `request.idempotencyKey`.
    public func issueInteraction(_ request: IssueInteractionRequest) async throws -> IssuedInteraction {
        let response = try await perform(APIRoutes.businessIssueInteraction.descriptor, body: request, idempotencyKey: request.idempotencyKey)
        return IssuedInteraction(interaction: try decode(Interaction.self, response), wasCreated: response.status == 201)
    }

    /// The outcome of an interaction (`GET /v1/business/interactions/{id}`, scope `interactions:read`).
    public func interactionOutcome(id: InteractionID) async throws -> InteractionOutcome {
        try decode(InteractionOutcome.self, try await perform(APIRoutes.businessInteractionOutcome.descriptor, parameters: ["interactionId": id.description]))
    }

    /// Cancels a pending interaction (scope `interactions:write`). Cancelling an already-final interaction returns its outcome.
    public func cancelInteraction(id: InteractionID) async throws -> InteractionOutcome {
        try decode(InteractionOutcome.self, try await perform(APIRoutes.businessCancelInteraction.descriptor, parameters: ["interactionId": id.description], naturallyIdempotent: true))
    }

    // MARK: Messages and statuses

    /// Sends a message into the customer's conversation with you (scope `messages:write`).
    public func sendMessage(_ request: BusinessSendMessageRequest) async throws -> ConversationMessage {
        try decode(ConversationMessage.self, try await perform(APIRoutes.businessSendMessage.descriptor, body: request, idempotencyKey: request.idempotencyKey))
    }

    /// Updates an ongoing-event status; a newer update with the same `activityKey` replaces the earlier one (scope `statuses:write`).
    public func updateStatus(_ request: BusinessStatusUpdateRequest) async throws -> Interaction {
        try decode(Interaction.self, try await perform(APIRoutes.businessUpdateStatus.descriptor, body: request, idempotencyKey: request.idempotencyKey))
    }

    // MARK: Webhooks (scope `webhooks:manage`)

    public func listWebhooks() async throws -> [WebhookSubscription] {
        try decode([WebhookSubscription].self, try await perform(APIRoutes.businessWebhooksList.descriptor))
    }

    /// Creates a subscription. The returned `secret` is shown **once**: store it in your secrets manager.
    public func createWebhook(url: URL, events: [WebhookEventType]) async throws -> WebhookSecretResponse {
        try decode(WebhookSecretResponse.self, try await perform(APIRoutes.businessWebhookCreate.descriptor, body: CreateWebhookRequest(url: url, events: events)))
    }

    public func deleteWebhook(id: WebhookSubscriptionID) async throws {
        _ = try await perform(APIRoutes.businessWebhookDelete.descriptor, parameters: ["webhookId": id.description])
    }

    /// Rotates the signing secret. The previous secret keeps signing for 24 hours so you can switch over without dropping events
    /// (verify with both: `WebhookVerifier(secrets: [new, old])`).
    public func rotateWebhookSecret(id: WebhookSubscriptionID) async throws -> WebhookSecretResponse {
        try decode(WebhookSecretResponse.self, try await perform(APIRoutes.businessWebhookRotate.descriptor, parameters: ["webhookId": id.description]))
    }

    // MARK: Plumbing

    func perform<Body: Encodable>(_ endpoint: AnyEndpoint, parameters: [String: String] = [:], body: Body?, idempotencyKey: String? = nil,
                                  naturallyIdempotent: Bool = false) async throws -> BusinessHTTPResponse {
        let path: String
        do { path = try endpoint.path(parameters) } catch { throw ViadereSDKError.invalidPath }
        guard let url = URL(string: baseURL.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + path) else { throw ViadereSDKError.invalidPath }
        var headers = ["Authorization": "Bearer \(apiKey)", "Accept": "application/json", "User-Agent": Self.userAgent]
        var payload: Data?
        if let body {
            do { payload = try ViadereJSON.encode(body) } catch { throw ViadereSDKError.encodingFailed }
            headers["Content-Type"] = "application/json"
        }
        if let idempotencyKey {
            guard IdempotencyKey.isValid(idempotencyKey) else { throw ViadereAPIError(status: 400, code: .badRequest, message: "Invalid idempotency key.", requestId: nil, details: nil, retryAfter: nil) }
            headers[ViadereHeader.idempotencyKey] = idempotencyKey
        }
        let safeToRetry = endpoint.method == .GET || idempotencyKey != nil || naturallyIdempotent
        let request = BusinessHTTPRequest(method: endpoint.method.rawValue, url: url, headers: headers, body: payload)
        return try await send(request, retryable: safeToRetry)
    }

    func perform(_ endpoint: AnyEndpoint, parameters: [String: String] = [:], naturallyIdempotent: Bool = false) async throws -> BusinessHTTPResponse {
        try await perform(endpoint, parameters: parameters, body: Optional<EmptyBody>.none, naturallyIdempotent: naturallyIdempotent)
    }

    private func send(_ request: BusinessHTTPRequest, retryable: Bool) async throws -> BusinessHTTPResponse {
        var attempt = 0
        while true {
            attempt += 1
            let outcome: Result<BusinessHTTPResponse, any Error>
            do { outcome = .success(try await transport.send(request)) } catch { outcome = .failure(error) }
            switch outcome {
            case .success(let response):
                if (200..<300).contains(response.status) { return response }
                let error = Self.apiError(response)
                if retryable, error.isRetryable, attempt < retry.maxAttempts {
                    await sleep(retry.delay(attempt: attempt, retryAfter: error.retryAfter))
                    continue
                }
                throw error
            case .failure(let error):
                if retryable, attempt < retry.maxAttempts {
                    await sleep(retry.delay(attempt: attempt, retryAfter: nil))
                    continue
                }
                if let sdk = error as? ViadereSDKError { throw sdk }
                throw ViadereSDKError.transport(String(describing: type(of: error)))
            }
        }
    }

    static func apiError(_ response: BusinessHTTPResponse) -> ViadereAPIError {
        let retryAfter = response.header("Retry-After").flatMap(TimeInterval.init)
        if let body = try? ViadereJSON.decode(APIErrorResponse.self, from: response.body) {
            return ViadereAPIError(status: response.status, code: body.error.code, message: body.error.message, requestId: body.error.requestId,
                                   details: body.error.details, retryAfter: retryAfter)
        }
        return ViadereAPIError(status: response.status, code: nil, message: "Unexpected response from the Viadere API.",
                               requestId: response.header("X-Request-Id"), details: nil, retryAfter: retryAfter)
    }

    private func decode<T: Decodable>(_ type: T.Type, _ response: BusinessHTTPResponse) throws -> T {
        do { return try ViadereJSON.decode(type, from: response.body) } catch {
            throw ViadereSDKError.decodingFailed(String(describing: T.self))
        }
    }
}
