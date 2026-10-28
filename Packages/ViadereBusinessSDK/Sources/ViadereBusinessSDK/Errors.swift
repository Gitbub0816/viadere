import Foundation
import ViadereCore

/// The API answered with an error. `code` is the stable machine code (`APIErrorCode`); `message` is safe to log.
public struct ViadereAPIError: Error, Sendable, Equatable, CustomStringConvertible {
    public var status: Int
    public var code: APIErrorCode?
    public var message: String
    /// Quote this when contacting Viadere support.
    public var requestId: String?
    public var details: [String: String]?
    /// Seconds from `Retry-After` (429 / 503), when present.
    public var retryAfter: TimeInterval?

    public var description: String {
        "Viadere API error \(status) \(code?.rawValue ?? "unknown"): \(message)" + (requestId.map { " (request \($0))" } ?? "")
    }

    /// The request is safe to retry unchanged (rate limited or a server-side failure).
    public var isRetryable: Bool { status == 429 || status >= 500 }

    /// The key lacks the capability (`insufficient_scope`), the business is not (or no longer) entitled to it (`not_entitled`), or it is
    /// switched off (`capability_disabled`). Retrying unchanged cannot help: use a key with the capability, ask Viadere for the
    /// entitlement, or wait for the capability to be re-enabled. `details["capability"]` names it.
    public var isCapabilityDenied: Bool { code == .insufficientScope || code == .notEntitled || code == .capabilityDisabled }

    /// The capability the request needed, when the API says so.
    public var deniedCapability: Capability? { details?["capability"].map { Capability(rawValue: $0) } }
}

/// Failures that are not API errors.
public enum ViadereSDKError: Error, Sendable, Equatable {
    /// The API key does not look like a Viadere key.
    case invalidAPIKey
    /// The base URL is not an https URL (http is allowed only for loopback hosts, for local development).
    case insecureBaseURL
    /// The response was not an HTTP response or could not be decoded.
    case invalidResponse
    case decodingFailed(String)
    case encodingFailed
    /// A path parameter was empty or missing.
    case invalidPath
    /// The request failed locally (network, TLS, timeout) on every attempt.
    case transport(String)
}

/// Why a webhook was rejected. Respond `400` (or `401`) and do **not** process the event.
public enum WebhookVerificationError: Error, Sendable, Equatable {
    case missingSignatureHeader
    case malformedSignature
    /// `|now - t|` exceeded the tolerance: a replayed or badly delayed delivery.
    case timestampOutsideTolerance
    case noMatchingSignature
    case malformedBody
    /// `Viadere-Event-Id` / `Viadere-Event-Type` disagree with the signed body.
    case headerBodyMismatch
    case duplicateEvent
    /// The request is not a `webhook.verification` challenge.
    case notAVerificationRequest
}
