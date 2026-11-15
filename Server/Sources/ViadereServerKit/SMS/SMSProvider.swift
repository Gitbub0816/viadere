@preconcurrency import Crypto
import Foundation
import Vapor
import ViadereCore

/// A webhook request from the messaging provider, as received.
public struct ProviderWebhookRequest: Sendable {
    /// Which provider callback the request arrived on (a provider may use a different signing secret per route).
    public enum Route: Sendable, Equatable { case inbound, status }

    /// The exact public URL the provider called (built from configuration, never from the Host header).
    public var url: String
    public var route: Route
    public var signature: String?
    public var body: Data
    public var receivedAt: Date

    public init(url: String, route: Route = .inbound, signature: String?, body: Data, receivedAt: Date) {
        self.url = url
        self.route = route
        self.signature = signature
        self.body = body
        self.receivedAt = receivedAt
    }
}

public struct OutboundSMSRequest: Sendable {
    public var to: PhoneNumber
    public var body: String
    /// Our queue row id, for correlation with delivery receipts.
    public var reference: String
}

public struct OutboundSMSResult: Sendable {
    public var providerMessageId: String
}

public enum SMSProviderError: Error, Sendable, Equatable {
    /// Temporary failure: retry with backoff.
    case transient(String)
    /// Permanent failure for this message (bad number, blocked). `recipientOptedOut` marks carrier-level STOP.
    case permanent(code: String, recipientOptedOut: Bool)
    case malformedWebhook
}

public struct SMSDeliveryUpdate: Sendable, Equatable {
    public enum Status: String, Sendable { case delivered, failed, sent, queued }
    public var providerMessageId: String
    public var status: Status
    public var errorCode: String?
}

/// Provider-agnostic SMS adapter: webhook authenticity, parsing and sending.
public protocol SMSProvider: Sendable {
    var name: String { get }
    /// The request header carrying the webhook signature.
    var signatureHeader: String { get }
    /// Constant-time verification of the provider's webhook signature.
    func verifyWebhook(_ request: ProviderWebhookRequest) -> Bool
    func parseInbound(_ request: ProviderWebhookRequest) throws -> InboundSMS
    func parseDeliveryUpdate(_ request: ProviderWebhookRequest) throws -> SMSDeliveryUpdate?
    func send(_ request: OutboundSMSRequest) async throws -> OutboundSMSResult
}

extension SMSProvider {
    public var signatureHeader: String { "X-Twilio-Signature" }
}

/// Parses `application/x-www-form-urlencoded` bodies into ordered pairs.
enum FormParams {
    static func parse(_ data: Data) -> [(String, String)] {
        guard let text = String(data: data, encoding: .utf8) else { return [] }
        return text.split(separator: "&", omittingEmptySubsequences: true).compactMap { pair in
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard let rawKey = parts.first else { return nil }
            func decode(_ s: Substring) -> String? { s.replacingOccurrences(of: "+", with: " ").removingPercentEncoding }
            guard let key = decode(rawKey), let value = decode(parts.count > 1 ? parts[1] : "") else { return nil }
            return (key, value)
        }
    }
}

/// Used when no provider is configured: rejects all webhooks and cannot send.
public struct UnconfiguredSMSProvider: SMSProvider {
    public init() {}
    public var name: String { "unconfigured" }
    public func verifyWebhook(_ request: ProviderWebhookRequest) -> Bool { false }
    public func parseInbound(_ request: ProviderWebhookRequest) throws -> InboundSMS { throw SMSProviderError.malformedWebhook }
    public func parseDeliveryUpdate(_ request: ProviderWebhookRequest) throws -> SMSDeliveryUpdate? { nil }
    public func send(_ request: OutboundSMSRequest) async throws -> OutboundSMSResult { throw SMSProviderError.transient("unconfigured") }
}
