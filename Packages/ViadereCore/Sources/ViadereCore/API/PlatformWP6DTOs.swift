import Foundation

// MARK: - Webhook endpoint ownership, pause and test (WP6, SEC-API-006)

/// The outcome of `POST /v1/business/webhooks/{webhookId}/verify`: Viadere POSTs a single-use challenge to the endpoint, which must answer
/// 2xx and echo it (as `{"challenge": "..."}` or as the bare body). Until it does, the endpoint receives no events.
public struct WebhookVerificationResult: Codable, Sendable, Hashable {
    public var verified: Bool
    /// `no_echo`, `http_<status>` or `unreachable` when not verified.
    public var failure: String?
    public init(verified: Bool, failure: String? = nil) {
        self.verified = verified
        self.failure = failure
    }
}

public struct PauseWebhookRequest: Codable, Sendable, Hashable {
    public var reason: String?
    public init(reason: String? = nil) { self.reason = reason }
}

// MARK: - Subject access export (LEG-PR-004)

/// Asks for an export of the caller's data. `recipientKey` is the device's P-256 key-agreement public key (`E2EEPublicKey`, base64url X9.63):
/// the export is sealed to it and the server keeps nothing that can open it.
public struct AccountExportRequest: Codable, Sendable, Hashable {
    public var recipientKey: String
    public init(recipientKey: String) { self.recipientKey = recipientKey }
}

public struct AccountExportStatus: Codable, Sendable, Hashable {
    public var exportId: String
    /// `queued`, `ready` or `expired`.
    public var status: String
    public var createdAt: Date
    public var readyAt: Date?
    public var expiresAt: Date
    /// Present when `ready`: where to fetch the sealed bundle (device-signed request, same account).
    public var downloadPath: String?
    public init(exportId: String, status: String, createdAt: Date, readyAt: Date?, expiresAt: Date, downloadPath: String?) {
        self.exportId = exportId
        self.status = status
        self.createdAt = createdAt
        self.readyAt = readyAt
        self.expiresAt = expiresAt
        self.downloadPath = downloadPath
    }
}

/// The export itself: `E2EEEnvelope`s (serialized, base64url) sealed to the requesting device's key, in order. Each opens to one UTF-8 JSON
/// chunk; concatenated they are one JSON document (`format` `viadere-export-v1`).
public struct AccountExportBundle: Codable, Sendable, Hashable {
    public var exportId: String
    public var format: String
    public var envelopes: [String]
    public init(exportId: String, format: String = "viadere-export-v1", envelopes: [String]) {
        self.exportId = exportId
        self.format = format
        self.envelopes = envelopes
    }
}
