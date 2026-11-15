import Foundation
import Vapor
import ViadereCore

/// Message attachment configuration (SECURITY.md §2.113). The store is a **private** container of its own, never the audit-head container
/// (write-once) and never the brand-asset container (brand images are served by hash; attachments never are):
///
/// * `AZURE_ATTACHMENT_BLOB_ENDPOINT` + `AZURE_ATTACHMENT_BLOB_CONTAINER` (managed identity, Entra only), or
/// * `ATTACHMENT_DIRECTORY` (development only).
///
/// Without either, development and tests keep attachments in memory; staging and production answer uploads `503` (text messages still work).
public struct AttachmentSettings: Sendable {
    public var blobEndpoint: String?
    public var blobContainer: String?
    public var directory: String?
    /// Uploads per account (all of its conversations), per business (API key and console together).
    public var uploadRatePerConsumer: RateRule = .perHour(60, burst: 20)
    public var uploadRatePerBusiness: RateRule = .perHour(1200, burst: 120)
    /// Images decoded at the same time by one process (up to 25 MP × 4 bytes each), separate from the Brand Kit gate.
    public var maxConcurrentIngestions = 2

    public init() {}
}

extension ServerConfig {
    /// `AZURE_ATTACHMENT_BLOB_ENDPOINT`, `AZURE_ATTACHMENT_BLOB_CONTAINER`, `ATTACHMENT_DIRECTORY`.
    mutating func applyAttachmentEnvironment(_ env: [String: String], production: Bool) throws {
        func value(_ name: String) -> String? { env[name].flatMap { $0.isEmpty ? nil : $0 } }
        var settings = AttachmentSettings()
        if let raw = value("AZURE_ATTACHMENT_BLOB_ENDPOINT") {
            guard AzureBlobObjectStore.normalizedEndpoint(raw) != nil else {
                throw ServerConfigError.invalid("AZURE_ATTACHMENT_BLOB_ENDPOINT (https://<account>.blob.core.windows.net/)")
            }
            guard let container = value("AZURE_ATTACHMENT_BLOB_CONTAINER"), AzureBlobObjectStore.isContainerName(container) else {
                throw ServerConfigError.invalid("AZURE_ATTACHMENT_BLOB_CONTAINER (a container name; required with AZURE_ATTACHMENT_BLOB_ENDPOINT)")
            }
            guard azure.clientId != nil, value("IDENTITY_ENDPOINT") != nil, value("IDENTITY_HEADER") != nil else {
                throw ServerConfigError.missing("AZURE_CLIENT_ID with a managed identity (for AZURE_ATTACHMENT_BLOB_ENDPOINT)")
            }
            let endpoint = AzureBlobObjectStore.normalizedEndpoint(raw)
            for (otherEndpoint, otherContainer, name) in [(azure.auditBlobEndpoint, azure.auditBlobContainer, "the audit-head container"),
                                                          (brandKits.blobEndpoint, brandKits.blobContainer, "the brand-asset container")] {
                if let otherEndpoint, let otherContainer, AzureBlobObjectStore.normalizedEndpoint(otherEndpoint) == endpoint, otherContainer == container {
                    throw ServerConfigError.invalid("AZURE_ATTACHMENT_BLOB_CONTAINER (must not be \(name))")
                }
            }
            settings.blobEndpoint = raw
            settings.blobContainer = container
        }
        if let directory = value("ATTACHMENT_DIRECTORY") {
            guard !production else { throw ServerConfigError.invalid("ATTACHMENT_DIRECTORY (development only; use AZURE_ATTACHMENT_BLOB_ENDPOINT)") }
            settings.directory = directory
        }
        attachments = settings
    }
}

/// Process-wide attachment collaborators: the private store and the decode gate. Built once by `configure`.
final class AttachmentRuntime: @unchecked Sendable {
    /// `nil` = no store configured (uploads answer `503`).
    var store: (any ObjectStore)?
    let gate: IngestGate

    init(store: (any ObjectStore)? = nil, maxConcurrent: Int = 2) {
        self.store = store
        self.gate = IngestGate(limit: maxConcurrent)
    }

    /// The store: the override (tests), the Azure container, a development directory, memory outside staging and production, else none.
    static func store(config: ServerConfig, override: (any ObjectStore)?, tokens: (any AccessTokenSource)?, http: any OutboundHTTP,
                      now: @escaping @Sendable () -> Date) throws -> (any ObjectStore)? {
        if let override { return override }
        let settings = config.attachments
        if let endpoint = settings.blobEndpoint, let container = settings.blobContainer {
            guard let tokens else { throw ServerConfigError.missing("a managed identity (for AZURE_ATTACHMENT_BLOB_ENDPOINT)") }
            return try AzureBlobObjectStore(endpoint: endpoint, container: container, tokens: tokens, http: http, now: now)
        }
        if let directory = settings.directory { return DirectoryObjectStore(directory: directory) }
        return config.isStrict ? nil : MemoryObjectStore()
    }
}

private struct AttachmentRuntimeKey: StorageKey { typealias Value = AttachmentRuntime }

extension Application {
    var attachments: AttachmentRuntime {
        get {
            if let value = storage[AttachmentRuntimeKey.self] { return value }
            let value = AttachmentRuntime()
            storage[AttachmentRuntimeKey.self] = value
            return value
        }
        set { storage[AttachmentRuntimeKey.self] = newValue }
    }
}

extension Request {
    var attachments: AttachmentRuntime { application.attachments }
}
