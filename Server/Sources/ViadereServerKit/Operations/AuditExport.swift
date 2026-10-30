@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore

// MARK: - Outbound HTTP (cloud APIs)

/// A tiny HTTP seam for the Azure data-plane REST calls (Key Vault, Blob Storage, Service Bus). Replaceable in tests (`Overrides.outboundHTTP`);
/// the real one uses Vapor's client over TLS behind the identity-endpoint guard.
public protocol OutboundHTTP: Sendable {
    func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data)
    /// The same call, also returning the response headers (lowercased names). Service Bus answers a receive with the lock `Location` and the
    /// `BrokerProperties` in headers.
    func sendReturningHeaders(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, headers: [String: String], body: Data)
}

extension OutboundHTTP {
    public func sendReturningHeaders(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, headers: [String: String], body: Data) {
        let response = try await send(method: method, url: url, headers: headers, body: body)
        return (response.status, [:], response.body)
    }
}

struct VaporOutboundHTTP: OutboundHTTP {
    let client: any Client
    /// Refuses the managed-identity endpoint and the metadata services (SSRF, SECURITY.md §1).
    let destinationGuard: OutboundDestinationGuard

    init(client: any Client, guard destinationGuard: OutboundDestinationGuard = OutboundDestinationGuard(identityEndpoint: nil)) {
        self.client = client
        self.destinationGuard = destinationGuard
    }

    func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data) {
        let response = try await sendReturningHeaders(method: method, url: url, headers: headers, body: body)
        return (response.status, response.body)
    }

    func sendReturningHeaders(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, headers: [String: String], body: Data) {
        guard url.hasPrefix("https://"), let parsed = URL(string: url) else { throw Abort(.badRequest) }
        try await destinationGuard.check(parsed)
        var request = ClientRequest(method: method, url: URI(string: url))
        for (name, value) in headers { request.headers.replaceOrAdd(name: name, value: value) }
        if let body { request.body = ByteBuffer(data: body) }
        let response = try await client.send(request)
        var buffer = response.body ?? ByteBuffer()
        var responseHeaders: [String: String] = [:]
        for (name, value) in response.headers { responseHeaders[name.lowercased()] = value }
        return (Int(response.status.code), responseHeaders, Data(buffer.readBytes(length: min(buffer.readableBytes, 256 * 1024)) ?? []))
    }
}

struct UnconfiguredOutboundHTTP: OutboundHTTP {
    func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data) { throw Abort(.serviceUnavailable) }
}

// MARK: - Exporter

/// Writes the signed audit-chain head to write-once storage on a schedule (`AUDIT_HEAD_EXPORT`, `AZURE_AUDIT_BLOB_*`), signed by the chain key and,
/// when configured, by the Key Vault key `AZURE_KEY_VAULT_AUDIT_HEAD_KEY` (ES256, verifiable by anyone with the published public key and independent
/// of `AUDIT_CHAIN_KEY`, so a server compromise cannot forge an old head). The head is the only defence against an attacker who holds both the
/// database and the chain key, so the container is immutable (version-level WORM) and objects are create-only (`If-None-Match: *`). The time of the
/// last success is `platform_flags.audit.export_mark` (also the retention job's proof that older events are safely anchored, and the
/// `viadere_audit_head_export_age_seconds` gauge).
struct AuditHeadExporter {
    let db: any Database
    let ctx: ServerContext

    struct Exported: Codable, Equatable {
        var head: AuditService.SignedHead
        /// The exact Key Vault key version that signed (`audit-head-signing/<version>`).
        var kmsKey: String?
        /// base64url of the raw ES256 signature `r ‖ s` (low-S) over SHA-256 of `head.message()`.
        var kmsSignature: String?
    }

    enum ExportError: Error { case storeUnavailable, signerUnavailable }

    func store(for settings: AuditHeadExportSettings) throws -> any ObjectStore {
        if let store = ctx.auditObjectStore { return store }
        switch settings.kind {
        case .directory: return DirectoryObjectStore(directory: settings.target)
        case .azureBlob: throw ExportError.storeUnavailable // built in `configure` with the managed identity; never without it
        }
    }

    /// Exports when the interval has passed since the last success. Returns whether an object was written.
    @discardableResult
    func runIfDue(force: Bool = false) async throws -> Bool {
        guard let settings = ctx.config.operations.auditExport else { return false }
        let now = ctx.now
        let mark = try await PlatformFlagRecord.query(on: db).filter(\.$flag == PlatformFlag.auditExportMark.rawValue).first()
        if !force, let mark, now.timeIntervalSince(mark.updatedAt) < settings.interval { return false }
        guard let head = try await AuditService.signedHead(on: db, keyring: AuditKeyring(config: ctx.config), now: now) else { return false }
        // Nothing new since the last export: refresh the mark so the age gauge stays honest, write nothing.
        if let mark, mark.value == String(head.seq) {
            mark.updatedAt = now
            try await mark.update(on: db)
            return false
        }
        var exported = Exported(head: head, kmsKey: nil, kmsSignature: nil)
        if let keyRef = settings.signingKey {
            guard let kms = ctx.kms else { throw ExportError.signerUnavailable }
            // Pin the version first and sign with exactly that version (the KMS verifies the signature against its public key before returning).
            let pinned = try await kms.resolveVersion(keyRef: keyRef)
            exported.kmsKey = pinned
            exported.kmsSignature = Base64URL.encode(try await kms.sign(keyRef: pinned, message: head.message()))
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let day = String(head.exportedAt.prefix(10))
        let name = "\(settings.prefix)\(day)/\(String(format: "%012d", head.seq))-\(head.exportedAt.replacingOccurrences(of: ":", with: "")).json"
        try await store(for: settings).create(name: name, data: try encoder.encode(exported), contentType: "application/json")
        if let mark {
            mark.value = String(head.seq)
            mark.updatedAt = now
            mark.reason = "exported \(name)"
            try await mark.update(on: db)
        } else {
            let row = PlatformFlagRecord()
            row.id = UUID()
            row.flag = PlatformFlag.auditExportMark.rawValue
            row.scope = PlatformFlags.globalScope
            row.value = String(head.seq)
            row.reason = "exported \(name)"
            row.updatedBy = "system"
            row.updatedAt = now
            try await row.create(on: db)
        }
        return true
    }
}

/// `ViadereServer audit-export [--force]` runs one export now (for the scheduled job's first run, drills and verification).
public struct AuditExportCommand: AsyncCommand {
    public struct Signature: CommandSignature {
        @Flag(name: "force") var force: Bool
        public init() {}
    }
    public let signature = Signature()
    public let help = "Exports the signed audit-chain head to the configured write-once storage now."
    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        let app = context.application
        guard app.ctx.config.operations.auditExport != nil else {
            context.console.error("AUDIT_HEAD_EXPORT is not configured.")
            throw Abort(.internalServerError)
        }
        let wrote = try await AuditHeadExporter(db: app.db, ctx: app.ctx).runIfDue(force: signature.force)
        context.console.print(wrote ? "Exported the audit head." : "Nothing to export.")
    }
}
