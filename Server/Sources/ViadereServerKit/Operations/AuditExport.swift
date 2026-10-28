@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore

// MARK: - Outbound HTTP (cloud APIs)

/// A tiny HTTP seam for the calls to Google Cloud and R2. Replaceable in tests (`Overrides.outboundHTTP`); the real one uses Vapor's client over TLS.
public protocol OutboundHTTP: Sendable {
    func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data)
}

struct VaporOutboundHTTP: OutboundHTTP {
    let client: any Client

    func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data) {
        guard url.hasPrefix("https://") else { throw Abort(.badRequest) }
        var request = ClientRequest(method: method, url: URI(string: url))
        for (name, value) in headers { request.headers.replaceOrAdd(name: name, value: value) }
        if let body { request.body = ByteBuffer(data: body) }
        let response = try await client.send(request)
        var buffer = response.body ?? ByteBuffer()
        return (Int(response.status.code), Data(buffer.readBytes(length: min(buffer.readableBytes, 256 * 1024)) ?? []))
    }
}

struct UnconfiguredOutboundHTTP: OutboundHTTP {
    func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data) { throw Abort(.serviceUnavailable) }
}

// MARK: - Google Cloud: workload identity federation, KMS signing, Cloud Storage

/// Where the OIDC token that proves "this is the Viadere server on Fly" comes from: a file (`GCP_SUBJECT_TOKEN_FILE`, any platform that can write one)
/// or Fly's local OIDC endpoint. No service-account key exists anywhere; the token is exchanged at Google STS for a short-lived access token that
/// impersonates the dedicated service account (Infra/terraform/kms.tf).
struct GoogleAuth: Sendable {
    let http: any OutboundHTTP
    let audience: String
    let serviceAccount: String
    let subjectToken: @Sendable () async throws -> String

    func accessToken() async throws -> String {
        let subject = try await subjectToken()
        let exchange = try await http.send(method: .POST, url: "https://sts.googleapis.com/v1/token",
            headers: ["Content-Type": "application/json"],
            body: try JSONSerialization.data(withJSONObject: [
                "grantType": "urn:ietf:params:oauth:grant-type:token-exchange", "audience": audience, "scope": "https://www.googleapis.com/auth/cloud-platform",
                "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token", "subjectToken": subject, "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
            ]))
        guard exchange.status == 200, let federated = (try? JSONSerialization.jsonObject(with: exchange.body) as? [String: Any])?["access_token"] as? String else { throw Abort(.badGateway) }
        let impersonate = try await http.send(method: .POST,
            url: "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/\(serviceAccount):generateAccessToken",
            headers: ["Content-Type": "application/json", "Authorization": "Bearer \(federated)"],
            body: try JSONSerialization.data(withJSONObject: ["scope": ["https://www.googleapis.com/auth/cloud-platform"], "lifetime": "300s"]))
        guard impersonate.status == 200, let token = (try? JSONSerialization.jsonObject(with: impersonate.body) as? [String: Any])?["accessToken"] as? String else { throw Abort(.badGateway) }
        return token
    }
}

/// `asymmetricSign` with the HSM key for audit heads (`audit-head` in Infra/terraform/kms.tf): the signature is verifiable by anyone with the
/// public key and is independent of `AUDIT_CHAIN_KEY`, so a server compromise cannot forge an old head.
struct KMSHeadSigner: Sendable {
    let http: any OutboundHTTP
    let auth: GoogleAuth
    /// `projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N`
    let keyVersion: String

    func sign(_ message: Data) async throws -> String {
        let token = try await auth.accessToken()
        let digest = Data(SHA256.hash(data: message))
        let response = try await http.send(method: .POST, url: "https://cloudkms.googleapis.com/v1/\(keyVersion):asymmetricSign",
            headers: ["Content-Type": "application/json", "Authorization": "Bearer \(token)"],
            body: try JSONSerialization.data(withJSONObject: ["digest": ["sha256": digest.base64EncodedString()]]))
        guard response.status == 200, let signature = (try? JSONSerialization.jsonObject(with: response.body) as? [String: Any])?["signature"] as? String else { throw Abort(.badGateway) }
        return signature
    }
}

// MARK: - Sinks

protocol AuditHeadSink: Sendable {
    /// Writes a new object. Must fail if the name already exists (write-once).
    func store(name: String, data: Data) async throws
}

/// Development and tests: a directory on disk.
struct DirectoryHeadSink: AuditHeadSink {
    let directory: String
    func store(name: String, data: Data) async throws {
        let url = URL(fileURLWithPath: directory).appendingPathComponent(name)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        guard !FileManager.default.fileExists(atPath: url.path) else { throw Abort(.conflict) }
        // `withoutOverwriting` makes the write create-only (it cannot be combined with `atomic`).
        try data.write(to: url, options: [.withoutOverwriting])
    }
}

/// A Cloud Storage bucket with a locked retention policy (Infra/terraform/audit_bucket.tf). `ifGenerationMatch=0` makes the upload create-only.
struct GCSHeadSink: AuditHeadSink {
    let http: any OutboundHTTP
    let auth: GoogleAuth
    let bucket: String

    func store(name: String, data: Data) async throws {
        let token = try await auth.accessToken()
        let encoded = name.addingPercentEncoding(withAllowedCharacters: CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")) ?? name
        let response = try await http.send(method: .POST,
            url: "https://storage.googleapis.com/upload/storage/v1/b/\(bucket)/o?uploadType=media&name=\(encoded)&ifGenerationMatch=0",
            headers: ["Content-Type": "application/json", "Authorization": "Bearer \(token)"], body: data)
        guard (200..<300).contains(response.status) else { throw Abort(.badGateway) }
    }
}

/// Cloudflare R2 (S3-compatible, object-lock bucket) with AWS Signature V4. `If-None-Match: *` makes the upload create-only.
struct R2HeadSink: AuditHeadSink {
    let http: any OutboundHTTP
    let endpoint: String
    let bucket: String
    let accessKeyId: String
    let secretAccessKey: String
    let now: @Sendable () -> Date

    func store(name: String, data: Data) async throws {
        guard let base = URL(string: endpoint), let host = base.host else { throw Abort(.badRequest) }
        let path = "/\(bucket)/" + name.split(separator: "/").map { Self.encode(String($0)) }.joined(separator: "/")
        let date = now()
        let amz = Self.amzDate(date), day = String(Self.amzDate(date).prefix(8))
        let payloadHash = SecureToken.sha256Hex(data)
        var headers = ["host": host, "x-amz-content-sha256": payloadHash, "x-amz-date": amz, "if-none-match": "*", "content-type": "application/json"]
        let signedHeaders = headers.keys.sorted().joined(separator: ";")
        let canonicalHeaders = headers.keys.sorted().map { "\($0):\(headers[$0]!)\n" }.joined()
        let canonical = ["PUT", path, "", canonicalHeaders, signedHeaders, payloadHash].joined(separator: "\n")
        let scope = "\(day)/auto/s3/aws4_request"
        let toSign = ["AWS4-HMAC-SHA256", amz, scope, SecureToken.sha256Hex(Data(canonical.utf8))].joined(separator: "\n")
        func hmac(_ key: Data, _ message: String) -> Data { Data(HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: SymmetricKey(data: key))) }
        let signingKey = hmac(hmac(hmac(hmac(Data("AWS4\(secretAccessKey)".utf8), day), "auto"), "s3"), "aws4_request")
        let signature = Hex.encode(hmac(signingKey, toSign))
        headers["authorization"] = "AWS4-HMAC-SHA256 Credential=\(accessKeyId)/\(scope), SignedHeaders=\(signedHeaders), Signature=\(signature)"
        let response = try await http.send(method: .PUT, url: endpoint + path, headers: headers, body: data)
        guard (200..<300).contains(response.status) else { throw Abort(.badGateway) }
    }

    static func encode(_ part: String) -> String {
        part.addingPercentEncoding(withAllowedCharacters: CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")) ?? part
    }

    static func amzDate(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        return f.string(from: date)
    }
}

// MARK: - Exporter

/// Writes the signed audit-chain head to write-once storage on a schedule (`AUDIT_HEAD_EXPORT_*`), signed by the chain key and, when configured,
/// by the KMS signing key. The head is the only defence against an attacker who holds both the database and the chain key, so the bucket has a
/// locked retention policy (Terraform) and objects are create-only. The time of the last success is `platform_flags.audit.export_mark`
/// (also the retention job's proof that older events are safely anchored, and the `viadere_audit_head_export_age_seconds` gauge).
struct AuditHeadExporter {
    let db: any Database
    let ctx: ServerContext

    struct Exported: Codable, Equatable {
        var head: AuditService.SignedHead
        var kmsKey: String?
        var kmsSignature: String?
    }

    func sink(for settings: AuditHeadExportSettings) throws -> any AuditHeadSink {
        switch settings.kind {
        case .directory: return DirectoryHeadSink(directory: settings.target)
        case .gcs: return GCSHeadSink(http: ctx.outbound, auth: try googleAuth(settings), bucket: settings.target)
        case .r2:
            guard let endpoint = settings.endpoint, let id = settings.r2AccessKeyId, let secret = settings.r2SecretAccessKey else { throw Abort(.internalServerError) }
            return R2HeadSink(http: ctx.outbound, endpoint: endpoint, bucket: settings.target, accessKeyId: id, secretAccessKey: secret, now: { [clock = ctx.clock] in clock.now() })
        }
    }

    func googleAuth(_ settings: AuditHeadExportSettings) throws -> GoogleAuth {
        guard let audience = settings.googleAudience, let account = settings.googleServiceAccount else { throw Abort(.internalServerError) }
        let file = settings.subjectTokenFile
        return GoogleAuth(http: ctx.outbound, audience: audience, serviceAccount: account) {
            guard let file else { throw Abort(.internalServerError) }
            return try String(contentsOfFile: file, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
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
        if let keyVersion = settings.kmsKey {
            exported.kmsKey = keyVersion
            exported.kmsSignature = try await KMSHeadSigner(http: ctx.outbound, auth: try googleAuth(settings), keyVersion: keyVersion).sign(head.message())
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let day = String(head.exportedAt.prefix(10))
        let name = "\(settings.prefix)\(day)/\(String(format: "%012d", head.seq))-\(head.exportedAt.replacingOccurrences(of: ":", with: "")).json"
        try await sink(for: settings).store(name: name, data: try encoder.encode(exported))
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

/// `ViadereServer audit-export [--force]` runs one export now (for the cron-like job's first run, drills and verification).
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
