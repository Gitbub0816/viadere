@preconcurrency import Crypto
import Foundation
import ViadereCore

/// Where the scheduled audit-head export writes (`AUDIT_HEAD_EXPORT_*`).
public struct AuditHeadExportSettings: Sendable, Equatable {
    public enum Kind: String, Sendable, Equatable { case gcs, r2, directory }
    public var kind: Kind
    /// Bucket name (`gcs`, `r2`) or an absolute directory (`directory`: development and tests only).
    public var target: String
    public var prefix: String
    /// R2 only: the S3-compatible endpoint (`https://<account>.r2.cloudflarestorage.com`).
    public var endpoint: String?
    public var interval: TimeInterval
    /// Sign the head with the KMS signing key as well as the chain MAC (`AUDIT_HEAD_KMS_KEY`, a full KMS crypto key version resource name).
    public var kmsKey: String?
}

/// Server settings added by WP6 (operations, key rotation, edge lock, metrics, webhooks, API keys).
public struct OperationsSettings: Sendable {
    // MARK: Edge lock (G-10) and Tier E client certificates (SEC-TR-005)
    /// Accepted values of `X-Viadere-Edge-Token` as the exact header text: `EDGE_TOKEN` then `EDGE_TOKEN_PREVIOUS`. Empty = lock off (development and tests only).
    public var edgeTokens: [Data] = []
    /// Peers (the TCP source address) of Fly's health checker; used with the absence of every proxy header.
    public var healthPeerNetworks: [IPNetwork] = ["fdaa::/16", "172.16.0.0/12", "10.0.0.0/8", "127.0.0.0/8", "::1/128"].compactMap(IPNetwork.init)
    public var edgeHeader = "X-Viadere-Edge-Token"
    /// Set by Cloudflare API Shield (rule: `cf.tls_client_auth.cert_verified` and the SHA-256 fingerprint). Trusted only on an edge-locked request.
    public var clientCertFingerprintHeader = "X-Viadere-Client-Cert-Sha256"
    public var clientCertIssuerHeader = "X-Viadere-Client-Cert-Issuer-Ski"
    public var clientCertVerifiedHeader = "X-Viadere-Client-Cert-Verified"

    // MARK: Metrics (G-13)
    public var metricsToken: Data?
    /// A separate internal listener (not routed by Fly's proxy); `nil` = only the token-protected route on the main port.
    public var metricsPort: Int?

    // MARK: Webhooks, keys
    /// `required` (the default in staging and production): an endpoint receives events only after it echoed our challenge.
    public var webhookOwnershipVerification = true
    public var apiKeyMaxOverlap: TimeInterval = 30 * 86_400
    public var privilegedInactivity: TimeInterval = 300

    // MARK: Onboarding assurance
    public var domainRecheckInterval: TimeInterval = 30 * 86_400
    public var assuranceGrace: TimeInterval = 14 * 86_400

    // MARK: Key rotation (G-8)
    /// The id of `DATA_ENCRYPTION_KEY`. The default `k1` is the implicit id of every `v1.`/`v2.` ciphertext written before key ids existed
    /// and is written in the `v2.` form; any other id writes `v3.<id>.`.
    public var dataKeyId = FieldCipher.legacyKeyId
    public var previousDataKeys: [String: SymmetricKey] = [:]
    public var pepperId = Hasher256.legacyPepperId
    public var previousPeppers: [String: Data] = [:]
    public var auditKeyEpoch = 1
    public var previousAuditKeys: [Int: SymmetricKey] = [:]
    public var connectKeyId = ConnectKeyring.legacyKeyId
    public var previousConnectKeys: [String: SymmetricKey] = [:]

    // MARK: Database roles, audit export
    /// `DATABASE_MIGRATION_URL`: the DDL-capable role the `migrate` command uses. The runtime role (`DATABASE_URL`) needs no DDL.
    public var migrationDatabaseURL: String?
    public var auditExport: AuditHeadExportSettings?

    public init() {}
}

extension ServerConfig {
    mutating func applyOperationsEnvironment(_ env: [String: String], production strict: Bool) throws {
        var ops = OperationsSettings()
        // G-10: required whenever the server is internet-facing.
        for name in ["EDGE_TOKEN", "EDGE_TOKEN_PREVIOUS"] {
            guard let raw = env[name], !raw.isEmpty else {
                if name == "EDGE_TOKEN", strict { throw ServerConfigError.missing("EDGE_TOKEN") }
                continue
            }
            guard Self.isOpaqueToken(raw) else { throw ServerConfigError.invalid("\(name) (at least 32 printable characters, no spaces)") }
            ops.edgeTokens.append(Data(raw.utf8))
        }
        if let raw = env["METRICS_TOKEN"], !raw.isEmpty {
            guard Self.isOpaqueToken(raw) else { throw ServerConfigError.invalid("METRICS_TOKEN (at least 32 printable characters, no spaces)") }
            ops.metricsToken = Data(raw.utf8)
        }
        if let raw = env["METRICS_PORT"], !raw.isEmpty {
            guard let port = Int(raw), (1024...65535).contains(port) else { throw ServerConfigError.invalid("METRICS_PORT (1024-65535)") }
            ops.metricsPort = port
        }
        // Webhook ownership verification cannot be switched off where the server is internet-facing.
        switch (env["WEBHOOK_OWNERSHIP_VERIFICATION"] ?? "").lowercased() {
        case "": ops.webhookOwnershipVerification = strict
        case "required": ops.webhookOwnershipVerification = true
        case "off":
            if strict { throw ServerConfigError.invalid("WEBHOOK_OWNERSHIP_VERIFICATION (cannot be off in staging or production)") }
            ops.webhookOwnershipVerification = false
        default: throw ServerConfigError.invalid("WEBHOOK_OWNERSHIP_VERIFICATION (required or off)")
        }
        if let v = env["API_KEY_MAX_OVERLAP_DAYS"].flatMap(Double.init) {
            guard (1...90).contains(v) else { throw ServerConfigError.invalid("API_KEY_MAX_OVERLAP_DAYS (1-90)") }
            ops.apiKeyMaxOverlap = v * 86_400
        }
        if let v = env["DOMAIN_RECHECK_DAYS"].flatMap(Double.init) {
            guard (1...180).contains(v) else { throw ServerConfigError.invalid("DOMAIN_RECHECK_DAYS (1-180)") }
            ops.domainRecheckInterval = v * 86_400
        }
        if let v = env["ASSURANCE_GRACE_DAYS"].flatMap(Double.init) {
            guard (1...90).contains(v) else { throw ServerConfigError.invalid("ASSURANCE_GRACE_DAYS (1-90)") }
            ops.assuranceGrace = v * 86_400
        }
        // Key ids and previous keys. Previous keys are secrets: `id:base64url` pairs separated by commas.
        func previous(_ name: String, minimum: Int) throws -> [(String, Data)] {
            guard let raw = env[name], !raw.isEmpty else { return [] }
            var out: [(String, Data)] = []
            for pair in raw.split(separator: ",") {
                let parts = pair.split(separator: ":", maxSplits: 1).map(String.init)
                guard parts.count == 2, Self.isKeyId(parts[0]), let data = Base64URL.decode(parts[1]) ?? Data(base64Encoded: parts[1]),
                      data.count >= minimum, !out.contains(where: { $0.0 == parts[0] }) else { throw ServerConfigError.invalid("\(name) (id:base64url,...)") }
                out.append((parts[0], data))
            }
            return out
        }
        func keyId(_ name: String, fallback: String) throws -> String {
            guard let raw = env[name], !raw.isEmpty else { return fallback }
            guard Self.isKeyId(raw) else { throw ServerConfigError.invalid("\(name) (1-16 characters: letters, digits, dash)") }
            return raw
        }
        ops.dataKeyId = try keyId("DATA_ENCRYPTION_KEY_ID", fallback: FieldCipher.legacyKeyId)
        for (id, data) in try previous("DATA_ENCRYPTION_KEYS_PREVIOUS", minimum: 32) { ops.previousDataKeys[id] = SymmetricKey(data: data.prefix(32)) }
        guard !ops.previousDataKeys.keys.contains(ops.dataKeyId) else { throw ServerConfigError.invalid("DATA_ENCRYPTION_KEYS_PREVIOUS (repeats the current key id)") }
        ops.pepperId = try keyId("SERVER_PEPPER_ID", fallback: Hasher256.legacyPepperId)
        for (id, data) in try previous("SERVER_PEPPERS_PREVIOUS", minimum: 32) { ops.previousPeppers[id] = data }
        guard !ops.previousPeppers.keys.contains(ops.pepperId) else { throw ServerConfigError.invalid("SERVER_PEPPERS_PREVIOUS (repeats the current pepper id)") }
        if let raw = env["AUDIT_CHAIN_KEY_EPOCH"], !raw.isEmpty {
            guard let epoch = Int(raw), (1...10_000).contains(epoch) else { throw ServerConfigError.invalid("AUDIT_CHAIN_KEY_EPOCH (1-10000)") }
            ops.auditKeyEpoch = epoch
        }
        for (id, data) in try previous("AUDIT_CHAIN_KEYS_PREVIOUS", minimum: 32) {
            guard let epoch = Int(id), (1...10_000).contains(epoch), epoch < ops.auditKeyEpoch else { throw ServerConfigError.invalid("AUDIT_CHAIN_KEYS_PREVIOUS (epoch:key with epoch below the current one)") }
            ops.previousAuditKeys[epoch] = SymmetricKey(data: data)
        }
        // A rotated chain key must keep every earlier epoch, or the chain cannot be verified.
        if ops.auditKeyEpoch > 1, Set(ops.previousAuditKeys.keys) != Set(1..<ops.auditKeyEpoch) {
            throw ServerConfigError.invalid("AUDIT_CHAIN_KEYS_PREVIOUS (must list every epoch from 1 to the one below AUDIT_CHAIN_KEY_EPOCH)")
        }
        ops.connectKeyId = try keyId("CONNECT_LINK_SIGNING_KEY_ID", fallback: ConnectKeyring.legacyKeyId)
        for (id, data) in try previous("CONNECT_LINK_SIGNING_KEYS_PREVIOUS", minimum: 32) { ops.previousConnectKeys[id] = SymmetricKey(data: data) }
        // Database roles.
        if let url = env["DATABASE_MIGRATION_URL"], !url.isEmpty {
            guard url.hasPrefix("postgres://") || url.hasPrefix("postgresql://") else { throw ServerConfigError.invalid("DATABASE_MIGRATION_URL (postgres URL)") }
            ops.migrationDatabaseURL = url
        }
        // Audit head export.
        if let kindRaw = env["AUDIT_HEAD_EXPORT"], !kindRaw.isEmpty {
            guard let kind = AuditHeadExportSettings.Kind(rawValue: kindRaw.lowercased()) else { throw ServerConfigError.invalid("AUDIT_HEAD_EXPORT (gcs, r2 or directory)") }
            if kind == .directory, strict { throw ServerConfigError.invalid("AUDIT_HEAD_EXPORT (directory is for development only)") }
            guard let target = env["AUDIT_HEAD_EXPORT_TARGET"], !target.isEmpty, target.count <= 255 else { throw ServerConfigError.missing("AUDIT_HEAD_EXPORT_TARGET") }
            var endpoint = env["AUDIT_HEAD_EXPORT_ENDPOINT"].flatMap { $0.isEmpty ? nil : $0 }
            if kind == .r2 {
                guard let e = endpoint, let url = URL(string: e), url.scheme == "https", url.host != nil else { throw ServerConfigError.invalid("AUDIT_HEAD_EXPORT_ENDPOINT (https URL for r2)") }
                endpoint = e.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            }
            let hours = env["AUDIT_HEAD_EXPORT_INTERVAL_HOURS"].flatMap(Double.init) ?? 6
            guard (0.01...168).contains(hours) else { throw ServerConfigError.invalid("AUDIT_HEAD_EXPORT_INTERVAL_HOURS") }
            ops.auditExport = AuditHeadExportSettings(kind: kind, target: target, prefix: env["AUDIT_HEAD_EXPORT_PREFIX"] ?? "audit-heads/",
                                                      endpoint: endpoint, interval: hours * 3600,
                                                      kmsKey: env["AUDIT_HEAD_KMS_KEY"].flatMap { $0.isEmpty ? nil : $0 })
        }
        operations = ops
    }

    /// A shared header value: the exact text Cloudflare sends (or a scraper presents). Compared as bytes, never decoded.
    static func isOpaqueToken(_ text: String) -> Bool {
        text.count >= 32 && text.count <= 256 && text.unicodeScalars.allSatisfy { $0.isASCII && $0.value > 0x20 && $0.value < 0x7F }
    }

    static func isKeyId(_ text: String) -> Bool {
        (1...16).contains(text.count) && text.unicodeScalars.allSatisfy { ($0.isASCII && ($0.properties.isAlphabetic || ("0"..."9").contains($0))) || $0 == "-" }
    }
}
