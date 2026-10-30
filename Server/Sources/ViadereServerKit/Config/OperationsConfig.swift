@preconcurrency import Crypto
import Foundation
import ViadereCore

/// Where the scheduled audit-head export writes (`AUDIT_HEAD_EXPORT`, `AZURE_AUDIT_BLOB_*`, `AZURE_KEY_VAULT_AUDIT_HEAD_KEY`).
public struct AuditHeadExportSettings: Sendable, Equatable {
    public enum Kind: String, Sendable, Equatable {
        /// An immutable Azure Blob container through the managed identity (WP-B2; replaces the GCS and R2 sinks).
        case azureBlob = "azure-blob"
        /// A directory on disk (development and tests only).
        case directory
    }
    public var kind: Kind
    /// The container (`azure-blob`) or an absolute directory (`directory`).
    public var target: String
    public var prefix: String
    /// `azure-blob` only: `https://<account>.blob.core.windows.net`.
    public var endpoint: String?
    public var interval: TimeInterval
    /// Key Vault signing key (`AZURE_KEY_VAULT_AUDIT_HEAD_KEY`, e.g. `audit-head-signing`) that signs each head in addition to the chain MAC.
    public var signingKey: String?

    public init(kind: Kind, target: String, prefix: String = "audit-heads/", endpoint: String? = nil, interval: TimeInterval, signingKey: String? = nil) {
        self.kind = kind
        self.target = target
        self.prefix = prefix
        self.endpoint = endpoint
        self.interval = interval
        self.signingKey = signingKey
    }
}

/// Server settings added by WP6 (operations, key rotation, edge lock, metrics, webhooks, API keys).
public struct OperationsSettings: Sendable {
    // MARK: Edge lock (G-10) and Tier E client certificates (SEC-TR-005)
    /// Accepted values of `X-Viadere-Edge-Token` as the exact header text: `EDGE_TOKEN` then `EDGE_TOKEN_PREVIOUS`. Empty = lock off (development and tests only).
    public var edgeTokens: [Data] = []
    /// Peers (the TCP source address) of the platform's health prober; used with the absence of every proxy header. `HEALTH_PEER_NETWORKS`
    /// (comma-separated CIDRs; the Container Apps infrastructure subnet on Azure) replaces the default, which covers Fly's private network and
    /// RFC 1918 space until the Fly cutover.
    public var healthPeerNetworks: [IPNetwork] = OperationsSettings.defaultHealthPeerNetworks
    public static let defaultHealthPeerNetworks: [IPNetwork] = ["fdaa::/16", "172.16.0.0/12", "10.0.0.0/8", "127.0.0.0/8", "::1/128"].compactMap(IPNetwork.init)
    public var edgeHeader = "X-Viadere-Edge-Token"
    /// Set by Cloudflare API Shield (rule: `cf.tls_client_auth.cert_verified` and the SHA-256 fingerprint). Trusted only on an edge-locked request.
    public var clientCertFingerprintHeader = "X-Viadere-Client-Cert-Sha256"
    public var clientCertIssuerHeader = "X-Viadere-Client-Cert-Issuer-Ski"
    public var clientCertIssuerSHA256Header = "X-Viadere-Client-Cert-Issuer-Sha256"
    public var clientCertVerifiedHeader = "X-Viadere-Client-Cert-Verified"

    // MARK: Metrics (G-13)
    public var metricsToken: Data?
    /// A separate internal listener (not routed by Fly's proxy); `nil` = only the token-protected route on the main port.
    public var metricsPort: Int?
    /// Where the internal listener binds: `METRICS_BIND_HOST` (a private address of this replica), else Fly's `FLY_PRIVATE_IP` (kept until the Fly
    /// cutover), else loopback. Never a wildcard address (`0.0.0.0` / `::`), which would expose it on every interface the machine has.
    public var metricsHost = "127.0.0.1"

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
    /// Where new support tickets and appeals are announced (`SUPPORT_NOTIFY_EMAIL`); `nil` = operators watch the console.
    public var supportEmail: String?

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
            // The listener always demands the bearer token as well: the private network is not a credential (platform gate L3).
            guard ops.metricsToken != nil else { throw ServerConfigError.missing("METRICS_TOKEN (required when METRICS_PORT is set)") }
            for name in ["METRICS_BIND_HOST", "FLY_PRIVATE_IP"] {
                guard let ip = env[name], !ip.isEmpty else { continue }
                guard IPNetwork(ip) != nil, !ip.contains("/"), ip != "0.0.0.0", ip != "::" else { throw ServerConfigError.invalid("\(name) (an IP address, not a wildcard)") }
                ops.metricsHost = ip
                break
            }
        }
        if let raw = env["HEALTH_PEER_NETWORKS"], !raw.isEmpty {
            var networks: [IPNetwork] = []
            for part in raw.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) }) where !part.isEmpty {
                // A CIDR is required (a bare address would be a /32 by accident), and nothing as wide as "everything".
                guard part.contains("/"), let network = IPNetwork(part), !["0.0.0.0/0", "::/0"].contains(part) else {
                    throw ServerConfigError.invalid("HEALTH_PEER_NETWORKS (comma-separated CIDRs, e.g. 10.40.0.0/23)")
                }
                networks.append(network)
            }
            guard !networks.isEmpty else { throw ServerConfigError.invalid("HEALTH_PEER_NETWORKS") }
            ops.healthPeerNetworks = networks
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
        if let raw = env["SUPPORT_NOTIFY_EMAIL"], !raw.isEmpty {
            guard let email = DashboardAuthService.normalizeEmail(raw) else { throw ServerConfigError.invalid("SUPPORT_NOTIFY_EMAIL") }
            ops.supportEmail = email
        }
        // Database roles.
        if let url = env["DATABASE_MIGRATION_URL"], !url.isEmpty {
            guard url.hasPrefix("postgres://") || url.hasPrefix("postgresql://") else { throw ServerConfigError.invalid("DATABASE_MIGRATION_URL (postgres URL)") }
            ops.migrationDatabaseURL = url
        }
        // Audit head export: an immutable Azure Blob container (inferred from AZURE_AUDIT_BLOB_ENDPOINT) or, in development, a directory.
        let exportKind = env["AUDIT_HEAD_EXPORT"].flatMap { $0.isEmpty ? nil : $0.lowercased() } ?? (azure.auditBlobEndpoint != nil ? "azure-blob" : nil)
        if let kindRaw = exportKind {
            guard let kind = AuditHeadExportSettings.Kind(rawValue: kindRaw) else { throw ServerConfigError.invalid("AUDIT_HEAD_EXPORT (azure-blob or directory)") }
            let hours = env["AUDIT_HEAD_EXPORT_INTERVAL_HOURS"].flatMap(Double.init) ?? 6
            guard (0.01...168).contains(hours) else { throw ServerConfigError.invalid("AUDIT_HEAD_EXPORT_INTERVAL_HOURS") }
            let prefix = env["AUDIT_HEAD_EXPORT_PREFIX"].flatMap { $0.isEmpty ? nil : $0 } ?? "audit-heads/"
            guard prefix.hasSuffix("/"), ObjectNames.isValid(String(prefix.dropLast())) else { throw ServerConfigError.invalid("AUDIT_HEAD_EXPORT_PREFIX (path segments ending in /)") }
            switch kind {
            case .directory:
                if strict { throw ServerConfigError.invalid("AUDIT_HEAD_EXPORT (directory is for development only)") }
                guard let target = env["AUDIT_HEAD_EXPORT_TARGET"], !target.isEmpty, target.count <= 255 else { throw ServerConfigError.missing("AUDIT_HEAD_EXPORT_TARGET") }
                ops.auditExport = AuditHeadExportSettings(kind: .directory, target: target, prefix: prefix, interval: hours * 3600, signingKey: azure.auditHeadKey)
            case .azureBlob:
                guard let endpoint = azure.auditBlobEndpoint, let container = azure.auditBlobContainer else {
                    throw ServerConfigError.missing("AZURE_AUDIT_BLOB_ENDPOINT and AZURE_AUDIT_BLOB_CONTAINER (required for AUDIT_HEAD_EXPORT=azure-blob)")
                }
                ops.auditExport = AuditHeadExportSettings(kind: .azureBlob, target: container, prefix: prefix, endpoint: AzureBlobObjectStore.normalizedEndpoint(endpoint),
                                                          interval: hours * 3600, signingKey: azure.auditHeadKey)
            }
        }
        // Retired with the GCS/R2 sinks (WP-B2): refuse them rather than silently ignore a configuration that no longer exports anywhere.
        for name in ["AUDIT_HEAD_KMS_KEY", "GCP_WORKLOAD_IDENTITY_AUDIENCE", "GCP_SERVICE_ACCOUNT_EMAIL", "GCP_SUBJECT_TOKEN_FILE",
                     "AUDIT_HEAD_EXPORT_ACCESS_KEY_ID", "AUDIT_HEAD_EXPORT_SECRET_ACCESS_KEY", "AUDIT_HEAD_EXPORT_ENDPOINT"] where env[name].map({ !$0.isEmpty }) == true {
            throw ServerConfigError.invalid("\(name) (retired: the audit head is exported to Azure Blob Storage and signed with AZURE_KEY_VAULT_AUDIT_HEAD_KEY)")
        }
        // Production signs every exported head with the Key Vault key as well as the chain MAC: without it a compromise of the database and the chain
        // key could forge heads that nobody can tell from real ones (platform gate C2). Only the processes that export (worker, scheduled jobs, or the
        // single combined process) need it; the api never exports.
        if env["ENVIRONMENT"].flatMap(DeploymentEnvironment.parse) == .production, role != .api {
            guard ops.auditExport != nil else { throw ServerConfigError.missing("AUDIT_HEAD_EXPORT (required in production: AZURE_AUDIT_BLOB_ENDPOINT and AZURE_AUDIT_BLOB_CONTAINER)") }
            guard ops.auditExport?.signingKey != nil else { throw ServerConfigError.missing("AZURE_KEY_VAULT_AUDIT_HEAD_KEY (required in production: the Key Vault key that signs each exported audit head)") }
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
