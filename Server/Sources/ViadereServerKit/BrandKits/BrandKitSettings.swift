@preconcurrency import Crypto
import Foundation
import ViadereCore

/// Brand Kits configuration (WP-2.1; ADR-0017; SECURITY.md §2.93). Everything is optional: without a signing key or an asset store, Brand
/// Kits are simply unavailable (every business is served neutral) and nothing else changes (INV-1).
///
/// * `ASSET_DOMAIN`: the dedicated, cookie-less asset host (`https://{ASSET_DOMAIN}/b/{sha256}.png`), configured like `LINK_DOMAIN`. It
///   must differ from every other host the server answers for, and in staging and production may not be one of them or a subdomain of one.
/// * The `brand-manifest` signing key (P-256, signs brand manifests only): the Key Vault key `AZURE_KEY_VAULT_BRAND_MANIFEST_KEY` on Azure
///   (loaded at boot as a `KMSSigningKey`), else the environment secret `BRAND_MANIFEST_SIGNING_KEY` (base64url raw scalar). Development
///   and tests use an ephemeral key; staging and production without either have Brand Kits off.
/// * `BRAND_SELECTION_KEY`: 32-byte HMAC key of the random-pool seed (`BrandSelectionSeed`). Without it no seed is served and the pool is
///   skipped.
/// * Asset store: `AZURE_BRAND_BLOB_ENDPOINT` + `AZURE_BRAND_BLOB_CONTAINER` (private container, managed identity), or
///   `BRAND_ASSET_DIRECTORY` (development only).
public struct BrandKitSettings: Sendable {
    public var assetDomain: LinkDomain?
    /// Key Vault reference of the `brand-manifest` key (`AZURE_KEY_VAULT_BRAND_MANIFEST_KEY`); resolved by `configure`.
    public var keyVaultManifestKey: String?
    /// The signing key in use; `nil` = Brand Kits unavailable.
    public var manifestKey: (any DeviceSigningKey)?
    public var selectionKey: SymmetricKey?
    public var blobEndpoint: String?
    public var blobContainer: String?
    public var assetDirectory: String?

    /// How long a signed manifest is valid (≤ `BrandManifest.maxLifetime`), and when the server re-issues it.
    public var manifestLifetime: Int64 = 14 * 86400
    public var reissueBefore: Int64 = 7 * 86400

    /// Per-business limits (WP-2.8; plan O4 initial values).
    public var maxKitsPerBusiness = BrandManifest.maxKits
    public var maxAssetsPerBusiness = 40
    public var maxStoredBytesPerBusiness = 24 * 1024 * 1024
    /// Uploads per business, and per console user.
    public var uploadRatePerBusiness: RateRule = .perHour(20, burst: 10)
    public var uploadRatePerUser: RateRule = .perHour(20, burst: 10)
    /// Manifest fetches per account.
    public var fetchRate: RateRule = .perMinute(30, burst: 30)
    /// Images decoded at the same time by one process (decoding is CPU- and memory-bound: up to 25 MP × 4 bytes each).
    public var maxConcurrentIngestions = 2

    public init() {}

    /// Whether manifests can be signed at all.
    public var signingAvailable: Bool { manifestKey != nil }
}

extension ServerConfig {
    /// `ASSET_DOMAIN`, `AZURE_KEY_VAULT_BRAND_MANIFEST_KEY`, `BRAND_MANIFEST_SIGNING_KEY`, `BRAND_SELECTION_KEY`, `AZURE_BRAND_BLOB_ENDPOINT`,
    /// `AZURE_BRAND_BLOB_CONTAINER`, `BRAND_ASSET_DIRECTORY`.
    mutating func applyBrandKitEnvironment(_ env: [String: String], production: Bool) throws {
        func value(_ name: String) -> String? { env[name].flatMap { $0.isEmpty ? nil : $0 } }
        var settings = BrandKitSettings()
        if let raw = value("ASSET_DOMAIN") {
            guard let domain = LinkDomain(raw) else { throw ServerConfigError.invalid("ASSET_DOMAIN (a DNS name such as assets.viadere-cdn.example, no scheme or path)") }
            settings.assetDomain = domain
        }
        try validateAssetDomain(settings.assetDomain, strict: production)

        if let raw = value("AZURE_KEY_VAULT_BRAND_MANIFEST_KEY") {
            guard KMSKeyRef.parse(raw) != nil else { throw ServerConfigError.invalid("AZURE_KEY_VAULT_BRAND_MANIFEST_KEY (a key name, optionally /version)") }
            guard azure.keyVaultURL != nil else { throw ServerConfigError.missing("AZURE_KEY_VAULT_URL (required with AZURE_KEY_VAULT_BRAND_MANIFEST_KEY)") }
            guard azure.clientId != nil, value("IDENTITY_ENDPOINT") != nil, value("IDENTITY_HEADER") != nil else {
                throw ServerConfigError.missing("AZURE_CLIENT_ID with a managed identity (for AZURE_KEY_VAULT_BRAND_MANIFEST_KEY)")
            }
            if value("BRAND_MANIFEST_SIGNING_KEY") != nil {
                throw ServerConfigError.invalid("BRAND_MANIFEST_SIGNING_KEY (unset it when AZURE_KEY_VAULT_BRAND_MANIFEST_KEY is configured)")
            }
            let others = [azure.kdLogKey, azure.linkDescriptorKey, azure.auditHeadKey, azure.kekKey].compactMap { $0.flatMap { KMSKeyRef.parse($0)?.name } }
            if others.contains(KMSKeyRef.parse(raw)!.name) {
                throw ServerConfigError.invalid("AZURE_KEY_VAULT_BRAND_MANIFEST_KEY must name its own key (one key, one role)")
            }
            settings.keyVaultManifestKey = raw
        } else if let raw = value("BRAND_MANIFEST_SIGNING_KEY") {
            guard let bytes = Base64URL.decode(raw), let key = try? SoftwareP256SigningKey(rawRepresentation: bytes) else {
                throw ServerConfigError.invalid("BRAND_MANIFEST_SIGNING_KEY (base64url, 32-byte P-256 private scalar)")
            }
            settings.manifestKey = key
        } else if !production {
            // Development and tests: an ephemeral key (manifests signed before a restart stop verifying, which only means neutral styling).
            settings.manifestKey = SoftwareP256SigningKey()
        }

        if let raw = value("BRAND_SELECTION_KEY") {
            guard let bytes = Base64URL.decode(raw), bytes.count == 32 else { throw ServerConfigError.invalid("BRAND_SELECTION_KEY (base64url, 32 bytes)") }
            settings.selectionKey = SymmetricKey(data: bytes)
        } else if !production {
            settings.selectionKey = SymmetricKey(size: .bits256)
        }

        if let raw = value("AZURE_BRAND_BLOB_ENDPOINT") {
            guard AzureBlobObjectStore.normalizedEndpoint(raw) != nil else { throw ServerConfigError.invalid("AZURE_BRAND_BLOB_ENDPOINT (https://<account>.blob.core.windows.net/)") }
            guard let container = value("AZURE_BRAND_BLOB_CONTAINER"), AzureBlobObjectStore.isContainerName(container) else {
                throw ServerConfigError.invalid("AZURE_BRAND_BLOB_CONTAINER (a container name; required with AZURE_BRAND_BLOB_ENDPOINT)")
            }
            guard azure.clientId != nil, value("IDENTITY_ENDPOINT") != nil, value("IDENTITY_HEADER") != nil else {
                throw ServerConfigError.missing("AZURE_CLIENT_ID with a managed identity (for AZURE_BRAND_BLOB_ENDPOINT)")
            }
            if let audit = azure.auditBlobEndpoint, let auditContainer = azure.auditBlobContainer,
               AzureBlobObjectStore.normalizedEndpoint(audit) == AzureBlobObjectStore.normalizedEndpoint(raw), auditContainer == container {
                throw ServerConfigError.invalid("AZURE_BRAND_BLOB_CONTAINER (must not be the audit-head container)")
            }
            settings.blobEndpoint = raw
            settings.blobContainer = container
        }
        if let directory = value("BRAND_ASSET_DIRECTORY") {
            guard !production else { throw ServerConfigError.invalid("BRAND_ASSET_DIRECTORY (development only; use AZURE_BRAND_BLOB_ENDPOINT)") }
            settings.assetDirectory = directory
        }
        brandKits = settings
    }

    /// The asset host is a host of its own: never the API, link, passkey or console host, and in staging and production never one of their
    /// subdomains either (a parent-domain cookie must not reach it).
    func validateAssetDomain(_ domain: LinkDomain?, strict: Bool) throws {
        guard let domain else { return }
        var hosts: Set<String> = [relyingPartyID.lowercased(), linkDomain.host]
        for origin in [publicBaseURL, relyingPartyOrigin, dashboardOrigin].compactMap({ $0 }) {
            if let host = URL(string: origin)?.host?.lowercased() { hosts.insert(host) }
        }
        for host in hosts {
            if domain.host == host { throw ServerConfigError.invalid("ASSET_DOMAIN (must be a host of its own, not \(host))") }
            if strict, domain.host.hasSuffix("." + host) { throw ServerConfigError.invalid("ASSET_DOMAIN (must not be a subdomain of \(host))") }
        }
    }
}
