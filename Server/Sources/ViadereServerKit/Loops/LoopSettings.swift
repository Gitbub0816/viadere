import Foundation
import ViadereCore

/// Hosted Loops configuration (WP-3.2..3.5).
public struct LoopSettings: Sendable {
    /// The `loop-publication` key (P-256): signs Loop publication manifests and nothing else (one key, one role). On Azure it is the Key Vault
    /// key `AZURE_KEY_VAULT_LOOP_PUBLICATION_KEY` (`loop-publication`, loaded at boot by `configure`); elsewhere `LOOP_PUBLICATION_SIGNING_KEY`
    /// holds its 32-byte raw scalar, base64url. In staging and production without either, publishing refuses (no ephemeral key whose
    /// manifests devices could not verify after a restart).
    public var publicationKey: any DeviceSigningKey = SoftwareP256SigningKey()
    /// Manifest lifetime; active publications are re-signed by the maintenance job before `not_after`.
    public var manifestLifetime: TimeInterval = 30 * 86_400
    /// Instances a customer may start (per account).
    public var instanceRate: RateRule = .perHour(30, burst: 10)
    /// Action submissions per account.
    public var actionRate: RateRule = .perMinute(30, burst: 15)
    /// Reports per account.
    public var reportRate: RateRule = .perHour(10, burst: 5)
    /// Inbox items kept after they are closed (then purged with their events' inputs by the retention job).
    public var inboxRetention: TimeInterval = 180 * 86_400

    public init() {}
}

/// Small helpers shared by the Loop services.
enum LoopIDs {
    /// The Loop identifier grammar (`[a-z0-9][a-z0-9_-]*`, at most 40), as in the definition schema.
    static func isValid(_ value: String) -> Bool {
        guard let first = value.utf8.first, value.utf8.count <= 40 else { return false }
        func alnum(_ c: UInt8) -> Bool { (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39) }
        guard alnum(first) else { return false }
        return value.utf8.allSatisfy { alnum($0) || $0 == 0x5F || $0 == 0x2D }
    }

    /// Parses JSON (stored canonical documents and sealed inputs).
    static func json(_ data: Data) -> JSONValue? { try? ViadereJSON.decode(JSONValue.self, from: data) }
}

extension ServerConfig {
    /// `LOOP_PUBLICATION_SIGNING_KEY` (base64url P-256 scalar) unless the Key Vault key `AZURE_KEY_VAULT_LOOP_PUBLICATION_KEY` is configured.
    mutating func applyLoopEnvironment(_ env: [String: String], production: Bool) throws {
        let raw = env["LOOP_PUBLICATION_SIGNING_KEY"].flatMap { $0.isEmpty ? nil : $0 }
        if azure.loopPublicationKey != nil {
            if raw != nil { throw ServerConfigError.invalid("LOOP_PUBLICATION_SIGNING_KEY (unset it when AZURE_KEY_VAULT_LOOP_PUBLICATION_KEY is configured)") }
        } else if let raw {
            guard let bytes = Base64URL.decode(raw), let key = try? SoftwareP256SigningKey(rawRepresentation: bytes) else {
                throw ServerConfigError.invalid("LOOP_PUBLICATION_SIGNING_KEY (base64url, 32-byte P-256 private scalar)")
            }
            loops.publicationKey = key
        } else if production || role == .worker || hasDatabase {
            // Fail closed: publishing refuses until a real key is configured (Loops stay dark; nothing else is affected).
            loops.publicationKey = UnavailableSigningKey()
        }
        if let loop = azure.loopPublicationKey.flatMap({ KMSKeyRef.parse($0)?.name }),
           [azure.kdLogKey, azure.linkDescriptorKey, azure.auditHeadKey].compactMap({ $0.flatMap { KMSKeyRef.parse($0)?.name } }).contains(loop) {
            throw ServerConfigError.invalid("AZURE_KEY_VAULT_LOOP_PUBLICATION_KEY must name its own key")
        }
        try requireDistinctLoopKey()
    }

    /// One key, one role: the publication key differs from the key-directory log key and the link-descriptor key.
    func requireDistinctLoopKey() throws {
        guard !(loops.publicationKey is UnavailableSigningKey) else { return }
        let key = loops.publicationKey.publicKey
        if key == approve.logKey.publicKey || key == approve.linkDescriptorKey.publicKey {
            throw ServerConfigError.invalid("LOOP_PUBLICATION_SIGNING_KEY must differ from KEY_DIRECTORY_LOG_KEY and LINK_DESCRIPTOR_SIGNING_KEY")
        }
    }
}
