import Fluent
import Foundation
import NIOCore
import Vapor
import ViadereCore

/// Process-wide Brand Kit collaborators: the private asset store and the ingestion gate. Built once by `configure`.
final class BrandKitRuntime: @unchecked Sendable {
    /// `nil` = no asset store configured (uploads answer 503; manifests still work without assets).
    var store: (any ObjectStore)?
    let gate: IngestGate

    init(store: (any ObjectStore)? = nil, maxConcurrent: Int = 2) {
        self.store = store
        self.gate = IngestGate(limit: maxConcurrent)
    }

    /// `brand/{business}/{sha256}.png`: the only object name an asset has.
    static func objectName(business: UUID, sha256: String) -> String { "brand/\(business.uuidString.lowercased())/\(sha256).png" }
}

/// Bounds how many images one process decodes at once. A caller that cannot get a slot within `wait` is refused (`503`), so a burst of
/// uploads queues briefly instead of exhausting memory.
actor IngestGate {
    private let limit: Int
    private var running = 0

    init(limit: Int) { self.limit = max(1, limit) }

    func acquire() -> Bool {
        guard running < limit else { return false }
        running += 1
        return true
    }

    func release() { running = max(0, running - 1) }
}

/// Development and tests: objects in memory, create-only like every store.
final class MemoryObjectStore: ObjectStore, @unchecked Sendable {
    private let lock = NSLock()
    private var objects: [String: (Data, String)] = [:]

    init() {}

    func create(name: String, data: Data, contentType: String) async throws {
        guard ObjectNames.isValid(name) else { throw ObjectStoreError.invalidName }
        try lock.withLock {
            guard objects[name] == nil else { throw ObjectStoreError.alreadyExists }
            objects[name] = (data, contentType)
        }
    }

    func read(name: String) async throws -> Data? {
        guard ObjectNames.isValid(name) else { throw ObjectStoreError.invalidName }
        return lock.withLock { objects[name]?.0 }
    }

    var names: [String] { lock.withLock { Array(objects.keys) } }
}

private struct BrandKitRuntimeKey: StorageKey { typealias Value = BrandKitRuntime }

extension Application {
    var brandKits: BrandKitRuntime {
        get {
            if let value = storage[BrandKitRuntimeKey.self] { return value }
            let value = BrandKitRuntime()
            storage[BrandKitRuntimeKey.self] = value
            return value
        }
        set { storage[BrandKitRuntimeKey.self] = newValue }
    }
}

extension Request {
    var brandKits: BrandKitRuntime { application.brandKits }
}

enum BrandKitRegistration {
    /// Resolves the Key Vault `brand-manifest` key (its public key is fetched now, so a missing key fails the boot) and checks that it is
    /// not the key of another role.
    static func resolveSigningKey(config: inout ServerConfig, kms: (any KeyManagementService)?) async throws {
        if let ref = config.brandKits.keyVaultManifestKey {
            guard let kms else { throw ServerConfigError.missing("AZURE_KEY_VAULT_URL (for AZURE_KEY_VAULT_BRAND_MANIFEST_KEY)") }
            config.brandKits.manifestKey = try await KMSSigningKey.load(kms: kms, keyRef: ref)
        }
        // A worker never signs manifests (only the api serves them): its stand-in refuses.
        if config.role == .worker, config.brandKits.manifestKey != nil { config.brandKits.manifestKey = UnavailableSigningKey() }
        if let key = config.brandKits.manifestKey, config.role != .worker,
           key.publicKey == config.approve.logKey.publicKey || key.publicKey == config.approve.linkDescriptorKey.publicKey {
            throw ServerConfigError.invalid("BRAND_MANIFEST_SIGNING_KEY (one key, one role: it must differ from the log and link-descriptor keys)")
        }
    }

    /// The asset store: the override (tests), the Azure container, a development directory, memory outside staging and production, else none.
    static func store(config: ServerConfig, override: (any ObjectStore)?, tokens: (any AccessTokenSource)?, http: any OutboundHTTP,
                      now: @escaping @Sendable () -> Date) throws -> (any ObjectStore)? {
        if let override { return override }
        let settings = config.brandKits
        if let endpoint = settings.blobEndpoint, let container = settings.blobContainer {
            guard let tokens else { throw ServerConfigError.missing("a managed identity (for AZURE_BRAND_BLOB_ENDPOINT)") }
            return try AzureBlobObjectStore(endpoint: endpoint, container: container, tokens: tokens, http: http, now: now)
        }
        if let directory = settings.assetDirectory { return DirectoryObjectStore(directory: directory) }
        return config.isStrict ? nil : MemoryObjectStore()
    }
}

/// Collects a request body up to `max` bytes **before** the dashboard authentication middleware reads the CSRF field from it (an upload is
/// larger than one network read, so it would otherwise still be streaming). A declared length above `max` is refused before anything is read.
struct CollectBodyMiddleware: AsyncMiddleware {
    let max: Int

    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        if let length = request.headers.first(name: .contentLength).flatMap(Int.init), length > max {
            throw APIError(.payloadTooLarge, .badRequest, "That file is too large.")
        }
        if request.body.data == nil {
            _ = try await request.body.collect(max: max).get()
        }
        return try await next.respond(to: request)
    }
}


/// `ViadereServer brand-manifest-key` prints the **public** `brand-manifest` key and its key id as configured (the Key Vault key on Azure,
/// else `BRAND_MANIFEST_SIGNING_KEY`): the value the app pins (`VIADERE_BRAND_MANIFEST_KEYS`) to verify brand manifests. Never a private key.
public struct BrandManifestKeyCommand: AsyncCommand {
    public struct Signature: CommandSignature { public init() {} }
    public let signature = Signature()
    public let help = "Prints the public brand-manifest key (for the app build)."
    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        guard let key = context.application.ctx.config.brandKits.manifestKey, !(key is UnavailableSigningKey) else {
            context.console.print("brand kits are off: no brand-manifest key is configured")
            return
        }
        context.console.print("kid=\(KeyIdentifier.make(try key.publicKey.signingKey()))")
        context.console.print("public_key=\(key.publicKey.base64URL)")
    }
}
