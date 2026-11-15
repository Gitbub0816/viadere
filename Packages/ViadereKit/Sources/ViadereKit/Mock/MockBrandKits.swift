import Crypto
import Foundation
import ViadereCore

/// An in-memory brand server for previews, the demo world and tests: serves signed manifests with `ETag` / `304`, and asset bytes by hash.
public actor MockBrandKitAPI: BrandKitAPI, BrandAssetFetcher {
    /// The software `brand-manifest` key of the mock world (never a real key).
    public static let signingKey = try! SoftwareP256SigningKey(rawRepresentation: Data(SHA256.hash(data: Data("viadere-mock-brand-manifest".utf8))))
    public static var kid: String { (try? KeyIdentifier.make(p256X963: signingKey.publicKey.x963)) ?? "mock-brand-manifest" }
    public static var pinnedKey: PinnedManifestKey { PinnedManifestKey(kid: kid, publicKey: signingKey.publicKey) }
    public static let assetHost = "assets.viadere-mock.test"

    private var responses: [BusinessID: (BrandManifestResponse, String)] = [:]
    private var blobs: [String: Data] = [:]
    public private(set) var manifestCalls = 0
    public private(set) var assetCalls = 0
    public private(set) var lastIfNoneMatch: String??
    private var failing = false

    public init() {}

    public func setFailing(_ value: Bool) { failing = value }

    /// Serves `response` for its business with the given `ETag`.
    public func serve(_ response: BrandManifestResponse, etag: String = "\"\(UUID().uuidString)\"") { responses[response.businessId] = (response, etag) }

    public func serveAsset(_ data: Data, sha256: String) { blobs[sha256] = data }

    public func stopServing(_ business: BusinessID) { responses[business] = nil }

    public func brandManifest(business: BusinessID, ifNoneMatch: String?) async throws -> BrandManifestFetch {
        manifestCalls += 1
        lastIfNoneMatch = .some(ifNoneMatch)
        if failing { throw APIError.transport("offline") }
        guard let (response, etag) = responses[business] else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        if let ifNoneMatch, ifNoneMatch == etag { return .notModified }
        return .fetched(response, etag: etag)
    }

    public func fetch(_ url: URL, maxBytes: Int) async throws -> Data {
        assetCalls += 1
        if failing { throw APIError.transport("offline") }
        let name = url.deletingPathExtension().lastPathComponent
        guard url.host == Self.assetHost, let data = blobs[name] else { throw BrandKitError.assetStatus(404) }
        guard data.count <= maxBytes else { throw BrandKitError.assetTooLarge }
        return data
    }

    /// A signed branded response for `manifest` (signed with `key`, the mock key by default).
    public static func response(_ manifest: BrandManifest, key: SoftwareP256SigningKey = MockBrandKitAPI.signingKey, seed: Data? = nil,
                                pins: [BrandKitPin] = [], assetHost: String? = MockBrandKitAPI.assetHost) async throws -> BrandManifestResponse {
        BrandManifestResponse(businessId: manifest.businessId, status: .branded, manifest: try await manifest.sign(with: key),
                              manifestHash: try manifest.manifestHash(), selectionSeed: seed.map(Base64URL.encode), pins: pins, assetHost: assetHost)
    }

    /// A tiny valid PNG signature followed by `payload` (the device checks signature, size and hash, not pixels).
    public static func pngBytes(_ payload: String) -> Data { Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + Data(payload.utf8) }

    public static func ref(for data: Data, width: Int = 256, height: Int = 256) -> BrandAssetRef {
        BrandAssetRef(sha256: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(), width: width, height: height, bytes: data.count)
    }
}
