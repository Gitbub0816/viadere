import Crypto
import Foundation
import ViadereCore

/// The result of a conditional brand-manifest fetch.
public enum BrandManifestFetch: Sendable, Equatable {
    /// `304`: the cached response (sent as `If-None-Match`) is still current.
    case notModified
    case fetched(BrandManifestResponse, etag: String?)
}

/// `GET /v1/businesses/{businessId}/brand` (WP-2.3). Separate from `ViadereAPI` so extensions build without it.
public protocol BrandKitAPI: Sendable {
    func brandManifest(business: BusinessID, ifNoneMatch: String?) async throws -> BrandManifestFetch
}

/// Downloads one content-addressed brand asset (`https://{assetHost}/b/{sha256}.png`). No credentials, no cookies: the asset host is a
/// public, cookie-less origin, and the bytes are trusted only after `BrandKitStore` checked their SHA-256.
public protocol BrandAssetFetcher: Sendable {
    func fetch(_ url: URL, maxBytes: Int) async throws -> Data
}

public enum BrandKitError: Error, Sendable, Equatable {
    case assetTooLarge
    case assetStatus(Int)
    case timedOut
}

/// `BrandKitAPI` through the app's signed `APIClient`.
public struct LiveBrandKitAPI: BrandKitAPI {
    let client: APIClient
    public init(client: APIClient) { self.client = client }

    public func brandManifest(business: BusinessID, ifNoneMatch: String?) async throws -> BrandManifestFetch {
        switch try await client.conditional(APIRoutes.businessBrandGet, params: ["businessId": business.description], ifNoneMatch: ifNoneMatch) {
        case .notModified: return .notModified
        case .fresh(let body, let etag): return .fetched(body, etag: etag)
        }
    }
}

/// Plain `GET` over the app's transport (certificate pinning applies only to the API host; the asset host relies on the hash check).
public struct TransportBrandAssetFetcher: BrandAssetFetcher {
    let transport: any HTTPTransport
    public init(transport: any HTTPTransport) { self.transport = transport }

    public func fetch(_ url: URL, maxBytes: Int) async throws -> Data {
        let response = try await transport.send(HTTPRequest(method: .GET, url: url, headers: ["Accept": "image/png"]))
        guard response.status == 200 else { throw BrandKitError.assetStatus(response.status) }
        guard response.body.count <= maxBytes else { throw BrandKitError.assetTooLarge }
        return response.body
    }
}

/// Byte checks for a downloaded or cached asset: exact size, PNG signature, SHA-256 equal to the reference (constant-time compare).
public enum BrandAssetVerifier {
    static let pngSignature: [UInt8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]

    public static func isValid(_ data: Data, for ref: BrandAssetRef) -> Bool {
        guard ContractHash.isLowerHex64(ref.sha256), data.count == ref.bytes, data.starts(with: pngSignature) else { return false }
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        return ConstantTime.equals(digest, ref.sha256)
    }
}
