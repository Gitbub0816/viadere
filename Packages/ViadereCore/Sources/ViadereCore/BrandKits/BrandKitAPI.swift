import Foundation

/// The kit pinned to one of the caller's active interactions with the business (plan section 4.6, WP-2.4): chosen by the server when the
/// interaction was created, so its appearance never changes mid-flow. `kitId` names a kit of the manifest; if the manifest no longer
/// contains it the device renders neutral (never another kit, `BrandKitSelector`).
public struct BrandKitPin: Codable, Sendable, Hashable {
    /// Lowercase UUID of the interaction.
    public var interactionId: String
    public var kitId: String

    public init(interactionId: String, kitId: String) {
        self.interactionId = interactionId
        self.kitId = kitId
    }
}

/// `GET /v1/businesses/{businessId}/brand` (WP-2.3; SECURITY.md §2.93 "Serving"). Only for a verified business the caller is actively
/// connected to; any other business answers `404` (the same answer as one that does not exist).
///
/// `status` is `neutral` whenever Viadere serves no branding for the business: no published kit, the `brand_kits` kill switch (global or for
/// this business), a banned category, or no signing key. The reason is deliberately not given. A device that gets `neutral`, fails to
/// verify `manifest`, or cannot reach the server renders Viadere's neutral style at once; nothing waits for branding (spec B4.4).
public struct BrandManifestResponse: Codable, Sendable, Hashable {
    public enum Status: String, Codable, Sendable, Hashable {
        case branded, neutral
    }

    public var businessId: BusinessID
    public var status: Status
    /// Compact JWS (`typ` `viadere-brand-manifest+jws`), verified with the pinned `brand-manifest` keys (`BrandManifest.verify`). `nil` when neutral.
    public var manifest: String?
    /// `sha256:<hex>` of the canonical payload, also the response `ETag`. `nil` when neutral.
    public var manifestHash: String?
    /// Base64url HMAC seed for the random pool (`BrandSelectionSeed`), per (customer, business). `nil` when neutral or not configured: the
    /// pool is then skipped and selection falls through to the default kit.
    public var selectionSeed: String?
    /// Kits pinned to the caller's active interactions with this business.
    public var pins: [BrandKitPin]
    /// The dedicated asset host (`ASSET_DOMAIN`); assets are `https://{assetHost}/b/{sha256}.png` (`BrandAssetRef.url(assetHost:)`).
    public var assetHost: String?

    public init(businessId: BusinessID, status: Status, manifest: String? = nil, manifestHash: String? = nil, selectionSeed: String? = nil,
                pins: [BrandKitPin] = [], assetHost: String? = nil) {
        self.businessId = businessId
        self.status = status
        self.manifest = manifest
        self.manifestHash = manifestHash
        self.selectionSeed = selectionSeed
        self.pins = pins
        self.assetHost = assetHost
    }

    /// The neutral answer.
    public static func neutral(_ business: BusinessID) -> BrandManifestResponse { BrandManifestResponse(businessId: business, status: .neutral) }

    /// Device-side: the selection seed bytes, if present and well formed (32 bytes).
    public var selectionSeedData: Data? {
        guard let selectionSeed, let data = Base64URL.decode(selectionSeed), data.count == 32 else { return nil }
        return data
    }
}

extension APIRoutes {
    /// The signed brand manifest of a connected business, with the caller's random-pool seed and interaction pins. Honors `If-None-Match`
    /// (the manifest hash): `304` when unchanged.
    public static let businessBrandGet = Endpoint<EmptyBody, BrandManifestResponse>(
        "businesses.brand.get", .GET, "/v1/businesses/{businessId}/brand", auth: .deviceSignedBearer)

    /// Appended to `APIRoutes.all`.
    public static let brandKitEndpoints: [AnyEndpoint] = [businessBrandGet.descriptor]
}
