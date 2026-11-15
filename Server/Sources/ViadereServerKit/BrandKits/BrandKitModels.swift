import Fluent
import Foundation

/// A re-encoded, content-addressed brand image (WP-2.2). The bytes live in the private asset container at `brand/{business}/{sha256}.png`;
/// this row records what they are and whether they may be served. Only `ready` assets are ever served or placed in a manifest.
final class BrandAssetRecord: Model, @unchecked Sendable {
    static let schema = "brand_assets"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "sha256") var sha256: String
    @Field(key: "slot") var slot: String
    @Field(key: "width") var width: Int
    @Field(key: "height") var height: Int
    @Field(key: "bytes") var bytes: Int
    /// `pending_review` → `ready` | `rejected`; `ready` → `taken_down`.
    @Field(key: "state") var state: String
    @OptionalField(key: "review_note") var reviewNote: String?
    @OptionalField(key: "created_by") var createdBy: String?
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "reviewed_by") var reviewedBy: String?
    @OptionalField(key: "reviewed_at") var reviewedAt: Date?
    init() {}
}

/// A named Brand Kit of a business (WP-2.3). The editable draft (`tokens_json`, `frame_id`, `assets_json`) and the last **approved** snapshot
/// (`approved_json`, the exact kit object a manifest carries) are kept apart, so an edit under review never changes what customers see.
final class BrandKitRecord: Model, @unchecked Sendable {
    static let schema = "brand_kits"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    /// The manifest `kit_id` (`ContractIdentifier`), unique per business.
    @Field(key: "kit_key") var kitKey: String
    @Field(key: "name") var name: String
    /// Increments on every saved edit.
    @Field(key: "version") var version: Int
    /// `pending_review`, `approved`, `rejected`, `taken_down`.
    @Field(key: "status") var status: String
    @Field(key: "tokens_json") var tokensJSON: String
    @OptionalField(key: "frame_id") var frameId: String?
    /// `{"logo":"<asset uuid>",...}`.
    @Field(key: "assets_json") var assetsJSON: String
    @OptionalField(key: "approved_json") var approvedJSON: String?
    @OptionalField(key: "approved_version") var approvedVersion: Int?
    @OptionalField(key: "review_note") var reviewNote: String?
    @OptionalField(key: "created_by") var createdBy: String?
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "updated_at") var updatedAt: Date
    @OptionalField(key: "reviewed_by") var reviewedBy: String?
    @OptionalField(key: "reviewed_at") var reviewedAt: Date?
    init() {}
}

/// The business's kit schedule (one row per business): canonical JSON of `BrandSchedule`, validated on save.
final class BrandKitScheduleRecord: Model, @unchecked Sendable {
    static let schema = "brand_kit_schedules"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "schedule_json") var scheduleJSON: String
    @OptionalField(key: "updated_by") var updatedBy: String?
    @Field(key: "updated_at") var updatedAt: Date
    init() {}
}

/// Every signed manifest version of a business (append-only by version). The newest row is served while unexpired; a `withdrawn` row means
/// "serve neutral" (no kit is approved any more, or every kit was taken down).
final class BrandManifestRecord: Model, @unchecked Sendable {
    static let schema = "brand_manifests"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "version") var version: Int
    /// `active` or `withdrawn`.
    @Field(key: "status") var status: String
    @OptionalField(key: "manifest_json") var manifestJSON: String?
    @OptionalField(key: "jws") var jws: String?
    @OptionalField(key: "manifest_hash") var manifestHash: String?
    @OptionalField(key: "kid") var kid: String?
    @OptionalField(key: "issued_at") var issuedAt: Date?
    @OptionalField(key: "not_after") var notAfter: Date?
    @Field(key: "created_at") var createdAt: Date
    init() {}
}

/// The kit pinned to an interaction at creation (WP-2.4). A narrow view of `interactions` so Brand Kit code reads and writes only this column.
final class InteractionBrandPinRecord: Model, @unchecked Sendable {
    static let schema = "interactions"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "status") var status: String
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "brand_kit_pin") var brandKitPin: String?
    init() {}
}
