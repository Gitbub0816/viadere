import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore

/// Upload and serving of brand images (WP-2.1, WP-2.2; ADR-0017; SECURITY.md §2.93 "Assets").
struct BrandAssetService {
    let db: any Database
    let ctx: ServerContext
    let runtime: BrandKitRuntime

    /// Human wording for each refusal (shown in the Studio; the code is what is audited and counted).
    static func message(_ rejection: BrandAssetPolicy.Rejection) -> String {
        switch rejection {
        case .tooLarge: "That file is larger than 2 MB."
        case .empty: "That file is empty."
        case .unsupportedFormat: "Upload a PNG or JPEG image."
        case .svgRefused: "SVG files are not accepted. Export your logo as a PNG."
        case .markupRefused: "That file is not an image."
        case .contentTypeMismatch: "The file's type does not match its contents. Upload a real PNG or JPEG."
        case .dimensionsTooLarge: "That image is too large (at most 8192 pixels per side and 25 megapixels)."
        case .dimensionsInvalid: "That image has no valid size."
        case .truncated: "That file is incomplete."
        case .malformed: "That file is damaged or uses an encoding we do not accept."
        case .animated: "Animated images are not accepted."
        case .trailingData: "That file contains data after the end of the image. Re-export it from your design tool."
        case .decodeFailed: "That image could not be read."
        case .outputTooLarge: "That image is too detailed for its slot even after resizing. Simplify it or use a smaller one."
        }
    }

    /// Ingests one upload for `businessId` (the console principal's organization). Returns the asset row (an identical image already
    /// uploaded to the same slot is returned as is).
    func ingest(businessId: UUID, data: Data, declaredContentType: String, slot: BrandAssetSlot, actor: AuditActor) async throws -> BrandAssetRecord {
        _ = try await BrandKitService(db: db, ctx: ctx).editableBusiness(businessId)
        guard let store = runtime.store else { throw APIError(.serviceUnavailable, .unavailable, "Image uploads are not available right now.") }
        let settings = ctx.config.brandKits
        try await ctx.limiter.enforce("brand-upload-business", key: businessId.uuidString.lowercased(), rule: settings.uploadRatePerBusiness)
        try await ctx.limiter.enforce("brand-upload-user", key: actor.id ?? "", rule: settings.uploadRatePerUser)
        let live = try await BrandAssetRecord.query(on: db).filter(\.$businessId == businessId)
            .filter(\.$state ~~ [BrandKitService.AssetState.pendingReview.rawValue, BrandKitService.AssetState.ready.rawValue]).all()
        guard live.count < settings.maxAssetsPerBusiness, live.reduce(0, { $0 + $1.bytes }) < settings.maxStoredBytesPerBusiness else {
            throw APIError(.conflict, .conflict, "You have reached the image limit. Remove unused images or ask Viadere support.")
        }
        guard await runtime.gate.acquire() else { throw APIError(.serviceUnavailable, .unavailable, "Uploads are busy. Try again in a moment.") }
        let result = BrandImagePipeline.process(data, declaredContentType: declaredContentType, slot: slot)
        await runtime.gate.release()
        let output: BrandImagePipeline.Output
        switch result {
        case .failure(let rejection):
            ctx.metrics.countBrandRejection(rejection)
            try await AuditService(db: db, ctx: ctx).record("brandkit.asset_rejected", outcome: .denied, actor: actor, businessId: BusinessID(businessId),
                                                            subjectType: "brand_asset", metadata: ["slot": slot.rawValue, "reason": rejection.rawValue, "stage": "ingestion"])
            throw APIError.validation(Self.message(rejection), details: ["file": rejection.rawValue])
        case .success(let value): output = value
        }
        if let existing = try await BrandAssetRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$sha256 == output.sha256)
            .filter(\.$slot == slot.rawValue).first() {
            if existing.state == BrandKitService.AssetState.takenDown.rawValue || existing.state == BrandKitService.AssetState.rejected.rawValue {
                throw APIError(.conflict, .conflict, "Viadere already declined this image.")
            }
            return existing
        }
        do {
            try await store.create(name: BrandKitRuntime.objectName(business: businessId, sha256: output.sha256), data: output.png, contentType: BrandAssetPolicy.outputContentType)
        } catch ObjectStoreError.alreadyExists {
            // Same name means same bytes (content addressed).
        }
        let row = BrandAssetRecord()
        row.id = UUID()
        row.businessId = businessId
        row.sha256 = output.sha256
        row.slot = slot.rawValue
        row.width = output.width
        row.height = output.height
        row.bytes = output.png.count
        row.state = BrandKitService.AssetState.pendingReview.rawValue
        row.createdBy = actor.id
        row.createdAt = ctx.now
        try await row.create(on: db)
        ctx.metrics.count(.brandAssetAccepted)
        try await AuditService(db: db, ctx: ctx).record("brandkit.asset_uploaded", actor: actor, businessId: BusinessID(businessId), subjectType: "brand_asset",
                                                        subjectId: row.id?.uuidString.lowercased(),
                                                        metadata: ["slot": slot.rawValue, "sha256": output.sha256, "width": String(output.width), "height": String(output.height),
                                                                   "bytes": String(output.png.count)])
        return row
    }

    /// The stored bytes of an asset, verified against its name (storage tampering or corruption serves nothing).
    func bytes(of asset: BrandAssetRecord) async throws -> Data? {
        guard let store = runtime.store,
              let data = try await store.read(name: BrandKitRuntime.objectName(business: asset.businessId, sha256: asset.sha256)) else { return nil }
        guard Hex.encode(Data(SHA256.hash(data: data))) == asset.sha256 else {
            ctx.logger.error("brand asset hash mismatch", metadata: ["asset": "\(asset.id?.uuidString.lowercased() ?? "")"])
            return nil
        }
        return data
    }

    /// Public serving by hash: only a `ready` asset of a business whose branding is not switched off.
    func servable(sha256: String) async throws -> Data? {
        guard ContractHash.isLowerHex64(sha256) else { return nil }
        for asset in try await BrandAssetRecord.query(on: db).filter(\.$sha256 == sha256).filter(\.$state == BrandKitService.AssetState.ready.rawValue).limit(4).all() {
            guard let business = try await BusinessRecord.find(asset.businessId, on: db), !BrandKitService.isBanned(business), business.status != .suspended,
                  !(await PlatformFlags(db: db, ctx: ctx).brandKitsStopped(businessId: asset.businessId)) else { continue }
            if let data = try await bytes(of: asset) { return data }
        }
        return nil
    }

    /// The safe response for image bytes: `image/png`, `nosniff`, a sandboxing CSP, no cookies.
    static func imageResponse(_ data: Data, cache: String) -> Response {
        let response = Response(status: .ok, body: .init(data: data))
        response.headers.replaceOrAdd(name: .contentType, value: BrandAssetPolicy.outputContentType)
        response.headers.replaceOrAdd(name: "X-Content-Type-Options", value: "nosniff")
        response.headers.replaceOrAdd(name: "Content-Security-Policy", value: "default-src 'none'; sandbox")
        response.headers.replaceOrAdd(name: "Content-Disposition", value: "inline")
        response.headers.replaceOrAdd(name: .cacheControl, value: cache)
        return response
    }
}
