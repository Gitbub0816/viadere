import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore

/// Brand Kits: kits, schedules, review, manifest building and signing, and the consumer view (WP-2.3, WP-2.4, WP-2.8; SECURITY.md §2.93).
///
/// Every query is scoped by the business taken from the authenticated principal (console) or from the path **after** the caller's
/// relationship has been checked (consumer). Nothing a business supplies reaches a device except through `BrandManifest`'s closed schema,
/// and only after a Viadere operator approved the kit and its images.
struct BrandKitService {
    let db: any Database
    let ctx: ServerContext

    enum KitStatus: String { case pendingReview = "pending_review", approved, rejected, takenDown = "taken_down" }
    enum AssetState: String { case pendingReview = "pending_review", ready, rejected, takenDown = "taken_down" }

    // MARK: Eligibility

    /// Healthcare and its synonyms are banned platform-wide (FX-4): such a business gets no Brand Kit features at all.
    static func isBanned(_ business: BusinessRecord) -> Bool { LoopCategoryPolicy.bannedPlatformWide.contains(business.category.lowercased()) }

    /// The business a console member may edit kits for: not banned, not suspended.
    func editableBusiness(_ businessId: UUID) async throws -> BusinessRecord {
        guard let business = try await BusinessRecord.find(businessId, on: db) else { throw APIError.notFound }
        if Self.isBanned(business) { throw APIError(.forbidden, .forbidden, "Brand Kits are not available for this business category.") }
        if business.status == .suspended { throw APIError(.forbidden, .forbidden, "This organization is suspended.") }
        return business
    }

    // MARK: Kits

    struct KitDraft {
        var kitKey: String
        var name: String
        var tokens: BrandTokens
        var frameId: String?
        var assets: [BrandAssetSlot: UUID]
    }

    func kits(businessId: UUID) async throws -> [BrandKitRecord] {
        try await BrandKitRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$createdAt, .ascending).all()
    }

    func kit(businessId: UUID, id: UUID) async throws -> BrandKitRecord {
        guard let kit = try await BrandKitRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        return kit
    }

    /// The asset references of a draft, resolved for this business only (a foreign or missing asset id is a validation error, never a
    /// cross-tenant read).
    func resolveAssets(businessId: UUID, _ ids: [BrandAssetSlot: UUID], allowPending: Bool) async throws -> [BrandAssetSlot: BrandAssetRef] {
        var refs: [BrandAssetSlot: BrandAssetRef] = [:]
        for (slot, id) in ids {
            guard let asset = try await BrandAssetRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first(),
                  asset.slot == slot.rawValue,
                  asset.state == AssetState.ready.rawValue || (allowPending && asset.state == AssetState.pendingReview.rawValue) else {
                throw APIError.validation("Choose one of your uploaded images for the \(slot.rawValue).", details: ["assets.\(slot.rawValue)": "invalid"])
            }
            refs[slot] = BrandAssetRef(sha256: asset.sha256, width: asset.width, height: asset.height, bytes: asset.bytes)
        }
        return refs
    }

    /// Creates or edits a kit. Every save is a new version that waits for operator review; the last approved version keeps serving meanwhile.
    @discardableResult
    func save(businessId: UUID, kitId: UUID?, draft: KitDraft, actor: AuditActor) async throws -> BrandKitRecord {
        _ = try await editableBusiness(businessId)
        let refs = try await resolveAssets(businessId: businessId, draft.assets, allowPending: true)
        let candidate = BrandKit(kitId: draft.kitKey, name: draft.name.trimmingCharacters(in: .whitespaces), tokens: draft.tokens, frameId: draft.frameId, assets: refs)
        let issues = candidate.validationIssues()
        guard issues.isEmpty else {
            throw APIError.validation("Check the highlighted fields.", details: Dictionary(issues.map { ($0.path, $0.code) }, uniquingKeysWith: { a, _ in a }))
        }
        let now = ctx.now
        let assetsJSON = String(decoding: try JSONEncoder.sortedKeys.encode(Dictionary(uniqueKeysWithValues: draft.assets.map { ($0.key.rawValue, $0.value.uuidString.lowercased()) })), as: UTF8.self)
        let tokensJSON = String(decoding: try CanonicalJSON.serialize(draft.tokens.jsonValue), as: UTF8.self)
        let record: BrandKitRecord
        if let kitId {
            record = try await kit(businessId: businessId, id: kitId)
            guard record.kitKey == draft.kitKey else { throw APIError.validation("A kit's identifier cannot change.", details: ["kit_id": "immutable"]) }
            record.version += 1
        } else {
            let count = try await BrandKitRecord.query(on: db).filter(\.$businessId == businessId).count()
            guard count < ctx.config.brandKits.maxKitsPerBusiness else {
                throw APIError(.conflict, .conflict, "You already have \(ctx.config.brandKits.maxKitsPerBusiness) kits. Delete one first.")
            }
            guard try await BrandKitRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$kitKey == draft.kitKey).first() == nil else {
                throw APIError.validation("You already have a kit with that identifier.", details: ["kit_id": "duplicate_id"])
            }
            record = BrandKitRecord()
            record.id = UUID()
            record.businessId = businessId
            record.kitKey = draft.kitKey
            record.version = 1
            record.createdBy = actor.id
            record.createdAt = now
        }
        record.name = candidate.name
        record.tokensJSON = tokensJSON
        record.frameId = draft.frameId
        record.assetsJSON = assetsJSON
        record.status = KitStatus.pendingReview.rawValue
        record.reviewNote = nil
        record.updatedAt = now
        try await record.save(on: db)
        try await AuditService(db: db, ctx: ctx).record("brandkit.kit_saved", actor: actor, businessId: BusinessID(businessId), subjectType: "brand_kit",
                                                        subjectId: record.id?.uuidString.lowercased(),
                                                        metadata: ["kit": record.kitKey, "version": String(record.version)])
        return record
    }

    func delete(businessId: UUID, kitId: UUID, actor: AuditActor) async throws {
        let record = try await kit(businessId: businessId, id: kitId)
        try await record.delete(on: db)
        try await AuditService(db: db, ctx: ctx).record("brandkit.kit_deleted", actor: actor, businessId: BusinessID(businessId), subjectType: "brand_kit",
                                                        subjectId: kitId.uuidString.lowercased(), metadata: ["kit": record.kitKey])
        try await republish(businessId: businessId, actor: actor)
    }

    /// The draft of a stored kit as Core values.
    static func draftKit(_ record: BrandKitRecord, refs: [BrandAssetSlot: BrandAssetRef] = [:]) -> BrandKit? {
        guard let tokensValue = JSONValue.parseContract(Data(record.tokensJSON.utf8)), let tokens = BrandTokens.parse(tokensValue).tokens else { return nil }
        return BrandKit(kitId: record.kitKey, name: record.name, tokens: tokens, frameId: record.frameId, assets: refs)
    }

    static func draftAssetIds(_ record: BrandKitRecord) -> [BrandAssetSlot: UUID] {
        guard let map = try? JSONDecoder().decode([String: String].self, from: Data(record.assetsJSON.utf8)) else { return [:] }
        var out: [BrandAssetSlot: UUID] = [:]
        for (k, v) in map { if let slot = BrandAssetSlot(rawValue: k), let id = UUID(uuidString: v) { out[slot] = id } }
        return out
    }

    /// The approved snapshot (what a manifest carries), if any.
    static func approvedKit(_ record: BrandKitRecord) -> BrandKit? {
        guard let json = record.approvedJSON, let value = JSONValue.parseContract(Data(json.utf8)) else { return nil }
        let wrapper: JSONValue = .object(["v": .integer(1), "business_id": .string(BusinessID(record.businessId).description), "version": .integer(1),
                                          "kits": .array([value]), "schedule": BrandSchedule(timezone: "UTC").jsonValue,
                                          "issued_at": .integer(0), "not_after": .integer(1), "kid": .string("k")])
        return BrandManifest.parse(wrapper).manifest?.kits.first
    }

    // MARK: Schedule

    func schedule(businessId: UUID) async throws -> BrandSchedule? {
        guard let row = try await BrandKitScheduleRecord.query(on: db).filter(\.$businessId == businessId).first(),
              let value = JSONValue.parseContract(Data(row.scheduleJSON.utf8)) else { return nil }
        return BrandSchedule.parse(value).schedule
    }

    /// Saves the schedule after the publish rules (overlap, empty windows, time zone, kit references) pass against the business's kits, then
    /// re-publishes.
    func saveSchedule(businessId: UUID, schedule: BrandSchedule, actor: AuditActor) async throws {
        _ = try await editableBusiness(businessId)
        let ids = Set(try await kits(businessId: businessId).map(\.kitKey))
        let issues = schedule.validationIssues(kitIds: ids)
        guard issues.isEmpty else {
            throw APIError.validation(Self.scheduleMessage(issues), details: Dictionary(issues.map { ($0.path, $0.code) }, uniquingKeysWith: { a, _ in a }))
        }
        let json = String(decoding: try CanonicalJSON.serialize(schedule.jsonValue), as: UTF8.self)
        let now = ctx.now
        if let row = try await BrandKitScheduleRecord.query(on: db).filter(\.$businessId == businessId).first() {
            row.scheduleJSON = json
            row.updatedBy = actor.id
            row.updatedAt = now
            try await row.update(on: db)
        } else {
            let row = BrandKitScheduleRecord()
            row.id = UUID()
            row.businessId = businessId
            row.scheduleJSON = json
            row.updatedBy = actor.id
            row.updatedAt = now
            try await row.create(on: db)
        }
        try await AuditService(db: db, ctx: ctx).record("brandkit.schedule_saved", actor: actor, businessId: BusinessID(businessId), subjectType: "brand_schedule",
                                                        metadata: ["windows": String(schedule.windows.count), "pool": String(schedule.randomPool.count)])
        try await republish(businessId: businessId, actor: actor)
    }

    static func scheduleMessage(_ issues: [ContractIssue]) -> String {
        if issues.contains(where: { $0.code == "ambiguous_overlap" }) { return "Two windows with the same priority overlap. Give one a higher priority or change the dates." }
        if issues.contains(where: { $0.code == "empty_window" }) { return "A window ends before it starts." }
        if issues.contains(where: { $0.code == "unknown_kit" }) { return "The schedule names a kit that does not exist." }
        return "Check the schedule."
    }

    // MARK: Review (operator)

    func approveKit(id: UUID, actor: AuditActor, note: String?) async throws {
        guard let record = try await BrandKitRecord.find(id, on: db) else { throw APIError.notFound }
        guard record.status == KitStatus.pendingReview.rawValue || record.status == KitStatus.rejected.rawValue else {
            throw APIError(.conflict, .conflict, "This kit is not waiting for review.")
        }
        guard let business = try await BusinessRecord.find(record.businessId, on: db), !Self.isBanned(business) else {
            throw APIError(.forbidden, .forbidden, "Brand Kits are not available for this business category.")
        }
        // Every image the kit uses must itself be approved: approving a kit never publishes an unreviewed image.
        let refs: [BrandAssetSlot: BrandAssetRef]
        do { refs = try await resolveAssets(businessId: record.businessId, Self.draftAssetIds(record), allowPending: false) } catch {
            throw APIError(.conflict, .conflict, "Approve or reject this kit's images first.")
        }
        guard let kit = Self.draftKit(record, refs: refs), kit.validationIssues().isEmpty else { throw APIError(.conflict, .conflict, "This kit no longer validates.") }
        let snapshot = BrandManifest(businessId: BusinessID(record.businessId), manifestVersion: 1, kits: [kit], schedule: BrandSchedule(timezone: "UTC"),
                                     issuedAt: 0, notAfter: 1, kid: "k")
        guard case .object(let root) = snapshot.jsonValue, case .array(let kits)? = root["kits"], let first = kits.first else { throw APIError.notFound }
        record.approvedJSON = String(decoding: try CanonicalJSON.serialize(first), as: UTF8.self)
        record.approvedVersion = record.version
        record.status = KitStatus.approved.rawValue
        record.reviewNote = note
        record.reviewedBy = actor.id
        record.reviewedAt = ctx.now
        try await record.update(on: db)
        try await AuditService(db: db, ctx: ctx).record("brandkit.kit_approved", actor: actor, businessId: BusinessID(record.businessId), subjectType: "brand_kit",
                                                        subjectId: id.uuidString.lowercased(), metadata: ["kit": record.kitKey, "version": String(record.version)])
        try await republish(businessId: record.businessId, actor: actor)
    }

    func rejectKit(id: UUID, actor: AuditActor, reason: String) async throws {
        guard let record = try await BrandKitRecord.find(id, on: db) else { throw APIError.notFound }
        guard record.status == KitStatus.pendingReview.rawValue else { throw APIError(.conflict, .conflict, "This kit is not waiting for review.") }
        record.status = KitStatus.rejected.rawValue
        record.reviewNote = reason
        record.reviewedBy = actor.id
        record.reviewedAt = ctx.now
        try await record.update(on: db)
        try await AuditService(db: db, ctx: ctx).record("brandkit.kit_rejected", actor: actor, businessId: BusinessID(record.businessId), subjectType: "brand_kit",
                                                        subjectId: id.uuidString.lowercased(), metadata: ["kit": record.kitKey, "reason": reason])
    }

    /// Takedown: the kit stops serving at once (a new manifest without it, or a withdrawal) and cannot come back without a new review.
    func takeDownKit(id: UUID, actor: AuditActor, reason: String) async throws {
        guard let record = try await BrandKitRecord.find(id, on: db) else { throw APIError.notFound }
        record.status = KitStatus.takenDown.rawValue
        record.approvedJSON = nil
        record.approvedVersion = nil
        record.reviewNote = reason
        record.reviewedBy = actor.id
        record.reviewedAt = ctx.now
        try await record.update(on: db)
        ctx.metrics.count(.brandTakedown)
        try await AuditService(db: db, ctx: ctx).record("brandkit.kit_taken_down", actor: actor, businessId: BusinessID(record.businessId), subjectType: "brand_kit",
                                                        subjectId: id.uuidString.lowercased(), metadata: ["kit": record.kitKey, "reason": reason])
        try await republish(businessId: record.businessId, actor: actor)
    }

    func reviewAsset(id: UUID, approve: Bool, actor: AuditActor, reason: String?) async throws {
        guard let asset = try await BrandAssetRecord.find(id, on: db) else { throw APIError.notFound }
        guard asset.state == AssetState.pendingReview.rawValue else { throw APIError(.conflict, .conflict, "This image is not waiting for review.") }
        asset.state = approve ? AssetState.ready.rawValue : AssetState.rejected.rawValue
        asset.reviewNote = reason
        asset.reviewedBy = actor.id
        asset.reviewedAt = ctx.now
        try await asset.update(on: db)
        var metadata = ["slot": asset.slot, "sha256": asset.sha256]
        if let reason { metadata["reason"] = reason }
        try await AuditService(db: db, ctx: ctx).record(approve ? "brandkit.asset_approved" : "brandkit.asset_rejected", actor: actor,
                                                        businessId: BusinessID(asset.businessId), subjectType: "brand_asset", subjectId: id.uuidString.lowercased(),
                                                        metadata: metadata)
    }

    func takeDownAsset(id: UUID, actor: AuditActor, reason: String) async throws {
        guard let asset = try await BrandAssetRecord.find(id, on: db) else { throw APIError.notFound }
        asset.state = AssetState.takenDown.rawValue
        asset.reviewNote = reason
        asset.reviewedBy = actor.id
        asset.reviewedAt = ctx.now
        try await asset.update(on: db)
        ctx.metrics.count(.brandTakedown)
        try await AuditService(db: db, ctx: ctx).record("brandkit.asset_taken_down", actor: actor, businessId: BusinessID(asset.businessId), subjectType: "brand_asset",
                                                        subjectId: id.uuidString.lowercased(), metadata: ["slot": asset.slot, "sha256": asset.sha256, "reason": reason])
        try await republish(businessId: asset.businessId, actor: actor)
    }

    // MARK: Manifest

    /// What would be published now: approved snapshots only, each image still `ready`, and the schedule restricted to those kits.
    func buildPublishable(businessId: UUID) async throws -> (kits: [BrandKit], schedule: BrandSchedule) {
        let ready = Set(try await BrandAssetRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$state == AssetState.ready.rawValue).all()
            .map { "\($0.slot)|\($0.sha256)" })
        var published: [BrandKit] = []
        for record in try await kits(businessId: businessId) where record.status != KitStatus.takenDown.rawValue {
            guard var kit = Self.approvedKit(record) else { continue }
            kit.assets = kit.assets.filter { ready.contains("\($0.key.rawValue)|\($0.value.sha256)") }
            published.append(kit)
        }
        published = Array(published.prefix(BrandManifest.maxKits))
        let ids = Set(published.map(\.kitId))
        var plan = try await schedule(businessId: businessId) ?? BrandSchedule(timezone: "UTC", defaultKit: published.first?.kitId)
        plan.windows = plan.windows.filter { ids.contains($0.kit) }
        plan.randomPool = plan.randomPool.filter { ids.contains($0.kit) }
        if let d = plan.defaultKit, !ids.contains(d) { plan.defaultKit = nil }
        return (published, plan)
    }

    /// Builds, validates, signs and stores a new manifest version (or a withdrawal when nothing is publishable). Safe to call after any change.
    @discardableResult
    func republish(businessId: UUID, actor: AuditActor) async throws -> BrandManifestRecord? {
        guard let key = ctx.config.brandKits.manifestKey else { return nil }
        let (kits, schedule) = try await buildPublishable(businessId: businessId)
        let latest = try await BrandManifestRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$version, .descending).first()
        let now = ctx.now
        let row = BrandManifestRecord()
        row.id = UUID()
        row.businessId = businessId
        row.version = (latest?.version ?? 0) + 1
        row.createdAt = now
        if kits.isEmpty {
            guard let latest, latest.status == "active" else { return latest }
            row.status = "withdrawn"
            try await row.create(on: db)
            try await AuditService(db: db, ctx: ctx).record("brandkit.manifest_withdrawn", actor: actor, businessId: BusinessID(businessId), subjectType: "brand_manifest",
                                                            subjectId: String(row.version))
            return row
        }
        let issued = Int64(now.timeIntervalSince1970.rounded(.down))
        let kid = KeyIdentifier.make(try key.publicKey.signingKey())
        let manifest = BrandManifest(businessId: BusinessID(businessId), manifestVersion: Int64(row.version), kits: kits, schedule: schedule,
                                     issuedAt: issued, notAfter: issued + min(ctx.config.brandKits.manifestLifetime, BrandManifest.maxLifetime), kid: kid)
        let issues = manifest.validationIssues()
        guard issues.isEmpty else {
            throw APIError.validation("The published kits do not validate.", details: Dictionary(issues.map { ($0.path, $0.code) }, uniquingKeysWith: { a, _ in a }))
        }
        let jws: String
        do {
            jws = try await manifest.sign(with: key)
            // Verify our own signature with the public key before storing it (a misbehaving key service never hands out a bad manifest).
            _ = try BrandManifest.verify(jws, expectedBusiness: BusinessID(businessId), keys: [PinnedManifestKey(kid: kid, publicKey: key.publicKey)], now: now)
        } catch {
            ctx.metrics.count(.brandManifestSignFailed)
            ctx.logger.error("brand manifest signing failed", metadata: ["type": "\(type(of: error))"])
            throw APIError(.serviceUnavailable, .unavailable, "Branding could not be published right now. Try again.")
        }
        row.status = "active"
        row.manifestJSON = String(decoding: try CanonicalJSON.serialize(manifest.jsonValue), as: UTF8.self)
        row.jws = jws
        row.manifestHash = try manifest.manifestHash()
        row.kid = kid
        row.issuedAt = Date(timeIntervalSince1970: TimeInterval(issued))
        row.notAfter = Date(timeIntervalSince1970: TimeInterval(manifest.notAfter))
        // Unique (business_id, version): of two concurrent publishes one fails instead of both claiming the version.
        try await row.create(on: db)
        ctx.metrics.count(.brandManifestPublished)
        try await AuditService(db: db, ctx: ctx).record("brandkit.manifest_published", actor: actor, businessId: BusinessID(businessId), subjectType: "brand_manifest",
                                                        subjectId: String(row.version), metadata: ["kits": kits.map(\.kitId).joined(separator: ","), "kid": kid])
        return row
    }

    /// The manifest to serve: the newest version if active and unexpired. One close to expiry is re-issued (same content, new lifetime).
    func current(businessId: UUID) async throws -> BrandManifestRecord? {
        guard let latest = try await BrandManifestRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$version, .descending).first(),
              latest.status == "active", let notAfter = latest.notAfter else { return nil }
        let remaining = notAfter.timeIntervalSince(ctx.now)
        if remaining < TimeInterval(ctx.config.brandKits.reissueBefore) {
            if let fresh = try? await republish(businessId: businessId, actor: AuditActor(kind: .system, id: "brand-manifest-reissue")), fresh.status == "active" {
                return fresh
            }
        }
        return remaining > 0 ? latest : nil
    }

    /// The parsed active manifest (for server-side selection), without re-issuing.
    func activeManifest(businessId: UUID) async throws -> BrandManifest? {
        guard let latest = try await BrandManifestRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$version, .descending).first(),
              latest.status == "active", let json = latest.manifestJSON, let value = JSONValue.parseContract(Data(json.utf8)) else { return nil }
        return BrandManifest.parse(value).manifest
    }

    // MARK: Consumer view

    /// `GET /v1/businesses/{id}/brand`: `404` unless the caller has an active relationship with a verified business; otherwise the signed
    /// manifest, or `neutral` (kill switch, banned category, nothing published, no signing key).
    func view(consumer: ConsumerID, business: BusinessID) async throws -> BrandManifestResponse {
        guard try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$businessId == business.uuid)
            .filter(\.$status == "active").first() != nil,
              let record = try await DirectoryService(db: db).verified(id: business.uuid) else { throw APIError.notFound }
        guard !Self.isBanned(record), ctx.config.brandKits.signingAvailable,
              !(await PlatformFlags(db: db, ctx: ctx).brandKitsStopped(businessId: business.uuid)),
              let manifest = try await current(businessId: business.uuid), let jws = manifest.jws else {
            ctx.metrics.count(.brandManifestWithheld)
            return .neutral(business)
        }
        let seed = ctx.config.brandKits.selectionKey.map { Base64URL.encode(BrandSelectionSeed.derive(key: $0, consumer: consumer, business: business)) }
        let pins = try await InteractionBrandPinRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$businessId == business.uuid)
            .filter(\.$status == InteractionStatus.pending.rawValue).filter(\.$expiresAt > ctx.now).filter(\.$brandKitPin != nil)
            .sort(\.$expiresAt, .ascending).limit(50).all()
            .compactMap { row in row.brandKitPin.map { BrandKitPin(interactionId: row.id!.uuidString.lowercased(), kitId: $0) } }
        ctx.metrics.count(.brandManifestServed)
        return BrandManifestResponse(businessId: business, status: .branded, manifest: jws, manifestHash: manifest.manifestHash, selectionSeed: seed,
                                     pins: pins, assetHost: ctx.config.brandKits.assetDomain?.host)
    }

    // MARK: Pinning (WP-2.4)

    /// The kit to pin to a new interaction: the selection at creation time with the customer's seed, or `nil` (security requests, no
    /// manifest, kill switch, banned category). Never throws into the caller: branding must not affect delivery.
    func pin(businessId: UUID, consumerId: UUID, purpose: InteractionPurpose, kind: InteractionKind) async -> String? {
        guard BrandSurfacePolicy.allowsBranding(purpose: purpose, kind: kind), ctx.config.brandKits.signingAvailable else { return nil }
        do {
            guard let business = try await BusinessRecord.find(businessId, on: db), !Self.isBanned(business),
                  !(await PlatformFlags(db: db, ctx: ctx).brandKitsStopped(businessId: businessId)),
                  let manifest = try await activeManifest(businessId: businessId) else { return nil }
            let seed = ctx.config.brandKits.selectionKey.map { BrandSelectionSeed.derive(key: $0, consumer: ConsumerID(consumerId), business: BusinessID(businessId)) }
            return BrandKitSelector.select(manifest: manifest, now: ctx.now, selectionSeed: seed).kitId
        } catch {
            ctx.logger.warning("brand pin skipped", metadata: ["type": "\(type(of: error))"])
            return nil
        }
    }
}

extension JSONEncoder {
    static var sortedKeys: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }
}
