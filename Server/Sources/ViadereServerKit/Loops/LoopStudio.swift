import Fluent
import FluentSQL
import Foundation
import SQLKit
import ViadereCore

// MARK: - Model

/// A Loop Studio draft (WP-3.7): the business's working copy of one Loop, edited in the console and submitted for Viadere review as a new
/// immutable revision. Holds business-authored display text only (never customer input), so it is stored like `loop_revisions`
/// (not field-encrypted). One draft per Loop key per business; every query is scoped by the authenticated tenant.
final class LoopStudioDraftRecord: Model, @unchecked Sendable {
    static let schema = "loop_studio_drafts"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    /// The Loop this draft revises (`loop_definitions.key`). Fixed when the draft is created.
    @Field(key: "loop_key") var loopKey: String
    /// The locked template the draft started from, if any. The fast-path flag is recomputed from the document on every submission.
    @OptionalField(key: "template_key") var templateKey: String?
    /// Canonical JSON of the typed draft definition (may fail validation: the Studio shows the report).
    @Field(key: "definition_json") var definitionJSON: String
    /// Optimistic concurrency: every save increments it; a form rendered from an older version is refused.
    @Field(key: "version") var version: Int
    @Field(key: "created_by") var createdBy: UUID
    @Field(key: "updated_by") var updatedBy: UUID
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "updated_at") var updatedAt: Date
    init() {}
}

/// `LoopStudio.v1` (additive, forward-only): one table of per-business drafts.
struct CreateLoopStudioSchema: AsyncMigration {
    var name: String { "LoopStudio.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(LoopStudioDraftRecord.schema).id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("loop_key", .string, .required)
            .field("template_key", .string)
            .field("definition_json", .string, .required)
            .field("version", .int, .required)
            .field("created_by", .uuid, .required)
            .field("updated_by", .uuid, .required)
            .field("created_at", .datetime, .required)
            .field("updated_at", .datetime, .required)
            .unique(on: "business_id", "loop_key").create()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(LoopStudioDraftRecord.schema).delete()
    }
}

// MARK: - Service

/// Loop Studio (WP-3.7; SECURITY.md §2.99). Drafts are data only: they never reach a customer. The only way out is `submit`, which hands
/// the canonical document to `LoopPublicationService.submit`, the same pipeline every revision takes (hard gate, human review, signing).
/// There is no publish path here.
struct LoopStudioService {
    let db: any Database
    let ctx: ServerContext

    static let maxDraftsPerBusiness = 50

    // MARK: Eligibility

    /// The business may author Loops: exists, not suspended, and its category is eligible (healthcare and prohibited categories are
    /// refused, FX-4 layer 1, as `LoopPublicationService.submit` does).
    func authoringBusiness(_ businessId: UUID) async throws -> BusinessRecord {
        guard let business = try await BusinessRecord.find(businessId, on: db) else { throw APIError.notFound }
        if case .refused(let reason) = LoopCategoryPolicy.loops(BusinessCategory(rawValue: business.category)) {
            throw APIError(.forbidden, .forbidden, reason == "healthcare_banned"
                ? "Healthcare organizations can't use Loops on Viadere." : "Organizations in this category can't use Loops on Viadere.")
        }
        if business.status == .suspended { throw APIError(.forbidden, .forbidden, "This organization is suspended.") }
        return business
    }

    static func refusal(_ business: BusinessRecord) -> String? {
        if case .refused(let reason) = LoopCategoryPolicy.loops(BusinessCategory(rawValue: business.category)) {
            return reason == "healthcare_banned" ? "Healthcare organizations can't use Loops on Viadere." : "Organizations in this category can't use Loops on Viadere."
        }
        return nil
    }

    // MARK: Reads (always tenant-scoped)

    func drafts(businessId: UUID) async throws -> [LoopStudioDraftRecord] {
        try await LoopStudioDraftRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$updatedAt, .descending).limit(Self.maxDraftsPerBusiness).all()
    }

    /// A draft of this business; another tenant's id is indistinguishable from a missing one (404).
    func draft(businessId: UUID, id: UUID) async throws -> LoopStudioDraftRecord {
        guard let draft = try await LoopStudioDraftRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else {
            throw APIError.notFound
        }
        return draft
    }

    static func definition(_ draft: LoopStudioDraftRecord) -> LoopDefinition? { LoopDefinition.parse(Data(draft.definitionJSON.utf8)).definition }

    /// Revisions of the draft's Loop, newest first.
    func revisions(businessId: UUID, loopKey: String, limit: Int = 10) async throws -> [LoopRevisionRecord] {
        guard let definition = try await LoopDefinitionRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$key == loopKey).first() else { return [] }
        return try await LoopRevisionRecord.query(on: db).filter(\.$definitionId == definition.id!).filter(\.$businessId == businessId)
            .sort(\.$revision, .descending).limit(limit).all()
    }

    // MARK: Validation

    /// The validation context Studio and the pipeline share: publisher from the business record, the business's own approved Brand Kits.
    func validationContext(_ business: BusinessRecord) async throws -> LoopValidationContext {
        let publisher = LoopPublisherIdentity(publisherType: .business, businessId: BusinessID(business.id!), verificationStatus: business.status,
                                              category: BusinessCategory(rawValue: business.category))
        return LoopValidationContext(submittingBusinessId: BusinessID(business.id!), publisher: publisher, phase: .hosted,
                                     brandKitKeys: try await LoopPublicationService.approvedBrandKitKeys(businessId: business.id!, on: db))
    }

    func report(_ definition: LoopDefinition, business: BusinessRecord) async throws -> LoopValidationReport {
        LoopPolicyValidator.validate(definition, context: try await validationContext(business))
    }

    // MARK: Writes

    /// Starts a draft from a locked template. The Loop key is the template's, made unique among this business's drafts and Loops.
    func create(businessId: UUID, authorId: UUID, templateKey: String) async throws -> LoopStudioDraftRecord {
        _ = try await authoringBusiness(businessId)
        guard let template = LoopTemplateCatalog.template(templateKey) else { throw APIError.validation("Choose a template.", details: ["template": "unknown"]) }
        let count = try await LoopStudioDraftRecord.query(on: db).filter(\.$businessId == businessId).count()
        guard count < Self.maxDraftsPerBusiness else { throw APIError.conflict("You already have \(Self.maxDraftsPerBusiness) drafts. Delete one first.") }
        var definition = template.definition
        definition.key = try await uniqueKey(businessId: businessId, base: template.definition.key)
        let now = ctx.now
        let record = LoopStudioDraftRecord()
        record.id = UUID()
        record.businessId = businessId
        record.loopKey = definition.key
        record.templateKey = template.key
        record.definitionJSON = String(decoding: try definition.canonicalJSON(), as: UTF8.self)
        record.version = 1
        record.createdBy = authorId
        record.updatedBy = authorId
        record.createdAt = now
        record.updatedAt = now
        try await record.create(on: db)
        try await AuditService(db: db, ctx: ctx).record("loop.studio_draft_created", actor: LoopPublicationService.businessActor(authorId),
                                                        businessId: BusinessID(businessId), subjectType: "loop_studio_draft",
                                                        subjectId: record.id!.uuidString.lowercased(), metadata: ["loop": record.loopKey, "template": template.key])
        return record
    }

    private func uniqueKey(businessId: UUID, base: String) async throws -> String {
        let drafts = Set(try await LoopStudioDraftRecord.query(on: db).filter(\.$businessId == businessId).all().map(\.loopKey))
        let loops = Set(try await LoopDefinitionRecord.query(on: db).filter(\.$businessId == businessId).all().map(\.key))
        for n in 1...Self.maxDraftsPerBusiness + 1 {
            let candidate = n == 1 ? base : "\(base)-\(n)"
            if !drafts.contains(candidate) && !loops.contains(candidate) { return candidate }
        }
        throw APIError.conflict("Choose another template.")
    }

    /// Saves an edited draft. The Loop key never changes; the form was rendered from `expectedVersion` (else 409).
    @discardableResult
    func save(businessId: UUID, id: UUID, expectedVersion: Int, definition input: LoopDefinition, authorId: UUID) async throws -> LoopStudioDraftRecord {
        _ = try await authoringBusiness(businessId)
        let record = try await draft(businessId: businessId, id: id)
        guard record.version == expectedVersion else { throw APIError.conflict("This draft changed in another window. Reload it and try again.") }
        var definition = input
        definition.key = record.loopKey
        let canonical = try definition.canonicalJSON()
        guard canonical.count <= LoopLimits.maxDefinitionBytes * 2 else { throw APIError.validation("This draft is too large.") }
        let json = String(decoding: canonical, as: UTF8.self)
        guard try await DB.swap(db, table: LoopStudioDraftRecord.schema, id: id, column: "version", expected: expectedVersion, newValue: expectedVersion + 1,
                                extra: [("definition_json", json), ("updated_by", authorId), ("updated_at", ctx.now)]) else {
            throw APIError.conflict("This draft changed in another window. Reload it and try again.")
        }
        try await AuditService(db: db, ctx: ctx).record("loop.studio_draft_saved", actor: LoopPublicationService.businessActor(authorId),
                                                        businessId: BusinessID(businessId), subjectType: "loop_studio_draft", subjectId: id.uuidString.lowercased(),
                                                        metadata: ["loop": record.loopKey, "version": String(expectedVersion + 1)])
        return try await draft(businessId: businessId, id: id)
    }

    func delete(businessId: UUID, id: UUID, authorId: UUID) async throws {
        let record = try await draft(businessId: businessId, id: id)
        try await record.delete(on: db)
        try await AuditService(db: db, ctx: ctx).record("loop.studio_draft_deleted", actor: LoopPublicationService.businessActor(authorId),
                                                        businessId: BusinessID(businessId), subjectType: "loop_studio_draft", subjectId: id.uuidString.lowercased(),
                                                        metadata: ["loop": record.loopKey])
    }

    /// Submits the draft for Viadere review **through the publication pipeline** (`LoopPublicationService.submit`): a new immutable revision
    /// that passes the hard gate again, waits for human review and is signed only after approval. The template flag is set only when the
    /// document still has the template's structure.
    func submit(businessId: UUID, id: UUID, expectedVersion: Int, authorId: UUID) async throws -> LoopRevisionRecord {
        let business = try await authoringBusiness(businessId)
        let record = try await draft(businessId: businessId, id: id)
        guard record.version == expectedVersion else { throw APIError.conflict("This draft changed in another window. Reload it and try again.") }
        guard let definition = Self.definition(record) else { throw APIError.validation("This draft could not be read.") }
        let report = try await report(definition, business: business)
        guard report.gate.passed else {
            throw APIError.validation("Fix the problems in the validation report before submitting.", details: LoopPublicationService.details(report.hardGateHits))
        }
        // The exact document is already waiting for review: don't queue it twice.
        if let hash = report.definitionHash, try await revisions(businessId: businessId, loopKey: record.loopKey, limit: 50)
            .contains(where: { $0.stateValue == .inReview && $0.definitionHash == hash }) {
            throw APIError.conflict("This exact version is already waiting for Viadere review.")
        }
        let template = LoopTemplateCatalog.matching(definition, startedFrom: record.templateKey)?.key
        let revision = try await LoopPublicationService(db: db, ctx: ctx).submit(businessId: businessId, authorId: authorId,
                                                                                 definition: try definition.canonicalJSON(), templateKey: template)
        try await AuditService(db: db, ctx: ctx).record("loop.studio_submitted", actor: LoopPublicationService.businessActor(authorId),
                                                        businessId: BusinessID(businessId), subjectType: "loop_studio_draft", subjectId: id.uuidString.lowercased(),
                                                        metadata: ["loop": record.loopKey, "revision_id": revision.id!.uuidString.lowercased(),
                                                                   "template": template ?? "none"])
        return revision
    }
}

// MARK: - Preview

/// The presentation trees a Loop would show, for the Studio preview and the operator review (plan 4.12: reviewers see what customers see).
/// Built by `PresentationBuilder` from a preview manifest signed with a throwaway key that no device pins, the verified business record and
/// the business's **own** approved Brand Kit (a kit key of another business never resolves: the lookup is scoped by business id, and the
/// builder ignores a kit whose business differs from the instance's).
enum LoopPreview {
    struct Screen: Sendable {
        var label: String
        var tree: PresentationTree
        /// A confirmation view: the device shows its own Face ID / passcode prompt here.
        var confirmation: Bool
    }

    static func brand(for definition: LoopDefinition, businessId: UUID, on db: any Database) async throws -> BrandKitPresentation? {
        guard case .brandKit(let key) = definition.appearance,
              let record = try await BrandKitRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$kitKey == key).first(),
              let kit = BrandKitService.approvedKit(record) else { return nil }
        return BrandKitPresentation(businessId: BusinessID(businessId), kitId: kit.kitId, tokens: kit.tokens, frameId: kit.frameId)
    }

    static func screens(definition: LoopDefinition, business: BusinessRecord, brand: BrandKitPresentation?, now: Date) async -> [Screen] {
        let key = SoftwareP256SigningKey()
        guard let kid = try? KeyIdentifier.make(key.publicKey.signingKey()), let hash = try? definition.definitionHash() else { return [] }
        let from = Int64(now.timeIntervalSince1970)
        let manifest = LoopPublicationManifest(publisherType: .business, publisherBusinessId: BusinessID(business.id!), publishedDefinitionId: LoopPublicationID(UUID()),
                                               revision: 1, definitionHash: hash, validFrom: from, notAfter: from + 3600, kid: kid)
        guard let compact = try? await manifest.sign(with: key) else { return [] }
        let record = VerifiedBusinessRecord(id: BusinessID(business.id!), displayName: business.displayName, verificationStatus: business.status,
                                            category: BusinessCategory(rawValue: business.category))
        let context = LoopPresentationContext(manifest: compact, pinnedKeys: [PinnedManifestKey(kid: kid, publicKey: key.publicKey)], definition: definition,
                                              instanceBusinessId: BusinessID(business.id!), publisher: record, brand: brand, now: now)
        var screens: [Screen] = []
        for (index, step) in definition.steps.enumerated() {
            let tree = PresentationBuilder.build(context, phase: .step(step.id, outcome: step.type == .result ? .pending : nil))
            screens.append(Screen(label: "Step \(index + 1)", tree: tree, confirmation: false))
            for action in step.actions {
                guard case .registered(let def) = LoopActionRegistry.v1.resolve(action.action), def.confirmation != nil else { continue }
                screens.append(Screen(label: "Step \(index + 1): confirmation", tree: PresentationBuilder.build(context, phase: .confirm(stepId: step.id, actionId: action.id)),
                                      confirmation: true))
            }
        }
        return screens
    }
}
