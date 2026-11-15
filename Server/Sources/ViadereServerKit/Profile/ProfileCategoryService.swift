import Fluent
import Foundation
import ViadereCore

/// Which customer-profile categories a business may use, decided like an Apple entitlement (docs/PROFILES.md §Access):
///
/// 1. The business **asks** (onboarding checklist or later, console `Organization > Customer profile access`): it picks categories and, for those
///    marked `requiresJustification`, writes why it needs them. Asking creates `profile_category_requests` rows and **nothing else**: there is
///    no path from the business console to an entitlement.
/// 2. A Viadere operator **reviews** each request and approves or denies it (it can allow fewer than asked). Approval goes through
///    `EntitlementService.grant(profileCategory:)`: justification required, audited, operator recorded, revocable; the business must be verified
///    and not in a banned category.
/// 3. Enforcement reads only `business_entitlements` (`kind = profile_category`) at request time and at every read.
struct ProfileCategoryService {
    let db: any Database
    let ctx: ServerContext

    static let minimumJustification = 20
    static let maximumJustification = 1000

    struct Selection: Sendable {
        var category: ProfileCategory
        var justification: String?
    }

    /// The business asks for categories. Validates the justifications, skips categories already allowed or already pending, and audits.
    /// Returns the created requests.
    @discardableResult
    func submit(businessId: UUID, selections: [Selection], requestedBy: UUID?) async throws -> [ProfileCategoryRequestRecord] {
        guard !selections.isEmpty, Set(selections.map(\.category)).count == selections.count else {
            throw APIError.validation("Choose at least one category, once.", details: ["categories": "invalid"])
        }
        guard let business = try await BusinessRecord.find(businessId, on: db) else { throw APIError.notFound }
        if OnboardingService.isBanned(business.category) {
            throw APIError(.forbidden, .forbidden, BusinessOnboarding.categoryBannedMessage, details: ["category": "category_blocked"])
        }
        var cleaned: [(ProfileCategory, String?)] = []
        for selection in selections {
            let text = selection.justification.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.flatMap { $0.isEmpty ? nil : $0 }
            if let text {
                guard text.count <= Self.maximumJustification, !DisplayTextSanitizer.containsDisallowedScalars(text, allowNewlines: true) else {
                    throw APIError.validation("The justification for \(selection.category.title) can't be stored as written.", details: [selection.category.rawValue: "invalid"])
                }
            }
            if selection.category.requiresJustification {
                guard let text, text.count >= Self.minimumJustification else {
                    throw APIError.validation("Explain why you need \(selection.category.title) (at least \(Self.minimumJustification) characters).",
                                              details: [selection.category.rawValue: "justification_required"])
                }
            }
            cleaned.append((selection.category, text))
        }
        let allowed = try await EntitlementService(db: db, ctx: ctx).snapshot(businessId: businessId).profileCategories
        let pending = Set(try await ProfileCategoryRequestRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$status == "pending").all()
            .compactMap(\.categoryValue))
        let now = ctx.now
        let toCreate = cleaned.filter { !allowed.contains($0.0) && !pending.contains($0.0) }
            .map { ProfileCategoryRequestRecord(businessId: businessId, category: $0.0, justification: $0.1, requestedBy: requestedBy, now: now) }
        try await db.transaction { tx in
            for row in toCreate { try await row.create(on: tx) }
            if !toCreate.isEmpty {
                _ = try await AuditService(db: tx, ctx: ctx).record("profile.categories_requested", actor: AuditActor(kind: .business, id: requestedBy?.uuidString.lowercased() ?? "dashboard"),
                    businessId: BusinessID(businessId), subjectType: "profile_category_request", subjectId: nil,
                    metadata: ["categories": toCreate.map(\.category).joined(separator: " ")])
            }
        }
        return toCreate
    }

    /// The business withdraws a pending request.
    func withdraw(businessId: UUID, requestId: UUID) async throws {
        guard let row = try await ProfileCategoryRequestRecord.query(on: db).filter(\.$id == requestId).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        guard row.status == "pending" else { throw APIError.conflict("Only a pending request can be withdrawn.") }
        row.status = "withdrawn"
        row.decidedAt = ctx.now
        try await row.update(on: db)
    }

    func requests(businessId: UUID) async throws -> [ProfileCategoryRequestRecord] {
        try await ProfileCategoryRequestRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$createdAt, .descending).limit(200).all()
    }

    /// Operator decision on one request. Approval grants the entitlement (and needs the review reference for `verified` and `birthdate`); a
    /// denial records the note. Only a pending request of that business can be decided, so an operator cannot allow a category the business never
    /// asked for (or quietly widen what it asked).
    func decide(businessId: UUID, requestId: UUID, approve: Bool, operatorId: UUID, justification rawJustification: String,
                reviewReference: String?) async throws {
        guard let row = try await ProfileCategoryRequestRecord.query(on: db).filter(\.$id == requestId).filter(\.$businessId == businessId).first(),
              let category = row.categoryValue else { throw APIError.notFound }
        guard row.status == "pending" else { throw APIError.conflict("This request was already decided.") }
        let justification = rawJustification.trimmingCharacters(in: .whitespacesAndNewlines)
        let actor = EntitlementActor.operatorUser(operatorId)
        if approve {
            try await EntitlementService(db: db, ctx: ctx).grant(businessId: businessId, profileCategory: category, actor: actor,
                                                                 justification: justification, reviewReference: reviewReference)
        } else {
            guard (8...1000).contains(justification.count) else {
                throw APIError.validation("Record why the category is not allowed.", details: ["justification": "required"])
            }
            _ = try await AuditService(db: db, ctx: ctx).record("profile.category_denied", actor: AuditActor(kind: actor.kind, id: actor.id), businessId: BusinessID(businessId),
                subjectType: "profile_category_request", subjectId: requestId.uuidString.lowercased(), metadata: ["category": category.rawValue, "justification": justification])
        }
        guard try await DB.swap(db, table: ProfileCategoryRequestRecord.schema, id: requestId, column: "status", expected: "pending",
                                newValue: approve ? "approved" : "denied",
                                extra: [("decided_at", ctx.now), ("decided_by", actor.id), ("decision_note", justification)]) else {
            throw APIError.conflict("This request was already decided.")
        }
    }
}
