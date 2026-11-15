import Fluent
import Foundation
import SQLKit
import ViadereCore

/// A verified business asks to change an **identity-bearing** part of its public profile (G20, docs/SECURITY.md §2.111): the display name, the
/// handle or the website customers see. Nothing goes live on the business's say-so: the change waits here until **two different Viadere
/// operators** approve it, and the impersonation checks of first verification (and stricter ones) run again at every approval.
///
/// The logo customers see comes from the business's approved Brand Kit, which already has its own operator review and image pipeline, so it is
/// not edited here. The data model has no low-risk profile field (support contact, description) that could apply immediately: every column of
/// `businesses` that a customer sees is identity-bearing, so every change goes through review.
final class BusinessProfileChangeRecord: Model, @unchecked Sendable {
    static let schema = "business_profile_changes"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "requested_by") var requestedBy: UUID
    @Field(key: "requested_at") var requestedAt: Date
    /// `pending`, `first_approved`, `applied`, `rejected`, `refused` (an approval found it no longer passes the checks) or `cancelled`.
    @Field(key: "status") var status: String
    /// Proposed values; `nil` means "unchanged".
    @OptionalField(key: "display_name") var displayName: String?
    @OptionalField(key: "handle") var handle: String?
    @OptionalField(key: "website") var website: String?
    /// What customers saw when the change was requested (for the reviewer's comparison and the audit trail).
    @Field(key: "previous_display_name") var previousDisplayName: String
    @OptionalField(key: "previous_handle") var previousHandle: String?
    @OptionalField(key: "previous_website") var previousWebsite: String?
    @OptionalField(key: "first_reviewer") var firstReviewer: UUID?
    @OptionalField(key: "first_reviewed_at") var firstReviewedAt: Date?
    @OptionalField(key: "decided_by") var decidedBy: UUID?
    @OptionalField(key: "decided_at") var decidedAt: Date?
    @OptionalField(key: "decision_note") var decisionNote: String?

    init() {}

    static let openStatuses = ["pending", "first_approved"]
    var isOpen: Bool { Self.openStatuses.contains(status) }
}

/// `BusinessProfileChanges.v1` (additive): one table, at most one open change per business (enforced by the service; the index keeps the
/// per-business lookups cheap).
struct CreateBusinessProfileChangesSchema: AsyncMigration {
    var name: String { "BusinessProfileChanges.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(BusinessProfileChangeRecord.schema).id()
            .field("business_id", .uuid, .required, .references("businesses", "id", onDelete: .cascade))
            .field("requested_by", .uuid, .required)
            .field("requested_at", .datetime, .required)
            .field("status", .string, .required)
            .field("display_name", .string)
            .field("handle", .string)
            .field("website", .string)
            .field("previous_display_name", .string, .required)
            .field("previous_handle", .string)
            .field("previous_website", .string)
            .field("first_reviewer", .uuid)
            .field("first_reviewed_at", .datetime)
            .field("decided_by", .uuid)
            .field("decided_at", .datetime)
            .field("decision_note", .string)
            .create()
        guard let sql = db as? any SQLDatabase else { return }
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_business_profile_changes_business ON business_profile_changes (business_id, status)").run()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(BusinessProfileChangeRecord.schema).delete()
    }
}

/// The impersonation checks a public name must pass (first verification's rules for handles, plus name rules that verification left to the
/// reviewer): no Viadere look-alike anywhere in the name, no disallowed or invisible characters, and no name confusable with another verified
/// business's name or handle. Pure; the service supplies the other businesses.
enum BusinessIdentityPolicy {
    static let nameLength = 2...80
    static let websiteMaxLength = 200

    /// Legal-form words dropped before comparing ("Acme Roasters Inc" is the same name as "Acme Roasters").
    static let legalSuffixes: Set<String> = ["inc", "incorporated", "llc", "ltd", "limited", "co", "corp", "corporation", "company", "gmbh", "sa", "sas",
                                             "sarl", "plc", "bv", "ag", "pty", "lp", "llp", "the"]

    /// Cyrillic and Greek letters that render like Latin ones, reduced before the handle skeleton.
    static let homoglyphs: [Character: Character] = [
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "ո": "n",
        "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "υ": "u", "χ": "x",
    ]

    /// Letters and digits only, width-, case- and accent-insensitive, homoglyphs and legal suffixes removed, then `BusinessHandle`'s skeleton
    /// (`rn`→`m`, `0`→`o`, ...). Two names with the same skeleton look the same to a customer.
    static func skeleton(_ name: String) -> String {
        let folded = name.folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: Locale(identifier: "en_US_POSIX"))
        let mapped = String(folded.map { homoglyphs[$0] ?? $0 })
        let words = mapped.split(whereSeparator: { !($0.isLetter || $0.isNumber) }).map { String($0) }.filter { !legalSuffixes.contains($0) }
        let ascii = words.joined().unicodeScalars.filter { $0.isASCII && (CharacterSet.alphanumerics.contains($0)) }
        return BusinessHandle.confusableSkeleton(String(String.UnicodeScalarView(ascii)))
    }

    /// Whether two skeletons are confusable: equal, one edit apart (when long enough for that to be a typo-squat rather than a short word), or
    /// one contains a long other (`amazonorders` contains `amazon`... only from eight characters, so short common words do not block names).
    static func confusable(_ a: String, _ b: String) -> Bool {
        guard !a.isEmpty, !b.isEmpty else { return false }
        if a == b { return true }
        if min(a.count, b.count) >= 6, abs(a.count - b.count) <= 1, editDistance(a, b, limit: 1) <= 1 { return true }
        let (short, long) = a.count <= b.count ? (a, b) : (b, a)
        return short.count >= 8 && long.contains(short)
    }

    /// Levenshtein distance, stopping early above `limit`.
    static func editDistance(_ a: String, _ b: String, limit: Int) -> Int {
        let x = Array(a), y = Array(b)
        var previous = Array(0...y.count)
        for i in 1...max(1, x.count) where !x.isEmpty {
            var current = [i] + Array(repeating: 0, count: y.count)
            var rowMin = current[0]
            for j in 1...max(1, y.count) where !y.isEmpty {
                current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (x[i - 1] == y[j - 1] ? 0 : 1))
                rowMin = min(rowMin, current[j])
            }
            if rowMin > limit { return limit + 1 }
            previous = current
        }
        return x.isEmpty ? y.count : (y.isEmpty ? x.count : previous[y.count])
    }

    struct Other: Sendable {
        var businessId: UUID
        var displayName: String
        /// Active **and** retired handles: a retired handle keeps its owner's identity forever.
        var handles: [String]
    }

    /// Why `name` may not be a public name, or `nil`. `others` are the other verified businesses.
    static func nameIssue(_ name: String, others: [Other]) -> String? {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard nameLength.contains(trimmed.count) else { return "Use 2 to 80 characters." }
        switch DisplayTextSanitizer.violation(of: trimmed, maxCharacters: nameLength.upperBound, identity: true) {
        case .impersonation?: return "A name can't mention Viadere or look like it."
        case .some: return "Remove invisible or special characters from the name."
        case nil: break
        }
        let mine = skeleton(trimmed)
        guard mine.count >= 2 else { return "Use letters or digits in the name." }
        if similar(to: trimmed, others: others) != nil { return "This name is too close to another verified organization's name or handle." }
        return nil
    }

    /// The first other business the name is confusable with (by name or by any handle it ever held).
    static func similar(to name: String, others: [Other]) -> Other? {
        let mine = skeleton(name)
        return others.first { other in
            confusable(mine, skeleton(other.displayName)) || other.handles.contains { confusable(mine, BusinessHandle.confusableSkeleton($0)) }
        }
    }

    /// The website must be `https`, without credentials, and on one of the business's **verified** domains (or a subdomain of one).
    static func websiteIssue(_ raw: String, verifiedDomains: [String]) -> String? {
        guard raw.count <= websiteMaxLength, let url = URL(string: raw), url.scheme?.lowercased() == "https", url.user == nil, url.password == nil,
              let host = url.host?.lowercased(), !host.isEmpty else { return "Enter an https:// address." }
        let domains = verifiedDomains.map { $0.lowercased() }
        guard domains.contains(where: { host == $0 || host.hasSuffix("." + $0) }) else {
            return "The website must be on a domain your organization has verified (Organization > Domains)."
        }
        return nil
    }
}

struct BusinessProfileChanges {
    let db: any Database
    let ctx: ServerContext

    static let noteLength = 8...300

    struct Proposal: Equatable, Sendable {
        var displayName: String?
        var handle: String?
        var website: String?
        var isEmpty: Bool { displayName == nil && handle == nil && website == nil }
    }

    // MARK: Reading

    func open(businessId: UUID) async throws -> BusinessProfileChangeRecord? {
        try await BusinessProfileChangeRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$status ~~ BusinessProfileChangeRecord.openStatuses)
            .sort(\.$requestedAt, .descending).first()
    }

    func latest(businessId: UUID) async throws -> BusinessProfileChangeRecord? {
        try await BusinessProfileChangeRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$requestedAt, .descending).first()
    }

    func queue() async throws -> [BusinessProfileChangeRecord] {
        try await BusinessProfileChangeRecord.query(on: db).filter(\.$status ~~ BusinessProfileChangeRecord.openStatuses).sort(\.$requestedAt, .ascending).limit(200).all()
    }

    func currentHandle(_ businessId: UUID) async throws -> String? {
        try await BusinessHandleRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$status == "active").first()?.handle
    }

    /// Every other verified business with its name and every handle it ever held.
    func others(excluding businessId: UUID) async throws -> [BusinessIdentityPolicy.Other] {
        let businesses = try await BusinessRecord.query(on: db).filter(\.$verificationStatus == VerificationStatus.verified.rawValue).filter(\.$id != businessId).all()
        let ids = businesses.compactMap(\.id)
        let handles = ids.isEmpty ? [] : try await BusinessHandleRecord.query(on: db).filter(\.$businessId ~~ ids).all()
        let byBusiness = Dictionary(grouping: handles, by: \.businessId)
        return businesses.compactMap { b in b.id.map { BusinessIdentityPolicy.Other(businessId: $0, displayName: b.displayName, handles: byBusiness[$0]?.map(\.handle) ?? []) } }
    }

    /// The automated checks, field by field (`displayName`, `handle`, `website`). Empty when the proposal may be reviewed.
    func vet(businessId: UUID, _ proposal: Proposal) async throws -> [String: String] {
        var issues: [String: String] = [:]
        if let name = proposal.displayName, let issue = BusinessIdentityPolicy.nameIssue(name, others: try await others(excluding: businessId)) {
            issues["displayName"] = issue
        }
        if let raw = proposal.handle {
            do {
                let handle = try BusinessHandle.validateForRegistration(raw)
                try await BusinessRegistry.checkHandleAvailable(handle, on: db)
            } catch BusinessRegistry.RegistryError.handleTaken {
                issues["handle"] = "That handle is taken or was used before. Handles are never reused."
            } catch BusinessRegistry.RegistryError.confusableHandle {
                issues["handle"] = "That handle looks like one that is taken or was used before."
            } catch {
                issues["handle"] = "Use 3 to 30 letters, digits or underscores, not a reserved word."
            }
        }
        if let website = proposal.website {
            let domains = try await BusinessDomainRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$status == "verified").all().map(\.domain)
            if let issue = BusinessIdentityPolicy.websiteIssue(website, verifiedDomains: domains) { issues["website"] = issue }
        }
        return issues
    }

    static func proposal(of record: BusinessProfileChangeRecord) -> Proposal {
        Proposal(displayName: record.displayName, handle: record.handle, website: record.website)
    }

    // MARK: Business side

    /// Normalizes the form: an empty field or one equal to what customers see now is "unchanged".
    func normalize(business: BusinessRecord, currentHandle: String?, displayName: String?, handle: String?, website: String?) -> Proposal {
        func clean(_ s: String?) -> String? {
            let t = (s ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            return t.isEmpty ? nil : t
        }
        var p = Proposal()
        if let name = clean(displayName), name != business.displayName { p.displayName = name }
        if var h = clean(handle) {
            if h.hasPrefix("@") { h.removeFirst() }
            h = h.lowercased()
            if !h.isEmpty, h != currentHandle { p.handle = h }
        }
        if let w = clean(website), w != business.websiteURL { p.website = w }
        return p
    }

    /// A member with `manageOrganization` of a **verified** organization asks for a change. Refused while another change is open.
    @discardableResult
    func request(principal: DashboardPrincipal, displayName: String?, handle: String?, website: String?) async throws -> BusinessProfileChangeRecord {
        guard principal.realm == .business, principal.can(.manageOrganization), let business = principal.business, let businessId = business.id,
              let userId = principal.user.id else { throw APIError.forbidden }
        guard business.isVerified else { throw APIError(.forbidden, .forbidden, "Profile changes are available once Viadere has verified your organization.") }
        let current = try await currentHandle(businessId)
        let proposal = normalize(business: business, currentHandle: current, displayName: displayName, handle: handle, website: website)
        guard !proposal.isEmpty else { throw APIError.validation("Nothing changed: enter at least one new value.") }
        let issues = try await vet(businessId: businessId, proposal)
        guard issues.isEmpty else {
            _ = try await AuditService(db: db, ctx: ctx).record("business.profile_change_refused", outcome: .denied, actor: Self.actor(userId),
                businessId: BusinessID(businessId), subjectType: "organization", subjectId: businessId.uuidString.lowercased(),
                metadata: ["stage": "request", "fields": issues.keys.sorted().joined(separator: ",")])
            throw APIError.validation(issues.values.sorted().joined(separator: " "), details: issues)
        }
        guard try await open(businessId: businessId) == nil else {
            throw APIError.conflict("A profile change is already waiting for Viadere's review. Cancel it to ask for a different one.")
        }
        let record = BusinessProfileChangeRecord()
        record.id = UUID()
        record.businessId = businessId
        record.requestedBy = userId
        record.requestedAt = ctx.now
        record.status = "pending"
        record.displayName = proposal.displayName
        record.handle = proposal.handle
        record.website = proposal.website
        record.previousDisplayName = business.displayName
        record.previousHandle = current
        record.previousWebsite = business.websiteURL
        try await record.create(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("business.profile_change_requested", actor: Self.actor(userId), businessId: BusinessID(businessId),
            subjectType: "profile_change", subjectId: record.id?.uuidString.lowercased(), metadata: Self.fields(proposal))
        await Notifier(db: db, ctx: ctx).notifyBusiness(businessId, roles: [.owner, .orgAdmin], includeSecurityContacts: true,
            subject: "A change to your public profile was requested",
            text: "A team member asked Viadere to change your organization's public \(Self.describe(proposal)). Customers keep seeing the current profile until two Viadere reviewers approve it. If you did not expect this, cancel it in the console under Organization.",
            kind: "profile-change-requested")
        return record
    }

    func cancel(id: UUID, principal: DashboardPrincipal) async throws {
        guard principal.realm == .business, principal.can(.manageOrganization), let businessId = principal.business?.id, let userId = principal.user.id else {
            throw APIError.forbidden
        }
        guard let record = try await BusinessProfileChangeRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        guard record.isOpen, try await swapOpen(id, from: record.status, to: "cancelled", extra: [("decided_by", userId), ("decided_at", ctx.now)]) else {
            throw APIError.conflict("This change was already decided.")
        }
        _ = try await AuditService(db: db, ctx: ctx).record("business.profile_change_cancelled", actor: Self.actor(userId), businessId: BusinessID(businessId),
            subjectType: "profile_change", subjectId: id.uuidString.lowercased())
    }

    // MARK: Operator side

    enum Approval: Equatable { case firstApproval, applied }

    /// The first approval records the reviewer; the second, by a **different** operator, applies the change. Both re-run the checks: a name
    /// that became confusable with a business verified in the meantime, or a handle taken since, is refused (and the change closed as `refused`).
    func approve(id: UUID, operatorId: UUID, note: String?) async throws -> Approval {
        guard let record = try await BusinessProfileChangeRecord.find(id, on: db) else { throw APIError.notFound }
        guard record.isOpen else { throw APIError.conflict("This change was already decided.") }
        if record.status == "first_approved", record.firstReviewer == operatorId {
            _ = try await AuditService(db: db, ctx: ctx).record("business.profile_change_second_review_refused", outcome: .denied, actor: Self.operatorActor(operatorId),
                businessId: BusinessID(record.businessId), subjectType: "profile_change", subjectId: id.uuidString.lowercased())
            throw APIError(.forbidden, .forbidden, "A second, different operator has to approve this change.")
        }
        guard let business = try await BusinessRecord.find(record.businessId, on: db), business.isVerified else {
            throw APIError.conflict("The organization is not verified (suspended or revoked); the change cannot be applied.")
        }
        let proposal = Self.proposal(of: record)
        let issues = try await vet(businessId: record.businessId, proposal)
        guard issues.isEmpty else {
            _ = try await swapOpen(id, from: record.status, to: "refused", extra: [("decided_by", operatorId), ("decided_at", ctx.now),
                                                                                 ("decision_note", String(issues.values.sorted().joined(separator: " ").prefix(300)))])
            _ = try await AuditService(db: db, ctx: ctx).record("business.profile_change_refused", outcome: .denied, actor: Self.operatorActor(operatorId),
                businessId: BusinessID(record.businessId), subjectType: "profile_change", subjectId: id.uuidString.lowercased(),
                metadata: ["stage": record.status, "fields": issues.keys.sorted().joined(separator: ",")])
            await notifyDecision(record.businessId, applied: false, reason: issues.values.sorted().joined(separator: " "))
            throw APIError.validation("The change no longer passes the checks: \(issues.values.sorted().joined(separator: " "))", details: issues)
        }
        if record.status == "pending" {
            guard try await swapOpen(id, from: "pending", to: "first_approved", extra: [("first_reviewer", operatorId), ("first_reviewed_at", ctx.now)]) else {
                throw APIError.conflict("This change was already decided.")
            }
            _ = try await AuditService(db: db, ctx: ctx).record("business.profile_change_first_approval", actor: Self.operatorActor(operatorId),
                businessId: BusinessID(record.businessId), subjectType: "profile_change", subjectId: id.uuidString.lowercased(),
                metadata: ["note": String((note ?? "").prefix(300))])
            return .firstApproval
        }
        let now = ctx.now
        try await db.transaction { tx in
            guard try await DB.swap(tx, table: BusinessProfileChangeRecord.schema, id: id, column: "status", expected: "first_approved", newValue: "applied",
                                    extra: [("decided_by", operatorId), ("decided_at", now), ("decision_note", String((note ?? "").prefix(300)))]) else {
                throw APIError.conflict("This change was already decided.")
            }
            guard let business = try await BusinessRecord.find(record.businessId, on: tx) else { throw APIError.notFound }
            if let name = proposal.displayName { business.displayName = name.trimmingCharacters(in: .whitespacesAndNewlines) }
            if let website = proposal.website { business.websiteURL = website }
            var handleValue = try await BusinessHandleRecord.query(on: tx).filter(\.$businessId == record.businessId).filter(\.$status == "active").first()?.handle
            if let raw = proposal.handle {
                let handle = try BusinessHandle.validateForRegistration(raw)
                // Checked again inside the transaction; the unique indexes on handle and skeleton are the backstop against a racing claim.
                do { try await BusinessRegistry.checkHandleAvailable(handle, on: tx) } catch { throw APIError.conflict("That handle was taken in the meantime.") }
                // The old handle is retired, never deleted: it stays bound to this business and can never be issued again.
                try await BusinessHandleRecord.query(on: tx).filter(\.$businessId == record.businessId).filter(\.$status == "active").set(\.$status, to: "retired").update()
                try await BusinessHandleRecord(businessId: record.businessId, handle: handle, now: now).create(on: tx)
                handleValue = handle.value
            }
            business.searchText = ([business.displayName] + (handleValue.map { [$0] } ?? [])).joined(separator: " ").lowercased()
            try await business.update(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("business.profile_change_applied", actor: Self.operatorActor(operatorId),
                businessId: BusinessID(record.businessId), subjectType: "profile_change", subjectId: id.uuidString.lowercased(),
                metadata: Self.fields(proposal).merging(["first_reviewer": record.firstReviewer?.uuidString.lowercased() ?? ""], uniquingKeysWith: { a, _ in a }))
        }
        await notifyDecision(record.businessId, applied: true, reason: nil)
        return .applied
    }

    func reject(id: UUID, operatorId: UUID, note: String) async throws {
        let reason = note.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.noteLength.contains(reason.count) else { throw APIError.validation("Say why (8 to 300 characters); the business sees it.", details: ["note": "required"]) }
        guard let record = try await BusinessProfileChangeRecord.find(id, on: db) else { throw APIError.notFound }
        guard record.isOpen, try await swapOpen(id, from: record.status, to: "rejected", extra: [("decided_by", operatorId), ("decided_at", ctx.now), ("decision_note", reason)]) else {
            throw APIError.conflict("This change was already decided.")
        }
        _ = try await AuditService(db: db, ctx: ctx).record("business.profile_change_rejected", outcome: .denied, actor: Self.operatorActor(operatorId),
            businessId: BusinessID(record.businessId), subjectType: "profile_change", subjectId: id.uuidString.lowercased())
        await notifyDecision(record.businessId, applied: false, reason: reason)
    }

    // MARK: Helpers

    private func swapOpen(_ id: UUID, from: String, to: String, extra: [(String, any Encodable & Sendable)]) async throws -> Bool {
        try await DB.swap(db, table: BusinessProfileChangeRecord.schema, id: id, column: "status", expected: from, newValue: to, extra: extra)
    }

    private func notifyDecision(_ businessId: UUID, applied: Bool, reason: String?) async {
        await Notifier(db: db, ctx: ctx).notifyBusiness(businessId, roles: [.owner, .orgAdmin], includeSecurityContacts: false,
            subject: applied ? "Your public profile was updated" : "Your profile change was not approved",
            text: applied ? "Viadere approved the change to your organization's public profile. Customers now see the new details."
                : "Viadere did not approve the change to your organization's public profile. \(String((reason ?? "").prefix(300))) Customers keep seeing the current profile.",
            kind: applied ? "profile-change-applied" : "profile-change-declined")
    }

    static func actor(_ userId: UUID) -> AuditActor { AuditActor(kind: .business, id: userId.uuidString.lowercased()) }
    static func operatorActor(_ id: UUID) -> AuditActor { AuditActor(kind: .operator_, id: id.uuidString.lowercased()) }

    static func fields(_ p: Proposal) -> [String: String] {
        var out: [String: String] = [:]
        if let v = p.displayName { out["display_name"] = String(v.prefix(80)) }
        if let v = p.handle { out["handle"] = v }
        if let v = p.website { out["website"] = String(v.prefix(200)) }
        return out
    }

    static func describe(_ p: Proposal) -> String {
        var parts: [String] = []
        if p.displayName != nil { parts.append("name") }
        if p.handle != nil { parts.append("handle") }
        if p.website != nil { parts.append("website") }
        return parts.count <= 1 ? (parts.first ?? "profile") : parts.dropLast().joined(separator: ", ") + " and " + parts.last!
    }
}
