import Fluent
import Foundation
import ViadereCore

/// A contract document a business accepts. `slug` and `version` are those of the public legal page (`Site/content/legal/<slug>`, front matter
/// `version`); a test compares this list with the Site so the two cannot drift. The accepted *version* is what is recorded, never "latest".
struct LegalDocument: Sendable, Equatable {
    enum Requirement: Sendable, Equatable {
        /// Every business.
        case always
        /// Only while the business holds this risk tier (capability addenda).
        case tier(BusinessRiskTier)
    }

    var slug: String
    var title: String
    var version: String
    /// The version at which the terms last changed in substance. An acceptance of this version or a later one stays valid across editorial
    /// bumps; an older acceptance no longer counts (re-acceptance, spec §9.3: "version and reapprove materially changed policies").
    var materialSince: String
    var requirement: Requirement

    /// The stable address of exactly this version on the public site.
    func url(siteOrigin: String) -> String { "\(siteOrigin)/legal/\(slug)/versions/\(version)/" }
}

enum LegalCatalog {
    static let documents: [LegalDocument] = [
        LegalDocument(slug: "business-services-agreement", title: "Business Services Agreement", version: "0.1.0", materialSince: "0.1.0", requirement: .always),
        LegalDocument(slug: "data-processing-addendum", title: "Data Processing Addendum", version: "0.1.0", materialSince: "0.1.0", requirement: .always),
        LegalDocument(slug: "acceptable-use-policy", title: "Acceptable Use Policy", version: "0.1.0", materialSince: "0.1.0", requirement: .always),
        LegalDocument(slug: "messaging-consent-content-policy-addendum", title: "Messaging Consent and Content Policy Addendum", version: "0.1.0",
                      materialSince: "0.1.0", requirement: .always),
        LegalDocument(slug: "mfa-approval-services-addendum", title: "MFA and Approval Services Addendum", version: "0.1.0", materialSince: "0.1.0",
                      requirement: .tier(.a)),
        LegalDocument(slug: "verification-services-addendum", title: "Verification Services Addendum", version: "0.1.0", materialSince: "0.1.0",
                      requirement: .tier(.v)),
    ]

    static func document(slug: String) -> LegalDocument? { documents.first { $0.slug == slug } }

    /// Dotted numeric comparison (`0.10.0` > `0.9.0`); a malformed component compares as 0.
    static func compare(_ a: String, _ b: String) -> Int {
        let x = a.split(separator: ".").map { Int($0) ?? 0 }, y = b.split(separator: ".").map { Int($0) ?? 0 }
        for index in 0..<max(x.count, y.count) {
            let l = index < x.count ? x[index] : 0, r = index < y.count ? y[index] : 0
            if l != r { return l < r ? -1 : 1 }
        }
        return 0
    }
}

struct ContractService {
    let db: any Database
    let ctx: ServerContext

    struct Status {
        var document: LegalDocument
        /// The version the business accepted that still counts, if any.
        var acceptedVersion: String?
        var acceptedAt: Date?
        var current: Bool { acceptedVersion != nil }
    }

    /// The documents a business must have accepted at this moment (capability addenda follow its tiers).
    func required(businessId: UUID) async throws -> [LegalDocument] {
        let tiers = try await EntitlementService(db: db, ctx: ctx).snapshot(businessId: businessId).tiers
        return LegalCatalog.documents.filter { document in
            switch document.requirement {
            case .always: true
            case .tier(let tier): tiers.contains(tier)
            }
        }
    }

    func statuses(businessId: UUID, documents: [LegalDocument]? = nil) async throws -> [Status] {
        let docs: [LegalDocument]
        if let documents { docs = documents } else { docs = try await required(businessId: businessId) }
        let accepted = try await ContractAcceptanceRecord.query(on: db).filter(\.$businessId == businessId).all()
        return docs.map { document in
            let valid = accepted.filter { $0.slug == document.slug && LegalCatalog.compare($0.version, document.materialSince) >= 0 }
                .sorted { LegalCatalog.compare($0.version, $1.version) > 0 }.first
            return Status(document: document, acceptedVersion: valid?.version, acceptedAt: valid?.acceptedAt)
        }
    }

    func outstanding(businessId: UUID) async throws -> [LegalDocument] {
        try await statuses(businessId: businessId).filter { !$0.current }.map(\.document)
    }

    /// Records one acceptance: who, when, which version, and hashes of the address and agent. The version must be the catalog's current one
    /// (a stale form cannot accept an older text).
    @discardableResult
    func accept(businessId: UUID, slug: String, version: String, by userId: UUID, ip: String, userAgent: String) async throws -> ContractAcceptanceRecord {
        guard let document = LegalCatalog.document(slug: slug), document.version == version else {
            throw APIError.conflict("That document changed. Reload the page and read the current version.")
        }
        if let existing = try await ContractAcceptanceRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$slug == slug)
            .filter(\.$version == version).first() { return existing }
        let record = ContractAcceptanceRecord()
        record.id = UUID()
        record.businessId = businessId
        record.slug = slug
        record.version = version
        record.acceptedBy = userId
        record.acceptedAt = ctx.now
        record.ipHash = ctx.hasher.versionedHex("contract-ip", ip)
        record.uaHash = ctx.hasher.versionedHex("contract-ua", String(userAgent.prefix(300)))
        do { try await record.create(on: db) } catch {
            if error.isConstraintViolation, let existing = try await ContractAcceptanceRecord.query(on: db).filter(\.$businessId == businessId)
                .filter(\.$slug == slug).filter(\.$version == version).first() { return existing }
            throw error
        }
        _ = try await AuditService(db: db, ctx: ctx).record("contract.accepted", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
            businessId: BusinessID(businessId), subjectType: "contract", subjectId: slug, metadata: ["version": version])
        return record
    }

    func history(businessId: UUID) async throws -> [ContractAcceptanceRecord] {
        try await ContractAcceptanceRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$acceptedAt, .descending).all()
    }
}
