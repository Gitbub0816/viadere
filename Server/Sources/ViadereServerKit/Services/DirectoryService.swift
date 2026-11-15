import Fluent
import Foundation
import ViadereCore

/// Read access to the business directory. Only **verified** businesses are ever returned by discovery
/// and resolution; every other state looks identical to "does not exist".
struct DirectoryService {
    let db: any Database

    // MARK: Summaries

    func summaries(for businesses: [BusinessRecord]) async throws -> [BusinessSummary] {
        let ids = businesses.compactMap(\.id)
        guard !ids.isEmpty else { return [] }
        let handles = try await BusinessHandleRecord.query(on: db).filter(\.$businessId ~~ ids).filter(\.$status == "active").all()
        let codes = try await BusinessCodeRecord.query(on: db).filter(\.$businessId ~~ ids).all()
        let handleByBusiness = Dictionary(handles.map { ($0.businessId, $0.handle) }, uniquingKeysWith: { first, _ in first })
        let codeByBusiness = Dictionary(codes.map { ($0.businessId, $0.canonical) }, uniquingKeysWith: { first, _ in first })
        return businesses.compactMap { business in
            guard let id = business.id, let canonical = codeByBusiness[id], let code = BusinessCode(parsing: canonical) else { return nil }
            return BusinessSummary(id: BusinessID(id), displayName: business.displayName,
                                   handle: handleByBusiness[id].flatMap { BusinessHandle(parsing: $0) }, code: code,
                                   verificationStatus: business.status)
        }
    }

    func summary(for business: BusinessRecord) async throws -> BusinessSummary? {
        try await summaries(for: [business]).first
    }

    func profile(for business: BusinessRecord) async throws -> BusinessProfile? {
        guard let summary = try await summary(for: business) else { return nil }
        return BusinessProfile(id: summary.id, displayName: summary.displayName, legalName: business.legalName, handle: summary.handle,
                               code: summary.code, verificationStatus: summary.verificationStatus, verifiedAt: business.verifiedAt,
                               category: BusinessCategory(rawValue: business.category),
                               brandColor: business.brandColor.flatMap(BrandColor.init), logoURL: business.logoURL.flatMap(URL.init(string:)),
                               websiteURL: business.websiteURL.flatMap(URL.init(string:)))
    }

    // MARK: Lookups (verified only)

    func verified(id: UUID) async throws -> BusinessRecord? {
        guard let business = try await BusinessRecord.find(id, on: db), business.isVerified else { return nil }
        return business
    }

    func verified(code: BusinessCode) async throws -> BusinessRecord? {
        guard let record = try await BusinessCodeRecord.query(on: db).filter(\.$canonical == code.canonical).first() else { return nil }
        return try await verified(id: record.businessId)
    }

    func verified(handle: BusinessHandle) async throws -> BusinessRecord? {
        guard let record = try await BusinessHandleRecord.query(on: db).filter(\.$handle == handle.value)
            .filter(\.$status == "active").first() else { return nil }
        return try await verified(id: record.businessId)
    }

    /// Name/handle search among verified businesses. Wildcard characters in the query are stripped, so the
    /// user cannot craft `LIKE` patterns.
    func search(_ query: String, limit: Int, offset: Int = 0) async throws -> [BusinessRecord] {
        let needle = Self.normalizeQuery(query)
        guard needle.count >= 2 else { return [] }
        let candidates = try await BusinessRecord.query(on: db)
            .filter(\.$verificationStatus == VerificationStatus.verified.rawValue)
            .filter(\.$searchText ~~ needle)
            .limit(200).all()
        let ranked = candidates.sorted { lhs, rhs in
            let l = Self.rank(lhs.searchText, needle), r = Self.rank(rhs.searchText, needle)
            return l == r ? lhs.displayName < rhs.displayName : l < r
        }
        return Array(ranked.dropFirst(offset).prefix(limit))
    }

    static func normalizeQuery(_ raw: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: " ._'&-"))
        let cleaned = raw.unicodeScalars.filter { allowed.contains($0) }
        return String(String.UnicodeScalarView(cleaned)).lowercased().trimmingCharacters(in: .whitespaces).prefix(64).description
    }

    private static func rank(_ text: String, _ needle: String) -> Int {
        if text == needle { return 0 }
        if text.hasPrefix(needle) { return 1 }
        if text.split(separator: " ").contains(where: { $0.hasPrefix(needle) }) { return 2 }
        return 3
    }
}

/// Business onboarding primitives (used by the seed command and tests; the dashboard comes in P5).
struct BusinessRegistry {
    let db: any Database
    let ctx: ServerContext

    enum RegistryError: Error, Equatable {
        case invalidHandle, handleTaken, confusableHandle, codeExhausted, codeUnavailable
    }

    /// Registers a business with a handle and a freshly issued permanent code.
    @discardableResult
    func register(displayName: String, legalName: String? = nil, handle rawHandle: String?, category: BusinessCategory,
                  status: VerificationStatus, tier: String = "free", dailyQuota: Int? = nil,
                  explicitCode: BusinessCode? = nil) async throws -> BusinessRecord {
        let now = ctx.now
        return try await db.transaction { tx in
            let business = BusinessRecord(displayName: String(displayName.prefix(80)), legalName: legalName, category: category,
                                          status: status, verifiedAt: status == .verified ? now : nil, tier: tier,
                                          dailyQuota: dailyQuota ?? ctx.config.freeDailyInteractionQuota, now: now)
            if let rawHandle {
                let handle: BusinessHandle
                do { handle = try BusinessHandle.validateForRegistration(rawHandle) } catch { throw RegistryError.invalidHandle }
                try await Self.checkHandleAvailable(handle, on: tx)
                business.searchText = (displayName + " " + handle.value).lowercased()
                try await business.create(on: tx)
                try await BusinessHandleRecord(businessId: business.id!, handle: handle, now: now).create(on: tx)
            } else {
                try await business.create(on: tx)
            }
            let code = try await Self.issueCode(for: business.id!, explicit: explicitCode, now: now, on: tx)
            _ = code
            return business
        }
    }

    static func checkHandleAvailable(_ handle: BusinessHandle, on db: any Database) async throws {
        if try await BusinessHandleRecord.query(on: db).filter(\.$handle == handle.value).first() != nil { throw RegistryError.handleTaken }
        if try await BusinessHandleRecord.query(on: db).filter(\.$skeleton == handle.confusableSkeleton).first() != nil {
            throw RegistryError.confusableHandle
        }
    }

    /// A random code that contains at least one digit. Typed input is classified as a *code* only when it has a digit
    /// (an all-letter string is more likely a business name), so an all-letter code could not be found by typing it.
    static func generateDiscoverableCode() -> BusinessCode {
        while true {
            let code = BusinessCode.generate()
            if code.canonical.contains(where: \.isNumber) { return code }
        }
    }

    /// Issues a code that has never been used by any business, active or retired (codes are never reassigned).
    static func issueCode(for businessId: UUID, explicit: BusinessCode?, now: Date, on db: any Database) async throws -> BusinessCode {
        for attempt in 0..<20 {
            let candidate = (attempt == 0 ? explicit : nil) ?? generateDiscoverableCode()
            let active = try await BusinessCodeRecord.query(on: db).filter(\.$canonical == candidate.canonical).count()
            let retired = try await RetiredBusinessCodeRecord.query(on: db).filter(\.$canonical == candidate.canonical).count()
            if active + retired == 0 {
                try await BusinessCodeRecord(businessId: businessId, code: candidate, now: now).create(on: db)
                return candidate
            }
            if explicit != nil && attempt == 0 { throw RegistryError.codeUnavailable }
        }
        throw RegistryError.codeExhausted
    }

    /// Retires the business's current code (kept forever in the retired table) and issues a new one.
    func rotateCode(businessId: UUID) async throws -> BusinessCode {
        let now = ctx.now
        return try await db.transaction { tx in
            if let current = try await BusinessCodeRecord.query(on: tx).filter(\.$businessId == businessId).first() {
                try await RetiredBusinessCodeRecord(businessId: businessId, canonical: current.canonical, now: now).create(on: tx)
                try await current.delete(on: tx)
            }
            return try await Self.issueCode(for: businessId, explicit: nil, now: now, on: tx)
        }
    }
}
