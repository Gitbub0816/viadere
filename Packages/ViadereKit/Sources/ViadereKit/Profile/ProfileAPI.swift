import Foundation
import ViadereCore

/// The customer-profile calls (docs/PROFILES.md). Separate from `ViadereAPI` so extensions and the App Clip build without it.
public protocol ProfileAPI: Sendable {
    func profile() async throws -> CustomerProfile
    func updateProfile(_ update: ProfileUpdateRequest) async throws -> CustomerProfile
    func access(business: BusinessID) async throws -> ProfileAccessView
    func setAccess(business: BusinessID, grantedKeys: [String]) async throws -> ProfileAccessView
    func requests(pendingOnly: Bool) async throws -> [ProfileRequestPrompt]
    func request(_ id: ProfileRequestID) async throws -> ProfileRequestPrompt
    func answer(_ id: ProfileRequestID, approvedKeys: [String]) async throws -> ProfileRequestPrompt
    func receipts() async throws -> [ProfileDisclosureReceipt]
    func beginVerification(_ begin: ProfileVerificationBegin) async throws -> ProfileVerificationStart
    func completeVerification(_ attempt: ProfileAttemptID, envelope: String?) async throws -> ProfileVerificationOutcome
    func removeVerifiedFacts(_ facts: [ProfileVerifiedFactKind]) async throws -> CustomerProfile
}

/// `ProfileAPI` over HTTP through the app's signed `APIClient`.
public struct LiveProfileAPI: ProfileAPI {
    let client: APIClient
    public init(client: APIClient) { self.client = client }

    public func profile() async throws -> CustomerProfile { try await client.call(APIRoutes.profileGet) }
    public func updateProfile(_ update: ProfileUpdateRequest) async throws -> CustomerProfile { try await client.call(APIRoutes.profilePut, body: update) }
    public func access(business: BusinessID) async throws -> ProfileAccessView {
        try await client.call(APIRoutes.profileAccessGet, params: ["businessId": business.description])
    }
    public func setAccess(business: BusinessID, grantedKeys: [String]) async throws -> ProfileAccessView {
        try await client.call(APIRoutes.profileAccessPut, params: ["businessId": business.description], body: ProfileAccessUpdate(grantedKeys: grantedKeys))
    }
    public func requests(pendingOnly: Bool) async throws -> [ProfileRequestPrompt] {
        try await client.call(APIRoutes.profileRequestsList, query: pendingOnly ? [("status", "pending")] : [])
    }
    public func request(_ id: ProfileRequestID) async throws -> ProfileRequestPrompt {
        try await client.call(APIRoutes.profileRequestGet, params: ["requestId": id.description])
    }
    public func answer(_ id: ProfileRequestID, approvedKeys: [String]) async throws -> ProfileRequestPrompt {
        try await client.call(APIRoutes.profileRequestAnswer, params: ["requestId": id.description], body: ProfileRequestAnswer(approvedKeys: approvedKeys))
    }
    public func receipts() async throws -> [ProfileDisclosureReceipt] { try await client.call(APIRoutes.profileReceiptsList) }
    public func beginVerification(_ begin: ProfileVerificationBegin) async throws -> ProfileVerificationStart {
        try await client.call(APIRoutes.profileVerificationBegin, body: begin)
    }
    public func completeVerification(_ attempt: ProfileAttemptID, envelope: String?) async throws -> ProfileVerificationOutcome {
        try await client.call(APIRoutes.profileVerificationComplete, params: ["attemptId": attempt.description], body: ProfileVerificationComplete(envelope: envelope))
    }
    public func removeVerifiedFacts(_ facts: [ProfileVerifiedFactKind]) async throws -> CustomerProfile {
        try await client.call(APIRoutes.profileVerificationRemove, body: ProfileVerifiedFactsRemove(facts: facts))
    }
}

extension LiveProfileAPI {
    /// A client that shares the app's session, device keys and certificate pinning.
    public static func make(services: ViadereServices) -> LiveProfileAPI {
        let transport = URLSessionTransport(configuration: services.configuration)
        let signer = DeviceRequestSigner(records: services.records, keys: services.keys, clock: services.clock)
        let executor = RequestExecutor(baseURL: services.configuration.apiBaseURL, transport: transport, signer: signer)
        let revocation = services.revocation
        return LiveProfileAPI(client: APIClient(executor: executor, sessions: services.sessions, onDeviceRejected: { revocation.notify() }))
    }
}

/// An in-memory `ProfileAPI` for previews and tests. It applies the catalog and the access policy like the server does, so view models are
/// tested against the same rules.
public actor MockProfileAPI: ProfileAPI {
    public private(set) var stored = CustomerProfile(publicName: nil, customPublicName: nil, derivedPublicName: nil, fields: [], verified: [])
    public var accountName: String?
    public var allowed: [BusinessID: Set<ProfileCategory>] = [:]
    public var names: [BusinessID: String] = [:]
    public var grants: [BusinessID: [String: Date]] = [:]
    public var pending: [ProfileRequestPrompt] = []
    public var receiptLog: [ProfileDisclosureReceipt] = []
    public var now: Date
    public var failNext: APIError?

    public init(accountName: String? = nil, now: Date = Date(timeIntervalSince1970: 1_800_000_000)) {
        self.accountName = accountName
        self.now = now
        stored = Self.recompute(stored, accountName: accountName)
    }

    public func connect(_ business: BusinessID, name: String, allowed categories: Set<ProfileCategory>) {
        names[business] = name
        allowed[business] = categories
    }

    public func addRequest(_ prompt: ProfileRequestPrompt) { pending.append(prompt) }
    public func setVerified(_ facts: [ProfileVerifiedFact]) { stored.verified = facts }
    public func fail(with error: APIError) { failNext = error }

    private func check() throws {
        if let error = failNext { failNext = nil; throw error }
    }

    private static func recompute(_ profile: CustomerProfile, accountName: String?) -> CustomerProfile {
        var p = profile
        func text(_ key: String) -> String? { if case .text(let v)? = p.fields.first(where: { $0.key == key })?.value { v } else { nil } }
        p.derivedPublicName = PublicName.derive(givenName: text("personal.given_name"), familyName: text("personal.family_name")) ?? PublicName.derive(fullName: accountName)
        p.publicName = p.customPublicName ?? p.derivedPublicName
        return p
    }

    public func profile() async throws -> CustomerProfile { try check(); return stored }

    public func updateProfile(_ update: ProfileUpdateRequest) async throws -> CustomerProfile {
        try check()
        var next = stored
        if let custom = update.customPublicName {
            if let issue = PublicName.validate(custom) { throw APIError.server(status: 422, code: .validationFailed, message: "That public name can't be used. (\(issue.rawValue))") }
            next.customPublicName = PublicName.clean(custom)
        }
        if update.useDerivedPublicName == true { next.customPublicName = nil }
        for ref in update.remove { next.fields.removeAll { $0.key == ref.key && $0.entry == ref.entry } }
        for entry in update.set {
            do {
                let value = try ProfileCatalog.validate(key: entry.key, entry: entry.entry, value: entry.value)
                let label = try ProfileCatalog.validateEntry(entry.entry, for: ProfileCatalog.definition(for: entry.key)!)
                next.fields.removeAll { $0.key == entry.key && $0.entry == label }
                next.fields.append(ProfileFieldEntry(key: entry.key, entry: label, value: value, updatedAt: now))
            } catch let issue as ProfileValueIssue {
                throw APIError.server(status: 422, code: .validationFailed, message: "A profile value is not valid. (\(issue.rawValue))")
            }
        }
        next.fields.sort { ($0.key, $0.entry ?? "") < ($1.key, $1.entry ?? "") }
        stored = Self.recompute(next, accountName: accountName)
        return stored
    }

    private func view(_ business: BusinessID) throws -> ProfileAccessView {
        guard let name = names[business] else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        let categories = allowed[business] ?? []
        let granted = grants[business] ?? [:]
        let keys = ProfileCatalog.fields.map(\.key).filter { (ProfileCatalog.category(of: $0).map(categories.contains) ?? false) || granted[$0] != nil }
        return ProfileAccessView(businessId: business, businessName: name, publicName: stored.publicName, allowedCategories: categories.sorted(),
                                 fields: keys.map { ProfileAccessField(key: $0, granted: granted[$0] != nil, grantedAt: granted[$0],
                                                                       hasValue: ProfileRules.hasValue($0, in: stored)) })
    }

    public func access(business: BusinessID) async throws -> ProfileAccessView { try check(); return try view(business) }

    public func setAccess(business: BusinessID, grantedKeys: [String]) async throws -> ProfileAccessView {
        try check()
        let current = Set((grants[business] ?? [:]).keys)
        let wanted = Set(grantedKeys)
        let refused = ProfileAccessPolicy.disallowed(Array(wanted.subtracting(current)), allowed: allowed[business] ?? [])
        guard refused.isEmpty else { throw APIError.server(status: 422, code: .validationFailed, message: "This business can't receive some of these fields.") }
        var next: [String: Date] = [:]
        for key in wanted { next[key] = grants[business]?[key] ?? now }
        grants[business] = next
        let name = names[business] ?? ""
        if !wanted.subtracting(current).isEmpty {
            receiptLog.insert(ProfileDisclosureReceipt(id: ProfileReceiptID(), businessId: business, businessName: name, action: .granted,
                                                       fieldKeys: wanted.subtracting(current).sorted(), purpose: nil, requestId: nil, createdAt: now), at: 0)
        }
        if !current.subtracting(wanted).isEmpty {
            receiptLog.insert(ProfileDisclosureReceipt(id: ProfileReceiptID(), businessId: business, businessName: name, action: .revoked,
                                                       fieldKeys: current.subtracting(wanted).sorted(), purpose: nil, requestId: nil, createdAt: now), at: 0)
        }
        return try view(business)
    }

    public func requests(pendingOnly: Bool) async throws -> [ProfileRequestPrompt] {
        try check()
        return pendingOnly ? pending.filter { $0.isActionable(at: now) } : pending
    }

    public func request(_ id: ProfileRequestID) async throws -> ProfileRequestPrompt {
        try check()
        guard let found = pending.first(where: { $0.id == id }) else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        return found
    }

    public func answer(_ id: ProfileRequestID, approvedKeys: [String]) async throws -> ProfileRequestPrompt {
        try check()
        guard let index = pending.firstIndex(where: { $0.id == id }) else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        var prompt = pending[index]
        guard prompt.isActionable(at: now) else { throw APIError.server(status: 409, code: .conflict, message: "This request is no longer open.") }
        guard Set(approvedKeys).isSubset(of: Set(prompt.fields.map(\.key))) else {
            throw APIError.server(status: 422, code: .validationFailed, message: "Only fields the business asked for can be approved.")
        }
        prompt.status = approvedKeys.isEmpty ? .declined : .answered
        prompt.approvedKeys = approvedKeys.sorted()
        pending[index] = prompt
        let business = prompt.business.id
        for key in approvedKeys { grants[business, default: [:]][key] = now }
        return prompt
    }

    public func receipts() async throws -> [ProfileDisclosureReceipt] { try check(); return receiptLog }

    public func beginVerification(_ begin: ProfileVerificationBegin) async throws -> ProfileVerificationStart {
        try check()
        return ProfileVerificationStart(attemptId: ProfileAttemptID(), method: begin.method, nonce: begin.method == .wallet ? "bm9uY2U" : nil,
                                        merchantIdentifier: begin.method == .wallet ? "merchant.test" : nil, requestedElements: ["issuing_authority"],
                                        sessionToken: begin.method == .document ? "session-token" : nil, expiresAt: now.addingTimeInterval(300))
    }

    public func completeVerification(_ attempt: ProfileAttemptID, envelope: String?) async throws -> ProfileVerificationOutcome {
        try check()
        let fact = ProfileVerifiedFact(fact: .identity, method: .walletMdoc, verifiedAt: now, assurance: "issuer_signed_credential_device_bound", policyVersion: VerifyPolicy.version)
        stored.verified = [fact]
        return ProfileVerificationOutcome(status: .verified, facts: [fact])
    }

    public func removeVerifiedFacts(_ facts: [ProfileVerifiedFactKind]) async throws -> CustomerProfile {
        try check()
        stored.verified.removeAll { facts.isEmpty || facts.contains($0.fact) }
        return stored
    }
}
