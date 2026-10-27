import Foundation
import ViadereCore

/// An in-memory Verify server for previews and tests. It follows the real server's rules where they matter to the client logic: consent
/// needs the digest of what was shown, attempts need consent, a nonce is single-use, a withdrawn receipt ends the request.
public actor MockVerifyAPI: VerifyAPI {
    public private(set) var prompts: [VerificationRequestID: VerificationPrompt] = [:]
    private var history: [VerificationHistoryItem] = []
    private var nonces: [UUID: (request: VerificationRequestID, nonce: String)] = [:]
    public private(set) var consentLog: [(VerificationRequestID, String)] = []
    public private(set) var walletEnvelopes: [Data] = []
    public private(set) var declined: [VerificationRequestID] = []
    public private(set) var documentBegins = 0
    /// What the next completion answers (default: released).
    public var walletOutcome = VerificationAttemptOutcome(status: .released, label: .verifiedAgeThreshold, receiptId: UUID(), canRetry: false)
    public var documentOutcome = VerificationAttemptOutcome(status: .released, label: .verifiedAgeThreshold, receiptId: UUID(), canRetry: false)
    public var failNext: APIError?
    public var walletAvailableOnServer = true
    public var documentAvailableOnServer = true

    public init() {}

    public func add(_ prompt: VerificationPrompt) { prompts[prompt.id] = prompt }
    public func setHistory(_ items: [VerificationHistoryItem]) { history = items }
    public func setWalletOutcome(_ outcome: VerificationAttemptOutcome) { walletOutcome = outcome }
    public func setDocumentOutcome(_ outcome: VerificationAttemptOutcome) { documentOutcome = outcome }
    public func setFailure(_ error: APIError?) { failNext = error }

    private func check() throws {
        if let error = failNext {
            failNext = nil
            throw error
        }
    }

    private func current(_ id: VerificationRequestID) throws -> VerificationPrompt {
        guard var prompt = prompts[id] else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        prompt.methods = [VerificationMethodOption(kind: .wallet, available: walletAvailableOnServer), VerificationMethodOption(kind: .document, available: documentAvailableOnServer)]
        return prompt
    }

    public func list() async throws -> VerificationListResponse {
        try check()
        return VerificationListResponse(pending: prompts.values.filter { $0.status.isOpen }.sorted { $0.createdAt > $1.createdAt }, history: history)
    }

    public func prompt(_ id: VerificationRequestID) async throws -> VerificationPrompt {
        try check()
        return try current(id)
    }

    public func consent(_ id: VerificationRequestID, displayDigest: String) async throws -> VerificationPrompt {
        try check()
        var prompt = try current(id)
        guard prompt.status == .pendingConsent else { throw APIError.server(status: 409, code: .conflict, message: "answered") }
        guard prompt.displayDigest == displayDigest else { throw APIError.server(status: 409, code: .conflict, message: "changed") }
        consentLog.append((id, displayDigest))
        prompt.status = .consented
        prompt.receiptId = UUID()
        prompts[id] = prompt
        return prompt
    }

    public func decline(_ id: VerificationRequestID) async throws {
        try check()
        declined.append(id)
        prompts[id]?.status = .declined
    }

    public func revoke(_ id: VerificationRequestID) async throws -> VerificationHistoryItem {
        try check()
        guard let index = history.firstIndex(where: { $0.id == id }) else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        guard history[index].revocable else { throw APIError.server(status: 409, code: .conflict, message: "already made") }
        history[index].status = .revoked
        history[index].revocable = false
        return history[index]
    }

    public func beginWallet(_ id: VerificationRequestID) async throws -> WalletAttemptStart {
        try check()
        let prompt = try current(id)
        guard prompt.status == .consented else { throw APIError.server(status: 409, code: .conflict, message: "consent first") }
        let attempt = UUID()
        let nonce = Base64URL.encode(SecureToken.randomBytes(32))
        nonces[attempt] = (id, nonce)
        return WalletAttemptStart(attemptId: attempt, nonce: nonce, merchantIdentifier: "merchant.com.viadere.test", expiresAt: Date().addingTimeInterval(300))
    }

    public func completeWallet(_ id: VerificationRequestID, attemptId: UUID, envelope: Data) async throws -> VerificationAttemptOutcome {
        try check()
        // Single use: the nonce is spent by the first completion.
        guard nonces.removeValue(forKey: attemptId)?.request == id else { return VerificationAttemptOutcome(status: .consented, label: nil, receiptId: nil, canRetry: true) }
        walletEnvelopes.append(envelope)
        prompts[id]?.status = walletOutcome.status
        return walletOutcome
    }

    public func beginDocument(_ id: VerificationRequestID) async throws -> DocumentAttemptStart {
        try check()
        documentBegins += 1
        return DocumentAttemptStart(attemptId: UUID(), sessionToken: "token-for-tests", expiresAt: Date().addingTimeInterval(600))
    }

    public func completeDocument(_ id: VerificationRequestID, attemptId: UUID) async throws -> VerificationAttemptOutcome {
        try check()
        prompts[id]?.status = documentOutcome.status
        return documentOutcome
    }
}

extension VerificationPrompt {
    /// A preview/test prompt for an age threshold.
    public static func sampleAge(years: Int64 = 21, business: String = "Northwind Spirits", expiresIn: TimeInterval = 300, now: Date = Date()) -> VerificationPrompt {
        let id = VerificationRequestID()
        let businessId = BusinessID()
        let parameters: [String: JSONValue] = ["years": .integer(years)]
        let digest = VerificationPrompt.displayDigest(requestId: id, businessId: businessId, recipientName: business, capability: .ageMinimum, parameters: parameters,
                                                      purposeCode: "age_restricted_access", fields: ["meets_threshold"], expiresAt: now.addingTimeInterval(expiresIn))
        return VerificationPrompt(
            id: id, status: .pendingConsent, businessId: businessId, recipientName: business, recipientHandle: "@northwind", recipientVerified: true, capability: .ageMinimum,
            parameters: parameters, purposeCode: "age_restricted_access", disclosure: VerificationPromptContent.disclosure(for: .ageMinimum, parameters: parameters),
            notDisclosed: VerificationPromptContent.notDisclosed(for: .ageMinimum), includedMetadata: VerificationPromptContent.metadata,
            methods: [VerificationMethodOption(kind: .wallet, available: true), VerificationMethodOption(kind: .document, available: true)], createdAt: now,
            expiresAt: now.addingTimeInterval(expiresIn), displayDigest: digest)
    }
}
