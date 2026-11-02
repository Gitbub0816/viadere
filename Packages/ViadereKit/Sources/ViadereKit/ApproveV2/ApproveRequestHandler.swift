import Crypto
import Foundation
import ViadereCore

/// How much the app can say about where a request's details came from.
public enum RequestAssurance: Sendable, Equatable {
    /// Decrypted on this device and signed by a key the business published in the verified key directory: the relay could not read or alter it.
    case endToEndSigned
    /// The relay held the details in the clear and nothing but the business's API credential vouches for them. The screen says so.
    case relayAsserted
}

/// A request that passed every check on this device, ready to show.
public struct ApprovalPrompt: Identifiable, Sendable, Equatable {
    public var id: UUID
    public var request: ApproveDeviceRequest
    public var content: ApprovalRequestContent
    public var assurance: RequestAssurance
    public var key: LocalApprovalKey
    public var business: BusinessSummary { request.business }
    /// SEC-DEV-008: "You've received several requests" (the relay's count, or this device's own, whichever is higher).
    public var showFatigueWarning: Bool
    public var requestsInWindow: Int
    /// The line shown on the Face ID sheet.
    public var promptReason: String {
        switch content.details {
        case .transaction(let t): "Approve \(MoneyFormatting.display(minor: t.amountMinor, currency: t.currency)) to \(t.payeeDisplay)"
        case .authentication(let a): a.actionDisplay
        }
    }

    public static func == (lhs: ApprovalPrompt, rhs: ApprovalPrompt) -> Bool { lhs.id == rhs.id && lhs.content == rhs.content && lhs.assurance == rhs.assurance }
}

/// A request that failed verification and was hidden: shown as a security notice, not as a prompt.
public struct RejectedRequest: Identifiable, Sendable, Equatable {
    public var id: UUID
    public var requestId: String
    public var businessName: String
    public var reason: String
}

/// Loads, verifies, displays and answers approval requests on the device (APP-003, APP-004, SEC-CR-004).
public struct ApproveRequestHandler: Sendable, NumberMatchAttemptRecording {
    private let api: any ApproveAPI
    private let vault: any ApprovalKeyVault
    private let store: any ApproveLocalStore
    private let directory: BusinessDirectoryClient
    private let policy: ApprovalPromptPolicy
    private let clock: @Sendable () -> Date
    private let assertion: AssertionSource?

    public init(api: any ApproveAPI, vault: any ApprovalKeyVault, store: any ApproveLocalStore, directory: BusinessDirectoryClient,
                policy: ApprovalPromptPolicy = .standard, clock: @escaping @Sendable () -> Date = { Date() }, assertion: AssertionSource? = nil) {
        self.api = api
        self.vault = vault
        self.store = store
        self.directory = directory
        self.policy = policy
        self.clock = clock
        self.assertion = assertion
    }

    public struct Loaded: Sendable {
        public var prompts: [ApprovalPrompt]
        public var rejected: [RejectedRequest]
    }

    /// Fetches the requests addressed to this device and verifies each one independently of the relay.
    public func load() async throws -> Loaded {
        let requests: [ApproveDeviceRequest]
        do { requests = try await api.requests() } catch let error as APIError { throw ApproveError.api(error) }
        let local = try await store.load()
        var prompts: [ApprovalPrompt] = []
        var rejected: [RejectedRequest] = []
        var directories: [BusinessID: Result<DirectoryCheck, ApproveError>] = [:]
        for request in requests where request.status == .pending && request.expiresAt > clock() {
            guard let key = local.keys.first(where: { $0.kid == request.kid && $0.status == .active }) else { continue }
            do {
                // A business whose root changed or is contradicted asks for nothing until the person has dealt with it.
                if let alert = try await directory.alert(for: key.businessId) {
                    throw ApproveError.requestRejected(alert == .rootConflict ? "root_conflict" : "root_changed")
                }
                let prompt = try await verify(request, key: key, local: local, directories: &directories)
                prompts.append(prompt)
            } catch let error as ApproveError {
                rejected.append(RejectedRequest(id: request.id, requestId: request.requestId, businessName: key.businessName, reason: Self.describe(error)))
            } catch {
                rejected.append(RejectedRequest(id: request.id, requestId: request.requestId, businessName: key.businessName, reason: "unverifiable"))
            }
        }
        // R4-02: wrong-entry counts live as long as their request is open.
        let open = Set(prompts.map(\.request.requestId))
        if let attempts = local.matchAttempts, !Set(attempts.keys).isSubset(of: open) {
            try? await store.update { state in state.matchAttempts = state.matchAttempts?.filter { open.contains($0.key) } }
        }
        return Loaded(prompts: prompts, rejected: rejected)
    }

    private func verify(_ request: ApproveDeviceRequest, key: LocalApprovalKey, local: ApproveLocalState,
                        directories: inout [BusinessID: Result<DirectoryCheck, ApproveError>]) async throws -> ApprovalPrompt {
        let now = clock()
        // The business the person enrolled with is the only business this key serves, whatever the relay labels the request.
        guard request.business.id == key.businessId, request.subjectRef == key.subject else { throw ApproveError.requestRejected("misattributed") }
        let content: ApprovalRequestContent
        let assurance: RequestAssurance
        switch request.protection {
        case .endToEnd:
            guard let envelope = request.envelope, let hpke = try await vault.hpkeKey(enrollment: key.enrollmentId) else { throw ApproveError.requestRejected("missing_envelope") }
            let plaintext: Data
            do {
                plaintext = try E2EE.open(envelope, using: hpke, expecting: E2EEExpectation(purpose: "approve.request", requestId: request.requestId,
                                                                                            sender: "biz_" + key.businessId.description, recipient: "ak_" + key.kid), now: now)
            } catch { throw ApproveError.requestRejected("decryption_failed") }
            let check = try await directoryCheck(for: key.businessId, cache: &directories)
            let signed: BusinessSignedStatement
            do { signed = try ApprovalRequestContent.parseSigned(plaintext) } catch { throw ApproveError.requestRejected("malformed") }
            guard let signingKey = check.state.validKey(kid: signed.kid, purpose: .approvalRequestSigning, at: now)?.signingKey else { throw ApproveError.requestRejected("signer_not_published") }
            do {
                content = try ApprovalRequestContent.verify(signed, signingKey: signingKey, expectedBusiness: key.businessId, expectedSubject: key.subject, expectedKid: key.kid,
                                                            expectedRequestId: request.requestId, now: now)
            } catch { throw ApproveError.requestRejected("signature_or_binding_invalid") }
            assurance = .endToEndSigned
        case .serverVisible, .unknown:
            guard request.protection == .serverVisible, let challenge = request.challenge, ChallengeNonce(challenge) != nil else { throw ApproveError.requestRejected("malformed") }
            let details: ApprovalSubject
            switch (request.capability, request.transaction, request.authentication) {
            case (.transactionApprove, let transaction?, nil): details = .transaction(transaction)
            case (.authChallenge, nil, let authentication?): details = .authentication(authentication)
            default: throw ApproveError.requestRejected("malformed")
            }
            do { try details.validate() } catch { throw ApproveError.requestRejected("invalid_details") }
            // Number matching on a server-visible request (ADR-0022 §2.2): the relay holds the code. The requirement is also in the digest the business checks
            // (`match_digits`), so a relay that strips it breaks the business's verification; a requirement without a usable code is refused here.
            var numberMatch: ApprovalNumberMatch?
            if let carried = request.numberMatch {
                guard let code = carried.code, ApprovalNumberMatch.isValid(code: code, digits: carried.digits) else { throw ApproveError.requestRejected("malformed_number_match") }
                numberMatch = ApprovalNumberMatch(digits: carried.digits, code: code)
            }
            if case .authentication(let a) = details, a.matchDigits != numberMatch?.digits { throw ApproveError.requestRejected("malformed_number_match") }
            content = ApprovalRequestContent(businessId: key.businessId, subject: key.subject, requestId: request.requestId, challenge: challenge, details: details, toKid: key.kid,
                                            issuedAt: request.createdAt, expiresAt: request.expiresAt, numberMatch: numberMatch)
            assurance = .relayAsserted
        }
        guard content.expiresAtDate > now else { throw ApproveError.expired }
        // The relay's count, and this device's own record of what it answered recently.
        let recent = local.decisions.filter { $0.businessId == key.businessId && now.timeIntervalSince($0.at) < policy.window }.count
        let count = max(request.requestsInWindow, recent + 1)
        return ApprovalPrompt(id: request.id, request: request, content: content, assurance: assurance, key: key,
                              showFatigueWarning: request.showFatigueWarning || count >= policy.warnAtRequests, requestsInWindow: count)
    }

    private func directoryCheck(for businessId: BusinessID, cache: inout [BusinessID: Result<DirectoryCheck, ApproveError>]) async throws -> DirectoryCheck {
        if let cached = cache[businessId] { return try cached.get() }
        do {
            let check = try await directory.verify(businessId: businessId)
            cache[businessId] = .success(check)
            return check
        } catch let error as ApproveError {
            cache[businessId] = .failure(error)
            throw error
        }
    }

    // MARK: Answer

    /// Signs the answer with the pairwise key — **over exactly the content that was displayed** — and sends it. The Face ID sheet names the
    /// business and the amount. Denying and reporting are signed too: they are results a business can verify.
    public func answer(_ prompt: ApprovalPrompt, decision: ApprovalDecision, numberMatch: ApprovalNumberMatchAnswer? = nil) async throws -> ApprovalRequestStatus {
        let now = clock()
        guard prompt.content.expiresAtDate > now else { throw ApproveError.expired }
        if decision == .approve, let alert = try await directory.alert(for: prompt.key.businessId) {
            throw alert == .rootConflict ? ApproveError.rootConflict(prompt.key.businessId) : ApproveError.rootChanged(prompt.key.businessId)
        }
        guard let key = try await vault.approvalKey(enrollment: prompt.key.enrollmentId) else { throw ApproveError.keyMissing }
        guard key.publicKey == (try? ApprovalEnrollmentStatement.verify(prompt.key.statement).publicKey) else { throw ApproveError.keyMissing }
        let verb: String
        switch decision {
        case .approve: verb = prompt.promptReason
        case .deny: verb = "Decline the request from \(prompt.business.displayName)"
        case .report: verb = "Report the request from \(prompt.business.displayName) as suspicious"
        }
        let amr: ApprovalAMR = prompt.key.assurance
        let jws: String
        do {
            jws = try await ApprovalResultFactory.sign(displayed: prompt.content, decision: decision, amr: amr, key: PromptBoundKey(key, prompt: SigningPrompt(reason: verb)), now: now,
                                                       numberMatch: numberMatch)
        } catch let error as KeyStoreError {
            switch error {
            case .userCancelled: throw ApproveError.userCancelled
            case .authenticationFailed: throw ApproveError.authenticationFailed
            case .keyInvalidated, .keyNotFound: throw ApproveError.keyMissing
            default: throw ApproveError.keysUnavailable
            }
        }
        let status: ApprovalRequestStatus
        // An attested device asserts over exactly this result (WP-C2); the relay rebuilds the same client data from the route and the body.
        let assertionValue = await assertion?(ApprovalAppAttest.clientData(deliveryId: prompt.id, result: jws))
        do { status = try await api.submitResult(id: prompt.id, result: jws, appAttestAssertion: assertionValue).status } catch let error as APIError {
            switch error.code {
            case .approvalsFrozen?: throw ApproveError.frozen
            case .expired?, .gone?: throw ApproveError.expired
            default: throw ApproveError.api(error)
            }
        }
        let businessId = prompt.key.businessId
        try await store.update { $0.decisions.append(LocalDecision(businessId: businessId, at: now, decision: decision)); $0.decisions = Array($0.decisions.suffix(200)) }
        return status
    }

    // MARK: Wrong number entries (R4-02)

    /// The persisted wrong-entry count of a group: the highest count of any of its open requests.
    public func wrongEntries(requestIds: [String]) async -> Int {
        let attempts = (try? await store.load())?.matchAttempts ?? [:]
        return requestIds.map { attempts[$0] ?? 0 }.max() ?? 0
    }

    /// Records one more wrong entry for every request of the group and returns the new count.
    @discardableResult
    public func recordWrongEntry(requestIds: [String]) async -> Int {
        let current = await wrongEntries(requestIds: requestIds)
        let next = min(current + 1, NumberMatchAttemptLimit.max)
        try? await store.update { state in
            var attempts = state.matchAttempts ?? [:]
            for id in requestIds { attempts[id] = next }
            state.matchAttempts = attempts
        }
        return next
    }

    static func describe(_ error: ApproveError) -> String {
        switch error {
        case .requestRejected(let reason): reason
        case .rootChanged: "root_changed"
        case .rootConflict: "root_conflict"
        case .directory(let error): "directory_\(error)"
        default: "unverifiable"
        }
    }
}
