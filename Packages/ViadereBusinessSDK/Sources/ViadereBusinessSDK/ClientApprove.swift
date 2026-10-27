import Crypto
import Foundation
import ViadereCore

/// An enrollment you verified and confirmed: **store this in your own database.** `key` is what `ApprovalVerifier` needs; `hpke` is where
/// you encrypt end-to-end requests to this device.
public struct ConfirmedEnrollment: Sendable, Hashable {
    public var key: EnrolledApprovalKey
    /// The device's per-relationship HPKE key, authenticated by the device's own signature over the statement.
    public var hpke: E2EEPublicKey
    /// The device's signed statement, kept as evidence.
    public var statement: SignedStatement
    public var enrollmentId: UUID

    public var kid: String { key.kid }
    public var target: ApprovalDeviceTarget { ApprovalDeviceTarget(kid: key.kid, hpkePublicKey: hpke) }
}

/// A device to deliver an end-to-end request to.
public struct ApprovalDeviceTarget: Sendable, Hashable {
    public var kid: String
    public var hpkePublicKey: E2EEPublicKey
    public init(kid: String, hpkePublicKey: E2EEPublicKey) {
        self.kid = kid
        self.hpkePublicKey = hpkePublicKey
    }
}

/// Builds approval requests.
public struct ApprovalRequestBuilder: Sendable {
    public let businessId: BusinessID
    private let requestSigningKey: (any DeviceSigningKey)?
    private let clock: @Sendable () -> Date

    /// - Parameter requestSigningKey: your published `approval-request-signing` key. Required for end-to-end requests, which the device accepts
    ///   only if this key signed them.
    public init(businessId: BusinessID, requestSigningKey: (any DeviceSigningKey)? = nil, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.businessId = businessId
        self.requestSigningKey = requestSigningKey
        self.clock = clock
    }

    /// A fresh `challenge`: 256 random bits, base64url. Never reuse one.
    public static func newChallenge() -> String { SecureToken.generate(byteCount: 32) }

    /// A fresh `request_id`.
    public static func newRequestId() -> String { "req_" + SecureToken.generate(byteCount: 16) }

    /// Spec 14.2: the details travel to Viadere in the clear (the app marks such requests as not end-to-end protected).
    public func serverVisible(requestId: String, subject: SubjectRef, challenge: String, details: ApprovalSubject, expiresIn: Int = 120) throws -> CreateApprovalRequest {
        try details.validate()
        switch details {
        case .transaction(let transaction):
            return CreateApprovalRequest(requestId: requestId, subjectRef: subject, capability: .transactionApprove, challenge: challenge, transaction: transaction, expiresInSeconds: expiresIn)
        case .authentication(let authentication):
            return CreateApprovalRequest(requestId: requestId, subjectRef: subject, capability: .authChallenge, challenge: challenge, authentication: authentication, expiresInSeconds: expiresIn)
        }
    }

    /// End to end: the request is signed with your request-signing key and HPKE-encrypted **once per device**; Viadere relays ciphertext only.
    public func endToEnd(requestId: String, subject: SubjectRef, challenge: String, details: ApprovalSubject, devices: [ApprovalDeviceTarget], expiresIn: Int = 120) async throws -> CreateApprovalRequest {
        guard let requestSigningKey else { throw ApprovalRequestBuilderError.requestSigningKeyRequired }
        guard !devices.isEmpty else { throw ApprovalRequestBuilderError.noDevices }
        try details.validate()
        let now = clock()
        let expires = now.addingTimeInterval(TimeInterval(expiresIn))
        var deliveries: [ApprovalEnvelopeDelivery] = []
        for device in devices {
            let content = ApprovalRequestContent(businessId: businessId, subject: subject, requestId: requestId, challenge: challenge, details: details, toKid: device.kid, issuedAt: now, expiresAt: expires)
            let plaintext = try await content.sealedPlaintext(signedWith: requestSigningKey)
            let context = E2EEContext(purpose: "approve.request", requestId: requestId, sender: "biz_" + businessId.description, recipient: "ak_" + device.kid, expiresAt: expires)
            deliveries.append(ApprovalEnvelopeDelivery(kid: device.kid, envelope: try E2EE.seal(plaintext, to: device.hpkePublicKey, context: context)))
        }
        return CreateApprovalRequest(requestId: requestId, subjectRef: subject, capability: details.capability, envelopes: deliveries, expiresInSeconds: expiresIn)
    }
}

public enum ApprovalRequestBuilderError: Error, Sendable, Equatable {
    case requestSigningKeyRequired
    case noDevices
}

/// Failures while confirming an enrollment, before anything is sent to Viadere.
public enum ApprovalEnrollmentFailure: Error, Sendable, Equatable {
    /// The device has not completed the enrollment yet.
    case notReady
    case invalidStatement(ApprovalEnrollmentError)
    /// The statement is not for this enrollment, customer or business.
    case bindingMismatch(ApprovalEnrollmentError)
    /// The key is weaker than your policy requires.
    case assuranceTooLow
}

extension ViadereBusinessClient {
    // MARK: Key directory (scope `keydirectory:manage`, live key)

    /// Publishes one signed entry (`POST /v1/business/key-directory/entries`). Not retried automatically: a repeated entry would be refused anyway.
    @discardableResult
    public func publishKeyEntry(_ entry: KeyLogEntry) async throws -> PublishKeyEntryResponse {
        try decode(PublishKeyEntryResponse.self, try await perform(APIRoutes.businessKeyDirectoryPublish.descriptor, body: PublishKeyEntryRequest(entry: Base64URL.encode(try entry.leafData()))))
    }

    /// Your own log entries with proofs (`GET /v1/business/key-directory/entries`). `since` is the tree size you last verified.
    public func keyDirectoryEntries(since: Int? = nil) async throws -> KeyDirectoryResponse {
        try decode(KeyDirectoryResponse.self, try await perform(APIRoutes.businessKeyDirectoryEntries.descriptor, query: since.map { [("since", String($0))] } ?? []))
    }

    /// Fetches and **verifies** your directory page against the Viadere log key you pinned, and returns the state (next serial, current root).
    public func verifiedKeyDirectory(businessId: BusinessID, logKeys: [DevicePublicKey], logId: String = TransparencyLog.defaultLogId, lastSeen: SeenTreeHead? = nil,
                                     now: Date = Date()) async throws -> KeyDirectoryState {
        let response = try await keyDirectoryEntries(since: lastSeen?.treeSize)
        let verified = try KeyDirectoryVerifier(logKeys: logKeys, logId: logId).verify(response, businessId: businessId, lastSeen: lastSeen, now: now)
        return KeyDirectoryState(head: verified.head, state: verified.state)
    }

    // MARK: Enrollment (scope `approvals:manage`, capability `auth.challenge` or `transaction.approve`)

    /// Starts an enrollment for a customer you already have a relationship with. Show `ticket.code` (as `ABCD-EFGH`) or a QR of `ticket.deepLink`
    /// in **your own signed-in session**. Never send it by SMS or email.
    public func createApprovalEnrollment(subject: SubjectRef, capability: Capability, expiresIn: Int? = nil) async throws -> ApprovalEnrollmentTicket {
        try decode(ApprovalEnrollmentTicket.self, try await perform(APIRoutes.businessApproveEnrollmentCreate.descriptor,
                                                                    body: CreateApprovalEnrollmentRequest(subjectRef: subject, capability: capability, expiresInSeconds: expiresIn)))
    }

    public func approvalEnrollment(id: UUID) async throws -> ApprovalEnrollmentView {
        try decode(ApprovalEnrollmentView.self, try await perform(APIRoutes.businessApproveEnrollmentGet.descriptor, parameters: ["enrollmentId": id.uuidString.lowercased()]))
    }

    @discardableResult
    public func cancelApprovalEnrollment(id: UUID) async throws -> ApprovalEnrollmentView {
        try decode(ApprovalEnrollmentView.self, try await perform(APIRoutes.businessApproveEnrollmentCancel.descriptor, parameters: ["enrollmentId": id.uuidString.lowercased()],
                                                                  body: Optional<EmptyBody>.none, naturallyIdempotent: true))
    }

    /// Verifies the device's enrollment statement **yourself** and, if it is right, confirms it with your `approval-enrollment-confirmation` key.
    ///
    /// Returns the enrollment to store (`ConfirmedEnrollment`): from now on your records, not the relay's, decide which key may approve.
    /// - Parameters:
    ///   - businessId: your business id: the statement must name it.
    ///   - expectedSubject: the customer you started the enrollment for.
    ///   - minimumAssurance: refuse keys weaker than this (default `.biometric`).
    public func confirmApprovalEnrollment(id: UUID, businessId: BusinessID, expectedSubject: SubjectRef, confirmationKey: any DeviceSigningKey, minimumAssurance: ApprovalAMR = .biometric,
                                          now: Date = Date()) async throws -> ConfirmedEnrollment {
        let view = try await approvalEnrollment(id: id)
        guard view.status == .deviceCompleted, let signed = view.deviceStatement else { throw ApprovalEnrollmentFailure.notReady }
        let statement: ApprovalEnrollmentStatement
        do { statement = try ApprovalEnrollmentStatement.verify(signed) } catch let error as ApprovalEnrollmentError { throw ApprovalEnrollmentFailure.invalidStatement(error) }
        do {
            // The statement must be for this business, this customer and this enrollment: nothing the relay says is trusted.
            try statement.checkBinding(businessId: businessId, subject: expectedSubject, enrollmentId: id)
        } catch let error as ApprovalEnrollmentError { throw ApprovalEnrollmentFailure.bindingMismatch(error) }
        guard statement.assurance.satisfies(minimumAssurance) else { throw ApprovalEnrollmentFailure.assuranceTooLow }
        let confirmation = try await ApprovalEnrollmentConfirmation(confirming: statement, signed: signed, at: now).sign(with: confirmationKey)
        _ = try decode(ApprovalKeyView.self, try await perform(APIRoutes.businessApproveEnrollmentConfirm.descriptor, parameters: ["enrollmentId": id.uuidString.lowercased()],
                                                                body: ConfirmApprovalEnrollmentRequest(confirmation: confirmation)))
        return ConfirmedEnrollment(key: statement.enrolledKey, hpke: statement.hpkePublicKey, statement: signed, enrollmentId: id)
    }

    /// Keys the relay lists for a customer. **For display and reconciliation only**: authorize against your own `ApprovalKeyStore`.
    public func approvalKeys(subject: SubjectRef) async throws -> [ApprovalKeyView] {
        try decode([ApprovalKeyView].self, try await perform(APIRoutes.businessApproveKeys.descriptor, query: [("subject_ref", subject.rawValue)]))
    }

    @discardableResult
    public func revokeApprovalKey(kid: String, reason: String? = nil) async throws -> ApprovalKeyView {
        try decode(ApprovalKeyView.self, try await perform(APIRoutes.businessApproveKeyRevoke.descriptor, parameters: ["kid": kid], body: RevokeApprovalKeyRequest(reason: reason), naturallyIdempotent: true))
    }

    // MARK: Requests

    /// Creates the request. `request.requestId` is the idempotency key: a retry with the same id and body returns the original.
    public func createApprovalRequest(_ request: CreateApprovalRequest) async throws -> ApprovalRequestView {
        try decode(ApprovalRequestView.self, try await perform(APIRoutes.businessApproveRequestCreate.descriptor, body: request, naturallyIdempotent: true))
    }

    /// The relay's view. **Never authorize on `status`**: fetch the result and verify it with `ApprovalVerifier`.
    public func approvalRequest(requestId: String) async throws -> ApprovalRequestView {
        try decode(ApprovalRequestView.self, try await perform(APIRoutes.businessApproveRequestGet.descriptor, parameters: ["requestId": requestId]))
    }

    @discardableResult
    public func cancelApprovalRequest(requestId: String) async throws -> ApprovalRequestView {
        try decode(ApprovalRequestView.self, try await perform(APIRoutes.businessApproveRequestCancel.descriptor, parameters: ["requestId": requestId], body: Optional<EmptyBody>.none, naturallyIdempotent: true))
    }

    /// The signed result for a `result_ref` (from the webhook or the request view), retrieved with your own credentials.
    public func approvalResult(resultRef: String) async throws -> ApprovalResultResponse {
        try decode(ApprovalResultResponse.self, try await perform(APIRoutes.businessApproveResult.descriptor, parameters: ["resultRef": resultRef]))
    }

    /// Stops (or resumes) approvals for one customer. You can lift only your own freeze, never the customer's.
    @discardableResult
    public func freezeApprovals(subject: SubjectRef, frozen: Bool, reason: String? = nil) async throws -> FreezeStatus {
        try decode(FreezeStatus.self, try await perform(APIRoutes.businessApproveFreeze.descriptor, body: BusinessFreezeRequest(subjectRef: subject, frozen: frozen, reason: reason), naturallyIdempotent: true))
    }
}
