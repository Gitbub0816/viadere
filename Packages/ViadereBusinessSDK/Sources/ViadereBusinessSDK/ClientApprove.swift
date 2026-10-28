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

/// What you show the customer, built **by the SDK** (gate findings F1 and F3), and what you must keep until the enrollment is confirmed.
///
/// * `link` is `https://viadere.com/a/{CODE}?rk={your root key id}#es={secret}`. The root key id is the one **you** passed, not the relay's;
///   the secret travels in the URL fragment, which no server (Viadere's included) ever receives. Show it as a QR or button in your own
///   signed-in session. Never send it by SMS or email.
/// * `code` and `checkCode` are for a customer who types instead of scanning: the customer types **both** into the app, and the app shows a
///   six-digit number that you type into `confirmApprovalEnrollment(sas:)`.
/// * `secret` is the 256-bit enrollment secret. **Keep it server-side, tied to `enrollmentId`, until you confirm or cancel.** Never log it,
///   never send it to Viadere. Losing it only costs you a new enrollment.
public struct ApprovalEnrollmentInvitation: Sendable, Hashable {
    public let enrollmentId: UUID
    /// Canonical code (eight characters, no separator); `displayCode` is `ABCD-EFGH`.
    public let code: String
    public let rootKid: String
    public let secret: ApprovalEnrollmentSecret
    public let expiresAt: Date

    public init(enrollmentId: UUID, code: String, rootKid: String, secret: ApprovalEnrollmentSecret, expiresAt: Date) {
        self.enrollmentId = enrollmentId
        self.code = code
        self.rootKid = rootKid
        self.secret = secret
        self.expiresAt = expiresAt
    }

    public var displayCode: String { ApprovalEnrollmentCode.display(code) }
    /// The 40-bit check code for the typed path, as `ABCD-EFGH`.
    public var checkCode: String { ApprovalEnrollmentCode.display(secret.checkCode) }
    /// The link or QR content.
    public var link: String { ApprovalEnrollmentCode.deepLink(code: code, rootKid: rootKid, secret: secret) }
}

/// Failures while confirming an enrollment, before anything is sent to Viadere.
public enum ApprovalEnrollmentFailure: Error, Sendable, Equatable {
    /// The device has not completed the enrollment yet.
    case notReady
    /// The relay's ticket does not match the root key you passed, or its code is malformed: the relay is lying about who you are. Nothing was shown.
    case rootKeyMismatch
    /// The statement carries no binding tag and no SAS was given: ask the customer for the six digits the app shows (typed path), or start over.
    /// Nothing was changed; you may call again with the SAS.
    case verificationRequired
    /// The binding tag is not the HMAC of this statement under your enrollment secret: the statement did not come from the app that opened your link
    /// (a forged or swapped statement). The enrollment was cancelled and the pending key revoked.
    case bindingTagInvalid
    /// The six digits do not match the statement. The enrollment was cancelled (start a new one): one guess per enrollment.
    case sasMismatch
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

    /// Starts an enrollment for a customer you already have a relationship with and returns the invitation **built by the SDK**: show
    /// `invitation.link` (QR or button) or `invitation.displayCode` plus `invitation.checkCode` in **your own signed-in session**. Never send them
    /// by SMS or email, and keep `invitation.secret` until you confirm (see `ApprovalEnrollmentInvitation`).
    ///
    /// - Parameter rootKid: your own root key id (`BusinessKeyAuthority.rootKid`). The SDK refuses a relay ticket that names any other root.
    public func createApprovalEnrollment(subject: SubjectRef, capability: Capability, rootKid: String, expiresIn: Int? = nil) async throws -> ApprovalEnrollmentInvitation {
        guard KeyIdentifier.isValid(rootKid) else { throw ApprovalEnrollmentFailure.rootKeyMismatch }
        let ticket = try decode(ApprovalEnrollmentTicket.self, try await perform(APIRoutes.businessApproveEnrollmentCreate.descriptor,
                                                                                  body: CreateApprovalEnrollmentRequest(subjectRef: subject, capability: capability, expiresInSeconds: expiresIn)))
        // Gate finding F3: the root key id in the link is what the customer's app treats as "verified out of band". The relay's suggestion is
        // never shown; it is only checked against your own root, and a ticket that disagrees (or has no root at all) is refused.
        guard let canonical = ApprovalEnrollmentCode.canonical(ticket.code), canonical == ticket.code,
              let url = URL(string: ticket.deepLink), let parsed = ApprovalEnrollmentCode.parse(link: url), parsed.code == ticket.code, parsed.secret == nil,
              let relayRoot = parsed.rootKid, ConstantTime.equals(relayRoot, rootKid) else {
            _ = try? await cancelApprovalEnrollment(id: ticket.enrollmentId)
            throw ApprovalEnrollmentFailure.rootKeyMismatch
        }
        return ApprovalEnrollmentInvitation(enrollmentId: ticket.enrollmentId, code: ticket.code, rootKid: rootKid, secret: ApprovalEnrollmentSecret(), expiresAt: ticket.expiresAt)
    }

    /// `createApprovalEnrollment(subject:capability:rootKid:expiresIn:)` with the root of your `BusinessKeyAuthority`.
    public func createApprovalEnrollment(subject: SubjectRef, capability: Capability, authority: BusinessKeyAuthority, expiresIn: Int? = nil) async throws -> ApprovalEnrollmentInvitation {
        try await createApprovalEnrollment(subject: subject, capability: capability, rootKid: authority.rootKid, expiresIn: expiresIn)
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
    ///
    /// **A valid statement proves nothing by itself** (gate finding F1): the relay can make a key of its own and sign a flawless statement. Before
    /// anything is signed the SDK therefore requires proof that the statement came from the customer's app, using the secret only you and
    /// that app hold:
    /// * the app opened your `invitation.link`: the statement must carry a **binding tag** that verifies under `invitation.secret`; or
    /// * the customer typed the codes: pass `sas`, the six digits the app shows, typed into your own signed-in session.
    ///
    /// Anything else is refused and the enrollment cancelled (the relay-held pending key is revoked).
    /// - Parameters:
    ///   - invitation: what `createApprovalEnrollment` returned (with its secret, as you stored it).
    ///   - businessId: your business id: the statement must name it.
    ///   - expectedSubject: the customer you started the enrollment for.
    ///   - sas: the six digits (typed path only).
    ///   - minimumAssurance: refuse keys weaker than this (default `.biometric`).
    public func confirmApprovalEnrollment(invitation: ApprovalEnrollmentInvitation, businessId: BusinessID, expectedSubject: SubjectRef, sas: String? = nil,
                                          confirmationKey: any DeviceSigningKey, minimumAssurance: ApprovalAMR = .biometric, now: Date = Date()) async throws -> ConfirmedEnrollment {
        let id = invitation.enrollmentId
        let view = try await approvalEnrollment(id: id)
        guard view.status == .deviceCompleted, let signed = view.deviceStatement else { throw ApprovalEnrollmentFailure.notReady }
        let statement: ApprovalEnrollmentStatement
        do { statement = try ApprovalEnrollmentStatement.verify(signed) } catch let error as ApprovalEnrollmentError { throw ApprovalEnrollmentFailure.invalidStatement(error) }
        do {
            // The statement must be for this business, this customer and this enrollment: nothing the relay says is trusted.
            try statement.checkBinding(businessId: businessId, subject: expectedSubject, enrollmentId: id)
        } catch let error as ApprovalEnrollmentError { throw ApprovalEnrollmentFailure.bindingMismatch(error) }
        guard statement.assurance.satisfies(minimumAssurance) else { throw ApprovalEnrollmentFailure.assuranceTooLow }
        // Who made this statement? Only the holder of `es` can say so.
        if let tag = view.bindingTag {
            guard invitation.secret.verifyBindingTag(tag, for: signed) else {
                _ = try? await cancelApprovalEnrollment(id: id)
                throw ApprovalEnrollmentFailure.bindingTagInvalid
            }
        } else {
            guard let sas else { throw ApprovalEnrollmentFailure.verificationRequired }
            guard invitation.secret.verifySAS(sas, for: signed) else {
                _ = try? await cancelApprovalEnrollment(id: id)
                throw ApprovalEnrollmentFailure.sasMismatch
            }
        }
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

    /// Resolves the opaque `request_id` of an `approve.frozen` webhook (`frz_...`) to the customer and whether approvals are frozen now.
    public func approvalFreeze(ref: String) async throws -> FreezeStatus {
        try decode(FreezeStatus.self, try await perform(APIRoutes.businessApproveFreezeGet.descriptor, parameters: ["freezeRef": ref]))
    }

    /// Stops (or resumes) approvals for one customer. You can lift only your own freeze, never the customer's.
    @discardableResult
    public func freezeApprovals(subject: SubjectRef, frozen: Bool, reason: String? = nil) async throws -> FreezeStatus {
        try decode(FreezeStatus.self, try await perform(APIRoutes.businessApproveFreeze.descriptor, body: BusinessFreezeRequest(subjectRef: subject, frozen: frozen, reason: reason), naturallyIdempotent: true))
    }
}
