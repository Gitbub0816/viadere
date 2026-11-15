import Crypto
import Foundation
import ViadereCore

/// What you show the customer to link their Viadere app to your customer record (WP-C1, `docs/SECURITY.md` §2.59), built **by the SDK**, and what
/// you keep until you confirm.
///
/// * `link` is `https://{link domain}/k/{CODE}#es={secret}`: show it as a QR or button in **your own signed-in session**, right after you
///   authenticated the customer (a step-up). Never send it by SMS or email. The secret travels in the URL fragment, which no server ever receives.
/// * `displayCode` + `checkCode` are for a customer who types instead of scanning (both go into the app; the app then shows six digits).
/// * `secret` stays on your server, with `sessionId`, until you confirm or cancel. Never log it, never send it to Viadere.
public struct LinkSessionInvitation: Sendable, Hashable {
    public let sessionId: UUID
    /// Canonical code (eight characters); `displayCode` is `ABCD-EFGH`.
    public let code: String
    public let rootKid: String
    public let secret: LinkSessionSecret
    public let capabilities: [Capability]
    public let expiresAt: Date
    public let domain: LinkDomain

    public init(sessionId: UUID, code: String, rootKid: String, secret: LinkSessionSecret, capabilities: [Capability], expiresAt: Date, domain: LinkDomain = .production) {
        self.sessionId = sessionId
        self.code = code
        self.rootKid = rootKid
        self.secret = secret
        self.capabilities = LinkCapabilities.canonical(capabilities)
        self.expiresAt = expiresAt
        self.domain = domain
    }

    public var displayCode: String { LinkSessionCode.display(code) }
    /// The 40-bit check code for the typed path, as `ABCD-EFGH`.
    public var checkCode: String { LinkSessionCode.display(secret.checkCode) }
    /// The link or QR content.
    public var link: String { LinkSessionLink.build(code: code, secret: secret, domain: domain) }
}

/// A completed session you verified, ready for the person to compare the SAS **in your signed-in session**.
public struct LinkSessionReview: Sendable, Hashable {
    public let invitation: LinkSessionInvitation
    /// The pairwise reference of the Viadere account that completed the session (also the `connection_id`). Bind it to your customer record only
    /// after you confirmed.
    public let subjectRef: SubjectRef
    /// Show it next to the SAS: "Viadere account ABCD-EFGH". The app shows the same value.
    public let pseudonym: String
    /// The six digits the app shows; show them (compare) or ask the person to type what their app shows (typed).
    public let sas: String
    /// True when the app opened your QR or link (it proved it holds your secret). Without it only a typed SAS is accepted.
    public let hasBindingTag: Bool
    public let statement: SignedStatement
    public let linkStatement: LinkStatement
    public let approvalStatement: SignedStatement?
    public let approval: ApprovalEnrollmentStatement?
    /// Viadere's signed account of the completion (`LinkResult`), verified against the `link-descriptor` keys you pinned.
    public let result: LinkResult
}

/// How the person verified the SAS in your signed-in session. **Required**: the SDK never confirms without one.
public enum LinkSASCheck: Sendable, Hashable {
    /// The person typed the six digits their app shows (always accepted; required on the typed path).
    case typed(String)
    /// You showed `review.sas` and the person confirmed their app shows the same digits (only with a valid binding tag).
    case comparedByCustomer
}

/// A confirmed link: store `subjectRef` with your customer record, and `approval` (if any) as for an Approve v2 enrollment.
public struct ConfirmedLink: Sendable, Hashable {
    public let sessionId: UUID
    public let subjectRef: SubjectRef
    public let connectionKid: String
    public let approval: ConfirmedEnrollment?
}

public enum LinkSessionFailure: Error, Sendable, Equatable {
    /// You did not authenticate the customer within the last five minutes: step up first, then create the session.
    case stepUpRequired
    /// The relay's ticket names another root key, another host, or a malformed code. The session was cancelled.
    case ticketMismatch
    case notReady
    /// The result is not signed by a `link-descriptor` key you pinned, or does not describe this statement.
    case resultInvalid(LinkSessionError)
    case statementInvalid(LinkSessionError)
    /// The binding tag is not the HMAC of this statement under your secret: the statement did not come from the app that opened your link. Cancelled.
    case bindingTagInvalid
    /// No SAS check was given: have the person compare or type the six digits in your signed-in session.
    case sasComparisonRequired
    /// A compared SAS is not enough on the typed path (no binding tag): the person must type the digits.
    case typedSASRequired
    /// The typed digits do not match. Cancelled: one guess per session.
    case sasMismatch
}

extension ViadereBusinessClient {
    /// The longest a step-up may be old when you create a session (§2.12: authenticate the customer immediately before showing the QR).
    public static let linkStepUpWindow: TimeInterval = 300

    /// Creates a link session for the customer you **just** authenticated (`customerAuthenticatedAt` at most five minutes ago) and returns the
    /// invitation built by the SDK. `customerRef` is your own opaque reference (hashed by Viadere, never shown).
    ///
    /// - Parameter rootKid: your own root key id; a ticket naming another is refused and cancelled.
    public func createLinkSession(customerRef: String, capabilities: [Capability], displayHint: String? = nil, rootKid: String, customerAuthenticatedAt: Date,
                                  expiresIn: Int? = nil, now: Date = Date()) async throws -> LinkSessionInvitation {
        guard customerAuthenticatedAt <= now.addingTimeInterval(60), now.timeIntervalSince(customerAuthenticatedAt) <= Self.linkStepUpWindow else {
            throw LinkSessionFailure.stepUpRequired
        }
        guard KeyIdentifier.isValid(rootKid) else { throw LinkSessionFailure.ticketMismatch }
        let ticket = try decode(LinkSessionTicket.self, try await perform(APIRoutes.businessLinkSessionCreate.descriptor,
            body: CreateLinkSessionRequest(customerRef: customerRef, capabilities: capabilities, displayHint: displayHint, expiresInSeconds: expiresIn)))
        // The relay's link is never shown: it is checked (host, code, no secret) and so is its root against yours.
        guard let canonical = LinkSessionCode.canonical(ticket.code), canonical == ticket.code, let url = URL(string: ticket.link),
              let parsed = LinkSessionLink.parse(url, domain: linkDomain), parsed.code == ticket.code, parsed.secret == nil,
              ConstantTime.equals(ticket.rootKid, rootKid) else {
            _ = try? await cancelLinkSession(id: ticket.sessionId)
            throw LinkSessionFailure.ticketMismatch
        }
        return LinkSessionInvitation(sessionId: ticket.sessionId, code: ticket.code, rootKid: rootKid, secret: LinkSessionSecret(), capabilities: capabilities,
                                     expiresAt: ticket.expiresAt, domain: linkDomain)
    }

    public func linkSession(id: UUID) async throws -> LinkSessionView {
        try decode(LinkSessionView.self, try await perform(APIRoutes.businessLinkSessionGet.descriptor, parameters: ["sessionId": id.uuidString.lowercased()]))
    }

    @discardableResult
    public func cancelLinkSession(id: UUID) async throws -> LinkSessionView {
        try decode(LinkSessionView.self, try await perform(APIRoutes.businessLinkSessionCancel.descriptor, parameters: ["sessionId": id.uuidString.lowercased()],
                                                           body: Optional<EmptyBody>.none, naturallyIdempotent: true))
    }

    /// After `link.completed`: fetches the session and verifies everything **yourself** — Viadere's signed result against the `link-descriptor` keys
    /// you pinned, the device's statement (this session, your business, the account the result names, exactly your capabilities), the approval
    /// statement it commits to, and the binding tag under your secret. Then show `review.sas` and `review.pseudonym` in your signed-in session.
    public func reviewLinkSession(invitation: LinkSessionInvitation, businessId: BusinessID, viadereKeys: [DevicePublicKey]) async throws -> LinkSessionReview {
        let view = try await linkSession(id: invitation.sessionId)
        guard view.status == .deviceCompleted, let signed = view.statement, let signedResult = view.result else { throw LinkSessionFailure.notReady }
        let result: LinkResult
        do { result = try LinkResult.verify(signedResult, trustedKeys: viadereKeys) } catch let error as LinkSessionError { throw LinkSessionFailure.resultInvalid(error) }
        guard result.sessionId == invitation.sessionId, result.businessId == businessId,
              ConstantTime.equals(result.statementDigest, LinkStatement.digest(of: signed)),
              result.approvalStatementDigest == view.approvalStatement.map(ApprovalEnrollmentStatement.digest(of:)) else {
            throw LinkSessionFailure.resultInvalid(.statementMismatch)
        }
        let statement: LinkStatement
        let approval: ApprovalEnrollmentStatement?
        do {
            statement = try LinkStatement.verify(signed)
            try statement.checkBinding(sessionId: invitation.sessionId, businessId: businessId, subject: result.subject, capabilities: invitation.capabilities)
            approval = try statement.checkApprovalStatement(view.approvalStatement)
        } catch let error as LinkSessionError { throw LinkSessionFailure.statementInvalid(error) }
        if let tag = view.bindingTag {
            guard invitation.secret.verifyBindingTag(tag, for: signed) else {
                _ = try? await cancelLinkSession(id: invitation.sessionId)
                throw LinkSessionFailure.bindingTagInvalid
            }
        }
        return LinkSessionReview(invitation: invitation, subjectRef: result.subject, pseudonym: LinkPseudonym.make(result.subject), sas: invitation.secret.expectedSAS(for: signed),
                                 hasBindingTag: view.bindingTag != nil, statement: signed, linkStatement: statement, approvalStatement: view.approvalStatement,
                                 approval: approval, result: result)
    }

    /// Confirms a reviewed session with your `approval-enrollment-confirmation` key. **Refuses without a SAS check** (`sasComparisonRequired`); a
    /// wrong typed SAS cancels the session. After this, send the customer an out-of-band notice through your own channel ("A Viadere app was linked to
    /// your account. Not you?") with a way to revoke.
    public func confirmLinkSession(_ review: LinkSessionReview, sasCheck: LinkSASCheck?, confirmationKey: any DeviceSigningKey, now: Date = Date()) async throws -> ConfirmedLink {
        guard let sasCheck else { throw LinkSessionFailure.sasComparisonRequired }
        let verification: LinkVerification
        switch sasCheck {
        case .typed(let typed):
            guard review.invitation.secret.verifySAS(typed, for: review.statement) else {
                _ = try? await cancelLinkSession(id: review.invitation.sessionId)
                throw LinkSessionFailure.sasMismatch
            }
            verification = .sasTyped
        case .comparedByCustomer:
            guard review.hasBindingTag else { throw LinkSessionFailure.typedSASRequired }
            verification = .sasCompared
        }
        let confirmation = try await LinkConfirmation(confirming: review.linkStatement, signed: review.statement, verification: verification, at: now).sign(with: confirmationKey)
        var approvalConfirmation: BusinessSignedStatement?
        var confirmedApproval: ConfirmedEnrollment?
        if let approval = review.approval, let signed = review.approvalStatement {
            approvalConfirmation = try await ApprovalEnrollmentConfirmation(confirming: approval, signed: signed, at: now).sign(with: confirmationKey)
            confirmedApproval = ConfirmedEnrollment(key: approval.enrolledKey, hpke: approval.hpkePublicKey, statement: signed, enrollmentId: review.invitation.sessionId)
        }
        _ = try decode(LinkSessionView.self, try await perform(APIRoutes.businessLinkSessionConfirm.descriptor, parameters: ["sessionId": review.invitation.sessionId.uuidString.lowercased()],
                                                               body: ConfirmLinkSessionRequest(confirmation: confirmation, approvalConfirmation: approvalConfirmation)))
        return ConfirmedLink(sessionId: review.invitation.sessionId, subjectRef: review.subjectRef, connectionKid: review.linkStatement.kid, approval: confirmedApproval)
    }
}
