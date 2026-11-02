import Foundation
import ViadereCore

/// "Verify with Viadere" on your **server** (`docs/VERIFY-BUTTON.md`): create a verification session for the page or app screen that shows the
/// button, hand the ticket's `link` (and `code`) to your front end, and after the person finished, read the session and **verify Viadere's signed
/// result yourself**. Never let the browser or your app tell your server that a person is verified.
public enum VerificationSessionFailure: Error, Sendable, Equatable {
    /// The relay's ticket names another host or a malformed code. The session was cancelled.
    case ticketMismatch
    /// The session has not completed yet (`status` is `open` or `accepted`), or it expired or was cancelled without a result.
    case notCompleted(VerificationSessionStatus)
    /// The result is not signed by a `link-descriptor` key you pinned, or describes another session, business, origin or capability.
    case resultInvalid(VerificationSessionError)
    /// The result reference the session returned is not the one the signed result commits to.
    case resultRefMismatch
}

/// A completed session whose result you verified.
public struct VerifiedVerificationSession: Sendable, Hashable {
    /// Viadere's signed statement, verified against your pinned keys and checked against the session you created.
    public let result: VerificationSessionResult
    /// `verified` or `not_verified` (never why).
    public var outcome: VerificationOutcome { result.outcome }
    /// The pairwise reference of the account that verified (the same value `relationship.connected` names).
    public var subjectRef: SubjectRef { result.subject }
    /// Single use: `verificationResult(ref:)` returns the attribute values once (`identity.name`, `identity.address`).
    public let resultRef: VerificationResultRef
}

extension ViadereBusinessClient {
    /// Creates a verification session for `request.origin` (one of your verified domains or a subdomain; live keys only). Give the ticket's `link`
    /// to the button (`<viadere-verify link="…">`, `VerifyWithViadereButton`, the Android `VerifyWithViadereButton`) and keep `sessionId` on your
    /// server with the visitor's own session. The code is valid for at most five minutes; create a new one when the page is shown again.
    public func createVerificationSession(_ request: CreateVerificationSessionRequest) async throws -> VerificationSessionTicket {
        let ticket = try decode(VerificationSessionTicket.self, try await perform(APIRoutes.businessVerificationSessionCreate.descriptor, body: request))
        // The relay's link is checked before anything shows it: the configured link domain, `/v/{CODE}`, nothing else.
        guard let canonical = VerificationSessionCode.canonical(ticket.code), canonical == ticket.code, let url = URL(string: ticket.link),
              VerificationSessionLink.parse(url, domain: linkDomain) == ticket.code else {
            _ = try? await cancelVerificationSession(id: ticket.sessionId)
            throw VerificationSessionFailure.ticketMismatch
        }
        return ticket
    }

    public func verificationSession(id: UUID) async throws -> VerificationSessionView {
        try decode(VerificationSessionView.self, try await perform(APIRoutes.businessVerificationSessionGet.descriptor, parameters: ["sessionId": id.uuidString.lowercased()]))
    }

    @discardableResult
    public func cancelVerificationSession(id: UUID) async throws -> VerificationSessionView {
        try decode(VerificationSessionView.self, try await perform(APIRoutes.businessVerificationSessionCancel.descriptor, parameters: ["sessionId": id.uuidString.lowercased()],
                                                                   body: Optional<EmptyBody>.none, naturallyIdempotent: true))
    }

    /// Reads the session and verifies **everything yourself**: Viadere's signature against the `link-descriptor` keys you pinned, that the result
    /// is for this session, your business, the origin and the capability you asked for, and that the result reference matches. Throws
    /// `notCompleted` until the person finished (poll it, or call it on the `verification.completed` webhook).
    public func verifiedVerificationSession(id: UUID, businessId: BusinessID, origin: String, capability: Capability,
                                            viadereKeys: [DevicePublicKey]) async throws -> VerifiedVerificationSession {
        let view = try await verificationSession(id: id)
        guard view.status == .completed, let signed = view.result, let ref = view.resultRef else { throw VerificationSessionFailure.notCompleted(view.status) }
        let result: VerificationSessionResult
        do {
            result = try VerificationSessionResult.verify(signed, trustedKeys: viadereKeys)
            try result.check(sessionId: id, businessId: businessId, origin: origin, capability: capability)
        } catch let error as VerificationSessionError { throw VerificationSessionFailure.resultInvalid(error) }
        guard result.matches(ref) else { throw VerificationSessionFailure.resultRefMismatch }
        return VerifiedVerificationSession(result: result, resultRef: ref)
    }
}
