import Crypto
import Foundation
import Testing
import ViadereCore
@testable import ViadereBusinessSDK

/// WP-C1 on the business side: the SDK builds the link, refuses a lying relay, authenticates the statement with the business's secret, and never
/// confirms without the person's SAS comparison.
@Suite("Link sessions (business SDK)")
struct LinkSessionSDKTests {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    let business = BusinessID()
    let viadere = SoftwareP256SigningKey()
    let root = KeyIdentifier.make(try! SoftwareP256SigningKey().publicKey.signingKey())
    let subject = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 3, count: 32)))!
    let sessionId = UUID()

    func ticket(root: String? = nil, link: String? = nil) -> LinkSessionTicket {
        LinkSessionTicket(sessionId: sessionId, code: "K7QFM2XA", link: link ?? "https://viadere.com/k/K7QFM2XA", rootKid: root ?? self.root,
                          expiresAt: Self.now.addingTimeInterval(300))
    }

    func invitation(_ secret: LinkSessionSecret = LinkSessionSecret()) -> LinkSessionInvitation {
        LinkSessionInvitation(sessionId: sessionId, code: "K7QFM2XA", rootKid: root, secret: secret, capabilities: [.messageSend], expiresAt: Self.now.addingTimeInterval(300))
    }

    /// The view the relay returns after the phone completed: the phone's statement and tag, and Viadere's signed result over it.
    func completedView(secret: LinkSessionSecret, statementSubject: SubjectRef? = nil, resultSigner: SoftwareP256SigningKey? = nil,
                       substitute: Bool = false) async throws -> LinkSessionView {
        let phoneKey = SoftwareP256SigningKey()
        let statement = try LinkStatement(sessionId: sessionId, businessId: business, subject: statementSubject ?? subject, capabilities: [.messageSend],
                                          descriptorDigest: String(repeating: "d", count: 64), publicKey: phoneKey.publicKey, approvalStatement: nil, createdAt: Self.now)
        let signed = try await statement.sign(with: phoneKey)
        let tag = secret.bindingTag(for: signed)
        var relayed = signed
        if substitute {
            // The relay swaps in a statement of its own (another key): the phone's tag stays, but cannot cover it.
            let relayKey = SoftwareP256SigningKey()
            relayed = try await LinkStatement(sessionId: sessionId, businessId: business, subject: subject, capabilities: [.messageSend],
                                              descriptorDigest: String(repeating: "d", count: 64), publicKey: relayKey.publicKey, approvalStatement: nil, createdAt: Self.now).sign(with: relayKey)
        }
        let signer = resultSigner ?? viadere
        let kid = KeyIdentifier.make(try signer.publicKey.signingKey())
        let result = LinkResult(sessionId: sessionId, businessId: business, subject: subject, statementDigest: LinkStatement.digest(of: relayed),
                                approvalStatementDigest: nil, completedAt: Self.now)
        let signedResult = try await SignedStatement.sign(result.object(signerKid: kid), domain: LinkDomainSeparator.result, with: signer)
        return LinkSessionView(sessionId: sessionId, status: .deviceCompleted, capabilities: [.messageSend], createdAt: Self.now, expiresAt: Self.now.addingTimeInterval(300),
                               subjectRef: subject, statement: relayed, bindingTag: tag,
                               result: ViadereSignedStatement(kid: kid, payload: signedResult.payload, signature: signedResult.signature), completedAt: Self.now)
    }

    @Test func noSessionWithoutARecentStepUp() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        await #expect(throws: LinkSessionFailure.stepUpRequired) {
            _ = try await client.createLinkSession(customerRef: "cust_1", capabilities: [.messageSend], rootKid: root, customerAuthenticatedAt: Self.now.addingTimeInterval(-301), now: Self.now)
        }
        #expect(transport.requests.isEmpty, "nothing is sent")
    }

    @Test func theSDKBuildsTheLinkAndRefusesALyingTicket() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        try transport.enqueue(status: 201, json: ticket())
        let invitation = try await client.createLinkSession(customerRef: "cust_1", capabilities: [.messageSend], rootKid: root, customerAuthenticatedAt: Self.now, now: Self.now)
        #expect(invitation.link == "https://viadere.com/k/K7QFM2XA#es=\(invitation.secret.base64URL)")
        #expect(invitation.checkCode.count == 9)
        // Another root, or a link on another host: refused and cancelled.
        for bad in [ticket(root: KeyIdentifier.make(try SoftwareP256SigningKey().publicKey.signingKey())), ticket(link: "https://viadere.evil/k/K7QFM2XA")] {
            try transport.enqueue(status: 201, json: bad)
            try transport.enqueue(status: 200, json: LinkSessionView(sessionId: sessionId, status: .cancelled, capabilities: [.messageSend], createdAt: Self.now, expiresAt: Self.now))
            await #expect(throws: LinkSessionFailure.ticketMismatch) {
                _ = try await client.createLinkSession(customerRef: "cust_1", capabilities: [.messageSend], rootKid: root, customerAuthenticatedAt: Self.now, now: Self.now)
            }
            #expect(transport.requests.last?.url.path.hasSuffix("/cancel") == true)
        }
        // A staging client accepts only its own host.
        let staging = try ViadereBusinessClient(apiKey: Fixtures.key, transport: transport, linkDomain: LinkDomain("viadere.cksites.dev")!)
        try transport.enqueue(status: 201, json: ticket(link: "https://viadere.cksites.dev/k/K7QFM2XA"))
        let stagingInvitation = try await staging.createLinkSession(customerRef: "c", capabilities: [.messageSend], rootKid: root, customerAuthenticatedAt: Self.now, now: Self.now)
        #expect(stagingInvitation.link.hasPrefix("https://viadere.cksites.dev/k/"))
    }

    @Test func aRelaySubstitutedStatementFailsTheBindingTagAndTheSessionIsCancelled() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        let secret = LinkSessionSecret()
        try transport.enqueue(status: 200, json: try await completedView(secret: secret, substitute: true))
        try transport.enqueue(status: 200, json: LinkSessionView(sessionId: sessionId, status: .cancelled, capabilities: [.messageSend], createdAt: Self.now, expiresAt: Self.now))
        await #expect(throws: LinkSessionFailure.bindingTagInvalid) {
            _ = try await client.reviewLinkSession(invitation: invitation(secret), businessId: business, viadereKeys: [viadere.publicKey])
        }
        #expect(transport.requests.last?.url.path.hasSuffix("/cancel") == true)
    }

    @Test func theResultMustBeSignedByAPinnedViadereKeyAndNameTheStatementsAccount() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        let secret = LinkSessionSecret()
        try transport.enqueue(status: 200, json: try await completedView(secret: secret, resultSigner: SoftwareP256SigningKey()))
        await #expect(throws: LinkSessionFailure.resultInvalid(.untrustedSigner)) {
            _ = try await client.reviewLinkSession(invitation: invitation(secret), businessId: business, viadereKeys: [viadere.publicKey])
        }
        // A statement for another account than the one Viadere says completed it.
        let other = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 4, count: 32)))!
        try transport.enqueue(status: 200, json: try await completedView(secret: secret, statementSubject: other))
        await #expect(throws: LinkSessionFailure.statementInvalid(.wrongSubject)) {
            _ = try await client.reviewLinkSession(invitation: invitation(secret), businessId: business, viadereKeys: [viadere.publicKey])
        }
    }

    @Test func confirmingNeedsTheSASCheck() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        let secret = LinkSessionSecret()
        let confirmKey = SoftwareP256SigningKey()
        try transport.enqueue(status: 200, json: try await completedView(secret: secret))
        let review = try await client.reviewLinkSession(invitation: invitation(secret), businessId: business, viadereKeys: [viadere.publicKey])
        #expect(review.subjectRef == subject)
        #expect(review.pseudonym == LinkPseudonym.make(subject))
        let sent = transport.requests.count
        // No comparison flag at all: refused, nothing sent.
        await #expect(throws: LinkSessionFailure.sasComparisonRequired) { _ = try await client.confirmLinkSession(review, sasCheck: nil, confirmationKey: confirmKey, now: Self.now) }
        #expect(transport.requests.count == sent)
        // A wrong typed SAS cancels (one guess).
        try transport.enqueue(status: 200, json: LinkSessionView(sessionId: sessionId, status: .cancelled, capabilities: [.messageSend], createdAt: Self.now, expiresAt: Self.now))
        let wrong = review.sas == "000000" ? "111111" : "000000"
        await #expect(throws: LinkSessionFailure.sasMismatch) { _ = try await client.confirmLinkSession(review, sasCheck: .typed(wrong), confirmationKey: confirmKey, now: Self.now) }
        #expect(transport.requests.last?.url.path.hasSuffix("/cancel") == true)
        // The right digits: the confirmation is signed over this statement and sent.
        try transport.enqueue(status: 200, json: LinkSessionView(sessionId: sessionId, status: .confirmed, capabilities: [.messageSend], createdAt: Self.now, expiresAt: Self.now))
        let confirmed = try await client.confirmLinkSession(review, sasCheck: .typed(LinkSAS.display(review.sas)), confirmationKey: confirmKey, now: Self.now)
        #expect(confirmed.subjectRef == subject)
        let body = try ViadereJSON.decode(ConfirmLinkSessionRequest.self, from: try #require(transport.requests.last?.body))
        let parsed = try LinkConfirmation.verify(body.confirmation, confirmationKey: confirmKey.publicKey)
        try parsed.checkMatches(review.linkStatement, signed: review.statement)
        #expect(parsed.verification == .sasTyped)
    }

    @Test func aComparedSASNeedsTheBindingTag() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        let secret = LinkSessionSecret()
        var view = try await completedView(secret: secret)
        view.bindingTag = nil
        try transport.enqueue(status: 200, json: view)
        let review = try await client.reviewLinkSession(invitation: invitation(secret), businessId: business, viadereKeys: [viadere.publicKey])
        #expect(!review.hasBindingTag)
        await #expect(throws: LinkSessionFailure.typedSASRequired) {
            _ = try await client.confirmLinkSession(review, sasCheck: .comparedByCustomer, confirmationKey: SoftwareP256SigningKey(), now: Self.now)
        }
    }
}
