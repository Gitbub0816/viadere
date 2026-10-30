import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// WP-C1: the link-session protocol objects (`docs/SECURITY.md` §2.59). Each test reproduces an attack on the protocol and shows it is refused.
@Suite("Link sessions (WP-C1)")
struct LinkSessionTests {
    let viadere = SoftwareP256SigningKey()          // the `link-descriptor` key (KMS-held on the server)
    let business = BusinessID()
    let session = UUID()
    let subject = SubjectRef.derive(key: SymmetricKey(size: .bits256), businessId: BusinessID(), consumerId: ConsumerID())
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let staging = LinkDomain("viadere.cksites.dev")!

    var viadereKid: String { KeyIdentifier.make(try! viadere.publicKey.signingKey()) }

    func descriptor(capabilities: [Capability] = [.messageSend, .authChallenge], expiresIn: TimeInterval = 300, issuedAt: Date? = nil,
                    signer: SoftwareP256SigningKey? = nil) async throws -> ViadereSignedStatement {
        let key = signer ?? viadere
        let kid = KeyIdentifier.make(try key.publicKey.signingKey())
        let d = LinkSessionDescriptor(sessionId: session, businessId: business, businessName: "Northwind Bank", businessDomain: "northwind.example",
                                      rootKid: KeyIdentifier.make(try SoftwareP256SigningKey().publicKey.signingKey()), capabilities: capabilities,
                                      displayHint: "Account ending 4821", subject: subject, issuedAt: issuedAt ?? now,
                                      expiresAt: (issuedAt ?? now).addingTimeInterval(expiresIn))
        let signed = try await SignedStatement.sign(d.object(signerKid: kid), domain: LinkDomainSeparator.descriptor, with: key)
        return ViadereSignedStatement(kid: kid, payload: signed.payload, signature: signed.signature)
    }

    func statement(capabilities: [Capability] = [.messageSend], descriptorDigest: String = String(repeating: "a", count: 64), approval: SignedStatement? = nil,
                   key: SoftwareP256SigningKey = SoftwareP256SigningKey(), sessionId: UUID? = nil, subject: SubjectRef? = nil) async throws -> SignedStatement {
        try await LinkStatement(sessionId: sessionId ?? session, businessId: business, subject: subject ?? self.subject, capabilities: capabilities,
                                descriptorDigest: descriptorDigest, publicKey: key.publicKey, approvalStatement: approval, createdAt: now).sign(with: key)
    }

    // MARK: Descriptor

    @Test func theDeviceAcceptsOnlyADescriptorSignedByAPinnedKey() async throws {
        let signed = try await descriptor()
        let parsed = try LinkSessionDescriptor.verify(signed, trustedKeys: [viadere.publicKey], now: now)
        #expect(parsed.capabilities.map(\.rawValue) == ["auth.challenge", "message.send"], "canonical order")
        #expect(parsed.subject == subject)
        // Spoofed business: a descriptor signed by any other key (a relay or a man in the middle that does not hold the KMS key).
        let forged = try await descriptor(signer: SoftwareP256SigningKey())
        #expect(throws: LinkSessionError.untrustedSigner) { try LinkSessionDescriptor.verify(forged, trustedKeys: [viadere.publicKey], now: now) }
        // The pinned key's id on a forged signature.
        var relabelled = forged
        relabelled.kid = viadereKid
        #expect(throws: LinkSessionError.badSignature) { try LinkSessionDescriptor.verify(relabelled, trustedKeys: [viadere.publicKey], now: now) }
        // A tampered payload (another business name, more capabilities).
        var tampered = signed
        let payload = String(decoding: try #require(Base64URL.decode(signed.payload)), as: UTF8.self).replacingOccurrences(of: "Northwind Bank", with: "Northwind Bonk")
        tampered.payload = Base64URL.encode(Data(payload.utf8))
        #expect(throws: LinkSessionError.badSignature) { try LinkSessionDescriptor.verify(tampered, trustedKeys: [viadere.publicKey], now: now) }
        // No pinned key at all: fail closed.
        #expect(throws: LinkSessionError.untrustedSigner) { try LinkSessionDescriptor.verify(signed, trustedKeys: [], now: now) }
    }

    @Test func anExpiredOrLongLivedDescriptorIsRefused() async throws {
        let signed = try await descriptor()
        #expect(throws: LinkSessionError.expired) { try LinkSessionDescriptor.verify(signed, trustedKeys: [viadere.publicKey], now: now.addingTimeInterval(301)) }
        let future = try await descriptor(issuedAt: now.addingTimeInterval(120))
        #expect(throws: LinkSessionError.issuedInFuture) { try LinkSessionDescriptor.verify(future, trustedKeys: [viadere.publicKey], now: now) }
        let tooLong = try await descriptor(expiresIn: 3600)
        #expect(throws: LinkSessionError.malformed("descriptor")) { try LinkSessionDescriptor.verify(tooLong, trustedKeys: [viadere.publicKey], now: now) }
        let unknownCapability = try await descriptor(capabilities: [.unknown("loop.run_anything")])
        #expect(throws: LinkSessionError.malformed("descriptor")) { try LinkSessionDescriptor.verify(unknownCapability, trustedKeys: [viadere.publicKey], now: now) }
    }

    // MARK: Statement

    @Test func theStatementIsBoundToItsSessionBusinessAccountCapabilitiesAndDescriptor() async throws {
        let signed = try await statement(capabilities: [.messageSend, .consentRequest])
        let parsed = try LinkStatement.verify(signed)
        try parsed.checkBinding(sessionId: session, businessId: business, subject: subject, capabilities: [.consentRequest, .messageSend, .messageSend],
                                descriptorDigest: String(repeating: "a", count: 64))
        #expect(throws: LinkSessionError.wrongSession) { try parsed.checkBinding(sessionId: UUID(), businessId: business, subject: subject, capabilities: [.messageSend, .consentRequest]) }
        #expect(throws: LinkSessionError.wrongBusiness) { try parsed.checkBinding(sessionId: session, businessId: BusinessID(), subject: subject, capabilities: [.messageSend, .consentRequest]) }
        let other = SubjectRef.derive(key: SymmetricKey(size: .bits256), businessId: business, consumerId: ConsumerID())
        #expect(throws: LinkSessionError.wrongSubject) { try parsed.checkBinding(sessionId: session, businessId: business, subject: other, capabilities: [.messageSend, .consentRequest]) }
        #expect(throws: LinkSessionError.wrongCapabilities) { try parsed.checkBinding(sessionId: session, businessId: business, subject: subject, capabilities: [.messageSend]) }
        #expect(throws: LinkSessionError.wrongDescriptor) {
            try parsed.checkBinding(sessionId: session, businessId: business, subject: subject, capabilities: [.messageSend, .consentRequest], descriptorDigest: String(repeating: "b", count: 64))
        }
        // A forged signature over the same payload.
        let otherSignature = try await statement().signature
        #expect(throws: LinkSessionError.badSignature) { try LinkStatement.verify(SignedStatement(payload: signed.payload, signature: otherSignature)) }
    }

    @Test func approvalCapabilitiesNeedTheMatchingApprovalStatement() async throws {
        let approvalKey = SoftwareP256SigningKey()
        let approval = try await ApprovalEnrollmentStatement(businessId: business, subject: subject, enrollmentId: session, publicKey: approvalKey.publicKey,
                                                             hpkePublicKey: SoftwareE2EEPrivateKey().publicKey, assurance: .biometric, createdAt: now).sign(with: approvalKey)
        let signed = try await statement(capabilities: [.transactionApprove], approval: approval)
        let parsed = try LinkStatement.verify(signed)
        #expect(try parsed.checkApprovalStatement(approval)?.kid == KeyIdentifier.make(try approvalKey.publicKey.signingKey()))
        // Substituted approval key (the relay swaps in its own key after the device signed): the digest no longer matches.
        let relayKey = SoftwareP256SigningKey()
        let substituted = try await ApprovalEnrollmentStatement(businessId: business, subject: subject, enrollmentId: session, publicKey: relayKey.publicKey,
                                                                hpkePublicKey: SoftwareE2EEPrivateKey().publicKey, assurance: .biometric, createdAt: now).sign(with: relayKey)
        #expect(throws: LinkSessionError.approvalStatementMismatch) { try parsed.checkApprovalStatement(substituted) }
        #expect(throws: LinkSessionError.approvalStatementMismatch) { try parsed.checkApprovalStatement(nil) }
        // An approval capability without any approval statement, and a weaker key than the capability needs.
        let missing = try LinkStatement.verify(try await statement(capabilities: [.transactionApprove]))
        #expect(throws: LinkSessionError.approvalStatementMismatch) { try missing.checkApprovalStatement(nil) }
        let presence = try await ApprovalEnrollmentStatement(businessId: business, subject: subject, enrollmentId: session, publicKey: approvalKey.publicKey,
                                                             hpkePublicKey: SoftwareE2EEPrivateKey().publicKey, assurance: .presence, createdAt: now).sign(with: approvalKey)
        let weak = try LinkStatement.verify(try await statement(capabilities: [.transactionApprove], approval: presence))
        #expect(throws: LinkSessionError.approvalStatementMismatch) { try weak.checkApprovalStatement(presence) }
        // And no approval statement may ride along with messaging-only capabilities.
        let messaging = try LinkStatement.verify(try await statement(capabilities: [.messageSend]))
        #expect(throws: LinkSessionError.approvalStatementMismatch) { try messaging.checkApprovalStatement(approval) }
    }

    // MARK: Session swapping and relay substitution

    @Test func aRelaySubstitutedStatementFailsTheBindingTagAndShowsADifferentSAS() async throws {
        let es = LinkSessionSecret()
        let device = try await statement()
        let tag = es.bindingTag(for: device)
        #expect(es.verifyBindingTag(tag, for: device))
        // The relay replaces the statement with one of its own key: it cannot compute a tag for it, and the device's tag does not move.
        let relay = try await statement()
        #expect(!es.verifyBindingTag(tag, for: relay))
        #expect(!LinkSessionSecret().verifyBindingTag(tag, for: device), "another session's secret")
        // The SAS the person compares differs (except with probability 10^-6), and the relay cannot compute either without the check code.
        let deviceSAS = try #require(LinkSAS.compute(checkCode: es.checkCode, statement: device))
        #expect(es.verifySAS(deviceSAS, for: device))
        #expect(es.verifySAS(LinkSAS.display(deviceSAS), for: device), "spaces are ignored")
        #expect(!es.verifySAS(deviceSAS, for: relay))
        #expect(es.expectedSAS(for: relay) != deviceSAS)
        // The typed path: the person types the check code; the phone shows the same six digits the business computes from `es`.
        #expect(LinkSAS.compute(checkCode: LinkSessionCode.display(es.checkCode).lowercased(), statement: device) == deviceSAS)
        // Approve v2's SAS is a different domain: a value from one protocol is never valid in the other.
        #expect(ApprovalEnrollmentSAS.compute(checkCode: es.checkCode, statement: device) != deviceSAS)
    }

    @Test func theConfirmationMustCoverTheDevicesOwnStatement() async throws {
        let businessKey = SoftwareP256SigningKey()
        let signed = try await statement()
        let parsed = try LinkStatement.verify(signed)
        let confirmation = try await LinkConfirmation(confirming: parsed, signed: signed, verification: .sasTyped, at: now).sign(with: businessKey)
        let verified = try LinkConfirmation.verify(confirmation, confirmationKey: businessKey.publicKey)
        try verified.checkMatches(parsed, signed: signed)
        #expect(verified.verification == .sasTyped)
        // A confirmation of the relay's statement (the business was shown another one) does not activate the device's link.
        let relay = try await statement()
        let relayParsed = try LinkStatement.verify(relay)
        let wrong = try LinkConfirmation.verify(try await LinkConfirmation(confirming: relayParsed, signed: relay, verification: .sasTyped, at: now).sign(with: businessKey),
                                                confirmationKey: businessKey.publicKey)
        #expect(throws: LinkSessionError.keyMismatch) { try wrong.checkMatches(parsed, signed: signed) }
        // A confirmation signed by another key than the one it names.
        #expect(throws: LinkSessionError.keyMismatch) { try LinkConfirmation.verify(confirmation, confirmationKey: SoftwareP256SigningKey().publicKey) }
        // An Approve v2 confirmation is not a link confirmation (domain separation).
        var crossProtocol = confirmation
        crossProtocol.signature = try await BusinessSignedStatement.sign(verified.object(confirmKid: confirmation.kid), domain: ApproveDomain.confirmation, with: businessKey).signature
        #expect(throws: LinkSessionError.badSignature) { try LinkConfirmation.verify(crossProtocol, confirmationKey: businessKey.publicKey) }
    }

    @Test func theResultIsVerifiedAgainstViaderesPinnedKey() async throws {
        let result = LinkResult(sessionId: session, businessId: business, subject: subject, statementDigest: String(repeating: "c", count: 64), approvalStatementDigest: nil, completedAt: now)
        let signed = try await SignedStatement.sign(result.object(signerKid: viadereKid), domain: LinkDomainSeparator.result, with: viadere)
        let wrapped = ViadereSignedStatement(kid: viadereKid, payload: signed.payload, signature: signed.signature)
        #expect(try LinkResult.verify(wrapped, trustedKeys: [viadere.publicKey]).subject == subject)
        #expect(throws: LinkSessionError.untrustedSigner) { try LinkResult.verify(wrapped, trustedKeys: [SoftwareP256SigningKey().publicKey]) }
        // A descriptor signature is never a result signature.
        let asDescriptor = try await SignedStatement.sign(result.object(signerKid: viadereKid), domain: LinkDomainSeparator.descriptor, with: viadere)
        #expect(throws: LinkSessionError.badSignature) {
            try LinkResult.verify(ViadereSignedStatement(kid: viadereKid, payload: asDescriptor.payload, signature: asDescriptor.signature), trustedKeys: [viadere.publicKey])
        }
    }

    // MARK: Links

    @Test func theLinkIsBuiltAndParsedStrictly() throws {
        let es = LinkSessionSecret()
        let link = LinkSessionLink.build(code: "ABCDEFGH", secret: es, domain: staging)
        #expect(link == "https://viadere.cksites.dev/k/ABCDEFGH#es=\(es.base64URL)")
        let url = try #require(URL(string: link))
        let parsed = try #require(LinkSessionLink.parse(url, domain: staging))
        #expect(parsed.code == "ABCDEFGH")
        #expect(parsed.secret == es)
        #expect(LinkSessionLink.parse(try #require(URL(string: "https://viadere.cksites.dev/k/ABCDEFGH")), domain: staging)?.secret == nil)
        for bad in ["https://viadere.com/k/ABCDEFGH", "https://www.viadere.cksites.dev/k/ABCDEFGH", "http://viadere.cksites.dev/k/ABCDEFGH",
                    "https://viadere.cksites.dev:8443/k/ABCDEFGH", "https://u@viadere.cksites.dev/k/ABCDEFGH", "https://viadere.cksites.dev/k/ABCDEFGH?x=1",
                    "https://viadere.cksites.dev/k/ABCD-EFGH", "https://viadere.cksites.dev/k/abcdefgh", "https://viadere.cksites.dev/k/ABCDEFGH/x",
                    "https://viadere.cksites.dev/k/ABCDEFGH#es=short", "https://viadere.cksites.dev/k/ABCDEFGH#rk=\(es.base64URL)",
                    "https://viadere.cksites.dev/a/ABCDEFGH"] {
            #expect(LinkSessionLink.parse(try #require(URL(string: bad)), domain: staging) == nil, "\(bad)")
        }
    }

    @Test func thePseudonymIsPairwise() {
        let other = SubjectRef.derive(key: SymmetricKey(size: .bits256), businessId: BusinessID(), consumerId: ConsumerID())
        #expect(LinkPseudonym.make(subject) == LinkPseudonym.make(subject))
        #expect(LinkPseudonym.make(subject) != LinkPseudonym.make(other))
        #expect(LinkPseudonym.make(subject).count == 9)
    }

    // MARK: Action registry and alerts (spec v4 A4, C5)

    @Test func theActionRegistryHoldsItsInvariants() {
        #expect(ActionRegistry.audit() == [])
        #expect(Set(Capability.known.filter { ActionRegistry.grant($0) != nil }.map(\.rawValue))
            == ["message.send", "contact.reachable", "consent.request", "auth.challenge", "transaction.approve"])
        #expect(ActionRegistry.grant(.identityName) == nil, "verification is never granted by linking: it needs a per-request receipt")
        #expect(ActionRegistry.grant(.transactionApprove)?.risk == .high)
        #expect(ActionRegistry.approval(for: .transactionApprove)?.timeout == 30...600)
        #expect(ActionRegistry.loops.allSatisfy { !$0.isLive && !$0.linkable })
        #expect(ActionRegistry.definition(ActionID("loop.run_anything")) == nil)
    }

    @Test func anExpiredAlertIsNeverActionable() {
        let alert = AlertDescriptor(eventId: AlertDescriptor.eventId(kind: "approve_request", id: session), category: .approval, businessId: business,
                                    urgency: .critical, status: .pending, expiresAt: now.addingTimeInterval(60), action: ActionRegistry.approveTransaction.id, now: now)
        #expect(alert.isActionable(at: now))
        #expect(!alert.isActionable(at: now.addingTimeInterval(61)))
        let expired = AlertDescriptor(eventId: alert.eventId, category: .approval, businessId: business, urgency: .critical, status: .pending,
                                      expiresAt: now.addingTimeInterval(-1), action: nil, now: now)
        #expect(!expired.actionable)
        #expect(alert.eventId == AlertDescriptor.eventId(kind: "approve_request", id: session), "stable: the dedupe key")
        #expect(alert.eventId != AlertDescriptor.eventId(kind: "link_session", id: session))
        #expect(alert.eventId.hasPrefix("alr_") && alert.eventId.count == 36)
    }
}

extension SubjectRef {
    static func derive(key: SymmetricKey, businessId: BusinessID, consumerId: ConsumerID) -> SubjectRef {
        SubjectRefDeriver(key: key).subjectRef(businessId: businessId, consumerId: consumerId)
    }
}
