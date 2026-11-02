@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Verification sessions — the "Verify with Viadere" button (`docs/SECURITY.md` §2.100). Each test reproduces an attack on the hand-off (QR / universal
/// link) or on the result and shows it is refused: origin binding, single use, short expiry, descriptor binding, tenant isolation, signed results.
private func aneq<T: Equatable>(_ lhs: T, _ rhs: T, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertNotEqual(lhs, rhs, message, file: file, line: line)
}

final class VerificationSessionTests: XCTestCase {
    let pki = TestMDocPKI()
    let merchantKey = P256.KeyAgreement.PrivateKey()

    struct Rig {
        var h: TestHarness
        var b: TestBusiness
        var domain: String
        var origin: String { "https://shop." + domain }
    }

    func withVerify(enabled: Bool = true, _ body: (TestHarness) async throws -> Void) async throws {
        try await withHarness({ config in
            config.verify.enabled = enabled
            config.verify.walletMerchantIdentifier = TestWalletSealer.merchant
            config.verify.walletEncryptionKeyPaths = ["test-only"]
            config.verify.walletIACADirectory = "test-only"
        }) { h in
            h.app.verify.trust = pki.trustStore()
            h.app.verify.walletKeys = LocalWalletEncryptionKeys([merchantKey])
            try await body(h)
        }
    }

    func rig(_ h: TestHarness, name: String = "Northwind Spirits", handle: String = "northwindspirits", live: Bool = true,
             capabilities: [Capability] = Capability.operational + [.ageMinimum, .identityName, .identityAddress, .identityVerified]) async throws -> Rig {
        let b = try await h.makeBusiness(name: name, handle: handle, live: live, capabilities: capabilities)
        try await h.ensureVerifiedDomain(b.id.uuid)
        let record = try await XCTUnwrapAsync(try await BusinessDomainRecord.query(on: h.db).filter(\.$businessId == b.id.uuid).first())
        return Rig(h: h, b: b, domain: try XCTUnwrap(record.verifiedDomain))
    }

    func create(_ r: Rig, origin: String? = nil, returnURL: String? = nil, capability: Capability = .ageMinimum, years: Int64 = 21,
                purpose: String = "age_restricted_purchase", expires: Int? = nil, key: String? = nil) async throws -> HTTPResult {
        try await r.h.businessPost(r.b, APIRoutes.businessVerificationSessionCreate.template,
            CreateVerificationSessionRequest(capability: capability, parameters: capability == .ageMinimum ? ["years": .integer(years)] : [:], purposeCode: purpose,
                                             origin: origin ?? r.origin, returnURL: returnURL, expiresInSeconds: expires), key: key)
    }

    func ticket(_ r: Rig, returnURL: String? = nil) async throws -> VerificationSessionTicket {
        let created = try await create(r, returnURL: returnURL)
        XCTAssertEqual(created.status, .created, created.text)
        return try created.json(VerificationSessionTicket.self)
    }

    func lookup(_ h: TestHarness, _ consumer: TestConsumer, code: String) async throws -> HTTPResult {
        try await h.signedPost(consumer, APIRoutes.verificationSessionLookup.template, VerificationSessionLookupRequest(code: code))
    }

    /// The app: looks the code up, verifies the descriptor with Viadere's pinned key, accepts exactly what it showed.
    func accept(_ h: TestHarness, _ consumer: TestConsumer, _ ticket: VerificationSessionTicket, digest: String? = nil) async throws -> (HTTPResult, VerificationSessionDescriptor?) {
        let looked = try await lookup(h, consumer, code: ticket.displayCode)
        guard looked.status == .ok else { return (looked, nil) }
        let offer = try looked.json(VerificationSessionOffer.self)
        let descriptor = try VerificationSessionDescriptor.verify(offer.descriptor, trustedKeys: [h.config.approve.linkDescriptorKey.publicKey], now: h.clock.now())
        let accepted = try await h.signedPost(consumer, "/v1/verification-sessions/\(descriptor.sessionId.uuidString.lowercased())/accept",
                                              VerificationSessionAcceptRequest(descriptorDigest: digest ?? VerificationSessionDescriptor.digest(of: offer.descriptor)))
        return (accepted, descriptor)
    }

    func view(_ r: Rig, _ id: UUID, business: TestBusiness? = nil) async throws -> HTTPResult {
        try await r.h.business(business ?? r.b, .GET, "/v1/business/verification-sessions/\(id.uuidString.lowercased())")
    }

    func consentAndPresentAge(_ h: TestHarness, _ consumer: TestConsumer, _ prompt: VerificationPrompt, over years: Int = 21, value: Bool = true) async throws -> HTTPResult {
        let consent = try await h.signedPost(consumer, "/v1/verifications/\(prompt.id)/consent", VerificationConsentRequest(displayDigest: prompt.renderedDigest()))
        XCTAssertEqual(consent.status, .ok, consent.text)
        let begin = try await h.signedPost(consumer, "/v1/verifications/\(prompt.id)/wallet/begin", EmptyBody())
        XCTAssertEqual(begin.status, .ok, begin.text)
        let start = try begin.json(WalletAttemptStart.self)
        let envelope = try TestWalletSealer.seal(TestMDoc(pki: pki, elements: TestMDoc.ageOver(years, value)), nonce: try XCTUnwrap(Base64URL.decode(start.nonce)),
                                                 recipient: merchantKey.publicKey)
        return try await h.signedPost(consumer, "/v1/verifications/\(prompt.id)/wallet/complete",
                                      WalletAttemptComplete(attemptId: start.attemptId, envelope: Base64URL.encode(envelope)))
    }

    // MARK: Happy path

    func testAVerifiedSessionEndsWithASignedResultTheBusinessCanCheck() async throws {
        try await withVerify { h in
            let r = try await rig(h)
            let consumer = try await h.readyConsumer()
            let t = try await ticket(r, returnURL: r.origin + "/checkout?step=2")
            XCTAssertEqual(t.link, "https://viadere.com/v/\(t.code)", "a plain link: no secret, no query, nothing about the business")
            XCTAssertLessThanOrEqual(t.expiresAt.timeIntervalSince(h.clock.now()), 300)
            let open = try await view(r, t.sessionId).json(VerificationSessionView.self)
            XCTAssertEqual(open.status, .open)
            XCTAssertNil(open.result)

            // The app shows the verified business, its verified domain and the origin before anything happens.
            let (accepted, descriptor) = try await accept(h, consumer, t)
            XCTAssertEqual(accepted.status, .created, accepted.text)
            let d = try XCTUnwrap(descriptor)
            XCTAssertEqual(d.businessName, "Northwind Spirits")
            XCTAssertEqual(d.originHost, "shop." + r.domain)
            XCTAssertEqual(d.businessDomain, r.domain)
            XCTAssertEqual(d.subject, h.subjectRef(r.b, consumer))
            let body = try accepted.json(VerificationSessionAccepted.self)
            XCTAssertEqual(body.returnURL, r.origin + "/checkout?step=2")
            XCTAssertEqual(body.prompt.status, .pendingConsent)
            XCTAssertEqual(body.prompt.recipientName, "Northwind Spirits")
            XCTAssertEqual(body.prompt.capability, .ageMinimum)
            // Accepting connected the account (the app said so); the request is an ordinary one, so the ordinary consent flow applies.
            let relationship = try await XCTUnwrapAsync(try await RelationshipRecord.query(on: h.db).filter(\.$consumerId == consumer.id.uuid).filter(\.$businessId == r.b.id.uuid).first())
            XCTAssertTrue(relationship.isActive)
            let accepting = try await view(r, t.sessionId).json(VerificationSessionView.self)
            XCTAssertEqual(accepting.status, .accepted)
            XCTAssertEqual(accepting.requestId, body.prompt.id)
            XCTAssertNil(accepting.result, "no result before the request ends")

            let released = try await consentAndPresentAge(h, consumer, body.prompt)
            XCTAssertEqual(released.status, .ok, released.text)
            let done = try await view(r, t.sessionId).json(VerificationSessionView.self)
            XCTAssertEqual(done.status, .completed)
            let result = try VerificationSessionResult.verify(try XCTUnwrap(done.result), trustedKeys: [h.config.approve.linkDescriptorKey.publicKey])
            try result.check(sessionId: t.sessionId, businessId: r.b.id, origin: r.origin, capability: .ageMinimum)
            XCTAssertEqual(result.outcome, .verified)
            XCTAssertEqual(result.subject, h.subjectRef(r.b, consumer))
            XCTAssertEqual(result.requestId, body.prompt.id)
            let ref = try XCTUnwrap(done.resultRef)
            XCTAssertTrue(result.matches(ref))
            // The attribute values come from the ordinary single-use retrieval.
            let values = try await h.business(r.b, .GET, "/v1/verification-results/\(ref)")
            XCTAssertEqual(values.status, .ok, values.text)
            XCTAssertEqual(try values.json(VerificationResult.self).outcome, .verified)
            aeq(try await h.business(r.b, .GET, "/v1/verification-results/\(ref)").status, .gone)
        }
    }

    func testADeclineEndsWithASignedNotVerifiedThatSaysNothingMore() async throws {
        try await withVerify { h in
            let r = try await rig(h)
            let consumer = try await h.readyConsumer()
            let t = try await ticket(r)
            let (accepted, _) = try await accept(h, consumer, t)
            let prompt = try accepted.json(VerificationSessionAccepted.self).prompt
            aeq(try await h.signedPost(consumer, "/v1/verifications/\(prompt.id)/decline", EmptyBody()).status, .ok)
            let done = try await view(r, t.sessionId).json(VerificationSessionView.self)
            XCTAssertEqual(done.status, .completed)
            let result = try VerificationSessionResult.verify(try XCTUnwrap(done.result), trustedKeys: [h.config.approve.linkDescriptorKey.publicKey])
            XCTAssertEqual(result.outcome, .notVerified)
            XCTAssertFalse(try XCTUnwrap(Base64URL.decode(try XCTUnwrap(done.result).payload)).contains(Data("declined".utf8)), "AGE-005: no reason")
        }
    }

    // MARK: Origin binding

    func testTheOriginMustBeTheBusinesssVerifiedDomain() async throws {
        try await withVerify { h in
            let r = try await rig(h)
            // A phishing site cannot obtain a session that names its own origin under the business's name.
            for origin in ["https://evil.test", "https://" + r.domain + ".evil.test", "https://evil" + r.domain, "http://shop." + r.domain,
                           "https://shop." + r.domain + ":8443", "https://shop." + r.domain + "/path", "javascript:alert(1)"] {
                let created = try await create(r, origin: origin)
                XCTAssertNotEqual(created.status, .created, origin)
                XCTAssertTrue(created.text.contains("origin"), created.text)
            }
            // The apex domain and its subdomains are fine; the stored origin is canonical.
            aeq(try await create(r, origin: "https://" + r.domain.uppercased()).status, .created)
            // No open redirect: the return URL stays on the origin.
            for back in ["https://evil.test/", "https://" + r.domain + "/", "https://shop." + r.domain + "@evil.test/", "https://shop." + r.domain + "/#x"] {
                let created = try await create(r, returnURL: back)
                XCTAssertNotEqual(created.status, .created, back)
                XCTAssertTrue(created.text.contains("return_url"), created.text)
            }
            // A business without any verified domain cannot create one at all.
            let bare = try await h.makeBusiness(name: "No Domain", handle: "nodomain", capabilities: Capability.operational + [.ageMinimum])
            let refused = try await h.businessPost(bare, APIRoutes.businessVerificationSessionCreate.template,
                CreateVerificationSessionRequest(capability: .ageMinimum, parameters: ["years": .integer(18)], purposeCode: "age_restricted_purchase", origin: "https://nodomain.example"))
            XCTAssertNotEqual(refused.status, .created)
        }
    }

    func testCreationIsCapabilityGatedLiveOnlyAndShortLived() async throws {
        try await withVerify { h in
            // A key without the Verify capability learns nothing (acceptance 1 of Verify).
            let messaging = try await rig(h, name: "Messaging Only", handle: "messagingonly", capabilities: Capability.operational)
            aneq(try await create(messaging).status, .created)
            let r = try await rig(h)
            aneq(try await create(r, capability: .messageSend).status, .created, "only Verify capabilities")
            aneq(try await create(r, purpose: "Free text please").status, .created)
            for expires in [59, 301, 3600] { aneq(try await create(r, expires: expires).status, .created, "\(expires)") }
            aeq(try await create(r, expires: 60).status, .created)
            let sandbox = try await rig(h, name: "Sandbox Shop", handle: "sandboxshop", live: false)
            aeq(try await create(sandbox).status, .forbidden)
        }
    }

    // MARK: Single use, expiry, binding

    func testASessionIsAcceptedOnceAndThenNoLongerLooksUp() async throws {
        try await withVerify { h in
            let r = try await rig(h)
            let first = try await h.readyConsumer()
            let second = try await h.readyConsumer(name: "Someone Else")
            let t = try await ticket(r)
            // Someone else photographed the QR and looked it up, but only one accept wins.
            let theirs = try await lookup(h, second, code: t.code)
            XCTAssertEqual(theirs.status, .ok)
            let theirOffer = try theirs.json(VerificationSessionOffer.self)
            aeq(try await accept(h, first, t).0.status, .created)
            aeq(try await lookup(h, second, code: t.code).status, .notFound)
            let late = try await h.signedPost(second, "/v1/verification-sessions/\(t.sessionId.uuidString.lowercased())/accept",
                                              VerificationSessionAcceptRequest(descriptorDigest: VerificationSessionDescriptor.digest(of: theirOffer.descriptor)))
            XCTAssertEqual(late.status, .conflict, late.text)
            // A replay by the winner is a conflict too.
            let replay = try await h.signedPost(first, "/v1/verification-sessions/\(t.sessionId.uuidString.lowercased())/accept",
                                                VerificationSessionAcceptRequest(descriptorDigest: String(repeating: "a", count: 64)))
            XCTAssertEqual(replay.status, .conflict)
            aeq(try await VerificationRequestRecord.query(on: h.db).count(), 1)
        }
    }

    func testAnExpiredSessionNeitherLooksUpNorAccepts() async throws {
        try await withVerify { h in
            let r = try await rig(h)
            let consumer = try await h.readyConsumer()
            let created = try await create(r, expires: 60)
            let t = try created.json(VerificationSessionTicket.self)
            let offer = try await lookup(h, consumer, code: t.code).json(VerificationSessionOffer.self)
            h.clock.advance(by: 61)
            aeq(try await lookup(h, consumer, code: t.code).status, .notFound)
            let late = try await h.signedPost(consumer, "/v1/verification-sessions/\(t.sessionId.uuidString.lowercased())/accept",
                                              VerificationSessionAcceptRequest(descriptorDigest: VerificationSessionDescriptor.digest(of: offer.descriptor)))
            XCTAssertEqual(late.status, .gone, late.text)
            aeq(try await view(r, t.sessionId).json(VerificationSessionView.self).status, .expired)
        }
    }

    func testTheAppMustAcceptExactlyTheDescriptorItShowed() async throws {
        try await withVerify { h in
            let r = try await rig(h)
            let consumer = try await h.readyConsumer()
            let other = try await h.readyConsumer(name: "Other")
            let t = try await ticket(r)
            // Another account's descriptor (another subject_ref) or a made-up digest never accepts this account's session.
            let otherOffer = try await lookup(h, other, code: t.code).json(VerificationSessionOffer.self)
            let (wrong, _) = try await accept(h, consumer, t, digest: VerificationSessionDescriptor.digest(of: otherOffer.descriptor))
            XCTAssertEqual(wrong.status, .conflict, wrong.text)
            let (garbage, _) = try await accept(h, consumer, t, digest: "not-a-digest")
            XCTAssertEqual(garbage.status, .conflict)
            aeq(try await view(r, t.sessionId).json(VerificationSessionView.self).status, .open, "a refused accept does not spend the session")
            aeq(try await accept(h, consumer, t).0.status, .created)
        }
    }

    func testARevokedKeyOrACancelledSessionOpensNothing() async throws {
        try await withVerify { h in
            let r = try await rig(h)
            let consumer = try await h.readyConsumer()
            let cancelled = try await ticket(r)
            let c = try await h.businessPost(r.b, "/v1/business/verification-sessions/\(cancelled.sessionId.uuidString.lowercased())/cancel", EmptyBody())
            XCTAssertEqual(try c.json(VerificationSessionView.self).status, .cancelled)
            aeq(try await lookup(h, consumer, code: cancelled.code).status, .notFound)

            let t = try await ticket(r)
            let offer = try await lookup(h, consumer, code: t.code).json(VerificationSessionOffer.self)
            try await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == r.b.id.uuid).set(\.$revokedAt, to: h.clock.now()).update()
            let refused = try await h.signedPost(consumer, "/v1/verification-sessions/\(t.sessionId.uuidString.lowercased())/accept",
                                                 VerificationSessionAcceptRequest(descriptorDigest: VerificationSessionDescriptor.digest(of: offer.descriptor)))
            XCTAssertEqual(refused.status, .gone, refused.text)
            aeq(try await VerificationRequestRecord.query(on: h.db).count(), 0)
            aeq(try await RelationshipRecord.query(on: h.db).filter(\.$consumerId == consumer.id.uuid).count(), 0, "nothing was connected")
        }
    }

    // MARK: Tenant isolation (spec v4 D3)

    func testAnotherBusinessCannotReadOrCancelASession() async throws {
        try await withVerify { h in
            let r = try await rig(h)
            let rival = try await rig(h, name: "Rival Co", handle: "rivalco")
            let t = try await ticket(r)
            aeq(try await view(r, t.sessionId, business: rival.b).status, .notFound)
            aeq(try await h.businessPost(rival.b, "/v1/business/verification-sessions/\(t.sessionId.uuidString.lowercased())/cancel", EmptyBody()).status, .notFound)
            aeq(try await view(r, t.sessionId).json(VerificationSessionView.self).status, .open)
        }
    }

    // MARK: Web surface and release gate

    func testTheLandingPageLooksNothingUpAndTheAppClaimsTheLinks() async throws {
        try await withVerify { h in
            let r = try await rig(h)
            let t = try await ticket(r)
            let page = try await h.request(.GET, "/v/\(t.code)")
            XCTAssertEqual(page.status, .ok)
            XCTAssertFalse(page.text.contains("Northwind"), "no oracle: the page never names the business")
            XCTAssertTrue(page.text.contains(VerificationSessionCode.display(t.code)))
            XCTAssertEqual(page.headers.first(name: .cacheControl), "no-store")
            // An unknown but well-formed code looks the same; a malformed one is a 404 and nothing is echoed.
            aeq(try await h.request(.GET, "/v/ABCDEFGH").status, .ok)
            let hostile = try await h.request(.GET, "/v/%3Cscript%3E")
            XCTAssertEqual(hostile.status, .notFound)
            XCTAssertFalse(hostile.text.contains("<script>"))
            let aasa = try await h.request(.GET, "/.well-known/apple-app-site-association")
            XCTAssertTrue(aasa.text.contains("\"/v/*\""), aasa.text)
        }
    }

    func testEveryRouteIsClosedWhileVerifyIsOff() async throws {
        try await withVerify(enabled: false) { h in
            let r = try await rig(h)
            let consumer = try await h.readyConsumer()
            aeq(try await create(r).status, .notFound)
            aeq(try await view(r, UUID()).status, .notFound)
            aeq(try await lookup(h, consumer, code: "ABCDEFGH").status, .notFound)
        }
    }
}
