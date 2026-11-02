import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// The app side of "Verify with Viadere" (`docs/SECURITY.md` §2.100): the link routes strictly, the review shows only what Viadere signed, and the
/// app accepts exactly that, never opening a return URL outside the session's origin.
@Suite("Verification sessions (app)")
struct VerificationSessionFlowTests {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    let viadere = SoftwareP256SigningKey()
    let businessId = BusinessID()
    let sessionId = UUID()
    let subject = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 9, count: 32)))!

    actor FakeAPI: VerificationSessionAPI {
        var offer: VerificationSessionOffer
        var accepted: VerificationSessionAccepted?
        private(set) var acceptRequests: [VerificationSessionAcceptRequest] = []
        init(offer: VerificationSessionOffer, accepted: VerificationSessionAccepted?) {
            self.offer = offer
            self.accepted = accepted
        }
        func lookupVerificationSession(code: String) async throws -> VerificationSessionOffer { offer }
        func acceptVerificationSession(id: UUID, request: VerificationSessionAcceptRequest) async throws -> VerificationSessionAccepted {
            acceptRequests.append(request)
            guard let accepted else { throw CancellationError() }
            return accepted
        }
    }

    func descriptor(origin: String = "https://shop.northwind.example", signer: SoftwareP256SigningKey? = nil, subject: SubjectRef? = nil) async throws -> ViadereSignedStatement {
        let key = signer ?? viadere
        let kid = KeyIdentifier.make(try key.publicKey.signingKey())
        let d = VerificationSessionDescriptor(sessionId: sessionId, businessId: businessId, businessName: "Northwind Spirits", businessDomain: "northwind.example",
                                              origin: origin, capability: .ageMinimum, parameters: ["years": .integer(21)], purposeCode: "age_restricted_purchase",
                                              subject: subject ?? self.subject, issuedAt: Self.now, expiresAt: Self.now.addingTimeInterval(300))
        let signed = try await SignedStatement.sign(d.object(signerKid: kid), domain: VerificationSessionDomainSeparator.descriptor, with: key)
        return ViadereSignedStatement(kid: kid, payload: signed.payload, signature: signed.signature)
    }

    func offer(_ descriptor: ViadereSignedStatement, connected: Bool = false) throws -> VerificationSessionOffer {
        VerificationSessionOffer(sessionId: sessionId, descriptor: descriptor,
                                 business: BusinessSummary(id: businessId, displayName: "Northwind Spirits", handle: nil, code: try BusinessCode("SK1234"), verificationStatus: .verified),
                                 subjectRef: subject, alreadyConnected: connected, expiresAt: Self.now.addingTimeInterval(300))
    }

    func prompt(capability: Capability = .ageMinimum, business: BusinessID? = nil) -> VerificationPrompt {
        VerificationPrompt(id: VerificationRequestID(), status: .pendingConsent, businessId: business ?? businessId, recipientName: "Northwind Spirits", recipientHandle: nil,
                           recipientVerified: true, capability: capability, parameters: ["years": .integer(21)], purposeCode: "age_restricted_purchase",
                           disclosure: [], notDisclosed: [], includedMetadata: [], methods: [], createdAt: Self.now, expiresAt: Self.now.addingTimeInterval(600),
                           displayDigest: "")
    }

    func flow(_ api: FakeAPI, keys: [DevicePublicKey]? = nil, at: Date = Self.now) -> VerificationSessionFlow {
        VerificationSessionFlow(api: api, descriptorKeys: keys ?? [viadere.publicKey], clock: { at })
    }

    @Test func theLinkRoutesStrictly() {
        let domain = LinkDomain.production
        #expect(DeepLinkRouter.route("https://viadere.com/v/K7QFM2XA", domain: domain) == .verificationSession(code: "K7QFM2XA"))
        for bad in ["https://viadere.com/v/K7QFM2XA?return=https://evil.test", "https://viadere.com/v/K7QFM2XA#x", "https://viadere.com/v/k7qfm2xa",
                    "https://evil.test/v/K7QFM2XA", "https://viadere.com/v/K7QFM2XA/more", "viadere://v/K7QFM2XA"] {
            #expect(DeepLinkRouter.route(bad, domain: domain) == nil, "\(bad)")
        }
    }

    @Test func theReviewShowsOnlyWhatViadereSigned() async throws {
        let api = FakeAPI(offer: try offer(try await descriptor()), accepted: nil)
        let review = try await flow(api).review(code: "K7QFM2XA")
        #expect(review.businessName == "Northwind Spirits")
        #expect(review.businessDomain == "northwind.example")
        #expect(review.originHost == "shop.northwind.example")
        #expect(review.connects)
        #expect(review.disclosure.map(\.field) == ["meets_threshold"])
        #expect(review.warning.contains("shop.northwind.example"))
        // A relay's own signature, a pinned-key build missing, another account's descriptor: nothing to review.
        await #expect(throws: VerificationSessionFlowError.descriptorInvalid(.untrustedSigner)) {
            try await flow(FakeAPI(offer: try offer(try await descriptor(signer: SoftwareP256SigningKey())), accepted: nil)).review(code: "K7QFM2XA")
        }
        await #expect(throws: VerificationSessionFlowError.notConfigured) { try await flow(api, keys: []).review(code: "K7QFM2XA") }
        let other = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 1, count: 32)))!
        await #expect(throws: VerificationSessionFlowError.mismatch) {
            try await flow(FakeAPI(offer: try offer(try await descriptor(subject: other)), accepted: nil)).review(code: "K7QFM2XA")
        }
        await #expect(throws: VerificationSessionFlowError.expired) { try await flow(api, at: Self.now.addingTimeInterval(301)).review(code: "K7QFM2XA") }
    }

    @Test func acceptingQuotesTheDescriptorAndNeverOpensAnotherOrigin() async throws {
        let signed = try await descriptor()
        let good = prompt()
        let api = FakeAPI(offer: try offer(signed), accepted: VerificationSessionAccepted(sessionId: sessionId, prompt: good, returnURL: "https://shop.northwind.example/checkout"))
        let f = flow(api)
        let review = try await f.review(code: "K7QFM2XA")
        let (accepted, back) = try await f.accept(review)
        #expect(accepted == good)
        #expect(back?.absoluteString == "https://shop.northwind.example/checkout")
        #expect(await api.acceptRequests == [VerificationSessionAcceptRequest(descriptorDigest: VerificationSessionDescriptor.digest(of: signed))])

        // A compromised relay cannot turn the app into an open redirect, nor swap in another business's request or another capability.
        for evil in ["https://evil.test/", "https://northwind.example/", "javascript:alert(1)"] {
            let api2 = FakeAPI(offer: try offer(signed), accepted: VerificationSessionAccepted(sessionId: sessionId, prompt: good, returnURL: evil))
            #expect(try await flow(api2).accept(review).returnURL == nil, "\(evil)")
        }
        for swapped in [prompt(capability: .identityName), prompt(business: BusinessID())] {
            let api3 = FakeAPI(offer: try offer(signed), accepted: VerificationSessionAccepted(sessionId: sessionId, prompt: swapped, returnURL: nil))
            await #expect(throws: VerificationSessionFlowError.promptMismatch) { try await flow(api3).accept(review) }
        }
    }
}
