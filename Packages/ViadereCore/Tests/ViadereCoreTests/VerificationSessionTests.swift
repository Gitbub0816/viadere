import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// Verification sessions ("Verify with Viadere", `docs/SECURITY.md` §2.60). Each test reproduces an attack on the hand-off and shows it is refused.
@Suite("Verification sessions")
struct VerificationSessionTests {
    let viadere = SoftwareP256SigningKey()          // the `link-descriptor` key (KMS-held on the server)
    let business = BusinessID()
    let session = UUID()
    let subject = SubjectRef.derive(key: SymmetricKey(size: .bits256), businessId: BusinessID(), consumerId: ConsumerID())
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let staging = LinkDomain("viadere.cksites.dev")!

    var viadereKid: String { KeyIdentifier.make(try! viadere.publicKey.signingKey()) }

    func descriptor(origin: String = "https://shop.northwind.example", domain: String = "northwind.example", expiresIn: TimeInterval = 300,
                    issuedAt: Date? = nil, signer: SoftwareP256SigningKey? = nil, separator: String = VerificationSessionDomainSeparator.descriptor,
                    mutate: ((inout [String: JSONValue]) -> Void)? = nil) async throws -> ViadereSignedStatement {
        let key = signer ?? viadere
        let kid = KeyIdentifier.make(try key.publicKey.signingKey())
        let d = VerificationSessionDescriptor(sessionId: session, businessId: business, businessName: "Northwind Spirits", businessDomain: domain, origin: origin,
                                              capability: .ageMinimum, parameters: ["years": .integer(21)], purposeCode: "age_restricted_purchase",
                                              subject: subject, issuedAt: issuedAt ?? now, expiresAt: (issuedAt ?? now).addingTimeInterval(expiresIn))
        var object = d.object(signerKid: kid)
        mutate?(&object)
        let signed = try await SignedStatement.sign(object, domain: separator, with: key)
        return ViadereSignedStatement(kid: kid, payload: signed.payload, signature: signed.signature)
    }

    func result(outcome: VerificationOutcome = .verified, ref: VerificationResultRef, separator: String = VerificationSessionDomainSeparator.result,
                origin: String = "https://shop.northwind.example") async throws -> ViadereSignedStatement {
        let r = VerificationSessionResult(sessionId: session, businessId: business, requestId: VerificationRequestID(), subject: subject, capability: .ageMinimum,
                                          parameters: ["years": .integer(21)], purposeCode: "age_restricted_purchase", origin: origin, outcome: outcome,
                                          resultRef: ref, completedAt: now)
        let signed = try await SignedStatement.sign(r.object(signerKid: viadereKid), domain: separator, with: viadere)
        return ViadereSignedStatement(kid: viadereKid, payload: signed.payload, signature: signed.signature)
    }

    // MARK: Descriptor (what the person sees before accepting)

    @Test func theAppAcceptsOnlyADescriptorSignedByAPinnedKey() async throws {
        let signed = try await descriptor()
        let parsed = try VerificationSessionDescriptor.verify(signed, trustedKeys: [viadere.publicKey], now: now)
        #expect(parsed.businessName == "Northwind Spirits")
        #expect(parsed.originHost == "shop.northwind.example")
        #expect(parsed.capability == .ageMinimum)
        #expect(parsed.parameters["years"] == .integer(21))
        #expect(parsed.subject == subject)
        // A phishing relay signs its own descriptor ("Northwind Spirits" on its own origin): not a pinned key.
        let forged = try await descriptor(signer: SoftwareP256SigningKey())
        #expect(throws: VerificationSessionError.untrustedSigner) { try VerificationSessionDescriptor.verify(forged, trustedKeys: [viadere.publicKey], now: now) }
        // The signature must cover exactly the payload shown.
        var tampered = signed
        tampered.payload = try await descriptor(origin: "https://northwind.example").payload
        #expect(throws: VerificationSessionError.badSignature) { try VerificationSessionDescriptor.verify(tampered, trustedKeys: [viadere.publicKey], now: now) }
    }

    @Test func aLinkSessionSignatureIsNeverAVerificationSessionSignature() async throws {
        // Same key, another protocol: domain separation keeps a link-session descriptor (or result) from being replayed here.
        for separator in [LinkDomainSeparator.descriptor, LinkDomainSeparator.result, VerificationSessionDomainSeparator.result] {
            let crossProtocol = try await descriptor(separator: separator)
            #expect(throws: VerificationSessionError.badSignature) { try VerificationSessionDescriptor.verify(crossProtocol, trustedKeys: [viadere.publicKey], now: now) }
        }
    }

    @Test func aDescriptorIsShortLivedAndCurrent() async throws {
        let expired = try await descriptor(issuedAt: now.addingTimeInterval(-400))
        #expect(throws: VerificationSessionError.expired) { try VerificationSessionDescriptor.verify(expired, trustedKeys: [viadere.publicKey], now: now) }
        let future = try await descriptor(issuedAt: now.addingTimeInterval(120))
        #expect(throws: VerificationSessionError.issuedInFuture) { try VerificationSessionDescriptor.verify(future, trustedKeys: [viadere.publicKey], now: now) }
        // A session may never outlive five minutes (a QR photographed now is useless later).
        let long = try await descriptor(expiresIn: 301)
        #expect(throws: VerificationSessionError.malformed("descriptor")) { try VerificationSessionDescriptor.verify(long, trustedKeys: [viadere.publicKey], now: now) }
    }

    @Test func theOriginMustLieInsideTheVerifiedBusinessDomain() async throws {
        // Even a correctly signed descriptor is refused when its origin is not the business's own (defence in depth against a server bug).
        for origin in ["https://northwind.example.evil.test", "https://evilnorthwind.example", "https://example"] {
            let outside = try await descriptor(origin: origin)
            #expect(throws: (any Error).self) { try VerificationSessionDescriptor.verify(outside, trustedKeys: [viadere.publicKey], now: now) }
        }
        let apex = try await descriptor(origin: "https://northwind.example")
        #expect(try VerificationSessionDescriptor.verify(apex, trustedKeys: [viadere.publicKey], now: now).originHost == "northwind.example")
        // A non-canonical origin (path, port, upper case, http) is malformed.
        for origin in ["https://shop.northwind.example/", "https://shop.northwind.example:8443", "https://Shop.northwind.example", "http://shop.northwind.example"] {
            let odd = try await descriptor(origin: origin)
            #expect(throws: VerificationSessionError.malformed("descriptor")) { try VerificationSessionDescriptor.verify(odd, trustedKeys: [viadere.publicKey], now: now) }
        }
    }

    @Test func extraOrMissingMembersAreRefused() async throws {
        let extra = try await descriptor { $0["return_url"] = .string("https://evil.test/") }
        #expect(throws: VerificationSessionError.malformed("descriptor")) { try VerificationSessionDescriptor.verify(extra, trustedKeys: [viadere.publicKey], now: now) }
        let missing = try await descriptor { $0.removeValue(forKey: "purpose_code") }
        #expect(throws: VerificationSessionError.malformed("descriptor")) { try VerificationSessionDescriptor.verify(missing, trustedKeys: [viadere.publicKey], now: now) }
        let freeText = try await descriptor { $0["purpose_code"] = .string("Please verify now!") }
        #expect(throws: VerificationSessionError.malformed("descriptor")) { try VerificationSessionDescriptor.verify(freeText, trustedKeys: [viadere.publicKey], now: now) }
        let nested = try await descriptor { $0["parameters"] = .object(["years": .object(["a": .integer(1)])]) }
        #expect(throws: VerificationSessionError.malformed("descriptor")) { try VerificationSessionDescriptor.verify(nested, trustedKeys: [viadere.publicKey], now: now) }
        let unknownCapability = try await descriptor { $0["capability"] = .string("wallet.drain") }
        #expect(throws: VerificationSessionError.malformed("descriptor")) { try VerificationSessionDescriptor.verify(unknownCapability, trustedKeys: [viadere.publicKey], now: now) }
    }

    @Test func theAcceptDigestIsOverTheExactPayload() async throws {
        let a = try await descriptor()
        let b = try await descriptor(origin: "https://northwind.example")
        #expect(VerificationSessionDescriptor.digest(of: a) == SecureToken.sha256Hex(Data(a.payload.utf8)))
        #expect(VerificationSessionDescriptor.digest(of: a) != VerificationSessionDescriptor.digest(of: b))
    }

    // MARK: Result (what the business trusts)

    @Test func theResultIsVerifiedAgainstViaderesPinnedKeyAndChecked() async throws {
        let ref = VerificationResultRef.generate()
        let signed = try await result(ref: ref)
        let parsed = try VerificationSessionResult.verify(signed, trustedKeys: [viadere.publicKey])
        #expect(parsed.outcome == .verified)
        #expect(parsed.matches(ref))
        #expect(!parsed.matches(VerificationResultRef.generate()))
        try parsed.check(sessionId: session, businessId: business, origin: "https://shop.northwind.example", capability: .ageMinimum)
        // A result for another session, business, origin or capability is not this one (session swapping, tenant confusion).
        #expect(throws: VerificationSessionError.wrongSession) { try parsed.check(sessionId: UUID(), businessId: business, origin: "https://shop.northwind.example", capability: .ageMinimum) }
        #expect(throws: VerificationSessionError.wrongBusiness) { try parsed.check(sessionId: session, businessId: BusinessID(), origin: "https://shop.northwind.example", capability: .ageMinimum) }
        #expect(throws: VerificationSessionError.wrongOrigin) { try parsed.check(sessionId: session, businessId: business, origin: "https://other.northwind.example", capability: .ageMinimum) }
        #expect(throws: VerificationSessionError.wrongCapability) { try parsed.check(sessionId: session, businessId: business, origin: "https://shop.northwind.example", capability: .identityName) }
        // Untrusted signer; a descriptor signature or a link-session result is not a verification result.
        #expect(throws: VerificationSessionError.untrustedSigner) { try VerificationSessionResult.verify(signed, trustedKeys: [SoftwareP256SigningKey().publicKey]) }
        for separator in [VerificationSessionDomainSeparator.descriptor, LinkDomainSeparator.result] {
            let cross = try await result(ref: ref, separator: separator)
            #expect(throws: VerificationSessionError.badSignature) { try VerificationSessionResult.verify(cross, trustedKeys: [viadere.publicKey]) }
        }
        // A forged "verified" over a "not_verified" payload.
        let notVerified = try await result(outcome: .notVerified, ref: ref)
        var flipped = notVerified
        flipped.payload = signed.payload
        #expect(throws: VerificationSessionError.badSignature) { try VerificationSessionResult.verify(flipped, trustedKeys: [viadere.publicKey]) }
        // The result carries no personal data: the outcome and digests only.
        let text = signed.payload
        for word in ["given_name", "family_name", "address", "birth", "1990"] { #expect(!(Base64URL.decode(text).map { String(decoding: $0, as: UTF8.self) } ?? text).contains(word)) }
    }

    // MARK: Link, origin, return URL

    @Test func theLinkIsBuiltAndParsedStrictly() throws {
        let code = "ABCDEFGH"
        #expect(VerificationSessionLink.build(code: code, domain: .production) == "https://viadere.com/v/ABCDEFGH")
        #expect(VerificationSessionLink.build(code: code, domain: staging) == "https://viadere.cksites.dev/v/ABCDEFGH")
        #expect(VerificationSessionLink.parse(URL(string: "https://viadere.com/v/ABCDEFGH")!, domain: .production) == code)
        #expect(VerificationSessionLink.parse(URL(string: "https://viadere.cksites.dev/v/ABCDEFGH")!, domain: staging) == code)
        for bad in ["http://viadere.com/v/ABCDEFGH", "https://www.viadere.com/v/ABCDEFGH", "https://viadere.com:443/v/ABCDEFGH",
                    "https://user@viadere.com/v/ABCDEFGH", "https://viadere.com/v/ABCDEFGH?x=1", "https://viadere.com/v/ABCDEFGH#es=x",
                    "https://viadere.com/v/abcdefgh", "https://viadere.com/v/ABCD-EFGH", "https://viadere.com/k/ABCDEFGH", "https://viadere.com/v/ABCDEFGH/x",
                    "https://viadere.com.evil.test/v/ABCDEFGH", "https://VIADERE.com/v/ABCDEFGH", "https://viadere.cksites.dev/v/ABCDEFGH"] {
            #expect(VerificationSessionLink.parse(URL(string: bad)!, domain: .production) == nil, "\(bad)")
        }
    }

    @Test func originsAreCanonicalHTTPSHostsOnly() {
        #expect(VerificationSessionOrigin.canonical("https://Shop.Northwind.example") == "https://shop.northwind.example")
        #expect(VerificationSessionOrigin.canonical("https://shop.northwind.example/") == "https://shop.northwind.example")
        for bad in ["http://shop.example", "https://shop.example:8443", "https://shop.example/path", "https://shop.example?x", "https://shop.example#x",
                    "https://u:p@shop.example", "https://10.0.0.1", "https://localhost", "javascript:alert(1)", "shop.example", "", "https://*.example",
                    "https://shop..example", "https://-shop.example"] {
            #expect(VerificationSessionOrigin.canonical(bad) == nil, "\(bad)")
        }
        #expect(VerificationSessionOrigin.isWithin("https://shop.northwind.example", domain: "northwind.example"))
        #expect(VerificationSessionOrigin.isWithin("https://northwind.example", domain: "NorthWind.example"))
        #expect(!VerificationSessionOrigin.isWithin("https://evilnorthwind.example", domain: "northwind.example"))
        #expect(!VerificationSessionOrigin.isWithin("https://northwind.example.evil.test", domain: "northwind.example"))
        #expect(!VerificationSessionOrigin.isWithin("https://northwind.example", domain: ""))
    }

    @Test func theReturnURLStaysOnTheSessionsOrigin() {
        let origin = "https://shop.northwind.example"
        #expect(VerificationSessionOrigin.validReturnURL("https://shop.northwind.example/checkout?step=2", origin: origin) != nil)
        #expect(VerificationSessionOrigin.validReturnURL("https://shop.northwind.example/", origin: origin) != nil)
        // An open redirect through Viadere's app is impossible: another host, a look-alike, a scheme change, user info, a port, a fragment.
        for bad in ["https://evil.test/", "https://shop.northwind.example.evil.test/", "https://northwind.example/", "http://shop.northwind.example/",
                    "javascript:alert(1)", "https://shop.northwind.example@evil.test/", "https://shop.northwind.example:444/", "https://shop.northwind.example/#x",
                    "https://SHOP.northwind.example/", "https://shop.northwind.example/a b", "https://shop.northwind.example/\u{7}",
                    "//evil.test/", "https://shop.northwind.example/" + String(repeating: "a", count: 520), "https://shop.northwind.example"] {
            #expect(VerificationSessionOrigin.validReturnURL(bad, origin: origin) == nil, "\(bad)")
        }
    }

    @Test func purposeCodesAreSnakeCaseIdentifiers() {
        #expect(VerificationPurposeCode.isValid("age_restricted_purchase"))
        for bad in ["", "a", "Age", "age-restricted", "age restricted", "_age", "1age", String(repeating: "a", count: 65)] { #expect(!VerificationPurposeCode.isValid(bad), "\(bad)") }
    }

    // MARK: Wire format

    @Test func theWireFormatIsSnakeCase() throws {
        let request = CreateVerificationSessionRequest(capability: .ageMinimum, parameters: ["years": .integer(18)], purposeCode: "age_restricted_purchase",
                                                       origin: "https://shop.example", returnURL: "https://shop.example/done", callbackId: nil, expiresInSeconds: 120)
        let json = String(decoding: try ViadereJSON.encode(request), as: UTF8.self)
        for key in ["\"purpose_code\"", "\"return_url\"", "\"expires_in_seconds\"", "\"origin\""] { #expect(json.contains(key), "\(key)") }
        #expect(try ViadereJSON.decode(CreateVerificationSessionRequest.self, from: Data(json.utf8)) == request)
        let ticket = VerificationSessionTicket(sessionId: session, code: "ABCDEFGH", link: "https://viadere.com/v/ABCDEFGH", expiresAt: now)
        #expect(ticket.displayCode == "ABCD-EFGH")
        #expect(try ViadereJSON.decode(VerificationSessionTicket.self, from: try ViadereJSON.encode(ticket)) == ticket)
        #expect(try ViadereJSON.decode(VerificationSessionStatus.self, from: Data("\"future_state\"".utf8)) == .unknown)
        let accept = String(decoding: try ViadereJSON.encode(VerificationSessionAcceptRequest(descriptorDigest: "ab")), as: UTF8.self)
        #expect(accept.contains("\"descriptor_digest\""))
    }

    @Test func theRoutesAreInTheCatalog() {
        let paths = APIRoutes.all.map { "\($0.method) \($0.template)" }
        for endpoint in APIRoutes.verificationSessionEndpoints { #expect(paths.filter { $0 == "\(endpoint.method) \(endpoint.template)" }.count == 1, "\(endpoint.template)") }
        #expect(APIRoutes.Web.verificationSessionPrefix == "/v/")
    }
}
