import Crypto
import Foundation
import XCTest
@testable import ViadereCore

/// Exploit-first tests of Approve v2 (acceptance 3 and 5): a result is verified against the verifier's own records.
final class ApprovalResultTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let businessId = BusinessID()
    private let subject = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 7, count: 32)))!
    private let challenge = Base64URL.encode(Data(repeating: 9, count: 32))
    private let requestId = "req_0123456789abcdefghij"
    private let details = ApprovalSubject.transaction(TransactionDetails(currency: "USD", amountMinor: 250_000, payeeDisplay: "Example Merchant", transactionReference: "bank_tx_123"))
    private let key = SoftwareP256SigningKey()

    private var kid: String { KeyIdentifier.make(try! key.publicKey.signingKey()) }
    private var enrolled: EnrolledApprovalKey { EnrolledApprovalKey(kid: kid, publicKey: key.publicKey, subject: subject, assurance: .biometric) }

    private var expectation: ApprovalExpectation {
        ApprovalExpectation(audience: businessId, subject: subject, requestId: requestId, challenge: challenge, subjectDetails: details,
                            requestExpiresAt: now.addingTimeInterval(120), minimumAMR: .biometric)
    }

    private var content: ApprovalRequestContent {
        ApprovalRequestContent(businessId: businessId, subject: subject, requestId: requestId, challenge: challenge, details: details, toKid: kid,
                               issuedAt: now, expiresAt: now.addingTimeInterval(120))
    }

    private func claims(decision: ApprovalDecision = .approve, amr: ApprovalAMR = .biometric, mutate: (inout ApprovalResultClaims) -> Void = { _ in }) -> ApprovalResultClaims {
        var claims = ApprovalResultClaims(kid: kid, audience: businessId, subject: subject, requestId: requestId, challenge: challenge, capability: .transactionApprove,
                                          decision: decision, amr: amr, issuedAt: now, expiresAt: now.addingTimeInterval(300), transactionDigest: try! details.digest())
        mutate(&claims)
        return claims
    }

    private func jws(_ claims: ApprovalResultClaims? = nil, signedBy signer: SoftwareP256SigningKey? = nil) async throws -> String {
        try await ApprovalResultJWS.sign(claims ?? self.claims(), with: signer ?? key)
    }

    /// A compact JWS with arbitrary (canonical) header and payload objects, signed properly: what a hostile signer or a relay with a
    /// stolen key could produce.
    private func forge(header: [String: JSONValue], payload: [String: JSONValue]? = nil, signer: SoftwareP256SigningKey? = nil) async throws -> String {
        let h = Base64URL.encode(try CanonicalJSON.serialize(.object(header)))
        let p = Base64URL.encode(try CanonicalJSON.serialize(.object(payload ?? claims().object)))
        let signature = try await (signer ?? key).signature(for: Data((h + "." + p).utf8))
        return h + "." + p + "." + ViadereSignatureEncoding.encode(signature)
    }

    private func assertRejected(_ compact: String, _ expected: ApprovalVerificationError, expectation: ApprovalExpectation? = nil, keys: [EnrolledApprovalKey]? = nil,
                                at date: Date? = nil, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try ApprovalResultVerifier.verify(compact, expecting: expectation ?? self.expectation, keys: keys ?? [enrolled], now: date ?? now), file: file, line: line) {
            XCTAssertEqual($0 as? ApprovalVerificationError, expected, file: file, line: line)
        }
    }

    // MARK: Happy path

    func testSignedResultVerifies() async throws {
        let compact = try await ApprovalResultFactory.sign(displayed: content, decision: .approve, amr: .biometric, key: key, now: now)
        XCTAssertEqual(compact.split(separator: ".").count, 3)
        let verified = try ApprovalResultVerifier.verify(compact, expecting: expectation, keys: [enrolled], now: now)
        XCTAssertEqual(verified.decision, .approve)
        XCTAssertEqual(verified.claims.transactionDigest, try details.digest())
        XCTAssertEqual(verified.claims.audience, businessId)
        XCTAssertEqual(verified.claims.kid, kid)
    }

    func testHeaderAndPayloadAreTheDocumentedCanonicalForm() async throws {
        let compact = try await jws()
        let parts = compact.split(separator: ".").map(String.init)
        XCTAssertEqual(String(decoding: Base64URL.decode(parts[0])!, as: UTF8.self), #"{"alg":"ES256","kid":"\#(kid)","typ":"viadere-approval+jws"}"#)
        let payload = String(decoding: Base64URL.decode(parts[1])!, as: UTF8.self)
        XCTAssertTrue(payload.hasPrefix(#"{"alg":"ES256","amr":"biometric","aud":"\#(businessId)","cap":"transaction.approve","challenge":""#), payload)
        XCTAssertEqual(Base64URL.decode(parts[2])!.count, 64, "ES256 raw r||s")
    }

    // MARK: Replay (acceptance 3)

    func testReplayIsRefusedAndAForgedResultCannotBurnAChallenge() async throws {
        let guardian = InMemoryReplayGuard()
        let good = try await jws()
        _ = try await ApprovalResultVerifier.verifyAndConsume(good, expecting: expectation, keys: [enrolled], now: now, replayGuard: guardian)
        do {
            _ = try await ApprovalResultVerifier.verifyAndConsume(good, expecting: expectation, keys: [enrolled], now: now, replayGuard: guardian)
            XCTFail("replay accepted")
        } catch { XCTAssertEqual(error as? ApprovalVerificationError, .replayed) }
        // A re-signed result for the same challenge (different bytes, same one-time nonce) is also a replay.
        do {
            _ = try await ApprovalResultVerifier.verifyAndConsume(try await jws(claims(mutate: { $0.expiresAt += 1 })), expecting: expectation, keys: [enrolled], now: now, replayGuard: guardian)
            XCTFail()
        } catch { XCTAssertEqual(error as? ApprovalVerificationError, .replayed) }
        // A forged result (wrong signer) is rejected *before* consuming: the real one still works afterwards.
        let fresh = InMemoryReplayGuard()
        do {
            _ = try await ApprovalResultVerifier.verifyAndConsume(try await jws(signedBy: SoftwareP256SigningKey()), expecting: expectation, keys: [enrolled], now: now, replayGuard: fresh)
            XCTFail()
        } catch { XCTAssertEqual(error as? ApprovalVerificationError, .badSignature) }
        _ = try await ApprovalResultVerifier.verifyAndConsume(good, expecting: expectation, keys: [enrolled], now: now, replayGuard: fresh)
        // A denial never consumes a challenge and never authorizes.
        let denied = try await jws(claims(decision: .deny))
        do {
            _ = try await ApprovalResultVerifier.verifyAndConsume(denied, expecting: expectation, keys: [enrolled], now: now, replayGuard: InMemoryReplayGuard())
            XCTFail()
        } catch { XCTAssertEqual(error as? ApprovalVerificationError, .notApproved(.deny)) }
    }

    // MARK: Substitution (acceptance 3)

    func testSubstitutingAnyDisplayedParameterFails() async throws {
        // The device signed 2500.00 USD to "Example Merchant". The business's own record says otherwise: each change is a mismatch.
        let signed = try await jws()
        func tampered(_ transform: (inout TransactionDetails) -> Void) -> ApprovalExpectation {
            guard case .transaction(var d) = details else { fatalError() }
            transform(&d)
            var e = expectation
            e.subjectDetails = .transaction(d)
            return e
        }
        assertRejected(signed, .transactionMismatch, expectation: tampered { $0.amountMinor = 25_000_000 })
        assertRejected(signed, .transactionMismatch, expectation: tampered { $0.amountMinor += 1 })
        assertRejected(signed, .transactionMismatch, expectation: tampered { $0.payeeDisplay = "Example Merchan7" })
        assertRejected(signed, .transactionMismatch, expectation: tampered { $0.currency = "EUR" })
        assertRejected(signed, .transactionMismatch, expectation: tampered { $0.transactionReference = "bank_tx_124" })
        var otherCapability = expectation
        otherCapability.capability = .authChallenge; otherCapability.subjectDetails = .authentication(AuthenticationDetails(actionDisplay: "Sign in"))
        assertRejected(signed, .wrongCapability, expectation: otherCapability)
    }

    func testSubstitutingBusinessNonceRequestSubjectOrExpiryFails() async throws {
        let signed = try await jws()
        var e = expectation
        e.audience = BusinessID()
        assertRejected(signed, .wrongAudience, expectation: e)
        e = expectation
        e.challenge = Base64URL.encode(Data(repeating: 1, count: 32))
        assertRejected(signed, .challengeMismatch, expectation: e)
        e = expectation
        e.requestId = "req_other_other_other_x"
        assertRejected(signed, .wrongRequest, expectation: e)
        e = expectation
        e.subject = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 8, count: 32)))!
        assertRejected(signed, .wrongSubject, expectation: e)
        // The same result presented to a verifier that holds the key for another subject.
        assertRejected(signed, .wrongSubject, keys: [EnrolledApprovalKey(kid: kid, publicKey: key.publicKey, subject: SubjectRef("sub_" + Base64URL.encode(Data(repeating: 6, count: 32)))!, assurance: .biometric)])
        // Expiry: used after exp, and the signature covers exp so extending it by editing the payload breaks the signature.
        assertRejected(signed, .expired, at: now.addingTimeInterval(301))
        let parts = signed.split(separator: ".").map(String.init)
        var payload = String(decoding: Base64URL.decode(parts[1])!, as: UTF8.self)
        payload = payload.replacingOccurrences(of: "\"exp\":\(ViadereDate.unixSeconds(now.addingTimeInterval(300)))", with: "\"exp\":\(ViadereDate.unixSeconds(now.addingTimeInterval(86_400)))")
        assertRejected(parts[0] + "." + Base64URL.encode(Data(payload.utf8)) + "." + parts[2], .badSignature)
        // Editing amount-bearing digest or decision in the payload also breaks it.
        var flipped = String(decoding: Base64URL.decode(parts[1])!, as: UTF8.self)
        flipped = flipped.replacingOccurrences(of: "\"decision\":\"approve\"", with: "\"decision\":\"deny\"")
        assertRejected(parts[0] + "." + Base64URL.encode(Data(flipped.utf8)) + "." + parts[2], .badSignature)
    }

    func testTimeRules() async throws {
        assertRejected(try await jws(claims(mutate: { $0.issuedAt += 3600; $0.expiresAt += 3600 })), .issuedInFuture)
        assertRejected(try await jws(claims(mutate: { $0.expiresAt = $0.issuedAt + 601 })), .lifetimeTooLong)
        // Decided after the request had expired (a business-side deadline).
        assertRejected(try await jws(claims(mutate: { $0.issuedAt += 200; $0.expiresAt += 200 })), .decidedAfterRequestExpiry, at: now.addingTimeInterval(200))
    }

    // MARK: Algorithms, headers, keys

    func testAlgorithmDowngradeAndHeaderAttacks() async throws {
        for alg in ["none", "HS256", "ES384", "ES256K", "RS256", "PS256", "EdDSA", "es256", "ES256 "] {
            assertRejected(try await forge(header: ["alg": .string(alg), "kid": .string(kid), "typ": .string(ApprovalResultJWS.type)]), .unsupportedAlgorithm(alg))
        }
        // Missing alg.
        assertRejected(try await forge(header: ["kid": .string(kid), "typ": .string(ApprovalResultJWS.type)]), .malformed("alg"))
        // Wrong typ.
        assertRejected(try await forge(header: ["alg": .string("ES256"), "kid": .string(kid), "typ": .string("JWT")]), .unsupportedType)
        // Unknown critical header.
        assertRejected(try await forge(header: ["alg": .string("ES256"), "kid": .string(kid), "typ": .string(ApprovalResultJWS.type), "crit": .array([.string("exp-ext")]), "exp-ext": .integer(1)]),
                       .unknownCriticalHeader("exp-ext"))
        // Even a crit naming a registered header is refused: this version understands no critical extension.
        assertRejected(try await forge(header: ["alg": .string("ES256"), "kid": .string(kid), "typ": .string(ApprovalResultJWS.type), "crit": .array([.string("b64")]), "b64": .bool(false)]),
                       .unknownCriticalHeader("b64"))
        assertRejected(try await forge(header: ["alg": .string("ES256"), "kid": .string(kid), "typ": .string(ApprovalResultJWS.type), "crit": .array([])]), .malformed("crit"))
        // Key-injection headers are not accepted even when not critical.
        for member in ["jwk", "jku", "x5u", "x5c", "x5t", "zip", "b64", "cty", "enc", "epk"] {
            assertRejected(try await forge(header: ["alg": .string("ES256"), "kid": .string(kid), "typ": .string(ApprovalResultJWS.type), member: .string("x")]), .malformed("header members"))
        }
        // kid in the payload must equal the header's, alg in the payload must be ES256.
        var mismatch = claims().object
        mismatch["kid"] = .string(KeyIdentifier.make(try SoftwareP256SigningKey().publicKey.signingKey()))
        assertRejected(try await forge(header: ["alg": .string("ES256"), "kid": .string(kid), "typ": .string(ApprovalResultJWS.type)], payload: mismatch), .headerPayloadMismatch)
        var algMismatch = claims().object
        algMismatch["alg"] = .string("none")
        assertRejected(try await forge(header: ["alg": .string("ES256"), "kid": .string(kid), "typ": .string(ApprovalResultJWS.type)], payload: algMismatch), .headerPayloadMismatch)
    }

    func testMalformedCompactForms() async throws {
        let good = try await jws()
        assertRejected("", .malformed("segments"))
        assertRejected("a.b", .malformed("segments"))
        assertRejected(good + ".extra", .malformed("segments"))
        assertRejected(".b.c", .malformed("segments"))
        XCTAssertThrowsError(try ApprovalResultVerifier.verify(good.replacingOccurrences(of: "-", with: "+") + "=", expecting: expectation, keys: [enrolled], now: now))
        assertRejected(String(repeating: "a", count: ApprovalResultJWS.maxBytes + 1), .malformed("size"))
        // "none" with an empty signature.
        let parts = good.split(separator: ".").map(String.init)
        let none = Base64URL.encode(try CanonicalJSON.serialize(.object(["alg": .string("none"), "typ": .string(ApprovalResultJWS.type), "kid": .string(kid)])))
        assertRejected(none + "." + parts[1] + ".", .malformed("segments"))
        // Whitespace-padded / non-canonical JSON: refused so a signature covers exactly one byte string.
        let spaced = Base64URL.encode(Data(#"{ "alg":"ES256","kid":"\#(kid)","typ":"viadere-approval+jws"}"#.utf8))
        assertRejected(spaced + "." + parts[1] + "." + parts[2], .malformed("encoding"))
        // Extra / missing claims.
        var extra = claims().object
        extra["admin"] = .bool(true)
        assertRejected(try await forge(header: ["alg": .string("ES256"), "kid": .string(kid), "typ": .string(ApprovalResultJWS.type)], payload: extra), .malformed("claims"))
        var missing = claims().object
        missing["txn_digest"] = nil
        assertRejected(try await forge(header: ["alg": .string("ES256"), "kid": .string(kid), "typ": .string(ApprovalResultJWS.type)], payload: missing), .malformed("claims"))
        var future = claims().object
        future["v"] = .integer(2)
        assertRejected(try await forge(header: ["alg": .string("ES256"), "kid": .string(kid), "typ": .string(ApprovalResultJWS.type)], payload: future), .unsupportedVersion(2))
    }

    func testKeyHandling() async throws {
        let signed = try await jws()
        assertRejected(signed, .unknownKey, keys: [])
        assertRejected(signed, .unknownKey, keys: [EnrolledApprovalKey(kid: KeyIdentifier.make(try SoftwareP256SigningKey().publicKey.signingKey()), publicKey: SoftwareP256SigningKey().publicKey, subject: subject, assurance: .biometric)])
        var revoked = enrolled
        revoked.revoked = true
        assertRejected(signed, .keyRevoked, keys: [revoked])
        // A record whose kid does not match its public key (corrupt store, or relay lying about a key) is not trusted.
        let impostor = SoftwareP256SigningKey()
        assertRejected(try await jws(signedBy: impostor), .unknownKey, keys: [EnrolledApprovalKey(kid: kid, publicKey: impostor.publicKey, subject: subject, assurance: .biometric)])
        // Signed by a different key under the right kid.
        assertRejected(try await jws(signedBy: impostor), .badSignature)
        // A presence-class key cannot claim biometric authentication; the business can demand a minimum.
        let presenceKey = EnrolledApprovalKey(kid: kid, publicKey: key.publicKey, subject: subject, assurance: .presence)
        assertRejected(signed, .amrExceedsKey, keys: [presenceKey])
        let presenceResult = try await jws(claims(amr: .presence))
        assertRejected(presenceResult, .insufficientAuthentication)
        var relaxed = expectation
        relaxed.minimumAMR = .presence
        XCTAssertNoThrow(try ApprovalResultVerifier.verify(presenceResult, expecting: relaxed, keys: [presenceKey], now: now))
    }

    func testHighSAndLowSSignaturesBothVerify() async throws {
        // Secure Enclave may produce either S; the encoding normalizes, and a business verifying the raw bytes with any JOSE library sees a valid ES256 signature.
        let compact = try await jws()
        let parts = compact.split(separator: ".").map(String.init)
        let raw = Base64URL.decode(parts[2])!
        XCTAssertTrue(ViadereSignatureEncoding.isCanonical(try P256.Signing.ECDSASignature(rawRepresentation: raw)))
        let signingInput = Data((parts[0] + "." + parts[1]).utf8)
        XCTAssertTrue(try key.publicKey.signingKey().isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: raw), for: signingInput))
    }

    // MARK: Transaction canonicalization

    func testTransactionCanonicalFormAndDigest() throws {
        let canonical = String(decoding: try details.canonicalJSON(), as: UTF8.self)
        XCTAssertEqual(canonical, #"{"amount_minor":250000,"capability":"transaction.approve","currency":"USD","payee_display":"Example Merchant","transaction_reference":"bank_tx_123","v":1}"#)
        XCTAssertEqual(try details.digest(), SecureToken.sha256Hex(Data("VIADERE-TXN-V1\n".utf8) + Data(canonical.utf8)))
        let auth = ApprovalSubject.authentication(AuthenticationDetails(actionDisplay: "Sign in to Example Bank", reference: "login_77"))
        XCTAssertEqual(String(decoding: try auth.canonicalJSON(), as: UTF8.self), #"{"action_display":"Sign in to Example Bank","capability":"auth.challenge","reference":"login_77","v":1}"#)
        XCTAssertNotEqual(try auth.digest(), try details.digest())
    }

    func testDisplayedParametersAreValidatedStrictly() {
        func check(_ d: TransactionDetails, _ field: String, file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertThrowsError(try ApprovalSubject.transaction(d).validate(), file: file, line: line) { XCTAssertEqual($0 as? ApprovalTransactionError, .invalid(field: field), file: file, line: line) }
        }
        let ok = TransactionDetails(currency: "USD", amountMinor: 100, payeeDisplay: "Cafe Rio", transactionReference: "ref-1")
        XCTAssertNoThrow(try ApprovalSubject.transaction(ok).validate())
        var d = ok; d.currency = "usd"; check(d, "currency")
        d = ok; d.currency = "US"; check(d, "currency")
        d = ok; d.amountMinor = 0; check(d, "amount_minor")
        d = ok; d.amountMinor = 1_000_000_000_000; check(d, "amount_minor")
        d = ok; d.payeeDisplay = "Pay\u{202E}eziL"; check(d, "payee_display")          // bidi override
        d = ok; d.payeeDisplay = "Cafe\u{200B}Rio"; check(d, "payee_display")           // zero width
        d = ok; d.payeeDisplay = "Cafe\nRio"; check(d, "payee_display")                 // line break (forged second row)
        d = ok; d.payeeDisplay = "Cafe\u{0301}"; check(d, "payee_display")              // not NFC (e + combining acute)
        d = ok; d.payeeDisplay = " Cafe"; check(d, "payee_display")
        d = ok; d.payeeDisplay = String(repeating: "a", count: 81); check(d, "payee_display")
        d = ok; d.transactionReference = "has space"; check(d, "transaction_reference")
        d = ok; d.transactionReference = String(repeating: "a", count: 65); check(d, "transaction_reference")
        d = ok; d.transactionReference = ""; check(d, "transaction_reference")
        XCTAssertThrowsError(try ApprovalSubject.authentication(AuthenticationDetails(actionDisplay: "")).validate())
        XCTAssertThrowsError(try ApprovalSubject.authentication(AuthenticationDetails(actionDisplay: "Sign in", reference: "bad ref")).validate())
        XCTAssertEqual(MoneyFormatting.display(minor: 250_000, currency: "USD"), "2500.00 USD")
        XCTAssertEqual(MoneyFormatting.display(minor: 5, currency: "USD"), "0.05 USD")
        XCTAssertEqual(MoneyFormatting.display(minor: 500, currency: "JPY"), "500 JPY")
    }

    // MARK: Business-signed request

    func testBusinessSignedRequestAuthenticatesTheBusiness() async throws {
        let businessKey = SoftwareP256SigningKey()
        let plaintext = try await content.sealedPlaintext(signedWith: businessKey)
        let signed = try ApprovalRequestContent.parseSigned(plaintext)
        let parsed = try ApprovalRequestContent.verify(signed, signingKey: businessKey.publicKey, expectedBusiness: businessId, expectedSubject: subject, expectedKid: kid,
                                                      expectedRequestId: requestId, now: now)
        XCTAssertEqual(parsed, content)
        // A relay that encrypts its own request (it knows the device's public key) cannot sign as the business.
        let relayKey = SoftwareP256SigningKey()
        let forged = try ApprovalRequestContent.parseSigned(try await content.sealedPlaintext(signedWith: relayKey))
        XCTAssertThrowsError(try ApprovalRequestContent.verify(forged, signingKey: businessKey.publicKey, expectedBusiness: businessId, expectedSubject: subject, expectedKid: kid, expectedRequestId: requestId, now: now)) {
            XCTAssertEqual($0 as? ApprovalRequestError, .badSignature)
        }
        func fails(_ error: ApprovalRequestError, business: BusinessID? = nil, sub: SubjectRef? = nil, kid: String? = nil, request: String? = nil, at: Date? = nil) {
            XCTAssertThrowsError(try ApprovalRequestContent.verify(signed, signingKey: businessKey.publicKey, expectedBusiness: business ?? businessId, expectedSubject: sub ?? subject,
                                                                   expectedKid: kid ?? self.kid, expectedRequestId: request ?? requestId, now: at ?? now)) { XCTAssertEqual($0 as? ApprovalRequestError, error) }
        }
        fails(.wrongBusiness, business: BusinessID())
        fails(.wrongSubject, sub: SubjectRef("sub_" + Base64URL.encode(Data(repeating: 1, count: 32))))
        fails(.wrongDevice, kid: KeyIdentifier.make(try SoftwareP256SigningKey().publicKey.signingKey()))
        fails(.wrongRequest, request: "req_a_different_one_xx")
        fails(.expired, at: now.addingTimeInterval(121))
        fails(.notYetValid, at: now.addingTimeInterval(-3600))
        // Signed with a key whose kid the statement does not name.
        XCTAssertThrowsError(try ApprovalRequestContent.verify(BusinessSignedStatement(kid: KeyIdentifier.make(try relayKey.publicKey.signingKey()), payload: signed.payload, signature: signed.signature),
                                                              signingKey: businessKey.publicKey, expectedBusiness: businessId, expectedSubject: subject, expectedKid: kid, expectedRequestId: requestId, now: now))
    }

    func testPromptPolicy() {
        let policy = ApprovalPromptPolicy.standard
        let t = now
        func records(_ n: Int, decision: ApprovalDecision? = nil, ago: TimeInterval = 60) -> [ApprovalPromptPolicy.Record] {
            (0..<n).map { ApprovalPromptPolicy.Record(createdAt: t.addingTimeInterval(-ago - Double($0)), decision: decision) }
        }
        XCTAssertEqual(policy.evaluate(history: [], now: t), .allow(requestsInWindow: 1, showWarning: false))
        XCTAssertEqual(policy.evaluate(history: records(2), now: t), .allow(requestsInWindow: 3, showWarning: true))
        guard case .rateLimited = policy.evaluate(history: records(6, decision: .approve), now: t) else { return XCTFail() }
        guard case .autoDeny(let until) = policy.evaluate(history: records(3, decision: .deny), now: t) else { return XCTFail() }
        XCTAssertEqual(until, t.addingTimeInterval(-60).addingTimeInterval(3600))
        guard case .autoDeny = policy.evaluate(history: records(3, decision: .report), now: t) else { return XCTFail() }
        // Old denials fall out of the window.
        XCTAssertEqual(policy.evaluate(history: records(3, decision: .deny, ago: 7200), now: t), .allow(requestsInWindow: 1, showWarning: false))
        // Too many open prompts at once.
        guard case .rateLimited = policy.evaluate(history: (0..<3).map { _ in ApprovalPromptPolicy.Record(createdAt: t, decision: nil, isOpen: true) }, now: t) else { return XCTFail() }
    }
}

final class ApprovalEnrollmentTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let businessId = BusinessID()
    private let subject = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 3, count: 32)))!
    private let enrollmentId = UUID()

    private func statement(key: SoftwareP256SigningKey, hpke: SoftwareE2EEPrivateKey, assurance: ApprovalAMR = .biometric) throws -> ApprovalEnrollmentStatement {
        try ApprovalEnrollmentStatement(businessId: businessId, subject: subject, enrollmentId: enrollmentId, publicKey: key.publicKey, hpkePublicKey: hpke.publicKey,
                                        assurance: assurance, createdAt: now)
    }

    func testDeviceStatementProvesPossessionAndBinds() async throws {
        let key = SoftwareP256SigningKey()
        let hpke = SoftwareE2EEPrivateKey()
        let s = try statement(key: key, hpke: hpke)
        let signed = try await s.sign(with: key)
        let verified = try ApprovalEnrollmentStatement.verify(signed)
        XCTAssertEqual(verified, s)
        XCTAssertNoThrow(try verified.checkBinding(businessId: businessId, subject: subject, enrollmentId: enrollmentId))
        XCTAssertThrowsError(try verified.checkBinding(businessId: BusinessID(), subject: subject, enrollmentId: enrollmentId)) { XCTAssertEqual($0 as? ApprovalEnrollmentError, .wrongBusiness) }
        XCTAssertThrowsError(try verified.checkBinding(businessId: businessId, subject: SubjectRef("sub_" + Base64URL.encode(Data(repeating: 4, count: 32)))!, enrollmentId: enrollmentId)) { XCTAssertEqual($0 as? ApprovalEnrollmentError, .wrongSubject) }
        XCTAssertThrowsError(try verified.checkBinding(businessId: businessId, subject: subject, enrollmentId: UUID())) { XCTAssertEqual($0 as? ApprovalEnrollmentError, .wrongEnrollment) }
        // Signing with a key that is not the statement's key is refused outright.
        do { _ = try await s.sign(with: SoftwareP256SigningKey()); XCTFail() } catch { XCTAssertEqual(error as? ApprovalEnrollmentError, .keyMismatch) }
        // A relay substituting the public key inside the statement breaks possession proof (it cannot sign as the device key).
        let attacker = SoftwareP256SigningKey()
        let swapped = try statement(key: attacker, hpke: hpke)
        let forged = SignedStatement(payload: try await swapped.sign(with: attacker).payload, signature: signed.signature)
        XCTAssertThrowsError(try ApprovalEnrollmentStatement.verify(forged)) { XCTAssertEqual($0 as? ApprovalEnrollmentError, .badSignature) }
        // Replacing only the HPKE key (so the relay could read future requests) also breaks the signature.
        let evilHpke = try statement(key: key, hpke: SoftwareE2EEPrivateKey())
        let forgedHpke = SignedStatement(payload: try await evilHpke.sign(with: key).payload, signature: signed.signature)
        XCTAssertThrowsError(try ApprovalEnrollmentStatement.verify(forgedHpke)) { XCTAssertEqual($0 as? ApprovalEnrollmentError, .badSignature) }
        // A passcode-only assurance cannot be enrolled (the key classes are biometric or user presence).
        XCTAssertThrowsError(try statement(key: key, hpke: hpke, assurance: .passcode))
    }

    func testBusinessConfirmationCommitsToTheExactKeyAndTheDeviceChecksIt() async throws {
        let key = SoftwareP256SigningKey()
        let hpke = SoftwareE2EEPrivateKey()
        let s = try statement(key: key, hpke: hpke)
        let signed = try await s.sign(with: key)
        let confirmKey = SoftwareP256SigningKey()
        let confirmation = ApprovalEnrollmentConfirmation(confirming: s, signed: signed, at: now)
        let wire = try await confirmation.sign(with: confirmKey)
        let parsed = try ApprovalEnrollmentConfirmation.verify(wire, confirmationKey: confirmKey.publicKey)
        XCTAssertNoThrow(try parsed.checkMatches(s, signed: signed))
        // Relay key substitution: the business received (and confirmed) the attacker's key, not the device's. The device notices.
        let attacker = SoftwareP256SigningKey()
        let attackerStatement = try statement(key: attacker, hpke: hpke)
        let attackerSigned = try await attackerStatement.sign(with: attacker)
        let confirmedAttacker = try ApprovalEnrollmentConfirmation.verify(try await ApprovalEnrollmentConfirmation(confirming: attackerStatement, signed: attackerSigned, at: now).sign(with: confirmKey),
                                                                          confirmationKey: confirmKey.publicKey)
        XCTAssertThrowsError(try confirmedAttacker.checkMatches(s, signed: signed)) { XCTAssertEqual($0 as? ApprovalEnrollmentError, .keyMismatch) }
        // Same kid but a different statement (e.g. different HPKE key): the digest differs.
        let otherHpke = try statement(key: key, hpke: SoftwareE2EEPrivateKey())
        let otherSigned = try await otherHpke.sign(with: key)
        let confirmedOther = try ApprovalEnrollmentConfirmation.verify(try await ApprovalEnrollmentConfirmation(confirming: otherHpke, signed: otherSigned, at: now).sign(with: confirmKey), confirmationKey: confirmKey.publicKey)
        XCTAssertThrowsError(try confirmedOther.checkMatches(s, signed: signed)) { XCTAssertEqual($0 as? ApprovalEnrollmentError, .statementMismatch) }
        // A confirmation signed by a key the directory does not vouch for does not verify under the directory key.
        XCTAssertThrowsError(try ApprovalEnrollmentConfirmation.verify(wire, confirmationKey: SoftwareP256SigningKey().publicKey))
        // The confirmation key and the request-signing key are different purposes: the domain strings differ, so one cannot stand in for the other.
        let asRequest = SignedStatement(payload: wire.payload, signature: wire.signature)
        XCTAssertFalse(asRequest.isValid(domain: ApproveDomain.request, publicKey: confirmKey.publicKey))
    }

    func testFreezeProofIsBoundToTheDeviceAndScope() async throws {
        let key = SoftwareP256SigningKey()
        let device = DeviceID()
        let proof = ApproveFreezeProof(scope: .account, relationshipId: nil, deviceId: device, signedAt: now)
        let signed = try await proof.sign(with: key)
        XCTAssertEqual(ApproveFreezeProof.verify(signed, deviceKey: key.publicKey), proof)
        XCTAssertNil(ApproveFreezeProof.verify(signed, deviceKey: SoftwareP256SigningKey().publicKey))
        // A relationship-scoped proof needs a relationship; an account-scoped proof must not carry one.
        let relationship = RelationshipID()
        let scoped = ApproveFreezeProof(scope: .relationship, relationshipId: relationship, deviceId: device, signedAt: now)
        let scopedSigned = try await scoped.sign(with: key)
        XCTAssertEqual(ApproveFreezeProof.verify(scopedSigned, deviceKey: key.publicKey)?.relationshipId, relationship)
        let inconsistent = ApproveFreezeProof(scope: .relationship, relationshipId: nil, deviceId: device, signedAt: now)
        let inconsistentSigned = try await inconsistent.sign(with: key)
        XCTAssertNil(ApproveFreezeProof.verify(inconsistentSigned, deviceKey: key.publicKey))
        // The freeze domain cannot be satisfied by a statement made for another purpose.
        let enrollmentLike = try await SignedStatement.sign(["v": .integer(1)], domain: ApproveDomain.enrollment, with: key)
        XCTAssertNil(ApproveFreezeProof.verify(enrollmentLike, deviceKey: key.publicKey))
    }

    func testWebhookEnvelopeV2IsStrictAndOpaque() throws {
        let envelope = WebhookEnvelopeV2(id: "evt_abc", type: "approve.request.decided", tenantId: "ten_abc", requestId: "req_abc", occurredAt: now, resultRef: "res_abc")
        let data = try ViadereJSON.encode(envelope)
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertEqual(text, #"{"id":"evt_abc","occurred_at":"2027-01-15T08:00:00.000Z","request_id":"req_abc","result_ref":"res_abc","tenant_id":"ten_abc","type":"approve.request.decided","version":"2026-10-27"}"#)
        XCTAssertEqual(try ViadereJSON.decode(WebhookEnvelopeV2.self, from: data), envelope)
        XCTAssertThrowsError(try ViadereJSON.decode(WebhookEnvelopeV2.self, from: Data(text.replacingOccurrences(of: "{", with: #"{"amount":1,"#, options: [], range: text.startIndex..<text.index(after: text.startIndex)).utf8)))
    }
}
