@preconcurrency import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// The authority wire formats in Core (ADR-0023 §2-§5, ADR-0024, ADR-0033): JOSE profile, RFC 7638 thumbprints, factor assertions, challenge statements,
/// grants, pairwise subjects, PKCE and redirect rules. Expected values of the derivations were computed independently in Python (standard library).
@Suite("Authority wire formats")
struct AuthorityCoreTests {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)

    // MARK: Vectors

    @Test func rfc7638ThumbprintVector() {
        // RFC 7638 §3.1 example key.
        let n = Base64URL.decode("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")!
        let e = Base64URL.decode("AQAB")!
        #expect(JWKThumbprint.rsa(modulus: n, exponent: e) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
        // Leading zero bytes do not change the thumbprint.
        #expect(JWKThumbprint.rsa(modulus: Data([0]) + n, exponent: Data([0, 0]) + e) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
    }

    @Test func pkceVectorFromRFC7636AppendixB() {
        #expect(OIDCProfile.pkceMatches(verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))
        #expect(!OIDCProfile.pkceMatches(verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl", challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))
        // `plain` does not exist: the verifier itself is never a valid challenge match.
        #expect(!OIDCProfile.pkceMatches(verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", challenge: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
        #expect(!OIDCProfile.isValidCodeVerifier("short"))
    }

    @Test func pairwiseSubjectAndAccountRefVectors() {
        let account = UUID(uuidString: "6F9619FF-8B86-D011-B42D-00C04FC964FF")!
        let sub = OIDCProfile.pairwiseSubject(key: SymmetricKey(data: Data(repeating: 7, count: 32)), sectorHost: "RP.example.com", accountId: account)
        #expect(sub == "AQS1LD2eDux8agy4_5MYHKADn_yCYeHBcGoYIxUSPh0")
        #expect(sub.count == 43)
        #expect(OIDCProfile.accountRef(key: SymmetricKey(data: Data(repeating: 8, count: 32)), accountId: account) == "acct_dd7a9fd0d7287e10318d5dd06ef30d67")
    }

    @Test func displayDigestVector() throws {
        let display = AuthorityDisplay.oidcLogin(clientName: "Example Shop", redirectURI: "https://rp.example.com/callback", matchDigits: 2)
        #expect(try AuthorityDisplay.digest(display) == "2a395453b88904a73ad5b6f6f3564e1a0057d51b4ef3c24e6ec04b7d872ceb4d")
    }

    // MARK: JOSE profile (ADR-0023 §2)

    static func compact(header: [String: JSONValue], payload: [String: JSONValue], key: P256.Signing.PrivateKey) throws -> String {
        let input = Base64URL.encode(try CanonicalJSON.serialize(.object(header))) + "." + Base64URL.encode(try CanonicalJSON.serialize(.object(payload)))
        return input + "." + Base64URL.encode(try key.signature(for: Data(input.utf8)).rawRepresentation)
    }

    @Test func profileRefusesExtraHeaderMembersAndForeignAlgorithms() throws {
        let key = P256.Signing.PrivateKey()
        let payload: [String: JSONValue] = ["v": .integer(1)]
        let good = try Self.compact(header: ["alg": .string("ES256"), "kid": .string("k"), "typ": .string("t")], payload: payload, key: key)
        #expect(throws: Never.self) { try AuthorityJWS.parse(good, expectedType: "t", allowedAlgorithms: ["ES256"]) }
        for extra in ["jwk", "jku", "x5u", "x5c", "crit", "b64", "zip", "cty"] {
            let bad = try Self.compact(header: ["alg": .string("ES256"), "kid": .string("k"), "typ": .string("t"), extra: .string("x")], payload: payload, key: key)
            #expect(throws: AuthorityJOSEError.self) { try AuthorityJWS.parse(bad, expectedType: "t", allowedAlgorithms: ["ES256"]) }
        }
        for alg in ["none", "HS256", "ES384", "RS256"] {
            let bad = try Self.compact(header: ["alg": .string(alg), "kid": .string("k"), "typ": .string("t")], payload: payload, key: key)
            #expect(throws: AuthorityJOSEError.self) { try AuthorityJWS.parse(bad, expectedType: "t", allowedAlgorithms: ["ES256"]) }
        }
        // Missing kid, another typ.
        let noKid = try Self.compact(header: ["alg": .string("ES256"), "typ": .string("t")], payload: payload, key: key)
        #expect(throws: AuthorityJOSEError.self) { try AuthorityJWS.parse(noKid, expectedType: "t", allowedAlgorithms: ["ES256"]) }
        #expect(throws: AuthorityJOSEError.wrongType) { try AuthorityJWS.parse(good, expectedType: "other", allowedAlgorithms: ["ES256"]) }
    }

    @Test func profileRefusesNonCanonicalDuplicateAndOversizedPayloads() throws {
        let header = Base64URL.encode(try CanonicalJSON.serialize(.object(["alg": .string("ES256"), "kid": .string("k"), "typ": .string("t")])))
        for raw in [#"{"v": 1}"#, #"{"v":1,"v":2}"#, #"{"v":1.0}"#, #"{"b":1,"a":2}"#] {
            let compact = header + "." + Base64URL.encode(Data(raw.utf8)) + "." + Base64URL.encode(Data(repeating: 1, count: 64))
            #expect(throws: AuthorityJOSEError.self) { try AuthorityJWS.parse(compact, expectedType: "t", allowedAlgorithms: ["ES256"]) }
        }
        let big = header + "." + Base64URL.encode(Data(String(repeating: "a", count: 5000).utf8)) + ".x"
        #expect(throws: AuthorityJOSEError.malformed("size")) { try AuthorityJWS.parse(big, expectedType: "t", allowedAlgorithms: ["ES256"]) }
    }

    // MARK: Challenge statements (ADR-0033 §2)

    static func statement(env: AuthorityEnvironment = .staging, purpose: AuthorityPurpose = .oidcLogin, redirect: String? = "https://rp.example.com/callback",
                          returnURL: String? = nil, display: JSONValue? = nil) -> AuthorityChallengeStatement {
        let t = Int64(now.timeIntervalSince1970)
        return AuthorityChallengeStatement(environment: env, challengeId: AuthorityChallengeID.generate(), nonce: AuthorityNonce.generate(), purpose: purpose,
                                           display: display ?? AuthorityDisplay.oidcLogin(clientName: "Example Shop", redirectURI: "https://rp.example.com/callback", matchDigits: 2),
                                           returnURL: returnURL, redirectURI: redirect, matchRequired: true, issuedAt: t, expiresAt: t + 120)
    }

    static func sign(_ payload: [String: JSONValue], typ: String = AuthorityChallengeStatement.type, key: P256.Signing.PrivateKey, kid: String? = nil) throws -> String {
        try compact(header: ["alg": .string("ES256"), "kid": .string(kid ?? JWKThumbprint.p256(key.publicKey)), "typ": .string(typ)], payload: payload, key: key)
    }

    @Test func deviceVerifiesAChallengeStatementOnlyFromAPinnedKeyForItsEnvironment() throws {
        let pinned = P256.Signing.PrivateKey()
        let statement = Self.statement()
        let compact = try Self.sign(statement.payload, key: pinned)
        let verified = try AuthorityStatementVerifier.verifyChallenge(compact, pinnedKeys: [pinned.publicKey], environment: .staging, now: Self.now)
        #expect(verified == statement)
        // An unpinned key, a revoked pinned key, another environment, another typ, an expired statement.
        #expect(throws: AuthorityJOSEError.unknownKey) {
            try AuthorityStatementVerifier.verifyChallenge(try Self.sign(statement.payload, key: P256.Signing.PrivateKey()), pinnedKeys: [pinned.publicKey], environment: .staging, now: Self.now)
        }
        #expect(throws: AuthorityJOSEError.unknownKey) {
            try AuthorityStatementVerifier.verifyChallenge(compact, pinnedKeys: [pinned.publicKey], revokedKids: [JWKThumbprint.p256(pinned.publicKey)], environment: .staging, now: Self.now)
        }
        #expect(throws: AuthorityJOSEError.self) { try AuthorityStatementVerifier.verifyChallenge(compact, pinnedKeys: [pinned.publicKey], environment: .production, now: Self.now) }
        for typ in ["viadere-keylog-head+jws", "viadere-tenant-keys+jws", "viadere-device-keys-revocation+jws", "viadere-factor+jws"] {
            #expect(throws: AuthorityJOSEError.wrongType) {
                try AuthorityStatementVerifier.verifyChallenge(try Self.sign(statement.payload, typ: typ, key: pinned), pinnedKeys: [pinned.publicKey], environment: .staging, now: Self.now)
            }
        }
        #expect(throws: AuthorityJOSEError.expired) {
            try AuthorityStatementVerifier.verifyChallenge(compact, pinnedKeys: [pinned.publicKey], environment: .staging, now: Self.now.addingTimeInterval(400))
        }
        // The SPKI-hash KeyIdentifier is not an authority kid.
        #expect(throws: AuthorityJOSEError.unknownKey) {
            try AuthorityStatementVerifier.verifyChallenge(try Self.sign(statement.payload, key: pinned, kid: KeyIdentifier.make(pinned.publicKey)), pinnedKeys: [pinned.publicKey],
                                                           environment: .staging, now: Self.now)
        }
    }

    @Test func statementMembersAreExactAndURLsBelongToTheirPurpose() throws {
        let pinned = P256.Signing.PrivateKey()
        var payload = Self.statement().payload
        payload["account_ref"] = .string("acct_x")
        #expect(throws: AuthorityJOSEError.claims("members")) {
            try AuthorityStatementVerifier.verifyChallenge(try Self.sign(payload, key: pinned), pinnedKeys: [pinned.publicKey], environment: .staging, now: Self.now)
        }
        let linkWithRedirect = Self.statement(purpose: .linkOpen, redirect: "https://rp.example.com/callback", returnURL: "https://shop.example.com/r",
                                              display: AuthorityDisplay.linkOpen(tenantName: "T", clientName: "C", returnURL: "https://shop.example.com/r", matchDigits: nil))
        #expect(throws: AuthorityJOSEError.self) {
            try AuthorityStatementVerifier.verifyChallenge(try Self.sign(linkWithRedirect.payload, key: pinned), pinnedKeys: [pinned.publicKey], environment: .staging, now: Self.now)
        }
        // A display for another purpose is refused.
        let mismatched = Self.statement(display: AuthorityDisplay.linkOpen(tenantName: "T", clientName: "C", returnURL: "https://shop.example.com/r", matchDigits: nil))
        #expect(throws: AuthorityJOSEError.claims("display")) {
            try AuthorityStatementVerifier.verifyChallenge(try Self.sign(mismatched.payload, key: pinned), pinnedKeys: [pinned.publicKey], environment: .staging, now: Self.now)
        }
    }

    // MARK: Factor assertions (ADR-0023 §3)

    @Test func factorAssertionRoundTripsAndBindsToTheStatementDisplay() async throws {
        let device = SoftwareP256SigningKey()
        let statement = Self.statement()
        let claims = try FactorAssertionClaims.answering(statement, decision: .approve, userVerification: .biometric, match: "42", now: Self.now)
        #expect(claims.displayDigest == (try AuthorityDisplay.digest(statement.display)))
        #expect(claims.expiresAt - claims.issuedAt == 120)
        let compact = try await FactorAssertion.sign(claims, with: device)
        let parsed = try FactorAssertion.parse(compact)
        #expect(parsed.claims == claims)
        #expect(parsed.kid == KeyIdentifier.make(try device.publicKey.signingKey()))
        try FactorAssertion.verifySignature(parsed, loggedKey: try device.publicKey.signingKey())
        #expect(throws: AuthorityJOSEError.unknownKey) { try FactorAssertion.verifySignature(parsed, loggedKey: P256.Signing.PrivateKey().publicKey) }
    }

    @Test func factorAssertionMemberRules() async throws {
        let device = SoftwareP256SigningKey()
        let base = try FactorAssertionClaims.answering(Self.statement(), decision: .approve, userVerification: .userPresence, match: "42", now: Self.now)
        func refused(_ mutate: (inout FactorAssertionClaims) -> Void) async throws -> Bool {
            var claims = base
            mutate(&claims)
            let compact = try await FactorAssertion.sign(claims, with: device)
            do { _ = try FactorAssertion.parse(compact); return false } catch { return true }
        }
        #expect(try await refused { $0.expiresAt = $0.issuedAt + 121 })                          // lifetime
        #expect(try await refused { $0.returnURL = "https://x.example.com" })                   // return_url only for link_open
        #expect(try await refused { $0.envelopeDigest = "abc" })                                // recovery_codes_set only
        #expect(try await refused { $0.headHash = "abc"; $0.seq = 1 })                          // enrollment_confirmed only
        #expect(try await refused { $0.codeHash = Base64URL.encode(Data(repeating: 1, count: 32)) })
        #expect(try await refused { $0.match = "4a" })
        #expect(try await refused { $0.decision = .deny })                                       // a typed number only with approve
        #expect(try await refused { $0.displayDigest = "ABC" })
        #expect(try await refused { $0.challengeId = "ach_short" })
        // An unknown member.
        var payload = base.payload
        payload["display"] = .string("Your Bank")
        let extra = try await AuthorityJWS.signES256(typ: FactorAssertionClaims.type, payload: payload, key: device)
        #expect(throws: AuthorityJOSEError.claims("members")) { try FactorAssertion.parse(extra) }
    }

    // MARK: Grants (ADR-0023 §5)

    @Test func grantVerifierChecksKeyIssuerAudienceCodeChallengeAndTime() throws {
        let key = P256.Signing.PrivateKey()
        let t = Int64(Self.now.timeIntervalSince1970)
        let claims = AuthorityGrantClaims(issuer: "https://id.example/grant", audience: "lcl_a", subject: "sub", tenantId: "tnt", transaction: "adl_x", purpose: "sign_in",
                                          acr: OIDCProfile.acrApp, amr: ["hwk", "mfa"], authTime: t, issuedAt: t, expiresAt: t + 60,
                                          jti: Base64URL.encode(Data(repeating: 3, count: 16)), codeChallenge: "cch")
        let compact = try Self.sign(claims.payload, typ: AuthorityGrantClaims.type, key: key)
        let keys = [JWKThumbprint.p256(key.publicKey): key.publicKey]
        #expect(try AuthorityGrantVerifier.verify(compact, keys: keys, issuer: "https://id.example/grant", audience: "lcl_a", codeChallenge: "cch", now: Self.now) == claims)
        #expect(throws: AuthorityJOSEError.self) { try AuthorityGrantVerifier.verify(compact, keys: keys, issuer: "https://id.example/grant", audience: "lcl_b", codeChallenge: "cch", now: Self.now) }
        #expect(throws: AuthorityJOSEError.self) { try AuthorityGrantVerifier.verify(compact, keys: keys, issuer: "https://id.example/grant", audience: "lcl_a", codeChallenge: "other", now: Self.now) }
        #expect(throws: AuthorityJOSEError.self) { try AuthorityGrantVerifier.verify(compact, keys: keys, issuer: "https://id.example", audience: "lcl_a", codeChallenge: "cch", now: Self.now) }
        #expect(throws: AuthorityJOSEError.expired) {
            try AuthorityGrantVerifier.verify(compact, keys: keys, issuer: "https://id.example/grant", audience: "lcl_a", codeChallenge: "cch", now: Self.now.addingTimeInterval(200))
        }
        #expect(throws: AuthorityJOSEError.unknownKey) {
            try AuthorityGrantVerifier.verify(compact, keys: [:], issuer: "https://id.example/grant", audience: "lcl_a", codeChallenge: "cch", now: Self.now)
        }
        // The grant typ is not interchangeable with an id_token.
        let asJWT = try Self.sign(claims.payload, typ: "JWT", key: key)
        #expect(throws: AuthorityJOSEError.wrongType) {
            try AuthorityGrantVerifier.verify(asJWT, keys: keys, issuer: "https://id.example/grant", audience: "lcl_a", codeChallenge: "cch", now: Self.now)
        }
    }

    // MARK: OIDC profile (ADR-0024)

    @Test func redirectURIRegistrationRules() {
        #expect(OIDCProfile.isRegistrableRedirectURI("https://rp.example.com/callback"))
        for bad in ["http://rp.example.com/cb", "https://*.example.com/cb", "https://rp.example.com/cb#f", "https://user@rp.example.com/cb", "https://127.0.0.1/cb",
                    "https://localhost/cb", "https://[::1]/cb", "myapp://cb", "https://RP.example.com/cb", "https://rp/cb", "https://xn--bcher-kva.example/cb#"] {
            #expect(!OIDCProfile.isRegistrableRedirectURI(bad), "\(bad)")
        }
    }

    @Test func discoveryDocumentAdvertisesOnlyTheStagingSurface() throws {
        let doc = OIDCProfile.discoveryDocument(issuer: "https://id.staging.example").objectValue!
        func list(_ key: String) -> [String] { if case .array(let items)? = doc[key] { return items.compactMap(\.stringValue) }; return [] }
        #expect(list("response_types_supported") == ["code"])
        #expect(list("grant_types_supported") == ["authorization_code"])
        #expect(list("code_challenge_methods_supported") == ["S256"])
        #expect(list("token_endpoint_auth_methods_supported") == ["private_key_jwt"])
        #expect(list("subject_types_supported") == ["pairwise"])
        #expect(list("scopes_supported") == ["openid"])
        #expect(list("id_token_signing_alg_values_supported") == ["RS256", "ES256"])
        #expect(doc["authorization_response_iss_parameter_supported"] == .bool(true))
        #expect(doc["request_parameter_supported"] == .bool(false))
        #expect(doc["jwks_uri"]?.stringValue == "https://id.staging.example/oidc/jwks.json")
    }

    @Test func amrNeverImpliesHardwareOrModality() {
        #expect(OIDCProfile.appAMR(userVerification: .biometric, hardwareAttested: true) == ["hwk", "user", "mfa"])
        #expect(OIDCProfile.appAMR(userVerification: .userPresence, hardwareAttested: true) == ["hwk", "mfa"])
        #expect(OIDCProfile.appAMR(userVerification: .biometric, hardwareAttested: false) == ["swk", "user", "mfa"])
        #expect(OIDCProfile.appAMR(userVerification: .userPresence, hardwareAttested: false) == ["swk", "mfa"])
    }

    @Test func policyRaisesNeverLower() {
        let raised = AuthorityPolicy.v1.raised(requireBiometric: true, requirePasskey: false)
        #expect(raised.raised(requireBiometric: false, requirePasskey: false).requireBiometric)
        #expect(raised.evaluateAppEvidence(userVerification: .userPresence, decision: .approve) == .deny("biometric_required"))
        #expect(raised.evaluateAppEvidence(userVerification: .biometric, decision: .approve) == .allow)
        #expect(AuthorityPolicy.v1.raised(requireBiometric: false, requirePasskey: true).evaluateAppEvidence(userVerification: .biometric, decision: .approve) == .deny("passkey_required"))
        #expect(AuthorityPolicy.v1.evaluateAppEvidence(userVerification: .biometric, decision: .deny) == .deny("not_approved"))
    }

    @Test func wireRequestsAreClosed() throws {
        let body = #"{"factor":"a.b.c","account_id":"6F9619FF-8B86-D011-B42D-00C04FC964FF","grant":"x"}"#
        #expect(throws: DecodingError.self) { try ViadereJSON.decode(AuthorityEvidenceRequest.self, from: Data(body.utf8)) }
        let ok = #"{"factor":"a.b.c"}"#
        #expect(try ViadereJSON.decode(AuthorityEvidenceRequest.self, from: Data(ok.utf8)).factor == "a.b.c")
    }

    @Test func pinnedStatementKeysAreEmptyUntilTheFirstAttestedInventory() {
        // Fail closed: with no pinned key every statement is refused on the device and the authority refuses to start with grants on.
        #expect(AuthorityPinnedKeys.deviceStatementKids(.production).isEmpty)
    }
}
