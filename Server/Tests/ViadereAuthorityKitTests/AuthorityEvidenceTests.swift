@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore
import XCTest
@testable import ViadereAuthorityKit

/// ADR-0023 §3 verification order and ADR-0033 authority-built displays, end to end through the internal routes.
final class AuthorityEvidenceTests: XCTestCase {
    var h: AuthorityHarness!

    override func setUp() async throws { h = try await AuthorityHarness.make() }
    override func tearDown() async throws { try await h.shutdown() }

    func challengeState(_ id: String) async throws -> (state: String, failures: Int) {
        let row = try await AuthorityChallenge.find(id, on: h.app.db)!
        return (row.state, row.matchFailures)
    }

    // MARK: Authority-built display (ADR-0033 §1)

    func testChallengeStatementCarriesTheAuthorityBuiltDisplayAndVerifiesOnTheDevice() async throws {
        let created = try await h.createOIDCChallenge()
        XCTAssertEqual(created.status, .created)
        let response = try XCTUnwrap(created.response)
        let statement = try AuthorityStatementVerifier.verifyChallenge(response.statement, pinnedKeys: [h.statementKey], environment: .staging, now: h.clock.now)
        XCTAssertEqual(statement.purpose, .oidcLogin)
        XCTAssertEqual(statement.redirectURI, AuthorityHarness.redirectURI)
        XCTAssertTrue(statement.matchRequired)
        // The client name comes from the reviewed registration, not from the request.
        XCTAssertEqual(statement.display, AuthorityDisplay.oidcLogin(clientName: "Example Shop", redirectURI: AuthorityHarness.redirectURI, matchDigits: 2))
        let code = try XCTUnwrap(response.matchCode)
        XCTAssertTrue((10...99).contains(Int(code)!))
        // The JOSE kid is the RFC 7638 thumbprint, never the SPKI-hash KeyIdentifier (ADR-0023 §2).
        let parts = try AuthorityJWS.parse(response.statement, expectedType: AuthorityChallengeStatement.type, allowedAlgorithms: ["ES256"])
        XCTAssertEqual(parts.kid, JWKThumbprint.p256(h.statementKey))
        XCTAssertNotEqual(parts.kid, KeyIdentifier.make(h.statementKey))
    }

    func testChallengeForAnUnregisteredRedirectURIIsRefused() async throws {
        for uri in ["https://rp.example.com/callback/", "https://rp.example.com/callback?x=1", "https://evil.example.com/callback", "http://rp.example.com/callback"] {
            let created = try await h.createOIDCChallenge(redirectURI: uri)
            XCTAssertEqual(created.status, .unprocessableEntity, uri)
        }
    }

    func testChallengeRequestBodyIsClosed() async throws {
        // A relay cannot smuggle display text into the request.
        let body = #"{"purpose":"oidc_login","display":{"client_name":"Bank"},"oidc":{"client_id":"ocl_testclient","redirect_uri":"https://rp.example.com/callback","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256","nonce":"n"}}"#
        let result = try await h.call(.POST, AuthorityRoute.challenges, json: Data(body.utf8))
        XCTAssertEqual(result.status, .unprocessableEntity)
        let nested = #"{"purpose":"oidc_login","oidc":{"client_id":"ocl_testclient","client_name":"Bank","redirect_uri":"https://rp.example.com/callback","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256","nonce":"n"}}"#
        let second = try await h.call(.POST, AuthorityRoute.challenges, json: Data(nested.utf8))
        XCTAssertEqual(second.status, .unprocessableEntity)
    }

    func testPlainPKCEAndPasskeyOnlyRequestsCreateNoAppChallenge() async throws {
        var body = AuthorityChallengeCreateRequest(purpose: .oidcLogin, oidc: .init(clientId: AuthorityHarness.clientId, redirectURI: AuthorityHarness.redirectURI,
                                                                                   codeChallenge: AuthorityHarness.codeVerifier, codeChallengeMethod: "plain", nonce: "n"))
        var result = try await h.call(.POST, AuthorityRoute.challenges, json: try ViadereJSON.encode(body))
        XCTAssertEqual(result.status, .unprocessableEntity)
        body.oidc?.codeChallengeMethod = "S256"
        body.oidc?.codeChallenge = AuthorityHarness.challenge(for: AuthorityHarness.codeVerifier)
        body.oidc?.acrValues = [OIDCProfile.acrPasskey]
        result = try await h.call(.POST, AuthorityRoute.challenges, json: try ViadereJSON.encode(body))
        XCTAssertEqual(result.status, .unprocessableEntity)
        XCTAssertTrue(String(decoding: result.body, as: UTF8.self).contains("passkey_required"))
    }

    func testChallengeSigningHasAPerTenantBulkhead() async throws {
        for _ in 0..<h.config.challengeBudgetPerTenantPerMinute { _ = try await h.createOIDCChallenge() }
        let over = try await h.createOIDCChallenge()
        XCTAssertEqual(over.status, .tooManyRequests)
        h.clock.advance(61)
        let later = try await h.createOIDCChallenge()
        XCTAssertEqual(later.status, .created)
    }

    // MARK: Evidence: success and single use

    func testApprovedEvidenceYieldsACodeOnceAndTheChallengeIsConsumed() async throws {
        let challenge = try await h.createOIDCChallenge().response!
        let factor = try await h.answer(challenge)
        let first = try await h.submit(factor, accountId: h.accountId)
        XCTAssertEqual(first.status, .ok)
        XCTAssertNotNil(first.response?.code)
        await XCTAssertEqualAsync(try await challengeState(challenge.challengeId).state, "used")
        // Replay of the same assertion, and a fresh assertion for the same challenge: refused.
        let replay = try await h.submit(factor)
        XCTAssertEqual(replay.status, .unauthorized)
        let again = try await h.submit(try await h.answer(challenge))
        XCTAssertEqual(again.status, .unauthorized)
    }

    func testRefusalsAreGenericAndAudited() async throws {
        let challenge = try await h.createOIDCChallenge().response!
        let factor = try await h.answer(challenge) { $0.displayDigest = String(repeating: "0", count: 64) }
        let result = try await h.call(.POST, AuthorityRoute.evidence, json: try ViadereJSON.encode(AuthorityEvidenceRequest(factor: factor)))
        XCTAssertEqual(result.status, .unauthorized)
        XCTAssertTrue(String(decoding: result.body, as: UTF8.self).contains("evidence_invalid"))
        XCTAssertFalse(String(decoding: result.body, as: UTF8.self).contains("display"))
        let events = try await AuthorityAuditEvent.query(on: h.app.db).filter(\.$reason == "display_mismatch").count()
        XCTAssertEqual(events, 1)
    }

    // MARK: Each step of ADR-0023 §3 refuses

    func testWrongDisplayDigestIsRefusedAndDoesNotBurnTheChallenge() async throws {
        let challenge = try await h.createOIDCChallenge().response!
        let forged = try await h.answer(challenge) { $0.displayDigest = try! AuthorityDisplay.digest(AuthorityDisplay.oidcLogin(clientName: "Your Bank", redirectURI: AuthorityHarness.redirectURI, matchDigits: 2)) }
        await XCTAssertEqualAsync(try await h.submit(forged).status, .unauthorized)
        await XCTAssertEqualAsync(try await challengeState(challenge.challengeId).state, "pending")
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge)).status, .ok)
    }

    func testForgedSignatureDoesNotBurnTheChallenge() async throws {
        let challenge = try await h.createOIDCChallenge().response!
        // Signed by a key the authority does not know, but carrying the logged key's kid.
        let genuine = try await h.answer(challenge)
        let stranger = try await h.answer(challenge, key: SoftwareP256SigningKey())
        let forged = genuine.split(separator: ".").prefix(2).joined(separator: ".") + "." + stranger.split(separator: ".")[2]
        await XCTAssertEqualAsync(try await h.submit(forged).status, .unauthorized)
        await XCTAssertEqualAsync(try await challengeState(challenge.challengeId).state, "pending")
        await XCTAssertEqualAsync(try await h.submit(genuine).status, .ok)
    }

    func testUnknownAndRevokedKeysAreRefused() async throws {
        let challenge = try await h.createOIDCChallenge().response!
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge, key: SoftwareP256SigningKey())).status, .unauthorized)
        let kid = KeyIdentifier.make(try h.biometricKey.publicKey.signingKey())
        let revoke = try await h.call(.POST, AuthorityRoute.revocations, token: StaticCallerVerifier.workerToken,
                                      json: try ViadereJSON.encode(AuthorityRevocationRequest(kid: kid, reason: "device_lost")))
        XCTAssertEqual(revoke.status, .ok)
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge)).status, .unauthorized)
        // The revocation is a key-log entry (append-only chain).
        let entries = try await AuthorityKeylogEntry.query(on: h.app.db).sort(\.$seq).all()
        // The harness device confirmed its imported keys (ADR-0032 §1.4) before the revocation.
        XCTAssertEqual(entries.map(\.type), ["imported", "imported", "enrollment_confirmed", "key_revoked"])
        XCTAssertEqual(entries.last?.kid, kid)
        XCTAssertEqual(entries[0].prevHash, AuthorityKeyLog.genesisHash)
        for i in 1..<entries.count { XCTAssertEqual(entries[i].prevHash, entries[i - 1].entryHash) }
    }

    func testAccountBindingMismatchIsRefused() async throws {
        let challenge = try await h.createOIDCChallenge().response!
        let factor = try await h.answer(challenge)
        await XCTAssertEqualAsync(try await h.submit(factor, accountId: UUID()).status, .unauthorized)
        await XCTAssertEqualAsync(try await AuthorityAuditEvent.query(on: h.app.db).filter(\.$reason == "account_binding_mismatch").count(), 1)
        await XCTAssertEqualAsync(try await h.submit(factor, accountId: h.accountId).status, .ok)
    }

    func testWrongAudienceNonceAndPurposeAreRefused() async throws {
        let challenge = try await h.createOIDCChallenge().response!
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge) { $0.audience = AuthorityEnvironment.production.authorityURN }).status, .unauthorized)
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge) { $0.nonce = AuthorityNonce.generate() }).status, .unauthorized)
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge) { $0.challengeId = AuthorityChallengeID.generate() }).status, .unauthorized)
        await XCTAssertEqualAsync(try await challengeState(challenge.challengeId).state, "pending")
    }

    func testBiometricClaimFromAUserPresenceKeyIsRefused() async throws {
        let challenge = try await h.createOIDCChallenge().response!
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge, key: h.presenceKey, uv: .biometric)).status, .unauthorized)
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge, key: h.presenceKey, uv: .userPresence)).status, .ok)
    }

    func testExpiredChallengeAndAssertionTimeBoundsAreRefused() async throws {
        let challenge = try await h.createOIDCChallenge().response!
        let factor = try await h.answer(challenge)
        h.clock.advance(h.config.challengeLifetime + 1)
        await XCTAssertEqualAsync(try await h.submit(factor).status, .unauthorized)
        await XCTAssertEqualAsync(try await challengeState(challenge.challengeId).state, "expired")

        let fresh = try await h.createOIDCChallenge().response!
        let future = try await h.answer(fresh) { $0.issuedAt += 600; $0.expiresAt += 600 }
        await XCTAssertEqualAsync(try await h.submit(future).status, .unauthorized)
    }

    func testWrongNumberCountsAndTheThirdFailsTheChallenge() async throws {
        let challenge = try await h.createOIDCChallenge().response!
        let wrong = challenge.matchCode == "42" ? "43" : "42"
        for attempt in 1...3 {
            await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge, match: .some(wrong))).status, .unauthorized)
            let state = try await challengeState(challenge.challengeId)
            XCTAssertEqual(state.failures, attempt)
            XCTAssertEqual(state.state, attempt < 3 ? "pending" : "failed")
        }
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge)).status, .unauthorized)
        // A missing number is refused too.
        let other = try await h.createOIDCChallenge().response!
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(other, match: .some(nil))).status, .unauthorized)
    }

    func testDenyClosesTheChallengeWithoutACode() async throws {
        let challenge = try await h.createOIDCChallenge().response!
        let result = try await h.submit(try await h.answer(challenge, decision: .deny))
        XCTAssertEqual(result.status, .ok)
        XCTAssertEqual(result.response?.decision, .deny)
        XCTAssertNil(result.response?.code)
        await XCTAssertEqualAsync(try await challengeState(challenge.challengeId).state, "denied")
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge)).status, .unauthorized)
    }

    func testNonGrantCapableKeyIsRefused() async throws {
        let kid = KeyIdentifier.make(try h.biometricKey.publicKey.signingKey())
        let key = try await AuthorityKey.find(kid, on: h.app.db)!
        key.grantCapable = false
        try await key.update(on: h.app.db)
        let challenge = try await h.createOIDCChallenge().response!
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge)).status, .unauthorized)
    }

    func testFrozenAccountIsRefused() async throws {
        let account = try await AuthorityAccount.find(h.accountId, on: h.app.db)!
        account.frozen = true
        try await account.update(on: h.app.db)
        let challenge = try await h.createOIDCChallenge().response!
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge)).status, .unauthorized)
    }

    func testUnsupportedPurposesAreRefused() async throws {
        let body = AuthorityChallengeCreateRequest(purpose: .keylogDeviceAdded)
        let result = try await h.call(.POST, AuthorityRoute.challenges, json: try ViadereJSON.encode(body))
        XCTAssertEqual(result.status, .unprocessableEntity)
    }

    // MARK: Link service grant (ADR-0023 §5)

    func testLinkOpenEvidenceYieldsAGrantForTheTenantSubjectRef() async throws {
        let challenge = try await h.createLinkChallenge(crossDevice: true)
        let result = try await h.submit(try await h.answer(challenge), accountId: h.accountId)
        XCTAssertEqual(result.status, .ok)
        // ADR-0021 §5.3: the evidence answer carries no grant (the api never holds one); the business redeems it.
        XCTAssertNil(result.response?.grant)
        await XCTAssertEqualAsync(try await AuthorityGrantRecord.query(on: h.app.db).filter(\.$kind == "grant").count(), 0)
        let redeemed = try await h.post(AuthorityKeyLogRoute.linkRedeem, ["link_client_id": .string(AuthorityHarness.linkClientId),
                                                                          "business_id": .string(AuthorityHarness.businessId.uuidString),
                                                                          "code_verifier": .string(AuthorityHarness.codeVerifier), "ach": .string(challenge.challengeId)])
        XCTAssertEqual(redeemed.status, .ok)
        let grant = try XCTUnwrap(redeemed.body["grant"]?.stringValue)
        let claims = try AuthorityGrantVerifier.verify(grant, keys: [JWKThumbprint.p256(h.grantKey): h.grantKey], issuer: AuthorityHarness.issuer + "/grant",
                                                       audience: AuthorityHarness.linkClientId, codeChallenge: AuthorityHarness.challenge(for: AuthorityHarness.codeVerifier),
                                                       now: h.clock.now)
        let expected = SubjectRefDeriver(key: h.config.subjectRefKey).subjectRef(businessId: BusinessID(AuthorityHarness.businessId), consumerId: ConsumerID(h.accountId))
        XCTAssertEqual(claims.subject, expected.rawValue)
        XCTAssertEqual(claims.amr, ["hwk", "user", "mfa"])
        XCTAssertEqual(claims.acr, OIDCProfile.acrApp)
        await XCTAssertEqualAsync(try await AuthorityGrantRecord.query(on: h.app.db).filter(\.$kind == "grant").count(), 1)
        // Another audience, another code challenge: refused by the SDK verifier.
        XCTAssertThrowsError(try AuthorityGrantVerifier.verify(grant, keys: [JWKThumbprint.p256(h.grantKey): h.grantKey], issuer: AuthorityHarness.issuer + "/grant",
                                                               audience: "lcl_other", codeChallenge: AuthorityHarness.challenge(for: AuthorityHarness.codeVerifier), now: h.clock.now))
    }

    func testLinkOpenNeedsTheExactReturnURLAndSameDeviceNeedsACodeHash() async throws {
        let cross = try await h.createLinkChallenge(crossDevice: true)
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(cross) { $0.returnURL = AuthorityHarness.returnURL + "?next=/admin" }).status, .unauthorized)
        let same = try await h.createLinkChallenge(crossDevice: false)
        XCTAssertNil(same.matchCode)
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(same)).status, .unauthorized)
        let codeHash = Base64URL.encode(Data(SHA256.hash(data: Data("device-link-code".utf8))))
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(same, codeHash: codeHash)).status, .ok)
    }

    func testRequireBiometricRaiseRefusesUserPresence() async throws {
        let client = try await AuthorityLinkClient.find(AuthorityHarness.linkClientId, on: h.app.db)!
        client.requireBiometric = true
        try await client.update(on: h.app.db)
        let challenge = try await h.createLinkChallenge(crossDevice: true)
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge, key: h.presenceKey, uv: .userPresence)).status, .unauthorized)
        await XCTAssertEqualAsync(try await AuthorityAuditEvent.query(on: h.app.db).filter(\.$reason == "policy_biometric_required").count(), 1)
    }

    // MARK: Append-only history

    func testGrantsAuditAndKeyLogAreAppendOnly() async throws {
        _ = try await h.approvedCode()
        guard let sql = h.app.db as? any SQLDatabase else { return XCTFail("SQL database expected") }
        for (table, column) in [(AuthorityAuditEvent.schema, "event"), (AuthorityKeylogEntry.schema, "type")] {
            do {
                try await sql.raw("UPDATE \(ident: table) SET \(ident: column) = 'x'").run()
                XCTFail("update of \(table) must fail")
            } catch {}
            do {
                try await sql.raw("DELETE FROM \(ident: table)").run()
                XCTFail("delete from \(table) must fail")
            } catch {}
        }
    }
}
