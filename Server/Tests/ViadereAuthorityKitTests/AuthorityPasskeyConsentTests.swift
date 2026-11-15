@preconcurrency import Crypto
import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore
import XCTest
@testable import ViadereAuthorityKit

/// ADR-0023 §3a, ADR-0024 §4 method 1, §8: the passkey method verified by the authority itself, consent records, and the `login_hint` check.
final class AuthorityPasskeyConsentTests: XCTestCase {
    var h: AuthorityHarness!

    override func setUp() async throws { h = try await AuthorityHarness.make() }
    override func tearDown() async throws { try await h.shutdown() }

    static let origin = AuthorityHarness.issuer
    static let rpId = "viadere.test"

    // MARK: Helpers

    func passkeyChallenge(acr: [String]? = nil) async throws -> (status: HTTPStatus, response: AuthorityPasskeyChallengeResponse?) {
        let body = AuthorityPasskeyChallengeRequest(oidc: .init(clientId: AuthorityHarness.clientId, redirectURI: AuthorityHarness.redirectURI,
                                                                codeChallenge: AuthorityHarness.challenge(for: AuthorityHarness.codeVerifier),
                                                                codeChallengeMethod: "S256", nonce: "n-0S6_WzA2Mj", acrValues: acr))
        let result = try await h.call(.POST, AuthorityRoute.oidcPasskeyChallenges, json: try ViadereJSON.encode(body))
        return (result.status, result.status == .created ? try ViadereJSON.decode(AuthorityPasskeyChallengeResponse.self, from: result.body) : nil)
    }

    /// A WebAuthn assertion built byte by byte, so every member the authority checks can be varied.
    func assertion(challenge: String, credential: PasskeyCredential? = nil, origin: String = AuthorityPasskeyConsentTests.origin, type: String = "webauthn.get",
                   extraClientData: String = "", rpId: String = AuthorityPasskeyConsentTests.rpId, userVerified: Bool = true, counter: UInt32 = 0,
                   id: String? = nil) throws -> PasskeyAssertionCredential {
        let credential = credential ?? h.passkey
        let json = "{\"type\":\"\(type)\",\"challenge\":\"\(challenge)\",\"origin\":\"\(origin)\"\(extraClientData)}"
        var flags: UInt8 = 0x01 | 0x08 | 0x10 // UP, BE, BS
        if userVerified { flags |= 0x04 }
        var authData = Data(SHA256.hash(data: Data(rpId.utf8)))
        authData.append(flags)
        authData.append(contentsOf: [UInt8(counter >> 24 & 0xFF), UInt8(counter >> 16 & 0xFF), UInt8(counter >> 8 & 0xFF), UInt8(counter & 0xFF)])
        let key = try P256.Signing.PrivateKey(rawRepresentation: credential.privateKey)
        let signature = try key.signature(for: authData + Data(SHA256.hash(data: Data(json.utf8))))
        let credentialId = id ?? Base64URL.encode(credential.credentialId)
        return PasskeyAssertionCredential(id: credentialId, rawId: credentialId, authenticatorData: Base64URL.encode(authData),
                                          clientDataJSON: Base64URL.encode(Data(json.utf8)), signature: Base64URL.encode(signature.derRepresentation),
                                          userHandle: Base64URL.encode(credential.userHandle))
    }

    func submit(_ ach: String, _ credential: PasskeyAssertionCredential, token: String = StaticCallerVerifier.apiToken) async throws -> (status: HTTPStatus, response: AuthorityEvidenceResponse?) {
        let result = try await h.call(.POST, AuthorityRoute.oidcPasskeyEvidence, token: token,
                                      json: try ViadereJSON.encode(AuthorityPasskeyEvidenceRequest(challengeId: ach, credential: credential)))
        return (result.status, result.status == .ok ? try ViadereJSON.decode(AuthorityEvidenceResponse.self, from: result.body) : nil)
    }

    func claims(_ jwt: String) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: Base64URL.decode(String(jwt.split(separator: ".")[1]))!) as! [String: Any]
    }

    func challengeState(_ ach: String) async throws -> String? { try await AuthorityPasskeyChallenge.find(ach, on: h.app.db)?.state }

    /// `XCTUnwrap` for a value computed by an `async` call (XCTest's autoclosures are synchronous).
    func unwrapped<T>(_ value: T?, file: StaticString = #filePath, line: UInt = #line) throws -> T { try XCTUnwrap(value, file: file, line: line) }

    // MARK: Passkey method

    func testPasskeyAssertionYieldsACodeWithThePasskeyAcrAndRecordsConsent() async throws {
        let challenge = try unwrapped(try await passkeyChallenge().response)
        XCTAssertEqual(challenge.relyingPartyId, Self.rpId)
        XCTAssertTrue(AuthorityNonce.isValid(challenge.challenge))
        // Nothing was signed for a passkey challenge, and it is not an app challenge.
        // (The harness's own enrollment confirmation is an `enrollment_confirmed` challenge.)
        let appChallenges = try await AuthorityChallenge.query(on: h.app.db).filter(\.$purpose == AuthorityPurpose.oidcLogin.rawValue).count()
        XCTAssertEqual(appChallenges, 0)

        let result = try await submit(challenge.challengeId, try assertion(challenge: challenge.challenge))
        XCTAssertEqual(result.status, .ok)
        let code = try XCTUnwrap(result.response?.code)
        let tokens = try await h.call(.POST, AuthorityRoute.oidcToken, form: try h.tokenForm(code: code))
        XCTAssertEqual(tokens.status, .ok)
        let json = try JSONSerialization.jsonObject(with: tokens.body) as! [String: Any]
        let id = try claims(json["id_token"] as! String)
        XCTAssertEqual(id["acr"] as? String, OIDCProfile.acrPasskey)
        // The imported passkey has no device-bound attestation: `swk`, never an implied `hwk`.
        XCTAssertEqual(id["amr"] as? [String], ["swk", "user", "mfa"])
        XCTAssertEqual(id["sub"] as? String, OIDCProfile.pairwiseSubject(key: h.config.oidcPairwiseKey, sectorHost: "rp.example.com", accountId: h.accountId))

        // Consent: recorded on first use (ADR-0024 §8), last use moves on the next one.
        let consents = try await AuthorityOIDCConsent.query(on: h.app.db).all()
        XCTAssertEqual(consents.count, 1)
        XCTAssertEqual(consents.first?.clientId, AuthorityHarness.clientId)
        let granted = try XCTUnwrap(consents.first?.grantedAt)
        h.clock.advance(30)
        _ = try await h.approvedCode()
        let after = try await AuthorityOIDCConsent.query(on: h.app.db).all()
        XCTAssertEqual(after.count, 1)
        XCTAssertEqual(after.first?.grantedAt, granted)
        XCTAssertEqual(after.first?.lastUsedAt, h.clock.now)
    }

    /// ADR-0023 §3a item 2: `oidc_login` accepts exactly the issuer origin; not cross-origin, no `topOrigin`, only `webauthn.get`. A refusal never
    /// touches the challenge.
    func testOriginAllowListAndClientDataRules() async throws {
        let challenge = try unwrapped(try await passkeyChallenge().response)
        let refused: [PasskeyAssertionCredential] = [
            try assertion(challenge: challenge.challenge, origin: "https://viadere.test"),
            try assertion(challenge: challenge.challenge, origin: "https://evil.example"),
            try assertion(challenge: challenge.challenge, origin: AuthorityHarness.issuer + ":8443"),
            try assertion(challenge: challenge.challenge, extraClientData: ",\"crossOrigin\":true"),
            try assertion(challenge: challenge.challenge, extraClientData: ",\"crossOrigin\":\"false\""),
            try assertion(challenge: challenge.challenge, extraClientData: ",\"topOrigin\":\"https://evil.example\""),
            try assertion(challenge: challenge.challenge, type: "webauthn.create"),
        ]
        for credential in refused {
            await XCTAssertEqualAsync(try await submit(challenge.challengeId, credential).status, .unauthorized)
        }
        let state = try await challengeState(challenge.challengeId)
        XCTAssertEqual(state, "pending")
        let reasons = Set(try await AuthorityAuditEvent.query(on: h.app.db).filter(\.$event == "authority.passkey_evidence").all().compactMap(\.reason))
        XCTAssertTrue(reasons.isSuperset(of: ["origin_not_allowed", "client_data", "ceremony_type"]), "\(reasons)")
        // `crossOrigin: false` is fine, and the untouched challenge still works.
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, try assertion(challenge: challenge.challenge, extraClientData: ",\"crossOrigin\":false")).status, .ok)
    }

    func testUserVerificationTheLoggedKeyAndTheRPIdAreRequired() async throws {
        let challenge = try unwrapped(try await passkeyChallenge().response)
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, try assertion(challenge: challenge.challenge, userVerified: false)).status, .unauthorized)
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, try assertion(challenge: challenge.challenge, rpId: "evil.example")).status, .unauthorized)
        // Signed by another key under the logged credential id.
        var other = h.passkey
        other.privateKey = P256.Signing.PrivateKey().rawRepresentation
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, try assertion(challenge: challenge.challenge, credential: other,
                                                                                         id: Base64URL.encode(h.passkey.credentialId))).status, .unauthorized)
        // A passkey the authority never logged (for example one created on a web page).
        let foreign = try WebAuthnAuthenticator.makeCredential(rpId: Self.rpId, userHandle: Data([1]), userName: "x", clientDataHash: Data(repeating: 2, count: 32),
                                                               requireUserVerification: true, userVerified: true, backedUp: true, now: h.clock.now).credential
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, try assertion(challenge: challenge.challenge, credential: foreign)).status, .unauthorized)
        // Another challenge's nonce.
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, try assertion(challenge: AuthorityNonce.generate())).status, .unauthorized)
        let state = try await challengeState(challenge.challengeId)
        XCTAssertEqual(state, "pending")

        // A revoked or frozen key is refused.
        let passkeyId = Base64URL.encode(h.passkey.credentialId)
        try await AuthorityPasskey.query(on: h.app.db).filter(\.$id == passkeyId).set(\.$revokedAt, to: h.clock.now).update()
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, try assertion(challenge: challenge.challenge)).status, .unauthorized)
        try await AuthorityPasskey.query(on: h.app.db).filter(\.$id == passkeyId).set(\.$revokedAt, to: nil).update()
        try await AuthorityAccount.query(on: h.app.db).filter(\.$id == h.accountId).set(\.$frozen, to: true).update()
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, try assertion(challenge: challenge.challenge)).status, .unauthorized)
    }

    /// ST-REC-17 (ADR-0023 §3a items 1 and 5): a passkey assertion is accepted only on a passkey `oidc_login` challenge. It cannot answer an app,
    /// link or key-log challenge, whatever its origin; and a factor JWS cannot answer a passkey challenge.
    func testPasskeyAssertionsAnswerOnlyPasskeyChallenges() async throws {
        let app = try unwrapped(try await h.createOIDCChallenge().response)
        let appRow = try unwrapped(try await AuthorityChallenge.find(app.challengeId, on: h.app.db))
        await XCTAssertEqualAsync(try await submit(app.challengeId, try assertion(challenge: appRow.nonce)).status, .unauthorized)
        let link = try await h.createLinkChallenge(crossDevice: true)
        let linkRow = try unwrapped(try await AuthorityChallenge.find(link.challengeId, on: h.app.db))
        await XCTAssertEqualAsync(try await submit(link.challengeId, try assertion(challenge: linkRow.nonce)).status, .unauthorized)
        let appState = try await AuthorityChallenge.find(app.challengeId, on: h.app.db)?.state
        XCTAssertEqual(appState, "pending")

        // A factor JWS naming a passkey challenge finds no challenge.
        let passkey = try unwrapped(try await passkeyChallenge().response)
        let factor = try await h.answer(app) { $0.challengeId = passkey.challengeId; $0.nonce = passkey.challenge }
        await XCTAssertEqualAsync(try await h.submit(factor, accountId: h.accountId).status, .unauthorized)
        let passkeyState = try await challengeState(passkey.challengeId)
        XCTAssertEqual(passkeyState, "pending")
    }

    /// Imported keys need the device's confirmation before they produce a grant or a code (ADR-0032 §1.4, §1.6); an imported passkey follows its
    /// account: refused until a device of the account confirmed the log.
    func testImportedPasskeyIsRefusedUntilADeviceConfirmedTheAccount() async throws {
        try await h.shutdown()
        var options = AuthorityHarness.Options()
        options.confirmImportedKeys = false
        h = try await AuthorityHarness.make(options)
        let challenge = try unwrapped(try await passkeyChallenge().response)
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, try assertion(challenge: challenge.challenge)).status, .unauthorized)
        let reasons = try await AuthorityAuditEvent.query(on: h.app.db).filter(\.$event == "authority.passkey_evidence").all().compactMap(\.reason)
        XCTAssertEqual(reasons, ["not_grant_capable"])
        let state = try await challengeState(challenge.challengeId)
        XCTAssertEqual(state, "pending")
    }

    func testPasskeyChallengeIsSingleUseAndExpires() async throws {
        let challenge = try unwrapped(try await passkeyChallenge().response)
        let credential = try assertion(challenge: challenge.challenge)
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, credential).status, .ok)
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, credential).status, .unauthorized)
        let codes = try await AuthorityOIDCCode.query(on: h.app.db).count()
        XCTAssertEqual(codes, 1)

        let late = try unwrapped(try await passkeyChallenge().response)
        h.clock.advance(h.config.challengeLifetime + 1)
        await XCTAssertEqualAsync(try await submit(late.challengeId, try assertion(challenge: late.challenge)).status, .unauthorized)
    }

    /// Concurrent submissions of one assertion: the compare-and-swap lets exactly one through (the state read alone cannot).
    func testConcurrentSubmissionsYieldOneCode() async throws {
        let challenge = try unwrapped(try await passkeyChallenge().response)
        let credential = try assertion(challenge: challenge.challenge)
        let harness: AuthorityHarness = h
        let body = try ViadereJSON.encode(AuthorityPasskeyEvidenceRequest(challengeId: challenge.challengeId, credential: credential))
        let statuses = try await withThrowingTaskGroup(of: HTTPStatus.self) { group in
            for _ in 0..<6 { group.addTask { try await harness.call(.POST, AuthorityRoute.oidcPasskeyEvidence, json: body).status } }
            return try await group.reduce(into: [HTTPStatus]()) { $0.append($1) }
        }
        XCTAssertEqual(statuses.filter { $0 == .ok }.count, 1, "\(statuses)")
        let codes = try await AuthorityOIDCCode.query(on: h.app.db).count()
        XCTAssertEqual(codes, 1)
    }

    /// A signature counter that does not grow is a possible clone: refused, and the stored counter moves only forward.
    func testSignatureCounterMustGrow() async throws {
        let passkeyId = Base64URL.encode(h.passkey.credentialId)
        try await AuthorityPasskey.query(on: h.app.db).filter(\.$id == passkeyId).set(\.$signCount, to: 5).update()
        let challenge = try unwrapped(try await passkeyChallenge().response)
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, try assertion(challenge: challenge.challenge, counter: 5)).status, .unauthorized)
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, try assertion(challenge: challenge.challenge, counter: 3)).status, .unauthorized)
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, try assertion(challenge: challenge.challenge, counter: 9)).status, .ok)
        let stored = try await AuthorityPasskey.find(passkeyId, on: h.app.db)?.signCount
        XCTAssertEqual(stored, 9)
    }

    func testPasskeyRoutesNeedTheApiRoleAndTheFlags() async throws {
        let challenge = try unwrapped(try await passkeyChallenge().response)
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, try assertion(challenge: challenge.challenge), token: StaticCallerVerifier.workerToken).status, .forbidden)
        await XCTAssertEqualAsync(try await submit(challenge.challengeId, try assertion(challenge: challenge.challenge), token: StaticCallerVerifier.apiWithoutRoleToken).status, .forbidden)
        // Unknown members are refused (closed bodies).
        let open = Data(#"{"oidc":{"client_id":"ocl_testclient","redirect_uri":"https://rp.example.com/callback","code_challenge":"x","code_challenge_method":"S256","nonce":"n"},"extra":1}"#.utf8)
        await XCTAssertEqualAsync(try await h.call(.POST, AuthorityRoute.oidcPasskeyChallenges, json: open).status, .unprocessableEntity)
        // A login hint is an app-path concept only.
        let hinted = AuthorityPasskeyChallengeRequest(oidc: .init(clientId: AuthorityHarness.clientId, redirectURI: AuthorityHarness.redirectURI,
                                                                  codeChallenge: AuthorityHarness.challenge(for: AuthorityHarness.codeVerifier), codeChallengeMethod: "S256",
                                                                  nonce: "n", loginHint: "sub_x"))
        await XCTAssertEqualAsync(try await h.call(.POST, AuthorityRoute.oidcPasskeyChallenges, json: try ViadereJSON.encode(hinted)).status, .unprocessableEntity)

        var off = AuthorityHarness.Options()
        off.oidc = false
        let disabled = try await AuthorityHarness.make(off)
        let body = AuthorityPasskeyChallengeRequest(oidc: .init(clientId: AuthorityHarness.clientId, redirectURI: AuthorityHarness.redirectURI,
                                                                codeChallenge: AuthorityHarness.challenge(for: AuthorityHarness.codeVerifier), codeChallengeMethod: "S256", nonce: "n"))
        await XCTAssertEqualAsync(try await disabled.call(.POST, AuthorityRoute.oidcPasskeyChallenges, json: try ViadereJSON.encode(body)).status, .notFound)
        await XCTAssertEqualAsync(try await disabled.call(.POST, AuthorityRoute.oidcConsents, json: try ViadereJSON.encode(AuthorityConsentListRequest(accountId: UUID()))).status, .notFound)
        try await disabled.shutdown()
    }

    func testAnUnregisteredRedirectGetsNoPasskeyChallenge() async throws {
        let body = AuthorityPasskeyChallengeRequest(oidc: .init(clientId: AuthorityHarness.clientId, redirectURI: "https://rp.example.com/other",
                                                                codeChallenge: AuthorityHarness.challenge(for: AuthorityHarness.codeVerifier), codeChallengeMethod: "S256", nonce: "n"))
        await XCTAssertEqualAsync(try await h.call(.POST, AuthorityRoute.oidcPasskeyChallenges, json: try ViadereJSON.encode(body)).status, .unprocessableEntity)
        let count = try await AuthorityPasskeyChallenge.query(on: h.app.db).count()
        XCTAssertEqual(count, 0)
    }

    // MARK: Consents (ADR-0024 §8)

    func testConsentListIsPerAccountAndRevokeIsReduceOnly() async throws {
        _ = try await h.approvedCode()
        let list = try await h.call(.POST, AuthorityRoute.oidcConsents, json: try ViadereJSON.encode(AuthorityConsentListRequest(accountId: h.accountId)))
        XCTAssertEqual(list.status, .ok)
        let consents = try ViadereJSON.decode(AuthorityConsentListResponse.self, from: list.body).consents
        XCTAssertEqual(consents.map(\.clientId), [AuthorityHarness.clientId])
        XCTAssertEqual(consents.first?.clientName, "Example Shop")
        XCTAssertEqual(consents.first?.host, "rp.example.com")
        let stranger = UUID()
        let other = try await h.call(.POST, AuthorityRoute.oidcConsents, json: try ViadereJSON.encode(AuthorityConsentListRequest(accountId: stranger)))
        XCTAssertEqual(try ViadereJSON.decode(AuthorityConsentListResponse.self, from: other.body).consents, [])

        // Another account cannot remove it; the worker (reduce-only role) and the api can remove their named account's consent.
        let foreign = try await h.call(.POST, AuthorityRoute.oidcConsentRevoke,
                                       json: try ViadereJSON.encode(AuthorityConsentRevokeRequest(accountId: stranger, clientId: AuthorityHarness.clientId)))
        XCTAssertEqual(String(decoding: foreign.body, as: UTF8.self), #"{"revoked":false}"#)
        let stillThere = try await AuthorityOIDCConsent.query(on: h.app.db).count()
        XCTAssertEqual(stillThere, 1)
        await XCTAssertEqualAsync(try await h.call(.POST, AuthorityRoute.oidcConsentRevoke, token: StaticCallerVerifier.apiWithoutRoleToken,
                                                   json: try ViadereJSON.encode(AuthorityConsentRevokeRequest(accountId: h.accountId, clientId: AuthorityHarness.clientId))).status,
                                  .forbidden)
        await XCTAssertEqualAsync(try await h.call(.POST, AuthorityRoute.oidcConsents, token: StaticCallerVerifier.workerToken,
                                                   json: try ViadereJSON.encode(AuthorityConsentListRequest(accountId: h.accountId))).status, .forbidden)
        let revoked = try await h.call(.POST, AuthorityRoute.oidcConsentRevoke, token: StaticCallerVerifier.workerToken,
                                       json: try ViadereJSON.encode(AuthorityConsentRevokeRequest(accountId: h.accountId, clientId: AuthorityHarness.clientId)))
        XCTAssertEqual(String(decoding: revoked.body, as: UTF8.self), #"{"revoked":true}"#)
        let gone = try await AuthorityOIDCConsent.query(on: h.app.db).count()
        XCTAssertEqual(gone, 0)
        let audit = try await AuthorityAuditEvent.query(on: h.app.db).filter(\.$event == "authority.oidc_consent_revoked").count()
        XCTAssertEqual(audit, 1)
        await XCTAssertEqualAsync(try await h.call(.POST, AuthorityRoute.oidcConsentRevoke,
                                                   json: Data(#"{"account_id":"\#(h.accountId.uuidString)","client_id":"lcl_testlink"}"#.utf8)).status, .unprocessableEntity)
    }

    // MARK: login_hint (ADR-0024 §4 method 2)

    func testLoginHintIsAcceptedOnlyForTheAccountsSubjectRefAtTheClientsBusiness() async throws {
        try await h.shutdown()
        var options = AuthorityHarness.Options()
        options.clientExtras = ["business_id": .string(AuthorityHarness.businessId.uuidString)]
        h = try await AuthorityHarness.make(options)
        let deriver = SubjectRefDeriver(key: h.config.subjectRefKey)
        let hint = deriver.subjectRef(businessId: BusinessID(AuthorityHarness.businessId), consumerId: ConsumerID(h.accountId)).rawValue

        func create(hint: String?, account: UUID?) async throws -> Bool? {
            let body = AuthorityChallengeCreateRequest(purpose: .oidcLogin, oidc: .init(clientId: AuthorityHarness.clientId, redirectURI: AuthorityHarness.redirectURI,
                                                                                        codeChallenge: AuthorityHarness.challenge(for: AuthorityHarness.codeVerifier),
                                                                                        codeChallengeMethod: "S256", nonce: "n", loginHint: hint, hintAccountId: account))
            let result = try await h.call(.POST, AuthorityRoute.challenges, json: try ViadereJSON.encode(body))
            XCTAssertEqual(result.status, .created)
            return try ViadereJSON.decode(AuthorityChallengeCreateResponse.self, from: result.body).hintAccepted
        }
        let accepted = try await create(hint: hint, account: h.accountId)
        XCTAssertEqual(accepted, true)
        let none = try await create(hint: nil, account: nil)
        XCTAssertNil(none)
        // The api naming another account, another business's ref, or a malformed hint: no push.
        let wrongAccount = try await create(hint: hint, account: UUID())
        XCTAssertEqual(wrongAccount, false)
        let otherBusiness = deriver.subjectRef(businessId: BusinessID(UUID()), consumerId: ConsumerID(h.accountId)).rawValue
        let wrongBusiness = try await create(hint: otherBusiness, account: h.accountId)
        XCTAssertEqual(wrongBusiness, false)
        let malformed = try await create(hint: "someone@example.com", account: h.accountId)
        XCTAssertEqual(malformed, false)
        try await AuthorityAccount.query(on: h.app.db).filter(\.$id == h.accountId).set(\.$frozen, to: true).update()
        let frozen = try await create(hint: hint, account: h.accountId)
        XCTAssertEqual(frozen, false)
    }

    func testLoginHintNeedsARegisteredBusiness() async throws {
        let hint = SubjectRefDeriver(key: h.config.subjectRefKey).subjectRef(businessId: BusinessID(AuthorityHarness.businessId), consumerId: ConsumerID(h.accountId)).rawValue
        let created = try await h.call(.POST, AuthorityRoute.challenges, json: try ViadereJSON.encode(AuthorityChallengeCreateRequest(
            purpose: .oidcLogin, oidc: .init(clientId: AuthorityHarness.clientId, redirectURI: AuthorityHarness.redirectURI,
                                             codeChallenge: AuthorityHarness.challenge(for: AuthorityHarness.codeVerifier), codeChallengeMethod: "S256", nonce: "n",
                                             loginHint: hint, hintAccountId: h.accountId))))
        XCTAssertEqual(try ViadereJSON.decode(AuthorityChallengeCreateResponse.self, from: created.body).hintAccepted, false)
    }

    // MARK: Reviewed import and config

    func testPasskeyImportRules() async throws {
        let db = h.app.db
        let key = P256.Signing.PrivateKey()
        let cose = WebAuthnAuthenticator.coseES256(key.publicKey)
        func change(_ passkeys: JSONValue, keys: JSONValue = .array([])) throws -> Data {
            try CanonicalJSON.serialize(.object(["accounts": .array([.object(["account_id": .string(UUID().uuidString), "keys": keys, "passkeys": passkeys])])]))
        }
        func run(_ data: Data) async throws {
            try await AuthorityAdmin.run(command: "keylog-import", changeFile: data, commit: AuthorityHarness.commit, db: db, config: h.config, now: h.clock.now)
        }
        // A passkey-only account is accepted (staged, then applied by the serving authority).
        let id = Base64URL.encode(SecureToken.randomBytes(16))
        try await run(try change(.array([.object(["credential_id": .string(id), "public_key": .string(Base64URL.encode(cose)), "hardware_bound": .bool(true)])])))
        try await AuthorityAdmin.applyPendingImports(db: db, config: h.config, now: h.clock.now)
        let stored = try await AuthorityPasskey.find(id, on: db)
        XCTAssertEqual(stored?.hardwareBound, true)
        let entry = try await AuthorityKeylogEntry.query(on: db).filter(\.$kid == "passkey:" + id).first()
        XCTAssertEqual(entry?.type, "imported")
        XCTAssertEqual(entry?.keyPurpose, "passkey")
        // A credential already in the log, a duplicate inside one file, a non-ES256 or non-canonical key, unknown members: refused.
        do { try await run(try change(.array([.object(["credential_id": .string(id), "public_key": .string(Base64URL.encode(cose))])]))); XCTFail("in use") } catch {}
        let other = Base64URL.encode(SecureToken.randomBytes(16))
        let twice: JSONValue = .object(["credential_id": .string(other), "public_key": .string(Base64URL.encode(cose))])
        do { try await run(try change(.array([twice, twice]))); XCTFail("duplicate") } catch {}
        var rs256 = [UInt8](cose)
        rs256[4] = 0x39 // alg: not -7
        do { try await run(try change(.array([.object(["credential_id": .string(other), "public_key": .string(Base64URL.encode(Data(rs256)))])]))); XCTFail("alg") } catch {}
        do { try await run(try change(.array([.object(["credential_id": .string(other), "public_key": .string(Base64URL.encode(cose)), "aaguid": .string("x")])]))); XCTFail("member") } catch {}
        do { try await run(try change(.array([]))); XCTFail("empty") } catch {}
        // The imported passkey of an account no device has confirmed produces nothing (like imported keys, ADR-0032 §1.6).
        XCTAssertEqual(stored?.grantCapable, false)
    }

    func testPasskeyConfigurationIsStrict() throws {
        var env = ["ENVIRONMENT": "staging", "AUTHORITY_ENABLED": "true", "AUTHORITY_OIDC_ENABLED": "true", "OIDC_ISSUER": "https://id.staging.example",
                   "AZURE_TENANT_ID": UUID().uuidString, "AUTHORITY_ENTRA_AUDIENCE": "api://viadere-authority-staging",
                   "AUTHORITY_CALLER_OIDS": "api:\(UUID().uuidString)", "AUTHORITY_OUTBOUND_ALLOWLIST": "login.microsoftonline.com",
                   "AZURE_KEY_VAULT_URL": "https://kv.vault.azure.net/", "DATABASE_AUTH": "entra", "DATABASE_HOST": "db", "DATABASE_USER": "u",
                   "OIDC_PAIRWISE_KEY": Base64URL.encode(SecureToken.randomBytes(32)), "ACCOUNT_REF_KEY": Base64URL.encode(SecureToken.randomBytes(32)),
                   "SUBJECT_REF_KEY": Base64URL.encode(SecureToken.randomBytes(32))]
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env), "the RP id is required with OIDC on")
        env["AUTHORITY_WEBAUTHN_RP_ID"] = "other.example"
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env), "the issuer must be inside the RP id")
        env["AUTHORITY_WEBAUTHN_RP_ID"] = "Staging.Example"
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env))
        env["AUTHORITY_WEBAUTHN_RP_ID"] = "staging.example"
        XCTAssertEqual(try AuthorityConfig.fromEnvironment(env).webAuthnRelyingPartyID, "staging.example")
        XCTAssertEqual(OIDCProfile.passkeyOrigins(for: .oidcLogin, issuer: "https://id.staging.example"), ["https://id.staging.example"])
        for purpose in AuthorityPurpose.allCases where purpose != .oidcLogin {
            XCTAssertEqual(OIDCProfile.passkeyOrigins(for: purpose, issuer: "https://id.staging.example"), [], purpose.rawValue)
        }
    }
}
