@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import ViadereServiceSupport
import XCTest
@testable import ViadereAuthorityKit

/// Device and browser helpers shared by the passkey key-log tests.
extension AuthorityHarness {
    /// A UV WebAuthn assertion built byte by byte (so origin, UV and counter can be varied), for `challenge` (base64url nonce).
    func passkeyAssertion(challenge: String, credential: PasskeyCredential? = nil, origin: String = "https://viadere.test", userVerified: Bool = true,
                          counter: UInt32 = 0, rpId: String = "viadere.test") throws -> PasskeyAssertionCredential {
        let credential = credential ?? passkey
        let json = "{\"type\":\"webauthn.get\",\"challenge\":\"\(challenge)\",\"origin\":\"\(origin)\"}"
        var flags: UInt8 = 0x01 | 0x08 | 0x10
        if userVerified { flags |= 0x04 }
        var authData = Data(SHA256.hash(data: Data(rpId.utf8)))
        authData.append(flags)
        authData.append(contentsOf: [UInt8(counter >> 24 & 0xFF), UInt8(counter >> 16 & 0xFF), UInt8(counter >> 8 & 0xFF), UInt8(counter & 0xFF)])
        let key = try P256.Signing.PrivateKey(rawRepresentation: credential.privateKey)
        let signature = try key.signature(for: authData + Data(SHA256.hash(data: Data(json.utf8))))
        let id = Base64URL.encode(credential.credentialId)
        return PasskeyAssertionCredential(id: id, rawId: id, authenticatorData: Base64URL.encode(authData), clientDataJSON: Base64URL.encode(Data(json.utf8)),
                                          signature: Base64URL.encode(signature.derRepresentation), userHandle: Base64URL.encode(credential.userHandle))
    }

    static func newPasskey() -> PasskeyCredential {
        try! WebAuthnAuthenticator.makeCredential(rpId: "viadere.test", userHandle: Data(SecureToken.randomBytes(8)), userName: "account",
                                                  clientDataHash: Data(repeating: 1, count: 32), requireUserVerification: true, userVerified: true, backedUp: true,
                                                  now: Date(timeIntervalSince1970: 1_800_000_000)).credential
    }

    func passkeyCancelChallenge(_ accountId: UUID) async throws -> (status: HTTPStatus, body: [String: JSONValue]) {
        try await post(AuthorityKeyLogRoute.passkeyCancelChallenges, ["account_id": .string(accountId.uuidString)])
    }

    func passkeyCancel(_ ach: String, _ credential: PasskeyAssertionCredential, path: String = AuthorityKeyLogRoute.passkeyCancel) async throws -> HTTPStatus {
        try await call(.POST, path, json: try ViadereJSON.encode(AuthorityPasskeyEvidenceRequest(challengeId: ach, credential: credential))).status
    }

    func deniedReasons(_ event: String) async throws -> Set<String> {
        Set(try await AuthorityAuditEvent.query(on: app.db).filter(\.$event == event).filter(\.$outcome == "denied").all().compactMap(\.reason))
    }

    var harnessAccountRef: String { OIDCProfile.accountRef(key: config.accountRefKey, accountId: accountId) }

    /// A code set and a sealed start with new keys: the account then has one pending recovery (ADR-0032 §3.2).
    @discardableResult
    func startPendingRecovery() async throws -> SoftwareP256SigningKey {
        let setId = RecoverySeal.generateSetId()
        let created = try await keylogChallenge(["purpose": .string("recovery_codes_set"), "account_id": .string(accountId.uuidString), "set_id": .string(setId)])
        let statement = try XCTUnwrap(created.statement)
        let codes = RecoverySeal.generateCodes()
        let set = try RecoverySeal.seal(RecoverySeal.setPlaintext(accountRef: harnessAccountRef, setId: setId, nonce: statement.nonce, codes: codes), to: sealPublicKey,
                                        purpose: .codesSet, environment: .staging, challengeId: statement.challengeId, nonce: statement.nonce)
        let factor = try await factor(statement, key: biometricKey) { $0.envelopeDigest = set.digest }
        let registered = try await post(AuthorityKeyLogRoute.evidence, ["factor": .string(factor), "envelope": set.json])
        XCTAssertEqual(registered.status, .ok, "\(registered.body)")
        let recoveryId = RecoveryCodeFormat.normalizeRecoveryID("ABCD-EFGH-JKMN")!
        let startChallenge = try await keylogChallenge(["purpose": .string("recovery_started"), "account_id": .string(accountId.uuidString), "recovery_id": .string(recoveryId)])
        let start = try XCTUnwrap(startChallenge.statement, "\(startChallenge.body)")
        let newKey = SoftwareP256SigningKey()
        let envelope = try RecoverySeal.seal(RecoverySeal.startPlaintext(recoveryId: recoveryId, nonce: start.nonce, code: codes[0], newKids: [Self.kid(newKey)]),
                                             to: sealPublicKey, purpose: .start, environment: .staging, challengeId: start.challengeId, nonce: start.nonce)
        let keys = try await submitted([(newKey, .approvalBiometric)], type: "recovery_started", nonce: start.nonce, extra: [envelope.digest])
        let started = try await post(AuthorityKeyLogRoute.recoveryStart, ["ach": .string(start.challengeId), "envelope": envelope.json, "keys": keys])
        XCTAssertEqual(started.status, .ok, "\(started.body)")
        return newKey
    }

    func pendingRecoveries() async throws -> Int {
        try await AuthorityRecovery.query(on: app.db).filter(\.$accountRef == harnessAccountRef).filter(\.$state == "pending").count()
    }

    func entries(_ type: String) async throws -> [AuthorityKeylogEntry] {
        try await AuthorityKeylogEntry.query(on: app.db).filter(\.$accountRef == harnessAccountRef).filter(\.$type == type).all()
    }
}

/// The passkey `recovery_cancel` (ADR-0023 §3a item 1, §4): reduce-only, a UV assertion by a logged passkey of the same account, recorded in the key log.
final class AuthorityPasskeyRecoveryCancelTests: XCTestCase {
    var h: AuthorityHarness!
    var recoveringKey: SoftwareP256SigningKey!

    override func setUp() async throws {
        h = try await AuthorityHarness.make()
        try await h.installSealKey()
        recoveringKey = try await h.startPendingRecovery()
    }
    override func tearDown() async throws { try await h.shutdown() }

    func cancelChallenge() async throws -> (ach: String, nonce: String) {
        let created = try await h.passkeyCancelChallenge(h.accountId)
        XCTAssertEqual(created.status, .ok, "\(created.body)")
        return (try XCTUnwrap(created.body["ach"]?.stringValue), try XCTUnwrap(created.body["challenge"]?.stringValue))
    }

    func testALoggedPasskeyOfTheAccountCancelsThePendingRecoveryAndTheLogRecordsIt() async throws {
        let challenge = try await cancelChallenge()
        let created = try await h.passkeyCancelChallenge(h.accountId)
        XCTAssertEqual(created.body["rp_id"]?.stringValue, "viadere.test")
        XCTAssertEqual(created.body["display"]?.objectValue?["purpose"]?.stringValue, "recovery_cancel")
        // The challenge is a passkey challenge (kept apart from every factor-JWS challenge, ST-REC-17), bound to the account and its recovery.
        let row = try await XCTUnwrapAsync(try await AuthorityPasskeyChallenge.find(challenge.ach, on: h.app.db))
        XCTAssertEqual(row.purpose, "recovery_cancel")
        XCTAssertEqual(row.accountRef, h.harnessAccountRef)
        await XCTAssertNilAsync(try await AuthorityChallenge.find(challenge.ach, on: h.app.db))

        let status = try await h.passkeyCancel(challenge.ach, try h.passkeyAssertion(challenge: challenge.nonce))
        XCTAssertEqual(status, .ok)
        await XCTAssertEqualAsync(try await h.pendingRecoveries(), 0)
        let cancels = try await h.entries("recovery_cancel")
        let entry = try XCTUnwrap(cancels.first)
        XCTAssertEqual(cancels.count, 1)
        XCTAssertEqual(entry.keyPurpose, "passkey")
        XCTAssertEqual(entry.kid, AuthorityKeyLogFormat.passkeyKid(cose: try h.passkey.cosePublicKey()))
        XCTAssertTrue(entry.detail.contains("\"method\":\"passkey\""))
        await XCTAssertNilAsync(try await AuthorityKeyLog.verifyChain(h.app.db, accountRef: h.harnessAccountRef))
        // The authority enforces it: no activation after the hold.
        h.clock.advance(73 * 3600)
        await XCTAssertEqualAsync(try await AuthorityRecoveryService(ctx: h.app.authority, db: h.app.db).activateDue(), 0)
        await XCTAssertEqualAsync(try await AuthorityKey.find(AuthorityHarness.kid(h.biometricKey), on: h.app.db)?.revokedAt == nil, true)
        // Nothing is pending any more: no cancel challenge.
        await XCTAssertEqualAsync(try await h.passkeyCancelChallenge(h.accountId).status, .unprocessableEntity)
    }

    /// Replay: one assertion cancels once; a cancel assertion is not an `oidc_login` answer and an `oidc_login` challenge is not a cancel challenge.
    func testAReplayedOrCrossPurposeAssertionIsRefused() async throws {
        let challenge = try await cancelChallenge()
        let assertion = try h.passkeyAssertion(challenge: challenge.nonce, counter: 0)
        // The cancel assertion relayed to the OIDC passkey route: not an `oidc_login` challenge.
        await XCTAssertEqualAsync(try await h.passkeyCancel(challenge.ach, assertion, path: AuthorityRoute.oidcPasskeyEvidence), .unauthorized)
        await XCTAssertEqualAsync(try await AuthorityPasskeyChallenge.find(challenge.ach, on: h.app.db)?.state, "pending")
        // An `oidc_login` passkey challenge answered at the cancel route: refused, untouched.
        let oidc = try await h.call(.POST, AuthorityRoute.oidcPasskeyChallenges, json: try ViadereJSON.encode(AuthorityPasskeyChallengeRequest(oidc: .init(
            clientId: AuthorityHarness.clientId, redirectURI: AuthorityHarness.redirectURI, codeChallenge: AuthorityHarness.challenge(for: AuthorityHarness.codeVerifier),
            codeChallengeMethod: "S256", nonce: "n-0S6_WzA2Mj", acrValues: nil))))
        let login = try ViadereJSON.decode(AuthorityPasskeyChallengeResponse.self, from: oidc.body)
        await XCTAssertEqualAsync(try await h.passkeyCancel(login.challengeId, try h.passkeyAssertion(challenge: login.challenge, origin: AuthorityHarness.issuer)),
                                  .unauthorized)
        await XCTAssertEqualAsync(try await AuthorityPasskeyChallenge.find(login.challengeId, on: h.app.db)?.state, "pending")
        // The genuine cancel, then the same assertion again.
        await XCTAssertEqualAsync(try await h.passkeyCancel(challenge.ach, assertion), .ok)
        await XCTAssertEqualAsync(try await h.passkeyCancel(challenge.ach, assertion), .unauthorized)
        // And the assertion against a fresh challenge (a new recovery): the nonce differs, the signature does not cover it.
        try await h.startPendingRecovery()
        let next = try await cancelChallenge()
        await XCTAssertEqualAsync(try await h.passkeyCancel(next.ach, assertion), .unauthorized)
        await XCTAssertEqualAsync(try await h.pendingRecoveries(), 1)
        await XCTAssertEqualAsync(try await h.entries("recovery_cancel").count, 1)
        let reasons = try await h.deniedReasons("authority.passkey_cancel")
        XCTAssertTrue(reasons.isSuperset(of: ["unknown_challenge", "challenge_not_pending", "assertion_invalid"]), "\(reasons)")
    }

    /// Wrong account: a passkey logged for another account cannot cancel this account's recovery (and the challenge stays usable).
    func testAPasskeyOfAnotherAccountCannotCancel() async throws {
        let other = AuthorityHarness.newPasskey()
        let row = AuthorityPasskey()
        row.id = Base64URL.encode(other.credentialId)
        row.accountRef = "acct_" + String(repeating: "b", count: 32)
        row.publicKey = Base64URL.encode(try other.cosePublicKey())
        row.signCount = 0
        row.hardwareBound = false
        row.grantCapable = true
        row.createdAt = h.clock.now
        try await row.create(on: h.app.db)
        let challenge = try await cancelChallenge()
        await XCTAssertEqualAsync(try await h.passkeyCancel(challenge.ach, try h.passkeyAssertion(challenge: challenge.nonce, credential: other)), .unauthorized)
        await XCTAssertEqualAsync(try await h.pendingRecoveries(), 1)
        await XCTAssertEqualAsync(try await AuthorityPasskeyChallenge.find(challenge.ach, on: h.app.db)?.state, "pending")
        let reasons = try await h.deniedReasons("authority.passkey_cancel")
        XCTAssertTrue(reasons.contains("account_binding_mismatch"), "\(reasons)")
        // A revoked passkey of the account itself cannot cancel either.
        try await AuthorityPasskey.query(on: h.app.db).filter(\.$id == Base64URL.encode(h.passkey.credentialId)).set(\.$revokedAt, to: h.clock.now).update()
        await XCTAssertEqualAsync(try await h.passkeyCancel(challenge.ach, try h.passkeyAssertion(challenge: challenge.nonce)), .unauthorized)
        await XCTAssertEqualAsync(try await h.pendingRecoveries(), 1)
    }

    /// Cancel after completion: a recovery that activated after the challenge was created is never reported as cancelled, and nothing is logged.
    func testACancelAfterTheRecoveryActivatedIsRefusedAndNotLogged() async throws {
        let challenge = try await cancelChallenge()
        // The device-key path too: its challenge was created while the recovery was pending.
        let created = try await h.keylogChallenge(["purpose": .string("recovery_cancel"), "account_id": .string(h.accountId.uuidString)])
        let factorChallenge = try XCTUnwrap(created.statement)
        // The hold ends now (the challenges stay inside their lifetime): activation adds the recovering key and revokes the earlier ones.
        try await AuthorityRecovery.query(on: h.app.db).set(\.$activatesAt, to: h.clock.now).update()
        await XCTAssertEqualAsync(try await AuthorityRecoveryService(ctx: h.app.authority, db: h.app.db).activateDue(), 1)
        await XCTAssertEqualAsync(try await h.passkeyCancel(challenge.ach, try h.passkeyAssertion(challenge: challenge.nonce)), .unauthorized)
        let reasons = try await h.deniedReasons("authority.passkey_cancel")
        XCTAssertTrue(reasons.contains("recovery_not_pending"), "\(reasons)")
        // The recovered key is a logged active key of the account, so it reaches the state check (before this change it was answered `approve`).
        let factor = try await h.factor(factorChallenge, key: recoveringKey)
        await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.evidence, ["factor": .string(factor)]).status, .unauthorized)
        let keylogReasons = try await h.deniedReasons("authority.keylog_evidence")
        XCTAssertTrue(keylogReasons.contains("recovery_not_pending"), "\(keylogReasons)")
        await XCTAssertEqualAsync(try await h.entries("recovery_cancel").count, 0)
        await XCTAssertEqualAsync(try await AuthorityRecovery.query(on: h.app.db).filter(\.$state == "activated").count(), 1)
    }

    /// ADR-0023 §3a item 2: `recovery_cancel` accepts the issuer origin and `https://<RP_ID>` only; user verification is required.
    func testOriginsAndUserVerification() async throws {
        let challenge = try await cancelChallenge()
        for refused in [try h.passkeyAssertion(challenge: challenge.nonce, origin: "https://evil.example"),
                        try h.passkeyAssertion(challenge: challenge.nonce, origin: "https://viadere.test:8443"),
                        try h.passkeyAssertion(challenge: challenge.nonce, userVerified: false),
                        try h.passkeyAssertion(challenge: challenge.nonce, rpId: "evil.example")] {
            await XCTAssertEqualAsync(try await h.passkeyCancel(challenge.ach, refused), .unauthorized)
        }
        await XCTAssertEqualAsync(try await h.pendingRecoveries(), 1)
        await XCTAssertEqualAsync(try await h.passkeyCancel(challenge.ach, try h.passkeyAssertion(challenge: challenge.nonce, origin: AuthorityHarness.issuer)), .ok)
        XCTAssertEqual(OIDCProfile.passkeyOrigins(for: .recoveryCancel, issuer: "https://id.example.com", relyingPartyID: "example.com"),
                       ["https://id.example.com", "https://example.com"])
        for purpose in AuthorityPurpose.allCases where ![.oidcLogin, .recoveryCancel].contains(purpose) {
            XCTAssertEqual(OIDCProfile.passkeyOrigins(for: purpose, issuer: "https://id.example.com", relyingPartyID: "example.com"), [], purpose.rawValue)
        }
    }

    /// Reduce-only: a cancel never waits for the seal key (activation does not need it either).
    func testACancelDoesNotNeedTheSealKey() async throws {
        try await h.reloadSeal(pins: [])
        XCTAssertNil(h.app.authority.seal)
        let factorChallenge = try await h.keylogChallenge(["purpose": .string("recovery_cancel"), "account_id": .string(h.accountId.uuidString)])
        XCTAssertEqual(factorChallenge.status, .ok, "\(factorChallenge.body)")
        XCTAssertNotNil(factorChallenge.statement)
        let challenge = try await cancelChallenge()
        await XCTAssertEqualAsync(try await h.passkeyCancel(challenge.ach, try h.passkeyAssertion(challenge: challenge.nonce)), .ok)
        await XCTAssertEqualAsync(try await h.pendingRecoveries(), 0)
    }
}

/// `passkey_added` (ADR-0023 §4): a factor JWS by a grant-capable biometric key of the device that created the passkey, over the authority's display
/// of exactly that credential; never a WebAuthn assertion; strict formats.
final class AuthorityPasskeyAddedTests: XCTestCase {
    var h: AuthorityHarness!

    override func setUp() async throws { h = try await AuthorityHarness.make() }
    override func tearDown() async throws { try await h.shutdown() }

    func request(_ credential: PasskeyCredential, credentialId: String? = nil, publicKey: String? = nil) throws -> [String: JSONValue] {
        ["purpose": .string("keylog_passkey_added"), "account_id": .string(h.accountId.uuidString),
         "credential_id": .string(credentialId ?? Base64URL.encode(credential.credentialId)),
         "public_key": .string(try publicKey ?? Base64URL.encode(credential.cosePublicKey()))]
    }

    func testTheCreatingDeviceAddsItsPasskeyWhichThenSignsIn() async throws {
        let passkey = AuthorityHarness.newPasskey()
        let created = try await h.keylogChallenge(try request(passkey))
        let statement = try XCTUnwrap(created.statement, "\(created.body)")
        // What the app checks before signing: exactly the credential it just created, and the fixed label.
        let kid = try XCTUnwrap(AuthorityKeyLogFormat.passkeyKid(cose: try passkey.cosePublicKey()))
        XCTAssertEqual(statement.kids, [kid])
        XCTAssertEqual(statement.accountRef, h.harnessAccountRef)
        XCTAssertEqual(statement.display, AuthorityDisplay.passkeyAdded(kid: kid))
        XCTAssertEqual(statement.display.objectValue?["label"]?.stringValue, "New passkey on this phone")
        let factor = try await h.factor(statement, key: h.biometricKey)
        let result = try await h.post(AuthorityKeyLogRoute.evidence, ["factor": .string(factor)])
        XCTAssertEqual(result.status, .ok, "\(result.body)")
        let row = try await XCTUnwrapAsync(try await AuthorityPasskey.find(Base64URL.encode(passkey.credentialId), on: h.app.db))
        XCTAssertEqual(row.accountRef, h.harnessAccountRef)
        XCTAssertTrue(row.grantCapable)
        XCTAssertFalse(row.hardwareBound)
        let added = try await h.entries("passkey_added")
        let entry = try XCTUnwrap(added.first)
        XCTAssertEqual(entry.kid, kid)
        XCTAssertEqual(entry.keyPurpose, "passkey")
        XCTAssertTrue(entry.detail.contains(AuthorityHarness.kid(h.biometricKey)))
        await XCTAssertNilAsync(try await AuthorityKeyLog.verifyChain(h.app.db, accountRef: h.harnessAccountRef))
        // The added passkey answers an `oidc_login` passkey challenge.
        let oidc = try await h.call(.POST, AuthorityRoute.oidcPasskeyChallenges, json: try ViadereJSON.encode(AuthorityPasskeyChallengeRequest(oidc: .init(
            clientId: AuthorityHarness.clientId, redirectURI: AuthorityHarness.redirectURI, codeChallenge: AuthorityHarness.challenge(for: AuthorityHarness.codeVerifier),
            codeChallengeMethod: "S256", nonce: "n-0S6_WzA2Mj", acrValues: nil))))
        let login = try ViadereJSON.decode(AuthorityPasskeyChallengeResponse.self, from: oidc.body)
        let answer = try await h.call(.POST, AuthorityRoute.oidcPasskeyEvidence, json: try ViadereJSON.encode(AuthorityPasskeyEvidenceRequest(
            challengeId: login.challengeId, credential: try h.passkeyAssertion(challenge: login.challenge, credential: passkey, origin: AuthorityHarness.issuer))))
        XCTAssertEqual(answer.status, .ok)
        // The same credential cannot be added twice (one account per credential).
        let again = try await h.keylogChallenge(try request(passkey))
        XCTAssertEqual(again.status, .conflict)
    }

    /// Strict base64url (SECURITY.md §2.1) and canonical ES256 COSE: anything else is refused before a challenge exists.
    func testNonStrictEncodingsAndNonCanonicalKeysAreRefused() async throws {
        let passkey = AuthorityHarness.newPasskey()
        let id = Base64URL.encode(passkey.credentialId)
        let cose = try passkey.cosePublicKey()
        let key = Base64URL.encode(cose)
        var flipped = cose
        flipped[4] = 0x27 // alg -8 (EdDSA)
        // Non-canonical trailing bits: the last character of a 32-byte id carries 2 spare bits that must be zero.
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        let spare = String(id.dropLast()) + String(alphabet[alphabet.firstIndex(of: id.last!)! ^ 1])
        let refused: [(String?, String?)] = [
            (id + "=", nil), (passkey.credentialId.base64EncodedString(), nil), (String(id.dropLast()) + "~", nil), (spare, nil),
            (Base64URL.encode(Data(repeating: 1, count: 15)), nil), (nil, key + "="), (nil, cose.base64EncodedString() + "/"),
            (nil, Base64URL.encode(flipped)), (nil, Base64URL.encode(cose.prefix(76))),
        ]
        for (badId, badKey) in refused {
            let created = try await h.keylogChallenge(try request(passkey, credentialId: badId, publicKey: badKey))
            XCTAssertEqual(created.status, .unprocessableEntity, "\(badId ?? "") \(badKey ?? "")")
        }
        XCTAssertNil(AuthorityKeyLogFormat.strictBytes("QQ=="))
        XCTAssertNil(AuthorityKeyLogFormat.strictBytes("QR"))
        XCTAssertEqual(AuthorityKeyLogFormat.strictBytes("QQ"), Data([0x41]))
        await XCTAssertEqualAsync(try await AuthorityChallenge.query(on: h.app.db).filter(\.$purpose == "keylog_passkey_added").count(), 0)
    }

    /// Only a grant-capable `approvalBiometric` key with `uv = biometric`, and never a WebAuthn assertion (ST-REC-17), adds a passkey.
    func testOnlyTheBiometricDeviceKeyAddsAndNoAssertionCan() async throws {
        let passkey = AuthorityHarness.newPasskey()
        let first = try await h.keylogChallenge(try request(passkey))
        let statement = try XCTUnwrap(first.statement)
        let presence = try await h.factor(statement, key: h.presenceKey, uv: .userPresence)
        await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.evidence, ["factor": .string(presence)]).status, .unauthorized)
        // The account's own passkey over the challenge's nonce, at both passkey routes: no passkey challenge has that id.
        let assertion = try h.passkeyAssertion(challenge: statement.nonce)
        await XCTAssertEqualAsync(try await h.passkeyCancel(statement.challengeId, assertion), .unauthorized)
        await XCTAssertEqualAsync(try await h.passkeyCancel(statement.challengeId, assertion, path: AuthorityRoute.oidcPasskeyEvidence), .unauthorized)
        await XCTAssertNilAsync(try await AuthorityPasskey.find(Base64URL.encode(passkey.credentialId), on: h.app.db))
        // A display for another credential (a substituted one) is a display mismatch for the device's signature.
        let second = try await h.keylogChallenge(try request(AuthorityHarness.newPasskey()))
        let other = try XCTUnwrap(second.statement)
        let crossed = try await h.factor(other, key: h.biometricKey) { $0.displayDigest = try! AuthorityDisplay.digest(statement.display) }
        await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.evidence, ["factor": .string(crossed)]).status, .unauthorized)
        // The genuine approval still works.
        let genuine = try await h.factor(statement, key: h.biometricKey)
        await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.evidence, ["factor": .string(genuine)]).status, .ok)
    }

    func testTheImportedCredentialAndKeysInUseAreRefused() async throws {
        let created = try await h.keylogChallenge(try request(h.passkey))
        XCTAssertEqual(created.status, .conflict)
        let reasons = try await h.deniedReasons("authority.passkey_added")
        XCTAssertTrue(reasons.contains("key_in_use"))
    }
}
