import Fluent
import Foundation
import ViadereCore
import XCTest
@testable import ViadereServerKit

final class AuthTests: XCTestCase {
    func testPasskeyRegisterThenLoginIssuesSessionsAndRotatesRefresh() async throws {
        try await withHarness { h in
            let consumer = try await h.registerConsumer()
            XCTAssertNotNil(consumer.session.refreshToken)
            XCTAssertEqual(consumer.session.tokenType, "Bearer")
            // Registration options are bound to the relying party.
            let begin = try await h.post(APIRoutes.registerBegin.template, PasskeyRegistrationBeginRequest(displayName: "Ana"))
            let options = try begin.json(PasskeyRegistrationOptions.self)
            XCTAssertEqual(options.relyingPartyId, "viadere.com")
            XCTAssertEqual(options.userVerification, "required")
            XCTAssertGreaterThanOrEqual(Base64URL.decode(options.challenge)?.count ?? 0, 32)

            // Login with the credential that registration stored.
            let credential = try await PasskeyCredentialRecord.query(on: h.db).first()!
            let loginBegin = try await h.post(APIRoutes.loginBegin.template, PasskeyLoginBeginRequest())
            let loginOptions = try loginBegin.json(PasskeyAssertionOptions.self)
            let assertion = PasskeyAssertionCredential(id: credential.credentialId, rawId: credential.credentialId, authenticatorData: "AA",
                                                       clientDataJSON: loginOptions.challenge, signature: "valid", userHandle: nil)
            let login = try await h.post(APIRoutes.loginFinish.template, PasskeyLoginFinishRequest(ceremonyId: loginOptions.ceremonyId, credential: assertion))
            XCTAssertEqual(login.status, .ok, login.text)
            XCTAssertEqual(try login.json(AuthSession.self).consumerId, consumer.id)
            // The same ceremony cannot be used twice.
            let replay = try await h.post(APIRoutes.loginFinish.template, PasskeyLoginFinishRequest(ceremonyId: loginOptions.ceremonyId, credential: assertion))
            XCTAssertEqual(replay.status, .unauthorized)
        }
    }

    func testRegistrationWithWrongChallengeOrExpiredCeremonyFails() async throws {
        try await withHarness { h in
            let begin = try await h.post(APIRoutes.registerBegin.template, PasskeyRegistrationBeginRequest(displayName: "Ana"))
            let options = try begin.json(PasskeyRegistrationOptions.self)
            let bad = PasskeyRegistrationCredential(id: "cred1", rawId: "cred1", attestationObject: SecureToken.generate(byteCount: 32),
                                                    clientDataJSON: SecureToken.generate(byteCount: 32))
            let wrong = try await h.post(APIRoutes.registerFinish.template, PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: bad))
            XCTAssertEqual(wrong.status, .unauthorized)
            // Failed ceremonies are burned: even the right answer afterwards is refused.
            let good = PasskeyRegistrationCredential(id: "cred2", rawId: "cred2", attestationObject: SecureToken.generate(byteCount: 32),
                                                     clientDataJSON: options.challenge)
            let retry = try await h.post(APIRoutes.registerFinish.template, PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: good))
            XCTAssertEqual(retry.status, .unauthorized)
            // Expiry.
            let second = try await h.post(APIRoutes.registerBegin.template, PasskeyRegistrationBeginRequest(displayName: "Ana"))
            let secondOptions = try second.json(PasskeyRegistrationOptions.self)
            h.clock.advance(by: 6 * 60)
            let late = PasskeyRegistrationCredential(id: "cred3", rawId: "cred3", attestationObject: SecureToken.generate(byteCount: 32),
                                                     clientDataJSON: secondOptions.challenge)
            let expired = try await h.post(APIRoutes.registerFinish.template, PasskeyRegistrationFinishRequest(ceremonyId: secondOptions.ceremonyId, credential: late))
            XCTAssertEqual(expired.status, .unauthorized)
            let consumers = try await ConsumerRecord.query(on: h.db).count()
            XCTAssertEqual(consumers, 0)
        }
    }

    func testRealWebAuthnVerifierRejectsMalformedCredentials() async throws {
        let verifier = WebAuthnPasskeyVerifier(config: .testing())
        let challenge = verifier.makeChallenge()
        XCTAssertEqual(challenge.count, 32)
        let garbage = PasskeyRegistrationCredential(id: "AAAA", rawId: "AAAA", attestationObject: "AAAA", clientDataJSON: "AAAA")
        do {
            _ = try await verifier.verifyRegistration(garbage, challenge: challenge) { _ in false }
            XCTFail("garbage attestation must not verify")
        } catch { XCTAssertTrue(error is PasskeyError) }
        let assertion = PasskeyAssertionCredential(id: "AAAA", rawId: "AAAA", authenticatorData: "AAAA", clientDataJSON: "AAAA", signature: "AAAA", userHandle: nil)
        XCTAssertThrowsError(try verifier.verifyAssertion(assertion, challenge: challenge, publicKey: Data([1, 2, 3]), signCount: 0))
    }

    func testAccessTokensExpireAndLogoutRevokes() async throws {
        try await withHarness { h in
            var consumer = try await h.registerConsumer()
            consumer = try await h.enrollDevice(consumer)
            let ok = try await h.signed(consumer, .GET, "/v1/devices")
            XCTAssertEqual(ok.status, .ok, ok.text)
            // Plain bearer-only routes work too, until the token expires (15 minutes).
            h.clock.advance(by: 16 * 60)
            let expired = try await h.request(.POST, "/v1/devices/enroll/begin", headers: ["Authorization": "Bearer \(consumer.token)"])
            XCTAssertEqual(expired.status, .unauthorized)

            let fresh = try await h.readyConsumer()
            // Logout is device-signed: a bearer token alone cannot end the session.
            let bearerOnly = try await h.request(.POST, "/v1/auth/logout", headers: ["Authorization": "Bearer \(fresh.token)"])
            XCTAssertEqual(bearerOnly.status, .unauthorized)
            let logout = try await h.signed(fresh, .POST, "/v1/auth/logout")
            XCTAssertEqual(logout.status, .ok)
            let after = try await h.request(.POST, "/v1/devices/enroll/begin", headers: ["Authorization": "Bearer \(fresh.token)"])
            XCTAssertEqual(after.status, .unauthorized)
            // Logout also kills the refresh token family.
            let refresh = try await h.post("/v1/auth/refresh", AuthRefreshRequest(refreshToken: fresh.session.refreshToken!))
            XCTAssertEqual(refresh.status, .unauthorized)
        }
    }

    func testRefreshRotationAndReuseDetectionRevokesTheFamily() async throws {
        try await withHarness { h in
            let consumer = try await h.registerConsumer()
            let first = consumer.session.refreshToken!
            let rotated = try await h.post("/v1/auth/refresh", AuthRefreshRequest(refreshToken: first))
            XCTAssertEqual(rotated.status, .ok, rotated.text)
            let second = try rotated.json(AuthSession.self)
            XCTAssertNotEqual(second.refreshToken, first)
            XCTAssertNotEqual(second.accessToken, consumer.token)
            // The previous access token stops working once rotated.
            let oldAccess = try await h.request(.POST, "/v1/devices/enroll/begin", headers: ["Authorization": "Bearer \(consumer.token)"])
            XCTAssertEqual(oldAccess.status, .unauthorized)
            let newAccess = try await h.request(.POST, "/v1/devices/enroll/begin", headers: ["Authorization": "Bearer \(second.accessToken)"])
            XCTAssertEqual(newAccess.status, .ok)
            // Presenting the already-used refresh token is theft (after the 60 s grace window): the whole family is revoked, including the newest pair.
            h.clock.advance(by: 61)
            let reuse = try await h.post("/v1/auth/refresh", AuthRefreshRequest(refreshToken: first))
            XCTAssertEqual(reuse.status, .unauthorized)
            let afterReuse = try await h.request(.POST, "/v1/devices/enroll/begin", headers: ["Authorization": "Bearer \(second.accessToken)"])
            XCTAssertEqual(afterReuse.status, .unauthorized)
            let newest = try await h.post("/v1/auth/refresh", AuthRefreshRequest(refreshToken: second.refreshToken!))
            XCTAssertEqual(newest.status, .unauthorized)
            let events = try await AuditEventRecord.query(on: h.db).filter(\.$action == "auth.refresh_reuse_detected").count()
            XCTAssertEqual(events, 1)
        }
    }

    func testTokensAreStoredHashedOnly() async throws {
        try await withHarness { h in
            let consumer = try await h.registerConsumer()
            let stored = try await AccessTokenRecord.query(on: h.db).all().map(\.tokenHash) + RefreshTokenRecord.query(on: h.db).all().map(\.tokenHash)
            XCTAssertFalse(stored.contains(consumer.token))
            XCTAssertFalse(stored.contains(consumer.session.refreshToken!))
            XCTAssertTrue(stored.contains(SecureToken.hash(consumer.token)))
        }
    }
}
