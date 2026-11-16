@preconcurrency import Crypto
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Staging lives on subdomains of the production domain (owner decision 2026-11-16; SECURITY.md §2.116): `staging.viadere.io` (web, links,
/// passkey RP) and `api-staging.viadere.io`. A page on staging may ask a browser for an assertion with the RP ID `viadere.io` (a registrable
/// suffix of its own host), so production must refuse every ceremony whose client data names another origin, and staging and production
/// passkeys, cookies and names must never be interchangeable.
final class StagingSubdomainTests: XCTestCase {
    static let stagingOrigin = "https://staging.viadere.io"

    private func clientData(type: String, challenge: Data, origin: String) -> (json: String, hash: Data) {
        let json = "{\"type\":\"\(type)\",\"challenge\":\"\(Base64URL.encode(challenge))\",\"origin\":\"\(origin)\",\"crossOrigin\":false}"
        return (Base64URL.encode(Data(json.utf8)), Data(SHA256.hash(data: Data(json.utf8))))
    }

    private var stagingConfig: ServerConfig {
        var config = ServerConfig.testing()
        config.relyingPartyID = "staging.viadere.io"
        config.relyingPartyOrigin = Self.stagingOrigin
        config.publicBaseURL = "https://api-staging.viadere.io"
        config.linkDomain = LinkDomain("staging.viadere.io")!
        return config
    }

    /// Registers a passkey for `rpId` through `verifier` with client data from `origin`, the way a browser on that origin would.
    private func register(rpId: String, origin: String, verifier: WebAuthnPasskeyVerifier) async throws
        -> (credential: PasskeyCredential, id: String, publicKey: Data) {
        let challenge = verifier.makeChallenge()
        let create = clientData(type: "webauthn.create", challenge: challenge, origin: origin)
        let created = try WebAuthnAuthenticator.makeCredential(rpId: rpId, userHandle: Data([1, 2, 3, 4]), userName: "alice", clientDataHash: create.hash,
                                                               requireUserVerification: true, userVerified: true, backedUp: true, attestation: .none,
                                                               now: Date(timeIntervalSince1970: 1_800_000_000))
        let id = Base64URL.encode(created.credential.credentialId)
        let verified = try await verifier.verifyRegistration(
            PasskeyRegistrationCredential(id: id, rawId: id, attestationObject: Base64URL.encode(created.attestationObject), clientDataJSON: create.json),
            challenge: challenge, credentialAlreadyRegistered: { _ in false })
        return (created.credential, id, verified.publicKey)
    }

    private func assertion(_ credential: PasskeyCredential, id: String, rpId: String, origin: String, challenge: Data) throws
        -> PasskeyAssertionCredential {
        let get = clientData(type: "webauthn.get", challenge: challenge, origin: origin)
        let signed = try WebAuthnAuthenticator.getAssertion(credential: credential, rpId: rpId, clientDataHash: get.hash, requireUserVerification: true,
                                                           userVerified: true, backedUp: true)
        return PasskeyAssertionCredential(id: id, rawId: id, authenticatorData: Base64URL.encode(signed.authenticatorData), clientDataJSON: get.json,
                                          signature: Base64URL.encode(signed.signature), userHandle: Base64URL.encode(signed.userHandle))
    }

    /// The exploit path: a page on staging.viadere.io asks for an assertion with RP ID `viadere.io`, which the browser allows. The
    /// authenticator signs with the production passkey, but the client data names the staging origin, so production refuses it.
    func testAProductionPasskeyAssertionMadeOnAStagingPageDoesNotVerifyInProduction() async throws {
        let production = ServerConfig.testing()
        XCTAssertEqual(production.relyingPartyID, "viadere.io")
        XCTAssertEqual(production.relyingPartyOrigin, "https://viadere.io")
        let verifier = WebAuthnPasskeyVerifier(config: production)
        let passkey = try await register(rpId: "viadere.io", origin: production.relyingPartyOrigin, verifier: verifier)

        let challenge = verifier.makeChallenge()
        let genuine = try assertion(passkey.credential, id: passkey.id, rpId: "viadere.io", origin: production.relyingPartyOrigin, challenge: challenge)
        XCTAssertNoThrow(try verifier.verifyAssertion(genuine, challenge: challenge, publicKey: passkey.publicKey, signCount: 0), "the control case verifies")

        for origin in [Self.stagingOrigin, "https://api-staging.viadere.io", "https://www.viadere.io", "https://evil.staging.viadere.io", "http://viadere.io"] {
            let relayed = try assertion(passkey.credential, id: passkey.id, rpId: "viadere.io", origin: origin, challenge: challenge)
            XCTAssertThrowsError(try verifier.verifyAssertion(relayed, challenge: challenge, publicKey: passkey.publicKey, signCount: 0), origin)
        }
        // A registration ceremony run on a staging page for RP ID viadere.io is refused the same way.
        let challenge2 = verifier.makeChallenge()
        let create = clientData(type: "webauthn.create", challenge: challenge2, origin: Self.stagingOrigin)
        let made = try WebAuthnAuthenticator.makeCredential(rpId: "viadere.io", userHandle: Data([5]), userName: "mallory", clientDataHash: create.hash,
                                                            requireUserVerification: true, userVerified: true, backedUp: true, now: Date())
        let madeId = Base64URL.encode(made.credential.credentialId)
        do {
            _ = try await verifier.verifyRegistration(PasskeyRegistrationCredential(id: madeId, rawId: madeId, attestationObject: Base64URL.encode(made.attestationObject),
                                                                                    clientDataJSON: create.json),
                                                      challenge: challenge2, credentialAlreadyRegistered: { _ in false })
            XCTFail("a registration made on the staging origin must not verify in production")
        } catch {}
    }

    /// Staging passkeys are bound to RP ID `staging.viadere.io`: production refuses them by the RP ID hash even with production client data,
    /// and staging refuses production passkeys and production-origin client data.
    func testStagingAndProductionPasskeysAreNeverInterchangeable() async throws {
        let production = WebAuthnPasskeyVerifier(config: ServerConfig.testing())
        let staging = WebAuthnPasskeyVerifier(config: stagingConfig)
        let stagingKey = try await register(rpId: "staging.viadere.io", origin: Self.stagingOrigin, verifier: staging)
        let productionKey = try await register(rpId: "viadere.io", origin: "https://viadere.io", verifier: production)
        let challenge = production.makeChallenge()

        let stagingOnStaging = try assertion(stagingKey.credential, id: stagingKey.id, rpId: "staging.viadere.io", origin: Self.stagingOrigin, challenge: challenge)
        XCTAssertNoThrow(try staging.verifyAssertion(stagingOnStaging, challenge: challenge, publicKey: stagingKey.publicKey, signCount: 0))
        XCTAssertThrowsError(try production.verifyAssertion(stagingOnStaging, challenge: challenge, publicKey: stagingKey.publicKey, signCount: 0))
        let stagingKeyProductionOrigin = try assertion(stagingKey.credential, id: stagingKey.id, rpId: "staging.viadere.io", origin: "https://viadere.io",
                                                       challenge: challenge)
        XCTAssertThrowsError(try production.verifyAssertion(stagingKeyProductionOrigin, challenge: challenge, publicKey: stagingKey.publicKey, signCount: 0),
                             "the RP ID hash is staging's")
        let productionOnProduction = try assertion(productionKey.credential, id: productionKey.id, rpId: "viadere.io", origin: "https://viadere.io",
                                                   challenge: challenge)
        XCTAssertThrowsError(try staging.verifyAssertion(productionOnProduction, challenge: challenge, publicKey: productionKey.publicKey, signCount: 0))
        let productionKeyStagingOrigin = try assertion(productionKey.credential, id: productionKey.id, rpId: "viadere.io", origin: Self.stagingOrigin,
                                                       challenge: challenge)
        XCTAssertThrowsError(try staging.verifyAssertion(productionKeyStagingOrigin, challenge: challenge, publicKey: productionKey.publicKey, signCount: 0),
                             "the RP ID hash is production's")
    }

    /// A staging server never runs with a production name as its RP ID, link domain, origin or API base.
    func testStagingRefusesTheProductionHostsAndAcceptsItsOwn() throws {
        let staging = PlatformGateOpsTests.productionEnvironment("staging")
        let config = try ServerConfig.fromEnvironment(staging)
        XCTAssertEqual(config.relyingPartyID, "staging.viadere.io")
        XCTAssertEqual(config.linkDomain.host, "staging.viadere.io")
        for (name, value) in [("RP_ID", "viadere.io"), ("LINK_DOMAIN", "viadere.io"), ("LINK_DOMAIN", "www.viadere.io"), ("PUBLIC_BASE_URL", "https://api.viadere.io"),
                              ("PUBLIC_BASE_URL", "https://viadere.io"), ("DASHBOARD_ORIGIN", "https://viadere.io")] {
            var env = staging
            env[name] = value
            XCTAssertThrowsError(try ServerConfig.fromEnvironment(env), "\(name)=\(value)")
        }
        var bothProduction = staging
        bothProduction["RP_ID"] = "viadere.io"
        bothProduction["RP_ORIGIN"] = "https://viadere.io"
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(bothProduction))
        // Production itself keeps its names.
        XCTAssertEqual(try ServerConfig.fromEnvironment(PlatformGateOpsTests.productionEnvironment()).relyingPartyID, "viadere.io")
    }

    /// `__Host-` session cookies (business, operator) carry no Domain, are Secure and Path=/, including the cookies that clear them: a
    /// production cookie never reaches staging.viadere.io, and staging can never set one for viadere.io.
    func testConsoleCookiesAreHostOnly() {
        for realm in [DashboardRealm.business, .operator] {
            XCTAssertTrue(realm.cookieName.hasPrefix("__Host-"))
            let header = DashboardSessionStore.clearingCookie(realm: realm).serialize(name: realm.cookieName).lowercased()
            let attributes = header.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }
            XCTAssertFalse(attributes.contains { $0.hasPrefix("domain=") }, header)
            XCTAssertTrue(attributes.contains("secure") && attributes.contains("path=/") && attributes.contains("httponly"), header)
        }
    }
}
