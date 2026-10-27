@preconcurrency import Crypto
import Foundation
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Passkeys made by the vault's authenticator engine (ViadereCore) are verified by an **independent** WebAuthn implementation, the one the
/// server uses for its own sign-in (`webauthn-swift`), exactly as a relying party would verify them.
final class PasskeyInteropTests: XCTestCase {
    private func clientData(type: String, challenge: Data, origin: String) -> (json: String, hash: Data) {
        let json = "{\"type\":\"\(type)\",\"challenge\":\"\(Base64URL.encode(challenge))\",\"origin\":\"\(origin)\",\"crossOrigin\":false}"
        return (Base64URL.encode(Data(json.utf8)), Data(SHA256.hash(data: Data(json.utf8))))
    }

    private func roundTrip(attestation: AttestationFormat) async throws {
        let config = ServerConfig.testing()
        let verifier = WebAuthnPasskeyVerifier(config: config)
        let rpId = config.relyingPartyID
        let origin = config.relyingPartyOrigin

        // Registration.
        let challenge = verifier.makeChallenge()
        let create = clientData(type: "webauthn.create", challenge: challenge, origin: origin)
        let created = try WebAuthnAuthenticator.makeCredential(rpId: rpId, userHandle: Data([1, 2, 3, 4]), userName: "alice", clientDataHash: create.hash,
                                                               requireUserVerification: true, userVerified: true, backedUp: true, attestation: attestation,
                                                               now: Date(timeIntervalSince1970: 1_800_000_000))
        let credentialId = Base64URL.encode(created.credential.credentialId)
        let registration = PasskeyRegistrationCredential(id: credentialId, rawId: credentialId, attestationObject: Base64URL.encode(created.attestationObject),
                                                         clientDataJSON: create.json)
        let verified = try await verifier.verifyRegistration(registration, challenge: challenge, credentialAlreadyRegistered: { _ in false })
        XCTAssertEqual(verified.credentialId, credentialId)
        XCTAssertEqual(verified.signCount, 0)
        XCTAssertTrue(verified.backupEligible)

        // Assertion with the public key the relying party stored.
        let loginChallenge = verifier.makeChallenge()
        let get = clientData(type: "webauthn.get", challenge: loginChallenge, origin: origin)
        let assertion = try WebAuthnAuthenticator.getAssertion(credential: created.credential, rpId: rpId, clientDataHash: get.hash, requireUserVerification: true,
                                                               userVerified: true, backedUp: true)
        let credential = PasskeyAssertionCredential(id: credentialId, rawId: credentialId, authenticatorData: Base64URL.encode(assertion.authenticatorData),
                                                    clientDataJSON: get.json, signature: Base64URL.encode(assertion.signature),
                                                    userHandle: Base64URL.encode(assertion.userHandle))
        let result = try verifier.verifyAssertion(credential, challenge: loginChallenge, publicKey: verified.publicKey, signCount: 0)
        XCTAssertEqual(result.newSignCount, 0, "synced passkeys keep signCount 0")

        // The same assertion does not verify for another challenge, another origin's client data, or without user verification.
        XCTAssertThrowsError(try verifier.verifyAssertion(credential, challenge: verifier.makeChallenge(), publicKey: verified.publicKey, signCount: 0))
        let other = clientData(type: "webauthn.get", challenge: loginChallenge, origin: "https://evil.example")
        var wrongOrigin = credential
        wrongOrigin.clientDataJSON = other.json
        XCTAssertThrowsError(try verifier.verifyAssertion(wrongOrigin, challenge: loginChallenge, publicKey: verified.publicKey, signCount: 0))
        let noUV = try WebAuthnAuthenticator.getAssertion(credential: created.credential, rpId: rpId, clientDataHash: get.hash, requireUserVerification: false,
                                                          userVerified: false, backedUp: true)
        let unverified = PasskeyAssertionCredential(id: credentialId, rawId: credentialId, authenticatorData: Base64URL.encode(noUV.authenticatorData),
                                                    clientDataJSON: get.json, signature: Base64URL.encode(noUV.signature), userHandle: nil)
        XCTAssertThrowsError(try verifier.verifyAssertion(unverified, challenge: loginChallenge, publicKey: verified.publicKey, signCount: 0),
                             "a relying party that requires user verification refuses an assertion without it")
        // A credential made for another relying party is refused by this one.
        let foreign = try WebAuthnAuthenticator.makeCredential(rpId: "other-site.example", userHandle: Data([9]), userName: "a", clientDataHash: create.hash,
                                                               requireUserVerification: true, userVerified: true, backedUp: true, now: Date())
        let foreignId = Base64URL.encode(foreign.credential.credentialId)
        let foreignRegistration = PasskeyRegistrationCredential(id: foreignId, rawId: foreignId, attestationObject: Base64URL.encode(foreign.attestationObject), clientDataJSON: create.json)
        do {
            _ = try await verifier.verifyRegistration(foreignRegistration, challenge: challenge, credentialAlreadyRegistered: { _ in false })
            XCTFail("a registration for another relying party must not verify")
        } catch {}
    }

    func testNoneAttestationVerifiesWithAnIndependentWebAuthnImplementation() async throws {
        try await roundTrip(attestation: .none)
    }

    func testPackedSelfAttestationVerifiesWithAnIndependentWebAuthnImplementation() async throws {
        try await roundTrip(attestation: .packedSelf)
    }
}
