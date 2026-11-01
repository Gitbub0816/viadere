import Foundation
import ViadereCore
import WebAuthn

/// Result of verifying a registration ceremony.
public struct VerifiedPasskeyRegistration: Sendable {
    public var credentialId: String
    public var publicKey: Data
    public var signCount: UInt32
    public var backupEligible: Bool
}

public struct VerifiedPasskeyAssertion: Sendable {
    public var newSignCount: UInt32
}

public enum PasskeyError: Error, Sendable { case invalid }

/// Abstracts WebAuthn verification so tests can use a deterministic fake while production uses webauthn-swift.
public protocol PasskeyVerifier: Sendable {
    /// Fresh random challenge (≥ 32 bytes).
    func makeChallenge() -> Data
    func verifyRegistration(_ credential: PasskeyRegistrationCredential, challenge: Data,
                            credentialAlreadyRegistered: @Sendable (String) async throws -> Bool) async throws -> VerifiedPasskeyRegistration
    func verifyAssertion(_ credential: PasskeyAssertionCredential, challenge: Data, publicKey: Data, signCount: UInt32) throws
        -> VerifiedPasskeyAssertion
}

/// Production verifier built on webauthn-swift (RP ID `viadere.com`, user verification required).
public struct WebAuthnPasskeyVerifier: PasskeyVerifier {
    private let manager: WebAuthnManager

    public init(config: ServerConfig) {
        self.init(config: config, origin: config.relyingPartyOrigin)
    }

    /// A verifier for a different origin under the same RP ID (the business dashboard may live on a sub-domain).
    public init(config: ServerConfig, origin: String) {
        manager = WebAuthnManager(configuration: .init(relyingPartyID: config.relyingPartyID, relyingPartyName: config.relyingPartyName,
                                                       relyingPartyOrigin: origin))
    }

    public func makeChallenge() -> Data { SecureToken.randomBytes(32) }

    public func verifyRegistration(_ credential: PasskeyRegistrationCredential, challenge: Data,
                                   credentialAlreadyRegistered: @Sendable (String) async throws -> Bool) async throws -> VerifiedPasskeyRegistration {
        // Re-shape our flat DTO into the standard `navigator.credentials.create()` JSON.
        let json: [String: Any] = [
            "id": credential.id, "rawId": credential.rawId, "type": "public-key",
            "response": ["attestationObject": credential.attestationObject, "clientDataJSON": credential.clientDataJSON],
        ]
        do {
            let data = try JSONSerialization.data(withJSONObject: json)
            let decoded = try JSONDecoder().decode(RegistrationCredential.self, from: data)
            let verified = try await manager.finishRegistration(
                challenge: [UInt8](challenge), credentialCreationData: decoded, requireUserVerification: true,
                confirmCredentialIDNotRegisteredYet: { id in !(try await credentialAlreadyRegistered(PasskeyCredentialID.canonical(id))) })
            return VerifiedPasskeyRegistration(credentialId: PasskeyCredentialID.canonical(verified.id), publicKey: Data(verified.publicKey),
                                               signCount: verified.signCount, backupEligible: verified.backupEligible)
        } catch {
            throw PasskeyError.invalid
        }
    }

    public func verifyAssertion(_ credential: PasskeyAssertionCredential, challenge: Data, publicKey: Data,
                                signCount: UInt32) throws -> VerifiedPasskeyAssertion {
        var response: [String: Any] = [
            "authenticatorData": credential.authenticatorData, "clientDataJSON": credential.clientDataJSON,
            "signature": credential.signature,
        ]
        if let handle = credential.userHandle { response["userHandle"] = handle }
        let json: [String: Any] = ["id": credential.id, "rawId": credential.rawId, "type": "public-key", "response": response]
        do {
            let data = try JSONSerialization.data(withJSONObject: json)
            let decoded = try JSONDecoder().decode(AuthenticationCredential.self, from: data)
            let verified = try manager.finishAuthentication(credential: decoded, expectedChallenge: [UInt8](challenge),
                                                            credentialPublicKey: [UInt8](publicKey),
                                                            credentialCurrentSignCount: signCount, requireUserVerification: true)
            return VerifiedPasskeyAssertion(newSignCount: verified.newSignCount)
        } catch {
            throw PasskeyError.invalid
        }
    }
}

/// The one stored form of a credential id: unpadded base64url, exactly the `id` a browser or `ASAuthorization` sends at sign-in, which is what
/// every lookup compares against. webauthn-swift reports registered ids as padded standard base64, so they are converted before storage.
enum PasskeyCredentialID {
    static func canonical(_ id: String) -> String {
        var out = id.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        while out.hasSuffix("=") { out.removeLast() }
        return out
    }

    /// The padded standard base64 form passkeys registered before canonicalisation were stored under.
    static func legacy(_ id: String) -> String {
        var out = canonical(id).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while out.count % 4 != 0 { out.append("=") }
        return out
    }

    /// Every stored form of one credential id, for lookups: rows written before canonicalisation keep working without a data migration.
    /// The two forms encode the same bytes, so this never matches another credential.
    static func storedForms(_ id: String) -> [String] {
        let forms = [canonical(id), legacy(id)]
        return forms[0] == forms[1] ? [forms[0]] : forms
    }
}
