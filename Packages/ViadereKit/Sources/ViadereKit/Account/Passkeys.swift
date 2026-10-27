import Foundation
import ViadereCore

public enum PasskeyError: Error, Equatable, Sendable {
    case cancelled
    case unsupported
    case failed(String)

    public var userMessage: String {
        switch self {
        case .cancelled: "Passkey setup was cancelled."
        case .unsupported: "Passkeys aren't available on this device."
        case .failed: "We couldn't use your passkey. Please try again."
        }
    }
}

/// Platform passkeys (WebAuthn, relying party `viadere.com`).
/// iOS: `ASAuthorizationPlatformPublicKeyCredentialProvider` (`ApplePasskeyService`). Previews/tests: `MockPasskeyService`.
public protocol PasskeyService: Sendable {
    func register(options: PasskeyRegistrationOptions) async throws -> PasskeyRegistrationCredential
    func assert(options: PasskeyAssertionOptions) async throws -> PasskeyAssertionCredential
}

public struct MockPasskeyService: PasskeyService {
    public var fail: PasskeyError?
    public init(fail: PasskeyError? = nil) { self.fail = fail }

    public func register(options: PasskeyRegistrationOptions) async throws -> PasskeyRegistrationCredential {
        if let fail { throw fail }
        let id = SecureToken.generate(byteCount: 16)
        return PasskeyRegistrationCredential(id: id, rawId: id, attestationObject: SecureToken.generate(), clientDataJSON: SecureToken.generate(),
                                             transports: ["internal"])
    }

    /// A WebAuthn-shaped assertion: client data `{"type":"webauthn.get","challenge":…}` and authenticator data with the
    /// user-present and user-verified flags, so the mock server can check the challenge binding and user verification.
    public func assert(options: PasskeyAssertionOptions) async throws -> PasskeyAssertionCredential {
        if let fail { throw fail }
        let id = SecureToken.generate(byteCount: 16)
        let clientData = Data("{\"type\":\"webauthn.get\",\"challenge\":\"\(options.challenge)\",\"origin\":\"https://\(options.relyingPartyId)\"}".utf8)
        let authenticatorData = Data(repeating: 0, count: 32) + Data([0x05, 0, 0, 0, 1])
        return PasskeyAssertionCredential(id: id, rawId: id, authenticatorData: Base64URL.encode(authenticatorData),
                                          clientDataJSON: Base64URL.encode(clientData), signature: SecureToken.generate(), userHandle: nil)
    }
}
