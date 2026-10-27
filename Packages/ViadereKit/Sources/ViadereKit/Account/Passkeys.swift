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

    public func assert(options: PasskeyAssertionOptions) async throws -> PasskeyAssertionCredential {
        if let fail { throw fail }
        let id = SecureToken.generate(byteCount: 16)
        return PasskeyAssertionCredential(id: id, rawId: id, authenticatorData: SecureToken.generate(), clientDataJSON: SecureToken.generate(),
                                          signature: SecureToken.generate(), userHandle: nil)
    }
}
