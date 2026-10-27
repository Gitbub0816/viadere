import Foundation
import ViadereCore

#if os(iOS) && canImport(AuthenticationServices) && canImport(UIKit)
import AuthenticationServices
import UIKit

/// Platform passkeys via `ASAuthorizationPlatformPublicKeyCredentialProvider` (relying party `viadere.com`;
/// requires the `webcredentials:viadere.com` associated domain and the server's apple-app-site-association file).
///
/// The Kit never touches `UIApplication` (so it stays safe to link into app extensions); the app passes the window
/// that should host the system passkey sheet.
public final class ApplePasskeyService: PasskeyService, @unchecked Sendable {
    private let anchorProvider: @MainActor @Sendable () -> UIWindow?

    /// - Parameter anchorProvider: returns the key window of the foreground scene.
    public init(anchorProvider: @escaping @MainActor @Sendable () -> UIWindow?) {
        self.anchorProvider = anchorProvider
    }

    public func register(options: PasskeyRegistrationOptions) async throws -> PasskeyRegistrationCredential {
        guard let challenge = Base64URL.decode(options.challenge), let userID = Base64URL.decode(options.userId) else {
            throw PasskeyError.failed("options")
        }
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: options.relyingPartyId)
        let request = provider.createCredentialRegistrationRequest(challenge: challenge, name: options.userName, userID: userID)
        if #available(iOS 17.4, *) { request.displayName = options.userDisplayName }
        request.userVerificationPreference = .required
        let authorization = try await PasskeyCoordinator.perform([request], anchorProvider: anchorProvider)
        guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration,
              let attestation = credential.rawAttestationObject else { throw PasskeyError.failed("credential") }
        return PasskeyRegistrationCredential(
            id: Base64URL.encode(credential.credentialID), rawId: Base64URL.encode(credential.credentialID),
            attestationObject: Base64URL.encode(attestation), clientDataJSON: Base64URL.encode(credential.rawClientDataJSON),
            transports: ["internal", "hybrid"])
    }

    public func assert(options: PasskeyAssertionOptions) async throws -> PasskeyAssertionCredential {
        guard let challenge = Base64URL.decode(options.challenge) else { throw PasskeyError.failed("options") }
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: options.relyingPartyId)
        let request = provider.createCredentialAssertionRequest(challenge: challenge)
        request.userVerificationPreference = .required
        let allowed = options.allowCredentialIds.compactMap(Base64URL.decode).map { ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0) }
        if !allowed.isEmpty { request.allowedCredentials = allowed }
        let authorization = try await PasskeyCoordinator.perform([request], anchorProvider: anchorProvider)
        guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
            throw PasskeyError.failed("credential")
        }
        return PasskeyAssertionCredential(
            id: Base64URL.encode(credential.credentialID), rawId: Base64URL.encode(credential.credentialID),
            authenticatorData: Base64URL.encode(credential.rawAuthenticatorData), clientDataJSON: Base64URL.encode(credential.rawClientDataJSON),
            signature: Base64URL.encode(credential.signature), userHandle: Base64URL.encode(credential.userID))
    }
}

/// Bridges the delegate-based `ASAuthorizationController` to async/await. Main-actor only (it presents UI).
/// `@preconcurrency` conformances keep this correct whether or not the SDK annotates the protocols `@MainActor`.
@MainActor
private final class PasskeyCoordinator: NSObject, @preconcurrency ASAuthorizationControllerDelegate,
                                        @preconcurrency ASAuthorizationControllerPresentationContextProviding {
    private var continuation: CheckedContinuation<ASAuthorization, any Error>?
    private var controller: ASAuthorizationController?
    private let anchorProvider: @MainActor @Sendable () -> UIWindow?
    /// Keeps the coordinator alive while the system sheet is up.
    private static var active: PasskeyCoordinator?

    private init(anchorProvider: @escaping @MainActor @Sendable () -> UIWindow?) {
        self.anchorProvider = anchorProvider
        super.init()
    }

    static func perform(_ requests: [ASAuthorizationRequest],
                        anchorProvider: @escaping @MainActor @Sendable () -> UIWindow?) async throws -> ASAuthorization {
        let coordinator = PasskeyCoordinator(anchorProvider: anchorProvider)
        active = coordinator
        defer { active = nil }
        return try await coordinator.run(requests)
    }

    private func run(_ requests: [ASAuthorizationRequest]) async throws -> ASAuthorization {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let controller = ASAuthorizationController(authorizationRequests: requests)
            controller.delegate = self
            controller.presentationContextProvider = self
            self.controller = controller
            controller.performRequests()
        }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        continuation?.resume(returning: authorization)
        continuation = nil
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: any Error) {
        let mapped: PasskeyError
        if let authError = error as? ASAuthorizationError, authError.code == .canceled { mapped = .cancelled } else { mapped = .failed("authorization") }
        continuation?.resume(throwing: mapped)
        continuation = nil
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        anchorProvider() ?? ASPresentationAnchor()
    }
}
#endif
