import AuthenticationServices
import LocalAuthentication
import SwiftUI
import UIKit
import ViadereCore
import ViadereKit

/// Viadere Authenticator as a third-party credential provider: passkeys (iOS 17), one-time codes (iOS 18).
///
/// Security shape:
/// - **Never silent.** `provideCredentialWithoutUserInteraction` always asks for interaction, because the vault opens only with Face ID / Touch ID /
///   the passcode. A passkey is created or used only after that verification, and the authenticator data says so (UV).
/// - **No network.** The extension builds its engine with no sync client. It reads and writes the same encrypted local vault as the app
///   (App Group container); the app uploads changes the next time it opens.
/// - **Ciphertext at rest.** Nothing in the shared container is readable without the device's vault keys. The only plaintext the system
///   keeps is AutoFill identity metadata (site, account name) and only if "Suggest in AutoFill" is on (`IdentityStoreSync`).
/// - **The OS builds the client data.** The extension signs the client-data hash it is given for the relying party it is given; it never sees
///   an origin it could be tricked into trusting.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let flow = ProviderFlowModel()
    private var task: Task<Void, Never>?
    /// One engine, and so one fresh biometric evaluation, per time the extension is on screen: choosing a row in the picker reuses the unlock that
    /// opened the picker instead of asking for Face ID a second time (gate review L7).
    private var sessionEngine: VaultEngine?
    private var verifiedAt: Date?
    /// A user verification stays good for this long. The authenticator data says UV only for an evaluation this recent.
    private static let verificationWindow: TimeInterval = 60

    // MARK: Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        let host = UIHostingController(rootView: ProviderFlowView(model: flow))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
        flow.onCancel = { [weak self] in self?.cancel(.userCanceled) }
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        task?.cancel()
        let engine = sessionEngine
        sessionEngine = nil
        verifiedAt = nil
        Task { await engine?.lock() }
    }

    private func engine() throws -> VaultEngine {
        if let sessionEngine { return sessionEngine }
        let made = try makeEngine()
        sessionEngine = made
        return made
    }

    private func makeEngine() throws -> VaultEngine {
        let info = Bundle.main.infoDictionary ?? [:]
        return try VaultRuntime.makeEngine(appGroupID: info["ViadereAppGroupID"] as? String ?? "", vaultKeychainAccessGroup: info["ViadereVaultKeychainAccessGroup"] as? String,
                                           api: nil, deviceLabel: "")
    }

    private func cancel(_ code: ASExtensionError.Code) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }

    /// Opens the vault. This is the user verification: the system asks for Face ID / Touch ID / the passcode inside the key use. An unlock that
    /// is less than `verificationWindow` old is reused (one prompt per interaction); an older one is repeated before anything is signed.
    private func unlockedEngine() async throws -> VaultEngine {
        let engine = try engine()
        let recent = verifiedAt.map { Date().timeIntervalSince($0) <= Self.verificationWindow } ?? false
        switch try await engine.phase() {
        case .empty: throw ProviderError.noVault
        case .locked:
            try await engine.unlock()
            verifiedAt = Date()
        case .unlocked:
            if !recent {
                await engine.lock()
                try await engine.unlock()
                verifiedAt = Date()
            }
        }
        return engine
    }

    private enum ProviderError: Error { case noVault, notFound, unsupported }

    private func fail(_ error: Error) {
        switch error {
        case ProviderError.noVault:
            flow.step = .failed("Open Viadere and set up Authenticator first.")
        case ProviderError.notFound:
            cancel(.credentialIdentityNotFound)
        case VaultKeyError.userCancelled, VaultEngineError.deviceKeyMissing:
            cancel(.userCanceled)
        case WebAuthnError.credentialExcluded:
            flow.step = .failed("You already have a passkey for this account.")
        case WebAuthnError.unsupportedAlgorithm:
            flow.step = .failed("This site needs a kind of passkey Authenticator can't make yet.")
        default:
            flow.step = .failed("That didn't work. Try again from the site.")
        }
    }

    // MARK: Passkey assertion (iOS 17)

    /// Always interactive: the vault never opens without the person.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        cancel(.userInteractionRequired)
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        flow.step = .working("Confirm it's you")
        if let request = credentialRequest as? ASPasskeyCredentialRequest, let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity {
            task = Task { await assert(rpId: identity.relyingPartyIdentifier, credentialId: identity.credentialID, clientDataHash: request.clientDataHash) }
            return
        }
        if #available(iOS 18.0, *), let request = credentialRequest as? ASOneTimeCodeCredentialRequest, let id = request.credentialIdentity.recordIdentifier.flatMap(UUID.init(uuidString:)) {
            task = Task { await provideCode(id) }
            return
        }
        cancel(.failed)
    }

    private func assert(rpId: String, credentialId: Data, clientDataHash: Data) async {
        do {
            let engine = try await unlockedEngine()
            let assertion = try await engine.assertPasskey(credentialId: credentialId, rpId: rpId, clientDataHash: clientDataHash, userVerified: true)
            await finish(assertion, rpId: rpId, clientDataHash: clientDataHash)
        } catch VaultEngineError.itemNotFound {
            fail(ProviderError.notFound)
        } catch {
            fail(error)
        }
    }

    @MainActor private func finish(_ assertion: PasskeyAssertion, rpId: String, clientDataHash: Data) {
        let credential = ASPasskeyAssertionCredential(userHandle: assertion.userHandle, relyingParty: rpId, signature: assertion.signature, clientDataHash: clientDataHash,
                                                      authenticatorData: assertion.authenticatorData, credentialID: assertion.credentialId)
        extensionContext.completeAssertionRequest(using: credential)
    }

    // MARK: Passkey picker (iOS 17)

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters) {
        let rpId = requestParameters.relyingPartyIdentifier
        let clientDataHash = requestParameters.clientDataHash
        let allowed = Set(requestParameters.allowedCredentials)
        flow.step = .working("Confirm it's you")
        task = Task {
            do {
                let engine = try await unlockedEngine()
                let matches = try await engine.passkeys(for: rpId).filter { allowed.isEmpty || allowed.contains($0.credentialId) }
                let rows = matches.map { ProviderFlowModel.Row(id: UUID(), title: ProviderText.clean(rpId), subtitle: ProviderText.clean($0.displayName ?? $0.userName)) }
                await MainActor.run {
                    flow.step = .list(title: "Sign in to \(ProviderText.clean(rpId))", rows: rows)
                    flow.onChoose = { [weak self] chosen in
                        guard let self, let index = rows.firstIndex(where: { $0.id == chosen }) else { return }
                        let credentialId = matches[index].credentialId
                        self.task = Task { await self.assert(rpId: rpId, credentialId: credentialId, clientDataHash: clientDataHash) }
                    }
                }
            } catch {
                fail(error)
            }
        }
    }

    /// Passwords are not offered (this provider has none).
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        flow.step = .failed("Authenticator keeps passkeys and one-time codes. It doesn't store passwords.")
    }

    // MARK: Passkey registration (iOS 17)

    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest, let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            cancel(.failed)
            return
        }
        let rpId = identity.relyingPartyIdentifier
        let site = ProviderText.clean(rpId)
        let account = ProviderText.clean(identity.userName)
        // The relying party's "don't register again" list (iOS 18): a credential in the vault for this site that it lists blocks the new one.
        var excluded: [Data] = []
        if #available(iOS 18.0, *) { excluded = (request.excludedCredentials ?? []).map(\.credentialID) }
        let registration = PasskeyRegistrationRequest(rpId: rpId, userName: identity.userName, displayName: nil, userHandle: identity.userHandle,
                                                      clientDataHash: request.clientDataHash, supportedAlgorithms: request.supportedAlgorithms.map(\.rawValue),
                                                      excludedCredentialIds: excluded, requireUserVerification: true)
        flow.step = .confirmCreate(site: site, account: account)
        flow.onConfirm = { [weak self] in
            guard let self else { return }
            self.flow.step = .working("Confirm it's you")
            self.task = Task {
                do {
                    let engine = try await self.unlockedEngine()
                    let created = try await engine.registerPasskey(registration, userVerified: true)
                    await IdentityStoreSync.replace(from: engine)
                    await MainActor.run {
                        let credential = ASPasskeyRegistrationCredential(relyingParty: rpId, clientDataHash: request.clientDataHash, credentialID: created.credential.credentialId,
                                                                         attestationObject: created.attestationObject)
                        self.extensionContext.completeRegistrationRequest(using: credential)
                    }
                } catch {
                    self.fail(error)
                }
            }
        }
    }

    // MARK: One-time codes (iOS 18)

    @available(iOS 18.0, *)
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        flow.step = .working("Confirm it's you")
        task = Task {
            do {
                let engine = try await unlockedEngine()
                // Only codes that belong to the site that asked: a page must not be able to make the picker list every account.
                let domains = serviceIdentifiers.compactMap { identifier -> String? in
                    switch identifier.type {
                    case .domain: identifier.identifier
                    case .URL: URL(string: identifier.identifier)?.host
                    @unknown default: nil
                    }
                }
                let identities = try await engine.oneTimeCodeIdentities(matching: domains)
                if identities.isEmpty, let site = domains.first {
                    await MainActor.run { flow.step = .failed("No saved code matches \(ProviderText.clean(site)). Open Viadere to find the code.") }
                    return
                }
                let rows = identities.compactMap { identity -> ProviderFlowModel.Row? in
                    guard let id = UUID(uuidString: identity.recordIdentifier) else { return nil }
                    return ProviderFlowModel.Row(id: id, title: ProviderText.clean(identity.label), subtitle: "One-time code")
                }
                await MainActor.run {
                    flow.step = .list(title: "Choose a code", rows: rows)
                    flow.onChoose = { [weak self] id in
                        guard let self else { return }
                        self.task = Task { await self.provideCode(id) }
                    }
                }
            } catch {
                fail(error)
            }
        }
    }

    @available(iOS 18.0, *)
    private func provideCode(_ id: UUID) async {
        do {
            let engine = try await unlockedEngine()
            let code = try await engine.oneTimeCode(for: id)
            await MainActor.run { extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code)) }
        } catch VaultEngineError.itemNotFound {
            fail(ProviderError.notFound)
        } catch {
            fail(error)
        }
    }

    // MARK: Settings (the system's "Passwords & AutoFill" row)

    override func prepareInterfaceForExtensionConfiguration() {
        flow.step = .failed("Open Viadere to manage Authenticator, turn on sync, or change what AutoFill may suggest.")
    }
}
