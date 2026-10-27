import AuthenticationServices
import ViadereKit

/// Keeps the system's AutoFill identity store (`ASCredentialIdentityStore`) in step with the vault, so passkeys appear in the keyboard bar and
/// on sign-in sheets. **What the operating system stores here is metadata only**: relying-party ID, account name, credential ID and user
/// handle for passkeys, and a label for one-time codes. It never receives a key, a secret or a code. People who don't want even that in the
/// system store turn off "Suggest in AutoFill" in Authenticator (`replace(with: [])` clears it).
enum IdentityStoreSync {
    static func replace(from engine: VaultEngine) async {
        let state = await ASCredentialIdentityStore.shared.state()
        guard state.isEnabled else { return }
        do {
            let passkeys = try await engine.passkeyIdentities().map {
                ASPasskeyCredentialIdentity(relyingPartyIdentifier: $0.rpId, userName: $0.userName, credentialID: $0.credentialId, userHandle: $0.userHandle,
                                            recordIdentifier: $0.recordIdentifier)
            }
            try await ASCredentialIdentityStore.shared.replaceCredentialIdentities(passkeys)
        } catch {
            // Best effort: the list inside Authenticator is the source of truth.
        }
    }

    static func clear() async {
        try? await ASCredentialIdentityStore.shared.removeAllCredentialIdentities()
    }
}
