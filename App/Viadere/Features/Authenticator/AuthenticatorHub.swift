import UIKit
import ViadereKit

/// Owns the Authenticator vault engine for the app process: one engine and one view model for all the screens, so the unlocked state and the
/// live codes survive navigation. The credential-provider extension builds its own engine over the same encrypted local vault (without a
/// sync client).
@MainActor
final class AuthenticatorHub {
    static let shared = AuthenticatorHub()

    let engine: VaultEngine?
    let model: AuthenticatorViewModel?

    private init() {
        let services = AppEnvironment.services
        let group = Bundle.main.infoDictionary?["ViadereVaultKeychainAccessGroup"] as? String
        if let engine = try? VaultRuntime.makeEngine(appGroupID: services.configuration.appGroupID, vaultKeychainAccessGroup: group,
                                                     api: LiveVaultSyncAPI.make(services: services), deviceLabel: UIDevice.current.model) {
            self.engine = engine
            model = AuthenticatorViewModel(engine: engine)
        } else {
            engine = nil
            model = nil
        }
    }

    /// Wipes the local vault and this device's vault keys. Only the explicit "Delete Authenticator from this iPhone" action calls it: signing out of
    /// Viadere does not touch the vault, because passkeys and codes must not disappear with a session.
    func wipe() async {
        try? await engine?.wipeLocal()
        await IdentityStoreSync.clear()
    }
}

/// "Suggest in AutoFill" preference (default on). Off keeps even the metadata out of the system AutoFill store.
enum AuthenticatorPreferences {
    static let suggestInAutoFillKey = "authenticator.suggestInAutoFill"
    static var suggestInAutoFill: Bool {
        get { UserDefaults.standard.object(forKey: suggestInAutoFillKey) as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: suggestInAutoFillKey) }
    }
}
