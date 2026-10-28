@preconcurrency import Crypto
import Fluent
import Foundation
import Logging
import Vapor
import ViadereCore

/// The collaborators of Verify, held by the application: the provider client, the Wallet trust store and the merchant encryption key
/// source. Built once from the configuration (`VerifyRegistration.configure`); tests replace them after creating the application.
///
/// Key custody (ADR-03): the Wallet identity-encryption private key is loaded through `WalletEncryptionKeySource`. In staging and
/// production it is a KMS-wrapped key unwrapped through `keyUnwrapper` (the platform KMS from WP8 provides the implementation and
/// assigns it here); a key file is for development. **Integration point:** until a `WalletKeyUnwrapper` is assigned, a configuration
/// that names wrapped keys offers no Wallet method (fail closed) and logs why.
final class VerifyRuntime: @unchecked Sendable {
    private let lock = NSLock()
    private var _didit: (any DiditAPI)?
    private var _trust: IACATrustStore?
    private var _keys: (any WalletEncryptionKeySource)?
    private var _keyUnwrapper: (any WalletKeyUnwrapper)?
    private var loadedWalletFromConfig = false
    let logger = Logger(label: "viadere.verify")

    var didit: (any DiditAPI)? {
        get { lock.withLock { _didit } }
        set { lock.withLock { _didit = newValue } }
    }

    /// Replaces the trust store (tests, and reloads after the IACA directory changes).
    var trust: IACATrustStore? {
        get { lock.withLock { _trust } }
        set { lock.withLock { _trust = newValue } }
    }

    var walletKeys: (any WalletEncryptionKeySource)? {
        get { lock.withLock { _keys } }
        set { lock.withLock { _keys = newValue } }
    }

    /// KMS integration point (WP8): unwraps `WALLET_ENCRYPTION_KEY_WRAPPED`.
    var keyUnwrapper: (any WalletKeyUnwrapper)? {
        get { lock.withLock { _keyUnwrapper } }
        set { lock.withLock { _keyUnwrapper = newValue; loadedWalletFromConfig = false } }
    }

    /// Loads the Wallet trust store and key source from the configuration once, unless they were assigned directly.
    func prepareWallet(settings: VerifySettings, now: Date) {
        lock.lock()
        defer { lock.unlock() }
        guard !loadedWalletFromConfig else { return }
        loadedWalletFromConfig = true
        guard settings.walletConfigured else { return }
        if _trust == nil, let directory = settings.walletIACADirectory {
            do {
                let loaded = try IACATrustStore.load(directory: directory, now: now, pinned: settings.walletIACAPinned)
                _trust = loaded.store
                logger.info("wallet trust store loaded", metadata: ["trusted": "\(loaded.report.trusted)", "rejected": "\(loaded.report.rejected.count)"])
                for (name, reason) in loaded.report.rejected.sorted(by: { $0.key < $1.key }) {
                    logger.warning("iaca certificate not trusted", metadata: ["file": "\(name)", "reason": "\(reason)"])
                }
            } catch {
                logger.error("wallet trust store could not be loaded")
            }
        }
        if _keys == nil {
            if !settings.walletEncryptionKeyWrapped.isEmpty {
                if let unwrapper = _keyUnwrapper {
                    _keys = WrappedWalletEncryptionKeys(wrapped: settings.walletEncryptionKeyWrapped.compactMap { Base64URL.decode($0) }, unwrapper: unwrapper)
                } else {
                    logger.error("wallet encryption key is KMS-wrapped but no unwrapper is configured; the Wallet method is unavailable")
                }
            } else if let local = try? LocalWalletEncryptionKeys(paths: settings.walletEncryptionKeyPaths), !local.keys.isEmpty {
                _keys = local
            } else if !settings.walletEncryptionKeyPaths.isEmpty {
                logger.error("wallet encryption key file could not be read; the Wallet method is unavailable")
            }
        }
    }

    /// Whether the Wallet method can run now: configured, a non-empty trust store and a key source.
    func walletAvailable(settings: VerifySettings, now: Date) -> Bool {
        prepareWallet(settings: settings, now: now)
        return settings.walletConfigured && !(trust?.isEmpty ?? true) && walletKeys != nil
    }

    /// Whether a **new** document verification can start: fully configured, the new-sessions switch on, and a client.
    func documentAvailable(settings: VerifySettings) -> Bool { settings.diditConfigured && settings.diditNewSessionsEnabled && didit != nil }
}

private struct VerifyRuntimeKey: StorageKey { typealias Value = VerifyRuntime }

extension Application {
    var verify: VerifyRuntime {
        get {
            if let value = storage[VerifyRuntimeKey.self] { return value }
            let value = VerifyRuntime()
            storage[VerifyRuntimeKey.self] = value
            return value
        }
        set { storage[VerifyRuntimeKey.self] = newValue }
    }
}

extension Request {
    var verify: VerifyRuntime { application.verify }
}

enum VerifyRegistration {
    /// Builds the runtime from the configuration (one line in `configure`). The provider client exists only when it is fully configured.
    static func configure(_ app: Application, config: ServerConfig) {
        let runtime = app.verify
        let settings = config.verify
        // The client exists whenever credentials do, even with new sessions switched off or the workflow unset: it is the purge client.
        if let key = settings.diditAPIKey, !key.isEmpty, runtime.didit == nil {
            runtime.didit = VaporDiditAPI(client: app.client, apiKey: key, base: settings.diditAPIBase)
        }
    }
}
