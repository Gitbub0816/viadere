import Foundation
import ViadereCore

/// The object graph of Approve v2 on the device. Built by the app (`ApproveEnvironment.live`) or by tests with fakes.
public struct ApproveEnvironment: Sendable {
    public var api: any ApproveAPI
    public var vault: any ApprovalKeyVault
    public var store: any ApproveLocalStore
    public var directory: BusinessDirectoryClient
    public var enrollment: ApproveEnrollmentFlow
    public var requests: ApproveRequestHandler
    public var freeze: ApproveFreezeFlow
    /// Fresh Face ID / Touch ID proof required before a changed business root is trusted.
    public var rootChangeAuthorizer: any RootChangeAuthorizer
    /// False when the build pins no transparency-log key: nothing about a business's keys can then be verified, so Approve v2 stays closed.
    public var isConfigured: Bool

    public init(api: any ApproveAPI, vault: any ApprovalKeyVault, store: any ApproveLocalStore, logKeys: [DevicePublicKey], logId: String = TransparencyLog.defaultLogId,
                keys: any DeviceKeyStore, records: any DeviceRecordStore, policy: ApprovalPromptPolicy = .standard, clock: @escaping @Sendable () -> Date = { Date() },
                assertion: AssertionSource? = nil) {
        self.api = api
        self.vault = vault
        self.store = store
        let directory = BusinessDirectoryClient(api: api, store: store, logKeys: logKeys, logId: logId, clock: clock)
        self.directory = directory
        enrollment = ApproveEnrollmentFlow(api: api, vault: vault, store: store, directory: directory, clock: clock)
        requests = ApproveRequestHandler(api: api, vault: vault, store: store, directory: directory, policy: policy, clock: clock, assertion: assertion)
        freeze = ApproveFreezeFlow(api: api, keys: keys, records: records, clock: clock)
        rootChangeAuthorizer = DeviceBiometricAuthorizer(keys: keys)
        isConfigured = !logKeys.isEmpty
    }

    /// The environment for `services` with a given vault and local store (the app passes the Keychain-backed ones).
    public init(services: ViadereServices, api: any ApproveAPI, vault: any ApprovalKeyVault, store: any ApproveLocalStore) {
        self.init(api: api, vault: vault, store: store, logKeys: services.configuration.parsedKeyDirectoryLogKeys, logId: services.configuration.keyDirectoryLogId,
                  keys: services.keys, records: services.records, clock: services.clock,
                  assertion: DeviceAssertions(provider: services.appAttest, records: services.records).source)
    }

    /// Business link sessions on top of this environment (WP-C1): needs the link API and the build's pinned `link-descriptor` keys; `secrets` keeps the
    /// completed links until the business confirms.
    public func linkFlow(api: any LinkSessionAPI, descriptorKeys: [DevicePublicKey], secrets: any SecretStore, assertion: AssertionSource? = nil,
                         clock: @escaping @Sendable () -> Date = { Date() }) -> LinkSessionFlow {
        LinkSessionFlow(api: api, approve: self, descriptorKeys: descriptorKeys, secrets: secrets, assertion: assertion, clock: clock)
    }
}
