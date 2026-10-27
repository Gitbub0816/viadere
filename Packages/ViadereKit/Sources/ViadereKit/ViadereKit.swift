/// ViadereKit: the client SDK shared by the iOS app, its extensions, the App Clip and the watch app.
///
/// Everything platform-neutral (API client, request signing, approvals, notification-action mapping,
/// deep-link routing, code entry, view models) compiles and is unit-tested on Linux. Apple-only code
/// (Secure Enclave, Keychain, passkeys, pinning, LocalAuthentication) is guarded by `#if canImport(...)`
/// and lives under `Platform/` and `Keys/`.
public enum ViadereKit {
    public static let version = "1.0.0"
}
