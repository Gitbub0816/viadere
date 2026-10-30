/// ViadereCore: the shared, platform-neutral contract between the Viadere server,
/// the iOS app, and any other client.
///
/// Areas:
/// - Identifiers & registry primitives (`BusinessCode`, `BusinessHandle`, typed IDs, `ConnectLink`)
/// - Interaction protocol (`Interaction`, payloads, `AssurancePolicy`, `ChannelRenderer`)
/// - Security primitives (`RequestSigner`/`RequestVerifier`, `DecisionSigner`/`DecisionVerifier`,
///   `WebhookSignature`, `SecureToken`, `ReplayGuard`)
/// - SMS gateway state machine (`SMSGatewayEngine`)
/// - Shared models / DTOs and the `APIRoutes` catalog
///
/// Wire formats are specified in `docs/SECURITY.md`.
public enum ViadereCore {
    /// Semantic version of the shared contract.
    public static let version = "1.0.0"
    // `domain` (the configured link domain) is in `Identifiers/LinkDomain.swift`.
    /// Bundle identifier prefix for Apple targets.
    public static let bundlePrefix = "com.viadere"
}
