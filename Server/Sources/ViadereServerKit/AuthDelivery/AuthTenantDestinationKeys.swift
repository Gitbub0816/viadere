@preconcurrency import Crypto
import Foundation
import Vapor
import ViadereCore

/// `GET /v1/auth-tenants/{tenantId}/destination-keys` (ADR-0031 §2): the device fetches the authority-signed tenant record and the latest pinned-key
/// revocation list through the api, which **relays both unchanged**. The api signs neither and holds no key that could (decision 12, `API-NO-NEW-KEYS`);
/// the device verifies both against its pinned authority keys, so a record the api fabricates or alters is refused there.
///
/// `404` while `AUTH_DELIVERY_ENABLED` or `AUTH_DESTINATION_RECORDS_ENABLED` is off; `404` for a tenant the authority does not know; `503` when no
/// authority is configured or it does not answer (the device shows S-LINK-11 and the link waits).
enum AuthTenantKeyRelay {
    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.authTenantDestinationKeys) { req in
            try AuthDeliveryGate.require(req.ctx)
            guard req.ctx.config.authDelivery.destinationRecordsEnabled else { throw APIError.notFound }
            _ = try req.consumer
            guard let tenant = req.parameters.get("tenantId"), AuthorityTenantRecord.isTenantId(tenant) else { throw APIError.notFound }
            guard let transport = req.application.authorityTransport else {
                throw APIError(.serviceUnavailable, .unavailable, "Sign-in links can't be checked right now.")
            }
            switch await AuthorityClient(transport: transport).tenantDestinationKeys(tenantId: tenant) {
            case .found(let keys):
                let out = try req.jsonResponse(keys)
                out.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
                return out
            case .unknown: throw APIError.notFound
            case .unavailable: throw APIError(.serviceUnavailable, .unavailable, "Sign-in links can't be checked right now.")
            }
        }
    }
}

extension AuthorityClient {
    enum TenantKeysResult: Sendable {
        case found(AuthTenantDestinationKeys)
        case unknown
        case unavailable
    }

    /// `POST /v1/tenant-keys/record {tenant_id}`. The answer is decoded strictly (exactly `record` and an optional `revocation_list`, each at most 4096
    /// bytes) and passed on byte for byte; its signatures are the device's to check.
    func tenantDestinationKeys(tenantId: String) async -> TenantKeysResult {
        let result: (status: Int, body: Data)
        do {
            result = try await transport.send(method: .POST, path: AuthorityTenantKeyRoute.record, contentType: "application/json",
                                              body: try CanonicalJSON.serialize(.object(["tenant_id": .string(tenantId)])))
        } catch { return .unavailable }
        if result.status == 404 { return .unknown }
        guard result.status == 200, let keys = try? ViadereJSON.decode(AuthTenantDestinationKeys.self, from: result.body) else { return .unavailable }
        return .found(keys)
    }
}

/// The api's own (defense-in-depth) view of a tenant's destination keys at create: the authority-signed record, verified here against the pinned
/// statement keys exactly as the device does. The api's check is **not** relied on (ADR-0031 §3); without a verifiable record it knows no key, so
/// business-mode create fails closed with `422 destination_signature_required`.
struct AuthorityRecordTenantKeys: TenantDestinationKeyDirectory {
    let transport: any AuthorityTransport
    let pinnedKeys: [P256.Signing.PublicKey]
    let environment: AuthorityEnvironment
    let clock: @Sendable () -> Date

    func activeKeys(tenantId: String) async -> [String: (key: DevicePublicKey, notAfter: Date?)] {
        guard !pinnedKeys.isEmpty, case .found(let keys) = await AuthorityClient(transport: transport).tenantDestinationKeys(tenantId: tenantId),
              let record = try? AuthorityStatementVerifier.verifyTenantRecord(keys.record, pinnedKeys: pinnedKeys, environment: environment, tenantId: tenantId,
                                                                            minimumSeq: 0, now: clock()) else { return [:] }
        return record.expectation(requestId: "", purpose: .signIn, now: clock()).keys
    }
}

/// The create-time directory when `AUTH_DESTINATION_RECORDS_ENABLED` is on and an authority is configured: the authority record verified against the
/// Core-pinned statement keys of the deployment's environment (owner placeholders resolve to none, so every business-mode create stays `422`).
func authorityTenantKeys(config: ServerConfig, app: Application, clock: any ServerClock) -> (any TenantDestinationKeyDirectory)? {
    guard config.authDelivery.destinationRecordsEnabled, let transport = app.authorityTransport else { return nil }
    let environment: AuthorityEnvironment = config.environment == .production ? .production : .staging
    return AuthorityRecordTenantKeys(transport: transport, pinnedKeys: AuthorityPinnedKeys.deviceStatementKeys(environment), environment: environment,
                                     clock: { clock.now() })
}
