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

/// `POST /v1/business/destination-keys/registration-nonce` (ADR-0031 §1.2 rule (a); SECURITY.md §2.110 "Registration"): the business-facing relay of the
/// authority route `POST /v1/tenant-keys/registration-nonce`. The api names the tenant from the **authenticated live key** (never from the body),
/// relays only `{tenant_id, kid}`, decodes the authority's answer strictly and returns exactly what the registration proof signs. It adds, removes and
/// consumes nothing: keys, hosts and names are still registered only by the reviewed admin job, which consumes the nonce once.
///
/// `404` while `AUTH_DELIVERY_ENABLED` or `AUTH_DESTINATION_RECORDS_ENABLED` is off, while the authority's `AUTHORITY_TENANT_KEYS_ENABLED` is off, and for
/// no pending nonce (another tenant's key, consumed, expired: one body); `403` for a test key; `429` per tenant (namespace `authdl-keynonce`, fail closed);
/// `503` without an authority or for an answer that does not decode. Every read and refusal after authentication is audited (ids and outcome only).
enum AuthDestinationKeyNonceRelay {
    static let rateNamespace = "authdl-keynonce"

    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.businessDestinationKeyNonce, scope: BusinessAPIKeys.Scope.authDeliveriesWrite) { req in
            try AuthDeliveryGate.require(req.ctx)
            guard req.ctx.config.authDelivery.destinationRecordsEnabled else { throw APIError.notFound }
            let principal = try req.business
            let audit = AuditService(db: req.db, ctx: req.ctx)
            let actor = AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased())
            func record(_ outcome: AuditEvent.Outcome, _ reason: String) async {
                _ = try? await audit.record("auth_destination_key.registration_nonce", outcome: outcome, actor: actor, businessId: principal.businessId,
                                            subjectType: "destination_key", metadata: ["result": reason])
            }
            // Destination keys protect live sign-in links: a test key never reads a registration nonce.
            guard principal.livemode else {
                await record(.denied, "test_key")
                throw APIError(.forbidden, .forbidden, "Destination keys are registered with a live API key.")
            }
            try await AuthDeliveryService(db: req.db, ctx: req.ctx).requireLiveKeyAssurance(principal)
            do {
                try await req.ctx.limiter.enforce(rateNamespace, key: principal.businessId.description, rule: req.ctx.config.authDelivery.registrationNonceRate)
            } catch {
                await record(.denied, "rate_limited")
                throw error
            }
            let body: AuthDestinationKeyNonceRequest
            do { body = try ViadereJSON.decode(AuthDestinationKeyNonceRequest.self, from: req.bodyBytes) } catch {
                throw APIError.validation("kid is required.", details: ["kid": "invalid"])
            }
            guard body.isWellFormed else { throw APIError.validation("kid must be the key's RFC 7638 thumbprint.", details: ["kid": "invalid"]) }
            guard let transport = req.application.authorityTransport else {
                await record(.failure, "unavailable")
                throw APIError(.serviceUnavailable, .unavailable, "Destination keys can't be registered right now.")
            }
            let tenant = WebhookService(db: req.db, ctx: req.ctx).tenantId(of: principal.businessId)
            switch await AuthorityClient(transport: transport).registrationNonce(tenantId: tenant, kid: body.kid) {
            case .found(let nonce, let hosts, let expiresAt):
                await record(.success, "issued")
                let environment: AuthorityEnvironment = req.ctx.config.environment == .production ? .production : .staging
                let out = try req.jsonResponse(AuthDestinationKeyNonceResponse(tenantId: tenant, aud: environment.authorityURN, kid: body.kid, hosts: hosts,
                                                                               nonce: nonce, expiresAt: expiresAt))
                out.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
                return out
            case .none:
                await record(.denied, "no_pending_registration")
                throw APIError.notFound
            case .unavailable:
                await record(.failure, "unavailable")
                throw APIError(.serviceUnavailable, .unavailable, "Destination keys can't be registered right now.")
            }
        }
    }
}

extension AuthorityClient {
    enum RegistrationNonceResult: Sendable {
        case found(nonce: String, hosts: [String], expiresAt: Int64)
        case none
        case unavailable
    }

    /// `POST /v1/tenant-keys/registration-nonce {tenant_id, kid}`. `404` (flag off at the authority, or no pending nonce) is `none`; the answer must be
    /// exactly `{nonce, hosts, expires_at}` with a 256-bit base64url nonce and 1 to 20 hosts, or it is `unavailable` (never passed on).
    func registrationNonce(tenantId: String, kid: String) async -> RegistrationNonceResult {
        let result: (status: Int, body: Data)
        do {
            result = try await transport.send(method: .POST, path: AuthorityTenantKeyRoute.registrationNonce, contentType: "application/json",
                                              body: try CanonicalJSON.serialize(.object(["tenant_id": .string(tenantId), "kid": .string(kid)])))
        } catch { return .unavailable }
        if result.status == 404 { return .none }
        guard result.status == 200, case .object(let o)? = try? JSONDecoder().decode(JSONValue.self, from: result.body), Set(o.keys) == ["nonce", "hosts", "expires_at"],
              let nonce = o["nonce"]?.stringValue, Base64URL.isValid(nonce, minLength: 43, maxLength: 43), Base64URL.decode(nonce)?.count == 32,
              case .array(let list)? = o["hosts"], (1...20).contains(list.count), let expiresAt = o["expires_at"]?.authorityInteger else { return .unavailable }
        let hosts = list.compactMap(\.stringValue)
        guard hosts.count == list.count, Set(hosts).count == hosts.count, hosts.allSatisfy({ (try? AuthDestinationValidator.validateHost($0)) != nil }) else {
            return .unavailable
        }
        return .found(nonce: nonce, hosts: hosts, expiresAt: expiresAt)
    }

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
