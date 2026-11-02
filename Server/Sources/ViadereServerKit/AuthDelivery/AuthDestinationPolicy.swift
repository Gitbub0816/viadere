import Fluent
import Foundation
import ViadereCore

/// The tenant's destination-signing keys as the authority publishes them (ADR-0031 section 1). The authority is built in Stage 6; until then
/// `UnavailableTenantDestinationKeys` knows none, so **business-mode links fail closed**: create returns `422 destination_signature_required`. The api's
/// own check of a statement is defense in depth only: the device verifies the signature against the authority-signed record before Continue is enabled.
public protocol TenantDestinationKeyDirectory: Sendable {
    /// The tenant's active keys by `kid` (`tenantId` is the business-visible `ten_…` id). Empty = none known.
    func activeKeys(tenantId: String) async -> [String: (key: DevicePublicKey, notAfter: Date?)]
}

struct UnavailableTenantDestinationKeys: TenantDestinationKeyDirectory {
    func activeKeys(tenantId: String) async -> [String: (key: DevicePublicKey, notAfter: Date?)] { [:] }
}

/// The hosts a tenant may use for business-mode magic links: exact A-label hosts on its verified domain (ADR-0021 section 2).
struct AuthDestinationHosts {
    let db: any Database
    let ctx: ServerContext

    /// Hosts usable now: active (not revoked, past the new-tenant hold) and on a currently verified domain of the tenant.
    func allowed(businessId: UUID) async throws -> Set<String> {
        let now = ctx.now
        let domains = try await BusinessDomainRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$status == "verified").all()
            .compactMap { $0.verifiedDomain ?? $0.domain }.map { $0.lowercased() }
        guard !domains.isEmpty else { return [] }
        let rows = try await AuthDestinationHostRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).filter(\.$activatedAt <= now).all()
        return Set(rows.map(\.host).filter { host in domains.contains { host == $0 || host.hasSuffix("." + $0) } })
    }

    /// Adds a host. The console route (fresh passkey step-up by an Owner or Security Admin, notice to every Owner) is a later stage; this is the one place
    /// that decides the hold: a tenant verified less than 30 days ago gets 24 hours before the host is usable (spec Appendix B).
    @discardableResult
    func add(businessId: UUID, host: String, by actor: String) async throws -> AuthDestinationHostRecord {
        do { try AuthDestinationValidator.validateHost(host) } catch { throw APIError.validation("The host is not a valid A-label host.", details: ["host": "invalid"]) }
        let business = try await BusinessRecord.find(businessId, on: db)
        let young = business?.verifiedAt.map { ctx.now.timeIntervalSince($0) < 30 * 86_400 } ?? true
        let row = AuthDestinationHostRecord()
        row.id = UUID()
        row.businessId = businessId
        row.host = host
        row.createdBy = actor
        row.createdAt = ctx.now
        row.activatedAt = young ? ctx.now.addingTimeInterval(24 * 3600) : ctx.now
        try await row.create(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("auth_destination_host.added", actor: AuditActor(kind: .business, id: actor), businessId: BusinessID(businessId),
                                                          subjectType: "auth_destination_host", subjectId: row.id?.uuidString.lowercased(), metadata: ["held": young ? "true" : "false"])
        return row
    }

    /// Reduce-only: a host can always be revoked.
    func revoke(businessId: UUID, host: String) async throws {
        try await AuthDestinationHostRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$host == host).filter(\.$revokedAt == nil)
            .set(\.$revokedAt, to: ctx.now).update()
    }
}

/// What the api validates of a business-mode destination at create (ADR-0021 section 3, ADR-0031 section 3). Every failure is a `422` about the business's own
/// input; none of it depends on the customer.
struct AuthDestinationCheck {
    let db: any Database
    let ctx: ServerContext

    struct Result: Sendable {
        var host: String
        var statement: String
        var url: String
    }

    func validate(_ destination: AuthDestinationRequest, request: AuthDeliveryCreateRequest, businessId: BusinessID, expiresAt: Date) async throws -> Result {
        switch destination.linkMode {
        case .viadere:
            // The link service needs the authority (Stage 6): refused, never approximated.
            throw APIError.validation("The Viadere link service is not available yet.", details: ["destination.link_mode": "unavailable"])
        case .business:
            break
        }
        guard destination.linkClientId == nil, destination.returnUrl == nil, destination.codeChallenge == nil, destination.codeChallengeMethod == nil else {
            throw APIError.validation("Link-service members are not allowed in business mode.", details: ["destination": "invalid"])
        }
        guard let url = destination.url else { throw APIError.validation("destination.url is required.", details: ["destination.url": "required"]) }
        let required = ctx.config.authDelivery.destinationSignatureRequired
        // 1. The URL: strict https on exactly a host of the tenant's allow-list.
        let hosts = try await AuthDestinationHosts(db: db, ctx: ctx).allowed(businessId: businessId.uuid)
        let parsed: AuthDestination
        do { parsed = try AuthDestinationValidator.validate(url, allowedHosts: hosts) } catch {
            throw APIError(.unprocessableEntity, .destinationNotAllowed, "The destination is not on a website your business verified for sign-in links.",
                           details: ["destination.url": error.rawValue])
        }
        guard required else { return Result(host: parsed.host, statement: destination.signature ?? "", url: url) }
        guard let signature = destination.signature, !signature.isEmpty else { throw Self.signatureRequired("missing") }
        // 2. The business-signed statement: shape, then a key from the authority-published record. No key known = fail closed.
        let tenant = WebhookService(db: db, ctx: ctx).tenantId(of: businessId)
        let parsedStatement: AuthDestinationStatement.Parsed
        do { parsedStatement = try AuthDestinationStatement.parse(signature) } catch { throw Self.signatureRequired(error.rawValue) }
        let statement = parsedStatement.statement
        let keys = await ctx.tenantDestinationKeys.activeKeys(tenantId: tenant)
        guard let entry = keys[statement.kid] else { throw Self.signatureRequired(keys.isEmpty ? "no_active_key" : "unknown_key") }
        if let notAfter = entry.notAfter, notAfter <= ctx.now { throw Self.signatureRequired("key_expired") }
        do { try parsedStatement.verifySignature(with: entry.key) } catch { throw Self.signatureRequired("bad_signature") }
        // 3. Bindings (the device repeats every one of these itself).
        let now = Int64(ctx.now.timeIntervalSince1970)
        guard statement.tenantId == tenant, statement.requestId == request.requestId, statement.purpose == request.purpose, statement.subjectRef == request.subjectRef,
              statement.host == parsed.host, statement.urlSHA256 == AuthDestinationStatement.digest(of: url),
              statement.issuedAt <= now + AuthDestinationStatement.skew, statement.expiresAt + AuthDestinationStatement.skew >= now,
              statement.expiresAt <= Int64(expiresAt.timeIntervalSince1970) + AuthDestinationStatement.skew else { throw Self.signatureRequired("binding") }
        // The statement is single use at the api too.
        guard try await DatabaseReplayGuard(db: db).registerIfFresh(nonce: statement.jti, scope: "auth-destination:\(businessId.description)",
                                                                    expiresAt: Date(timeIntervalSince1970: TimeInterval(statement.expiresAt + 60)), now: ctx.now) else {
            throw Self.signatureRequired("replayed")
        }
        return Result(host: parsed.host, statement: signature, url: url)
    }

    static func signatureRequired(_ reason: String) -> APIError {
        APIError(.unprocessableEntity, .destinationSignatureRequired, "A valid business-signed destination statement is required for sign-in links.",
                 details: ["destination.signature": reason])
    }
}
