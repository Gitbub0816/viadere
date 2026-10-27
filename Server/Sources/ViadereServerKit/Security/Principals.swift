import Fluent
import Foundation
import Vapor
import ViadereCore

/// An authenticated consumer session (and, for device-signed routes, the verified device).
public struct ConsumerPrincipal: Authenticatable, Sendable {
    public let consumerId: ConsumerID
    public let tokenId: UUID
    public let familyId: UUID
    /// Present on `deviceSignedBearer` routes: the device whose signature was verified.
    public let deviceId: DeviceID?
}

/// An authenticated business API key. Every business query must be scoped to `businessId`.
public struct BusinessPrincipal: Authenticatable, Sendable {
    public let businessId: BusinessID
    public let keyId: UUID
    public let livemode: Bool
    public let scopes: Set<String>
    public let businessName: String
}

extension Request {
    var consumer: ConsumerPrincipal {
        get throws {
            guard let principal = auth.get(ConsumerPrincipal.self) else { throw APIError.unauthorized }
            return principal
        }
    }

    var business: BusinessPrincipal {
        get throws {
            guard let principal = auth.get(BusinessPrincipal.self) else { throw APIError.unauthorized }
            return principal
        }
    }

    var bearerToken: String? {
        guard let header = headers.first(name: .authorization) else { return nil }
        let parts = header.split(separator: " ", maxSplits: 1)
        guard parts.count == 2, parts[0].lowercased() == "bearer" else { return nil }
        let token = parts[1].trimmingCharacters(in: .whitespaces)
        return token.isEmpty ? nil : token
    }
}

/// `Authorization: Bearer <access token>` only (`AuthRequirement.bearer`).
struct BearerAuthMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        guard let token = request.bearerToken,
              let record = try await ConsumerTokenService.authenticate(accessToken: token, db: request.db, now: request.ctx.now),
              let id = record.id,
              let consumer = try await ConsumerRecord.find(record.consumerId, on: request.db), consumer.status == "active"
        else { throw APIError.unauthorized }
        request.auth.login(ConsumerPrincipal(consumerId: ConsumerID(record.consumerId), tokenId: id, familyId: record.familyId,
                                             deviceId: nil))
        return try await next.respond(to: request)
    }
}

/// Bearer **and** a `VIADERE-SIG-V1` device signature from a non-revoked device of the same consumer
/// (`AuthRequirement.deviceSignedBearer`). Verifies signature, clock skew, nonce freshness (DB-backed
/// replay guard), device ownership and revocation.
struct DeviceSignedBearerMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let ctx = request.ctx
        let db = request.db
        let now = ctx.now
        // 1. Bearer token.
        guard let token = request.bearerToken,
              let tokenRecord = try await ConsumerTokenService.authenticate(accessToken: token, db: db, now: now),
              let tokenId = tokenRecord.id else { throw APIError.unauthorized }
        // 2. Signature headers.
        let headers: SignedRequestHeaders
        do {
            headers = try SignedRequestHeaders(lookup: { request.headers.first(name: $0) })
        } catch {
            throw APIError.signatureInvalid
        }
        // 3. Device must exist, belong to the token's consumer and not be revoked.
        guard let device = try await DeviceRecord.find(headers.deviceId.uuid, on: db) else { throw APIError.signatureInvalid }
        guard device.revokedAt == nil else {
            _ = try? await AuditService(db: db, ctx: ctx).record("auth.revoked_device_rejected", outcome: .denied,
                actor: AuditActor(kind: .device, id: headers.deviceId.description), consumerId: ConsumerID(tokenRecord.consumerId))
            throw APIError(.unauthorized, .signatureInvalid, "This device has been revoked.")
        }
        guard device.consumerId == tokenRecord.consumerId else { throw APIError.forbidden }
        guard let keyRecord = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == headers.deviceId.uuid)
            .filter(\.$purpose == DeviceKeyPurpose.request.rawValue).first(),
              let publicKey = try? DevicePublicKey(base64URL: keyRecord.publicKey) else { throw APIError.signatureInvalid }
        // 4. Verify exactly what is on the request line, the body hash, skew and nonce freshness.
        let body = try await request.collectedBody(limit: ctx.config.maxBodyBytes)
        do {
            try await RequestVerifier().verify(method: request.method.rawValue, pathAndQuery: request.url.string, body: body,
                                               headers: headers, publicKey: publicKey, now: now,
                                               replayGuard: DatabaseReplayGuard(db: db))
        } catch let error as RequestVerificationError {
            switch error {
            case .clockSkew: throw APIError(.unauthorized, .clockSkew, "Request timestamp is outside the allowed window.")
            case .replayed:
                _ = try? await AuditService(db: db, ctx: ctx).record("auth.replay_rejected", outcome: .denied,
                    actor: AuditActor(kind: .device, id: headers.deviceId.description), consumerId: ConsumerID(tokenRecord.consumerId))
                throw APIError(.unauthorized, .replayDetected, "This request was already used.")
            default: throw APIError.signatureInvalid
            }
        }
        // 5. Rate limit per device after authentication.
        try await ctx.limiter.enforce("device", key: headers.deviceId.description, rule: ctx.config.rateLimits.device)
        if device.lastSeenAt == nil || now.timeIntervalSince(device.lastSeenAt ?? now) > 60 {
            try await DeviceRecord.query(on: db).filter(\.$id == headers.deviceId.uuid).set(\.$lastSeenAt, to: now).update()
        }
        request.auth.login(ConsumerPrincipal(consumerId: ConsumerID(tokenRecord.consumerId), tokenId: tokenId,
                                             familyId: tokenRecord.familyId, deviceId: headers.deviceId))
        return try await next.respond(to: request)
    }
}

/// Business API key authentication (`AuthRequirement.businessAPIKey`) with per-business rate limiting.
struct BusinessAPIKeyMiddleware: AsyncMiddleware {
    let requiredScope: String?

    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let ctx = request.ctx
        let db = request.db
        guard let token = request.bearerToken, BusinessAPIKeys.looksLikeKey(token) else { throw APIError.unauthorized }
        let hash = SecureToken.hash(token)
        let now = ctx.now
        guard let key = try await BusinessAPIKeyRecord.query(on: db).filter(\.$keyHash == hash).first(),
              SecureToken.matches(token, hash: key.keyHash), key.revokedAt == nil, (key.expiresAt ?? .distantFuture) > now,
              let business = try await BusinessRecord.find(key.businessId, on: db) else { throw APIError.unauthorized }
        // Suspended or revoked businesses lose API access immediately.
        guard business.isVerified else { throw APIError(.forbidden, .forbidden, "This business is not currently active.") }
        if let required = requiredScope, !key.scopeSet.contains(required) {
            throw APIError(.forbidden, .forbidden, "This API key does not have the required scope.")
        }
        try await ctx.limiter.enforce("business", key: business.id?.uuidString ?? "", rule: ctx.config.rateLimits.business)
        if key.lastUsedAt == nil || now.timeIntervalSince(key.lastUsedAt ?? now) > 300 {
            try await BusinessAPIKeyRecord.query(on: db).filter(\.$id == key.id!).set(\.$lastUsedAt, to: now).update()
        }
        request.auth.login(BusinessPrincipal(businessId: business.businessID, keyId: key.id ?? UUID(), livemode: key.livemode,
                                             scopes: key.scopeSet, businessName: business.displayName))
        return try await next.respond(to: request)
    }
}

extension Request {
    /// Collects the (size-limited) request body so it can be hashed for signature verification.
    func collectedBody(limit: Int) async throws -> Data {
        if body.data == nil {
            _ = try await body.collect(max: limit).get()
        }
        guard let buffer = body.data else { return Data() }
        guard buffer.readableBytes <= limit else { throw APIError(.payloadTooLarge, .badRequest, "Request body is too large.") }
        return Data(buffer.readableBytesView)
    }
}
