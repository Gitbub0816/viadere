import Fluent
import Foundation
import ViadereCore

/// Business API key format and lifecycle. Keys look like `vdk_live_<43 chars>`; only the SHA-256 is stored.
enum BusinessAPIKeys {
    static let livePrefix = "vdk_live_"
    static let testPrefix = "vdk_test_"

    enum Scope {
        static let interactionsWrite = "interactions:write"
        static let interactionsRead = "interactions:read"
        static let messagesWrite = "messages:write"
        static let statusesWrite = "statuses:write"
        static let webhooksManage = "webhooks:manage"
        static let rewardsWrite = "rewards:write"
        static let all: [String] = [interactionsWrite, interactionsRead, messagesWrite, statusesWrite, webhooksManage, rewardsWrite]
    }

    struct Issued {
        /// The full key, shown exactly once.
        let key: String
        let record: BusinessAPIKeyRecord
    }

    static func issue(businessId: UUID, name: String, live: Bool, scopes: [String], now: Date, expiresAt: Date? = nil,
                      on db: any Database) async throws -> Issued {
        let key = (live ? livePrefix : testPrefix) + SecureToken.generate(byteCount: 32)
        let record = BusinessAPIKeyRecord(businessId: businessId, keyHash: SecureToken.hash(key), prefix: live ? livePrefix : testPrefix,
                                          last4: String(key.suffix(4)), name: String(name.prefix(64)), scopes: scopes, now: now,
                                          expiresAt: expiresAt)
        try await record.create(on: db)
        return Issued(key: key, record: record)
    }

    static func looksLikeKey(_ token: String) -> Bool {
        (token.hasPrefix(livePrefix) || token.hasPrefix(testPrefix)) && token.count <= 80
    }
}

/// Consumer access/refresh token issuance with rotation and reuse detection.
struct ConsumerTokenService {
    static let accessPrefix = "vda_"
    static let refreshPrefix = "vdr_"

    let db: any Database
    let ctx: ServerContext

    struct IssuedSession {
        let accessToken: String
        let accessExpiresAt: Date
        let refreshToken: String
        let refreshExpiresAt: Date
    }

    /// Starts a new token family (after a passkey ceremony).
    func startSession(consumerId: UUID) async throws -> IssuedSession {
        try await issue(consumerId: consumerId, familyId: UUID())
    }

    private func issue(consumerId: UUID, familyId: UUID) async throws -> IssuedSession {
        let now = ctx.now
        let access = Self.accessPrefix + SecureToken.generate()
        let refresh = Self.refreshPrefix + SecureToken.generate()
        let accessExpiry = now.addingTimeInterval(ctx.config.accessTokenTTL)
        let refreshExpiry = now.addingTimeInterval(ctx.config.refreshTokenTTL)
        try await AccessTokenRecord(consumerId: consumerId, tokenHash: SecureToken.hash(access), familyId: familyId, now: now,
                                    expiresAt: accessExpiry).create(on: db)
        try await RefreshTokenRecord(consumerId: consumerId, tokenHash: SecureToken.hash(refresh), familyId: familyId, now: now,
                                     expiresAt: refreshExpiry).create(on: db)
        return IssuedSession(accessToken: access, accessExpiresAt: accessExpiry, refreshToken: refresh, refreshExpiresAt: refreshExpiry)
    }

    enum RefreshFailure: Error { case invalid, reuseDetected(consumerId: UUID, familyId: UUID) }

    /// Rotates a refresh token. A token that was already rotated indicates theft: the whole family is revoked.
    func rotate(refreshToken: String) async throws -> (consumerId: UUID, session: IssuedSession) {
        guard refreshToken.hasPrefix(Self.refreshPrefix), refreshToken.count <= 80,
              let record = try await RefreshTokenRecord.query(on: db).filter(\.$tokenHash == SecureToken.hash(refreshToken)).first(),
              let id = record.id else { throw RefreshFailure.invalid }
        let now = ctx.now
        if record.state == "revoked" { throw RefreshFailure.invalid }
        if record.state != "active" {
            // Reuse of an already-rotated token means it was copied: burn the whole family.
            try await revokeFamily(record.familyId, now: now)
            throw RefreshFailure.reuseDetected(consumerId: record.consumerId, familyId: record.familyId)
        }
        guard record.expiresAt > now else { throw RefreshFailure.invalid }
        // Atomically flip active -> used; only one concurrent rotation can win.
        guard try await DB.swap(db, table: RefreshTokenRecord.schema, id: id, column: "state", expected: "active", newValue: "used")
        else {
            try await revokeFamily(record.familyId, now: now)
            throw RefreshFailure.reuseDetected(consumerId: record.consumerId, familyId: record.familyId)
        }
        try await RefreshTokenRecord.query(on: db).filter(\.$id == id).set(\.$usedAt, to: now).update()
        // Revoke the access tokens of the previous generation; the new pair replaces them.
        try await AccessTokenRecord.query(on: db).filter(\.$familyId == record.familyId).filter(\.$revokedAt == nil)
            .set(\.$revokedAt, to: now).update()
        let session = try await issue(consumerId: record.consumerId, familyId: record.familyId)
        return (record.consumerId, session)
    }

    func revokeFamily(_ familyId: UUID, now: Date) async throws {
        try await AccessTokenRecord.query(on: db).filter(\.$familyId == familyId).filter(\.$revokedAt == nil)
            .set(\.$revokedAt, to: now).update()
        try await RefreshTokenRecord.query(on: db).filter(\.$familyId == familyId).set(\.$state, to: "revoked").update()
    }

    /// Revokes every session of a consumer (e.g. after suspicious activity).
    func revokeAll(consumerId: UUID, now: Date) async throws {
        try await AccessTokenRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$revokedAt == nil)
            .set(\.$revokedAt, to: now).update()
        try await RefreshTokenRecord.query(on: db).filter(\.$consumerId == consumerId).set(\.$state, to: "revoked").update()
    }

    /// Looks up a presented access token. Returns `nil` for unknown, expired or revoked tokens.
    static func authenticate(accessToken: String, db: any Database, now: Date) async throws -> AccessTokenRecord? {
        guard accessToken.hasPrefix(accessPrefix), accessToken.count <= 80 else { return nil }
        let hash = SecureToken.hash(accessToken)
        guard let record = try await AccessTokenRecord.query(on: db).filter(\.$tokenHash == hash).first() else { return nil }
        guard SecureToken.matches(accessToken, hash: record.tokenHash), record.revokedAt == nil, record.expiresAt > now else { return nil }
        return record
    }
}
