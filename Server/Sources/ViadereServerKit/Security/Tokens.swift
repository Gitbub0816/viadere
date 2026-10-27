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
///
/// A **family** is one signed-in session: the access and refresh tokens that descend from one passkey ceremony. Each family has a
/// `TokenFamilyRecord`, which (a) lets the session that was just created by a passkey ceremony enroll one device without a second
/// assertion, (b) binds the session to the device it enrolled so a stolen bearer token is useless without that device's key, and
/// (c) ties revocation together: revoking a family (logout elsewhere, refresh-token reuse) revokes the devices enrolled through it,
/// and revoking a device revokes the families bound to it.
struct ConsumerTokenService {
    static let accessPrefix = "vda_"
    static let refreshPrefix = "vdr_"
    /// A session created by a passkey ceremony may enroll one device, without a separate assertion, for this long.
    static let freshEnrollmentWindow: TimeInterval = 5 * 60

    let db: any Database
    let ctx: ServerContext

    struct IssuedSession {
        let accessToken: String
        let accessExpiresAt: Date
        let refreshToken: String
        let refreshExpiresAt: Date
        let familyId: UUID
    }

    /// Starts a new token family (after a passkey ceremony: `register` or `login`).
    func startSession(consumerId: UUID, origin: String = "login") async throws -> IssuedSession {
        let familyId = UUID()
        try await TokenFamilyRecord(id: familyId, consumerId: consumerId, origin: origin, now: ctx.now,
                                    enrollUntil: ctx.now.addingTimeInterval(Self.freshEnrollmentWindow)).create(on: db)
        return try await issue(consumerId: consumerId, familyId: familyId)
    }

    private func issue(consumerId: UUID, familyId: UUID) async throws -> IssuedSession {
        let now = ctx.now
        let access = Self.accessPrefix + SecureToken.generate()
        let refresh = Self.refreshPrefix + SecureToken.generate()
        var accessExpiry = now.addingTimeInterval(ctx.config.accessTokenTTL)
        var refreshExpiry = now.addingTimeInterval(ctx.config.refreshTokenTTL)
        // App Clip sessions are capped (7 days) however often they refresh.
        if let cap = try await TokenFamilyRecord.find(familyId, on: db)?.expiresAt {
            accessExpiry = min(accessExpiry, cap)
            refreshExpiry = min(refreshExpiry, cap)
        }
        try await AccessTokenRecord(consumerId: consumerId, tokenHash: SecureToken.hash(access), familyId: familyId, now: now,
                                    expiresAt: accessExpiry).create(on: db)
        try await RefreshTokenRecord(consumerId: consumerId, tokenHash: SecureToken.hash(refresh), familyId: familyId, now: now,
                                     expiresAt: refreshExpiry).create(on: db)
        return IssuedSession(accessToken: access, accessExpiresAt: accessExpiry, refreshToken: refresh, refreshExpiresAt: refreshExpiry,
                             familyId: familyId)
    }

    enum RefreshFailure: Error { case invalid, reuseDetected(consumerId: UUID, familyId: UUID) }

    /// Rotates a refresh token. A token that was already rotated indicates theft: the whole family is revoked, **and so are the
    /// devices that were enrolled through it** (a thief who enrolled a device from the stolen session loses it too).
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
        if let family = try await TokenFamilyRecord.find(record.familyId, on: db) {
            guard family.revokedAt == nil, (family.expiresAt ?? .distantFuture) > now else { throw RefreshFailure.invalid }
        }
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

    /// Revokes a session. With `cascadeToDevices` (the default) every device enrolled through it is revoked as well.
    func revokeFamily(_ familyId: UUID, now: Date, cascadeToDevices: Bool = true) async throws {
        try await AccessTokenRecord.query(on: db).filter(\.$familyId == familyId).filter(\.$revokedAt == nil)
            .set(\.$revokedAt, to: now).update()
        try await RefreshTokenRecord.query(on: db).filter(\.$familyId == familyId).set(\.$state, to: "revoked").update()
        if let family = try await TokenFamilyRecord.find(familyId, on: db) {
            if family.revokedAt == nil {
                try await TokenFamilyRecord.query(on: db).filter(\.$id == familyId).set(\.$revokedAt, to: now).update()
            }
            guard cascadeToDevices else { return }
            var deviceIds = try await DeviceRecord.query(on: db).filter(\.$familyId == familyId).filter(\.$revokedAt == nil).all().compactMap(\.id)
            if let bound = family.deviceId, !deviceIds.contains(bound) { deviceIds.append(bound) }
            try await DeviceLifecycle(db: db, ctx: ctx).revoke(deviceIds: deviceIds, now: now, cascadeToFamilies: false)
        } else if cascadeToDevices {
            let ids = try await DeviceRecord.query(on: db).filter(\.$familyId == familyId).filter(\.$revokedAt == nil).all().compactMap(\.id)
            try await DeviceLifecycle(db: db, ctx: ctx).revoke(deviceIds: ids, now: now, cascadeToFamilies: false)
        }
    }

    /// Revokes every session of a consumer (e.g. after suspicious activity).
    func revokeAll(consumerId: UUID, now: Date) async throws {
        try await AccessTokenRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$revokedAt == nil)
            .set(\.$revokedAt, to: now).update()
        try await RefreshTokenRecord.query(on: db).filter(\.$consumerId == consumerId).set(\.$state, to: "revoked").update()
        try await TokenFamilyRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$revokedAt == nil)
            .set(\.$revokedAt, to: now).update()
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

/// Device revocation, in one place so every path (user revoke, reuse detection, session revoke, account deletion, expiry)
/// removes the same things.
struct DeviceLifecycle {
    let db: any Database
    let ctx: ServerContext

    /// Marks devices revoked, drops their push tokens, and (by default) revokes the sessions bound to them.
    func revoke(deviceIds: [UUID], now: Date, cascadeToFamilies: Bool = true) async throws {
        guard !deviceIds.isEmpty else { return }
        try await DeviceRecord.query(on: db).filter(\.$id ~~ deviceIds).filter(\.$revokedAt == nil).set(\.$revokedAt, to: now).update()
        try await APNsTokenRecord.query(on: db).filter(\.$deviceId ~~ deviceIds).delete()
        try await LiveActivityTokenRecord.query(on: db).filter(\.$deviceId ~~ deviceIds).delete()
        guard cascadeToFamilies else { return }
        var familyIds = Set(try await TokenFamilyRecord.query(on: db).filter(\.$deviceId ~~ deviceIds).filter(\.$revokedAt == nil).all().compactMap(\.id))
        for device in try await DeviceRecord.query(on: db).filter(\.$id ~~ deviceIds).all() {
            if let family = device.familyId { familyIds.insert(family) }
        }
        let tokens = ConsumerTokenService(db: db, ctx: ctx)
        for family in familyIds { try await tokens.revokeFamily(family, now: now, cascadeToDevices: false) }
    }

    /// Revokes devices whose own lifetime has passed (App Clips after 7 days).
    @discardableResult
    func revokeExpired() async throws -> Int {
        let now = ctx.now
        let expired = try await DeviceRecord.query(on: db).filter(\.$revokedAt == nil).filter(\.$expiresAt != nil).filter(\.$expiresAt <= now).all()
        try await revoke(deviceIds: expired.compactMap(\.id), now: now)
        return expired.count
    }
}
