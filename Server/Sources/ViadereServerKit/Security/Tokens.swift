import Fluent
import Foundation
import ViadereCore

/// Business API key format and lifecycle (SEC-API-001..003).
///
/// New keys look like `vdk_live_<kid>.<secret>`: `kid` is a non-secret 16-hex key id (indexed, shown in the console and logs) and `secret` is
/// 256 bits from the CSPRNG (43 base64url characters), shown exactly once. Only the SHA-256 of the whole key is stored (the secret has 256 bits
/// of entropy, so a fast hash is a sound verifier). Keys issued before key ids existed (`vdk_live_<43 chars>`, no dot) have no `kid` and are
/// found by their hash exactly as before; they keep working until revoked or rotated.
enum BusinessAPIKeys {
    static let livePrefix = "vdk_live_"
    static let testPrefix = "vdk_test_"
    static let kidLength = 16

    enum Scope {
        static let interactionsWrite = "interactions:write"
        static let interactionsRead = "interactions:read"
        static let messagesWrite = "messages:write"
        static let statusesWrite = "statuses:write"
        static let webhooksManage = "webhooks:manage"
        static let rewardsWrite = "rewards:write"
        /// Approve v2 enrollments, requests, results and freezes (the approval capabilities are required as well).
        static let approvalsManage = "approvals:manage"
        /// Registers and rotates the business root key and publishes operational keys in the key directory. Issue it to a dedicated,
        /// tightly held key: whoever holds it before the business registered its root could register their own.
        static let keyDirectoryManage = "keydirectory:manage"
        static let all: [String] = [interactionsWrite, interactionsRead, messagesWrite, statusesWrite, webhooksManage, rewardsWrite, approvalsManage, keyDirectoryManage]
    }

    struct Issued {
        /// The full key, shown exactly once.
        let key: String
        let record: BusinessAPIKeyRecord
    }

    /// Restrictions fixed when a key is issued.
    struct Options {
        var expiresAt: Date?
        /// CIDR blocks (validated by the caller with `IPNetwork.parseList`); empty = anywhere.
        var ipAllowlist: [IPNetwork] = []
        var requiresMTLS = false
        var certBinding: UUID?
        var createdBy: UUID?
        var rotatedFrom: UUID?
        init(expiresAt: Date? = nil) { self.expiresAt = expiresAt }
    }

    /// `scopes` are the operational scopes of the key; `capabilities` are what it may ever do (SEC-API-003), bounded **at use time**
    /// by the business's entitlements. The default is Tier M (messaging) only: a key never carries approval or verification
    /// capabilities unless the caller names them, and the dashboard only offers what the business is entitled to.
    static func issue(businessId: UUID, name: String, live: Bool, scopes: [String], capabilities: [Capability] = Capability.messaging,
                      now: Date, expiresAt: Date? = nil, options: Options? = nil, on db: any Database) async throws -> Issued {
        var options = options ?? Options()
        if let expiresAt { options.expiresAt = expiresAt }
        let prefix = live ? livePrefix : testPrefix
        // A key id collision (2^-64 per pair) is retried against the unique index.
        for _ in 0..<5 {
            let kid = SecureToken.randomBytes(8).map { String(format: "%02x", $0) }.joined()
            let key = prefix + kid + "." + SecureToken.generate(byteCount: 32)
            let record = BusinessAPIKeyRecord(businessId: businessId, keyHash: SecureToken.hash(key), prefix: prefix, last4: String(key.suffix(4)),
                                              name: String(name.prefix(64)), scopes: scopes, capabilities: capabilities, now: now, expiresAt: options.expiresAt)
            record.kid = kid
            record.ipAllowlist = options.ipAllowlist.isEmpty ? nil : options.ipAllowlist.map(\.description).joined(separator: ",")
            record.requiresMTLS = options.requiresMTLS
            record.certBinding = options.certBinding
            record.createdBy = options.createdBy
            record.rotatedFrom = options.rotatedFrom
            do {
                try await record.create(on: db)
                return Issued(key: key, record: record)
            } catch {
                if error.isConstraintViolation { continue }
                throw error
            }
        }
        throw APIError.internalError
    }

    /// `(prefix, kid or nil, whole token)` for a well-formed key, else `nil`.
    struct Parsed {
        var prefix: String
        var kid: String?
        var token: String
    }

    static func parse(_ token: String) -> Parsed? {
        guard token.count <= 80 else { return nil }
        for prefix in [livePrefix, testPrefix] where token.hasPrefix(prefix) {
            let rest = token.dropFirst(prefix.count)
            guard !rest.isEmpty, rest.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" || $0 == ".") }) else { return nil }
            if let dot = rest.firstIndex(of: ".") {
                let kid = String(rest[rest.startIndex..<dot])
                let secret = rest[rest.index(after: dot)...]
                guard kid.count == kidLength, kid.allSatisfy(\.isHexDigit), secret.count == 43, !secret.contains(".") else { return nil }
                return Parsed(prefix: prefix, kid: kid, token: token)
            }
            return Parsed(prefix: prefix, kid: nil, token: token)
        }
        return nil
    }

    static func looksLikeKey(_ token: String) -> Bool { parse(token) != nil }

    /// The key record a presented token names, **after** the secret was verified in constant time. Does not check revocation or expiry.
    static func record(for parsed: Parsed, on db: any Database) async throws -> BusinessAPIKeyRecord? {
        let hash = SecureToken.hash(parsed.token)
        let found: BusinessAPIKeyRecord?
        if let kid = parsed.kid {
            found = try await BusinessAPIKeyRecord.query(on: db).filter(\.$kid == kid).first()
        } else {
            found = try await BusinessAPIKeyRecord.query(on: db).filter(\.$keyHash == hash).first()
        }
        guard let found, SecureToken.matches(parsed.token, hash: found.keyHash), found.prefix == parsed.prefix else { return nil }
        return found
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

    /// For this long after a refresh token was rotated, presenting it again returns the **same** new pair (idempotent): a response that
    /// was lost on the wire, or the app and an extension racing with the same token, is not theft. Afterwards it is reuse.
    static let graceWindow: TimeInterval = 60

    /// Which devices a revoked session takes with it.
    enum DeviceCascade {
        /// Every device enrolled through the session, and the one it is bound to (a user revoking a session).
        case all
        /// None: the session ends, the devices stay (logout).
        case none
        /// Only devices enrolled through the session after `Date` (refresh-token reuse: what a thief with the copied token could have
        /// added), not the device the session belonged to before the token was copied.
        case enrolledAfter(Date)
    }

    private struct SealedSession: Codable {
        var accessToken: String
        var accessExpiresAt: Date
        var refreshToken: String
        var refreshExpiresAt: Date
        var familyId: UUID
    }

    private struct RotationLost: Error {}

    struct Rotation {
        var consumerId: UUID
        var session: IssuedSession
        /// True when this was the idempotent replay of a token rotated moments ago.
        var replayed: Bool
    }

    /// The session record of a family, created on first sight for a legacy family (tokens from before families existed), optionally
    /// bound to `deviceId`. Without it a legacy session could never be bound to a device or marked revoked.
    @discardableResult
    func ensureFamily(_ familyId: UUID, consumerId: UUID, deviceId: UUID? = nil) async throws -> TokenFamilyRecord {
        if let existing = try await TokenFamilyRecord.find(familyId, on: db) { return existing }
        let legacy = TokenFamilyRecord(id: familyId, consumerId: consumerId, origin: "legacy", now: ctx.now, enrollUntil: nil)
        legacy.deviceId = deviceId
        do {
            try await legacy.create(on: db)
            return legacy
        } catch {
            if error.isConstraintViolation, let existing = try await TokenFamilyRecord.find(familyId, on: db) { return existing }
            throw error
        }
    }

    /// Rotates a refresh token.
    ///
    /// * An expired token is simply invalid (checked first: an old token is not evidence of theft).
    /// * A token rotated less than `graceWindow` ago returns the pair it was rotated into.
    /// * A token rotated earlier indicates theft: the family is revoked, **and so are the devices enrolled through it after that token
    ///   was issued** (what a thief could have added), not the device the session already belonged to.
    func rotate(refreshToken: String) async throws -> Rotation {
        guard refreshToken.hasPrefix(Self.refreshPrefix), refreshToken.count <= 80,
              let record = try await RefreshTokenRecord.query(on: db).filter(\.$tokenHash == SecureToken.hash(refreshToken)).first(),
              record.id != nil else { throw RefreshFailure.invalid }
        let now = ctx.now
        if record.state == "revoked" { throw RefreshFailure.invalid }
        guard record.expiresAt > now else { throw RefreshFailure.invalid }
        let family = try await ensureFamily(record.familyId, consumerId: record.consumerId)
        guard family.revokedAt == nil, (family.expiresAt ?? .distantFuture) > now else { throw RefreshFailure.invalid }
        if record.state != "active" { return try await usedToken(record, now: now) }
        do {
            let session = try await db.transaction { tx -> IssuedSession in
                // Atomically flip active -> used; only one concurrent rotation can win (the loser's UPDATE matches nothing).
                guard try await DB.swap(tx, table: RefreshTokenRecord.schema, id: record.id!, column: "state", expected: "active", newValue: "used")
                else { throw RotationLost() }
                // Revoke the access tokens of the previous generation; the new pair replaces them.
                try await AccessTokenRecord.query(on: tx).filter(\.$familyId == record.familyId).filter(\.$revokedAt == nil)
                    .set(\.$revokedAt, to: now).update()
                let issued = try await ConsumerTokenService(db: tx, ctx: ctx).issue(consumerId: record.consumerId, familyId: record.familyId)
                let sealed = SealedSession(accessToken: issued.accessToken, accessExpiresAt: issued.accessExpiresAt, refreshToken: issued.refreshToken,
                                           refreshExpiresAt: issued.refreshExpiresAt, familyId: issued.familyId)
                try await RefreshTokenRecord.query(on: tx).filter(\.$id == record.id!).set(\.$usedAt, to: now)
                    .set(\.$successorSealed, to: try ctx.cipher.seal(try JSONEncoder().encode(sealed), context: "refresh_tokens.successor", rowId: record.id!)).update()
                // Older generations' sealed successors are past their grace window: wipe them.
                try await RefreshTokenRecord.query(on: tx).filter(\.$familyId == record.familyId).filter(\.$state == "used")
                    .filter(\.$usedAt < now.addingTimeInterval(-Self.graceWindow)).set(\.$successorSealed, to: nil).update()
                return issued
            }
            return Rotation(consumerId: record.consumerId, session: session, replayed: false)
        } catch is RotationLost {
            // A concurrent request rotated the same token first: treat ours as the replay it is.
            guard let fresh = try await RefreshTokenRecord.find(record.id!, on: db) else { throw RefreshFailure.invalid }
            if fresh.state == "revoked" { throw RefreshFailure.invalid }
            return try await usedToken(fresh, now: now)
        }
    }

    /// A refresh token that is no longer active: the idempotent replay inside the grace window, otherwise reuse.
    private func usedToken(_ record: RefreshTokenRecord, now: Date) async throws -> Rotation {
        if let usedAt = record.usedAt, now >= usedAt, now.timeIntervalSince(usedAt) <= Self.graceWindow, let sealed = record.successorSealed,
           let data = try? ctx.cipher.open(sealed, context: "refresh_tokens.successor", rowId: record.id!),
           let pair = try? JSONDecoder().decode(SealedSession.self, from: data) {
            return Rotation(consumerId: record.consumerId, session: IssuedSession(
                accessToken: pair.accessToken, accessExpiresAt: pair.accessExpiresAt, refreshToken: pair.refreshToken,
                refreshExpiresAt: pair.refreshExpiresAt, familyId: pair.familyId), replayed: true)
        }
        // Reuse of an already-rotated token means it was copied: burn the family and what was enrolled through it since.
        try await revokeFamily(record.familyId, now: now, devices: .enrolledAfter(record.createdAt))
        throw RefreshFailure.reuseDetected(consumerId: record.consumerId, familyId: record.familyId)
    }

    /// Revokes a session. `devices` says which devices go with it (default: every device enrolled through it).
    func revokeFamily(_ familyId: UUID, now: Date, devices: DeviceCascade = .all) async throws {
        try await AccessTokenRecord.query(on: db).filter(\.$familyId == familyId).filter(\.$revokedAt == nil)
            .set(\.$revokedAt, to: now).update()
        try await RefreshTokenRecord.query(on: db).filter(\.$familyId == familyId).set(\.$state, to: "revoked").set(\.$successorSealed, to: nil).update()
        let family = try await TokenFamilyRecord.find(familyId, on: db)
        if let family, family.revokedAt == nil {
            try await TokenFamilyRecord.query(on: db).filter(\.$id == familyId).set(\.$revokedAt, to: now).update()
        }
        var deviceIds: [UUID]
        switch devices {
        case .none: return
        case .all:
            deviceIds = try await DeviceRecord.query(on: db).filter(\.$familyId == familyId).filter(\.$revokedAt == nil).all().compactMap(\.id)
            if let bound = family?.deviceId, !deviceIds.contains(bound) { deviceIds.append(bound) }
        case .enrolledAfter(let date):
            deviceIds = try await DeviceRecord.query(on: db).filter(\.$familyId == familyId).filter(\.$revokedAt == nil)
                .filter(\.$createdAt >= date).all().compactMap(\.id)
        }
        try await DeviceLifecycle(db: db, ctx: ctx).revoke(deviceIds: deviceIds, now: now, cascadeToFamilies: false)
    }

    /// Revokes every session of a consumer (e.g. after suspicious activity).
    func revokeAll(consumerId: UUID, now: Date) async throws {
        try await AccessTokenRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$revokedAt == nil)
            .set(\.$revokedAt, to: now).update()
        try await RefreshTokenRecord.query(on: db).filter(\.$consumerId == consumerId).set(\.$state, to: "revoked").set(\.$successorSealed, to: nil).update()
        try await TokenFamilyRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$revokedAt == nil)
            .set(\.$revokedAt, to: now).update()
    }

    /// The token record for a presented access token whatever its state (revoked and expired included). Never an authentication.
    static func lookup(accessToken: String, db: any Database) async throws -> AccessTokenRecord? {
        guard accessToken.hasPrefix(accessPrefix), accessToken.count <= 80 else { return nil }
        return try await AccessTokenRecord.query(on: db).filter(\.$tokenHash == SecureToken.hash(accessToken)).first()
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

    /// Marks devices revoked, drops their push tokens, and (by default) revokes the sessions bound to them, except `keepFamily` (the
    /// session of the caller that is replacing a device: it moves to the new device instead of ending).
    func revoke(deviceIds: [UUID], now: Date, cascadeToFamilies: Bool = true, keepFamily: UUID? = nil) async throws {
        guard !deviceIds.isEmpty else { return }
        try await DeviceRecord.query(on: db).filter(\.$id ~~ deviceIds).filter(\.$revokedAt == nil).set(\.$revokedAt, to: now).update()
        try await APNsTokenRecord.query(on: db).filter(\.$deviceId ~~ deviceIds).delete()
        try await LiveActivityTokenRecord.query(on: db).filter(\.$deviceId ~~ deviceIds).delete()
        // Approval keys live and die with their device: a lost, replaced or expired device leaves no usable key behind (acceptance 7).
        try await ApproveKeyService(db: db, ctx: ctx).revokeKeys(where: .devices(deviceIds), reason: "device_revoked")
        guard cascadeToFamilies else { return }
        var familyIds = Set(try await TokenFamilyRecord.query(on: db).filter(\.$deviceId ~~ deviceIds).filter(\.$revokedAt == nil).all().compactMap(\.id))
        for device in try await DeviceRecord.query(on: db).filter(\.$id ~~ deviceIds).all() {
            if let family = device.familyId { familyIds.insert(family) }
        }
        let tokens = ConsumerTokenService(db: db, ctx: ctx)
        familyIds.remove(keepFamily ?? UUID())
        for family in familyIds { try await tokens.revokeFamily(family, now: now, devices: .none) }
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
