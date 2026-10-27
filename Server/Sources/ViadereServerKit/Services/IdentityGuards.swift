import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore

/// What a handler needs to verify a `VIADERE-SIG-V1` signature on a request whose route has no bearer token (`auth/refresh`).
struct SignedRequestContext: Sendable {
    var method: String
    var pathAndQuery: String
    var body: Data
    var headers: HTTPHeaders

    init(_ request: Request) {
        method = request.method.rawValue
        pathAndQuery = request.url.string
        body = request.bodyBytes
        headers = request.headers
    }

    init(method: String, pathAndQuery: String, body: Data, headers: HTTPHeaders) {
        self.method = method
        self.pathAndQuery = pathAndQuery
        self.body = body
        self.headers = headers
    }
}

extension AuthService {
    /// A refresh token whose session is bound to a device is honoured only with that device's `VIADERE-SIG-V1` signature over this
    /// exact request (the 60 s grace replay included). A session that never bound a device (fresh passkey sign-in, a legacy family)
    /// refreshes without one until it binds. Nothing is changed before the signature verifies, so a thief holding a copied token can
    /// neither obtain the grace pair nor trip reuse detection against the owner.
    func requireBoundDeviceSignature(refreshToken: String, http: SignedRequestContext) async throws {
        guard refreshToken.hasPrefix(ConsumerTokenService.refreshPrefix), refreshToken.count <= 80,
              let record = try await RefreshTokenRecord.query(on: db).filter(\.$tokenHash == SecureToken.hash(refreshToken)).first(),
              let family = try await TokenFamilyRecord.find(record.familyId, on: db), let bound = family.deviceId else { return }
        let consumer = ConsumerID(record.consumerId)
        func denied(_ reason: String) async -> APIError {
            _ = try? await AuditService(db: db, ctx: ctx).record("auth.refresh_unsigned", outcome: .denied, actor: AuditActor(kind: .system),
                consumerId: consumer, subjectType: "token_family", subjectId: record.familyId.uuidString.lowercased(), metadata: ["reason": reason])
            return APIError(.unauthorized, .signatureInvalid, "This session can only be refreshed by the device it belongs to.")
        }
        let headers: SignedRequestHeaders
        do { headers = try SignedRequestHeaders(lookup: { http.headers.first(name: $0) }) } catch { throw await denied("missing_signature") }
        guard headers.deviceId.uuid == bound else { throw await denied("wrong_device") }
        guard let device = try await DeviceRecord.find(bound, on: db), device.revokedAt == nil, device.consumerId == record.consumerId,
              let keyRecord = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == bound)
                  .filter(\.$purpose == DeviceKeyPurpose.request.rawValue).first(),
              let publicKey = try? DevicePublicKey(base64URL: keyRecord.publicKey) else { throw await denied("device_unavailable") }
        do {
            try await RequestVerifier().verify(method: http.method, pathAndQuery: http.pathAndQuery, body: http.body, headers: headers,
                                               publicKey: publicKey, now: ctx.now, replayGuard: DatabaseReplayGuard(db: db))
        } catch let error as RequestVerificationError {
            switch error {
            case .clockSkew: throw APIError(.unauthorized, .clockSkew, "Request timestamp is outside the allowed window.")
            case .replayed: throw APIError(.unauthorized, .replayDetected, "This request was already used.")
            default: throw await denied("bad_signature")
            }
        }
    }

    /// "Not you? Cancel" on a pending replacement: revokes the NEW device and leaves the old one (and its sessions) untouched. A trusted
    /// device other than the new one must sign it, normally the device being replaced.
    func cancelReplacement(_ principal: ConsumerPrincipal, newDeviceId: DeviceID) async throws {
        try await ctx.limiter.enforce("replacement-cancel", key: principal.consumerId.description, rule: .perHour(30, burst: 10))
        let now = ctx.now
        let caller = try await DeviceTrust.require(principal, db: db, now: now)
        guard caller.id != newDeviceId.uuid else { throw APIError.forbidden }
        guard let new = try await DeviceRecord.query(on: db).filter(\.$id == newDeviceId.uuid)
            .filter(\.$consumerId == principal.consumerId.uuid).first(), new.revokedAt == nil else { throw APIError.notFound }
        let waiting = try await DeviceRecord.query(on: db).filter(\.$pendingReplacementBy == newDeviceId.uuid).filter(\.$revokedAt == nil).all()
        guard !waiting.isEmpty else { throw APIError.conflict("No replacement is pending for this device.") }
        try await db.transaction { tx in
            try await DeviceLifecycle(db: tx, ctx: ctx).revoke(deviceIds: [newDeviceId.uuid], now: now)
            try await DeviceRecord.query(on: tx).filter(\.$pendingReplacementBy == newDeviceId.uuid).set(\.$pendingReplacementBy, to: nil).update()
            _ = try await AuditService(db: tx, ctx: ctx).record("device.replacement_cancelled", principal: principal, subjectType: "device",
                subjectId: newDeviceId.description, metadata: ["replaced": waiting.compactMap(\.id).map { DeviceID($0).description }.joined(separator: ",")])
        }
        await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(of: principal.consumerId.uuid, except: caller.id, notice: .replacementCancelled,
                                                                  subjectId: newDeviceId.description)
    }
}

/// Time-driven identity work, run by the background jobs (and lazily where a request would otherwise see stale state): completing
/// "Set up again" replacements, activating or expiring account recoveries, and purging one-time secrets that outlived their use.
struct IdentityMaintenance {
    let db: any Database
    let ctx: ServerContext

    func run() async throws {
        try await finalizeDueReplacements()
        try await RecoveryService(db: db, ctx: ctx).sweep()
        if await ctx.limiter.allow("idempotency-purge", key: "all", rule: .perMinute(1, burst: 1)) {
            try await BusinessIdempotency(db: db, ctx: ctx).purge()
        }
    }

    /// Completes every replacement whose new device is confirmed or out of its cool-down.
    func finalizeDueReplacements() async throws {
        let waiting = try await DeviceRecord.query(on: db).filter(\.$revokedAt == nil).filter(\.$pendingReplacementBy != nil).limit(200).all()
        for old in waiting { _ = try await finalizeIfDue(old) }
    }

    func finalizeReplacements(forNewDevice newId: UUID) async throws {
        let waiting = try await DeviceRecord.query(on: db).filter(\.$pendingReplacementBy == newId).filter(\.$revokedAt == nil).all()
        for old in waiting { _ = try await finalizeIfDue(old) }
    }

    /// Revokes `old` (and the sessions bound to it) if the device replacing it is confirmed or past its cool-down. Returns true when it
    /// did. If the new device is gone (revoked), the replacement is simply abandoned and the old device stays.
    @discardableResult
    func finalizeIfDue(_ old: DeviceRecord) async throws -> Bool {
        guard old.revokedAt == nil, let newId = old.pendingReplacementBy, let oldId = old.id else { return false }
        let now = ctx.now
        guard let new = try await DeviceRecord.find(newId, on: db), new.revokedAt == nil, !new.isExpired(at: now) else {
            try await DeviceRecord.query(on: db).filter(\.$id == oldId).set(\.$pendingReplacementBy, to: nil).update()
            _ = try? await AuditService(db: db, ctx: ctx).record("device.replacement_abandoned", actor: AuditActor(kind: .system),
                consumerId: ConsumerID(old.consumerId), subjectType: "device", subjectId: DeviceID(oldId).description)
            return false
        }
        if new.isCoolingDown(at: now) { return false }
        // Compare-and-swap on the pending marker inside the transaction, so concurrent callers complete it once and the marker never
        // clears without the old device being revoked.
        do {
            try await db.transaction { tx in
                guard try await DB.swap(tx, table: DeviceRecord.schema, id: oldId, column: "pending_replacement_by", expected: newId,
                                        newValue: Optional<UUID>.none) else { throw ConcurrencyConflict() }
                try await DeviceLifecycle(db: tx, ctx: ctx).revoke(deviceIds: [oldId], now: now)
                _ = try await AuditService(db: tx, ctx: ctx).record("device.replaced", actor: AuditActor(kind: .system),
                    consumerId: ConsumerID(old.consumerId), subjectType: "device", subjectId: DeviceID(oldId).description,
                    metadata: ["new_device": DeviceID(newId).description, "mode": "pending_completed"])
            }
        } catch is ConcurrencyConflict {
            return false
        }
        await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(of: old.consumerId, except: newId, notice: .deviceReplaced,
                                                                  subjectId: DeviceID(newId).description)
        return true
    }
}

/// App Attest assertions for devices that were attested at enrollment: verifies the signature with the stored key and advances the
/// per-key counter with a compare-and-swap, so a replayed or out-of-order assertion can never be accepted twice.
struct AppAttestAssertions {
    let db: any Database
    let ctx: ServerContext

    /// Throws `401 signature_invalid` unless `assertion` verifies for this device's attested key over `clientData` with a counter
    /// above the stored one; `403` if the device has no attested key.
    func verify(deviceId: UUID, assertion: Data, clientData: Data) async throws {
        guard let key = try await AppAttestKeyRecord.query(on: db).filter(\.$deviceId == deviceId).first(), let keyId = key.id,
              let publicKey = Base64URL.decode(key.publicKey), let device = try await DeviceRecord.find(deviceId, on: db), device.revokedAt == nil else {
            throw APIError.forbidden
        }
        let denied = APIError(.unauthorized, .signatureInvalid, "The device integrity check failed.")
        let counter: Int
        do {
            counter = try ctx.integrity.verifyAssertion(assertion, clientData: clientData, publicKeyX963: publicKey, storedCounter: key.counter, clientKind: device.kind)
        } catch {
            _ = try? await AuditService(db: db, ctx: ctx).record("device.assertion_failed", outcome: .denied, actor: AuditActor(kind: .device, id: DeviceID(deviceId).description),
                consumerId: ConsumerID(device.consumerId), metadata: ["reason": (error as? AppAttestFailure)?.rawValue ?? "invalid"])
            throw denied
        }
        guard try await DB.swap(db, table: AppAttestKeyRecord.schema, id: keyId, column: "counter", expected: key.counter, newValue: counter,
                                extra: [("last_assertion_at", ctx.now)]) else { throw denied }
    }
}
