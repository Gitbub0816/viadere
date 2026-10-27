import Fluent
import FluentSQL
import Foundation
import SQLKit
import ViadereCore

/// Publishing into the business key directory (ADR-07, SEC-CR-006).
///
/// Viadere is a **notary, not a key custodian**: the business generates its root key and signs every statement itself. The server checks the
/// signatures and the rules (`BusinessKeyState`) before logging an entry, serializes publishes per business under the log's lock so the log can
/// never contain an entry that breaks a business's history, and signs the new tree head. Devices and the business's monitor re-verify
/// everything; the server's checks only keep garbage out of an append-only log.
struct KeyDirectoryService {
    let db: any Database
    let ctx: ServerContext

    func publish(principal: BusinessPrincipal, request: PublishKeyEntryRequest) async throws -> PublishKeyEntryResponse {
        // Test keys never write to the production log.
        guard principal.livemode else { throw APIError(.forbidden, .forbidden, "Test-mode keys cannot publish to the key directory.") }
        try await ctx.limiter.enforce("kd-publish", key: principal.businessId.description, rule: ctx.config.approve.publishRate)
        guard request.entry.utf8.count <= KeyLogEntry.maxBytes * 4 / 3 + 4, let bytes = Base64URL.decode(request.entry), bytes.count <= KeyLogEntry.maxBytes else {
            throw APIError.validation("The entry is not valid base64url or is too large.", details: ["entry": "invalid"])
        }
        let entry: KeyLogEntry
        let statement: KeyStatement
        do {
            entry = try KeyLogEntry.parse(bytes)
            statement = try entry.decodeStatement()
        } catch {
            throw Self.validation(error)
        }
        guard entry.businessId == principal.businessId else { throw APIError.validation("The entry is for another business.", details: ["reason": "wrong_business"]) }
        let now = ctx.now
        try Self.sanity(statement, now: now)

        let log = KeyLogService(db: db, ctx: ctx)
        let leaf = MerkleTree.leafHash(bytes)
        let index: Int
        do {
            index = try await DB.retryingTransient {
                try await db.transaction { tx in
                    // One writer at a time: the entry is validated against the business's history *inside* the lock, so two racing publishes cannot
                    // both be valid against the same state and then break it together.
                    if DB.isPostgres(tx), let sql = tx as? any SQLDatabase { try await sql.raw("SELECT pg_advisory_xact_lock(746175)").run() }
                    let txLog = KeyLogService(db: tx, ctx: ctx)
                    var state = try await txLog.state(for: principal.businessId.uuid)
                    guard try await txLog.count(for: principal.businessId.uuid) < KeyLogService.maxEntriesPerBusiness else {
                        throw APIError.conflict("The key directory entry limit for this business was reached.")
                    }
                    let next = try await KDLogEntryRecord.query(on: tx).count()
                    try state.apply(entry, index: next)
                    try await KDLogEntryRecord(idx: next, businessId: entry.businessId.uuid, entryType: entry.type, entry: Base64URL.encode(bytes),
                                               leafHash: Hex.encode(leaf), now: now).create(on: tx)
                    return next
                }
            }
        } catch let error as KeyDirectoryError {
            _ = try? await AuditService(db: db, ctx: ctx).record("keydirectory.entry_rejected", outcome: .denied, actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                                                                 businessId: principal.businessId, metadata: ["type": entry.type, "reason": String(describing: error).prefix(60).description])
            throw Self.validation(error)
        }
        let head = try await log.signHead(of: try await log.tree())
        var metadata = ["type": entry.type, "index": String(index)]
        switch statement {
        case .key(let key): metadata["kid"] = key.kid; metadata["purpose"] = key.purpose.rawValue
        case .revocation(let revocation): metadata["kid"] = revocation.kid
        case .root(let root): metadata["kid"] = root.rootKid
        case .succession(let succession): metadata["kid"] = succession.newRootKid
        }
        // A root registration or change is the event a business (and a security team) most wants to see.
        let action = entry.type == "root" ? "keydirectory.root_registered" : (entry.type == "root-succession" ? "keydirectory.root_changed" : "keydirectory.entry_published")
        _ = try await AuditService(db: db, ctx: ctx).record(action, actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                                                           businessId: principal.businessId, subjectType: "key_log", subjectId: String(index), metadata: metadata)
        return PublishKeyEntryResponse(index: index, treeSize: index + 1 > 0 ? (try await log.tree()).size : 0, sth: head)
    }

    /// Time sanity that the rules in `BusinessKeyState` deliberately leave to the caller's clock.
    static func sanity(_ statement: KeyStatement, now: Date) throws {
        let t = ViadereDate.unixSeconds(now)
        let day: Int64 = 86_400
        switch statement {
        case .root(let root): guard abs(root.createdAt - t) <= day else { throw APIError.validation("created_at is not current.", details: ["reason": "created_at"]) }
        case .succession(let succession): guard abs(succession.createdAt - t) <= day else { throw APIError.validation("created_at is not current.", details: ["reason": "created_at"]) }
        case .key(let key):
            guard key.notAfter > t else { throw APIError.validation("The key has already expired.", details: ["reason": "expired"]) }
            guard key.notBefore <= t + day else { throw APIError.validation("not_before is too far in the future.", details: ["reason": "not_before"]) }
        case .revocation(let revocation): guard abs(revocation.revokedAt - t) <= day else { throw APIError.validation("revoked_at is not current.", details: ["reason": "revoked_at"]) }
        }
    }

    static func validation(_ error: any Error) -> APIError {
        guard let error = error as? KeyDirectoryError else { return .validation("The entry could not be accepted.") }
        let reason: String
        switch error {
        case .malformed(let what): reason = "malformed_\(what)".replacingOccurrences(of: " ", with: "_")
        case .unsupportedVersion: reason = "unsupported_version"
        case .invalidSignature(let what): reason = "invalid_signature_\(what)".replacingOccurrences(of: " ", with: "_")
        case .invalidKey: reason = "invalid_key"
        case .wrongBusiness: reason = "wrong_business"
        case .noRoot: reason = "no_root"
        case .rootAlreadyRegistered: reason = "root_already_registered"
        case .rootMismatch: reason = "root_mismatch"
        case .serialOutOfOrder(let expected, _): reason = "serial_out_of_order_expected_\(expected)"
        case .unknownKey: reason = "unknown_key"
        case .duplicateKey: reason = "duplicate_key"
        case .invalidValidity: reason = "invalid_validity"
        default: reason = "rejected"
        }
        return .validation("The key directory entry was rejected.", details: ["reason": reason])
    }
}
