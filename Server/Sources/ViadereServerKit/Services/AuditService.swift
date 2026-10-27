import Fluent
import FluentSQL
@preconcurrency import Crypto
import Foundation
import SQLKit
import ViadereCore

/// Redacts audit metadata: secrets and free text are dropped, phone numbers masked, values length-capped.
enum AuditRedactor {
    static let sensitiveKeyFragments = ["token", "secret", "otp", "password", "signature", "body", "text", "message", "reply",
                                        "authorization", "challenge", "apikey", "api_key", "key", "code", "credential"]

    static func redact(_ metadata: [String: String]) -> [String: String] {
        var out: [String: String] = [:]
        for (key, value) in metadata.prefix(32) {
            let lowered = key.lowercased()
            if lowered.hasSuffix("id") || lowered == "state" || lowered == "reason" || lowered == "keyword_class" {
                out[key] = redactValue(value)
            } else if sensitiveKeyFragments.contains(where: { lowered.contains($0) }) {
                out[key] = "[redacted]"
            } else {
                out[key] = redactValue(value)
            }
        }
        return out
    }

    static func redactValue(_ value: String) -> String {
        LogRedactor.redact(String(value.prefix(200)))
    }
}

/// Appends to the hash-chained audit log. Each event's hash covers the previous event's hash and the
/// canonical JSON of the event, so any later modification or deletion breaks the chain.
///
/// **Keyed chain (version 2).** An unkeyed hash chain only detects edits by someone who cannot recompute it; a database writer can.
/// Version 2 events are `HMAC-SHA256(AUDIT_CHAIN_KEY, canonical JSON)` and the row id is part of the hashed content, so rewriting the
/// chain needs a key that is not in the database. Version 1 (legacy, unkeyed) events are accepted only up to `AUDIT_CHAIN_LEGACY_THROUGH_SEQ` (default none), so the chain cannot be downgraded.
/// For tamper evidence against someone who also holds the key, export the head periodically to external write-once storage
/// (`ViadereServer audit-head`).
struct AuditService {
    let db: any Database
    let ctx: ServerContext

    static let genesisHash = String(repeating: "0", count: 64)

    @discardableResult
    func record(_ action: String, outcome: AuditEvent.Outcome = .success, actor: AuditActor, consumerId: ConsumerID? = nil,
                businessId: BusinessID? = nil, subjectType: String? = nil, subjectId: String? = nil,
                correlationId: String? = nil, metadata: [String: String] = [:]) async throws -> AuditEventRecord {
        let now = ctx.now
        let redacted = AuditRedactor.redact(metadata)
        let metadataJSON = String(decoding: try CanonicalJSON.serialize(.object(redacted.mapValues { .string($0) })), as: UTF8.self)
        var lastError: (any Error)?
        for _ in 0..<8 {
            do {
                return try await db.transaction { tx in
                    if DB.isPostgres(tx), let sql = tx as? any SQLDatabase {
                        // Serialize appenders so the chain has no forks.
                        try await sql.raw("SELECT pg_advisory_xact_lock(746172)").run()
                    }
                    let head = try await AuditEventRecord.query(on: tx).sort(\.$seq, .descending).first()
                    let record = AuditEventRecord()
                    record.id = UUID()
                    record.seq = (head?.seq ?? 0) + 1
                    record.occurredAt = ViadereDate.truncatedToMilliseconds(now)
                    record.actorKind = actor.kind.rawValue
                    record.actorId = actor.id
                    record.action = action
                    record.outcome = outcome.rawValue
                    record.consumerId = consumerId?.uuid
                    record.businessId = businessId?.uuid
                    record.subjectType = subjectType
                    record.subjectId = subjectId
                    record.correlationId = correlationId
                    record.metadataJSON = metadataJSON
                    record.prevHash = head?.hash ?? Self.genesisHash
                    record.chainVersion = 2
                    record.hash = try Self.hash(of: record, key: ctx.config.auditChainKey)
                    try await record.create(on: tx)
                    return record
                }
            } catch {
                if error.isConstraintViolation { lastError = error; continue }
                throw error
            }
        }
        throw lastError ?? APIError.internalError
    }

    /// Convenience for request handlers.
    @discardableResult
    func record(_ action: String, outcome: AuditEvent.Outcome = .success, principal: ConsumerPrincipal, businessId: BusinessID? = nil,
                subjectType: String? = nil, subjectId: String? = nil, metadata: [String: String] = [:]) async throws -> AuditEventRecord {
        try await record(action, outcome: outcome, actor: AuditActor(kind: .device, id: principal.deviceId?.description),
                         consumerId: principal.consumerId, businessId: businessId, subjectType: subjectType, subjectId: subjectId,
                         metadata: metadata)
    }

    static func hash(of record: AuditEventRecord, key: SymmetricKey) throws -> String {
        var object: [String: JSONValue] = [
            "seq": .integer(Int64(record.seq)),
            "at": .string(ViadereDate.format(record.occurredAt)),
            "actorKind": .string(record.actorKind),
            "action": .string(record.action),
            "outcome": .string(record.outcome),
            "meta": .string(record.metadataJSON),
            "prev": .string(record.prevHash),
        ]
        if let v = record.actorId { object["actorId"] = .string(v) }
        if let v = record.consumerId { object["consumerId"] = .string(v.uuidString.lowercased()) }
        if let v = record.businessId { object["businessId"] = .string(v.uuidString.lowercased()) }
        if let v = record.subjectType { object["subjectType"] = .string(v) }
        if let v = record.subjectId { object["subjectId"] = .string(v) }
        if let v = record.correlationId { object["correlationId"] = .string(v) }
        if record.chainVersion >= 2 {
            object["v"] = .integer(Int64(record.chainVersion))
            if let id = record.id { object["id"] = .string(id.uuidString.lowercased()) }
            let mac = HMAC<SHA256>.authenticationCode(for: try CanonicalJSON.serialize(.object(object)), using: key)
            return Hex.encode(mac)
        }
        return SecureToken.sha256Hex(try CanonicalJSON.serialize(.object(object)))
    }

    struct ChainVerification: Equatable {
        var valid: Bool
        var checked: Int
        var firstBrokenSeq: Int?
    }

    /// Recomputes the whole chain. Any edited, removed, reordered or downgraded event is reported.
    /// Events at or below `legacyThroughSeq` may be version 1 (unkeyed); every later event must be version 2.
    static func verifyChain(on db: any Database, key: SymmetricKey, legacyThroughSeq: Int = 0) async throws -> ChainVerification {
        let events = try await AuditEventRecord.query(on: db).sort(\.$seq, .ascending).all()
        var expectedPrev = genesisHash
        var expectedSeq = 1
        var sawKeyed = false
        for event in events {
            if event.chainVersion >= 2 { sawKeyed = true } else if sawKeyed || event.seq > legacyThroughSeq {
                // Only the pre-upgrade prefix may be unkeyed, and a keyed event can never be followed by an unkeyed one: a downgrade.
                return ChainVerification(valid: false, checked: expectedSeq - 1, firstBrokenSeq: event.seq)
            }
            let recomputed = try hash(of: event, key: key)
            if event.seq != expectedSeq || event.prevHash != expectedPrev || !ConstantTime.equals(recomputed, event.hash) {
                return ChainVerification(valid: false, checked: expectedSeq - 1, firstBrokenSeq: event.seq)
            }
            expectedPrev = event.hash
            expectedSeq += 1
        }
        return ChainVerification(valid: true, checked: events.count, firstBrokenSeq: nil)
    }

    /// The current head, authenticated with the chain key, for export to external write-once storage.
    struct SignedHead: Codable, Equatable {
        var seq: Int
        var hash: String
        var occurredAt: String
        var exportedAt: String
        /// `HMAC-SHA256(AUDIT_CHAIN_KEY, "VIADERE-AUDIT-HEAD-V1\n{seq}\n{hash}\n{occurredAt}\n{exportedAt}")`, hex.
        var mac: String
    }

    static func signedHead(on db: any Database, key: SymmetricKey, now: Date) async throws -> SignedHead? {
        guard let head = try await AuditEventRecord.query(on: db).sort(\.$seq, .descending).first() else { return nil }
        let at = ViadereDate.format(head.occurredAt)
        let exported = ViadereDate.format(now)
        let message = Data("VIADERE-AUDIT-HEAD-V1\n\(head.seq)\n\(head.hash)\n\(at)\n\(exported)".utf8)
        return SignedHead(seq: head.seq, hash: head.hash, occurredAt: at, exportedAt: exported,
                          mac: Hex.encode(HMAC<SHA256>.authenticationCode(for: message, using: key)))
    }

    /// Checks an exported head against the chain: the event at `seq` must still have that hash (and the MAC must be ours).
    static func verify(head: SignedHead, on db: any Database, key: SymmetricKey) async throws -> Bool {
        let message = Data("VIADERE-AUDIT-HEAD-V1\n\(head.seq)\n\(head.hash)\n\(head.occurredAt)\n\(head.exportedAt)".utf8)
        guard ConstantTime.equals(Hex.encode(HMAC<SHA256>.authenticationCode(for: message, using: key)), head.mac),
              let event = try await AuditEventRecord.query(on: db).filter(\.$seq == head.seq).first() else { return false }
        return ConstantTime.equals(event.hash, head.hash)
    }
}
