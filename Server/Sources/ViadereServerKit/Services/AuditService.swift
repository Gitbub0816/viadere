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

/// The chain keys by epoch (G-8). Epoch 1 is `AUDIT_CHAIN_KEY` as first deployed; rotating it means setting `AUDIT_CHAIN_KEY_EPOCH` to the next
/// number, `AUDIT_CHAIN_KEY` to the new key and listing every earlier key in `AUDIT_CHAIN_KEYS_PREVIOUS`. Events written under epoch N record
/// N (chain version 3), so the chain stays verifiable end to end and an attacker cannot re-label an event with an older, weaker epoch: epochs
/// may never decrease along the chain.
struct AuditKeyring: Sendable {
    var currentEpoch: Int
    var keys: [Int: SymmetricKey]

    init(currentEpoch: Int, keys: [Int: SymmetricKey]) {
        self.currentEpoch = currentEpoch
        self.keys = keys
    }

    init(key: SymmetricKey) { self.init(currentEpoch: 1, keys: [1: key]) }

    init(config: ServerConfig) {
        var keys = config.operations.previousAuditKeys
        keys[config.operations.auditKeyEpoch] = config.auditChainKey
        self.init(currentEpoch: config.operations.auditKeyEpoch, keys: keys)
    }

    var current: SymmetricKey { keys[currentEpoch] ?? keys.values.first! }
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
                    let keyring = AuditKeyring(config: ctx.config)
                    // Epoch 1 keeps the version 2 form; a rotated key records its epoch (version 3).
                    record.chainVersion = keyring.currentEpoch > 1 ? 3 : 2
                    record.keyEpoch = keyring.currentEpoch > 1 ? keyring.currentEpoch : nil
                    record.hash = try Self.hash(of: record, key: keyring.current)
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
            if record.chainVersion >= 3, let epoch = record.keyEpoch { object["ke"] = .integer(Int64(epoch)) }
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
    /// Events at or below `legacyThroughSeq` may be version 1 (unkeyed); every later event must be version 2 or later, and the key epoch
    /// of version 3 events may never decrease.
    static func verifyChain(on db: any Database, key: SymmetricKey, legacyThroughSeq: Int = 0) async throws -> ChainVerification {
        try await verifyChain(on: db, keyring: AuditKeyring(key: key), legacyThroughSeq: legacyThroughSeq)
    }

    static func verifyChain(on db: any Database, keyring: AuditKeyring, legacyThroughSeq: Int = 0) async throws -> ChainVerification {
        // Events removed by the retention job leave a checkpoint; the chain is verified from the newest one.
        let checkpoint = try await AuditCheckpointRecord.query(on: db).sort(\.$seq, .descending).first()
        var remaining = AuditEventRecord.query(on: db).sort(\.$seq, .ascending)
        if let checkpoint { remaining = remaining.filter(\.$seq > checkpoint.seq) }
        let events = try await remaining.all()
        var expectedPrev = checkpoint?.hash ?? genesisHash
        var expectedSeq = (checkpoint?.seq ?? 0) + 1
        var sawKeyed = checkpoint != nil
        var lastEpoch = checkpoint?.keyEpoch ?? 1
        for event in events {
            if event.chainVersion >= 2 { sawKeyed = true } else if sawKeyed || event.seq > legacyThroughSeq {
                // Only the pre-upgrade prefix may be unkeyed, and a keyed event can never be followed by an unkeyed one: a downgrade.
                return ChainVerification(valid: false, checked: expectedSeq - 1, firstBrokenSeq: event.seq)
            }
            let epoch = event.chainVersion >= 3 ? (event.keyEpoch ?? 0) : 1
            guard let key = keyring.keys[epoch], epoch >= lastEpoch else {
                return ChainVerification(valid: false, checked: expectedSeq - 1, firstBrokenSeq: event.seq)
            }
            lastEpoch = epoch
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
        /// The `AUDIT_CHAIN_KEY` epoch that signed this head; absent for epoch 1 (the original, version 1 form).
        var keyEpoch: Int?
        /// `HMAC-SHA256(key, "VIADERE-AUDIT-HEAD-V1\n{seq}\n{hash}\n{occurredAt}\n{exportedAt}")`, hex; for a head signed under epoch N > 1
        /// `"VIADERE-AUDIT-HEAD-V2\n{N}\n{seq}..."`.
        var mac: String

        func message() -> Data {
            if let keyEpoch, keyEpoch > 1 { return Data("VIADERE-AUDIT-HEAD-V2\n\(keyEpoch)\n\(seq)\n\(hash)\n\(occurredAt)\n\(exportedAt)".utf8) }
            return Data("VIADERE-AUDIT-HEAD-V1\n\(seq)\n\(hash)\n\(occurredAt)\n\(exportedAt)".utf8)
        }
    }

    static func signedHead(on db: any Database, key: SymmetricKey, now: Date) async throws -> SignedHead? {
        try await signedHead(on: db, keyring: AuditKeyring(key: key), now: now)
    }

    static func signedHead(on db: any Database, keyring: AuditKeyring, now: Date) async throws -> SignedHead? {
        guard let head = try await AuditEventRecord.query(on: db).sort(\.$seq, .descending).first() else { return nil }
        let epoch = keyring.currentEpoch
        var signed = SignedHead(seq: head.seq, hash: head.hash, occurredAt: ViadereDate.format(head.occurredAt), exportedAt: ViadereDate.format(now),
                                keyEpoch: epoch > 1 ? epoch : nil, mac: "")
        signed.mac = Hex.encode(HMAC<SHA256>.authenticationCode(for: signed.message(), using: keyring.current))
        return signed
    }

    /// Checks an exported head against the chain: the event at `seq` must still have that hash (and the MAC must be ours).
    static func verify(head: SignedHead, on db: any Database, key: SymmetricKey) async throws -> Bool {
        try await verify(head: head, on: db, keyring: AuditKeyring(key: key))
    }

    static func verify(head: SignedHead, on db: any Database, keyring: AuditKeyring) async throws -> Bool {
        guard let key = keyring.keys[head.keyEpoch ?? 1],
              ConstantTime.equals(Hex.encode(HMAC<SHA256>.authenticationCode(for: head.message(), using: key)), head.mac),
              let event = try await AuditEventRecord.query(on: db).filter(\.$seq == head.seq).first() else { return false }
        return ConstantTime.equals(event.hash, head.hash)
    }
}
