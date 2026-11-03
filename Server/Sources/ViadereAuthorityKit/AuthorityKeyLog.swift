@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore

/// The authority's key log (ADR-0023 §4): append-only entries hash-chained per account, plus the current-key view (`authority_keys`). Entry types:
/// `genesis`, `imported` (the reviewed one-time import, residual R-16), `enrollment_confirmed`, `device_added`, `recovery_codes_set`,
/// `recovery_started`, `recovery_started_legacy`, `recovery_cancel`, `recovery_activated`, `key_revoked` (reduce-only), `account_closed`.
/// `entry_hash = hex SHA-256("VIADERE-KEYLOG-ENTRY-V1\n" ‖ canonical(entry without entry_hash))`, the entry including `prev_hash` (ADR-0033 §5).
enum AuthorityKeyLog {
    static let genesisHash = AuthorityKeyLogFormat.zeroHash

    /// The canonical entry body that `entry_hash` covers.
    static func body(accountRef: String, seq: Int, type: String, kid: String, publicKey: String, keyPurpose: String, detail: [String: JSONValue], createdAt: Date,
                     prevHash: String) -> [String: JSONValue] {
        ["account_ref": .string(accountRef), "seq": .integer(Int64(seq)), "type": .string(type), "kid": .string(kid), "public_key": .string(publicKey),
         "key_purpose": .string(keyPurpose), "detail": .object(detail), "created_at": .integer(Int64(createdAt.timeIntervalSince1970)), "prev_hash": .string(prevHash)]
    }

    /// Appends one entry. Callers run it inside the transaction that changes the current-key view; `(account_ref, seq)` is unique, so a concurrent
    /// append for the same account fails instead of forking the chain.
    @discardableResult
    static func append(_ db: any Database, accountRef: String, type: String, kid: String, publicKey: String, keyPurpose: String, detail: [String: JSONValue],
                       now: Date) async throws -> AuthorityKeylogEntry {
        let last = try await AuthorityKeylogEntry.query(on: db).filter(\.$accountRef == accountRef).sort(\.$seq, .descending).first()
        let seq = (last?.seq ?? -1) + 1
        let prev = last?.entryHash ?? genesisHash
        let entry = AuthorityKeylogEntry()
        entry.accountRef = accountRef
        entry.seq = seq
        entry.type = type
        entry.kid = kid
        entry.publicKey = publicKey
        entry.keyPurpose = keyPurpose
        entry.detail = String(decoding: try CanonicalJSON.serialize(.object(detail)), as: UTF8.self)
        entry.createdAt = Date(timeIntervalSince1970: TimeInterval(Int64(now.timeIntervalSince1970)))
        entry.prevHash = prev
        entry.entryHash = try AuthorityKeyLogFormat.entryHash(body(accountRef: accountRef, seq: seq, type: type, kid: kid, publicKey: publicKey, keyPurpose: keyPurpose,
                                                                   detail: detail, createdAt: entry.createdAt, prevHash: prev))
        try await entry.create(on: db)
        return entry
    }

    /// Recomputes the chain of one account from its stored entries (tests and the maintenance check): `nil` when every link and hash holds.
    static func verifyChain(_ db: any Database, accountRef: String) async throws -> String? {
        var prev = genesisHash
        for (index, entry) in try await AuthorityKeylogEntry.query(on: db).filter(\.$accountRef == accountRef).sort(\.$seq).all().enumerated() {
            guard entry.seq == index, entry.prevHash == prev,
                  case .object(let detail)? = try? JSONDecoder().decode(JSONValue.self, from: Data(entry.detail.utf8)) else { return "link \(index)" }
            let expected = try AuthorityKeyLogFormat.entryHash(body(accountRef: accountRef, seq: entry.seq, type: entry.type, kid: entry.kid, publicKey: entry.publicKey,
                                                                   keyPurpose: entry.keyPurpose, detail: detail, createdAt: entry.createdAt, prevHash: entry.prevHash))
            guard ConstantTime.equals(expected, entry.entryHash) else { return "hash \(index)" }
            prev = entry.entryHash
        }
        return nil
    }

    /// `POST /v1/revocations` (reduce-only; the api and the worker may revoke, ADR-0023 §4). Revoking an unknown or revoked key changes nothing.
    static func revoke(_ db: any Database, kid: String, reason: String, caller: AuthorityCaller?, now: Date) async throws -> Bool {
        guard KeyIdentifier.isValid(kid), (1...64).contains(reason.utf8.count), reason.allSatisfy({ $0.isASCII && ($0.isLetter || $0 == "_") }) else {
            throw Abort(.unprocessableEntity, reason: "invalid_request")
        }
        return try await db.transaction { tx in
            guard let key = try await AuthorityKey.find(kid, on: tx), key.revokedAt == nil else { return false }
            try await revokeKey(tx, key, reason: reason, by: caller?.name ?? "admin", now: now)
            await AuthorityAudit.record(tx, "authority.key_revoked", outcome: "success", reason: reason, accountRef: key.accountRef, kid: kid, caller: caller?.name, at: now)
            return true
        }
    }

    /// Marks one key revoked and appends its `key_revoked` entry (inside the caller's transaction).
    static func revokeKey(_ db: any Database, _ key: AuthorityKey, reason: String, by: String, now: Date) async throws {
        key.revokedAt = now
        key.grantCapable = false
        try await key.update(on: db)
        try await append(db, accountRef: key.accountRef, type: "key_revoked", kid: key.id!, publicKey: key.publicKey, keyPurpose: key.keyPurpose,
                         detail: ["reason": .string(reason), "by": .string(by)], now: now)
    }
}
