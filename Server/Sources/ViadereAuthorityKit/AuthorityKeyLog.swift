@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore

/// The authority's key log (ADR-0023 §4): append-only entries hash-chained per account, plus the current-key view. Stage 6 writes two entry types:
/// `imported` (the reviewed one-time import, residual R-16) and `key_revoked` (reduce-only). Genesis, `enrollment_confirmed`, `device_added` and the
/// recovery entries arrive with ADR-0032 / ADR-0034.
enum AuthorityKeyLog {
    static let genesisHash = String(repeating: "0", count: 64)

    static func append(_ db: any Database, accountRef: String, type: String, kid: String, publicKey: String, keyPurpose: String, detail: [String: JSONValue],
                       now: Date) async throws {
        let last = try await AuthorityKeylogEntry.query(on: db).filter(\.$accountRef == accountRef).sort(\.$seq, .descending).first()
        let seq = (last?.seq ?? -1) + 1
        let prev = last?.entryHash ?? genesisHash
        let body: JSONValue = .object(["account_ref": .string(accountRef), "seq": .integer(Int64(seq)), "type": .string(type), "kid": .string(kid),
                                       "public_key": .string(publicKey), "key_purpose": .string(keyPurpose), "detail": .object(detail),
                                       "created_at": .integer(Int64(now.timeIntervalSince1970))])
        let canonical = try CanonicalJSON.serialize(body)
        let entry = AuthorityKeylogEntry()
        entry.accountRef = accountRef
        entry.seq = seq
        entry.type = type
        entry.kid = kid
        entry.publicKey = publicKey
        entry.keyPurpose = keyPurpose
        entry.detail = String(decoding: try CanonicalJSON.serialize(.object(detail)), as: UTF8.self)
        entry.createdAt = now
        entry.prevHash = prev
        entry.entryHash = SecureToken.sha256Hex(Data(prev.utf8) + canonical)
        try await entry.create(on: db)
    }

    /// `POST /v1/revocations` (reduce-only; the api and the worker may revoke, ADR-0023 §4). Revoking an unknown or revoked key changes nothing.
    static func revoke(_ db: any Database, kid: String, reason: String, caller: AuthorityCaller?, now: Date) async throws -> Bool {
        guard KeyIdentifier.isValid(kid), (1...64).contains(reason.utf8.count), reason.allSatisfy({ $0.isASCII && ($0.isLetter || $0 == "_") }) else {
            throw Abort(.unprocessableEntity, reason: "invalid_request")
        }
        return try await db.transaction { tx in
            guard let key = try await AuthorityKey.find(kid, on: tx), key.revokedAt == nil else { return false }
            key.revokedAt = now
            try await key.update(on: tx)
            try await append(tx, accountRef: key.accountRef, type: "key_revoked", kid: kid, publicKey: key.publicKey, keyPurpose: key.keyPurpose,
                             detail: ["reason": .string(reason), "by": .string(caller?.name ?? "admin")], now: now)
            await AuthorityAudit.record(tx, "authority.key_revoked", outcome: "success", reason: reason, accountRef: key.accountRef, kid: kid, caller: caller?.name, at: now)
            return true
        }
    }
}
