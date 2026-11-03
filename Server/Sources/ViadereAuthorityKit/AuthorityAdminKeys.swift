@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import Foundation
import ViadereCore

// Admin commands for the reviewed key inventory (S6-06) and the recovery-seal keys (ADR-0034 §5.1, §8.2). Like every admin command they run only in
// the reviewer-gated admin job, from a change file that is a reviewed commit on protected `main`, with no Key Vault role (AUTH-ADMIN-NO-KV).
extension AuthorityAdmin {
    /// One inventory entry of a change file: `{name, version, jwk}` for a Key Vault key, `{kid, jwk}` (in `seal_keys`) for a seal key.
    struct InventoryEntry: Equatable {
        let name: String
        let version: String
        let source: String
        let jwk: [String: JSONValue]
        let thumbprint: String
    }

    static let privateMembers: Set<String> = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"]

    /// A public JWK reduced to its key members: EC P-256 (`kty`, `crv`, `x`, `y`) or RSA (`kty`, `n`, `e`), with its RFC 7638 thumbprint.
    static func publicJWK(_ value: JSONValue?) throws -> (jwk: [String: JSONValue], thumbprint: String) {
        guard let o = value?.objectValue, privateMembers.isDisjoint(with: o.keys) else { throw Failure.invalid("jwk (public members only)") }
        switch o["kty"]?.stringValue {
        case "EC":
            guard o["crv"]?.stringValue == "P-256", let x = o["x"]?.stringValue.flatMap(Base64URL.decode), let y = o["y"]?.stringValue.flatMap(Base64URL.decode),
                  x.count == 32, y.count == 32, let key = try? P256.Signing.PublicKey(rawRepresentation: x + y) else { throw Failure.invalid("jwk (EC P-256)") }
            let jwk = JWKThumbprint.p256JWK(key).filter { ["kty", "crv", "x", "y"].contains($0.key) }
            return (jwk, JWKThumbprint.p256(key))
        case "RSA":
            guard let n = o["n"]?.stringValue.flatMap(Base64URL.decode), let e = o["e"]?.stringValue.flatMap(Base64URL.decode), n.count >= 256, !e.isEmpty else {
                throw Failure.invalid("jwk (RSA)")
            }
            let jwk = JWKThumbprint.rsaJWK(modulus: n, exponent: e).filter { ["kty", "n", "e"].contains($0.key) }
            return (jwk, JWKThumbprint.rsa(modulus: n, exponent: e))
        default:
            throw Failure.invalid("jwk (kty)")
        }
    }

    /// Strict parse: `{"keys": [{name, version, jwk}], "seal_keys": [{kid, jwk}]}` (either list may be absent, not both; at most 20 entries).
    static func parseInventory(_ o: [String: JSONValue]) throws -> [InventoryEntry] {
        guard Set(o.keys).isSubset(of: ["keys", "seal_keys"]), !o.isEmpty else { throw Failure.invalid("members (keys, seal_keys)") }
        var out: [InventoryEntry] = []
        if let raw = o["keys"] {
            guard case .array(let items) = raw else { throw Failure.invalid("keys") }
            for item in items {
                guard let e = item.objectValue, Set(e.keys) == ["name", "version", "jwk"] else { throw Failure.invalid("keys entry (name, version, jwk)") }
                let name = try string(e, "name", max: 127), version = try string(e, "version", max: 64)
                guard name.allSatisfy({ $0.isASCII && ($0.isLowercase || $0.isNumber || $0 == "-") }) else { throw Failure.invalid("name") }
                guard version.count == 32, version.allSatisfy(\.isHexDigit) else { throw Failure.invalid("version") }
                let (jwk, thumbprint) = try publicJWK(e["jwk"])
                out.append(InventoryEntry(name: name, version: version.lowercased(), source: "key_vault", jwk: jwk, thumbprint: thumbprint))
            }
        }
        if let raw = o["seal_keys"] {
            guard case .array(let items) = raw else { throw Failure.invalid("seal_keys") }
            for item in items {
                guard let e = item.objectValue, Set(e.keys) == ["kid", "jwk"], let kid = e["kid"]?.stringValue else { throw Failure.invalid("seal_keys entry (kid, jwk)") }
                let (jwk, thumbprint) = try publicJWK(e["jwk"])
                guard jwk["kty"]?.stringValue == "EC", ConstantTime.equals(kid, thumbprint) else { throw Failure.invalid("seal key kid (its RFC 7638 thumbprint)") }
                out.append(InventoryEntry(name: "recovery-seal", version: kid, source: "seal_key", jwk: jwk, thumbprint: thumbprint))
            }
        }
        guard !out.isEmpty, out.count <= 20, Set(out.map(\.thumbprint)).count == out.count else { throw Failure.invalid("entries (1-20, distinct keys)") }
        return out
    }

    /// `key-inventory-record`: stores the reviewed rows as `pending`. The serving authority verifies them (`AuthorityKeyInventory.verifyPending`).
    static func recordInventory(_ o: [String: JSONValue], commit: String, db: any Database, now: Date) async throws {
        for entry in try parseInventory(o) {
            let row = AuthorityInventoryRow()
            row.changeCommit = commit
            row.name = entry.name
            row.version = entry.version
            row.source = entry.source
            row.jwk = String(decoding: try CanonicalJSON.serialize(.object(entry.jwk)), as: UTF8.self)
            row.thumbprint = entry.thumbprint
            row.status = "pending"
            row.recordedAt = now
            try await row.create(on: db)
        }
    }

    /// `key-inventory-check`: succeeds only when every entry of the change file has a row the serving authority marked `verified`. Its exit status
    /// is what `authority-admin.yml` waits for before it attests the inventory (no log is read).
    static func checkInventory(_ o: [String: JSONValue], db: any Database) async throws {
        for entry in try parseInventory(o) {
            let verified = try await AuthorityInventoryRow.query(on: db).filter(\.$thumbprint == entry.thumbprint).filter(\.$name == entry.name)
                .filter(\.$version == entry.version).filter(\.$status == "verified").count()
            guard verified > 0 else { throw Failure.invalid("\(entry.name)/\(entry.version) is not verified by the serving authority") }
        }
    }

    /// `seal-key-create` (ADR-0034 §5.1): a fresh P-256 KEM key pair, its private scalar wrapped **locally** under the public half of the KEK named in
    /// the change file (RSA 3072, e = 65537, RSA-OAEP-256), which must be a `verified` inventory row. One creation per job execution (the active and
    /// the standby come from two separate reviewed runs). Stores only the public JWK and the wrapped blob; the scalar buffer is zeroed.
    static func createSealKey(_ o: [String: JSONValue], commit: String, db: any Database, config: AuthorityConfig, executionId: String?, now: Date) async throws {
        guard Set(o.keys) == ["role", "kek"], let role = o["role"]?.stringValue, ["active", "standby"].contains(role),
              let kek = o["kek"]?.objectValue, Set(kek.keys) == ["name", "version", "jwk"] else { throw Failure.invalid("members (role, kek {name, version, jwk})") }
        let kekName = try string(kek, "name", max: 127), kekVersion = try string(kek, "version", max: 64).lowercased()
        guard kekName == (role == "active" ? "recovery-seal-kek" : "recovery-seal-kek-standby") else { throw Failure.invalid("kek name for role \(role)") }
        let (kekJWK, kekThumbprint) = try publicJWK(kek["jwk"])
        // The active KEK must be verified by the serving authority (it holds unwrap on it); the standby KEK carries no authority role until rollover,
        // so its reviewed row stays `unavailable` (ADR-0034 §5.1: a substituted KEK fails closed at the first unwrap).
        let accepted = role == "active" ? ["verified"] : ["verified", "unavailable"]
        guard try await AuthorityInventoryRow.query(on: db).filter(\.$name == kekName).filter(\.$version == kekVersion).filter(\.$thumbprint == kekThumbprint)
            .filter(\.$status ~~ accepted).count() > 0 else { throw Failure.invalid("kek is not a reviewed inventory row") }
        guard kekJWK["kty"]?.stringValue == "RSA", kekJWK["e"]?.stringValue == "AQAB", let n = kekJWK["n"]?.stringValue.flatMap(Base64URL.decode),
              let wrapping = try? _RSA.Encryption.PublicKey(n: n, e: Data([1, 0, 1])), wrapping.keySizeInBits == 3072 else {
            throw Failure.invalid("kek (RSA 3072, e = 65537)")
        }
        let execution: String
        if let executionId, !executionId.isEmpty {
            execution = executionId
        } else {
            guard !config.deployment.isStrict else { throw Failure.invalid("no job execution id (CONTAINER_APP_JOB_EXECUTION_NAME)") }
            execution = "local-" + UUID().uuidString.lowercased()
        }
        guard try await AuthoritySealKey.query(on: db).filter(\.$jobExecutionId == execution).count() == 0 else {
            throw Failure.invalid("one seal-key create per job execution")
        }
        guard try await AuthoritySealKey.query(on: db).filter(\.$role == role).filter(\.$state == "ready").count() == 0 else {
            throw Failure.invalid("a ready \(role) seal key exists (rotation is its own reviewed procedure)")
        }
        let key = P256.KeyAgreement.PrivateKey()
        var scalar = key.rawRepresentation
        defer { scalar.resetBytes(in: 0..<scalar.count) }
        let wrapped = try wrapping.encrypt(scalar, padding: .PKCS1_OAEP_SHA256)
        let kid = RecoverySeal.kid(key.publicKey)
        let raw = key.publicKey.rawRepresentation
        let jwk: JSONValue = .object(["kty": .string("EC"), "crv": .string("P-256"), "x": .string(Base64URL.encode(raw.prefix(32))), "y": .string(Base64URL.encode(raw.suffix(32)))])
        let row = AuthoritySealKey()
        row.id = kid
        row.publicJWK = String(decoding: try CanonicalJSON.serialize(jwk), as: UTF8.self)
        row.wrappedPrivate = Base64URL.encode(wrapped)
        row.kekName = kekName
        row.kekVersion = kekVersion
        row.role = role
        row.state = "ready"
        row.createdAt = now
        row.notAfter = now.addingTimeInterval(182 * 86_400)
        row.jobExecutionId = execution
        row.changeCommit = commit
        try await row.create(on: db)
    }

    /// `seal-key exposed` (ADR-0034 §8.2 step 2): marks the key exposed and, in one transaction, invalidates **every** set sealed to it and no other.
    static func sealKeyExposed(_ o: [String: JSONValue], db: any Database, now: Date) async throws {
        guard Set(o.keys) == ["kid"], let kid = o["kid"]?.stringValue, Base64URL.isValid(kid, minLength: 43, maxLength: 43) else { throw Failure.invalid("members (kid)") }
        guard try await AuthoritySealKey.find(kid, on: db) != nil else { throw Failure.invalid("unknown seal key") }
        try await db.transaction { tx in
            try await AuthoritySealKey.query(on: tx).filter(\.$id == kid).set(\.$state, to: "exposed").update()
            let affected = Set(try await AuthorityRecoveryCode.query(on: tx).filter(\.$sealKid == kid).filter(\.$state == "active").all().map(\.accountRef))
            try await AuthorityRecoveryCode.query(on: tx).filter(\.$sealKid == kid).filter(\.$state == "active").set(\.$state, to: "invalidated").update()
            for account in affected.sorted() {
                await AuthorityAudit.record(tx, "authority.recovery_set_invalidated", outcome: "success", reason: "seal_key_exposed", accountRef: account, kid: kid, caller: "admin", at: now)
            }
        }
    }
}
