@preconcurrency import Crypto
import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore

// Tenant destination keys (ADR-0031 §1, §2) and the pinned-key revocation list (ADR-0033 §3.3) at the authority.
//
// * Keys, hosts and names are **added only by the admin job** (`tenant-key-nonce`, then `tenant-key-register`), from a reviewed change file, after a
//   proof of possession by the new key over a nonce the job issued and recorded, and only when the attested domain evidence names the key's
//   thumbprint for every host. No HTTP route adds anything (ST-AUTH-16).
// * Reduction works with or without the api: `POST /v1/tenant-keys/revocations` (api, worker; reduce-only) and the admin commands
//   `revoke-tenant-key` and `remove-tenant-host`.
// * The serving authority signs the tenant record (`viadere-tenant-keys+jws`) with the `device-statement-signing` key on change and whenever the
//   cached copy is older than 5 minutes when served; `seq` grows by one on every change of the tenant's keys, hosts or name.

/// `authority_tenant_keys`: one destination key of one tenant (purpose `auth-destination-signing`, P-256 only).
final class AuthorityTenantKeyRow: Model, @unchecked Sendable {
    static let schema = "authority_tenant_keys"
    /// RFC 7638 thumbprint.
    @ID(custom: "kid", generatedBy: .user) var id: String?
    @Field(key: "tenant_id") var tenantId: String
    /// Canonical public JWK `{crv, kty, x, y}`.
    @Field(key: "public_key") var publicKey: String
    @Field(key: "purpose") var purpose: String
    /// JSON array of lowercase A-label hosts.
    @Field(key: "allowed_hosts") var allowedHosts: String
    @Field(key: "display_name") var displayName: String
    /// `active` | `revoked`.
    @Field(key: "status") var status: String
    @Field(key: "not_after") var notAfter: Date
    @Field(key: "registered_at") var registeredAt: Date
    @Field(key: "change_commit") var changeCommit: String
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    @OptionalField(key: "revoke_reason") var revokeReason: String?
    init() {}
}

/// `authority_tenant_records`: the tenant's record state (`seq`, name) and the cached signed statement.
final class AuthorityTenantRecordRow: Model, @unchecked Sendable {
    static let schema = "authority_tenant_records"
    @ID(custom: "tenant_id", generatedBy: .user) var id: String?
    @Field(key: "seq") var seq: Int
    @Field(key: "display_name") var displayName: String
    @OptionalField(key: "statement") var statement: String?
    /// Digest of the signed payload without `issued_at`: a change of keys, hosts or name invalidates the cache.
    @OptionalField(key: "content_digest") var contentDigest: String?
    @OptionalField(key: "signed_at") var signedAt: Date?
    init() {}
}

/// `authority_registration_nonces` (ADR-0031 §1.2 rule (a)): issued by the admin job for one tenant, key and host set; accepted **once**.
final class AuthorityRegistrationNonce: Model, @unchecked Sendable {
    static let schema = "authority_registration_nonces"
    @ID(custom: "id", generatedBy: .user) var id: String?
    @Field(key: "nonce") var nonce: String
    @Field(key: "tenant_id") var tenantId: String
    @Field(key: "kid") var kid: String
    @Field(key: "hosts") var hosts: String
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "consumed_at") var consumedAt: Date?
    @Field(key: "change_commit") var changeCommit: String
    init() {}
}

/// `authority_device_key_revocations`: pinned keys the reviewed admin path revoked (ADR-0033 §3.4). Sticky: never deleted.
final class AuthorityDeviceKeyRevocation: Model, @unchecked Sendable {
    static let schema = "authority_device_key_revocations"
    @ID(custom: "kid", generatedBy: .user) var id: String?
    @Field(key: "key_family") var keyFamily: String
    @Field(key: "recorded_at") var recordedAt: Date
    @Field(key: "change_commit") var changeCommit: String
    init() {}
}

/// The signed revocation list, cached until the revoked set changes (a list has no freshness limit, ADR-0033 §3.3).
final class AuthorityRevocationListCache: Model, @unchecked Sendable {
    static let schema = "authority_revocation_list_cache"
    @ID(custom: "id", generatedBy: .user) var id: String?
    @Field(key: "content_digest") var contentDigest: String
    @Field(key: "statement") var statement: String
    @Field(key: "signed_at") var signedAt: Date
    init() {}
}

struct CreateAuthorityTenantKeysSchema: AsyncMigration {
    var name: String { "Authority.v3" }

    func prepare(on db: any Database) async throws {
        try await db.schema(AuthorityTenantKeyRow.schema)
            .field("kid", .string, .identifier(auto: false)).field("tenant_id", .string, .required).field("public_key", .string, .required)
            .field("purpose", .string, .required).field("allowed_hosts", .string, .required).field("display_name", .string, .required)
            .field("status", .string, .required).field("not_after", .datetime, .required).field("registered_at", .datetime, .required)
            .field("change_commit", .string, .required).field("revoked_at", .datetime).field("revoke_reason", .string).create()
        try await db.schema(AuthorityTenantRecordRow.schema)
            .field("tenant_id", .string, .identifier(auto: false)).field("seq", .int, .required).field("display_name", .string, .required)
            .field("statement", .string).field("content_digest", .string).field("signed_at", .datetime).create()
        try await db.schema(AuthorityRegistrationNonce.schema)
            .field("id", .string, .identifier(auto: false)).field("nonce", .string, .required).field("tenant_id", .string, .required)
            .field("kid", .string, .required).field("hosts", .string, .required).field("expires_at", .datetime, .required).field("consumed_at", .datetime)
            .field("change_commit", .string, .required).unique(on: "nonce").create()
        try await db.schema(AuthorityDeviceKeyRevocation.schema)
            .field("kid", .string, .identifier(auto: false)).field("key_family", .string, .required).field("recorded_at", .datetime, .required)
            .field("change_commit", .string, .required).create()
        try await db.schema(AuthorityRevocationListCache.schema)
            .field("id", .string, .identifier(auto: false)).field("content_digest", .string, .required).field("statement", .string, .required)
            .field("signed_at", .datetime, .required).create()
        guard let sql = db as? any SQLDatabase else { return }
        // Pinned-key revocations are evidence and sticky: never rewritten or deleted.
        if sql.dialect.name == "postgresql" {
            try await sql.raw("""
                CREATE TRIGGER authority_device_key_revocations_append_only BEFORE UPDATE OR DELETE ON authority_device_key_revocations
                FOR EACH ROW EXECUTE FUNCTION viadere_authority_append_only()
                """).run()
        } else {
            try await sql.raw("CREATE TRIGGER authority_device_key_revocations_no_update BEFORE UPDATE ON authority_device_key_revocations BEGIN SELECT RAISE(ABORT, 'append-only table'); END").run()
            try await sql.raw("CREATE TRIGGER authority_device_key_revocations_no_delete BEFORE DELETE ON authority_device_key_revocations BEGIN SELECT RAISE(ABORT, 'append-only table'); END").run()
        }
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_authority_tenant_keys_tenant ON authority_tenant_keys (tenant_id)").run()
    }

    func revert(on db: any Database) async throws {
        for table in [AuthorityRevocationListCache.schema, AuthorityDeviceKeyRevocation.schema, AuthorityRegistrationNonce.schema, AuthorityTenantRecordRow.schema,
                      AuthorityTenantKeyRow.schema] {
            try await db.schema(table).delete()
        }
    }
}

// MARK: - Admin commands (reviewer-gated job; no Key Vault role)

extension AuthorityAdmin {
    static let tenantKeyPurpose = "auth-destination-signing"
    /// Registration nonces live long enough for the tenant to sign and the reviewer to review the registration change.
    static let registrationNonceLifetime: TimeInterval = 72 * 3600
    /// ADR-0031 §1.3: `not_after` at most 13 months after registration.
    static func maxNotAfter(_ now: Date) -> Date {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar.date(byAdding: .month, value: 13, to: now) ?? now
    }

    static func tenantId(_ o: [String: JSONValue]) throws -> String {
        let tenant = try string(o, "tenant_id", max: 64)
        guard AuthorityTenantRecord.isTenantId(tenant) else { throw Failure.invalid("tenant_id") }
        return tenant
    }

    static func hosts(_ o: [String: JSONValue]) throws -> [String] {
        let hosts = try strings(o, "hosts")
        guard !hosts.isEmpty, hosts.count <= AuthorityTenantRecord.maxHosts, Set(hosts).count == hosts.count,
              hosts.allSatisfy({ (try? AuthDestinationValidator.validateHost($0)) != nil }) else { throw Failure.invalid("hosts (1-20 distinct lowercase A-label hosts)") }
        return hosts.sorted()
    }

    static func kid(_ o: [String: JSONValue]) throws -> String {
        let kid = try string(o, "kid", max: 43)
        guard Base64URL.isValid(kid, minLength: 43, maxLength: 43) else { throw Failure.invalid("kid (RFC 7638 thumbprint)") }
        return kid
    }

    static func jsonText(_ values: [String]) throws -> String { String(decoding: try JSONEncoder().encode(values), as: UTF8.self) }

    /// `tenant-key-nonce` (first run of a registration, ADR-0031 §1.2 rule (a)): `{tenant_id, kid, hosts}` → a 256-bit nonce from the job's CSPRNG,
    /// recorded with the tenant, the `kid`, the hosts and an expiry. Any earlier unconsumed nonce for the same tenant and key is expired.
    static func issueRegistrationNonce(_ o: [String: JSONValue], commit: String, db: any Database, now: Date) async throws {
        guard Set(o.keys) == ["tenant_id", "kid", "hosts"] else { throw Failure.invalid("members (tenant_id, kid, hosts)") }
        let tenant = try tenantId(o), kid = try kid(o), hosts = try hosts(o)
        try await AuthorityRegistrationNonce.query(on: db).filter(\.$tenantId == tenant).filter(\.$kid == kid).filter(\.$consumedAt == nil)
            .set(\.$expiresAt, to: now).update()
        let row = AuthorityRegistrationNonce()
        row.id = "rgn_" + Base64URL.encode(SecureToken.randomBytes(16))
        row.nonce = Base64URL.encode(SecureToken.randomBytes(32))
        row.tenantId = tenant
        row.kid = kid
        row.hosts = try jsonText(hosts)
        row.expiresAt = now.addingTimeInterval(registrationNonceLifetime)
        row.changeCommit = commit
        try await row.create(on: db)
    }

    /// Domain-control evidence for one host (ADR-0031 §1.2), as the reviewer-gated workflow fetched it and the reviewer committed it:
    /// `{host, method: "dns_txt", dnssec: "validated" | "unsigned", answers: [{resolver, records: [...]}, {…}]}` (two distinct resolvers, each
    /// returning the TXT value `v=1; kid=<thumbprint>` for `_viadere-destkey.<host>`; a DNSSEC-bogus answer is never accepted), or
    /// `{host, method: "well_known", url: "https://<host>/.well-known/viadere-verification.json", kids: [...]}` (the thumbprint listed in the
    /// tenant's verification file).
    static func checkEvidence(_ raw: JSONValue?, hosts: [String], kid: String) throws {
        guard case .array(let items)? = raw, items.count == hosts.count else { throw Failure.invalid("evidence (one entry per host)") }
        var covered = Set<String>()
        let expected = "v=1; kid=\(kid)"
        for item in items {
            guard let e = item.objectValue, let host = e["host"]?.stringValue, hosts.contains(host), covered.insert(host).inserted else {
                throw Failure.invalid("evidence host")
            }
            switch e["method"]?.stringValue {
            case "dns_txt":
                guard Set(e.keys) == ["host", "method", "dnssec", "answers"] else { throw Failure.invalid("evidence members (dns_txt)") }
                guard let dnssec = e["dnssec"]?.stringValue, ["validated", "unsigned"].contains(dnssec) else { throw Failure.invalid("evidence dnssec (bogus or unknown)") }
                guard case .array(let answers)? = e["answers"], answers.count == 2 else { throw Failure.invalid("evidence answers (two resolvers)") }
                var resolvers = Set<String>()
                for answer in answers {
                    guard let a = answer.objectValue, Set(a.keys) == ["resolver", "records"], let resolver = a["resolver"]?.stringValue, !resolver.isEmpty,
                          resolvers.insert(resolver).inserted, case .array(let records)? = a["records"],
                          records.compactMap(\.stringValue).contains(expected) else { throw Failure.invalid("evidence for \(host) does not name the key's thumbprint") }
                }
            case "well_known":
                guard Set(e.keys) == ["host", "method", "url", "kids"], e["url"]?.stringValue == "https://\(host)/.well-known/viadere-verification.json",
                      case .array(let kids)? = e["kids"], kids.compactMap(\.stringValue).contains(kid) else {
                    throw Failure.invalid("evidence for \(host) does not name the key's thumbprint")
                }
            default:
                throw Failure.invalid("evidence method")
            }
        }
    }

    /// `tenant-key-register` (ADR-0031 §1.2): `{tenant_id, display_name, public_key, hosts, not_after, pop, evidence}`. Refused unless the proof of
    /// possession verifies with the submitted key over the recorded nonce for this tenant, key and host set (consumed here, once), the attested
    /// evidence names the key's thumbprint for every host, and `not_after` is within 13 months. A renewal of an active key repeats all of it.
    static func registerTenantKey(_ o: [String: JSONValue], commit: String, db: any Database, config: AuthorityConfig, now: Date) async throws {
        guard Set(o.keys) == ["tenant_id", "display_name", "public_key", "hosts", "not_after", "pop", "evidence"] else {
            throw Failure.invalid("members (tenant_id, display_name, public_key, hosts, not_after, pop, evidence)")
        }
        let tenant = try tenantId(o), hosts = try hosts(o)
        let name = try displayName(try string(o, "display_name", max: 240))
        let (jwk, kid) = try publicJWK(o["public_key"])
        guard jwk["kty"]?.stringValue == "EC", let x = jwk["x"]?.stringValue.flatMap(Base64URL.decode), let y = jwk["y"]?.stringValue.flatMap(Base64URL.decode),
              let key = try? P256.Signing.PublicKey(rawRepresentation: x + y) else { throw Failure.invalid("public_key (EC P-256)") }
        guard let notAfterSeconds = o["not_after"]?.authorityInteger else { throw Failure.invalid("not_after") }
        let notAfter = Date(timeIntervalSince1970: TimeInterval(notAfterSeconds))
        guard notAfter > now, notAfter <= maxNotAfter(now) else { throw Failure.invalid("not_after (at most 13 months from registration)") }
        try checkEvidence(o["evidence"], hosts: hosts, kid: kid)
        if let existing = try await AuthorityTenantKeyRow.find(kid, on: db) {
            guard existing.status == "active" else { throw Failure.invalid("revoked key re-registered") }
            guard existing.tenantId == tenant else { throw Failure.invalid("key_in_use (another tenant)") }
        }
        let pop = try string(o, "pop", max: AuthorityJWS.maxBytes)
        let pending = try await AuthorityRegistrationNonce.query(on: db).filter(\.$tenantId == tenant).filter(\.$kid == kid).filter(\.$consumedAt == nil)
            .filter(\.$expiresAt > now).all()
        // Rule (c): the nonce was issued for exactly these hosts.
        guard let nonce = pending.first(where: { (try? JSONDecoder().decode([String].self, from: Data($0.hosts.utf8))).map(Set.init) == Set(hosts) }) else {
            throw Failure.invalid("no unconsumed registration nonce for this tenant, key and host set (run tenant-key-nonce first)")
        }
        let nonceId = nonce.id!
        do {
            _ = try await DestinationKeyRegistration.verify(pop, publicKey: key, tenantId: tenant, environment: config.deployment.statementEnvironment, hosts: Set(hosts),
                                                            expectedNonce: nonce.nonce, now: now, consumeNonce: {
                // Compare-and-swap: the nonce is accepted once, whatever runs concurrently.
                guard let sql = db as? any SQLDatabase else { return false }
                let rows = try await sql.update(AuthorityRegistrationNonce.schema).set("consumed_at", to: now).where("id", .equal, nonceId)
                    .where("consumed_at", .is, SQLLiteral.null).returning("id").all()
                return rows.count == 1
            })
        } catch {
            throw Failure.invalid("registration proof of possession: \(error.rawValue)")
        }
        try await db.transaction { tx in
            let row = try await AuthorityTenantKeyRow.find(kid, on: tx) ?? AuthorityTenantKeyRow()
            let isNew = row.id == nil
            row.id = kid
            row.tenantId = tenant
            row.publicKey = String(decoding: try CanonicalJSON.serialize(.object(jwk)), as: UTF8.self)
            row.purpose = tenantKeyPurpose
            row.allowedHosts = try jsonText(hosts)
            row.displayName = name
            row.status = "active"
            row.notAfter = notAfter
            row.registeredAt = now
            row.changeCommit = commit
            if isNew { try await row.create(on: tx) } else { try await row.update(on: tx) }
            try await AuthorityTenantRecords.bump(tenant, displayName: name, db: tx)
        }
        await AuthorityAudit.record(db, "authority.tenant_key_registered", outcome: "success", tenant: tenant, kid: kid, caller: "admin", detail: "commit:\(commit)", at: now)
    }

    /// `revoke-tenant-key` (reduce-only, works without the api): `{tenant_id, kid, reason}`.
    static func revokeTenantKey(_ o: [String: JSONValue], db: any Database, now: Date) async throws {
        guard Set(o.keys) == ["tenant_id", "kid", "reason"] else { throw Failure.invalid("members (tenant_id, kid, reason)") }
        let tenant = try tenantId(o), kid = try kid(o), reason = try string(o, "reason", max: 64)
        guard try await AuthorityTenantRecords.revoke(tenant: tenant, kid: kid, reason: reason, db: db, now: now) else { throw Failure.invalid("unknown active key") }
    }

    /// `remove-tenant-host` (reduce-only, works without the api): `{tenant_id, host}`.
    static func removeTenantHost(_ o: [String: JSONValue], db: any Database, now: Date) async throws {
        guard Set(o.keys) == ["tenant_id", "host"] else { throw Failure.invalid("members (tenant_id, host)") }
        let tenant = try tenantId(o), host = try string(o, "host", max: 253)
        guard try await AuthorityTenantRecords.removeHost(tenant: tenant, host: host, db: db, now: now) else { throw Failure.invalid("host not listed for the tenant") }
    }

    /// `device-key-revoke` (ADR-0033 §3.4): `{key_family, kid}` records a revocation of the **active** pinned key of that family. The serving authority
    /// signs the list (a statement-family list only once it runs on the standby key, after the reviewed rollover). Sticky.
    static func revokeDeviceKey(_ o: [String: JSONValue], commit: String, db: any Database, config: AuthorityConfig, now: Date) async throws {
        guard Set(o.keys) == ["key_family", "kid"], let family = o["key_family"]?.stringValue.flatMap(AuthorityKeyFamily.init(rawValue:)) else {
            throw Failure.invalid("members (key_family device-statement | recovery-seal, kid)")
        }
        let kid = try kid(o)
        let pins = family == .deviceStatement ? config.statementPins : config.sealPins
        guard pins.first == kid else { throw Failure.invalid("kid is not the active pinned key of \(family.rawValue) (no list can revoke a standby)") }
        guard try await AuthorityDeviceKeyRevocation.query(on: db).filter(\.$keyFamily == family.rawValue).count() == 0 else {
            throw Failure.invalid("\(family.rawValue) already has a recorded revocation")
        }
        let row = AuthorityDeviceKeyRevocation()
        row.id = kid
        row.keyFamily = family.rawValue
        row.recordedAt = now
        row.changeCommit = commit
        try await row.create(on: db)
    }
}

// MARK: - Records, reduction and the revocation list

enum AuthorityTenantRecords {
    static let resignAfter: TimeInterval = 300

    /// `seq` + 1 for every change of keys, hosts or name (ADR-0031 §2, S1-A3-R04 item 5); the cached statement is dropped.
    static func bump(_ tenant: String, displayName: String? = nil, db: any Database) async throws {
        let row = try await AuthorityTenantRecordRow.find(tenant, on: db) ?? AuthorityTenantRecordRow()
        let isNew = row.id == nil
        row.id = tenant
        row.seq = isNew ? 1 : row.seq + 1
        if let displayName { row.displayName = displayName } else if isNew { row.displayName = tenant }
        row.statement = nil
        row.contentDigest = nil
        row.signedAt = nil
        if isNew { try await row.create(on: db) } else { try await row.update(on: db) }
    }

    static func hosts(_ row: AuthorityTenantKeyRow) -> [String] { (try? JSONDecoder().decode([String].self, from: Data(row.allowedHosts.utf8))) ?? [] }

    /// Reduce-only: revokes an active key. False when there is none.
    static func revoke(tenant: String, kid: String, reason: String, db: any Database, now: Date) async throws -> Bool {
        try await db.transaction { tx in
            guard let row = try await AuthorityTenantKeyRow.find(kid, on: tx), row.tenantId == tenant, row.status == "active" else { return false }
            row.status = "revoked"
            row.revokedAt = now
            row.revokeReason = reason
            try await row.update(on: tx)
            try await bump(tenant, db: tx)
            await AuthorityAudit.record(tx, "authority.tenant_key_revoked", outcome: "success", reason: reason, tenant: tenant, kid: kid, at: now)
            return true
        }
    }

    /// Reduce-only: removes `host` from every key of the tenant (the weekly domain re-check uses this when a host fails). False when not listed.
    static func removeHost(tenant: String, host: String, db: any Database, now: Date) async throws -> Bool {
        try await db.transaction { tx in
            var changed = false
            for row in try await AuthorityTenantKeyRow.query(on: tx).filter(\.$tenantId == tenant).all() {
                let before = hosts(row)
                guard before.contains(host) else { continue }
                row.allowedHosts = try AuthorityAdmin.jsonText(before.filter { $0 != host })
                try await row.update(on: tx)
                changed = true
            }
            if changed {
                try await bump(tenant, db: tx)
                await AuthorityAudit.record(tx, "authority.tenant_host_removed", outcome: "success", tenant: tenant, detail: "host:\(host)", at: now)
            }
            return changed
        }
    }

    /// The record the authority states now: active keys whose `not_after` has not passed, with the union of their hosts. `nil` for an unknown tenant.
    static func compute(tenant: String, ctx: AuthorityContext, db: any Database) async throws -> AuthorityTenantRecord? {
        guard let state = try await AuthorityTenantRecordRow.find(tenant, on: db) else { return nil }
        let now = ctx.now
        let rows = try await AuthorityTenantKeyRow.query(on: db).filter(\.$tenantId == tenant).filter(\.$status == "active").all()
            .filter { $0.notAfter > now }.sorted { $0.id! < $1.id! }
        var keys: [AuthorityTenantKey] = []
        var hosts = Set<String>()
        for row in rows.prefix(AuthorityTenantRecord.maxKeys) {
            guard case .object(let jwk)? = try? JSONDecoder().decode(JSONValue.self, from: Data(row.publicKey.utf8)),
                  let x = jwk["x"]?.stringValue.flatMap(Base64URL.decode), let y = jwk["y"]?.stringValue.flatMap(Base64URL.decode),
                  let key = try? P256.Signing.PublicKey(rawRepresentation: x + y), JWKThumbprint.p256(key) == row.id else { continue }
            keys.append(AuthorityTenantKey(key, notAfter: Int64(row.notAfter.timeIntervalSince1970)))
            hosts.formUnion(Self.hosts(row))
        }
        // A tenant whose keys are all revoked or expired still gets a record, with no key (every statement then fails as an integrity failure, not
        // as an outage); a record needs at least one host, so it names the hosts its keys had.
        if keys.isEmpty {
            for row in try await AuthorityTenantKeyRow.query(on: db).filter(\.$tenantId == tenant).all() { hosts.formUnion(Self.hosts(row)) }
        }
        guard !hosts.isEmpty else { return nil }
        return AuthorityTenantRecord(environment: ctx.environment, tenantId: tenant, seq: Int64(state.seq), displayName: state.displayName,
                                     allowedHosts: hosts.sorted().prefix(AuthorityTenantRecord.maxHosts).map { $0 }, keys: keys,
                                     issuedAt: Int64(now.timeIntervalSince1970))
    }

    /// The signed record, re-signed when its content changed or the cached copy is older than 5 minutes.
    static func signed(tenant: String, ctx: AuthorityContext, db: any Database) async throws -> String? {
        let keys = try ctx.requireKeys()
        guard let record = try await compute(tenant: tenant, ctx: ctx, db: db), let state = try await AuthorityTenantRecordRow.find(tenant, on: db) else { return nil }
        var content = record.payload
        content["issued_at"] = nil
        let digest = SecureToken.sha256Hex(try CanonicalJSON.serialize(.object(content)))
        if let cached = state.statement, state.contentDigest == digest, let at = state.signedAt, ctx.now.timeIntervalSince(at) < resignAfter { return cached }
        let statement = try await StatementBuilder(kms: ctx.kms, keys: keys, environment: ctx.environment).sign(tenantRecord: record)
        state.statement = statement
        state.contentDigest = digest
        state.signedAt = ctx.now
        try await state.update(on: db)
        return statement
    }

    /// The pinned-key revocation list, or `nil` when nothing is revoked or the list cannot be signed under ADR-0033 §3.3 (a statement-family
    /// revocation is signed only by the standby, so only once this authority runs on it).
    static func revocationList(ctx: AuthorityContext, db: any Database) async throws -> String? {
        let keys = try ctx.requireKeys()
        let rows = try await AuthorityDeviceKeyRevocation.query(on: db).all().sorted { $0.keyFamily < $1.keyFamily }
        guard !rows.isEmpty else { return nil }
        let pins = ctx.config.statementPins
        if rows.contains(where: { $0.keyFamily == AuthorityKeyFamily.deviceStatement.rawValue }) {
            guard pins.count == 2, keys.statement.kid == pins[1] else {
                await AuthorityAudit.record(db, "authority.revocation_list", outcome: "denied", reason: "statement_family_needs_standby", at: ctx.now)
                return nil
            }
        }
        let revoked = rows.compactMap { row in AuthorityKeyFamily(rawValue: row.keyFamily).map { AuthorityRevokedKey(family: $0, kid: row.id!) } }
        let digest = SecureToken.sha256Hex(Data(revoked.map { "\($0.family.rawValue)/\($0.kid)" }.joined(separator: "\n").utf8) + Data(keys.statement.kid.utf8))
        if let cached = try await AuthorityRevocationListCache.find("current", on: db), cached.contentDigest == digest { return cached.statement }
        let list = AuthorityRevocationList(environment: ctx.environment, revoked: revoked, issuedAt: Int64(ctx.now.timeIntervalSince1970))
        let statement = try await StatementBuilder(kms: ctx.kms, keys: keys, environment: ctx.environment).sign(revocationList: list)
        let cache = try await AuthorityRevocationListCache.find("current", on: db) ?? AuthorityRevocationListCache()
        let isNew = cache.id == nil
        cache.id = "current"
        cache.contentDigest = digest
        cache.statement = statement
        cache.signedAt = ctx.now
        if isNew { try await cache.create(on: db) } else { try await cache.update(on: db) }
        return statement
    }
}

// MARK: - Routes

extension AuthorityApplication {
    static func tenantKeyRoutes(_ app: Application, verifier: any AuthorityCallerVerifier) throws {
        let api = app.grouped(AuthorityRoleMiddleware(verifier: verifier, roles: [.evidenceSubmit], callerNames: ["api"]))
        let reduce = app.grouped(AuthorityRoleMiddleware(verifier: verifier, roles: [.revocations, .evidenceSubmit], callerNames: ["api", "worker"]))
        func path(_ route: String) -> [PathComponent] { route.split(separator: "/").map { PathComponent(stringLiteral: String($0)) } }
        @Sendable func requireEnabled(_ req: Request) throws -> AuthorityContext {
            let ctx = req.application.authority
            guard ctx.config.tenantKeysEnabled else { throw Abort(.notFound) }
            _ = try ctx.requireKeys()
            return ctx
        }
        api.on(.POST, path(AuthorityTenantKeyRoute.record)) { req async throws -> Response in
            let ctx = try requireEnabled(req)
            let o = try AuthorityBody.object(req, allowed: ["tenant_id"], required: ["tenant_id"])
            guard let tenant = o["tenant_id"]?.stringValue, AuthorityTenantRecord.isTenantId(tenant) else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
            guard let record = try await AuthorityTenantRecords.signed(tenant: tenant, ctx: ctx, db: req.db) else { throw Abort(.notFound, reason: "tenant_unknown") }
            var out: [String: JSONValue] = ["record": .string(record)]
            if let list = try await AuthorityTenantRecords.revocationList(ctx: ctx, db: req.db) { out["revocation_list"] = .string(list) }
            return try jsonObject(out)
        }
        api.on(.POST, path(AuthorityTenantKeyRoute.registrationNonce)) { req async throws -> Response in
            let ctx = try requireEnabled(req)
            let o = try AuthorityBody.object(req, allowed: ["tenant_id", "kid"], required: ["tenant_id", "kid"])
            guard let tenant = o["tenant_id"]?.stringValue, AuthorityTenantRecord.isTenantId(tenant), let kid = o["kid"]?.stringValue,
                  Base64URL.isValid(kid, minLength: 43, maxLength: 43) else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
            // Not a secret (the proof of possession is what counts), and useless without the key and the domain evidence.
            guard let row = try await AuthorityRegistrationNonce.query(on: req.db).filter(\.$tenantId == tenant).filter(\.$kid == kid)
                .filter(\.$consumedAt == nil).filter(\.$expiresAt > ctx.now).sort(\.$expiresAt, .descending).first() else { throw Abort(.notFound, reason: "no_pending_registration") }
            return try jsonObject(["nonce": .string(row.nonce), "hosts": .array(AuthorityTenantRecords.jsonArray(row.hosts).map { .string($0) }),
                                   "expires_at": .integer(Int64(row.expiresAt.timeIntervalSince1970))])
        }
        reduce.on(.POST, path(AuthorityTenantKeyRoute.revocations)) { req async throws -> Response in
            let ctx = try requireEnabled(req)
            let o = try AuthorityBody.object(req, allowed: ["tenant_id", "kid", "host", "reason"], required: ["tenant_id", "reason"])
            guard let tenant = o["tenant_id"]?.stringValue, AuthorityTenantRecord.isTenantId(tenant), let reason = o["reason"]?.stringValue,
                  (1...64).contains(reason.utf8.count), (o["kid"] == nil) != (o["host"] == nil) else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
            let revoked: Bool
            if let kid = o["kid"]?.stringValue {
                revoked = try await AuthorityTenantRecords.revoke(tenant: tenant, kid: kid, reason: reason, db: req.db, now: ctx.now)
            } else {
                revoked = try await AuthorityTenantRecords.removeHost(tenant: tenant, host: o["host"]?.stringValue ?? "", db: req.db, now: ctx.now)
            }
            return try jsonObject(["revoked": .bool(revoked)])
        }
    }
}

extension AuthorityTenantRecords {
    static func jsonArray(_ text: String) -> [String] { (try? JSONDecoder().decode([String].self, from: Data(text.utf8))) ?? [] }
}
