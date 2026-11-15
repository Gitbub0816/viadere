@preconcurrency import Crypto
import Foundation

// Tenant destination keys (ADR-0031 §1, §2), the pinned-key revocation list (ADR-0033 §2, §3.3) and the registration proof of possession
// (ADR-0031 §1.2). All three use the JOSE profile of ADR-0023 §2 (`AuthorityJWS.parse`): header exactly `alg`, `kid`, `typ`; canonical payload;
// at most 4096 bytes. The two device statements are signed by the pinned `device-statement-signing` key family and separated from challenges and
// key-log heads by `typ` only; every verifier takes its `typ` as a constant, so a statement of one type is never accepted as another.

// MARK: - viadere-tenant-keys+jws

/// One destination key of a tenant as the authority lists it: `{kid, public_key: {crv, kty, x, y}, not_after}`.
public struct AuthorityTenantKey: Sendable, Hashable {
    /// RFC 7638 thumbprint of `publicKey`.
    public var kid: String
    /// Raw `x ‖ y` (64 bytes).
    public var publicKey: Data
    public var notAfter: Int64

    public init(kid: String, publicKey: Data, notAfter: Int64) {
        self.kid = kid
        self.publicKey = publicKey
        self.notAfter = notAfter
    }

    public init(_ key: P256.Signing.PublicKey, notAfter: Int64) {
        self.init(kid: JWKThumbprint.p256(key), publicKey: key.rawRepresentation, notAfter: notAfter)
    }

    var json: JSONValue {
        .object(["kid": .string(kid), "public_key": .object(["crv": .string("P-256"), "kty": .string("EC"), "x": .string(Base64URL.encode(publicKey.prefix(32))),
                                                             "y": .string(Base64URL.encode(publicKey.suffix(32)))]),
                 "not_after": .integer(notAfter)])
    }

    /// The key as the destination-statement verifier takes it.
    public var devicePublicKey: DevicePublicKey? {
        guard let key = try? P256.Signing.PublicKey(rawRepresentation: publicKey) else { return nil }
        return DevicePublicKey(key)
    }
}

/// The authority-signed tenant record (ADR-0031 §2): exactly
/// `{v:1, iss, aud, env, tenant_id, seq, display_name, allowed_hosts[], keys:[{kid, public_key, not_after}], issued_at}`.
public struct AuthorityTenantRecord: Sendable, Hashable {
    public static let type = "viadere-tenant-keys+jws"
    /// A record older than this is refused (availability class, S-LINK-11).
    public static let maxAge: Int64 = 900
    public static let maxKeys = 10
    public static let maxHosts = 20
    static let members: Set<String> = ["v", "iss", "aud", "env", "tenant_id", "seq", "display_name", "allowed_hosts", "keys", "issued_at"]

    public var environment: AuthorityEnvironment
    public var tenantId: String
    public var seq: Int64
    public var displayName: String
    public var allowedHosts: [String]
    public var keys: [AuthorityTenantKey]
    public var issuedAt: Int64

    public init(environment: AuthorityEnvironment, tenantId: String, seq: Int64, displayName: String, allowedHosts: [String], keys: [AuthorityTenantKey],
                issuedAt: Int64) {
        self.environment = environment
        self.tenantId = tenantId
        self.seq = seq
        self.displayName = displayName
        self.allowedHosts = allowedHosts
        self.keys = keys
        self.issuedAt = issuedAt
    }

    public var payload: [String: JSONValue] {
        ["v": .integer(1), "iss": .string(environment.authorityURN), "aud": .string(AuthorityAudience.device), "env": .string(environment.rawValue),
         "tenant_id": .string(tenantId), "seq": .integer(seq), "display_name": .string(displayName), "allowed_hosts": .array(allowedHosts.map { .string($0) }),
         "keys": .array(keys.map(\.json)), "issued_at": .integer(issuedAt)]
    }

    /// The expectation the destination-statement check runs against: keys whose `not_after` has not passed, the record's hosts and tenant.
    public func expectation(requestId: String, purpose: AuthDeliveryPurpose, now: Date) -> AuthDestinationStatement.Expectation {
        var map: [String: (key: DevicePublicKey, notAfter: Date?)] = [:]
        for key in keys { if let device = key.devicePublicKey { map[key.kid] = (device, Date(timeIntervalSince1970: TimeInterval(key.notAfter))) } }
        return .init(keys: map, allowedHosts: Set(allowedHosts), tenantId: tenantId, requestId: requestId, purpose: purpose, now: now)
    }

    /// The tenant's verified business name as the authority states it: 1-60 characters, NFC, no control or format characters (UX_COPY rule 1).
    public static func isDisplayName(_ value: String) -> Bool {
        value == value.precomposedStringWithCanonicalMapping && (1...60).contains(value.count)
            && !value.unicodeScalars.contains { $0.properties.generalCategory == .control || $0.properties.generalCategory == .format }
    }

    /// Tenant ids as businesses see them (`ten_…`, and the vector ids): 1-64 of `[A-Za-z0-9_-]`.
    public static func isTenantId(_ value: String) -> Bool { AuthDestinationStatement.isTenantId(value) }
}

/// The refusals specific to tenant records. `stale` is an **availability** failure (the link waits, S-LINK-11); every other refusal, `rollback`
/// included (ADR-0031 §4 revision 3.1, S3-A2-5), is an **integrity** failure.
public enum AuthorityTenantRecordError: String, Error, Sendable, Equatable {
    case stale
    /// `seq` below the highest this device stored for the tenant: a replayed record.
    case rollback
    /// The record is for another tenant than the one the statement names.
    case wrongTenant = "wrong_tenant"
}

extension AuthorityStatementVerifier {
    /// The device check of a `viadere-tenant-keys+jws` (ADR-0031 §2, §4 step 1): pinned, non-revoked statement key named by the header `kid`;
    /// signature; exact `typ` and member set; `iss`, `aud`, `env` of the build; `tenant_id` equal to `tenantId`; hosts and keys well formed (every
    /// key `kid` its own RFC 7638 thumbprint, public members only); `issued_at` not more than 60 s ahead and at most 15 minutes old; `seq` not below
    /// `minimumSeq`.
    public static func verifyTenantRecord(_ compact: String, pinnedKeys: [P256.Signing.PublicKey], revokedKids: Set<String> = [], environment: AuthorityEnvironment,
                                          tenantId: String, minimumSeq: Int64, now: Date) throws -> AuthorityTenantRecord {
        let parts = try AuthorityJWS.parse(compact, expectedType: AuthorityTenantRecord.type, allowedAlgorithms: ["ES256"])
        guard !revokedKids.contains(parts.kid), let key = pinnedKeys.first(where: { JWKThumbprint.p256($0) == parts.kid }) else { throw AuthorityJOSEError.unknownKey }
        try AuthorityJWS.verifyES256(parts, key: key)
        let o = parts.payload
        guard Set(o.keys) == AuthorityTenantRecord.members else { throw AuthorityJOSEError.claims("members") }
        guard o["v"]?.authorityInteger == 1, o["iss"]?.stringValue == environment.authorityURN, o["aud"]?.stringValue == AuthorityAudience.device,
              o["env"]?.stringValue == environment.rawValue else { throw AuthorityJOSEError.claims("issuer") }
        guard let tenant = o["tenant_id"]?.stringValue, AuthorityTenantRecord.isTenantId(tenant), let seq = o["seq"]?.authorityInteger, seq >= 0,
              let name = o["display_name"]?.stringValue, AuthorityTenantRecord.isDisplayName(name), let issuedAt = o["issued_at"]?.authorityInteger,
              case .array(let hostItems)? = o["allowed_hosts"], case .array(let keyItems)? = o["keys"] else { throw AuthorityJOSEError.claims("values") }
        let hosts = hostItems.compactMap(\.stringValue)
        guard hosts.count == hostItems.count, (1...AuthorityTenantRecord.maxHosts).contains(hosts.count), Set(hosts).count == hosts.count,
              hosts.allSatisfy({ (try? AuthDestinationValidator.validateHost($0)) != nil }) else { throw AuthorityJOSEError.claims("allowed_hosts") }
        guard (0...AuthorityTenantRecord.maxKeys).contains(keyItems.count) else { throw AuthorityJOSEError.claims("keys") }
        var keys: [AuthorityTenantKey] = []
        for item in keyItems {
            guard let k = item.objectValue, Set(k.keys) == ["kid", "public_key", "not_after"], let kid = k["kid"]?.stringValue,
                  let jwk = k["public_key"]?.objectValue, Set(jwk.keys) == ["crv", "kty", "x", "y"], jwk["crv"]?.stringValue == "P-256", jwk["kty"]?.stringValue == "EC",
                  let xText = jwk["x"]?.stringValue, Base64URL.isValid(xText, minLength: 43, maxLength: 43), let x = Base64URL.decode(xText), x.count == 32,
                  let yText = jwk["y"]?.stringValue, Base64URL.isValid(yText, minLength: 43, maxLength: 43), let y = Base64URL.decode(yText), y.count == 32,
                  let publicKey = try? P256.Signing.PublicKey(rawRepresentation: x + y), JWKThumbprint.p256(publicKey) == kid,
                  let notAfter = k["not_after"]?.authorityInteger else { throw AuthorityJOSEError.claims("keys") }
            keys.append(AuthorityTenantKey(kid: kid, publicKey: x + y, notAfter: notAfter))
        }
        guard Set(keys.map(\.kid)).count == keys.count else { throw AuthorityJOSEError.claims("keys") }
        let t = Int64(now.timeIntervalSince1970)
        guard issuedAt <= t + skew else { throw AuthorityJOSEError.notYetValid }
        guard t - issuedAt <= AuthorityTenantRecord.maxAge else { throw AuthorityTenantRecordError.stale }
        guard tenant == tenantId else { throw AuthorityTenantRecordError.wrongTenant }
        guard seq >= minimumSeq else { throw AuthorityTenantRecordError.rollback }
        return AuthorityTenantRecord(environment: environment, tenantId: tenant, seq: seq, displayName: name, allowedHosts: hosts, keys: keys, issuedAt: issuedAt)
    }
}

// MARK: - viadere-device-keys-revocation+jws

/// The two pinned key families a revocation list can name (ADR-0033 §3.3).
public enum AuthorityKeyFamily: String, Sendable, Hashable, CaseIterable {
    case deviceStatement = "device-statement"
    case recoverySeal = "recovery-seal"
}

/// One revoked pinned key.
public struct AuthorityRevokedKey: Sendable, Hashable {
    public var family: AuthorityKeyFamily
    public var kid: String
    public init(family: AuthorityKeyFamily, kid: String) {
        self.family = family
        self.kid = kid
    }
    var json: JSONValue { .object(["key_family": .string(family.rawValue), "kid": .string(kid)]) }
}

/// `{v:1, iss, aud, env, revoked:[{key_family, kid}], issued_at}` (ADR-0033 §2).
public struct AuthorityRevocationList: Sendable, Hashable {
    public static let type = "viadere-device-keys-revocation+jws"
    static let members: Set<String> = ["v", "iss", "aud", "env", "revoked", "issued_at"]

    public var environment: AuthorityEnvironment
    public var revoked: [AuthorityRevokedKey]
    public var issuedAt: Int64

    public init(environment: AuthorityEnvironment, revoked: [AuthorityRevokedKey], issuedAt: Int64) {
        self.environment = environment
        self.revoked = revoked
        self.issuedAt = issuedAt
    }

    public var payload: [String: JSONValue] {
        ["v": .integer(1), "iss": .string(environment.authorityURN), "aud": .string(AuthorityAudience.device), "env": .string(environment.rawValue),
         "revoked": .array(revoked.map(\.json)), "issued_at": .integer(issuedAt)]
    }
}

/// A list whose members are well formed but that breaks a rule of ADR-0033 §3.3 is refused **as a whole** (`rule`).
public enum AuthorityRevocationListError: String, Error, Sendable, Equatable {
    case rule
}

extension AuthorityStatementVerifier {
    /// The device check of a `viadere-device-keys-revocation+jws` (ADR-0033 §3.3, revision 3.1 list processing).
    ///
    /// - `statementKeys` and `sealKids` are the pinned lists **in order** `[active, standby]`; `alreadyRevoked` is the device's sticky set.
    /// - Signer: a pinned statement key that is not already revoked (else `unknownKey`), then signature, exact members, `iss`/`aud`/`env`.
    /// - `revoked`: 1 or 2 entries, at most one per family (else `claims`).
    /// - `device-statement`: signed only by the **standby** and naming only the **active** statement key; `recovery-seal`: naming only the active
    ///   seal key. Any entry that breaks a rule refuses the whole list (`rule`). `issued_at` at most 60 s ahead; no freshness limit.
    public static func verifyRevocationList(_ compact: String, statementKeys: [P256.Signing.PublicKey], sealKids: [String], alreadyRevoked: Set<String> = [],
                                            environment: AuthorityEnvironment, now: Date) throws -> AuthorityRevocationList {
        let parts = try AuthorityJWS.parse(compact, expectedType: AuthorityRevocationList.type, allowedAlgorithms: ["ES256"])
        let pinnedKids = statementKeys.map(JWKThumbprint.p256)
        guard !alreadyRevoked.contains(parts.kid), let index = pinnedKids.firstIndex(of: parts.kid) else { throw AuthorityJOSEError.unknownKey }
        try AuthorityJWS.verifyES256(parts, key: statementKeys[index])
        let o = parts.payload
        guard Set(o.keys) == AuthorityRevocationList.members else { throw AuthorityJOSEError.claims("members") }
        guard o["v"]?.authorityInteger == 1, o["iss"]?.stringValue == environment.authorityURN, o["aud"]?.stringValue == AuthorityAudience.device,
              o["env"]?.stringValue == environment.rawValue else { throw AuthorityJOSEError.claims("issuer") }
        guard let issuedAt = o["issued_at"]?.authorityInteger, case .array(let items)? = o["revoked"], (1...2).contains(items.count) else {
            throw AuthorityJOSEError.claims("revoked")
        }
        var revoked: [AuthorityRevokedKey] = []
        for item in items {
            guard let e = item.objectValue, Set(e.keys) == ["key_family", "kid"], let family = e["key_family"]?.stringValue.flatMap(AuthorityKeyFamily.init(rawValue:)),
                  let kid = e["kid"]?.stringValue, Base64URL.isValid(kid, minLength: 43, maxLength: 43) else { throw AuthorityJOSEError.claims("revoked") }
            revoked.append(AuthorityRevokedKey(family: family, kid: kid))
        }
        guard Set(revoked.map(\.family)).count == revoked.count else { throw AuthorityJOSEError.claims("revoked") }
        for entry in revoked {
            switch entry.family {
            case .deviceStatement:
                // Only the standby signs it, and it names only the active key: no list can revoke the standby or the last pinned key.
                guard pinnedKids.count == 2, index == 1, entry.kid == pinnedKids[0] else { throw AuthorityRevocationListError.rule }
            case .recoverySeal:
                guard sealKids.count == 2, entry.kid == sealKids[0] else { throw AuthorityRevocationListError.rule }
            }
        }
        guard issuedAt <= Int64(now.timeIntervalSince1970) + skew else { throw AuthorityJOSEError.notYetValid }
        return AuthorityRevocationList(environment: environment, revoked: revoked, issuedAt: issuedAt)
    }
}

// MARK: - viadere-destination-key-registration+jws

/// Why a destination-key registration proof was refused (ADR-0031 §1.2, revision 3.1 rules (a) to (d)).
public enum DestinationKeyRegistrationError: String, Error, Sendable, Equatable, CaseIterable {
    case malformed
    case unsupportedAlgorithm = "unsupported_algorithm"
    case wrongType = "wrong_type"
    /// The header `kid` (or the payload `kid`) is not the RFC 7638 thumbprint of the submitted key.
    case unknownKey = "unknown_key"
    case badSignature = "bad_signature"
    case wrongIssuer = "wrong_issuer"
    case wrongAudience = "wrong_audience"
    /// `hosts[]` is not exactly the change file's hosts.
    case hostsMismatch = "hosts_mismatch"
    case lifetimeTooLong = "lifetime_too_long"
    case notYetValid = "not_yet_valid"
    case expired
    /// The nonce is not the one the admin job issued for this tenant and key.
    case nonceMismatch = "nonce_mismatch"
    /// The nonce was issued but has been consumed (or expired) already.
    case nonceReused = "nonce_reused"
}

/// The proof of possession a tenant signs with a **new** destination key before the admin job registers it (ADR-0031 §1.2):
/// header exactly `{alg: "ES256", kid, typ: "viadere-destination-key-registration+jws"}`, payload exactly
/// `{v:1, iss: <tenant_id>, aud: "urn:viadere:authority:<env>", kid, hosts[], nonce, iat, exp}` with `exp − iat ≤ 3600`.
public struct DestinationKeyRegistration: Sendable, Hashable {
    public static let type = "viadere-destination-key-registration+jws"
    public static let maxLifetime: Int64 = 3600
    public static let skew: Int64 = 60
    static let members: Set<String> = ["v", "iss", "aud", "kid", "hosts", "nonce", "iat", "exp"]

    public var tenantId: String
    public var environment: AuthorityEnvironment
    public var kid: String
    public var hosts: [String]
    public var nonce: String
    public var issuedAt: Int64
    public var expiresAt: Int64

    public init(tenantId: String, environment: AuthorityEnvironment, kid: String, hosts: [String], nonce: String, issuedAt: Int64, expiresAt: Int64) {
        self.tenantId = tenantId
        self.environment = environment
        self.kid = kid
        self.hosts = hosts
        self.nonce = nonce
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
    }

    public var payload: [String: JSONValue] {
        ["v": .integer(1), "iss": .string(tenantId), "aud": .string(environment.authorityURN), "kid": .string(kid), "hosts": .array(hosts.map { .string($0) }),
         "nonce": .string(nonce), "iat": .integer(issuedAt), "exp": .integer(expiresAt)]
    }

    /// Registration nonces: at least 128 bits from the admin job's CSPRNG (the job issues 256), base64url.
    public static func isNonce(_ value: String) -> Bool { Base64URL.isValid(value, minLength: 22, maxLength: 86) && (Base64URL.decode(value)?.count ?? 0) >= 16 }

    /// What the business SDK calls (`signDestinationKeyRegistration`): the proof by `key` for `hosts` over the issued `nonce`.
    public static func sign(tenantId: String, hosts: [String], nonce: String, environment: AuthorityEnvironment, key: any DeviceSigningKey, issuedAt: Date,
                            lifetime: Int64 = 600) async throws -> String {
        let signing = try key.publicKey.signingKey()
        let kid = JWKThumbprint.p256(signing)
        let iat = Int64(issuedAt.timeIntervalSince1970)
        let claims = DestinationKeyRegistration(tenantId: tenantId, environment: environment, kid: kid, hosts: hosts, nonce: nonce, issuedAt: iat,
                                                expiresAt: iat + min(lifetime, maxLifetime))
        let input = try AuthorityJWS.signingInput(alg: "ES256", kid: kid, typ: type, payload: claims.payload)
        return input + "." + ViadereSignatureEncoding.encode(try await key.signature(for: Data(input.utf8)))
    }

    /// The admin job's check, in this order: profile and `typ`; header `kid` = thumbprint of `publicKey`; signature (both S forms); exact members;
    /// payload `kid` = header `kid`; `iss`; `aud`; `hosts[]` exactly `hosts` (as a set, no duplicates); time (`iat ≤ now + 60`, `exp ≥ now`,
    /// `0 < exp − iat ≤ 3600`); nonce equal to `expectedNonce` (constant time); and last `consumeNonce`, the compare-and-swap that accepts the nonce
    /// **once** (a forged or stale proof therefore never burns a nonce).
    public static func verify(_ compact: String, publicKey: P256.Signing.PublicKey, tenantId: String, environment: AuthorityEnvironment, hosts: Set<String>,
                              expectedNonce: String, now: Date, consumeNonce: () async throws -> Bool) async throws(DestinationKeyRegistrationError) -> DestinationKeyRegistration {
        let parts: AuthorityJWSParts
        do { parts = try AuthorityJWS.parse(compact, expectedType: type, allowedAlgorithms: ["ES256"]) } catch let error as AuthorityJOSEError {
            switch error {
            case .unsupportedAlgorithm: throw .unsupportedAlgorithm
            case .wrongType: throw .wrongType
            default: throw .malformed
            }
        } catch { throw .malformed }
        let kid = JWKThumbprint.p256(publicKey)
        guard ConstantTime.equals(parts.kid, kid) else { throw .unknownKey }
        do { try AuthorityJWS.verifyES256(parts, key: publicKey) } catch { throw .badSignature }
        let o = parts.payload
        guard Set(o.keys) == members, o["v"]?.authorityInteger == 1, let iss = o["iss"]?.stringValue, let aud = o["aud"]?.stringValue,
              let payloadKid = o["kid"]?.stringValue, case .array(let hostItems)? = o["hosts"], let nonce = o["nonce"]?.stringValue, isNonce(nonce),
              let iat = o["iat"]?.authorityInteger, let exp = o["exp"]?.authorityInteger else { throw .malformed }
        let signedHosts = hostItems.compactMap(\.stringValue)
        guard signedHosts.count == hostItems.count, Set(signedHosts).count == signedHosts.count else { throw .malformed }
        guard ConstantTime.equals(payloadKid, kid) else { throw .unknownKey }
        guard iss == tenantId else { throw .wrongIssuer }
        guard aud == environment.authorityURN else { throw .wrongAudience }
        guard Set(signedHosts) == hosts else { throw .hostsMismatch }
        guard exp > iat, exp - iat <= maxLifetime else { throw .lifetimeTooLong }
        let t = Int64(now.timeIntervalSince1970)
        guard iat <= t + skew else { throw .notYetValid }
        guard exp >= t else { throw .expired }
        guard ConstantTime.equals(nonce, expectedNonce) else { throw .nonceMismatch }
        let consumed: Bool
        do { consumed = try await consumeNonce() } catch { throw .nonceReused }
        guard consumed else { throw .nonceReused }
        return DestinationKeyRegistration(tenantId: iss, environment: environment, kid: kid, hosts: signedHosts, nonce: nonce, issuedAt: iat, expiresAt: exp)
    }
}
