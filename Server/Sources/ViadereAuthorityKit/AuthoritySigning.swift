@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import Foundation
import ViadereCore
import ViadereServiceSupport

// THE ONLY FILE OF THIS MODULE THAT CALLS THE KMS `sign` OPERATIONS (ADR-0023 §6 "no signing oracle"). `AuthoritySigningScopeTests` scans the
// module and fails if any other file calls `.sign(keyRef:` or `.signRS256(`. Every builder here signs an object it assembles itself from authority
// records or from a value only a verifier can construct (`VerifiedEvidence`, `VerifiedCode`); none takes caller-supplied bytes.

public enum AuthorityKeyError: Error, Sendable, Equatable, CustomStringConvertible {
    /// No reviewed pin for this key name (ADR-0028 §2: never "latest").
    case notPinned(String)
    /// The pinned version's RFC 7638 thumbprint differs from the pinned (attested) thumbprint.
    case thumbprintMismatch(String)
    /// The statement key is not one of the app-pinned keys for this environment (ADR-0033 §3.7).
    case statementKeyNotAppPinned
    case keyUnavailable(String)

    public var description: String {
        switch self {
        case .notPinned(let name): "no reviewed version pin for key \(name)"
        case .thumbprintMismatch(let name): "the pinned version of \(name) does not match its pinned thumbprint"
        case .statementKeyNotAppPinned: "the device-statement key is not an app-pinned key for this environment"
        case .keyUnavailable(let name): "key \(name) is unavailable"
        }
    }
}

/// One authority key at an explicit `name/version`, with its RFC 7638 thumbprint (the JOSE `kid`).
struct PinnedP256Key: Sendable {
    let keyRef: String
    let kid: String
    let publicKey: P256.Signing.PublicKey
}

struct PinnedRSAKey: Sendable {
    let keyRef: String
    let kid: String
    let publicKey: _RSA.Signing.PublicKey
    let modulus: Data
    let exponent: Data
}

/// The authority's signing keys, resolved once at startup (fail closed): every key needs a reviewed pin (`authority_key_pins`), the pinned version's
/// public key must hash to the pinned thumbprint, and the statement key must also be one of the app-pinned keys for the environment.
struct AuthorityKeyRing: Sendable {
    let grant: PinnedP256Key
    let statement: PinnedP256Key
    let oidcES256: PinnedP256Key?
    let oidcRS256: PinnedRSAKey?

    static func load(kms: any KeyManagementService, config: AuthorityConfig, db: any Database) async throws -> AuthorityKeyRing {
        func pin(_ name: String) async throws -> AuthorityKeyPin {
            guard let pin = try await AuthorityKeyPin.find(name, on: db) else { throw AuthorityKeyError.notPinned(name) }
            return pin
        }
        func p256(_ name: String) async throws -> PinnedP256Key {
            let pin = try await pin(name)
            let ref = "\(name)/\(pin.version)"
            let key: P256.Signing.PublicKey
            do { key = try await kms.publicKey(keyRef: ref) } catch { throw AuthorityKeyError.keyUnavailable(name) }
            let kid = JWKThumbprint.p256(key)
            guard ConstantTime.equals(kid, pin.thumbprint) else { throw AuthorityKeyError.thumbprintMismatch(name) }
            return PinnedP256Key(keyRef: ref, kid: kid, publicKey: key)
        }
        func rsa(_ name: String) async throws -> PinnedRSAKey {
            let pin = try await pin(name)
            let ref = "\(name)/\(pin.version)"
            let key: _RSA.Signing.PublicKey
            do { key = try await kms.rsaPublicKey(keyRef: ref) } catch { throw AuthorityKeyError.keyUnavailable(name) }
            let primitives = try key.getKeyPrimitives()
            let kid = JWKThumbprint.rsa(modulus: primitives.modulus, exponent: primitives.publicExponent)
            guard ConstantTime.equals(kid, pin.thumbprint) else { throw AuthorityKeyError.thumbprintMismatch(name) }
            return PinnedRSAKey(keyRef: ref, kid: kid, publicKey: key, modulus: primitives.modulus, exponent: primitives.publicExponent)
        }
        let statement = try await p256(config.deviceStatementKeyName)
        guard config.statementPins.contains(statement.kid) else { throw AuthorityKeyError.statementKeyNotAppPinned }
        let grant = try await p256(config.grantKeyName)
        var es: PinnedP256Key?
        var rs: PinnedRSAKey?
        if config.oidcEnabled {
            es = try await p256(config.oidcES256KeyName)
            rs = try await rsa(config.oidcRS256KeyName)
        }
        // The grant JWKS and the OIDC JWKS never share a key (ADR-0024 §7.5), and no key serves two families.
        let kids = [grant.kid, statement.kid, es?.kid, rs?.kid].compactMap { $0 }
        guard Set(kids).count == kids.count else { throw AuthorityKeyError.thumbprintMismatch("shared key") }
        return AuthorityKeyRing(grant: grant, statement: statement, oidcES256: es, oidcRS256: rs)
    }

    /// The public JWKs of the OIDC token keys (what `authority-publish.yml` publishes from the attested inventory, and what the api verifies with).
    var oidcPublicJWKs: [JSONValue] {
        var keys: [JSONValue] = []
        if let rs = oidcRS256 { keys.append(.object(JWKThumbprint.rsaJWK(modulus: rs.modulus, exponent: rs.exponent))) }
        if let es = oidcES256 { keys.append(.object(JWKThumbprint.p256JWK(es.publicKey))) }
        return keys
    }

    var grantPublicJWKs: [JSONValue] { [.object(JWKThumbprint.p256JWK(grant.publicKey))] }

}

/// The reviewed key inventory (ADR-0024 §7.3, S6-06). **No process prints key material for CI to parse.** The inventory arrives as a reviewed change
/// file (public JWKs read by the crypto-officer group through PIM, or the public half of a seal key) that the admin job records (`key-inventory-record`);
/// the serving authority then checks every recorded row against its **own** source of truth, here: the Key Vault public key at exactly `name/version`
/// (ES256 or RSA), or the `authority_seal_keys` row (whose private half it unwraps and checks at start). The outcome (`verified`, `mismatch`,
/// `unavailable`) is stored; `key-inventory-check` (admin) exits non-zero unless every row of a change is `verified`, and `authority-admin.yml` attests
/// the inventory only after that check succeeded. A wrong or substituted JWK in the change file therefore never reaches the attested inventory.
enum AuthorityKeyInventory {
    /// Verifies every `pending` row (at start, before the pin check, and from the maintenance loop). Returns the number of rows checked.
    @discardableResult
    static func verifyPending(kms: any KeyManagementService, db: any Database, now: Date) async throws -> Int {
        let rows = try await AuthorityInventoryRow.query(on: db).filter(\.$status == "pending").all()
        for row in rows {
            let status = await check(row, kms: kms, db: db)
            row.status = status
            row.checkedAt = now
            try await row.update(on: db)
            await AuthorityAudit.record(db, "authority.key_inventory_check", outcome: status == "verified" ? "success" : "denied", reason: status == "verified" ? nil : status,
                                        kid: row.thumbprint, caller: "authority", detail: "\(row.name)/\(row.version) commit:\(row.changeCommit)", at: now)
        }
        return rows.count
    }

    static func check(_ row: AuthorityInventoryRow, kms: any KeyManagementService, db: any Database) async -> String {
        guard case .object(let jwk)? = try? JSONDecoder().decode(JSONValue.self, from: Data(row.jwk.utf8)) else { return "mismatch" }
        switch row.source {
        case "key_vault":
            let ref = "\(row.name)/\(row.version)"
            let actual: String
            if jwk["kty"]?.stringValue == "RSA" {
                guard let key = try? await kms.rsaPublicKey(keyRef: ref), let p = try? key.getKeyPrimitives() else { return "unavailable" }
                actual = JWKThumbprint.rsa(modulus: p.modulus, exponent: p.publicExponent)
            } else {
                guard let key = try? await kms.publicKey(keyRef: ref) else { return "unavailable" }
                actual = JWKThumbprint.p256(key)
            }
            return ConstantTime.equals(actual, row.thumbprint) ? "verified" : "mismatch"
        case "seal_key":
            guard let seal = try? await AuthoritySealKey.find(row.thumbprint, on: db), seal.state == "ready",
                  ConstantTime.equals(Data(seal.publicJWK.utf8), (try? CanonicalJSON.serialize(.object(jwk))) ?? Data()) else { return "mismatch" }
            return "verified"
        default:
            return "mismatch"
        }
    }
}

/// The active `recovery-seal` private key in authority memory (lean construction, ADR-0034 §5.2, residual R-23). Loaded once at start: the start writes
/// a sign record (`unwrap`) before the Key Vault call (`RecordingKMS`), so the reconciliation expects exactly one `unwrapKey` per start.
struct SealKeyHolder: Sendable {
    let kid: String
    let notAfter: Date
    let privateKey: P256.KeyAgreement.PrivateKey

    /// Unwraps the newest `ready` active seal key. Fails closed: a key whose public half differs from its row, or that is not app-pinned for the
    /// environment (strict deployments; development pins otherwise), is never loaded.
    static func load(kms: any KeyManagementService, db: any Database, pinnedKids: [String], now: Date) async throws -> SealKeyHolder? {
        guard let row = try await AuthoritySealKey.query(on: db).filter(\.$role == "active").filter(\.$state == "ready").sort(\.$createdAt, .descending).first() else {
            return nil
        }
        guard row.notAfter > now, pinnedKids.contains(row.id!), let wrapped = Base64URL.decode(row.wrappedPrivate) else { return nil }
        var raw = try await kms.unwrap(keyRef: "\(row.kekName)/\(row.kekVersion)", ciphertext: wrapped)
        defer { raw.resetBytes(in: 0..<raw.count) }
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: raw)
        guard ConstantTime.equals(RecoverySeal.kid(key.publicKey), row.id!) else { throw AuthorityKeyError.thumbprintMismatch("recovery-seal") }
        return SealKeyHolder(kid: row.id!, notAfter: row.notAfter, privateKey: key)
    }
}

/// ES256 and RS256 compact JWS through the KMS, verified locally against the pinned public key before it is returned.
private enum KMSJWS {
    static func es256(kms: any KeyManagementService, key: PinnedP256Key, typ: String, payload: [String: JSONValue]) async throws -> String {
        let input = try AuthorityJWS.signingInput(alg: "ES256", kid: key.kid, typ: typ, payload: payload)
        let raw = try await kms.sign(keyRef: key.keyRef, digest: Data(SHA256.hash(data: Data(input.utf8))))
        guard let signature = try? P256.Signing.ECDSASignature(rawRepresentation: ViadereSignatureEncoding.normalizedRaw(raw)),
              key.publicKey.isValidSignature(signature, for: Data(input.utf8)) else { throw KMSError.signatureMismatch }
        return input + "." + ViadereSignatureEncoding.encode(signature)
    }

    static func rs256(kms: any KeyManagementService, key: PinnedRSAKey, typ: String, payload: [String: JSONValue]) async throws -> String {
        let input = try AuthorityJWS.signingInput(alg: "RS256", kid: key.kid, typ: typ, payload: payload)
        let raw = try await kms.signRS256(keyRef: key.keyRef, digest: Data(SHA256.hash(data: Data(input.utf8))))
        guard key.publicKey.isValidSignature(_RSA.Signing.RSASignature(rawRepresentation: raw), for: Data(input.utf8), padding: .insecurePKCS1v1_5) else {
            throw KMSError.signatureMismatch
        }
        return input + "." + Base64URL.encode(raw)
    }
}

/// `viadere-challenge+jws` from a **stored** challenge row (ADR-0033 §2): the display is the one the authority built and stored.
struct StatementBuilder {
    let kms: any KeyManagementService
    let keys: AuthorityKeyRing
    let environment: AuthorityEnvironment

    /// `accountRef` and `kids` only for key-log purposes (ADR-0033 §2), from the authority's own records.
    func sign(_ challenge: AuthorityChallenge, accountRef: String? = nil, kids: [String]? = nil) async throws -> String {
        guard let purpose = AuthorityPurpose(rawValue: challenge.purpose), let display = try? JSONDecoder().decode(JSONValue.self, from: Data(challenge.display.utf8)) else {
            throw AuthorityKeyError.keyUnavailable("statement")
        }
        guard purpose.isKeyLog || (accountRef == nil && kids == nil) else { throw AuthorityKeyError.keyUnavailable("statement") }
        let statement = AuthorityChallengeStatement(environment: environment, challengeId: challenge.id!, nonce: challenge.nonce, purpose: purpose, display: display,
                                                    returnURL: purpose == .linkOpen ? challenge.targetURL : nil,
                                                    redirectURI: purpose == .oidcLogin ? challenge.targetURL : nil,
                                                    matchRequired: challenge.matchCode != nil,
                                                    issuedAt: Int64(challenge.createdAt.timeIntervalSince1970), expiresAt: Int64(challenge.expiresAt.timeIntervalSince1970),
                                                    accountRef: accountRef, kids: kids)
        return try await KMSJWS.es256(kms: kms, key: keys.statement, typ: AuthorityChallengeStatement.type, payload: statement.payload)
    }

    /// `viadere-keylog-head+jws` (ADR-0033 §2) from a head the authority computed from its own log (`AuthorityHeads`).
    func sign(head: AuthorityKeyLogHead) async throws -> String {
        guard head.environment == environment else { throw AuthorityKeyError.keyUnavailable("statement") }
        return try await KMSJWS.es256(kms: kms, key: keys.statement, typ: AuthorityKeyLogHead.type, payload: head.payload)
    }
}

/// Wraps the authority's KMS: every `sign`, `signRS256` and `unwrap` first writes an `authority_sign_records` row (key reference and operation, never
/// the digest), and the call is refused when the row cannot be written. The Key Vault `AuditEvent` reconciliation (`AuthorityReconciliation`) matches
/// every Key Vault operation against these rows; an operation without a row alerts (ADR-0023 §6, ADR-0028 §2, ADR-0034 §5.2).
struct RecordingKMS: KeyManagementService {
    let base: any KeyManagementService
    let db: any Database
    let clock: @Sendable () -> Date

    private func record(_ keyRef: String, _ kind: String) async throws {
        let row = AuthoritySignRecord()
        row.keyRef = keyRef
        row.kind = kind
        row.at = clock()
        try await row.create(on: db)
    }

    func sign(keyRef: String, digest: Data) async throws -> Data {
        try await record(keyRef, "sign")
        return try await base.sign(keyRef: keyRef, digest: digest)
    }

    func signRS256(keyRef: String, digest: Data) async throws -> Data {
        try await record(keyRef, "sign")
        return try await base.signRS256(keyRef: keyRef, digest: digest)
    }

    func unwrap(keyRef: String, ciphertext: Data) async throws -> Data {
        try await record(keyRef, "unwrap")
        return try await base.unwrap(keyRef: keyRef, ciphertext: ciphertext)
    }

    func publicKey(keyRef: String) async throws -> P256.Signing.PublicKey { try await base.publicKey(keyRef: keyRef) }
    func rsaPublicKey(keyRef: String) async throws -> _RSA.Signing.PublicKey { try await base.rsaPublicKey(keyRef: keyRef) }
    func wrap(keyRef: String, plaintext: Data) async throws -> KMSWrappedKey { try await base.wrap(keyRef: keyRef, plaintext: plaintext) }
    func resolveVersion(keyRef: String) async throws -> String { try await base.resolveVersion(keyRef: keyRef) }
}

/// `viadere-grant+jwt` (ADR-0023 §5) from a redeemed link code (`VerifiedLinkCode`, constructible only by the redemption) and the link-client record;
/// `aud`, `tid` and the business id come from the record, `sub` from the account that owns the verified key. Signed only at redemption (ADR-0021 §5.4).
struct GrantBuilder {
    let kms: any KeyManagementService
    let keys: AuthorityKeyRing
    let config: AuthorityConfig

    func sign(link: VerifiedLinkCode, client: AuthorityLinkClient, now: Date) async throws -> (compact: String, claims: AuthorityGrantClaims) {
        let subject = SubjectRefDeriver(key: config.subjectRefKey).subjectRef(businessId: BusinessID(client.businessId), consumerId: ConsumerID(link.accountId)).rawValue
        let t = Int64(now.timeIntervalSince1970)
        let claims = AuthorityGrantClaims(issuer: config.issuer + "/grant", audience: client.id!, subject: subject, tenantId: client.tenantId,
                                          transaction: link.deliveryId, purpose: link.purpose, acr: OIDCProfile.acrApp,
                                          amr: link.amr, authTime: Int64(link.authTime.timeIntervalSince1970), issuedAt: t, expiresAt: t + AuthorityGrantClaims.lifetime,
                                          jti: Base64URL.encode(SecureToken.randomBytes(16)), codeChallenge: link.codeChallenge)
        return (try await KMSJWS.es256(kms: kms, key: keys.grant, typ: AuthorityGrantClaims.type, payload: claims.payload), claims)
    }
}

/// id_token and RFC 9068 access token from a verified, consumed authorization code (ADR-0024 §6).
struct OIDCTokenBuilder {
    let kms: any KeyManagementService
    let keys: AuthorityKeyRing
    let config: AuthorityConfig

    struct Tokens {
        let idToken: String
        let accessToken: String
        let idTokenJTI: String
        let accessTokenJTI: String
        let idTokenKid: String
        let accessTokenKid: String
        let subject: String
    }

    func sign(code: VerifiedCode, client: AuthorityOIDCClient, now: Date) async throws -> Tokens {
        let t = Int64(now.timeIntervalSince1970)
        let sub = OIDCProfile.pairwiseSubject(key: config.oidcPairwiseKey, sectorHost: client.sectorIdentifier, accountId: code.accountId)
        let idJTI = Base64URL.encode(SecureToken.randomBytes(16)), atJTI = Base64URL.encode(SecureToken.randomBytes(16))
        let idClaims: [String: JSONValue] = [
            "iss": .string(config.issuer), "sub": .string(sub), "aud": .string(client.id!), "azp": .string(client.id!), "nonce": .string(code.nonce),
            "auth_time": .integer(Int64(code.authTime.timeIntervalSince1970)), "acr": .string(code.acr), "amr": .array(code.amr.map { .string($0) }),
            "iat": .integer(t), "exp": .integer(t + OIDCProfile.tokenLifetime), "jti": .string(idJTI),
        ]
        let atClaims: [String: JSONValue] = [
            "iss": .string(config.issuer), "sub": .string(sub), "aud": .string(config.issuer + "/oidc/userinfo"), "client_id": .string(client.id!),
            "scope": .string("openid"), "iat": .integer(t), "exp": .integer(t + OIDCProfile.tokenLifetime), "jti": .string(atJTI),
        ]
        guard let es = keys.oidcES256, let rs = keys.oidcRS256 else { throw AuthorityKeyError.keyUnavailable("oidc") }
        let idToken: String
        let idKid: String
        if client.idTokenAlg == "ES256" {
            idToken = try await KMSJWS.es256(kms: kms, key: es, typ: "JWT", payload: idClaims)
            idKid = es.kid
        } else {
            idToken = try await KMSJWS.rs256(kms: kms, key: rs, typ: "JWT", payload: idClaims)
            idKid = rs.kid
        }
        let accessToken = try await KMSJWS.es256(kms: kms, key: es, typ: "at+jwt", payload: atClaims)
        return Tokens(idToken: idToken, accessToken: accessToken, idTokenJTI: idJTI, accessTokenJTI: atJTI, idTokenKid: idKid, accessTokenKid: es.kid, subject: sub)
    }
}
