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

    /// One structured inventory line per key (ADR-0024 §7.3): `name/version` and the public JWK, never private material.
    func inventoryLines() throws -> [String] {
        var entries: [(String, String, [String: JSONValue])] = [
            ("grant-signing", grant.keyRef, JWKThumbprint.p256JWK(grant.publicKey)),
            ("device-statement-signing", statement.keyRef, JWKThumbprint.p256JWK(statement.publicKey)),
        ]
        if let es = oidcES256 { entries.append(("oidc-signing-es256", es.keyRef, JWKThumbprint.p256JWK(es.publicKey))) }
        if let rs = oidcRS256 { entries.append(("oidc-signing-rs256", rs.keyRef, JWKThumbprint.rsaJWK(modulus: rs.modulus, exponent: rs.exponent))) }
        return try entries.map { family, ref, jwk in
            String(decoding: try CanonicalJSON.serialize(.object(["authority_key_inventory": .integer(1), "family": .string(family), "key": .string(ref), "jwk": .object(jwk)])), as: UTF8.self)
        }
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

    func sign(_ challenge: AuthorityChallenge) async throws -> String {
        guard let purpose = AuthorityPurpose(rawValue: challenge.purpose), let display = try? JSONDecoder().decode(JSONValue.self, from: Data(challenge.display.utf8)) else {
            throw AuthorityKeyError.keyUnavailable("statement")
        }
        let statement = AuthorityChallengeStatement(environment: environment, challengeId: challenge.id!, nonce: challenge.nonce, purpose: purpose, display: display,
                                                    returnURL: purpose == .linkOpen ? challenge.targetURL : nil,
                                                    redirectURI: purpose == .oidcLogin ? challenge.targetURL : nil,
                                                    matchRequired: challenge.matchCode != nil,
                                                    issuedAt: Int64(challenge.createdAt.timeIntervalSince1970), expiresAt: Int64(challenge.expiresAt.timeIntervalSince1970))
        return try await KMSJWS.es256(kms: kms, key: keys.statement, typ: AuthorityChallengeStatement.type, payload: statement.payload)
    }
}

/// `viadere-grant+jwt` (ADR-0023 §5) from verified evidence and the link-client record; `aud`, `tid` and the business id come from the record.
struct GrantBuilder {
    let kms: any KeyManagementService
    let keys: AuthorityKeyRing
    let config: AuthorityConfig

    func sign(evidence: VerifiedEvidence, client: AuthorityLinkClient, challenge: AuthorityChallenge, now: Date) async throws -> (compact: String, claims: AuthorityGrantClaims) {
        let subject = SubjectRefDeriver(key: config.subjectRefKey).subjectRef(businessId: BusinessID(client.businessId), consumerId: ConsumerID(evidence.accountId)).rawValue
        let t = Int64(now.timeIntervalSince1970)
        let claims = AuthorityGrantClaims(issuer: config.issuer + "/grant", audience: client.id!, subject: subject, tenantId: client.tenantId,
                                          transaction: challenge.deliveryId ?? "", purpose: challenge.linkPurpose ?? "sign_in", acr: OIDCProfile.acrApp,
                                          amr: evidence.amr, authTime: t, issuedAt: t, expiresAt: t + AuthorityGrantClaims.lifetime,
                                          jti: Base64URL.encode(SecureToken.randomBytes(16)), codeChallenge: challenge.codeChallenge ?? "")
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
