@preconcurrency import Crypto
import Foundation

/// How the device verified the person (ADR-0023 §3): `biometric` only from an `approvalBiometric` key; `user_presence` from an
/// `approvalUserPresence` key (biometric or passcode, modality unknown).
public enum FactorUserVerification: String, Sendable, Codable, CaseIterable, Hashable {
    case biometric
    case userPresence = "user_presence"
}

public enum FactorDecision: String, Sendable, Codable, CaseIterable, Hashable {
    case approve, deny, report
}

/// The claims of a `viadere-factor+jws` (device → authority, ADR-0023 §3). Header `{"alg":"ES256","kid":<device KeyIdentifier>,"typ":"viadere-factor+jws"}`.
public struct FactorAssertionClaims: Sendable, Hashable {
    public static let type = "viadere-factor+jws"
    /// `exp − iat ≤ 120`; `iat ≤ now + 60`.
    public static let maxLifetime: Int64 = 120
    public static let skew: Int64 = 60

    public var audience: String
    public var challengeId: String
    public var nonce: String
    public var purpose: AuthorityPurpose
    public var displayDigest: String
    public var returnURL: String?
    public var decision: FactorDecision
    public var userVerification: FactorUserVerification
    public var match: String?
    public var envelopeDigest: String?
    public var headHash: String?
    public var seq: Int64?
    public var codeHash: String?
    public var issuedAt: Int64
    public var expiresAt: Int64

    public init(audience: String, challengeId: String, nonce: String, purpose: AuthorityPurpose, displayDigest: String, returnURL: String? = nil,
                decision: FactorDecision, userVerification: FactorUserVerification, match: String? = nil, envelopeDigest: String? = nil,
                headHash: String? = nil, seq: Int64? = nil, codeHash: String? = nil, issuedAt: Int64, expiresAt: Int64) {
        self.audience = audience
        self.challengeId = challengeId
        self.nonce = nonce
        self.purpose = purpose
        self.displayDigest = displayDigest
        self.returnURL = returnURL
        self.decision = decision
        self.userVerification = userVerification
        self.match = match
        self.envelopeDigest = envelopeDigest
        self.headHash = headHash
        self.seq = seq
        self.codeHash = codeHash
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
    }

    /// The claims a device signs for a verified challenge statement: the digest is computed over the **statement's** display.
    public static func answering(_ statement: AuthorityChallengeStatement, decision: FactorDecision, userVerification: FactorUserVerification, match: String?,
                                 codeHash: String? = nil, now: Date) throws -> FactorAssertionClaims {
        let t = Int64(now.timeIntervalSince1970)
        return FactorAssertionClaims(audience: statement.environment.authorityURN, challengeId: statement.challengeId, nonce: statement.nonce, purpose: statement.purpose,
                                     displayDigest: try AuthorityDisplay.digest(statement.display), returnURL: statement.returnURL, decision: decision,
                                     userVerification: userVerification, match: match, codeHash: codeHash, issuedAt: t, expiresAt: t + maxLifetime)
    }

    public var payload: [String: JSONValue] {
        var o: [String: JSONValue] = [
            "v": .integer(1), "aud": .string(audience), "ach": .string(challengeId), "nonce": .string(nonce), "purpose": .string(purpose.rawValue),
            "display_digest": .string(displayDigest), "decision": .string(decision.rawValue), "uv": .string(userVerification.rawValue),
            "iat": .integer(issuedAt), "exp": .integer(expiresAt),
        ]
        if let returnURL { o["return_url"] = .string(returnURL) }
        if let match { o["match"] = .string(match) }
        if let envelopeDigest { o["envelope_digest"] = .string(envelopeDigest) }
        if let headHash { o["head_hash"] = .string(headHash) }
        if let seq { o["seq"] = .integer(seq) }
        if let codeHash { o["code_hash"] = .string(codeHash) }
        return o
    }

    static let required: Set<String> = ["v", "aud", "ach", "nonce", "purpose", "display_digest", "decision", "uv", "iat", "exp"]
    static let optional: Set<String> = ["return_url", "match", "envelope_digest", "head_hash", "seq", "code_hash"]
}

/// A factor assertion that passed the strict structural checks (not yet the signature: the authority looks the `kid` up in its own key log first).
public struct ParsedFactorAssertion: Sendable {
    public let parts: AuthorityJWSParts
    public let claims: FactorAssertionClaims
    /// The device `KeyIdentifier` (SPKI hash) of the signing key.
    public var kid: String { parts.kid }
}

public enum FactorAssertion {
    public static func sign(_ claims: FactorAssertionClaims, with key: any DeviceSigningKey) async throws -> String {
        try await AuthorityJWS.signES256(typ: FactorAssertionClaims.type, payload: claims.payload, key: key)
    }

    /// Step 1 of ADR-0023 §3: strict parse and JOSE profile, exact member set per purpose, value formats, lifetime ≤ 120 s.
    public static func parse(_ compact: String) throws -> ParsedFactorAssertion {
        let parts = try AuthorityJWS.parse(compact, expectedType: FactorAssertionClaims.type, allowedAlgorithms: ["ES256"])
        guard KeyIdentifier.isValid(parts.kid) else { throw AuthorityJOSEError.malformed("kid") }
        let o = parts.payload
        let keys = Set(o.keys)
        guard FactorAssertionClaims.required.isSubset(of: keys), keys.isSubset(of: FactorAssertionClaims.required.union(FactorAssertionClaims.optional)) else {
            throw AuthorityJOSEError.claims("members")
        }
        guard o["v"]?.authorityInteger == 1, let aud = o["aud"]?.stringValue, let ach = o["ach"]?.stringValue, AuthorityChallengeID.isValid(ach),
              let nonce = o["nonce"]?.stringValue, AuthorityNonce.isValid(nonce),
              let purpose = o["purpose"]?.stringValue.flatMap(AuthorityPurpose.init(rawValue:)),
              let digest = o["display_digest"]?.stringValue, digest.count == 64, digest.allSatisfy({ ("0"..."9").contains($0) || ("a"..."f").contains($0) }),
              let decision = o["decision"]?.stringValue.flatMap(FactorDecision.init(rawValue:)),
              let uv = o["uv"]?.stringValue.flatMap(FactorUserVerification.init(rawValue:)),
              let iat = o["iat"]?.authorityInteger, let exp = o["exp"]?.authorityInteger, iat > 0, exp > iat,
              exp - iat <= FactorAssertionClaims.maxLifetime else { throw AuthorityJOSEError.claims("values") }
        // Purpose-bound members: present exactly where the purpose defines them.
        func string(_ name: String) throws -> String? {
            guard let raw = o[name] else { return nil }
            guard let value = raw.stringValue, !value.isEmpty, value.utf8.count <= 2048 else { throw AuthorityJOSEError.claims(name) }
            return value
        }
        let returnURL = try string("return_url"), match = try string("match"), envelope = try string("envelope_digest"), head = try string("head_hash"),
            codeHash = try string("code_hash")
        var seq: Int64?
        if let raw = o["seq"] { guard let value = raw.authorityInteger, value >= 0 else { throw AuthorityJOSEError.claims("seq") }; seq = value }
        guard (returnURL != nil) == (purpose == .linkOpen) else { throw AuthorityJOSEError.claims("return_url") }
        guard codeHash == nil || purpose == .linkOpen else { throw AuthorityJOSEError.claims("code_hash") }
        guard (envelope != nil) == (purpose == .recoveryCodesSet) else { throw AuthorityJOSEError.claims("envelope_digest") }
        guard (head != nil) == (purpose == .enrollmentConfirmed), (seq != nil) == (purpose == .enrollmentConfirmed) else { throw AuthorityJOSEError.claims("head") }
        if let match { guard (2...6).contains(match.count), match.allSatisfy({ ("0"..."9").contains($0) }) else { throw AuthorityJOSEError.claims("match") } }
        if let codeHash { guard Base64URL.isValid(codeHash, minLength: 43, maxLength: 43) else { throw AuthorityJOSEError.claims("code_hash") } }
        // Only an approve carries a typed number; a deny or report never needs one.
        if match != nil, decision != .approve { throw AuthorityJOSEError.claims("match") }
        let claims = FactorAssertionClaims(audience: aud, challengeId: ach, nonce: nonce, purpose: purpose, displayDigest: digest, returnURL: returnURL,
                                           decision: decision, userVerification: uv, match: match, envelopeDigest: envelope, headHash: head, seq: seq,
                                           codeHash: codeHash, issuedAt: iat, expiresAt: exp)
        return ParsedFactorAssertion(parts: parts, claims: claims)
    }

    /// Step 3: the signature with the **logged** public key; the key's `KeyIdentifier` is recomputed and must equal the header `kid`.
    public static func verifySignature(_ parsed: ParsedFactorAssertion, loggedKey: P256.Signing.PublicKey) throws {
        guard KeyIdentifier.make(loggedKey) == parsed.kid else { throw AuthorityJOSEError.unknownKey }
        try AuthorityJWS.verifyES256(parsed.parts, key: loggedKey)
    }
}
