import Crypto
import Foundation

/// What the customer decided.
public enum ApprovalDecision: String, Sendable, Codable, CaseIterable, Hashable {
    case approve, deny
    /// "This wasn't me": a signed denial that also reports the request as suspicious.
    case report
}

/// Why an `ApprovalResult` was refused. Every case is a refusal: a business must never treat any of them as an approval.
public enum ApprovalVerificationError: Error, Sendable, Equatable {
    case malformed(String)
    /// The header names an algorithm other than `ES256` (downgrade protection: `none`, `HS256`, anything else).
    case unsupportedAlgorithm(String)
    case unsupportedType
    /// A `crit` header names an extension this verifier does not understand.
    case unknownCriticalHeader(String)
    case unsupportedVersion(Int64)
    /// The header's `kid` is not an enrolled, active key for this subject.
    case unknownKey
    case keyRevoked
    case badSignature
    /// The payload's `alg` or `kid` disagrees with the signed header.
    case headerPayloadMismatch
    case wrongAudience
    case wrongSubject
    case wrongRequest
    case wrongCapability
    case challengeMismatch
    /// The signed transaction digest is not the digest of the transaction the business holds.
    case transactionMismatch
    case expired
    case issuedInFuture
    case notYetValid
    case lifetimeTooLong
    case decidedAfterRequestExpiry
    case notApproved(ApprovalDecision)
    case insufficientAuthentication
    /// The claimed authentication method exceeds what the enrolled key can provide.
    case amrExceedsKey
    case replayed
    /// ADR-0022 §3: the request required a typed number, and the result is v1 (no `match` member exists) — a downgrade.
    case numberMatchRequired
    /// The approve's `match` is missing or differs from the code the verifier recorded.
    case numberMismatch
    /// The result carries `match` for a request that never asked for one.
    case unexpectedMatch
}

/// The claims of an ApprovalResult (section 2.54): v1, or v2 (ADR-0022 §3, ADR-0023 §2) with `jti` and the optional `match`, `deny_reason` and
/// `invalid_match_attempts`.
public struct ApprovalResultClaims: Sendable, Hashable {
    public static let version: Int64 = 1
    /// Number matching and the replay id (ADR-0022 §3).
    public static let version2: Int64 = 2
    /// Longest `exp - iat` a verifier accepts.
    public static let maxLifetime: TimeInterval = 600
    static let v1Members: Set<String> = ["v", "alg", "kid", "aud", "sub", "request_id", "challenge", "cap", "decision", "amr", "iat", "exp", "txn_digest"]
    static let v2Required: Set<String> = v1Members.union(["jti"])
    static let v2Optional: Set<String> = ["match", "deny_reason", "invalid_match_attempts"]

    /// `1` or `2`.
    public var v: Int64 = ApprovalResultClaims.version
    /// v2 only: 128 random bits, base64url (22 characters). Stored by the relay and by the business's verifier for replay rejection.
    public var jti: String?
    /// v2 only: the number the person typed (2 or 3 digits). Present on an approve of a number-matched request.
    public var match: String?
    /// v2 only, and only when `decision` is `deny` (`number_mismatch`, `destination_unverified`) or `report` (`not_me`).
    public var denyReason: ApprovalDenyReason?
    /// v2 only: wrong entries the device counted for this request (0...3). Advisory.
    public var invalidMatchAttempts: Int?

    public var kid: String
    /// The business the result is addressed to.
    public var audience: BusinessID
    /// The business's pairwise reference for the customer.
    public var subject: SubjectRef
    public var requestId: String
    public var challenge: String
    public var capability: Capability
    public var decision: ApprovalDecision
    public var amr: ApprovalAMR
    public var issuedAt: Int64
    public var expiresAt: Int64
    /// `ApprovalSubject.digest()` of what the device displayed.
    public var transactionDigest: String

    public init(kid: String, audience: BusinessID, subject: SubjectRef, requestId: String, challenge: String, capability: Capability,
                decision: ApprovalDecision, amr: ApprovalAMR, issuedAt: Date, expiresAt: Date, transactionDigest: String) {
        self.kid = kid
        self.audience = audience
        self.subject = subject
        self.requestId = requestId
        self.challenge = challenge
        self.capability = capability
        self.decision = decision
        self.amr = amr
        self.issuedAt = ViadereDate.unixSeconds(issuedAt)
        self.expiresAt = ViadereDate.unixSeconds(expiresAt)
        self.transactionDigest = transactionDigest
    }

    /// These claims as a v2 result: a fresh `jti` (unless given) and the number-match members.
    public func asVersion2(jti: String = SecureToken.generate(byteCount: 16), match: String?, denyReason: ApprovalDenyReason?, invalidMatchAttempts: Int?) -> ApprovalResultClaims {
        var copy = self
        copy.v = Self.version2
        copy.jti = jti
        copy.match = match
        copy.denyReason = denyReason
        copy.invalidMatchAttempts = invalidMatchAttempts
        return copy
    }

    var object: [String: JSONValue] {
        var o: [String: JSONValue] = [
            "v": .integer(v), "alg": .string("ES256"), "kid": .string(kid), "aud": .string(audience.description), "sub": .string(subject.rawValue),
            "request_id": .string(requestId), "challenge": .string(challenge), "cap": .string(capability.rawValue), "decision": .string(decision.rawValue),
            "amr": .string(amr.rawValue), "iat": .integer(issuedAt), "exp": .integer(expiresAt), "txn_digest": .string(transactionDigest)]
        guard v == Self.version2 else { return o }
        o["jti"] = jti.map(JSONValue.string)
        if let match { o["match"] = .string(match) }
        if let denyReason { o["deny_reason"] = .string(denyReason.rawValue) }
        if let invalidMatchAttempts { o["invalid_match_attempts"] = .integer(Int64(invalidMatchAttempts)) }
        return o
    }

    /// `jti`: exactly 16 bytes, base64url without padding.
    public static func isValidJTI(_ value: String) -> Bool { Base64URL.isValid(value, minLength: 22, maxLength: 22) && Base64URL.decode(value)?.count == 16 }

    /// The v2 presence rules (ADR-0022 §3): `deny_reason` only on a refusal and consistent with it; `match` well-formed; attempts 0...3.
    static func v2MembersAreConsistent(decision: ApprovalDecision, match: String?, denyReason: ApprovalDenyReason?, attempts: Int?) -> Bool {
        if let match, !ApprovalNumberMatch.isValid(code: match, digits: match.utf8.count) { return false }
        if let attempts, !(0...3).contains(attempts) { return false }
        switch (decision, denyReason) {
        case (_, nil): return true
        case (.approve, _?): return false
        case (.report, .notMe?): return true
        case (.deny, .numberMismatch?), (.deny, .destinationUnverified?): return true
        default: return false
        }
    }

    public var issuedAtDate: Date { Date(timeIntervalSince1970: TimeInterval(issuedAt)) }
    public var expiresAtDate: Date { Date(timeIntervalSince1970: TimeInterval(expiresAt)) }
}

/// The compact JWS (RFC 7515) of an ApprovalResult: `BASE64URL(header) . BASE64URL(payload) . BASE64URL(signature)`.
///
/// * **Header** (canonical JSON): `{"alg":"ES256","kid":"<approval key id>","typ":"viadere-approval+jws"}`. Only `alg`, `kid`, `typ` and
///   `crit` are accepted; any other header parameter is refused (no `jwk`, `jku`, `x5u`, `b64`, `zip`, ...), and a `crit` header is refused
///   because this version defines no critical extensions. `alg` must be exactly `ES256`: `none`, `HS256`, `ES384`, ... are rejected.
/// * **Payload** (canonical JSON, byte for byte): `v, alg, kid, aud, sub, request_id, challenge, cap, decision, amr, iat, exp, txn_digest`.
///   `alg` and `kid` repeat the header, and the verifier requires them equal, so neither can be swapped after signing.
/// * **Signature**: ECDSA P-256 / SHA-256, raw `r ‖ s` (64 bytes), over the ASCII bytes `header64 + "." + payload64` (RFC 7515 section 5.1).
public enum ApprovalResultJWS {
    public static let type = "viadere-approval+jws"
    public static let maxBytes = 2048
    /// Critical header extensions this verifier understands. None in version 1: a `crit` header is always refused.
    static let understoodCritical: Set<String> = []

    // MARK: Sign (device)

    public static func sign(_ claims: ApprovalResultClaims, with key: any DeviceSigningKey) async throws -> String {
        let header = try CanonicalJSON.serialize(.object(["alg": .string("ES256"), "kid": .string(claims.kid), "typ": .string(type)]))
        let payload = try CanonicalJSON.serialize(.object(claims.object))
        let signingInput = Base64URL.encode(header) + "." + Base64URL.encode(payload)
        let signature = try await key.signature(for: Data(signingInput.utf8))
        return signingInput + "." + ViadereSignatureEncoding.encode(signature)
    }

    // MARK: Parse

    /// The structurally valid parts of a compact JWS. Nothing is trusted until the signature has verified.
    public struct Parts: Sendable {
        public let kid: String
        let signingInput: Data
        let signature: P256.Signing.ECDSASignature
        let payload: [String: JSONValue]
    }

    /// Strict structural parse: three base64url segments, canonical header with an allowed member set, `alg == ES256`, `typ`, no `crit`,
    /// canonical payload. Does **not** check the signature.
    public static func parse(_ compact: String) throws -> Parts {
        guard compact.utf8.count <= maxBytes else { throw ApprovalVerificationError.malformed("size") }
        let segments = compact.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3, segments.allSatisfy({ !$0.isEmpty }) else { throw ApprovalVerificationError.malformed("segments") }
        guard let headerBytes = Base64URL.decode(String(segments[0])), let payloadBytes = Base64URL.decode(String(segments[1])),
              Base64URL.isValid(String(segments[0])), Base64URL.isValid(String(segments[1])),
              case .object(let header)? = try? JSONDecoder().decode(JSONValue.self, from: headerBytes),
              case .object(let payload)? = try? JSONDecoder().decode(JSONValue.self, from: payloadBytes),
              (try? CanonicalJSON.serialize(.object(header))) == headerBytes, (try? CanonicalJSON.serialize(.object(payload))) == payloadBytes else {
            throw ApprovalVerificationError.malformed("encoding")
        }
        // Critical extensions first: a header with an extension we do not understand is refused whatever else it says (RFC 7515 4.1.11).
        if let crit = header["crit"] {
            guard case .array(let names) = crit, !names.isEmpty, names.allSatisfy({ $0.stringValue != nil }) else { throw ApprovalVerificationError.malformed("crit") }
            for name in names.compactMap(\.stringValue) where !understoodCritical.contains(name) { throw ApprovalVerificationError.unknownCriticalHeader(String(name.prefix(40))) }
        }
        guard Set(header.keys).isSubset(of: ["alg", "typ", "kid", "crit"]) else { throw ApprovalVerificationError.malformed("header members") }
        guard let alg = header["alg"]?.stringValue else { throw ApprovalVerificationError.malformed("alg") }
        guard alg == "ES256" else { throw ApprovalVerificationError.unsupportedAlgorithm(String(alg.prefix(20))) }
        guard header["typ"]?.stringValue == type else { throw ApprovalVerificationError.unsupportedType }
        guard let kid = header["kid"]?.stringValue, KeyIdentifier.isValid(kid) else { throw ApprovalVerificationError.malformed("kid") }
        guard let signature = ViadereSignatureEncoding.decode(String(segments[2])) else { throw ApprovalVerificationError.malformed("signature") }
        return Parts(kid: kid, signingInput: Data((String(segments[0]) + "." + String(segments[1])).utf8), signature: signature, payload: payload)
    }

    /// Verifies the signature of `parts` with `key` and decodes the claims, checking the header/payload agreement.
    static func claims(of parts: Parts, key: DevicePublicKey) throws -> ApprovalResultClaims {
        guard let verifying = try? key.signingKey(), verifying.isValidSignature(parts.signature, for: parts.signingInput) else { throw ApprovalVerificationError.badSignature }
        let o = parts.payload
        guard case .integer(let v)? = o["v"] else { throw ApprovalVerificationError.malformed("v") }
        guard v == ApprovalResultClaims.version || v == ApprovalResultClaims.version2 else { throw ApprovalVerificationError.unsupportedVersion(v) }
        // Exact member sets (S1-A3-09): v1 is closed; v2 is the v1 set plus `jti`, plus only the three optional number-match members.
        let keys = Set(o.keys)
        if v == ApprovalResultClaims.version {
            guard keys == ApprovalResultClaims.v1Members else { throw ApprovalVerificationError.malformed("claims") }
        } else {
            guard ApprovalResultClaims.v2Required.isSubset(of: keys), keys.isSubset(of: ApprovalResultClaims.v2Required.union(ApprovalResultClaims.v2Optional)) else {
                throw ApprovalVerificationError.malformed("claims")
            }
        }
        guard o["alg"]?.stringValue == "ES256", o["kid"]?.stringValue == parts.kid else { throw ApprovalVerificationError.headerPayloadMismatch }
        guard let aud = o["aud"]?.stringValue.flatMap(BusinessID.init), let sub = o["sub"]?.stringValue.flatMap({ SubjectRef($0) }),
              let requestId = o["request_id"]?.stringValue, E2EEContext.validIdentifier(requestId),
              let challenge = o["challenge"]?.stringValue, ChallengeNonce(challenge) != nil,
              let cap = o["cap"]?.stringValue.map(Capability.init(rawValue:)), cap == .authChallenge || cap == .transactionApprove,
              let decision = o["decision"]?.stringValue.flatMap(ApprovalDecision.init(rawValue:)),
              let amr = o["amr"]?.stringValue.flatMap(ApprovalAMR.init(rawValue:)),
              let iat = o["iat"]?.int64Value, let exp = o["exp"]?.int64Value, iat > 0, exp > iat,
              let digest = o["txn_digest"]?.stringValue, Interaction.isValidContextDigest(digest) else { throw ApprovalVerificationError.malformed("claims values") }
        var claims = ApprovalResultClaims(kid: parts.kid, audience: aud, subject: sub, requestId: requestId, challenge: challenge, capability: cap,
                                          decision: decision, amr: amr, issuedAt: Date(timeIntervalSince1970: TimeInterval(iat)),
                                          expiresAt: Date(timeIntervalSince1970: TimeInterval(exp)), transactionDigest: digest)
        guard v == ApprovalResultClaims.version2 else { return claims }
        guard let jti = o["jti"]?.stringValue, ApprovalResultClaims.isValidJTI(jti) else { throw ApprovalVerificationError.malformed("jti") }
        var match: String?
        if let raw = o["match"] { guard let value = raw.stringValue else { throw ApprovalVerificationError.malformed("match") }; match = value }
        var reason: ApprovalDenyReason?
        if let raw = o["deny_reason"] {
            guard let value = raw.stringValue.flatMap(ApprovalDenyReason.init(rawValue:)) else { throw ApprovalVerificationError.malformed("deny_reason") }
            reason = value
        }
        var attempts: Int?
        if let raw = o["invalid_match_attempts"] {
            guard let value = raw.int64Value, (0...3).contains(value) else { throw ApprovalVerificationError.malformed("invalid_match_attempts") }
            attempts = Int(value)
        }
        guard ApprovalResultClaims.v2MembersAreConsistent(decision: decision, match: match, denyReason: reason, attempts: attempts) else {
            throw ApprovalVerificationError.malformed("claims values")
        }
        claims = claims.asVersion2(jti: jti, match: match, denyReason: reason, invalidMatchAttempts: attempts)
        return claims
    }
}

/// An approval key the verifier knows (the business's own enrollment record; the relay's database on the Viadere side).
public struct EnrolledApprovalKey: Sendable, Hashable {
    public var kid: String
    public var publicKey: DevicePublicKey
    /// The pairwise customer reference this key was enrolled for.
    public var subject: SubjectRef
    /// The access-control class the key was **enrolled** with (signed in the enrollment statement). A result may not claim more.
    public var assurance: ApprovalAMR
    public var revoked: Bool

    public init(kid: String, publicKey: DevicePublicKey, subject: SubjectRef, assurance: ApprovalAMR, revoked: Bool = false) {
        self.kid = kid
        self.publicKey = publicKey
        self.subject = subject
        self.assurance = assurance
        self.revoked = revoked
    }
}

/// What the business (or the relay) requires of a result: everything comes from the verifier's **own records**, never from the result.
public struct ApprovalExpectation: Sendable {
    public var audience: BusinessID
    public var subject: SubjectRef
    public var requestId: String
    public var capability: Capability
    /// The business's nonce. `nil` only for the relay of an end-to-end request, which never sees it.
    public var challenge: String?
    /// The transaction as the business recorded it (its digest is recomputed). `nil` only for the relay of an end-to-end request.
    public var subjectDetails: ApprovalSubject?
    /// When the request expires; a decision issued later is refused.
    public var requestExpiresAt: Date?
    public var minimumAMR: ApprovalAMR?
    public var maxClockSkew: TimeInterval
    /// Number matching (ADR-0022 §3, S1-A3-08): **required in every initializer, with no default**, so a verifier cannot forget it and accept a
    /// result without the typed number for a request that asked for one.
    public var numberMatch: NumberMatchExpectation

    /// The business's expectation: the challenge and the transaction come from **its own** records, so a result for different parameters
    /// cannot verify.
    public init(audience: BusinessID, subject: SubjectRef, requestId: String, challenge: String, subjectDetails: ApprovalSubject, numberMatch: NumberMatchExpectation,
                requestExpiresAt: Date? = nil, minimumAMR: ApprovalAMR? = nil, maxClockSkew: TimeInterval = 60) {
        self.audience = audience
        self.subject = subject
        self.requestId = requestId
        capability = subjectDetails.capability
        self.challenge = challenge
        self.subjectDetails = subjectDetails
        self.numberMatch = numberMatch
        self.requestExpiresAt = requestExpiresAt
        self.minimumAMR = minimumAMR
        self.maxClockSkew = maxClockSkew
    }

    /// The relay's expectation (Viadere's own defense-in-depth check): it knows the business, customer, request and capability, and knows the
    /// challenge and details only for server-visible requests. **Never use it to authorize anything**: only the business can check the digest
    /// against its own transaction record.
    public init(relayAudience audience: BusinessID, subject: SubjectRef, requestId: String, capability: Capability, challenge: String?,
                subjectDetails: ApprovalSubject?, numberMatch: NumberMatchExpectation, requestExpiresAt: Date?, minimumAMR: ApprovalAMR?, maxClockSkew: TimeInterval = 60) {
        self.audience = audience
        self.subject = subject
        self.requestId = requestId
        self.capability = capability
        self.challenge = challenge
        self.subjectDetails = subjectDetails
        self.numberMatch = numberMatch
        self.requestExpiresAt = requestExpiresAt
        self.minimumAMR = minimumAMR
        self.maxClockSkew = maxClockSkew
    }
}

/// A result that passed every check. `replayKey` identifies it for the one-time-use cache.
public struct VerifiedApproval: Sendable, Hashable {
    public var claims: ApprovalResultClaims
    public var decision: ApprovalDecision { claims.decision }
    /// `aud ‖ kid ‖ challenge`: consume it atomically (`ReplayGuard`) **after** verification succeeded, expiring at `expiresAt`.
    public var replayKey: String { "approval:\(claims.audience)|\(claims.kid)|\(claims.challenge)" }
    /// v2: `aud ‖ jti`, consumed as well (ADR-0023 §7 "business side: `jti` / `aud‖kid‖challenge`").
    public var jtiReplayKey: String? { claims.jti.map { "approval-jti:\(claims.audience)|\($0)" } }
}

/// Verifies an ApprovalResult against the verifier's own records. Pure; the replay cache is the caller's (`ReplayGuard`).
public enum ApprovalResultVerifier {
    /// - Parameters:
    ///   - keys: the enrolled keys for the expected subject. A `kid` outside this list is refused (`unknownKey`).
    /// - Throws: `ApprovalVerificationError`. Only a returned `VerifiedApproval` with `decision == .approve` authorizes anything.
    public static func verify(_ compact: String, expecting expectation: ApprovalExpectation, keys: [EnrolledApprovalKey], now: Date) throws -> VerifiedApproval {
        let parts = try ApprovalResultJWS.parse(compact)
        guard let key = keys.first(where: { $0.kid == parts.kid }) else { throw ApprovalVerificationError.unknownKey }
        guard !key.revoked else { throw ApprovalVerificationError.keyRevoked }
        // The kid is only a handle: the key it names must really have that identifier.
        guard (try? key.publicKey.signingKey()).map({ KeyIdentifier.make($0) == key.kid }) == true else { throw ApprovalVerificationError.unknownKey }
        let claims = try ApprovalResultJWS.claims(of: parts, key: key.publicKey)

        guard claims.audience == expectation.audience else { throw ApprovalVerificationError.wrongAudience }
        guard claims.subject == expectation.subject, key.subject == expectation.subject else { throw ApprovalVerificationError.wrongSubject }
        guard claims.requestId == expectation.requestId else { throw ApprovalVerificationError.wrongRequest }
        guard claims.capability == expectation.capability else { throw ApprovalVerificationError.wrongCapability }
        if let challenge = expectation.challenge, !ConstantTime.equals(claims.challenge, challenge) { throw ApprovalVerificationError.challengeMismatch }
        if let details = expectation.subjectDetails {
            guard ConstantTime.equals(claims.transactionDigest, try details.digest()) else { throw ApprovalVerificationError.transactionMismatch }
        }

        guard claims.issuedAtDate <= now.addingTimeInterval(expectation.maxClockSkew) else { throw ApprovalVerificationError.issuedInFuture }
        guard claims.expiresAtDate > now else { throw ApprovalVerificationError.expired }
        guard TimeInterval(claims.expiresAt - claims.issuedAt) <= ApprovalResultClaims.maxLifetime else { throw ApprovalVerificationError.lifetimeTooLong }
        if let requestExpiry = expectation.requestExpiresAt, claims.issuedAtDate > requestExpiry.addingTimeInterval(expectation.maxClockSkew) {
            throw ApprovalVerificationError.decidedAfterRequestExpiry
        }
        guard claims.amr.rank <= key.assurance.rank else { throw ApprovalVerificationError.amrExceedsKey }
        if let minimum = expectation.minimumAMR, !claims.amr.satisfies(minimum) { throw ApprovalVerificationError.insufficientAuthentication }
        try checkNumberMatch(claims, expectation.numberMatch)
        return VerifiedApproval(claims: claims)
    }

    /// ADR-0022 §3: `.required` needs v2 and, on an approve, `match` equal in constant time to the verifier's own code; `.notRequested` refuses any `match`.
    static func checkNumberMatch(_ claims: ApprovalResultClaims, _ expectation: NumberMatchExpectation) throws {
        switch expectation.kind {
        case .notRequested:
            guard claims.match == nil else { throw ApprovalVerificationError.unexpectedMatch }
        case .required(let code):
            guard claims.v == ApprovalResultClaims.version2 else { throw ApprovalVerificationError.numberMatchRequired }
            if claims.decision == .approve {
                guard let match = claims.match, ConstantTime.equals(match, code) else { throw ApprovalVerificationError.numberMismatch }
            }
        case .relayRequired(let digits):
            guard claims.v == ApprovalResultClaims.version2 else { throw ApprovalVerificationError.numberMatchRequired }
            if claims.decision == .approve {
                guard let match = claims.match, match.utf8.count == digits else { throw ApprovalVerificationError.numberMismatch }
            }
        }
    }

    /// `verify`, then requires `approve` and consumes the one-time challenge in `replayGuard` (atomic). Use this to grant access.
    public static func verifyAndConsume(_ compact: String, expecting expectation: ApprovalExpectation, keys: [EnrolledApprovalKey], now: Date,
                                        replayGuard: any ReplayGuard) async throws -> VerifiedApproval {
        let verified = try verify(compact, expecting: expectation, keys: keys, now: now)
        guard verified.decision == .approve else { throw ApprovalVerificationError.notApproved(verified.decision) }
        // Consumed only after every other check passed: a forged or wrong result cannot burn a real challenge.
        let horizon = verified.claims.expiresAtDate.addingTimeInterval(expectation.maxClockSkew)
        let fresh = try await replayGuard.registerIfFresh(nonce: verified.replayKey, scope: "approval-result", expiresAt: horizon, now: now)
        guard fresh else { throw ApprovalVerificationError.replayed }
        // v2: the `jti` is recorded too, so the same signed bytes are refused under any other expectation as well.
        if let jtiKey = verified.jtiReplayKey {
            guard try await replayGuard.registerIfFresh(nonce: jtiKey, scope: "approval-jti", expiresAt: horizon, now: now) else { throw ApprovalVerificationError.replayed }
        }
        return verified
    }
}
