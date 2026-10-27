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
}

/// The claims of an ApprovalResult v1 (section 2.54).
public struct ApprovalResultClaims: Sendable, Hashable {
    public static let version: Int64 = 1
    /// Longest `exp - iat` a verifier accepts.
    public static let maxLifetime: TimeInterval = 600

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

    var object: [String: JSONValue] {
        ["v": .integer(Self.version), "alg": .string("ES256"), "kid": .string(kid), "aud": .string(audience.description), "sub": .string(subject.rawValue),
         "request_id": .string(requestId), "challenge": .string(challenge), "cap": .string(capability.rawValue), "decision": .string(decision.rawValue),
         "amr": .string(amr.rawValue), "iat": .integer(issuedAt), "exp": .integer(expiresAt), "txn_digest": .string(transactionDigest)]
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
        guard v == ApprovalResultClaims.version else { throw ApprovalVerificationError.unsupportedVersion(v) }
        guard Set(o.keys) == ["v", "alg", "kid", "aud", "sub", "request_id", "challenge", "cap", "decision", "amr", "iat", "exp", "txn_digest"] else {
            throw ApprovalVerificationError.malformed("claims")
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
        return ApprovalResultClaims(kid: parts.kid, audience: aud, subject: sub, requestId: requestId, challenge: challenge, capability: cap,
                                    decision: decision, amr: amr, issuedAt: Date(timeIntervalSince1970: TimeInterval(iat)),
                                    expiresAt: Date(timeIntervalSince1970: TimeInterval(exp)), transactionDigest: digest)
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

    /// The business's expectation: the challenge and the transaction come from **its own** records, so a result for different parameters
    /// cannot verify.
    public init(audience: BusinessID, subject: SubjectRef, requestId: String, challenge: String, subjectDetails: ApprovalSubject,
                requestExpiresAt: Date? = nil, minimumAMR: ApprovalAMR? = nil, maxClockSkew: TimeInterval = 60) {
        self.audience = audience
        self.subject = subject
        self.requestId = requestId
        capability = subjectDetails.capability
        self.challenge = challenge
        self.subjectDetails = subjectDetails
        self.requestExpiresAt = requestExpiresAt
        self.minimumAMR = minimumAMR
        self.maxClockSkew = maxClockSkew
    }

    /// The relay's expectation (Viadere's own defense-in-depth check): it knows the business, customer, request and capability, and knows the
    /// challenge and details only for server-visible requests. **Never use it to authorize anything**: only the business can check the digest
    /// against its own transaction record.
    public init(relayAudience audience: BusinessID, subject: SubjectRef, requestId: String, capability: Capability, challenge: String?,
                subjectDetails: ApprovalSubject?, requestExpiresAt: Date?, minimumAMR: ApprovalAMR?, maxClockSkew: TimeInterval = 60) {
        self.audience = audience
        self.subject = subject
        self.requestId = requestId
        self.capability = capability
        self.challenge = challenge
        self.subjectDetails = subjectDetails
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
        return VerifiedApproval(claims: claims)
    }

    /// `verify`, then requires `approve` and consumes the one-time challenge in `replayGuard` (atomic). Use this to grant access.
    public static func verifyAndConsume(_ compact: String, expecting expectation: ApprovalExpectation, keys: [EnrolledApprovalKey], now: Date,
                                        replayGuard: any ReplayGuard) async throws -> VerifiedApproval {
        let verified = try verify(compact, expecting: expectation, keys: keys, now: now)
        guard verified.decision == .approve else { throw ApprovalVerificationError.notApproved(verified.decision) }
        // Consumed only after every other check passed: a forged or wrong result cannot burn a real challenge.
        let fresh = try await replayGuard.registerIfFresh(nonce: verified.replayKey, scope: "approval-result", expiresAt: verified.claims.expiresAtDate.addingTimeInterval(expectation.maxClockSkew), now: now)
        guard fresh else { throw ApprovalVerificationError.replayed }
        return verified
    }
}
