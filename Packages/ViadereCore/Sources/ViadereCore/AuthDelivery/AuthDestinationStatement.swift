import Crypto
import Foundation

/// Why a business-signed destination statement was refused (ADR-0031 sections 3 and 4). Every case is a refusal: the device does not enable Continue,
/// never requests the URL, and reports `destination_unverified`.
public enum AuthDestinationStatementError: String, Error, Sendable, Hashable, CaseIterable {
    case missing
    case malformed
    case unsupportedAlgorithm = "unsupported_algorithm"
    case wrongType = "wrong_type"
    case unknownCriticalHeader = "unknown_critical_header"
    /// The `kid` is not in the authority-published tenant record (or the record was not available: fail closed).
    case unknownKey = "unknown_key"
    case keyExpired = "key_expired"
    case badSignature = "bad_signature"
    case wrongIssuer = "wrong_issuer"
    case wrongAudience = "wrong_audience"
    case wrongSubject = "wrong_subject"
    /// `brq` differs from the delivery's request id.
    case wrongRequest = "wrong_request"
    case wrongPurpose = "wrong_purpose"
    case lifetimeTooLong = "lifetime_too_long"
    case notYetValid = "not_yet_valid"
    case expired
    /// The URL bytes the device received do not hash to `url_sha256`.
    case urlMismatch = "url_mismatch"
    /// The statement's host is not the URL's host, or not in the authority record's `allowed_hosts`.
    case hostNotAllowed = "host_not_allowed"
    case replayed
}

/// `viadere-destination+jws` (ADR-0031 section 3): the business's statement that it issued **this** URL for **this** customer and request.
///
/// * Header exactly `{"alg":"ES256","kid":"…","typ":"viadere-destination+jws"}` (no `crit`, no other member).
/// * Payload (canonical JSON, byte for byte): `{v:1, iss:<tenant id>, aud:"urn:viadere:device", sub:<subject_ref>, brq:<request id>, purpose,
///   url_sha256:<base64url SHA-256 of the exact URL bytes>, host:<lowercase A-label host>, iat, exp, jti}`; integers only; no duplicate members
///   (a canonical payload cannot contain one); `exp - iat <= 600`; `jti` is 128 random bits.
/// * It carries a **digest** of the URL, never the URL, so the statement is not a bearer value (class T).
///
/// The api validates the shape at create, but its check is **not** relied on: the device verifies the signature against the authority-published tenant
/// record (Stage 6) before it enables Continue and compares the URL bytes with `url_sha256` before it opens anything.
public struct AuthDestinationStatement: Sendable, Hashable {
    public static let type = "viadere-destination+jws"
    public static let audience = "urn:viadere:device"
    public static let maxBytes = 2048
    public static let maxLifetime: Int64 = 600
    /// Device clock skew allowance (section 4, step 5).
    public static let skew: Int64 = 60

    public var kid: String
    public var tenantId: String
    public var subjectRef: SubjectRef
    public var requestId: String
    public var purpose: AuthDeliveryPurpose
    public var urlSHA256: String
    public var host: String
    public var issuedAt: Int64
    public var expiresAt: Int64
    public var jti: String

    public init(kid: String, tenantId: String, subjectRef: SubjectRef, requestId: String, purpose: AuthDeliveryPurpose, urlSHA256: String, host: String,
                issuedAt: Int64, expiresAt: Int64, jti: String) {
        self.kid = kid
        self.tenantId = tenantId
        self.subjectRef = subjectRef
        self.requestId = requestId
        self.purpose = purpose
        self.urlSHA256 = urlSHA256
        self.host = host
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.jti = jti
    }

    /// `base64url(SHA-256(url bytes))`.
    public static func digest(of url: String) -> String { Base64URL.encode(Data(SHA256.hash(data: Data(url.utf8)))) }

    /// A fresh `jti`: 128 random bits.
    public static func newJTI() -> String { SecureToken.generate(byteCount: 16) }

    /// What the business's SDK calls (`signAuthDestination`): builds the statement for `url` and signs it with the tenant's destination key.
    public static func build(url: String, tenantId: String, subjectRef: SubjectRef, requestId: String, purpose: AuthDeliveryPurpose, kid: String,
                             issuedAt: Date, lifetime: Int64 = 300, jti: String = newJTI()) throws(AuthDestinationError) -> AuthDestinationStatement {
        let destination = try AuthDestinationValidator.parse(url)
        let iat = Int64(issuedAt.timeIntervalSince1970)
        return AuthDestinationStatement(kid: kid, tenantId: tenantId, subjectRef: subjectRef, requestId: requestId, purpose: purpose, urlSHA256: digest(of: url),
                                        host: destination.host, issuedAt: iat, expiresAt: iat + min(lifetime, maxLifetime), jti: jti)
    }

    var payload: [String: JSONValue] {
        ["v": .integer(1), "iss": .string(tenantId), "aud": .string(Self.audience), "sub": .string(subjectRef.rawValue), "brq": .string(requestId),
         "purpose": .string(purpose.rawValue), "url_sha256": .string(urlSHA256), "host": .string(host), "iat": .integer(issuedAt), "exp": .integer(expiresAt),
         "jti": .string(jti)]
    }

    /// The compact JWS. ECDSA P-256 / SHA-256, raw `r||s`.
    public func sign(with key: any DeviceSigningKey) async throws -> String {
        let header = try CanonicalJSON.serialize(.object(["alg": .string("ES256"), "kid": .string(kid), "typ": .string(Self.type)]))
        let body = try CanonicalJSON.serialize(.object(payload))
        let signingInput = Base64URL.encode(header) + "." + Base64URL.encode(body)
        return signingInput + "." + ViadereSignatureEncoding.encode(try await key.signature(for: Data(signingInput.utf8)))
    }

    // MARK: Parse (shape, no signature)

    /// A parsed, **not yet signature-verified** statement plus the signing input and signature.
    public struct Parsed: Sendable, Hashable {
        public var statement: AuthDestinationStatement
        fileprivate var signingInput: String
        fileprivate var signature: String

        /// Verifies the signature with the tenant's public key (from the authority-published record).
        public func verifySignature(with key: DevicePublicKey) throws(AuthDestinationStatementError) {
            guard let sig = ViadereSignatureEncoding.decode(signature), let verifying = try? key.signingKey(),
                  verifying.isValidSignature(sig, for: Data(signingInput.utf8)) else { throw .badSignature }
        }
    }

    /// Checks the compact form, the exact header and the canonical, closed payload (types, charsets, lifetime). Does not check any signature or time.
    public static func parse(_ compact: String?) throws(AuthDestinationStatementError) -> Parsed {
        guard let compact, !compact.isEmpty else { throw .missing }
        guard compact.utf8.count <= maxBytes else { throw .malformed }
        let segments = compact.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3, segments.allSatisfy({ !$0.isEmpty }), Base64URL.isValid(String(segments[0])), Base64URL.isValid(String(segments[1])),
              let headerBytes = Base64URL.decode(String(segments[0])), let payloadBytes = Base64URL.decode(String(segments[1])),
              case .object(let header)? = JSONValue.parseContract(headerBytes), case .object(let payload)? = JSONValue.parseContract(payloadBytes),
              (try? CanonicalJSON.serialize(.object(header))) == headerBytes, (try? CanonicalJSON.serialize(.object(payload))) == payloadBytes else { throw .malformed }
        if header["crit"] != nil { throw .unknownCriticalHeader }
        guard Set(header.keys) == ["alg", "kid", "typ"] else { throw .malformed }
        guard header["alg"]?.stringValue == "ES256" else { throw .unsupportedAlgorithm }
        guard header["typ"]?.stringValue == type else { throw .wrongType }
        guard let kid = header["kid"]?.stringValue, ManifestJWS.isValidKid(kid) else { throw .malformed }
        let members: Set<String> = ["v", "iss", "aud", "sub", "brq", "purpose", "url_sha256", "host", "iat", "exp", "jti"]
        guard Set(payload.keys) == members, case .integer(1)? = payload["v"], case .integer(let iat)? = payload["iat"], case .integer(let exp)? = payload["exp"],
              let iss = payload["iss"]?.stringValue, let aud = payload["aud"]?.stringValue, let sub = payload["sub"]?.stringValue.flatMap({ SubjectRef($0) }),
              let brq = payload["brq"]?.stringValue, let purposeRaw = payload["purpose"]?.stringValue, let purpose = AuthDeliveryPurpose(rawValue: purposeRaw),
              let digest = payload["url_sha256"]?.stringValue, let host = payload["host"]?.stringValue, let jti = payload["jti"]?.stringValue else { throw .malformed }
        guard isTenantId(iss), AuthDeliveryValidation.isValidIdentifier(brq), Base64URL.isValid(digest, minLength: 43, maxLength: 43), Base64URL.decode(digest)?.count == 32,
              Base64URL.isValid(jti, minLength: 22, maxLength: 22), (try? AuthDestinationValidator.validateHost(host)) != nil else { throw .malformed }
        guard aud == audience else { throw .wrongAudience }
        guard iat > 0, exp > iat, exp - iat <= maxLifetime else { throw .lifetimeTooLong }
        let statement = AuthDestinationStatement(kid: kid, tenantId: iss, subjectRef: sub, requestId: brq, purpose: purpose, urlSHA256: digest, host: host,
                                                 issuedAt: iat, expiresAt: exp, jti: jti)
        return Parsed(statement: statement, signingInput: String(segments[0]) + "." + String(segments[1]), signature: String(segments[2]))
    }

    static func isTenantId(_ value: String) -> Bool {
        (1...64).contains(value.utf8.count) && value.utf8.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || $0 == 0x5F || $0 == 0x2D
        }
    }

    // MARK: Device verification (ADR-0031 section 4, steps 2 to 7)

    /// What the device knows independently of the api.
    public struct Expectation: Sendable {
        /// The tenant's keys from the authority-published, freshly verified record: `kid` to key and `not_after`.
        public var keys: [String: (key: DevicePublicKey, notAfter: Date?)]
        public var allowedHosts: Set<String>
        public var tenantId: String
        public var requestId: String
        public var purpose: AuthDeliveryPurpose
        /// The customer's own reference for the business, when the device knows it from a source other than the api (else `nil`: R-07').
        public var subjectRef: SubjectRef?
        public var now: Date

        public init(keys: [String: (key: DevicePublicKey, notAfter: Date?)], allowedHosts: Set<String>, tenantId: String, requestId: String,
                    purpose: AuthDeliveryPurpose, subjectRef: SubjectRef? = nil, now: Date) {
            self.keys = keys
            self.allowedHosts = allowedHosts
            self.tenantId = tenantId
            self.requestId = requestId
            self.purpose = purpose
            self.subjectRef = subjectRef
            self.now = now
        }
    }

    /// Verifies a statement as the device does **before Continue is enabled**: signature with a key of the authority record, `typ`, `iss`, `aud`, `brq`,
    /// `purpose`, time window (±60 s skew), `host` in the record's `allowed_hosts`, and `jti` not seen before (`seen` records it; keep it until `exp + 60 s`).
    /// With no key in the expectation (the authority record is missing or stale) every statement fails with `unknownKey`: **fail closed**.
    public static func verifyForDevice(_ compact: String?, expectation: Expectation, seenJTI: (String) -> Bool) throws(AuthDestinationStatementError) -> AuthDestinationStatement {
        let parsed = try parse(compact)
        let s = parsed.statement
        guard let entry = expectation.keys[s.kid] else { throw .unknownKey }
        if let notAfter = entry.notAfter, notAfter <= expectation.now { throw .keyExpired }
        try parsed.verifySignature(with: entry.key)
        guard s.tenantId == expectation.tenantId else { throw .wrongIssuer }
        guard s.requestId == expectation.requestId else { throw .wrongRequest }
        guard s.purpose == expectation.purpose else { throw .wrongPurpose }
        if let subject = expectation.subjectRef, subject != s.subjectRef { throw .wrongSubject }
        let now = Int64(expectation.now.timeIntervalSince1970)
        guard s.issuedAt <= now + skew else { throw .notYetValid }
        guard s.expiresAt + skew >= now else { throw .expired }
        guard expectation.allowedHosts.contains(s.host) else { throw .hostNotAllowed }
        guard seenJTI(s.jti) else { throw .replayed }
        return s
    }

    /// After `open` returned the URL: the exact bytes must hash to `url_sha256` and the parsed host must equal `host`; the shared validator runs again.
    public func verifyOpened(url: String, allowedHosts: Set<String>) throws(AuthDestinationStatementError) {
        guard Self.digest(of: url) == urlSHA256 else { throw .urlMismatch }
        guard let destination = try? AuthDestinationValidator.validate(url, allowedHosts: allowedHosts), destination.host == host else { throw .hostNotAllowed }
    }
}
