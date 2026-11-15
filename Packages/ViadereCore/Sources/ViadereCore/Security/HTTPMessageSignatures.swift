import Crypto
import Foundation

/// The Viadere profile of RFC 9421 (HTTP Message Signatures) with RFC 9530 `Content-Digest`, for business API requests (SECURITY §2.112,
/// ADR-0020 §3). Shared by the server's verifier and the Swift business SDK's signer; the TypeScript SDK and the Python vector generator are
/// independent implementations checked against `docs/protocol/vectors/http-signatures-v1.json`.
///
/// ```
/// Content-Digest:  sha-256=:<base64 SHA-256 of the exact body>:          (only when there is a body)
/// Signature-Input: sig1=("@method" "@authority" "@path" "@query" "content-digest" "content-type");created=…;expires=…;keyid="vsk_…";nonce="…";tag="viadere-api-v1"
/// Signature:       sig1=:<base64 raw r‖s, 64 bytes, low S>:
/// ```
/// A request without a body covers exactly `"@method" "@authority" "@path" "@query"`. Nothing else is accepted: no other component, no component
/// parameter, no other algorithm, one signature per request.
public enum HTTPSignatureProfile {
    public static let tag = "viadere-api-v1"
    public static let algorithm = "ecdsa-p256-sha256"
    /// The label the SDKs write. A verifier accepts any one well-formed label that both fields share.
    public static let label = "sig1"
    public static let bodyComponents = ["@method", "@authority", "@path", "@query", "content-digest", "content-type"]
    public static let bodilessComponents = ["@method", "@authority", "@path", "@query"]
    public static let requiredParameters: Set<String> = ["created", "expires", "keyid", "nonce", "tag"]
    public static let optionalParameters: Set<String> = ["alg"]
    /// `now - created` may not exceed this (the device-signing window of SECURITY §2.3).
    public static let maxAge: Int64 = 300
    /// `created - now` may not exceed this.
    public static let maxFutureSkew: Int64 = 300
    /// `expires - created` is in `1...maxLifetime`.
    public static let maxLifetime: Int64 = 300
    /// How long a nonce stays recorded (it outlives every signature that could carry it).
    public static let nonceTTL: TimeInterval = 600
    /// Header names (lowercase, as component names).
    public static let signatureInputField = "signature-input"
    public static let signatureField = "signature"
    public static let contentDigestField = "content-digest"
    public static let contentTypeField = "content-type"

    /// `vsk_` and 16 lowercase hex characters (issued by Viadere at registration).
    public static func isValidKeyId(_ value: String) -> Bool {
        value.count == 20 && value.hasPrefix("vsk_") && value.dropFirst(4).allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
    }

    /// base64url, 22 to 64 characters (at least 16 random bytes).
    public static func isValidNonce(_ value: String) -> Bool { Base64URL.isValid(value, minLength: 22, maxLength: 64) }

    /// The replay-guard scope of a nonce.
    public static func replayScope(businessId: String, keyId: String) -> String { "bizsig:\(businessId.lowercased()):\(keyId)" }

    /// `sha-256=:<base64>:` of `body` (RFC 9530).
    public static func contentDigest(_ body: Data) -> String { "sha-256=:" + Data(SHA256.hash(data: body)).base64EncodedString() + ":" }

    /// The `@authority` of an origin: lowercase host, the default port omitted (RFC 9110 §4.2.3).
    public static func authority(host: String, port: Int?, scheme: String) -> String {
        let h = host.lowercased()
        guard let port, !((scheme == "https" && port == 443) || (scheme == "http" && port == 80)) else { return h }
        return "\(h):\(port)"
    }

    /// `@authority` of a base URL such as `https://viadere.com`.
    public static func authority(of url: URL) -> String? {
        guard let host = url.host, !host.isEmpty, let scheme = url.scheme?.lowercased() else { return nil }
        return authority(host: host, port: url.port, scheme: scheme)
    }

    /// `@path` and `@query` from the request target exactly as on the request line (never decoded): `/a?b=c` → (`/a`, `?b=c`); no query → `?`.
    public static func pathAndQuery(_ target: String) -> (path: String, query: String) {
        if let mark = target.firstIndex(of: "?") {
            return (String(target[..<mark]), String(target[mark...]))
        }
        return (target, "?")
    }
}

/// Why a request signature is refused. The raw values are the normative error codes of the vectors and the audit trail; the order in which the
/// verifier checks them is SECURITY §2.112.
public enum HTTPSignatureError: String, Error, Sendable, CaseIterable {
    case missingSignature = "missing_signature"
    case signatureIncomplete = "signature_incomplete"
    case duplicateField = "duplicate_field"
    case malformedSignatureInput = "malformed_signature_input"
    case malformedSignature = "malformed_signature"
    case multipleSignatures = "multiple_signatures"
    case labelMismatch = "label_mismatch"
    case componentParameters = "component_parameters"
    case digestRequired = "digest_required"
    case digestNotAllowed = "digest_not_allowed"
    case malformedDigest = "malformed_digest"
    case digestMismatch = "digest_mismatch"
    case contentTypeRequired = "content_type_required"
    case wrongComponents = "wrong_components"
    case unknownParameter = "unknown_parameter"
    case duplicateParameter = "duplicate_parameter"
    case malformedParameter = "malformed_parameter"
    case missingParameter = "missing_parameter"
    case wrongAlgorithm = "wrong_algorithm"
    case wrongTag = "wrong_tag"
    case malformedKeyId = "malformed_keyid"
    case malformedNonce = "malformed_nonce"
    case createdInFuture = "created_in_future"
    case stale = "stale"
    case invalidExpires = "invalid_expires"
    case expired = "expired"
    case notRawSignature = "not_raw_signature"
    case highS = "high_s"
    case unknownKey = "unknown_key"
    case revokedKey = "revoked_key"
    case wrongBusiness = "wrong_business"
    case wrongAPIKey = "wrong_api_key"
    case badSignature = "bad_signature"
    case replayed = "replayed"
    case nonASCII = "non_ascii"

    /// A time-window refusal (the server answers `clock_skew` so an integrator can tell a clock problem from a forgery).
    public var isClock: Bool { self == .createdInFuture || self == .stale || self == .expired }
}

/// The parameters of one signature, in the order they were (or will be) serialized.
public struct HTTPSignatureParameters: Sendable, Hashable {
    public enum Value: Sendable, Hashable {
        case integer(Int64)
        case string(String)
    }

    /// Covered component names, in order.
    public var components: [String]
    /// `(name, value)` pairs in serialization order.
    public var parameters: [(String, Value)]

    public init(components: [String], parameters: [(String, Value)]) {
        self.components = components
        self.parameters = parameters
    }

    /// The parameters the SDKs write: created, expires, keyid, nonce, tag.
    public init(components: [String], created: Int64, expires: Int64, keyId: String, nonce: String, tag: String = HTTPSignatureProfile.tag) {
        self.init(components: components, parameters: [("created", .integer(created)), ("expires", .integer(expires)), ("keyid", .string(keyId)),
                                                       ("nonce", .string(nonce)), ("tag", .string(tag))])
    }

    public static func == (a: Self, b: Self) -> Bool {
        a.components == b.components && a.parameters.count == b.parameters.count && zip(a.parameters, b.parameters).allSatisfy { $0.0 == $1.0 && $0.1 == $1.1 }
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(components)
        for (name, value) in parameters { hasher.combine(name); hasher.combine(value) }
    }

    /// The `@signature-params` value (RFC 9421 §2.3): an inner list of sf-strings, then `;name=value` for each parameter.
    public var serialized: String {
        var out = "(" + components.map { "\"\($0)\"" }.joined(separator: " ") + ")"
        for (name, value) in parameters {
            switch value {
            case .integer(let i): out += ";\(name)=\(i)"
            case .string(let s): out += ";\(name)=\"\(s)\""
            }
        }
        return out
    }

    public func integer(_ name: String) -> Int64? {
        for (n, v) in parameters where n == name { if case .integer(let i) = v { return i } }
        return nil
    }

    public func string(_ name: String) -> String? {
        for (n, v) in parameters where n == name { if case .string(let s) = v { return s } }
        return nil
    }
}

/// The values a signature covers.
public struct HTTPSignatureMessage: Sendable, Hashable {
    public var method: String
    public var authority: String
    /// The request target exactly as on the request line (`/path?query`).
    public var target: String
    public var contentDigest: String?
    public var contentType: String?

    public init(method: String, authority: String, target: String, contentDigest: String? = nil, contentType: String? = nil) {
        self.method = method
        self.authority = authority
        self.target = target
        self.contentDigest = contentDigest
        self.contentType = contentType
    }

    func value(of component: String) throws -> String {
        let (path, query) = HTTPSignatureProfile.pathAndQuery(target)
        switch component {
        case "@method": return method
        case "@authority": return authority
        case "@path": return path
        case "@query": return query
        case "content-digest":
            guard let contentDigest else { throw HTTPSignatureError.digestRequired }
            return contentDigest
        case "content-type":
            guard let contentType else { throw HTTPSignatureError.contentTypeRequired }
            return contentType
        default: throw HTTPSignatureError.wrongComponents
        }
    }
}

public enum HTTPMessageSignature {
    /// The signature base (RFC 9421 §2.5): `"name": value` LF for each component, then the `@signature-params` line, no trailing LF. ASCII only.
    public static func signatureBase(_ message: HTTPSignatureMessage, _ parameters: HTTPSignatureParameters) throws -> String {
        var out = ""
        var seen = Set<String>()
        for component in parameters.components {
            guard seen.insert(component).inserted else { throw HTTPSignatureError.wrongComponents }
            out += "\"\(component)\": " + (try message.value(of: component)) + "\n"
        }
        out += "\"@signature-params\": " + parameters.serialized
        guard out.unicodeScalars.allSatisfy({ $0.value == 0x0A || (0x20...0x7E).contains($0.value) }) else { throw HTTPSignatureError.nonASCII }
        return out
    }

    /// `true` when the 64-byte raw signature has `s <= n/2` and `0 < s < n`.
    public static func isLowS(_ raw: Data) -> Bool {
        guard raw.count == 64 else { return false }
        return ViadereSignatureEncoding.normalizedRaw(raw) == raw
    }

    // MARK: Strict structured-field parsing (only what the profile uses)

    struct Scanner {
        let bytes: [UInt8]
        var i = 0
        init(_ s: String) { bytes = Array(s.utf8) }
        var atEnd: Bool { i >= bytes.count }
        var peek: UInt8? { atEnd ? nil : bytes[i] }
        mutating func expect(_ c: UInt8) throws(HTTPSignatureError) {
            guard peek == c else { throw HTTPSignatureError.malformedSignatureInput }
            i += 1
        }
        /// sf-key: lcalpha / "*", then lcalpha / DIGIT / "_" / "-" / "." / "*" (RFC 8941 §3.1.2), at most 64 characters.
        mutating func key() throws(HTTPSignatureError) -> String {
            let start = i
            guard let first = peek, (0x61...0x7A).contains(first) || first == 0x2A else { throw HTTPSignatureError.malformedSignatureInput }
            i += 1
            while let c = peek, (0x61...0x7A).contains(c) || (0x30...0x39).contains(c) || c == 0x5F || c == 0x2D || c == 0x2E || c == 0x2A { i += 1 }
            guard i - start <= 64 else { throw HTTPSignatureError.malformedSignatureInput }
            return String(decoding: bytes[start..<i], as: UTF8.self)
        }
        /// sf-string without escapes (no profile value contains `"` or `\`).
        mutating func string() throws(HTTPSignatureError) -> String {
            try expect(0x22)
            let start = i
            while let c = peek, c != 0x22 {
                guard (0x20...0x7E).contains(c), c != 0x5C else { throw HTTPSignatureError.malformedSignatureInput }
                i += 1
            }
            let value = String(decoding: bytes[start..<i], as: UTF8.self)
            try expect(0x22)
            return value
        }
        /// sf-integer, non-negative, at most 15 digits, no leading zero.
        mutating func integer() throws(HTTPSignatureError) -> Int64 {
            let start = i
            while let c = peek, (0x30...0x39).contains(c) { i += 1 }
            let digits = bytes[start..<i]
            guard !digits.isEmpty, digits.count <= 15, !(digits.count > 1 && digits.first == 0x30), let value = Int64(String(decoding: digits, as: UTF8.self)) else {
                throw HTTPSignatureError.malformedSignatureInput
            }
            return value
        }
    }

    /// Parses `Signature-Input` and requires its strict serialization: one dictionary member `label=(…)` with parameters. Component parameters are
    /// recognized only to be refused (`component_parameters`).
    public static func parseSignatureInput(_ value: String) throws(HTTPSignatureError) -> (label: String, parameters: HTTPSignatureParameters) {
        var s = Scanner(value)
        let label = try s.key()
        try s.expect(0x3D) // =
        try s.expect(0x28) // (
        var components: [String] = []
        var componentParameters = false
        while s.peek != 0x29 {
            if !components.isEmpty { try s.expect(0x20) }
            components.append(try s.string())
            // A component identifier with parameters (`"content-type";sf`, `;key="a"`, `;req`, `;bs`, `;tr`).
            while s.peek == 0x3B {
                s.i += 1
                _ = try s.key()
                if s.peek == 0x3D { s.i += 1; if s.peek == 0x22 { _ = try s.string() } else { _ = try s.integer() } }
                componentParameters = true
            }
        }
        try s.expect(0x29) // )
        var parameters: [(String, HTTPSignatureParameters.Value)] = []
        while s.peek == 0x3B {
            s.i += 1
            let name = try s.key()
            try s.expect(0x3D)
            if s.peek == 0x22 { parameters.append((name, .string(try s.string()))) } else { parameters.append((name, .integer(try s.integer()))) }
        }
        if s.peek == 0x2C { throw HTTPSignatureError.multipleSignatures }
        guard s.atEnd else { throw HTTPSignatureError.malformedSignatureInput }
        if componentParameters { throw HTTPSignatureError.componentParameters }
        let parsed = HTTPSignatureParameters(components: components, parameters: parameters)
        // Strict serialization: what we would write is exactly what was received.
        guard "\(label)=" + parsed.serialized == value else { throw HTTPSignatureError.malformedSignatureInput }
        return (label, parsed)
    }

    /// Parses `Signature`: one member `label=:base64:` (an RFC 8941 byte sequence, canonical padded standard base64).
    public static func parseSignature(_ value: String) throws(HTTPSignatureError) -> (label: String, signature: Data) {
        var s = Scanner(value)
        let label: String
        do { label = try s.key() } catch { throw HTTPSignatureError.malformedSignature }
        guard s.peek == 0x3D else { throw HTTPSignatureError.malformedSignature }
        s.i += 1
        guard s.peek == 0x3A else { throw HTTPSignatureError.malformedSignature }
        s.i += 1
        let start = s.i
        while let c = s.peek, c != 0x3A {
            guard (0x41...0x5A).contains(c) || (0x61...0x7A).contains(c) || (0x30...0x39).contains(c) || c == 0x2B || c == 0x2F || c == 0x3D else {
                throw HTTPSignatureError.malformedSignature
            }
            s.i += 1
        }
        let text = String(decoding: s.bytes[start..<s.i], as: UTF8.self)
        guard s.peek == 0x3A else { throw HTTPSignatureError.malformedSignature }
        s.i += 1
        if s.peek == 0x2C { throw HTTPSignatureError.multipleSignatures }
        guard s.atEnd, let bytes = Data(base64Encoded: text), bytes.base64EncodedString() == text else { throw HTTPSignatureError.malformedSignature }
        return (label, bytes)
    }

    /// `Content-Digest` with exactly one member, `sha-256`, of 32 bytes; returns the digest bytes.
    public static func parseContentDigest(_ value: String) throws(HTTPSignatureError) -> Data {
        let prefix = "sha-256=:"
        guard value.hasPrefix(prefix), value.hasSuffix(":"), value.count == prefix.count + 44 + 1 else { throw HTTPSignatureError.malformedDigest }
        let text = String(value.dropFirst(prefix.count).dropLast())
        guard let bytes = Data(base64Encoded: text), bytes.count == 32, bytes.base64EncodedString() == text else { throw HTTPSignatureError.malformedDigest }
        return bytes
    }
}

// MARK: Verification

/// A received request, as the verifier needs it.
public struct HTTPSignatureRequest: Sendable {
    public var method: String
    /// The request target exactly as on the request line.
    public var target: String
    /// Every field line, in order (name case-insensitive). Duplicates matter: they are refused, never joined.
    public var fields: [(name: String, value: String)]
    public var body: Data

    public init(method: String, target: String, fields: [(name: String, value: String)], body: Data) {
        self.method = method
        self.target = target
        self.fields = fields
        self.body = body
    }

    func values(_ name: String) -> [String] {
        fields.filter { $0.name.lowercased() == name }.map { $0.value.trimmingCharacters(in: CharacterSet(charactersIn: " \t")) }
    }

    /// Whether the request carries any signature field (a request without one is unsigned, not malformed).
    public var isSigned: Bool { !values(HTTPSignatureProfile.signatureInputField).isEmpty || !values(HTTPSignatureProfile.signatureField).isEmpty }
}

/// A request whose signature passed every check that needs no key: structure, components, parameters, time window, digest, signature encoding.
public struct ParsedHTTPSignature: Sendable {
    public var label: String
    public var parameters: HTTPSignatureParameters
    /// 64 bytes, low S.
    public var signature: Data
    public var keyId: String
    public var nonce: String
    public var created: Int64
    public var expires: Int64
    public var method: String
    public var target: String
    public var contentDigest: String?
    public var contentType: String?

    /// The signature base for a candidate authority.
    public func signatureBase(authority: String) throws -> String {
        try HTTPMessageSignature.signatureBase(HTTPSignatureMessage(method: method, authority: authority, target: target, contentDigest: contentDigest,
                                                                   contentType: contentType), parameters)
    }

    /// Verifies the signature against `publicKey` over each accepted authority (the verifier never reads `Host`; the authorities come from configuration).
    public func verify(publicKey: DevicePublicKey, authorities: [String]) throws(HTTPSignatureError) {
        guard let key = try? publicKey.signingKey(), let ecdsa = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { throw HTTPSignatureError.badSignature }
        for authority in authorities {
            guard let base = try? signatureBase(authority: authority) else { continue }
            if key.isValidSignature(ecdsa, for: Data(base.utf8)) { return }
        }
        throw HTTPSignatureError.badSignature
    }
}

public enum HTTPSignatureVerifier {
    /// Steps 1 to 6 of SECURITY §2.112 (everything before the key lookup), in the normative order.
    public static func parse(_ request: HTTPSignatureRequest, now: Date) throws(HTTPSignatureError) -> ParsedHTTPSignature {
        // 1. Field lines.
        let inputs = request.values(HTTPSignatureProfile.signatureInputField)
        let signatures = request.values(HTTPSignatureProfile.signatureField)
        if inputs.isEmpty && signatures.isEmpty { throw HTTPSignatureError.missingSignature }
        if inputs.count > 1 || signatures.count > 1 { throw HTTPSignatureError.duplicateField }
        guard inputs.count == 1, signatures.count == 1 else { throw HTTPSignatureError.signatureIncomplete }
        let digests = request.values(HTTPSignatureProfile.contentDigestField)
        let types = request.values(HTTPSignatureProfile.contentTypeField)
        guard digests.count <= 1, types.count <= 1 else { throw HTTPSignatureError.duplicateField }
        // 2. Signature-Input and Signature.
        let (label, parameters) = try HTTPMessageSignature.parseSignatureInput(inputs[0])
        let (signatureLabel, signature) = try HTTPMessageSignature.parseSignature(signatures[0])
        guard label == signatureLabel else { throw HTTPSignatureError.labelMismatch }
        // 3. Body, digest, content type, then the covered components.
        let hasBody = !request.body.isEmpty
        var contentDigest: String?
        var contentType: String?
        if hasBody {
            guard let digest = digests.first else { throw HTTPSignatureError.digestRequired }
            let expected = Data(SHA256.hash(data: request.body))
            guard try HTTPMessageSignature.parseContentDigest(digest) == expected else { throw HTTPSignatureError.digestMismatch }
            guard let type = types.first, !type.isEmpty else { throw HTTPSignatureError.contentTypeRequired }
            contentDigest = digest
            contentType = type
        } else if !digests.isEmpty {
            throw HTTPSignatureError.digestNotAllowed
        }
        guard parameters.components == (hasBody ? HTTPSignatureProfile.bodyComponents : HTTPSignatureProfile.bodilessComponents) else {
            throw HTTPSignatureError.wrongComponents
        }
        // 4. Parameters.
        var names = Set<String>()
        for (name, _) in parameters.parameters {
            guard HTTPSignatureProfile.requiredParameters.contains(name) || HTTPSignatureProfile.optionalParameters.contains(name) else { throw HTTPSignatureError.unknownParameter }
            guard names.insert(name).inserted else { throw HTTPSignatureError.duplicateParameter }
        }
        for (name, value) in parameters.parameters {
            switch (name, value) {
            case ("created", .integer), ("expires", .integer), ("keyid", .string), ("nonce", .string), ("tag", .string), ("alg", .string): continue
            default: throw HTTPSignatureError.malformedParameter
            }
        }
        guard HTTPSignatureProfile.requiredParameters.isSubset(of: names), let created = parameters.integer("created"), let expires = parameters.integer("expires"),
              let keyId = parameters.string("keyid"), let nonce = parameters.string("nonce"), let tag = parameters.string("tag") else {
            throw HTTPSignatureError.missingParameter
        }
        if let alg = parameters.string("alg"), alg != HTTPSignatureProfile.algorithm { throw HTTPSignatureError.wrongAlgorithm }
        guard tag == HTTPSignatureProfile.tag else { throw HTTPSignatureError.wrongTag }
        guard HTTPSignatureProfile.isValidKeyId(keyId) else { throw HTTPSignatureError.malformedKeyId }
        guard HTTPSignatureProfile.isValidNonce(nonce) else { throw HTTPSignatureError.malformedNonce }
        // 5. Time.
        let current = Int64(now.timeIntervalSince1970.rounded(.down))
        guard created - current <= HTTPSignatureProfile.maxFutureSkew else { throw HTTPSignatureError.createdInFuture }
        guard current - created <= HTTPSignatureProfile.maxAge else { throw HTTPSignatureError.stale }
        guard expires > created, expires - created <= HTTPSignatureProfile.maxLifetime else { throw HTTPSignatureError.invalidExpires }
        guard current <= expires else { throw HTTPSignatureError.expired }
        // 6. Signature encoding: raw r‖s (64 bytes, so DER is refused), canonical low S.
        guard signature.count == 64 else { throw HTTPSignatureError.notRawSignature }
        guard HTTPMessageSignature.isLowS(signature) else { throw HTTPSignatureError.highS }
        return ParsedHTTPSignature(label: label, parameters: parameters, signature: signature, keyId: keyId, nonce: nonce, created: created, expires: expires,
                                   method: request.method, target: request.target, contentDigest: contentDigest, contentType: contentType)
    }

    /// A registered request-signing key as the verifier sees it.
    public struct RegisteredKey: Sendable {
        public var publicKey: DevicePublicKey
        public var businessId: String
        public var apiKeyIds: Set<String>
        public var revoked: Bool
        public init(publicKey: DevicePublicKey, businessId: String, apiKeyIds: Set<String>, revoked: Bool) {
            self.publicKey = publicKey
            self.businessId = businessId.lowercased()
            self.apiKeyIds = Set(apiKeyIds.map { $0.lowercased() })
            self.revoked = revoked
        }
    }

    /// Steps 7 to 9: key binding, signature, single-use nonce. `apiKeyId` is the API key that authenticated the request; the signing key must be
    /// bound to it (a rotation successor carries the binding, see the server).
    public static func verify(_ parsed: ParsedHTTPSignature, key: RegisteredKey?, businessId: String, apiKeyId: String, authorities: [String],
                              replayGuard: any ReplayGuard, now: Date) async throws -> ParsedHTTPSignature {
        guard let key else { throw HTTPSignatureError.unknownKey }
        guard !key.revoked else { throw HTTPSignatureError.revokedKey }
        guard key.businessId == businessId.lowercased() else { throw HTTPSignatureError.wrongBusiness }
        guard key.apiKeyIds.contains(apiKeyId.lowercased()) else { throw HTTPSignatureError.wrongAPIKey }
        try parsed.verify(publicKey: key.publicKey, authorities: authorities)
        let fresh = try await replayGuard.registerIfFresh(nonce: parsed.nonce, scope: HTTPSignatureProfile.replayScope(businessId: businessId, keyId: parsed.keyId),
                                                          expiresAt: now.addingTimeInterval(HTTPSignatureProfile.nonceTTL), now: now)
        guard fresh else { throw HTTPSignatureError.replayed }
        return parsed
    }
}

// MARK: Signing

/// Signs with a request-signing key: a software key, or a KMS/HSM. Returns raw `r‖s` (64 bytes) or DER; either S; the SDK normalizes and checks.
public protocol HTTPRequestSigningKey: Sendable {
    /// The `vsk_…` id Viadere showed when the key was registered.
    var keyId: String { get }
    /// The public half (base64url X9.63), used to check every signature before it is sent.
    var publicKey: DevicePublicKey { get }
    /// ECDSA P-256 / SHA-256 over `message` (the implementation hashes).
    func sign(_ message: Data) async throws -> Data
}

/// A software key (tests, small deployments). Prefer a KMS or HSM in production.
public struct SoftwareHTTPRequestSigningKey: HTTPRequestSigningKey {
    public let keyId: String
    private let raw: Data
    public let publicKey: DevicePublicKey

    public init(keyId: String, rawRepresentation: Data) throws {
        let key = try P256.Signing.PrivateKey(rawRepresentation: rawRepresentation)
        self.keyId = keyId
        raw = key.rawRepresentation
        publicKey = DevicePublicKey(key.publicKey)
    }

    public init(keyId: String, privateKey: P256.Signing.PrivateKey) {
        self.keyId = keyId
        raw = privateKey.rawRepresentation
        publicKey = DevicePublicKey(privateKey.publicKey)
    }

    public func sign(_ message: Data) async throws -> Data {
        try P256.Signing.PrivateKey(rawRepresentation: raw).signature(for: message).rawRepresentation
    }
}

public enum HTTPSignatureSigningError: Error, Sendable, Equatable {
    case invalidKeyId
    case invalidNonce
    case notAnECDSASignature
    case signatureDoesNotVerify
    case nonASCII
}

public struct HTTPRequestSigner: Sendable {
    public let key: any HTTPRequestSigningKey
    /// Seconds between `created` and `expires` (1 to 300).
    public var lifetime: Int64

    public init(key: any HTTPRequestSigningKey, lifetime: Int64 = HTTPSignatureProfile.maxLifetime) {
        self.key = key
        self.lifetime = min(max(1, lifetime), HTTPSignatureProfile.maxLifetime)
    }

    /// The header fields to add: `Content-Digest` (when there is a body), `Signature-Input`, `Signature`. The caller sets `Content-Type` to the
    /// value passed here, and sends `target` and `body` byte for byte.
    public func sign(method: String, authority: String, target: String, body: Data?, contentType: String?, now: Date = Date(),
                     nonce: String = SecureToken.generate(byteCount: 16)) async throws -> [(name: String, value: String)] {
        guard HTTPSignatureProfile.isValidKeyId(key.keyId) else { throw HTTPSignatureSigningError.invalidKeyId }
        guard HTTPSignatureProfile.isValidNonce(nonce) else { throw HTTPSignatureSigningError.invalidNonce }
        let created = Int64(now.timeIntervalSince1970.rounded(.down))
        let payload = body ?? Data()
        let hasBody = !payload.isEmpty
        let digest = hasBody ? HTTPSignatureProfile.contentDigest(payload) : nil
        let parameters = HTTPSignatureParameters(components: hasBody ? HTTPSignatureProfile.bodyComponents : HTTPSignatureProfile.bodilessComponents,
                                                 created: created, expires: created + lifetime, keyId: key.keyId, nonce: nonce)
        let base: String
        do {
            base = try HTTPMessageSignature.signatureBase(HTTPSignatureMessage(method: method.uppercased(), authority: authority, target: target, contentDigest: digest,
                                                                              contentType: hasBody ? (contentType ?? "application/json") : nil), parameters)
        } catch { throw HTTPSignatureSigningError.nonASCII }
        let produced = try await key.sign(Data(base.utf8))
        let parsed: P256.Signing.ECDSASignature
        if produced.count == 64, let raw = try? P256.Signing.ECDSASignature(rawRepresentation: produced) { parsed = raw }
        else if let fromDER = try? P256.Signing.ECDSASignature(derRepresentation: produced) { parsed = fromDER }
        else { throw HTTPSignatureSigningError.notAnECDSASignature }
        let raw = ViadereSignatureEncoding.normalizedRaw(parsed.rawRepresentation)
        guard let check = try? P256.Signing.ECDSASignature(rawRepresentation: raw), let verifier = try? key.publicKey.signingKey(),
              verifier.isValidSignature(check, for: Data(base.utf8)) else { throw HTTPSignatureSigningError.signatureDoesNotVerify }
        var fields: [(name: String, value: String)] = []
        if let digest { fields.append(("Content-Digest", digest)) }
        fields.append(("Signature-Input", "\(HTTPSignatureProfile.label)=" + parameters.serialized))
        fields.append(("Signature", "\(HTTPSignatureProfile.label)=:" + raw.base64EncodedString() + ":"))
        return fields
    }
}

/// Proof of possession for registering a request-signing key in the console: sign
/// `"viadere-request-signing-key-v1" LF challenge LF public-key-base64url` and paste the base64url raw `r‖s`.
public enum HTTPSigningKeyProof {
    public static let context = "viadere-request-signing-key-v1"

    public static func message(challenge: String, publicKey: DevicePublicKey) -> Data {
        Data([context, challenge, publicKey.base64URL].joined(separator: "\n").utf8)
    }

    /// The proof the console expects, made with `key`.
    public static func prove(challenge: String, key: any HTTPRequestSigningKey) async throws -> String {
        let produced = try await key.sign(message(challenge: challenge, publicKey: key.publicKey))
        if produced.count == 64 { return Base64URL.encode(ViadereSignatureEncoding.normalizedRaw(produced)) }
        guard let der = try? P256.Signing.ECDSASignature(derRepresentation: produced) else { throw HTTPSignatureSigningError.notAnECDSASignature }
        return ViadereSignatureEncoding.encode(der)
    }

    /// Server side: the proof verifies under `publicKey` (either S accepted, like every other Viadere proof, SECURITY §2.1).
    public static func verify(proof: String, challenge: String, publicKey: DevicePublicKey) -> Bool {
        guard let signature = ViadereSignatureEncoding.decode(proof), let key = try? publicKey.signingKey() else { return false }
        return key.isValidSignature(signature, for: message(challenge: challenge, publicKey: publicKey))
    }
}
