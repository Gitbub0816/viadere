import Crypto
import Foundation

/// Why an envelope could not be built or opened. Never carries plaintext or key material.
public enum E2EEError: Error, Sendable, Equatable {
    case invalidKey
    case malformed(String)
    case unsupportedVersion(Int64)
    case unsupportedSuite(String)
    case tooLarge
    /// The envelope is addressed to a different recipient key than the one offered.
    case wrongRecipientKey
    /// The envelope's authenticated context differs from what the caller expected (purpose, request, sender or recipient).
    case contextMismatch(String)
    case expired
    /// AEAD authentication failed: tampered, truncated, or for another recipient/context.
    case authenticationFailed
}

/// The authenticated context of an envelope (SEC-CR-001): **purpose, request ID, sender, recipient, expiry**. It is bound twice: as HPKE
/// `info` (key schedule) and as AEAD AAD, so changing any of it makes decryption fail.
public struct E2EEContext: Sendable, Hashable {
    public static let maxFieldLength = 128

    /// What the plaintext is for, such as `approve.request`. Lowercase `[a-z0-9._-]`, 1...64.
    public var purpose: String
    /// The request this belongs to (`[A-Za-z0-9_.:-]`, 1...128).
    public var requestId: String
    /// Who encrypted it, an opaque identifier such as `biz_<business id>`.
    public var sender: String
    /// Who may open it, such as `dev_<hpke kid>`.
    public var recipient: String
    /// Whole seconds since 1970 after which the envelope must not be opened.
    public var expiresAtSeconds: Int64

    public init(purpose: String, requestId: String, sender: String, recipient: String, expiresAt: Date) {
        self.purpose = purpose
        self.requestId = requestId
        self.sender = sender
        self.recipient = recipient
        expiresAtSeconds = ViadereDate.unixSeconds(expiresAt)
    }

    init(purpose: String, requestId: String, sender: String, recipient: String, expiresAtSeconds: Int64) {
        self.purpose = purpose
        self.requestId = requestId
        self.sender = sender
        self.recipient = recipient
        self.expiresAtSeconds = expiresAtSeconds
    }

    public var expiresAt: Date { Date(timeIntervalSince1970: TimeInterval(expiresAtSeconds)) }

    static func isToken(_ value: String, allowed: (UInt8) -> Bool, max: Int = maxFieldLength) -> Bool {
        !value.isEmpty && value.utf8.count <= max && value.utf8.allSatisfy(allowed)
    }

    static func validPurpose(_ value: String) -> Bool {
        isToken(value, allowed: { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2E || $0 == 0x5F || $0 == 0x2D }, max: 64)
    }

    static func validIdentifier(_ value: String) -> Bool {
        isToken(value, allowed: {
            ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2E || $0 == 0x5F || $0 == 0x2D || $0 == 0x3A
        })
    }

    /// Whether every field is well formed.
    var isWellFormed: Bool {
        Self.validPurpose(purpose) && Self.validIdentifier(requestId) && Self.validIdentifier(sender) && Self.validIdentifier(recipient)
            && expiresAtSeconds > 0
    }

    var json: JSONValue {
        .object(["purpose": .string(purpose), "request_id": .string(requestId), "sender": .string(sender), "recipient": .string(recipient),
                 "exp": .integer(expiresAtSeconds)])
    }
}

/// What a recipient requires of an envelope before opening it. `nil` members are not checked; **`purpose` is always required** so an
/// envelope for one use can never be opened as another.
public struct E2EEExpectation: Sendable, Hashable {
    public var purpose: String
    public var requestId: String?
    public var sender: String?
    public var recipient: String?

    public init(purpose: String, requestId: String? = nil, sender: String? = nil, recipient: String? = nil) {
        self.purpose = purpose
        self.requestId = requestId
        self.sender = sender
        self.recipient = recipient
    }
}

/// The supported HPKE suites (SEC-CR-007: negotiated by identifier, never by guesswork; an unknown suite is rejected).
public enum E2EESuite: String, Sendable, CaseIterable {
    /// RFC 9180 base mode: KEM 0x0010 DHKEM(P-256, HKDF-SHA256), KDF 0x0001 HKDF-SHA256, AEAD 0x0002 AES-256-GCM.
    case p256HKDFSHA256AES256GCM = "hpke-0010-0001-0002"
}

/// An end-to-end encrypted payload (normative: `docs/SECURITY.md` section 2.50).
///
/// ```json
/// {"v":1,"suite":"hpke-0010-0001-0002","kid":"<recipient key id>","enc":"<base64url 65 bytes>","ct":"<base64url>",
///  "ctx":{"exp":1800000120,"purpose":"approve.request","recipient":"dev_...","request_id":"...","sender":"biz_..."}}
/// ```
///
/// Each envelope uses one fresh HPKE sender context (one `seal`, sequence number 0), so an AEAD nonce is never reused with a key.
public struct E2EEEnvelope: Sendable, Hashable, Codable {
    public static let version: Int64 = 1
    public static let maxEnvelopeBytes = 128 * 1024
    public static let maxPlaintextBytes = 64 * 1024
    static let aeadTagLength = 16
    static let aadDomain = "VIADERE-E2EE-V1\n"
    static let infoDomain = "VIADERE-E2EE-INFO-V1\n"

    public let suite: E2EESuite
    /// The recipient key (`KeyIdentifier`).
    public let kid: String
    /// HPKE encapsulated key (65 bytes, X9.63).
    public let enc: Data
    /// AEAD ciphertext with the 16-byte tag.
    public let ct: Data
    public let context: E2EEContext

    init(suite: E2EESuite, kid: String, enc: Data, ct: Data, context: E2EEContext) {
        self.suite = suite
        self.kid = kid
        self.enc = enc
        self.ct = ct
        self.context = context
    }

    // MARK: Bound header bytes

    /// `{ctx, kid, suite, v}` as canonical JSON: the header every envelope binds into HPKE `info` and AEAD AAD.
    func headerBytes() throws -> Data {
        try CanonicalJSON.serialize(.object(["v": .integer(Self.version), "suite": .string(suite.rawValue), "kid": .string(kid), "ctx": context.json]))
    }

    static func aad(header: Data) -> Data { Data(aadDomain.utf8) + header }
    static func info(header: Data) -> Data { Data(infoDomain.utf8) + header }

    // MARK: Wire form

    /// Canonical JSON bytes of the whole envelope.
    public func serialized() throws -> Data {
        try CanonicalJSON.serialize(.object([
            "v": .integer(Self.version), "suite": .string(suite.rawValue), "kid": .string(kid), "enc": .string(Base64URL.encode(enc)),
            "ct": .string(Base64URL.encode(ct)), "ctx": context.json,
        ]))
    }

    /// Strictly parses an envelope. Rejects unknown versions and suites, unknown or missing members, malformed encodings, an invalid
    /// encapsulated key and oversized input.
    public static func parse(_ data: Data) throws -> E2EEEnvelope {
        guard data.count <= maxEnvelopeBytes else { throw E2EEError.tooLarge }
        guard let value = try? JSONDecoder().decode(JSONValue.self, from: data) else { throw E2EEError.malformed("json") }
        return try parse(value)
    }

    static func parse(_ value: JSONValue) throws -> E2EEEnvelope {
        guard case .object(let members) = value else { throw E2EEError.malformed("object") }
        // The version is checked first, so a future format is reported as such and never half-parsed as this one.
        guard let version = members["v"] else { throw E2EEError.malformed("v") }
        guard case .integer(let v) = version else { throw E2EEError.malformed("v") }
        guard v == Self.version else { throw E2EEError.unsupportedVersion(v) }
        guard Set(members.keys) == ["v", "suite", "kid", "enc", "ct", "ctx"] else { throw E2EEError.malformed("members") }
        guard let suiteName = members["suite"]?.stringValue else { throw E2EEError.malformed("suite") }
        guard let suite = E2EESuite(rawValue: suiteName) else { throw E2EEError.unsupportedSuite(String(suiteName.prefix(40))) }
        guard let kid = members["kid"]?.stringValue, KeyIdentifier.isValid(kid) else { throw E2EEError.malformed("kid") }
        guard let encText = members["enc"]?.stringValue, encText.utf8.count <= 100, let enc = Base64URL.decode(encText), enc.count == 65,
              (try? P256.KeyAgreement.PublicKey(x963Representation: enc)) != nil else { throw E2EEError.malformed("enc") }
        guard let ctText = members["ct"]?.stringValue, ctText.utf8.count <= (maxPlaintextBytes + aeadTagLength) * 4 / 3 + 4,
              let ct = Base64URL.decode(ctText), ct.count >= aeadTagLength, ct.count <= maxPlaintextBytes + aeadTagLength else { throw E2EEError.malformed("ct") }
        guard case .object(let ctx)? = members["ctx"], Set(ctx.keys) == ["purpose", "request_id", "sender", "recipient", "exp"],
              let purpose = ctx["purpose"]?.stringValue, let requestId = ctx["request_id"]?.stringValue, let sender = ctx["sender"]?.stringValue,
              let recipient = ctx["recipient"]?.stringValue, case .integer(let exp)? = ctx["exp"] else { throw E2EEError.malformed("ctx") }
        let context = E2EEContext(purpose: purpose, requestId: requestId, sender: sender, recipient: recipient, expiresAtSeconds: exp)
        guard context.isWellFormed else { throw E2EEError.malformed("ctx") }
        return E2EEEnvelope(suite: suite, kid: kid, enc: enc, ct: ct, context: context)
    }

    public init(from decoder: any Decoder) throws {
        self = try Self.parse(try JSONValue(from: decoder))
    }

    public func encode(to encoder: any Encoder) throws {
        let data = try serialized()
        try (try JSONDecoder().decode(JSONValue.self, from: data)).encode(to: encoder)
    }
}

/// HPKE (RFC 9180) end-to-end encryption: base mode, `DHKEM(P-256, HKDF-SHA256)`, `HKDF-SHA256`, `AES-256-GCM`.
///
/// Base mode does not authenticate the sender: anyone holding the recipient's public key can encrypt to it. **The sender is authenticated
/// by a signature inside the plaintext** (see `ApprovalRequest`, signed by the business's directory-published signing key) or by the
/// protocol using the envelope. Never treat a successfully opened envelope as proof of who sent it.
public enum E2EE {
    /// Encrypts `plaintext` to `recipient`, binding `context`. Throws `.tooLarge` over 64 KiB.
    public static func seal(_ plaintext: Data, to recipient: E2EEPublicKey, context: E2EEContext) throws -> E2EEEnvelope {
        guard plaintext.count <= E2EEEnvelope.maxPlaintextBytes else { throw E2EEError.tooLarge }
        guard context.isWellFormed else { throw E2EEError.malformed("ctx") }
        let suite = E2EESuite.p256HKDFSHA256AES256GCM
        let provisional = E2EEEnvelope(suite: suite, kid: recipient.kid, enc: Data(), ct: Data(), context: context)
        let header = try provisional.headerBytes()
        do {
            var sender = try HPKE.Sender(recipientKey: try recipient.agreementKey(), ciphersuite: .P256_SHA256_AES_GCM_256, info: E2EEEnvelope.info(header: header))
            let ciphertext = try sender.seal(plaintext, authenticating: E2EEEnvelope.aad(header: header))
            return E2EEEnvelope(suite: suite, kid: recipient.kid, enc: Data(sender.encapsulatedKey), ct: Data(ciphertext), context: context)
        } catch let error as E2EEError {
            throw error
        } catch {
            throw E2EEError.invalidKey
        }
    }

    /// Opens an envelope. Checks, in this order, before any decryption: the recipient key, the expectation (purpose always; request,
    /// sender and recipient when given) and the expiry; then the AEAD authenticates the whole header.
    public static func open(_ envelope: E2EEEnvelope, using key: any E2EEPrivateKey, expecting expectation: E2EEExpectation, now: Date) throws -> Data {
        guard ConstantTime.equals(envelope.kid, key.publicKey.kid) else { throw E2EEError.wrongRecipientKey }
        let context = envelope.context
        guard context.purpose == expectation.purpose else { throw E2EEError.contextMismatch("purpose") }
        if let requestId = expectation.requestId, context.requestId != requestId { throw E2EEError.contextMismatch("request_id") }
        if let sender = expectation.sender, context.sender != sender { throw E2EEError.contextMismatch("sender") }
        if let recipient = expectation.recipient, context.recipient != recipient { throw E2EEError.contextMismatch("recipient") }
        guard context.expiresAt > now else { throw E2EEError.expired }
        let header = try envelope.headerBytes()
        do {
            var recipient = try key.recipient(info: E2EEEnvelope.info(header: header), encapsulatedKey: envelope.enc)
            return try recipient.open(envelope.ct, authenticating: E2EEEnvelope.aad(header: header))
        } catch {
            // One answer for every cause (wrong key, tampered ciphertext, tampered context): no oracle.
            throw E2EEError.authenticationFailed
        }
    }
}
