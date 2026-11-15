import Crypto
import Foundation

/// A CKey Safe Action (openckey.org, `spec/CKey-Safe-Actions.md`, draft 1): a signed request from a known site (the issuer) to a known app
/// to run one registered action. Text form `ckey-action:1:<envelope>`, the envelope in base64url without padding:
///
///     version u8 (1) | scope u8 (0 same-device, 1 cross-device)
///     issuer, app, action, key_id, request_id     each u8 length + bytes
///     issued_at u64 BE | expires_at u64 BE         Unix seconds
///     params u16 BE length + bytes                 at most 1024
///     signature 64 bytes                           over the signing input "CKey Safe Action v1" + 0x00 + every byte above:
///                                                  Ed25519, or ES256 (ECDSA P-256 / SHA-256, raw r‖s, low-S)
///
/// The envelope does not name the algorithm; the key does (`PublicKey`: the `alg` of the key file entry or of the app's pin). ES256 needs
/// CKey 0.1.0-build.118 or later in other readers (on Stable-Release from 0.1.0-build.127). This file parses, verifies and signs, in pure Swift (swift-crypto; no CKey C or C++ is linked). It decides nothing about whether an
/// action may run: that is the reader's job (`ViadereKit.SafeActionReader`, SECURITY.md §2.104). It reaches every verdict of the CKey
/// conformance vectors (`docs/protocol/vectors/ckey-safe-actions-v1.json`; `CKeySafeActionTests`).
public struct CKeySafeAction: Sendable, Equatable {
    public enum Scope: UInt8, Sendable, Equatable {
        /// The result stays in the receiving app on the scanning device.
        case sameDevice = 0
        /// The action approves something somewhere else (a browser sign-in). Never automatic.
        case crossDevice = 1
    }

    public var scope: Scope
    /// The issuing site's DNS name, lower case.
    public var issuer: String
    /// The receiving app's id.
    public var app: String
    public var action: String
    public var keyId: String
    /// Single use.
    public var requestId: String
    /// Unix seconds.
    public var issuedAt: UInt64
    public var expiresAt: UInt64
    public var params: Data

    public init(scope: Scope, issuer: String, app: String, action: String, keyId: String, requestId: String, issuedAt: UInt64, expiresAt: UInt64,
                params: Data = Data()) {
        self.scope = scope
        self.issuer = issuer
        self.app = app
        self.action = action
        self.keyId = keyId
        self.requestId = requestId
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.params = params
    }

    public static let prefix = "ckey-action:1:"
    /// The longest envelope text the reference accepts after the prefix.
    public static let maxEnvelopeCharacters = 4096
    public static let maxParamsBytes = 1024
    public static let signatureBytes = 64
    /// Tolerated clock difference for an action issued "in the future" (spec: 2 minutes).
    public static let clockToleranceSeconds: UInt64 = 120
    /// The app's limit when it names none (spec default), and the most any app may allow.
    public static let defaultMaxLifetimeSeconds = 600
    public static let maxLifetimeRange = 1...3600
    /// Signed with its terminating zero byte.
    static let signingContext: [UInt8] = Array("CKey Safe Action v1".utf8) + [0]

    public enum Field: String, Sendable, Equatable { case issuer, app, action, keyId, requestId }

    /// An issuer's public key with its algorithm (spec "Issuer keys"). An unknown `alg` is ignored by readers, so it is never a key.
    public enum PublicKey: Sendable, Equatable {
        /// 32 bytes (RFC 8032).
        case ed25519(Data)
        /// A point on P-256 (swift-crypto refuses a point off the curve when the key is made).
        case es256(P256.Signing.PublicKey)

        public static let ed25519Name = "Ed25519"
        public static let es256Name = "ES256"

        public enum KeyError: Error, Sendable, Equatable {
            /// Not `Ed25519` or `ES256`: a reader ignores the key.
            case unknownAlgorithm
            /// Wrong length, not hex, or not a point on the curve.
            case invalidKey
        }

        /// From a key file entry or a pin: `Ed25519` with 64 hex digits, or `ES256` with the SEC 1 encoding, 66 hex digits (compressed,
        /// `02`/`03`) or 130 (uncompressed, `04`). Hex digits in either case.
        public init(alg: String, hex: String) throws {
            guard let bytes = Self.bytes(hex: hex) else { throw KeyError.invalidKey }
            switch alg {
            case Self.ed25519Name:
                guard bytes.count == 32, (try? Curve25519.Signing.PublicKey(rawRepresentation: bytes)) != nil else { throw KeyError.invalidKey }
                self = .ed25519(bytes)
            case Self.es256Name:
                let key: P256.Signing.PublicKey?
                switch (bytes.count, bytes.first) {
                case (33, 0x02?), (33, 0x03?): key = try? P256.Signing.PublicKey(compressedRepresentation: bytes)
                case (65, 0x04?): key = try? P256.Signing.PublicKey(x963Representation: bytes)
                default: key = nil
                }
                guard let key else { throw KeyError.invalidKey }
                self = .es256(key)
            default:
                throw KeyError.unknownAlgorithm
            }
        }

        public var alg: String {
            switch self {
            case .ed25519: Self.ed25519Name
            case .es256: Self.es256Name
            }
        }

        /// Lower-case hex as a key file publishes it: 64 digits for Ed25519, the 66-digit compressed SEC 1 point for ES256.
        public var hex: String {
            let bytes: Data = switch self {
            case .ed25519(let raw): raw
            case .es256(let key): key.compressedRepresentation
            }
            return bytes.map { String(format: "%02x", $0) }.joined()
        }

        public static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
            switch (lhs, rhs) {
            case (.ed25519(let a), .ed25519(let b)): a == b
            case (.es256(let a), .es256(let b)): a.x963Representation == b.x963Representation
            default: false
            }
        }

        static func bytes(hex text: String) -> Data? {
            let digits = Array(text.utf8)
            guard !digits.isEmpty, digits.count % 2 == 0 else { return nil }
            func value(_ c: UInt8) -> UInt8? {
                switch c {
                case 0x30...0x39: c - 0x30
                case 0x61...0x66: c - 0x61 + 10
                case 0x41...0x46: c - 0x41 + 10
                default: nil
                }
            }
            var out = Data(capacity: digits.count / 2)
            for index in stride(from: 0, to: digits.count, by: 2) {
                guard let high = value(digits[index]), let low = value(digits[index + 1]) else { return nil }
                out.append(high << 4 | low)
            }
            return out
        }
    }

    public enum ParseError: Error, Sendable, Equatable {
        /// No `ckey-action:1:` prefix, or nothing after it.
        case notASafeAction
        /// Not canonical unpadded base64url (bad character, padding, impossible length, non-zero unused bits), or too long.
        case encoding
        case unsupportedVersion
        case unknownScope
        /// A text field breaks its length or character rule.
        case field(Field)
        case truncated
        case paramsTooLong
        /// Not exactly 64 signature bytes after the params (missing, short, or followed by anything).
        case signatureLength
        /// `expires_at` is not later than `issued_at`.
        case lifetime
    }

    /// What a verifier concludes, in the words of the conformance vectors.
    public enum Verdict: Sendable, Equatable {
        /// Genuine, within its lifetime and within the app's limit. Whether it may run is still the reader's decision.
        case ok(CKeySafeAction)
        /// Malformed.
        case invalid
        /// The signature does not match this key (or its scalar is not canonical).
        case integrity
        /// Out of time, issued too far in the future, or valid for longer than the app allows.
        case expired
    }

    // MARK: Parsing

    /// The claimed fields of a well-formed envelope. **Nothing is verified**: use it only to find the key, then call `verify`.
    public static func parse(text: String) throws -> CKeySafeAction {
        let decoded = try decode(text)
        guard decoded.action.expiresAt > decoded.action.issuedAt else { throw ParseError.lifetime }
        return decoded.action
    }

    public static func isSafeAction(_ text: String) -> Bool { text.hasPrefix(prefix) && text.utf8.count > prefix.utf8.count }

    /// - Parameters:
    ///   - publicKey: the issuer's Ed25519 public key, 32 bytes.
    ///   - maxLifetime: the longest lifetime the app accepts, 1...3600 seconds; anything else is refused as `invalid`.
    ///
    /// Order as in the reference: form, signature, then time. Time rules: `expires_at` later than `issued_at`, lifetime within `maxLifetime`,
    /// not issued more than 120 s in the future, and `now` before `expires_at` (no grace after expiry: the conformance vector `expired`
    /// requires a code to be dead one second after `expires_at`).
    public static func verify(text: String, publicKey: Data, now: Date, maxLifetime: Int = defaultMaxLifetimeSeconds) -> Verdict {
        verify(text: text, key: .ed25519(publicKey), now: now, maxLifetime: maxLifetime)
    }

    /// Ed25519: the scalar S must be below the group order. ES256: 1 ≤ r, s < n and s ≤ n/2 (a high-S signature is refused here, before
    /// swift-crypto, which would accept it), then ECDSA P-256 over SHA-256 of the signing input.
    public static func verify(text: String, key: PublicKey, now: Date, maxLifetime: Int = defaultMaxLifetimeSeconds) -> Verdict {
        guard maxLifetimeRange.contains(maxLifetime), let decoded = try? decode(text) else { return .invalid }
        let signature = Data(decoded.bytes[decoded.signatureOffset...])
        let input = Data(signingContext + decoded.bytes[..<decoded.signatureOffset])
        switch key {
        case .ed25519(let raw):
            guard raw.count == 32, isCanonicalScalar(ArraySlice([UInt8](signature.suffix(32)))),
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw), key.isValidSignature(signature, for: input) else { return .integrity }
        case .es256(let key):
            guard isCanonicalES256(signature), let ecdsa = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
                  key.isValidSignature(ecdsa, for: input) else { return .integrity }
        }
        let action = decoded.action
        let seconds = now.timeIntervalSince1970
        guard seconds >= 0, seconds < 9_007_199_254_740_992 else { return .expired }
        let current = UInt64(seconds)
        guard action.expiresAt > action.issuedAt, action.expiresAt - action.issuedAt <= UInt64(maxLifetime),
              action.issuedAt <= current + clockToleranceSeconds, current < action.expiresAt else { return .expired }
        return .ok(action)
    }

    // MARK: Signing (issuers)

    public enum SigningError: Error, Sendable, Equatable {
        /// The fields would not parse (a reader would refuse the envelope), so nothing is signed.
        case invalidFields(ParseError)
        case invalidSeed
        /// Not 64 bytes.
        case invalidSignature
    }

    /// Signs with an Ed25519 key given as its 32-byte seed. The fields pass the same parser readers use, so a signed envelope always parses.
    public func signed(seed: Data) throws -> String {
        guard seed.count == 32, let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else { throw SigningError.invalidSeed }
        return try signed(with: key)
    }

    public func signed(with key: Curve25519.Signing.PrivateKey) throws -> String {
        let input = try signingInput()
        let signature = try key.signature(for: input)
        return try assembled(signature: signature)
    }

    /// ES256 with a key in this process (tests and development; issuers sign through a key service with `signingInput` and `assembled`).
    /// The signature is folded to low-S.
    public func signed(with key: P256.Signing.PrivateKey) throws -> String {
        let signature = try key.signature(for: try signingInput())
        return try assembled(signature: Self.lowS(signature.rawRepresentation))
    }

    /// What the issuer's key signs: `CKey Safe Action v1`, a zero byte, then every envelope byte before the signature. The fields pass the
    /// same parser readers use, so an envelope assembled from this input always parses.
    public func signingInput() throws -> Data { Data(Self.signingContext + (try body())) }

    /// The payload text from these fields and a 64-byte signature made over `signingInput()` (Ed25519, or ES256 raw r‖s already low-S).
    /// Nothing is verified here: an issuer verifies the result once with its public key before publishing it.
    public func assembled(signature: Data) throws -> String {
        guard signature.count == Self.signatureBytes else { throw SigningError.invalidSignature }
        return Self.prefix + Self.base64URLEncode(try body() + [UInt8](signature))
    }

    /// `s` folded into the lower half of P-256's group (`s ≤ n/2`), as the spec requires of ES256 issuers.
    public static func lowS(_ raw: Data) -> Data { ViadereSignatureEncoding.normalizedRaw(raw) }

    func body() throws -> [UInt8] {
        var body: [UInt8] = [1, scope.rawValue]
        for (field, value) in [(Field.issuer, issuer), (.app, app), (.action, action), (.keyId, keyId), (.requestId, requestId)] {
            let bytes = Array(value.utf8)
            guard bytes.count <= 255 else { throw SigningError.invalidFields(.field(field)) }
            body.append(UInt8(bytes.count))
            body += bytes
        }
        body += Self.bigEndian(issuedAt) + Self.bigEndian(expiresAt)
        guard params.count <= Self.maxParamsBytes else { throw SigningError.invalidFields(.paramsTooLong) }
        body += [UInt8(params.count >> 8), UInt8(params.count & 0xFF)] + params
        do {
            let probe = try Self.decode(envelope: body + [UInt8](repeating: 0, count: Self.signatureBytes))
            guard probe.action == self else { throw ParseError.truncated }
            guard expiresAt > issuedAt else { throw ParseError.lifetime }
        } catch let error as ParseError {
            throw SigningError.invalidFields(error)
        }
        return body
    }

    // MARK: Internals

    struct Decoded {
        var action: CKeySafeAction
        var bytes: [UInt8]
        var signatureOffset: Int
    }

    /// Text to envelope fields. Does not compare the two timestamps (a verifier reports that as `expired`, after the signature).
    static func decode(_ text: String) throws -> Decoded {
        let utf8 = Array(text.utf8)
        let head = Array(prefix.utf8)
        guard utf8.count > head.count, Array(utf8[..<head.count]) == head else { throw ParseError.notASafeAction }
        guard utf8.count - head.count <= maxEnvelopeCharacters, let bytes = base64URLDecode(utf8[head.count...]) else { throw ParseError.encoding }
        return try decode(envelope: bytes)
    }

    static func decode(envelope bytes: [UInt8]) throws -> Decoded {
        guard bytes.count >= 2 else { throw ParseError.truncated }
        guard bytes[0] == 1 else { throw ParseError.unsupportedVersion }
        guard let scope = Scope(rawValue: bytes[1]) else { throw ParseError.unknownScope }
        var at = 2
        func text(_ field: Field) throws -> String {
            guard at < bytes.count else { throw ParseError.truncated }
            let length = Int(bytes[at])
            at += 1
            guard at + length <= bytes.count else { throw ParseError.truncated }
            let slice = bytes[at..<(at + length)]
            guard isValid(slice, as: field) else { throw ParseError.field(field) }
            at += length
            return String(decoding: slice, as: UTF8.self)
        }
        let issuer = try text(.issuer), app = try text(.app), action = try text(.action), keyId = try text(.keyId), requestId = try text(.requestId)
        guard at + 18 <= bytes.count else { throw ParseError.truncated }
        let issuedAt = bytes[at..<(at + 8)].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        let expiresAt = bytes[(at + 8)..<(at + 16)].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        let paramsLength = Int(bytes[at + 16]) << 8 | Int(bytes[at + 17])
        at += 18
        guard paramsLength <= maxParamsBytes else { throw ParseError.paramsTooLong }
        guard at + paramsLength <= bytes.count else { throw ParseError.truncated }
        let params = Data(bytes[at..<(at + paramsLength)])
        at += paramsLength
        guard bytes.count == at + signatureBytes else { throw ParseError.signatureLength }
        return Decoded(action: CKeySafeAction(scope: scope, issuer: issuer, app: app, action: action, keyId: keyId, requestId: requestId,
                                              issuedAt: issuedAt, expiresAt: expiresAt, params: params),
                       bytes: bytes, signatureOffset: at)
    }

    /// The envelope table's length and character rules.
    public static func isValid(_ bytes: ArraySlice<UInt8>, as field: Field) -> Bool {
        func lower(_ c: UInt8) -> Bool { c >= 0x61 && c <= 0x7A }
        func upper(_ c: UInt8) -> Bool { c >= 0x41 && c <= 0x5A }
        func digit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }
        let dot: UInt8 = 0x2E, dash: UInt8 = 0x2D, underscore: UInt8 = 0x5F
        switch field {
        case .issuer:
            // A DNS name: lower case letters, digits, `-` and `.`; at least one dot; no empty label.
            guard (1...253).contains(bytes.count), bytes.first != dot, bytes.last != dot, bytes.contains(dot) else { return false }
            var previous: UInt8 = 0
            for c in bytes {
                if c == dot, previous == dot { return false }
                guard lower(c) || digit(c) || c == dash || c == dot else { return false }
                previous = c
            }
            return true
        case .app:
            return (1...255).contains(bytes.count) && bytes.allSatisfy { lower($0) || upper($0) || digit($0) || $0 == dot || $0 == underscore || $0 == dash }
        case .action:
            return (1...64).contains(bytes.count) && bytes.allSatisfy { lower($0) || digit($0) || $0 == dot || $0 == underscore || $0 == dash }
        case .keyId:
            return (1...32).contains(bytes.count) && bytes.allSatisfy { lower($0) || upper($0) || digit($0) || $0 == dot || $0 == underscore || $0 == dash }
        case .requestId:
            return (8...64).contains(bytes.count) && bytes.allSatisfy { lower($0) || upper($0) || digit($0) || $0 == underscore || $0 == dash }
        }
    }

    /// RFC 8032 §5.1.7: the signature's scalar S (its last 32 bytes, little-endian) must be below the group order
    /// L = 2^252 + 27742317777372353535851937790883648493. Checked here and not left to the library, so S and S + L are never both accepted.
    static func isCanonicalScalar(_ scalar: ArraySlice<UInt8>) -> Bool {
        guard scalar.count == 32 else { return false }
        let s = Array(scalar)
        for index in stride(from: 31, through: 0, by: -1) where s[index] != groupOrder[index] {
            return s[index] < groupOrder[index]
        }
        return false // S == L
    }

    /// ES256: r and s are 32-byte big-endian integers with 1 ≤ r, s < n, and s ≤ n/2 (one valid signature value per envelope).
    public static func isCanonicalES256(_ signature: Data) -> Bool {
        guard signature.count == 64 else { return false }
        let bytes = [UInt8](signature)
        let r = Array(bytes[0..<32]), s = Array(bytes[32..<64])
        func isZero(_ v: [UInt8]) -> Bool { v.allSatisfy { $0 == 0 } }
        func less(_ a: [UInt8], _ b: [UInt8]) -> Bool {
            for index in 0..<32 where a[index] != b[index] { return a[index] < b[index] }
            return false
        }
        return !isZero(r) && !isZero(s) && less(r, p256Order) && !less(p256HalfOrder, s)
    }

    /// n of P-256, big-endian, and ⌊n/2⌋.
    static let p256Order: [UInt8] = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                     0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51]
    static let p256HalfOrder: [UInt8] = [0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                         0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8]

    static let groupOrder: [UInt8] = [0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]

    static func bigEndian(_ value: UInt64) -> [UInt8] { (0..<8).map { UInt8(truncatingIfNeeded: value >> (8 * UInt64(7 - $0))) } }

    /// Strict base64url: the URL alphabet only, no padding, no length of 1 mod 4, and zero unused low bits, so an envelope has one text form.
    static func base64URLDecode(_ text: ArraySlice<UInt8>) -> [UInt8]? {
        guard text.count % 4 != 1 else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(text.count * 3 / 4)
        var accumulator: UInt32 = 0
        var bits = 0
        for c in text {
            let value: UInt32
            switch c {
            case 0x41...0x5A: value = UInt32(c) - 0x41
            case 0x61...0x7A: value = UInt32(c) - 0x61 + 26
            case 0x30...0x39: value = UInt32(c) - 0x30 + 52
            case 0x2D: value = 62
            case 0x5F: value = 63
            default: return nil
            }
            accumulator = (accumulator << 6 | value) & 0xFFFF
            bits += 6
            if bits >= 8 {
                bits -= 8
                out.append(UInt8(truncatingIfNeeded: accumulator >> UInt32(bits)))
            }
        }
        return accumulator & ((1 << UInt32(bits)) - 1) == 0 ? out : nil
    }

    static func base64URLEncode(_ bytes: [UInt8]) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)
        var out: [UInt8] = []
        out.reserveCapacity((bytes.count * 4 + 2) / 3)
        var accumulator: UInt32 = 0
        var bits = 0
        for byte in bytes {
            accumulator = (accumulator << 8 | UInt32(byte)) & 0xFFFF
            bits += 8
            while bits >= 6 {
                bits -= 6
                out.append(alphabet[Int(accumulator >> UInt32(bits)) & 63])
            }
        }
        if bits > 0 { out.append(alphabet[Int(accumulator << UInt32(6 - bits)) & 63]) }
        return String(decoding: out, as: UTF8.self)
    }
}
