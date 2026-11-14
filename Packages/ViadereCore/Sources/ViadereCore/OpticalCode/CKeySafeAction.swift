import Crypto
import Foundation

/// A CKey Safe Action (openckey.org, `spec/CKey-Safe-Actions.md`, draft 1): a signed request from a known site (the issuer) to a known app
/// to run one registered action. Text form `ckey-action:1:<envelope>`, the envelope in base64url without padding:
///
///     version u8 (1) | scope u8 (0 same-device, 1 cross-device)
///     issuer, app, action, key_id, request_id     each u8 length + bytes
///     issued_at u64 BE | expires_at u64 BE         Unix seconds
///     params u16 BE length + bytes                 at most 1024
///     signature 64 bytes                           Ed25519 over "CKey Safe Action v1" + 0x00 + every byte above
///
/// This file parses, verifies and signs, in pure Swift (swift-crypto; no CKey C or C++ is linked). It decides nothing about whether an
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
        guard maxLifetimeRange.contains(maxLifetime), let decoded = try? decode(text) else { return .invalid }
        let signature = decoded.bytes[decoded.signatureOffset...]
        guard publicKey.count == 32, isCanonicalScalar(signature.suffix(32)),
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey),
              key.isValidSignature(Data(signature), for: Data(signingContext + decoded.bytes[..<decoded.signatureOffset])) else { return .integrity }
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
    }

    /// Signs with an Ed25519 key given as its 32-byte seed. The fields pass the same parser readers use, so a signed envelope always parses.
    public func signed(seed: Data) throws -> String {
        guard seed.count == 32, let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else { throw SigningError.invalidSeed }
        return try signed(with: key)
    }

    public func signed(with key: Curve25519.Signing.PrivateKey) throws -> String {
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
        let signature = try key.signature(for: Data(Self.signingContext + body))
        guard signature.count == Self.signatureBytes else { throw SigningError.invalidSeed }
        return Self.prefix + Self.base64URLEncode(body + signature)
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
