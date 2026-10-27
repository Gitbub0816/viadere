@preconcurrency import Crypto
import Foundation
import ViadereCore
@_spi(FixedExpiryValidationTime) @preconcurrency import X509

/// Strict CBOR access for ISO 18013-5 structures (the same reader as App Attest and WebAuthn, with the three tags mdoc uses).
///
/// Digests in an MSO are computed over the **exact bytes** of each `IssuerSignedItemBytes` as the issuer encoded them, so the parser
/// keeps raw slices of those items instead of re-encoding decoded values.
enum RawCBOR {
    /// 0 date-time (`tdate`), 24 encoded CBOR data item, 1004 full-date. Every other tag is refused.
    static let limits = CBOR.Limits(maxDepth: 14, maxBytes: 192 * 1024, maxItems: 2048, allowedTags: [0, 24, 1004])

    static func decode(_ data: Data) throws -> CBORValue { try CBOR.decode(data, limits: limits) }

    /// The initial byte's major type and argument, and the head length.
    private static func head(_ data: Data) throws -> (major: UInt8, argument: UInt64, length: Int) {
        guard let first = data.first else { throw CBORError.truncated }
        let major = first >> 5
        let info = first & 0x1F
        switch info {
        case 0...23: return (major, UInt64(info), 1)
        case 24...27:
            let width = 1 << Int(info - 24)
            guard data.count >= 1 + width else { throw CBORError.truncated }
            var value: UInt64 = 0
            for byte in data.dropFirst().prefix(width) { value = value << 8 | UInt64(byte) }
            return (major, value, 1 + width)
        default: throw CBORError.unsupported
        }
    }

    /// The raw slices of the elements of the CBOR array in `data`.
    static func arrayElements(_ data: Data) throws -> [Data] {
        let (major, count, headLength) = try head(data)
        guard major == 4, count <= UInt64(limits.maxItems) else { throw CBORError.malformed }
        var offset = headLength
        var out: [Data] = []
        for _ in 0..<Int(count) {
            let rest = Data(data.dropFirst(offset))
            let length = try CBOR.decodePrefix(rest, limits: limits).length
            out.append(Data(rest.prefix(length)))
            offset += length
        }
        guard offset == data.count else { throw CBORError.trailingBytes }
        return out
    }

    /// The raw slice of the value stored under `key` in the CBOR map in `data`.
    static func mapValue(_ data: Data, key: String) throws -> Data? {
        let (major, count, headLength) = try head(data)
        guard major == 5, count <= UInt64(limits.maxItems) else { throw CBORError.malformed }
        var offset = headLength
        var found: Data?
        for _ in 0..<Int(count) {
            let keyRest = Data(data.dropFirst(offset))
            let keyItem = try CBOR.decodePrefix(keyRest, limits: limits)
            offset += keyItem.length
            let valueRest = Data(data.dropFirst(offset))
            let valueLength = try CBOR.decodePrefix(valueRest, limits: limits).length
            if keyItem.value == .text(key) { found = Data(valueRest.prefix(valueLength)) }
            offset += valueLength
        }
        guard offset == data.count else { throw CBORError.trailingBytes }
        return found
    }
}

/// A COSE signature algorithm (RFC 9053). Only the ECDSA algorithms ISO 18013-5 allows for mdoc signatures are accepted: ES256, ES384
/// and ES512. EdDSA, RSA, HMAC and everything else are refused, as is an algorithm that does not match the key's curve.
enum COSEAlgorithm: Int64 {
    case es256 = -7
    case es384 = -35
    case es512 = -36

    var curve: COSECurve {
        switch self {
        case .es256: .p256
        case .es384: .p384
        case .es512: .p521
        }
    }

    var signatureLength: Int {
        switch self {
        case .es256: 64
        case .es384: 96
        case .es512: 132
        }
    }
}

enum COSECurve: Int64 {
    case p256 = 1
    case p384 = 2
    case p521 = 3
}

/// A public key for verifying ECDSA signatures on P-256, P-384 or P-521.
enum COSEVerificationKey {
    case p256(P256.Signing.PublicKey)
    case p384(P384.Signing.PublicKey)
    case p521(P521.Signing.PublicKey)

    var curve: COSECurve {
        switch self {
        case .p256: .p256
        case .p384: .p384
        case .p521: .p521
        }
    }

    /// From a COSE_Key `{1: 2 (EC2), -1: crv, -2: x, -3: y}` (RFC 9052). Anything else is refused.
    init?(coseKey value: CBORValue) {
        guard case .map(let entries) = value, entries.count >= 4, value[1]?.intValue == 2,
              let crv = value[-1]?.intValue.flatMap(COSECurve.init(rawValue:)),
              let x = value[-2]?.byteString, let y = value[-3]?.byteString else { return nil }
        let size: Int
        switch crv {
        case .p256: size = 32
        case .p384: size = 48
        case .p521: size = 66
        }
        guard x.count == size, y.count == size else { return nil }
        let point = Data([0x04]) + x + y
        switch crv {
        case .p256: guard let key = try? P256.Signing.PublicKey(x963Representation: point) else { return nil }; self = .p256(key)
        case .p384: guard let key = try? P384.Signing.PublicKey(x963Representation: point) else { return nil }; self = .p384(key)
        case .p521: guard let key = try? P521.Signing.PublicKey(x963Representation: point) else { return nil }; self = .p521(key)
        }
    }

    init?(certificateKey: Certificate.PublicKey) {
        if let key = P256.Signing.PublicKey(certificateKey) { self = .p256(key) }
        else if let key = P384.Signing.PublicKey(certificateKey) { self = .p384(key) }
        else if let key = P521.Signing.PublicKey(certificateKey) { self = .p521(key) }
        else { return nil }
    }

    func isValid(rawSignature: Data, for message: Data, algorithm: COSEAlgorithm) -> Bool {
        guard algorithm.curve == curve, rawSignature.count == algorithm.signatureLength else { return false }
        switch self {
        case .p256(let key):
            guard let signature = try? P256.Signing.ECDSASignature(rawRepresentation: rawSignature) else { return false }
            return key.isValidSignature(signature, for: message)
        case .p384(let key):
            guard let signature = try? P384.Signing.ECDSASignature(rawRepresentation: rawSignature) else { return false }
            return key.isValidSignature(signature, for: message)
        case .p521(let key):
            guard let signature = try? P521.Signing.ECDSASignature(rawRepresentation: rawSignature) else { return false }
            return key.isValidSignature(signature, for: message)
        }
    }
}

/// A parsed `COSE_Sign1` (RFC 9052 §4.2): `[protected: bstr, unprotected: map, payload: bstr / nil, signature: bstr]`.
struct COSESign1 {
    var protectedBytes: Data
    var unprotected: CBORValue
    var payload: Data?
    var signature: Data
    var algorithm: COSEAlgorithm

    /// Parses the structure and its algorithm. The algorithm must be in the **protected** header and nowhere else (an unprotected
    /// `alg` could be swapped by anyone on the path), and must be one of ES256, ES384, ES512.
    init(_ value: CBORValue) throws {
        guard let items = value.arrayValue, items.count == 4, let protectedBytes = items[0].byteString,
              case .map = items[1], let signature = items[3].byteString else { throw MDocFailure.malformedResponse }
        let payload: Data?
        switch items[2] {
        case .bytes(let data): payload = data
        case .null: payload = nil
        default: throw MDocFailure.malformedResponse
        }
        guard !protectedBytes.isEmpty, let protected = try? RawCBOR.decode(protectedBytes), case .map = protected else { throw MDocFailure.malformedResponse }
        guard items[1][1] == nil else { throw MDocFailure.unsupportedAlgorithm }
        guard let alg = protected[1]?.intValue else { throw MDocFailure.unsupportedAlgorithm }
        guard let algorithm = COSEAlgorithm(rawValue: alg) else { throw MDocFailure.unsupportedAlgorithm }
        self.protectedBytes = protectedBytes
        unprotected = items[1]
        self.payload = payload
        self.signature = signature
        self.algorithm = algorithm
    }

    /// `Sig_structure = ["Signature1", protected, external_aad = h'', payload]` (RFC 9052 §4.4).
    func signatureInput(payload: Data) -> Data {
        CBOR.encode(.array([.text("Signature1"), .bytes(protectedBytes), .bytes(Data()), .bytes(payload)]))
    }

    func verify(key: COSEVerificationKey, payload: Data) -> Bool {
        key.isValid(rawSignature: signature, for: signatureInput(payload: payload), algorithm: algorithm)
    }
}
