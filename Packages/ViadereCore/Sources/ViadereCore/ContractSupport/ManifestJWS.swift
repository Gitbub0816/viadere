import Crypto
import Foundation

/// Why a signed v4 manifest (Loop publication manifest, brand manifest) was refused. Every case is a refusal: the client renders the
/// safe fallback (a neutral "can't be shown" state for a Loop, neutral styling for a brand manifest).
public enum ManifestVerificationError: Error, Sendable, Hashable {
    case missing
    case malformed(String)
    /// Header `alg` other than `ES256` (no `none`, `HS256`, ...).
    case unsupportedAlgorithm
    /// Header `typ` is not this manifest's type (a brand manifest never verifies as a publication manifest and vice versa).
    case wrongType
    case unknownCriticalHeader
    /// `kid` is not in the pinned key set.
    case unknownKey
    case badSignature
    case headerPayloadMismatch
    case unsupportedVersion
    case notYetValid
    case expired
    case lifetimeTooLong
}

/// A trusted verification key for v4 manifests, pinned on the device (served with the key directory, `KeyDirectory/*`).
public struct PinnedManifestKey: Sendable, Hashable {
    public var kid: String
    public var publicKey: DevicePublicKey

    public init(kid: String, publicKey: DevicePublicKey) {
        self.kid = kid
        self.publicKey = publicKey
    }
}

/// Compact JWS (RFC 7515) over canonical JSON, the pattern of `ApprovalResultJWS` with a manifest-specific `typ` (domain separation).
///
/// * Header (canonical JSON): exactly `{"alg":"ES256","kid":"…","typ":"<type>"}`. Any other member, `crit` included, is refused.
/// * Payload: canonical JSON, byte for byte; it repeats `kid` and the verifier requires the two equal.
/// * Signature: ECDSA P-256 / SHA-256, raw `r‖s`, base64url, over `header64 + "." + payload64`.
enum ManifestJWS {
    static func isValidKid(_ kid: String) -> Bool {
        !kid.isEmpty && kid.utf8.count <= 64 && kid.utf8.allSatisfy {
            ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D || $0 == 0x5F || $0 == 0x2E
        }
    }

    static func sign(payload: [String: JSONValue], type: String, kid: String, with key: any DeviceSigningKey) async throws -> String {
        let header = try CanonicalJSON.serialize(.object(["alg": .string("ES256"), "kid": .string(kid), "typ": .string(type)]))
        let body = try CanonicalJSON.serialize(.object(payload))
        let signingInput = Base64URL.encode(header) + "." + Base64URL.encode(body)
        let signature = try await key.signature(for: Data(signingInput.utf8))
        return signingInput + "." + ViadereSignatureEncoding.encode(signature)
    }

    /// Parses, checks the header, verifies the signature with the pinned key named by `kid`, and returns the canonical payload object.
    static func verify(_ compact: String?, type: String, maxBytes: Int, keys: [PinnedManifestKey]) throws(ManifestVerificationError) -> [String: JSONValue] {
        guard let compact, !compact.isEmpty else { throw .missing }
        guard compact.utf8.count <= maxBytes else { throw .malformed("size") }
        let segments = compact.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3, segments.allSatisfy({ !$0.isEmpty }) else { throw .malformed("segments") }
        guard Base64URL.isValid(String(segments[0])), Base64URL.isValid(String(segments[1])),
              let headerBytes = Base64URL.decode(String(segments[0])), let payloadBytes = Base64URL.decode(String(segments[1])),
              case .object(let header)? = JSONValue.parseContract(headerBytes), case .object(let payload)? = JSONValue.parseContract(payloadBytes),
              (try? CanonicalJSON.serialize(.object(header))) == headerBytes, (try? CanonicalJSON.serialize(.object(payload))) == payloadBytes else {
            throw .malformed("encoding")
        }
        if header["crit"] != nil { throw .unknownCriticalHeader }
        guard Set(header.keys) == ["alg", "kid", "typ"] else { throw .malformed("header members") }
        guard header["alg"]?.stringValue == "ES256" else { throw .unsupportedAlgorithm }
        guard header["typ"]?.stringValue == type else { throw .wrongType }
        guard let kid = header["kid"]?.stringValue, isValidKid(kid) else { throw .malformed("kid") }
        guard let key = keys.first(where: { $0.kid == kid }) else { throw .unknownKey }
        guard let signature = ViadereSignatureEncoding.decode(String(segments[2])), let verifying = try? key.publicKey.signingKey(),
              verifying.isValidSignature(signature, for: Data((String(segments[0]) + "." + String(segments[1])).utf8)) else { throw .badSignature }
        guard payload["kid"]?.stringValue == kid else { throw .headerPayloadMismatch }
        return payload
    }
}
