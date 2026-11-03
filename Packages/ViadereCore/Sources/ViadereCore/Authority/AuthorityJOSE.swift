@preconcurrency import Crypto
import Foundation

// The JOSE profile of every artifact the private authority verifies or signs (ADR-0023 §2, RFC 7515, RFC 8725):
// header members exactly `alg`, `kid`, `typ`; `alg` fixed by `typ`; payload canonical JSON (SECURITY §2.2) re-serialized and compared byte for
// byte (duplicate members and floats are refused that way); total length ≤ 4096 bytes. Every verifier checks `typ`, `iss` and `aud` for its own type.

/// The authority's environment, as it appears in audiences and statements (`urn:viadere:authority:<env>`).
public enum AuthorityEnvironment: String, Sendable, Codable, CaseIterable, Hashable {
    case staging = "stg"
    case production = "prod"

    /// The audience of evidence sent to the authority, and the `iss` of authority statements to devices.
    public var authorityURN: String { "urn:viadere:authority:\(rawValue)" }

    /// `ENVIRONMENT` values of the server and the authority mapped to the statement environment. Development and tests use `stg`.
    public static func forDeployment(_ environment: String) -> AuthorityEnvironment {
        environment.lowercased() == "production" ? .production : .staging
    }
}

/// Audiences of authority statements to devices.
public enum AuthorityAudience {
    public static let device = "urn:viadere:device"
}

/// Why a JOSE object was refused. Verifiers turn every case into one generic answer (`401 evidence_invalid`); the case is for the audit record only.
public enum AuthorityJOSEError: Error, Sendable, Equatable {
    case malformed(String)
    case unsupportedAlgorithm
    case wrongType
    case unknownKey
    case badSignature
    case claims(String)
    case expired
    case notYetValid
}

/// A structurally valid compact JWS under the profile. Nothing is trusted until a signature has verified.
public struct AuthorityJWSParts: Sendable {
    public let alg: String
    public let kid: String
    public let typ: String
    public let signingInput: Data
    public let signature: Data
    public let payload: [String: JSONValue]
    public let payloadBytes: Data
}

public enum AuthorityJWS {
    /// ADR-0023 §2: total length of every new type.
    public static let maxBytes = 4096

    /// Strict parse: three non-empty base64url segments; header is canonical JSON with **exactly** `alg`, `kid`, `typ` (any other member, `crit`,
    /// `jku`, `jwk`, `x5u`, `x5c`, `b64`, `zip`, `cty` included, is refused); `typ` equals `expectedType`; `alg` is one of `allowedAlgorithms`
    /// (`none` and `HS*` can never be allowed); payload canonical JSON. Does **not** check the signature.
    public static func parse(_ compact: String, expectedType: String, allowedAlgorithms: Set<String>) throws -> AuthorityJWSParts {
        precondition(!allowedAlgorithms.contains("none") && !allowedAlgorithms.contains(where: { $0.hasPrefix("HS") }), "symmetric or none algorithms are never allowed")
        guard compact.utf8.count <= maxBytes else { throw AuthorityJOSEError.malformed("size") }
        let segments = compact.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard segments.count == 3, segments.allSatisfy({ !$0.isEmpty }) else { throw AuthorityJOSEError.malformed("segments") }
        guard Base64URL.isValid(segments[0]), Base64URL.isValid(segments[1]), Base64URL.isValid(segments[2]),
              let headerBytes = Base64URL.decode(segments[0]), let payloadBytes = Base64URL.decode(segments[1]),
              let signature = Base64URL.decode(segments[2]),
              case .object(let header)? = try? JSONDecoder().decode(JSONValue.self, from: headerBytes),
              case .object(let payload)? = try? JSONDecoder().decode(JSONValue.self, from: payloadBytes),
              (try? CanonicalJSON.serialize(.object(header))) == headerBytes,
              (try? CanonicalJSON.serialize(.object(payload))) == payloadBytes else { throw AuthorityJOSEError.malformed("encoding") }
        guard Set(header.keys) == ["alg", "kid", "typ"] else { throw AuthorityJOSEError.malformed("header members") }
        guard let alg = header["alg"]?.stringValue, allowedAlgorithms.contains(alg) else { throw AuthorityJOSEError.unsupportedAlgorithm }
        guard header["typ"]?.stringValue == expectedType else { throw AuthorityJOSEError.wrongType }
        guard let kid = header["kid"]?.stringValue, !kid.isEmpty, kid.utf8.count <= 128 else { throw AuthorityJOSEError.malformed("kid") }
        return AuthorityJWSParts(alg: alg, kid: kid, typ: expectedType, signingInput: Data((segments[0] + "." + segments[1]).utf8),
                                 signature: signature, payload: payload, payloadBytes: payloadBytes)
    }

    /// ES256 verification (raw `r ‖ s`, 64 bytes; low-S is normalized by `ViadereSignatureEncoding`, so a high-S twin verifies the same).
    public static func verifyES256(_ parts: AuthorityJWSParts, key: P256.Signing.PublicKey) throws {
        guard parts.alg == "ES256", parts.signature.count == 64,
              let signature = ViadereSignatureEncoding.decode(Base64URL.encode(parts.signature)),
              key.isValidSignature(signature, for: parts.signingInput) else { throw AuthorityJOSEError.badSignature }
    }

    /// The signing input of a new object under the profile.
    public static func signingInput(alg: String, kid: String, typ: String, payload: [String: JSONValue]) throws -> String {
        let header = try CanonicalJSON.serialize(.object(["alg": .string(alg), "kid": .string(kid), "typ": .string(typ)]))
        let body = try CanonicalJSON.serialize(.object(payload))
        guard header.count + body.count < maxBytes else { throw AuthorityJOSEError.malformed("size") }
        return Base64URL.encode(header) + "." + Base64URL.encode(body)
    }

    /// Signs with a device key (`viadere-factor+jws`, PoPs): ES256 over the signing input; the `kid` is the device `KeyIdentifier` (SPKI hash).
    public static func signES256(typ: String, payload: [String: JSONValue], key: any DeviceSigningKey) async throws -> String {
        let kid = KeyIdentifier.make(try key.publicKey.signingKey())
        let input = try signingInput(alg: "ES256", kid: kid, typ: typ, payload: payload)
        let signature = try await key.signature(for: Data(input.utf8))
        return input + "." + ViadereSignatureEncoding.encode(signature)
    }
}

/// RFC 7638 JWK thumbprints (SHA-256, base64url): the `kid` of every **authority** key (signing and seal) and of tenant destination keys
/// (ADR-0023 §2, second definition). Never mixed with the device `KeyIdentifier` (SPKI hash).
public enum JWKThumbprint {
    /// EC P-256: members `crv`, `kty`, `x`, `y` in lexicographic order.
    public static func p256(_ key: P256.Signing.PublicKey) -> String {
        let raw = key.rawRepresentation
        let x = Base64URL.encode(raw.prefix(32)), y = Base64URL.encode(raw.suffix(32))
        return digest("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(x)\",\"y\":\"\(y)\"}")
    }

    /// RSA: members `e`, `kty`, `n` (unsigned big-endian modulus and exponent without leading zero bytes, base64url).
    public static func rsa(modulus: Data, exponent: Data) -> String {
        digest("{\"e\":\"\(Base64URL.encode(stripLeadingZeros(exponent)))\",\"kty\":\"RSA\",\"n\":\"\(Base64URL.encode(stripLeadingZeros(modulus)))\"}")
    }

    public static func stripLeadingZeros(_ data: Data) -> Data {
        let trimmed = data.drop(while: { $0 == 0 })
        return trimmed.isEmpty ? Data([0]) : Data(trimmed)
    }

    static func digest(_ canonical: String) -> String { Base64URL.encode(Data(SHA256.hash(data: Data(canonical.utf8)))) }

    /// A public JWK as published in a JWKS (`kid`, `use: sig`, `alg` always present; ADR-0024 §7.5).
    public static func p256JWK(_ key: P256.Signing.PublicKey) -> [String: JSONValue] {
        let raw = key.rawRepresentation
        return ["kty": .string("EC"), "crv": .string("P-256"), "x": .string(Base64URL.encode(raw.prefix(32))), "y": .string(Base64URL.encode(raw.suffix(32))),
                "kid": .string(p256(key)), "use": .string("sig"), "alg": .string("ES256")]
    }

    public static func rsaJWK(modulus: Data, exponent: Data) -> [String: JSONValue] {
        ["kty": .string("RSA"), "n": .string(Base64URL.encode(stripLeadingZeros(modulus))), "e": .string(Base64URL.encode(stripLeadingZeros(exponent))),
         "kid": .string(rsa(modulus: modulus, exponent: exponent)), "use": .string("sig"), "alg": .string("RS256")]
    }
}

extension JSONValue {
    /// Integers only (the profile has no floats).
    public var authorityInteger: Int64? {
        if case .integer(let value) = self { return value }
        return nil
    }
}
