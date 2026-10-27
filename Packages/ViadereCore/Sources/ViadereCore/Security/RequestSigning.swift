import Crypto
import Foundation

/// HTTP header names used by Viadere.
public enum ViadereHeader {
    /// Device ID (lowercase UUID) of the signing device.
    public static let device = "Viadere-Device"
    /// Unix seconds (decimal integer string).
    public static let timestamp = "Viadere-Timestamp"
    /// Per-request nonce (base64url, 16–64 chars).
    public static let nonce = "Viadere-Nonce"
    /// Device request signature (base64url raw r||s) — or, on outbound webhooks, `t=…,v1=…`.
    public static let signature = "Viadere-Signature"
    /// Webhook event id.
    public static let eventId = "Viadere-Event-Id"
    /// Webhook event type.
    public static let eventType = "Viadere-Event-Type"
    /// Idempotency key for business API POSTs (1–128 chars). Business API keys travel in
    /// `Authorization: Bearer vk_…`.
    public static let idempotencyKey = "Idempotency-Key"
}

/// Canonical request signing, version 1.
///
/// ```
/// string-to-sign = "VIADERE-SIG-V1" LF
///                  METHOD LF          ; uppercase
///                  path-and-query LF  ; exactly as on the request line, e.g. /v1/interactions?limit=20
///                  timestamp LF       ; unix seconds, decimal
///                  nonce LF           ; Viadere-Nonce value
///                  hex(sha256(body))  ; lowercase; body = exact bytes sent (empty body → sha256(""))
/// signature      = base64url( raw r||s of ECDSA-P256-SHA256(UTF-8(string-to-sign)) )
/// ```
public enum RequestSignature {
    public static let scheme = "VIADERE-SIG-V1"
    /// Default allowed clock skew (± seconds).
    public static let defaultAllowedSkew: TimeInterval = 300

    /// Builds the exact string to sign.
    public static func stringToSign(method: String, pathAndQuery: String, timestamp: Int64, nonce: String, bodySHA256Hex: String) -> String {
        [scheme, method.uppercased(), pathAndQuery, String(timestamp), nonce, bodySHA256Hex].joined(separator: "\n")
    }

    /// Lowercase hex SHA-256 of a body.
    public static func bodyHash(_ body: Data) -> String { SecureToken.sha256Hex(body) }

    /// Valid nonce: base64url, 16–64 characters.
    public static func isValidNonce(_ nonce: String) -> Bool { Base64URL.isValid(nonce, minLength: 16, maxLength: 64) }

    /// Clock-skew check: `|now - timestamp| <= allowedSkew`.
    public static func isWithinSkew(timestamp: Int64, now: Date, allowedSkew: TimeInterval = defaultAllowedSkew) -> Bool {
        abs(now.timeIntervalSince1970 - TimeInterval(timestamp)) <= allowedSkew
    }
}

/// Signature headers for one request.
public struct SignedRequestHeaders: Sendable, Hashable {
    public var deviceId: DeviceID
    public var timestamp: Int64
    public var nonce: String
    public var signature: String

    public init(deviceId: DeviceID, timestamp: Int64, nonce: String, signature: String) {
        self.deviceId = deviceId
        self.timestamp = timestamp
        self.nonce = nonce
        self.signature = signature
    }

    /// Header name → value.
    public var fields: [String: String] {
        [
            ViadereHeader.device: deviceId.description,
            ViadereHeader.timestamp: String(timestamp),
            ViadereHeader.nonce: nonce,
            ViadereHeader.signature: signature,
        ]
    }

    /// Parses headers using a case-insensitive lookup function (e.g. Vapor's `req.headers.first(name:)`).
    public init(lookup: (String) -> String?) throws {
        guard let device = lookup(ViadereHeader.device), let deviceId = DeviceID(device) else {
            throw RequestVerificationError.missingHeader(ViadereHeader.device)
        }
        guard let ts = lookup(ViadereHeader.timestamp) else { throw RequestVerificationError.missingHeader(ViadereHeader.timestamp) }
        guard ts.count <= 12, ts.allSatisfy({ $0.isASCII && $0.isNumber }), let timestamp = Int64(ts) else {
            throw RequestVerificationError.malformedTimestamp
        }
        guard let nonce = lookup(ViadereHeader.nonce) else { throw RequestVerificationError.missingHeader(ViadereHeader.nonce) }
        guard let signature = lookup(ViadereHeader.signature) else { throw RequestVerificationError.missingHeader(ViadereHeader.signature) }
        self.init(deviceId: deviceId, timestamp: timestamp, nonce: nonce, signature: signature)
    }

    /// Parses from a header dictionary (case-insensitive keys).
    public init(headers: [String: String]) throws {
        let lowered = Dictionary(headers.map { ($0.key.lowercased(), $0.value) }, uniquingKeysWith: { first, _ in first })
        try self.init(lookup: { lowered[$0.lowercased()] })
    }
}

/// Request verification failures.
public enum RequestVerificationError: Error, Sendable, Equatable {
    case missingHeader(String)
    case malformedTimestamp
    case malformedNonce
    case malformedSignature
    case clockSkew
    case badSignature
    case replayed
}

/// Signs outgoing device requests.
public struct RequestSigner: Sendable {
    public let deviceId: DeviceID
    public let key: any DeviceSigningKey

    public init(deviceId: DeviceID, key: any DeviceSigningKey) {
        self.deviceId = deviceId
        self.key = key
    }

    /// Signs a request. `pathAndQuery` must be exactly what goes on the request line.
    public func sign(method: String, pathAndQuery: String, body: Data, now: Date = Date(),
                     nonce: String = SecureToken.generate(byteCount: 16)) async throws -> SignedRequestHeaders {
        let timestamp = ViadereDate.unixSeconds(now)
        let message = RequestSignature.stringToSign(method: method, pathAndQuery: pathAndQuery, timestamp: timestamp,
                                                    nonce: nonce, bodySHA256Hex: RequestSignature.bodyHash(body))
        let signature = try await key.signature(for: Data(message.utf8))
        return SignedRequestHeaders(deviceId: deviceId, timestamp: timestamp, nonce: nonce,
                                    signature: ViadereSignatureEncoding.encode(signature))
    }
}

/// Verifies device-signed requests (server side). Replay protection is applied by the caller
/// with a `ReplayGuard` keyed by `(deviceId, nonce)` after `verify` succeeds — or use `verify(…, replayGuard:)`.
public struct RequestVerifier: Sendable {
    public var allowedSkew: TimeInterval

    public init(allowedSkew: TimeInterval = RequestSignature.defaultAllowedSkew) {
        self.allowedSkew = allowedSkew
    }

    /// Verifies structure, clock skew and signature.
    public func verify(method: String, pathAndQuery: String, body: Data, headers: SignedRequestHeaders,
                       publicKey: DevicePublicKey, now: Date) throws {
        guard RequestSignature.isValidNonce(headers.nonce) else { throw RequestVerificationError.malformedNonce }
        guard RequestSignature.isWithinSkew(timestamp: headers.timestamp, now: now, allowedSkew: allowedSkew) else {
            throw RequestVerificationError.clockSkew
        }
        guard let signature = ViadereSignatureEncoding.decode(headers.signature) else {
            throw RequestVerificationError.malformedSignature
        }
        let message = RequestSignature.stringToSign(method: method, pathAndQuery: pathAndQuery, timestamp: headers.timestamp,
                                                    nonce: headers.nonce, bodySHA256Hex: RequestSignature.bodyHash(body))
        guard let key = try? publicKey.signingKey(), key.isValidSignature(signature, for: Data(message.utf8)) else {
            throw RequestVerificationError.badSignature
        }
    }

    /// Verifies and then records the nonce in `replayGuard` (scope `req:{deviceId}`), rejecting reuse.
    public func verify(method: String, pathAndQuery: String, body: Data, headers: SignedRequestHeaders,
                       publicKey: DevicePublicKey, now: Date, replayGuard: any ReplayGuard) async throws {
        try verify(method: method, pathAndQuery: pathAndQuery, body: body, headers: headers, publicKey: publicKey, now: now)
        let fresh = try await replayGuard.registerIfFresh(nonce: headers.nonce, scope: "req:\(headers.deviceId)",
                                                          expiresAt: now.addingTimeInterval(allowedSkew * 2), now: now)
        guard fresh else { throw RequestVerificationError.replayed }
    }
}
