import Foundation

/// An E.164 phone number such as `+14805550123`.
public struct PhoneNumber: Hashable, Sendable, Codable, CustomStringConvertible {
    public let e164: String

    /// Accepts `+` followed by 7–15 digits (first digit 1–9). Spaces, dashes, dots and
    /// parentheses are stripped first.
    public init?(_ input: String) {
        let stripped = input.filter { !" -.()\t".contains($0) }
        guard stripped.hasPrefix("+") else { return nil }
        let digits = stripped.dropFirst()
        guard (7...15).contains(digits.count), digits.allSatisfy({ $0.isASCII && $0.isNumber }), digits.first != "0" else {
            return nil
        }
        e164 = stripped
    }

    public var description: String { e164 }

    /// Masked form for display/logging: `+1•••••0123`.
    public var masked: String {
        let digits = Array(e164.dropFirst())
        guard digits.count > 5 else { return "+•••" }
        return "+" + String(digits.prefix(1)) + String(repeating: "•", count: digits.count - 5) + String(digits.suffix(4))
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        guard let value = PhoneNumber(try container.decode(String.self)) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid E.164 number")
        }
        self = value
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(e164)
    }
}

/// A brand color `#RRGGBB` (uppercase on the wire).
public struct BrandColor: Hashable, Sendable, Codable {
    public let hex: String

    public init?(_ input: String) {
        let body = input.hasPrefix("#") ? String(input.dropFirst()) : input
        guard body.count == 6, Hex.decode(body) != nil else { return nil }
        hex = "#" + body.uppercased()
    }

    /// RGB components 0–255.
    public var rgb: (red: UInt8, green: UInt8, blue: UInt8) {
        let bytes = Hex.decode(String(hex.dropFirst())) ?? Data([0, 0, 0])
        return (bytes[0], bytes[1], bytes[2])
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        guard let value = BrandColor(try container.decode(String.self)) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid brand color")
        }
        self = value
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(hex)
    }
}

/// Cursor-paginated list envelope.
public struct Page<Item: Codable & Sendable>: Codable, Sendable {
    public var items: [Item]
    /// Opaque cursor for the next page; `nil` at the end.
    public var nextCursor: String?

    public init(items: [Item], nextCursor: String? = nil) {
        self.items = items
        self.nextCursor = nextCursor
    }
}

extension Page: Equatable where Item: Equatable {}
extension Page: Hashable where Item: Hashable {}

/// Standard API error body: `{"error":{"code":"…","message":"…","requestId":"…"}}`.
public struct APIErrorResponse: Codable, Sendable, Hashable, Error {
    public struct Body: Codable, Sendable, Hashable {
        public var code: APIErrorCode
        public var message: String
        public var requestId: String?
        /// Field-level details (e.g. validation issues), never secrets.
        public var details: [String: String]?

        public init(code: APIErrorCode, message: String, requestId: String? = nil, details: [String: String]? = nil) {
            self.code = code
            self.message = message
            self.requestId = requestId
            self.details = details
        }
    }

    public var error: Body

    public init(code: APIErrorCode, message: String, requestId: String? = nil, details: [String: String]? = nil) {
        error = Body(code: code, message: message, requestId: requestId, details: details)
    }
}

/// Machine-readable API error codes. Unknown codes decode as `.unknown`.
public enum APIErrorCode: String, Codable, Sendable, CaseIterable {
    case badRequest = "bad_request"
    case validationFailed = "validation_failed"
    case unauthorized
    case signatureInvalid = "signature_invalid"
    case replayDetected = "replay_detected"
    case clockSkew = "clock_skew"
    case forbidden
    case notFound = "not_found"
    case conflict
    case gone
    case expired
    case insufficientAssurance = "insufficient_assurance"
    case consentRequired = "consent_required"
    /// The API key does not carry the capability the request needs (SEC-API-003).
    case insufficientScope = "insufficient_scope"
    /// The business holds no current entitlement for the capability (it was never granted, or it was revoked).
    case notEntitled = "not_entitled"
    /// The capability is switched off by Viadere (operator kill switch) or blocked by a law/policy rule.
    case capabilityDisabled = "capability_disabled"
    /// A policy check other than scope, entitlement, consent or a kill switch denied the request (`details.reason`).
    case policyDenied = "policy_denied"
    case rateLimited = "rate_limited"
    case idempotencyConflict = "idempotency_conflict"
    case internalError = "internal_error"
    case unavailable
    /// `POST /v1/devices` without the required passkey assertion (or with one that does not verify).
    case passkeyAssertionRequired = "passkey_assertion_required"
    /// The device is in its new-device cool-down and may not approve high or critical requests yet.
    case deviceCoolDown = "device_cool_down"
    /// A decision that needs a v2 payload (`contextDigest`) was signed without one.
    case contextDigestRequired = "context_digest_required"
    /// The signed `contextDigest` is not the digest of the interaction the server holds.
    case contextMismatch = "context_mismatch"
    /// The server requires App Attest (`APP_ATTEST_MODE=require`) and the enrollment carried no valid attestation (`403`).
    case attestationRequired = "attestation_required"
    /// Approvals are frozen for this relationship or account (by the customer or by the business).
    case approvalsFrozen = "approvals_frozen"
    /// The customer's protection against repeated prompts paused requests from this business for a while.
    case approvalsPaused = "approvals_paused"
    /// The approval request locked after too many invalid result submissions (`423`, WP-C2); the business starts a new one.
    case requestLocked = "request_locked"
    /// The request addressed the customer by `relationshipId` after its sunset (`400`, WP-C2): use `subjectRef` (or `connectionId`).
    case relationshipIdSunset = "relationship_id_sunset"
    case unknown

    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = APIErrorCode(rawValue: raw) ?? .unknown
    }
}
