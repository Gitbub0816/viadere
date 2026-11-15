@preconcurrency import Crypto
import Foundation

/// A pairwise, pseudonymous reference to one customer **as seen by one business** (spec §3.2). The same customer has an unrelated
/// `subject_ref` at every business; a business can neither compute nor guess another's, and Viadere's global consumer id is never
/// exposed on a business API.
///
/// Wire form: `sub_` followed by 43 base64url characters (a 256-bit HMAC-SHA256 tag).
public struct SubjectRef: Hashable, Sendable, Codable, CustomStringConvertible, LosslessStringConvertible {
    public static let prefix = "sub_"
    /// Characters after the prefix: unpadded base64url of 32 bytes.
    static let bodyLength = 43

    public let rawValue: String

    /// Parses a wire value; `nil` unless it is exactly `sub_` plus 43 base64url characters that decode to 32 bytes.
    public init?(_ string: String) {
        guard string.hasPrefix(Self.prefix) else { return nil }
        let body = String(string.dropFirst(Self.prefix.count))
        guard body.count == Self.bodyLength, Base64URL.isValid(body, minLength: Self.bodyLength, maxLength: Self.bodyLength),
              Base64URL.decode(body)?.count == 32 else { return nil }
        rawValue = string
    }

    public init?(rawValue: String) { self.init(rawValue) }

    public var description: String { rawValue }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let string = try container.decode(String.self)
        guard let value = SubjectRef(string) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid subject_ref")
        }
        self = value
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

/// `subject_ref = "sub_" + base64url(HMAC-SHA256(SUBJECT_REF_KEY, "VIADERE-SUBJECT-V1\n{businessId}\n{consumerId}"))` with lowercase
/// canonical UUIDs. The key is a dedicated secret (`SUBJECT_REF_KEY`, distinct from every other server secret), so the value is
/// non-enumerable: without the key, neither the consumer nor the business can be recovered from it, and refs of one consumer at two
/// businesses are unrelated. Stable per (business, consumer) for as long as the key lives.
public struct SubjectRefDeriver: Sendable {
    public static let domain = "VIADERE-SUBJECT-V1"
    private let key: SymmetricKey

    public init(key: SymmetricKey) { self.key = key }

    public func message(businessId: BusinessID, consumerId: ConsumerID) -> Data {
        Data("\(Self.domain)\n\(businessId.description)\n\(consumerId.description)".utf8)
    }

    public func subjectRef(businessId: BusinessID, consumerId: ConsumerID) -> SubjectRef {
        let tag = HMAC<SHA256>.authenticationCode(for: message(businessId: businessId, consumerId: consumerId), using: key)
        // 32 bytes always encode to a valid reference.
        return SubjectRef(SubjectRef.prefix + Base64URL.encode(Data(tag)))!
    }
}
