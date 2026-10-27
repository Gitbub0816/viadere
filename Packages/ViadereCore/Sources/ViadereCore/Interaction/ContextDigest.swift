import Crypto
import Foundation

extension Interaction {
    /// Domain separator mixed into every context digest.
    public static let contextDigestDomain = "VIADERE-CONTEXT-V1\n"

    /// The part of an interaction a person actually sees and decides on, as canonical JSON:
    /// `{"businessId", "expiresAt", "kind", "payload"}` (see `CanonicalJSON`; `payload` is the interaction payload as
    /// it appears on the wire; absent optionals omitted; any non-integer number becomes the string `"n:<shortest decimal>"`;
    /// `expiresAt` is ISO-8601 UTC with milliseconds).
    ///
    /// It deliberately excludes everything that differs between the app and the business view (the challenge and the
    /// consumer reference) or that the person never sees (priority, channels, idempotency key).
    public func displayContext() throws -> Data {
        let wire = try ViadereJSON.decode(JSONValue.self, from: ViadereJSON.encode(self))
        guard case .object(let members) = wire, let payload = members["payload"] else { throw CanonicalJSON.Error.floatingPointNotAllowed }
        let context: [String: JSONValue] = [
            "businessId": .string(businessId.description),
            "kind": .string(kind.rawValue),
            "payload": Self.canonicalized(payload),
            "expiresAt": .string(ViadereDate.format(expiresAt)),
        ]
        return try CanonicalJSON.serialize(.object(context))
    }

    /// Lowercase hex SHA-256 of `"VIADERE-CONTEXT-V1\n"` followed by `displayContext()`.
    ///
    /// A device signs this inside a v2 `DecisionPayload` (`contextDigest`), which binds the decision to the exact amount,
    /// merchant, service, options and expiry that were shown; the server recomputes it from the stored interaction and
    /// rejects a mismatch. Returns the empty string if the interaction cannot be encoded (never a valid digest).
    public func displayContextDigest() -> String {
        guard let context = try? displayContext() else { return "" }
        return SecureToken.sha256Hex(Data(Self.contextDigestDomain.utf8) + context)
    }

    /// True for lowercase 64-character hex, the only valid form of a digest.
    public static func isValidContextDigest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }

    private static func canonicalized(_ value: JSONValue) -> JSONValue {
        switch value {
        case .number(let number):
            if number.rounded() == number, abs(number) < 9.0e15 { return .integer(Int64(number)) }
            return .string("n:\(number)")
        case .array(let items): return .array(items.map(canonicalized))
        case .object(let members): return .object(members.compactMapValues { if case .null = $0 { nil } else { canonicalized($0) } })
        default: return value
        }
    }
}
