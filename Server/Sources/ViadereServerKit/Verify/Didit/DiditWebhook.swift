@preconcurrency import Crypto
import Foundation
import ViadereCore

/// Didit's canonical JSON for `X-Signature-V2` (https://docs.didit.me/integration/webhooks, "Signature verification"): the parsed body
/// re-serialized with sorted keys, compact separators and unescaped Unicode (`json.dumps(sort_keys=True, separators=(",", ":"),
/// ensure_ascii=False)`), after whole-valued floats are turned into integers (`shorten_floats`). Keys sort by Unicode code point, as
/// Python's `str` ordering does; only `"`, `\` and control characters below U+0020 are escaped.
enum DiditCanonicalJSON {
    static func serialize(_ value: JSONValue) -> Data {
        var out = ""
        write(value, into: &out)
        return Data(out.utf8)
    }

    private static func write(_ value: JSONValue, into out: inout String) {
        switch value {
        case .null: out += "null"
        case .bool(let flag): out += flag ? "true" : "false"
        case .integer(let n): out += String(n)
        case .number(let d): out += number(d)
        case .string(let s): writeString(s, into: &out)
        case .array(let items):
            out += "["
            for (index, item) in items.enumerated() {
                if index > 0 { out += "," }
                write(item, into: &out)
            }
            out += "]"
        case .object(let members):
            out += "{"
            let keys = members.keys.sorted { Array($0.unicodeScalars.map(\.value)).lexicographicallyPrecedes(Array($1.unicodeScalars.map(\.value))) }
            for (index, key) in keys.enumerated() {
                if index > 0 { out += "," }
                writeString(key, into: &out)
                out += ":"
                write(members[key]!, into: &out)
            }
            out += "}"
        }
    }

    /// Whole-valued floats print as integers; other floats print as the shortest round-trip form (as Python's `repr`).
    static func number(_ d: Double) -> String {
        if d.isFinite, d == d.rounded(), abs(d) < 9e18 { return String(Int64(d)) }
        return "\(d)"
    }

    private static func writeString(_ s: String, into out: inout String) {
        out += "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if scalar.value < 0x20 {
                    let hex = String(scalar.value, radix: 16)
                    out += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        out += "\""
    }
}

/// Verifies a Didit webhook. **Only** the two body-covering signatures are accepted:
///
/// - `X-Signature-V2`: HMAC-SHA256 (hex) over `DiditCanonicalJSON` of the parsed body (middleware-safe);
/// - `X-Signature`: HMAC-SHA256 (hex) over the exact raw body bytes.
///
/// For 24 hours after the signing secret is rotated Didit adds `X-Signature-V2-Previous` and `X-Signature-Previous`, made with the old
/// secret; a match on either header with either configured secret passes, so a rotation never drops events. `X-Signature-Simple`
/// (deprecated by Didit) authenticates only the envelope and is **not** accepted. `X-Timestamp` must be within the tolerance. Even then
/// the webhook body is **never trusted for the decision**: the caller re-fetches it from the API.
struct DiditWebhookVerifier: Sendable {
    enum Failure: String, Error {
        case missingTimestamp = "missing_timestamp"
        case staleTimestamp = "stale_timestamp"
        case malformedBody = "malformed_body"
        case noSignature = "no_signature"
        case badSignature = "bad_signature"
        case noSecret = "no_secret"
    }

    struct Headers: Sendable {
        var signatureV2: String?
        var signatureV2Previous: String?
        var signature: String?
        var signaturePrevious: String?
        var timestamp: String?
    }

    var secrets: [String]
    var tolerance: TimeInterval

    /// The verified body (an object). Throws the reason otherwise.
    func verify(body: Data, headers: Headers, now: Date) throws -> [String: JSONValue] {
        guard !secrets.isEmpty else { throw Failure.noSecret }
        guard let raw = headers.timestamp, raw.count <= 12, raw.allSatisfy({ $0.isASCII && $0.isNumber }), let timestamp = Int64(raw) else { throw Failure.missingTimestamp }
        guard abs(now.timeIntervalSince1970 - Double(timestamp)) <= tolerance else { throw Failure.staleTimestamp }
        guard let parsed = try? JSONDecoder().decode(JSONValue.self, from: body), case .object(let object) = parsed else { throw Failure.malformedBody }
        let v2 = [headers.signatureV2, headers.signatureV2Previous].compactMap { $0 }
        let v1 = [headers.signature, headers.signaturePrevious].compactMap { $0 }
        guard !v2.isEmpty || !v1.isEmpty else { throw Failure.noSignature }
        var valid = false
        if !v2.isEmpty {
            let canonical = DiditCanonicalJSON.serialize(parsed)
            for secret in secrets { valid = Self.matches(candidates: v2, message: canonical, secret: secret) || valid }
        }
        if !v1.isEmpty {
            for secret in secrets { valid = Self.matches(candidates: v1, message: body, secret: secret) || valid }
        }
        guard valid else { throw Failure.badSignature }
        return object
    }

    /// Hex HMAC-SHA256 comparison in constant time against every candidate header value.
    private static func matches(candidates: [String], message: Data, secret: String) -> Bool {
        let expected = Hex.encode(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: Data(secret.utf8))))
        var found = false
        for candidate in candidates where candidate.count == expected.count {
            if ConstantTime.equals(Data(candidate.lowercased().utf8), Data(expected.utf8)) { found = true }
        }
        return found
    }
}
