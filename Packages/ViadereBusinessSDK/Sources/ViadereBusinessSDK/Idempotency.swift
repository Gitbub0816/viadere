import Foundation
import ViadereCore

/// Idempotency keys for `POST /v1/business/*`. The server keeps one result per `(business, key)`: retrying a request with
/// the **same key and body** returns the original; reusing a key with a **different** body is a `409 idempotency_conflict`.
public enum IdempotencyKey {
    /// Characters the API accepts: ASCII letters, digits and `_ . - :`, at most 128.
    public static let maxLength = 128

    public static func isValid(_ key: String) -> Bool {
        !key.isEmpty && key.count <= maxLength && key.unicodeScalars.allSatisfy {
            $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "_.-:".unicodeScalars.contains($0))
        }
    }

    /// A fresh random key (128 bits). Use when each call is a new logical operation, and **persist it** before sending so a
    /// crash-and-retry reuses it.
    public static func generate(prefix: String? = nil) -> String {
        let random = SecureToken.generate(byteCount: 16)
        guard let prefix, !prefix.isEmpty else { return random }
        let cleaned = String(prefix.unicodeScalars.filter { isValid(String($0)) }.prefix(40).map(Character.init))
        return cleaned.isEmpty ? random : "\(cleaned)-\(random)"
    }

    /// A stable key derived from the business object being acted on (order id, ticket id, …), so *every* retry of the same
    /// logical operation — even from a different process — produces the same key without storing anything.
    /// `parts` are joined with an unambiguous length-prefixed encoding, so `["ab","c"]` and `["a","bc"]` differ.
    public static func deterministic(namespace: String, _ parts: [String]) -> String {
        var material = Data()
        for part in [namespace] + parts {
            material.append(Data("\(part.utf8.count):".utf8))
            material.append(Data(part.utf8))
        }
        let digest = SecureToken.sha256Hex(material).prefix(40)
        let ns = String(namespace.unicodeScalars.filter { isValid(String($0)) }.prefix(40).map(Character.init))
        return ns.isEmpty ? String(digest) : "\(ns)-\(digest)"
    }
}
