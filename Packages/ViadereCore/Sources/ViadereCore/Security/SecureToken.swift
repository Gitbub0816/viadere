import Crypto
import Foundation

/// Secure random tokens and at-rest hashing.
///
/// - Tokens: base64url (unpadded) of CSPRNG bytes (`SystemRandomNumberGenerator`, which is
///   `arc4random_buf` on Apple platforms and `getrandom(2)` on Linux).
/// - Storage: persist only `hash(_:)` (lowercase hex SHA-256 of the token's UTF-8 bytes), never the token.
/// - Comparison: `matches(_:hash:)` is constant-time.
public enum SecureToken {
    /// Default token entropy: 32 bytes (256 bits) → 43 characters.
    public static let defaultByteCount = 32

    /// Returns `byteCount` random bytes.
    public static func randomBytes(_ byteCount: Int) -> Data {
        var rng = SystemRandomNumberGenerator()
        var data = Data(count: byteCount)
        for index in 0..<byteCount { data[index] = UInt8.random(in: .min ... .max, using: &rng) }
        return data
    }

    /// A new base64url token with `byteCount` bytes of entropy.
    public static func generate(byteCount: Int = defaultByteCount) -> String {
        Base64URL.encode(randomBytes(byteCount))
    }

    /// Lowercase hex SHA-256 of the token's UTF-8 bytes, for at-rest storage.
    public static func hash(_ token: String) -> String {
        Hex.encode(SHA256.hash(data: Data(token.utf8)))
    }

    /// Constant-time check that `token` hashes to `storedHash` (hex, either case).
    public static func matches(_ token: String, hash storedHash: String) -> Bool {
        guard let stored = Hex.decode(storedHash) else { return false }
        return ConstantTime.equals(Data(SHA256.hash(data: Data(token.utf8))), stored)
    }

    /// Lowercase hex SHA-256 of arbitrary bytes.
    public static func sha256Hex<D: DataProtocol>(_ data: D) -> String {
        Hex.encode(SHA256.hash(data: data))
    }
}
