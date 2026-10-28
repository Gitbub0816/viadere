import Foundation
import Logging

/// Removes secrets and personal data from log text: bearer tokens, API keys, session/refresh tokens,
/// webhook secrets, signatures, OTP-looking digit runs next to "code", and phone numbers.
public enum LogRedactor {
    private static let patterns: [(NSRegularExpression, String)] = {
        let specs: [(String, String)] = [
            (#"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"#, "Bearer [redacted]"),
            // Keys are `vdk_<env>_<16 hex key id>.<43 char secret>`: the dot belongs to the key (older keys have none).
            (#"vdk_(live|test)_[A-Za-z0-9_.-]{8,}"#, "vdk_$1_[redacted]"),
            (#"vd[ar]_[A-Za-z0-9_-]{16,}"#, "[redacted-token]"),
            (#"whsec_[A-Za-z0-9_-]{8,}"#, "whsec_[redacted]"),
            (#"(?i)(t=\d+,\s*)?v1=[0-9a-f]{32,}"#, "[redacted-signature]"),
            (#"(?i)(signature|sig|token|secret|otp|code)\s*[=:]\s*[^\s,;&"]{4,}"#, "$1=[redacted]"),
            (#"(?i)viadere-signature[^\n]*"#, "Viadere-Signature: [redacted]"),
            (#"\+\d{7,15}"#, "[phone]"),
            (#"/(l|h)/[A-Za-z0-9_-]{20,}"#, "/$1/[token]"),
            (#"/(invite|enroll)/[A-Za-z0-9_-]{20,}"#, "/$1/[token]"),
            (#"vds_[A-Za-z0-9_-]{16,}"#, "[redacted-session]"),
            (#"vrp1\.[A-Za-z0-9_.-]{20,}"#, "[redacted-postback]"),
            // Reward redemption codes (XXXXX-XXXXX), household invitation codes (XXXX-XXXX) and Wallet authentication tokens.
            (#"\b[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}\b"#, "[redacted-code]"),
            (#"\b[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}\b"#, "[redacted-code]"),
            (#"ApplePass\s+[A-Za-z0-9_-]{16,}"#, "ApplePass [redacted]"),
        ]
        return specs.compactMap { spec in (try? NSRegularExpression(pattern: spec.0)).map { ($0, spec.1) } }
    }()

    public static func redact(_ text: String) -> String {
        var out = text
        for (regex, template) in patterns {
            out = regex.stringByReplacingMatches(in: out, range: NSRange(out.startIndex..., in: out), withTemplate: template)
        }
        return out
    }
}

/// A `LogHandler` that writes one JSON object per line and redacts message and metadata.
public struct StructuredLogHandler: LogHandler {
    public var metadata: Logger.Metadata = [:]
    public var logLevel: Logger.Level
    private let label: String
    private let output: @Sendable (String) -> Void

    public init(label: String, level: Logger.Level = .info, output: @escaping @Sendable (String) -> Void = { line in
        FileHandle.standardOutput.write(Data((line + "\n").utf8))
    }) {
        self.label = label
        logLevel = level
        self.output = output
    }

    public subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }

    public func log(event: LogEvent) {
        var merged = metadata
        if let explicit = event.metadata { merged.merge(explicit) { _, new in new } }
        let level = event.level
        let message = event.message
        var object: [String: Any] = [
            "ts": ISO8601DateFormatter().string(from: Date()),
            "level": level.rawValue,
            "label": label,
            "msg": LogRedactor.redact(message.description),
        ]
        if !merged.isEmpty {
            object["meta"] = merged.mapValues { LogRedactor.redact($0.description) }
        }
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) else { return }
        output(String(decoding: data, as: UTF8.self))
    }
}
