import Foundation

/// Certificate pinning configuration: SHA-256 hashes of the server's SubjectPublicKeyInfo (SPKI),
/// base64-encoded. Pin the current leaf (or intermediate) key **and at least one backup key**, so a
/// rotation or a compromised key never bricks the app.
///
/// Compute a pin:
/// ```
/// openssl s_client -connect api.viadere.com:443 -servername api.viadere.com </dev/null 2>/dev/null \
///   | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
///   | openssl dgst -sha256 -binary | openssl enc -base64
/// ```
///
/// TODO(release): replace the placeholder pins in `ViadereConfiguration.productionPinning` before shipping.
/// Until then release builds fail closed (no connection) rather than silently skipping pinning.
public struct PinningConfiguration: Sendable, Equatable {
    public static let placeholderPrefix = "REPLACE_ME"

    /// Host the pins apply to.
    public var host: String
    /// Also pin `*.host`.
    public var includeSubdomains: Bool
    /// Base64 SHA-256 SPKI hashes (current + backup).
    public var pins: [String]

    public init(host: String, includeSubdomains: Bool = true, pins: [String]) {
        self.host = host.lowercased()
        self.includeSubdomains = includeSubdomains
        self.pins = pins
    }

    /// A real pin is base64 of exactly 32 bytes.
    static func isValidPin(_ pin: String) -> Bool { Data(base64Encoded: pin)?.count == 32 }

    /// True once real pins (at least two: primary + backup) are present.
    public var isConfigured: Bool {
        pins.count >= 2 && pins.allSatisfy(Self.isValidPin)
    }

    /// True while the TODO placeholders are still in place.
    public var isPlaceholder: Bool { pins.contains { $0.hasPrefix(Self.placeholderPrefix) } }

    public func applies(to candidate: String) -> Bool {
        let h = candidate.lowercased()
        return h == host || (includeSubdomains && h.hasSuffix("." + host))
    }
}

/// Pure pin evaluation (the Apple-only trust plumbing extracts the chain hashes and calls this).
public enum PinEvaluator {
    public enum Verdict: Sendable, Equatable {
        /// A certificate in the chain matched a pin.
        case allow
        /// Pinning applies and nothing matched, or pins are unconfigured on a fail-closed build.
        case deny
        /// Pinning does not apply (other host, or unconfigured on a development build): use default trust evaluation.
        case useDefaultEvaluation
    }

    /// - Parameters:
    ///   - chainSPKIHashes: base64 SHA-256 SPKI hash of every certificate in the (already system-validated) chain.
    ///   - failClosed: release builds pass `true`: unconfigured pins deny instead of falling back.
    public static func evaluate(host: String, chainSPKIHashes: [String], configuration: PinningConfiguration,
                                failClosed: Bool) -> Verdict {
        guard configuration.applies(to: host) else { return .useDefaultEvaluation }
        guard configuration.isConfigured else { return failClosed ? .deny : .useDefaultEvaluation }
        let pins = Set(configuration.pins)
        return chainSPKIHashes.contains(where: pins.contains) ? .allow : .deny
    }
}
