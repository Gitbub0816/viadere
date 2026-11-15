@preconcurrency import Crypto
import _CryptoExtras
import Foundation
import ViadereCore

/// The Android platform seams (SECURITY.md §2.114): the app identity that `/.well-known/assetlinks.json` publishes and Play Integrity checks, the FCM
/// HTTP v1 sender (`FCM_ENABLED`, off by default) and local Play Integrity verification (`PLAY_INTEGRITY_ENABLED`, off by default). Nothing here is
/// on unless the owner configured it; every half-configured combination refuses to boot.
public struct AndroidSettings: Sendable {
    /// The Android application id (`ANDROID_PACKAGE_NAME`, e.g. `com.viadere.android`). `nil` = no Android app: no assetlinks, no FCM, no Play Integrity.
    public var packageName: String?
    /// SHA-256 fingerprints of the app's signing certificates (`ANDROID_CERT_SHA256_FINGERPRINTS`, 32 bytes each; the Play App Signing key first).
    public var certificateFingerprints: [Data] = []
    /// The FCM sender's service account; `nil` = FCM off (`FCM_ENABLED` unset or `false`).
    public var fcm: FCMServiceAccount?
    /// Local Play Integrity verification keys; `nil` = Android evidence is never attested (the fail-closed stub).
    public var playIntegrity: PlayIntegrityKeys?

    public init() {}

    /// `AB:CD:…` (uppercase, colon separated): the form Digital Asset Links and the Play Console use.
    public static func fingerprintText(_ digest: Data) -> String { digest.map { String(format: "%02X", $0) }.joined(separator: ":") }

    /// Parses one `AB:CD:…` (or plain hex) SHA-256 fingerprint.
    public static func parseFingerprint(_ raw: String) -> Data? {
        let hex = raw.replacingOccurrences(of: ":", with: "").trimmingCharacters(in: .whitespaces)
        guard hex.count == 64, hex.allSatisfy(\.isHexDigit) else { return nil }
        return Hex.decode(hex.lowercased())
    }

    /// An Android application id: two or more dot-separated segments, each a letter followed by letters, digits or underscores.
    public static func isPackageName(_ raw: String) -> Bool {
        let segments = raw.split(separator: ".", omittingEmptySubsequences: false)
        guard raw.count <= 255, segments.count >= 2 else { return false }
        return segments.allSatisfy { segment in
            guard let first = segment.first, first.isASCII, first.isLetter else { return false }
            return segment.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") }
        }
    }
}

/// A Google service account allowed to send through FCM (`FCM_SERVICE_ACCOUNT_JSON`, the key file the Firebase console downloads). Only
/// `project_id`, `client_email`, `private_key` (RSA, PKCS#8 PEM) and `private_key_id` are read; `token_uri` must be Google's, so the signed
/// assertion never goes anywhere else.
public struct FCMServiceAccount: Sendable {
    public static let tokenURI = "https://oauth2.googleapis.com/token"
    public var projectId: String
    public var clientEmail: String
    public var privateKeyId: String?
    public var privateKeyPEM: String

    public init(projectId: String, clientEmail: String, privateKeyId: String?, privateKeyPEM: String) {
        self.projectId = projectId
        self.clientEmail = clientEmail
        self.privateKeyId = privateKeyId
        self.privateKeyPEM = privateKeyPEM
    }

    /// A Google Cloud project id: 6 to 30 lowercase letters, digits or hyphens, starting with a letter.
    static func isProjectId(_ raw: String) -> Bool {
        (6...30).contains(raw.count) && raw.first?.isLetter == true && raw.allSatisfy { ($0.isASCII && ($0.isLowercase || $0.isNumber)) || $0 == "-" }
    }

    static func parse(json raw: String) throws -> FCMServiceAccount {
        struct File: Decodable {
            var type: String?
            var project_id: String?
            var client_email: String?
            var private_key: String?
            var private_key_id: String?
            var token_uri: String?
        }
        let invalid = ServerConfigError.invalid("FCM_SERVICE_ACCOUNT_JSON (a Google service account key file: type, project_id, client_email, private_key)")
        guard let file = try? JSONDecoder().decode(File.self, from: Data(raw.utf8)) else { throw invalid }
        guard file.type == "service_account", let project = file.project_id, isProjectId(project),
              let email = file.client_email, email.count <= 254, email.hasSuffix(".iam.gserviceaccount.com"), !email.contains(" "),
              let pem = file.private_key, (try? _RSA.Signing.PrivateKey(pemRepresentation: pem)) != nil else { throw invalid }
        if let uri = file.token_uri, uri != tokenURI { throw ServerConfigError.invalid("FCM_SERVICE_ACCOUNT_JSON (token_uri must be \(tokenURI))") }
        return FCMServiceAccount(projectId: project, clientEmail: email, privateKeyId: file.private_key_id, privateKeyPEM: pem)
    }
}

/// The two Play Integrity response keys of "manage your own response encryption" in the Play Console: the AES-256 key that decrypts the JWE and the
/// P-256 public key that verifies the inner JWS.
public struct PlayIntegrityKeys: Sendable {
    public var decryptionKey: SymmetricKey
    public var verificationKey: P256.Signing.PublicKey

    public init(decryptionKey: SymmetricKey, verificationKey: P256.Signing.PublicKey) {
        self.decryptionKey = decryptionKey
        self.verificationKey = verificationKey
    }
}

extension ServerConfig {
    /// `ANDROID_PACKAGE_NAME`, `ANDROID_CERT_SHA256_FINGERPRINTS`, `FCM_ENABLED` + `FCM_SERVICE_ACCOUNT_JSON`, `PLAY_INTEGRITY_ENABLED` +
    /// `PLAY_INTEGRITY_DECRYPTION_KEY` + `PLAY_INTEGRITY_VERIFICATION_KEY`.
    mutating func applyAndroidEnvironment(_ env: [String: String]) throws {
        func value(_ name: String) -> String? { env[name].flatMap { $0.isEmpty ? nil : $0 } }
        func flag(_ name: String) throws -> Bool {
            switch value(name) {
            case nil, "false": return false
            case "true": return true
            default: throw ServerConfigError.invalid("\(name) (true or false)")
            }
        }
        var settings = AndroidSettings()
        if let raw = value("ANDROID_PACKAGE_NAME") {
            guard AndroidSettings.isPackageName(raw) else { throw ServerConfigError.invalid("ANDROID_PACKAGE_NAME (an Android application id such as com.viadere.android)") }
            settings.packageName = raw
        }
        if let raw = value("ANDROID_CERT_SHA256_FINGERPRINTS") {
            let parts = raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            let parsed = parts.compactMap(AndroidSettings.parseFingerprint)
            guard !parts.isEmpty, parsed.count == parts.count, parsed.count <= 10, Set(parsed).count == parsed.count else {
                throw ServerConfigError.invalid("ANDROID_CERT_SHA256_FINGERPRINTS (comma-separated SHA-256 fingerprints AB:CD:…, at most 10)")
            }
            guard settings.packageName != nil else { throw ServerConfigError.missing("ANDROID_PACKAGE_NAME (for ANDROID_CERT_SHA256_FINGERPRINTS)") }
            settings.certificateFingerprints = parsed
        }
        if try flag("FCM_ENABLED") {
            guard let raw = value("FCM_SERVICE_ACCOUNT_JSON") else { throw ServerConfigError.missing("FCM_SERVICE_ACCOUNT_JSON (FCM_ENABLED=true)") }
            guard settings.packageName != nil else { throw ServerConfigError.missing("ANDROID_PACKAGE_NAME (FCM_ENABLED=true)") }
            settings.fcm = try FCMServiceAccount.parse(json: raw)
        }
        if try flag("PLAY_INTEGRITY_ENABLED") {
            guard settings.packageName != nil, !settings.certificateFingerprints.isEmpty else {
                throw ServerConfigError.missing("ANDROID_PACKAGE_NAME and ANDROID_CERT_SHA256_FINGERPRINTS (PLAY_INTEGRITY_ENABLED=true)")
            }
            guard let rawKey = value("PLAY_INTEGRITY_DECRYPTION_KEY"), let key = Data(base64Encoded: rawKey) ?? Base64URL.decode(rawKey), key.count == 32 else {
                throw ServerConfigError.invalid("PLAY_INTEGRITY_DECRYPTION_KEY (the base64 AES-256 response decryption key from the Play Console)")
            }
            guard let rawPublic = value("PLAY_INTEGRITY_VERIFICATION_KEY"), let der = Data(base64Encoded: rawPublic) ?? Base64URL.decode(rawPublic),
                  let verification = try? P256.Signing.PublicKey(derRepresentation: der) else {
                throw ServerConfigError.invalid("PLAY_INTEGRITY_VERIFICATION_KEY (the base64 DER P-256 response verification key from the Play Console)")
            }
            settings.playIntegrity = PlayIntegrityKeys(decryptionKey: SymmetricKey(data: key), verificationKey: verification)
        }
        android = settings
    }
}
