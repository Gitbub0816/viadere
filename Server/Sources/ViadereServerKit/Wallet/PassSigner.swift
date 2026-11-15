@preconcurrency import Crypto
import Foundation
import SwiftASN1
@_spi(CMS) import X509

/// Signs a pass manifest. `PKPassBuilder` is the only caller; tests inject a fake, production uses `X509PassSigner`.
public protocol PassSigner: Sendable {
    /// Pass Type ID, e.g. `pass.com.viadere.wallet`. Must match the Pass Type ID certificate's UID.
    var passTypeIdentifier: String { get }
    /// Apple Developer Team ID that owns the Pass Type ID.
    var teamIdentifier: String { get }
    /// A detached PKCS#7 / CMS `SignedData` (DER) over `manifest`, including the signing certificate and the WWDR intermediate.
    func sign(manifest: Data, at date: Date) throws -> Data
}

/// Pass certificate material, from the environment (never committed).
public struct PassConfig: Sendable {
    public var passTypeIdentifier: String
    /// PEM of the Pass Type ID certificate issued by Apple.
    public var certificatePEM: String
    /// PEM private key (PKCS#8, PKCS#1 or SEC1) matching `certificatePEM`. Unencrypted: store it in your secret manager.
    public var privateKeyPEM: String
    /// PEM of Apple's WWDR intermediate certificate.
    public var wwdrCertificatePEM: String

    public init(passTypeIdentifier: String, certificatePEM: String, privateKeyPEM: String, wwdrCertificatePEM: String) {
        self.passTypeIdentifier = passTypeIdentifier
        self.certificatePEM = certificatePEM
        self.privateKeyPEM = privateKeyPEM
        self.wwdrCertificatePEM = wwdrCertificatePEM
    }
}

public enum PassSignerError: Error, CustomStringConvertible, Sendable {
    case invalidCertificate
    case invalidPrivateKey
    case keyDoesNotMatchCertificate
    case certificateExpired
    case signingFailed

    public var description: String {
        switch self {
        case .invalidCertificate: "The pass certificate or WWDR certificate is not a valid PEM certificate."
        case .invalidPrivateKey: "The pass private key is not a valid unencrypted PEM key."
        case .keyDoesNotMatchCertificate: "The pass private key does not match the pass certificate."
        case .certificateExpired: "The pass certificate has expired."
        case .signingFailed: "Signing the pass manifest failed."
        }
    }
}

/// Real signer: builds the PKCS#7 detached signature with swift-certificates' CMS support. The `SignedData` it produces
/// has the structure Apple documents (and `openssl smime -binary -sign -outform DER` emits): `signedAttrs` with the content
/// type, signing time and message digest, `SHA-256` digests, the pass certificate and the WWDR intermediate in the
/// certificate set, and no encapsulated content.
public struct X509PassSigner: PassSigner {
    public let passTypeIdentifier: String
    public let teamIdentifier: String
    private let certificate: Certificate
    private let wwdr: Certificate
    private let privateKey: Certificate.PrivateKey

    /// Parses and validates everything up front so a bad deployment fails at startup, not when the first pass is requested.
    public init(config: PassConfig, teamIdentifier: String, now: Date = Date()) throws {
        guard let certificate = try? Certificate(pemEncoded: config.certificatePEM),
              let wwdr = try? Certificate(pemEncoded: config.wwdrCertificatePEM) else { throw PassSignerError.invalidCertificate }
        guard let key = try? Certificate.PrivateKey(pemEncoded: config.privateKeyPEM) else { throw PassSignerError.invalidPrivateKey }
        guard key.publicKey == certificate.publicKey else { throw PassSignerError.keyDoesNotMatchCertificate }
        guard certificate.notValidAfter > now else { throw PassSignerError.certificateExpired }
        self.certificate = certificate
        self.wwdr = wwdr
        privateKey = key
        passTypeIdentifier = config.passTypeIdentifier
        self.teamIdentifier = teamIdentifier
    }

    /// Expiry of the signing certificate, for monitoring.
    public var certificateNotValidAfter: Date { certificate.notValidAfter }

    public func sign(manifest: Data, at date: Date) throws -> Data {
        do {
            let der = try CMS.sign(manifest, additionalIntermediateCertificates: [wwdr], certificate: certificate,
                                   privateKey: privateKey, signingTime: date, detached: true)
            return Data(der)
        } catch {
            throw PassSignerError.signingFailed
        }
    }
}
