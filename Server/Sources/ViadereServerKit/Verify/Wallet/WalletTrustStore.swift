@preconcurrency import Crypto
import Foundation
import SwiftASN1
import ViadereCore
@_spi(FixedExpiryValidationTime) @preconcurrency import X509

/// Why a presentation was refused. The raw value is the audit reason; it is never returned to the business (AGE-005), and never carries
/// document content.
enum MDocFailure: String, Error {
    case malformedResponse = "malformed_response"
    case unsupportedVersion = "unsupported_version"
    case unsupportedDocType = "unsupported_doc_type"
    case unsupportedAlgorithm = "unsupported_algorithm"
    case noIssuerCertificate = "no_issuer_certificate"
    case untrustedIssuer = "untrusted_issuer"
    case badIssuerCertificateUsage = "bad_issuer_certificate_usage"
    case badIssuerSignature = "bad_issuer_signature"
    case badMobileSecurityObject = "bad_mobile_security_object"
    case digestMismatch = "digest_mismatch"
    case outsideValidity = "outside_validity"
    case missingDeviceAuthentication = "missing_device_authentication"
    case badDeviceSignature = "bad_device_signature"
    case unexpectedDeviceNamespaces = "unexpected_device_namespaces"
    case envelopeMalformed = "envelope_malformed"
    case unsupportedEnvelope = "unsupported_envelope"
    case wrongRecipientKey = "wrong_recipient_key"
    case transcriptMismatch = "transcript_mismatch"
    case decryptionFailed = "decryption_failed"
    case noRequestedElement = "no_requested_element"
    case thresholdUnavailable = "threshold_unavailable"
    case issuerChainNotDirect = "issuer_chain_not_direct"
    case issuerCountryMismatch = "issuer_country_mismatch"
}

/// The IACA trust anchors for mdoc issuers (ISO 18013-5 Annex B): one root per issuing authority (state DMV, Apple's digital ID IACA).
///
/// Loaded from a **directory** on disk (`WALLET_IACA_DIR`): `.pem`, `.crt`, `.cer` and `.der` files. Viadere does not bundle a trust
/// list. Every candidate must be a self-signed CA certificate (basicConstraints `cA`, keyUsage `keyCertSign`) with an EC P-256/P-384/
/// P-521 key, valid now. When `pinnedFingerprints` is set (`WALLET_IACA_SHA256`, a comma-separated list), only a certificate whose
/// SHA-256 fingerprint is listed is trusted, so a file dropped into the directory cannot add an issuer; production configuration
/// requires pinning. An optional AAMVA VICAL import would feed the same directory after its own signature check (not implemented here).
struct IACATrustStore: Sendable {
    struct Entry: Sendable {
        var certificate: Certificate
        var fingerprint: String
        var subject: String
    }

    struct LoadReport: Sendable, Equatable {
        var trusted = 0
        var rejected: [String: String] = [:]
    }

    private(set) var entries: [Entry]

    init(entries: [Entry]) { self.entries = entries }

    var roots: [Certificate] { entries.map(\.certificate) }
    var fingerprints: Set<String> { Set(entries.map(\.fingerprint)) }
    var isEmpty: Bool { entries.isEmpty }

    static let maxFileBytes = 16 * 1024
    static let maxFiles = 512

    /// Builds the store from one certificate's DER, applying every acceptance rule. Throws the reason it is not acceptable.
    static func entry(der: Data, now: Date, pinned: Set<String>?) throws -> Entry {
        guard der.count <= maxFileBytes, let certificate = try? Certificate(derEncoded: Array(der)) else { throw IACARejection.unparseable }
        let fingerprint = SecureToken.sha256Hex(der)
        if let pinned, !pinned.isEmpty, !pinned.contains(fingerprint) { throw IACARejection.notPinned }
        guard certificate.subject == certificate.issuer,
              certificate.publicKey.isValidSignature(certificate.signature, for: certificate) else { throw IACARejection.notSelfSigned }
        guard case .isCertificateAuthority? = try? certificate.extensions.basicConstraints else { throw IACARejection.notCA }
        guard let usage = try? certificate.extensions.keyUsage, usage.keyCertSign else { throw IACARejection.keyUsage }
        guard COSEVerificationKey(certificateKey: certificate.publicKey) != nil else { throw IACARejection.keyType }
        guard certificate.notValidBefore <= now, now < certificate.notValidAfter else { throw IACARejection.notValidNow }
        return Entry(certificate: certificate, fingerprint: fingerprint, subject: certificate.subject.description)
    }

    enum IACARejection: String, Error {
        case unparseable, notPinned = "not_pinned", notSelfSigned = "not_self_signed", notCA = "not_ca", keyUsage = "key_usage"
        case keyType = "key_type", notValidNow = "not_valid_now"
    }

    /// Loads every acceptable certificate in `directory`. A rejected file is reported (by name and reason) and ignored; the store may be
    /// empty, in which case every presentation is refused (fail closed).
    static func load(directory: String, now: Date, pinned: Set<String>?) throws -> (store: IACATrustStore, report: LoadReport) {
        let fileManager = FileManager.default
        let names = try fileManager.contentsOfDirectory(atPath: directory).sorted().prefix(maxFiles)
        var entries: [Entry] = []
        var report = LoadReport()
        for name in names {
            let lower = name.lowercased()
            guard ["pem", "crt", "cer", "der"].contains(where: { lower.hasSuffix("." + $0) }), !name.hasPrefix(".") else { continue }
            let path = (directory as NSString).appendingPathComponent(name)
            // Regular files only, never a symlink out of the directory.
            guard let attributes = try? fileManager.attributesOfItem(atPath: path), attributes[.type] as? FileAttributeType == .typeRegular,
                  let data = fileManager.contents(atPath: path) else {
                report.rejected[name] = "unreadable"
                continue
            }
            do {
                let der: Data
                if let text = String(data: data, encoding: .utf8), text.contains("-----BEGIN CERTIFICATE-----") {
                    guard let pem = try? PEMDocument(pemString: text.trimmingCharacters(in: .whitespacesAndNewlines)), pem.discriminator == "CERTIFICATE" else {
                        throw IACARejection.unparseable
                    }
                    der = Data(pem.derBytes)
                } else {
                    der = data
                }
                let entry = try entry(der: der, now: now, pinned: pinned)
                if !entries.contains(where: { $0.fingerprint == entry.fingerprint }) { entries.append(entry) }
                report.trusted = entries.count
            } catch let rejection as IACARejection {
                report.rejected[name] = rejection.rawValue
            } catch {
                report.rejected[name] = "unreadable"
            }
        }
        return (IACATrustStore(entries: entries), report)
    }

    /// The result of validating an issuer certificate chain.
    struct ValidatedIssuer: Sendable {
        var leaf: Certificate
        /// Lowercase hex SHA-256 of the trust anchor's DER.
        var anchorFingerprint: String
        /// The country (ISO 3166-1 alpha-2, upper case) of the document signer **and** the IACA, which are required to agree.
        var country: String
    }

    /// The `countryName` (C) of a certificate subject, as an assigned ISO 3166-1 alpha-2 code, or `nil`.
    static func country(of certificate: Certificate) -> String? {
        for rdn in certificate.subject {
            for attribute in rdn where attribute.type == .RDNAttributeType.countryName {
                if let value = String(attribute.value), value.count == 2, let code = CountryCodes.alpha2(value) { return code }
            }
        }
        return nil
    }

    /// Document signer EKU (ISO 18013-5 Annex B.1.1): `id-mdl-kp-mdlDS`, 1.0.18013.5.1.2.
    static let documentSignerEKU: ASN1ObjectIdentifier = [1, 0, 18013, 5, 1, 2]

    /// Validates `chain` (leaf first) to a trusted IACA at `now`: RFC 5280 path validation, then the mdoc profile on the leaf (keyUsage
    /// `digitalSignature`, EKU `id-mdl-kp-mdlDS`, an EC key) and the ISO 18013-5 Annex B shape: the document signer is issued **directly**
    /// by the IACA (the validated path is exactly DS → IACA; no intermediates, which Annex B does not define), and the document signer's
    /// country equals the IACA's.
    func validate(chain: [Certificate], now: Date) async throws -> ValidatedIssuer {
        guard let leaf = chain.first, chain.count <= 3 else { throw MDocFailure.noIssuerCertificate }
        guard !entries.isEmpty else { throw MDocFailure.untrustedIssuer }
        var verifier = Verifier(rootCertificates: CertificateStore(roots)) { RFC5280Policy(fixedExpiryValidationTime: now) }
        let outcome = await verifier.validate(leaf: leaf, intermediates: CertificateStore(chain.dropFirst()))
        guard case .validCertificate(let validated) = outcome else { throw MDocFailure.untrustedIssuer }
        guard validated.count == 2 else { throw MDocFailure.issuerChainNotDirect }
        var serializer = DER.Serializer()
        try serializer.serialize(validated.root)
        let anchor = SecureToken.sha256Hex(serializer.serializedBytes)
        // The anchor must be one we loaded (not merely an equal-looking certificate supplied in the chain).
        guard fingerprints.contains(anchor) else { throw MDocFailure.untrustedIssuer }
        guard let usage = try? leaf.extensions.keyUsage, usage.digitalSignature,
              let eku = try? leaf.extensions.extendedKeyUsage, eku.contains(ExtendedKeyUsage.Usage(oid: Self.documentSignerEKU)),
              COSEVerificationKey(certificateKey: leaf.publicKey) != nil else { throw MDocFailure.badIssuerCertificateUsage }
        if case .isCertificateAuthority? = try? leaf.extensions.basicConstraints { throw MDocFailure.badIssuerCertificateUsage }
        guard let country = Self.country(of: leaf), country == Self.country(of: validated.last!) else { throw MDocFailure.issuerCountryMismatch }
        return ValidatedIssuer(leaf: leaf, anchorFingerprint: anchor, country: country)
    }
}
