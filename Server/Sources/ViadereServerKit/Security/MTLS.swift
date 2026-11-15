@preconcurrency import Crypto
import Fluent
import Foundation
import SwiftASN1
@preconcurrency import X509
import ViadereCore

/// Tier E client certificates (SEC-TR-005). Fly's proxy does not verify client certificates, so mutual TLS is terminated at Cloudflare (API Shield
/// mTLS on the enterprise API hostname). Cloudflare forwards the SHA-256 fingerprint of the verified certificate (and its issuer's subject key
/// identifier) in headers that the server reads **only** from a request that passed the origin lock (`EdgeLockMiddleware`). A tenant binds
/// certificates here; a key that requires mTLS (or a tenant that requires it for every key) is refused unless the verified certificate is one
/// the tenant bound. mTLS adds a factor: the API key still authenticates and every authorization check still applies.
struct MTLSCertificates {
    let db: any Database
    let ctx: ServerContext

    static let maxPerBusiness = 20

    /// What a certificate or CA upload reduces to.
    struct Identity: Equatable {
        var kind: String
        var fingerprint: String
        var subject: String
        var notAfter: Date
        /// For a CA: its subject key identifier (lowercase hex). Only a lookup key for the header the edge forwards: `fingerprint` is the binding.
        var issuerSKI: String? = nil
    }

    // MARK: Parsing

    /// Reads a PEM certificate. A leaf upload is bound by its SHA-256 fingerprint; a CA upload (`asCA`) by the SHA-256 of the CA certificate (its key
    /// identifier is text the CA's owner chooses, so it is never the binding), so every certificate that CA issues to the tenant works. Only the public certificate is read; a private key in the upload is refused.
    static func identity(pem: String, asCA: Bool) throws -> Identity {
        let text = pem.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.count <= 16 * 1024, text.hasPrefix("-----BEGIN CERTIFICATE-----"), !text.contains("PRIVATE KEY"),
              text.components(separatedBy: "-----BEGIN").count == 2 else {
            throw APIError.validation("Upload one PEM-encoded public certificate.", details: ["certificate": "invalid"])
        }
        let certificate: Certificate
        do { certificate = try Certificate(pemEncoded: text) } catch {
            throw APIError.validation("The certificate could not be read.", details: ["certificate": "invalid"])
        }
        let subject = String(certificate.subject.description.prefix(200))
        if asCA {
            guard let basic = try? certificate.extensions.basicConstraints, case .isCertificateAuthority = basic,
                  let ski = try? certificate.extensions.subjectKeyIdentifier else {
                throw APIError.validation("That certificate is not a certificate authority with a subject key identifier.", details: ["certificate": "not_ca"])
            }
            return Identity(kind: "issuer", fingerprint: try fingerprint(of: certificate), subject: subject, notAfter: certificate.notValidAfter,
                            issuerSKI: Hex.encode(ski.keyIdentifier))
        }
        return Identity(kind: "leaf", fingerprint: try fingerprint(of: certificate), subject: subject, notAfter: certificate.notValidAfter)
    }

    /// SHA-256 of the DER encoding (lowercase hex).
    static func fingerprint(of certificate: Certificate) throws -> String {
        var serializer = DER.Serializer()
        try certificate.serialize(into: &serializer)
        return SecureToken.sha256Hex(Data(serializer.serializedBytes))
    }

    /// A SHA-256 fingerprint typed or pasted by the tenant (hex, with or without colons).
    static func identity(fingerprint raw: String) throws -> Identity {
        guard let hex = EdgeLockMiddleware.hex(raw, length: 64) else {
            throw APIError.validation("Enter the 64-character SHA-256 fingerprint of the certificate.", details: ["fingerprint": "invalid"])
        }
        return Identity(kind: "leaf", fingerprint: hex, subject: "", notAfter: .distantFuture)
    }

    // MARK: Management (the caller checks the role and the fresh re-authentication)

    func list(businessId: UUID) async throws -> [BusinessMTLSCertRecord] {
        try await BusinessMTLSCertRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$createdAt, .descending).all()
    }

    func add(businessId: UUID, label rawLabel: String, identity: Identity, by userId: UUID) async throws -> BusinessMTLSCertRecord {
        let snapshot = try await EntitlementService(db: db, ctx: ctx).snapshot(businessId: businessId)
        guard snapshot.tiers.contains(.e) else {
            throw APIError(.forbidden, .forbidden, "Client certificates are part of the Enterprise tier. Ask Viadere to enable it for your organization.")
        }
        let label = rawLabel.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...64).contains(label.count), !label.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw APIError.validation("Give the certificate a label of up to 64 characters.", details: ["label": "invalid"])
        }
        guard identity.notAfter > ctx.now else { throw APIError.validation("That certificate has expired.", details: ["certificate": "expired"]) }
        guard try await BusinessMTLSCertRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).count() < Self.maxPerBusiness else {
            throw APIError.conflict("Remove an unused certificate before adding another.")
        }
        if identity.kind == "issuer" {
            // A CA is matched at request time by the key identifier the edge forwards, so no other tenant may hold the same identifier: that would let
            // a CA that merely copies it stand in for this one (and the shared mTLS hostname trusts every uploaded CA).
            guard let ski = identity.issuerSKI, !ski.isEmpty else { throw APIError.validation("That certificate authority has no subject key identifier.", details: ["certificate": "not_ca"]) }
            let clash = try await BusinessMTLSCertRecord.query(on: db).filter(\.$kind == "issuer").filter(\.$issuerSKI == ski).filter(\.$revokedAt == nil)
                .filter(\.$businessId != businessId).count()
            guard clash == 0 else { throw APIError.conflict("That certificate authority is already registered.") }
        }
        let record = BusinessMTLSCertRecord()
        record.id = UUID()
        record.businessId = businessId
        record.kind = identity.kind
        record.fingerprint = identity.fingerprint
        record.issuerSKI = identity.issuerSKI
        record.label = label
        record.subject = identity.subject.isEmpty ? nil : identity.subject
        record.notAfter = identity.notAfter == .distantFuture ? nil : identity.notAfter
        record.createdBy = userId
        record.createdAt = ctx.now
        do { try await record.create(on: db) } catch {
            // The same certificate cannot belong to two tenants (the unique index spans tenants); do not say whose it is.
            if error.isConstraintViolation { throw APIError.conflict("That certificate is already registered.") }
            throw error
        }
        _ = try await AuditService(db: db, ctx: ctx).record("mtls.certificate_added", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
            businessId: BusinessID(businessId), subjectType: "mtls_certificate", subjectId: record.id?.uuidString.lowercased(),
            metadata: ["kind": identity.kind, "label": label, "fingerprint_prefix": String(identity.fingerprint.prefix(12))])
        return record
    }

    func revoke(businessId: UUID, id: UUID, by userId: UUID) async throws {
        guard let record = try await BusinessMTLSCertRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        guard record.revokedAt == nil else { return }
        record.revokedAt = ctx.now
        record.revokedBy = userId
        try await record.update(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("mtls.certificate_revoked", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
            businessId: BusinessID(businessId), subjectType: "mtls_certificate", subjectId: id.uuidString.lowercased())
    }

    // MARK: Enforcement

    /// Whether the verified certificate on this request is one `businessId` bound (and, if the key names a certificate, that very one).
    /// Nothing but a request that passed the origin lock can have `edge.clientCertFingerprint`.
    func permits(businessId: UUID, certBinding: UUID?, edge: EdgeContext) async throws -> Bool {
        guard edge.viaEdge, edge.clientCertFingerprint != nil || edge.clientCertIssuerSKI != nil else { return false }
        var query = BusinessMTLSCertRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$revokedAt == nil)
        if let certBinding { query = query.filter(\.$id == certBinding) }
        let now = ctx.now
        var matched = false
        for cert in try await query.all() where cert.isActive(at: now) {
            if cert.kind == "leaf" {
                if let presented = edge.clientCertFingerprint, ConstantTime.equals(presented, cert.fingerprint) { matched = true }
            } else if let ski = cert.issuerSKI, let presented = edge.clientCertIssuerSKI, ConstantTime.equals(presented, ski) {
                // The identifier selects the binding; when the edge also forwards the SHA-256 of the issuer certificate it has to be this CA's.
                if let issuerHash = edge.clientCertIssuerSHA256, !ConstantTime.equals(issuerHash, cert.fingerprint) { continue }
                matched = true
            }
        }
        return matched
    }
}
