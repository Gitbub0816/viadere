@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import Vapor
import SwiftASN1
import ViadereCore
import XCTest
@preconcurrency import X509
@testable import ViadereServerKit

/// Origin lock (G-10) and Tier E client certificates (SEC-TR-005): a header Cloudflare sets is trusted only on a request that proved it came
/// through Cloudflare, and a certificate-bound key refuses everything else.
final class WP6EdgeTests: XCTestCase {
    private let token = SecureToken.generate()
    private let previous = SecureToken.generate()
    private let probe = "/v1/business/webhooks"
    private let fingerprintA = String(repeating: "ab", count: 32)
    private let fingerprintB = String(repeating: "cd", count: 32)

    private func locked(_ config: inout ServerConfig) { config.operations.edgeTokens = [Data(token.utf8), Data(previous.utf8)] }

    private func edgeHeaders(fingerprint: String? = nil, verified: String = "true", issuer: String? = nil, edgeToken: String? = nil) -> [String: String] {
        var headers = ["X-Viadere-Edge-Token": edgeToken ?? token]
        if let fingerprint { headers["X-Viadere-Client-Cert-Sha256"] = fingerprint; headers["X-Viadere-Client-Cert-Verified"] = verified }
        if let issuer { headers["X-Viadere-Client-Cert-Issuer-Ski"] = issuer; headers["X-Viadere-Client-Cert-Verified"] = verified }
        return headers
    }

    // MARK: Origin lock

    func testRequestsWithoutTheEdgeTokenAreRefusedBeforeAnyRouting() async throws {
        try await withHarness(locked) { h in
            for path in ["/v1/directory/search?q=a", "/dashboard/login", "/operator/login", "/.well-known/apple-app-site-association", "/metrics", "/healthz"] {
                let result = try await h.request(.GET, path)
                XCTAssertEqual(result.status, .misdirectedRequest, path)
                XCTAssertFalse(result.text.contains("Viadere-Edge"), "the refusal does not help a prober")
            }
            let post = try await h.request(.POST, "/v1/auth/login/begin", body: Data("{}".utf8))
            XCTAssertEqual(post.status, .misdirectedRequest)
            // A wrong token, a truncated token and a token with the right prefix are all the same refusal.
            for bad in ["", "x", String(token.dropLast()), token + "x", token.uppercased()] {
                let result = try await h.request(.GET, "/v1/directory/search?q=a", headers: bad.isEmpty ? [:] : ["X-Viadere-Edge-Token": bad])
                XCTAssertEqual(result.status, .misdirectedRequest, "'\(bad)'")
            }
            // The right token (current or previous, for rotation) passes.
            for good in [token, previous] {
                let result = try await h.request(.GET, "/v1/directory/search?q=a", headers: ["X-Viadere-Edge-Token": good])
                XCTAssertNotEqual(result.status, .misdirectedRequest)
            }
            // The token is also required for the console (an attacker who reaches the origin directly gets no login page either).
            let console = try await h.request(.GET, "/dashboard/login", headers: ["X-Viadere-Edge-Token": token])
            XCTAssertEqual(console.status, .ok)
        }
    }

    func testHealthChecksAreExemptOnlyFromFlysInternalNetworkAndOnlyWithoutProxyHeaders() {
        var settings = OperationsSettings()
        settings.edgeTokens = [Data(token.utf8)]
        func decide(token: String? = nil, path: String = "/healthz", method: HTTPMethod = .GET, headers: [String] = [], peer: String? = "172.19.0.2") -> EdgeLockMiddleware.Decision {
            EdgeLockMiddleware.decide(settings: settings, token: token, path: path, method: method, headerNames: headers, peer: peer)
        }
        XCTAssertEqual(decide(), .allow(viaEdge: false))
        XCTAssertEqual(decide(path: "/readyz", peer: "fdaa:0:1::3"), .allow(viaEdge: false))
        XCTAssertEqual(decide(peer: "203.0.113.9"), .rejectMissingToken, "a public peer is not Fly's checker")
        XCTAssertEqual(decide(peer: nil), .rejectMissingToken)
        for header in EdgeLockMiddleware.proxyHeaders {
            XCTAssertEqual(decide(headers: [header]), .rejectMissingToken, header)
            XCTAssertEqual(decide(headers: [header.uppercased()]), .rejectMissingToken, header)
        }
        XCTAssertEqual(decide(path: "/v1/auth/login/begin"), .rejectMissingToken)
        XCTAssertEqual(decide(path: "/healthz", method: .POST), .rejectMissingToken)
        XCTAssertEqual(decide(path: "/healthz/../v1/x"), .rejectMissingToken)
        XCTAssertEqual(decide(token: "wrong"), .rejectBadToken, "a wrong token is refused even on a health path")
        XCTAssertEqual(decide(token: token, path: "/v1/x", headers: ["x-forwarded-for"]), .allow(viaEdge: true))
        // With no token configured (development, tests) nothing is enforced and nothing is trusted.
        XCTAssertEqual(EdgeLockMiddleware.decide(settings: OperationsSettings(), token: nil, path: "/v1/x", method: .GET, headerNames: [], peer: nil), .allow(viaEdge: false))
    }

    func testProductionConfigurationRequiresAnEdgeTokenAndRejectsWeakOnes() throws {
        var env = [
            "ENVIRONMENT": "production", "DATABASE_URL": "postgres://u:p@db/viadere", "CONNECT_LINK_SIGNING_KEY": SecureToken.generate(), "SERVER_PEPPER": SecureToken.generate(),
            "DATA_ENCRYPTION_KEY": SecureToken.generate(), "APNS_KEY_P8": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "APNS_KEY_ID": "ABC123DEFG",
            "AUDIT_CHAIN_KEY": SecureToken.generate(), "SUBJECT_REF_KEY": SecureToken.generate(), "KEY_DIRECTORY_LOG_KEY": SecureToken.generate(), "EDGE_TOKEN": token,
            "APNS_TEAM_ID": "TEAM123456", "TWILIO_ACCOUNT_SID": "AC1", "TWILIO_AUTH_TOKEN": "tok", "TWILIO_FROM_NUMBER": "+15550001111", "APPLE_TEAM_ID": "TEAM123456",
            "EMAIL_API_URL": "https://mail.example.com/v1/send", "EMAIL_API_KEY": "key_123", "EMAIL_FROM_ADDRESS": "no-reply@viadere.com",
        ]
        let config = try ServerConfig.fromEnvironment(env)
        XCTAssertEqual(config.operations.edgeTokens, [Data(token.utf8)])
        XCTAssertTrue(config.operations.webhookOwnershipVerification, "required by default in production")
        // Missing, too short, or containing whitespace: the server does not start.
        var missing = env
        missing["EDGE_TOKEN"] = nil
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(missing))
        for weak in ["", "short", String(repeating: "a", count: 31), "has space in it but is long enough to pass the length check"] {
            var broken = env
            broken["EDGE_TOKEN"] = weak
            XCTAssertThrowsError(try ServerConfig.fromEnvironment(broken), "'\(weak)'")
        }
        // Rotation: the previous value is accepted too.
        env["EDGE_TOKEN_PREVIOUS"] = previous
        XCTAssertEqual(try ServerConfig.fromEnvironment(env).operations.edgeTokens, [Data(token.utf8), Data(previous.utf8)])
        // Ownership verification cannot be switched off in production, and a staging environment needs the token as well.
        env["WEBHOOK_OWNERSHIP_VERIFICATION"] = "off"
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(env))
        env["WEBHOOK_OWNERSHIP_VERIFICATION"] = nil
        env["ENVIRONMENT"] = "staging"
        env["EDGE_TOKEN"] = nil
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(env))
        // Development stays open.
        XCTAssertEqual(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development"]).operations.edgeTokens, [])
    }

    // MARK: Tier E

    /// Console setup passes through the origin lock like real traffic does; the token is dropped again before the assertions.
    private func organization(_ h: TestHarness, email: String = "owner@example.com", org: String = "Acme Roasters", handle: String = "acmeroasters", tierE: Bool = true)
        async throws -> (businessId: UUID, owner: DashSession) {
        let saved = h.edgeTokenForRequests
        h.edgeTokenForRequests = token
        defer { h.edgeTokenForRequests = saved }
        let (owner, _, businessId) = try await h.verifiedOwner(email: email, org: org, handle: handle)
        if tierE { try await EntitlementService(db: h.db, ctx: h.ctx).grant(businessId: businessId, tier: .e, actor: .system("test"), justification: "Test fixture: Tier E.") }
        return (businessId, owner)
    }

    private func bind(_ h: TestHarness, _ businessId: UUID, kind: String = "leaf", fingerprint: String, issuerSKI: String? = nil, label: String = "gateway",
                      notAfter: Date? = nil) async throws -> BusinessMTLSCertRecord {
        try await MTLSCertificates(db: h.db, ctx: h.ctx).add(businessId: businessId, label: label,
            identity: .init(kind: kind, fingerprint: fingerprint, subject: "CN=\(label)", notAfter: notAfter ?? h.clock.now().addingTimeInterval(86_400 * 365), issuerSKI: issuerSKI), by: UUID())
    }

    /// A self-signed CA certificate with a chosen subject key identifier (the identifier is attacker-chosen text, which is the point of M4).
    private func caPEM(ski: [UInt8], name: String) throws -> String {
        let key = P256.Signing.PrivateKey()
        let dn = try DistinguishedName { CommonName(name) }
        let now = Date()
        let certificate = try Certificate(version: .v3, serialNumber: Certificate.SerialNumber(), publicKey: .init(key.publicKey),
            notValidBefore: now.addingTimeInterval(-3600), notValidAfter: now.addingTimeInterval(86_400 * 365), issuer: dn, subject: dn,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                SubjectKeyIdentifier(keyIdentifier: ArraySlice(ski))
            }, issuerPrivateKey: .init(key))
        return try certificate.serializeAsPEM().pemString
    }

    private func derSHA256(_ pem: String) throws -> String {
        var serializer = DER.Serializer()
        try Certificate(pemEncoded: pem).serialize(into: &serializer)
        return SecureToken.sha256Hex(Data(serializer.serializedBytes))
    }

    private func mtlsKey(_ h: TestHarness, _ businessId: UUID, certBinding: UUID? = nil, requires: Bool = true) async throws -> String {
        var options = BusinessAPIKeys.Options()
        options.requiresMTLS = requires
        options.certBinding = certBinding
        return try await BusinessAPIKeys.issue(businessId: businessId, name: "enterprise", live: false, scopes: ["webhooks:manage"], now: h.clock.now(), options: options, on: h.db).key
    }

    func testACertificateBoundKeyNeedsTheVerifiedCertificateAndNothingElseWillDo() async throws {
        try await withHarness(locked) { h in
            let (businessId, _) = try await organization(h)
            _ = try await bind(h, businessId, fingerprint: fingerprintA)
            let key = try await mtlsKey(h, businessId)
            func call(_ headers: [String: String]) async throws -> HTTPStatus { try await h.apiGet(key, probe, headers: headers).status }
            // The right certificate, forwarded by the edge: works. The API key is still what authenticates.
            let good = try await call(edgeHeaders(fingerprint: fingerprintA))
            XCTAssertEqual(good, .ok)
            let colons = try await call(edgeHeaders(fingerprint: stride(from: 0, to: 64, by: 2).map { String(fingerprintA.dropFirst($0).prefix(2)) }.joined(separator: ":").uppercased()))
            XCTAssertEqual(colons, .ok, "colon-separated, upper case fingerprints are normalized")
            // Everything that is not that certificate is the same 401.
            let none = try await call(edgeHeaders())
            let other = try await call(edgeHeaders(fingerprint: fingerprintB))
            let unverified = try await call(edgeHeaders(fingerprint: fingerprintA, verified: "false"))
            let malformed = try await call(edgeHeaders(fingerprint: "not-hex"))
            let short = try await call(edgeHeaders(fingerprint: String(fingerprintA.prefix(63))))
            for status in [none, other, unverified, malformed, short] { XCTAssertEqual(status, .unauthorized) }
            // A request without the key fails on the key, whatever certificate it presents.
            let noKey = try await h.request(.GET, probe, headers: edgeHeaders(fingerprint: fingerprintA))
            XCTAssertEqual(noKey.status, .unauthorized)
            // The refusal is audited (rate-limited), without the fingerprint.
            let denied = try await AuditEventRecord.query(on: h.db).filter(\.$action == "apikey.mtls_denied").all()
            XCTAssertEqual(denied.count, 1)
            XCTAssertFalse(denied[0].metadataJSON.contains(fingerprintA))
        }
    }

    func testASpoofedCertificateHeaderWithoutTheEdgeTokenNeverAuthenticates() async throws {
        try await withHarness(locked) { h in
            let (businessId, _) = try await organization(h)
            _ = try await bind(h, businessId, fingerprint: fingerprintA)
            let key = try await mtlsKey(h, businessId)
            // The attacker holds the key and sends the verified-certificate headers straight to the origin: the lock refuses before anything is read.
            let spoof = try await h.apiGet(key, probe, headers: ["X-Viadere-Client-Cert-Sha256": fingerprintA, "X-Viadere-Client-Cert-Verified": "true"])
            XCTAssertEqual(spoof.status, .misdirectedRequest)
            let wrongToken = try await h.apiGet(key, probe, headers: edgeHeaders(fingerprint: fingerprintA, edgeToken: SecureToken.generate()))
            XCTAssertEqual(wrongToken.status, .misdirectedRequest)
            let reached = try await AuditEventRecord.query(on: h.db).filter(\.$action == "apikey.mtls_denied").count()
            XCTAssertEqual(reached, 0, "it never got as far as the key")
        }
        // Where no lock is configured (development, tests) the headers are not trusted at all: a certificate-bound key stays unusable.
        try await withHarness { h in
            let (businessId, _) = try await organization(h)
            _ = try await bind(h, businessId, fingerprint: fingerprintA)
            let key = try await mtlsKey(h, businessId)
            let spoof = try await h.apiGet(key, probe, headers: ["X-Viadere-Client-Cert-Sha256": fingerprintA, "X-Viadere-Client-Cert-Verified": "true", "X-Viadere-Edge-Token": token])
            XCTAssertEqual(spoof.status, .unauthorized)
        }
    }

    func testCertificatesAreTenantBoundRevocableAndExpire() async throws {
        try await withHarness(locked) { h in
            let (businessId, _) = try await organization(h)
            let (otherId, _) = try await organization(h, email: "o2@example.net", org: "Other Co", handle: "otherco")
            let mine = try await bind(h, businessId, fingerprint: fingerprintA)
            _ = try await bind(h, otherId, fingerprint: fingerprintB, label: "theirs")
            let key = try await mtlsKey(h, businessId)
            // Another tenant's certificate does not open my key; mine cannot be registered by them.
            let theirs = try await h.apiGet(key, probe, headers: edgeHeaders(fingerprint: fingerprintB)).status
            XCTAssertEqual(theirs, .unauthorized)
            do {
                _ = try await bind(h, otherId, fingerprint: fingerprintA, label: "stolen")
                XCTFail("a fingerprint belongs to one tenant")
            } catch let error as APIError { XCTAssertEqual(error.status, .conflict) }
            // Expiry and revocation end the binding at once.
            let before = try await h.apiGet(key, probe, headers: edgeHeaders(fingerprint: fingerprintA)).status
            XCTAssertEqual(before, .ok)
            try await MTLSCertificates(db: h.db, ctx: h.ctx).revoke(businessId: businessId, id: mine.id!, by: UUID())
            let after = try await h.apiGet(key, probe, headers: edgeHeaders(fingerprint: fingerprintA)).status
            XCTAssertEqual(after, .unauthorized)
            let short = try await bind(h, businessId, fingerprint: String(repeating: "ef", count: 32), label: "short", notAfter: h.clock.now().addingTimeInterval(3600))
            let live = try await h.apiGet(key, probe, headers: edgeHeaders(fingerprint: short.fingerprint)).status
            XCTAssertEqual(live, .ok)
            h.clock.advance(by: 3601)
            let expired = try await h.apiGet(key, probe, headers: edgeHeaders(fingerprint: short.fingerprint)).status
            XCTAssertEqual(expired, .unauthorized)
            // A tenant that is not Enterprise cannot bind anything.
            let (plainId, _) = try await organization(h, email: "o3@example.net", org: "Plain Co", handle: "plainco", tierE: false)
            do {
                _ = try await bind(h, plainId, fingerprint: String(repeating: "12", count: 32))
                XCTFail("Tier E only")
            } catch let error as APIError { XCTAssertEqual(error.status, .forbidden) }
        }
    }

    func testAKeyBoundToOneCertificateRefusesAnotherCertificateOfTheSameTenant() async throws {
        try await withHarness(locked) { h in
            let (businessId, _) = try await organization(h)
            let first = try await bind(h, businessId, fingerprint: fingerprintA, label: "primary")
            _ = try await bind(h, businessId, fingerprint: fingerprintB, label: "secondary")
            let bound = try await mtlsKey(h, businessId, certBinding: first.id)
            let unbound = try await mtlsKey(h, businessId)
            let withFirst = try await h.apiGet(bound, probe, headers: edgeHeaders(fingerprint: fingerprintA)).status
            let withSecond = try await h.apiGet(bound, probe, headers: edgeHeaders(fingerprint: fingerprintB)).status
            XCTAssertEqual(withFirst, .ok)
            XCTAssertEqual(withSecond, .unauthorized, "bound to a specific certificate")
            let anyForUnbound = try await h.apiGet(unbound, probe, headers: edgeHeaders(fingerprint: fingerprintB)).status
            XCTAssertEqual(anyForUnbound, .ok, "a key that only requires mTLS accepts any of the tenant's certificates")
        }
    }

    func testTenantWideRequirementAndIssuerBindings() async throws {
        try await withHarness(locked) { h in
            let (businessId, owner) = try await organization(h)
            let plainKey = try await mtlsKey(h, businessId, requires: false)
            let noCert = try await h.apiGet(plainKey, probe, headers: edgeHeaders()).status
            XCTAssertEqual(noCert, .ok, "no requirement yet")
            _ = try await bind(h, businessId, kind: "issuer", fingerprint: String(repeating: "5a", count: 32), issuerSKI: "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567", label: "corporate CA")
            // The tenant turns the requirement on for every key (the console form is behind the lock, so set the row the form sets).
            try await SecuritySettings(db: h.db, ctx: h.ctx).setMTLSRequired(businessId: businessId, required: true, by: UUID())
            let refused = try await h.apiGet(plainKey, probe, headers: edgeHeaders()).status
            XCTAssertEqual(refused, .unauthorized)
            let viaIssuer = try await h.apiGet(plainKey, probe, headers: edgeHeaders(issuer: "0A:1B:2C:3D:4E:5F:60:71:82:93:A4:B5:C6:D7:E8:F9:01:23:45:67")).status
            XCTAssertEqual(viaIssuer, .ok, "a certificate issued by the bound CA")
            let wrongIssuer = try await h.apiGet(plainKey, probe, headers: edgeHeaders(issuer: "ffffffffffffffffffffffffffffffffffffffff")).status
            XCTAssertEqual(wrongIssuer, .unauthorized)
            // A leaf fingerprint is not an issuer id: the kinds do not mix.
            _ = try await bind(h, businessId, fingerprint: fingerprintA, label: "leaf")
            let leafAsIssuer = try await h.apiGet(plainKey, probe, headers: edgeHeaders(issuer: fingerprintA)).status
            XCTAssertEqual(leafAsIssuer, .unauthorized)
            _ = owner
        }
    }

    /// Platform gate M4 exploit: the SKI is text the CA's owner chooses. Binding by it let one tenant register a CA that copies another tenant's
    /// identifier; the binding is now the SHA-256 of the CA certificate, and a second tenant may not claim an identifier already in use.
    func testACaIsBoundByItsCertificateHashAndAnotherTenantCannotClaimItsKeyIdentifier() async throws {
        try await withHarness(locked) { h in
            let (victim, _) = try await organization(h)
            let (attacker, _) = try await organization(h, email: "evil@example.com", org: "Evil Roasters", handle: "evilroasters")
            let ski: [UInt8] = Array(0x10...0x23)
            let victimPEM = try caPEM(ski: ski, name: "Victim CA")
            let forgedPEM = try caPEM(ski: ski, name: "Forged CA")
            let identity = try MTLSCertificates.identity(pem: victimPEM, asCA: true)
            XCTAssertEqual(identity.fingerprint, try derSHA256(victimPEM), "bound by the SHA-256 of the CA certificate")
            XCTAssertEqual(identity.issuerSKI, Hex.encode(ski))
            _ = try await MTLSCertificates(db: h.db, ctx: h.ctx).add(businessId: victim, label: "corp CA", identity: identity, by: UUID())
            // The attacker's CA copies the identifier: refused at onboarding, whichever tenant came first.
            let forged = try MTLSCertificates.identity(pem: forgedPEM, asCA: true)
            XCTAssertNotEqual(forged.fingerprint, identity.fingerprint)
            do {
                _ = try await MTLSCertificates(db: h.db, ctx: h.ctx).add(businessId: attacker, label: "mine", identity: forged, by: UUID())
                XCTFail("a duplicate key identifier across tenants must be refused")
            } catch let error as APIError { XCTAssertEqual(error.status, .conflict) }
            // At request time the identifier alone authorizes only the tenant that owns the binding.
            let victimKey = try await mtlsKey(h, victim)
            let attackerKey = try await mtlsKey(h, attacker)
            let skiHeader = Hex.encode(ski)
            let ok = try await h.apiGet(victimKey, probe, headers: edgeHeaders(issuer: skiHeader)).status
            XCTAssertEqual(ok, .ok)
            let notMine = try await h.apiGet(attackerKey, probe, headers: edgeHeaders(issuer: skiHeader)).status
            XCTAssertEqual(notMine, .unauthorized)
            // When the edge also forwards the issuer certificate's hash, it must be the bound CA's.
            var withHash = edgeHeaders(issuer: skiHeader)
            withHash["X-Viadere-Client-Cert-Issuer-Sha256"] = forged.fingerprint
            let wrongHash = try await h.apiGet(victimKey, probe, headers: withHash).status
            XCTAssertEqual(wrongHash, .unauthorized, "same identifier, different CA certificate")
            withHash["X-Viadere-Client-Cert-Issuer-Sha256"] = identity.fingerprint
            let rightHash = try await h.apiGet(victimKey, probe, headers: withHash).status
            XCTAssertEqual(rightHash, .ok)
        }
    }

    func testRequiringMTLSForAKeyNeedsTierEAndABoundCertificateInTheConsole() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let denied = try await h.createKey(owner, scopes: ["webhooks:manage"], extra: [("requireMtls", "1")])
            XCTAssertEqual(denied.status, .forbidden, "Enterprise tier only")
            try await EntitlementService(db: h.db, ctx: h.ctx).grant(businessId: businessId, tier: .e, actor: .system("test"), justification: "Test fixture: Tier E.")
            let noCert = try await h.createKey(owner, scopes: ["webhooks:manage"], extra: [("requireMtls", "1")])
            XCTAssertEqual(noCert.status, .conflict, "bind a certificate first: a key nobody can use is a mistake")
            let added = try await h.formPost("/dashboard/security/certificates", owner, [("label", "gateway"), ("fingerprint", fingerprintA), ("kind", "leaf")])
            XCTAssertEqual(added.status, .seeOther, added.text)
            let ok = try await h.createKey(owner, scopes: ["webhooks:manage"], extra: [("requireMtls", "1")])
            XCTAssertEqual(ok.status, .ok, ok.text)
            let record = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            XCTAssertTrue(record.requiresMTLS)
            // Without the edge in front (no lock configured in this harness) the key cannot be used: failing closed.
            let status = try await h.apiGet(try XCTUnwrap(ok.secret), probe).status
            XCTAssertEqual(status, .unauthorized)
        }
    }
}
