@preconcurrency import Crypto
import Fluent
import Foundation
import NIOCore
import NIOHTTP1
import Vapor
import XCTest
import ViadereCore
@testable import ViadereServerKit

/// RFC 9421 request signatures for business API calls (SECURITY §2.112, ADR-0020 §3). Every refusal of the profile is reproduced from the
/// cross-language vectors (`docs/protocol/vectors/http-signatures-v1.json`) against the server's own adapter and, where the route exists, over HTTP
/// before any handler runs; then the end-to-end paths: a live key authenticated by a signature without mutual TLS, mutual TLS still working, the
/// console registration with proof of possession, revocation, rotation and configuration.
final class RequestSignatureTests: AuthDeliveryTestBase {
    // MARK: Vectors

    struct VRequest: Decodable {
        var method: String, pathAndQuery: String, headers: [[String]], body: String
        enum CodingKeys: String, CodingKey { case method, pathAndQuery = "path_and_query", headers, body }
    }
    struct VPresenter: Decodable {
        var businessId: String, apiKeyId: String
        enum CodingKeys: String, CodingKey { case businessId = "business_id", apiKeyId = "api_key_id" }
    }
    struct VUsed: Decodable { var scope: String, nonce: String }
    struct VCase: Decodable {
        var name: String, request: VRequest, presenter: VPresenter, expectedError: String?, usedNonces: [VUsed]?, nonce: String?
        enum CodingKeys: String, CodingKey { case name, request, presenter, expectedError = "expected_error", usedNonces = "used_nonces", nonce }
    }
    struct VKey: Decodable {
        var keyid: String, publicKey: String, businessId: String, apiKeyId: String, revoked: Bool
        enum CodingKeys: String, CodingKey { case keyid, publicKey = "public_key", businessId = "business_id", apiKeyId = "api_key_id", revoked }
    }
    struct Vectors: Decodable {
        var now: Int64, keys: [VKey], signerPrivateKeyHex: String, positive: [VCase], negative: [VCase]
        enum CodingKeys: String, CodingKey { case now, keys, signerPrivateKeyHex = "signer_private_key_hex", positive, negative }
    }

    static let vectors: Vectors = {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 { url.deleteLastPathComponent() }
        return try! JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url.appendingPathComponent("docs/protocol/vectors/http-signatures-v1.json")))
    }()

    /// The vector world on a real database: vector business and API-key ids map to real records; the signing keys are registered with the vector
    /// key ids and public keys.
    struct World {
        var businesses: [String: TestBusiness] = [:]
        var keys: [String: (secret: String, record: BusinessAPIKeyRecord)] = [:]
        func secret(_ p: VPresenter) -> String { keys[p.apiKeyId]!.secret }
        func record(_ p: VPresenter) -> BusinessAPIKeyRecord { keys[p.apiKeyId]!.record }
        func scope(_ vectorScope: String) -> String {
            var s = vectorScope
            for (vid, b) in businesses { s = s.replacingOccurrences(of: vid, with: b.id.uuid.uuidString.lowercased()) }
            return s
        }
    }

    func world(_ h: TestHarness) async throws -> World {
        h.clock.set(Date(timeIntervalSince1970: TimeInterval(Self.vectors.now)))
        var w = World()
        var n = 0
        for k in Self.vectors.keys {
            if w.businesses[k.businessId] == nil {
                n += 1
                w.businesses[k.businessId] = try await h.makeBusiness(name: "Vector \(n)", handle: "vector\(n)",
                                                                      capabilities: Capability.operational)
            }
            let business = w.businesses[k.businessId]!
            if w.keys[k.apiKeyId] == nil {
                let issued = try await BusinessAPIKeys.issue(businessId: business.id.uuid, name: "vector", live: true, scopes: BusinessAPIKeys.Scope.all,
                                                             capabilities: Capability.operational, now: h.clock.now(), on: h.db)
                w.keys[k.apiKeyId] = (issued.key, issued.record)
            }
            let row = BusinessRequestSigningKeyRecord()
            row.id = UUID(); row.businessId = business.id.uuid; row.apiKeyId = w.keys[k.apiKeyId]!.record.id!
            row.keyid = k.keyid; row.publicKey = k.publicKey; row.fingerprint = try DevicePublicKey(base64URL: k.publicKey).fingerprint
            row.label = "vector"; row.createdBy = UUID(); row.createdAt = h.clock.now(); row.revokedAt = k.revoked ? h.clock.now() : nil
            try await row.create(on: h.db)
        }
        return w
    }

    /// The server's own adapter (Vapor request → profile), exactly as the middleware calls it.
    func adapter(_ h: TestHarness, _ w: World, _ c: VCase) async throws -> Result<String, APIError> {
        var headers = HTTPHeaders()
        for pair in c.request.headers { headers.add(name: pair[0], value: pair[1]) }
        let body = Data(c.request.body.utf8)
        let request = Request(application: h.app, method: HTTPMethod(rawValue: c.request.method), url: URI(string: c.request.pathAndQuery), headers: headers,
                              collectedBody: body.isEmpty ? nil : ByteBuffer(data: body), on: h.app.eventLoopGroup.next())
        do { return .success(try await RequestSigningKeys.verify(request, key: w.record(c.presenter), ctx: h.ctx, db: h.db)) } catch let e as APIError { return .failure(e) }
    }

    /// Over HTTP, through routing and the API-key middleware (duplicate field lines kept as separate lines).
    func http(_ h: TestHarness, _ w: World, _ c: VCase) async throws -> HTTPResult {
        var headers = HTTPHeaders()
        headers.add(name: "Authorization", value: "Bearer \(w.secret(c.presenter))")
        headers.add(name: "Idempotency-Key", value: UUID().uuidString)
        for pair in c.request.headers { headers.add(name: pair[0], value: pair[1]) }
        let box = Box<HTTPResult>()
        let body = Data(c.request.body.utf8)
        try await h.app.test(HTTPMethod(rawValue: c.request.method), c.request.pathAndQuery, headers: headers, body: body.isEmpty ? nil : ByteBuffer(data: body)) { response async throws in
            box.value = HTTPResult(status: response.status, headers: response.headers, body: Data(response.body.readableBytesView))
        }
        return box.value!
    }

    func preload(_ h: TestHarness, _ w: World, _ c: VCase) async throws {
        for u in c.usedNonces ?? [] {
            try await ReplayNonceRecord(scope: w.scope(u.scope), nonce: u.nonce, expiresAt: h.clock.now().addingTimeInterval(600)).create(on: h.db)
        }
    }

    func expectedCode(_ reason: String) -> APIErrorCode {
        switch reason {
        case "created_in_future", "stale", "expired": .clockSkew
        case "replayed": .replayDetected
        default: .signatureInvalid
        }
    }

    func testEveryNegativeVectorIsRefusedByTheServerAdapterWithItsReason() async throws {
        try await harness({ $0.authDelivery.liveKeyAssurance = .mtlsOrSignature }) { h in
            let w = try await world(h)
            for c in Self.vectors.negative where c.expectedError != "missing_signature" {
                try await preload(h, w, c)
                let outcome = try await adapter(h, w, c)
                guard case .failure(let error) = outcome else { XCTFail("\(c.name) was accepted"); continue }
                XCTAssertEqual(error.status, .unauthorized, c.name)
                XCTAssertEqual(error.code, expectedCode(c.expectedError!), c.name)
                // Structural reasons are named; key and signature failures are one answer.
                if ["unknown_key", "revoked_key", "wrong_business", "wrong_api_key", "bad_signature"].contains(c.expectedError!) {
                    XCTAssertNil(error.details, c.name)
                } else if error.code == .signatureInvalid {
                    XCTAssertEqual(error.details?["reason"], c.expectedError, c.name)
                }
            }
            // Each refusal is audited with its reason (rate-limited per key and reason), and counted.
            let audits = try await AuditEventRecord.query(on: h.db).filter(\.$action == "apikey.signature_denied").all()
            let reasons = Set(audits.compactMap { try? JSONSerialization.jsonObject(with: Data($0.metadataJSON.utf8)) as? [String: String] }.compactMap { $0["reason"] })
            for c in Self.vectors.negative where c.expectedError != "missing_signature" { XCTAssertTrue(reasons.contains(c.expectedError!), "no audit for \(c.expectedError!)") }
            XCTAssertGreaterThan(h.ctx.metrics.value(.apiKeySignatureDenied), 0)
        }
    }

    func testNegativeVectorsOnAuthRoutesAreRefusedOverHTTPBeforeAnyHandler() async throws {
        try await harness({ $0.authDelivery.liveKeyAssurance = .mtlsOrSignature }) { h in
            let w = try await world(h)
            var checked = 0
            for c in Self.vectors.negative where c.request.pathAndQuery.hasPrefix("/v1/business/auth-deliveries") {
                try await preload(h, w, c)
                let r = try await http(h, w, c)
                // A body that is not `application/json` never reaches authentication: the content-type gate in front of every JSON route answers
                // `415` first. Refused before any handler either way.
                if c.name == "body_without_content_type" || c.name == "other_content_type" {
                    XCTAssertEqual(r.status, .unsupportedMediaType, "\(c.name): \(r.text)")
                    continue
                }
                XCTAssertEqual(r.status, .unauthorized, "\(c.name): \(r.text)")
                XCTAssertEqual(r.errorCode, c.expectedError == "missing_signature" ? .signatureRequired : expectedCode(c.expectedError!), c.name)
                checked += 1
            }
            XCTAssertGreaterThan(checked, 40)
            // Nothing reached a handler: no delivery, no idempotency record.
            let deliveries = try await AuthDeliveryRecord.query(on: h.db).count()
            XCTAssertEqual(deliveries, 0)
        }
    }

    func testPositiveVectorsVerifyAndSpendTheirNonceOnce() async throws {
        try await harness({ $0.authDelivery.liveKeyAssurance = .mtlsOrSignature }) { h in
            let w = try await world(h)
            for c in Self.vectors.positive {
                guard case .success(let keyId) = try await adapter(h, w, c) else { XCTFail("\(c.name) refused"); continue }
                XCTAssertEqual(keyId, "vsk_0123456789abcdef")
                let spent = try await ReplayNonceRecord.query(on: h.db).filter(\.$nonce == c.nonce!).first()
                XCTAssertEqual(spent?.scope, "bizsig:\(w.record(c.presenter).businessId.uuidString.lowercased()):vsk_0123456789abcdef", c.name)
                // The same request again is a replay.
                guard case .failure(let again) = try await adapter(h, w, c) else { XCTFail("\(c.name) replayed"); continue }
                XCTAssertEqual(again.code, .replayDetected, c.name)
            }
        }
    }

    func testAPositiveVectorPassesTheMiddlewareOverHTTP() async throws {
        try await harness({ $0.authDelivery.liveKeyAssurance = .mtlsOrSignature }) { h in
            let w = try await world(h)
            // `post_json_body` names a subject nobody has: past the signature, the live-key check and into the handler, which answers 404 not_deliverable.
            let c = Self.vectors.positive.first { $0.name == "post_json_body" }!
            let r = try await http(h, w, c)
            XCTAssertNotEqual(r.status, .unauthorized, r.text)
            XCTAssertTrue([.notFound, .unprocessableEntity].contains(r.status), r.text)
            let used = try await BusinessRequestSigningKeyRecord.query(on: h.db).filter(\.$keyid == "vsk_0123456789abcdef").first()
            XCTAssertNotNil(used?.lastUsedAt)
        }
    }

    // MARK: End to end

    /// A fresh software key (the `vsk_` id is assigned at registration).
    func signer() -> P256.Signing.PrivateKey { P256.Signing.PrivateKey() }

    /// Registers `privateKey`'s public key for `apiKey` through the service the console uses (challenge, proof of possession); returns a signer
    /// under the `vsk_` id the server issued.
    func register(_ h: TestHarness, _ b: TestBusiness, apiKey: BusinessAPIKeyRecord, key privateKey: P256.Signing.PrivateKey) async throws -> SoftwareHTTPRequestSigningKey {
        let key = SoftwareHTTPRequestSigningKey(keyId: "vsk_0000000000000000", privateKey: privateKey)
        let user = UUID()
        let service = RequestSigningKeys(db: h.db, ctx: h.ctx)
        let challenge = service.challenge(businessId: b.id.uuid, apiKeyId: apiKey.id!, userId: user)
        let proof = try await HTTPSigningKeyProof.prove(challenge: challenge, key: key)
        let record = try await service.add(businessId: b.id.uuid, apiKeyId: apiKey.id!, label: "gateway", publicKey: key.publicKey.base64URL, challenge: challenge, proof: proof, by: user)
        return SoftwareHTTPRequestSigningKey(keyId: record.keyid, privateKey: privateKey)
    }

    func signedCreate(_ h: TestHarness, apiKey: String, body: Data, key: (any HTTPRequestSigningKey)?, authority: String = "viadere.io",
                      extra: [String: String] = [:]) async throws -> HTTPResult {
        var headers = ["Authorization": "Bearer \(apiKey)", "Idempotency-Key": UUID().uuidString]
        if let key {
            for field in try await HTTPRequestSigner(key: key).sign(method: "POST", authority: authority, target: "/v1/business/auth-deliveries", body: body,
                                                                    contentType: "application/json", now: h.clock.now()) { headers[field.name] = field.value }
        }
        for (k, v) in extra { headers[k] = v }
        return try await h.request(.POST, "/v1/business/auth-deliveries", headers: headers, body: body)
    }

    func testALiveKeyAuthenticatedByASignatureSendsADeliveryWithoutMutualTLS() async throws {
        try await harness({ $0.authDelivery.liveKeyAssurance = .mtlsOrSignature }) { h in
            let s = try await scene(h)
            let apiKey = try await BusinessAPIKeys.issue(businessId: s.b.id.uuid, name: "live", live: true, scopes: BusinessAPIKeys.Scope.all,
                                                         capabilities: Capability.operational, now: h.clock.now(), on: h.db)
            // Unsigned: a live key alone is refused (a stolen bearer key cannot send sign-in prompts).
            let unsigned = try await signedCreate(h, apiKey: apiKey.key, body: otpBody(s), key: nil)
            XCTAssertEqual(unsigned.status, .unauthorized); XCTAssertEqual(unsigned.errorCode, .signatureRequired)
            // Signed with a key nobody registered: refused.
            let stranger = try await signedCreate(h, apiKey: apiKey.key, body: otpBody(s), key: SoftwareHTTPRequestSigningKey(keyId: "vsk_9999999999999999", privateKey: P256.Signing.PrivateKey()))
            XCTAssertEqual(stranger.status, .unauthorized); XCTAssertEqual(stranger.errorCode, .signatureInvalid)
            // Registered and signed: created, no certificate anywhere.
            let key = try await register(h, s.b, apiKey: apiKey.record, key: signer())
            let ok = try await signedCreate(h, apiKey: apiKey.key, body: otpBody(s), key: key)
            XCTAssertEqual(ok.status, .created, ok.text)
            // The same signature over a body changed in flight: the digest no longer matches.
            let body = otpBody(s, id: "tampered")
            var headers = ["Authorization": "Bearer \(apiKey.key)", "Idempotency-Key": UUID().uuidString]
            for f in try await HTTPRequestSigner(key: key).sign(method: "POST", authority: "viadere.io", target: "/v1/business/auth-deliveries", body: body,
                                                                contentType: "application/json", now: h.clock.now()) { headers[f.name] = f.value }
            let tampered = try await h.request(.POST, "/v1/business/auth-deliveries", headers: headers, body: otpBody(s, id: "tampered-2"))
            XCTAssertEqual(tampered.status, .unauthorized); XCTAssertEqual(tampered.errorDetails?["reason"], "digest_mismatch")
            // The signature is bound to this API key: another live key of the same business presenting it is refused.
            let other = try await BusinessAPIKeys.issue(businessId: s.b.id.uuid, name: "other", live: true, scopes: BusinessAPIKeys.Scope.all,
                                                        capabilities: Capability.operational, now: h.clock.now(), on: h.db)
            let borrowed = try await signedCreate(h, apiKey: other.key, body: otpBody(s), key: key)
            XCTAssertEqual(borrowed.status, .unauthorized); XCTAssertEqual(borrowed.errorCode, .signatureInvalid)
            // A signature for another authority (an attacker's host relaying the request) is refused.
            let elsewhere = try await signedCreate(h, apiKey: apiKey.key, body: otpBody(s), key: key, authority: "viadere.io.evil.example")
            XCTAssertEqual(elsewhere.status, .unauthorized)
            // Revoked: refused at once.
            let record = try await BusinessRequestSigningKeyRecord.query(on: h.db).filter(\.$keyid == key.keyId).first()!
            try await RequestSigningKeys(db: h.db, ctx: h.ctx).revoke(businessId: s.b.id.uuid, id: record.id!, by: "test")
            let revoked = try await signedCreate(h, apiKey: apiKey.key, body: otpBody(s), key: key)
            XCTAssertEqual(revoked.status, .unauthorized); XCTAssertEqual(revoked.errorCode, .signatureInvalid)
            let audited = try await AuditEventRecord.query(on: h.db).filter(\.$action ~~ ["request_signing_key.added", "request_signing_key.revoked"]).count()
            XCTAssertEqual(audited, 2)
        }
    }

    func testMutualTLSStillAuthenticatesALiveKeyWithoutASignature() async throws {
        let token = SecureToken.generate()
        try await harness({ $0.authDelivery.liveKeyAssurance = .mtlsOrSignature; $0.operations.edgeTokens = [Data(token.utf8)] }) { h in
            h.edgeTokenForRequests = token
            let s = try await scene(h)
            try await EntitlementService(db: h.db, ctx: h.ctx).grant(businessId: s.b.id.uuid, tier: .e, actor: .system("test"), justification: "Test fixture: Tier E.")
            let fingerprint = String(repeating: "ab", count: 32)
            _ = try await MTLSCertificates(db: h.db, ctx: h.ctx).add(businessId: s.b.id.uuid, label: "gateway",
                identity: .init(kind: "leaf", fingerprint: fingerprint, subject: "CN=gateway", notAfter: h.clock.now().addingTimeInterval(86_400 * 365)), by: UUID())
            var options = BusinessAPIKeys.Options()
            options.requiresMTLS = true
            let apiKey = try await BusinessAPIKeys.issue(businessId: s.b.id.uuid, name: "mtls", live: true, scopes: BusinessAPIKeys.Scope.all,
                                                         capabilities: Capability.operational, now: h.clock.now(), options: options, on: h.db)
            let edge = ["X-Viadere-Client-Cert-Sha256": fingerprint, "X-Viadere-Client-Cert-Verified": "true"]
            let ok = try await signedCreate(h, apiKey: apiKey.key, body: otpBody(s), key: nil, extra: edge)
            XCTAssertEqual(ok.status, .created, ok.text)
            // Without the certificate the bound key is refused, signature or not.
            let noCert = try await signedCreate(h, apiKey: apiKey.key, body: otpBody(s), key: nil)
            XCTAssertEqual(noCert.status, .unauthorized)
        }
    }

    func testStrictMTLSModeRefusesASignatureAlone() async throws {
        try await harness({ $0.authDelivery.liveKeyAssurance = .mtls }) { h in
            let s = try await scene(h)
            let apiKey = try await BusinessAPIKeys.issue(businessId: s.b.id.uuid, name: "live", live: true, scopes: BusinessAPIKeys.Scope.all,
                                                         capabilities: Capability.operational, now: h.clock.now(), on: h.db)
            let key = try await register(h, s.b, apiKey: apiKey.record, key: signer())
            let r = try await signedCreate(h, apiKey: apiKey.key, body: otpBody(s), key: key)
            XCTAssertEqual(r.status, .unauthorized); XCTAssertEqual(r.errorCode, .signatureRequired)
        }
    }

    func testAnInvalidSignatureIsRefusedOnEveryBusinessRouteEvenWhereUnsignedWouldPass() async throws {
        try await harness { h in
            let s = try await scene(h)
            let ok = try await h.business(s.b, .GET, "/v1/business/capabilities")
            XCTAssertEqual(ok.status, .ok)
            let bad = try await h.request(.GET, "/v1/business/capabilities", headers: ["Authorization": "Bearer \(s.b.key)",
                "Signature-Input": "sig1=(\"@method\" \"@authority\" \"@path\" \"@query\");created=1;expires=2;keyid=\"vsk_0123456789abcdef\";nonce=\"AAAAAAAAAAAAAAAAAAAAAA\";tag=\"viadere-api-v1\"",
                "Signature": "sig1=:AAAA:"])
            XCTAssertEqual(bad.status, .unauthorized)
        }
    }

    func testRotationCarriesTheBindingAndThePredecessorKeepsItDuringTheOverlap() async throws {
        try await harness({ $0.authDelivery.liveKeyAssurance = .mtlsOrSignature }) { h in
            let s = try await scene(h)
            let apiKey = try await BusinessAPIKeys.issue(businessId: s.b.id.uuid, name: "live", live: true, scopes: BusinessAPIKeys.Scope.all,
                                                         capabilities: Capability.operational, now: h.clock.now(), on: h.db)
            let key = try await register(h, s.b, apiKey: apiKey.record, key: signer())
            let successor = try await APIKeyLifecycle(db: h.db, ctx: h.ctx).rotate(id: apiKey.record.id!, businessId: s.b.id.uuid, overlap: 3600, actor: .user(UUID()))
            let viaNew = try await signedCreate(h, apiKey: successor.key, body: otpBody(s), key: key)
            XCTAssertEqual(viaNew.status, .created, viaNew.text)
            let viaOld = try await signedCreate(h, apiKey: apiKey.key, body: otpBody(s), key: key)
            XCTAssertEqual(viaOld.status, .created, viaOld.text)
            h.clock.advance(by: 3601)
            let afterOverlap = try await signedCreate(h, apiKey: apiKey.key, body: otpBody(s), key: key)
            XCTAssertEqual(afterOverlap.status, .unauthorized)
        }
    }

    // MARK: Console registration

    func testTheConsoleRegistersAKeyOnlyWithAFreshProofOfPossessionAndTellsTheOwners() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            _ = try await h.newKey(owner)
            let apiKey = try await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == businessId).first()!
            let page = try await h.page("/dashboard/security/signing-keys", owner)
            XCTAssertEqual(page.status, .ok)
            let challenge = try XCTUnwrap(page.text.components(separatedBy: "<code>").dropFirst().map { $0.components(separatedBy: "</code>")[0] }
                .first { $0.split(separator: ".").count == 3 })
            let key = SoftwareHTTPRequestSigningKey(keyId: "vsk_0000000000000000", privateKey: signer())
            let proof = try await HTTPSigningKeyProof.prove(challenge: challenge, key: key)
            func post(_ publicKey: String, _ challenge: String, _ proof: String) async throws -> HTTPResult {
                try await h.formPost("/dashboard/security/signing-keys", owner, [("label", "gateway"), ("api_key", apiKey.id!.uuidString.lowercased()),
                                                                                 ("public_key", publicKey), ("challenge", challenge), ("proof", proof)])
            }
            // A proof made with another key, a private key pasted, a forged challenge: refused, nothing stored.
            let otherProof = try await HTTPSigningKeyProof.prove(challenge: challenge, key: SoftwareHTTPRequestSigningKey(keyId: "vsk_0000000000000000", privateKey: signer()))
            let wrongKey = try await post(key.publicKey.base64URL, challenge, otherProof)
            XCTAssertEqual(wrongKey.status, .unprocessableEntity)
            let privatePasted = try await post("-----BEGIN PRIVATE KEY-----", challenge, proof)
            XCTAssertEqual(privatePasted.status, .unprocessableEntity)
            let forged = try await post(key.publicKey.base64URL, challenge.replacingOccurrences(of: ".", with: "x"), proof)
            XCTAssertEqual(forged.status, .unprocessableEntity)
            // The challenge was spent by the first refused attempt, so even a correct proof over it fails now: a new page, a new challenge.
            let reused = try await post(key.publicKey.base64URL, challenge, proof)
            XCTAssertEqual(reused.status, .unprocessableEntity)
            var stored = try await BusinessRequestSigningKeyRecord.query(on: h.db).count()
            XCTAssertEqual(stored, 0)
            let fresh = try await h.page("/dashboard/security/signing-keys", owner)
            let next = try XCTUnwrap(fresh.text.components(separatedBy: "<code>").dropFirst().map { $0.components(separatedBy: "</code>")[0] }
                .first { $0.split(separator: ".").count == 3 })
            let nextProof = try await HTTPSigningKeyProof.prove(challenge: next, key: key)
            let added = try await post(key.publicKey.base64URL, next, nextProof)
            XCTAssertEqual(added.status, .seeOther, added.text)
            stored = try await BusinessRequestSigningKeyRecord.query(on: h.db).count()
            XCTAssertEqual(stored, 1)
            let audit = try await AuditEventRecord.query(on: h.db).filter(\.$action == "request_signing_key.added").count()
            XCTAssertEqual(audit, 1)
            XCTAssertTrue(h.emails.messages(to: "owner@example.com").contains { $0.subject == "A request-signing key was added" })
            // The same public key cannot be registered twice.
            let thirdPage = try await h.page("/dashboard/security/signing-keys", owner)
            let third = try XCTUnwrap(thirdPage.text.components(separatedBy: "<code>").dropFirst().map { $0.components(separatedBy: "</code>")[0] }
                .first { $0.split(separator: ".").count == 3 })
            let thirdProof = try await HTTPSigningKeyProof.prove(challenge: third, key: key)
            let duplicate = try await post(key.publicKey.base64URL, third, thirdProof)
            XCTAssertEqual(duplicate.status, .conflict)
        }
    }

    func testADeveloperCannotRegisterASigningKey() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            _ = try await h.newKey(owner)
            let developer = try await h.addMember(owner: owner, role: .developer, email: "dev@example.com").session
            let r = try await h.formPost("/dashboard/security/signing-keys", developer, [("label", "x"), ("api_key", UUID().uuidString), ("public_key", "x"), ("challenge", "x"), ("proof", "x")])
            XCTAssertEqual(r.status, .forbidden, r.text)
        }
    }

    // MARK: Configuration

    func testStrictEnvironmentsDefaultToSignatureOrMutualTLSAndParseAuthorities() throws {
        var c = ServerConfig.testing()
        try c.applyAuthDeliveryEnvironment([:], production: true)
        XCTAssertEqual(c.authDelivery.liveKeyAssurance, .mtlsOrSignature)
        try c.applyAuthDeliveryEnvironment(["AUTH_LIVE_KEY_ASSURANCE": "mtls"], production: true)
        XCTAssertEqual(c.authDelivery.liveKeyAssurance, .mtls)
        XCTAssertThrowsError(try { var x = ServerConfig.testing(); try x.applyAuthDeliveryEnvironment(["AUTH_LIVE_KEY_ASSURANCE": "none"], production: true) }())
        XCTAssertEqual(ServerConfig.testing().requestSignatureAuthorities, ["viadere.io"])
        try c.applyAuthDeliveryEnvironment(["REQUEST_SIGNATURE_AUTHORITIES": "api.viadere.io, viadere.io"], production: true)
        XCTAssertEqual(c.requestSignatureAuthorities, ["api.viadere.io", "viadere.io"])
        for bad in ["API.viadere.io", "viadere.io:443", "https://viadere.io", "a b", "x:0"] {
            XCTAssertThrowsError(try RequestSignatureSettings.parse(bad), bad)
        }
    }

    func testAConfiguredSecondAuthorityIsAccepted() async throws {
        try await harness({ $0.authDelivery.liveKeyAssurance = .mtlsOrSignature; $0.requestSignatures.authorities = ["api.viadere.io", "viadere.io"] }) { h in
            let s = try await scene(h)
            let apiKey = try await BusinessAPIKeys.issue(businessId: s.b.id.uuid, name: "live", live: true, scopes: BusinessAPIKeys.Scope.all,
                                                         capabilities: Capability.operational, now: h.clock.now(), on: h.db)
            let key = try await register(h, s.b, apiKey: apiKey.record, key: signer())
            let r = try await signedCreate(h, apiKey: apiKey.key, body: otpBody(s), key: key, authority: "api.viadere.io")
            XCTAssertEqual(r.status, .created, r.text)
        }
    }
}

private extension HTTPResult {
    var errorDetails: [String: String]? { (try? ViadereJSON.decode(APIErrorResponse.self, from: body))?.error.details }
}
