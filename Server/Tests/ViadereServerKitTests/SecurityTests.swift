@preconcurrency import Crypto
import Fluent
import FluentSQL
import Foundation
import Logging
import NIOHTTP1
import SQLKit
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

final class SecurityTests: XCTestCase {
    // MARK: Contract coverage

    func testEveryCatalogRouteIsRegisteredAndEnforcesItsAuthRequirement() async throws {
        try await withHarness { h in
            let id = UUID().uuidString.lowercased()
            for endpoint in APIRoutes.all {
                var path = endpoint.template
                for name in endpoint.parameterNames { path = path.replacingOccurrences(of: "{\(name)}", with: id) }
                let method = NIOHTTP1.HTTPMethod(rawValue: endpoint.method.rawValue)
                let body: Data? = endpoint.method == .GET || endpoint.method == .DELETE ? nil : Data("{}".utf8)
                let response = try await h.request(method, path, body: body)
                switch endpoint.auth {
                case .bearer, .deviceSigned, .deviceSignedBearer, .businessAPIKey:
                    XCTAssertEqual(response.status, .unauthorized, "\(endpoint.name) must require authentication")
                case .providerSignature:
                    XCTAssertEqual(response.status, .forbidden, "\(endpoint.name) must verify the provider signature")
                case .none:
                    XCTAssertNotEqual(response.status, .unauthorized, endpoint.name)
                    XCTAssertNotEqual(response.status, .notImplemented, endpoint.name)
                }
                XCTAssertNotEqual(response.status, .internalServerError, endpoint.name)
                XCTAssertNotEqual(response.status.code, 405, "\(endpoint.name) is not registered")
            }
        }
    }

    // MARK: Headers, content types, limits, errors

    func testSecurityHeadersOnEveryResponse() async throws {
        try await withHarness { h in
            for path in ["/healthz", "/v1/devices", "/nope", "/.well-known/apple-app-site-association"] {
                let response = try await h.request(.GET, path)
                let headers = response.headers
                XCTAssertTrue(headers.first(name: "Strict-Transport-Security")?.contains("max-age=") ?? false, path)
                XCTAssertEqual(headers.first(name: "X-Content-Type-Options"), "nosniff", path)
                XCTAssertEqual(headers.first(name: "Referrer-Policy"), "no-referrer", path)
                XCTAssertTrue(headers.first(name: "Content-Security-Policy")?.contains("frame-ancestors 'none'") ?? false, path)
                XCTAssertEqual(headers.first(name: "X-Frame-Options"), "DENY", path)
                XCTAssertNil(headers.first(name: "Server"), path)
                XCTAssertNotNil(headers.first(name: "X-Request-Id"), path)
            }
        }
    }

    func testHealthEndpointsLeakNothing() async throws {
        try await withHarness { h in
            let health = try await h.request(.GET, "/healthz")
            XCTAssertEqual(health.status, .ok)
            XCTAssertEqual(health.text, "{\"status\":\"ok\"}")
            let ready = try await h.request(.GET, "/readyz")
            XCTAssertEqual(ready.text, "{\"status\":\"ok\"}")
        }
    }

    func testJsonOnlyAndBodySizeLimits() async throws {
        try await withHarness { h in
            let body = Data(#"{"displayName":"Ana"}"#.utf8)
            let form = try await h.request(.POST, "/v1/auth/register/begin", body: body, contentType: "application/x-www-form-urlencoded")
            XCTAssertEqual(form.status, .unsupportedMediaType)
            let text = try await h.request(.POST, "/v1/auth/register/begin", body: body, contentType: "text/plain")
            XCTAssertEqual(text.status, .unsupportedMediaType)
            let missing = try await h.request(.POST, "/v1/auth/register/begin", body: body, contentType: nil)
            XCTAssertEqual(missing.status, .unsupportedMediaType)
            let ok = try await h.request(.POST, "/v1/auth/register/begin", body: body, contentType: "application/json; charset=utf-8")
            XCTAssertEqual(ok.status, .ok)
            let huge = Data(repeating: UInt8(ascii: "a"), count: h.config.maxBodyBytes + 1024)
            let big = try await h.request(.POST, "/v1/auth/register/begin", body: huge)
            XCTAssertEqual(big.status, .payloadTooLarge)
            XCTAssertEqual(big.errorCode, .badRequest)
        }
    }

    func testErrorsUseTheUniformEnvelopeAndNeverLeakInternals() async throws {
        try await withHarness { h in
            for (method, path, body) in [(NIOHTTP1.HTTPMethod.GET, "/v1/doesnotexist", nil), (.POST, "/v1/auth/register/begin", Data("{not json".utf8)),
                                          (.POST, "/v1/auth/register/begin", Data(#"{"displayName":123}"#.utf8)), (.GET, "/v1/devices", nil)] as [(NIOHTTP1.HTTPMethod, String, Data?)] {
                let response = try await h.request(method, path, body: body)
                XCTAssertGreaterThanOrEqual(response.status.code, 400)
                let envelope = try response.json(APIErrorResponse.self)
                XCTAssertFalse(envelope.error.message.isEmpty)
                XCTAssertNotNil(envelope.error.requestId)
                XCTAssertEqual(envelope.error.requestId, response.headers.first(name: "X-Request-Id"))
                for needle in ["Fluent", "SQL", "sqlite", "DecodingError", "Swift", "stack", "/home/", ".swift", "keyNotFound"] {
                    XCTAssertFalse(response.text.contains(needle), "\(path) leaked \(needle): \(response.text)")
                }
                XCTAssertEqual(response.headers.contentType?.subType, "json")
            }
        }
    }

    func testCORSIsLockedDown() async throws {
        try await withHarness { h in
            let preflight = try await h.request(.OPTIONS, "/v1/devices", headers: ["Origin": "https://evil.example", "Access-Control-Request-Method": "GET"])
            XCTAssertEqual(preflight.status, .forbidden)
            XCTAssertNil(preflight.headers.first(name: "Access-Control-Allow-Origin"))
            let simple = try await h.request(.GET, "/healthz", headers: ["Origin": "https://evil.example"])
            XCTAssertNil(simple.headers.first(name: "Access-Control-Allow-Origin"))
        }
        try await withHarness({ $0.corsAllowedOrigins = ["https://dashboard.viadere.example"] }) { h in
            let allowed = try await h.request(.GET, "/healthz", headers: ["Origin": "https://dashboard.viadere.example"])
            XCTAssertEqual(allowed.headers.first(name: "Access-Control-Allow-Origin"), "https://dashboard.viadere.example")
            XCTAssertNil(allowed.headers.first(name: "Access-Control-Allow-Credentials"))
            let other = try await h.request(.GET, "/healthz", headers: ["Origin": "https://dashboard.viadere.example.evil.io"])
            XCTAssertNil(other.headers.first(name: "Access-Control-Allow-Origin"))
        }
    }

    // MARK: Rate limiting

    func testTokenBucketRefillsOverTime() async {
        let store = InMemoryRateLimitStore()
        let rule = RateRule(capacity: 3, perMinute: 60)
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        for _ in 0..<3 { let ok = await store.take(key: "k", rule: rule, cost: 1, now: t0).allowed; XCTAssertTrue(ok) }
        let denied = await store.take(key: "k", rule: rule, cost: 1, now: t0)
        XCTAssertFalse(denied.allowed)
        XCTAssertEqual(denied.retryAfter, 1, accuracy: 0.01)
        let later = await store.take(key: "k", rule: rule, cost: 1, now: t0.addingTimeInterval(1.1))
        XCTAssertTrue(later.allowed)
        let other = await store.take(key: "other", rule: rule, cost: 1, now: t0)
        XCTAssertTrue(other.allowed, "buckets are independent per key")
        let capped = await store.take(key: "k", rule: rule, cost: 3, now: t0.addingTimeInterval(1000))
        XCTAssertTrue(capped.allowed, "refill never exceeds capacity")
        let again = await store.take(key: "k", rule: rule, cost: 1, now: t0.addingTimeInterval(1000))
        XCTAssertFalse(again.allowed)
    }

    func testAuthCeremonyEndpointsAreRateLimitedPerIP() async throws {
        try await withHarness({ $0.rateLimits.authCeremony = RateRule(capacity: 3, perMinute: 6) }) { h in
            var statuses: [UInt] = []
            for _ in 0..<5 {
                statuses.append(try await h.post("/v1/auth/register/begin", PasskeyRegistrationBeginRequest(displayName: "Ana")).status.code)
            }
            XCTAssertEqual(statuses, [200, 200, 200, 429, 429])
            let limited = try await h.post("/v1/auth/register/begin", PasskeyRegistrationBeginRequest(displayName: "Ana"))
            XCTAssertEqual(limited.errorCode, .rateLimited)
            XCTAssertNotNil(limited.headers.first(name: "Retry-After"))
            // Recovers as the bucket refills.
            h.clock.advance(by: 20)
            let recovered = try await h.post("/v1/auth/register/begin", PasskeyRegistrationBeginRequest(displayName: "Ana"))
            XCTAssertEqual(recovered.status, .ok)
        }
    }

    func testDirectoryAndRefreshAndBusinessRateLimits() async throws {
        try await withHarness({
            $0.rateLimits.directory = RateRule(capacity: 2, perMinute: 1)
            $0.rateLimits.business = RateRule(capacity: 3, perMinute: 1)
            $0.rateLimits.refresh = RateRule(capacity: 2, perMinute: 1)
        }) { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            var directory: [UInt] = []
            for _ in 0..<4 { directory.append(try await h.request(.GET, "/v1/directory/search?q=north").status.code) }
            XCTAssertEqual(directory, [200, 200, 429, 429])
            var business: [UInt] = []
            for _ in 0..<5 { business.append(try await h.business(b, .GET, "/v1/business/webhooks").status.code) }
            XCTAssertEqual(business, [200, 200, 200, 429, 429])
            var refresh: [UInt] = []
            for _ in 0..<3 { refresh.append(try await h.post("/v1/auth/refresh", AuthRefreshRequest(refreshToken: "vdr_bogus")).status.code) }
            XCTAssertEqual(refresh, [401, 401, 429])
        }
    }

    func testDeviceRateLimitAppliesAfterAuthentication() async throws {
        try await withHarness({ $0.rateLimits.device = RateRule(capacity: 3, perMinute: 1) }) { h in
            let consumer = try await h.readyConsumer()
            var statuses: [UInt] = []
            for _ in 0..<5 { statuses.append(try await h.signed(consumer, .GET, "/v1/devices").status.code) }
            XCTAssertEqual(statuses, [200, 200, 200, 429, 429])
        }
    }

    func testForwardedForIsIgnoredUnlessProxiesAreTrusted() async throws {
        let app = try await Application.make(.testing)
        let request = Request(application: app, method: .GET, url: URI(path: "/"), headers: ["X-Forwarded-For": "203.0.113.9, 198.51.100.7"], on: app.eventLoopGroup.next())
        XCTAssertEqual(ClientIP.resolve(request, trustedProxies: 0), "unknown")
        XCTAssertEqual(ClientIP.resolve(request, trustedProxies: 1), "198.51.100.7")
        XCTAssertEqual(ClientIP.resolve(request, trustedProxies: 2), "203.0.113.9")
        XCTAssertEqual(ClientIP.resolve(request, trustedProxies: 5), "unknown")
        try await app.asyncShutdown()
    }

    // MARK: Audit log

    func testAuditLogIsHashChainedAppendOnlyAndTamperEvident() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            _ = try await h.connect(consumer, to: b)
            let verification = try await AuditService.verifyChain(on: h.db, key: h.ctx.config.auditChainKey)
            XCTAssertTrue(verification.valid)
            XCTAssertGreaterThanOrEqual(verification.checked, 3)
            let events = try await AuditEventRecord.query(on: h.db).sort(\.$seq).all()
            XCTAssertEqual(events.map(\.seq), Array(1...events.count))
            XCTAssertEqual(events[0].prevHash, AuditService.genesisHash)
            XCTAssertEqual(events[1].prevHash, events[0].hash)

            let sql = h.db as! any SQLDatabase
            // The database itself refuses in-place edits and deletions.
            do {
                try await sql.raw("UPDATE audit_events SET action = 'tampered' WHERE seq = 1").run()
                XCTFail("UPDATE must be rejected")
            } catch {}
            do {
                try await sql.raw("DELETE FROM audit_events WHERE seq = 2").run()
                XCTFail("DELETE must be rejected")
            } catch {}
            // Even if an attacker with schema privileges removes the triggers, the chain exposes the edit.
            try await dropAuditTriggers(sql)
            try await sql.raw("UPDATE audit_events SET outcome = 'denied' WHERE seq = 2").run()
            let broken = try await AuditService.verifyChain(on: h.db, key: h.ctx.config.auditChainKey)
            XCTAssertFalse(broken.valid)
            XCTAssertEqual(broken.firstBrokenSeq, 2)
        }
    }

    /// Simulates an attacker with schema privileges removing the append-only triggers (dialect-aware).
    func dropAuditTriggers(_ sql: any SQLDatabase) async throws {
        if sql.dialect.name == "postgresql" {
            try await sql.raw("DROP TRIGGER audit_events_no_update ON audit_events").run()
        } else {
            try await sql.raw("DROP TRIGGER audit_events_no_update").run()
            try await sql.raw("DROP TRIGGER audit_events_no_delete").run()
        }
    }

    func testAuditChainDetectsDeletedEvents() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            _ = try await h.connect(consumer, to: b)
            let sql = h.db as! any SQLDatabase
            try await dropAuditTriggers(sql)
            try await sql.raw("DELETE FROM audit_events WHERE seq = 2").run()
            let result = try await AuditService.verifyChain(on: h.db, key: h.ctx.config.auditChainKey)
            XCTAssertFalse(result.valid)
        }
    }

    func testAuditAppendIsSafeUnderConcurrency() async throws {
        try await withHarness { h in
            let ctx = h.ctx
            let db = h.db
            try await withThrowingTaskGroup(of: Void.self) { group in
                for i in 0..<10 {
                    group.addTask { _ = try await AuditService(db: db, ctx: ctx).record("test.event", actor: AuditActor(kind: .system), metadata: ["n": String(i)]) }
                }
                try await group.waitForAll()
            }
            let result = try await AuditService.verifyChain(on: h.db, key: h.ctx.config.auditChainKey)
            XCTAssertTrue(result.valid)
            XCTAssertEqual(result.checked, 10)
        }
    }

    func testAuditMetadataIsRedacted() {
        let redacted = AuditRedactor.redact([
            "token": "vda_abcdefghijklmnopqrstuvwxyz0123456789", "otp": "123456", "messageBody": "my secret", "signature": "abc", "phone": "+14805550123",
            "note": "call +14805550123 now", "deviceId": "3f2a", "reason": "bad_signature", "authHeader": "Bearer abcdefghijklmnop",
        ])
        XCTAssertEqual(redacted["token"], "[redacted]")
        XCTAssertEqual(redacted["otp"], "[redacted]")
        XCTAssertEqual(redacted["messageBody"], "[redacted]")
        XCTAssertEqual(redacted["signature"], "[redacted]")
        XCTAssertFalse((redacted["phone"] ?? "").contains("4805550123"))
        XCTAssertFalse((redacted["note"] ?? "").contains("4805550123"))
        XCTAssertEqual(redacted["reason"], "bad_signature")
        XCTAssertFalse((redacted["authHeader"] ?? "").contains("abcdefghijklmnop"))
    }

    // MARK: Logging

    func testLogRedactionRemovesSecretsAndPersonalData() {
        let samples = [
            "Authorization: Bearer abc123def456ghi789", "key vdk_live_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "token vda_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abc",
            "secret whsec_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "Viadere-Signature: t=1,v1=" + String(repeating: "a", count: 64),
            "otp=123456 for +14805550123", "GET /l/\(SecureToken.generate())", "signature=deadbeefdeadbeef",
        ]
        for sample in samples {
            let cleaned = LogRedactor.redact(sample)
            for secret in ["abc123def456ghi789", "AbCdEfGhIjKlMnOpQrStUvWxYz", "aaaaaaaaaaaaaaaa", "123456", "4805550123", "deadbeef"] {
                XCTAssertFalse(cleaned.contains(secret), "\(sample) -> \(cleaned)")
            }
        }
        XCTAssertEqual(LogRedactor.redact("plain message"), "plain message")
    }

    func testStructuredLogHandlerEmitsRedactedJSON() throws {
        let captured = NIOLockedBox<[String]>([])
        let handler = StructuredLogHandler(label: "test", level: .trace) { line in captured.mutate { $0.append(line) } }
        var logger = Logger(label: "test") { _ in handler }
        logger.logLevel = .trace
        logger.info("login with Bearer supersecrettoken1234", metadata: ["phone": "+14805550123", "requestId": "r-1"])
        let line = try XCTUnwrap(captured.values.first)
        XCTAssertFalse(line.contains("supersecrettoken1234"))
        XCTAssertFalse(line.contains("4805550123"))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
        XCTAssertEqual(object["level"] as? String, "info")
        XCTAssertEqual((object["meta"] as? [String: String])?["requestId"], "r-1")
    }

    func testRequestLogPathsNeverContainTokens() {
        XCTAssertEqual(RequestLoggingMiddleware.safePath("/l/abcdefghijklmnopqrstuvwxyz"), "/l/:token")
        XCTAssertEqual(RequestLoggingMiddleware.safePath("/h/abcdefghijklmnopqrstuvwxyz"), "/h/:token")
        XCTAssertEqual(RequestLoggingMiddleware.safePath("/v1/directory/codes/AF2345"), "/v1/directory/codes/:id")
        XCTAssertEqual(RequestLoggingMiddleware.safePath("/v1/interactions"), "/v1/interactions")
    }

    // MARK: Crypto helpers

    func testFieldCipherRoundTripsBindsContextAndRowAndRejectsTampering() throws {
        let cipher = FieldCipher(key: SymmetricKey(data: Data(repeating: 9, count: 32)))
        let row = UUID()
        let sealed = try cipher.seal("+14805550123", context: "phone", rowId: row)
        XCTAssertTrue(sealed.hasPrefix("v2."))
        XCTAssertFalse(sealed.contains("4805550123"))
        XCTAssertEqual(try cipher.openString(sealed, context: "phone", rowId: row), "+14805550123")
        XCTAssertThrowsError(try cipher.open(sealed, context: "other-column", rowId: row))
        // A2-style swap: the same ciphertext moved to another row of the same column no longer opens.
        XCTAssertThrowsError(try cipher.open(sealed, context: "phone", rowId: UUID()))
        XCTAssertThrowsError(try cipher.open(sealed + "A", context: "phone", rowId: row))
        XCTAssertThrowsError(try cipher.open("garbage", context: "phone", rowId: row))
        let otherKey = FieldCipher(key: SymmetricKey(data: Data(repeating: 8, count: 32)))
        XCTAssertThrowsError(try otherKey.open(sealed, context: "phone", rowId: row))
        XCTAssertNotEqual(try cipher.seal("x", context: "c", rowId: row), try cipher.seal("x", context: "c", rowId: row), "fresh nonce per encryption")
        // Rows written before row binding (v1) still open, with the column context, for any row id.
        let legacy = try cipher.sealLegacy("+14805550123", context: "phone")
        XCTAssertTrue(FieldCipher.isLegacy(legacy))
        XCTAssertEqual(try cipher.openString(legacy, context: "phone", rowId: row), "+14805550123")
        XCTAssertThrowsError(try cipher.open(legacy, context: "other-column", rowId: row))
    }

    // MARK: Configuration

    func testProductionConfigurationFailsClosedWithoutSecrets() {
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(["ENVIRONMENT": "production"]))
        var env = [
            "ENVIRONMENT": "production", "AUDIT_HEAD_EXPORT": "gcs", "AUDIT_HEAD_EXPORT_TARGET": "viadere-audit-heads", "AUDIT_HEAD_KMS_KEY": "projects/p/locations/l/keyRings/r/cryptoKeys/audit-head/cryptoKeyVersions/1", "GCP_WORKLOAD_IDENTITY_AUDIENCE": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/fly", "GCP_SERVICE_ACCOUNT_EMAIL": "audit@p.iam.gserviceaccount.com", "GCP_SUBJECT_TOKEN_FILE": "/tmp/subject-token",
            "DATABASE_URL": "postgres://u:p@db/viadere", "CONNECT_LINK_SIGNING_KEY": SecureToken.generate(), "SERVER_PEPPER": SecureToken.generate(),
            "DATA_ENCRYPTION_KEY": SecureToken.generate(), "APNS_KEY_P8": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "APNS_KEY_ID": "ABC123DEFG",
            "AUDIT_CHAIN_KEY": SecureToken.generate(), "SUBJECT_REF_KEY": SecureToken.generate(), "KEY_DIRECTORY_LOG_KEY": SecureToken.generate(), "EDGE_TOKEN": SecureToken.generate(), "APNS_TEAM_ID": "TEAM123456", "TWILIO_ACCOUNT_SID": "AC1", "TWILIO_AUTH_TOKEN": "tok", "TWILIO_FROM_NUMBER": "+15550001111", "APPLE_TEAM_ID": "TEAM123456",
            "EMAIL_API_URL": "https://mail.example.com/v1/send", "EMAIL_API_KEY": "key_123", "EMAIL_FROM_ADDRESS": "no-reply@viadere.com",
        ]
        XCTAssertNoThrow(try ServerConfig.fromEnvironment(env))
        for key in ["DATABASE_URL", "CONNECT_LINK_SIGNING_KEY", "SERVER_PEPPER", "DATA_ENCRYPTION_KEY", "AUDIT_CHAIN_KEY", "SUBJECT_REF_KEY", "TWILIO_AUTH_TOKEN", "APNS_KEY_P8", "APPLE_TEAM_ID"] {
            var broken = env
            broken[key] = nil
            XCTAssertThrowsError(try ServerConfig.fromEnvironment(broken), "\(key) must be required in production")
        }
        env["DATA_ENCRYPTION_KEY"] = "short"
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(env))
        env["DATA_ENCRYPTION_KEY"] = SecureToken.generate()
        env["PUBLIC_BASE_URL"] = "http://viadere.com"
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(env), "production must use https")
        // Development works with nothing but defaults and never has production-only toggles on.
        let dev = try? ServerConfig.fromEnvironment(["ENVIRONMENT": "development"])
        XCTAssertNotNil(dev)
        XCTAssertFalse(dev?.isProduction ?? true)
        XCTAssertNil(dev?.databaseURL)
    }

    func testProductionRefusesToStartWithoutADatabase() async throws {
        var config = ServerConfig.testing()
        config.environment = .production
        do {
            let app = try await makeApplication(environment: .testing, config: config)
            try? await app.asyncShutdown()
            XCTFail("production without DATABASE_URL must not start")
        } catch {}
    }

    // MARK: Web pages

    func testConnectLandingPageSmartBannerEscapingAndCSP() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Juniper <script>alert(1)</script> & Co", handle: "junipercoffee")
            let page = try await h.request(.GET, "/c/\(b.summary.code.display)")
            XCTAssertEqual(page.status, .ok)
            XCTAssertTrue(page.text.contains("apple-itunes-app"))
            XCTAssertTrue(page.text.contains("app-id=1234567890"))
            XCTAssertTrue(page.text.contains("app-clip-bundle-id=com.viadere.app.Clip"))
            XCTAssertTrue(page.text.contains("https://viadere.com/c/\(b.summary.code.canonical)"))
            XCTAssertFalse(page.text.contains("<script>alert"), "business names are HTML-escaped")
            XCTAssertTrue(page.text.contains("&lt;script&gt;"))
            let csp = page.headers.first(name: "Content-Security-Policy")!
            XCTAssertTrue(csp.contains("default-src 'none'") && csp.contains("style-src 'sha256-") && csp.contains("frame-ancestors 'none'"))
            XCTAssertEqual(page.headers.contentType?.type, "text")
            try await eq(try await h.request(.GET, "/c/ZZZZZZ").status, .notFound)
            try await eq(try await h.request(.GET, "/c/%3Cscript%3E").status, .notFound)
            let notFound = try await h.request(.GET, "/c/ZZZZZZ")
            XCTAssertFalse(notFound.text.contains("ZZZZZZ"), "input is not reflected")
        }
    }

    func testAppleAppSiteAssociation() async throws {
        try await withHarness { h in
            let response = try await h.request(.GET, "/.well-known/apple-app-site-association")
            XCTAssertEqual(response.status, .ok)
            XCTAssertEqual(response.headers.contentType?.subType, "json")
            let json = try XCTUnwrap(JSONSerialization.jsonObject(with: response.body) as? [String: Any])
            let applinks = try XCTUnwrap((json["applinks"] as? [String: Any])?["details"] as? [[String: Any]])
            XCTAssertEqual(applinks[0]["appIDs"] as? [String], ["TEAMID1234.com.viadere.app"])
            let components = try XCTUnwrap(applinks[0]["components"] as? [[String: String]])
            XCTAssertEqual(Set(components.compactMap { $0["/"] }), ["/c/*", "/l/*", "/h/*"])
            XCTAssertEqual((json["webcredentials"] as? [String: Any])?["apps"] as? [String], ["TEAMID1234.com.viadere.app"])
            XCTAssertEqual((json["appclips"] as? [String: Any])?["apps"] as? [String], ["TEAMID1234.com.viadere.app.Clip"])
        }
    }

    // MARK: Concurrency primitive

    func testCompareAndSwapAllowsExactlyOneWinner() async throws {
        try await withHarness { h in
            let row = SMSContextRecord()
            row.id = UUID()
            row.phoneHash = "p"
            row.contextCiphertext = "c"
            row.revision = 1
            row.optedOut = false
            row.updatedAt = h.clock.now()
            try await row.create(on: h.db)
            let id = row.id!
            let db = h.db
            let wins = try await withThrowingTaskGroup(of: Bool.self) { group -> Int in
                for _ in 0..<8 { group.addTask { try await DB.swap(db, table: "sms_contexts", id: id, column: "revision", expected: 1, newValue: 2) } }
                var count = 0
                for try await won in group where won { count += 1 }
                return count
            }
            XCTAssertEqual(wins, 1)
            let revision = try await SMSContextRecord.find(id, on: h.db)?.revision
            XCTAssertEqual(revision, 2)
        }
    }

    // MARK: Seed

    func testSeedCreatesFictionalVerifiedBusinessesOnceAndRefusesInProduction() async throws {
        try await withHarness { h in
            let seeded = try await Seeder(db: h.db, ctx: h.ctx).seed()
            XCTAssertEqual(seeded.map(\.name), ["Northwind Air", "Juniper Coffee"])
            XCTAssertTrue(seeded.allSatisfy { $0.testKey.hasPrefix("vdk_test_") })
            let businesses = try await BusinessRecord.query(on: h.db).all()
            XCTAssertTrue(businesses.allSatisfy { $0.isVerified && ($0.legalName ?? "").contains("fictional") })
            let again = try await Seeder(db: h.db, ctx: h.ctx).seed()
            XCTAssertTrue(again.isEmpty, "idempotent")
            // Seeded businesses are discoverable and their test keys work.
            try await eq(try await h.request(.GET, "/v1/directory/handles/northwindair").status, .ok)
            try await eq(try await h.request(.GET, "/v1/business/webhooks", headers: ["Authorization": "Bearer \(seeded[0].testKey)"]).status, .ok)
        }
        var production = ServerConfig.testing()
        production.environment = .production
        production.databaseURL = nil
        let harness = try await TestHarness.make()
        // Simulate a production-configured context for the command's guard.
        let console = Terminal()
        let input = CommandInput(arguments: ["viadere"])
        var context = CommandContext(console: console, input: input)
        context.userInfo["application"] = harness.app
        harness.app.ctx = ServerContext(config: production, clock: harness.clock, apns: harness.push, sms: harness.texts, passkeys: FakePasskeyVerifier(), webhookTransport: harness.webhooks)
        do {
            try await SeedCommand().run(using: context, signature: SeedCommand.Signature())
            XCTFail("seed must refuse in production")
        } catch {}
        let count = try await BusinessRecord.query(on: harness.db).count()
        XCTAssertEqual(count, 0)
        try await harness.shutdown()
    }
}

final class NIOLockedBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: T
    init(_ value: T) { storage = value }
    var values: T { lock.withLock { storage } }
    func mutate(_ body: (inout T) -> Void) { lock.withLock { body(&storage) } }
}
