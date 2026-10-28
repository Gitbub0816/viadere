@preconcurrency import Crypto
import Fluent
import FluentSQL
import Foundation
import Logging
import NIOCore
import NIOHTTP1
import SQLKit
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Platform round 4: shared rate-limit store, dashboard email verification, household budget, delegate notifications.
final class PlatformRound4Tests: XCTestCase {
    // MARK: - 1. Shared rate-limit store

    private func bucketCount(_ h: TestHarness, keyPrefix: String? = nil) async throws -> Int {
        let sql = try XCTUnwrap(h.db as? any SQLDatabase)
        let row: (any SQLRow)?
        if let keyPrefix {
            row = try await sql.raw("SELECT COUNT(*) AS c FROM rate_limit_buckets WHERE key LIKE \(bind: keyPrefix + "%")").first()
        } else {
            row = try await sql.raw("SELECT COUNT(*) AS c FROM rate_limit_buckets").first()
        }
        return try XCTUnwrap(row).decode(column: "c", as: Int.self)
    }

    /// Two application instances (own limiter, own local state) over one database share one budget: the limit is global, not per instance.
    func testTheLimitIsGlobalAcrossTwoInstancesSharingOneDatabase() async throws {
        try await withHarness({
            $0.rateLimits.globalIP = RateRule(capacity: 5, perMinute: 1)
            $0.rateLimitStore = .database
        }) { a in
            // Instance B: a second application. On PostgreSQL it connects to the same database as A; on SQLite (in-memory, one database per
            // app) it is pointed at A's database for the limiter only.
            let shared: (any RateLimitStore)? = a.config.databaseURL == nil ? DatabaseRateLimitStore.forApplication(a.app) : nil
            let b = try await makeApplication(environment: .testing, config: a.config,
                                              overrides: Overrides(clock: a.clock, passkeys: FakePasskeyVerifier(), rateLimitStore: shared))
            do {
                func hit(_ app: Application) async throws -> UInt {
                    let box = Box<UInt>()
                    try await app.test(.GET, "/healthz") { response async throws in box.value = response.status.code }
                    return try XCTUnwrap(box.value)
                }
                var codes: [UInt] = []
                for _ in 0..<3 { codes.append(try await hit(a.app)) }
                for _ in 0..<2 { codes.append(try await hit(b)) }
                XCTAssertEqual(codes, [200, 200, 200, 200, 200], "five requests in total are within the budget")
                // The budget is spent: both instances now refuse, although each served fewer than five requests itself.
                try await eq(try await hit(b), 429)
                try await eq(try await hit(a.app), 429)
                // And it refills for both together.
                a.clock.advance(by: 90)
                try await eq(try await hit(b), 200)
            } catch {
                try? await b.asyncShutdown()
                throw error
            }
            try await b.asyncShutdown()
        }
    }

    func testDatabaseBucketRefillsPerKeyAndNamespaceAndNeverExceedsCapacity() async throws {
        try await withHarness { h in
            let store = DatabaseRateLimitStore.forApplication(h.app)
            let rule = RateRule(capacity: 3, perMinute: 60)
            let t0 = Date(timeIntervalSince1970: 1_800_000_000)
            for _ in 0..<3 { let r = await store.take(key: "otp|a", rule: rule, cost: 1, now: t0); XCTAssertTrue(r.allowed) }
            let denied = await store.take(key: "otp|a", rule: rule, cost: 1, now: t0)
            XCTAssertFalse(denied.allowed)
            XCTAssertEqual(denied.retryAfter, 1, accuracy: 0.05)
            // Keys and namespaces are independent.
            let otherKey = await store.take(key: "otp|b", rule: rule, cost: 1, now: t0)
            XCTAssertTrue(otherKey.allowed)
            let otherNamespace = await store.take(key: "link-redeem|a", rule: rule, cost: 1, now: t0)
            XCTAssertTrue(otherNamespace.allowed)
            // Refill, capped at the capacity.
            let later = await store.take(key: "otp|a", rule: rule, cost: 1, now: t0.addingTimeInterval(1.1))
            XCTAssertTrue(later.allowed)
            let big = await store.take(key: "otp|a", rule: rule, cost: 3, now: t0.addingTimeInterval(1000))
            XCTAssertTrue(big.allowed)
            let again = await store.take(key: "otp|a", rule: rule, cost: 1, now: t0.addingTimeInterval(1000))
            XCTAssertFalse(again.allowed, "refill never exceeds capacity")
            // A refund (negative cost) gives tokens back, also never beyond capacity.
            let refunded = await store.take(key: "otp|a", rule: rule, cost: -1, now: t0.addingTimeInterval(1000))
            XCTAssertTrue(refunded.allowed)
            let spent = await store.take(key: "otp|a", rule: rule, cost: 1, now: t0.addingTimeInterval(1000))
            XCTAssertTrue(spent.allowed)
            let overRefund = await store.take(key: "otp|fresh", rule: rule, cost: -10, now: t0)
            XCTAssertTrue(overRefund.allowed)
            for _ in 0..<3 { let r = await store.take(key: "otp|fresh", rule: rule, cost: 1, now: t0); XCTAssertTrue(r.allowed) }
            let capped = await store.take(key: "otp|fresh", rule: rule, cost: 1, now: t0)
            XCTAssertFalse(capped.allowed)
        }
    }

    /// IPv6 clients are keyed by their /64, so a host cannot mint 2^64 buckets; the store keys on whatever the caller passes.
    func testIPv6AddressesInOneSlash64ShareOneBucket() async throws {
        try await withHarness { h in
            let store = DatabaseRateLimitStore.forApplication(h.app)
            let limiter = RateLimiter(store: store, clock: h.clock)
            let rule = RateRule(capacity: 2, perMinute: 1)
            let keys = ["2001:db8:1:2::1", "2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::ffff"].map { ClientIP.normalize($0) }
            XCTAssertEqual(Set(keys).count, 1)
            let results = await [limiter.allow("ip", key: keys[0], rule: rule), limiter.allow("ip", key: keys[1], rule: rule), limiter.allow("ip", key: keys[2], rule: rule)]
            XCTAssertEqual(results, [true, true, false])
            let elsewhere = await limiter.allow("ip", key: ClientIP.normalize("2001:db8:1:3::1"), rule: rule)
            XCTAssertTrue(elsewhere)
        }
    }

    /// The check is one atomic statement: concurrent requests (instances) can never take more tokens than the bucket holds.
    func testConcurrentChecksNeverExceedTheBudget() async throws {
        try await withHarness { h in
            let sql = try XCTUnwrap(h.db as? any SQLDatabase)
            let now = h.clock.now()
            let rule = RateRule(capacity: 10, perMinute: 0.0001)
            var allowed = 0
            for batch in 0..<4 {
                let decisions = try await withThrowingTaskGroup(of: Bool.self) { group in
                    for _ in 0..<10 {
                        group.addTask {
                            try await DatabaseRateLimitStore.take(on: sql, key: "phonelink-verify|burst", namespace: "phonelink-verify", rule: rule, cost: 1, now: now).allowed
                        }
                    }
                    return try await group.reduce(into: [Bool]()) { $0.append($1) }
                }
                allowed += decisions.filter { $0 }.count
                _ = batch
            }
            XCTAssertEqual(allowed, 10)
        }
    }

    /// Database down: security-critical namespaces fail closed; the IP namespace (and the rest) degrade to a local in-memory limiter.
    func testWhenTheDatabaseIsUnavailableCriticalNamespacesFailClosedAndTheIPNamespaceDegradesToLocal() async throws {
        let rule = RateRule(capacity: 2, perMinute: 1)
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let down = DatabaseRateLimitStore(database: { nil })
        for ns in ["phonelink-verify", "link-redeem", "household-invite-global", "household-invite-attempt", "enroll", "dashboard-verify-email", "dashboard-signup-email"] {
            let r = await down.take(key: "\(ns)|x", rule: rule, cost: 1, now: now)
            XCTAssertFalse(r.allowed, "\(ns) must fail closed")
            XCTAssertGreaterThan(r.retryAfter, 0)
        }
        var ip: [Bool] = []
        for _ in 0..<3 { ip.append(await down.take(key: "ip|203.0.113.9", rule: rule, cost: 1, now: now).allowed) }
        XCTAssertEqual(ip, [true, true, false], "the IP limiter keeps working locally with the same rule")
        // An erroring database (the table is missing) behaves the same, and the breaker spares the next requests the failing call.
        try await withHarness { h in
            try await h.db.schema("rate_limit_buckets").delete()
            let store = DatabaseRateLimitStore.forApplication(h.app)
            let closed = await store.take(key: "otp|a", rule: rule, cost: 1, now: now)
            XCTAssertFalse(closed.allowed)
            var local: [Bool] = []
            for _ in 0..<3 { local.append(await store.take(key: "ip|198.51.100.1", rule: rule, cost: 1, now: now).allowed) }
            XCTAssertEqual(local, [true, true, false])
        }
    }

    func testExpiredBucketsArePurgedByTheJobLoopAndLiveOnesAreKept() async throws {
        try await withHarness({ $0.rateLimitStore = .database }) { h in
            let limiter = h.app.ctx.limiter
            try await limiter.enforce("stale-test", key: "old", rule: RateRule(capacity: 5, perMinute: 60))
            try await limiter.enforce("stale-test", key: "slow", rule: RateRule(capacity: 5, perMinute: 0.001))
            try await eq(try await bucketCount(h, keyPrefix: "stale-test|"), 2)
            h.clock.advance(by: 7_200)
            try await h.runJobs()
            // The fast bucket has been full again for ages and is gone; the one that refills for days is still tracked.
            try await eq(try await bucketCount(h, keyPrefix: "stale-test|old"), 0)
            try await eq(try await bucketCount(h, keyPrefix: "stale-test|slow"), 1)
        }
    }

    func testConfigurationDefaultsAndValidation() throws {
        let base: [String: String] = [
            "ENVIRONMENT": "production", "DATABASE_URL": "postgres://u:p@db/viadere", "CONNECT_LINK_SIGNING_KEY": SecureToken.generate(), "SERVER_PEPPER": SecureToken.generate(),
            "DATA_ENCRYPTION_KEY": SecureToken.generate(), "APNS_KEY_P8": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "APNS_KEY_ID": "ABC123DEFG",
            "AUDIT_CHAIN_KEY": SecureToken.generate(), "SUBJECT_REF_KEY": SecureToken.generate(), "KEY_DIRECTORY_LOG_KEY": SecureToken.generate(), "EDGE_TOKEN": SecureToken.generate(), "APNS_TEAM_ID": "TEAM123456", "TWILIO_ACCOUNT_SID": "AC1", "TWILIO_AUTH_TOKEN": "tok", "TWILIO_FROM_NUMBER": "+15550001111",
            "APPLE_TEAM_ID": "TEAM123456",
        ]
        let email = ["EMAIL_API_URL": "https://mail.example.com/v1/send", "EMAIL_API_KEY": "key_123", "EMAIL_FROM_ADDRESS": "Viadere <no-reply@viadere.com>"]
        let production = base.merging(email) { $1 }
        let config = try ServerConfig.fromEnvironment(production)
        XCTAssertEqual(config.rateLimitStore, .database, "production defaults to the shared store")
        XCTAssertEqual(config.email?.apiURL.absoluteString, "https://mail.example.com/v1/send")
        XCTAssertEqual(config.email?.authHeader, "Authorization")
        XCTAssertEqual(try ServerConfig.fromEnvironment(production.merging(["RATE_LIMIT_STORE": "memory"]) { $1 }).rateLimitStore, .memory)
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(production.merging(["RATE_LIMIT_STORE": "redis"]) { $1 }))
        // Production needs the email provider; partial or insecure settings are refused.
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(base), "production needs email")
        for key in email.keys {
            var broken = production
            broken[key] = nil
            XCTAssertThrowsError(try ServerConfig.fromEnvironment(broken), "\(key) is required")
        }
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(production.merging(["EMAIL_API_URL": "http://mail.example.com/send"]) { $1 }), "https only")
        let custom = try ServerConfig.fromEnvironment(production.merging(["EMAIL_API_AUTH_HEADER": "X-Api-Key", "EMAIL_API_AUTH_SCHEME": ""]) { $1 })
        XCTAssertEqual(custom.email?.authHeader, "X-Api-Key")
        XCTAssertEqual(custom.email?.authScheme, "")
        // Development: memory store, no email required.
        let development = try ServerConfig.fromEnvironment(["ENVIRONMENT": "development"])
        XCTAssertEqual(development.rateLimitStore, .memory)
        XCTAssertNil(development.email)
    }

    // MARK: - 2. Email senders

    final class CapturingLogHandler: LogHandler, @unchecked Sendable {
        let lines = LockedBox<[String]>([])
        var logLevel: Logger.Level = .trace
        var metadata: Logger.Metadata = [:]
        subscript(metadataKey key: String) -> Logger.Metadata.Value? {
            get { metadata[key] }
            set { metadata[key] = newValue }
        }
        func log(event: LogEvent) {
            let text = "\(event.message) \(event.metadata ?? [:])"
            lines.withLockedValue { $0.append(text) }
        }
    }

    func testTheLoggingSenderNeverLogsACodeInProductionAndDoesInDevelopment() async throws {
        let message = EmailVerificationService.codeMessage(to: "owner@example.com", code: "482913", kind: "signup-code")
        for environment in [DeploymentEnvironment.production, .staging] {
            let handler = CapturingLogHandler()
            try await LoggingEmailSender(environment: environment, logger: Logger(label: "t", factory: { _ in handler })).send(message)
            let logged = handler.lines.withLockedValue { $0 }.joined()
            XCTAssertFalse(logged.contains("482913"), "\(environment) must not log the code")
            XCTAssertFalse(logged.contains("owner@example.com"), "nor the full address")
            XCTAssertTrue(logged.contains("example.com"))
        }
        let dev = CapturingLogHandler()
        try await LoggingEmailSender(environment: .development, logger: Logger(label: "t", factory: { _ in dev })).send(message)
        XCTAssertTrue(dev.lines.withLockedValue { $0 }.joined().contains("482913"), "a developer can read the code locally")
    }

    /// A client that records the outbound request instead of using the network.
    final class RecordingClient: Client, @unchecked Sendable {
        let eventLoop: any EventLoop
        let status: HTTPStatus
        let requests = LockedBox<[ClientRequest]>([])
        init(eventLoop: any EventLoop, status: HTTPStatus = .accepted) {
            self.eventLoop = eventLoop
            self.status = status
        }
        func delegating(to eventLoop: any EventLoop) -> any Client { self }
        func send(_ request: ClientRequest) -> EventLoopFuture<ClientResponse> {
            requests.withLockedValue { $0.append(request) }
            return eventLoop.makeSucceededFuture(ClientResponse(status: status, headers: [:], body: nil))
        }
    }

    func testTheHTTPSenderPostsTheDocumentedBodyWithTheKeyInTheConfiguredHeader() async throws {
        try await withHarness { h in
            let loop = h.app.eventLoopGroup.next()
            let client = RecordingClient(eventLoop: loop)
            let config = EmailConfig(apiURL: URL(string: "https://mail.example.com/v1/send")!, apiKey: "key_123", fromAddress: "Viadere <no-reply@viadere.com>")
            try await HTTPEmailSender(config: config, client: client).send(EmailMessage(to: "a@b.co", subject: "Hi", text: "Body", kind: "x"))
            let request = try XCTUnwrap(client.requests.withLockedValue { $0.first })
            XCTAssertEqual(request.method, .POST)
            XCTAssertEqual(request.url.string, "https://mail.example.com/v1/send")
            XCTAssertEqual(request.headers.first(name: "Authorization"), "Bearer key_123")
            var body = try XCTUnwrap(request.body)
            let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(body.readBytes(length: body.readableBytes) ?? [])) as? [String: String])
            XCTAssertEqual(json, ["from": "Viadere <no-reply@viadere.com>", "to": "a@b.co", "subject": "Hi", "text": "Body"])
            // A bare key in a custom header.
            var custom = config
            custom.authHeader = "X-Api-Key"
            custom.authScheme = ""
            try await HTTPEmailSender(config: custom, client: client).send(EmailMessage(to: "a@b.co", subject: "Hi", text: "Body", kind: "x"))
            let second = try XCTUnwrap(client.requests.withLockedValue { $0.last })
            XCTAssertEqual(second.headers.first(name: "X-Api-Key"), "key_123")
            XCTAssertNil(second.headers.first(name: "Authorization"))
            // A provider error is an error (nothing from the response is surfaced).
            let failing = RecordingClient(eventLoop: loop, status: .unauthorized)
            do {
                try await HTTPEmailSender(config: config, client: failing).send(EmailMessage(to: "a@b.co", subject: "Hi", text: "Body", kind: "x"))
                XCTFail("a 401 must throw")
            } catch let error as EmailError {
                XCTAssertEqual(error, .rejected(401))
            }
        }
    }

    // MARK: - 2. Dashboard email verification

    private func signupBegin(_ h: TestHarness, _ email: String, handle: String? = nil) async throws -> HTTPResult {
        try await h.jsonPost("/dashboard/auth/signup/begin", SignupBeginBody(email: email, displayName: "Eve", organizationName: "Eve Org", category: "retail",
                                                                              legalName: nil, website: nil, requestedHandle: handle, description: nil))
    }

    func testSignupEmailsACodeAndTheAccountStaysUnverifiedUntilItIsEntered() async throws {
        try await withHarness { h in
            let (account, finish) = try await h.dashSignupUnverified(email: "owner@acme.test")
            // No session and no organization yet.
            XCTAssertNil(h.sessionCookie(finish))
            let user = try await XCTUnwrapAsync(try await DashboardUserRecord.find(account.userId, on: h.db))
            XCTAssertEqual(user.status, "unverified")
            try await eq(try await BusinessRecord.query(on: h.db).count(), 0)
            try await eq(try await OrgMembershipRecord.query(on: h.db).count(), 0)
            // A 6-digit code went to the address, and only a peppered hash of it is stored.
            let code = try XCTUnwrap(h.emails.lastCode(to: "owner@acme.test"))
            XCTAssertNotNil(code.range(of: #"^[0-9]{6}$"#, options: .regularExpression))
            let record = try await XCTUnwrapAsync(try await DashboardEmailCodeRecord.query(on: h.db).first())
            XCTAssertEqual(record.codeHash.count, 64)
            XCTAssertNotEqual(record.codeHash, code)
            XCTAssertEqual(record.expiresAt, h.clock.now().addingTimeInterval(15 * 60))
            XCTAssertEqual(record.attempts, 0)
            XCTAssertFalse((record.payload ?? "").contains("Eve Org"), "sign-up details are sealed")
            // An unverified account cannot sign in (the passkey alone is not enough) and creates nothing.
            let (session, login) = try await h.dashLogin(account)
            XCTAssertNil(session)
            XCTAssertEqual(login.status, .unauthorized)
            // Entering the code activates it, creates the pending organization, and the user then signs in with the passkey.
            let verified = try await h.dashVerifyEmail("owner@acme.test")
            XCTAssertEqual(verified.status, .ok, verified.text)
            try await eq(try await DashboardUserRecord.find(account.userId, on: h.db)?.status, "active")
            try await eq(try await BusinessRecord.query(on: h.db).all().filter { $0.status == .pending }.count, 1)
            let (afterSession, _) = try await h.dashLogin(account)
            XCTAssertNotNil(afterSession)
            // The code is single use.
            try await eq(try await h.dashVerifyEmail("owner@acme.test", code: code).status, .unprocessableEntity)
        }
    }

    func testVerificationHasFiveAttemptsAndFifteenMinutes() async throws {
        try await withHarness { h in
            _ = try await h.dashSignupUnverified(email: "owner@acme.test")
            let code = try XCTUnwrap(h.emails.lastCode(to: "owner@acme.test"))
            let wrong = code == "000000" ? "111111" : "000000"
            for _ in 0..<5 { try await eq(try await h.dashVerifyEmail("owner@acme.test", code: wrong).status, .unprocessableEntity) }
            // Out of attempts: even the right code no longer works.
            try await eq(try await h.dashVerifyEmail("owner@acme.test", code: code).status, .unprocessableEntity)
            try await eq(try await DashboardUserRecord.query(on: h.db).filter(\.$status == "unverified").count(), 1)
            // A new code (resend) starts over, and replaces the old one.
            let resend = try await h.request(.POST, "/dashboard/verify/resend", headers: ["Origin": h.origin], body: formBody([("email", "owner@acme.test")]),
                                             contentType: "application/x-www-form-urlencoded")
            XCTAssertEqual(resend.status, .ok)
            let fresh = try XCTUnwrap(h.emails.lastCode(to: "owner@acme.test"))
            try await eq(try await DashboardEmailCodeRecord.query(on: h.db).count(), 1)
            // Expiry: 15 minutes.
            h.clock.advance(by: 15 * 60 + 1)
            try await eq(try await h.dashVerifyEmail("owner@acme.test", code: fresh).status, .unprocessableEntity)
            _ = try await h.request(.POST, "/dashboard/verify/resend", headers: ["Origin": h.origin], body: formBody([("email", "owner@acme.test")]),
                                    contentType: "application/x-www-form-urlencoded")
            let last = try XCTUnwrap(h.emails.lastCode(to: "owner@acme.test"))
            try await eq(try await h.dashVerifyEmail("owner@acme.test", code: last).status, .ok)
        }
    }

    func testConcurrentGuessesCannotExceedTheAttemptBudget() async throws {
        try await withHarness { h in
            _ = try await h.dashSignupUnverified(email: "owner@acme.test")
            let code = try XCTUnwrap(h.emails.lastCode(to: "owner@acme.test"))
            let wrong = (0..<20).map { String(format: "%06d", 900_000 + $0) }.filter { $0 != code }
            let record = try await XCTUnwrapAsync(try await DashboardEmailCodeRecord.query(on: h.db).first())
            let service = EmailVerificationService(db: h.db, ctx: h.ctx)
            let outcomes = try await withThrowingTaskGroup(of: Bool.self) { group in
                for guess in wrong { group.addTask { try await service.check(record, code: guess) } }
                return try await group.reduce(into: [Bool]()) { $0.append($1) }
            }
            XCTAssertEqual(outcomes.filter { $0 }.count, 0)
            let after = try await XCTUnwrapAsync(try await DashboardEmailCodeRecord.find(record.id!, on: h.db))
            XCTAssertEqual(after.attempts, 5, "exactly five guesses were ever evaluated")
            let correct = try await service.check(after, code: code)
            XCTAssertFalse(correct, "and then the code is dead")
        }
    }

    /// Non-enumeration: every way verification can fail, and every way sign-up can start, looks the same from outside.
    func testResponsesAreTheSameWhetherOrNotAnAddressExists() async throws {
        try await withHarness { h in
            // Sign-up begin: free address, unverified address, verified address.
            let verified = try await h.dashSignup(email: "verified@acme.test", org: "Verified Org", handle: "verifiedorg")
            _ = verified
            _ = try await h.dashSignupUnverified(email: "pending@acme.test", org: "Pending Org", handle: nil)
            let begins = try await ["fresh@acme.test", "pending@acme.test", "verified@acme.test"].asyncMap { try await signupBegin(h, $0) }
            XCTAssertEqual(Set(begins.map(\.status.code)), [200])
            // Verify: unknown address, pending address + wrong code, verified address + any code, malformed address, malformed code.
            let cases: [(String, String)] = [("nobody@acme.test", "123456"), ("pending@acme.test", "000000"), ("verified@acme.test", "123456"),
                                             ("not-an-email", "123456"), ("pending@acme.test", "abc")]
            let failures = try await cases.asyncMap { try await h.dashVerifyEmail($0.0, code: $0.1) }
            XCTAssertEqual(Set(failures.map(\.status.code)), [422])
            let messages = Set(failures.map { $0.text.components(separatedBy: "role=\"alert\">").dropFirst().first?.components(separatedBy: "<").first ?? "?" })
            XCTAssertEqual(messages.count, 1, "one message for every failure: \(messages)")
            // Resend: the same page for an address with a pending sign-up and for one without; mail goes only to the former.
            func resend(_ email: String) async throws -> HTTPResult {
                try await h.request(.POST, "/dashboard/verify/resend", headers: ["Origin": h.origin], body: formBody([("email", email)]),
                                    contentType: "application/x-www-form-urlencoded")
            }
            let sentBefore = h.emails.sent.count
            let known = try await resend("pending@acme.test")
            let unknown = try await resend("nobody@acme.test")
            let activeAccount = try await resend("verified@acme.test")
            XCTAssertEqual([known.status, unknown.status, activeAccount.status], [.ok, .ok, .ok])
            XCTAssertEqual(known.text, unknown.text)
            XCTAssertEqual(known.text, activeAccount.text)
            XCTAssertEqual(h.emails.sent.count, sentBefore + 1)
        }
    }

    func testSendingIsRateLimitedPerAddressAndPerIPWithoutRevealingAnything() async throws {
        try await withHarness { h in
            func resend(_ email: String) async throws -> HTTPResult {
                try await h.request(.POST, "/dashboard/verify/resend", headers: ["Origin": h.origin], body: formBody([("email", email)]),
                                    contentType: "application/x-www-form-urlencoded")
            }
            // Per address: the sixth request in an hour is refused, for a real pending address and for an unknown one alike.
            _ = try await h.dashSignupUnverified(email: "pending@acme.test", org: "Pending Org", handle: nil)
            var real: [UInt] = []
            var unknown: [UInt] = []
            for _ in 0..<6 { real.append(try await resend("pending@acme.test").status.code) }
            _ = try await signupBegin(h, "nobody@acme.test") // the same one sign-up call the pending address has already made
            for _ in 0..<6 { unknown.append(try await resend("nobody@acme.test").status.code) }
            XCTAssertTrue(real.contains(429))
            XCTAssertEqual(real.map { $0 == 429 }, unknown.map { $0 == 429 }.map { $0 })
            // Sign-up begin is limited per address too (one address cannot be mail-bombed from one place).
            var begins: [UInt] = []
            for _ in 0..<7 { begins.append(try await signupBegin(h, "bomb@acme.test").status.code) }
            XCTAssertTrue(begins.contains(429), "\(begins)")
        }
    }

    func testAnUnverifiedSignupIsPurgedAfter24HoursAndFreesTheAddress() async throws {
        try await withHarness { h in
            let (account, _) = try await h.dashSignupUnverified(email: "owner@acme.test")
            h.clock.advance(by: 23 * 3600)
            try await h.runJobs()
            try await notNil(try await DashboardUserRecord.find(account.userId, on: h.db), "still within 24 hours")
            h.clock.advance(by: 2 * 3600)
            // The maintenance gate allows the purge once a minute.
            try await h.runJobs()
            try await isNil(try await DashboardUserRecord.find(account.userId, on: h.db))
            try await eq(try await DashboardPasskeyRecord.query(on: h.db).count(), 0)
            try await eq(try await DashboardEmailCodeRecord.query(on: h.db).count(), 0)
            // The address is free: a new sign-up proceeds (and a verified account is never purged).
            let again = try await h.dashSignup(email: "owner@acme.test")
            h.clock.advance(by: 48 * 3600)
            try await h.runJobs()
            try await notNil(try await DashboardUserRecord.find(again.account.userId, on: h.db))
        }
    }

    func testALaterSignupReplacesAnUnverifiedOneForTheSameAddress() async throws {
        try await withHarness { h in
            let (first, _) = try await h.dashSignupUnverified(email: "owner@acme.test", org: "Squatter Org", handle: nil)
            // A sign-up under 15 minutes old is protected from being wiped (DashboardRound5Tests); an older one never holds the address.
            h.clock.advance(by: 16 * 60)
            let (second, _) = try await h.dashSignupUnverified(email: "owner@acme.test", org: "Real Org", handle: nil)
            try await isNil(try await DashboardUserRecord.find(first.userId, on: h.db))
            try await notNil(try await DashboardUserRecord.find(second.userId, on: h.db))
            // The squatter's code is dead; only the newest code works, and it creates the real owner's organization.
            try await eq(try await DashboardEmailCodeRecord.query(on: h.db).count(), 1)
            try await eq(try await h.dashVerifyEmail("owner@acme.test").status, .ok)
            let org = try await XCTUnwrapAsync(try await BusinessRecord.query(on: h.db).first())
            XCTAssertEqual(org.displayName, "Real Org")
            try await notNil(try await h.dashLogin(second).session)
            try await isNil(try await h.dashLogin(first).session)
        }
    }

    /// The point of the feature: pre-registering someone's address without owning the mailbox no longer blocks their invitation.
    func testSquattingAnAddressWithoutVerifyingDoesNotBlockTheRealOwnersInvite() async throws {
        try await withHarness { h in
            let owner = try await h.verifiedOwner(email: "owner@acme.test", org: "Acme Roasters", handle: "acmeroasters")
            // Mallory registers alice's address (a passkey, but no access to alice's mailbox: she cannot verify).
            let (mallory, _) = try await h.dashSignupUnverified(email: "alice@acme.test", name: "Mallory", org: "Mallory Org", handle: nil)
            // The owner invites alice. The page treats alice as new (the squatter is not an "existing account").
            let invite = try await h.formPost("/dashboard/team/invite", owner.session, [("email", "alice@acme.test"), ("role", "admin")])
            XCTAssertEqual(invite.status, .ok, invite.text)
            let token = try XCTUnwrap(h.emails.lastInviteToken(to: "alice@acme.test"))
            let page = try await h.page("/dashboard/invite/\(token)", nil)
            XCTAssertFalse(page.text.contains("already have a Viadere account"))
            XCTAssertTrue(page.text.contains("Email me a code"))
            // Alice proves her mailbox and registers: the squatter's record is replaced.
            let code = try await h.inviteCode(token: token, email: "alice@acme.test")
            let begin = try await h.jsonPost("/dashboard/auth/invite/begin", InviteBeginBody(token: token, displayName: "Alice", code: code))
            XCTAssertEqual(begin.status, .ok, begin.text)
            let options = try begin.json(PasskeyRegistrationOptions.self)
            let finish = try await h.jsonPost("/dashboard/auth/invite/finish", PasskeyRegistrationFinishRequest(
                ceremonyId: options.ceremonyId, credential: h.registrationCredential(for: options, credentialId: "alice-cred", publicKey: SecureToken.generate(byteCount: 32))))
            XCTAssertEqual(finish.status, .ok, finish.text)
            try await isNil(try await DashboardUserRecord.find(mallory.userId, on: h.db))
            let alice = try await XCTUnwrapAsync(try await DashboardUserRecord.query(on: h.db).filter(\.$displayName == "Alice").first())
            XCTAssertEqual(alice.status, "active")
            let membership = try await XCTUnwrapAsync(try await OrgMembershipRecord.query(on: h.db).filter(\.$userId == alice.id!).first())
            XCTAssertEqual(membership.role, "admin")
            // Mallory's passkey is gone: it signs nothing.
            try await isNil(try await h.dashLogin(mallory).session)
            // And a squatted address can be taken by a normal sign-up too (covered above); a verified account is never replaced:
            let again = try await signupBegin(h, "alice@acme.test")
            XCTAssertEqual(again.status, .ok, "same answer as any address")
        }
    }

    func testAcceptingAnInvitationNeedsTheEmailedCode() async throws {
        try await withHarness { h in
            let owner = try await h.verifiedOwner(email: "owner@acme.test", org: "Acme Roasters", handle: "acmeroasters")
            _ = try await h.formPost("/dashboard/team/invite", owner.session, [("email", "alice@acme.test"), ("role", "analyst")])
            _ = try await h.formPost("/dashboard/team/invite", owner.session, [("email", "bob@acme.test"), ("role", "analyst")])
            let aliceToken = try XCTUnwrap(h.emails.lastInviteToken(to: "alice@acme.test"))
            let bobToken = try XCTUnwrap(h.emails.lastInviteToken(to: "bob@acme.test"))
            // The token alone is not enough: no code, a made-up code, and another invitation's code are all refused.
            try await eq(try await h.jsonPost("/dashboard/auth/invite/begin", InviteBeginBody(token: aliceToken, displayName: "A")).status, .unprocessableEntity)
            let neverSent = try await h.jsonPost("/dashboard/auth/invite/begin", InviteBeginBody(token: aliceToken, displayName: "A", code: "123456"))
            XCTAssertEqual(neverSent.status, .unprocessableEntity)
            let bobCode = try await h.inviteCode(token: bobToken, email: "bob@acme.test")
            try await eq(try await h.jsonPost("/dashboard/auth/invite/begin", InviteBeginBody(token: aliceToken, displayName: "A", code: bobCode)).status, .unprocessableEntity)
            // Five wrong codes kill a code; a new one works.
            let aliceCode = try await h.inviteCode(token: aliceToken, email: "alice@acme.test")
            let wrong = aliceCode == "654321" ? "123456" : "654321"
            for _ in 0..<5 { try await eq(try await h.jsonPost("/dashboard/auth/invite/begin", InviteBeginBody(token: aliceToken, displayName: "A", code: wrong)).status, .unprocessableEntity) }
            try await eq(try await h.jsonPost("/dashboard/auth/invite/begin", InviteBeginBody(token: aliceToken, displayName: "A", code: aliceCode)).status, .unprocessableEntity)
            let renewed = try await h.inviteCode(token: aliceToken, email: "alice@acme.test")
            let begin = try await h.jsonPost("/dashboard/auth/invite/begin", InviteBeginBody(token: aliceToken, displayName: "A", code: renewed))
            XCTAssertEqual(begin.status, .ok, begin.text)
            // The code is single use.
            try await eq(try await h.jsonPost("/dashboard/auth/invite/begin", InviteBeginBody(token: aliceToken, displayName: "A", code: renewed)).status, .unprocessableEntity)
            // Invalid tokens cannot be used to send mail.
            let before = h.emails.sent.count
            let bogus = try await h.request(.POST, "/dashboard/invite/\(SecureToken.generate())/code", headers: ["Origin": h.origin], body: Data(),
                                            contentType: "application/x-www-form-urlencoded")
            XCTAssertEqual(bogus.status, .unprocessableEntity)
            XCTAssertEqual(h.emails.sent.count, before)
        }
    }

    func testTheInviterNeverSeesTheTokenAndAFailedEmailWithdrawsTheInvitation() async throws {
        try await withHarness { h in
            let owner = try await h.verifiedOwner(email: "owner@acme.test", org: "Acme Roasters", handle: "acmeroasters")
            let sent = try await h.formPost("/dashboard/team/invite", owner.session, [("email", "alice@acme.test"), ("role", "analyst")])
            let token = try XCTUnwrap(h.emails.lastInviteToken(to: "alice@acme.test"))
            XCTAssertFalse(sent.text.contains(token))
            XCTAssertFalse(sent.text.contains("/dashboard/invite/"))
            let message = try XCTUnwrap(h.emails.messages(to: "alice@acme.test").last)
            XCTAssertTrue(message.text.contains("https://viadere.com/dashboard/invite/\(token)"))
            XCTAssertFalse(message.text.contains(try XCTUnwrap(h.emails.lastCode(to: "alice@acme.test") ?? "no-code-sent-yet")), "the invitation carries no code")
            // The provider is down: the invitation is not left behind, and the answer says so without detail.
            h.emails.setFailing(true)
            let failed = try await h.formPost("/dashboard/team/invite", owner.session, [("email", "carol@acme.test"), ("role", "analyst")])
            XCTAssertEqual(failed.status, .notImplemented)
            try await eq(try await OrgInviteRecord.query(on: h.db).filter(\.$state == "open").count(), 1)
        }
    }

    func testAnUnverifiedAccountCannotAcceptInvitesOrReachTheDashboard() async throws {
        try await withHarness { h in
            let owner = try await h.verifiedOwner(email: "owner@acme.test", org: "Acme Roasters", handle: "acmeroasters")
            let (account, _) = try await h.dashSignupUnverified(email: "alice@acme.test", name: "Alice", org: "Alice Org", handle: nil)
            _ = try await h.formPost("/dashboard/team/invite", owner.session, [("email", "alice@acme.test"), ("role", "admin")])
            let token = try XCTUnwrap(h.emails.lastInviteToken(to: "alice@acme.test"))
            // Even a hand-built principal for the unverified user is refused by the invite acceptance itself.
            let user = try await XCTUnwrapAsync(try await DashboardUserRecord.find(account.userId, on: h.db))
            let session = DashboardSessionRecord()
            session.id = UUID()
            let principal = DashboardPrincipal(user: user, session: session, realm: .business, sessionToken: "x", csrf: "x", membership: nil, business: nil)
            do {
                _ = try await DashboardActions.acceptInvite(token: token, principal: principal, db: h.db, ctx: h.ctx)
                XCTFail("an unverified account must not accept an invitation")
            } catch let error as APIError {
                XCTAssertEqual(error.status, .forbidden)
            }
            try await eq(try await OrgMembershipRecord.query(on: h.db).filter(\.$userId == account.userId).count(), 0)
            // A session minted for it (a bug elsewhere) is still refused by the middleware, and it has no organization.
            let created = try await DashboardSessionStore(db: h.db, ctx: h.ctx).create(userId: account.userId, realm: .business, businessId: nil, replacing: nil)
            let forged = DashSession(token: created.token, realm: .business)
            try await eq(try await h.page("/dashboard", forged).status, .seeOther)
            try await eq(try await h.formPost("/dashboard/invite/\(token)/accept", forged).status, .seeOther)
        }
    }

    // MARK: - 3. Household invitation budget

    private func householdHarness(_ adjust: @escaping (inout ServerConfig) -> Void, _ body: (TestHarness) async throws -> Void) async throws {
        try await withHarness({ config in
            config.accessTokenTTL = 90 * 86_400
            config.rateLimits.inviteCreatePerConsumer = .perHour(1000, burst: 1000)
            // Many accounts register from one test "IP".
            config.rateLimits.authCeremony = .perMinute(10_000, burst: 10_000)
            config.rateLimits.globalIP = .perMinute(100_000, burst: 100_000)
            adjust(&config)
        }, body)
    }

    private func preview(_ h: TestHarness, _ c: TestConsumer, _ code: String) async throws -> HTTPResult {
        try await h.signedPost(c, "/v1/household/invitations/preview", DelegationInvitationRedeemRequest(code: code))
    }

    private func newInvitationCode(_ h: TestHarness, grantor: TestConsumer, business: TestBusiness) async throws -> String {
        let created = try await h.invite(grantor, h.invitation(purposes: [.support], businesses: [business]))
        XCTAssertEqual(created.status, .created, created.text)
        return try created.json(DelegationInvitation.self).code
    }

    /// The platform-wide budget guards against distributed guessing. Valid previews no longer spend it, so a crowd of accounts previewing real
    /// codes cannot lock everyone else out; failed lookups still do.
    func testValidPreviewsByManyAccountsDoNotDrainThePlatformWideBudget() async throws {
        try await householdHarness({ config in
            config.rateLimits.inviteAttemptGlobal = .perMinute(5, burst: 5)
            config.rateLimits.inviteAttemptPerConsumer = .perHour(100, burst: 100)
            config.rateLimits.invitePreviewPerConsumer = .perHour(100, burst: 100)
        }) { h in
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let alex = try await h.readyConsumer(name: "Alex")
            _ = try await h.connect(alex, to: business)
            // Several different grantors, so no single invitation reaches its own 10-lookup lock.
            var codes: [String] = []
            for _ in 0..<2 { codes.append(try await newInvitationCode(h, grantor: alex, business: business)) }
            var statuses: [UInt] = []
            for index in 0..<10 {
                let visitor = try await h.readyConsumer(name: "Visitor \(index)")
                statuses.append(try await preview(h, visitor, codes[index % 2]).status.code)
            }
            XCTAssertEqual(statuses, Array(repeating: 200, count: 10), "ten valid previews in a row, with a budget of five failures")
            // Failed lookups do spend it: after five wrong codes from different accounts, a lookup is refused for everybody for now.
            var wrong: [UInt] = []
            for index in 0..<5 {
                let guesser = try await h.readyConsumer(name: "Guesser \(index)")
                wrong.append(try await preview(h, guesser, "ZZZZ-ZZZZ").status.code)
            }
            XCTAssertEqual(wrong, Array(repeating: 404, count: 5))
            let victim = try await h.readyConsumer(name: "Victim")
            try await eq(try await preview(h, victim, codes[0]).status, .tooManyRequests)
            // The budget refills.
            h.clock.advance(by: 61)
            try await eq(try await preview(h, victim, codes[0]).status, .ok)
        }
    }

    func testEachAccountHasItsOwnPreviewLimitAndFailureBudget() async throws {
        try await householdHarness({ config in
            config.rateLimits.inviteAttemptGlobal = .perMinute(10_000, burst: 10_000)
            config.rateLimits.invitePreviewPerConsumer = .perHour(3, burst: 3)
            config.rateLimits.inviteAttemptPerConsumer = .perHour(2, burst: 2)
        }) { h in
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let alex = try await h.readyConsumer(name: "Alex")
            _ = try await h.connect(alex, to: business)
            let code = try await newInvitationCode(h, grantor: alex, business: business)
            let sam = try await h.readyConsumer(name: "Sam")
            let lee = try await h.readyConsumer(name: "Lee")
            // Previews: three per hour per account, valid or not; another account is unaffected.
            var sams: [UInt] = []
            for _ in 0..<4 { sams.append(try await preview(h, sam, code).status.code) }
            XCTAssertEqual(sams, [200, 200, 200, 429])
            try await eq(try await preview(h, lee, code).status, .ok)
            // Failures: two wrong codes per hour per account (the preview limit is not what stops this one).
            let ray = try await h.readyConsumer(name: "Ray")
            var rays: [UInt] = []
            for _ in 0..<3 { rays.append(try await preview(h, ray, "ZZZZ-ZZZZ").status.code) }
            XCTAssertEqual(rays, [404, 404, 429])
            // Ray's exhausted failure budget refuses even a valid code until it refills (brute force stays bounded per account).
            try await eq(try await preview(h, ray, code).status, .tooManyRequests)
        }
    }

    // MARK: - 4. Delegate notifications

    private func registerPush(_ h: TestHarness, _ consumer: TestConsumer, token: String) async throws {
        let response = try await h.signedPost(consumer, "/v1/push/apns-token", APNsTokenRegistration(token: token, environment: .sandbox, bundleId: "com.viadere.app"))
        XCTAssertEqual(response.status, .ok, response.text)
    }

    func testAnInteractionCoveredByADelegatesGrantIsPushedToTheDelegateToo() async throws {
        try await withHarness({ $0.accessTokenTTL = 90 * 86_400 }) { h in
            let northwind = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let alex = try await h.readyConsumer(name: "Alex")
            let sam = try await h.readyConsumer(name: "Sam")
            let alexToken = String(repeating: "ab", count: 32)
            let samToken = String(repeating: "cd", count: 32)
            try await registerPush(h, alex, token: alexToken)
            try await registerPush(h, sam, token: samToken)
            let relationship = try await h.connect(alex, to: northwind)
            _ = try await h.shareAccess(from: alex, to: sam, purposes: [.transactional], businesses: [northwind])
            let response = try await h.issue(northwind, relationship: relationship, payload: .authorize(.sample()), purpose: .transactional)
            XCTAssertEqual(response.status, .created, response.text)
            let interaction = try response.json(Interaction.self)
            let pushes = h.push.sent
            XCTAssertEqual(Set(pushes.map(\.deviceToken)), [alexToken, samToken], "the grantor and the delegate are both notified")
            XCTAssertEqual(pushes.count, 2)
            // The delegate's push follows the grantor's payload rules: opaque iid, generic text, nothing about the business or the request.
            let forSam = try XCTUnwrap(pushes.first { $0.deviceToken == samToken })
            let forAlex = try XCTUnwrap(pushes.first { $0.deviceToken == alexToken })
            XCTAssertEqual(forSam.interactionId, interaction.id.description)
            XCTAssertEqual(forSam.title, forAlex.title)
            XCTAssertEqual(forSam.body, forAlex.body)
            XCTAssertEqual(forSam.category, forAlex.category)
            XCTAssertTrue(forSam.mutableContent)
            for text in [forSam.title, forSam.body, forSam.category] {
                for secret in ["285.28", "Walmart", "Mesa", "Northwind", "Arizona", "Alex", "Sam"] { XCTAssertFalse(text.contains(secret), "push leaked \(secret)") }
            }
            // The delegate fetches the details through the scoped API.
            let detail = try await h.signed(sam, .GET, "/v1/interactions/\(interaction.id)")
            XCTAssertEqual(detail.status, .ok, detail.text)
        }
    }

    func testOutOfScopeInteractionsAreNeverPushedToDelegates() async throws {
        try await withHarness({ $0.accessTokenTTL = 90 * 86_400 }) { h in
            let northwind = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let juniper = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
            let alex = try await h.readyConsumer(name: "Alex")
            let sam = try await h.readyConsumer(name: "Sam")
            let lee = try await h.readyConsumer(name: "Lee")
            let alexToken = String(repeating: "ab", count: 32)
            let samToken = String(repeating: "cd", count: 32)
            let leeToken = String(repeating: "ef", count: 32)
            for (consumer, token) in [(alex, alexToken), (sam, samToken), (lee, leeToken)] { try await registerPush(h, consumer, token: token) }
            let atNorthwind = try await h.connect(alex, to: northwind)
            let atJuniper = try await h.connect(alex, to: juniper)
            let grant = try await h.shareAccess(from: alex, to: sam, purposes: [.transactional], businesses: [northwind])
            func tokens(after before: Int) -> Set<String> { Set(h.push.sent.dropFirst(before).map(\.deviceToken)) }

            // Another purpose, same business.
            var before = h.push.sent.count
            var issued = try await h.issue(northwind, relationship: atNorthwind, payload: .authorize(.sample()), purpose: .security)
            XCTAssertEqual(issued.status, .created, issued.text)
            XCTAssertEqual(tokens(after: before), [alexToken], "a security request is outside a transactional grant")
            let outOfPurpose = try issued.json(Interaction.self)
            try await eq(try await h.signed(sam, .GET, "/v1/interactions/\(outOfPurpose.id)").status, .notFound)
            // Same purpose, another business.
            before = h.push.sent.count
            issued = try await h.issue(juniper, relationship: atJuniper, payload: .authorize(.sample()), purpose: .transactional)
            XCTAssertEqual(issued.status, .created, issued.text)
            XCTAssertEqual(tokens(after: before), [alexToken], "another business is outside the grant")
            // Someone who holds no grant is never notified, and neither is the delegate of somebody else's grant.
            XCTAssertFalse(h.push.sent.contains { $0.deviceToken == leeToken })
            // In scope: notified. After the grant is revoked: not any more.
            before = h.push.sent.count
            issued = try await h.issue(northwind, relationship: atNorthwind, payload: .authorize(.sample()), purpose: .transactional)
            XCTAssertEqual(tokens(after: before), [alexToken, samToken])
            _ = try await DelegationGrantRecord.query(on: h.db).filter(\.$id == grant.grant.id.uuid).set(\.$revokedAt, to: h.clock.now()).update()
            before = h.push.sent.count
            issued = try await h.issue(northwind, relationship: atNorthwind, payload: .authorize(.sample()), purpose: .transactional)
            XCTAssertEqual(tokens(after: before), [alexToken], "a revoked grant stops the delegate's notifications")
            // An expired grant too.
            let second = try await h.shareAccess(from: alex, to: sam, purposes: [.transactional], businesses: [northwind], lifetimeDays: 1)
            _ = second
            h.clock.advance(by: 2 * 86_400)
            before = h.push.sent.count
            issued = try await h.issue(northwind, relationship: atNorthwind, payload: .authorize(.sample()), purpose: .transactional)
            XCTAssertEqual(issued.status, .created, issued.text)
            XCTAssertEqual(tokens(after: before), [alexToken], "an expired grant stops the delegate's notifications")
        }
    }
}

final class LockedBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T
    init(_ value: T) { self.value = value }
    func withLockedValue<R>(_ body: (inout T) -> R) -> R { lock.withLock { body(&value) } }
}

extension Sequence {
    func asyncMap<T>(_ transform: (Element) async throws -> T) async rethrows -> [T] {
        var result: [T] = []
        for element in self { result.append(try await transform(element)) }
        return result
    }
}
