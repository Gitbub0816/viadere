import Fluent
import Foundation
import Logging
import NIOHTTP1
import Vapor
import XCTest
import ViadereCore
@testable import ViadereServerKit

/// G23: email fallback for one-time codes (ADR-0020 section 7, UX_COPY C-OTP-03, SECURITY §2.101). Each test reproduces one way the channel could
/// be abused or leak the code.
final class AuthEmailFallbackTests: AuthDeliveryTestBase {
    let address = "pat@inbox.example.org"

    func fallbackHarness(enabled: Bool = true, _ body: (TestHarness) async throws -> Void) async throws {
        try await harness({ $0.authDelivery.emailFallbackEnabled = enabled }, body)
    }

    func allow(_ h: TestHarness, _ s: Scene, _ allowed: Bool = true) async throws {
        try await SecuritySettings(db: h.db, ctx: h.ctx).setEmailFallbackAllowed(businessId: s.b.id.uuid, allowed: allowed, by: UUID())
    }

    func emailExtra(_ address: String? = nil) -> [String: Any] {
        ["channels": ["push", "inbox", "email"], "fallback": ["email": ["address": address ?? self.address]]]
    }

    // MARK: Gate: the flag, staging and production

    func testFlagOffRefusesEmailEvenForATenantThatAllowsIt() async throws {
        try await fallbackHarness(enabled: false) { h in
            let s = try await scene(h)
            try await allow(h, s)
            let r = try await create(h, s.b, otpBody(s, extra: emailExtra()))
            XCTAssertEqual(r.status, .unprocessableEntity, r.text)
            XCTAssertEqual(r.errorCode, .validationFailed)
            XCTAssertTrue(r.text.contains("email_unavailable"), r.text)
            try await eq(try await AuthDeliveryRecord.query(on: h.db).count(), 0)
            XCTAssertTrue(h.emails.sent.isEmpty)
        }
    }

    func testTheFlagIsRefusedInStagingAndProductionUntilTheGateIsRecorded() throws {
        var config = ServerConfig.testing()
        XCTAssertThrowsError(try config.applyAuthDeliveryEnvironment(["AUTH_EMAIL_FALLBACK_ENABLED": "true"], production: true))
        XCTAssertThrowsError(try config.applyAuthDeliveryEnvironment(["AUTH_EMAIL_FALLBACK_ENABLED": "TRUE"], production: true))
        XCTAssertThrowsError(try config.applyAuthDeliveryEnvironment(["AUTH_EMAIL_FALLBACK_ENABLED": "yes"], production: false))
        try config.applyAuthDeliveryEnvironment([:], production: false)
        XCTAssertFalse(config.authDelivery.emailFallbackEnabled, "off by default")
        try config.applyAuthDeliveryEnvironment(["AUTH_EMAIL_FALLBACK_ENABLED": "true"], production: false)
        XCTAssertTrue(config.authDelivery.emailFallbackEnabled)
        XCTAssertFalse(AuthDeliverySettings().emailFallbackEnabled)
        // Through the whole configuration path too: a strict environment never starts with it.
        for environment in ["staging", "production"] {
            var env = PlatformGateOpsTests.productionEnvironment(environment)
            XCTAssertNoThrow(try ServerConfig.fromEnvironment(env), "the base \(environment) configuration starts")
            env["AUTH_EMAIL_FALLBACK_ENABLED"] = "true"
            XCTAssertThrowsError(try ServerConfig.fromEnvironment(env), environment)
        }
    }

    // MARK: Who may trigger it

    func testABusinessThatDidNotAllowEmailNeverTriggersIt() async throws {
        try await fallbackHarness { h in
            let s = try await scene(h)
            let refused = try await create(h, s.b, otpBody(s, extra: emailExtra()))
            XCTAssertEqual(refused.status, .unprocessableEntity, refused.text)
            XCTAssertTrue(refused.text.contains("email_not_allowed"), refused.text)
            // Turned on, then off again: refused again, and the change is audited both ways.
            try await allow(h, s)
            try await allow(h, s, false)
            let again = try await create(h, s.b, otpBody(s, extra: emailExtra()))
            XCTAssertEqual(again.status, .unprocessableEntity, again.text)
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == "security.email_fallback_set").count(), 2)
            // Allowed, but this request did not ask for email: no email.
            try await allow(h, s)
            _ = try await created(h, s)
            try await h.runJobs()
            XCTAssertTrue(h.emails.sent.isEmpty)
            try await eq(try await AuthDeliveryRecord.query(on: h.db).count(), 1)
        }
    }

    func testTurningThePolicyOffStopsAnEmailStillQueued() async throws {
        try await fallbackHarness { h in
            let s = try await scene(h)
            try await allow(h, s)
            _ = try await created(h, s, extra: emailExtra())
            try await allow(h, s, false)
            try await h.runJobs()
            XCTAssertTrue(h.emails.sent.isEmpty)
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == AuthEmailFallback.auditSuppressed).count(), 1)
        }
    }

    func testOnlyOneTimeCodesAndOnlyWithBothTheChannelAndTheAddress() async throws {
        try await fallbackHarness { h in
            let s = try await scene(h)
            try await allow(h, s)
            // A magic link by email would put a link in the email: refused.
            var link = try JSONSerialization.jsonObject(with: try await linkBody(h, s, id: "l-1")) as! [String: Any]
            for (k, v) in emailExtra() { link[k] = v }
            let refusedLink = try await create(h, s.b, try JSONSerialization.data(withJSONObject: link))
            XCTAssertEqual(refusedLink.status, .unprocessableEntity, refusedLink.text)
            XCTAssertTrue(refusedLink.text.contains("email_otp_only"), refusedLink.text)
            for extra: [String: Any] in [["channels": ["push", "inbox", "email"]], ["fallback": ["email": ["address": address]]]] {
                let r = try await create(h, s.b, otpBody(s, extra: extra))
                XCTAssertEqual(r.status, .unprocessableEntity, "\(extra) \(r.text)")
                XCTAssertTrue(r.text.contains("email_incomplete"), r.text)
            }
            try await eq(try await AuthDeliveryRecord.query(on: h.db).count(), 0)
        }
    }

    /// The task calls this "an unverified address": the consumer account holds no address (ADR-0020 section 7), so the address is the business's,
    /// and the server accepts exactly one plain mailbox. Anything that could add a recipient or a header, or reach an internal name, is refused.
    func testAnAddressThatIsNotOnePlainMailboxIsRefused() async throws {
        try await fallbackHarness { h in
            let s = try await scene(h)
            try await allow(h, s)
            for bad in ["Pat <pat@inbox.example.org>", "pat@inbox.example.org\r\nBcc: x@evil.example.com", "pat@inbox.example.org,x@evil.example.com",
                        "pat@inbox.example.org; x@evil.example.com", "pat@[127.0.0.1]", "pat@127.0.0.1", "pat@localhost", "pat@printer.local", "pat@db.internal",
                        "pät@inbox.example.org", "pat@exämple.org", "pat..x@inbox.example.org", ".pat@inbox.example.org", "\"pat\"@inbox.example.org",
                        "pat(comment)@inbox.example.org", "pat@inbox", "pat@-inbox.example.org", "pat@@inbox.example.org", "pat@inbox.example.1",
                        String(repeating: "a", count: 65) + "@inbox.example.org", ""] {
                let r = try await create(h, s.b, otpBody(s, extra: emailExtra(bad)))
                XCTAssertEqual(r.status, .unprocessableEntity, "\(bad) \(r.text)")
            }
            XCTAssertEqual(AuthEmailAddress.normalized("Pat.Smith+x@Inbox.Example.ORG"), "Pat.Smith+x@inbox.example.org")
            try await eq(try await AuthDeliveryRecord.query(on: h.db).count(), 0)
            XCTAssertTrue(h.emails.sent.isEmpty)
        }
    }

    // MARK: The email

    func testTheEmailCarriesTheCodeAndNoLinkIsSentOnceAndTheAddressIsDeleted() async throws {
        try await fallbackHarness { h in
            let s = try await scene(h)
            try await allow(h, s)
            let view = try await created(h, s, extra: emailExtra())
            // Stored sealed with the code, never in the delivery row.
            let row = try await AuthDeliveryRecord.find(view.id.uuid, on: h.db)
            XCTAssertFalse(String(decoding: try JSONEncoder().encode(XCTUnwrap(row)), as: UTF8.self).contains("inbox.example.org"))
            try await h.runJobs()
            let mails = h.emails.messages(to: address)
            XCTAssertEqual(mails.count, 1)
            let mail = try XCTUnwrap(mails.first)
            XCTAssertTrue(mail.sensitive)
            XCTAssertEqual(mail.subject, "Your Northwind code")
            XCTAssertTrue(mail.text.contains("482913"))
            XCTAssertTrue(mail.text.contains("Use it only on Northwind."))
            XCTAssertTrue(mail.text.contains("Northwind sent this code by email because you asked for it there. Email is easier to intercept than the Viadere app."))
            XCTAssertTrue(mail.text.contains("Expires at "))
            for forbidden in ["http", "://", "www.", "href", "<", ">", "@", "viadere.com", s.host] {
                XCTAssertFalse(mail.text.lowercased().contains(forbidden.lowercased()), "no link in the email: \(forbidden)")
            }
            XCTAssertFalse(mail.subject.contains("482913"), "the code is never in the subject")
            try await eq(try await get(h, s, view.id).status, .sent)
            // The address left the sealed secret before the send; the code stays for the app.
            let payload = await AuthDeliveryDeviceService(db: h.db, ctx: h.ctx).payload(try XCTUnwrap(row))
            XCTAssertNil(payload?.emailAddress)
            XCTAssertEqual(payload?.code, "482913")
            // A redelivered dispatch message, or a second worker, sends nothing more.
            _ = try await AuthDeliveryDispatcher(db: h.db, ctx: h.ctx).dispatch(id: view.id.uuid)
            try await AuthEmailFallback.dispatch(try XCTUnwrap(row), db: h.db, ctx: h.ctx).isFalse()
            try await h.runJobs()
            XCTAssertEqual(h.emails.messages(to: address).count, 1)
            // The business sees that the weaker channel was used, but never the address or the code.
            let events = try await h.business(s.b, .GET, "/v1/business/auth-deliveries/\(view.id)")
            XCTAssertFalse(events.text.contains("482913") || events.text.contains("inbox.example.org"), events.text)
            try await eq(try await AuthDeliveryEventRecord.query(on: h.db).filter(\.$reason == AuthEmailFallback.eventReason).count(), 1)
            // The app still opens the code once.
            let open = try await h.signed(s.consumer, .POST, "/v1/auth-deliveries/\(view.id)/open")
            XCTAssertEqual(try open.json(AuthDeliveryOpenResponse.self).code, "482913")
        }
    }

    func testTheCodeAndTheAddressAreNeverAuditedLoggedOrInEvents() async throws {
        try await fallbackHarness { h in
            let lines = LockedBox<[String]>([])
            h.app.logger = Logger(label: "capture") { _ in StructuredLogHandler(label: "capture", level: .trace) { line in lines.withLockedValue { $0.append(line) } } }
            let s = try await scene(h)
            try await allow(h, s)
            let view = try await created(h, s, extra: emailExtra())
            try await h.runJobs()
            XCTAssertEqual(h.emails.sent.count, 1)
            let audits = try await AuditEventRecord.query(on: h.db).all()
            let used = audits.filter { $0.action == AuthEmailFallback.auditUsed }
            XCTAssertEqual(used.count, 1)
            XCTAssertTrue(used[0].metadataJSON.contains("\"assurance\":\"email\""), used[0].metadataJSON)
            for audit in audits {
                let text = String(decoding: try JSONEncoder().encode(audit), as: UTF8.self)
                for secret in ["482913", "pat@", "inbox.example.org"] { XCTAssertFalse(text.contains(secret), "\(audit.action) carries \(secret)") }
            }
            let events = try await AuthDeliveryEventRecord.query(on: h.db).filter(\.$deliveryId == view.id.uuid).all()
            for event in events { XCTAssertFalse(String(decoding: try JSONEncoder().encode(event), as: UTF8.self).contains("482913")) }
            for delivery in try await WebhookDeliveryRecord.query(on: h.db).all() {
                let text = String(decoding: try JSONEncoder().encode(delivery), as: UTF8.self)
                XCTAssertFalse(text.contains("482913") || text.contains("inbox.example.org"))
            }
            let logged = lines.withLockedValue { $0 }.joined()
            XCTAssertFalse(logged.contains("482913") || logged.contains("inbox.example.org"))
        }
    }

    // MARK: The `auth.delivery.fallback_used` webhook (ADR-0020 section 7, THREAT_MODEL ST-DLV-05)

    /// A v2 endpoint of the scene's business that subscribes to `fallback_used` and `sent`.
    func fallbackHook(_ h: TestHarness, _ s: Scene) async throws -> URL {
        let url = URL(string: "https://hooks.example.com/fallback")!
        let r = try await h.businessPost(s.b, "/v1/business/webhooks", CreateWebhookRequest(url: url, events: [.authDeliveryFallbackUsed, .authDeliverySent],
                                                                                           envelopeVersion: WebhookEnvelopeV2.version, signatureVersion: .v2))
        XCTAssertEqual(r.status, .created, r.text)
        return url
    }

    func fallbackRows(_ h: TestHarness) async throws -> [WebhookDeliveryRecord] {
        try await WebhookDeliveryRecord.query(on: h.db).filter(\.$eventType == AuthDeliveryEventName.fallbackUsed.rawValue).all()
    }

    /// Every spelling of a secret a webhook body could smuggle it in.
    func encodings(_ secret: String) -> [String] {
        let data = Data(secret.utf8)
        let base64 = data.base64EncodedString()
        let base64url = base64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        let hex = data.map { String(format: "%02x", $0) }.joined()
        let percent = secret.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? secret
        let unicode = secret.unicodeScalars.map { $0 == "@" || $0 == "." ? String(format: "\\u%04x", $0.value) : String($0) }.joined()
        return [secret, secret.uppercased(), base64, base64url, hex, hex.uppercased(), percent, unicode]
    }

    func testFallbackUsedIsEmittedExactlyOnceWhenTheEmailIsSentAndCarriesOnlyIds() async throws {
        try await fallbackHarness { h in
            let s = try await scene(h)
            try await allow(h, s)
            let url = try await fallbackHook(h, s)
            let view = try await created(h, s, extra: emailExtra())
            try await h.runJobs()
            XCTAssertEqual(h.emails.messages(to: address).count, 1)
            // A redelivered dispatch message, a second worker and a direct second claim send no second email and no second event.
            _ = try await AuthDeliveryDispatcher(db: h.db, ctx: h.ctx).dispatch(id: view.id.uuid)
            let row = try await AuthDeliveryRecord.find(view.id.uuid, on: h.db)
            try await AuthEmailFallback.dispatch(try XCTUnwrap(row), db: h.db, ctx: h.ctx).isFalse()
            try await h.runJobs()
            try await h.runJobs()
            XCTAssertEqual(h.emails.messages(to: address).count, 1)
            let rows = try await fallbackRows(h)
            XCTAssertEqual(rows.count, 1)
            let received = h.webhooks.received.filter { $0.url == url && $0.headers[ViadereHeader.eventType] == "auth.delivery.fallback_used" }
            XCTAssertEqual(received.count, 1)
            let delivery = try XCTUnwrap(received.first)
            XCTAssertFalse(try XCTUnwrap(delivery.headers[ViadereHeader.signature]).contains("v1="), "v2 only")
            // The opaque envelope: ids, type, version, tenant and time. The request id is the delivery id.
            let envelope = try ViadereJSON.decode(WebhookEnvelopeV2.self, from: delivery.body)
            XCTAssertEqual(envelope.type, "auth.delivery.fallback_used")
            XCTAssertEqual(envelope.requestId, view.id.description)
            XCTAssertNil(envelope.resultRef)
            let members = try XCTUnwrap(JSONSerialization.jsonObject(with: delivery.body) as? [String: Any])
            XCTAssertEqual(Set(members.keys), ["id", "type", "version", "tenant_id", "request_id", "occurred_at"])
            // No address, domain or code in any encoding: in the body as sent, in the sealed stored body, or in the headers.
            let stored = try h.ctx.cipher.open(rows[0].body, context: "webhook_deliveries.body", rowId: try XCTUnwrap(rows[0].id))
            let texts = [String(decoding: delivery.body, as: UTF8.self), String(decoding: stored, as: UTF8.self),
                         delivery.headers.map { "\($0.key): \($0.value)" }.joined(separator: "\n")]
            for secret in ["482913", address, "pat@", "inbox.example.org", "example.org"] {
                for spelling in encodings(secret) {
                    for text in texts { XCTAssertFalse(text.contains(spelling), "\(secret) as \(spelling)") }
                }
            }
            // The `sent` event follows for the same delivery (the provider's acceptance moved it to `sent`).
            XCTAssertEqual(h.webhooks.received.filter { $0.url == url && $0.headers[ViadereHeader.eventType] == "auth.delivery.sent" }.count, 1)
        }
    }

    func testNoFallbackUsedWhenTheEmailIsSuppressedOrFails() async throws {
        try await fallbackHarness { h in
            let s = try await scene(h)
            try await allow(h, s)
            _ = try await fallbackHook(h, s)
            // Over the per-customer budget (3 per 10 minutes): three emails, three events; the fourth is suppressed and emits nothing.
            for _ in 0..<4 { _ = try await created(h, s, extra: emailExtra()) }
            try await h.runJobs()
            XCTAssertEqual(h.emails.messages(to: address).count, 3)
            try await eq(try await fallbackRows(h).count, 3)
            // The provider refuses: no email, no event.
            h.clock.advance(by: 3600)
            h.emails.setFailing(true)
            _ = try await created(h, s, extra: emailExtra())
            try await h.runJobs()
            h.emails.setFailing(false)
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == AuthEmailFallback.auditFailed).count(), 1)
            try await eq(try await fallbackRows(h).count, 3)
            // The tenant turned the policy off while the email was queued: suppressed at send time, no event.
            h.clock.advance(by: 3600)
            _ = try await created(h, s, extra: emailExtra())
            try await allow(h, s, false)
            try await h.runJobs()
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == AuthEmailFallback.auditSuppressed).count(), 2)
            try await eq(try await fallbackRows(h).count, 3)
            XCTAssertEqual(h.emails.messages(to: address).count, 3)
            // A delivery that did not ask for email never emits it.
            try await allow(h, s)
            _ = try await created(h, s)
            try await h.runJobs()
            try await eq(try await fallbackRows(h).count, 3)
        }
    }

    /// The development sender logs bodies so a developer can read a sign-up code; never one marked sensitive (the fallback code).
    func testTheDevelopmentSenderNeverLogsAFallbackCode() async throws {
        let message = AuthEmailFallback.message(to: address, business: "Northwind", code: "482913", expiresAt: Date(timeIntervalSince1970: 1_800_000_300))
        let handler = PlatformRound4Tests.CapturingLogHandler()
        try await LoggingEmailSender(environment: .development, logger: Logger(label: "t", factory: { _ in handler })).send(message)
        let logged = handler.lines.withLockedValue { $0 }.joined()
        XCTAssertFalse(logged.contains("482913"))
        XCTAssertFalse(logged.contains("pat@"))
        XCTAssertTrue(message.text.contains("Expires at 08:05 UTC on 2027-01-15"), message.text)
    }

    /// MailerSend v1: tracking off (no click rewriting, no open pixel, no content tracking) for the fallback email; unchanged for other mail.
    func testMailerSendTurnsTrackingOffForTheFallbackEmail() async throws {
        let app = try await Application.make(.testing)
        let client = PlatformRound4Tests.RecordingClient(eventLoop: app.eventLoopGroup.next())
        var config = EmailConfig(apiURL: URL(string: "https://api.mailersend.com/v1/email")!, apiKey: "mlsn.mail", fromAddress: "Viadere <no-reply@viadere.com>")
        config.format = .mailersend
        let sender = HTTPEmailSender(config: config, client: client)
        try await sender.send(AuthEmailFallback.message(to: address, business: "Northwind", code: "482913", expiresAt: Date()))
        try await sender.send(EmailMessage(to: address, subject: "Hi", text: "Body", kind: "x"))
        let requests = client.requests.withLockedValue { $0 }
        XCTAssertEqual(requests.count, 2)
        func json(_ request: ClientRequest) throws -> [String: Any] {
            var body = try XCTUnwrap(request.body)
            return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(body.readBytes(length: body.readableBytes) ?? [])) as? [String: Any])
        }
        XCTAssertEqual(try json(requests[0])["settings"] as? [String: Bool], ["track_clicks": false, "track_opens": false, "track_content": false])
        XCTAssertNil(try json(requests[1])["settings"])
        try await app.asyncShutdown()
    }

    // MARK: Budgets

    func testEmailBudgetsLimitTheEmailNotTheDelivery() async throws {
        try await fallbackHarness { h in
            let s = try await scene(h)
            try await allow(h, s)
            var ids: [AuthDeliveryID] = []
            for _ in 0..<4 { ids.append(try await created(h, s, extra: emailExtra()).id) }
            try await h.runJobs()
            // 3 per 10 minutes per customer: the fourth delivery exists and opens in the app, but no email was sent and no address was kept.
            XCTAssertEqual(h.emails.messages(to: address).count, 3)
            let suppressed = try await AuditEventRecord.query(on: h.db).filter(\.$action == AuthEmailFallback.auditSuppressed).all()
            XCTAssertEqual(suppressed.count, 1)
            XCTAssertTrue(suppressed[0].metadataJSON.contains("budget"), suppressed[0].metadataJSON)
            let last = try await AuthDeliveryRecord.find(ids[3].uuid, on: h.db)
            let lastPayload = await AuthDeliveryDeviceService(db: h.db, ctx: h.ctx).payload(try XCTUnwrap(last))
            XCTAssertNotNil(lastPayload?.code)
            XCTAssertNil(lastPayload?.emailAddress)
            let open = try await h.signed(s.consumer, .POST, "/v1/auth-deliveries/\(ids[3])/open")
            XCTAssertEqual(open.status, .ok, open.text)
        }
    }

    func testOneAddressIsLimitedAcrossCustomers() async throws {
        try await fallbackHarness { h in
            let s = try await scene(h)
            try await allow(h, s)
            let other = try await h.readyConsumer()
            _ = try await h.connect(other, to: s.b)
            let otherScene = Scene(b: s.b, consumer: other, subject: h.subjectRef(s.b, other), host: s.host)
            for _ in 0..<2 { _ = try await created(h, s, extra: emailExtra()) }
            for _ in 0..<2 { _ = try await created(h, otherScene, extra: emailExtra()) }
            try await h.runJobs()
            // Per address: at most 3 at once, whichever customer the business names.
            XCTAssertEqual(h.emails.messages(to: address).count, 3)
        }
    }

    func testEmailBudgetsFailClosedWhenTheSharedStoreIsDown() async {
        let store = DatabaseRateLimitStore(database: { nil })
        for name in ["authdl-email-tenant", "authdl-email-subject", "authdl-email-subject-day", "authdl-email-address"] {
            let decision = await store.take(key: "\(name)|k", rule: .perMinute(100), cost: 1, now: Date())
            XCTAssertFalse(decision.allowed, name)
        }
    }
}

private extension Bool {
    func isFalse(file: StaticString = #filePath, line: UInt = #line) { XCTAssertFalse(self, file: file, line: line) }
}
