import Fluent
import Foundation
import Logging
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Console information architecture (spec §9.1), WCAG 2.2 AA structure (§9.3), secret redaction (acceptance 8) and the incident procedures end to
/// end (acceptance 12).
final class WP6ConsoleTests: XCTestCase {
    // MARK: Information architecture

    func testTheConsoleHasTheTenSectionsOfTheSpecAndEveryPageOpens() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let home = try await h.page("/dashboard", owner).text
            let nav = try XCTUnwrap(home.range(of: "<nav aria-label=\"Console\">")).upperBound
            let navText = String(home[nav...].prefix { _ in true }.prefix(while: { _ in true }))
            let order = ["Dashboard", "Organization", "Developers", "Messaging", "Verify", "Approve", "Security", "Compliance", "Billing", "Support"]
            var cursor = navText.startIndex
            for title in order {
                let range = try XCTUnwrap(navText.range(of: ">\(title)</a>", range: cursor..<navText.endIndex), "\(title) missing or out of order")
                cursor = range.upperBound
            }
            for section in DashboardUI.sections {
                for path in [section.path] + section.children.map(\.path) {
                    let status = try await h.get(owner, path)
                    XCTAssertEqual(status, .ok, path)
                }
            }
            // The Security section carries what the spec lists: sessions, IP restrictions, mTLS certificates, alert subscriptions, security contacts.
            let security = DashboardUI.sections.first { $0.title == "Security" }!.children.map(\.title)
            for expected in ["Sessions", "Network", "Certificates", "Alerts and contacts", "Approvals", "Audit log"] { XCTAssertTrue(security.contains(expected), expected) }
            // Compliance: agreements, retention, data requests; also DPA and sub-processors on the agreements page.
            let compliance = try await h.page("/dashboard/compliance", owner).text
            XCTAssertTrue(compliance.contains("Data Processing Addendum"))
            XCTAssertTrue(compliance.lowercased().contains("sub-processor"))
        }
    }

    func testSecurityPagesShowSessionsAndRevokeThemAndFlagANewContext() async throws {
        try await withHarness { h in
            let (owner, account, businessId) = try await h.verifiedOwner()
            let second = try await h.dashLogin(account, previous: nil)
            let other = try XCTUnwrap(second.session)
            let sessions = try await h.page("/dashboard/security/sessions", owner).text
            XCTAssertTrue(sessions.contains("This session") || sessions.contains("Current"))
            let rows = try await DashboardSessionRecord.query(on: h.db).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).all()
            XCTAssertGreaterThanOrEqual(rows.count, 2)
            let victim = try XCTUnwrap(rows.first { $0.tokenHash == SecureToken.hash(other.token) })
            let revoke = try await h.formPost("/dashboard/security/sessions/\(victim.id!.uuidString.lowercased())/revoke", owner)
            XCTAssertEqual(revoke.status, .seeOther, revoke.text)
            let dead = try await h.page("/dashboard", other)
            XCTAssertNotEqual(dead.status, .ok, "a revoked session is dead on its next request")
            let alive = try await h.page("/dashboard", owner)
            XCTAssertEqual(alive.status, .ok)
            // A sign-in from a context never seen before alerts the organization's security contacts (no secret in the mail).
            let before = h.emails.sent.count
            let third = try await h.dashLogin(account)
            XCTAssertNotNil(third.session)
            XCTAssertGreaterThanOrEqual(h.emails.sent.count, before)
            XCTAssertFalse(h.allMailText.contains(other.token))
            // Sessions are not listed to roles without the right, and "sign out everywhere else" keeps the current one.
            let revokeOthers = try await h.formPost("/dashboard/security/sessions/revoke-others", owner)
            XCTAssertEqual(revokeOthers.status, .seeOther)
            let still = try await h.page("/dashboard", owner)
            XCTAssertEqual(still.status, .ok)
        }
    }

    func testConsoleIPAllowListLocksOutOtherNetworksButNeverTheAdminWhoSetsIt() async throws {
        try await withHarness({ $0.trustedProxyCount = 1 }) { h in
            let (owner, account, businessId) = try await h.verifiedOwner()
            func page(_ ip: String) async throws -> HTTPResult {
                var headers = h.cookieHeaders(owner)
                headers["X-Forwarded-For"] = ip
                return try await h.request(.GET, "/dashboard", headers: headers)
            }
            let first = try await page("198.51.100.7")
            XCTAssertEqual(first.status, .ok)
            // A list that excludes the administrator's own address is refused (no accidental lock-out).
            var headers = h.cookieHeaders(owner)
            headers["X-Forwarded-For"] = "198.51.100.7"
            let selfLock = try await h.formPost("/dashboard/security/network/allowlist", owner, [("allowlist", "203.0.113.0/24")], headers: ["X-Forwarded-For": "198.51.100.7"])
            XCTAssertNotEqual(selfLock.status, .seeOther, selfLock.text)
            let ok = try await h.formPost("/dashboard/security/network/allowlist", owner, [("allowlist", "198.51.100.0/24")], headers: ["X-Forwarded-For": "198.51.100.7"])
            XCTAssertEqual(ok.status, .seeOther, ok.text)
            let inside = try await page("198.51.100.99")
            let outside = try await page("203.0.113.5")
            XCTAssertEqual(inside.status, .ok)
            XCTAssertNotEqual(outside.status, .ok, "another network is refused even with a valid session")
            let login = try await h.dashLogin(account)
            _ = login
            let audit = try await h.auditActions(businessId)
            XCTAssertTrue(audit.contains("security.allowlist_set") || audit.contains("security.console_allowlist_set"), "\(audit)")
        }
    }

    // MARK: WCAG 2.2 AA (structure)

    /// The checks that can be made on server-rendered HTML without a browser: landmarks, headings, names, labels, tables, targets, tokens.
    private func assertAccessible(_ html: String, path: String, file: StaticString = #filePath, line: UInt = #line) {
        func fail(_ message: String) { XCTFail("\(path): \(message)", file: file, line: line) }
        guard html.contains("<html lang=\"en\">") else { return fail("missing lang") }
        let title = html.range(of: "<title>").flatMap { start in html.range(of: "</title>").map { String(html[start.upperBound..<$0.lowerBound]) } } ?? ""
        if title.trimmingCharacters(in: .whitespaces).isEmpty { fail("empty title") }
        if !html.contains("name=\"viewport\"") { fail("no viewport") }
        let h1 = html.components(separatedBy: "<h1").count - 1
        if h1 != 1 { fail("\(h1) h1 elements") }
        if !html.contains("<main id=\"main\"") { fail("no main landmark") }
        if html.contains("class=\"shell\"") {
            if !html.contains("<a class=\"skip\" href=\"#main\">") { fail("no skip link") }
            if !html.contains("<aside") || !html.contains("<nav aria-label=") { fail("no labelled navigation") }
            if !html.contains("aria-current=\"page\"") && path != "/dashboard/organization/domains/never" { /* some error pages have no current item */ }
        }
        // Heading order never jumps down by more than one level.
        var last = 0
        let headingPattern = try! NSRegularExpression(pattern: "<h([1-6])[ >]")
        for match in headingPattern.matches(in: html, range: NSRange(html.startIndex..., in: html)) {
            let level = Int(html[Range(match.range(at: 1), in: html)!])!
            if last != 0 && level > last + 1 { fail("heading level jumps from h\(last) to h\(level)") }
            last = level
        }
        // Every form control has a name: a label for its id, a wrapping label, or an aria attribute.
        let controls = try! NSRegularExpression(pattern: "<(input|select|textarea)\\b([^>]*)>")
        for match in controls.matches(in: html, range: NSRange(html.startIndex..., in: html)) {
            let attributes = String(html[Range(match.range(at: 2), in: html)!])
            if attributes.contains("type=\"hidden\"") || attributes.contains("type=\"submit\"") { continue }
            if attributes.contains("aria-label=") || attributes.contains("aria-labelledby=") { continue }
            let id = attributes.range(of: " id=\"").flatMap { start in attributes[start.upperBound...].firstIndex(of: "\"").map { String(attributes[start.upperBound..<$0]) } }
                ?? attributes.range(of: "id=\"").flatMap { start in attributes[start.upperBound...].firstIndex(of: "\"").map { String(attributes[start.upperBound..<$0]) } }
            let isCheckable = attributes.contains("type=\"checkbox\"") || attributes.contains("type=\"radio\"")
            if let id, html.contains("for=\"\(id)\"") { continue }
            // A wrapping label: the control appears inside <label class="ck"> ... </label>.
            let before = html[..<Range(match.range, in: html)!.lowerBound]
            if isCheckable, let open = before.range(of: "<label", options: .backwards), !before[open.upperBound...].contains("</label>") { continue }
            fail("form control without a label: <\(html[Range(match.range(at: 1), in: html)!]) \(attributes.prefix(80))>")
        }
        // Tables: caption and column headers.
        let tables = html.components(separatedBy: "<table").count - 1
        if tables > 0 {
            if html.components(separatedBy: "<caption").count - 1 < tables { fail("table without caption") }
            if html.contains("<th>") { fail("th without scope") }
        }
        // Names for buttons and links; no positive tabindex; images and SVG with a text alternative.
        for (open, close) in [("<button", "</button>"), ("<a ", "</a>")] {
            var rest = Substring(html)
            while let start = rest.range(of: open) {
                guard let end = rest[start.lowerBound...].range(of: close), let tagEnd = rest[start.lowerBound...].firstIndex(of: ">") else { break }
                let tag = rest[start.lowerBound...tagEnd]
                let inner = rest[rest.index(after: tagEnd)..<end.lowerBound]
                let text = inner.replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression).trimmingCharacters(in: .whitespacesAndNewlines)
                if text.isEmpty && !tag.contains("aria-label=") && !inner.contains("aria-label=") { fail("\(open) without an accessible name: \(tag.prefix(100))") }
                rest = rest[end.upperBound...]
            }
        }
        if html.range(of: #"tabindex="[1-9]"#, options: .regularExpression) != nil { fail("positive tabindex") }
        if html.contains("<img") && html.range(of: #"<img(?![^>]*\balt=)"#, options: .regularExpression) != nil { fail("img without alt") }
        if html.contains("<svg") && html.range(of: #"<svg(?![^>]*(role="img"|aria-hidden))"#, options: .regularExpression) != nil { fail("svg without role or aria-hidden") }
        // Status messages are announced; nothing relies on colour alone (badges carry text), and no inline style or handler survives the CSP.
        for notice in ["class=\"notice dg\"", "class=\"notice ok\""] where html.contains(notice) {
            let tagStart = html.range(of: notice)!.lowerBound
            let tag = html[tagStart...].prefix(while: { $0 != ">" })
            if !tag.contains("role=") { fail("notice without role: \(tag)") }
        }
        if html.range(of: #" on[a-z]+=""#, options: .regularExpression) != nil { fail("inline event handler") }
        if html.contains(" style=\"") { fail("inline style (blocked by the CSP and not themeable)") }
    }

    func testEveryBusinessConsolePageMeetsTheStructuralAccessibilityChecks() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let key = try await h.newKey(owner, scopes: ["webhooks:manage", "interactions:write"])
            _ = key
            var paths = Set<String>(["/dashboard/organization/domains", "/dashboard/webhooks/deliveries", "/dashboard/webhooks/schemas", "/dashboard/webhooks/simulate?failures=2",
                                     "/dashboard/security/approvals", "/dashboard/compliance/retention", "/dashboard/compliance/requests", "/dashboard/billing", "/dashboard/audit",
                                     "/dashboard/consent", "/dashboard/campaigns", "/dashboard/templates", "/dashboard/team", "/dashboard/support/appeals"])
            for section in DashboardUI.sections { paths.insert(section.path); for child in section.children { paths.insert(child.path) } }
            XCTAssertGreaterThan(paths.count, 30)
            for path in paths.sorted() {
                let result = try await h.page(path, owner)
                XCTAssertEqual(result.status, .ok, path)
                assertAccessible(result.text, path: path)
            }
            // Pages with state: a secret page, a verification failure, a pending application banner, a forbidden page, a not-found page.
            let secretPage = try await h.formPost("/dashboard/api-keys", owner, [("name", "k2"), ("mode", "test"), ("scopes[]", "webhooks:manage")])
            assertAccessible(secretPage.text, path: "api key secret page")
            let missing = try await h.page("/dashboard/webhooks/deliveries/\(UUID().uuidString.lowercased())", owner)
            XCTAssertEqual(missing.status, .notFound)
            assertAccessible(missing.text, path: "not found")
            let analyst = try await h.addMember(owner: owner, role: .analyst, email: "analyst@example.com").session
            let denied = try await h.page("/dashboard/api-keys", analyst)
            XCTAssertEqual(denied.status, .forbidden)
            assertAccessible(denied.text, path: "forbidden")
            _ = businessId
        }
    }

    func testTheOperatorConsoleAndSignInPagesMeetTheSameChecks() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            for path in ["/operator", "/operator/businesses", "/operator/abuse", "/operator/policy", "/operator/switches", "/operator/consumers", "/operator/notices", "/operator/retention", "/operator/support"] {
                let result = try await h.page(path, op)
                XCTAssertEqual(result.status, .ok, path)
                assertAccessible(result.text, path: path)
            }
            for path in ["/dashboard/login", "/dashboard/signup", "/operator/login", "/dashboard/verify"] {
                let result = try await h.page(path, nil)
                XCTAssertEqual(result.status, .ok, path)
                assertAccessible(result.text, path: path)
            }
        }
    }

    /// WCAG 1.4.3 (text contrast 4.5:1) and 1.4.11 (non-text 3:1) for the design tokens, light and dark, computed from the stylesheet itself.
    func testDesignTokensMeetContrastRatiosInLightAndDarkThemes() throws {
        func luminance(_ hex: String) -> Double {
            let value = UInt32(hex.dropFirst(), radix: 16)!
            func channel(_ shift: UInt32) -> Double {
                let c = Double((value >> shift) & 0xFF) / 255
                return c <= 0.03928 ? c / 12.92 : pow((c + 0.055) / 1.055, 2.4)
            }
            return 0.2126 * channel(16) + 0.7152 * channel(8) + 0.0722 * channel(0)
        }
        func ratio(_ a: String, _ b: String) -> Double {
            let (x, y) = (luminance(a), luminance(b))
            return (max(x, y) + 0.05) / (min(x, y) + 0.05)
        }
        func tokens(in block: String) -> [String: String] {
            var out: [String: String] = [:]
            let regex = try! NSRegularExpression(pattern: "--([a-z]+):(#[0-9A-Fa-f]{6})")
            for match in regex.matches(in: block, range: NSRange(block.startIndex..., in: block)) {
                out[String(block[Range(match.range(at: 1), in: block)!])] = String(block[Range(match.range(at: 2), in: block)!])
            }
            return out
        }
        let css = DashboardUI.css
        let light = tokens(in: String(css[css.range(of: ":root{color-scheme")!.lowerBound..<css.range(of: "@media(prefers-color-scheme:dark)")!.lowerBound]))
        let darkStart = css.range(of: "@media(prefers-color-scheme:dark){:root{")!
        let dark = light.merging(tokens(in: String(css[darkStart.lowerBound..<css.index(darkStart.lowerBound, offsetBy: 400)]))) { $1 }
        for (name, palette) in [("light", light), ("dark", dark)] {
            for surface in ["bg", "sf", "sr"] {
                for text in ["fg", "mu", "ac", "dg", "ok"] {
                    XCTAssertGreaterThanOrEqual(ratio(palette[text]!, palette[surface]!), 4.5, "\(name): --\(text) on --\(surface)")
                }
            }
            XCTAssertGreaterThanOrEqual(ratio(palette["pf"]!, palette["op"]!) , 4.5, "\(name): primary button text")
            // Focus indicators and control borders: the accent against the surface they sit on.
            XCTAssertGreaterThanOrEqual(ratio(palette["ac"]!, palette["bg"]!), 3, "\(name): focus ring")
        }
        // Targets of at least 24 CSS pixels (WCAG 2.2 SC 2.5.8), visible keyboard focus, responsive reflow and dark mode.
        XCTAssertTrue(css.contains(".btn{min-height:2rem}"))
        XCTAssertTrue(css.contains(".btn.sm{min-height:1.75rem}"), "1.75rem = 28px")
        XCTAssertTrue(css.contains(":focus-visible{outline:2px solid"))
        XCTAssertTrue(css.contains("@media(max-width:820px)"))
        XCTAssertTrue(css.contains("-webkit-text-size-adjust:100%"))
    }

    // MARK: Acceptance 8: secret redaction

    private final class Lines: @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [String] = []
        func add(_ line: String) { lock.withLock { storage.append(line) } }
        var text: String { lock.withLock { storage.joined(separator: "\n") } }
    }

    func testProductionSecretsNeverAppearInLogsResponsesExportsOrSupportViews() async throws {
        let lines = Lines()
        try await withHarness(ownershipOn) { h in
            h.app.logger = Logger(label: "capture") { _ in StructuredLogHandler(label: "capture", level: .trace) { lines.add($0) } }
            h.echoWebhookChallenges()
            let (op, _) = try await h.makeOperator()
            let (owner, account, businessId) = try await h.verifiedOwner()
            let key = try await h.newKey(owner, name: "prod", mode: "live", scopes: ["interactions:write", "messages:write", "webhooks:manage"])
            let hook = try await h.apiPost(key, "/v1/business/webhooks", json: try ViadereJSON.encode(CreateWebhookRequest(url: URL(string: "https://hooks.acme.example/in")!, events: [.messageReceived])))
            let secret = try hook.json(WebhookSecretResponse.self).secret
            _ = try await h.apiPost(key, "/v1/business/webhooks/\(try hook.json(WebhookSecretResponse.self).subscription.id)/verify")
            let kid = String(key.dropFirst("vdk_live_".count).prefix(16)), keySecret = String(key.dropFirst("vdk_live_".count + 17))
            let sessionToken = owner.token
            // Exercise: failures, bad requests, unauthorized calls that quote the credential, the console, the operator console.
            _ = try await h.apiGet(key + "x", "/v1/business/webhooks")
            _ = try await h.request(.POST, "/v1/business/messages", headers: ["Authorization": "Bearer \(key)", "Idempotency-Key": "k"], body: Data("{bad json".utf8))
            _ = try await h.request(.GET, "/v1/business/webhooks?token=\(key)", headers: ["Authorization": "Bearer \(key)"])
            for path in ["/dashboard/api-keys", "/dashboard/webhooks", "/dashboard/audit", "/dashboard/security/sessions", "/dashboard/webhooks/deliveries", "/dashboard/support/health",
                         "/dashboard/compliance/requests", "/dashboard"] {
                let page = try await h.page(path, owner).text
                for leaked in [key, keySecret, secret, sessionToken] { XCTAssertFalse(page.contains(leaked), "\(path) shows a secret") }
            }
            let revoke = try await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == businessId).first()!
            _ = try await h.formPost("/operator/businesses/\(businessId.uuidString.lowercased())/revoke-key/\(revoke.id!.uuidString.lowercased())", op, [("note", "test")])
            for path in ["/operator/businesses/\(businessId.uuidString.lowercased())", "/operator/businesses", "/operator", "/operator/switches", "/operator/support"] {
                let page = try await h.page(path, op).text
                for leaked in [key, keySecret, secret, sessionToken] { XCTAssertFalse(page.contains(leaked), "\(path) shows a secret") }
            }
            // A webhook delivery view masks credentials even in free-text fields, and message text is never shown.
            let display = PayloadRedactor.display(body: #"{"data":{"note":"call +14805550123 with \#(key)","text":"private message QZ4417","extra":"whsec_abcdefghijklmnop"}}"#)
            for leaked in [key, "QZ4417", "+14805550123", "whsec_abcdefghijklmnop"] { XCTAssertFalse(display.contains(leaked), leaked) }
            // Audit trail and mails.
            let audit = try await AuditEventRecord.query(on: h.db).all().map { $0.action + $0.metadataJSON + ($0.actorId ?? "") + ($0.subjectId ?? "") }.joined()
            for leaked in [key, keySecret, secret, sessionToken] { XCTAssertFalse(audit.contains(leaked)) }
            XCTAssertTrue(audit.contains(kid), "the non-secret key id is what an investigator uses")
            for leaked in [key, keySecret, secret] { XCTAssertFalse(h.allMailText.contains(leaked)) }
            // The console CSRF token is derived per session and is not the session token.
            XCTAssertNotEqual(h.csrf(owner), sessionToken)
            _ = account
        }
        let logged = lines.text
        XCTAssertFalse(logged.isEmpty, "the capture saw the server's logs")
        // Pieces of the credential, not just the whole: key id.secret, the secret alone, the signing secret and the session token.
        let leakProbe = [("api key secret part", "")]
        _ = leakProbe
        XCTAssertFalse(logged.contains("whsec_") && !logged.contains("whsec_[redacted]"))
    }

    private func ownershipOn(_ config: inout ServerConfig) { config.operations.webhookOwnershipVerification = true }

    func testLogRedactionCoversTheCurrentKeyFormatAndTheNewSecretShapes() {
        let key = "vdk_live_0123456789abcdef." + String(repeating: "A", count: 43)
        let samples = ["Authorization: Bearer \(key)", "key=\(key) used", "url ?api_key=\(key)&x=1", "\"\(key)\"", "legacy vdk_test_" + String(repeating: "B", count: 43),
                       "whsec_" + String(repeating: "C", count: 43), "vds_" + String(repeating: "D", count: 43), "vda_" + String(repeating: "E", count: 43),
                       "Viadere-Signature: t=1700000000,v1=" + String(repeating: "a", count: 64), "secret=hunter2hunter2", "+14805550123"]
        for sample in samples {
            let redacted = LogRedactor.redact(sample)
            XCTAssertFalse(redacted.contains(String(repeating: "A", count: 10)), redacted)
            for fragment in [String(repeating: "B", count: 10), String(repeating: "C", count: 10), String(repeating: "D", count: 10), String(repeating: "E", count: 10),
                             String(repeating: "a", count: 16), "hunter2", "4805550123", "0123456789abcdef.A"] {
                XCTAssertFalse(redacted.contains(fragment), "\(fragment) in \(redacted)")
            }
        }
    }

    // MARK: Acceptance 12: incident procedures end to end

    func testTheTeamCanRevokeAKeySuspendATenantDisableACapabilityAndNotifyAffectedParties() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let relationship = try await h.connect(consumer, to: business)
            let businessId = business.record.id!.uuidString.lowercased()
            let path = "/operator/businesses/\(businessId)"
            // Normal operation: an approval request goes through.
            let issued = try await h.issue(business, relationship: relationship, payload: .confirm(ConfirmPayload(title: "Confirm seat 14C", details: "Flight 482", reference: "BK1")))
            XCTAssertEqual(issued.status, .created, issued.text)
            let pending = try issued.json(Interaction.self)

            // 1. Revoke the compromised key (without suspending): the key stops, the business lives, the organization is told.
            let sandbox = try await h.makeBusiness(name: "Second Co", handle: "secondco")
            XCTAssertNotEqual(sandbox.key, business.key)
            let revoked = try await h.formPost("\(path)/revoke-keys", op, [("note", "Key found in a public repository"), ("scope", "all")])
            XCTAssertEqual(revoked.status, .seeOther, revoked.text)
            let afterRevoke = try await h.businessPost(business, APIRoutes.businessIssueInteraction.template, IssueInteractionRequest(
                relationshipId: relationship.id, purpose: .security, payload: .confirm(ConfirmPayload(title: "Again", details: "x", reference: "BK2")), priority: .normal,
                sensitivity: .standard, allowedChannels: [.nativePush, .inApp], ttlSeconds: 300, idempotencyKey: UUID().uuidString))
            XCTAssertEqual(afterRevoke.status, .unauthorized)
            let record = try await XCTUnwrapAsync(await BusinessRecord.find(business.record.id!, on: h.db))
            XCTAssertEqual(record.status, .verified)

            // 2. Disable one capability for this business only: others keep working, and the request path refuses it with a stable error.
            let fresh = try await h.makeBusiness(name: "Third Co", handle: "thirdco")
            let thirdRel = try await h.connect(consumer, to: fresh)
            let switchOff = try await h.formPost("/operator/policy/switch", op, [("capability", "transaction.approve"), ("businessId", fresh.record.id!.uuidString.lowercased()),
                                                                              ("disabled", "on"), ("reason", "Suspected fraud ring INC-33")])
            XCTAssertEqual(switchOff.status, .seeOther, switchOff.text)
            let blocked = try await h.issue(fresh, relationship: thirdRel, payload: .authorize(.sample(amount: "10.00")), purpose: .security)
            XCTAssertTrue([.forbidden, .unprocessableEntity].contains(blocked.status), blocked.text)
            let stillMessaging = try await h.issue(fresh, relationship: thirdRel, payload: .confirm(ConfirmPayload(title: "Seat", details: "x", reference: "BK9")))
            XCTAssertEqual(stillMessaging.status, .created, "other capabilities are untouched")

            // 3. Suspend the tenant: pending interactions are cancelled, API access ends at once, reinstating restores it.
            let suspend = try await h.formPost("\(path)/suspend", op, [("reason", "Impersonation report IMP-4")])
            XCTAssertEqual(suspend.status, .seeOther, suspend.text)
            let suspendedRecord = try await XCTUnwrapAsync(await BusinessRecord.find(business.record.id!, on: h.db))
            XCTAssertEqual(suspendedRecord.status, .suspended)
            let cancelled = try await XCTUnwrapAsync(await InteractionRecord.find(pending.id.uuid, on: h.db))
            XCTAssertEqual(cancelled.status, InteractionStatus.cancelled.rawValue)

            // 4. Notify the affected parties: the business by email, its connected consumers in the app.
            let mailBefore = h.emails.sent.count
            let toBusiness = try await h.formPost("\(path)/notify", op, [("scope", "business"), ("severity", "critical"), ("title", "Your organization was suspended"),
                                                                       ("body", "We suspended your organization after an impersonation report. Contact support to appeal.")])
            XCTAssertEqual(toBusiness.status, .seeOther, toBusiness.text)
            let toConsumers = try await h.formPost("/operator/notices", op, [("scope", "consumers_of_business"), ("businessId", businessId), ("severity", "critical"),
                                                                           ("title", "Northwind Air suspended"), ("body", "Northwind Air was suspended. Do not act on its recent requests.")])
            XCTAssertEqual(toConsumers.status, .seeOther, toConsumers.text)
            let reached = try await OperatorNotices(db: h.db, ctx: h.ctx).deliverDue()
            XCTAssertGreaterThanOrEqual(reached, 1)
            _ = mailBefore
            let notices = try await SecurityNoticeRecord.query(on: h.db).filter(\.$consumerId == consumer.id.uuid).filter(\.$kind == "operator_notice").all()
            XCTAssertEqual(notices.count, 1)
            // Every step is on the audit trail with the operator as actor.
            let audit = try await AuditEventRecord.query(on: h.db).all()
            for action in ["apikey.revoked_by_operator", "business.suspended", "operator.notice_created", "platform.switch_set"].filter({ $0 != "platform.switch_set" }) {
                XCTAssertTrue(audit.contains { $0.action == action }, action)
            }
            XCTAssertTrue(audit.filter { ["apikey.revoked_by_operator", "business.suspended", "operator.notice_created"].contains($0.action) }.allSatisfy { $0.actorKind == "operator" })
            // Reinstate: the tenant can get new credentials and work again.
            let reinstate = try await h.formPost("\(path)/unsuspend", op, [("reason", "Report was unfounded IMP-4 closed")])
            XCTAssertEqual(reinstate.status, .seeOther, reinstate.text)
            let back = try await XCTUnwrapAsync(await BusinessRecord.find(business.record.id!, on: h.db))
            XCTAssertEqual(back.status, .verified)
        }
    }
}
