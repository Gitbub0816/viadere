import Fluent
import Foundation
import Logging
import Vapor
import ViadereCore
import struct ViadereCore.Page
import XCTest
@testable import ViadereServerKit

/// G5 console conversation inbox (docs/SECURITY.md §2.108). Exploit paths first: cross-tenant reads and actions, a viewer replying, a
/// downgraded member keeping access, a double-submitted reply sending twice, message bodies leaking into audit or logs, and customer HTML
/// running in the console.
final class ConsoleConversationsTests: XCTestCase {
    static let secretBody = "My locker code is QZ-77114 <script>alert('pwn')</script><img src=x onerror=alert(1)>"

    struct Tenant {
        var owner: DashSession
        var account: DashAccount
        var businessId: UUID
        var business: TestBusiness
        var consumer: TestConsumer
        var session: UUID
    }

    /// An organization from the console with one connected customer who wrote a message.
    static func tenant(_ h: TestHarness, email: String = "owner@example.com", org: String = "Acme Roasters", handle: String = "acmeroasters",
                       body: String = secretBody) async throws -> Tenant {
        let (owner, account, businessId) = try await h.verifiedOwner(email: email, org: org, handle: handle)
        let business = try await h.testBusiness(businessId)
        let consumer = try await h.readyConsumer()
        _ = try await h.connect(consumer, to: business, optIn: [.support])
        let started = try await h.signedPost(consumer, APIRoutes.conversationStart.template, StartConversationRequest(businessId: business.id))
        XCTAssertEqual(started.status, .ok, started.text)
        let session = try started.json(ConversationSummary.self).id
        let sent = try await h.signedPost(consumer, "/v1/conversations/\(session)/messages", SendMessageRequest(body: body, clientMessageId: "c-\(UUID().uuidString)"))
        XCTAssertEqual(sent.status, .created, sent.text)
        return Tenant(owner: owner, account: account, businessId: businessId, business: business, consumer: consumer, session: session.uuid)
    }

    private func threadPath(_ id: UUID) -> String { "/dashboard/conversations/\(id.uuidString.lowercased())" }

    private func replyKey(_ html: String) throws -> String {
        let range = try XCTUnwrap(html.range(of: "name=\"idempotency_key\" value=\""))
        return String(html[range.upperBound...].prefix { $0 != "\"" })
    }

    func testAnotherTenantsThreadIsNotFoundForTheListTheThreadAReplyAndEveryAction() async throws {
        try await withHarness { h in
            let a = try await Self.tenant(h)
            let b = try await Self.tenant(h, email: "other@example.com", org: "Other Shop", handle: "othershop", body: "Other tenant's private words ZX-4410")
            let list = try await h.page("/dashboard/conversations", a.owner)
            XCTAssertEqual(list.status, .ok, list.text)
            XCTAssertTrue(list.text.contains(threadPath(a.session)))
            XCTAssertFalse(list.text.contains(b.session.uuidString.lowercased()))
            XCTAssertFalse(list.text.contains("ZX-4410"))
            try await eq(try await h.page(threadPath(b.session), a.owner).status, .notFound)
            try await eq(try await h.page(threadPath(UUID()), a.owner).status, .notFound)
            for (action, form) in [("reply", [("body", "Hi from A"), ("idempotency_key", "k" + String(repeating: "a", count: 20))]),
                                   ("assign", [("assignee", "none")]), ("close", []), ("reopen", [])] {
                let response = try await h.formPost("\(threadPath(b.session))/\(action)", a.owner, form)
                XCTAssertEqual(response.status, .notFound, "\(action): \(response.text)")
            }
            // Nothing was written to the other tenant's thread, and no read of it was recorded for A.
            try await eq(try await ConversationMessageRecord.query(on: h.db).filter(\.$sessionId == b.session).count(), 1)
            try await eq(try await ConversationConsoleReadRecord.query(on: h.db).filter(\.$sessionId == b.session).count(), 0)
            try await eq(try await ConversationConsoleStateRecord.query(on: h.db).filter(\.$sessionId == b.session).count(), 0)
            try await eq(try await ConversationSessionRecord.find(b.session, on: h.db)?.state, "open")
            // A member of A assigned to B's thread does not exist either way: assigning someone from another organization is refused.
            let thread = try await h.page(threadPath(a.session), a.owner)
            XCTAssertEqual(thread.status, .ok, thread.text)
            let foreign = try await DashboardUserRecord.query(on: h.db).filter(\.$id != a.account.userId).first()!.id!
            try await eq(try await h.formPost("\(threadPath(a.session))/assign", a.owner, [("assignee", foreign.uuidString)]).status, .unprocessableEntity)
        }
    }

    func testAViewerCannotReplyAndARoleDowngradeTakesEffectOnTheNextRequest() async throws {
        try await withHarness { h in
            let t = try await Self.tenant(h)
            let auditor = try await h.addMember(owner: t.owner, role: .auditor, email: "auditor@example.com")
            let operatorMember = try await h.addMember(owner: t.owner, role: .messagingOperator, email: "ops@example.com", name: "Sam Operator")
            let developer = try await h.addMember(owner: t.owner, role: .developer, email: "dev@example.com")
            // A role without the permission sees neither the list nor a thread.
            try await eq(try await h.page("/dashboard/conversations", developer.session).status, .forbidden)
            try await eq(try await h.page(threadPath(t.session), developer.session).status, .forbidden)
            // The viewer reads but has no reply form and every action is refused.
            let viewed = try await h.page(threadPath(t.session), auditor.session)
            XCTAssertEqual(viewed.status, .ok, viewed.text)
            XCTAssertFalse(viewed.text.contains("idempotency_key"))
            for (action, form) in [("reply", [("body", "Not allowed"), ("idempotency_key", String(repeating: "b", count: 24))]),
                                   ("assign", [("assignee", "none")]), ("close", [])] {
                try await eq(try await h.formPost("\(threadPath(t.session))/\(action)", auditor.session, form).status, .forbidden)
            }
            // The operator replies...
            let page = try await h.page(threadPath(t.session), operatorMember.session)
            let reply = try await h.formPost("\(threadPath(t.session))/reply", operatorMember.session, [("body", "We have it."), ("idempotency_key", try replyKey(page.text))])
            XCTAssertEqual(reply.status, .seeOther, reply.text)
            // ...until downgraded: the next request is refused, without a new sign-in.
            try await OrgMembershipRecord.query(on: h.db).filter(\.$businessId == t.businessId).filter(\.$userId == operatorMember.account.userId)
                .set(\.$role, to: OrgRole.analyst.rawValue).update()
            try await eq(try await h.formPost("\(threadPath(t.session))/reply", operatorMember.session, [("body", "Again"), ("idempotency_key", String(repeating: "c", count: 24))]).status, .forbidden)
            try await eq(try await h.page(threadPath(t.session), operatorMember.session).status, .forbidden)
            try await eq(try await ConversationMessageRecord.query(on: h.db).filter(\.$sessionId == t.session)
                .filter(\.$direction == MessageDirection.businessToConsumer.rawValue).count(), 1)
        }
    }

    func testARepliesGoesThroughTheBusinessSendPathAndIsIdempotent() async throws {
        try await withHarness { h in
            let t = try await Self.tenant(h)
            let page = try await h.page(threadPath(t.session), t.owner)
            let key = try replyKey(page.text)
            let form = [("body", "Your table is ready."), ("agent_name", "Sam"), ("idempotency_key", key)]
            let first = try await h.formPost("\(threadPath(t.session))/reply", t.owner, form)
            XCTAssertEqual(first.status, .seeOther, first.text)
            XCTAssertTrue(first.headers.first(name: .location)?.contains("cm=sent") == true)
            // The same form submitted again (double click, resubmission) sends nothing new.
            let again = try await h.formPost("\(threadPath(t.session))/reply", t.owner, form)
            XCTAssertEqual(again.status, .seeOther, again.text)
            XCTAssertTrue(again.headers.first(name: .location)?.contains("cm=duplicate") == true)
            let sent = try await ConversationMessageRecord.query(on: h.db).filter(\.$sessionId == t.session)
                .filter(\.$direction == MessageDirection.businessToConsumer.rawValue).all()
            XCTAssertEqual(sent.count, 1)
            // The same key with a different body is the API's idempotency conflict.
            let conflict = try await h.formPost("\(threadPath(t.session))/reply", t.owner, [("body", "Something else"), ("idempotency_key", key)])
            XCTAssertEqual(conflict.status, .conflict, conflict.text)
            // A key the page did not generate is refused before anything is stored.
            try await eq(try await h.formPost("\(threadPath(t.session))/reply", t.owner, [("body", "x"), ("idempotency_key", "short")]).status, .unprocessableEntity)
            // The same validation as the API: an empty or oversized body is refused.
            try await eq(try await h.formPost("\(threadPath(t.session))/reply", t.owner, [("body", "   "), ("idempotency_key", String(repeating: "d", count: 24))]).status, .unprocessableEntity)
            try await eq(try await h.formPost("\(threadPath(t.session))/reply", t.owner, [("body", String(repeating: "x", count: 1601)), ("idempotency_key", String(repeating: "e", count: 24))]).status, .unprocessableEntity)
            // Attribution: the verified business name and the agent name, as the API sets it; the customer reads it in their thread.
            let messages = try await h.signed(t.consumer, .GET, "/v1/conversations/\(t.session.uuidString.lowercased())/messages")
            let page2 = try messages.json(Page<ConversationMessage>.self)
            let reply = try XCTUnwrap(page2.items.first { $0.direction == .businessToConsumer })
            XCTAssertEqual(reply.body, "Your table is ready.")
            XCTAssertEqual(reply.attribution.displayName, "Acme Roasters")
            XCTAssertEqual(reply.attribution.agentName, "Sam")
            XCTAssertEqual(reply.attribution.senderType, .agent)
            // The audit chain names the console user, not an API key.
            let audit = try await XCTUnwrapAsync(await AuditEventRecord.query(on: h.db).filter(\.$action == "message.business_sent").first())
            XCTAssertEqual(audit.actorKind, AuditActor.Kind.business.rawValue)
            XCTAssertEqual(audit.actorId, t.account.userId.uuidString.lowercased())
            XCTAssertTrue(audit.metadataJSON.contains("console"))
            // The thread shows who on the team sent it.
            let thread = try await h.page(threadPath(t.session), t.owner)
            XCTAssertTrue(thread.text.contains("sent by"), thread.text)
            // A closed conversation takes no reply until reopened.
            try await eq(try await h.formPost("\(threadPath(t.session))/close", t.owner).status, .seeOther)
            let closed = try await h.formPost("\(threadPath(t.session))/reply", t.owner, [("body", "Late"), ("idempotency_key", String(repeating: "f", count: 24))])
            XCTAssertEqual(closed.status, .conflict, closed.text)
            try await eq(try await h.formPost("\(threadPath(t.session))/reopen", t.owner).status, .seeOther)
            try await eq(try await ConversationSessionRecord.find(t.session, on: h.db)?.state, "open")
            for action in ["conversation.closed", "conversation.reopened"] {
                try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == action).count(), 1)
            }
        }
    }

    final class Lines: @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [String] = []
        func add(_ line: String) { lock.withLock { storage.append(line) } }
        var text: String { lock.withLock { storage.joined(separator: "\n") } }
    }

    func testBodiesNeverAppearInTheAuditChainOrTheLogsAndEveryReadIsAudited() async throws {
        let lines = Lines()
        try await withHarness { h in
            h.app.logger = Logger(label: "capture") { _ in StructuredLogHandler(label: "capture", level: .trace) { lines.add($0) } }
            let t = try await Self.tenant(h)
            _ = try await h.page("/dashboard/conversations", t.owner)
            let page = try await h.page(threadPath(t.session), t.owner)
            XCTAssertTrue(page.text.contains("QZ-77114"), "the owning tenant reads the body")
            _ = try await h.formPost("\(threadPath(t.session))/reply", t.owner, [("body", "Reply secret RT-55821"), ("idempotency_key", try replyKey(page.text))])
            _ = try await h.page(threadPath(t.session), t.owner)
            let reads = try await AuditEventRecord.query(on: h.db).filter(\.$action == "conversation.console_read").all()
            XCTAssertEqual(reads.count, 2)
            XCTAssertTrue(reads.allSatisfy { $0.subjectId == t.session.uuidString.lowercased() && $0.actorId == t.account.userId.uuidString.lowercased() })
            for event in try await AuditEventRecord.query(on: h.db).all() {
                for text in [event.metadataJSON, event.subjectId ?? "", event.actorId ?? ""] {
                    XCTAssertFalse(text.contains("QZ-77114") || text.contains("RT-55821"), "\(event.action): \(text)")
                }
            }
            XCTAssertFalse(lines.text.contains("QZ-77114"))
            XCTAssertFalse(lines.text.contains("RT-55821"))
            // At rest the bodies are field-encrypted.
            for row in try await ConversationMessageRecord.query(on: h.db).all() {
                XCTAssertFalse(row.bodyCiphertext.contains("QZ-77114") || row.bodyCiphertext.contains("RT-55821"))
            }
        }
    }

    func testCustomerHTMLIsInertAndTheCustomerAppearsOnlyAsTheBusinessReference() async throws {
        try await withHarness { h in
            let t = try await Self.tenant(h)
            let pages = [try await h.page("/dashboard/conversations", t.owner).text, try await h.page(threadPath(t.session), t.owner).text]
            let thread = pages[1]
            XCTAssertFalse(thread.contains("<script>alert"), "customer markup is escaped")
            XCTAssertFalse(thread.contains("<img src=x"))
            XCTAssertTrue(thread.contains("&lt;script&gt;alert("), thread)
            // The page CSP never allows inline script, so even a missed escape could not run.
            let csp = try await h.page(threadPath(t.session), t.owner).headers.first(name: "Content-Security-Policy") ?? ""
            XCTAssertFalse(csp.contains("unsafe-inline"))
            XCTAssertFalse(csp.contains("script-src"), "no script on this page at all")
            let ref = h.ctx.subjects.subjectRef(businessId: BusinessID(t.businessId), consumerId: t.consumer.id).rawValue
            XCTAssertTrue(thread.contains(ref))
            for page in pages {
                XCTAssertFalse(page.contains(t.consumer.id.uuid.uuidString.lowercased()), "never the Viadere account id")
                XCTAssertFalse(page.contains(t.consumer.id.uuid.uuidString.uppercased()))
                XCTAssertFalse(page.contains("Test User"), "never the account's name")
            }
            // Unread for this member until opened; assignment to a teammate who can read conversations.
            let ops = try await h.addMember(owner: t.owner, role: .messagingOperator, email: "ops@example.com", name: "Sam Operator")
            let unread = try await h.page("/dashboard/conversations?view=unread", ops.session)
            XCTAssertTrue(unread.text.contains(threadPath(t.session)))
            _ = try await h.page(threadPath(t.session), ops.session)
            try await isFalse(try await h.page("/dashboard/conversations?view=unread", ops.session).text.contains(threadPath(t.session)))
            try await eq(try await h.formPost("\(threadPath(t.session))/assign", t.owner, [("assignee", ops.account.userId.uuidString)]).status, .seeOther)
            try await isTrue(try await h.page("/dashboard/conversations?view=mine", ops.session).text.contains(threadPath(t.session)))
            let analyst = try await h.addMember(owner: t.owner, role: .analyst, email: "analyst@example.com")
            try await eq(try await h.formPost("\(threadPath(t.session))/assign", t.owner, [("assignee", analyst.account.userId.uuidString)]).status, .unprocessableEntity)
        }
    }

    func testReplyingToARealCustomerNeedsProductionAccess() async throws {
        try await withHarness { h in
            let t = try await Self.tenant(h)
            // Production access withdrawn (go-live not approved): a live customer cannot be answered from the console, like a live key.
            try await BusinessOnboardingRecord.query(on: h.db).filter(\.$businessId == t.businessId).set(\.$goLiveStatus, to: OnboardingGoLive.requested.rawValue).update()
            let page = try await h.page(threadPath(t.session), t.owner)
            let refused = try await h.formPost("\(threadPath(t.session))/reply", t.owner, [("body", "Hello"), ("idempotency_key", try replyKey(page.text))])
            XCTAssertEqual(refused.status, .forbidden, refused.text)
            try await eq(try await ConversationMessageRecord.query(on: h.db).filter(\.$direction == MessageDirection.businessToConsumer.rawValue).count(), 0)
        }
    }
}
