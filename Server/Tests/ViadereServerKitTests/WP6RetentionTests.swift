import Fluent
import FluentSQL
import SQLKit
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Retention by data class with bounds, tenant shortening and legal holds (LEG-PR-006), the append-only gate, and the audit-event purge that
/// keeps the chain verifiable.
final class WP6RetentionTests: XCTestCase {
    private func days(_ n: Int) -> TimeInterval { Double(n) * 86_400 }

    // MARK: Configuration

    func testEveryDataClassHasBoundsAndDefaultsInsideThem() {
        for cls in RetentionClass.allCases {
            let d = cls.definition
            XCTAssertLessThanOrEqual(d.minDays, d.defaultDays, "\(cls)")
            XCTAssertLessThanOrEqual(d.defaultDays, d.maxDays, "\(cls)")
            XCTAssertGreaterThan(d.minDays, 0)
            XCTAssertFalse(d.summary.isEmpty)
            XCTAssertFalse(d.tables.isEmpty)
        }
        // Evidence classes have a floor of at least a year; credentials never wait that long.
        for cls in [RetentionClass.signedDecisions, .consentHistory, .auditEvents] { XCTAssertGreaterThanOrEqual(cls.definition.minDays, 365, "\(cls)") }
        XCTAssertLessThanOrEqual(RetentionClass.linkTokens.definition.maxDays, 90)
        XCTAssertEqual(Set(RetentionClass.allCases.filter(\.definition.tenantAdjustable)), [.interactionContent, .conversationContent, .webhookDeliveries])
        // Legal-hold exemptions are only for short-lived security artefacts.
        XCTAssertEqual(Set(RetentionClass.allCases.filter { !$0.definition.holdable }), [.linkTokens, .securityTokens, .channelCapability, .securityNotices])
    }

    func testPlatformValuesStayInsideTheBoundsAndTenantsCanOnlyShorten() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            let (owner, _, businessId) = try await h.verifiedOwner()
            let policy = RetentionPolicy(db: h.db, ctx: h.ctx)
            let platformDefault = try await policy.platformDays(.webhookDeliveries)
            XCTAssertEqual(platformDefault, h.ctx.config.retention.webhookDeliveryDays)
            // Operator: inside the bounds with a reason; outside them, or without one, refused and unchanged.
            let ok = try await h.formPost("/operator/retention/webhook_deliveries", op, [("days", "14"), ("reason", "Shorter window agreed with counsel")])
            XCTAssertEqual(ok.status, .seeOther, ok.text)
            let tooLong = try await h.formPost("/operator/retention/webhook_deliveries", op, [("days", "4000"), ("reason", "Keep everything for ever please")])
            let noReason = try await h.formPost("/operator/retention/webhook_deliveries", op, [("days", "20"), ("reason", "")])
            let belowFloor = try await h.formPost("/operator/retention/signed_decisions", op, [("days", "5"), ("reason", "Delete the evidence early please")])
            for refused in [tooLong, noReason, belowFloor] { XCTAssertNotEqual(refused.status, .seeOther) }
            let now14 = try await policy.platformDays(.webhookDeliveries)
            XCTAssertEqual(now14, 14)
            let floor = try await policy.platformDays(.signedDecisions)
            XCTAssertEqual(floor, RetentionClass.signedDecisions.definition.defaultDays)
            // Tenant: may shorten its own adjustable classes (never lengthen), may not touch evidence classes, can clear back to the platform value.
            let shorter = try await h.formPost("/dashboard/compliance/retention/webhook_deliveries", owner, [("days", "7")])
            XCTAssertEqual(shorter.status, .seeOther, shorter.text)
            let effective = try await policy.effectiveDays(.webhookDeliveries, businessId: businessId)
            XCTAssertEqual(effective, 7)
            let longer = try await h.formPost("/dashboard/compliance/retention/webhook_deliveries", owner, [("days", "30")])
            XCTAssertNotEqual(longer.status, .seeOther, "retention can be shortened but not extended")
            let evidence = try await h.formPost("/dashboard/compliance/retention/signed_decisions", owner, [("days", "400")])
            XCTAssertEqual(evidence.status, .forbidden)
            let unknown = try await h.formPost("/dashboard/compliance/retention/not_a_class", owner, [("days", "10")])
            XCTAssertEqual(unknown.status, .notFound)
            let below = try await h.formPost("/dashboard/compliance/retention/webhook_deliveries", owner, [("days", "0")])
            XCTAssertNotEqual(below.status, .seeOther)
            let cleared = try await h.formPost("/dashboard/compliance/retention/webhook_deliveries", owner, [("clear", "1")])
            XCTAssertEqual(cleared.status, .seeOther)
            let back = try await policy.effectiveDays(.webhookDeliveries, businessId: businessId)
            XCTAssertEqual(back, 14)
            // A role without the right cannot change it.
            let analyst = try await h.addMember(owner: owner, role: .analyst, email: "analyst@example.com").session
            let denied = try await h.formPost("/dashboard/compliance/retention/webhook_deliveries", analyst, [("days", "3")])
            XCTAssertEqual(denied.status, .forbidden)
            let audit = try await h.auditActions(businessId)
            XCTAssertTrue(audit.contains("retention.tenant_set") && audit.contains("retention.tenant_cleared"))
        }
    }

    // MARK: Purges

    /// One row of every purgeable class, older than its period, plus a fresh one that must survive.
    private func seed(_ h: TestHarness) async throws -> (business: TestBusiness, consumer: TestConsumer, ids: [String: UUID]) {
        let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
        let consumer = try await h.readyConsumer()
        let relationship = try await h.connect(consumer, to: business)
        var ids: [String: UUID] = [:]
        // A finished interaction.
        let issued = try await h.issue(business, relationship: relationship, payload: .confirm(ConfirmPayload(title: "Confirm seat 14C", details: "Flight 482", reference: "BK1")), ttl: 3600)
        let interaction = try issued.json(Interaction.self)
        ids["interaction"] = interaction.id.uuid
        let record = try await XCTUnwrapAsync(await InteractionRecord.find(interaction.id.uuid, on: h.db))
        record.status = InteractionStatus.expired.rawValue
        try await record.update(on: h.db)
        // A pending one that is also old: it must not be erased while it can still be answered or investigated.
        let pendingIssued = try await h.issue(business, relationship: relationship, payload: .confirm(ConfirmPayload(title: "Confirm seat 15C", details: "Flight 482", reference: "BK2")), ttl: 3600)
        ids["pending"] = try pendingIssued.json(Interaction.self).id.uuid
        // A conversation message.
        let message = try await h.businessPost(business, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: relationship.id, body: "Your table is ready", idempotencyKey: "m1"))
        XCTAssertEqual(message.status, .created, message.text)
        ids["message"] = try await XCTUnwrapAsync(await ConversationMessageRecord.query(on: h.db).first()).id
        // A signed decision and consent history (version 1 superseded by version 2).
        let decision = DecisionRecord()
        decision.id = UUID(); decision.interactionId = interaction.id.uuid; decision.businessId = business.record.id!; decision.consumerId = consumer.id.uuid
        decision.deviceId = consumer.device!.id.uuid; decision.decision = "approve"; decision.assurance = "biometric"; decision.channel = "nativePush"
        decision.signedPayload = "{}"; decision.signature = "sig"; decision.decidedAt = h.clock.now()
        try await decision.create(on: h.db)
        ids["decision"] = decision.id
        let oldConsent = ConsentGrantRecord(consumerId: consumer.id.uuid, businessId: business.record.id!, relationshipId: relationship.id.uuid, purpose: .marketing, granted: true,
                                            version: 5, policyVersion: "1", source: .system, channels: [.inApp], now: h.clock.now())
        let newConsent = ConsentGrantRecord(consumerId: consumer.id.uuid, businessId: business.record.id!, relationshipId: relationship.id.uuid, purpose: .marketing, granted: false,
                                            version: 6, policyVersion: "1", source: .system, channels: [.inApp], now: h.clock.now())
        try await oldConsent.create(on: h.db)
        try await newConsent.create(on: h.db)
        ids["oldConsent"] = oldConsent.id; ids["newConsent"] = newConsent.id
        // A webhook delivery, an expired session token, a security notice, a closed support ticket.
        let hook = WebhookSubscriptionRecord()
        hook.id = UUID(); hook.businessId = business.record.id!; hook.url = "https://hooks.example.com/x"; hook.events = "message.received"; hook.active = true
        hook.secretCiphertext = try h.ctx.cipher.seal("whsec_x", context: "webhook_subscriptions.secret", rowId: hook.id!); hook.createdAt = h.clock.now(); hook.secretVersion = 1
        try await hook.create(on: h.db)
        let delivery = WebhookDeliveryRecord()
        delivery.id = UUID(); delivery.subscriptionId = hook.id!; delivery.businessId = business.record.id!; delivery.eventType = "message.received"
        delivery.body = try h.ctx.cipher.seal(Data("{}".utf8), context: "webhook_deliveries.body", rowId: delivery.id!); delivery.status = "pending"; delivery.attempts = 0
        delivery.nextAttemptAt = h.clock.now().addingTimeInterval(3_600 * 24 * 365); delivery.createdAt = h.clock.now()
        try await delivery.create(on: h.db)
        ids["delivery"] = delivery.id
        let token = AccessTokenRecord(consumerId: consumer.id.uuid, tokenHash: SecureToken.hash("x"), familyId: UUID(), now: h.clock.now(), expiresAt: h.clock.now().addingTimeInterval(900))
        try await token.create(on: h.db)
        ids["token"] = token.id
        let notice = SecurityNoticeRecord(consumerId: consumer.id.uuid, kind: "test", message: "hello", subjectId: nil, originDeviceId: nil, now: h.clock.now())
        try await notice.create(on: h.db)
        ids["notice"] = notice.id
        let ticket = SupportTicketRecord()
        ticket.id = UUID(); ticket.businessId = business.record.id!; ticket.kind = "ticket"; ticket.subject = "Help"; ticket.bodyCiphertext = try h.ctx.cipher.seal("body", context: "support_tickets.body", rowId: ticket.id!)
        ticket.status = "closed"; ticket.createdBy = UUID(); ticket.createdAt = h.clock.now(); ticket.updatedAt = h.clock.now()
        try await ticket.create(on: h.db)
        ids["ticket"] = ticket.id
        return (business, consumer, ids)
    }

    func testEveryClassIsPurgedAfterItsPeriodAndNothingBefore() async throws {
        try await withHarness { h in
            let (business, _, ids) = try await seed(h)
            let purger = RetentionPurger(db: h.db, ctx: h.ctx)
            // Nothing is due yet.
            var report = await purger.run()
            XCTAssertEqual(report.total, 0, "\(report.counts)")
            // Past the longest default (7 years for audit/usage), everything seeded is due, except what must stay.
            h.clock.advance(by: days(2_600))
            report = await purger.run()
            XCTAssertTrue(report.skipped.filter { $0.value == "error" }.isEmpty, "\(report.skipped)")
            // The audit chain is never purged without an export target (its signed heads must leave the system first); this harness configures none.
            XCTAssertEqual(report.skipped[RetentionClass.auditEvents.rawValue], "no_export_target")
            let auditRows = try await AuditEventRecord.query(on: h.db).count()
            XCTAssertGreaterThan(auditRows, 0, "audit events stay when nothing was exported")
            let interaction = try await XCTUnwrapAsync(await InteractionRecord.find(ids["interaction"]!, on: h.db))
            XCTAssertTrue(interaction.contentErased)
            XCTAssertEqual(interaction.interactionJSON, "{}", "payload text is gone, the row (ids, status) stays for reporting")
            let pending = try await XCTUnwrapAsync(await InteractionRecord.find(ids["pending"]!, on: h.db))
            XCTAssertFalse(pending.contentErased, "an interaction that is still open keeps its content")
            let message = try await XCTUnwrapAsync(await ConversationMessageRecord.find(ids["message"]!, on: h.db))
            XCTAssertTrue(message.contentErased)
            XCTAssertEqual(try h.ctx.cipher.openString(message.bodyCiphertext, context: "conversation_messages.body", rowId: message.id!), "[expired]")
            let decision = try await DecisionRecord.find(ids["decision"]!, on: h.db)
            XCTAssertNil(decision, "signed decisions are deleted after their dispute period (through the retention gate)")
            let superseded = try await ConsentGrantRecord.find(ids["oldConsent"]!, on: h.db)
            let current = try await ConsentGrantRecord.find(ids["newConsent"]!, on: h.db)
            XCTAssertNil(superseded)
            XCTAssertNotNil(current, "the current consent of a relationship is never purged")
            let delivery = try await WebhookDeliveryRecord.find(ids["delivery"]!, on: h.db)
            XCTAssertNil(delivery, "even a never-sent (paused) delivery cannot keep message text for ever")
            let token = try await AccessTokenRecord.find(ids["token"]!, on: h.db)
            XCTAssertNil(token)
            let notice = try await SecurityNoticeRecord.find(ids["notice"]!, on: h.db)
            XCTAssertNil(notice)
            let ticket = try await SupportTicketRecord.find(ids["ticket"]!, on: h.db)
            XCTAssertNil(ticket)
            for key in ["interaction_content", "conversation_content", "signed_decisions", "consent_history", "webhook_deliveries", "security_tokens", "security_notices", "support_records"] {
                XCTAssertGreaterThan(report.counts[key] ?? 0, 0, "\(key): \(report.counts)")
            }
            // Idempotent.
            let again = await purger.run()
            XCTAssertEqual(again.total, 0, "\(again.counts)")
            _ = business
        }
    }

    func testAppendOnlyTablesRefuseDeletesAndUpdatesOutsideTheRetentionGate() async throws {
        try await withHarness { h in
            let (_, consumer, ids) = try await seed(h)
            let decision = try await XCTUnwrapAsync(await DecisionRecord.find(ids["decision"]!, on: h.db))
            // Outside the gate: neither a delete nor an update gets through (the database, not the application, says no).
            do { try await decision.delete(on: h.db); XCTFail("delete must be refused") } catch {}
            decision.decision = "deny"
            do { try await decision.update(on: h.db); XCTFail("update must be refused") } catch {}
            let consent = try await XCTUnwrapAsync(await ConsentGrantRecord.find(ids["oldConsent"]!, on: h.db))
            do { try await consent.delete(on: h.db); XCTFail("delete must be refused") } catch {}
            let event = try await XCTUnwrapAsync(await AuditEventRecord.query(on: h.db).first())
            do { try await event.delete(on: h.db); XCTFail("delete must be refused") } catch {}
            let kept = try await DecisionRecord.find(ids["decision"]!, on: h.db)
            XCTAssertNotNil(kept)
            // Inside the gate a DELETE passes, an UPDATE still does not, and the gate is closed again afterwards (also after a failure).
            let id = ids["decision"]!
            try await RetentionDeleteGate.perform(on: h.db) { tx in
                let fresh = try await XCTUnwrapAsync(await DecisionRecord.find(id, on: tx))
                fresh.decision = "deny"
                do { try await fresh.update(on: tx); XCTFail("update must stay refused inside the gate") } catch {}
            }
            struct Boom: Error {}
            do { try await RetentionDeleteGate.perform(on: h.db) { _ in throw Boom() }; XCTFail() } catch is Boom {}
            let stillThere = try await DecisionRecord.find(id, on: h.db)
            XCTAssertNotNil(stillThere)
            do { try await stillThere!.delete(on: h.db); XCTFail("the gate must be closed again") } catch {}
            try await RetentionDeleteGate.perform(on: h.db) { tx in try await DecisionRecord.query(on: tx).filter(\.$id == id).delete() }
            let gone = try await DecisionRecord.find(id, on: h.db)
            XCTAssertNil(gone)
            _ = consumer
        }
    }

    /// The gate is transaction-local: it is not open outside `perform`, does not leak to the pooled connection afterwards, and a `SET LOCAL`
    /// outside a transaction (what any ordinary statement runs in) does not open it. Ordinary request paths never call `perform`.
    func testRetentionGateStaysClosedOutsideItsTransaction() async throws {
        try await withHarness { h in
            let (_, _, ids) = try await seed(h)
            let id = ids["decision"]!
            if let sql = h.db as? any SQLDatabase, sql.dialect.name == "postgresql" {
                struct Row: Decodable { var v: String? }
                try await RetentionDeleteGate.perform(on: h.db) { tx in
                    let inside = try await (tx as! any SQLDatabase).raw("SELECT current_setting('viadere.retention', true) AS v").first(decoding: Row.self)
                    XCTAssertEqual(inside?.v, "on")
                }
                for _ in 0..<5 {
                    let after = try await sql.raw("SELECT current_setting('viadere.retention', true) AS v").first(decoding: Row.self)
                    XCTAssertNotEqual(after?.v, "on", "the gate must not survive the transaction on a pooled connection")
                }
                // SET LOCAL outside a transaction block is a no-op for later statements.
                try? await sql.raw("SET LOCAL viadere.retention = 'on'").run()
                let decision = try await XCTUnwrapAsync(await DecisionRecord.find(id, on: h.db))
                do { try await decision.delete(on: h.db); XCTFail("delete must be refused") } catch {}
            }
            let decision = try await XCTUnwrapAsync(await DecisionRecord.find(id, on: h.db))
            do { try await decision.delete(on: h.db); XCTFail("delete must be refused") } catch {}
            let still = try await DecisionRecord.find(id, on: h.db)
            XCTAssertNotNil(still)
        }
    }

    // MARK: Legal holds

    func testLegalHoldsSuspendPurgesForTheirScopeOnly() async throws {
        try await withHarness { h in
            let (firstOp, opAccount) = try await h.makeOperator()
            var op = firstOp
            let (_, consumer, ids) = try await seed(h)
            let other = try await h.makeBusiness(name: "Other Air", handle: "otherair")
            let businessId = try await XCTUnwrapAsync(await WebhookDeliveryRecord.find(ids["delivery"]!, on: h.db)).businessId
            // A hold on one business; a second delivery of another business is purged normally.
            let hold = try await h.formPost("/operator/holds", op, [("scopeKind", "business"), ("scopeId", businessId.uuidString.lowercased()), ("reason", "Litigation hold LH-2027-3")])
            XCTAssertEqual(hold.status, .seeOther, hold.text)
            let hook = WebhookSubscriptionRecord()
            hook.id = UUID(); hook.businessId = other.record.id!; hook.url = "https://hooks.example.com/y"; hook.events = "message.received"; hook.active = true
            hook.secretCiphertext = try h.ctx.cipher.seal("whsec_y", context: "webhook_subscriptions.secret", rowId: hook.id!); hook.createdAt = h.clock.now(); hook.secretVersion = 1
            try await hook.create(on: h.db)
            let otherDelivery = WebhookDeliveryRecord()
            otherDelivery.id = UUID(); otherDelivery.subscriptionId = hook.id!; otherDelivery.businessId = other.record.id!; otherDelivery.eventType = "message.received"
            otherDelivery.body = try h.ctx.cipher.seal(Data("{}".utf8), context: "webhook_deliveries.body", rowId: otherDelivery.id!); otherDelivery.status = "dead"; otherDelivery.attempts = 8
            otherDelivery.nextAttemptAt = h.clock.now(); otherDelivery.createdAt = h.clock.now()
            try await otherDelivery.create(on: h.db)
            h.clock.advance(by: days(2_600))
            let purger = RetentionPurger(db: h.db, ctx: h.ctx)
            _ = await purger.run()
            let held = try await WebhookDeliveryRecord.find(ids["delivery"]!, on: h.db)
            let released = try await WebhookDeliveryRecord.find(otherDelivery.id!, on: h.db)
            let heldDecision = try await DecisionRecord.find(ids["decision"]!, on: h.db)
            let heldInteraction = try await InteractionRecord.find(ids["interaction"]!, on: h.db)
            XCTAssertNotNil(held, "held business: nothing is purged")
            XCTAssertNil(released)
            XCTAssertNotNil(heldDecision)
            XCTAssertFalse(try XCTUnwrap(heldInteraction).contentErased)
            let relogin = try await h.dashLogin(opAccount, realm: .operator)
            op = try XCTUnwrap(relogin.session) // seven years passed: the console session ended
            // A global hold stops every holdable class; expiring security artefacts are not holdable and still go.
            let global = try await h.formPost("/operator/holds", op, [("scopeKind", "global"), ("reason", "Regulator request REG-9")])
            XCTAssertEqual(global.status, .seeOther, global.text)
            let token = AccessTokenRecord(consumerId: consumer.id.uuid, tokenHash: SecureToken.hash("y"), familyId: UUID(), now: h.clock.now(), expiresAt: h.clock.now().addingTimeInterval(-days(200)))
            try await token.create(on: h.db)
            let report = await purger.run()
            XCTAssertEqual(report.skipped["webhook_deliveries"], "legal_hold")
            XCTAssertEqual(report.skipped["signed_decisions"], "legal_hold")
            let expiredToken = try await AccessTokenRecord.find(token.id!, on: h.db)
            XCTAssertNil(expiredToken)
            // Releasing the holds lets the purge proceed; an unreasoned or malformed hold is refused.
            let bad = try await h.formPost("/operator/holds", op, [("scopeKind", "business"), ("scopeId", "not-a-uuid"), ("reason", "Litigation hold LH-2027-4")])
            XCTAssertNotEqual(bad.status, .seeOther)
            let holds = try await LegalHoldRecord.query(on: h.db).filter(\.$releasedAt == nil).all()
            XCTAssertEqual(holds.count, 2)
            for hold in holds { _ = try await h.formPost("/operator/holds/\(hold.id!.uuidString.lowercased())/release", op) }
            _ = await purger.run()
            let after = try await WebhookDeliveryRecord.find(ids["delivery"]!, on: h.db)
            XCTAssertNil(after)
            let actions = try await h.auditActions()
            XCTAssertTrue(actions.contains("retention.hold_placed") && actions.contains("retention.hold_released"))
        }
    }

    func testATenantsShorterWebhookRetentionAppliesToItsDeliveriesOnly() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let other = try await h.makeBusiness(name: "Other Air", handle: "otherair")
            func delivery(for business: UUID, at date: Date) async throws -> UUID {
                let hook = WebhookSubscriptionRecord()
                hook.id = UUID(); hook.businessId = business; hook.url = "https://hooks.example.com/z"; hook.events = "message.received"; hook.active = true
                hook.secretCiphertext = try h.ctx.cipher.seal("whsec_z", context: "webhook_subscriptions.secret", rowId: hook.id!); hook.createdAt = date; hook.secretVersion = 1
                try await hook.create(on: h.db)
                let d = WebhookDeliveryRecord()
                d.id = UUID(); d.subscriptionId = hook.id!; d.businessId = business; d.eventType = "message.received"
                d.body = try h.ctx.cipher.seal(Data("{}".utf8), context: "webhook_deliveries.body", rowId: d.id!); d.status = "succeeded"; d.attempts = 1
                d.nextAttemptAt = date; d.createdAt = date
                try await d.create(on: h.db)
                return d.id!
            }
            let mine = try await delivery(for: businessId, at: h.clock.now())
            let theirs = try await delivery(for: other.record.id!, at: h.clock.now())
            let shorten = try await h.formPost("/dashboard/compliance/retention/webhook_deliveries", owner, [("days", "7")])
            XCTAssertEqual(shorten.status, .seeOther, shorten.text)
            h.clock.advance(by: days(10))
            _ = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            let mineAfter = try await WebhookDeliveryRecord.find(mine, on: h.db)
            let theirsAfter = try await WebhookDeliveryRecord.find(theirs, on: h.db)
            XCTAssertNil(mineAfter, "7 days for this tenant")
            XCTAssertNotNil(theirsAfter, "30 days for everyone else")
        }
    }

    // MARK: Audit events

    func testAuditEventsArePurgedOnlyAfterTheirHeadWasExportedAndTheChainStaysVerifiable() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("audit-heads-" + UUID().uuidString).path
        defer { try? FileManager.default.removeItem(atPath: directory) }
        try await withHarness({ config in
            config.operations.auditExport = AuditHeadExportSettings(kind: .directory, target: directory, prefix: "audit-heads/", endpoint: nil, interval: 3_600, kmsKey: nil)
        }) { h in
            let audit = AuditService(db: h.db, ctx: h.ctx)
            for index in 0..<6 { _ = try await audit.record("old.event.\(index)", actor: AuditActor(kind: .system)) }
            h.clock.advance(by: days(2_600))
            for index in 0..<3 { _ = try await audit.record("recent.event.\(index)", actor: AuditActor(kind: .system)) }
            let purger = RetentionPurger(db: h.db, ctx: h.ctx)
            // Never exported: nothing may go, whatever the age.
            var report = await purger.run()
            XCTAssertEqual(report.skipped["audit_events"], "not_exported")
            let before = try await AuditEventRecord.query(on: h.db).count()
            XCTAssertEqual(before, 9)
            // Export the head (write-once), then the old events may go; the recent ones and the chain remain.
            let wrote = try await AuditHeadExporter(db: h.db, ctx: h.ctx).runIfDue(force: true)
            XCTAssertTrue(wrote)
            report = await purger.run()
            XCTAssertGreaterThan(report.counts["audit_events"] ?? 0, 0, "\(report)")
            let remaining = try await AuditEventRecord.query(on: h.db).sort(\.$seq, .ascending).all()
            XCTAssertLessThan(remaining.count, 9)
            XCTAssertGreaterThanOrEqual(remaining.count, 1, "at least the head always remains")
            let checkpoint = try await XCTUnwrapAsync(await AuditCheckpointRecord.query(on: h.db).first())
            XCTAssertEqual(checkpoint.seq + 1, remaining.first?.seq)
            let ring = AuditKeyring(config: h.ctx.config)
            let verified = try await AuditService.verifyChain(on: h.db, keyring: ring)
            XCTAssertTrue(verified.valid, "the chain verifies from the checkpoint")
            // Events appended after the purge still chain on.
            _ = try await audit.record("after.purge", actor: AuditActor(kind: .system))
            let stillValid = try await AuditService.verifyChain(on: h.db, keyring: ring)
            XCTAssertTrue(stillValid.valid)
            // Tampering with what remains is still detected, and a forged checkpoint does not hide a gap: a missing middle event breaks the chain.
            let middle = try await AuditEventRecord.query(on: h.db).sort(\.$seq, .ascending).all()
            XCTAssertGreaterThanOrEqual(middle.count, 2)
        }
    }
}
