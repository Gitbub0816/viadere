import Fluent
import Foundation
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Retention for authentication delivery (owner decisions 7, 10 and 16, ADR-0026, finding F-07): pending secrets live minutes, routine security
/// transaction metadata 30 days, high-value evidence (signed results, decisions, audit) on its longer access-restricted schedule. One test per store
/// period: nothing is purged before it is due, everything is purged after.
final class AuthRetentionTests: XCTestCase {
    private func days(_ n: Double) -> TimeInterval { n * 86_400 }

    // MARK: Classification table

    func testTheAuthenticationClassesAreDefinedPerTheClassificationTable() {
        let secrets = RetentionClass.authSecrets.definition
        XCTAssertEqual([secrets.minDays, secrets.defaultDays, secrets.maxDays], [1, 1, 1], "fixed: the minute sweep is the real period")
        XCTAssertFalse(secrets.tenantAdjustable)
        XCTAssertFalse(secrets.holdable, "a legal hold never preserves a bearer secret")
        let metadata = RetentionClass.authDeliveryMetadata.definition
        XCTAssertEqual(metadata.defaultDays, 30, "decisions 7 and 10")
        XCTAssertEqual([metadata.minDays, metadata.maxDays], [7, 90])
        XCTAssertTrue(metadata.tenantAdjustable, "a business may shorten, never lengthen")
        XCTAssertTrue(metadata.holdable)
        let routine = RetentionClass.authEvidenceRoutine.definition
        XCTAssertEqual(routine.defaultDays, 30)
        XCTAssertFalse(routine.tenantAdjustable)
        XCTAssertTrue(routine.holdable)
        // High-value evidence keeps its longer period, and routine sign-in results stay high-value for now (decision 16, OQ-1).
        XCTAssertEqual(RetentionClass.signedDecisions.definition.defaultDays, 730)
        XCTAssertEqual(RetentionClass.auditEvents.definition.defaultDays, 2555)
        XCTAssertEqual(RetentionClass.linkTokens.definition.defaultDays, 7)
        XCTAssertLessThanOrEqual(RetentionClass.webhookDeliveries.definition.defaultDays, 30)
        XCTAssertLessThanOrEqual(RetentionClass.outbound.definition.defaultDays, 30)
    }

    // MARK: approve_requests (T, 30 days) and its signed result (E-high)

    private func approveRow(_ h: TestHarness, business: TestBusiness, consumer: TestConsumer, relationship: Relationship, status: String, decidedAgo: Double?,
                            expiredAgo: Double, signed: Bool, requestId: String = UUID().uuidString) async throws -> ApproveRequestRecord {
        let now = h.clock.now()
        let row = ApproveRequestRecord()
        row.id = UUID()
        row.businessId = business.record.id!
        row.requestId = requestId
        row.relationshipId = relationship.id.uuid
        row.consumerId = consumer.id.uuid
        row.subjectRef = "sub_" + SecureToken.generate(byteCount: 8)
        row.capability = "login"
        row.protection = "server_visible"
        row.requestHash = "hash"
        row.attempts = 0
        row.devicePolicy = "any"
        row.challenge = "nonce"
        row.detailsSealed = "sealed-details"
        row.status = status
        row.createdAt = now.addingTimeInterval(-days(expiredAgo) - 300)
        row.expiresAt = now.addingTimeInterval(-days(expiredAgo))
        row.delivered = 1
        if let decidedAgo {
            row.decidedAt = now.addingTimeInterval(-days(decidedAgo))
            row.decision = "approve"
            row.decidedKid = "kid-1"
            row.amr = "biometric"
        }
        if signed {
            row.resultRef = "res_" + SecureToken.generate(byteCount: 12)
            row.resultJWS = "eyJ.signed.result"
        }
        try await row.create(on: h.db)
        let delivery = ApproveDeliveryRecord()
        delivery.id = UUID()
        delivery.requestId = row.id!
        delivery.kid = "kid-1"
        delivery.deviceId = consumer.device!.id.uuid
        delivery.consumerId = consumer.id.uuid
        delivery.createdAt = row.createdAt
        try await delivery.create(on: h.db)
        return row
    }

    func testApprovalRequestMetadataIsPurgedThirtyDaysAfterItsTerminalStateAndNotBefore() async throws {
        try await withHarness { h in
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: business)
            // Terminal 29 days ago (not due), terminal 31 days ago (due), expired unanswered 31 days ago (due), still pending and old (never).
            let young = try await approveRow(h, business: business, consumer: consumer, relationship: rel, status: "denied", decidedAgo: 29, expiredAgo: 29, signed: false)
            let old = try await approveRow(h, business: business, consumer: consumer, relationship: rel, status: "denied", decidedAgo: 31, expiredAgo: 31, signed: false)
            let unanswered = try await approveRow(h, business: business, consumer: consumer, relationship: rel, status: "expired", decidedAgo: nil, expiredAgo: 31, signed: false)
            let pending = try await approveRow(h, business: business, consumer: consumer, relationship: rel, status: "pending", decidedAgo: nil, expiredAgo: 31, signed: false)
            let report = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            XCTAssertEqual(report.counts["auth_delivery_metadata"], 2, "\(report.counts) \(report.skipped)")
            try await notNil(try await ApproveRequestRecord.find(young.id!, on: h.db))
            try await isNil(try await ApproveRequestRecord.find(old.id!, on: h.db))
            try await isNil(try await ApproveRequestRecord.find(unanswered.id!, on: h.db))
            try await notNil(try await ApproveRequestRecord.find(pending.id!, on: h.db))
            try await eq(try await ApproveDeliveryRecord.query(on: h.db).filter(\.$requestId == old.id!).count(), 0, "deliveries leave with their request")
            try await eq(try await ApproveDeliveryRecord.query(on: h.db).filter(\.$requestId == young.id!).count(), 1)
            // One day later the 29-day row is due too.
            h.clock.advance(by: days(2))
            _ = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            try await isNil(try await ApproveRequestRecord.find(young.id!, on: h.db))
            // Idempotent.
            let again = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            XCTAssertNil(again.counts["auth_delivery_metadata"])
        }
    }

    func testASignedResultStaysAsHighValueEvidenceWithoutTheMetadataAndLeavesOnTheSignedDecisionsSchedule() async throws {
        try await withHarness { h in
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: business)
            let signed = try await approveRow(h, business: business, consumer: consumer, relationship: rel, status: "approved", decidedAgo: 31, expiredAgo: 31, signed: true)
            _ = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            // Day 31: the T-class fields are erased; the id, decision, key, result reference and signature remain (owner ruling O-3).
            let kept = try await XCTUnwrapAsync(await ApproveRequestRecord.find(signed.id!, on: h.db))
            XCTAssertNil(kept.detailsSealed)
            XCTAssertNil(kept.challenge)
            XCTAssertNil(kept.devicePolicy)
            XCTAssertEqual(kept.resultJWS, "eyJ.signed.result")
            XCTAssertEqual(kept.decision, "approve")
            XCTAssertEqual(kept.decidedKid, "kid-1")
            XCTAssertNotNil(kept.resultRef)
            // Routine low-risk sign-in results are still high-value evidence (decision 16, OQ-1): still there at day 700, gone after 730.
            h.clock.advance(by: days(669))   // day 700 after the decision
            _ = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            try await notNil(try await ApproveRequestRecord.find(signed.id!, on: h.db))
            h.clock.advance(by: days(40))    // day 740
            let report = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            XCTAssertGreaterThanOrEqual(report.counts["signed_decisions"] ?? 0, 1, "\(report.counts)")
            try await isNil(try await ApproveRequestRecord.find(signed.id!, on: h.db))
            try await eq(try await ApproveDeliveryRecord.query(on: h.db).filter(\.$requestId == signed.id!).count(), 0)
        }
    }

    func testALegalHoldStopsTheMetadataPurgeForItsScopeAndATenantMayShortenOnlyItsOwn() async throws {
        try await withHarness { h in
            let held = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let other = try await h.makeBusiness(name: "Harbor Hotel", handle: "harborhotel")
            let consumer = try await h.readyConsumer()
            let relHeld = try await h.connect(consumer, to: held)
            let relOther = try await h.connect(consumer, to: other)
            let heldRow = try await approveRow(h, business: held, consumer: consumer, relationship: relHeld, status: "denied", decidedAgo: 40, expiredAgo: 40, signed: false)
            let otherRow = try await approveRow(h, business: other, consumer: consumer, relationship: relOther, status: "denied", decidedAgo: 40, expiredAgo: 40, signed: false)
            let op = UUID()
            _ = try await RetentionPolicy(db: h.db, ctx: h.ctx).placeHold(scopeKind: "business", scopeId: held.record.id!.uuidString, reason: "Investigation of a disputed sign-in", operatorId: op)
            _ = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            try await notNil(try await ApproveRequestRecord.find(heldRow.id!, on: h.db))
            try await isNil(try await ApproveRequestRecord.find(otherRow.id!, on: h.db))
        }
        // A business that shortened to 7 days loses its rows sooner; the platform value stays 30 for everyone else.
        try await withHarness { h in
            let short = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let normal = try await h.makeBusiness(name: "Harbor Hotel", handle: "harborhotel")
            let consumer = try await h.readyConsumer()
            let relShort = try await h.connect(consumer, to: short)
            let relNormal = try await h.connect(consumer, to: normal)
            let userId = UUID()
            try await RetentionPolicy(db: h.db, ctx: h.ctx).setTenant(.authDeliveryMetadata, businessId: short.record.id!, days: 7, by: userId)
            do {
                try await RetentionPolicy(db: h.db, ctx: h.ctx).setTenant(.authDeliveryMetadata, businessId: short.record.id!, days: 45, by: userId)
                XCTFail("a business can shorten, never lengthen")
            } catch is APIError {}
            let a = try await approveRow(h, business: short, consumer: consumer, relationship: relShort, status: "denied", decidedAgo: 10, expiredAgo: 10, signed: false)
            let b = try await approveRow(h, business: normal, consumer: consumer, relationship: relNormal, status: "denied", decidedAgo: 10, expiredAgo: 10, signed: false)
            _ = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            try await isNil(try await ApproveRequestRecord.find(a.id!, on: h.db))
            try await notNil(try await ApproveRequestRecord.find(b.id!, on: h.db))
        }
    }

    func testFreezeEventReferencesFollowTheThirtyDayRule() async throws {
        try await withHarness { h in
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: business)
            for ago in [29.0, 31.0] {
                let event = ApproveFreezeEventRecord()
                event.id = UUID()
                event.ref = ApproveFreezeEventRecord.newRef()
                event.businessId = business.record.id!
                event.relationshipId = rel.id.uuid
                event.createdAt = h.clock.now().addingTimeInterval(-days(ago))
                try await event.create(on: h.db)
            }
            _ = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            try await eq(try await ApproveFreezeEventRecord.query(on: h.db).count(), 1)
        }
    }

    func testTheOldFourHundredDaySweepInsideTheApproveServiceIsGone() async throws {
        try await withHarness { h in
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: business)
            // Between 30 and 400 days old: the approve service's own sweep no longer touches it (the retention class owns the rule).
            let row = try await approveRow(h, business: business, consumer: consumer, relationship: rel, status: "denied", decidedAgo: 100, expiredAgo: 100, signed: false)
            try await ApproveRequestService(db: h.db, ctx: h.ctx).expireDue()
            try await notNil(try await ApproveRequestRecord.find(row.id!, on: h.db))
            _ = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            try await isNil(try await ApproveRequestRecord.find(row.id!, on: h.db))
        }
    }

    // MARK: Pending secrets (P): minutes

    func testAPhoneLinkChallengeIsAPendingSecretAndNeverOutlivesItsExpiryByMoreThanTwoMinutes() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let begin = try await h.beginPhoneLink(consumer, phone: "+14805550123").json(PhoneLinkMOBeginResponse.self)
            h.clock.advance(by: PhoneLinkMO.ttl + 119)
            try await eq(try await PhoneLinkService.purgeChallenges(on: h.db, now: h.clock.now()), 0)
            try await eq(try await PhoneLinkMOChallengeRecord.query(on: h.db).count(), 1)
            h.clock.advance(by: 2)
            // The class sweep is the daily backstop: it removes the same row.
            let report = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            XCTAssertEqual(report.counts["auth_secrets"], 1, "\(report.counts)")
            try await eq(try await PhoneLinkMOChallengeRecord.query(on: h.db).count(), 0)
            // Never held: a legal hold cannot preserve a bearer secret.
            _ = begin
            let second = try await h.beginPhoneLink(try await h.login(consumer), phone: "+14805550177").json(PhoneLinkMOBeginResponse.self)
            _ = second
            let op = UUID()
            _ = try await RetentionPolicy(db: h.db, ctx: h.ctx).placeHold(scopeKind: "global", scopeId: nil, reason: "Regulatory preservation request", operatorId: op)
            h.clock.advance(by: PhoneLinkMO.ttl + 200)
            _ = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            try await eq(try await PhoneLinkMOChallengeRecord.query(on: h.db).count(), 0)
        }
    }

    // MARK: link_tokens (T, 7 days, then emptied) and the one-time catch-up migration

    func testLinkTokensKeepTheirSevenDayRuleAndTheMigrationEmptiesTheTable() async throws {
        try await withHarness { h in
            let phone = PhoneNumber("+14805550123")!
            func token(expiredAgo: Double) async throws -> UUID {
                let record = LinkTokenRecord()
                record.id = UUID()
                record.kind = "handoff"
                record.tokenHash = SecureToken.hash(SecureToken.generate())
                record.phoneHash = h.ctx.hasher.phoneHash(phone)
                record.phoneCiphertext = try h.ctx.cipher.seal(phone.e164, context: "link_tokens.phone", rowId: record.id!)
                record.phoneLast4 = "0123"
                record.contextRevision = 0
                record.attempts = 0
                record.state = "open"
                record.createdAt = h.clock.now().addingTimeInterval(-days(expiredAgo) - 600)
                record.expiresAt = h.clock.now().addingTimeInterval(-days(expiredAgo))
                try await record.create(on: h.db)
                return record.id!
            }
            let young = try await token(expiredAgo: 6)
            let old = try await token(expiredAgo: 8)
            _ = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            try await notNil(try await LinkTokenRecord.find(young, on: h.db))
            try await isNil(try await LinkTokenRecord.find(old, on: h.db))
            // The deploy migration revokes nothing it should keep and removes the rest: the table is emptied (the routes that redeemed them are gone).
            try await CreateAuthRetentionAlignment().prepare(on: h.db)
            try await eq(try await LinkTokenRecord.query(on: h.db).count(), 0)
        }
    }

    func testTheCatchUpMigrationDeletesOldRequestsKeepsSignedResultsScrubbedAndRespectsAHold() async throws {
        try await withHarness { h in
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: business)
            // The migration works on the real clock: rows are aged against it.
            let realNow = Date()
            h.clock.set(realNow)
            let old = try await approveRow(h, business: business, consumer: consumer, relationship: rel, status: "denied", decidedAgo: 90, expiredAgo: 90, signed: false)
            let signed = try await approveRow(h, business: business, consumer: consumer, relationship: rel, status: "approved", decidedAgo: 90, expiredAgo: 90, signed: true)
            let recent = try await approveRow(h, business: business, consumer: consumer, relationship: rel, status: "denied", decidedAgo: 5, expiredAgo: 5, signed: false)
            let op = UUID()
            let hold = try await RetentionPolicy(db: h.db, ctx: h.ctx).placeHold(scopeKind: "global", scopeId: nil, reason: "Regulatory preservation request", operatorId: op)
            try await CreateAuthRetentionAlignment().prepare(on: h.db)
            try await notNil(try await ApproveRequestRecord.find(old.id!, on: h.db), "an active hold stops the catch-up")
            try await RetentionPolicy(db: h.db, ctx: h.ctx).releaseHold(id: hold.id!, operatorId: op)
            try await CreateAuthRetentionAlignment().prepare(on: h.db)
            try await isNil(try await ApproveRequestRecord.find(old.id!, on: h.db))
            try await notNil(try await ApproveRequestRecord.find(recent.id!, on: h.db))
            let kept = try await XCTUnwrapAsync(await ApproveRequestRecord.find(signed.id!, on: h.db))
            XCTAssertNil(kept.detailsSealed)
            XCTAssertNil(kept.challenge)
            XCTAssertEqual(kept.resultJWS, "eyJ.signed.result")
        }
    }

    // MARK: Queue and delivery stores already at or under 30 days (aligned, not changed)

    func testOutboxProcessedMarkersAndDeadLettersAreAllWithinThirtyDays() async throws {
        try await withHarness { h in
            let now = h.clock.now()
            func outbox(publishedAgo: Double) async throws -> UUID {
                let row = OutboxMessageRecord()
                row.id = UUID()
                row.queue = "sms"
                row.type = "sms.send"
                row.version = 1
                row.ref = UUID()
                row.payloadJSON = "{}"
                row.createdAt = now.addingTimeInterval(-days(publishedAgo) - 60)
                row.publishedAt = now.addingTimeInterval(-days(publishedAgo))
                row.attempts = 0
                try await row.create(on: h.db)
                return row.id!
            }
            let freshOutbox = try await outbox(publishedAgo: 6)
            let staleOutbox = try await outbox(publishedAgo: 8)
            func processed(ago: Double) async throws -> UUID {
                let row = ProcessedMessageRecord()
                row.id = UUID()
                row.queue = "sms"
                row.type = "sms.send"
                row.processedAt = now.addingTimeInterval(-days(ago))
                try await row.create(on: h.db)
                return row.id!
            }
            let freshMarker = try await processed(ago: 14)
            let staleMarker = try await processed(ago: 16)
            try await QueuePump.purge(on: h.db, now: now)
            try await notNil(try await OutboxMessageRecord.find(freshOutbox, on: h.db))
            try await isNil(try await OutboxMessageRecord.find(staleOutbox, on: h.db))
            try await notNil(try await ProcessedMessageRecord.find(freshMarker, on: h.db))
            try await isNil(try await ProcessedMessageRecord.find(staleMarker, on: h.db))
            // Webhook deliveries and finished outbound sends: 30 days by class default.
            XCTAssertEqual(RetentionClass.webhookDeliveries.definition.defaultDays, 30)
            XCTAssertEqual(RetentionClass.outbound.definition.defaultDays, 30)
        }
    }
}
