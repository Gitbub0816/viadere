import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Re-check of the SMS-removal review (F-4 composition, R-1 to R-4): every test reproduces the exploit or race first.
final class PhoneLinkHardeningTests: XCTestCase {
    let phone = "+14805550123"

    // MARK: Helpers

    private func pendingTransfer(_ h: TestHarness, oldOwner: TestConsumer, newOwner: inout TestConsumer) async throws -> (oldLink: PhoneLinkID, pending: PhoneLinkID) {
        let first = try await h.linkPhoneByText(oldOwner, phone: phone)
        let oldLink = try XCTUnwrap(first.status.link)
        h.clock.advance(by: 72 * 3600 + 1)
        newOwner = try await h.login(newOwner)
        let begin = try await h.beginPhoneLink(newOwner, phone: phone).json(PhoneLinkMOBeginResponse.self)
        try await h.textViadere(from: phone, begin.prefill)
        let pending = try await XCTUnwrapAsync(await PhoneLinkRecord.find(begin.phoneLinkId.uuid, on: h.db))
        XCTAssertEqual(pending.state, "pending_transfer")
        return (oldLink.id, begin.phoneLinkId)
    }

    private func notices(_ h: TestHarness, _ consumer: TestConsumer) async throws -> [SecurityNotice] {
        try await h.signed(consumer, .GET, "/v1/security-notices").json([SecurityNotice].self)
    }

    private func markSeen(_ h: TestHarness, _ consumer: TestConsumer, _ notice: SecurityNotice, relogin: Bool = true) async throws -> HTTPResult {
        // Fresh access token: the clock may have moved since the consumer logged in.
        let fresh = relogin ? try await h.login(consumer) : consumer
        return try await h.signedPost(fresh, "/v1/security-notices/\(notice.id.uuidString.lowercased())/seen", EmptyBody())
    }

    private func unlinkText(_ h: TestHarness, indicator: InboundSenderIndicator = .unsupported) async throws {
        let sms = InboundSMS(providerMessageId: "t:\(UUID())", from: PhoneNumber(phone)!, text: "UNLINK", receivedAt: h.clock.now(), senderIndicator: indicator)
        _ = try await GatewayService(db: h.db, ctx: h.ctx).handleInbound(sms, provider: "test")
        try await h.runJobs()
    }

    // MARK: F-4: a forged UNLINK never releases a number

    /// The composition the reviewer found: forged UNLINK frees the dormant owner's number, then a victim-induced text binds it fresh. Now UNLINK only
    /// suspends routing; the binding stays with the holder, so the induced text meets the pending-transfer rule and the dormant owner keeps it.
    func testAForgedUnlinkThenAVictimInducedTextCannotTakeADormantOwnersNumber() async throws {
        try await withHarness { h in
            let dormant = try await h.readyConsumer(name: "Dormant")
            var attacker = try await h.readyConsumer(name: "Attacker")
            let first = try await h.linkPhoneByText(dormant, phone: phone)
            let link = try XCTUnwrap(first.status.link)
            h.clock.advance(by: 72 * 3600 + 1)
            // Step 1: a forged UNLINK (never indicator-checked). Routing stops, the number is NOT released.
            try await unlinkText(h)
            let held = try await XCTUnwrapAsync(await PhoneLinkRecord.find(link.id.uuid, on: h.db))
            XCTAssertEqual(held.state, "verified", "an UNLINK text must not release the number")
            XCTAssertNotNil(held.verifiedPhoneHash, "the number stays bound to the holder until the holder confirms in the app")
            XCTAssertNotNil(held.suspendedAt)
            try await eq(try await h.gatewayConsumer(phone), nil, "routing is paused (fail-safe)")
            // Step 2: the attacker begins and talks the real phone's owner into sending the text.
            attacker = try await h.login(attacker)
            let begin = try await h.beginPhoneLink(attacker, phone: phone).json(PhoneLinkMOBeginResponse.self)
            try await h.textViadere(from: phone, begin.prefill)
            let pending = try await XCTUnwrapAsync(await PhoneLinkRecord.find(begin.phoneLinkId.uuid, on: h.db))
            XCTAssertEqual(pending.state, "pending_transfer", "a fresh verified link would bypass the holder's in-app notice")
            try await eq(try await h.gatewayConsumer(phone), nil)
            // The dormant owner never opens the app: the number never moves.
            let service = PhoneLinkService(db: h.db, ctx: h.ctx)
            for days in [2, 30, 365] {
                h.clock.advance(by: Double(days) * 86_400)
                try await eq(try await service.completeTransfers(), 0)
            }
            let after = try await XCTUnwrapAsync(await PhoneLinkRecord.find(link.id.uuid, on: h.db))
            XCTAssertEqual(after.state, "verified")
        }
    }

    func testAnUnlinkTextWithAPositiveSpoofIndicatorDoesNothing() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            try await h.linkVerifiedPhone(consumer, phone: phone)
            try await unlinkText(h, indicator: .suspectedSpoof)
            let link = try await XCTUnwrapAsync(await PhoneLinkRecord.query(on: h.db).first())
            XCTAssertNil(link.suspendedAt)
            try await eq(try await h.gatewayConsumer(phone), consumer.id)
            try await eq(h.texts.sent.count, 0, "no reply to a spoofed UNLINK")
            // The indicators the shipped adapters report keep working, so the real owner's safety valve is not lost.
            for indicator in [InboundSenderIndicator.unsupported, .notProvided, .verified] {
                try await unlinkText(h, indicator: indicator)
                let suspended = try await XCTUnwrapAsync(await PhoneLinkRecord.query(on: h.db).first())
                XCTAssertNotNil(suspended.suspendedAt, "\(indicator)")
                try await eq(try await h.gatewayConsumer(phone), nil)
                suspended.suspendedAt = nil
                try await suspended.update(on: h.db)
            }
        }
    }

    /// The holder releases the number only in the app (a trusted device); then it is free. The account that was unlinked can link again by text
    /// (a fresh waiting period) without a second row.
    func testTheHolderReleasesInTheAppOrLinksAgainByText() async throws {
        try await withHarness { h in
            var consumer = try await h.readyConsumer()
            let first = try await h.linkPhoneByText(consumer, phone: phone)
            let link = try XCTUnwrap(first.status.link)
            h.clock.advance(by: 72 * 3600 + 1)
            consumer = try await h.login(consumer)
            try await unlinkText(h)
            try await eq(try await h.gatewayConsumer(phone), nil)
            // The account is told in the app, in words that say the number is only paused.
            let second = try await h.enrollDevice(consumer)
            let list = try await notices(h, second)
            let notice = try XCTUnwrap(list.first { $0.topic == .phoneUnlinked })
            XCTAssertTrue(notice.message.contains("remove it"), notice.message)
            // Linking again by text resumes the same row, with a new waiting period.
            h.clock.advance(by: 25 * 3600)
            consumer = try await h.login(consumer)
            let again = try await h.beginPhoneLink(consumer, phone: phone).json(PhoneLinkMOBeginResponse.self)
            try await h.textViadere(from: phone, again.prefill)
            let resumed = try await XCTUnwrapAsync(await PhoneLinkRecord.find(link.id.uuid, on: h.db))
            XCTAssertNil(resumed.suspendedAt)
            XCTAssertNotNil(resumed.usableFrom)
            try await eq(try await h.gatewayConsumer(phone), nil, "cooling down again")
            h.clock.advance(by: 72 * 3600 + 1)
            try await eq(try await h.gatewayConsumer(phone), consumer.id)
            // Releasing in the app frees the number for anyone.
            consumer = try await h.login(consumer)
            try await eq(try await h.signed(consumer, .DELETE, "/v1/phone-links/\(link.id)").status, .ok)
            let released = try await XCTUnwrapAsync(await PhoneLinkRecord.find(link.id.uuid, on: h.db))
            XCTAssertEqual(released.state, "revoked")
        }
    }

    // MARK: R-1: "seen" means shown with its Keep action, and any of the holder's devices can Keep

    func testListingNoticesDoesNotCountAsSeenOnlyTheShownCallDoes() async throws {
        try await withHarness { h in
            var oldOwner = try await h.readyConsumer(name: "Old")
            var newOwner = try await h.readyConsumer(name: "New")
            _ = try await pendingTransfer(h, oldOwner: oldOwner, newOwner: &newOwner)
            oldOwner = try await h.login(oldOwner)
            let service = PhoneLinkService(db: h.db, ctx: h.ctx)
            // The app loads the list (cold launch behind the lock screen, or with a newer notice on top): not seen.
            let list = try await notices(h, oldOwner)
            let notice = try XCTUnwrap(list.first { $0.topic == .phoneTransferRequested })
            h.clock.advance(by: 72 * 3600 + 1)
            try await eq(try await service.completeTransfers(), 0, "fetched is not seen: the number does not move")
            // The banner rendered it with its Keep button.
            try await eq(try await markSeen(h, oldOwner, notice).status, .ok)
            try await eq(try await service.completeTransfers(), 1)
        }
    }

    func testSeenIsPrivateToTheAccountAndAnAppClipCannotRecordIt() async throws {
        try await withHarness { h in
            let oldOwner = try await h.readyConsumer(name: "Old")
            var newOwner = try await h.readyConsumer(name: "New")
            _ = try await pendingTransfer(h, oldOwner: oldOwner, newOwner: &newOwner)
            let list = try await notices(h, try await h.login(oldOwner))
            let notice = try XCTUnwrap(list.first { $0.topic == .phoneTransferRequested })
            // Another account cannot mark the holder's notice (404, like a dismissal).
            newOwner = try await h.login(newOwner)
            try await eq(try await markSeen(h, newOwner, notice, relogin: false).status, .notFound)
            // An App Clip session of the holder's account is not an app instance that can show Keep.
            let clip = try await h.enrollDevice(try await h.login(oldOwner), name: "Clip", purposes: [.request], clientKind: .appClip, assertion: false)
            let refused = try await markSeen(h, clip, notice, relogin: false)
            XCTAssertNotEqual(refused.status, .ok, refused.text)
            h.clock.advance(by: 72 * 3600 + 1)
            try await eq(try await PhoneLinkService(db: h.db, ctx: h.ctx).completeTransfers(), 0)
        }
    }

    func testADeviceStillInCoolDownCanSeeAndKeepTheNumber() async throws {
        try await withHarness { h in
            let oldOwner = try await h.readyConsumer(name: "Old")
            var newOwner = try await h.readyConsumer(name: "New")
            let ids = try await pendingTransfer(h, oldOwner: oldOwner, newOwner: &newOwner)
            // The owner is on a new phone that has not been approved yet.
            let newPhone = try await h.enrollDevice(try await h.login(oldOwner), name: "New phone")
            let device = try await XCTUnwrapAsync(await DeviceRecord.find(newPhone.device!.id.uuid, on: h.db))
            XCTAssertFalse(device.isTrusted(at: h.clock.now()), "precondition: the device is in cool-down")
            let list = try await notices(h, newPhone)
            let notice = try XCTUnwrap(list.first { $0.topic == .phoneTransferRequested })
            try await eq(try await markSeen(h, newPhone, notice).status, .ok)
            try await eq(try await h.signedPost(newPhone, "/v1/phone-links/\(ids.oldLink)/keep", EmptyBody()).status, .ok, "Keep only preserves the status quo")
            h.clock.advance(by: 72 * 3600 + 1)
            try await eq(try await PhoneLinkService(db: h.db, ctx: h.ctx).completeTransfers(), 0)
            try await eq(try await h.gatewayConsumer(phone), oldOwner.id)
            let dead = try await XCTUnwrapAsync(await PhoneLinkRecord.find(ids.pending.uuid, on: h.db))
            XCTAssertEqual(dead.state, "revoked")
        }
    }

    // MARK: R-3 and R-4

    func testTheTransferDropsWhenTheRequestersAccountIsNotActiveOrTheProvingDeviceIsGone() async throws {
        for scenario in ["account", "device"] {
            try await withHarness { h in
                let oldOwner = try await h.readyConsumer(name: "Old")
                var newOwner = try await h.readyConsumer(name: "New")
                let ids = try await pendingTransfer(h, oldOwner: oldOwner, newOwner: &newOwner)
                // The requester has another working device either way.
                _ = try await h.enrollDevice(newOwner, name: "Second")
                let owner = try await h.login(oldOwner)
                let noticeAll = try await notices(h, owner)
            let notice = try XCTUnwrap(noticeAll.first { $0.topic == .phoneTransferRequested })
                try await eq(try await markSeen(h, owner, notice).status, .ok)
                let pending = try await XCTUnwrapAsync(await PhoneLinkRecord.find(ids.pending.uuid, on: h.db))
                if scenario == "account" {
                    let account = try await XCTUnwrapAsync(await ConsumerRecord.find(newOwner.id.uuid, on: h.db))
                    account.status = "suspended"
                    try await account.update(on: h.db)
                } else {
                    let proving = try await XCTUnwrapAsync(await DeviceRecord.find(try XCTUnwrap(pending.provedByDeviceId), on: h.db))
                    proving.revokedAt = h.clock.now()
                    try await proving.update(on: h.db)
                }
                h.clock.advance(by: 72 * 3600 + 1)
                try await eq(try await PhoneLinkService(db: h.db, ctx: h.ctx).completeTransfers(), 0, scenario)
                try await eq(try await h.gatewayConsumer(phone), oldOwner.id, scenario)
                let dropped = try await XCTUnwrapAsync(await PhoneLinkRecord.find(ids.pending.uuid, on: h.db))
                XCTAssertEqual(dropped.state, "revoked", scenario)
            }
        }
    }

    /// R-4: a notice that scrolled out of the app's 30-day list can never be fetched, so a fresh one is written and the wait restarts.
    func testAnOldUnseenNoticeIsReplacedSoAnActiveOwnerCanStillKeepTheNumber() async throws {
        try await withHarness { h in
            var oldOwner = try await h.readyConsumer(name: "Old")
            var newOwner = try await h.readyConsumer(name: "New")
            let ids = try await pendingTransfer(h, oldOwner: oldOwner, newOwner: &newOwner)
            let service = PhoneLinkService(db: h.db, ctx: h.ctx)
            h.clock.advance(by: 31 * 86_400)
            oldOwner = try await h.login(oldOwner)
            // The owner is active again, but the original notice is older than the list window.
            let stale = try await SecurityNoticeRecord.query(on: h.db).filter(\.$consumerId == oldOwner.id.uuid).filter(\.$kind == "phoneTransferRequested").all()
            XCTAssertEqual(stale.count, 1)
            let listed = try await notices(h, oldOwner)
            XCTAssertTrue(listed.filter { $0.topic == .phoneTransferRequested }.isEmpty, "the old notice is out of the list window")
            try await eq(try await service.completeTransfers(), 0)
            let freshAll = try await notices(h, oldOwner)
            let fresh = try XCTUnwrap(freshAll.first { $0.topic == .phoneTransferRequested }, "a fresh notice replaces it")
            try await eq(try await service.completeTransfers(), 0, "the wait restarted")
            h.clock.advance(by: 25 * 3600)
            try await eq(try await service.completeTransfers(), 0, "not seen yet")
            oldOwner = try await h.login(oldOwner)
            try await eq(try await h.signedPost(oldOwner, "/v1/phone-links/\(ids.oldLink)/keep", EmptyBody()).status, .ok)
            _ = fresh
            try await eq(try await service.completeTransfers(), 0)
            try await eq(try await h.gatewayConsumer(phone), oldOwner.id)
        }
    }

    // MARK: R-2: jobs

    /// The ungated `maintenance` task no longer runs the minute task (two overlapping runs every five minutes); `minute` does the transfers.
    func testTransfersAreCompletedByTheMinuteTaskNotByTheFiveMinuteMaintenanceTask() async throws {
        try await withHarness { h in
            var oldOwner = try await h.readyConsumer(name: "Old")
            var newOwner = try await h.readyConsumer(name: "New")
            _ = try await pendingTransfer(h, oldOwner: oldOwner, newOwner: &newOwner)
            oldOwner = try await h.login(oldOwner)
            let noticeAll = try await notices(h, oldOwner)
            let notice = try XCTUnwrap(noticeAll.first { $0.topic == .phoneTransferRequested })
            try await eq(try await markSeen(h, oldOwner, notice).status, .ok)
            h.clock.advance(by: 72 * 3600 + 1)
            try await BackgroundJobs(app: h.app).run(.maintenance)
            try await eq(try await h.gatewayConsumer(phone), oldOwner.id, "maintenance does not run the transfers")
            try await BackgroundJobs(app: h.app).run(.minute)
            try await eq(try await h.gatewayConsumer(phone), newOwner.id)
        }
    }

    func testAJobLeaseAdmitsOneRunAtATimeAndExpires() async throws {
        try await withHarness { h in
            let (a, b) = (UUID(), UUID())
            try await eq(try await JobLease.acquire("phone-link-minute", holder: a, ttl: 50, on: h.db, now: h.clock.now()), true)
            try await eq(try await JobLease.acquire("phone-link-minute", holder: b, ttl: 50, on: h.db, now: h.clock.now()), false, "overlapping run")
            try await eq(try await JobLease.acquire("other", holder: b, ttl: 50, on: h.db, now: h.clock.now()), true, "leases are per name")
            // A crashed run's lease expires by itself.
            h.clock.advance(by: 51)
            try await eq(try await JobLease.acquire("phone-link-minute", holder: b, ttl: 50, on: h.db, now: h.clock.now()), true)
            try await eq(try await JobLease.acquire("phone-link-minute", holder: a, ttl: 50, on: h.db, now: h.clock.now()), false)
            // Only the holder releases it.
            try await JobLease.release("phone-link-minute", holder: a, on: h.db)
            try await eq(try await JobLease.acquire("phone-link-minute", holder: a, ttl: 50, on: h.db, now: h.clock.now()), false)
            try await JobLease.release("phone-link-minute", holder: b, on: h.db)
            try await eq(try await JobLease.acquire("phone-link-minute", holder: a, ttl: 50, on: h.db, now: h.clock.now()), true)
        }
    }

    func testAMinuteRunWhileAnotherHoldsTheLeaseDoesNothing() async throws {
        try await withHarness { h in
            var oldOwner = try await h.readyConsumer(name: "Old")
            var newOwner = try await h.readyConsumer(name: "New")
            _ = try await pendingTransfer(h, oldOwner: oldOwner, newOwner: &newOwner)
            oldOwner = try await h.login(oldOwner)
            let noticeAll = try await notices(h, oldOwner)
            let notice = try XCTUnwrap(noticeAll.first { $0.topic == .phoneTransferRequested })
            try await eq(try await markSeen(h, oldOwner, notice).status, .ok)
            h.clock.advance(by: 72 * 3600 + 1)
            let other = UUID()
            try await eq(try await JobLease.acquire(BackgroundJobs.minuteLease, holder: other, ttl: 50, on: h.db, now: h.clock.now()), true)
            try await BackgroundJobs(app: h.app).run(.minute)
            try await eq(try await h.gatewayConsumer(phone), oldOwner.id, "another run is in progress")
            try await JobLease.release(BackgroundJobs.minuteLease, holder: other, on: h.db)
            try await BackgroundJobs(app: h.app).run(.minute)
            try await eq(try await h.gatewayConsumer(phone), newOwner.id)
        }
    }

    // MARK: R-2: PostgreSQL concurrency

    private func requirePostgres() throws {
        guard ProcessInfo.processInfo.environment["TEST_DATABASE_URL"].map({ !$0.isEmpty }) == true else {
            throw XCTSkip("needs PostgreSQL (TEST_DATABASE_URL): SQLite serializes writers and has no row locks")
        }
    }

    /// A Keep that commits while the job already decided to move the number must win. The transaction below plays Keep: it takes the number's
    /// row locks (as `keep` does), holds them, revokes the pending row, and commits late. `completeTransfers` started in the meantime must wait
    /// for it and then see the revoked row, not overwrite it with `verified`.
    func testOnPostgresAKeepThatCommitsWhileTheJobRunsIsNeverUndone() async throws {
        try requirePostgres()
        try await withHarness { h in
            var oldOwner = try await h.readyConsumer(name: "Old")
            var newOwner = try await h.readyConsumer(name: "New")
            let ids = try await pendingTransfer(h, oldOwner: oldOwner, newOwner: &newOwner)
            oldOwner = try await h.login(oldOwner)
            let noticeAll = try await notices(h, oldOwner)
            let notice = try XCTUnwrap(noticeAll.first { $0.topic == .phoneTransferRequested })
            try await eq(try await markSeen(h, oldOwner, notice).status, .ok)
            h.clock.advance(by: 72 * 3600 + 1)
            let (db, ctx) = (h.db, h.ctx)
            let phoneHash = ctx.hasher.phoneHash(PhoneNumber(phone)!)
            let committed = LockedFlag()
            let holding = LockedFlag()
            let keeper = Task {
                try await db.transaction { tx in
                    try await PhoneLinkService.lockNumber(phoneHash: phoneHash, on: tx)
                    holding.set()
                    try await Task.sleep(nanoseconds: 1_500_000_000)
                    try await PhoneLinkRecord.query(on: tx).filter(\.$id == ids.pending.uuid).set(\.$state, to: "revoked").update()
                    committed.set()
                }
            }
            while !holding.value { try await Task.sleep(nanoseconds: 20_000_000) }
            let moved = try await PhoneLinkService(db: db, ctx: ctx).completeTransfers()
            XCTAssertTrue(committed.value, "the job waited for the Keep transaction instead of racing it")
            try await keeper.value
            XCTAssertEqual(moved, 0)
            let kept = try await XCTUnwrapAsync(await PhoneLinkRecord.find(ids.oldLink.uuid, on: db))
            XCTAssertEqual(kept.state, "verified")
            let pending = try await XCTUnwrapAsync(await PhoneLinkRecord.find(ids.pending.uuid, on: db))
            XCTAssertEqual(pending.state, "revoked", "a committed Keep is not set back to verified")
            try await eq(try await h.gatewayConsumer(phone), oldOwner.id)
        }
    }

    /// The same with UNLINK: a suspension committed during a transfer run is not undone and the number does not move to a requester.
    func testOnPostgresRealKeepAndTheJobRunTogetherAlwaysLeaveOneConsistentOutcome() async throws {
        try requirePostgres()
        try await withHarness { h in
            var oldOwner = try await h.readyConsumer(name: "Old")
            var newOwner = try await h.readyConsumer(name: "New")
            let ids = try await pendingTransfer(h, oldOwner: oldOwner, newOwner: &newOwner)
            oldOwner = try await h.login(oldOwner)
            let noticeAll = try await notices(h, oldOwner)
            let notice = try XCTUnwrap(noticeAll.first { $0.topic == .phoneTransferRequested })
            try await eq(try await markSeen(h, oldOwner, notice).status, .ok)
            h.clock.advance(by: 72 * 3600 + 1)
            oldOwner = try await h.login(oldOwner)  // the earlier session expired while the clock moved past the 72-hour window
            let (db, ctx) = (h.db, h.ctx)
            let owner = oldOwner
            async let job: Int = PhoneLinkService(db: db, ctx: ctx).completeTransfers()
            async let keep: HTTPResult = h.signedPost(owner, "/v1/phone-links/\(ids.oldLink)/keep", EmptyBody())
            async let job2: Int = PhoneLinkService(db: db, ctx: ctx).completeTransfers()
            let (moved1, keepResult, moved2) = try await (job, keep, job2)
            XCTAssertTrue([HTTPResponseStatus.ok, .notFound].contains(keepResult.status), "Keep either won or found the number already moved: \(keepResult.text)")
            let holders = try await PhoneLinkRecord.query(on: db).filter(\.$verifiedPhoneHash == ctx.hasher.phoneHash(PhoneNumber(phone)!)).all()
            XCTAssertEqual(holders.count, 1, "exactly one holder")
            let pending = try await XCTUnwrapAsync(await PhoneLinkRecord.find(ids.pending.uuid, on: db))
            if pending.state == "verified" {
                // The job won the race: the number moved exactly once and the old link is revoked (Keep found nothing left to refuse).
                XCTAssertEqual(moved1 + moved2, 1)
                XCTAssertEqual(keepResult.status, .notFound)
                XCTAssertEqual(holders.first?.id, ids.pending.uuid)
            } else {
                XCTAssertEqual(pending.state, "revoked")
                XCTAssertEqual(moved1 + moved2, 0)
                XCTAssertEqual(keepResult.status, .ok)
                XCTAssertEqual(holders.first?.id, ids.oldLink.uuid)
            }
        }
    }
}

/// A flag two tasks can poll without a data race.
final class LockedFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false
    var value: Bool { lock.lock(); defer { lock.unlock() }; return flag }
    func set() { lock.lock(); flag = true; lock.unlock() }
}
