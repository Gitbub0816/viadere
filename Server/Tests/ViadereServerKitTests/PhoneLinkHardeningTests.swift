import Fluent
import Foundation
import NIOCore
import NIOHTTP1
import SQLKit
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
            XCTAssertTrue(notice.message.contains("link it again"), notice.message)
            XCTAssertFalse(notice.message.contains("remove it in Viadere settings"), "the copy must not lead the holder to remove the number")
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

    func testADeviceStillInCoolDownCanKeepTheNumber() async throws {
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
            _ = try await markSeen(h, newPhone, notice)
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

    // MARK: R-8: a forged UNLINK is a nuisance, not a weapon

    /// A forged UNLINK used to revoke every waiting transfer of the number, so a forger could keep a legitimate requester (a recycled number's new
    /// owner) from ever completing. UNLINK now touches only the holder's link; the waiting claim stays and still needs the holder's app to show it.
    func testAForgedUnlinkDoesNotWithdrawAGenuinePendingTransfer() async throws {
        try await withHarness { h in
            var oldOwner = try await h.readyConsumer(name: "Old")
            var newOwner = try await h.readyConsumer(name: "New")
            let ids = try await pendingTransfer(h, oldOwner: oldOwner, newOwner: &newOwner)
            try await unlinkText(h)
            let holder = try await XCTUnwrapAsync(await PhoneLinkRecord.find(ids.oldLink.uuid, on: h.db))
            XCTAssertNotNil(holder.suspendedAt, "the holder's link is paused")
            XCTAssertEqual(holder.state, "verified")
            let pending = try await XCTUnwrapAsync(await PhoneLinkRecord.find(ids.pending.uuid, on: h.db))
            XCTAssertEqual(pending.state, "pending_transfer", "a text from the number's phone does not cancel the waiting claim")
            let withdrawn = try await AuditEventRecord.query(on: h.db).filter(\.$action == "phone_link.transfer_withdrawn_by_text").count()
            XCTAssertEqual(withdrawn, 0)
            // The claim still follows the normal rule: nothing moves until the holder's app showed the notice, and Keep still works.
            oldOwner = try await h.login(oldOwner)
            let list = try await notices(h, oldOwner)
            let notice = try XCTUnwrap(list.first { $0.topic == .phoneTransferRequested })
            h.clock.advance(by: 72 * 3600 + 1)
            try await eq(try await PhoneLinkService(db: h.db, ctx: h.ctx).completeTransfers(), 0, "not seen: the number stays")
            try await eq(try await markSeen(h, oldOwner, notice).status, .ok)
            try await eq(try await PhoneLinkService(db: h.db, ctx: h.ctx).completeTransfers(), 1)
            newOwner = try await h.login(newOwner)
            let moved = try await XCTUnwrapAsync(await PhoneLinkRecord.find(ids.pending.uuid, on: h.db))
            XCTAssertEqual(moved.state, "verified")
        }
    }

    /// An induced `pending_transfer` row counted toward the churn cap, so the holder's own resume text right after a forged UNLINK was refused
    /// for up to a day. The holder's text creates no row, so it never meets the cap.
    func testTheHoldersResumeTextIsNotRefusedByTheChurnLimitAfterAForgedUnlink() async throws {
        try await withHarness { h in
            var oldOwner = try await h.readyConsumer(name: "Old")
            var newOwner = try await h.readyConsumer(name: "New")
            let ids = try await pendingTransfer(h, oldOwner: oldOwner, newOwner: &newOwner)
            // Two verified-or-waiting links of the number now exist inside the week: the cap is reached for any *new* link.
            try await unlinkText(h)
            oldOwner = try await h.login(oldOwner)
            let again = try await h.beginPhoneLink(oldOwner, phone: phone).json(PhoneLinkMOBeginResponse.self)
            try await h.textViadere(from: phone, again.prefill)
            let resumed = try await XCTUnwrapAsync(await PhoneLinkRecord.find(ids.oldLink.uuid, on: h.db))
            XCTAssertNil(resumed.suspendedAt, "the holder is back without waiting for the churn window")
            let refused = try await AuditEventRecord.query(on: h.db).filter(\.$action == "phone_link.mo_refused").all()
            XCTAssertTrue(refused.isEmpty, "no refusal was recorded for the holder")
            // A *new* account's link is still bound by the cap.
            let third = try await h.readyConsumer(name: "Third")
            let begin = try await h.beginPhoneLink(try await h.login(third), phone: phone).json(PhoneLinkMOBeginResponse.self)
            try await h.textViadere(from: phone, begin.prefill)
            let capped = try await PhoneLinkRecord.find(begin.phoneLinkId.uuid, on: h.db)
            XCTAssertNil(capped, "the churn cap still applies to a link for another account")
        }
    }

    // MARK: R-9: wording that does not steer the holder toward the one step that frees the number

    func testTheUnlinkNoticeLeadsWithLinkingAgainAndSaysRemovingFreesTheNumber() {
        for body in [SecurityNotices.Notice.phoneUnlinked.body] {
            let lower = body.lowercased()
            let link = lower.range(of: "link it again")
            let remove = lower.range(of: "remov")
            XCTAssertNotNil(link, body)
            XCTAssertNotNil(remove, body)
            if let link, let remove { XCTAssertLessThan(link.lowerBound, remove.lowerBound, "linking again comes first: \(body)") }
            XCTAssertTrue(lower.contains("free") || lower.contains("release"), "says what removing does: \(body)")
            XCTAssertFalse(lower.contains("remove it in viadere settings"), body)
            XCTAssertFalse(body.contains("!"), body)
        }
    }

    // MARK: R-9: a device in cool-down cannot mark a notice seen

    /// "Seen" is the condition that lets a transfer complete, so it is not a harmless record. A device still in cool-down (for example one enrolled
    /// by someone who took the account over through recovery) can Keep, but its report does not count; a trusted device's does.
    func testADeviceInCoolDownCannotMarkTheTransferNoticeSeen() async throws {
        try await withHarness { h in
            let oldOwner = try await h.readyConsumer(name: "Old")
            var newOwner = try await h.readyConsumer(name: "New")
            let ids = try await pendingTransfer(h, oldOwner: oldOwner, newOwner: &newOwner)
            let service = PhoneLinkService(db: h.db, ctx: h.ctx)
            let coolingPhone = try await h.enrollDevice(try await h.login(oldOwner), name: "Unapproved phone")
            let device = try await XCTUnwrapAsync(await DeviceRecord.find(coolingPhone.device!.id.uuid, on: h.db))
            XCTAssertFalse(device.isTrusted(at: h.clock.now()), "precondition: the device is in cool-down")
            let list = try await notices(h, coolingPhone)
            let notice = try XCTUnwrap(list.first { $0.topic == .phoneTransferRequested })
            _ = try await markSeen(h, coolingPhone, notice)
            func fetchedAt() async throws -> Date? {
                try await XCTUnwrapAsync(await SecurityNoticeRecord.find(notice.id, on: h.db)).fetchedAt
            }
            let afterCoolDown = try await fetchedAt()
            XCTAssertNil(afterCoolDown, "a device in cool-down cannot say the holder saw the notice")
            h.clock.advance(by: 72 * 3600 + 1)
            try await eq(try await service.completeTransfers(), 0, "the number stays with the holder")
            try await eq(try await h.gatewayConsumer(phone), oldOwner.id)
            // The holder's trusted phone shows it: that counts.
            try await eq(try await markSeen(h, oldOwner, notice).status, .ok)
            let afterTrusted = try await fetchedAt()
            XCTAssertNotNil(afterTrusted)
            try await eq(try await service.completeTransfers(), 1)
            _ = ids
        }
    }

    // MARK: R-10: the lease never gates the P-class sweep

    /// F-3 isolated the challenge sweep from every other task so a failure elsewhere never skips it. The lease sat in front of it: a lease that is
    /// taken (or a lease table that fails, or a row written by an instance whose clock runs ahead) skipped the sweep too.
    func testTheChallengeSweepRunsEvenWhenTheMinuteLeaseIsTaken() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            _ = try await h.beginPhoneLink(consumer, phone: phone)
            try await eq(try await PhoneLinkMOChallengeRecord.query(on: h.db).count(), 1)
            h.clock.advance(by: 3600)
            let other = UUID()
            try await eq(try await JobLease.acquire(BackgroundJobs.minuteLease, holder: other, ttl: 50, on: h.db, now: h.clock.now()), true)
            try await BackgroundJobs(app: h.app).run(.minute)
            try await eq(try await PhoneLinkMOChallengeRecord.query(on: h.db).count(), 0, "an expired challenge is gone although another run holds the lease")
        }
    }

    // MARK: R-2: PostgreSQL concurrency

    private func requirePostgres() throws {
        guard ProcessInfo.processInfo.environment["TEST_DATABASE_URL"].map({ !$0.isEmpty }) == true else {
            throw XCTSkip("needs PostgreSQL (TEST_DATABASE_URL): SQLite serializes writers and has no row locks")
        }
    }

    /// Two databases on **different event loops**. Each event loop's pool holds its own connection, so these are two PostgreSQL sessions; two
    /// handles of the same loop (what `h.db` gives, captured once) share one connection and make a race test vacuous (R-6). The back-end process
    /// ids are compared, so the premise of every race test below is itself asserted.
    private func twoConnections(_ h: TestHarness) async throws -> (first: any Database, second: any Database) {
        let loops = Array(h.app.eventLoopGroup.makeIterator())
        try XCTSkipIf(loops.count < 2, "needs an event loop group with at least two loops")
        let first = try XCTUnwrap(h.app.databases.database(.psql, logger: h.app.logger, on: loops[0]))
        let second = try XCTUnwrap(h.app.databases.database(.psql, logger: h.app.logger, on: loops[1]))
        func pid(_ db: any Database) async throws -> Int {
            let sql = try XCTUnwrap(db as? any SQLDatabase)
            return try await XCTUnwrapAsync(await sql.raw("SELECT pg_backend_pid() AS pid").first(decodingColumn: "pid", as: Int.self))
        }
        let (a, b) = (try await pid(first), try await pid(second))
        XCTAssertNotEqual(a, b, "the two handles must be two PostgreSQL connections, otherwise the race test proves nothing")
        return (first, second)
    }

    /// Plays one side of a race: a transaction on its own connection that takes the number's row locks (as every real decision about a number
    /// does), holds them for a while, runs `work` and commits late. The caller starts the other side meanwhile.
    private func lateTransaction(on db: any Database, phoneHash: String, holding: LockedFlag, committed: LockedFlag,
                                 _ work: @escaping @Sendable (any Database) async throws -> Void) -> Task<Void, any Error> {
        Task {
            try await db.transaction { tx in
                try await PhoneLinkService.lockNumber(phoneHash: phoneHash, on: tx)
                holding.set()
                try await Task.sleep(nanoseconds: 1_500_000_000)
                try await work(tx)
                committed.set()
            }
        }
    }

    /// A Keep that commits while the job already decided to move the number must win. The Keep side runs on one connection and the job on
    /// another, so the job really has to wait for the Keep's row lock; with `lockNumber` removed from `completeTransfers` this test fails (the
    /// job moves the number first and the late Keep write is then lost or overwritten).
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
            let (keeperDB, jobDB) = try await twoConnections(h)
            let ctx = h.ctx
            let phoneHash = ctx.hasher.phoneHash(PhoneNumber(phone)!)
            let committed = LockedFlag()
            let holding = LockedFlag()
            let keeper = lateTransaction(on: keeperDB, phoneHash: phoneHash, holding: holding, committed: committed) { tx in
                try await PhoneLinkRecord.query(on: tx).filter(\.$id == ids.pending.uuid).set(\.$state, to: "revoked").update()
            }
            while !holding.value { try await Task.sleep(nanoseconds: 20_000_000) }
            let moved = try await PhoneLinkService(db: jobDB, ctx: ctx).completeTransfers()
            XCTAssertTrue(committed.value, "the job waited for the Keep transaction instead of racing it")
            try await keeper.value
            XCTAssertEqual(moved, 0)
            let kept = try await XCTUnwrapAsync(await PhoneLinkRecord.find(ids.oldLink.uuid, on: keeperDB))
            XCTAssertEqual(kept.state, "verified")
            let pending = try await XCTUnwrapAsync(await PhoneLinkRecord.find(ids.pending.uuid, on: keeperDB))
            XCTAssertEqual(pending.state, "revoked", "a committed Keep is not set back to verified")
            try await eq(try await h.gatewayConsumer(phone), oldOwner.id)
        }
    }

    /// UNLINK against the job on two connections (R-6 asked for the case). Unlike Keep, an UNLINK no longer rewrites the state of a waiting claim
    /// (R-8), so a stale job cannot undo it; whether or not the lock is there, the job's first write waits for the UNLINK's row locks. This test pins the
    /// outcome of that interleaving: the paused holder is the one that held the number, the waiting claim is not withdrawn, the number moves exactly
    /// once and the new owner's link is not paused. It was checked to stay green with `lockNumber` removed from `completeTransfers`; the Keep test
    /// above is the one that fails without the lock.
    func testOnPostgresAnUnlinkThatCommitsWhileTheJobRunsPausesTheHolderNotTheNewOwner() async throws {
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
            let (unlinkDB, jobDB) = try await twoConnections(h)
            let ctx = h.ctx
            let number = PhoneNumber(phone)!
            let phoneHash = ctx.hasher.phoneHash(number)
            let committed = LockedFlag()
            let holding = LockedFlag()
            let unlinker = lateTransaction(on: unlinkDB, phoneHash: phoneHash, holding: holding, committed: committed) { tx in
                try await PhoneLinkService(db: unlinkDB, ctx: ctx).unlink(number: number, indicator: .unsupported, on: tx)
            }
            while !holding.value { try await Task.sleep(nanoseconds: 20_000_000) }
            let moved = try await PhoneLinkService(db: jobDB, ctx: ctx).completeTransfers()
            XCTAssertTrue(committed.value, "the job waited for the UNLINK transaction instead of racing it")
            try await unlinker.value
            XCTAssertEqual(moved, 1, "an UNLINK does not withdraw the genuine waiting transfer (R-8)")
            let old = try await XCTUnwrapAsync(await PhoneLinkRecord.find(ids.oldLink.uuid, on: unlinkDB))
            XCTAssertNotNil(old.suspendedAt, "the UNLINK paused the holder it found")
            let new = try await XCTUnwrapAsync(await PhoneLinkRecord.find(ids.pending.uuid, on: unlinkDB))
            XCTAssertEqual(new.state, "verified")
            XCTAssertNil(new.suspendedAt, "the new owner's link was not paused by a text that arrived before the transfer")
        }
    }

    /// Keep through the real endpoint and the job together always leave one consistent outcome, each job on its own connection.
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
            let (db1, db2) = try await twoConnections(h)
            let ctx = h.ctx
            let owner = oldOwner
            async let job: Int = PhoneLinkService(db: db1, ctx: ctx).completeTransfers()
            async let keep: HTTPResult = h.signedPost(owner, "/v1/phone-links/\(ids.oldLink)/keep", EmptyBody())
            async let job2: Int = PhoneLinkService(db: db2, ctx: ctx).completeTransfers()
            let (moved1, keepResult, moved2) = try await (job, keep, job2)
            XCTAssertTrue([HTTPResponseStatus.ok, .notFound].contains(keepResult.status), "Keep either won or found the number already moved: \(keepResult.text)")
            let db = db1
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
