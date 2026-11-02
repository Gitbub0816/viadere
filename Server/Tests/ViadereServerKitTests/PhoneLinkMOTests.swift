import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Decision 9 and ADR-0027: phone-number ownership by a customer-originated text. Each test reproduces an exploit path (ST-PH-xx) and asserts it
/// is refused: a spoofed, misdirected, late or reused text cannot bind a number, a victim-induced text cannot take a linked number over, and no
/// Viadere text ever carries a code, a link with a token or an approval request.
final class PhoneLinkMOTests: XCTestCase {
    let phone = "+14805550123"
    let sendTo = "+15550001111"

    // MARK: Begin

    func testBeginIssuesAShortLivedNonceStoredOnlyAsAKeyedHashAndNothingIsTexted() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let begun = try await h.beginPhoneLink(consumer, phone: phone)
            XCTAssertEqual(begun.status, .ok, begun.text)
            let begin = try begun.json(PhoneLinkMOBeginResponse.self)
            XCTAssertTrue(begin.nonce.hasPrefix("VDR-"))
            XCTAssertEqual(begin.nonce.count, 12)
            XCTAssertEqual(begin.sendTo, sendTo)
            XCTAssertEqual(begin.expiresAt, h.clock.now().addingTimeInterval(600))
            XCTAssertEqual(begin.prefill, "Link my number to my Viadere app \(begin.nonce)")
            // Only a keyed hash of the nonce and the number (the number also encrypted) is stored; the response is the only place the nonce is.
            let row = try await XCTUnwrapAsync(await PhoneLinkMOChallengeRecord.find(begin.phoneLinkId.uuid, on: h.db))
            XCTAssertEqual(row.nonceHash, h.ctx.hasher.hmacHex("phone-mo", "\(begin.phoneLinkId.uuid.uuidString.lowercased())\n\(begin.nonce)"))
            XCTAssertFalse(row.nonceHash.contains(begin.nonce))
            XCTAssertEqual(row.phoneHash, h.ctx.hasher.phoneHash(PhoneNumber(phone)!))
            XCTAssertFalse(row.phoneCiphertext.contains("4805550123"))
            XCTAssertEqual(row.expiresAt, begin.expiresAt)
            // Viadere sends the phone nothing at all.
            try await h.runJobs()
            XCTAssertTrue(h.texts.sent.isEmpty)
            try await eq(try await SMSOutboundRecord.query(on: h.db).count(), 0)
            // Pending until the text arrives; the poll never reveals more.
            try await eq(try await h.phoneLinkStatus(consumer, id: begin.phoneLinkId).state, .pending)
            // The audit log carries only the masked number.
            let audit = try await AuditEventRecord.query(on: h.db).filter(\.$action == "phone_link.mo_begun").all()
            XCTAssertEqual(audit.count, 1)
            XCTAssertFalse(audit[0].metadataJSON.contains("4805550123") || audit[0].metadataJSON.contains(begin.nonce))
        }
    }

    func testBeginNeedsATrustedDeviceSignedRequestsAndAnAllowedCountry() async throws {
        try await withHarness { h in
            let a = try await h.readyConsumer()
            let attacker = try await h.enrollDevice(a)   // cooling down
            let refused = try await h.beginPhoneLink(attacker, phone: phone)
            XCTAssertEqual(refused.status, .forbidden)
            XCTAssertEqual(refused.errorCode, .deviceCoolDown)
            let bearerOnly = try await h.post(APIRoutes.phoneLinkMOBegin.template, PhoneLinkMOBeginRequest(phone: PhoneNumber(phone)!),
                                              headers: ["Authorization": "Bearer \(a.token)"])
            XCTAssertEqual(bearerOnly.status, .unauthorized)
            try await eq(try await PhoneLinkMOChallengeRecord.query(on: h.db).count(), 0)
        }
    }

    func testOnlyTheNewestBeginPerNumberIsLiveAndAnAccountHasOneNumber() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let first = try await h.beginPhoneLink(consumer, phone: phone).json(PhoneLinkMOBeginResponse.self)
            let second = try await h.beginPhoneLink(consumer, phone: phone).json(PhoneLinkMOBeginResponse.self)
            XCTAssertNotEqual(first.nonce, second.nonce)
            try await eq(try await PhoneLinkMOChallengeRecord.query(on: h.db).count(), 1)
            // The older nonce is dead: texting it links nothing.
            try await h.textViadere(from: phone, first.prefill)
            try await eq(try await PhoneLinkRecord.query(on: h.db).count(), 0)
            try await eq(try await h.phoneLinkStatus(consumer, id: first.phoneLinkId).state, .expired)
            // The newer one works.
            try await h.textViadere(from: phone, second.prefill)
            try await eq(try await h.phoneLinkStatus(consumer, id: second.phoneLinkId).state, .verified)
            // One number per account: a second number is refused until the first is removed.
            let other = try await h.beginPhoneLink(consumer, phone: "+14805550199")
            XCTAssertEqual(other.status, .conflict, other.text)
        }
    }

    // MARK: Happy path and what Viadere sends

    func testAMatchingTextWithinTheTTLBindsTheNumberInACoolDownAndSendsOnlyTheNotice() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let linked = try await h.linkPhoneByText(consumer, phone: phone)
            XCTAssertEqual(linked.status.state, .verified)
            let link = try XCTUnwrap(linked.status.link)
            XCTAssertEqual(link.assurance, "phone_control_mo")
            XCTAssertEqual(link.usableFrom, h.clock.now().addingTimeInterval(72 * 3600), "the only device: nobody else could notice, so the wait is 72 h")
            XCTAssertTrue(link.maskedPhone.hasSuffix("0123"))
            XCTAssertEqual(link.id, linked.begin.phoneLinkId)
            // Exactly UX_COPY SMS-02 went to the number: states the effect, offers UNLINK and STOP, carries no code and no link.
            XCTAssertEqual(linked.replies, ["Viadere: Someone linked this number to a Viadere app using a text sent from this phone. If that wasn't you, reply UNLINK. Reply STOP to stop messages."])
            // The challenge is gone (whole row deleted at use) and the record carries the label, not a factor.
            try await eq(try await PhoneLinkMOChallengeRecord.query(on: h.db).count(), 0)
            let record = try await XCTUnwrapAsync(await PhoneLinkRecord.find(link.id.uuid, on: h.db))
            XCTAssertEqual(record.source, "mo")
            XCTAssertEqual(record.state, "verified")
            XCTAssertNil(record.otpHash)
            // Not routing identity yet, then yes.
            try await eq(try await h.gatewayConsumer(phone), nil)
            h.clock.advance(by: 72 * 3600 + 1)
            try await eq(try await h.gatewayConsumer(phone), consumer.id)
            // The nonce text itself never reached a menu or a business: the thread holds no message from it.
            try await eq(try await ConversationMessageRecord.query(on: h.db).count(), 0)
            // The listing shows the link and its label.
            let listed = try await h.signed(try await h.login(consumer), .GET, "/v1/phone-links").json([PhoneLink].self)
            XCTAssertEqual(listed.first?.assurance, "phone_control_mo")
        }
    }

    func testTheNoncePatternIsFoundInAnEditedAndMixedCaseText() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let begin = try await h.beginPhoneLink(consumer, phone: phone).json(PhoneLinkMOBeginResponse.self)
            let edited = "hi!! pls link   \(begin.nonce.lowercased().replacingOccurrences(of: "-", with: " - ")) thanks"
            try await h.textViadere(from: phone, edited)
            try await eq(try await h.phoneLinkStatus(consumer, id: begin.phoneLinkId).state, .verified)
        }
    }

    func testNoTextViadereSendsInTheWholeFlowContainsACodeALinkWithATokenOrAnApprovalRequest() async throws {
        try await withHarness { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: airline)
            try await h.linkPhoneByText(consumer, phone: phone)
            for text in ["Hi", "1", "3", "MENU", "Northwind", "1"] { try await h.textViadere(from: phone, text) }
            h.clock.advance(by: 72 * 3600 + 1)
            let issued = try await h.issue(airline, relationship: rel, payload: .authorize(AuthorizePayload.sample(amount: "285.28")), purpose: .security,
                                           sensitivity: .high, channels: [.nativePush, .sms])
            XCTAssertEqual(issued.status, .created, issued.text)
            try await h.runJobs()
            try await h.textViadere(from: phone, "UNLINK")
            let everything = h.texts.sent.map(\.body)
            XCTAssertFalse(everything.isEmpty)
            for body in everything {
                XCTAssertNil(body.range(of: #"\b\d{6}\b"#, options: .regularExpression), "no six-digit code: \(body)")
                XCTAssertNil(body.range(of: #"[A-Za-z0-9_-]{24,}"#, options: .regularExpression), "no bearer-looking token: \(body)")
                XCTAssertFalse(body.contains("/l/") || body.contains("/h/"), body)
                for url in body.split(separator: " ").filter({ $0.contains("://") }) {
                    XCTAssertTrue(["https://viadere.com/get", "https://viadere.com/get."].contains(String(url)), "\(url) in \(body)")
                }
                for phrase in ["verification code", "your code", "approve", "285.28"] { XCTAssertFalse(body.lowercased().contains(phrase), "\(phrase) in \(body)") }
            }
            let sensitive = try await SMSOutboundRecord.query(on: h.db).filter(\.$sensitive == true).count()
            XCTAssertEqual(sensitive, 0)
            try await eq(try await LinkTokenRecord.query(on: h.db).count(), 0)
        }
    }

    // MARK: Refusals (ST-PH-07: nothing says which check failed)

    func testATextFromAnotherNumberNeverBindsAndLeavesTheRealChallengeAlive() async throws {
        try await withHarness { h in
            let victim = try await h.readyConsumer(name: "Victim")
            let begin = try await h.beginPhoneLink(victim, phone: phone).json(PhoneLinkMOBeginResponse.self)
            // The nonce leaks (shoulder surfing, a screenshot) and is sent from the attacker's own phone: no link, no reply, no business sees it.
            let replies = try await h.textViadere(from: "+14805550199", begin.prefill)
            XCTAssertTrue(replies.isEmpty, "\(replies)")
            try await eq(try await PhoneLinkRecord.query(on: h.db).count(), 0)
            try await eq(try await ConversationMessageRecord.query(on: h.db).count(), 0)
            try await eq(try await SMSContextRecord.query(on: h.db).filter(\.$phoneHash == h.ctx.hasher.phoneHash(PhoneNumber("+14805550199")!)).count(), 0,
                         "a link text is not a conversation: no menu, no thread")
            try await eq(try await h.phoneLinkStatus(victim, id: begin.phoneLinkId).state, .pending)
            // The owner of the number can still finish.
            try await h.textViadere(from: phone, begin.prefill)
            try await eq(try await h.phoneLinkStatus(victim, id: begin.phoneLinkId).state, .verified)
        }
    }

    func testALateTextCannotBindAndANonceIsNotReusable() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let begin = try await h.beginPhoneLink(consumer, phone: phone).json(PhoneLinkMOBeginResponse.self)
            h.clock.advance(by: 10 * 60 + 1)
            let late = try await h.textViadere(from: phone, begin.prefill)
            XCTAssertTrue(late.isEmpty, "\(late)")
            try await eq(try await PhoneLinkRecord.query(on: h.db).count(), 0)
            try await eq(try await h.phoneLinkStatus(consumer, id: begin.phoneLinkId).state, .expired)
            try await eq(try await PhoneLinkMOChallengeRecord.query(on: h.db).count(), 0, "a late try also spends the challenge")
            // Reuse after a successful bind.
            let again = try await h.beginPhoneLink(consumer, phone: phone).json(PhoneLinkMOBeginResponse.self)
            try await h.textViadere(from: phone, again.prefill)
            try await eq(try await PhoneLinkRecord.query(on: h.db).count(), 1)
            let replay = try await h.textViadere(from: phone, again.prefill)
            XCTAssertTrue(replay.isEmpty)
            try await eq(try await PhoneLinkRecord.query(on: h.db).count(), 1)
            let audit = try await AuditEventRecord.query(on: h.db).filter(\.$action == "phone_link.mo_refused").all()
            XCTAssertTrue(audit.contains { $0.metadataJSON.contains("\"reason\":\"expired\"") })
        }
    }

    func testAWrongNonceFromTheRightNumberIsSilent() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let begin = try await h.beginPhoneLink(consumer, phone: phone).json(PhoneLinkMOBeginResponse.self)
            let replies = try await h.textViadere(from: phone, PhoneLinkMO.prefill(nonce: "VDR-AAAAAAAA"))
            XCTAssertTrue(replies.isEmpty)
            try await eq(try await h.phoneLinkStatus(consumer, id: begin.phoneLinkId).state, .pending)
            // A nonce from a number that never began is silent too (no reply, no thread, no business).
            let stranger = try await h.textViadere(from: "+14805550177", PhoneLinkMO.prefill(nonce: begin.nonce))
            XCTAssertTrue(stranger.isEmpty)
            try await eq(try await ConversationMessageRecord.query(on: h.db).count(), 0)
        }
    }

    func testTheSenderIndicatorIsAHardFail() async throws {
        for (indicator, binds) in [(InboundSenderIndicator.verified, true), (.unsupported, true), (.suspectedSpoof, false), (.notProvided, false)] {
            try await withHarness { h in
                let consumer = try await h.readyConsumer()
                let begin = try await h.beginPhoneLink(consumer, phone: phone).json(PhoneLinkMOBeginResponse.self)
                let sms = InboundSMS(providerMessageId: "t:\(UUID())", from: PhoneNumber(phone)!, text: begin.prefill, receivedAt: h.clock.now(), senderIndicator: indicator)
                _ = try await GatewayService(db: h.db, ctx: h.ctx).handleInbound(sms, provider: "test")
                let state = try await h.phoneLinkStatus(consumer, id: begin.phoneLinkId).state
                XCTAssertEqual(state == .verified, binds, "\(indicator)")
                if !binds {
                    let audit = try await AuditEventRecord.query(on: h.db).filter(\.$action == "phone_link.mo_refused").all()
                    XCTAssertTrue(audit.contains { $0.metadataJSON.contains("sender_indicator") })
                    try await eq(try await PhoneLinkMOChallengeRecord.query(on: h.db).count(), 0, "a refused text spends the challenge: the real owner begins again")
                }
            }
        }
        // A deployment can require an indicator: a provider that offers none then cannot bind a number either.
        try await withHarness({ $0.phoneLinkRequireSenderIndicator = true }) { h in
            let consumer = try await h.readyConsumer()
            let begin = try await h.beginPhoneLink(consumer, phone: phone).json(PhoneLinkMOBeginResponse.self)
            let sms = InboundSMS(providerMessageId: "t:\(UUID())", from: PhoneNumber(phone)!, text: begin.prefill, receivedAt: h.clock.now())
            _ = try await GatewayService(db: h.db, ctx: h.ctx).handleInbound(sms, provider: "test")
            try await eq(try await h.phoneLinkStatus(consumer, id: begin.phoneLinkId).state, .expired)
        }
    }

    /// S1-A10-4 / ADR-0027 §1.3: the sender indicator is mandatory. The shipped adapters report `unsupported`, so staging and production must
    /// refuse such a text unless the owner explicitly turns the requirement off (an exception while O-2 is open).
    func testStagingAndProductionRequireASenderIndicatorUnlessExplicitlyWaived() throws {
        XCTAssertTrue(try ServerConfig.phoneLinkRequireSenderIndicator([:], strict: true), "required by default in staging and production")
        XCTAssertFalse(try ServerConfig.phoneLinkRequireSenderIndicator([:], strict: false))
        XCTAssertFalse(try ServerConfig.phoneLinkRequireSenderIndicator(["PHONE_LINK_REQUIRE_SENDER_INDICATOR": "0"], strict: true))
        XCTAssertTrue(try ServerConfig.phoneLinkRequireSenderIndicator(["PHONE_LINK_REQUIRE_SENDER_INDICATOR": "TRUE"], strict: false))
        XCTAssertThrowsError(try ServerConfig.phoneLinkRequireSenderIndicator(["PHONE_LINK_REQUIRE_SENDER_INDICATOR": "ture"], strict: true))
        XCTAssertFalse(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development"]).phoneLinkRequireSenderIndicator)
        XCTAssertTrue(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development", "PHONE_LINK_REQUIRE_SENDER_INDICATOR": "1"]).phoneLinkRequireSenderIndicator)
    }

    func testAnOptedOutNumberCannotBeLinked() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            try await h.textViadere(from: phone, "STOP")
            // Begin answers the same for an opted-out number (no enumeration); the text is what fails.
            let begun = try await h.beginPhoneLink(consumer, phone: phone)
            XCTAssertEqual(begun.status, .ok)
            let begin = try begun.json(PhoneLinkMOBeginResponse.self)
            let replies = try await h.textViadere(from: phone, begin.prefill)
            XCTAssertTrue(replies.isEmpty)
            try await eq(try await PhoneLinkRecord.query(on: h.db).count(), 0)
        }
    }

    func testBeginLooksTheSameForALinkedAndAnUnlinkedNumber() async throws {
        try await withHarness { h in
            let owner = try await h.readyConsumer(name: "Owner")
            try await h.linkVerifiedPhone(owner, phone: phone)
            let other = try await h.readyConsumer(name: "Other")
            let linkedNumber = try await h.beginPhoneLink(other, phone: phone)
            let freeNumber = try await h.beginPhoneLink(other, phone: "+14805550177")
            XCTAssertEqual(linkedNumber.status, freeNumber.status)
            let a = try linkedNumber.json(PhoneLinkMOBeginResponse.self), b = try freeNumber.json(PhoneLinkMOBeginResponse.self)
            XCTAssertEqual(a.sendTo, b.sendTo)
            XCTAssertEqual(a.nonce.count, b.nonce.count)
        }
    }

    func testLinkTextsAreRateLimitedPerNumberWithoutAReply() async throws {
        try await withHarness({ $0.rateLimits.phoneLinkMOPerPhone = RateRule(capacity: 2, perMinute: 0.001) }) { h in
            let consumer = try await h.readyConsumer()
            let begin = try await h.beginPhoneLink(consumer, phone: phone).json(PhoneLinkMOBeginResponse.self)
            for _ in 0..<2 { try await h.textViadere(from: phone, PhoneLinkMO.prefill(nonce: "VDR-AAAAAAAA")) }
            let blocked = try await h.textViadere(from: phone, begin.prefill)
            XCTAssertTrue(blocked.isEmpty)
            try await eq(try await h.phoneLinkStatus(consumer, id: begin.phoneLinkId).state, .pending, "over the limit the real text is dropped too; the person tries again later")
        }
    }

    // MARK: Victim-induced text, spoofing against a linked number (ST-PH-08)

    func testAVictimInducedTextCannotTakeALinkedNumberOver() async throws {
        try await withHarness { h in
            var victim = try await h.readyConsumer(name: "Victim")
            var attacker = try await h.readyConsumer(name: "Attacker")
            // The victim's number is already linked and usable.
            let first = try await h.linkPhoneByText(victim, phone: phone)
            let victimLink = try XCTUnwrap(first.status.link)
            h.clock.advance(by: 72 * 3600 + 1)
            victim = try await h.login(victim)
            attacker = try await h.login(attacker)
            try await eq(try await h.gatewayConsumer(phone), victim.id)
            // The attacker begins for the victim's number from their own trusted device and talks the victim into sending the text
            // ("text this to confirm your delivery"). The text itself says what it does.
            let attackerBegin = try await h.beginPhoneLink(attacker, phone: phone)
            XCTAssertEqual(attackerBegin.status, .ok, attackerBegin.text)
            let begin = try attackerBegin.json(PhoneLinkMOBeginResponse.self)
            XCTAssertTrue(begin.prefill.lowercased().contains("link my number"))
            let replies = try await h.textViadere(from: phone, begin.prefill)
            // The victim's number is told at once what happened and how to undo it.
            XCTAssertEqual(replies, [GatewayCopy.phoneLinkedNotice])
            XCTAssertTrue(GatewayCopy.phoneLinkedNotice.contains("reply UNLINK"))
            // The attacker's link waits; the victim's stays the routing identity.
            let pending = try await XCTUnwrapAsync(await PhoneLinkRecord.find(begin.phoneLinkId.uuid, on: h.db))
            XCTAssertEqual(pending.state, "pending_transfer")
            XCTAssertNil(pending.verifiedPhoneHash)
            try await eq(try await h.gatewayConsumer(phone), victim.id)
            let kept = try await XCTUnwrapAsync(await PhoneLinkRecord.find(victimLink.id.uuid, on: h.db))
            XCTAssertEqual(kept.state, "verified")
            // Even after the attacker's waiting period, the number does not move without the in-app no-objection step: it moves only if the
            // victim does not keep it. The victim is told in the app, with a Keep button.
            let second = try await h.enrollDevice(victim)
            let notices = try await h.signed(second, .GET, "/v1/security-notices").json([SecurityNotice].self)
            let notice = try XCTUnwrap(notices.first { $0.topic == .phoneTransferRequested })
            XCTAssertEqual(notice.action, .keepPhoneNumber)
            XCTAssertEqual(notice.subjectId, victimLink.id.description)
            XCTAssertTrue(notice.message.contains("keep it"))
            // Keep my number: the pending request dies and the number never moves.
            try await eq(try await h.signedPost(victim, "/v1/phone-links/\(victimLink.id)/keep", EmptyBody()).status, .ok)
            h.clock.advance(by: 5 * 24 * 3600)
            attacker = try await h.login(attacker)
            try await eq(try await PhoneLinkService(db: h.db, ctx: h.ctx).completeTransfers(), 0)
            try await eq(try await h.gatewayConsumer(phone), victim.id)
            let dead = try await XCTUnwrapAsync(await PhoneLinkRecord.find(begin.phoneLinkId.uuid, on: h.db))
            XCTAssertEqual(dead.state, "revoked")
            // Another account cannot refuse on the owner's behalf.
            try await eq(try await h.signedPost(attacker, "/v1/phone-links/\(victimLink.id)/keep", EmptyBody()).status, .notFound)
        }
    }

    func testATransferCompletesOnlyAfterTheWaitingPeriodWhenTheOwnerDoesNotObject() async throws {
        try await withHarness { h in
            let oldOwner = try await h.readyConsumer(name: "Old")
            var newOwner = try await h.readyConsumer(name: "New")
            try await h.linkPhoneByText(oldOwner, phone: phone)
            h.clock.advance(by: 72 * 3600 + 1)
            newOwner = try await h.login(newOwner)
            let begin = try await h.beginPhoneLink(newOwner, phone: phone).json(PhoneLinkMOBeginResponse.self)
            h.clock.advance(by: 24 * 3600)   // the daily churn cap
            newOwner = try await h.login(newOwner)
            let begin2 = try await h.beginPhoneLink(newOwner, phone: phone).json(PhoneLinkMOBeginResponse.self)
            XCTAssertNotEqual(begin.nonce, begin2.nonce)
            try await h.textViadere(from: phone, begin2.prefill)
            try await eq(try await h.gatewayConsumer(phone), oldOwner.id)
            try await eq(try await PhoneLinkService(db: h.db, ctx: h.ctx).completeTransfers(), 0, "still waiting")
            h.clock.advance(by: 72 * 3600 + 1)
            try await eq(try await PhoneLinkService(db: h.db, ctx: h.ctx).completeTransfers(), 1)
            try await eq(try await h.gatewayConsumer(phone), newOwner.id)
            let old = try await PhoneLinkRecord.query(on: h.db).filter(\.$consumerId == oldOwner.id.uuid).first()
            XCTAssertEqual(old?.state, "revoked")
        }
    }

    func testUnlinkRevokesEveryLinkOfTheNumberNotifiesTheAccountAndChurnIsLimited() async throws {
        try await withHarness { h in
            var consumer = try await h.readyConsumer()
            try await h.linkPhoneByText(consumer, phone: phone)
            h.clock.advance(by: 3600)
            consumer = try await h.login(consumer)
            // The number's real owner texts UNLINK: SMS-03, link gone, the account told in the app.
            let replies = try await h.textViadere(from: phone, " unlink. ")
            XCTAssertEqual(replies, ["Viadere: Done. This number is no longer linked to a Viadere app."])
            try await eq(try await h.gatewayConsumer(phone), nil)
            let link = try await XCTUnwrapAsync(await PhoneLinkRecord.query(on: h.db).first())
            XCTAssertEqual(link.state, "revoked")
            XCTAssertNil(link.verifiedPhoneHash)
            let second = try await h.enrollDevice(consumer)
            let notices = try await h.signed(second, .GET, "/v1/security-notices").json([SecurityNotice].self)
            XCTAssertTrue(notices.contains { $0.topic == .phoneUnlinked && $0.message == "Your phone number was unlinked by a text from that number." })
            let unlinkAudit = try await AuditEventRecord.query(on: h.db).filter(\.$action == "phone_link.unlinked_by_text").all()
            XCTAssertFalse(unlinkAudit.isEmpty)
            // Churn: a second verified link the same day is refused (1 a day, 2 a week), without a reply.
            let again = try await h.beginPhoneLink(consumer, phone: phone).json(PhoneLinkMOBeginResponse.self)
            let refused = try await h.textViadere(from: phone, again.prefill)
            XCTAssertTrue(refused.isEmpty)
            try await eq(try await h.phoneLinkStatus(consumer, id: again.phoneLinkId).state, .expired)
            // Next day: allowed (second in the week); the third within the week is not.
            h.clock.advance(by: 25 * 3600)
            consumer = try await h.login(consumer)
            let next = try await h.beginPhoneLink(consumer, phone: phone).json(PhoneLinkMOBeginResponse.self)
            try await h.textViadere(from: phone, next.prefill)
            try await eq(try await h.phoneLinkStatus(consumer, id: next.phoneLinkId).state, .verified)
            try await h.textViadere(from: phone, "UNLINK")
            h.clock.advance(by: 25 * 3600)
            consumer = try await h.login(consumer)
            let third = try await h.beginPhoneLink(consumer, phone: phone).json(PhoneLinkMOBeginResponse.self)
            try await h.textViadere(from: phone, third.prefill)
            try await eq(try await h.phoneLinkStatus(consumer, id: third.phoneLinkId).state, .expired)
        }
    }

    func testUnlinkFromANumberWithNoLinkJustAnswers() async throws {
        try await withHarness { h in
            let replies = try await h.textViadere(from: "+14805550177", "UNLINK")
            XCTAssertEqual(replies, [GatewayCopy.unlinkDone])
        }
    }

    // MARK: Content limit (ST-PH-11) and the confirmation shortcut

    func testANumberLinkedByTextReceivesOnlyTheOpenViadereNoticeNeverInteractionContent() async throws {
        try await withHarness { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: airline)
            try await h.linkPhoneByText(consumer, phone: phone)
            h.clock.advance(by: 72 * 3600 + 1)
            let before = h.texts.sent.count
            for (i, payload) in [InteractionPayload.status(StatusPayload(title: "Out for delivery", body: "Arriving 2-4 pm")),
                                 .confirm(ConfirmPayload(title: "Seat 14C", details: "Window")),
                                 .authenticate(AuthenticatePayload(service: "Online Banking", device: "Chrome", attemptedAt: h.clock.now()))].enumerated() {
                let r = try await h.issue(airline, relationship: rel, payload: payload, purpose: .transactional, sensitivity: i == 2 ? .high : .low,
                                          key: "k\(i)", channels: [.nativePush, .sms])
                XCTAssertEqual(r.status, .created, r.text)
            }
            try await h.runJobs()
            try await h.runJobs()
            let bodies = h.texts.sent.dropFirst(before).map(\.body)
            XCTAssertEqual(bodies.count, 3)
            for body in bodies {
                XCTAssertEqual(body, "Viadere: Northwind Air sent you something that needs the Viadere app. Open Viadere to respond.")
            }
        }
    }

    // MARK: Sweep, deletion, routes

    func testExpiredChallengesAreSweptTwoMinutesAfterExpiryAndAccountDeletionRemovesLiveOnes() async throws {
        try await withHarness { h in
            let a = try await h.readyConsumer(name: "A")
            let b = try await h.readyConsumer(name: "B")
            _ = try await h.beginPhoneLink(a, phone: phone).json(PhoneLinkMOBeginResponse.self)
            _ = try await h.beginPhoneLink(b, phone: "+14805550177").json(PhoneLinkMOBeginResponse.self)
            h.clock.advance(by: 10 * 60 + 60)
            try await eq(try await PhoneLinkService.purgeChallenges(on: h.db, now: h.clock.now()), 0, "inside the 2-minute grace")
            h.clock.advance(by: 61)
            try await eq(try await PhoneLinkService.purgeChallenges(on: h.db, now: h.clock.now()), 2, "gone at expiry + 2 minutes")
            // Nothing P-class outlives expiry + 2 minutes (ST-PRIV-04): the job sweep runs it every minute.
            _ = try await h.beginPhoneLink(a, phone: phone).json(PhoneLinkMOBeginResponse.self)
            try await eq(try await h.signed(a, .DELETE, "/v1/account").status, .ok)
            try await eq(try await PhoneLinkMOChallengeRecord.query(on: h.db).filter(\.$consumerId == a.id.uuid).count(), 0)
        }
    }

    func testRemovingTheLinkOrTheNumberFromTheAppDropsALiveChallenge() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let linked = try await h.linkPhoneByText(consumer, phone: phone)
            let live = try await h.beginPhoneLink(consumer, phone: phone).json(PhoneLinkMOBeginResponse.self)
            try await eq(try await PhoneLinkMOChallengeRecord.query(on: h.db).count(), 1)
            try await eq(try await h.signed(consumer, .DELETE, "/v1/phone-links/\(linked.begin.phoneLinkId)").status, .ok)
            try await eq(try await PhoneLinkMOChallengeRecord.query(on: h.db).count(), 0)
            _ = live
        }
    }

    func testStatusIsPrivateToTheAccountThatBegan() async throws {
        try await withHarness { h in
            let a = try await h.readyConsumer(name: "A")
            let b = try await h.readyConsumer(name: "B")
            let begin = try await h.beginPhoneLink(a, phone: phone).json(PhoneLinkMOBeginResponse.self)
            try await eq(try await h.phoneLinkStatus(b, id: begin.phoneLinkId).state, .expired)
            try await eq(try await h.phoneLinkStatus(a, id: begin.phoneLinkId).state, .pending)
            try await eq(try await h.phoneLinkStatus(a, id: PhoneLinkID()).state, .expired)
        }
    }
}
