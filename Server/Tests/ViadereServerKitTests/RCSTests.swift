import Fluent
import Foundation
import ViadereCore
import Vapor
import XCTest
@testable import ViadereServerKit

final class RCSTests: XCTestCase {
    let phone = RCSFixture.phone
    let channels: [DeliveryChannel] = [.nativePush, .inApp, .rcs, .sms]

    func withRCS(_ adjust: (inout ServerConfig) -> Void = { _ in }, _ body: (TestHarness, ScriptedRCSHTTP) async throws -> Void) async throws {
        let http = ScriptedRCSHTTP()
        try await withHarness(rcs: GenericRBMProvider(config: RCSFixture.config, http: http), adjust) { h in try await body(h, http) }
    }

    struct Scenario {
        var business: TestBusiness
        var consumer: TestConsumer
        var relationship: Relationship
    }

    func scenario(_ h: TestHarness, name: String = "Northwind Air", handle: String = "northwindair") async throws -> Scenario {
        let b = try await h.makeBusiness(name: name, handle: handle)
        let consumer = try await h.readyConsumer()
        try await h.linkVerifiedPhone(consumer)
        return Scenario(business: b, consumer: consumer, relationship: try await h.connect(consumer, to: b))
    }

    @discardableResult
    func issue(_ h: TestHarness, _ s: Scenario, _ payload: InteractionPayload, purpose: InteractionPurpose = .transactional, sensitivity: Sensitivity = .standard,
               channels: [DeliveryChannel]? = nil, key: String = UUID().uuidString) async throws -> Interaction {
        let r = try await h.issue(s.business, relationship: s.relationship, payload: payload, purpose: purpose, sensitivity: sensitivity, key: key, ttl: (payload.kind?.isSecuritySensitive ?? false) ? 600 : 3600,
                                  channels: channels ?? self.channels)
        XCTAssertEqual(r.status, .created, r.text)
        return try r.json(Interaction.self)
    }

    // MARK: Webhook authenticity

    func testInboundWebhooksMustCarryAValidFreshHMACSignature() async throws {
        try await withRCS { h, _ in
            let event: [String: Any] = ["messageId": "m1", "senderPhoneNumber": phone, "text": "hello"]
            let body = try JSONSerialization.data(withJSONObject: event, options: [.sortedKeys])
            // Missing, wrong-key, tampered-body, malformed and stale signatures are all the same 403.
            let missing = try await h.request(.POST, "/v1/providers/rcs/inbound", body: body)
            XCTAssertEqual(missing.status, .forbidden)
            let wrongKey = try await h.rcsInbound(event, secret: Base64URL.encode(Data(repeating: 1, count: 32)))
            XCTAssertEqual(wrongKey.status, .forbidden)
            let forSomethingElse = WebhookSignature.header(secret: RCSFixture.secret, body: Data("{}".utf8), now: h.clock.now())
            try await eq(try await h.rcsInbound(event, signature: forSomethingElse).status, .forbidden)
            try await eq(try await h.rcsInbound(event, signature: "garbage").status, .forbidden)
            try await eq(try await h.rcsInbound(event, signature: "t=1,v1=" + String(repeating: "0", count: 64)).status, .forbidden)
            try await eq(try await h.rcsInbound(event, at: h.clock.now().addingTimeInterval(-301)).status, .forbidden, "stale timestamp (replay)")
            try await eq(try await h.rcsInbound(event, at: h.clock.now().addingTimeInterval(301)).status, .forbidden, "future timestamp")
            try await eq(try await ProcessedProviderMessageRecord.query(on: h.db).count(), 0)
            // A correctly signed event is accepted (HMAC-SHA256 over "{t}." + body, constant time).
            try await eq(try await h.rcsInbound(event).status, .ok)
            // Rejections are audited without content.
            let audits = try await AuditEventRecord.query(on: h.db).filter(\.$action == "gateway.webhook_rejected").all()
            XCTAssertGreaterThanOrEqual(audits.count, 7)
            XCTAssertFalse(audits.contains { $0.metadataJSON.contains("hello") })
        }
    }

    func testMalformedAuthenticEventsAreRejectedWithoutSideEffects() async throws {
        try await withRCS { h, _ in
            for json in [["messageId": "", "senderPhoneNumber": phone, "text": "x"], ["senderPhoneNumber": phone, "text": "x"],
                         ["messageId": "m", "senderPhoneNumber": "not-a-phone", "text": "x"],
                         ["messageId": "m", "senderPhoneNumber": phone, "suggestionResponse": ["postbackData": String(repeating: "a", count: 300)]]] as [[String: Any]] {
                try await eq(try await h.rcsInbound(json).status, .badRequest)
            }
            // Unknown event types and empty events are ignored.
            try await eq(try await h.rcsInbound(["messageId": "m", "senderPhoneNumber": phone, "eventType": "TYPING"]).status, .ok)
            try await eq(try await h.rcsInbound(["messageId": "m2", "senderPhoneNumber": phone]).status, .ok)
        }
    }

    func testRCSIsRejectedWhenNoProviderIsConfigured() async throws {
        try await withHarness { h in
            XCTAssertFalse(h.ctx.channels.rcs.isEnabled)
            let r = try await h.rcsInbound(["messageId": "m", "senderPhoneNumber": phone, "text": "hi"])
            XCTAssertEqual(r.status, .forbidden)
        }
    }

    // MARK: Rendering and the postback flow

    func testConfirmIsRenderedAsSuggestedRepliesWithOpaqueSignedTokensAndTapsDecideIt() async throws {
        try await withRCS { h, http in
            let s = try await scenario(h)
            let interaction = try await issue(h, s, .confirm(ConfirmPayload(title: "Confirm seat 14C", details: "Flight NW 482", reference: "BK123")))
            // Nothing is sent until the worker runs (durable outbox).
            XCTAssertEqual(http.sends.count, 0)
            let outbox = try await XCTUnwrapAsync(await ChannelOutboundRecord.query(on: h.db).first())
            XCTAssertEqual(outbox.channel, "rcs")
            XCTAssertEqual(outbox.status, "queued")
            try await h.runJobs()
            XCTAssertEqual(http.capabilityChecks.count, 1)
            XCTAssertTrue(http.capabilityChecks[0].url.path.hasSuffix("/phones/\(phone)/capabilities"))
            XCTAssertEqual(http.capabilityChecks[0].headers["Authorization"], "Bearer provider-token-123")
            let sent = try h.rcsSentMessages(http)
            XCTAssertEqual(sent.count, 1)
            let message = sent[0]
            XCTAssertEqual(message["to"] as? String, phone)
            XCTAssertEqual(message["agentId"] as? String, "viadere-agent")
            let text = ((message["contentMessage"] as? [String: Any])?["text"] as? String) ?? ""
            XCTAssertTrue(text.hasPrefix("[Northwind Air]: Confirm seat 14C"), text)
            let taps = h.replyTokens(in: message)
            XCTAssertEqual(taps.map(\.text), ["Confirm", "Decline"])
            // Opaque: no interaction id, no decision words, no business id, no raw option — and the right shape.
            for (_, token) in taps {
                XCTAssertTrue(token.hasPrefix("vrp1."))
                XCTAssertLessThanOrEqual(token.count, 96)
                for forbidden in [interaction.id.description, s.business.id.description, "decision", "viadere:", "confirm", "decline"] {
                    XCTAssertFalse(token.lowercased().contains(forbidden.lowercased()), "\(forbidden) leaked into \(token)")
                }
                XCTAssertTrue(RCSPostbackTokens(hasher: h.ctx.hasher).isWellFormed(token))
            }
            XCTAssertNotEqual(taps[0].token, taps[1].token)
            // Only hashes are stored; the endpoint carries the active menu version.
            let postbacks = try await RCSPostbackRecord.query(on: h.db).all()
            XCTAssertEqual(postbacks.count, 2)
            XCTAssertTrue(postbacks.allSatisfy { $0.state == "open" && !taps.map(\.token).contains($0.tokenHash) && $0.menuVersion == 1 })
            try await eq(try await ChannelEndpointRecord.query(on: h.db).first()?.activeMenuVersion, 1)
            try await eq(try await ChannelOutboundRecord.query(on: h.db).first()?.status, "sent")
            // Metering: one RCS message, categorized as transport.
            let usage = try await UsageEventRecord.query(on: h.db).filter(\.$meter == "rcs_message").all()
            XCTAssertEqual(usage.count, 1)
            XCTAssertEqual(usage[0].category, "transport")
            // The user taps Confirm.
            let tap = try await h.rcsTap(token: taps[0].token)
            XCTAssertEqual(tap.status, .ok, tap.text)
            let record = try await XCTUnwrapAsync(await InteractionRecord.find(interaction.id.uuid, on: h.db))
            XCTAssertEqual(record.statusValue, .confirmed)
            let outcome = try ViadereJSON.decode(InteractionOutcome.self, from: Data(record.outcomeJSON!.utf8))
            XCTAssertEqual(outcome.decision, .confirm)
            XCTAssertEqual(outcome.channel, .rcs)
            XCTAssertNil(outcome.assurance, "an RCS tap is an unauthenticated channel reply, not a device-signed decision")
            XCTAssertNil(outcome.signedDecision)
            // The business learns it through its signed webhook, and everything is audited.
            let audits = try await AuditEventRecord.query(on: h.db).filter(\.$action == "interaction.decided").all()
            XCTAssertEqual(audits.count, 1)
            XCTAssertTrue(audits[0].metadataJSON.contains("channel_reply"))
            // Remaining tokens for this interaction are dead.
            try await isTrue(try await RCSPostbackRecord.query(on: h.db).all().allSatisfy { $0.state != "open" })
            try await isFalse(try await AuditEventRecord.query(on: h.db).all().contains { $0.metadataJSON.contains(taps[0].token) })
        }
    }

    func testChooseSelectionsComeFromTheServersStoredTargetsNeverFromThePostback() async throws {
        try await withRCS { h, http in
            let s = try await scenario(h)
            let options = [ChoiceOption(id: "slot-9", label: "9:00 am"), ChoiceOption(id: "slot-1030", label: "10:30 am"), ChoiceOption(id: "slot-14", label: "2:00 pm")]
            let interaction = try await issue(h, s, .choose(ChoosePayload(prompt: "Which time?", options: options)), purpose: .transactional)
            try await h.runJobs()
            let message = try h.rcsSentMessages(http)[0]
            let taps = h.replyTokens(in: message)
            XCTAssertEqual(taps.map(\.text), ["9:00 am", "10:30 am", "2:00 pm"])
            XCTAssertFalse(taps.contains { $0.token.contains("slot") })
            try await eq(try await h.rcsTap(token: taps[1].token).status, .ok)
            let record = try await XCTUnwrapAsync(await InteractionRecord.find(interaction.id.uuid, on: h.db))
            XCTAssertEqual(record.statusValue, .selected)
            let outcome = try ViadereJSON.decode(InteractionOutcome.self, from: Data(record.outcomeJSON!.utf8))
            XCTAssertEqual(outcome.selectedOptionIds, ["slot-1030"])
            XCTAssertEqual(outcome.decision, .select)
        }
    }

    func testReplyKindUsesSuggestedRepliesAndWithoutThemHandsOff() async throws {
        try await withRCS { h, http in
            let s = try await scenario(h)
            let interaction = try await issue(h, s, .reply(ReplyPayload(prompt: "Resolved?", suggestedReplies: ["Yes, thanks", "Not yet"])), purpose: .transactional)
            let free = try await issue(h, s, .reply(ReplyPayload(prompt: "Tell us more")), purpose: .transactional)
            try await h.runJobs()
            let sent = try h.rcsSentMessages(http)
            XCTAssertEqual(sent.count, 2)
            let withChips = sent.first { !h.replyTokens(in: $0).isEmpty }!
            let taps = h.replyTokens(in: withChips)
            XCTAssertEqual(taps.map(\.text), ["Yes, thanks", "Not yet"])
            // The second message went out later and superseded the first menu only if it had chips; it has none.
            let noChips = sent.first { h.replyTokens(in: $0).isEmpty }!
            XCTAssertTrue(h.suggestions(in: noChips).contains { ($0["action"] as? [String: Any])?["openUrlAction"] != nil })
            try await eq(try await h.rcsTap(token: taps[1].token).status, .ok)
            let record = try await XCTUnwrapAsync(await InteractionRecord.find(interaction.id.uuid, on: h.db))
            XCTAssertEqual(record.statusValue, .replied)
            XCTAssertEqual(try ViadereJSON.decode(InteractionOutcome.self, from: Data(record.outcomeJSON!.utf8)).reply, "Not yet")
            _ = free
        }
    }

    func testMultiSelectChoicesAndLongListsAreHandedOffNotSquashedIntoChips() async throws {
        try await withRCS { h, http in
            let s = try await scenario(h)
            let many = (1...4).map { ChoiceOption(id: "o\($0)", label: "Option \($0)") }
            _ = try await issue(h, s, .choose(ChoosePayload(prompt: "Pick any", options: many, allowsMultiple: true)), purpose: .transactional)
            try await h.runJobs()
            let message = try h.rcsSentMessages(http)[0]
            XCTAssertTrue(h.replyTokens(in: message).isEmpty)
            let urls = h.suggestions(in: message).compactMap { (($0["action"] as? [String: Any])?["openUrlAction"] as? [String: Any])?["url"] as? String }
            XCTAssertEqual(urls.count, 1)
            XCTAssertTrue(urls[0].hasPrefix("https://viadere.com/h/"))
            try await eq(try await RCSPostbackRecord.query(on: h.db).count(), 0)
        }
    }

    // MARK: Replay, staleness, TTL, binding

    func testPostbacksAreSingleUseAndProviderRedeliveriesAreIgnored() async throws {
        try await withRCS { h, http in
            let s = try await scenario(h)
            let interaction = try await issue(h, s, .confirm(ConfirmPayload(title: "Confirm")))
            try await h.runJobs()
            let token = h.replyTokens(in: try h.rcsSentMessages(http)[0])[0].token
            // The same provider event delivered twice is processed once.
            try await eq(try await h.rcsTap(token: token, messageId: "evt-1").status, .ok)
            try await eq(try await h.rcsTap(token: token, messageId: "evt-1").status, .ok)
            // A *new* event carrying the same token is a replay and is rejected and audited.
            try await eq(try await h.rcsTap(token: token, messageId: "evt-2").status, .ok)
            let decided = try await AuditEventRecord.query(on: h.db).filter(\.$action == "interaction.decided").count()
            XCTAssertEqual(decided, 1)
            let rejections = try await AuditEventRecord.query(on: h.db).filter(\.$action == "rcs.postback_rejected").all()
            XCTAssertEqual(rejections.count, 1)
            XCTAssertTrue(rejections[0].metadataJSON.contains("replayed"))
            try await eq(try await InteractionRecord.find(interaction.id.uuid, on: h.db)?.statusValue, .confirmed)
            // One webhook-worthy outcome only.
            let events = try await WebhookDeliveryRecord.query(on: h.db).count()
            XCTAssertEqual(events, 0, "no subscription in this test")
        }
    }

    func testStaleMenusAreRejectedLikeStaleSMSNumbers() async throws {
        try await withRCS { h, http in
            let s = try await scenario(h)
            let first = try await issue(h, s, .confirm(ConfirmPayload(title: "First")))
            try await h.runJobs()
            let firstToken = h.replyTokens(in: try h.rcsSentMessages(http)[0])[0].token
            // A newer menu goes out to the same phone: the earlier menu is superseded.
            h.clock.advance(by: 5)
            let second = try await issue(h, s, .confirm(ConfirmPayload(title: "Second")))
            try await h.runJobs()
            let sent = try h.rcsSentMessages(http)
            XCTAssertEqual(sent.count, 2)
            let secondToken = h.replyTokens(in: sent[1])[0].token
            try await eq(try await ChannelEndpointRecord.query(on: h.db).first()?.activeMenuVersion, 2)
            // Tapping the old menu does nothing to the interaction and tells the user, by SMS, to use the latest message.
            try await eq(try await h.rcsTap(token: firstToken).status, .ok)
            try await eq(try await InteractionRecord.find(first.id.uuid, on: h.db)?.statusValue, .pending)
            let rejection = try await XCTUnwrapAsync(await AuditEventRecord.query(on: h.db).filter(\.$action == "rcs.postback_rejected").first())
            XCTAssertTrue(rejection.metadataJSON.contains("stale"))
            try await h.runJobs()
            XCTAssertTrue(h.texts.sent.contains { $0.body.contains("no longer available") })
            // The current menu works.
            try await eq(try await h.rcsTap(token: secondToken).status, .ok)
            try await eq(try await InteractionRecord.find(second.id.uuid, on: h.db)?.statusValue, .confirmed)
        }
    }

    func testMenusExpireWithTheSameTTLAsSMSMenus() async throws {
        try await withRCS { h, http in
            let s = try await scenario(h)
            let interaction = try await issue(h, s, .confirm(ConfirmPayload(title: "Slow")))
            try await h.runJobs()
            let token = h.replyTokens(in: try h.rcsSentMessages(http)[0])[0].token
            h.clock.advance(by: GatewayConfiguration().menuTTL + 1)
            try await eq(try await h.rcsTap(token: token).status, .ok)
            try await eq(try await InteractionRecord.find(interaction.id.uuid, on: h.db)?.statusValue, .pending, "the interaction itself is still open in the app")
            let rejection = try await XCTUnwrapAsync(await AuditEventRecord.query(on: h.db).filter(\.$action == "rcs.postback_rejected").first())
            XCTAssertTrue(rejection.metadataJSON.contains("expired"))
        }
    }

    func testPostbacksAreBoundToThePhoneTheyWereSentTo() async throws {
        try await withRCS { h, http in
            let s = try await scenario(h)
            let interaction = try await issue(h, s, .confirm(ConfirmPayload(title: "Mine")))
            try await h.runJobs()
            let token = h.replyTokens(in: try h.rcsSentMessages(http)[0])[0].token
            // The same token tapped from another number (forwarded message, stolen token) is refused.
            try await eq(try await h.rcsTap(token: token, from: "+14805559999").status, .ok)
            try await eq(try await InteractionRecord.find(interaction.id.uuid, on: h.db)?.statusValue, .pending)
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "rcs.postback_rejected").all().contains { $0.metadataJSON.contains("wrong_phone") })
            // The real owner can still use it (a refused attempt must not burn the token).
            try await eq(try await h.rcsTap(token: token).status, .ok)
            try await eq(try await InteractionRecord.find(interaction.id.uuid, on: h.db)?.statusValue, .confirmed)
        }
    }

    func testForgedMalformedAndUnknownTokensDoNothing() async throws {
        try await withRCS { h, http in
            let s = try await scenario(h)
            let interaction = try await issue(h, s, .confirm(ConfirmPayload(title: "Target")))
            try await h.runJobs()
            let real = h.replyTokens(in: try h.rcsSentMessages(http)[0])[0].token
            let tokens = RCSPostbackTokens(hasher: h.ctx.hasher)
            let forgedMAC = String(real.dropLast(4)) + "0000"
            let rawId = "viadere:\(interaction.id):decision.confirm"
            let wellFormedUnknown = tokens.mint() // valid signature, never issued
            for (i, bad) in [forgedMAC, rawId, "vrp1.short", "", String(repeating: "x", count: 90), wellFormedUnknown, real.uppercased()].enumerated() {
                try await eq(try await h.rcsTap(token: bad, messageId: "bad-\(i)").status, .ok)
            }
            try await eq(try await InteractionRecord.find(interaction.id.uuid, on: h.db)?.statusValue, .pending)
            let reasons = try await AuditEventRecord.query(on: h.db).filter(\.$action == "rcs.postback_rejected").all().map(\.metadataJSON)
            XCTAssertEqual(reasons.count, 7)
            XCTAssertTrue(reasons.contains { $0.contains("unknown") })
            XCTAssertTrue(reasons.contains { $0.contains("malformed") })
            // Signature structure: tokens from a different server pepper do not verify.
            let other = RCSPostbackTokens(hasher: Hasher256(pepper: Data(repeating: 9, count: 32)))
            XCTAssertFalse(tokens.isWellFormed(other.mint()))
            XCTAssertTrue(tokens.isWellFormed(tokens.mint()))
        }
    }

    func testPostbackForAnotherBusinessesInteractionCannotBeUsed() async throws {
        try await withRCS { h, http in
            let a = try await scenario(h, name: "Alpha Air", handle: "alphaair")
            let b = try await h.makeBusiness(name: "Beta Bank", handle: "betabank")
            let relB = try await h.connect(a.consumer, to: b)
            let ia = try await issue(h, a, .confirm(ConfirmPayload(title: "Alpha")))
            let ib = try await issue(h, Scenario(business: b, consumer: a.consumer, relationship: relB), .confirm(ConfirmPayload(title: "Beta")))
            h.clock.advance(by: 1)
            try await h.runJobs()
            let sent = try h.rcsSentMessages(http)
            XCTAssertEqual(sent.count, 2)
            // Each token decides exactly its own interaction, whichever message it is found in.
            let textA = sent.first { (($0["contentMessage"] as? [String: Any])?["text"] as? String)?.contains("Alpha") == true }!
            let tokenA = h.replyTokens(in: textA)[0].token
            let stale = try await InteractionRecord.find(ia.id.uuid, on: h.db)!
            // Beta's menu is the newest (version 2), so Alpha's is stale for this phone — and still decides nothing of Beta's.
            try await eq(try await h.rcsTap(token: tokenA).status, .ok)
            try await eq(try await InteractionRecord.find(ib.id.uuid, on: h.db)?.statusValue, .pending)
            XCTAssertEqual(stale.businessId, a.business.id.uuid)
        }
    }

    // MARK: Authorize / sensitive interactions are never satisfiable over RCS

    func testAuthorizeNeverBecomesAnActionableRCSMessageAndCannotBeApprovedByAPostback() async throws {
        try await withRCS { h, http in
            let s = try await scenario(h)
            let interaction = try await issue(h, s, .authorize(AuthorizePayload.sample(amount: "285.28")), purpose: .security, sensitivity: .high, channels: [.nativePush, .rcs, .sms])
            try await h.runJobs()
            let message = try h.rcsSentMessages(http)[0]
            let text = ((message["contentMessage"] as? [String: Any])?["text"] as? String) ?? ""
            // A secure handoff only: an "open in Viadere" action, no reply chips, no transaction details.
            XCTAssertTrue(h.replyTokens(in: message).isEmpty)
            let urls = h.suggestions(in: message).compactMap { (($0["action"] as? [String: Any])?["openUrlAction"] as? [String: Any])?["url"] as? String }
            XCTAssertEqual(urls.count, 1)
            XCTAssertTrue(urls[0].hasPrefix("https://viadere.com/h/"))
            XCTAssertFalse(text.contains("285.28"))
            XCTAssertFalse(text.contains("Walmart"))
            XCTAssertTrue(text.lowercased().contains("never asks you to approve by text"))
            try await eq(try await RCSPostbackRecord.query(on: h.db).count(), 0)
            // The handoff token is single-use, bound to the consumer and to this interaction.
            let token = String(urls[0].dropFirst("https://viadere.com/h/".count))
            let link = try await XCTUnwrapAsync(await LinkTokenRecord.query(on: h.db).filter(\.$tokenHash == SecureToken.hash(token)).first())
            XCTAssertEqual(link.kind, "handoff")
            XCTAssertEqual(link.consumerId, s.consumer.id.uuid)
            XCTAssertEqual(link.interactionId, interaction.id.uuid)
            XCTAssertEqual(link.purpose, "interaction")
            try await eq(try await h.page("/h/\(token)", nil).status, .ok)
            // Even if a postback row existed (a bug, a DB write), the service refuses to approve over a text channel.
            let forged = RCSPostbackTokens(hasher: h.ctx.hasher).mint()
            let row = RCSPostbackRecord()
            row.id = UUID()
            row.tokenHash = RCSPostbackTokens.storedHash(forged)
            row.phoneHash = h.ctx.hasher.phoneHash(PhoneNumber(phone)!)
            row.interactionId = interaction.id.uuid
            row.menuVersion = 1
            row.target = RCSPostbackTarget.decision(.approve).storageValue
            row.state = "open"
            row.expiresAt = h.clock.now().addingTimeInterval(300)
            row.createdAt = h.clock.now()
            try await row.create(on: h.db)
            let endpoint = try await XCTUnwrapAsync(await ChannelEndpointRecord.query(on: h.db).first())
            endpoint.activeMenuVersion = 1
            endpoint.menuExpiresAt = h.clock.now().addingTimeInterval(300)
            try await endpoint.update(on: h.db)
            try await eq(try await h.rcsTap(token: forged).status, .ok)
            let record = try await XCTUnwrapAsync(await InteractionRecord.find(interaction.id.uuid, on: h.db))
            XCTAssertEqual(record.statusValue, .pending)
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "rcs.postback_rejected").all().contains { $0.metadataJSON.contains("not_permitted") })
            // The service-level rule, for every sensitive combination: never satisfiable by a channel reply.
            let service = InteractionService(db: h.db, ctx: h.ctx)
            for decision in [Decision.approve, .deny, .confirm, .report, .select] {
                do {
                    _ = try await service.decideViaChannel(record: record, decision: decision, selected: nil, reply: nil, channel: .rcs, actor: AuditActor(kind: .gateway))
                    XCTFail("authorize decided over RCS with \(decision)")
                } catch let error as APIError {
                    XCTAssertEqual(error.code, .insufficientAssurance)
                }
            }
            // And the device-signed route does not accept an authorize decision that claims the RCS channel either.
            let view = try await h.consumerInteraction(s.consumer, id: interaction.id)
            let signed = try await h.decision(s.consumer, interaction: view, decision: .approve, assurance: .biometric)
            let viaRCS = try await h.decide(s.consumer, id: interaction.id, signed: signed, channel: .rcs)
            XCTAssertNotEqual(viaRCS.status, .ok)
            try await eq(try await InteractionRecord.find(interaction.id.uuid, on: h.db)?.statusValue, .pending)
            // The native, device-signed path still works.
            let viaApp = try await h.decide(s.consumer, id: interaction.id, signed: signed, channel: .nativePush)
            XCTAssertEqual(viaApp.status, .ok, viaApp.text)
        }
    }

    func testNoSensitiveKindOrAssuranceIsEverSatisfiableByAnRCSReply() async throws {
        try await withRCS { h, _ in
            let s = try await scenario(h)
            let service = InteractionService(db: h.db, ctx: h.ctx)
            var n = 0
            let payloads: [InteractionPayload] = [
                .authenticate(AuthenticatePayload(service: "Bank", device: "Mac", attemptedAt: h.clock.now())), .authorize(AuthorizePayload.sample()),
                .confirm(ConfirmPayload(title: "c")), .choose(ChoosePayload(prompt: "p", options: [ChoiceOption(id: "a", label: "A"), ChoiceOption(id: "b", label: "B")])),
                .acknowledge(AcknowledgePayload(title: "t", body: "b")), .reply(ReplyPayload(prompt: "p")),
            ]
            for payload in payloads {
                for sensitivity in Sensitivity.allCases {
                    for purpose in [InteractionPurpose.security, .transactional, .support] where !(payload.kind!.isSecuritySensitive && purpose == .support) {
                        n += 1
                        let r = try await h.issue(s.business, relationship: s.relationship, payload: payload, purpose: purpose, sensitivity: sensitivity, key: "m\(n)", ttl: 600, channels: [.nativePush, .rcs])
                        guard r.status == .created else { continue }
                        let interaction = try r.json(Interaction.self)
                        let record = try await InteractionRecord.find(interaction.id.uuid, on: h.db)!
                        let stored = try record.interaction()
                        // `Decision.allowed(for:)` is a Set, and Swift gives every Set instance its own iteration order, so the
                        // decisions are sorted: the loop below must be deterministic (an earlier version compared `.first` of
                        // three differently ordered sets and failed intermittently, on any database).
                        for decision in Decision.allowed(for: stored.kind).sorted(by: { $0.rawValue < $1.rawValue }) {
                            let policy = AssurancePolicy.canSatisfy(stored, channel: .rcs, provided: .unauthenticatedReply, decision: decision)
                            do {
                                _ = try await service.decideViaChannel(record: record, decision: decision, selected: decision == .select ? ["a"] : nil,
                                                                       reply: decision == .reply ? "ok" : nil, channel: .rcs, actor: AuditActor(kind: .gateway))
                                // Allowed only when the policy says a channel reply suffices, and the server agrees with the policy.
                                XCTAssertTrue(policy, "\(stored.kind) \(sensitivity) \(purpose) \(decision): the server allowed what the policy forbids")
                                XCTAssertTrue(stored.requiredAssurance == .channelReply && !stored.kind.isSecuritySensitive && ![Decision.deny, .report].contains(decision),
                                              "\(stored.kind) \(sensitivity) \(purpose) \(decision) must not be satisfiable")
                                break // one decision per interaction
                            } catch let error as APIError {
                                XCTAssertTrue([.insufficientAssurance, .validationFailed].contains(error.code), "\(error.code)")
                                if error.code == .insufficientAssurance {
                                    XCTAssertFalse(policy, "\(stored.kind) \(sensitivity) \(purpose) \(decision): the server refused what the policy allows")
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: Capability and SMS fallback

    func testNonCapablePhonesFallBackToSMSForTheSameInteractionAndTheCapabilityIsCached() async throws {
        try await withRCS { h, http in
            http.setCapability(404, for: phone)
            let s = try await scenario(h)
            let first = try await issue(h, s, .confirm(ConfirmPayload(title: "Seat 14C")))
            try await h.runJobs()
            // RCS was checked, found unavailable, and nothing was sent over it; SMS carried the interaction.
            XCTAssertEqual(http.capabilityChecks.count, 1)
            XCTAssertEqual(http.sends.count, 0)
            let row = try await XCTUnwrapAsync(await ChannelOutboundRecord.query(on: h.db).first())
            XCTAssertEqual(row.channel, "sms")
            XCTAssertEqual(row.preferredChannel, "rcs")
            XCTAssertEqual(row.fallbackReason, "not_capable")
            XCTAssertEqual(row.status, "sent")
            try await h.runJobs()
            let sms = try XCTUnwrap(h.texts.sent.last)
            XCTAssertEqual(sms.to, phone)
            XCTAssertTrue(sms.body.hasPrefix("[Northwind Air]: "))
            // A confirm needs an answer, and SMS replies for interactions are not wired: it is a secure handoff, never "1. Confirm".
            XCTAssertTrue(sms.body.contains("https://viadere.com/h/"), sms.body)
            XCTAssertFalse(sms.body.contains("1. Confirm"))
            XCTAssertFalse(sms.body.contains("Seat 14C"), "details stay out of the insecure channel when an answer is needed")
            let handoff = try await XCTUnwrapAsync(await LinkTokenRecord.query(on: h.db).filter(\.$kind == "handoff").first())
            XCTAssertEqual(handoff.interactionId, first.id.uuid)
            let sentRow = try await XCTUnwrapAsync(await SMSOutboundRecord.query(on: h.db).first())
            XCTAssertEqual(sentRow.bodyCiphertext.hasPrefix("v1."), true)
            // The secret link is wiped from the queue after sending.
            XCTAssertEqual(try h.ctx.cipher.openString(sentRow.bodyCiphertext, context: "sms_outbound.body"), "[removed]")
            // Capability is cached for 24 h per phone; after that it is looked up again.
            _ = try await issue(h, s, .confirm(ConfirmPayload(title: "Second")))
            try await h.runJobs()
            XCTAssertEqual(http.capabilityChecks.count, 1)
            h.clock.advance(by: 25 * 3600)
            _ = try await issue(h, s, .confirm(ConfirmPayload(title: "Third")))
            try await h.runJobs()
            XCTAssertEqual(http.capabilityChecks.count, 2)
            XCTAssertEqual(http.sends.count, 0)
            // SMS usage is metered as transport segments.
            let usage = try await UsageEventRecord.query(on: h.db).filter(\.$meter == "sms_segment").all()
            XCTAssertEqual(usage.count, 3)
            XCTAssertTrue(usage.allSatisfy { $0.category == "transport" && $0.quantity >= 1 })
        }
    }

    func testInformationalInteractionsFallBackToPlainSMSText() async throws {
        try await withRCS { h, http in
            http.setCapability(404)
            let s = try await scenario(h)
            _ = try await issue(h, s, .status(StatusPayload(title: "Out for delivery", body: "Arriving 2-4 pm")), purpose: .transactional)
            try await h.runJobs()
            try await h.runJobs()
            let sms = try XCTUnwrap(h.texts.sent.last)
            XCTAssertEqual(sms.body, "[Northwind Air]: Out for delivery. Arriving 2-4 pm")
            XCTAssertFalse(sms.body.contains("/h/"))
            try await eq(try await LinkTokenRecord.query(on: h.db).filter(\.$kind == "handoff").count(), 0)
        }
    }

    func testSensitiveInteractionsAreNeverDowngradedByTheFallback() async throws {
        try await withRCS { h, http in
            http.setCapability(404)
            let s = try await scenario(h)
            let secrets = [(InteractionPayload.authorize(AuthorizePayload.sample(amount: "999.00")), InteractionPurpose.security, Sensitivity.high),
                           (.authenticate(AuthenticatePayload(service: "Online Banking", device: "Chrome", attemptedAt: h.clock.now())), .security, .standard),
                           (.confirm(ConfirmPayload(title: "Wire $9,000", details: "To account 1234")), .transactional, .critical)]
            for (i, (payload, purpose, sensitivity)) in secrets.enumerated() {
                _ = try await issue(h, s, payload, purpose: purpose, sensitivity: sensitivity, channels: [.nativePush, .rcs, .sms], key: "sec\(i)")
            }
            try await h.runJobs()
            try await h.runJobs()
            let bodies = h.texts.sent.map(\.body)
            XCTAssertEqual(bodies.count, 3)
            for body in bodies {
                XCTAssertTrue(body.contains("https://viadere.com/h/"), body)
                XCTAssertTrue(body.lowercased().contains("never asks you to approve by text"), body)
                for leak in ["999.00", "Online Banking", "9,000", "1234", "Reply", "1. ", "YES"] { XCTAssertFalse(body.contains(leak), "\(leak) in \(body)") }
            }
            XCTAssertEqual(http.sends.count, 0)
        }
    }

    func testProviderFailuresRetryThenFallBackToSMS() async throws {
        try await withRCS { h, http in
            let s = try await scenario(h)
            // Transient capability errors: retry with backoff, then fall back after three attempts.
            http.setCapability(503, for: phone)
            _ = try await issue(h, s, .confirm(ConfirmPayload(title: "Retry")))
            try await h.runJobs()
            var row = try await XCTUnwrapAsync(await ChannelOutboundRecord.query(on: h.db).first())
            XCTAssertEqual(row.status, "queued")
            XCTAssertEqual(row.channel, "rcs")
            try await h.runJobs() // not due yet
            XCTAssertEqual(http.capabilityChecks.count, 1)
            h.clock.advance(by: 31)
            try await h.runJobs()
            h.clock.advance(by: 121)
            try await h.runJobs()
            row = try await XCTUnwrapAsync(await ChannelOutboundRecord.query(on: h.db).first())
            XCTAssertEqual(row.channel, "sms")
            XCTAssertEqual(row.fallbackReason, "capability_unavailable")
            XCTAssertEqual(http.capabilityChecks.count, 3)
            XCTAssertEqual(row.status, "sent")
        }
        try await withRCS { h, http in
            let s = try await scenario(h)
            // Capable, but the send itself fails: 422 means "not capable" (immediate fallback, capability remembered).
            http.queueSendStatuses([422])
            _ = try await issue(h, s, .confirm(ConfirmPayload(title: "Send fails")))
            try await h.runJobs()
            let row = try await XCTUnwrapAsync(await ChannelOutboundRecord.query(on: h.db).first())
            XCTAssertEqual(row.channel, "sms")
            XCTAssertEqual(row.fallbackReason, "not_capable")
            try await eq(try await ChannelEndpointRecord.query(on: h.db).first()?.capability, "incapable")
            // The tokens minted for the failed attempt are void.
            try await isTrue(try await RCSPostbackRecord.query(on: h.db).all().allSatisfy { $0.state == "revoked" })
            // A permanent provider error also falls back; a transient one retries first.
            http.queueSendStatuses([400])
            let ep = try await ChannelEndpointRecord.query(on: h.db).first()!
            ep.capability = "capable"
            try await ep.update(on: h.db)
            h.clock.advance(by: 1)
            _ = try await issue(h, s, .confirm(ConfirmPayload(title: "Permanent")))
            try await h.runJobs()
            let rows = try await ChannelOutboundRecord.query(on: h.db).sort(\.$createdAt, .ascending).all()
            XCTAssertEqual(rows.last?.fallbackReason, "provider_error")
            XCTAssertEqual(rows.last?.channel, "sms")
            http.queueSendStatuses([503, 503, 503])
            h.clock.advance(by: 1)
            _ = try await issue(h, s, .confirm(ConfirmPayload(title: "Transient")))
            for _ in 0..<4 { try await h.runJobs(); h.clock.advance(by: 200) }
            let last = try await ChannelOutboundRecord.query(on: h.db).sort(\.$createdAt, .descending).first()!
            XCTAssertEqual(last.channel, "sms")
            XCTAssertEqual(last.fallbackReason, "provider_error")
        }
    }

    func testAFailedDeliveryReceiptReroutesAPendingInteractionToSMSAndADeliveredOneIsRecorded() async throws {
        try await withRCS { h, http in
            let s = try await scenario(h)
            _ = try await issue(h, s, .confirm(ConfirmPayload(title: "Will fail")))
            _ = try await issue(h, s, .status(StatusPayload(title: "Will deliver")), purpose: .transactional)
            try await h.runJobs()
            let rows = try await ChannelOutboundRecord.query(on: h.db).sort(\.$createdAt, .ascending).all()
            XCTAssertEqual(rows.count, 2)
            let ids = rows.compactMap(\.providerMessageId)
            XCTAssertEqual(ids.count, 2)
            try await eq(try await h.rcsInbound(["eventType": "DELIVERED", "messageId": ids[1], "senderPhoneNumber": phone]).status, .ok)
            try await eq(try await ChannelOutboundRecord.find(rows[1].id!, on: h.db)?.status, "delivered")
            try await eq(try await h.rcsInbound(["eventType": "FAILED", "messageId": ids[0], "senderPhoneNumber": phone, "errorCode": "UNREACHABLE"]).status, .ok)
            // A duplicate failure receipt cannot queue a second SMS.
            try await eq(try await h.rcsInbound(["eventType": "FAILED", "messageId": ids[0], "senderPhoneNumber": phone]).status, .ok)
            let failed = try await XCTUnwrapAsync(await ChannelOutboundRecord.find(rows[0].id!, on: h.db))
            XCTAssertEqual(failed.channel, "sms")
            XCTAssertEqual(failed.status, "queued")
            XCTAssertEqual(failed.fallbackReason, "rcs_failed")
            let before = h.texts.sent.count
            try await h.runJobs()
            try await h.runJobs()
            XCTAssertEqual(h.texts.sent.count - before, 1)
            XCTAssertTrue(h.texts.sent.last!.body.contains("https://viadere.com/h/"))
            // The dead RCS menu can no longer be used.
            try await isTrue(try await RCSPostbackRecord.query(on: h.db).all().allSatisfy { $0.state != "open" || $0.interactionId != rows[0].interactionId })
        }
    }

    func testChannelSelectionHonoursWhatTheBusinessAllowedAndWhatIsConfigured() async throws {
        // No provider configured: RCS-allowed interactions go out by SMS with the reason recorded.
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Plain Co", handle: "plainco")
            let c = try await h.readyConsumer()
            try await h.linkVerifiedPhone(c)
            let rel = try await h.connect(c, to: b)
            _ = try await h.issue(b, relationship: rel, payload: .status(StatusPayload(title: "Hello")), purpose: .transactional, key: "a", channels: [.nativePush, .rcs])
            _ = try await h.issue(b, relationship: rel, payload: .status(StatusPayload(title: "SMS only")), purpose: .transactional, key: "b", channels: [.nativePush, .sms])
            _ = try await h.issue(b, relationship: rel, payload: .status(StatusPayload(title: "App only")), purpose: .transactional, key: "c", channels: [.nativePush, .inApp])
            let rows = try await ChannelOutboundRecord.query(on: h.db).sort(\.$createdAt, .ascending).all()
            XCTAssertEqual(rows.count, 2, "nothing is queued when the business allowed neither text channel")
            XCTAssertEqual(rows[0].channel, "sms")
            XCTAssertEqual(rows[0].fallbackReason, "disabled")
            XCTAssertEqual(rows[1].channel, "sms")
            XCTAssertNil(rows[1].fallbackReason)
            try await h.runJobs()
            try await h.runJobs()
            XCTAssertEqual(h.texts.sent.count, 2)
        }
        // Test-mode keys never send real messages.
        try await withRCS { h, http in
            let b = try await h.makeBusiness(name: "Test Co", handle: "testco", live: false)
            let c = try await h.readyConsumer()
            try await h.linkVerifiedPhone(c)
            let rel = try await h.connect(c, to: b)
            _ = try await h.issue(b, relationship: rel, payload: .status(StatusPayload(title: "Hello")), purpose: .transactional, key: "t", channels: [.nativePush, .rcs, .sms])
            try await h.runJobs()
            try await eq(try await ChannelOutboundRecord.query(on: h.db).count(), 0)
            XCTAssertEqual(http.requests.count, 0)
        }
    }

    func testOptedOutPhonesUnlinkedConsumersAndMissingConsentAreNeverMessaged() async throws {
        try await withRCS { h, http in
            let s = try await scenario(h)
            // A consumer without a verified phone is app-only.
            let noPhone = try await h.readyConsumer(name: "No Phone")
            let relNoPhone = try await h.connect(noPhone, to: s.business)
            _ = try await h.issue(s.business, relationship: relNoPhone, payload: .status(StatusPayload(title: "x")), purpose: .transactional, key: "np", channels: channels)
            try await eq(try await ChannelOutboundRecord.query(on: h.db).count(), 0)
            // Marketing needs a grant that covers text channels; an app-only opt-in does not.
            let appOptIn = try await h.readyConsumer(name: "App Opt-in")
            try await h.linkVerifiedPhone(appOptIn, phone: "+14805550188")
            let relApp = try await h.connect(appOptIn, to: s.business, optIn: [.marketing])
            let m1 = try await h.issue(s.business, relationship: relApp, payload: .message(MessagePayload(text: "Sale!")), purpose: .marketing, key: "m1", channels: channels)
            XCTAssertEqual(m1.status, .created)
            try await eq(try await ChannelOutboundRecord.query(on: h.db).count(), 0, "marketing consent was given for the app only")
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "channel.skipped").all().contains { $0.metadataJSON.contains("no_text_channel_consent") })
            // Essential messages ride on the verified phone, until the user texts STOP.
            _ = try await issue(h, s, .status(StatusPayload(title: "Before stop")))
            try await eq(try await ChannelOutboundRecord.query(on: h.db).count(), 1)
            try await eq(try await h.rcsText("STOP").status, .ok)
            try await h.runJobs()
            let context = try await SMSContextRecord.query(on: h.db).first()
            XCTAssertEqual(context?.optedOut, true, "STOP over RCS opts the number out everywhere")
            // The queued message is cancelled and nothing new is queued; no RCS call was made for it.
            try await eq(try await ChannelOutboundRecord.query(on: h.db).first()?.status, "cancelled")
            _ = try await issue(h, s, .status(StatusPayload(title: "After stop")), key: "after")
            try await eq(try await ChannelOutboundRecord.query(on: h.db).count(), 1)
            XCTAssertEqual(http.sends.count, 0)
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "channel.skipped").all().contains { $0.metadataJSON.contains("opted_out") })
        }
    }

    func testFreeTextOverRCSJoinsTheSameGatewayThreadAndDuplicatesAreDropped() async throws {
        try await withRCS { h, _ in
            let r1 = try await h.rcsText("Hi", messageId: "t1")
            XCTAssertEqual(r1.status, .ok)
            try await h.runJobs()
            XCTAssertTrue(h.texts.sent.contains { $0.body.contains("1.") }, "the gateway answers with its numbered menu by SMS")
            let before = h.texts.sent.count
            try await eq(try await h.rcsText("Hi", messageId: "t1").status, .ok)
            try await h.runJobs()
            XCTAssertEqual(h.texts.sent.count, before, "provider redelivery produces no second reply")
            try await eq(try await ProcessedProviderMessageRecord.query(on: h.db).filter(\.$provider == "rcs").count(), 1)
        }
    }

    func testInboundRCSFloodsAreDroppedAndAudited() async throws {
        try await withRCS { h, _ in
            for i in 0..<30 { _ = try await h.rcsTap(token: "vrp1.junk", messageId: "f\(i)") }
            let limited = try await AuditEventRecord.query(on: h.db).filter(\.$action == "gateway.rate_limited").count()
            XCTAssertGreaterThan(limited, 0)
        }
    }

    // MARK: Adapter protocol and the Apple Messages for Business placeholder

    func testEveryChannelSharesOneAdapterProtocolAndTheSMSAdapterRendersWithTheCoreRenderer() async throws {
        try await withRCS { h, _ in
            let registry = h.ctx.channels
            XCTAssertEqual(registry.adapter(for: .sms)?.channel, .sms)
            XCTAssertEqual(registry.adapter(for: .rcs)?.channel, .rcs)
            XCTAssertEqual(registry.adapter(for: .appleMessagesForBusiness)?.channel, .appleMessagesForBusiness)
            XCTAssertNil(registry.adapter(for: .nativePush))
            XCTAssertTrue(registry.sms.isEnabled)
            XCTAssertTrue(registry.rcs.isEnabled)
            let business = BusinessSummary(id: BusinessID(), displayName: "Northwind Air", handle: nil, code: BusinessCode.generate(), verificationStatus: .verified)
            let interaction = Interaction(businessId: business.id, scope: RelationshipScope(consumerId: ConsumerID(), relationshipId: RelationshipID()),
                                          purpose: .transactional, payload: .confirm(ConfirmPayload(title: "Hi")), sensitivity: .standard,
                                          allowedChannels: [.sms, .rcs], createdAt: h.clock.now(), expiresAt: h.clock.now().addingTimeInterval(600),
                                          idempotencyKey: "x", challenge: .generate(), kind: .confirm)
            let sms = registry.sms.render(interaction, business: business, handoffURL: nil)
            XCTAssertEqual(sms.text, ChannelRenderer.sms(interaction, business: business, handoffURL: nil).body)
            let rcs = registry.rcs.render(interaction, business: business, handoffURL: nil)
            XCTAssertEqual(rcs.suggestions.map(\.text), ["Confirm", "Decline"])
            XCTAssertEqual(rcs.suggestions.compactMap { s -> RCSPostbackTarget? in if case .reply(let t) = s.action { t } else { nil } },
                           [.decision(.confirm), .decision(.decline)])
            // The postback target helper round-trips and rejects other interactions' placeholders.
            XCTAssertEqual(RCSPostbackTarget(storageValue: RCSPostbackTarget.option("x-1").storageValue), .option("x-1"))
            XCTAssertNil(RCSPostbackTarget.parse(postback: "viadere:\(InteractionID()):decision.confirm", interactionId: interaction.id))
            XCTAssertNil(RCSPostbackTarget.parse(postback: "viadere:\(interaction.id):decision.explode", interactionId: interaction.id))
        }
    }

    func testAppleMessagesForBusinessIsAnInertPlaceholderBehindAFlagThatDefaultsOff() async throws {
        XCTAssertFalse(ServerConfig.testing().channelFlags.appleMessagesForBusiness)
        XCTAssertFalse(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development"]).channelFlags.appleMessagesForBusiness)
        XCTAssertTrue(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development", "FEATURE_APPLE_MESSAGES_FOR_BUSINESS": "true"]).channelFlags.appleMessagesForBusiness)
        XCTAssertFalse(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development", "FEATURE_APPLE_MESSAGES_FOR_BUSINESS": "yes"]).channelFlags.appleMessagesForBusiness)
        for enabled in [false, true] {
            let amb = AppleMessagesForBusinessAdapter(flagEnabled: enabled)
            XCTAssertEqual(amb.channel, .appleMessagesForBusiness)
            XCTAssertEqual(amb.isEnabled, enabled)
            let capability = await amb.capability(for: PhoneNumber(phone)!)
            XCTAssertEqual(capability, .incapable, "never selectable, even with the flag on")
            XCTAssertFalse(amb.verifyInbound(ProviderWebhookRequest(url: "", signature: "x", body: Data(), receivedAt: Date())))
            XCTAssertThrowsError(try amb.parseInbound(ProviderWebhookRequest(url: "", signature: nil, body: Data(), receivedAt: Date())))
        }
        try await withHarness { h in
            let amb = AppleMessagesForBusinessAdapter(flagEnabled: true)
            let env = ChannelEnvironment(db: h.db, ctx: h.ctx, reference: "r", sensitive: false, businessId: nil)
            for (adapter, expected) in [(AppleMessagesForBusinessAdapter(flagEnabled: false), ChannelError.notEnabled), (amb, .notImplemented)] {
                do {
                    _ = try await adapter.send(OutboundChannelMessage(text: "x"), to: PhoneNumber(phone)!, environment: env)
                    XCTFail("AMB must never send")
                } catch let error as ChannelError {
                    XCTAssertEqual(error, expected)
                }
            }
            // Even the placeholder never renders an actionable message.
            let business = BusinessSummary(id: BusinessID(), displayName: "X", handle: nil, code: BusinessCode.generate(), verificationStatus: .verified)
            let interaction = Interaction(businessId: business.id, scope: RelationshipScope(consumerId: ConsumerID(), relationshipId: RelationshipID()),
                                          purpose: .security, payload: .authorize(AuthorizePayload.sample()), sensitivity: .high, allowedChannels: [.appleMessagesForBusiness],
                                          createdAt: h.clock.now(), expiresAt: h.clock.now().addingTimeInterval(300), idempotencyKey: "x", challenge: .generate(), kind: .authorize)
            let rendering = amb.render(interaction, business: business, handoffURL: nil)
            XCTAssertTrue(rendering.suggestions.isEmpty)
            XCTAssertTrue(rendering.isSecureHandoff)
            // The router can never choose it: AMB is not a delivery path for any interaction.
            let b = try await h.makeBusiness(name: "Amb Co", handle: "ambco")
            let c = try await h.readyConsumer()
            try await h.linkVerifiedPhone(c)
            let rel = try await h.connect(c, to: b)
            _ = try await h.issue(b, relationship: rel, payload: .status(StatusPayload(title: "x")), purpose: .transactional, key: "amb", channels: [.nativePush, .appleMessagesForBusiness])
            try await eq(try await ChannelOutboundRecord.query(on: h.db).count(), 0)
        }
    }

    func testRCSConfigurationIsValidatedAndFailsClosed() throws {
        let secret = Base64URL.encode(Data(repeating: 7, count: 32))
        let good = ["ENVIRONMENT": "production", "RCS_PROVIDER_BASE_URL": "https://rcs.example.com/v1", "RCS_PROVIDER_TOKEN": "t", "RCS_WEBHOOK_SECRET": secret, "RCS_AGENT_ID": "agent"]
        var config = ServerConfig.testing()
        XCTAssertNoThrow(try config.applyPlatformEnvironment(good, production: true))
        XCTAssertEqual(config.rcs?.agentId, "agent")
        for (key, value) in [("RCS_PROVIDER_BASE_URL", "http://insecure.example.com"), ("RCS_PROVIDER_TOKEN", ""), ("RCS_WEBHOOK_SECRET", "short"), ("RCS_AGENT_ID", "")] {
            var env = good
            env[key] = value
            var c = ServerConfig.testing()
            XCTAssertThrowsError(try c.applyPlatformEnvironment(env, production: true), key)
        }
        var none = ServerConfig.testing()
        try none.applyPlatformEnvironment(["ENVIRONMENT": "production"], production: true)
        XCTAssertNil(none.rcs, "RCS is simply off without configuration")
    }
}
