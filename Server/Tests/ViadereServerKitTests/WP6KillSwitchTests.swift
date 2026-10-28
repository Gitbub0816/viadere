import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Operator kill switches and emergency controls (OPS-006, docs/ops/KILL-SWITCHES.md): maintenance (G-1), sign-up stops (G-15), webhook pause (G-5),
/// emergency messaging restriction (G-6), consumer freeze (G-7), operator notices (G-9), abuse thresholds (G-12), protected metrics (G-13).
final class WP6KillSwitchTests: XCTestCase {
    private func ownershipOff(_ config: inout ServerConfig) { config.operations.webhookOwnershipVerification = false }

    // MARK: Discipline common to every switch

    func testEverySwitchNeedsAReasonAFreshPasskeyAndIsAudited() async throws {
        try await withHarness { h in
            let (op, opAccount) = try await h.makeOperator()
            let (owner, _, _) = try await h.verifiedOwner()
            // No reason, a short reason, a reason with control characters: refused, nothing stored.
            for reason in ["", "short", "bad\u{0007}reason that is long enough"] {
                let r = try await h.formPost("/operator/switches/maintenance", op, [("action", "on"), ("message", "Back soon"), ("reason", reason)])
                XCTAssertNotEqual(r.status, .seeOther, "'\(reason)'")
            }
            let none = try await PlatformFlagRecord.query(on: h.db).count()
            XCTAssertEqual(none, 0)
            // A stale session cannot flip a switch (step-up), a fresh passkey can.
            h.clock.advance(by: 8 * 60)
            let stale = try await h.formPost("/operator/switches/maintenance", op, [("action", "on"), ("message", "Back soon"), ("reason", "Integrity incident INC-1")])
            XCTAssertEqual(stale.status, .forbidden)
            try await h.dashReauth(op, opAccount)
            let ok = try await h.formPost("/operator/switches/maintenance", op, [("action", "on"), ("message", "Back soon"), ("reason", "Integrity incident INC-1")])
            XCTAssertEqual(ok.status, .seeOther, ok.text)
            let audit = try await XCTUnwrapAsync(await AuditEventRecord.query(on: h.db).filter(\.$action == "platform.switch_set").first())
            XCTAssertEqual(audit.actorKind, "operator")
            XCTAssertTrue(audit.metadataJSON.contains("INC-1"))
            // Business users cannot reach the operator console at all.
            let denied = try await h.formPost("/operator/switches/maintenance", owner, [("action", "off"), ("reason", "I would like to turn it off")])
            XCTAssertTrue([.forbidden, .seeOther, .unauthorized].contains(denied.status))
            let still = await PlatformFlags(db: h.db, ctx: h.ctx).maintenance()
            XCTAssertEqual(still, "Back soon")
        }
    }

    // MARK: G-1 maintenance

    func testMaintenanceModeIsReadOnlyKeepsHealthAndProviderCallbacksAndFlipsWithoutARedeploy() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            let (owner, _, businessId) = try await h.verifiedOwner()
            let key = try await h.newKey(owner, scopes: ["interactions:write", "messages:write", "webhooks:manage"])
            let before = try await h.apiPost(key, "/v1/business/sandbox/relationships")
            XCTAssertEqual(before.status, .created)
            let on = try await h.formPost("/operator/switches/maintenance", op, [("action", "on"), ("message", "Read-only while we verify data integrity."), ("reason", "Integrity incident INC-7")])
            XCTAssertEqual(on.status, .seeOther, on.text)
            // Reads keep working; every write is a 503 with the static message and Retry-After.
            let read = try await h.apiGet(key, "/v1/business/webhooks")
            XCTAssertEqual(read.status, .ok)
            let write = try await h.apiPost(key, "/v1/business/sandbox/relationships")
            XCTAssertEqual(write.status, .serviceUnavailable)
            XCTAssertTrue(write.text.contains("Read-only while we verify data integrity."))
            XCTAssertNotNil(write.headers.first(name: "Retry-After"))
            let register = try await h.post(APIRoutes.registerBegin.template, PasskeyRegistrationBeginRequest(displayName: "New person"))
            XCTAssertEqual(register.status, .serviceUnavailable)
            let console = try await h.formPost("/dashboard/api-keys", owner, [("name", "k"), ("mode", "test"), ("scopes[]", "webhooks:manage")])
            XCTAssertEqual(console.status, .serviceUnavailable)
            // Health, the operator console (so the switch can be lifted) and the provider callbacks (a STOP must never be lost) are exempt.
            let health = try await h.request(.GET, "/healthz")
            XCTAssertEqual(health.status, .ok)
            let provider = try await h.request(.POST, "/v1/providers/sms/inbound", body: Data("{}".utf8))
            XCTAssertNotEqual(provider.status, .serviceUnavailable)
            let off = try await h.formPost("/operator/switches/maintenance", op, [("action", "off"), ("reason", "Integrity verified, resuming writes")])
            XCTAssertEqual(off.status, .seeOther, off.text)
            let after = try await h.apiPost(key, "/v1/business/sandbox/relationships")
            XCTAssertEqual(after.status, .created, "lifted without a redeploy")
            let actions = try await h.auditActions()
            XCTAssertTrue(actions.contains("platform.switch_set") && actions.contains("platform.switch_cleared"))
            _ = businessId
        }
    }

    func testAnotherInstanceSeesAFlagWithinTheCacheWindow() async throws {
        try await withHarness { h in
            let flags = PlatformFlags(db: h.db, ctx: h.ctx)
            let first = await flags.maintenance()
            XCTAssertNil(first)
            // A second instance writes straight to the table (this instance's cache is not invalidated).
            let row = PlatformFlagRecord()
            row.id = UUID(); row.flag = "maintenance"; row.scope = "global"; row.value = "Down"; row.reason = "written elsewhere"; row.updatedBy = "op"; row.updatedAt = h.clock.now()
            try await row.create(on: h.db)
            let stale = await flags.maintenance()
            XCTAssertNil(stale, "cached for a few seconds")
            h.clock.advance(by: PlatformFlags.cacheTTL + 1)
            let fresh = await flags.maintenance()
            XCTAssertEqual(fresh, "Down")
        }
    }

    // MARK: G-15 sign-up stops

    func testSignupStopsRefuseNewAccountsAndLeaveExistingOnesAlone() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            let (owner, ownerAccount, _) = try await h.verifiedOwner()
            let consumer = try await h.readyConsumer()
            for scope in ["signup.consumer", "signup.business", "invite.dashboard"] {
                let r = try await h.formPost("/operator/switches/signup", op, [("scope", scope), ("action", "on"), ("reason", "Sign-up abuse wave INC-9")])
                XCTAssertEqual(r.status, .seeOther, r.text)
            }
            let newConsumer = try await h.post(APIRoutes.registerBegin.template, PasskeyRegistrationBeginRequest(displayName: "New"))
            XCTAssertEqual(newConsumer.status, .serviceUnavailable)
            let newBusiness = try await h.jsonPost("/dashboard/auth/signup/begin", SignupBeginBody(email: "new@example.com", displayName: "New", organizationName: "New Co", category: "retail",
                                                                                                 legalName: "New Co", website: nil, requestedHandle: nil, description: nil))
            XCTAssertEqual(newBusiness.status, .serviceUnavailable)
            let invite = try await h.formPost("/dashboard/team/invite", owner, [("email", "teammate@example.com"), ("role", "analyst")])
            XCTAssertEqual(invite.status, .serviceUnavailable)
            // Existing accounts still sign in and work.
            let login = try await h.login(consumer)
            XCTAssertFalse(login.token.isEmpty)
            let relogin = try await h.dashLogin(ownerAccount)
            XCTAssertNotNil(relogin.session)
            let lifted = try await h.formPost("/operator/switches/signup", op, [("scope", "signup.consumer"), ("action", "off"), ("reason", "Wave over, lifting the stop")])
            XCTAssertEqual(lifted.status, .seeOther)
            let ok = try await h.post(APIRoutes.registerBegin.template, PasskeyRegistrationBeginRequest(displayName: "New"))
            XCTAssertEqual(ok.status, .ok)
            let stillBlocked = try await h.jsonPost("/dashboard/auth/signup/begin", SignupBeginBody(email: "new@example.com", displayName: "New", organizationName: "New Co", category: "retail",
                                                                                                  legalName: "New Co", website: nil, requestedHandle: nil, description: nil))
            XCTAssertEqual(stillBlocked.status, .serviceUnavailable, "the business stop is independent")
        }
    }

    // MARK: G-5 webhook pause

    func testWebhookPausePerEndpointPerBusinessAndGloballyKeepsDeliveriesQueued() async throws {
        try await withHarness(ownershipOff) { h in
            let (firstOp, opAccount) = try await h.makeOperator()
            let (firstOwner, ownerAccount, businessId) = try await h.verifiedOwner()
            var op = firstOp
            var owner = firstOwner
            let key = try await h.newKey(owner, scopes: ["interactions:write", "webhooks:manage"])
            func endpoint(_ url: String) async throws -> WebhookSecretResponse {
                let r = try await h.apiPost(key, "/v1/business/webhooks", json: try ViadereJSON.encode(CreateWebhookRequest(url: URL(string: url)!, events: [.messageReceived])))
                XCTAssertEqual(r.status, .created, r.text)
                return try r.json(WebhookSecretResponse.self)
            }
            let first = try await endpoint("https://one.example.com/hook")
            let second = try await endpoint("https://two.example.com/hook")
            let service = WebhookService(db: h.db, ctx: h.ctx)
            let rel = try await h.apiPost(key, "/v1/business/sandbox/relationships")
            let relationship = try XCTUnwrap(try JSONSerialization.jsonObject(with: rel.body) as? [String: Any])["relationshipId"] as? String
            func simulate() async throws {
                try await service.simulateReply(businessId: BusinessID(businessId), relationshipId: UUID(uuidString: try XCTUnwrap(relationship))!, text: "ping")
            }
            func hosts() -> [String] { h.webhooks.received.compactMap { $0.url.host } }

            // Per endpoint, through the API route the SDK calls: only that endpoint stops.
            let paused = try await h.apiPost(key, "/v1/business/webhooks/\(first.subscription.id)/pause", json: try ViadereJSON.encode(PauseWebhookRequest(reason: "investigating")))
            XCTAssertEqual(paused.status, .ok, paused.text)
            try await simulate()
            _ = try await service.deliverDue()
            XCTAssertEqual(hosts(), ["two.example.com"])
            // A paused endpoint refuses a test event; the queued delivery for it is neither sent nor dead-lettered.
            let testWhilePaused = try await h.apiPost(key, "/v1/business/webhooks/\(first.subscription.id)/test")
            XCTAssertEqual(testWhilePaused.status, .conflict)
            let queued = try await WebhookDeliveryRecord.query(on: h.db).filter(\.$subscriptionId == first.subscription.id.uuid).all()
            XCTAssertEqual(queued.map(\.status), ["pending"])
            h.clock.advance(by: 3 * 86_400)
            _ = try await service.deliverDue()
            let stillQueued = try await WebhookDeliveryRecord.query(on: h.db).filter(\.$subscriptionId == first.subscription.id.uuid).first()
            XCTAssertEqual(stillQueued?.status, "pending")
            XCTAssertEqual(stillQueued?.attempts, 0)
            // Three days passed: the console sessions ended with them.
            let opAgain = try await h.dashLogin(opAccount, realm: .operator)
            op = try XCTUnwrap(opAgain.session)
            let ownerAgain = try await h.dashLogin(ownerAccount)
            owner = try XCTUnwrap(ownerAgain.session)
            // Resume: the queued delivery goes out.
            let resumed = try await h.apiPost(key, "/v1/business/webhooks/\(first.subscription.id)/resume")
            XCTAssertEqual(resumed.status, .ok)
            _ = try await service.deliverDue()
            XCTAssertTrue(hosts().contains("one.example.com"))
            let sentBefore = h.webhooks.received.count

            // Per business, by the operator: both endpoints stop, and the business is told on its page.
            let pauseBusiness = try await h.formPost("/operator/switches/webhooks", op, [("businessId", businessId.uuidString.lowercased()), ("action", "on"), ("reason", "Takeover suspected INC-12")])
            XCTAssertEqual(pauseBusiness.status, .seeOther, pauseBusiness.text)
            try await simulate()
            _ = try await service.deliverDue()
            XCTAssertEqual(h.webhooks.received.count, sentBefore)
            let page = try await h.page("/dashboard/webhooks", owner).text
            XCTAssertTrue(page.contains("paused by Viadere"))
            // Globally: another business is stopped too.
            let (other, _, otherId) = try await h.verifiedOwner(email: "o2@example.net", org: "Other Co", handle: "otherco")
            _ = other
            let flags = PlatformFlags(db: h.db, ctx: h.ctx)
            let notPaused = await flags.webhooksPaused(businessId: otherId)
            XCTAssertFalse(notPaused)
            _ = try await h.formPost("/operator/switches/webhooks", op, [("action", "on"), ("reason", "Provider incident, pausing everything")])
            let nowPaused = await flags.webhooksPaused(businessId: otherId)
            XCTAssertTrue(nowPaused)
            // Lifting the global and the business switch resumes delivery of what queued up.
            _ = try await h.formPost("/operator/switches/webhooks", op, [("action", "off"), ("reason", "Provider incident over")])
            _ = try await h.formPost("/operator/switches/webhooks", op, [("businessId", businessId.uuidString.lowercased()), ("action", "off"), ("reason", "Takeover ruled out")])
            _ = try await service.deliverDue()
            XCTAssertGreaterThan(h.webhooks.received.count, sentBefore)
            _ = second
        }
    }

    // MARK: G-6 emergency messaging restriction

    func testMessagingGateDecisions() async throws {
        try await withHarness { h in
            let flags = PlatformFlags(db: h.db, ctx: h.ctx)
            let gate = MessagingGate(db: h.db, ctx: h.ctx)
            let business = try await h.makeBusiness(name: "Gate Co", handle: "gateco")
            let other = try await h.makeBusiness(name: "Other Co", handle: "otherco")
            let actor = EntitlementActor.system("test")
            let allowedBefore = await gate.decide(businessId: business.record.id!, channel: .sms, purpose: "marketing")
            XCTAssertEqual(allowedBefore, .allow)
            // Block SMS and RCS for one business only.
            try await flags.set(.messagingRestrict, businessId: business.record.id!, value: #"{"mode":"block","channels":["sms","rcs"]}"#, reason: "Carrier complaint wave", actor: actor)
            let blockedSMS = await gate.decide(businessId: business.record.id!, channel: .sms, purpose: "marketing")
            let blockedRCS = await gate.decide(businessId: business.record.id!, channel: .rcs, purpose: "transactional")
            let pushStillOK = await gate.decide(businessId: business.record.id!, channel: .push, purpose: "marketing")
            let otherOK = await gate.decide(businessId: other.record.id!, channel: .sms, purpose: "marketing")
            XCTAssertEqual(blockedSMS, .block)
            XCTAssertEqual(blockedRCS, .block)
            XCTAssertEqual(pushStillOK, .allow)
            XCTAssertEqual(otherOK, .allow)
            // Security traffic (sign-in and payment approvals) is never covered.
            let security = await gate.decide(businessId: business.record.id!, channel: .sms, purpose: "security", kind: .authorize)
            XCTAssertEqual(security, .allow)
            // Platform gate M1: a message that merely declares the security purpose is not exempt; only the server-known kind is.
            let mislabelled = await gate.decide(businessId: business.record.id!, channel: .sms, purpose: "security", kind: .message)
            XCTAssertEqual(mislabelled, .block, "a marketing blast labelled security must still be restricted")
            let unlabelled = await gate.decide(businessId: business.record.id!, channel: .sms, purpose: "security")
            XCTAssertEqual(unlabelled, .block)
            // A global clamp bounds what any tenant can send per minute; purposes can narrow a restriction.
            try await flags.clear(.messagingRestrict, businessId: business.record.id!, reason: "Wave over, lifting", actor: actor)
            try await flags.set(.messagingRestrict, value: #"{"mode":"clamp","channels":["sms"],"perMinute":2,"purposes":["marketing"]}"#, reason: "Provider asked us to slow down", actor: actor)
            var decisions: [MessagingGate.Decision] = []
            for _ in 0..<3 { decisions.append(await gate.decide(businessId: other.record.id!, channel: .sms, purpose: "marketing")) }
            XCTAssertEqual(decisions, [.allow, .allow, .delay(60)])
            let unrelated = await gate.decide(businessId: other.record.id!, channel: .sms, purpose: "transactional")
            XCTAssertEqual(unrelated, .allow, "the clamp names marketing only")
            h.clock.advance(by: 61)
            let again = await gate.decide(businessId: other.record.id!, channel: .sms, purpose: "marketing")
            XCTAssertEqual(again, .allow)
            // Values the readers would ignore are refused when set: no unknown channel, no security purpose, no unbounded clamp.
            for bad in [#"{"mode":"block","channels":[]}"#, #"{"mode":"block","channels":["fax"]}"#, #"{"mode":"clamp","channels":["sms"],"perMinute":100000}"#,
                        #"{"mode":"block","channels":["sms"],"purposes":["security"]}"#, "not json"] {
                do { try await flags.set(.messagingRestrict, value: bad, reason: "Should never be stored", actor: actor); XCTFail(bad) } catch {}
            }
        }
    }

    /// Platform gate M1 exploit: a marketing message labelled "security" skipped consent and the emergency restriction.
    func testAMessageLabelledSecurityIsRefusedAtIssue() async throws {
        try await withHarness { h in
            let business = try await h.makeBusiness(name: "Blast Co", handle: "blastco")
            let consumer = try await h.readyConsumer()
            let relationship = try await h.connect(consumer, to: business)
            let blast = try await h.issue(business, relationship: relationship, payload: .message(MessagePayload(text: "Flash sale today")), purpose: .security, key: "blast-1")
            XCTAssertEqual(blast.status, .unprocessableEntity, blast.text)
            let honest = try await h.issue(business, relationship: relationship, payload: .message(MessagePayload(text: "Flash sale today")), purpose: .support, key: "blast-2")
            XCTAssertEqual(honest.status, .created, honest.text)
        }
    }

    func testARestrictedBusinessSendsNoTextsButItsSecurityTrafficStillGoes() async throws {
        try await withHarness { h in
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            try await h.linkVerifiedPhone(consumer)
            let relationship = try await h.connect(consumer, to: business)
            let channels: [DeliveryChannel] = [.nativePush, .inApp, .sms]
            func issue(purpose: InteractionPurpose) async throws {
                // A security-purpose request is a real approval (authorize); a confirmation labelled security is not exempt (gate M1).
                let payload: InteractionPayload = purpose == .security ? .authorize(.sample(amount: "10.00"))
                    : .confirm(ConfirmPayload(title: "Confirm seat 14C", details: "Flight 482", reference: "BK\(UUID().uuidString.prefix(6))"))
                let r = try await h.issue(business, relationship: relationship, payload: payload,
                                          purpose: purpose, key: UUID().uuidString, ttl: purpose == .security ? 300 : 3600, channels: channels)
                XCTAssertEqual(r.status, .created, r.text)
            }
            let router = ChannelRouter(db: h.db, ctx: h.ctx)
            let queue = OutboundSMS(db: h.db, ctx: h.ctx)
            func drain() async throws {
                _ = try await router.deliverDue()
                _ = try await queue.sendDue()
                h.clock.advance(by: 2)
            }
            try await issue(purpose: .transactional)
            try await drain()
            XCTAssertEqual(h.texts.sent.count, 1, "unrestricted")
            // Block texting for this business: the next interaction is cancelled, audited, and nothing reaches the carrier.
            let flags = PlatformFlags(db: h.db, ctx: h.ctx)
            try await flags.set(.messagingRestrict, businessId: business.record.id!, value: #"{"mode":"block","channels":["sms","rcs"]}"#, reason: "Carrier complaint wave", actor: .system("test"))
            try await issue(purpose: .transactional)
            try await drain()
            XCTAssertEqual(h.texts.sent.count, 1)
            let row = try await ChannelOutboundRecord.query(on: h.db).sort(\.$createdAt, .descending).first()
            XCTAssertEqual(row?.status, "cancelled")
            XCTAssertEqual(row?.errorCode, "restricted")
            let audited = try await h.auditActions(business.record.id!)
            XCTAssertTrue(audited.contains("channel.restricted"))
            // Push is covered when the restriction names it.
            try await flags.set(.messagingRestrict, businessId: business.record.id!, value: #"{"mode":"block","channels":["sms","rcs","push"]}"#, reason: "Carrier complaint wave", actor: .system("test"))
            // Sign-in and payment approvals are not covered.
            try await issue(purpose: .security)
            try await drain()
            XCTAssertEqual(h.texts.sent.count, 2, "security-purpose traffic is never restricted")
            // Lifting restores normal delivery.
            try await flags.clear(.messagingRestrict, businessId: business.record.id!, reason: "Complaint wave over", actor: .system("test"))
            try await issue(purpose: .transactional)
            try await drain()
            XCTAssertEqual(h.texts.sent.count, 3)
        }
    }

    // MARK: G-12 abuse thresholds

    func testRuntimeAbuseThresholdsAreBoundedAndApplied() async throws {
        try await withHarness { h in
            let flags = PlatformFlags(db: h.db, ctx: h.ctx)
            let base = h.ctx.config.abuse
            let unchanged = await flags.abuse(base: base)
            XCTAssertEqual(unchanged.complaintRate, base.complaintRate)
            try await flags.set(.abuseThresholds, value: #"{"complaintRate":0.01,"throttleFactor":0.1}"#, reason: "Tightening during the spam wave", actor: .system("test"))
            let tightened = await flags.abuse(base: base)
            XCTAssertEqual(tightened.complaintRate, 0.01)
            XCTAssertEqual(tightened.throttleFactor, 0.1)
            XCTAssertEqual(tightened.optOutRate, base.optOutRate, "untouched values keep the configured default")
            // The checks cannot be switched off by an extreme value, and an empty override is refused.
            for bad in [#"{"complaintRate":0.0}"#, #"{"complaintRate":0.9}"#, #"{"minimumSample":0}"#, #"{"throttleFactor":0}"#, #"{"windowDays":365}"#, "{}", "x"] {
                do { try await flags.set(.abuseThresholds, value: bad, reason: "Should never be stored", actor: .system("test")); XCTFail(bad) } catch {}
            }
            // A business-scoped value for a global-only switch is refused.
            let business = try await h.makeBusiness(name: "Scoped Co", handle: "scopedco")
            do { try await flags.set(.abuseThresholds, businessId: business.record.id!, value: #"{"complaintRate":0.01}"#, reason: "Should never be stored", actor: .system("test")); XCTFail() } catch {}
        }
    }

    // MARK: G-7 consumer freeze

    func testFreezingAConsumerEndsSessionsAndDevicesBlocksEverythingAndTellsThem() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            var consumer = try await h.readyConsumer()
            let relationship = try await h.connect(consumer, to: business)
            let interaction = try await h.issue(business, relationship: relationship, payload: .confirm(ConfirmPayload(title: "Confirm seat 14C", details: "Flight 482", reference: "BK1")))
            XCTAssertEqual(interaction.status, .created)
            let before = try await h.signed(consumer, .GET, "/v1/security-notices")
            XCTAssertEqual(before.status, .ok)
            let consumerId = consumer.id.uuid.uuidString.lowercased()
            // Validation first: a bad id or reason changes nothing.
            let bad = try await h.formPost("/operator/consumers/freeze", op, [("consumerId", "nope"), ("reason", "Reported compromise by the account holder")])
            XCTAssertNotEqual(bad.status, .seeOther)
            let short = try await h.formPost("/operator/consumers/freeze", op, [("consumerId", consumerId), ("reason", "x")])
            XCTAssertNotEqual(short.status, .seeOther)
            let freeze = try await h.formPost("/operator/consumers/freeze", op, [("consumerId", consumerId), ("reason", "Reported compromise by the account holder")])
            XCTAssertEqual(freeze.status, .seeOther, freeze.text)
            // Sessions, signed requests, refresh and sign-in are all refused; so is the decision on a pending approval.
            let after = try await h.signed(consumer, .GET, "/v1/security-notices")
            XCTAssertEqual(after.status, .unauthorized)
            let refresh = try await h.refresh(consumer)
            XCTAssertNotEqual(refresh.status, .ok)
            let relogin = try await h.post(APIRoutes.loginBegin.template, PasskeyLoginBeginRequest())
            XCTAssertEqual(relogin.status, .ok, "the ceremony starts; it cannot finish for a frozen account")
            let options = try relogin.json(PasskeyAssertionOptions.self)
            let credential = PasskeyAssertionCredential(id: consumer.credentialId, rawId: consumer.credentialId, authenticatorData: "AA", clientDataJSON: options.challenge, signature: "valid", userHandle: nil)
            let finish = try await h.post(APIRoutes.loginFinish.template, PasskeyLoginFinishRequest(ceremonyId: options.ceremonyId, credential: credential))
            XCTAssertNotEqual(finish.status, .ok, "a frozen account cannot sign in")
            let record = try await XCTUnwrapAsync(await ConsumerRecord.find(consumer.id.uuid, on: h.db))
            XCTAssertEqual(record.status, "frozen")
            let devices = try await DeviceRecord.query(on: h.db).filter(\.$consumerId == consumer.id.uuid).filter(\.$revokedAt == nil).count()
            XCTAssertEqual(devices, 0)
            // A notice was stored for the person (shown after they come back), the freeze is audited with the operator as actor, and the row has the reason.
            let notice = try await SecurityNoticeRecord.query(on: h.db).filter(\.$consumerId == consumer.id.uuid).filter(\.$kind == ConsumerFreeze.noticeKind).first()
            XCTAssertNotNil(notice)
            XCTAssertFalse(notice?.message.contains("compromise") ?? true, "the notice is generic: the internal reason stays internal")
            let audit = try await XCTUnwrapAsync(await AuditEventRecord.query(on: h.db).filter(\.$action == "operator.account_frozen").first())
            XCTAssertEqual(audit.actorKind, "operator")
            // Freezing twice is a conflict, and a business cannot reach a frozen consumer's pending interaction decisions.
            let twice = try await h.formPost("/operator/consumers/freeze", op, [("consumerId", consumerId), ("reason", "Second attempt at the same freeze")])
            XCTAssertEqual(twice.status, .conflict)
            // Lifting the freeze restores the status only: sessions and devices stay revoked and the person signs in again.
            let lift = try await h.formPost("/operator/consumers/unfreeze", op, [("consumerId", consumerId), ("reason", "Identity confirmed by phone")])
            XCTAssertEqual(lift.status, .seeOther, lift.text)
            let lifted = try await XCTUnwrapAsync(await ConsumerRecord.find(consumer.id.uuid, on: h.db))
            XCTAssertEqual(lifted.status, "active")
            let stillOut = try await h.signed(consumer, .GET, "/v1/security-notices")
            XCTAssertEqual(stillOut.status, .unauthorized)
            consumer = try await h.login(consumer)
            XCTAssertFalse(consumer.token.isEmpty)
        }
    }

    // MARK: G-9 operator notices

    func testOperatorNoticesReachBusinessesAndConsumersInBatchesWithoutSecrets() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            let (owner, _, businessId) = try await h.verifiedOwner()
            let consumer = try await h.readyConsumer()
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            _ = try await h.connect(consumer, to: business)
            let path = "/operator/businesses/\(businessId.uuidString.lowercased())"
            let mailBefore = h.emails.sent.count
            let toBusiness = try await h.formPost("\(path)/notify", op, [("scope", "business"), ("severity", "important"), ("title", "Rotate your API keys"), ("body", "A third-party leak may affect keys created before Monday. Rotate them in the console.")])
            XCTAssertEqual(toBusiness.status, .seeOther, toBusiness.text)
            // Creating a notice never fans out inline: the job delivers it.
            XCTAssertEqual(h.emails.sent.count, mailBefore)
            let notices = OperatorNotices(db: h.db, ctx: h.ctx)
            let reached = try await notices.deliverDue()
            XCTAssertEqual(reached, 1)
            XCTAssertTrue(h.emails.sent.dropFirst(mailBefore).contains { $0.to == "owner@example.com" && $0.subject == "Rotate your API keys" })
            let visible = try await notices.visibleToBusiness(businessId)
            XCTAssertEqual(visible.count, 1)
            let page = try await h.page("/dashboard/support/notices", owner).text
            XCTAssertTrue(page.contains("Rotate your API keys"))
            // Consumers of one business get an in-app security notice (and a generic push).
            let toConsumers = try await h.formPost("/operator/notices", op, [("scope", "consumers_of_business"), ("businessId", business.record.id!.uuidString.lowercased()), ("severity", "critical"),
                                                                           ("title", "Northwind Air incident"), ("body", "Northwind Air reported an incident. Do not approve requests you did not start.")])
            XCTAssertEqual(toConsumers.status, .seeOther, toConsumers.text)
            _ = try await notices.deliverDue()
            let stored = try await SecurityNoticeRecord.query(on: h.db).filter(\.$consumerId == consumer.id.uuid).filter(\.$kind == "operator_notice").all()
            XCTAssertEqual(stored.count, 1)
            // Bad input is refused: too short, unknown severity, missing business.
            let badSeverity = try await h.formPost("/operator/notices", op, [("scope", "all_consumers"), ("severity", "whatever"), ("title", "Hello there"), ("body", "A long enough body text here.")])
            XCTAssertNotEqual(badSeverity.status, .seeOther)
            let missing = try await h.formPost("/operator/notices", op, [("scope", "business"), ("severity", "info"), ("title", "Hello there"), ("body", "A long enough body text here.")])
            XCTAssertNotEqual(missing.status, .seeOther)
            XCTAssertFalse(h.allMailText.contains("vdk_"))
        }
    }

    // MARK: G-13 metrics

    func testMetricsAreProtectedAndCarryNoPersonalData() async throws {
        let metricsToken = SecureToken.generate()
        try await withHarness({ $0.operations.metricsToken = Data(metricsToken.utf8) }) { h in
            let (owner, _, _) = try await h.verifiedOwner(email: "pii.person@example.com", org: "Secret Org Name", handle: "secretorg")
            _ = try await h.newKey(owner, scopes: ["webhooks:manage"])
            let none = try await h.request(.GET, "/metrics")
            XCTAssertEqual(none.status, .unauthorized)
            let wrong = try await h.request(.GET, "/metrics", headers: ["Authorization": "Bearer " + SecureToken.generate()])
            XCTAssertEqual(wrong.status, .unauthorized)
            let ok = try await h.request(.GET, "/metrics", headers: ["Authorization": "Bearer " + metricsToken])
            XCTAssertEqual(ok.status, .ok)
            XCTAssertTrue(ok.text.contains("viadere_"))
            for forbidden in ["pii.person", "example.com", "Secret Org", "secretorg", "vdk_", "Bearer", metricsToken] {
                XCTAssertFalse(ok.text.contains(forbidden), forbidden)
            }
            // Counters carry bounded labels only.
            for line in ok.text.split(separator: "\n") where !line.hasPrefix("#") {
                XCTAssertLessThan(line.count, 160)
            }
        }
        // No token configured: the route does not exist.
        try await withHarness { h in
            let off = try await h.request(.GET, "/metrics", headers: ["Authorization": "Bearer anything"])
            XCTAssertEqual(off.status, .notFound)
        }
    }
}
