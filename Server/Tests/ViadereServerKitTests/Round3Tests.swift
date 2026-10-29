@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import SQLKit
import Vapor
import ViadereCore
import enum ViadereCore.Channel
import XCTest
@testable import ViadereServerKit

/// Security hardening, review round 3: each test reproduces the exploit path first and asserts it is now refused.
final class Round3Tests: XCTestCase {
    // MARK: #9 - deletion vs. non-repudiation

    func testDeletionKeepsNonFreeTextDecisionsVerifiableAndExportable() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b, optIn: [.support])
            // One approval (ids and digest only) and one free-text reply.
            let approval = try await h.highAuthorizeR3(b, rel)
            let approvalSeen = try await h.consumerInteraction(consumer, id: approval.id)
            let approved = try await h.decide(consumer, id: approval.id, signed: try await h.decision(consumer, interaction: approvalSeen))
            XCTAssertEqual(approved.status, .ok, approved.text)
            let ask = try await h.issue(b, relationship: rel, payload: .reply(ReplyPayload(prompt: "Any notes?")), purpose: .support, sensitivity: .low)
            let askId = try ask.json(Interaction.self).id
            let askSeen = try await h.consumerInteraction(consumer, id: askId)
            let replied = try await h.decide(consumer, id: askId, signed: try await h.decision(consumer, interaction: askSeen, decision: .reply, assurance: .none, reply: "My door code is QZ4417"))
            XCTAssertEqual(replied.status, .ok, replied.text)

            let before = try await ExportDisputeCommand.export(interactionId: approval.id.uuid, db: h.db, ctx: h.ctx)
            try await eq(try await h.signed(consumer, .DELETE, "/v1/account").status, .ok)

            let decisions = try await DecisionRecord.query(on: h.db).all()
            XCTAssertEqual(decisions.count, 2)
            let kept = try XCTUnwrap(decisions.first { $0.interactionId == approval.id.uuid })
            let erased = try XCTUnwrap(decisions.first { $0.interactionId == askId.uuid })
            XCTAssertEqual(erased.signedPayload, CreateSecurityHardeningSchema.erased, "the free-text reply is erased")
            XCTAssertNotEqual(kept.signedPayload, CreateSecurityHardeningSchema.erased, "an id-and-digest-only decision stays")
            XCTAssertFalse(kept.signedPayload.contains("QZ4417"))
            // The dispute export still works for the kept decision, with a verifiable signature and the same evidence.
            let afterOpt = try await ExportDisputeCommand.export(interactionId: approval.id.uuid, db: h.db, ctx: h.ctx)
            let after = try XCTUnwrap(afterOpt)
            XCTAssertEqual(after.signedPayload, before?.signedPayload)
            XCTAssertEqual(after.signature, before?.signature)
            XCTAssertEqual(after.evidenceRef, before?.evidenceRef)
            let payloadBytes = try XCTUnwrap(Base64URL.decode(after.signedPayload))
            let decoded = try DecisionPayload.decodeCanonical(payloadBytes)
            XCTAssertEqual(decoded.decision, .approve)
            XCTAssertNil(decoded.reply)
        }
    }

    // MARK: Helpers

    func say(_ h: TestHarness, _ text: String, from: String) async throws -> [String] {
        let before = h.texts.sent.count
        let response = try await sendInbound(h, from: from, body: text, sid: nil)
        XCTAssertEqual(response.status, .ok, response.text)
        try await h.runJobs()
        return h.texts.sent.dropFirst(before).map(\.body)
    }

    func requestLinkToken(_ h: TestHarness, from number: String) async throws -> String {
        _ = try await say(h, "Hi", from: number)
        _ = try await say(h, "Northwind", from: number)
        let sms = try await say(h, "1", from: number)
        let body = try XCTUnwrap(sms.first { $0.contains("/l/") })
        let range = try XCTUnwrap(body.range(of: "https://viadere.com/l/"))
        return String(body[range.upperBound...].prefix { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
    }

    func redeem(_ h: TestHarness, _ consumer: TestConsumer, token: String, last4: String) async throws -> PhoneLink {
        let preview = try await h.signed(consumer, .GET, "/v1/sms/link-tokens/\(token)/preview").json(SMSLinkPreview.self)
        let ok = try await h.signedPost(consumer, APIRoutes.smsLinkRedeem.template,
                                        SMSLinkRedeemRequest(token: token, confirmPhoneLast4: last4, confirmMaskedPhone: preview.maskedPhone))
        XCTAssertEqual(ok.status, .ok, ok.text)
        return try ok.json(PhoneLink.self)
    }

    func gatewayConsumer(_ h: TestHarness, _ phone: String) async throws -> ConsumerID? {
        try await GatewayService(db: h.db, ctx: h.ctx).loadContext(phone: PhoneNumber(phone)!, on: h.db).0.consumerId
    }

    // MARK: #2 - SMS gateway honours the phone-link cool-down

    func testALinkInItsCoolDownIsNotAnIdentityOnTheSMSGateway() async throws {
        try await withHarness { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let victim = try await h.readyConsumer(name: "Victim")
            _ = try await h.connect(victim, to: airline)
            // The attacker redeems their own link token from a device on the victim's account (stolen passkey / session).
            let attackerPhone = "+14805550199"
            let token = try await requestLinkToken(h, from: attackerPhone)
            let link = try await redeem(h, victim, token: token, last4: "0199")
            // No other trusted device exists to confirm it, so the delay is 72 h, not 24 h.
            XCTAssertEqual(link.usableFrom, h.clock.now().addingTimeInterval(72 * 3600))
            let notices = try await PhoneLinkRecord.query(on: h.db).filter(\.$state == "verified").count()
            XCTAssertEqual(notices, 1)

            // The attacker's phone is not the victim's account on SMS: no consumer, no session, no forwarded text, no recents.
            try await eq(try await gatewayConsumer(h, attackerPhone), nil)
            _ = try await say(h, "Hi", from: attackerPhone)
            _ = try await say(h, "Northwind", from: attackerPhone)
            let reply = try await say(h, "1", from: attackerPhone)
            XCTAssertTrue(reply.joined().contains("/l/") || reply.joined().contains("link your account"), reply.joined())
            _ = try await say(h, "hello", from: attackerPhone)
            try await eq(try await ConversationSessionRecord.query(on: h.db).count(), 0)
            try await eq(try await ConversationMessageRecord.query(on: h.db).count(), 0)
            try await eq(try await RelationshipRecord.query(on: h.db).filter(\.$source == "sms").count(), 0)
            try await eq(try await SMSContextRecord.query(on: h.db).first()?.consumerId, nil)

            // The account is told even though it has no other device: an in-app notice (and an audit event).
            let second = try await h.enrollDevice(victim)
            let seen = try await h.signed(second, .GET, "/v1/security-notices")
            XCTAssertEqual(seen.status, .ok, seen.text)
            XCTAssertTrue(try seen.json([SecurityNotice].self).contains { $0.kind == .newPhone })
            let audited = try await AuditEventRecord.query(on: h.db).filter(\.$action == "phone_link.verified").all()
            XCTAssertTrue(audited.contains { $0.metadataJSON.contains("\"cool_down\":\"true\"") })
            // The listing tells the app the link is pending.
            let listed = try await h.signed(victim, .GET, "/v1/phone-links").json([PhoneLink].self)
            XCTAssertNotNil(listed.first?.usableFrom)

            // 24 h is not enough without a confirmation; 72 h is.
            h.clock.advance(by: 24 * 3600 + 1)
            try await eq(try await gatewayConsumer(h, attackerPhone), nil)
            h.clock.advance(by: 48 * 3600)
            try await eq(try await gatewayConsumer(h, attackerPhone), victim.id)
        }
    }

    func testAConfirmedLinkWorksAtOnceAndTheDelayIs24HoursWithAnotherTrustedDevice() async throws {
        try await withHarness { h in
            _ = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let a = try await h.readyConsumer()
            let b = try await h.enrollDevice(a)
            // Device B is trusted (approved by A): then the delay is the short one.
            try await eq(try await h.confirm(b, from: a).status, .ok)
            let phone = "+14805550123"
            let token = try await requestLinkToken(h, from: phone)
            let link = try await redeem(h, a, token: token, last4: "0123")
            XCTAssertEqual(link.usableFrom, h.clock.now().addingTimeInterval(24 * 3600))
            try await eq(try await gatewayConsumer(h, phone), nil)
            let proof = try await ConfirmationProof.sign(subject: .phoneLink, subjectId: link.id.description, deviceId: b.device!.id, assurance: .biometric,
                                                         key: b.device!.biometricKey, now: h.clock.now())
            try await eq(try await h.signedPost(b, "/v1/phone-links/\(link.id)/confirm", ConfirmationRequest(proof: proof)).status, .ok)
            try await eq(try await gatewayConsumer(h, phone), a.id)
        }
    }

    // MARK: #3 - cross-business on RCS

    func testAnotherBusinessesTextIsNotSentOverRCSWhileTheThreadIsConnectedElsewhere() async throws {
        let http = ScriptedRCSHTTP()
        try await withHarness(rcs: GenericRBMProvider(config: RCSFixture.config, http: http)) { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let hotel = try await h.makeBusiness(name: "Harbor Hotel", handle: "harborhotel")
            let consumer = try await h.readyConsumer()
            try await h.linkVerifiedPhone(consumer)
            _ = try await h.connect(consumer, to: airline)
            let relHotel = try await h.connect(consumer, to: hotel)
            _ = try await say(h, "Hi", from: RCSFixture.phone)
            _ = try await say(h, "@northwindair", from: RCSFixture.phone)
            _ = try await say(h, "1", from: RCSFixture.phone)
            // The hotel sends a confirm over RCS: chips would be answered inside the airline's thread.
            let r = try await h.issue(hotel, relationship: relHotel, payload: .confirm(ConfirmPayload(title: "Room 9F upgrade")), purpose: .transactional,
                                      sensitivity: .low, channels: [.nativePush, .rcs, .sms])
            XCTAssertEqual(r.status, .created, r.text)
            try await h.runJobs()
            try await h.runJobs()
            let rcsBodies = http.sends.map { String(decoding: $0.body ?? Data(), as: UTF8.self) }
            let smsBodies = h.texts.sent.map(\.body)
            for body in rcsBodies + smsBodies.suffix(1) {
                XCTAssertFalse(body.contains("Room 9F"), body)
                XCTAssertFalse(body.contains("vrp1."), "no postback chips from the other business: \(body)")
            }
            XCTAssertTrue((rcsBodies + smsBodies).contains { $0.contains("Harbor Hotel") && $0.contains("Northwind Air") })
            try await eq(try await RCSPostbackRecord.query(on: h.db).count(), 0)
            let row = try await XCTUnwrapAsync(try await ChannelOutboundRecord.query(on: h.db).first())
            XCTAssertEqual(row.fallbackReason, "thread_connected_elsewhere")
        }
    }

    // MARK: #5 - refresh-token reuse, grace window, logout

    func refresh(_ h: TestHarness, _ token: String, as user: TestConsumer? = nil) async throws -> HTTPResult {
        if let user { return try await h.refresh(user, token: token) }
        return try await h.post(APIRoutes.authRefresh.template, AuthRefreshRequest(refreshToken: token))
    }

    func testALostRefreshResponseIsReplayedWithinTheGraceWindowAndIsTheftAfterwards() async throws {
        try await withHarness { h in
            let user = try await h.readyConsumer()
            let r1 = user.session.refreshToken!
            let first = try await refresh(h, r1, as: user)
            XCTAssertEqual(first.status, .ok, first.text)
            let pair = try first.json(AuthSession.self)
            // The response never arrived (or the extension raced the app): the same token again, 5 s later, returns the same pair.
            h.clock.advance(by: 5)
            let again = try await refresh(h, r1, as: user)
            XCTAssertEqual(again.status, .ok, again.text)
            let same = try again.json(AuthSession.self)
            XCTAssertEqual(same.refreshToken!, pair.refreshToken!)
            XCTAssertEqual(same.accessToken, pair.accessToken)
            // The successor is stored encrypted, never in the clear.
            let stored = try await RefreshTokenRecord.query(on: h.db).filter(\.$tokenHash == SecureToken.hash(r1)).first()
            let sealed = try XCTUnwrap(stored?.successorSealed)
            XCTAssertFalse(sealed.contains(pair.refreshToken!))
            XCTAssertTrue(sealed.hasPrefix("v2."))
            // The family and its device are untouched.
            try await isNil(try await TokenFamilyRecord.find(try XCTUnwrap(stored?.familyId), on: h.db)?.revokedAt)
            // After the window the same token is reuse.
            h.clock.advance(by: 120)
            let late = try await refresh(h, r1, as: user)
            XCTAssertEqual(late.status, .unauthorized)
            let wiped = try await RefreshTokenRecord.query(on: h.db).filter(\.$tokenHash == SecureToken.hash(r1)).first()
            _ = wiped
            try await notNil(try await TokenFamilyRecord.find(try XCTUnwrap(stored?.familyId), on: h.db)?.revokedAt)
            // The successor died with the family.
            try await eq(try await refresh(h, pair.refreshToken!, as: user).status, .unauthorized)
        }
    }

    func testReuseRevokesOnlyDevicesEnrolledAfterTheReusedTokenNotTheSessionsOwnDevice() async throws {
        try await withHarness { h in
            let user = try await h.readyConsumer()   // device D, enrolled before any rotation
            let deviceD = user.device!.id.uuid
            h.clock.advance(by: 1)
            let second = try await refresh(h, user.session.refreshToken!, as: user)
            var current = user
            current.session = try second.json(AuthSession.self)
            let r2 = current.session.refreshToken!
            h.clock.advance(by: 1)
            // A thief holding the session (and a passkey assertion) enrolls device E after R2 was issued.
            let thief = try await h.enrollInSession(current)
            XCTAssertNotNil(thief.device)
            h.clock.advance(by: 1)
            let third = try await refresh(h, r2, as: thief)   // legitimate rotation R2 -> R3
            XCTAssertEqual(third.status, .ok, third.text)
            h.clock.advance(by: 120)
            // R2 is presented again, long after: reuse.
            try await eq(try await refresh(h, r2, as: thief).status, .unauthorized)
            let d = try await XCTUnwrapAsync(try await DeviceRecord.find(deviceD, on: h.db))
            XCTAssertNil(d.revokedAt, "the device the session already belonged to survives (no cascade to the pre-existing device)")
            let e = try await XCTUnwrapAsync(try await DeviceRecord.find(thief.device!.id.uuid, on: h.db))
            XCTAssertNotNil(e.revokedAt, "what was enrolled through the session after the stolen token is revoked")
        }
    }

    func testAnExpiredUsedRefreshTokenIsJustInvalid() async throws {
        try await withHarness { h in
            let user = try await h.readyConsumer()
            _ = try await refresh(h, user.session.refreshToken!, as: user)
            h.clock.advance(by: h.config.refreshTokenTTL + 10)
            try await eq(try await refresh(h, user.session.refreshToken!, as: user).status, .unauthorized)
            let family = try await TokenFamilyRecord.query(on: h.db).first()
            XCTAssertNil(family?.revokedAt, "an expired token proves nothing; nothing is revoked")
            try await isNil(try await DeviceRecord.find(user.device!.id.uuid, on: h.db)?.revokedAt)
        }
    }

    func testLogoutIsDeviceSignedAndEndsTheSessionOnly() async throws {
        try await withHarness { h in
            let user = try await h.readyConsumer()
            // A bearer token alone cannot log anyone out.
            let bearerOnly = try await h.request(.POST, "/v1/auth/logout", headers: ["Authorization": "Bearer \(user.token)"])
            XCTAssertEqual(bearerOnly.status, .unauthorized)
            try await eq(try await h.signed(user, .GET, "/v1/devices").status, .ok)
            let out = try await h.signed(user, .POST, "/v1/auth/logout")
            XCTAssertEqual(out.status, .ok, out.text)
            // The session is over, the device is not revoked.
            try await eq(try await h.signed(user, .GET, "/v1/devices").status, .unauthorized)
            try await isNil(try await DeviceRecord.find(user.device!.id.uuid, on: h.db)?.revokedAt)
            let again = try await h.login(user)
            try await eq(try await h.signed(again, .GET, "/v1/devices").status, .ok)
        }
    }

    // MARK: #7 - cool-down scope, trusted-device predicate, confirmation assurance

    func testRevokingEveryDeviceDoesNotResetTheCoolDown() async throws {
        try await withHarness { h in
            let a = try await h.readyConsumer()
            let first = try await DeviceRecord.find(a.device!.id.uuid, on: h.db)
            XCTAssertNil(first?.approvalsLockedUntil, "the very first device has nobody to confirm it")
            // The owner (or a thief who beat them to it) removes the only device, then enrolls another.
            try await eq(try await h.signed(a, .DELETE, "/v1/devices/\(a.device!.id)").status, .ok)
            let b = try await h.enrollDevice(a)
            let record = try await XCTUnwrapAsync(try await DeviceRecord.find(b.device!.id.uuid, on: h.db))
            XCTAssertEqual(record.approvalsLockedUntil, h.clock.now().addingTimeInterval(24 * 3600), "any earlier device (revoked ones too) starts a cool-down")
            // A lapsed account (nothing for months) is NOT new again: an account that ever had an app device cools down.
            try await DeviceRecord.query(on: h.db).filter(\.$id == b.device!.id.uuid).set(\.$revokedAt, to: h.clock.now()).update()
            h.clock.advance(by: 400 * 86_400)
            let c = try await h.enrollDevice(b)
            let lapsed = try await XCTUnwrapAsync(try await DeviceRecord.find(c.device!.id.uuid, on: h.db))
            XCTAssertEqual(lapsed.approvalsLockedUntil, h.clock.now().addingTimeInterval(24 * 3600), "no lookback limit: a lapsed account's device cools down")
        }
    }

    func testARequestKeyOnlyAppDeviceStillCoolsDownAndIsUntrusted() async throws {
        try await withHarness { h in
            let a = try await h.readyConsumer()
            // An attacker with a synced passkey enrolls an app device without approval keys, hoping to skip the cool-down.
            let b = try await h.enrollDevice(a, purposes: [.request])
            let record = try await XCTUnwrapAsync(try await DeviceRecord.find(b.device!.id.uuid, on: h.db))
            XCTAssertNotNil(record.approvalsLockedUntil, "a request-key-only app device must still cool down")
            func refused(_ result: HTTPResult, _ what: String) {
                XCTAssertEqual(result.status, .forbidden, "\(what): \(result.text)")
                XCTAssertEqual(result.errorCode, .deviceCoolDown, what)
            }
            refused(try await h.signed(b, .DELETE, "/v1/devices/\(a.device!.id)"), "revoke the owner's device")
            refused(try await h.signedPost(b, "/v1/phone-links/start", PhoneLinkStartRequest(phone: PhoneNumber("+14805550123")!)), "phone link start")
            refused(try await h.signed(b, .DELETE, "/v1/account"), "account deletion")
            refused(try await h.signed(b, .DELETE, "/v1/phone-links/\(PhoneLinkID())"), "remove a phone link")
            refused(try await h.signed(b, .DELETE, "/v1/delegations/\(DelegationID())"), "end a household grant")
            try await isNil(try await DeviceRecord.find(a.device!.id.uuid, on: h.db)?.revokedAt)
        }
    }

    func testAnUntrustedDeviceCannotWidenOrEndAccess() async throws {
        try await withHarness { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let a = try await h.readyConsumer()
            let b = try await h.enrollDevice(a)   // the attacker's new device: cooling down
            func refused(_ result: HTTPResult, _ what: String) {
                XCTAssertEqual(result.status, .forbidden, "\(what): \(result.text)")
                XCTAssertEqual(result.errorCode, .deviceCoolDown, what)
            }
            let request = h.invitation(purposes: [.support], businesses: [airline])
            refused(try await h.invite(b, request), "household invite")
            refused(try await h.signedPost(b, "/v1/household/invitations/accept", DelegationInvitationRedeemRequest(code: "ABCD-2345")), "household accept")
            refused(try await h.signed(b, .DELETE, "/v1/devices/\(a.device!.id)"), "revoke another device")
            let sessions = try await h.signed(b, .GET, "/v1/sessions").json([SessionInfo].self)
            let other = try XCTUnwrap(sessions.first { !$0.current })
            refused(try await h.signed(b, .DELETE, "/v1/sessions/\(other.id)"), "revoke another session")
            refused(try await h.signedPost(b, "/v1/phone-links/start", PhoneLinkStartRequest(phone: PhoneNumber("+14805550123")!)), "phone link start")
            refused(try await h.signed(b, .DELETE, "/v1/account"), "account deletion")
            let status = try await ConsumerRecord.find(a.id.uuid, on: h.db)?.status
            XCTAssertEqual(status, "active")
            // Signing out of its own device is always allowed.
            try await eq(try await h.signed(b, .DELETE, "/v1/devices/\(b.device!.id)").status, .ok)
        }
    }

    func testConfirmationNeedsBiometricAndTheDeviceThenBecomesTrusted() async throws {
        try await withHarness { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let a = try await h.readyConsumer()
            _ = try await h.connect(a, to: airline)
            let b = try await h.enrollDevice(a)
            let target = b.device!.id
            let weak = try await ConfirmationProof.sign(subject: .device, subjectId: target.description, deviceId: a.device!.id, assurance: .devicePasscode,
                                                        key: a.device!.passcodeKey, now: h.clock.now())
            let low = try await h.signedPost(a, "/v1/devices/\(target)/confirm", ConfirmationRequest(proof: weak))
            XCTAssertEqual(low.status, .forbidden, low.text)
            XCTAssertEqual(low.errorCode, .insufficientAssurance)
            try await notNil(try await DeviceRecord.find(target.uuid, on: h.db)?.approvalsLockedUntil)
            let strong = try await ConfirmationProof.sign(subject: .device, subjectId: target.description, deviceId: a.device!.id, assurance: .biometric,
                                                          key: a.device!.biometricKey, now: h.clock.now())
            try await eq(try await h.signedPost(a, "/v1/devices/\(target)/confirm", ConfirmationRequest(proof: strong)).status, .ok)
            // Now trusted: it may invite.
            let request = h.invitation(purposes: [.support], businesses: [airline])
            try await eq(try await h.invite(b, request).status, .created)
        }
    }

    func testEveryEnrollmentIsAnnouncedAnAppClipToo() async throws {
        try await withHarness { h in
            let a = try await h.readyConsumer()
            try await registerPush(h, a)
            let before = h.push.sent.count
            let clip = try await h.enrollDevice(a, name: "Clip", purposes: [.request], clientKind: .appClip)
            XCTAssertNotNil(clip.device)
            XCTAssertGreaterThan(h.push.sent.count, before, "the account's app device is pushed")
            let notices = try await h.signed(a, .GET, "/v1/security-notices").json([SecurityNotice].self)
            XCTAssertTrue(notices.contains { $0.kind == .appClip })
            // The device that caused it is not told about itself; dismissing needs a trusted device.
            let own = try await h.signed(clip, .GET, "/v1/security-notices").json([SecurityNotice].self)
            XCTAssertTrue(own.isEmpty)
            let dismissByClip = try await h.signed(clip, .POST, "/v1/security-notices/\(notices[0].id)/dismiss")
            XCTAssertEqual(dismissByClip.status, .forbidden)
            try await eq(try await h.signed(a, .POST, "/v1/security-notices/\(notices[0].id)/dismiss").status, .ok)
            let left = try await h.signed(a, .GET, "/v1/security-notices").json([SecurityNotice].self)
            XCTAssertFalse(left.contains { $0.id == notices[0].id })
        }
    }

    func registerPush(_ h: TestHarness, _ c: TestConsumer) async throws {
        let r = try await h.signedPost(c, "/v1/push/apns-token", APNsTokenRegistration(token: String(repeating: "ab", count: 32), environment: .sandbox, bundleId: "com.viadere.app"))
        XCTAssertEqual(r.status, .ok, r.text)
    }

    // MARK: #8 - test keys on rewards, outcomes and activity keys

    func testTestKeysCannotTouchLiveRewardsPointsProgramsCodesOrInteractions() async throws {
        try await withHarness { h in
            let live = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let test = TestBusiness(record: live.record, key: try await BusinessAPIKeys.issue(businessId: live.record.id!, name: "t", live: false,
                                                                                                 scopes: BusinessAPIKeys.Scope.all, capabilities: Capability.operational, now: h.clock.now(), on: h.db).key,
                                    summary: live.summary)
            let consumer = try await h.readyConsumer()
            let real = try await h.connect(consumer, to: live, optIn: [.rewards])
            try await h.saveProgram(live)
            try await eq(try await h.enroll(consumer, live).status.code < 300, true)
            let reward = try await h.reward(live, title: "Free coffee", relationship: real)
            let broadcast = try await h.reward(live, title: "Everyone", kind: .perk)
            try await h.adjustPoints(live, real, 100)
            let redeemed = try await h.redeem(consumer, reward.id)
            XCTAssertEqual(redeemed.status, .created, redeemed.text)
            let code = try redeemed.json(RewardRedemption.self).redemptionCode
            let interaction = try await h.issue(live, relationship: real, payload: .confirm(ConfirmPayload(title: "Real")), purpose: .transactional, sensitivity: .low)
            let interactionId = try interaction.json(Interaction.self).id

            try await eq(try await h.createReward(test, IssueRewardRequest(relationshipId: real.id, title: "X", kind: .perk, idempotencyKey: "t1")).status, .forbidden)
            try await eq(try await h.createReward(test, IssueRewardRequest(relationshipId: nil, title: "X", kind: .perk, idempotencyKey: "t2")).status, .forbidden)
            try await eq(try await h.adjustPoints(test, real, 5000).status, .forbidden)
            let program = UpsertLoyaltyProgramRequest(programName: "Hijacked", summary: "x", termsVersion: "v9", timeZone: "UTC", tiers: [])
            try await eq(try await h.business(test, .PUT, "/v1/business/loyalty/program", body: try ViadereJSON.encode(program)).status, .forbidden)
            try await eq(try await h.business(test, .POST, "/v1/business/rewards/\(reward.id)/revoke").status, .notFound)
            try await eq(try await h.business(test, .POST, "/v1/business/rewards/\(broadcast.id)/revoke").status, .notFound)
            try await eq(try await h.consume(test, code: code).status, .notFound)
            try await eq(try await h.business(test, .GET, "/v1/business/interactions/\(interactionId)").status, .notFound)
            try await eq(try await h.business(test, .POST, "/v1/business/interactions/\(interactionId)/cancel").status, .notFound)
            // Nothing changed for the real person, and the live key still works.
            try await eq(try await RewardRecord.query(on: h.db).filter(\.$status == "revoked").count(), 0)
            try await eq(try await LoyaltyProgramRecord.query(on: h.db).first()?.programName, "Northwind Air Club")
            try await eq(try await h.consume(live, code: code).status, .ok)
            try await eq(try await h.business(live, .GET, "/v1/business/interactions/\(interactionId)").status, .ok)
        }
    }

    func testAnActivityKeyOnlySupersedesTheSameRelationshipAndMode() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let test = TestBusiness(record: b.record, key: try await BusinessAPIKeys.issue(businessId: b.record.id!, name: "t", live: false,
                                                                                              scopes: BusinessAPIKeys.Scope.all, capabilities: Capability.operational, now: h.clock.now(), on: h.db).key,
                                    summary: b.summary)
            let alice = try await h.readyConsumer(name: "Alice")
            let bob = try await h.readyConsumer(name: "Bob")
            let relA = try await h.connect(alice, to: b)
            let relB = try await h.connect(bob, to: b)
            let sandbox = try await h.sandboxRelationship(test)
            func status(_ business: TestBusiness, _ rel: Relationship, _ key: String) async throws -> Interaction {
                let r = try await h.businessPost(business, "/v1/business/statuses", BusinessStatusUpdateRequest(
                    relationshipId: rel.id, purpose: .transactional, status: StatusPayload(title: "Order", body: "update"), activityKey: "order-1", idempotencyKey: key),
                                                 idempotencyKey: key)
                XCTAssertTrue([.created, .ok].contains(r.status), r.text)
                return try r.json(Interaction.self)
            }
            let first = try await status(b, relA, "k1")
            _ = try await status(b, relB, "k2")        // same activity key, another person
            _ = try await status(test, sandbox, "k3")  // same activity key, test mode
            let pending = try await InteractionRecord.find(first.id.uuid, on: h.db)?.status
            XCTAssertEqual(pending, InteractionStatus.pending.rawValue, "another relationship's or mode's status did not supersede it")
            _ = try await status(b, relA, "k4")        // the same relationship does
            let superseded = try await InteractionRecord.find(first.id.uuid, on: h.db)?.status
            XCTAssertEqual(superseded, InteractionStatus.delivered.rawValue)
        }
    }

    // MARK: #10 - legacy sessions

    func testALegacySessionIsRecordedAndBoundToTheDeviceOfItsFirstRequest() async throws {
        try await withHarness { h in
            let a = try await h.readyConsumer()
            let b = try await h.enrollDevice(a)
            let familyRow = try await AccessTokenRecord.query(on: h.db).filter(\.$tokenHash == SecureToken.hash(a.token)).first()
            let familyId = try XCTUnwrap(familyRow?.familyId)
            // A session from before families existed: no TokenFamilyRecord.
            try await TokenFamilyRecord.query(on: h.db).filter(\.$id == familyId).delete()
            try await eq(try await h.signed(a, .GET, "/v1/devices").status, .ok)
            let family = try await XCTUnwrapAsync(try await TokenFamilyRecord.find(familyId, on: h.db))
            XCTAssertEqual(family.deviceId, a.device!.id.uuid)
            XCTAssertEqual(family.origin, "legacy")
            // The legacy bearer is now useless with the other device's key.
            var mixed = b
            mixed.session = a.session
            let stolen = try await h.signed(mixed, .GET, "/v1/devices")
            XCTAssertEqual(stolen.status, .forbidden, stolen.text)
            // Rotation also creates the record (unbound until a device signs).
            let c = try await h.readyConsumer(name: "C")
            let cRow = try await AccessTokenRecord.query(on: h.db).filter(\.$tokenHash == SecureToken.hash(c.token)).first()
            let cFamily = try XCTUnwrap(cRow?.familyId)
            try await TokenFamilyRecord.query(on: h.db).filter(\.$id == cFamily).delete()
            try await eq(try await refresh(h, c.session.refreshToken!).status, .ok)
            try await notNil(try await TokenFamilyRecord.find(cFamily, on: h.db))
        }
    }

    // MARK: #11 - "Set up again"

    func testSetUpAgainOfARevokedDeviceReplacesItAtOnceAndKeepsTheSession() async throws {
        try await withHarness { h in
            let a = try await h.readyConsumer()
            let oldId = a.device!.id
            // The old device was revoked (the normal biometric-change case); the owner signs in again with the passkey and sets up again.
            try await eq(try await h.signed(a, .DELETE, "/v1/devices/\(oldId)").status, .ok)
            let fresh = try await h.login(a)
            let famRow = try await AccessTokenRecord.query(on: h.db).filter(\.$tokenHash == SecureToken.hash(fresh.token)).first()
            let family = try XCTUnwrap(famRow?.familyId)
            let done = try await h.enrollRaw(fresh, replaces: oldId)
            XCTAssertEqual(done.0.status, .created, done.0.text)
            let newDevice = try done.0.json(Device.self)
            XCTAssertNotNil(newDevice.approvalsLockedUntil, "the 24 h cool-down still applies to the new device")
            XCTAssertNil(newDevice.replacementSession, "no second session: the caller's own session moves to the new device")
            XCTAssertNil(newDevice.pendingReplacementBy)
            let fam = try await XCTUnwrapAsync(try await TokenFamilyRecord.find(family, on: h.db))
            XCTAssertNil(fam.revokedAt, "the caller's own session is not cascade-revoked")
            XCTAssertEqual(fam.deviceId, newDevice.id.uuid, "the session moved to the new device")
            var renewed = fresh
            renewed.device = TestDevice(id: newDevice.id, requestKey: done.1[.request]!, passcodeKey: done.1[.approvalUserPresence]!, biometricKey: done.1[.approvalBiometric]!)
            try await eq(try await h.signed(renewed, .GET, "/v1/devices").status, .ok)
            let audited = try await AuditEventRecord.query(on: h.db).filter(\.$action == "device.replaced").count()
            XCTAssertEqual(audited, 1)
        }
    }

    func testSetUpAgainRefusesDevicesThatAreNotTheCallersOwnAndNeedsThePasskey() async throws {
        try await withHarness { h in
            let a = try await h.readyConsumer()
            let oldId = a.device!.id
            // Replacing a device that is not this session's own is refused (and revokes nothing).
            let stranger = try await h.enrollDevice(try await h.registerConsumer(name: "Stranger"))
            let foreign = try await h.enrollRaw(a, replaces: stranger.device!.id)
            XCTAssertEqual(foreign.0.status, .forbidden, foreign.0.text)
            // Without the passkey assertion (fresh-session shortcut) it is refused too.
            let fresh = try await h.login(a)
            let shortcut = try await h.enrollRaw(fresh, replaces: oldId, assertion: false)
            XCTAssertTrue([.unauthorized, .forbidden].contains(shortcut.0.status), shortcut.0.text)
            try await isNil(try await DeviceRecord.find(oldId.uuid, on: h.db)?.revokedAt)
        }
    }

    // MARK: #12 - old queued webhook bodies

    func testQueuedDecidedBodiesLoseTheRawSignedDecisionAtRestAndOnRead() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let hook = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/x")!, events: [.interactionDecided]))
            XCTAssertEqual(hook.status, .created)
            let sub = try await XCTUnwrapAsync(try await WebhookSubscriptionRecord.query(on: h.db).first())
            func body(_ id: UUID) -> String {
                #"{"id":"\#(id.uuidString.lowercased())","type":"interaction.decided","createdAt":"2027-01-15T08:00:00.000Z","businessId":"\#(b.id)","apiVersion":"2026-01-01","data":{"decision":"approve","signedDecision":{"payload":"AAAA","signature":"BBBB"}}}"#
            }
            func delivery(sealed: Bool, status: String) async throws -> WebhookDeliveryRecord {
                let d = WebhookDeliveryRecord()
                d.id = UUID()
                d.subscriptionId = sub.id!
                d.businessId = b.id.uuid
                d.eventType = "interaction.decided"
                d.body = sealed ? try h.ctx.cipher.seal(body(d.id!), context: "webhook_deliveries.body", rowId: d.id!) : body(d.id!)
                d.status = status
                d.attempts = 0
                d.nextAttemptAt = h.clock.now()
                d.createdAt = h.clock.now()
                try await d.create(on: h.db)
                return d
            }
            // Read before sending: a queued delivery written before the fix is never sent with the signed decision.
            let queued = try await delivery(sealed: true, status: "pending")
            try await h.runJobs()
            let sent = h.webhooks.received.last.map { String(decoding: $0.body, as: UTF8.self) } ?? ""
            XCTAssertFalse(sent.isEmpty)
            XCTAssertFalse(sent.contains("signedDecision"), sent)
            XCTAssertTrue(sent.contains("\"decision\":\"approve\""), "the rest of the event is intact")
            _ = queued
            // At rest: reencrypt-fields strips it from plaintext and sealed bodies alike.
            let plain = try await delivery(sealed: false, status: "succeeded")
            let sealed = try await delivery(sealed: true, status: "dead")
            _ = try await FieldReencryptor(db: h.db, ctx: h.ctx).run()
            for id in [plain.id!, sealed.id!] {
                let row = try await XCTUnwrapAsync(try await WebhookDeliveryRecord.find(id, on: h.db))
                XCTAssertTrue(row.body.hasPrefix("v2."))
                let text = String(decoding: try h.ctx.cipher.open(row.body, context: "webhook_deliveries.body", rowId: id), as: UTF8.self)
                XCTAssertFalse(text.contains("signedDecision"), text)
                XCTAssertTrue(text.contains("approve"))
            }
        }
    }
}

extension TestHarness {
    func highAuthorizeR3(_ b: TestBusiness, _ rel: Relationship, key: String = UUID().uuidString) async throws -> Interaction {
        let r = try await issue(b, relationship: rel, payload: .authorize(.sample()), sensitivity: .high, key: key)
        XCTAssertEqual(r.status, .created, r.text)
        return try r.json(Interaction.self)
    }
}

extension TestHarness {
    /// `POST /v1/devices` with the caller's own bearer (as the app does for "Set up again"), optionally replacing a device.
    func enrollRaw(_ consumer: TestConsumer, replaces: DeviceID? = nil, assertion: Bool = true) async throws -> (HTTPResult, [DeviceKeyPurpose: SoftwareP256SigningKey]) {
        let auth = ["Authorization": "Bearer \(consumer.token)"]
        let begin = try await request(.POST, APIRoutes.deviceEnrollBegin.template, headers: auth)
        XCTAssertEqual(begin.status, .ok, begin.text)
        let challenge = try begin.json(DeviceEnrollmentChallenge.self)
        var keys: [DeviceKeyPurpose: SoftwareP256SigningKey] = [:]
        var registrations: [DeviceKeyRegistration] = []
        for purpose in DeviceKeyPurpose.allCases {
            let key = SoftwareP256SigningKey()
            keys[purpose] = key
            registrations.append(try await DeviceEnrollment.register(key: key, purpose: purpose, hardwareBacked: true, consumerId: consumer.id, challenge: challenge.challenge))
        }
        let response = try await post(APIRoutes.deviceEnroll.template, DeviceEnrollRequest(
            name: "Phone", platform: .iOS, challenge: challenge.challenge, keys: registrations,
            assertion: assertion ? enrollmentAssertion(consumer, challenge: challenge.challenge) : nil, replacesDeviceId: replaces), headers: auth)
        return (response, keys)
    }

    /// A second device enrolled through the caller's own session (what a thief holding session and passkey would do).
    func enrollInSession(_ consumer: TestConsumer) async throws -> TestConsumer {
        var consumer = consumer
        let (response, keys) = try await enrollRaw(consumer)
        XCTAssertEqual(response.status, .created, response.text)
        let device = try response.json(Device.self)
        consumer.device = TestDevice(id: device.id, requestKey: keys[.request]!, passcodeKey: keys[.approvalUserPresence]!, biometricKey: keys[.approvalBiometric]!)
        return consumer
    }
}
