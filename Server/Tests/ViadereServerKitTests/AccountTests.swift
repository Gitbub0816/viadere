import APNSCore
import Fluent
import Foundation
import ViadereCore
import struct ViadereCore.Page
import XCTest
@testable import ViadereServerKit

final class AccountTests: XCTestCase {
    func testDenyAndReportNeedOnlyADeviceSignatureButApproveStillNeedsBiometric() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.enrollDevice(try await h.registerConsumer())
            let rel = try await h.connect(consumer, to: b)
            for sensitivity in [Sensitivity.standard, .high, .critical] {
                let issued = try await h.issue(b, relationship: rel, payload: .authorize(.sample()), sensitivity: sensitivity).json(Interaction.self)
                let real = try await h.consumerInteraction(consumer, id: issued.id)
                // Approve with the plain request key (assurance .none) is refused, and so is a passcode approve at high+.
                let weakApprove = try await h.decision(consumer, interaction: real, decision: .approve, assurance: .none)
                try await eq(try await h.decide(consumer, id: real.id, signed: weakApprove).errorCode, .insufficientAssurance)
                if sensitivity != .standard {
                    let passcode = try await h.decision(consumer, interaction: real, decision: .approve, assurance: .devicePasscode)
                    try await eq(try await h.decide(consumer, id: real.id, signed: passcode).errorCode, .insufficientAssurance)
                }
                // A lock-screen Deny (request key only) succeeds.
                let deny = try await h.decision(consumer, interaction: real, decision: .deny, assurance: .none)
                let result = try await h.decide(consumer, id: real.id, signed: deny)
                XCTAssertEqual(result.status, .ok, result.text)
                try await eq(try result.json(InteractionOutcome.self).status, .denied)
            }
            let issued = try await h.issue(b, relationship: rel, payload: .authorize(.sample()), sensitivity: .high).json(Interaction.self)
            let real = try await h.consumerInteraction(consumer, id: issued.id)
            let report = try await h.decision(consumer, interaction: real, decision: .report, assurance: .none)
            try await eq(try await h.decide(consumer, id: real.id, signed: report).json(InteractionOutcome.self).status, .reported)
            // Over SMS even a deny is refused.
            let again = try await h.issue(b, relationship: rel, payload: .authorize(.sample()), channels: [.nativePush, .sms]).json(Interaction.self)
            let realAgain = try await h.consumerInteraction(consumer, id: again.id)
            let smsDeny = try await h.decision(consumer, interaction: realAgain, decision: .deny, assurance: .none)
            try await eq(try await h.decide(consumer, id: realAgain.id, signed: smsDeny, channel: .sms).status, .forbidden)
        }
    }

    func testPushPayloadContract() throws {
        let message = PushMessage(deviceToken: String(repeating: "ab", count: 32), environment: .sandbox, topic: "com.viadere.app", title: "Viadere",
                                  body: "Action needed. Open to review a security request.", category: "viadere.authorize.secure", threadID: "business.x",
                                  interruptionLevel: "time-sensitive", interactionId: "11111111-2222-3333-4444-555555555555", highPriority: true)
        let data = try JSONEncoder().encode(APNSwiftSender.notification(for: message))
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let aps = try XCTUnwrap(json["aps"] as? [String: Any])
        XCTAssertEqual(aps["mutable-content"] as? Int, 1)
        XCTAssertEqual(aps["category"] as? String, "viadere.authorize.secure")
        XCTAssertEqual(aps["thread-id"] as? String, "business.x")
        XCTAssertEqual(aps["interruption-level"] as? String, "time-sensitive")
        XCTAssertNotNil(aps["alert"])
        XCTAssertEqual(json["iid"] as? String, "11111111-2222-3333-4444-555555555555")
        XCTAssertEqual(Set(json.keys), ["aps", "iid"])
    }

    func testPhoneLinksAndSessionsManagement() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let other = try await h.readyConsumer(name: "Other")
            let phone = PhoneNumber("+14805550123")!
            let link = try PhoneLinkRecord(consumerId: consumer.id.uuid, phone: phone, hasher: h.ctx.hasher, cipher: h.ctx.cipher, now: h.clock.now())
            link.state = "verified"
            link.verifiedPhoneHash = h.ctx.hasher.phoneHash(phone)
            link.verifiedAt = h.clock.now()
            try await link.create(on: h.db)
            let list = try await h.signed(consumer, .GET, "/v1/phone-links").json([PhoneLink].self)
            XCTAssertEqual(list.map(\.id.uuid), [link.id!])
            XCTAssertTrue(list[0].maskedPhone.hasSuffix("0123"))
            try await eq(try await h.signed(other, .GET, "/v1/phone-links").json([PhoneLink].self).count, 0)
            try await eq(try await h.signed(other, .DELETE, "/v1/phone-links/\(link.id!)").status, .notFound)
            try await eq(try await h.signed(consumer, .DELETE, "/v1/phone-links/\(link.id!)").status, .ok)
            try await eq(try await h.signed(consumer, .GET, "/v1/phone-links").json([PhoneLink].self).count, 0)

            // Sessions: a second sign-in appears; revoking it leaves the current one working.
            let sessions = try await h.signed(consumer, .GET, "/v1/sessions").json([SessionInfo].self)
            XCTAssertEqual(sessions.count, 1)
            XCTAssertTrue(sessions[0].current)
            let rotated = try await h.post("/v1/auth/refresh", AuthRefreshRequest(refreshToken: "vdr_x"))
            XCTAssertEqual(rotated.status, .unauthorized)
            // Create another family by registering the same passkey login.
            let credential = try await PasskeyCredentialRecord.query(on: h.db).filter(\.$consumerId == consumer.id.uuid).first()!
            let begin = try await h.post("/v1/auth/login/begin", PasskeyLoginBeginRequest()).json(PasskeyAssertionOptions.self)
            let second = try await h.post("/v1/auth/login/finish", PasskeyLoginFinishRequest(ceremonyId: begin.ceremonyId, credential: PasskeyAssertionCredential(
                id: credential.credentialId, rawId: credential.credentialId, authenticatorData: "AA", clientDataJSON: begin.challenge, signature: "valid", userHandle: nil))).json(AuthSession.self)
            let both = try await h.signed(consumer, .GET, "/v1/sessions").json([SessionInfo].self)
            XCTAssertEqual(both.count, 2)
            let secondFamily = try XCTUnwrap(both.first { !$0.current })
            try await eq(try await h.signed(other, .DELETE, "/v1/sessions/\(secondFamily.id)").status, .notFound)
            try await eq(try await h.signed(consumer, .DELETE, "/v1/sessions/\(secondFamily.id)").status, .ok)
            try await eq(try await h.post("/v1/auth/refresh", AuthRefreshRequest(refreshToken: second.refreshToken!)).status, .unauthorized)
            try await eq(try await h.signed(consumer, .GET, "/v1/sessions").json([SessionInfo].self).count, 1)
        }
    }

    func testAccountDeletionRevokesEverythingErasesPersonalDataAndKeepsAnAuditRecord() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            _ = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/x")!, events: [.relationshipDisconnected]))
            let consumer = try await h.readyConsumer(name: "Ana Example")
            let second = try await h.enrollDevice(consumer, name: "iPad")
            let rel = try await h.connect(consumer, to: b)
            _ = try await h.signedPost(consumer, "/v1/push/apns-token", APNsTokenRegistration(token: String(repeating: "ab", count: 32), environment: .sandbox, bundleId: "com.viadere.app"))
            let pending = try await h.issue(b, relationship: rel, payload: .authorize(.sample())).json(Interaction.self)
            _ = try await h.businessPost(b, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: rel.id, body: "private note 4417", idempotencyKey: "m"))
            let phone = PhoneNumber("+14805550123")!
            let link = try PhoneLinkRecord(consumerId: consumer.id.uuid, phone: phone, hasher: h.ctx.hasher, cipher: h.ctx.cipher, now: h.clock.now())
            link.state = "verified"
            link.verifiedPhoneHash = h.ctx.hasher.phoneHash(phone)
            try await link.create(on: h.db)

            let deleted = try await h.signed(consumer, .DELETE, "/v1/account")
            XCTAssertEqual(deleted.status, .ok, deleted.text)

            // Every device and token is dead.
            try await eq(try await h.signed(consumer, .GET, "/v1/devices").status, .unauthorized)
            try await eq(try await h.signed(second, .GET, "/v1/devices").status, .unauthorized)
            try await eq(try await h.post("/v1/auth/refresh", AuthRefreshRequest(refreshToken: consumer.session.refreshToken!)).status, .unauthorized)
            let devices = try await DeviceRecord.query(on: h.db).filter(\.$consumerId == consumer.id.uuid).all()
            XCTAssertTrue(devices.allSatisfy { $0.revokedAt != nil })
            // Personal data is erased.
            let row = try await ConsumerRecord.find(consumer.id.uuid, on: h.db)!
            XCTAssertEqual(row.displayName, "Deleted account")
            XCTAssertEqual(row.status, "deleted")
            let passkeys = try await PasskeyCredentialRecord.query(on: h.db).filter(\.$consumerId == consumer.id.uuid).count()
            let pushTokens = try await APNsTokenRecord.query(on: h.db).count()
            XCTAssertEqual(passkeys + pushTokens, 0)
            let phoneRow = try await PhoneLinkRecord.find(link.id!, on: h.db)!
            XCTAssertEqual(phoneRow.state, "revoked")
            XCTAssertNil(phoneRow.verifiedPhoneHash)
            XCTAssertEqual(try h.ctx.cipher.openString(phoneRow.phoneCiphertext, context: "phone_links.phone", rowId: phoneRow.id!), "[deleted]")
            for message in try await ConversationMessageRecord.query(on: h.db).all() {
                XCTAssertEqual(try h.ctx.cipher.openString(message.bodyCiphertext, context: "conversation_messages.body", rowId: message.id!), "[deleted]")
            }
            let interaction = try await InteractionRecord.find(pending.id.uuid, on: h.db)!
            XCTAssertEqual(interaction.status, InteractionStatus.cancelled.rawValue)
            XCTAssertFalse(interaction.interactionJSON.contains("Walmart"))
            // The business is told the relationship ended, and an audit record remains.
            try await h.runJobs()
            XCTAssertEqual(h.webhooks.received.compactMap { $0.headers[ViadereHeader.eventType] }, ["relationship.disconnected"])
            let audit = try await AuditEventRecord.query(on: h.db).filter(\.$action == "account.deleted").all()
            XCTAssertEqual(audit.count, 1)
            XCTAssertFalse(audit[0].metadataJSON.contains("Ana"))
            let chain = try await AuditService.verifyChain(on: h.db, key: h.ctx.config.auditChainKey)
            XCTAssertTrue(chain.valid)
            // The consumer cannot sign in again with the deleted passkey.
            try await eq(try await PasskeyCredentialRecord.query(on: h.db).count(), 0)
        }
    }
}
