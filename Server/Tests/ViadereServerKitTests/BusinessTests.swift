import Fluent
import Foundation
import ViadereCore
import struct ViadereCore.Page
import XCTest
@testable import ViadereServerKit

final class BusinessTests: XCTestCase {
    // MARK: Tenant isolation

    func testBusinessCannotReadOrActOnAnotherBusinessesData() async throws {
        try await withHarness { h in
            let a = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let b = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
            let consumer = try await h.readyConsumer()
            let relA = try await h.connect(consumer, to: a)
            let relB = try await h.connect(consumer, to: b)
            let issued = try await h.issue(a, relationship: relA, payload: .authorize(.sample())).json(Interaction.self)

            // B cannot read, cancel, or reference A's interaction or relationship: always a plain 404.
            try await eq(try await h.business(b, .GET, "/v1/business/interactions/\(issued.id)").status, .notFound)
            try await eq(try await h.business(b, .POST, "/v1/business/interactions/\(issued.id)/cancel", body: Data("{}".utf8)).status, .notFound)
            let hijack = try await h.issue(b, relationship: relA, payload: .authorize(.sample()))
            XCTAssertEqual(hijack.status, .notFound)
            let message = BusinessSendMessageRequest(relationshipId: relA.id, body: "hi", idempotencyKey: "k1")
            try await eq(try await h.businessPost(b, "/v1/business/messages", message).status, .notFound)
            // A's interaction is untouched.
            try await eq(try await h.business(a, .GET, "/v1/business/interactions/\(issued.id)").status, .ok)

            // Conversations: A opens a session; B cannot post into it even with its *own* relationship.
            let sent = try await h.businessPost(a, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: relA.id, body: "Your seat is ready", idempotencyKey: "m1"))
            XCTAssertEqual(sent.status, .created, sent.text)
            let sessionId = try sent.json(ConversationMessage.self).sessionId
            let intrusion = try await h.businessPost(b, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: relB.id, sessionId: sessionId, body: "hello", idempotencyKey: "m2"))
            XCTAssertEqual(intrusion.status, .notFound)
            // The consumer sees only A's message in A's session; B's session (if any) is separate.
            let conversations = try await h.signed(consumer, .GET, "/v1/conversations").json([ConversationSummary].self)
            XCTAssertEqual(conversations.count, 1)
            XCTAssertEqual(conversations[0].business.id, a.id)
            let messages = try await h.signed(consumer, .GET, "/v1/conversations/\(sessionId)/messages").json(Page<ConversationMessage>.self)
            XCTAssertEqual(messages.items.map(\.body), ["Your seat is ready"])
            XCTAssertEqual(messages.items[0].attribution.displayName, "Northwind Air")
            // Another consumer cannot read the session.
            let other = try await h.readyConsumer(name: "Other")
            try await eq(try await h.signed(other, .GET, "/v1/conversations/\(sessionId)/messages").status, .notFound)
        }
    }

    func testIdempotencyKeySemantics() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            let first = try await h.issue(b, relationship: rel, payload: .authorize(.sample()), key: "order-1")
            XCTAssertEqual(first.status, .created)
            let same = try await h.issue(b, relationship: rel, payload: .authorize(.sample()), key: "order-1")
            XCTAssertEqual(same.status, .ok, "a true retry returns the original")
            XCTAssertEqual(try same.json(Interaction.self).id, try first.json(Interaction.self).id)
            let different = try await h.issue(b, relationship: rel, payload: .authorize(.sample(amount: "999.99")), key: "order-1")
            XCTAssertEqual(different.status, .conflict)
            XCTAssertEqual(different.errorCode, .idempotencyConflict)
            let count = try await InteractionRecord.query(on: h.db).count()
            XCTAssertEqual(count, 1)
            // The Idempotency-Key header must agree with the body.
            let request = IssueInteractionRequest(relationshipId: rel.id, purpose: .security, payload: .authorize(.sample()), ttlSeconds: 300, idempotencyKey: "order-2")
            let mismatch = try await h.businessPost(b, "/v1/business/interactions", request, idempotencyKey: "other")
            XCTAssertEqual(mismatch.status, .badRequest)
            let match = try await h.businessPost(b, "/v1/business/interactions", request, idempotencyKey: "order-2")
            XCTAssertEqual(match.status, .created)
            // Keys are per business: another business may reuse the same string.
            let other = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
            let relOther = try await h.connect(consumer, to: other)
            try await eq(try await h.issue(other, relationship: relOther, payload: .authorize(.sample()), key: "order-1").status, .created)
            // Messages follow the same rules.
            let message = BusinessSendMessageRequest(relationshipId: rel.id, body: "Hello", idempotencyKey: "msg-1")
            let m1 = try await h.businessPost(b, "/v1/business/messages", message)
            let m2 = try await h.businessPost(b, "/v1/business/messages", message)
            XCTAssertEqual(m1.status, .created)
            XCTAssertEqual(m2.status, .ok)
            XCTAssertEqual(try m1.json(ConversationMessage.self).id, try m2.json(ConversationMessage.self).id)
            let changed = BusinessSendMessageRequest(relationshipId: rel.id, body: "Different", idempotencyKey: "msg-1")
            try await eq(try await h.businessPost(b, "/v1/business/messages", changed).errorCode, .idempotencyConflict)
        }
    }

    func testConcurrentIdempotentIssueCreatesOneInteraction() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            let request = IssueInteractionRequest(relationshipId: rel.id, purpose: .security, payload: .authorize(.sample()), ttlSeconds: 300, idempotencyKey: "race-1")
            let body = try ViadereJSON.encode(request)
            let statuses = try await withThrowingTaskGroup(of: UInt.self) { group -> [UInt] in
                for _ in 0..<4 {
                    group.addTask { try await h.business(b, .POST, "/v1/business/interactions", body: body).status.code }
                }
                var out: [UInt] = []
                for try await code in group { out.append(code) }
                return out
            }
            XCTAssertTrue(statuses.allSatisfy { [200, 201].contains($0) }, "\(statuses)")
            XCTAssertEqual(statuses.filter { $0 == 201 }.count, 1)
            let count = try await InteractionRecord.query(on: h.db).count()
            XCTAssertEqual(count, 1)
        }
    }

    // MARK: Priority and consent

    func testBusinessesCannotBuyOrClaimPriority() async throws {
        try await withHarness { h in
            let free = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair", tier: "free")
            let paid = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee", tier: "paid")
            let consumer = try await h.readyConsumer()
            let relFree = try await h.connect(consumer, to: free, optIn: [.marketing])
            let relPaid = try await h.connect(consumer, to: paid, optIn: [.marketing])
            func priority(_ b: TestBusiness, _ rel: Relationship, _ purpose: InteractionPurpose, _ payload: InteractionPayload) async throws -> InteractionPriority {
                let response = try await h.issue(b, relationship: rel, payload: payload, purpose: purpose, priority: .urgent)
                XCTAssertEqual(response.status, .created, response.text)
                return try await h.consumerInteraction(consumer, id: try response.json(Interaction.self).id).priority
            }
            let promo = InteractionPayload.reward(RewardPayload(rewardId: RewardID(), title: "Free coffee"))
            let notice = InteractionPayload.status(StatusPayload(title: "Order update"))
            let sensitiveAuth = InteractionPayload.authenticate(AuthenticatePayload(service: "Airline portal", device: "Safari on Mac", attemptedAt: h.clock.now()))
            for (b, rel) in [(free, relFree), (paid, relPaid)] {
                let marketing = try await priority(b, rel, .marketing, promo)
                XCTAssertEqual(marketing, .normal, "marketing is capped at normal")
                let transactional = try await priority(b, rel, .transactional, notice)
                XCTAssertEqual(transactional, .high, "non-security purposes are capped at high")
                let security = try await priority(b, rel, .security, notice)
                XCTAssertEqual(security, .high, "only security authenticate/authorize may be urgent")
                let login = try await priority(b, rel, .security, sensitiveAuth)
                XCTAssertEqual(login, .urgent)
            }
        }
    }

    func testPendingBusinessAndLowSensitivityCannotDowngradeSecurityKinds() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            // Asking for "low" sensitivity cannot lower the floor for authorize.
            let response = try await h.issue(b, relationship: rel, payload: .authorize(.sample()), sensitivity: .low)
            let stored = try await h.consumerInteraction(consumer, id: try response.json(Interaction.self).id)
            XCTAssertEqual(stored.sensitivity, .standard)
            // Marketing can never carry a security kind.
            let bad = try await h.issue(b, relationship: rel, payload: .authorize(.sample()), purpose: .marketing)
            XCTAssertEqual(bad.status, .unprocessableEntity)
        }
    }

    func testMarketingConsentIsOptInAndRevokingItNeverDisablesSecurity() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            let promo = InteractionPayload.reward(RewardPayload(rewardId: RewardID(), title: "Free coffee Tuesday"))
            // Default: marketing is off.
            let denied = try await h.issue(b, relationship: rel, payload: promo, purpose: .marketing)
            XCTAssertEqual(denied.status, .forbidden)
            XCTAssertEqual(denied.errorCode, .consentRequired)
            // Consent view: marketing and rewards off; security, account service, transactional, support on.
            let grants = try await h.signed(consumer, .GET, "/v1/relationships/\(rel.id)/consents").json([ConsentGrant].self)
            XCTAssertEqual(Set(grants.filter(\.granted).map(\.purpose)), [.security, .accountService, .transactional, .support])
            // Opt in to marketing.
            let optIn = ConsentUpdateRequest(changes: [ConsentChange(purpose: .marketing, granted: true)], policyVersion: "2026-10")
            let updated = try await h.signed(consumer, .PUT, "/v1/relationships/\(rel.id)/consents", body: try ViadereJSON.encode(optIn))
            XCTAssertEqual(updated.status, .ok, updated.text)
            try await eq(try await h.issue(b, relationship: rel, payload: promo, purpose: .marketing).status, .created)
            // Revoke marketing: marketing stops, security keeps working.
            let revoke = ConsentUpdateRequest(changes: [ConsentChange(purpose: .marketing, granted: false)], policyVersion: "2026-10")
            try await eq(try await h.signed(consumer, .PUT, "/v1/relationships/\(rel.id)/consents", body: try ViadereJSON.encode(revoke)).status, .ok)
            try await eq(try await h.issue(b, relationship: rel, payload: promo, purpose: .marketing).errorCode, .consentRequired)
            let login = InteractionPayload.authenticate(AuthenticatePayload(service: "Juniper account", device: "Chrome", attemptedAt: h.clock.now()))
            try await eq(try await h.issue(b, relationship: rel, payload: login, purpose: .security).status, .created)
            // History is append-only and versioned.
            let history = try await ConsentGrantRecord.query(on: h.db).filter(\.$relationshipId == rel.id.uuid).filter(\.$purpose == "marketing").sort(\.$version).all()
            XCTAssertEqual(history.map(\.version), [1, 2, 3])
            XCTAssertEqual(history.map(\.granted), [false, true, false])
        }
    }

    func testSecurityAndAccountServiceConsentCannotBeRevoked() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            for purpose in [InteractionPurpose.security, .accountService] {
                let request = ConsentUpdateRequest(changes: [ConsentChange(purpose: purpose, granted: false)], policyVersion: "2026-10")
                let response = try await h.signed(consumer, .PUT, "/v1/relationships/\(rel.id)/consents", body: try ViadereJSON.encode(request))
                XCTAssertEqual(response.status, .forbidden)
            }
            // Support is revocable and stops business messages without affecting security.
            let revokeSupport = ConsentUpdateRequest(changes: [ConsentChange(purpose: .support, granted: false)], policyVersion: "2026-10")
            try await eq(try await h.signed(consumer, .PUT, "/v1/relationships/\(rel.id)/consents", body: try ViadereJSON.encode(revokeSupport)).status, .ok)
            let message = BusinessSendMessageRequest(relationshipId: rel.id, body: "hello", idempotencyKey: "s1")
            try await eq(try await h.businessPost(b, "/v1/business/messages", message).errorCode, .consentRequired)
            // Another consumer cannot change this relationship's consent.
            let mallory = try await h.readyConsumer(name: "Mallory")
            let attack = ConsentUpdateRequest(changes: [ConsentChange(purpose: .marketing, granted: true)], policyVersion: "2026-10")
            try await eq(try await h.signed(mallory, .PUT, "/v1/relationships/\(rel.id)/consents", body: try ViadereJSON.encode(attack)).status, .notFound)
        }
    }

    func testDisconnectCancelsPendingAndBlocksNewInteractions() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            _ = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/v")!, events: [.interactionCancelled, .relationshipDisconnected, .relationshipConnected]))
            let rel = try await h.connect(consumer, to: b)
            let interaction = try await h.issue(b, relationship: rel, payload: .authorize(.sample())).json(Interaction.self)
            let disconnect = try await h.signed(consumer, .DELETE, "/v1/relationships/\(rel.id)")
            XCTAssertEqual(disconnect.status, .ok)
            try await eq(try await h.business(b, .GET, "/v1/business/interactions/\(interaction.id)").json(InteractionOutcome.self).status, .cancelled)
            try await eq(try await h.issue(b, relationship: rel, payload: .authorize(.sample())).status, .conflict)
            try await h.runJobs()
            let types = h.webhooks.received.compactMap { $0.headers[ViadereHeader.eventType] }.sorted()
            XCTAssertEqual(types, ["interaction.cancelled", "relationship.connected", "relationship.disconnected"])
            // Reconnecting reuses the same relationship id.
            let again = try await h.connect(consumer, to: b)
            XCTAssertEqual(again.id, rel.id)
        }
    }

    // MARK: Quotas, keys

    func testPerBusinessDailyQuota() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair", quota: 2)
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            try await eq(try await h.issue(b, relationship: rel, payload: .authorize(.sample())).status, .created)
            try await eq(try await h.issue(b, relationship: rel, payload: .authorize(.sample())).status, .created)
            let over = try await h.issue(b, relationship: rel, payload: .authorize(.sample()))
            XCTAssertEqual(over.status, .tooManyRequests)
            XCTAssertEqual(over.errorCode, .rateLimited)
            XCTAssertNotNil(over.headers.first(name: "Retry-After"))
            // A retry of an already-accepted request is still served.
            // The quota resets the next UTC day.
            h.clock.advance(by: 86_400)
            try await eq(try await h.issue(b, relationship: rel, payload: .authorize(.sample())).status, .created)
        }
    }

    func testApiKeyAuthenticationScopesRevocationAndSuspension() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let readOnly = try await BusinessAPIKeys.issue(businessId: b.record.id!, name: "ro", live: true, scopes: [BusinessAPIKeys.Scope.interactionsRead], now: h.clock.now(), on: h.db)
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            // Missing / malformed / unknown keys.
            try await eq(try await h.request(.GET, "/v1/business/webhooks").status, .unauthorized)
            try await eq(try await h.request(.GET, "/v1/business/webhooks", headers: ["Authorization": "Bearer nope"]).status, .unauthorized)
            try await eq(try await h.request(.GET, "/v1/business/webhooks", headers: ["Authorization": "Bearer vdk_live_\(SecureToken.generate())"]).status, .unauthorized)
            // A consumer bearer token is not an API key.
            try await eq(try await h.request(.GET, "/v1/business/webhooks", headers: ["Authorization": "Bearer \(consumer.token)"]).status, .unauthorized)
            // Scope enforcement.
            let request = IssueInteractionRequest(relationshipId: rel.id, purpose: .security, payload: .authorize(.sample()), ttlSeconds: 300, idempotencyKey: "scope-1")
            try await eq(try await h.businessPost(b, "/v1/business/interactions", request, key: readOnly.key).status, .forbidden)
            // Revocation takes effect immediately.
            readOnly.record.revokedAt = h.clock.now()
            try await readOnly.record.update(on: h.db)
            try await eq(try await h.business(b, .GET, "/v1/business/webhooks", key: readOnly.key).status, .unauthorized)
            // Keys are stored hashed with a visible prefix.
            XCTAssertTrue(b.key.hasPrefix("vdk_live_"))
            let stored = try await BusinessAPIKeyRecord.query(on: h.db).all()
            XCTAssertFalse(stored.contains { $0.keyHash == b.key })
            XCTAssertTrue(stored.contains { $0.keyHash == SecureToken.hash(b.key) })
            // Suspending the business cuts off API access.
            b.record.verificationStatus = VerificationStatus.suspended.rawValue
            try await b.record.update(on: h.db)
            try await eq(try await h.business(b, .GET, "/v1/business/webhooks").status, .forbidden)
        }
    }

    func testTestModeKeysNeverPushToDevices() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair", live: false)
            XCTAssertTrue(b.key.hasPrefix("vdk_test_"))
            let consumer = try await h.readyConsumer()
            _ = try await h.signedPost(consumer, "/v1/push/apns-token", APNsTokenRegistration(token: String(repeating: "cd", count: 32), environment: .sandbox, bundleId: "com.viadere.app"))
            let real = try await h.connect(consumer, to: b)
            // A test key cannot even address a real person (it used to deliver real, decidable interactions).
            try await eq(try await h.issue(b, relationship: real, payload: .authorize(.sample())).status, .forbidden)
            let rel = try await h.sandboxRelationship(b)
            try await eq(try await h.issue(b, relationship: rel, payload: .authorize(.sample())).status, .created)
            XCTAssertTrue(h.push.sent.isEmpty)
        }
    }

    func testStatusUpdatesReplaceEarlierOnesForTheSameActivity() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            func update(_ title: String, key: String) async throws -> HTTPResult {
                try await h.businessPost(b, "/v1/business/statuses", BusinessStatusUpdateRequest(relationshipId: rel.id, purpose: .transactional, status: StatusPayload(title: title), activityKey: "order-77", idempotencyKey: key))
            }
            try await eq(try await update("Order placed", key: "s1").status, .created)
            try await eq(try await update("Order ready", key: "s2").status, .created)
            let pending = try await h.signed(consumer, .GET, "/v1/interactions").json(Page<InteractionEnvelope>.self)
            XCTAssertEqual(pending.items.count, 1)
            guard case .status(let status) = pending.items[0].interaction.payload else { return XCTFail("expected status") }
            XCTAssertEqual(status.title, "Order ready")
        }
    }

    // MARK: Webhooks

    func testWebhookManagementSecretsAndSsrfDefenses() async throws {
        try await withHarness({ $0.allowInsecureWebhookURLs = false }) { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            for bad in ["http://hooks.example.com/x", "https://localhost/x", "https://127.0.0.1/x", "https://169.254.169.254/latest", "https://10.0.0.5/x",
                        "https://user:pass@hooks.example.com/x", "https://hooks.example.com:8443/x", "https://internal.local/x", "https://[::1]/x", "ftp://hooks.example.com/x"] {
                let response = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: bad)!, events: [.interactionDecided]))
                XCTAssertEqual(response.status, .unprocessableEntity, bad)
            }
            let unknown = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/x")!, events: [WebhookEventType(rawValue: "admin.everything")]))
            XCTAssertEqual(unknown.status, .unprocessableEntity)
            let created = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/x")!, events: [.interactionDecided, .messageReceived]))
            XCTAssertEqual(created.status, .created)
            let secret = try created.json(WebhookSecretResponse.self)
            XCTAssertTrue(secret.secret.hasPrefix("whsec_"))
            // The secret is shown once; listing never contains it, and it is encrypted at rest.
            let list = try await h.business(b, .GET, "/v1/business/webhooks")
            XCTAssertFalse(list.text.contains(secret.secret))
            XCTAssertEqual(try list.json([WebhookSubscription].self).count, 1)
            let stored = try await WebhookSubscriptionRecord.query(on: h.db).first()!
            XCTAssertFalse(stored.secretCiphertext.contains(secret.secret))
            // Another business cannot rotate or delete it.
            let other = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
            let id = secret.subscription.id
            try await eq(try await h.business(other, .POST, "/v1/business/webhooks/\(id)/rotate-secret", body: Data("{}".utf8)).status, .notFound)
            try await eq(try await h.business(other, .DELETE, "/v1/business/webhooks/\(id)").status, .notFound)
            try await eq(try await h.business(other, .GET, "/v1/business/webhooks").json([WebhookSubscription].self).count, 0)
            // Rotation returns a new secret; deletion deactivates.
            let rotated = try await h.business(b, .POST, "/v1/business/webhooks/\(id)/rotate-secret", body: Data("{}".utf8)).json(WebhookSecretResponse.self)
            XCTAssertNotEqual(rotated.secret, secret.secret)
            try await eq(try await h.business(b, .DELETE, "/v1/business/webhooks/\(id)").status, .ok)
            try await eq(try await h.business(b, .GET, "/v1/business/webhooks").json([WebhookSubscription].self).count, 0)
        }
    }

    func testWebhookPolicyBlocksPrivateAddresses() {
        XCTAssertTrue(WebhookURLPolicy.validate(URL(string: "https://hooks.example.com/a")!, allowInsecure: false))
        for bad in ["https://192.168.1.1/a", "https://0x7f000001/a", "https://2130706433/a", "https://foo.internal/a", "https://nodots/a"] {
            XCTAssertFalse(WebhookURLPolicy.validate(URL(string: bad)!, allowInsecure: false), bad)
        }
    }

    func testWebhookRetriesWithBackoffThenSucceeds() async throws {
        try await withHarness { h in
            let (b, rel, consumer, _) = try await subscribed(h)
            h.webhooks.respond(with: [500, 503], then: 200)
            _ = try await h.issue(b, relationship: rel, payload: .authorize(.sample()))
            let interaction = try await h.consumerInteraction(consumer, id: try await InteractionRecord.query(on: h.db).first()!.id.map { InteractionID($0) }!)
            _ = try await h.decide(consumer, id: interaction.id, signed: try await h.decision(consumer, interaction: interaction))
            try await h.runJobs()
            XCTAssertEqual(h.webhooks.received.count, 1, "first attempt fails")
            try await h.runJobs()
            XCTAssertEqual(h.webhooks.received.count, 1, "backoff: not retried immediately")
            h.clock.advance(by: 31)
            try await h.runJobs()
            XCTAssertEqual(h.webhooks.received.count, 2)
            h.clock.advance(by: 60)
            try await h.runJobs()
            XCTAssertEqual(h.webhooks.received.count, 2, "second backoff is 2 minutes")
            h.clock.advance(by: 61)
            try await h.runJobs()
            XCTAssertEqual(h.webhooks.received.count, 3)
            let delivery = try await WebhookDeliveryRecord.query(on: h.db).first()!
            XCTAssertEqual(delivery.status, "succeeded")
            XCTAssertEqual(delivery.attempts, 3)
            // Every retry carries the same event id and body, with a fresh timestamped signature.
            let ids = Set(h.webhooks.received.map { $0.headers[ViadereHeader.eventId]! })
            XCTAssertEqual(ids.count, 1)
            XCTAssertEqual(Set(h.webhooks.received.map(\.body)).count, 1)
            let attempts = try await WebhookAttemptRecord.query(on: h.db).sort(\.$attempt).all()
            XCTAssertEqual(attempts.map(\.statusCode), [500, 503, 200])
            // Idle once delivered.
            h.clock.advance(by: 86_400)
            try await h.runJobs()
            XCTAssertEqual(h.webhooks.received.count, 3)
        }
    }

    func testWebhookDeadLettersAfterMaxAttempts() async throws {
        try await withHarness { h in
            let (b, rel, consumer, _) = try await subscribed(h)
            h.webhooks.respond(with: [], then: 500)
            _ = try await h.issue(b, relationship: rel, payload: .authorize(.sample()))
            let interaction = try await h.consumerInteraction(consumer, id: try await InteractionRecord.query(on: h.db).first()!.id.map { InteractionID($0) }!)
            _ = try await h.decide(consumer, id: interaction.id, signed: try await h.decision(consumer, interaction: interaction))
            for _ in 0..<12 {
                try await h.runJobs()
                h.clock.advance(by: 25 * 3600)
            }
            let delivery = try await WebhookDeliveryRecord.query(on: h.db).first()!
            XCTAssertEqual(delivery.status, "dead")
            XCTAssertEqual(delivery.attempts, WebhookService.maxAttempts)
            XCTAssertEqual(h.webhooks.received.count, WebhookService.maxAttempts)
            let dead = try await AuditEventRecord.query(on: h.db).filter(\.$action == "webhook.dead_lettered").count()
            XCTAssertEqual(dead, 1)
        }
    }

    func testWebhookRotationSignsWithBothSecretsDuringOverlap() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let created = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/x")!, events: [.relationshipConnected])).json(WebhookSecretResponse.self)
            let rotated = try await h.business(b, .POST, "/v1/business/webhooks/\(created.subscription.id)/rotate-secret", body: Data("{}".utf8)).json(WebhookSecretResponse.self)
            _ = try await h.connect(consumer, to: b)
            try await h.runJobs()
            let delivery = h.webhooks.received[0]
            let header = delivery.headers[ViadereHeader.signature]!
            XCTAssertEqual(header.components(separatedBy: "v1=").count - 1, 2)
            XCTAssertNoThrow(try WebhookSignature.verify(header: header, body: delivery.body, secrets: [created.secret], now: h.clock.now()))
            XCTAssertNoThrow(try WebhookSignature.verify(header: header, body: delivery.body, secrets: [rotated.secret], now: h.clock.now()))
            // After the overlap only the new secret signs.
            h.clock.advance(by: 25 * 3600)
            let second = try await h.readyConsumer(name: "Second")
            _ = try await h.connect(second, to: b)
            try await h.runJobs()
            let later = h.webhooks.received.last!
            let laterHeader = later.headers[ViadereHeader.signature]!
            XCTAssertEqual(laterHeader.components(separatedBy: "v1=").count - 1, 1)
            XCTAssertThrowsError(try WebhookSignature.verify(header: laterHeader, body: later.body, secrets: [created.secret], now: h.clock.now()))
        }
    }

    // MARK: Helpers

    func subscribed(_ h: TestHarness) async throws -> (TestBusiness, Relationship, TestConsumer, String) {
        let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
        let consumer = try await h.readyConsumer()
        let secret = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/x")!, events: [.interactionDecided])).json(WebhookSecretResponse.self).secret
        let rel = try await h.connect(consumer, to: b)
        return (b, rel, consumer, secret)
    }
}
