import Fluent
import Foundation
import ViadereCore
import struct ViadereCore.Page
import XCTest
@testable import ViadereServerKit

final class LiveActivityTests: XCTestCase {
    private let startToken = String(repeating: "5a", count: 32)
    private let updateToken = String(repeating: "7c", count: 32)

    private struct Scene {
        var business: TestBusiness
        var consumer: TestConsumer
        var relationship: Relationship
    }

    private func scene(_ h: TestHarness, live: Bool = true, name: String = "Northwind Air", handle: String = "northwindair") async throws -> Scene {
        let business = try await h.makeBusiness(name: name, handle: handle, live: live)
        let consumer = try await h.readyConsumer()
        let relationship = try await h.connect(consumer, to: business)
        return Scene(business: business, consumer: consumer, relationship: relationship)
    }

    private func delivery(_ stage: DeliveryActivityState.Stage = .outForDelivery) -> LiveActivityStatus {
        .delivery(DeliveryActivityState(trackingReference: "1Z999", stage: stage, carrierName: "Parcel Co", estimatedDeliveryAt: Date(timeIntervalSince1970: 1_800_003_600), stopsAway: 3))
    }

    @discardableResult
    private func status(_ h: TestHarness, _ s: Scene, _ live: LiveActivityStatus?, purpose: InteractionPurpose = .transactional, key: String = "order-1",
                        id: String = UUID().uuidString) async throws -> HTTPResult {
        try await h.businessPost(s.business, "/v1/business/statuses", BusinessStatusUpdateRequest(
            relationshipId: s.relationship.id, purpose: purpose, status: StatusPayload(title: "Your order", body: "On its way", liveActivity: live),
            activityKey: key, idempotencyKey: id))
    }

    private func register(_ h: TestHarness, _ c: TestConsumer, kind: LiveActivityTokenRegistration.Kind, token: String, activity: String? = nil,
                          business: BusinessID? = nil, interaction: InteractionID? = nil) async throws -> HTTPResult {
        try await h.signedPost(c, "/v1/live-activities/tokens", LiveActivityTokenRegistration(kind: kind, activityId: activity, businessId: business, interactionId: interaction, pushToken: token))
    }

    func testPushToStartThenUpdatesThenEndFollowTheActivityChain() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            _ = try await h.signedPost(s.consumer, "/v1/push/apns-token", APNsTokenRegistration(token: String(repeating: "ab", count: 32), environment: .sandbox, bundleId: "com.viadere.app"))
            try await eq(try await register(h, s.consumer, kind: .pushToStart, token: startToken).status, .ok)
            // First ongoing status: no running activity, so the server starts one on the device.
            let first = try await status(h, s, delivery(.inTransit)).json(Interaction.self)
            var pushes = h.push.liveActivities
            XCTAssertEqual(pushes.count, 1)
            let start = try XCTUnwrap(pushes.first)
            XCTAssertEqual(start.event, .start)
            XCTAssertEqual(start.deviceToken, startToken)
            XCTAssertEqual(start.topic, "com.viadere.app.push-type.liveactivity")
            XCTAssertEqual(start.environment, .sandbox)
            XCTAssertEqual(start.content, delivery(.inTransit))
            XCTAssertEqual(start.attributes, LiveActivityPush.Attributes(businessName: "Northwind Air", businessId: s.business.id.description, interactionId: first.id.description))
            XCTAssertEqual(LiveActivityPush.attributesType, "ViadereActivityAttributes")
            XCTAssertEqual(start.alertBody, "There is an update.", "the start alert is neutral")
            XCTAssertEqual(start.timestamp, Int(h.clock.now().timeIntervalSince1970))
            // A quick second status must not start a second activity while the first one's update token is in flight.
            h.clock.advance(by: 5)
            try await status(h, s, delivery(.outForDelivery))
            XCTAssertEqual(h.push.liveActivities.count, 1)
            // The app registers the new activity's update token (bound to the interaction in the attributes).
            try await eq(try await register(h, s.consumer, kind: .update, token: updateToken, activity: "act-1", business: s.business.id, interaction: first.id).status, .ok)
            h.clock.advance(by: 5)
            try await status(h, s, delivery(.outForDelivery))
            pushes = h.push.liveActivities
            XCTAssertEqual(pushes.count, 2)
            XCTAssertEqual(pushes[1].event, .update)
            XCTAssertEqual(pushes[1].deviceToken, updateToken)
            XCTAssertEqual(pushes[1].content, delivery(.outForDelivery))
            XCTAssertNil(pushes[1].attributes)
            // Delivered is terminal: the activity ends.
            h.clock.advance(by: 5)
            try await status(h, s, delivery(.delivered))
            XCTAssertEqual(h.push.liveActivities.count, 3)
            XCTAssertEqual(h.push.liveActivities[2].event, .end)
            // A finished event never starts an activity by itself.
            try await status(h, s, delivery(.delivered), key: "order-2")
            XCTAssertEqual(h.push.liveActivities.count, 3)
            XCTAssertEqual(h.push.liveActivities.filter { $0.event == .start }.count, 1)
        }
    }

    func testOnlyEligibleStatusesEverReachAnActivity() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            try await eq(try await register(h, s.consumer, kind: .pushToStart, token: startToken).status, .ok)
            // Marketing consent granted, so the interaction itself is allowed: it still never becomes a Live Activity.
            let optIn = ConsentUpdateRequest(changes: [ConsentChange(purpose: .marketing, granted: true), ConsentChange(purpose: .rewards, granted: true)], policyVersion: "2026-10")
            let consent = try await h.request(.PUT, "/v1/relationships/\(s.relationship.id)/consents",
                                              headers: try await h.signedHeaders(s.consumer, .PUT, "/v1/relationships/\(s.relationship.id)/consents", body: try ViadereJSON.encode(optIn)),
                                              body: try ViadereJSON.encode(optIn))
            XCTAssertEqual(consent.status, .ok, consent.text)
            for (index, purpose) in [InteractionPurpose.marketing, .rewards, .security].enumerated() {
                let result = try await status(h, s, delivery(), purpose: purpose, key: "k\(index)")
                XCTAssertTrue([.created, .unprocessableEntity].contains(result.status), "\(purpose): \(result.text)")
            }
            XCTAssertEqual(h.push.liveActivities.count, 0, "marketing, rewards and security never drive a Live Activity")
            // A status with no live content is just a status.
            try await status(h, s, nil, key: "plain")
            XCTAssertEqual(h.push.liveActivities.count, 0)
            // Support and account-service updates are allowed.
            try await status(h, s, delivery(), purpose: .support, key: "support")
            XCTAssertEqual(h.push.liveActivities.count, 1)
            try await status(h, s, delivery(), purpose: .accountService, key: "account")
            XCTAssertEqual(h.push.liveActivities.count, 2)
            // The pure policy agrees.
            XCTAssertFalse(LiveActivityPolicy.isEligible(purpose: .marketing, status: delivery()))
            XCTAssertFalse(LiveActivityPolicy.isEligible(purpose: .security, status: delivery()))
        }
    }

    func testTestModeKeysRevokedDevicesAndOtherBusinessesNeverPush() async throws {
        try await withHarness { h in
            let test = try await scene(h, live: false, name: "Test Mode Air", handle: "testmodeair")
            try await eq(try await register(h, test.consumer, kind: .pushToStart, token: startToken).status, .ok)
            try await status(h, test, delivery())
            XCTAssertEqual(h.push.liveActivities.count, 0, "test keys never reach real devices")

            let s = try await scene(h)
            try await eq(try await register(h, s.consumer, kind: .pushToStart, token: startToken).status, .ok)
            // A token bound to business A's activity can't be driven by business B's statuses.
            let other = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
            let otherRelationship = try await h.connect(s.consumer, to: other)
            let first = try await status(h, s, delivery()).json(Interaction.self)
            try await eq(try await register(h, s.consumer, kind: .update, token: updateToken, activity: "a1", business: s.business.id, interaction: first.id).status, .ok)
            h.clock.advance(by: 5)
            let before = h.push.liveActivities.count
            let b = try await h.businessPost(other, "/v1/business/statuses", BusinessStatusUpdateRequest(
                relationshipId: otherRelationship.id, purpose: .transactional, status: StatusPayload(title: "Order", liveActivity: delivery(.outForDelivery)),
                activityKey: "order-1", idempotencyKey: "b-1"))
            XCTAssertEqual(b.status, .created, b.text)
            let afterB = h.push.liveActivities.dropFirst(before)
            XCTAssertFalse(afterB.contains { $0.deviceToken == updateToken }, "business B cannot drive business A's activity even with the same activity key")
            // Revoking the device ends pushes to it.
            let device = try XCTUnwrap(s.consumer.device)
            let revoked = try await h.signed(s.consumer, .DELETE, "/v1/devices/\(device.id)")
            XCTAssertEqual(revoked.status, .ok)
            let beforeRevokedPush = h.push.liveActivities.count
            h.clock.advance(by: 5)
            try await status(h, s, delivery(.delivered), key: "after-revoke")
            XCTAssertEqual(h.push.liveActivities.count, beforeRevokedPush, "a revoked device receives nothing")
        }
    }

    func testInvalidTokensAreDroppedAndRegistrationIsValidatedAndBounded() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            // Validation.
            try await eq(try await register(h, s.consumer, kind: .pushToStart, token: "zz").status, .unprocessableEntity)
            try await eq(try await register(h, s.consumer, kind: .pushToStart, token: String(repeating: "g", count: 40)).status, .unprocessableEntity)
            try await eq(try await register(h, s.consumer, kind: .update, token: updateToken, activity: "a", business: nil, interaction: nil).status, .unprocessableEntity)
            let stranger = try await h.makeBusiness(name: "Unconnected", handle: "unconnected")
            try await eq(try await register(h, s.consumer, kind: .update, token: updateToken, activity: "a", business: stranger.id, interaction: InteractionID()).status, .unprocessableEntity,
                         "only businesses the person is connected to")
            // Re-registering replaces rather than accumulates.
            for i in 0..<3 {
                try await eq(try await register(h, s.consumer, kind: .pushToStart, token: String(repeating: "0\(i)", count: 32)).status, .ok)
                try await eq(try await register(h, s.consumer, kind: .update, token: String(repeating: "1\(i)", count: 32), activity: "same", business: s.business.id, interaction: InteractionID()).status, .ok)
            }
            let tokens = try await LiveActivityTokenRecord.query(on: h.db).all()
            XCTAssertEqual(tokens.count, 2)
            XCTAssertEqual(tokens.first { $0.kind == "pushToStart" }?.pushToken, String(repeating: "02", count: 32))
            // Per-device cap.
            for i in 0..<(LiveActivityService.maxTokensPerDevice + 10) {
                _ = try await register(h, s.consumer, kind: .update, token: String(format: "%064x", i + 1), activity: "act-\(i)", business: s.business.id, interaction: InteractionID())
            }
            let updates = try await LiveActivityTokenRecord.query(on: h.db).filter(\.$kind == "update").count()
            XCTAssertLessThanOrEqual(updates, LiveActivityService.maxTokensPerDevice)
            // APNs says a token is dead: it is deleted.
            h.push.setOutcome(.tokenInvalid)
            let remaining = try await LiveActivityTokenRecord.query(on: h.db).filter(\.$kind == "pushToStart").count()
            XCTAssertEqual(remaining, 1)
            try await status(h, s, delivery(), key: "dead-token")
            let gone = try await LiveActivityTokenRecord.query(on: h.db).filter(\.$kind == "pushToStart").count()
            XCTAssertEqual(gone, 0)
        }
    }

    func testContentStateUsesActivityKitsDefaultJSONCoding() throws {
        // ActivityKit decodes `content-state` with a default JSONDecoder; the server's APNs encoder is the default JSONEncoder.
        for status in [delivery(), LiveActivityStatus.order(OrderActivityState(orderReference: "A1", stage: .ready, estimatedReadyAt: Date(timeIntervalSince1970: 1_800_000_000))),
                       LiveActivityStatus.appointment(AppointmentActivityState(title: "Check-up", startsAt: Date(timeIntervalSince1970: 1_800_000_000), stage: .checkInOpen))] {
            let data = try JSONEncoder().encode(status)
            XCTAssertEqual(try JSONDecoder().decode(LiveActivityStatus.self, from: data), status)
            let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
            XCTAssertEqual(json["type"] as? String, status.type)
        }
        // The real sender builds the exact payload the contract describes.
        let push = LiveActivityPush(deviceToken: startToken, environment: .production, bundleId: "com.viadere.app", event: .update, content: delivery(), timestamp: 1)
        XCTAssertEqual(push.topic, "com.viadere.app.push-type.liveactivity")
    }

    func testStatusCorrelationAndTicketDetailsReachTheActivityFeed() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let correlation = "trip-77"
            // A status, a ticket (now with venue, seat and start time) and a check-in confirm, grouped by one correlation id.
            let started = try await h.businessPost(s.business, "/v1/business/statuses", BusinessStatusUpdateRequest(
                relationshipId: s.relationship.id, purpose: .transactional, status: StatusPayload(title: "Flight SK12"), activityKey: "trip-77", idempotencyKey: "s1", correlationId: correlation))
            XCTAssertEqual(started.status, .created, started.text)
            XCTAssertEqual(try started.json(Interaction.self).correlationId, correlation)
            let ticket = TicketPayload(title: "SK12 PHX → SFO", ticketType: "boarding_pass", venue: "Gate B4", seat: "14C", startsAt: h.clock.now().addingTimeInterval(7200))
            let issued = try await h.businessPost(s.business, "/v1/business/interactions", IssueInteractionRequest(
                relationshipId: s.relationship.id, purpose: .transactional, payload: .ticket(ticket), ttlSeconds: 86_400, idempotencyKey: "t1", correlationId: correlation))
            XCTAssertEqual(issued.status, .created, issued.text)
            let checkIn = try await h.businessPost(s.business, "/v1/business/interactions", IssueInteractionRequest(
                relationshipId: s.relationship.id, purpose: .transactional, payload: .confirm(ConfirmPayload(title: "Check in")), ttlSeconds: 86_400, idempotencyKey: "c1", correlationId: correlation))
            XCTAssertEqual(checkIn.status, .created, checkIn.text)
            let page = try await h.signed(s.consumer, .GET, "/v1/interactions").json(Page<InteractionEnvelope>.self)
            XCTAssertEqual(page.items.count, 3)
            XCTAssertEqual(Set(page.items.compactMap(\.interaction.correlationId)), [correlation])
            XCTAssertEqual(Set(page.items.map(\.interaction.kind)), [.status, .ticket, .confirm])
            let ticketEnvelope = try XCTUnwrap(page.items.first { $0.interaction.kind == .ticket })
            guard case .ticket(let received) = ticketEnvelope.interaction.payload else { return XCTFail("ticket payload") }
            XCTAssertEqual(received.venue, "Gate B4")
            XCTAssertEqual(received.seat, "14C")
            XCTAssertEqual(received.startsAt, ViadereDate.truncatedToMilliseconds(ticket.startsAt!))
            // Correlation ids are validated like every identifier.
            let bad = try await h.businessPost(s.business, "/v1/business/statuses", BusinessStatusUpdateRequest(
                relationshipId: s.relationship.id, purpose: .transactional, status: StatusPayload(title: "x"), activityKey: "k", idempotencyKey: "s2", correlationId: "has space!"))
            XCTAssertEqual(bad.status, .unprocessableEntity)
            // The outcome carries it back to the business.
            let outcome = try await h.business(s.business, .GET, "/v1/business/interactions/\(try checkIn.json(Interaction.self).id)").json(InteractionOutcome.self)
            XCTAssertEqual(outcome.correlationId, correlation)
        }
    }
}
