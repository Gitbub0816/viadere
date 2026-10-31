import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Fixtures for the hosted Loops suites (WP-3.2..3.5, 3.9).
enum LoopFixtures {
    static func pickup(title: String = "Schedule your pickup", key: String = "pickup") -> Data {
        Data("""
        {"schema_version":1,"key":"\(key)","title":"\(title)","entry_points":["business_page","alert"],"appearance":{"mode":"standard"},
         "steps":[
          {"id":"s1","type":"form","title":"Pick a time","fields":[{"id":"slot","type":"single_choice","label":"Time","required":true,
            "options":[{"id":"am","label":"Morning"},{"id":"pm","label":"Afternoon"}]}],
           "actions":[{"id":"next","action":"select_pickup_time","label":"continue","next":"s2"}]},
          {"id":"s2","type":"summary","title":"Send it","actions":[{"id":"send","action":"acknowledge","label":"send_request","routing":{"mode":"hosted","queue":"pickups"},"next":"done"}]},
          {"id":"done","type":"result","show_outcome":true}],
         "limits":{"expires_in_seconds":86400}}
        """.utf8)
    }

    /// High risk (`review_estimate`): needs two different reviewers.
    static let estimate = Data("""
    {"schema_version":1,"key":"estimate","title":"Your repair estimate","entry_points":["message"],"appearance":{"mode":"standard"},
     "steps":[{"id":"s1","type":"summary","body":"Brake pads and rotors","actions":[{"id":"ack","action":"review_estimate","label":"send_acknowledgement",
       "routing":{"mode":"hosted"},"params":{"amount":{"value":"285.28","currency":"USD"},"terms":"Parts and labor, valid for 7 days"},"next":"done"}]},
      {"id":"done","type":"result","show_outcome":true}],"limits":{"expires_in_seconds":86400}}
    """.utf8)

    /// Fails the hard gate (health content, FX-4).
    static let health = Data("""
    {"schema_version":1,"key":"intake","title":"Describe your symptoms","entry_points":["message"],"appearance":{"mode":"standard"},
     "steps":[{"id":"s1","type":"summary","actions":[{"id":"ok","action":"acknowledge","label":"got_it","routing":{"mode":"hosted"},"next":"done"}]},
      {"id":"done","type":"result"}],"limits":{"expires_in_seconds":3600}}
    """.utf8)
}

/// A business, two Loop reviewers, a connected and consenting customer.
struct LoopWorld {
    let h: TestHarness
    let business: TestBusiness
    let author: UUID
    let reviewer1: UUID
    let reviewer2: UUID
    let alice: TestConsumer

    static func build(_ h: TestHarness, name: String = "Corner Bakery", handle: String = "cornerbakery") async throws -> LoopWorld {
        try await build(h, business: try await h.makeBusiness(name: name, handle: handle), tag: handle)
    }

    static func build(_ h: TestHarness, business: TestBusiness, tag: String) async throws -> LoopWorld {
        let r1 = try await operatorId(h, "r1-\(tag)@viadere.test")
        let r2 = try await operatorId(h, "r2-\(tag)@viadere.test")
        for id in [r1, r2] { try await OperatorPermissions(db: h.db, ctx: h.ctx).set(userId: id, permission: .loopReviewer, granted: true) }
        let alice = try await h.readyConsumer(name: "Alice")
        try await h.connect(alice, to: business)
        let world = LoopWorld(h: h, business: business, author: UUID(), reviewer1: r1, reviewer2: r2, alice: alice)
        try await world.consent(alice)
        return world
    }

    static func operatorId(_ h: TestHarness, _ email: String) async throws -> UUID {
        _ = try await DashboardAuthService(db: h.db, ctx: h.ctx).createOperator(email: email, displayName: "Reviewer")
        let auth = DashboardAuthService(db: h.db, ctx: h.ctx)
        return try await DashboardUserRecord.query(on: h.db).filter(\.$emailHash == auth.emailHash(email)).first()!.id!
    }

    var publications: LoopPublicationService { LoopPublicationService(db: h.db, ctx: h.ctx) }

    func submit(_ data: Data = LoopFixtures.pickup(), business: UUID? = nil, author: UUID? = nil) async throws -> LoopRevisionRecord {
        try await publications.submit(businessId: business ?? self.business.id.uuid, authorId: author ?? self.author, definition: data)
    }

    /// Submits, approves (two reviewers when required) and opens the rollout to everyone.
    @discardableResult
    func publish(_ data: Data = LoopFixtures.pickup()) async throws -> LoopPublicationRecord {
        let revision = try await submit(data)
        XCTAssertEqual(revision.stateValue, .inReview, revision.ruleHitsJSON)
        var updated = try await publications.review(revisionId: revision.id!, reviewerId: reviewer1, decision: .approve, reason: "Wording and data look right.")
        if updated.stateValue == .inReview {
            updated = try await publications.review(revisionId: revision.id!, reviewerId: reviewer2, decision: .approve, reason: "Second check done.")
        }
        XCTAssertEqual(updated.stateValue, .published)
        let publication = try await LoopPublicationRecord.query(on: h.db).filter(\.$revisionId == revision.id!).first()!
        try await publications.setRollout(publicationId: publication.id!, percent: 100, operatorId: reviewer1, reason: "Open to all customers.")
        return try await LoopPublicationRecord.find(publication.id!, on: h.db)!
    }

    func consent(_ consumer: TestConsumer, business: BusinessID? = nil) async throws {
        let text = LoopConsentCatalog.current
        var answers: [String: String] = [:]
        for check in text.checks { answers[check.id] = check.correctOptionId }
        let global = try await h.signed(consumer, .PUT, "/v1/loops/consent",
                                        body: try ViadereJSON.encode(LoopGlobalConsentRequest(textVersion: text.version, textDigest: text.digest, answers: answers, agree: true)))
        XCTAssertEqual(global.status, .ok, global.text)
        let own = try await h.signed(consumer, .PUT, "/v1/loops/consent/businesses/\(business ?? self.business.id)",
                                     body: try ViadereJSON.encode(LoopBusinessConsentRequest(textVersion: text.version, textDigest: text.digest, agree: true)))
        XCTAssertEqual(own.status, .ok, own.text)
    }

    func start(_ consumer: TestConsumer, _ publication: LoopPublicationRecord, entry: LoopEntryPoint = .businessPage) async throws -> HTTPResult {
        try await h.signed(consumer, .POST, "/v1/loops/instances",
                           body: try ViadereJSON.encode(LoopInstanceCreateRequest(publicationId: LoopPublicationID(publication.id!), entryPoint: entry)))
    }

    func instance(_ consumer: TestConsumer, _ publication: LoopPublicationRecord) async throws -> LoopInstanceView {
        let response = try await start(consumer, publication)
        XCTAssertEqual(response.status, .created, response.text)
        return try response.json(LoopInstanceView.self)
    }

    func act(_ consumer: TestConsumer, _ instance: LoopInstanceID, step: String, action: String, inputs: [String: JSONValue] = [:], key: String = UUID().uuidString) async throws -> HTTPResult {
        try await h.signed(consumer, .POST, "/v1/loops/instances/\(instance)/actions",
                           body: try ViadereJSON.encode(LoopActionRequest(stepId: step, actionId: action, inputs: inputs, idempotencyKey: key)))
    }

    /// Walks the pickup Loop to the delivering action.
    func submitPickup(_ consumer: TestConsumer, _ instance: LoopInstanceID) async throws -> LoopActionResult {
        let first = try await act(consumer, instance, step: "s1", action: "next", inputs: ["slot": .string("am")])
        XCTAssertEqual(first.status, .created, first.text)
        let second = try await act(consumer, instance, step: "s2", action: "send")
        XCTAssertEqual(second.status, .created, second.text)
        return try second.json(LoopActionResult.self)
    }

    func events() async throws -> Int { try await LoopActionEventRecord.query(on: h.db).count() }

    func refusals(_ reason: String) async throws -> Int {
        try await AuditEventRecord.query(on: h.db).filter(\.$action == "loop.access_refused").all().filter { $0.metadataJSON.contains("\"\(reason)\"") }.count
    }

    /// Publishes committed outbox rows and drains a queue.
    @discardableResult
    func drain(_ queue: QueueName) async throws -> [QueueConsumer.Outcome] {
        let transport = h.ctx.queue.transport!
        try await OutboxPublisher(db: h.db, ctx: h.ctx, transport: transport).publishDue()
        return try await QueueConsumer(db: h.db, ctx: h.ctx, transport: transport).drain(queue)
    }

    func raw(_ statement: String) async throws {
        try await (h.db as! any SQLDatabase).raw(SQLQueryString(statement)).run()
    }
}
