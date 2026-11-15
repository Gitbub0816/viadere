import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// The staging demo business: refused outside staging, idempotent, one live key at a time, and its sends take the normal path to a real
/// device (connection required, push with the opaque interaction id).
final class StagingDemoTests: XCTestCase {
    func testRefusedEverywhereButStaging() async throws {
        try await withHarness { h in
            for environment in [DeploymentEnvironment.development, .testing, .production] {
                XCTAssertThrowsError(try StagingDemo(db: h.db, ctx: h.ctx, environment: environment), "\(environment)") {
                    XCTAssertEqual($0 as? StagingDemo.Refusal, .notStaging)
                }
            }
            XCTAssertNoThrow(try StagingDemo(db: h.db, ctx: h.ctx, environment: .staging))
            let count = try await BusinessRecord.query(on: h.db).count()
            XCTAssertEqual(count, 0, "nothing is created by a refused run")
        }
    }

    func testDemoBusinessSendsRealMessagesAndApprovalsToAConnectedDevice() async throws {
        try await withHarness { h in
            let demo = try StagingDemo(db: h.db, ctx: h.ctx, environment: .staging)
            let business = try await demo.ensureBusiness()
            let again = try await demo.ensureBusiness()
            XCTAssertEqual(business.id, again.id, "idempotent")
            let all = try await BusinessRecord.query(on: h.db).count()
            XCTAssertEqual(all, 1)
            XCTAssertTrue(business.isVerified)

            let first = try await demo.issueLiveKey(businessId: business.id!)
            let key = try await demo.issueLiveKey(businessId: business.id!)
            XCTAssertTrue(key.hasPrefix("vdk_live_"))
            try await eq(try await h.request(.GET, "/v1/business/webhooks", headers: ["Authorization": "Bearer \(first)"]).status, .unauthorized,
                         "a new key revokes the previous one")
            try await eq(try await h.request(.GET, "/v1/business/webhooks", headers: ["Authorization": "Bearer \(key)"]).status, .ok)

            // A customer connects from the app and registers a push token.
            let consumer = try await h.readyConsumer()
            let token = String(repeating: "ab", count: 32)
            try await eq(try await h.signedPost(consumer, "/v1/push/apns-token",
                                                APNsTokenRegistration(token: token, environment: .sandbox, bundleId: "com.viadere.app")).status, .ok)
            let connected = try await h.signedPost(consumer, APIRoutes.relationshipConnect.template,
                                                   ConnectRequest(businessId: BusinessID(business.id!), source: .handle, optInPurposes: []))
            XCTAssertTrue([.ok, .created].contains(connected.status), connected.text)
            let connections = try await demo.connections(businessId: business.id!)
            XCTAssertEqual(connections.count, 1)
            let subjectRef = try XCTUnwrap(SubjectRef(rawValue: connections[0].subjectRef))

            let auth = ["Authorization": "Bearer \(key)"]
            let message = try await h.request(.POST, APIRoutes.businessSendMessage.template, headers: auth, body: try ViadereJSON.encode(
                BusinessSendMessageRequest(subjectRef: subjectRef, body: "Your table is ready.", idempotencyKey: "demo-msg-1")))
            XCTAssertTrue([.ok, .created].contains(message.status), message.text)
            let approval = try await h.request(.POST, APIRoutes.businessIssueInteraction.template, headers: auth, body: try ViadereJSON.encode(
                IssueInteractionRequest(subjectRef: subjectRef, purpose: .security, payload: .authorize(.sample()), sensitivity: .high,
                                        ttlSeconds: 300, idempotencyKey: "demo-approve-1")))
            XCTAssertTrue([.ok, .created].contains(approval.status), approval.text)
            let issued = try approval.json(Interaction.self)
            XCTAssertTrue(h.push.sent.contains { $0.deviceToken == token && $0.interactionId == issued.id.description && $0.mutableContent },
                          "the approval reaches the device as an opaque push")
            XCTAssertGreaterThanOrEqual(h.push.sent.filter { $0.deviceToken == token }.count, 2, "the message is pushed too")

            // Audit: the key issue is recorded with the system actor.
            let audited = try await AuditEventRecord.query(on: h.db).filter(\.$action == "staging_demo.key_issued").count()
            XCTAssertEqual(audited, 2)
        }
    }
}
