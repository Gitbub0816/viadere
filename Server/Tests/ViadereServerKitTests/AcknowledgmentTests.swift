import Fluent
import Foundation
import ViadereCore
import struct ViadereCore.Page
import XCTest
@testable import ViadereServerKit

final class AcknowledgmentTests: XCTestCase {
    private let digest = String(repeating: "ab", count: 32)

    private func acknowledgePayload(version: String? = "2026-10", digest: String? = nil) -> AcknowledgePayload {
        AcknowledgePayload(title: "Service estimate", body: "Please review the estimate of $420.", documentURL: URL(string: "https://example.com/estimate.pdf"),
                           documentVersion: version, documentDigest: digest)
    }

    func testAcknowledgmentsAreServerTimestampedRecordsOfSignedDecisions() async throws {
        try await withHarness { h in
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let relationship = try await h.connect(consumer, to: business)
            let issued = try await h.issue(business, relationship: relationship, payload: .acknowledge(acknowledgePayload(digest: digest)), purpose: .support).json(Interaction.self)
            try await eq(try await h.signed(consumer, .GET, "/v1/acknowledgments").json([AcknowledgmentRecord].self).isEmpty, true, "nothing until it is decided")
            let real = try await h.consumerInteraction(consumer, id: issued.id)
            // The device clock is 40 s behind the server when it signs; the record uses the server's time.
            let signed = try await h.decision(consumer, interaction: real, decision: .acknowledge, assurance: .biometric, signedAt: h.clock.now().addingTimeInterval(-40))
            h.clock.advance(by: 10)
            let decided = try await h.decide(consumer, id: issued.id, signed: signed, channel: .inApp)
            XCTAssertEqual(decided.status, .ok, decided.text)
            let records = try await h.signed(consumer, .GET, "/v1/acknowledgments").json([AcknowledgmentRecord].self)
            XCTAssertEqual(records.count, 1)
            let record = records[0]
            XCTAssertEqual(record.id, issued.id)
            XCTAssertEqual(record.business.id, business.id)
            XCTAssertEqual(record.title, "Service estimate")
            XCTAssertEqual(record.documentVersion, "2026-10")
            XCTAssertEqual(record.documentDigest, digest)
            XCTAssertTrue(record.acknowledged)
            XCTAssertEqual(record.recordedAt, h.clock.now(), "server time, not the device's signedAt")
            XCTAssertEqual(record.channel, .inApp)
            // Someone else sees nothing of it.
            let other = try await h.readyConsumer(name: "Other")
            try await eq(try await h.signed(other, .GET, "/v1/acknowledgments").json([AcknowledgmentRecord].self).isEmpty, true)
        }
    }

    func testDeclinedAcknowledgmentsAreRecordedAsNotAcknowledgedNewestFirst() async throws {
        try await withHarness { h in
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let relationship = try await h.connect(consumer, to: business)
            var ids: [InteractionID] = []
            for (index, decision) in [Decision.acknowledge, .decline].enumerated() {
                let issued = try await h.issue(business, relationship: relationship, payload: .acknowledge(acknowledgePayload(version: "v\(index)")), purpose: .support).json(Interaction.self)
                let real = try await h.consumerInteraction(consumer, id: issued.id)
                h.clock.advance(by: 30)
                try await eq(try await h.decide(consumer, id: issued.id, signed: try await h.decision(consumer, interaction: real, decision: decision), channel: .inApp).status, .ok)
                ids.append(issued.id)
            }
            let records = try await h.signed(consumer, .GET, "/v1/acknowledgments").json([AcknowledgmentRecord].self)
            XCTAssertEqual(records.map(\.id), ids.reversed())
            XCTAssertEqual(records.map(\.acknowledged), [false, true])
            XCTAssertEqual(records.map(\.documentVersion), ["v1", "v0"])
            XCTAssertNil(records[0].documentDigest)
            // An unanswered one is not a record.
            _ = try await h.issue(business, relationship: relationship, payload: .acknowledge(acknowledgePayload()), purpose: .support)
            try await eq(try await h.signed(consumer, .GET, "/v1/acknowledgments").json([AcknowledgmentRecord].self).count, 2)
        }
    }

    func testMalformedDocumentDigestsAreRejectedAtIssue() async throws {
        try await withHarness { h in
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let relationship = try await h.connect(consumer, to: business)
            for bad in ["xyz", String(repeating: "A", count: 64), String(repeating: "a", count: 63)] {
                let response = try await h.issue(business, relationship: relationship, payload: .acknowledge(acknowledgePayload(digest: bad)), purpose: .support)
                XCTAssertEqual(response.status, .unprocessableEntity, bad)
            }
        }
    }
}
