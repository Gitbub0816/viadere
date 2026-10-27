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
            let replied = try await h.decide(consumer, id: askId, signed: try await h.decision(consumer, interaction: askSeen, decision: .reply, assurance: .none, reply: "My door code is 4417"))
            XCTAssertEqual(replied.status, .ok, replied.text)

            let before = try await ExportDisputeCommand.export(interactionId: approval.id.uuid, db: h.db, ctx: h.ctx)
            try await eq(try await h.signed(consumer, .DELETE, "/v1/account").status, .ok)

            let decisions = try await DecisionRecord.query(on: h.db).all()
            XCTAssertEqual(decisions.count, 2)
            let kept = try XCTUnwrap(decisions.first { $0.interactionId == approval.id.uuid })
            let erased = try XCTUnwrap(decisions.first { $0.interactionId == askId.uuid })
            XCTAssertEqual(erased.signedPayload, CreateSecurityHardeningSchema.erased, "the free-text reply is erased")
            XCTAssertNotEqual(kept.signedPayload, CreateSecurityHardeningSchema.erased, "an id-and-digest-only decision stays")
            XCTAssertFalse(kept.signedPayload.contains("4417"))
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
}

extension TestHarness {
    func highAuthorizeR3(_ b: TestBusiness, _ rel: Relationship, key: String = UUID().uuidString) async throws -> Interaction {
        let r = try await issue(b, relationship: rel, payload: .authorize(.sample()), sensitivity: .high, key: key)
        XCTAssertEqual(r.status, .created, r.text)
        return try r.json(Interaction.self)
    }
}
