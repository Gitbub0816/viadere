import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Helpers for the customer-originated phone link (ADR-0027): the app begins, the person texts the nonce from the phone, the app polls.
extension TestHarness {
    /// The number the person texts (the harness' provider `To`).
    static let phoneLinkNumber = "+15550001111"

    func beginPhoneLink(_ consumer: TestConsumer, phone: String) async throws -> HTTPResult {
        try await signedPost(consumer, APIRoutes.phoneLinkMOBegin.template, PhoneLinkMOBeginRequest(phone: PhoneNumber(phone)!))
    }

    func phoneLinkStatus(_ consumer: TestConsumer, id: PhoneLinkID) async throws -> PhoneLinkMOStatus {
        let result = try await signed(consumer, .GET, "/v1/phone-links/\(id)")
        XCTAssertEqual(result.status, .ok, result.text)
        return try result.json(PhoneLinkMOStatus.self)
    }

    /// A text from `from` to the Viadere number through the signed provider webhook; returns what Viadere texted back.
    @discardableResult
    func textViadere(from: String, _ body: String) async throws -> [String] {
        let before = texts.sent.count
        let response = try await sendInbound(self, from: from, body: body, sid: nil)
        XCTAssertEqual(response.status, .ok, response.text)
        try await runJobs()
        return texts.sent.dropFirst(before).map(\.body)
    }

    /// Begin, send the pre-filled text from `phone`, and return the begin response and the status the app would then see.
    func linkPhoneByText(_ consumer: TestConsumer, phone: String) async throws -> (begin: PhoneLinkMOBeginResponse, status: PhoneLinkMOStatus, replies: [String]) {
        let begun = try await beginPhoneLink(consumer, phone: phone)
        XCTAssertEqual(begun.status, .ok, begun.text)
        let begin = try begun.json(PhoneLinkMOBeginResponse.self)
        let replies = try await textViadere(from: phone, begin.prefill)
        return (begin, try await phoneLinkStatus(consumer, id: begin.phoneLinkId), replies)
    }

    /// The gateway's view of the account behind a number.
    func gatewayConsumer(_ phone: String) async throws -> ConsumerID? {
        try await GatewayService(db: db, ctx: ctx).loadContext(phone: PhoneNumber(phone)!, on: db).0.consumerId
    }
}
