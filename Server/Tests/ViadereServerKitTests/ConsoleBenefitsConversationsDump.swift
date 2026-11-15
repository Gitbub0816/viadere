import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Rendering input for screenshots of the conversation and benefits pages: seeds a business with several customer threads, a loyalty program,
/// rewards and passes, and writes each page's HTML to `$CONSOLE_PAGES_DIR`. Skipped unless that variable is set.
final class ConsoleBenefitsConversationsDump: XCTestCase {
    func testDumpConversationAndBenefitPages() async throws {
        guard let dir = ProcessInfo.processInfo.environment["CONSOLE_PAGES_DIR"] else { throw XCTSkip("CONSOLE_PAGES_DIR not set") }
        let root = URL(fileURLWithPath: dir, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try await withHarness { h in
            let (owner, account, businessId) = try await h.verifiedOwner(org: "Acme Roasters and Provisions")
            let business = try await h.testBusiness(businessId)
            try await h.saveProgram(business)
            _ = try await h.addMember(owner: owner, role: .messagingOperator, email: "sam@example.com", name: "Sam Operator")
            let texts = ["Hi, is my order ready for pickup? I'm outside in a blue car.",
                         "Can I change my reservation to 7:30 tonight? We'll be four people instead of three.\nThanks!",
                         "<b>Is this bold?</b> Just checking your menu link works."]
            var sessions: [UUID] = []
            var firstCode = ""
            for (index, text) in texts.enumerated() {
                let consumer = try await h.readyConsumer()
                let relationship = try await h.connect(consumer, to: business, optIn: [.support])
                let started = try await h.signedPost(consumer, APIRoutes.conversationStart.template, StartConversationRequest(businessId: business.id))
                let session = try started.json(ConversationSummary.self).id
                sessions.append(session.uuid)
                _ = try await h.signedPost(consumer, "/v1/conversations/\(session)/messages", SendMessageRequest(body: text, clientMessageId: "c\(index)"))
                h.clock.advance(by: 300)
                _ = try await h.enroll(consumer, business)
                _ = try await h.businessPost(business, "/v1/business/wallet/passes", BusinessIssueWalletPassRequest(relationshipId: relationship.id, kind: .storeCard))
                if index == texts.count - 1 {
                    let reward = try await h.reward(business, title: "Free pastry with any coffee", kind: .coupon)
                    _ = try await h.claim(consumer, reward.id)
                    firstCode = try await h.redeem(consumer, reward.id).json(RewardRedemption.self).redemptionCode
                }
            }
            let revoked = try await h.reward(business, title: "Summer double points weekend", kind: .perk)
            _ = try await h.dashReauth(owner, account)
            _ = try await h.formPost("/dashboard/benefits/rewards/\(revoked.id)/revoke", owner)
            _ = try await h.reward(business, title: "Birthday drink on the house", kind: .perk)
            let thread = "/dashboard/conversations/\(sessions[0].uuidString.lowercased())"
            let page = try await h.page(thread, owner)
            let key = page.text.range(of: "name=\"idempotency_key\" value=\"").map { String(page.text[$0.upperBound...].prefix { $0 != "\"" }) } ?? ""
            _ = try await h.formPost("\(thread)/reply", owner, [("body", "Yes! Bringing it out to you now."), ("agent_name", "Dana"), ("idempotency_key", key)])
            let checked = try await h.formPost("/dashboard/benefits/check", owner, [("code", firstCode), ("location", "front-counter")])
            let pages: [(String, String)] = [
                ("conversations", try await h.page("/dashboard/conversations", owner).text),
                ("conversation-thread", try await h.page(thread + "?cm=sent", owner).text),
                ("benefits", try await h.page("/dashboard/benefits", owner).text),
                ("benefits-passes", try await h.page("/dashboard/benefits/passes", owner).text),
                ("benefits-check", try await h.page("/dashboard/benefits/check", owner).text),
                ("benefits-check-result", checked.text),
            ]
            for (name, html) in pages { try Data(html.utf8).write(to: root.appendingPathComponent(name + ".html")) }
        }
    }
}
