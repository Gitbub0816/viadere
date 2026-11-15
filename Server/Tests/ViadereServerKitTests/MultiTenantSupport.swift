import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP-0.5: a shared multi-tenant world and the leakage matrix every later endpoint joins.
///
/// Tenants: three verified businesses (`shop`, `bank`, `cafe`), one nobody is connected to (`stranger`), one Alice left (`dropped`).
/// Customers: Alice (shop, bank; was connected to `dropped`), Bob (bank, cafe) and Sam, Alice's household delegate for `transactional` at
/// `shop` only. Every connection holds a pending request and an informational update, so any cross-tenant read shows up as a foreign id.
struct TenantWorld {
    let h: TestHarness
    let shop: TestBusiness
    let bank: TestBusiness
    let cafe: TestBusiness
    let stranger: TestBusiness
    let dropped: TestBusiness
    let alice: TestConsumer
    let bob: TestConsumer
    let sam: TestConsumer
    var relationships: [String: Relationship]
    /// Interaction ids by "<consumer>/<business>/<kind>".
    var interactions: [String: InteractionID]

    func rel(_ consumer: String, _ business: String) -> Relationship { relationships["\(consumer)/\(business)"]! }

    static func build(_ h: TestHarness) async throws -> TenantWorld {
        let shop = try await h.makeBusiness(name: "Corner Shop", handle: "cornershop")
        let bank = try await h.makeBusiness(name: "Harbor Bank", handle: "harborbank")
        let cafe = try await h.makeBusiness(name: "Blue Cafe", handle: "bluecafe")
        let stranger = try await h.makeBusiness(name: "Stranger Store", handle: "strangerstore")
        let dropped = try await h.makeBusiness(name: "Old Gym", handle: "oldgym")
        let alice = try await h.readyConsumer(name: "Alice")
        let bob = try await h.readyConsumer(name: "Bob")
        let sam = try await h.readyConsumer(name: "Sam")
        var world = TenantWorld(h: h, shop: shop, bank: bank, cafe: cafe, stranger: stranger, dropped: dropped, alice: alice, bob: bob, sam: sam,
                                relationships: [:], interactions: [:])
        for (name, consumer, businesses) in [("alice", alice, [("shop", shop), ("bank", bank), ("dropped", dropped)]),
                                             ("bob", bob, [("bank", bank), ("cafe", cafe)])] {
            for (label, business) in businesses {
                let relationship = try await h.connect(consumer, to: business)
                world.relationships["\(name)/\(label)"] = relationship
                world.interactions["\(name)/\(label)/confirm"] = try await world.issueConfirm(business, relationship, title: "Confirm \(label) for \(name)")
                world.interactions["\(name)/\(label)/status"] = try await world.issueStatus(business, relationship, title: "Update \(label) for \(name)")
            }
        }
        // A security request at the shop, outside Sam's grant (purpose `security`).
        world.interactions["alice/shop/security"] = try await world.issueSignIn(shop, world.rel("alice", "shop"))
        // Alice leaves the gym: its items must disappear from every All view.
        let left = try await h.signed(alice, .DELETE, "/v1/relationships/\(world.rel("alice", "dropped").id)")
        XCTAssertEqual(left.status, .ok, left.text)
        _ = try await h.shareAccess(from: alice, to: sam, purposes: [.transactional], businesses: [shop])
        return world
    }

    @discardableResult
    func issueConfirm(_ business: TestBusiness, _ relationship: Relationship, title: String, ttl: Int = 3600) async throws -> InteractionID {
        let issued = try await h.issue(business, relationship: relationship, payload: .confirm(ConfirmPayload(title: title)), purpose: .transactional, ttl: ttl)
        XCTAssertEqual(issued.status, .created, issued.text)
        return try issued.json(Interaction.self).id
    }

    @discardableResult
    func issueStatus(_ business: TestBusiness, _ relationship: Relationship, title: String) async throws -> InteractionID {
        let issued = try await h.issue(business, relationship: relationship, payload: .status(StatusPayload(title: title)), purpose: .transactional)
        XCTAssertEqual(issued.status, .created, issued.text)
        return try issued.json(Interaction.self).id
    }

    @discardableResult
    func issueSignIn(_ business: TestBusiness, _ relationship: Relationship) async throws -> InteractionID {
        let payload = InteractionPayload.authenticate(AuthenticatePayload(service: "Online account", device: "Safari on Mac", attemptedAt: h.clock.now()))
        let issued = try await h.issue(business, relationship: relationship, payload: payload, purpose: .security, priority: .urgent)
        XCTAssertEqual(issued.status, .created, issued.text)
        return try issued.json(Interaction.self).id
    }

    /// Lowercase ids that must never appear in `consumer`'s responses from an All view.
    func foreignIds(for consumer: String) -> [String: String] {
        var out: [String: String] = ["stranger": stranger.id.description]
        switch consumer {
        case "alice":
            out["cafe"] = cafe.id.description
            out["bob"] = bob.id.description
            out["sam"] = sam.id.description
        case "bob":
            out["shop"] = shop.id.description
            out["dropped"] = dropped.id.description
            out["alice"] = alice.id.description
        default:
            out["bank"] = bank.id.description
            out["cafe"] = cafe.id.description
            out["dropped"] = dropped.id.description
            out["bob"] = bob.id.description
        }
        return out
    }
}

/// The leakage matrix (D3.T1). One row per consumer read that aggregates across businesses. Later phases append rows.
enum LeakageMatrix {
    struct Row {
        var path: String
        /// Whether a business the consumer **left** may still appear (its own history), or never (All views: Alerts, Benefits, Messages).
        var endedConnectionsAllowed: Bool
    }

    static let allViews: [Row] = [
        Row(path: "/v1/alerts", endedConnectionsAllowed: false),
        Row(path: "/v1/alerts?status=pending", endedConnectionsAllowed: false),
        Row(path: "/v1/alerts?status=completed", endedConnectionsAllowed: false),
        Row(path: "/v1/alerts?status=expired", endedConnectionsAllowed: false),
        Row(path: "/v1/benefits", endedConnectionsAllowed: false),
        // A thread with a business the customer left stays their own history (closed); it never shows another tenant.
        Row(path: "/v1/conversations", endedConnectionsAllowed: true),
        Row(path: "/v1/businesses", endedConnectionsAllowed: true),
        Row(path: "/v1/interactions", endedConnectionsAllowed: true),
        Row(path: "/v1/relationships", endedConnectionsAllowed: true),
        Row(path: "/v1/rewards/overview", endedConnectionsAllowed: false),
    ]

    /// Every consumer endpoint that takes a business filter or a business in its path: a foreign business must be `404`, never `403`.
    static func businessScoped(_ business: BusinessID) -> [String] {
        ["/v1/alerts?business_id=\(business)", "/v1/benefits?business_id=\(business)", "/v1/conversations?business_id=\(business)",
         "/v1/businesses/\(business)/preferences", "/v1/businesses/\(business)/surface", "/v1/businesses/\(business)/brand"]
    }

    static func assertNoLeak(_ world: TenantWorld, consumer name: String, file: StaticString = #filePath, line: UInt = #line) async throws {
        let consumer = name == "alice" ? world.alice : (name == "bob" ? world.bob : world.sam)
        let foreign = world.foreignIds(for: name)
        for row in allViews {
            let response = try await world.h.signed(consumer, .GET, row.path)
            XCTAssertEqual(response.status, .ok, "\(name) \(row.path): \(response.text)", file: file, line: line)
            let text = response.text.lowercased()
            for (label, id) in foreign {
                XCTAssertFalse(text.contains(id), "\(name) \(row.path) leaks \(label)", file: file, line: line)
            }
            if !row.endedConnectionsAllowed, name == "alice" {
                XCTAssertFalse(text.contains(world.dropped.id.description), "\(name) \(row.path) shows a business they left", file: file, line: line)
            }
        }
    }
}
