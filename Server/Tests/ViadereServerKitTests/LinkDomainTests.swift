import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP-C3: `LINK_DOMAIN` decides the host of every link the server builds, and the only host it accepts in a link a client sends.
final class LinkDomainServerTests: XCTestCase {
    let staging = LinkDomain("viadere.cksites.dev")!

    func testLinkDomainIsConfiguredValidatedAndDefaultsToTheRelyingParty() throws {
        let base = ["ENVIRONMENT": "development"]
        XCTAssertEqual(try ServerConfig.fromEnvironment(base).linkDomain, .production)
        XCTAssertEqual(try ServerConfig.fromEnvironment(base.merging(["RP_ID": "viadere.cksites.dev", "RP_ORIGIN": "https://viadere.cksites.dev"]) { $1 }).linkDomain.host,
                       "viadere.cksites.dev", "the web domain (RP_ID) is the default")
        XCTAssertEqual(try ServerConfig.fromEnvironment(base.merging(["LINK_DOMAIN": "Viadere.CKSites.dev"]) { $1 }).linkDomain.host, "viadere.cksites.dev")
        for bad in ["https://viadere.com", "viadere.com/c", "viadere", "*.viadere.com", "viadere.com:8443"] {
            XCTAssertThrowsError(try ServerConfig.fromEnvironment(base.merging(["LINK_DOMAIN": bad]) { $1 }), bad)
        }
    }

    func testLinksAreBuiltOnTheLinkDomainAndOtherHostsAreRefused() async throws {
        try await withHarness({ $0.linkDomain = self.staging }) { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let code = b.summary.code
            // Directory resolution: only a link on the configured host is a link; a production link in staging is not resolved as one.
            let ok = try await h.post("/v1/directory/resolve", DirectoryResolveRequest(input: "https://viadere.cksites.dev/c/\(code.canonical)"))
            XCTAssertEqual(ok.status, .ok, ok.text)
            XCTAssertEqual(try ok.json(DirectoryResolveResponse.self).method, .link)
            let foreign = try await h.post("/v1/directory/resolve", DirectoryResolveRequest(input: "https://viadere.com/c/\(code.canonical)"))
            if foreign.status == .ok { XCTAssertNotEqual(try foreign.json(DirectoryResolveResponse.self).method, .link) }
            // Connecting with a link of another host is refused.
            let consumer = try await h.readyConsumer()
            let refused = try await h.signedPost(consumer, APIRoutes.relationshipConnect.template,
                                                 ConnectRequest(businessId: b.id, source: .qr, link: "https://viadere.com/c/\(code.canonical)"))
            XCTAssertEqual(refused.status, .unprocessableEntity, refused.text)
            let accepted = try await h.signedPost(consumer, APIRoutes.relationshipConnect.template,
                                                  ConnectRequest(businessId: b.id, source: .qr, link: "https://viadere.cksites.dev/c/\(code.canonical)"))
            XCTAssertTrue([.ok, .created].contains(accepted.status), accepted.text)
            // Secure handoff links point at the link domain, not at the API host.
            let url = try await HandoffTokens(ctx: h.ctx).mint(consumerId: consumer.id.uuid, phone: PhoneNumber("+14155550100")!, interactionId: UUID(), on: h.db)
            XCTAssertEqual(url?.host, "viadere.cksites.dev")
            XCTAssertTrue(url?.path.hasPrefix(APIRoutes.Web.handoffPrefix) == true)
        }
    }
}
