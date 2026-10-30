import Foundation
import Testing
@testable import ViadereCore

/// WP-C3: the link domain is configured, and every strict link parser accepts only the configured host.
///
/// These tests pass the domain explicitly and never change the process-wide value (`LinkDomain.current`): swift-testing runs suites in
/// parallel and other suites rely on the production default.
@Suite("Link domain (WP-C3)")
struct LinkDomainTests {
    let staging = LinkDomain("viadere.cksites.dev")!
    let production = LinkDomain.production

    @Test func onlyPlainDNSNamesAreAccepted() {
        #expect(LinkDomain("viadere.com")?.host == "viadere.com")
        #expect(LinkDomain("Viadere.CKSites.dev")?.host == "viadere.cksites.dev")
        for bad in ["", "viadere", "https://viadere.com", "viadere.com/", "viadere.com:443", "user@viadere.com", "*.viadere.com", "$(VIADERE_LINK_DOMAIN)",
                    "-viadere.com", "viadere-.com", "viadere..com", ".viadere.com", "viadere.com.", "10.0.0.1", "viadere .com", "viadère.com",
                    String(repeating: "a", count: 64) + ".com"] {
            #expect(LinkDomain(bad) == nil, "\(bad)")
        }
        #expect(ViadereCore.configureLinkDomain("not a domain") == false, "an invalid value is refused and changes nothing")
        #expect(ViadereCore.defaultDomain == "viadere.com")
    }

    @Test func connectLinksUseAndAcceptOnlyTheConfiguredHost() throws {
        let code = try BusinessCode("AF2345")
        #expect(ConnectLink(code: code, domain: staging).urlString == "https://viadere.cksites.dev/c/AF2345")
        #expect(try ConnectLink.parse("https://viadere.cksites.dev/c/AF2345", domain: staging).host == "viadere.cksites.dev")
        #expect(try ConnectLink.parse("https://www.viadere.cksites.dev/c/AF2345", domain: staging).host == "viadere.cksites.dev")
        // A production link in a staging build, a staging link in a production build, and look-alikes are refused.
        #expect(throws: ConnectLink.ParseError.disallowedHost) { try ConnectLink.parse("https://viadere.com/c/AF2345", domain: staging) }
        #expect(throws: ConnectLink.ParseError.disallowedHost) { try ConnectLink.parse("https://viadere.cksites.dev/c/AF2345", domain: production) }
        #expect(throws: ConnectLink.ParseError.disallowedHost) { try ConnectLink.parse("https://viadere.cksites.dev.evil.com/c/AF2345", domain: staging) }
        #expect(throws: ConnectLink.ParseError.disallowedHost) { try ConnectLink.parse("https://evil.viadere.cksites.dev/c/AF2345", domain: staging) }
    }

    @Test func approveEnrollmentLinksUseAndAcceptOnlyTheConfiguredHost() throws {
        let link = ApprovalEnrollmentCode.deepLink(code: "ABCDEFGH", rootKid: nil, domain: staging)
        #expect(link == "https://viadere.cksites.dev/a/ABCDEFGH")
        #expect(ApprovalEnrollmentCode.parse(link: try #require(URL(string: link)), domain: staging)?.code == "ABCDEFGH")
        #expect(ApprovalEnrollmentCode.parse(link: try #require(URL(string: link)), domain: production) == nil)
        #expect(ApprovalEnrollmentCode.parse(link: try #require(URL(string: "https://viadere.com/a/ABCDEFGH")), domain: staging) == nil)
        #expect(ApprovalEnrollmentCode.parse(link: try #require(URL(string: "https://www.viadere.cksites.dev/a/ABCDEFGH")), domain: staging) == nil,
                "no www alias on the strict paths")
    }

    @Test func webLinksAreBuiltOnTheConfiguredHost() {
        let token = String(repeating: "A", count: 43)
        #expect(APIRoutes.Web.accountLinkURL(token: token, domain: staging)?.absoluteString == "https://viadere.cksites.dev/l/\(token)")
        #expect(APIRoutes.Web.handoffURL(token: token, domain: staging)?.absoluteString == "https://viadere.cksites.dev/h/\(token)")
    }
}
