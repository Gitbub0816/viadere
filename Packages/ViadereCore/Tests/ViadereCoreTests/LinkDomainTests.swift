import Foundation
import Testing
@testable import ViadereCore

/// WP-C3: the link domain is configured, and every strict link parser accepts only the configured host.
///
/// These tests pass the domain explicitly and never change the process-wide value (`LinkDomain.current`): swift-testing runs suites in
/// parallel and other suites rely on the production default.
@Suite("Link domain (WP-C3)")
struct LinkDomainTests {
    let staging = LinkDomain("staging.viadere.io")!
    let production = LinkDomain.production

    @Test func onlyPlainDNSNamesAreAccepted() {
        #expect(LinkDomain("viadere.io")?.host == "viadere.io")
        #expect(LinkDomain("Staging.Viadere.IO")?.host == "staging.viadere.io")
        for bad in ["", "viadere", "https://viadere.io", "viadere.io/", "viadere.io:443", "user@viadere.io", "*.viadere.io", "$(VIADERE_LINK_DOMAIN)",
                    "-viadere.io", "viadere-.io", "viadere..io", ".viadere.io", "viadere.io.", "10.0.0.1", "viadere .io", "viadère.io",
                    String(repeating: "a", count: 64) + ".com"] {
            #expect(LinkDomain(bad) == nil, "\(bad)")
        }
        #expect(ViadereCore.configureLinkDomain("not a domain") == false, "an invalid value is refused and changes nothing")
        #expect(ViadereCore.defaultDomain == "viadere.io")
    }

    @Test func connectLinksUseAndAcceptOnlyTheConfiguredHost() throws {
        let code = try BusinessCode("AF2345")
        #expect(ConnectLink(code: code, domain: staging).urlString == "https://staging.viadere.io/c/AF2345")
        #expect(try ConnectLink.parse("https://staging.viadere.io/c/AF2345", domain: staging).host == "staging.viadere.io")
        #expect(try ConnectLink.parse("https://www.staging.viadere.io/c/AF2345", domain: staging).host == "staging.viadere.io")
        // A production link in a staging build, a staging link in a production build, and look-alikes are refused.
        #expect(throws: ConnectLink.ParseError.disallowedHost) { try ConnectLink.parse("https://viadere.io/c/AF2345", domain: staging) }
        #expect(throws: ConnectLink.ParseError.disallowedHost) { try ConnectLink.parse("https://staging.viadere.io/c/AF2345", domain: production) }
        #expect(throws: ConnectLink.ParseError.disallowedHost) { try ConnectLink.parse("https://staging.viadere.io.evil.com/c/AF2345", domain: staging) }
        #expect(throws: ConnectLink.ParseError.disallowedHost) { try ConnectLink.parse("https://evil.staging.viadere.io/c/AF2345", domain: staging) }
    }

    @Test func approveEnrollmentLinksUseAndAcceptOnlyTheConfiguredHost() throws {
        let link = ApprovalEnrollmentCode.deepLink(code: "ABCDEFGH", rootKid: nil, domain: staging)
        #expect(link == "https://staging.viadere.io/a/ABCDEFGH")
        #expect(ApprovalEnrollmentCode.parse(link: try #require(URL(string: link)), domain: staging)?.code == "ABCDEFGH")
        #expect(ApprovalEnrollmentCode.parse(link: try #require(URL(string: link)), domain: production) == nil)
        #expect(ApprovalEnrollmentCode.parse(link: try #require(URL(string: "https://viadere.io/a/ABCDEFGH")), domain: staging) == nil)
        #expect(ApprovalEnrollmentCode.parse(link: try #require(URL(string: "https://www.staging.viadere.io/a/ABCDEFGH")), domain: staging) == nil,
                "no www alias on the strict paths")
    }

    /// Staging (`staging.viadere.io`) is a subdomain of production (`viadere.io`), SECURITY.md §2.116. Every strict parser compares the host
    /// exactly, so a staging link never opens in a production build and a production link never opens in a staging build, in either
    /// direction and for every link kind; the `www.` alias of one domain is never a host of the other.
    @Test func stagingIsASubdomainOfProductionButNeverTheSameLinkDomain() throws {
        #expect(staging.host.hasSuffix("." + production.host), "the premise: staging is one label below production")
        #expect(staging.connectHosts.isDisjoint(with: production.connectHosts))
        #expect(!production.matches("staging.viadere.io") && !production.matches("www.staging.viadere.io") && !staging.matches("viadere.io"))
        let code = try BusinessCode("AF2345")
        let challenge = AuthorityChallengeID.generate()
        let es = try #require(LinkSessionSecret(base64URL: Base64URL.encode(Data(repeating: 7, count: 32))))
        for (built, other) in [(staging, production), (production, staging)] {
            #expect(throws: ConnectLink.ParseError.disallowedHost) { try ConnectLink.parse(ConnectLink(code: code, domain: built).urlString, domain: other) }
            #expect(throws: ConnectLink.ParseError.disallowedHost) { try ConnectLink.parse("https://www.\(built.host)/c/AF2345", domain: other) }
            let approve = try #require(URL(string: ApprovalEnrollmentCode.deepLink(code: "ABCDEFGH", rootKid: nil, domain: built)))
            #expect(ApprovalEnrollmentCode.parse(link: approve, domain: built) != nil)
            #expect(ApprovalEnrollmentCode.parse(link: approve, domain: other) == nil)
            let session = try #require(URL(string: LinkSessionLink.build(code: "K7QFM2XA", secret: es, domain: built)))
            #expect(LinkSessionLink.parse(session, domain: built) != nil)
            #expect(LinkSessionLink.parse(session, domain: other) == nil)
            let verify = try #require(URL(string: VerificationSessionLink.build(code: "ABCDEFGH", domain: built)))
            #expect(VerificationSessionLink.parse(verify, domain: built) == "ABCDEFGH")
            #expect(VerificationSessionLink.parse(verify, domain: other) == nil)
            let oidc = try #require(URL(string: OIDCChallengeLink.build(challengeId: challenge, domain: built)))
            #expect(OIDCChallengeLink.parse(oidc, domain: built) == challenge)
            #expect(OIDCChallengeLink.parse(oidc, domain: other) == nil)
            let loop = try #require(LoopInstallLink(loopId: LoopDefinitionID(UUID())).url(domain: built))
            #expect(LoopInstallLink.parse(loop, domain: built) != nil)
            #expect(LoopInstallLink.parse(loop, domain: other) == nil)
        }
        // A deeper subdomain of staging, and production's www alias under staging, are not staging.
        #expect(throws: ConnectLink.ParseError.disallowedHost) { try ConnectLink.parse("https://api-staging.viadere.io/c/AF2345", domain: staging) }
        #expect(throws: ConnectLink.ParseError.disallowedHost) { try ConnectLink.parse("https://www.viadere.io.staging.viadere.io/c/AF2345", domain: staging) }
    }

    @Test func theOnRampPageIsOnTheConfiguredHostAndCarriesNoToken() {
        #expect(APIRoutes.Web.getAppURL(domain: staging)?.absoluteString == "https://staging.viadere.io/get")
    }
}
