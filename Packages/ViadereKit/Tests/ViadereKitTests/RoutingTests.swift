import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

@Suite("Deep links")
struct DeepLinkTests {
    let token = String(repeating: "A", count: 43)

    @Test func connectUniversalLink() {
        guard case .connect(let code, let link)? = DeepLinkRouter.route("https://viadere.io/c/af-2345".replacingOccurrences(of: "-", with: "")) else {
            Issue.record("expected connect"); return
        }
        #expect(code.canonical == "AF2345")
        #expect(link != nil)
        #expect(DeepLinkRouter.route("https://www.viadere.io/c/AF2345") != nil)
    }

    @Test func connectLinkIsStrict() {
        #expect(DeepLinkRouter.route("https://viadere.io.evil.com/c/AF2345") == nil)
        #expect(DeepLinkRouter.route("http://viadere.io/c/AF2345") == nil)
        #expect(DeepLinkRouter.route("https://user@viadere.io/c/AF2345") == nil)
        #expect(DeepLinkRouter.route("https://viadere.io/c/AF2345?redirect=evil") == nil)
        #expect(DeepLinkRouter.route("https://viadere.io/c/AF234") == nil)
        #expect(DeepLinkRouter.route("https://viadere.io:8443/c/AF2345") == nil)
    }

    @Test func retiredAccountLinkAndHandoffOnlyOpenTheNoLongerUsedNotice() {
        // ADR-0027: old text links carry no token into the app. They route to one case that redeems and reads nothing.
        #expect(DeepLinkRouter.route("https://viadere.io/l/\(token)") == .retiredLink)
        #expect(DeepLinkRouter.route("https://viadere.io/h/\(token)") == .retiredLink)
        #expect(DeepLinkRouter.route("viadere://h/\(token)") == nil)
        #expect(DeepLinkRouter.route("viadere://l/\(token)") == nil)
        #expect(DeepLinkRouter.route("https://viadere.io/h/short") == nil)
        #expect(DeepLinkRouter.route("https://viadere.io/h/\(token)?next=https://evil.com") == nil)
        #expect(DeepLinkRouter.route("https://viadere.io/h/\(token)#frag") == nil)
        #expect(DeepLinkRouter.route("https://viadere.io/h/\(token)/extra") == nil)
        #expect(DeepLinkRouter.route("https://evil.com/h/\(token)") == nil)
        #expect(DeepLinkRouter.route("https://viadere.io/x/\(token)") == nil)
        #expect(DeepLinkRouter.route("https://viadere.io/l/\(token.dropLast())+") == nil)
    }

    @Test func customScheme() {
        if case .connect(let code, let link)? = DeepLinkRouter.route("viadere://c/AF2345") {
            #expect(code.canonical == "AF2345"); #expect(link == nil)
        } else { Issue.record("expected connect") }
        #expect(DeepLinkRouter.route("viadere://b/harborbank") == .business(BusinessHandle(parsing: "@harborbank")!))
        let id = InteractionID()
        #expect(DeepLinkRouter.route("viadere://i/\(id)") == .interaction(id))
        let session = SessionID()
        #expect(DeepLinkRouter.route("viadere://m/\(session)") == .conversation(session))
        #expect(DeepLinkRouter.route("viadere://settings") == .settings)
        #expect(DeepLinkRouter.route("viadere://i/not-a-uuid") == nil)
        #expect(DeepLinkRouter.route("viadere://unknown/x") == nil)
        #expect(DeepLinkRouter.route("viadere://c/AF2345/extra") == nil)
        #expect(DeepLinkRouter.route("ftp://viadere.io/c/AF2345") == nil)
    }

    @Test func notificationUserInfo() {
        let id = InteractionID()
        #expect(DeepLinkRouter.route(notification: ["iid": id.description]) == .interaction(id))
        #expect(DeepLinkRouter.route(notification: ["interactionId": id.description]) == .interaction(id))
        #expect(DeepLinkRouter.route(notification: ["iid": "nope"]) == nil)
        #expect(PushPayload.stringify(["aps": ["x": 1], "iid": "a", "n": 3]) == ["iid": "a"])
    }
}

@Suite("Certificate pinning")
struct PinningTests {
    static let pinA = Data(repeating: 1, count: 32).base64EncodedString()
    static let pinB = Data(repeating: 2, count: 32).base64EncodedString()
    static let pinC = Data(repeating: 3, count: 32).base64EncodedString()
    let configured = PinningConfiguration(host: "api.viadere.io", pins: [pinA, pinB])

    @Test func pinMatchAllowsAndMismatchDenies() {
        #expect(PinEvaluator.evaluate(host: "api.viadere.io", chainSPKIHashes: [Self.pinC, Self.pinA], configuration: configured, failClosed: true) == .allow)
        // backup pin also allows
        #expect(PinEvaluator.evaluate(host: "api.viadere.io", chainSPKIHashes: [Self.pinB], configuration: configured, failClosed: true) == .allow)
        #expect(PinEvaluator.evaluate(host: "api.viadere.io", chainSPKIHashes: [Self.pinC], configuration: configured, failClosed: true) == .deny)
        #expect(PinEvaluator.evaluate(host: "api.viadere.io", chainSPKIHashes: [], configuration: configured, failClosed: true) == .deny)
    }

    @Test func hostScoping() {
        #expect(configured.applies(to: "API.viadere.io"))
        #expect(configured.applies(to: "x.api.viadere.io"))
        #expect(!configured.applies(to: "evilapi.viadere.io"))
        #expect(PinEvaluator.evaluate(host: "example.org", chainSPKIHashes: [], configuration: configured, failClosed: true) == .useDefaultEvaluation)
    }

    @Test func placeholdersFailClosedInRelease() {
        let placeholder = ViadereConfiguration.productionPinning
        #expect(placeholder.isPlaceholder)
        #expect(!placeholder.isConfigured)
        #expect(PinEvaluator.evaluate(host: "api.viadere.io", chainSPKIHashes: [Self.pinA], configuration: placeholder, failClosed: true) == .deny)
        #expect(PinEvaluator.evaluate(host: "api.viadere.io", chainSPKIHashes: [Self.pinA], configuration: placeholder, failClosed: false) == .useDefaultEvaluation)
    }

    @Test func requiresBackupPin() {
        #expect(!PinningConfiguration(host: "api.viadere.io", pins: [Self.pinA]).isConfigured)
        #expect(!PinningConfiguration(host: "api.viadere.io", pins: [Self.pinA, "not-a-pin"]).isConfigured)
        #expect(configured.isConfigured)
    }
}

@Suite("Configuration")
struct ConfigurationTests {
    @Test func releaseRejectsPlainHTTP() {
        let config = ViadereConfiguration.resolve(info: ["ViadereAPIBaseURL": "http://localhost:8080"], allowLocalHTTP: false)
        #expect(config.mode == .production)
        #expect(config.apiBaseURL.scheme == "https")
    }

    @Test func debugAllowsLocalhostOnly() {
        let local = ViadereConfiguration.resolve(info: ["ViadereAPIBaseURL": "http://localhost:8080"], allowLocalHTTP: true)
        #expect(local.mode == .local)
        #expect(local.apiBaseURL.absoluteString == "http://localhost:8080")
        let remote = ViadereConfiguration.resolve(info: ["ViadereAPIBaseURL": "http://evil.example.com"], allowLocalHTTP: true)
        #expect(remote.mode == .production)
    }

    @Test func rejectsOddURLs() {
        #expect(ViadereConfiguration.sanitizedBaseURL("https://user:pw@api.viadere.io", allowLocalHTTP: false) == nil)
        #expect(ViadereConfiguration.sanitizedBaseURL("https://api.viadere.io/v1", allowLocalHTTP: false) == nil)
        #expect(ViadereConfiguration.sanitizedBaseURL("ftp://api.viadere.io", allowLocalHTTP: true) == nil)
        #expect(ViadereConfiguration.sanitizedBaseURL("https://api.viadere.io", allowLocalHTTP: false)?.absoluteString == "https://api.viadere.io")
    }

    @Test func keychainGroupMustBeSubstituted() {
        let c = ViadereConfiguration.resolve(info: ["ViadereKeychainAccessGroup": "$(AppIdentifierPrefix)com.viadere.shared"], allowLocalHTTP: false)
        #expect(c.keychainAccessGroup == nil)
        let ok = ViadereConfiguration.resolve(info: ["ViadereKeychainAccessGroup": "ABCDE12345.com.viadere.shared"], allowLocalHTTP: false)
        #expect(ok.keychainAccessGroup == "ABCDE12345.com.viadere.shared")
    }
}

/// WP-C3: the app's link domain comes from the build (`VIADERE_LINK_DOMAIN`), and the router accepts only that host.
@Suite("Link domain")
struct LinkDomainRoutingTests {
    let staging = LinkDomain("staging.viadere.io")!
    let token = String(repeating: "A", count: 43)

    @Test func everyUniversalLinkForAnotherHostIsRefused() {
        // Built for staging: production links (and look-alikes) are not ours.
        for link in ["https://viadere.io/c/AF2345", "https://viadere.io/l/\(token)", "https://viadere.io/h/\(token)", "https://viadere.io/a/ABCDEFGH",
                     "https://staging.viadere.io.evil.com/c/AF2345", "https://www.staging.viadere.io/l/\(token)", "https://www.staging.viadere.io/h/\(token)"] {
            #expect(DeepLinkRouter.route(link, domain: staging) == nil, "\(link)")
        }
        #expect(DeepLinkRouter.route("https://staging.viadere.io/c/AF2345", domain: staging) != nil)
        #expect(DeepLinkRouter.route("https://www.staging.viadere.io/c/AF2345", domain: staging) != nil)
        #expect(DeepLinkRouter.route("https://staging.viadere.io/l/\(token)", domain: staging) == .retiredLink)
        #expect(DeepLinkRouter.route("https://staging.viadere.io/h/\(token)", domain: staging) == .retiredLink)
        #expect(DeepLinkRouter.route("https://staging.viadere.io/a/ABCDEFGH", domain: staging) == .approveEnrollment(code: "ABCDEFGH", rootKid: nil, secret: nil))
        // And a production build refuses staging links, although staging.viadere.io is a subdomain of viadere.io (SECURITY.md §2.116).
        for link in ["https://staging.viadere.io/c/AF2345", "https://www.staging.viadere.io/c/AF2345", "https://staging.viadere.io/a/ABCDEFGH",
                     "https://staging.viadere.io/l/\(token)", "https://api-staging.viadere.io/c/AF2345"] {
            #expect(DeepLinkRouter.route(link, domain: .production) == nil, "\(link)")
        }
    }

    /// Production pins `api.viadere.io` with its subdomains; the staging API `api-staging.viadere.io` is a sibling label, not a subdomain, so
    /// production pins never apply to it, and a staging build's pins never apply to the production API (SECURITY.md §2.116).
    @Test func productionAndStagingPinsNeverCoverEachOther() {
        let production = ViadereConfiguration.productionPinning
        #expect(production.includeSubdomains && production.applies(to: "api.viadere.io"))
        for host in ["api-staging.viadere.io", "staging.viadere.io", "viadere.io", "assets-staging.viadere.io"] {
            #expect(!production.applies(to: host), "\(host)")
        }
        let stagingBuild = ViadereConfiguration.resolve(info: ["ViadereAPIBaseURL": "https://api-staging.viadere.io"], allowLocalHTTP: false)
        #expect(stagingBuild.pinning.host == "api-staging.viadere.io")
        #expect(!stagingBuild.pinning.applies(to: "api.viadere.io") && !stagingBuild.pinning.applies(to: "viadere.io"))
        #expect(PinEvaluator.evaluate(host: "api-staging.viadere.io", chainSPKIHashes: [], configuration: production, failClosed: true) == .useDefaultEvaluation)
    }

    @Test func theBuildSettingSetsTheLinkDomainForNonProductionHostsOnly() {
        let stagingBuild = ViadereConfiguration.resolve(info: ["ViadereAPIBaseURL": "https://api-staging.viadere.io", "ViadereLinkDomain": "staging.viadere.io"],
                                                        allowLocalHTTP: false)
        #expect(stagingBuild.linkDomain.host == "staging.viadere.io")
        let unexpanded = ViadereConfiguration.resolve(info: ["ViadereAPIBaseURL": "https://api-staging.viadere.io", "ViadereLinkDomain": "$(VIADERE_LINK_DOMAIN)"],
                                                      allowLocalHTTP: false)
        #expect(unexpanded.linkDomain == .production)
        let production = ViadereConfiguration.resolve(info: ["ViadereAPIBaseURL": "https://api.viadere.io", "ViadereLinkDomain": "evil.example.com"], allowLocalHTTP: false)
        #expect(production.linkDomain == .production, "the production API never takes its link domain from the plist")
    }
}
