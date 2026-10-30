import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

@Suite("Deep links")
struct DeepLinkTests {
    let token = String(repeating: "A", count: 43)

    @Test func connectUniversalLink() {
        guard case .connect(let code, let link)? = DeepLinkRouter.route("https://viadere.com/c/af-2345".replacingOccurrences(of: "-", with: "")) else {
            Issue.record("expected connect"); return
        }
        #expect(code.canonical == "AF2345")
        #expect(link != nil)
        #expect(DeepLinkRouter.route("https://www.viadere.com/c/AF2345") != nil)
    }

    @Test func connectLinkIsStrict() {
        #expect(DeepLinkRouter.route("https://viadere.com.evil.com/c/AF2345") == nil)
        #expect(DeepLinkRouter.route("http://viadere.com/c/AF2345") == nil)
        #expect(DeepLinkRouter.route("https://user@viadere.com/c/AF2345") == nil)
        #expect(DeepLinkRouter.route("https://viadere.com/c/AF2345?redirect=evil") == nil)
        #expect(DeepLinkRouter.route("https://viadere.com/c/AF234") == nil)
        #expect(DeepLinkRouter.route("https://viadere.com:8443/c/AF2345") == nil)
    }

    @Test func accountLinkAndHandoff() {
        #expect(DeepLinkRouter.route("https://viadere.com/l/\(token)") == .accountLink(token: token))
        #expect(DeepLinkRouter.route("https://viadere.com/h/\(token)") == .handoff(token: token))
        #expect(DeepLinkRouter.route("https://viadere.com/h/short") == nil)
        #expect(DeepLinkRouter.route("https://viadere.com/h/\(token)?next=https://evil.com") == nil)
        #expect(DeepLinkRouter.route("https://viadere.com/h/\(token)#frag") == nil)
        #expect(DeepLinkRouter.route("https://viadere.com/h/\(token)/extra") == nil)
        #expect(DeepLinkRouter.route("https://evil.com/h/\(token)") == nil)
        #expect(DeepLinkRouter.route("https://viadere.com/x/\(token)") == nil)
        #expect(DeepLinkRouter.route("https://viadere.com/l/\(token.dropLast())+") == nil)
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
        #expect(DeepLinkRouter.route("ftp://viadere.com/c/AF2345") == nil)
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
    let configured = PinningConfiguration(host: "api.viadere.com", pins: [pinA, pinB])

    @Test func pinMatchAllowsAndMismatchDenies() {
        #expect(PinEvaluator.evaluate(host: "api.viadere.com", chainSPKIHashes: [Self.pinC, Self.pinA], configuration: configured, failClosed: true) == .allow)
        // backup pin also allows
        #expect(PinEvaluator.evaluate(host: "api.viadere.com", chainSPKIHashes: [Self.pinB], configuration: configured, failClosed: true) == .allow)
        #expect(PinEvaluator.evaluate(host: "api.viadere.com", chainSPKIHashes: [Self.pinC], configuration: configured, failClosed: true) == .deny)
        #expect(PinEvaluator.evaluate(host: "api.viadere.com", chainSPKIHashes: [], configuration: configured, failClosed: true) == .deny)
    }

    @Test func hostScoping() {
        #expect(configured.applies(to: "API.viadere.com"))
        #expect(configured.applies(to: "x.api.viadere.com"))
        #expect(!configured.applies(to: "evilapi.viadere.com"))
        #expect(PinEvaluator.evaluate(host: "example.org", chainSPKIHashes: [], configuration: configured, failClosed: true) == .useDefaultEvaluation)
    }

    @Test func placeholdersFailClosedInRelease() {
        let placeholder = ViadereConfiguration.productionPinning
        #expect(placeholder.isPlaceholder)
        #expect(!placeholder.isConfigured)
        #expect(PinEvaluator.evaluate(host: "api.viadere.com", chainSPKIHashes: [Self.pinA], configuration: placeholder, failClosed: true) == .deny)
        #expect(PinEvaluator.evaluate(host: "api.viadere.com", chainSPKIHashes: [Self.pinA], configuration: placeholder, failClosed: false) == .useDefaultEvaluation)
    }

    @Test func requiresBackupPin() {
        #expect(!PinningConfiguration(host: "api.viadere.com", pins: [Self.pinA]).isConfigured)
        #expect(!PinningConfiguration(host: "api.viadere.com", pins: [Self.pinA, "not-a-pin"]).isConfigured)
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
        #expect(ViadereConfiguration.sanitizedBaseURL("https://user:pw@api.viadere.com", allowLocalHTTP: false) == nil)
        #expect(ViadereConfiguration.sanitizedBaseURL("https://api.viadere.com/v1", allowLocalHTTP: false) == nil)
        #expect(ViadereConfiguration.sanitizedBaseURL("ftp://api.viadere.com", allowLocalHTTP: true) == nil)
        #expect(ViadereConfiguration.sanitizedBaseURL("https://api.viadere.com", allowLocalHTTP: false)?.absoluteString == "https://api.viadere.com")
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
    let staging = LinkDomain("viadere.cksites.dev")!
    let token = String(repeating: "A", count: 43)

    @Test func everyUniversalLinkForAnotherHostIsRefused() {
        // Built for staging: production links (and look-alikes) are not ours.
        for link in ["https://viadere.com/c/AF2345", "https://viadere.com/l/\(token)", "https://viadere.com/h/\(token)", "https://viadere.com/a/ABCDEFGH",
                     "https://viadere.cksites.dev.evil.com/c/AF2345", "https://www.viadere.cksites.dev/l/\(token)", "https://www.viadere.cksites.dev/h/\(token)"] {
            #expect(DeepLinkRouter.route(link, domain: staging) == nil, "\(link)")
        }
        #expect(DeepLinkRouter.route("https://viadere.cksites.dev/c/AF2345", domain: staging) != nil)
        #expect(DeepLinkRouter.route("https://www.viadere.cksites.dev/c/AF2345", domain: staging) != nil)
        #expect(DeepLinkRouter.route("https://viadere.cksites.dev/l/\(token)", domain: staging) == .accountLink(token: token))
        #expect(DeepLinkRouter.route("https://viadere.cksites.dev/h/\(token)", domain: staging) == .handoff(token: token))
        #expect(DeepLinkRouter.route("https://viadere.cksites.dev/a/ABCDEFGH", domain: staging) == .approveEnrollment(code: "ABCDEFGH", rootKid: nil, secret: nil))
        // And a production build refuses staging links.
        #expect(DeepLinkRouter.route("https://viadere.cksites.dev/c/AF2345", domain: .production) == nil)
    }

    @Test func theBuildSettingSetsTheLinkDomainForNonProductionHostsOnly() {
        let stagingBuild = ViadereConfiguration.resolve(info: ["ViadereAPIBaseURL": "https://viadere-api.cksites.dev", "ViadereLinkDomain": "viadere.cksites.dev"],
                                                        allowLocalHTTP: false)
        #expect(stagingBuild.linkDomain.host == "viadere.cksites.dev")
        let unexpanded = ViadereConfiguration.resolve(info: ["ViadereAPIBaseURL": "https://viadere-api.cksites.dev", "ViadereLinkDomain": "$(VIADERE_LINK_DOMAIN)"],
                                                      allowLocalHTTP: false)
        #expect(unexpanded.linkDomain == .production)
        let production = ViadereConfiguration.resolve(info: ["ViadereAPIBaseURL": "https://api.viadere.com", "ViadereLinkDomain": "evil.example.com"], allowLocalHTTP: false)
        #expect(production.linkDomain == .production, "the production API never takes its link domain from the plist")
    }
}
