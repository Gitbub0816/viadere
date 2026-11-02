import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// Installable Loops on the device (SECURITY.md §2.98 "Installed Loops"): the directory, the verified install sheet, the customer's choice,
/// Your Loops, and install links.
@Suite("Loop directory and installs")
@MainActor
struct LoopDirectoryDeviceTests {
    static let business = PreviewData.northfield

    /// A mock world where the customer is connected to nobody.
    func world() async -> (MockLoopsAPI, LoopSummary, LoopSummary) {
        let api = MockLoopsAPI(connected: [])
        let listed = await api.publish(MockLoopsAPI.pickupDefinition, business: Self.business.id, category: .foodAndDrink, featured: true)
        let unlisted = await api.publish(LP.checkIn, business: Self.business.id)
        return (api, listed, unlisted)
    }

    func enable(_ api: MockLoopsAPI) async throws -> LoopConsentStatus {
        try await api.enableLoops(LoopGlobalConsentRequest(textVersion: LP.text.version, textDigest: LP.text.digest, answers: LP.answers, agree: true))
    }

    @Test func theDirectoryShowsListedLoopsWithFeaturedFirstAndFilters() async throws {
        let (api, listed, unlisted) = await world()
        let status = try await api.consentStatus()
        let model = LoopDirectoryViewModel(api: api, consent: { status })
        await model.load()
        #expect(model.featured.map(\.publicationId) == [listed.publicationId])
        #expect(model.entries.isEmpty, "featured entries are not repeated")
        #expect(model.categories == [.foodAndDrink])
        #expect(!model.featured.contains { $0.publicationId == unlisted.publicationId }, "unlisted Loops are reached by link or business page")
        #expect(LoopDirectoryViewModel.attribution(model.featured[0].business) == "Built by \(Self.business.safeName)")
        model.query = "  pickup  "
        await model.load()
        #expect(model.featured.isEmpty)
        #expect(model.entries.count == 1)
        model.query = String(repeating: "x", count: 200)
        #expect(model.sentQuery.count == LoopDirectoryViewModel.maxQueryLength)
        model.query = ""
        await model.select(.travel)
        #expect(model.isEmpty)
        await model.select(nil)
        #expect(!model.isEmpty)
        // Platform switch off: nothing is listed.
        await api.setAvailable(false)
        let off = try await api.consentStatus()
        let offModel = LoopDirectoryViewModel(api: api, consent: { off })
        await offModel.load()
        #expect(offModel.isEmpty)
    }

    @Test func theInstallSheetVerifiesThePublicationAndDerivesThePermissions() async throws {
        let (api, listed, _) = await world()
        let status = try await api.consentStatus()
        let loopId = try #require(listed.loopId)
        let model = LoopDetailViewModel(loopId: loopId, source: .directory, api: api, keys: { [MockLoopsAPI.pinnedKey] }, consent: { status })
        await model.load()
        #expect(model.status == .ready)
        #expect(model.permissions.map(\.kind) == [.sendsAnswers, .outcomeUpdates, .noProfile, .noMessaging, .expires])
        #expect(model.permissions[0].fields == ["Pickup time"])
        model.mode = .installAndConnect
        #expect(model.permissions.contains { $0.kind == .connection })
        // A manifest signed by a key the device does not pin: nothing is shown and nothing can be installed.
        let untrusted = PinnedManifestKey(kid: "other", publicKey: try SoftwareP256SigningKey().publicKey)
        let refused = LoopDetailViewModel(loopId: loopId, source: .directory, api: api, keys: { [untrusted] }, consent: { status })
        await refused.load()
        #expect(refused.status == .unavailable)
        #expect(refused.permissions.isEmpty)
        #expect(!refused.canInstall)
        // An unknown Loop looks the same.
        let unknown = LoopDetailViewModel(loopId: LoopDefinitionID(), source: .link, api: api, keys: { [MockLoopsAPI.pinnedKey] }, consent: { status })
        await unknown.load()
        #expect(unknown.status == .unavailable)
    }

    @Test func aTamperedDefinitionFailsVerification() async throws {
        let (api, listed, _) = await world()
        let detail = try await api.directoryDetail(try #require(listed.loopId))
        #expect(LoopDetailViewModel.verified(detail, keys: [MockLoopsAPI.pinnedKey], now: Date()) != nil)
        var tampered = detail
        var definition = MockLoopsAPI.pickupDefinition
        definition.title = "Something else"
        tampered.definition = definition.jsonValue
        #expect(LoopDetailViewModel.verified(tampered, keys: [MockLoopsAPI.pinnedKey], now: Date()) == nil, "the hash no longer matches")
        var otherBusiness = detail
        otherBusiness.entry.business = PreviewData.harborBank
        #expect(LoopDetailViewModel.verified(otherBusiness, keys: [MockLoopsAPI.pinnedKey], now: Date()) == nil, "signed for another business")
        var expired = detail
        expired.entry.publicationId = LoopPublicationID()
        #expect(LoopDetailViewModel.verified(expired, keys: [MockLoopsAPI.pinnedKey], now: Date()) == nil, "another publication")
        #expect(LoopDetailViewModel.verified(detail, keys: [MockLoopsAPI.pinnedKey], now: Date().addingTimeInterval(40 * 86400)) == nil, "outside the window")
    }

    @Test func installOnlyNeedsLoopsTurnedOnAndOpensOnlyThatLoop() async throws {
        let (api, listed, unlisted) = await world()
        let consent = LoopConsentViewModel(api: api)
        await consent.load()
        let library = LoopLibraryViewModel(api: api, consent: { consent.status })
        let loopId = try #require(listed.loopId)
        let model = LoopDetailViewModel(loopId: loopId, source: .directory, api: api, keys: { [MockLoopsAPI.pinnedKey] }, consent: { consent.status },
                                        library: library, onConsent: { consent.adopt($0) })
        await model.load()
        #expect(model.needsGlobalConsent)
        #expect(await model.install() == .needsGlobalConsent)
        #expect(await api.installCalls == 0, "nothing is sent before the education")
        consent.adopt(try await enable(api))
        guard case .installed(let installed) = await model.install() else { Issue.record("install failed"); return }
        #expect(installed.mode == .installOnly)
        #expect(!installed.connected)
        #expect(library.isInstalled(loopId))
        #expect(model.isInstalled)
        #expect(consent.isAuthorized(Self.business.id), "the install sheet recorded the business authorization")
        // Startable from Your Loops; the business's other Loop is not.
        guard case .started(let view) = await library.start(try #require(library.loops.first)) else { Issue.record("start failed"); return }
        #expect(view.businessId == Self.business.id)
        await #expect(throws: APIError.self) {
            _ = try await api.startInstance(LoopInstanceCreateRequest(publicationId: unlisted.publicationId, entryPoint: .businessPage))
        }
        // The renderer gets the business's verified record from Your Loops (no connection to read it from).
        #expect(library.publisherRecords[Self.business.id]?.displayName == Self.business.displayName)
        #expect(LoopLibraryViewModel.subtitle(try #require(library.loops.first)) == "Built by \(Self.business.safeName) · Not connected")
        await library.load()
        #expect(LoopLibraryViewModel.subtitle(try #require(library.loops.first)) == "Built by \(Self.business.safeName) · 1 open request")
        // Uninstall cancels the open request and ends the authorization it supported.
        #expect(await library.uninstall(loopId))
        #expect(library.loops.isEmpty)
        #expect(try await api.instance(view.id).state == .cancelled)
        consent.adopt(try await api.consentStatus())
        #expect(!consent.isAuthorized(Self.business.id))
    }

    @Test func installAndConnectAlsoConnects() async throws {
        let (api, listed, unlisted) = await world()
        let consent = LoopConsentViewModel(api: api)
        consent.adopt(try await enable(api))
        let model = LoopDetailViewModel(loopId: try #require(listed.loopId), source: .link, api: api, keys: { [MockLoopsAPI.pinnedKey] },
                                        consent: { consent.status }, onConsent: { consent.adopt($0) })
        await model.load()
        #expect(model.offersConnect)
        model.mode = .installAndConnect
        guard case .installed(let installed) = await model.install() else { Issue.record("install failed"); return }
        #expect(installed.connected)
        #expect(installed.source == .link)
        // Connected: the business's other Loops open as they do for any connection.
        _ = try await api.startInstance(LoopInstanceCreateRequest(publicationId: unlisted.publicationId, entryPoint: .businessPage))
    }

    @Test func installLinksRouteToTheInstallSheetOnly() throws {
        let domain = try #require(LinkDomain("viadere.cksites.dev"))
        let id = LoopDefinitionID()
        #expect(DeepLinkRouter.route("https://viadere.cksites.dev/lp/\(id)", domain: domain) == .loopInstall(id))
        #expect(DeepLinkRouter.route("https://www.viadere.cksites.dev/lp/\(id)", domain: domain) == .loopInstall(id))
        #expect(DeepLinkRouter.route("viadere://lp/\(id)", domain: domain) == .loopInstall(id))
        #expect(DeepLinkRouter.route("https://viadere.cksites.dev/lp/\(id)?auto=install", domain: domain) == nil)
        #expect(DeepLinkRouter.route("https://viadere.cksites.dev/lp/\(id)#install", domain: domain) == nil)
        #expect(DeepLinkRouter.route("https://evil.example/lp/\(id)", domain: domain) == nil)
        #expect(DeepLinkRouter.route("viadere://lp/\(id)/extra", domain: domain) == nil)
        #expect(DeepLinkRouter.route("viadere://lp/nope", domain: domain) == nil)
    }
}
