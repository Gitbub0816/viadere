import Foundation
import Testing
@testable import ViadereCore

/// Installable Loops (SECURITY.md §2.98 "Installed Loops"): the permission list comes from the reviewed definition only, the install link
/// parses strictly, an install stands in for the relationship and nothing else, and the new routes are device-signed.
@Suite("Loop directory and installs")
struct LoopDirectoryTests {
    static let pickup = LoopTemplateCatalog.template("pickup_time")!.definition

    @Test func permissionsListWhatTheReviewedDefinitionSends() {
        let items = LoopPermissions.derive(Self.pickup, business: "Atlas Demo", connected: false)
        #expect(items.map(\.kind) == [.sendsAnswers, .outcomeUpdates, .noProfile, .noMessaging, .expires])
        #expect(items[0].fields == ["Pickup time"])
        #expect(items[0].title == "Sends Atlas Demo what you enter")
        #expect(items.last?.title == "Each request ends after 3 days")
        let connected = LoopPermissions.derive(Self.pickup, business: "Atlas Demo", connected: true)
        #expect(connected.contains { $0.kind == .connection })
        #expect(!connected.contains { $0.kind == .noMessaging })
    }

    @Test func aLoopThatDeliversNothingSaysSo() {
        var definition = Self.pickup
        // Drop the routing from the delivering action: nothing reaches the business.
        definition.steps[1].actions[0].routing = nil
        #expect(!LoopPermissions.delivers(definition))
        let items = LoopPermissions.derive(definition, business: "Atlas", connected: false)
        #expect(items.first?.kind == .sendsNothing)
        #expect(!items.contains { $0.kind == .sendsAnswers || $0.kind == .outcomeUpdates })
    }

    @Test func fieldLabelsAreSanitizedAndDeduplicated() {
        var definition = LoopTemplateCatalog.template("callback_request")!.definition
        definition.steps[0].fields.append(LoopField(id: "again", type: .singleChoice, label: "WHAT IS IT ABOUT?",
                                                    options: [LoopOption(id: "a", label: "A"), LoopOption(id: "b", label: "B")]))
        definition.steps[0].fields.append(LoopField(id: "seen", type: .acknowledgement, label: "I read this"))
        definition.steps[0].fields.append(LoopField(id: "bidi", type: .shortText, label: "Note\u{202E}evil"))
        let labels = LoopPermissions.fieldLabels(definition)
        #expect(labels.count == 3)
        #expect(labels[0] == "What is it about?")
        #expect(labels[1] == "Best time to call")
        #expect(!labels[2].unicodeScalars.contains { $0.value == 0x202E }, "bidi controls are stripped")
    }

    @Test func durations() {
        #expect(LoopPermissions.duration(300) == "1 hour")
        #expect(LoopPermissions.duration(7200) == "2 hours")
        #expect(LoopPermissions.duration(86_400) == "24 hours")
        #expect(LoopPermissions.duration(2 * 86_400) == "2 days")
        #expect(LoopPermissions.duration(30 * 86_400) == "30 days")
    }

    @Test func installLinksParseStrictly() throws {
        let domain = try #require(LinkDomain("viadere.cksites.dev"))
        let id = LoopDefinitionID()
        let url = try #require(LoopInstallLink(loopId: id).url(domain: domain))
        #expect(url.absoluteString == "https://viadere.cksites.dev/lp/\(id.description)")
        #expect(LoopInstallLink.parse(url, domain: domain)?.loopId == id)
        #expect(LoopInstallLink.parse(URL(string: "https://www.viadere.cksites.dev/lp/\(id)/")!, domain: domain)?.loopId == id)
        for bad in ["http://viadere.cksites.dev/lp/\(id)", "https://evil.example/lp/\(id)", "https://viadere.cksites.dev.evil.example/lp/\(id)",
                    "https://viadere.cksites.dev/lp/\(id)?x=1", "https://viadere.cksites.dev/lp/\(id)#f", "https://u@viadere.cksites.dev/lp/\(id)",
                    "https://viadere.cksites.dev:8443/lp/\(id)", "https://viadere.cksites.dev/lp/\(id)/more", "https://viadere.cksites.dev/lp/not-a-uuid",
                    "https://viadere.cksites.dev/c/\(id)", "https://viadere.cksites.dev/lp/"] {
            #expect(LoopInstallLink.parse(URL(string: bad)!, domain: domain) == nil, "\(bad)")
        }
    }

    @Test func anInstallStandsInForTheRelationshipAndNothingElse() {
        let current = LoopConsentCatalog.current.version
        let both = LoopConsentState(globalTextVersion: current, businessTextVersion: current)
        func input(_ consent: LoopConsentState, relationship: Bool, install: Bool, status: VerificationStatus = .verified,
                   category: BusinessCategory = .retail, switchedOff: Bool = false, publication: LoopPublicationStatus = .active) -> LoopAccessInput {
            LoopAccessInput(consent: consent, currentConsentTextVersion: current, relationshipActive: relationship, businessStatus: status,
                            businessCategory: category, publicationStatus: publication, businessLoopsSwitchedOff: switchedOff, installActive: install)
        }
        #expect(LoopAccessPolicy.evaluate(.createInstance, input(both, relationship: false, install: false)) == .denied(.relationshipInactive))
        #expect(LoopAccessPolicy.evaluate(.createInstance, input(both, relationship: false, install: true)) == .allowed)
        #expect(LoopAccessPolicy.evaluate(.createInstance, input(both, relationship: true, install: false)) == .allowed)
        // Every other gate still applies to an install.
        #expect(LoopAccessPolicy.evaluate(.createInstance, input(.none, relationship: false, install: true)) == .denied(.globalConsentMissing))
        #expect(LoopAccessPolicy.evaluate(.createInstance, input(LoopConsentState(globalTextVersion: current), relationship: false, install: true))
                == .denied(.businessConsentMissing))
        #expect(LoopAccessPolicy.evaluate(.createInstance, input(both, relationship: false, install: true, status: .suspended)) == .denied(.businessNotVerified))
        #expect(LoopAccessPolicy.evaluate(.createInstance, input(both, relationship: false, install: true, category: .healthcare)) == .denied(.categoryRefused))
        #expect(LoopAccessPolicy.evaluate(.createInstance, input(both, relationship: false, install: true, switchedOff: true)) == .denied(.businessSwitchedOff))
        #expect(LoopAccessPolicy.evaluate(.createInstance, input(both, relationship: false, install: true, publication: .suspended)) == .denied(.publicationNotActive))
        // Exhaustive: no combination without a relationship or an install is allowed.
        for operation in LoopAccessOperation.allCases {
            for status in LoopPublicationStatus.allCases {
                #expect(LoopAccessPolicy.evaluate(operation, input(both, relationship: false, install: false, publication: status)) != .allowed)
            }
        }
    }

    @Test func routesAreDeviceSignedAndInTheCatalog() {
        #expect(APIRoutes.loopInstallEndpoints.allSatisfy { $0.auth == .deviceSignedBearer })
        for endpoint in APIRoutes.loopInstallEndpoints { #expect(APIRoutes.all.contains(endpoint)) }
        #expect(Set(APIRoutes.all.map(\.name)).count == APIRoutes.all.count)
    }

    @Test func categoriesAreClosedAndUnknownValuesDegrade() throws {
        #expect(!LoopDirectoryCategory.known.map(\.rawValue).contains { $0.contains("health") || $0.contains("medical") })
        let decoded = try JSONDecoder().decode(LoopDirectoryCategory.self, from: Data("\"pets\"".utf8))
        #expect(!decoded.isKnown)
        #expect(decoded.title == "Other")
        #expect(LoopInstallSource.link.connectSource == .link)
        #expect(LoopInstallSource.directory.connectSource == .search)
    }

    @Test func summaryStaysDecodableWithoutTheNewMembers() throws {
        let old = """
        {"publicationId":"\(LoopPublicationID())","businessId":"\(BusinessID())","revision":1,"title":"T","entryPoints":["business_page"],"authorized":true}
        """
        let summary = try JSONDecoder().decode(LoopSummary.self, from: Data(old.utf8))
        #expect(summary.loopId == nil)
        #expect(summary.installed == nil)
    }
}
