import Foundation
import Testing
@testable import ViadereCore

/// WP-1.6 module registry and layouts; organization context, alert, mute and dedupe rules (spec C1–C5, C9.7).
@Suite("Surfaces and organization")
struct SurfaceOrganizationTests {
    func layout(_ modules: [(String, String)], template: String = "business_home", loops: Bool = false) -> (SurfaceLayout?, Set<String>) {
        let value: JSONValue = .object(["v": .integer(1), "template": .string(template),
                                        "modules": .array(modules.map { .object(["module": .string($0.0), "size": .string($0.1)]) })])
        let (l, issues) = SurfaceLayout.validate(value, loopsEnabled: loops)
        return (l, Set(issues.map(\.code)))
    }

    // MARK: Module layouts (WP-1.6 tests first)

    @Test func validLayoutRoundTrips() {
        let (l, issues) = layout([("profile", "regular"), ("message", "compact"), ("offers", "regular"), ("approvals", "compact")])
        #expect(issues.isEmpty)
        #expect(l?.modules.map(\.module) == ["profile", "message", "offers", "approvals"])
        #expect(SurfaceLayout.validate(l!.jsonValue).layout == l)
    }

    @Test func unknownDuplicateAndMissingProfileAreRejected() {
        #expect(layout([("profile", "regular"), ("casino", "regular")]).1.contains("unknown_module"))
        #expect(layout([("profile", "regular"), ("offers", "regular"), ("offers", "compact")]).1.contains("duplicate_module"))
        #expect(layout([("offers", "regular")]).1.contains("missing_required_module"))
        #expect(layout([("offers", "regular"), ("profile", "regular")]).1.contains("required_module_not_first"))
        #expect(layout([]).1.contains("empty_layout"))
        #expect(layout([("profile", "compact")]).1.contains("size_not_supported"))
        #expect(layout([("profile", "regular")], template: "full_screen_takeover").1.contains("unknown_template"))
    }

    @Test func businessCannotInfluenceNavigation() {
        // No member for tabs, navigation, deep links, colors or code: all refused.
        for extra in ["tabs", "navigation", "deep_link", "url", "css", "script", "title"] {
            let value: JSONValue = .object(["v": .integer(1), "template": .string("business_home"), extra: .string("x"),
                                            "modules": .array([.object(["module": .string("profile"), "size": .string("regular")])])])
            #expect(SurfaceLayout.validate(value).issues.contains { $0.code == ContractIssue.unknownMember }, "\(extra)")
        }
        let moduleExtra: JSONValue = .object(["v": .integer(1), "template": .string("business_home"),
                                              "modules": .array([.object(["module": .string("profile"), "size": .string("regular"), "action": .string("open_url")])])])
        #expect(SurfaceLayout.validate(moduleExtra).issues.contains { $0.code == ContractIssue.unknownMember })
        // The primary destinations do not depend on businesses.
        #expect(OrganizationDestination.primary == [.messages, .alerts, .benefits, .businesses])
    }

    @Test func gatedAndReservedModules() {
        #expect(layout([("profile", "regular"), ("loops", "regular")]).1.contains("module_not_enabled"))
        #expect(layout([("profile", "regular"), ("loops", "regular")], loops: true).1.isEmpty)
        // shop is data only until WP-4.6 (FX-5), and its handoff is the Shopify checkout.
        #expect(layout([("profile", "regular"), ("shop", "regular")], loops: true).1.contains("module_reserved"))
        let shop = ModuleRegistry.v1.module("shop")!
        #expect(shop.handoff == .shop && shop.availability == .reserved && shop.permissions.contains(.externalHandoff))
    }

    @Test func widgetsUseConstrainedSlots() {
        #expect(layout([("offers", "compact")], template: "widget_small").1.isEmpty)
        #expect(layout([("offers", "compact"), ("rewards", "compact")], template: "widget_small").1.contains("too_many_modules"))
        #expect(layout([("approvals", "compact")], template: "widget_small").1.contains("module_not_allowed_in_template"))
        #expect(layout([("offers", "regular")], template: "widget_small").1.contains("size_not_allowed_in_template"))
    }

    @Test func everyModuleDeclaresItsContract() {
        for m in ModuleRegistry.v1.modules {
            #expect(!m.sizes.isEmpty && !m.permissions.isEmpty)
            #expect(m.accessibility.minimumTouchTargetPoints >= 44)
            #expect(!m.accessibility.headingLabel.isEmpty)
            #expect(m.platforms["ios"] != nil && m.platforms["android"] == .specOnly)
        }
        #expect(Set(ModuleRegistry.v1.modules.map(\.id)).count == ModuleRegistry.v1.modules.count)
    }

    // MARK: Organization context (C3.5, C9.7)

    @Test func sensitiveFlowsNeverSwitchContextSilently() {
        let connected: Set<BusinessID> = [FX.business, FX.otherBusiness]
        var state = OrganizationContextState(saved: .business(FX.business))
        state.beginSensitiveFlow()
        // MFA for B while browsing A: the sheet shows B itself; the context does not move under it.
        let r1 = state.open(itemFrom: FX.otherBusiness, connected: connected)
        #expect(r1 == .deferredSensitiveFlow)
        let r2 = state.select(.all, connected: connected)
        #expect(r2 == .deferredSensitiveFlow)
        let r3 = state.returnToSaved()
        #expect(r3 == .deferredSensitiveFlow)
        #expect(state.effective == .business(FX.business))
        state.endSensitiveFlow()
        let r4 = state.select(.all, connected: connected)
        #expect(r4 == .changed)
    }

    @Test func pushForAnotherBusinessShowsTemporarilyWithoutRewritingSavedContext() {
        let connected: Set<BusinessID> = [FX.business, FX.otherBusiness]
        var state = OrganizationContextState(saved: .business(FX.business))
        let r5 = state.open(itemFrom: FX.otherBusiness, connected: connected)
        #expect(r5 == .changed)
        #expect(state.effective == .business(FX.otherBusiness))
        #expect(state.saved == .business(FX.business))
        #expect(state.showsTemporaryBanner)
        let r6 = state.returnToSaved()
        #expect(r6 == .changed)
        #expect(state.effective == .business(FX.business) && !state.showsTemporaryBanner)
        // Opening an item of the saved business needs no banner.
        let r7 = state.open(itemFrom: FX.business, connected: connected)
        #expect(r7 == .unchanged)
    }

    @Test func selectorCannotPickUnconnectedBusinesses() {
        var state = OrganizationContextState()
        #expect(state.effective == .all)
        let stranger = BusinessID()
        let r8 = state.select(.business(stranger), connected: [FX.business])
        #expect(r8 == .notConnected)
        let r9 = state.open(itemFrom: stranger, connected: [FX.business])
        #expect(r9 == .notConnected)
        #expect(state.effective == .all)
        let r10 = state.select(.business(FX.business), connected: [FX.business])
        #expect(r10 == .changed)
        state.businessDisconnected(FX.business)
        #expect(state.effective == .all)
    }

    @Test func contextEncodesAsAFilterOnly() throws {
        let data = try JSONEncoder().encode(OrganizationContext.business(FX.business))
        #expect(try JSONDecoder().decode(OrganizationContext.self, from: data) == .business(FX.business))
        #expect(OrganizationContext.all.businessFilter == nil)
        #expect(OrganizationContext.business(FX.business).businessFilter == FX.business)
        #expect(OrganizationDestination.settings.isFilteredByContext == false)
    }

    // MARK: Alerts (C5)

    func alert(_ status: AlertStatus = .pending, expires: TimeInterval? = 3600, business: BusinessID? = FX.business,
               purpose: InteractionPurpose = .transactional, actionRequired: Bool = true) -> AlertItem {
        AlertItem(source: .interaction, sourceId: "i-1", businessId: business, purpose: purpose, status: status,
                  expiresAt: expires.map { FX.now.addingTimeInterval($0) }, actionRequired: actionRequired, updatedAt: FX.now)
    }

    @Test func expiredAlertsAreNeverActionable() {
        #expect(AlertRules.isActionable(alert(), now: FX.now, businessStatus: .verified))
        // Stored as pending in a stale cache, but past expiry.
        let stale = alert(expires: -1)
        #expect(!AlertRules.isActionable(stale, now: FX.now, businessStatus: .verified))
        #expect(AlertRules.displayStatus(stale, now: FX.now) == .expired)
        #expect(AlertRules.matches(stale, context: .all, status: .expired, now: FX.now))
        #expect(!AlertRules.matches(stale, context: .all, status: .pending, now: FX.now))
        // Exactly at expiry is expired.
        #expect(!AlertRules.isActionable(alert(expires: 0), now: FX.now, businessStatus: .verified))
        // Revoked or suspended businesses: nothing actionable (D3.T8).
        #expect(!AlertRules.isActionable(alert(), now: FX.now, businessStatus: .revoked))
        #expect(!AlertRules.isActionable(alert(), now: FX.now, businessStatus: nil))
        #expect(!AlertRules.isActionable(alert(.completed), now: FX.now, businessStatus: .verified))
        #expect(!AlertRules.isActionable(alert(actionRequired: false), now: FX.now, businessStatus: .verified))
    }

    @Test func contextFiltersAlerts() {
        let a = alert()
        #expect(AlertRules.matches(a, context: .all, status: nil, now: FX.now))
        #expect(AlertRules.matches(a, context: .business(FX.business), status: .pending, now: FX.now))
        #expect(!AlertRules.matches(a, context: .business(FX.otherBusiness), status: nil, now: FX.now))
        #expect(a.alertId == "interaction:i-1")
    }

    @Test func muteNeverSuppressesSecurityOrActionRequired() {
        for level in MuteLevel.allCases {
            #expect(!MutePolicy.silences(level, purpose: .security, actionRequired: false))
            #expect(!MutePolicy.silences(level, purpose: .accountService, actionRequired: false))
            for purpose in InteractionPurpose.allCases { #expect(!MutePolicy.silences(level, purpose: purpose, actionRequired: true)) }
            #expect(!MutePolicy.hidesFromAlerts(level))
        }
        #expect(MutePolicy.silences(.promotional, purpose: .marketing, actionRequired: false))
        #expect(!MutePolicy.silences(.promotional, purpose: .transactional, actionRequired: false))
        #expect(MutePolicy.silences(.allNonEssential, purpose: .transactional, actionRequired: false))
    }

    @Test func pushDedupeByServerEventId() {
        var seen = SeenEventSet(capacity: 3)
        let r11 = seen.insert("interaction:1")
        #expect(r11)
        let r12 = seen.insert("interaction:1")
        #expect(!r12)
        let r13 = seen.insert("interaction:2") && seen.insert("interaction:3") && seen.insert("interaction:4")
        #expect(r13)
        #expect(seen.count == 3)
        #expect(!seen.contains("interaction:1"))
        #expect(seen.contains("interaction:4"))
        let r14 = seen.insert("")
        #expect(!r14)
        let r15 = seen.insert(String(repeating: "x", count: 300))
        #expect(!r15)
    }
}
