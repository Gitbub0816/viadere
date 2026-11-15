import Foundation
import Testing
@testable import ViadereCore

/// WP-1.1 contracts: the alert list query and cursor, actionability of list rows, benefits filters, the Businesses directory rules and the
/// renderable business home (SECURITY.md §2.96).
@Suite("Organization API contracts")
struct OrganizationAPITests {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)

    func business(_ name: String, status: VerificationStatus = .verified, handle: String? = nil) -> BusinessSummary {
        BusinessSummary(id: BusinessID(), displayName: name, handle: handle.flatMap { try? BusinessHandle($0) }, code: BusinessCode.generate(),
                        verificationStatus: status)
    }

    func entry(status: AlertStatus = .pending, expiresAt: Date? = now.addingTimeInterval(300), actionable: Bool = true,
               business: BusinessSummary? = nil, target: AlertTarget? = AlertTarget(kind: .interaction, id: UUID().uuidString.lowercased())) -> AlertEntry {
        let id = UUID()
        return AlertEntry(alertId: AlertIdentifier.make(.interaction, id), eventId: AlertDescriptor.eventId(kind: "interaction", id: id), source: .interaction,
                          business: business ?? self.business("Shop"), purpose: .transactional, category: .request, urgency: .normal, status: status,
                          title: "Confirm your pickup", expiresAt: expiresAt, actionRequired: true, actionable: actionable, unread: true,
                          createdAt: Self.now, updatedAt: Self.now, target: target)
    }

    // MARK: Cursor and query (strict parsing: unknown values are refused, never ignored)

    @Test func cursorRoundTripsAndOrdersByCreationThenId() throws {
        let id = AlertIdentifier.make(.interaction, UUID())
        let cursor = AlertCursor(createdAt: Self.now, alertId: id)
        let parsed = try #require(AlertCursor(encoded: cursor.encoded))
        #expect(parsed == cursor)
        #expect(cursor.precedes(createdAt: Self.now.addingTimeInterval(-1), alertId: id))
        #expect(!cursor.precedes(createdAt: Self.now.addingTimeInterval(1), alertId: id))
        #expect(!cursor.precedes(createdAt: Self.now, alertId: id))
        #expect(cursor.precedes(createdAt: Self.now, alertId: id + "z") == (id + "z" > id))
    }

    @Test func malformedCursorsAndQueriesAreRefused() {
        for raw in ["", "abc", Base64URL.encode(Data("v2|1|interaction:x".utf8)), Base64URL.encode(Data("v1|-5|interaction:\(UUID().uuidString.lowercased())".utf8)),
                    Base64URL.encode(Data("v1|5|interaction:\(UUID().uuidString)".utf8)), Base64URL.encode(Data("v1|5|casino:\(UUID().uuidString.lowercased())".utf8))] {
            #expect(AlertCursor(encoded: raw) == nil, "\(raw)")
        }
        func parse(_ values: [String: String]) -> AlertQuery? { try? AlertQuery.parse { values[$0] } }
        #expect(parse(["status": "pending"])?.status == .pending)
        #expect(parse(["status": "everything"]) == nil)
        #expect(parse(["unread": "yes"]) == nil)
        #expect(parse(["business_id": "' OR 1=1 --"]) == nil)
        #expect(parse(["limit": "500"]) == nil)
        #expect(parse(["limit": "0"]) == nil)
        #expect(parse(["since": "garbage"]) == nil)
        let business = BusinessID()
        let built = AlertQuery(status: .expired, unreadOnly: true, businessId: business, since: Self.now, limit: 10)
        let items = Dictionary(uniqueKeysWithValues: built.queryItems)
        let reparsed = parse(items)
        #expect(reparsed?.status == .expired && reparsed?.unreadOnly == true && reparsed?.businessId == business && reparsed?.limit == 10)
        #expect(reparsed?.since == Self.now)
    }

    @Test func seenRequestsAreBounded() {
        #expect(AlertSeenRequest(alertIds: [AlertIdentifier.make(.verification, UUID())]).isValid)
        #expect(!AlertSeenRequest(alertIds: []).isValid)
        #expect(!AlertSeenRequest(alertIds: ["interaction:1"]).isValid)
        #expect(!AlertSeenRequest(alertIds: (0...AlertSeenRequest.maxIds).map { _ in AlertIdentifier.make(.interaction, UUID()) }).isValid)
    }

    // MARK: Actionability: expired never actionable; a stale cache cannot resurrect anything (D3.T7, C5.3)

    @Test func expiredOrFinishedOrUnverifiedRowsAreNeverActionable() {
        #expect(entry().isActionable(at: Self.now))
        // The server said actionable when it answered, but the device clock passed the expiry since: not actionable.
        #expect(!entry(expiresAt: Self.now.addingTimeInterval(10)).isActionable(at: Self.now.addingTimeInterval(11)))
        #expect(!entry(status: .completed).isActionable(at: Self.now))
        #expect(!entry(status: .unknown).isActionable(at: Self.now))
        #expect(!entry(actionable: false).isActionable(at: Self.now))
        #expect(!entry(business: business("Gone", status: .suspended)).isActionable(at: Self.now))
        #expect(!entry(business: business("Revoked", status: .revoked)).isActionable(at: Self.now))
        #expect(!entry(target: nil).isActionable(at: Self.now))
    }

    @Test func unknownTargetKindsDecodeAsUnknown() throws {
        let json = Data(#"{"kind":"open_url","id":"https://evil.example"}"#.utf8)
        #expect(try ViadereJSON.decode(AlertTarget.self, from: json).kind == .unknown)
    }

    // MARK: Benefits filters (C6.1)

    @Test func benefitFiltersAreDisjointWhereTheyMustBe() {
        let shop = business("Bakery")
        func reward(_ status: Reward.Status, _ state: RewardEligibility.State, claimed: Bool = false) -> RewardEntry {
            RewardEntry(reward: Reward(id: RewardID(), business: shop, title: "Coffee", status: status), kind: .coupon,
                        eligibility: RewardEligibility(state: state, checkedAt: Self.now), claimedAt: claimed ? Self.now : nil)
        }
        let eligible = reward(.available, .eligible)
        let notToday = reward(.available, .notToday, claimed: true)
        let redeemed = reward(.redeemed, .redeemed)
        let expired = reward(.expired, .expired)
        let revoked = reward(.available, .revoked)
        #expect(BenefitRules.matches(eligible, filter: .available) && BenefitRules.matches(eligible, filter: .eligible))
        #expect(BenefitRules.matches(notToday, filter: .saved) && !BenefitRules.matches(notToday, filter: .eligible))
        #expect(!BenefitRules.matches(redeemed, filter: .available) && BenefitRules.matches(redeemed, filter: .redeemed))
        #expect(!BenefitRules.matches(expired, filter: .available) && BenefitRules.matches(expired, filter: .expired))
        // A revoked reward never shows as available or saved.
        #expect(!BenefitRules.matches(revoked, filter: .available) && !BenefitRules.matches(revoked, filter: .saved) && BenefitRules.matches(revoked, filter: .expired))
        #expect(BenefitRules.sorted([notToday, eligible]).first == eligible)
    }

    // MARK: Businesses directory (C3, C8, C9.2)

    @Test func favoritesComeFirstAndSearchFindsOneOfFifty() {
        var list: [ConnectedBusiness] = []
        for i in 0..<50 {
            let summary = business(String(format: "Business %02d", i), handle: String(format: "biz%02d", i))
            list.append(ConnectedBusiness(business: summary, category: .retail, relationshipId: RelationshipID(), status: .active,
                                          connectedAt: Self.now, lastActivityAt: Self.now.addingTimeInterval(Double(i)),
                                          preferences: BusinessPreferences(businessId: summary.id, favorite: i == 7)))
        }
        let ordered = BusinessDirectoryRules.ordered(list)
        #expect(ordered.first?.business.displayName == "Business 07")
        #expect(ordered[1].business.displayName == "Business 49")
        let found = ordered.filter { BusinessDirectoryRules.matches($0.business, query: "@biz33") }
        #expect(found.map(\.business.displayName) == ["Business 33"])
        #expect(ordered.filter { BusinessDirectoryRules.matches($0.business, query: "  ") }.count == 50)
        #expect(ordered.filter { BusinessDirectoryRules.matches($0.business, query: "BUSINESS 4") }.count == 10)
    }

    @Test func endedConnectionsSortAfterActiveOnes() {
        let a = business("Alpha"), b = business("Beta")
        let ended = ConnectedBusiness(business: a, category: nil, relationshipId: RelationshipID(), status: .disconnected, connectedAt: Self.now,
                                      lastActivityAt: Self.now.addingTimeInterval(100), preferences: BusinessPreferences(businessId: a.id, favorite: true))
        let active = ConnectedBusiness(business: b, category: nil, relationshipId: RelationshipID(), status: .active, connectedAt: Self.now,
                                       lastActivityAt: Self.now, preferences: BusinessPreferences(businessId: b.id))
        #expect(BusinessDirectoryRules.ordered([ended, active]).first == active)
    }

    @Test func timedMuteEnds() {
        let prefs = BusinessPreferences(businessId: BusinessID(), muteLevel: .promotional, muteUntil: Self.now.addingTimeInterval(60))
        #expect(prefs.effectiveMute(at: Self.now) == .promotional)
        #expect(prefs.effectiveMute(at: Self.now.addingTimeInterval(60)) == MuteLevel.none)
        // Mute never silences security, account service or anything that needs an answer.
        for level in MuteLevel.allCases {
            #expect(!MutePolicy.silences(level, purpose: .security, actionRequired: false))
            #expect(!MutePolicy.silences(level, purpose: .accountService, actionRequired: false))
            #expect(!MutePolicy.silences(level, purpose: .transactional, actionRequired: true))
        }
    }

    // MARK: Business home (WP-1.6): what a client renders, whatever the server sent

    @Test func renderableLayoutKeepsProfileFirstAndDropsWhatABusinessCannotHave() {
        let served = [SurfaceModule(module: "offers", size: .compact), SurfaceModule(module: "casino", size: .regular),
                      SurfaceModule(module: "loops", size: .regular), SurfaceModule(module: "shop", size: .regular),
                      SurfaceModule(module: "offers", size: .regular), SurfaceModule(module: "profile", size: .compact)]
        let modules = SurfaceLayout.renderable(served)
        #expect(modules.map(\.module) == ["profile", "offers"])
        #expect(modules[0].size == .regular)
        #expect(SurfaceLayout.renderable(served, loopsEnabled: true).map(\.module) == ["profile", "offers", "loops"])
        #expect(SurfaceLayout.renderable([]).map(\.module) == ["profile"])
    }

    @Test func defaultBusinessHomeIsAValidLayout() {
        let (layout, issues) = SurfaceLayout.validate(SurfaceLayout.defaultBusinessHome.jsonValue)
        #expect(issues.isEmpty)
        #expect(layout == SurfaceLayout.defaultBusinessHome)
        #expect(!layout!.modules.contains { $0.module == "loops" || $0.module == "shop" })
    }

    // MARK: Route catalog

    @Test func organizationRoutesAreDeviceSignedAndCatalogued() {
        let catalog = Set(APIRoutes.all.map(\.name))
        for route in APIRoutes.organizationEndpoints {
            #expect(route.auth == .deviceSignedBearer, "\(route.name)")
            #expect(catalog.contains(route.name), "\(route.name)")
        }
        #expect(Set(APIRoutes.all.map { "\($0.method.rawValue) \($0.template)" }).count == APIRoutes.all.count)
    }

    @Test func interactionKindsThatNeedAnAnswer() {
        #expect(InteractionKind.authorize.expectsResponse && InteractionKind.choose.expectsResponse)
        #expect(!InteractionKind.status.expectsResponse && !InteractionKind.reward.expectsResponse)
        #expect(AlertTitles.clip(String(repeating: "a", count: 300)).count == AlertTitles.maxLength)
        #expect(AlertTitles.clip("  \n ") == "Request")
    }
}
