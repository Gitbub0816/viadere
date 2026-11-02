import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

actor RecordingNotices: LocalSecurityNoticePosting {
    private(set) var posted = 0
    func postDenyNotSent() async { posted += 1 }
}

@Suite("Authentication-delivery notifications (Stage 4)")
struct AuthDeliveryNotificationTests {
    let reqId = "req_01HZXK3N9"
    let deliveryId = UUID()

    func handler(api: any AuthDeliveryAPI, notices: any LocalSecurityNoticePosting = NoLocalSecurityNotices()) async -> NotificationActionHandler {
        let services = await ViadereServices.mock(api: MockViadereAPI(seed: false))
        return NotificationActionHandler(api: services.api, approvals: services.approvals, authDelivery: api, notices: notices)
    }

    // MARK: Action configuration (A6/A7 H1, ADR-0022 §5.5, ADR-0021 §4 item 5)

    @Test func approveCategoryIsReviewAndDenyOnly() throws {
        let category = AuthNotificationCategory.approveCategory
        #expect(category.identifier == "viadere.approve")
        #expect(category.actions.map(\.title) == ["Review", "Deny"])
        let review = try #require(category.actions.first)
        let deny = try #require(category.actions.last)
        // Review needs unlock (iOS unlocks first for .foreground); Deny works on a locked phone: no .authenticationRequired, no .foreground.
        #expect(review.requiresAuthentication && review.opensApp)
        #expect(!deny.requiresAuthentication && !deny.opensApp)
        // No Approve and no Report action on an approval notification; neutral style (no red on the safe action).
        #expect(!category.actions.contains { $0.identifier.hasSuffix("approve") || $0.identifier.hasSuffix("report") })
        #expect(category.actions.allSatisfy { $0.style == .normal })
    }

    @Test func linkCategoryIsOpenAndThisWasntMe() throws {
        let category = AuthNotificationCategory.linkCategory
        #expect(category.identifier == "viadere.auth.link")
        #expect(category.actions.map(\.title) == ["Open", "This wasn't me"])
        let open = try #require(category.actions.first)
        let notMe = try #require(category.actions.last)
        #expect(open.requiresAuthentication && open.opensApp)
        #expect(!notMe.requiresAuthentication && !notMe.opensApp)
        #expect(notMe.identifier == "viadere.report")
        #expect(AuthNotificationCategory.codeCategory.actions.isEmpty)
    }

    @Test func authCategoriesAreRegisteredAtLaunch() {
        let ids = Set(NotificationEnricher.registeredCategorySpecs().map(\.identifier))
        #expect(AuthNotificationCategory.all.isSubset(of: ids))
    }

    @Test func rendererRefusalsNeverNeedUnlockAndApproveForegrounds() {
        // F-14 and H1 on the legacy sign-in and approval categories the renderer produces.
        for category in NotificationEnricher.staticCategorySpecs() where category.identifier.hasPrefix("viadere.authenticate") || category.identifier.hasPrefix("viadere.authorize") {
            for action in category.actions {
                switch action.identifier {
                case "viadere.deny", "viadere.report": #expect(!action.requiresAuthentication && !action.opensApp, "\(category.identifier) \(action.identifier)")
                case "viadere.approve": #expect(action.opensApp && action.requiresAuthentication, "\(category.identifier)")
                default: break
                }
            }
        }
    }

    @Test func securityNotificationsAreNeverTimeSensitive() async throws {
        let api = MockViadereAPI(seed: false)
        let envelope = PreviewData.authenticate(sensitivity: .high)
        await api.add(envelope)
        let result = try #require(await NotificationEnricher(api: api).enrich(userInfo: ["iid": envelope.id.description]))
        #expect(result.interruptionLevel == .active)
    }

    // MARK: Tap routing (F-14, F-15)

    @Test func approvePushRoutesToTheRequestNotAlerts() {
        #expect(PushPayload.target(category: "viadere.approve", userInfo: ["req": reqId]) == .approveRequest(reqId))
        #expect(PushPayload.target(category: "viadere.approve", userInfo: [:]) == .pendingRequests)
        #expect(PushPayload.target(category: "viadere.approve", userInfo: ["req": "bad id!"]) == .pendingRequests)
        #expect(PushPayload.target(category: "viadere.approve", userInfo: ["req": String(repeating: "a", count: 65)]) == .pendingRequests)
        let iid = InteractionID()
        #expect(PushPayload.target(category: "viadere.approve", userInfo: ["iid": iid.description]) == .interaction(iid))
        #expect(PushPayload.target(category: "viadere.auth.link", userInfo: ["adl": deliveryId.uuidString]) == .authDelivery(deliveryId))
        // The category picks the key: a `req` on a link push is not followed, an `adl` on an approval push is not either.
        #expect(PushPayload.target(category: "viadere.auth.link", userInfo: ["req": reqId]) == .pendingRequests)
        #expect(PushPayload.target(category: "viadere.approve", userInfo: ["adl": deliveryId.uuidString]) == .pendingRequests)
    }

    @Test func tapAndReviewOpenTheRequest() async {
        let h = await handler(api: MockAuthDeliveryAPI())
        for action in [NotificationActionID.systemDefaultTap, "viadere.review"] {
            let outcome = await h.handle(NotificationResponseInfo(actionIdentifier: action, categoryIdentifier: "viadere.approve", userInfo: ["req": reqId]))
            #expect(outcome == .openApproveRequest(reqId))
        }
        let nothing = await h.handle(NotificationResponseInfo(actionIdentifier: NotificationActionID.systemDefaultTap, categoryIdentifier: "viadere.approve", userInfo: [:]))
        #expect(nothing == .openRequests)
        let link = await h.handle(NotificationResponseInfo(actionIdentifier: "viadere.open", categoryIdentifier: "viadere.auth.link", userInfo: ["adl": deliveryId.uuidString]))
        #expect(link == .openAuthDelivery(deliveryId))
        #expect(await h.handle(NotificationResponseInfo(actionIdentifier: NotificationActionID.systemDismiss, categoryIdentifier: "viadere.approve", userInfo: ["req": reqId])) == .ignored)
    }

    @Test func nothingEverApprovesFromAnApprovalNotification() async {
        let api = MockAuthDeliveryAPI()
        let h = await handler(api: api)
        // Even a forged `approve` action identifier only opens the request.
        let outcome = await h.handle(NotificationResponseInfo(actionIdentifier: "viadere.approve", categoryIdentifier: "viadere.approve", userInfo: ["req": reqId]))
        #expect(outcome == .openApproveRequest(reqId))
        #expect(await api.reduceCalls.isEmpty)
    }

    // MARK: Deny and This wasn't me without unlock (H1), N-09 on failure

    @Test func denyAndReportAreReduceOnlyAndNeedNoApp() async {
        let api = MockAuthDeliveryAPI()
        let h = await handler(api: api)
        let deny = await h.handle(NotificationResponseInfo(actionIdentifier: "viadere.deny", categoryIdentifier: "viadere.approve", userInfo: ["req": reqId]))
        #expect(deny == .reduced(.deny))
        let report = await h.handle(NotificationResponseInfo(actionIdentifier: "viadere.report", categoryIdentifier: "viadere.auth.link", userInfo: ["adl": deliveryId.uuidString]))
        #expect(report == .reduced(.report))
        let calls = await api.reduceCalls
        #expect(calls.count == 2)
        #expect(calls[0].0 == .approveRequest(reqId) && calls[0].1 == .deny)
        #expect(calls[1].0 == .delivery(deliveryId) && calls[1].1 == .report)
    }

    @Test func aDenyThatCannotBeSentPostsTheLocalNoticeAndIsNeverQueued() async {
        let api = MockAuthDeliveryAPI()
        await api.failReduce(with: .offline)
        let notices = RecordingNotices()
        let h = await handler(api: api, notices: notices)
        let outcome = await h.handle(NotificationResponseInfo(actionIdentifier: "viadere.deny", categoryIdentifier: "viadere.approve", userInfo: ["req": reqId]))
        #expect(outcome == .failed(nil, "Deny not sent yet. Open Viadere."))
        #expect(await notices.posted == 1)
        #expect(await api.reduceCalls.count == 1, "one attempt, no retry queue")
    }

    @Test func aDenyWithoutAUsableIdOpensTheRequestListInsteadOfGuessing() async {
        let api = MockAuthDeliveryAPI()
        let h = await handler(api: api)
        let outcome = await h.handle(NotificationResponseInfo(actionIdentifier: "viadere.deny", categoryIdentifier: "viadere.approve", userInfo: [:]))
        #expect(outcome == .openRequests)
        #expect(await api.reduceCalls.isEmpty)
    }

    @Test func theDefaultAuthDeliveryClientFailsClosed() async {
        let h = await handler(api: UnavailableAuthDeliveryAPI(), notices: RecordingNotices())
        let outcome = await h.handle(NotificationResponseInfo(actionIdentifier: "viadere.deny", categoryIdentifier: "viadere.approve", userInfo: ["req": reqId]))
        guard case .failed = outcome else { Issue.record("expected failure"); return }
    }

    // MARK: watchOS (ADR-0022 §8)

    @Test func theWatchNeverApprovesASecurityItem() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let h = services.notificationHandler
        for envelope in [PreviewData.authorize(sensitivity: .low), PreviewData.authenticate(sensitivity: .low), PreviewData.authenticate(sensitivity: .standard)] {
            await api.add(envelope)
            let approve = WatchActionRequest(interactionId: envelope.id.description, decision: .approve)
            #expect(await WatchSync.handle(approve, using: h) == .ignored, "refused, not handed to the phone")
        }
        #expect(await api.decisionLog.isEmpty)
        // A refusal from the wrist is honoured.
        let auth = PreviewData.authenticate(sensitivity: .low)
        await api.add(auth)
        let deny = await WatchSync.handle(WatchActionRequest(interactionId: auth.id.description, decision: .deny), using: h)
        #expect(deny == .submitted(auth.id, .denied))
    }

    @Test func mirroredAuthNotificationsAllowOnlyDenyAndReportFromTheWrist() async {
        let api = MockAuthDeliveryAPI()
        let h = await handler(api: api)
        let info = ["req": reqId]
        for decision in [Decision.approve, .confirm, .select, .acknowledge] {
            let request = WatchActionRequest(interactionId: "", decision: decision, categoryIdentifier: "viadere.approve", pushUserInfo: info)
            #expect(await WatchSync.handle(request, using: h) == .ignored)
        }
        #expect(await WatchSync.handle(WatchActionRequest(interactionId: "", decision: .deny, categoryIdentifier: "viadere.approve", pushUserInfo: info), using: h) == .reduced(.deny))
        #expect(await WatchSync.handle(WatchActionRequest(interactionId: "", decision: .report, categoryIdentifier: "viadere.approve", pushUserInfo: info), using: h) == .reduced(.report))
        #expect(await api.reduceCalls.count == 2)
        #expect(WatchActionResult(.reduced(.deny)) == .done)
    }

    @Test func watchItemsSayApproveOnYourIPhone() {
        let now = ViadereDate.truncatedToMilliseconds(Date())
        let content = HomeContent.build(interactions: [PreviewData.authenticate(now: now, sensitivity: .standard), PreviewData.choose(now: now)], relationships: [], now: now)
        let items = WatchSync.items(from: content, now: now)
        let security = items.first { $0.isSecurity }
        #expect(security?.approveInstruction == "Approve on your iPhone.")
        #expect(security?.watchMayApprove == false)
        #expect(security?.headline.contains("sign-in request") == true)
        #expect(items.first { !$0.isSecurity }?.approveInstruction == nil)
    }

    // MARK: Copy

    @Test func copyMatchesUXCopyAndIsolatesVariables() {
        #expect(AuthDeliveryCopy.hiddenPreviewsPlaceholder == "You have a security item.")
        #expect(AuthDeliveryCopy.n08Body == "You have a new security item. Open Viadere to review it.")
        #expect(AuthDeliveryCopy.signInTitle(business: "Acme") == "Approve sign-in to \u{2068}Acme\u{2069}?")
        #expect(AuthDeliveryCopy.denyLine == "Deny says no. This wasn't me also reports it.")
        for forbidden in ["!", "immediately", "warning", "hacked", "Decline", "Not me"] {
            #expect(!AuthDeliveryCopy.reported(business: "Acme").contains(forbidden))
            #expect(!AuthDeliveryCopy.wrongNumber.contains(forbidden))
        }
    }
}
