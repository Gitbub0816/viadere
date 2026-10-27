import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

@Suite("Watch bridge and push registration")
struct WatchAndPushTests {
    @Test func watchItemsAreMinimalAndFlagPhoneOnlyApprovals() {
        let now = ViadereDate.truncatedToMilliseconds(Date())
        let content = HomeContent.build(interactions: [PreviewData.authorize(now: now), PreviewData.choose(now: now), PreviewData.confirm(now: now)],
                                        relationships: [], now: now)
        let items = WatchSync.items(from: content, now: now)
        #expect(items.count == 3)
        let money = items.first { $0.kindLabel == "Approval request" }
        #expect(money?.requiresPhone == true)
        #expect(money?.isSecurity == true)
        #expect(items.first { $0.kindLabel == "Choice" }?.options.count == 3)
        #expect(items.first { $0.kindLabel == "Confirmation" }?.requiresPhone == false)
        let data = WatchSync.encode(items)
        #expect(WatchSync.decode(data ?? Data()) == items)
        // nothing secret in the payload
        let text = String(decoding: data ?? Data(), as: UTF8.self)
        #expect(!text.contains("challenge"))
    }

    @Test func watchActionsGoThroughNotificationPolicy() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let auth = PreviewData.authorize(sensitivity: .low)
        await api.add(auth)
        let approve = WatchActionRequest(interactionId: auth.id.description, decision: .approve)
        #expect(await WatchSync.handle(approve, using: services.notificationHandler) == .requiresApp(auth.id))
        let choose = PreviewData.choose()
        await api.add(choose)
        let pick = WatchActionRequest(interactionId: choose.id.description, decision: .select, optionId: "fri_11")
        #expect(await WatchSync.handle(pick, using: services.notificationHandler) == .submitted(choose.id, .selected))
        #expect(await WatchSync.handle(WatchActionRequest(interactionId: "bad", decision: .deny), using: services.notificationHandler) == .ignored)
        let roundTrip = WatchSync.decodeRequest(WatchSync.encode(pick) ?? Data())
        #expect(roundTrip == pick)
    }

    @Test func watchResultsRoundTrip() {
        #expect(WatchActionResult(.submitted(InteractionID(), .denied)) == .done)
        #expect(WatchActionResult(.requiresApp(InteractionID())) == .needsPhone)
        #expect(WatchActionResult(.expired(InteractionID())) == .expired)
        for result in [WatchActionResult.done, .needsPhone, .stale, .expired, .failed] {
            #expect(WatchSync.decodeResult(WatchSync.encode(result)) == result)
        }
        #expect(WatchSync.decodeResult(Data("garbage".utf8)) == .failed)
    }

    @Test func pushTokensAreHexAndRegistered() async throws {
        #expect(PushRegistrar.hex(Data([0xAB, 0x01, 0xFF])) == "ab01ff")
        let api = MockViadereAPI(seed: false)
        let registrar = PushRegistrar(api: api, configuration: .local)
        try await registrar.registerAPNs(deviceToken: Data([1, 2, 3]))
        try await registrar.registerLiveActivity(activityId: "a1", businessId: PreviewData.juniperAir.id, interactionId: InteractionID(), pushToken: Data([9]))
        try await registrar.registerPushToStart(pushToken: Data([7]))
        let apns = await api.registeredAPNsTokens
        #expect(apns.first?.token == "010203")
        #expect(apns.first?.environment == .sandbox)
        let activity = await api.liveActivityTokens
        #expect(activity.map(\.kind) == [.update, .pushToStart])
    }

    @Test func liveActivityLifecycle() {
        let running = PreviewData.flightStatus().interaction
        if case .update = LiveActivityDecision.decide(for: running, isRunning: true) {} else { Issue.record("expected update") }
        if case .start = LiveActivityDecision.decide(for: running, isRunning: false) {} else { Issue.record("expected start") }
        // marketing never drives a Live Activity
        let promo = Interaction(
            businessId: PreviewData.juniperAir.id, scope: RelationshipScope(consumerId: PreviewData.consumerId, relationshipId: RelationshipID()),
            purpose: .marketing, payload: .status(StatusPayload(title: "Sale", liveActivity: .order(OrderActivityState(orderReference: "1", stage: .placed)))),
            createdAt: Date(), expiresAt: Date().addingTimeInterval(60), idempotencyKey: "p")
        #expect(LiveActivityDecision.decide(for: promo, isRunning: false) == .ignore)
        let landed = LiveActivityStatus.delivery(DeliveryActivityState(trackingReference: "T", stage: .delivered))
        let done = Interaction(
            businessId: PreviewData.juniperAir.id, scope: RelationshipScope(consumerId: PreviewData.consumerId, relationshipId: RelationshipID()),
            purpose: .transactional, payload: .status(StatusPayload(title: "Delivered", liveActivity: landed)),
            createdAt: Date(), expiresAt: Date().addingTimeInterval(60), idempotencyKey: "d")
        #expect(LiveActivityDecision.decide(for: done, isRunning: true) == .end(landed))
        #expect(LiveActivityDecision.decide(for: done, isRunning: false) == .ignore)
    }
}

@Suite("Live Activity presentation")
struct LiveActivityPresentationTests {
    @Test func flight() {
        let when = Date(timeIntervalSince1970: 1_800_000_000)
        let p = LiveActivityPresentation(status: .flight(FlightActivityState(
            flightNumber: "JA 482", departureAirport: "PHX", arrivalAirport: "SEA", stage: .delayed, scheduledDeparture: when,
            estimatedDeparture: when.addingTimeInterval(1_500), gate: "B12")), businessName: "Juniper Air")
        #expect(p.headline == "JA 482 · PHX to SEA")
        #expect(p.detail == "Delayed · Gate B12")
        #expect(p.isAlert)
        #expect(p.target == when.addingTimeInterval(1_500))
        #expect(p.symbol == "airplane")
    }

    @Test func deliveryStops() {
        let p = LiveActivityPresentation(status: .delivery(DeliveryActivityState(
            trackingReference: "T1", stage: .outForDelivery, carrierName: "Parcelwise", stopsAway: 3)), businessName: "x")
        #expect(p.detail == "Out for delivery · 3 stops away")
        #expect(p.compact == "3 stops")
        #expect(p.headline == "Parcelwise delivery")
        #expect(p.progress == 0.8)
    }

    @Test func orderAndAppointment() {
        let order = LiveActivityPresentation(status: .order(OrderActivityState(orderReference: "1042", stage: .ready)), businessName: "Copperline Coffee")
        #expect(order.detail == "Ready for pickup")
        #expect(order.headline == "Order 1042")
        let appointment = LiveActivityPresentation(status: .appointment(AppointmentActivityState(
            title: "Dental cleaning", startsAt: Date(), providerName: "Linden Dental", stage: .checkInOpen)), businessName: "Linden Dental")
        #expect(appointment.detail == "Check-in is open · Linden Dental")
        #expect(!appointment.isAlert)
        #expect(LiveActivityPresentation(status: .order(OrderActivityState(orderReference: "1", stage: .cancelled)), businessName: "x").progress == nil)
    }
}
