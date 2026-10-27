import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

@Suite("Activity feed")
struct ActivityFeedTests {
    private let now = tuesdayNoon

    private func world() -> (interactions: [InteractionEnvelope], rel: (BusinessSummary) -> RelationshipID) {
        var rels: [BusinessID: RelationshipID] = [:]
        func rel(_ b: BusinessSummary) -> RelationshipID {
            if let r = rels[b.id] { return r }
            let r = RelationshipID(); rels[b.id] = r; return r
        }
        let list: [InteractionEnvelope] = [
            PreviewData.orderStatus(now: now, relationship: rel(PreviewData.juniperCoffee)),
            PreviewData.appointmentStatus(now: now, relationship: rel(PreviewData.lindenDental)),
            PreviewData.appointmentCheckIn(now: now, relationship: rel(PreviewData.lindenDental)),
            PreviewData.appointmentReschedule(now: now, relationship: rel(PreviewData.lindenDental)),
            PreviewData.northwindFlight(now: now, relationship: rel(PreviewData.northwindAir)),
            PreviewData.rebookOffer(now: now, relationship: rel(PreviewData.northwindAir)),
            PreviewData.boardingPass(now: now, relationship: rel(PreviewData.northwindAir)),
            PreviewData.hotelReservation(now: now, relationship: rel(PreviewData.harborHotel)),
            PreviewData.eventTicket(now: now, relationship: rel(PreviewData.lumenTheater)),
            PreviewData.eventScheduleChange(now: now, relationship: rel(PreviewData.lumenTheater)),
            // not Activity: a security approval and a sign-in belong on Home
            PreviewData.authorize(now: now), PreviewData.authenticate(now: now),
        ]
        return (list, rel)
    }

    @Test func groupsByBusinessAndMergesCorrelatedInteractions() throws {
        let content = ActivityFeed.build(interactions: world().interactions, now: now)
        let names = content.groups.map(\.business.displayName)
        #expect(Set(names) == ["Juniper Coffee", "Linden Dental", "Northwind Air", "Harbor Hotel", "Lumen Theater"])
        #expect(!names.contains("Harbor Bank") && !names.contains("Northfield Market"))
        let dental = try #require(content.groups.first { $0.business.id == PreviewData.lindenDental.id })
        #expect(dental.items.count == 1)   // status + check-in + reschedule are one appointment
        let appointment = dental.items[0]
        #expect(appointment.category == .appointment && appointment.phase == .needsYou)
        #expect(appointment.pending.count == 2)
    }

    @Test func appointmentActionsAreConfirmCancelRescheduleAndCheckIn() throws {
        let content = ActivityFeed.build(interactions: world().interactions, now: now)
        let appointment = try #require(content.allItems.first { $0.category == .appointment })
        let labels = appointment.actions.map(\.label)
        #expect(labels.contains("Check in") && labels.contains("Cancel visit"))     // from the business's requestedActions
        #expect(labels.contains("Tue 9:00") && labels.contains("Fri 11:15"))        // reschedule options
        let checkIn = try #require(appointment.actions.first { $0.label == "Check in" })
        #expect(checkIn.decision == .confirm && checkIn.isPrimary && checkIn.route == .inline)
        let cancel = try #require(appointment.actions.first { $0.label == "Cancel visit" })
        #expect(cancel.decision == .decline)
        let reschedule = try #require(appointment.actions.first { $0.label == "Wed 2:30" })
        #expect(reschedule.decision == .select && reschedule.selectedOptionIds == ["wed_14"] && reschedule.route == .inline)
    }

    @Test func rebookingThatCostsMoneyRoutesThroughTheSecureSheet() throws {
        let content = ActivityFeed.build(interactions: world().interactions, now: now)
        let trip = try #require(content.allItems.first { $0.category == .travel })
        #expect(trip.phase == .needsYou && trip.isAlert)       // delayed flight
        #expect(trip.title == "Flight NW 482 delayed")
        #expect(trip.actions.count == 1 && trip.actions[0].route == .secureSheet)
        #expect(trip.walletPassId == PreviewData.boardingPassId)
    }

    @Test func routerRules() {
        let relationship = RelationshipID()
        // identity / money / security: always the sheet
        #expect(ActivityActionRouter.route(for: PreviewData.authorize().interaction, category: .order) == .secureSheet)
        #expect(ActivityActionRouter.route(for: PreviewData.authenticate().interaction, category: .other) == .secureSheet)
        // travel prompts: the sheet even when they look harmless
        #expect(ActivityActionRouter.route(for: PreviewData.appointmentCheckIn(relationship: relationship).interaction, category: .travel) == .secureSheet)
        #expect(ActivityActionRouter.route(for: PreviewData.appointmentCheckIn(relationship: relationship).interaction, category: .appointment) == .inline)
        // anything above low sensitivity: the sheet
        var standard = PreviewData.appointmentCheckIn(relationship: relationship)
        standard.interaction.sensitivity = .standard
        #expect(ActivityActionRouter.route(for: standard.interaction, category: .appointment) == .secureSheet)
        // security purpose: the sheet
        var security = PreviewData.appointmentCheckIn(relationship: relationship)
        security.interaction.purpose = .security
        #expect(ActivityActionRouter.route(for: security.interaction, category: .appointment) == .secureSheet)
    }

    @Test func eventsShowTicketsScheduleChangesAndVenueInfo() throws {
        let content = ActivityFeed.build(interactions: world().interactions, now: now)
        let event = try #require(content.allItems.first { $0.category == .event })
        #expect(event.phase == .upcoming)
        #expect(event.walletPassId == PreviewData.eventPassId)
        #expect(event.venueNote?.contains("Elm Street lobby") == true)
        #expect(event.actions.isEmpty)
        let stay = try #require(content.allItems.first { $0.category == .reservation })
        #expect(stay.phase == .upcoming && stay.walletPassId == PreviewData.reservationPassId)
    }

    @Test func ordersAreActiveWithProgressAndFinishedOnesBecomePast() throws {
        let content = ActivityFeed.build(interactions: world().interactions, now: now)
        let order = try #require(content.allItems.first { $0.category == .order })
        #expect(order.phase == .active && order.progress != nil && order.statusText?.contains("Being prepared") == true)

        let done = PreviewData.orderStatus(now: now, stage: .completed)
        let past = ActivityFeed.build(interactions: [done], now: now)
        #expect(past.allItems.first?.phase == .past)
        // old finished items fall out of the calm feed
        let later = ActivityFeed.build(interactions: [done], now: now.addingTimeInterval(30 * 86_400))
        #expect(later.isEmpty)
    }

    @Test func orderingPutsWhatNeedsYouFirstAndGroupsStayTogether() {
        let content = ActivityFeed.build(interactions: world().interactions, now: now)
        // businesses with something waiting come before businesses with only upcoming or active things
        let firstPhases = content.groups.map { $0.items.first?.phase ?? .past }
        #expect(firstPhases == firstPhases.sorted())
        #expect(content.needsYouCount == 2)
    }

    @Test func filtersByCategory() {
        let content = ActivityFeed.build(interactions: world().interactions, now: now)
        #expect(content.filtered(.travel).allItems.map(\.category).allSatisfy { $0 == .travel || $0 == .reservation })
        #expect(content.filtered(.travel).allItems.count == 2)
        #expect(content.filtered(.events).allItems.count == 1)
        #expect(content.filtered(.orders).allItems.count == 1)
        #expect(content.filtered(.appointments).allItems.count == 1)
        #expect(content.filtered(.all).allItems.count == content.allItems.count)
    }

    @Test func liveActivitiesOnlyForEligibleOngoingStatuses() {
        let fixtures = world().interactions
        let candidates = ActivityLiveEligibility.candidates(from: fixtures, now: now)
        // order, appointment and flight statuses
        #expect(candidates.count == 3)
        #expect(Set(candidates.compactMap { c -> String? in if case .status(let p) = c.interaction.payload { return p.liveActivity?.type } else { return nil } }) == ["order", "appointment", "flight"])

        // marketing and rewards never drive a Live Activity
        var promo = PreviewData.orderStatus(now: now)
        promo.interaction.purpose = .marketing
        var reward = PreviewData.orderStatus(now: now)
        reward.interaction.purpose = .rewards
        #expect(ActivityLiveEligibility.candidates(from: [promo, reward], now: now).isEmpty)
        // finished or expired ones don't either
        #expect(ActivityLiveEligibility.candidates(from: [PreviewData.orderStatus(now: now, stage: .completed)], now: now).isEmpty)
        #expect(ActivityLiveEligibility.candidates(from: [PreviewData.orderStatus(now: now)], now: now.addingTimeInterval(86_400)).isEmpty)
        // a status with no live activity (a schedule change) is not a Live Activity
        #expect(ActivityLiveEligibility.candidates(from: [PreviewData.eventScheduleChange(now: now)], now: now).isEmpty)
    }
}

@Suite("Activity view model")
@MainActor
struct ActivityViewModelTests {
    @Test func loadsFeedPassesAndLiveCandidates() async throws {
        let (services, _) = await p3World()
        let model = ActivityViewModel(services: services)
        await model.load()
        #expect(model.phase == .loaded)
        // 5 P3 businesses plus the P2 fixtures' Northfield delivery and Juniper Air flight
        #expect(model.content.groups.count == 7)
        #expect(model.liveCandidates.count == 5)
        #expect(model.passes.count == 4)
        let trip = try #require(model.content.allItems.first { $0.category == .travel })
        #expect(model.pass(for: trip)?.kind == .boardingPass)
        model.filter = .events
        #expect(model.visible.allItems.count == 1)
    }

    @Test func inlineActionsAreDeviceSignedAndRefreshTheFeed() async throws {
        let (services, api) = await p3World()
        let model = ActivityViewModel(services: services)
        await model.load()
        let appointment = try #require(model.content.allItems.first { $0.category == .appointment })
        let checkIn = try #require(appointment.actions.first { $0.label == "Check in" })
        let outcome = await model.perform(checkIn, in: appointment)
        #expect(outcome == .done)
        let log = await api.decisionLog
        #expect(log.count == 1 && log[0].1 == .confirm)
        // the check-in is no longer pending, but the reschedule options still are
        let updated = try #require(model.content.allItems.first { $0.category == .appointment })
        #expect(!updated.actions.contains { $0.label == "Check in" })
    }

    @Test func rebookingDoesNotSignInlineItAsksForTheSecureSheet() async throws {
        let (services, api) = await p3World()
        let model = ActivityViewModel(services: services)
        await model.load()
        let trip = try #require(model.content.allItems.first { $0.category == .travel })
        let outcome = await model.perform(trip.actions[0], in: trip)
        #expect(outcome == .needsSecureSheet(trip.pending[0].id))
        #expect(await api.decisionLog.isEmpty)
    }

    @Test func choosingAReplacementTimeSendsASelectDecision() async throws {
        let (services, api) = await p3World()
        let model = ActivityViewModel(services: services)
        await model.load()
        let appointment = try #require(model.content.allItems.first { $0.category == .appointment })
        let wed = try #require(appointment.actions.first { $0.label == "Wed 2:30" })
        #expect(await model.perform(wed, in: appointment) == .done)
        #expect(await api.decisionLog.first?.1 == .select)
    }

    @Test func staleItemsRefreshInsteadOfFailingLoudly() async throws {
        let (services, _) = await p3World()
        let model = ActivityViewModel(services: services)
        await model.load()
        let appointment = try #require(model.content.allItems.first { $0.category == .appointment })
        let checkIn = try #require(appointment.actions.first { $0.label == "Check in" })
        // handled on another device in the meantime
        let envelope = try #require(appointment.pending.first { $0.id == checkIn.interactionId })
        _ = try await services.approvals.submit(envelope, decision: .decline)
        let outcome = await model.perform(checkIn, in: appointment)
        guard case .failed = outcome else { Issue.record("expected a calm failure"); return }
        #expect(model.message != nil)
    }

    @Test func rescheduleFallbackOnlyWhenTheBusinessSentNoOptions() async throws {
        let (services, _) = await p3World()
        let model = ActivityViewModel(services: services)
        await model.load()
        let appointment = try #require(model.content.allItems.first { $0.category == .appointment })
        #expect(!model.canAskToReschedule(appointment))   // options are present
        var bare = appointment
        bare.actions = appointment.actions.filter { $0.decision != .select }
        #expect(model.canAskToReschedule(bare))
        let trip = try #require(model.content.allItems.first { $0.category == .travel })
        #expect(!model.canAskToReschedule(trip))
    }
}

@Suite("Activity presentation")
struct ActivityPresentationTests {
    private let now = tuesdayNoon
    private let utc = TimeZone(identifier: "UTC") ?? .gmt

    private func items() -> [ActivityItem] {
        let rel = RelationshipID()
        let list = [PreviewData.orderStatus(now: now, relationship: rel), PreviewData.appointmentStatus(now: now, relationship: rel),
                    PreviewData.appointmentCheckIn(now: now, relationship: rel), PreviewData.northwindFlight(now: now, relationship: rel),
                    PreviewData.rebookOffer(now: now, relationship: rel), PreviewData.eventTicket(now: now, relationship: rel),
                    PreviewData.hotelReservation(now: now, relationship: rel)]
        return ActivityFeed.build(interactions: list, now: now).allItems
    }

    @Test func whenTextIsRelativeWhereItHelps() {
        #expect(ActivityPresentation.whenText(now.addingTimeInterval(3_600), now: now, timeZone: utc).hasPrefix("Today"))
        #expect(ActivityPresentation.whenText(now.addingTimeInterval(86_400), now: now, timeZone: utc).hasPrefix("Tomorrow"))
        #expect(ActivityPresentation.whenText(now.addingTimeInterval(-86_400), now: now, timeZone: utc) == "Yesterday")
        #expect(!ActivityPresentation.whenText(now.addingTimeInterval(5 * 86_400), now: now, timeZone: utc).contains(":"))
    }

    @Test func detailRowsAreSpecificToTheKindOfItem() throws {
        let all = items()
        let flight = try #require(all.first { $0.category == .travel })
        let flightRows = ActivityPresentation.details(flight, now: now, timeZone: utc)
        #expect(flightRows.map(\.label).prefix(3) == ["Flight", "Route", "Scheduled"])
        #expect(flightRows.contains { $0.label == "Now departing" && $0.emphasized })
        #expect(flightRows.contains { $0.label == "Gate" && $0.value == "B12" } && flightRows.contains { $0.label == "Seat" && $0.value == "14A" })

        let appointment = try #require(all.first { $0.category == .appointment })
        #expect(ActivityPresentation.details(appointment, now: now, timeZone: utc).map(\.label) == ["When", "With", "Where"])

        let event = try #require(all.first { $0.category == .event })
        let eventRows = ActivityPresentation.details(event, now: now, timeZone: utc)
        #expect(eventRows.map(\.label) == ["Holder", "Starts", "Ends"])
        let stay = try #require(all.first { $0.category == .reservation })
        #expect(ActivityPresentation.details(stay, now: now, timeZone: utc).map(\.label) == ["Holder", "Check-in", "Check-out"])
    }

    @Test func secureNoteOnlyForTravelPromptsThatOpenTheSheet() throws {
        let all = items()
        let flight = try #require(all.first { $0.category == .travel })
        #expect(ActivityPresentation.needsSecureNote(flight))
        let appointment = try #require(all.first { $0.category == .appointment })
        #expect(!ActivityPresentation.needsSecureNote(appointment))
        #expect(ActivityPresentation.secureSheetNote.contains("secure approval screen"))
    }

    @Test func rowSubtitlesStayShort() throws {
        let all = items()
        for item in all { #expect(!ActivityPresentation.rowSubtitle(item, now: now, timeZone: utc).isEmpty) }
        let event = try #require(all.first { $0.category == .event })
        #expect(ActivityPresentation.rowSubtitle(event, now: now, timeZone: utc).contains("Upcoming"))
    }
}

@Suite("App shell integration")
@MainActor
struct P3ShellTests {
    @Test func launchLoadsActivityAndTheTabCarriesAnActivityTab() async throws {
        let (services, _) = await p3World()
        let model = AppModel(services: services)
        await model.bootstrap()
        #expect(model.phase == .ready)
        #expect(AppTab.allCases.contains(.activity))
        #expect(!model.activity.content.isEmpty && model.activity.needsYouCount == 2)
        #expect(model.wallet.canAddPasses == false)    // default library: Wallet unavailable until the app supplies PassKit
        await model.rewards.load()
        #expect(model.rewards.availableCount >= 1)
    }

    @Test func walletLibraryIsInjected() async throws {
        let (services, _) = await p3World()
        let model = AppModel(services: services, walletLibrary: MockWalletLibrary())
        #expect(model.wallet.canAddPasses)
    }
}
