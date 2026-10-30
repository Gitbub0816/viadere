import Foundation
import ViadereCore

/// Fictional P3 fixtures: loyalty, Wallet, orders, appointments, travel, events, acknowledgments, household.
/// Every business is invented; none represents a real company.
extension PreviewData {
    private static func id<Tag>(_ string: String) -> TypedID<Tag> { TypedID(UUID(uuidString: string) ?? UUID()) }
    private static func code(_ s: String) -> BusinessCode { BusinessCode(parsing: s) ?? BusinessCode.generate() }

    public static let juniperCoffee = BusinessSummary(
        id: id("a0000000-0000-4000-8000-000000000006"), displayName: "Juniper Coffee", handle: BusinessHandle(parsing: "@junipercoffee"),
        code: code("JC5T47"), verificationStatus: .verified)
    public static let northwindAir = BusinessSummary(
        id: id("a0000000-0000-4000-8000-000000000007"), displayName: "Northwind Air", handle: BusinessHandle(parsing: "@northwindair"),
        code: code("NW2K48"), verificationStatus: .verified)
    public static let harborHotel = BusinessSummary(
        id: id("a0000000-0000-4000-8000-000000000008"), displayName: "Harbor Hotel", handle: BusinessHandle(parsing: "@harborhotel"),
        code: code("HH6P31"), verificationStatus: .verified)
    public static let lumenTheater = BusinessSummary(
        id: id("a0000000-0000-4000-8000-000000000009"), displayName: "Lumen Theater", handle: BusinessHandle(parsing: "@lumentheater"),
        code: code("LT9R52"), verificationStatus: .verified)

    public static let p3Businesses: [BusinessSummary] = [juniperCoffee, northwindAir, harborHotel, lumenTheater]

    // Wallet pass ids (stable so previews and tests can refer to them).
    public static let loyaltyPassId: WalletPassID = id("c0000000-0000-4000-8000-000000000001")
    public static let boardingPassId: WalletPassID = id("c0000000-0000-4000-8000-000000000002")
    public static let eventPassId: WalletPassID = id("c0000000-0000-4000-8000-000000000003")
    public static let reservationPassId: WalletPassID = id("c0000000-0000-4000-8000-000000000004")
    public static let couponPassId: WalletPassID = id("c0000000-0000-4000-8000-000000000005")

    public static let passTypeLoyalty = "pass.com.viadere.loyalty"
    public static let passTypeTicket = "pass.com.viadere.ticket"

    public static func walletPass(_ passId: WalletPassID, business: BusinessSummary, kind: WalletPassKind, now: Date = Date()) -> WalletPassMetadata {
        WalletPassMetadata(id: passId, businessId: business.id, kind: kind,
                           passTypeIdentifier: kind == .storeCard || kind == .coupon ? passTypeLoyalty : passTypeTicket,
                           serialNumber: "SN-" + passId.description.prefix(8).uppercased(), updatedAt: now)
    }

    private static func scope(_ relationship: RelationshipID, account: String? = nil) -> RelationshipScope {
        RelationshipScope(consumerId: consumerId, relationshipId: relationship, accountReference: account)
    }

    private static func status(_ business: BusinessSummary, relationship: RelationshipID, now: Date, title: String, body: String?,
                               live: LiveActivityStatus?, correlation: String, purpose: InteractionPurpose = .transactional,
                               ageMinutes: Double = 0, lifetime: TimeInterval = 21_600) -> InteractionEnvelope {
        let interaction = Interaction(
            businessId: business.id, scope: scope(relationship), purpose: purpose,
            payload: .status(StatusPayload(title: title, body: body, liveActivity: live)),
            priority: .normal, sensitivity: .low, createdAt: now.addingTimeInterval(-ageMinutes * 60),
            expiresAt: now.addingTimeInterval(lifetime), idempotencyKey: UUID().uuidString, correlationId: correlation)
        return InteractionEnvelope(interaction: interaction, business: business, status: .delivered)
    }

    // MARK: Orders and deliveries

    public static func orderStatus(now: Date = Date(), stage: OrderActivityState.Stage = .preparing, business: BusinessSummary = juniperCoffee,
                                   relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let state = OrderActivityState(orderReference: "1042", stage: stage, estimatedReadyAt: now.addingTimeInterval(8 * 60))
        let title = stage == .ready ? "Order 1042 is ready" : "Order 1042 is being prepared"
        return status(business, relationship: relationship, now: now, title: title, body: "Two items · pick up at the counter",
                      live: .order(state), correlation: "order-1042", ageMinutes: 3)
    }

    public static func deliveryStatus(now: Date = Date(), business: BusinessSummary = northfield,
                                      relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let state = DeliveryActivityState(trackingReference: "NM-7731", stage: .outForDelivery, carrierName: "Northfield Delivery",
                                          estimatedDeliveryAt: now.addingTimeInterval(25 * 60), stopsAway: 3)
        return status(business, relationship: relationship, now: now, title: "Your delivery is out", body: "Leave at the front door.",
                      live: .delivery(state), correlation: "ship-7731", ageMinutes: 12)
    }

    // MARK: Appointments

    public static func appointmentStatus(now: Date = Date(), stage: AppointmentActivityState.Stage = .checkInOpen,
                                         business: BusinessSummary = lindenStudio,
                                         relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let state = AppointmentActivityState(title: "Haircut with Maya", startsAt: now.addingTimeInterval(50 * 60),
                                             location: "Suite 210", providerName: business.displayName, stage: stage)
        return status(business, relationship: relationship, now: now, title: "Check-in is open", body: "Suite 210 · starts in 50 minutes",
                      live: .appointment(state), correlation: "appt-8841", ageMinutes: 5)
    }

    public static func appointmentCheckIn(now: Date = Date(), business: BusinessSummary = lindenStudio,
                                          relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let payload = ConfirmPayload(title: "Check in for your haircut", details: "Today, \(now.addingTimeInterval(3_000).formatted(date: .omitted, time: .shortened)) · Suite 210",
                                     reference: "8841", scheduledAt: now.addingTimeInterval(3_000))
        let interaction = Interaction(
            businessId: business.id, scope: scope(relationship), purpose: .transactional, payload: .confirm(payload),
            requestedActions: [RequestedAction(id: "check_in", label: "Check in", role: .confirm),
                               RequestedAction(id: "cancel", label: "Cancel visit", role: .decline)],
            sensitivity: .low, createdAt: now.addingTimeInterval(-240), expiresAt: now.addingTimeInterval(3_600),
            idempotencyKey: UUID().uuidString, correlationId: "appt-8841")
        return InteractionEnvelope(interaction: interaction, business: business, status: .pending)
    }

    public static func appointmentReschedule(now: Date = Date(), business: BusinessSummary = lindenStudio,
                                             relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let payload = ChoosePayload(prompt: "Need a different time?", options: [
            ChoiceOption(id: "tue_9", label: "Tue 9:00"), ChoiceOption(id: "wed_14", label: "Wed 2:30"), ChoiceOption(id: "fri_11", label: "Fri 11:15")])
        let interaction = Interaction(
            businessId: business.id, scope: scope(relationship), purpose: .transactional, payload: .choose(payload),
            sensitivity: .low, createdAt: now.addingTimeInterval(-239), expiresAt: now.addingTimeInterval(3_600),
            idempotencyKey: UUID().uuidString, correlationId: "appt-8841")
        return InteractionEnvelope(interaction: interaction, business: business, status: .pending)
    }

    // MARK: Travel

    public static func northwindFlight(now: Date = Date(), stage: FlightActivityState.Stage = .delayed, business: BusinessSummary = northwindAir,
                                       relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let flight = FlightActivityState(flightNumber: "NW 482", departureAirport: "PHX", arrivalAirport: "SEA", stage: stage,
                                         scheduledDeparture: now.addingTimeInterval(7_200), estimatedDeparture: now.addingTimeInterval(8_700),
                                         gate: "B12", seat: "14A")
        return status(business, relationship: relationship, now: now, title: "Flight NW 482 delayed",
                      body: "Now departing later from gate B12.", live: .flight(flight), correlation: "NW482", ageMinutes: 8)
    }

    /// A rebooking offer with a fare difference: money, so it always goes through the secure approval sheet.
    public static func rebookOffer(now: Date = Date(), business: BusinessSummary = northwindAir,
                                   relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let payload = AuthorizePayload(
            actionDescription: "Rebook on NW 518 at 8:40 PM", amount: try? MoneyAmount(string: "48.00", currency: .usd),
            merchant: business.displayName, location: nil, effectOfApproval: "You'll move to NW 518 and be charged the fare difference.")
        let interaction = Interaction(
            businessId: business.id, scope: scope(relationship, account: "Booking K7QX2M"), purpose: .transactional,
            payload: .authorize(payload),
            requestedActions: [RequestedAction(id: "approve", label: "Rebook", role: .approve),
                               RequestedAction(id: "deny", label: "Keep my flight", role: .deny)],
            priority: .high, sensitivity: .high, createdAt: now.addingTimeInterval(-420), expiresAt: now.addingTimeInterval(1_800),
            idempotencyKey: UUID().uuidString, correlationId: "NW482")
        return InteractionEnvelope(interaction: interaction, business: business, status: .pending)
    }

    public static func boardingPass(now: Date = Date(), business: BusinessSummary = northwindAir,
                                    relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let payload = TicketPayload(title: "Boarding pass · PHX to SEA", ticketType: "boarding_pass", holderName: "Jordan Lee",
                                    validFrom: now.addingTimeInterval(7_200), validUntil: now.addingTimeInterval(9_000), walletPassId: boardingPassId)
        let interaction = Interaction(
            businessId: business.id, scope: scope(relationship), purpose: .transactional, payload: .ticket(payload),
            sensitivity: .low, createdAt: now.addingTimeInterval(-3_600), expiresAt: now.addingTimeInterval(21_600),
            idempotencyKey: UUID().uuidString, correlationId: "NW482")
        return InteractionEnvelope(interaction: interaction, business: business, status: .delivered)
    }

    public static func hotelReservation(now: Date = Date(), business: BusinessSummary = harborHotel,
                                        relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let payload = TicketPayload(title: "Harbor Hotel · 2 nights", ticketType: "reservation", holderName: "Jordan Lee",
                                    validFrom: now.addingTimeInterval(3 * 86_400), validUntil: now.addingTimeInterval(5 * 86_400),
                                    walletPassId: reservationPassId)
        let interaction = Interaction(
            businessId: business.id, scope: scope(relationship), purpose: .transactional, payload: .ticket(payload),
            sensitivity: .low, createdAt: now.addingTimeInterval(-86_400), expiresAt: now.addingTimeInterval(6 * 86_400),
            idempotencyKey: UUID().uuidString, correlationId: "stay-5520")
        return InteractionEnvelope(interaction: interaction, business: business, status: .delivered)
    }

    // MARK: Events

    public static func eventTicket(now: Date = Date(), business: BusinessSummary = lumenTheater,
                                   relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let payload = TicketPayload(title: "The Lantern Keeper · Row F, Seat 12", ticketType: "event", holderName: "Jordan Lee",
                                    validFrom: now.addingTimeInterval(2 * 86_400), validUntil: now.addingTimeInterval(2 * 86_400 + 10_800),
                                    walletPassId: eventPassId)
        let interaction = Interaction(
            businessId: business.id, scope: scope(relationship), purpose: .transactional, payload: .ticket(payload),
            sensitivity: .low, createdAt: now.addingTimeInterval(-2 * 86_400), expiresAt: now.addingTimeInterval(3 * 86_400),
            idempotencyKey: UUID().uuidString, correlationId: "evt-lumen-1")
        return InteractionEnvelope(interaction: interaction, business: business, status: .delivered)
    }

    public static func eventScheduleChange(now: Date = Date(), business: BusinessSummary = lumenTheater,
                                           relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        status(business, relationship: relationship, now: now, title: "Doors now open at 6:30 PM",
               body: "Curtain moved to 7:45 PM. Enter through the Elm Street lobby. Parking is in the Court Street garage.",
               live: nil, correlation: "evt-lumen-1", ageMinutes: 90, lifetime: 3 * 86_400)
    }

    // MARK: Acknowledgment

    public static func acknowledge(now: Date = Date(), business: BusinessSummary = harborHotel,
                                   relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let payload = AcknowledgePayload(
            title: "Room upgrade estimate",
            body: "Upgrade to a harbor-view suite for the nights of your stay. Estimated total change: $96.00 plus tax, charged at check-out. "
                + "Cancel any time before arrival at no cost. This estimate may change if your dates change.",
            documentURL: URL(string: "https://example.com/estimates/5520"), documentVersion: "2026-10")
        let interaction = Interaction(
            businessId: business.id, scope: scope(relationship, account: "Stay 5520"), purpose: .transactional, payload: .acknowledge(payload),
            requestedActions: [RequestedAction(id: "acknowledge", label: "Acknowledge", role: .acknowledge),
                               RequestedAction(id: "decline", label: "Decline", role: .decline)],
            sensitivity: .standard, createdAt: now.addingTimeInterval(-1_800), expiresAt: now.addingTimeInterval(3 * 86_400),
            idempotencyKey: UUID().uuidString, correlationId: "stay-5520")
        return InteractionEnvelope(interaction: interaction, business: business, status: .pending)
    }
}
