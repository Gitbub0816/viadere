import Foundation
import ViadereCore

/// Fictional merchants and interactions for previews, tests, the mock server and screenshots.
/// Every business here is invented; none represents a real company.
public enum PreviewData {
    private static func tid<Tag>(_ string: String) -> TypedID<Tag> { TypedID(UUID(uuidString: string) ?? UUID()) }
    private static func handle(_ s: String) -> BusinessHandle? { BusinessHandle(parsing: s) }
    private static func code(_ s: String) -> BusinessCode {
        BusinessCode(parsing: s) ?? BusinessCode.generate()
    }

    public static let consumerId: ConsumerID = tid("11111111-1111-4111-8111-111111111111")

    public static let harborBank = BusinessSummary(
        id: tid("a0000000-0000-4000-8000-000000000001"), displayName: "Harbor Bank", handle: handle("@harborbank"),
        code: code("HB7K29"), verificationStatus: .verified)
    public static let northfield = BusinessSummary(
        id: tid("a0000000-0000-4000-8000-000000000002"), displayName: "Northfield Market", handle: handle("@northfield"),
        code: code("NM4P82"), verificationStatus: .verified)
    public static let juniperAir = BusinessSummary(
        id: tid("a0000000-0000-4000-8000-000000000003"), displayName: "Juniper Air", handle: handle("@juniperair"),
        code: code("JA9X31"), verificationStatus: .verified)
    public static let lindenDental = BusinessSummary(
        id: tid("a0000000-0000-4000-8000-000000000004"), displayName: "Linden Dental", handle: handle("@lindendental"),
        code: code("LD2R56"), verificationStatus: .verified)
    public static let copperline = BusinessSummary(
        id: tid("a0000000-0000-4000-8000-000000000005"), displayName: "Copperline Coffee", handle: handle("@copperline"),
        code: code("CC8M40"), verificationStatus: .verified)

    public static let allBusinesses: [BusinessSummary] = [harborBank, northfield, juniperAir, lindenDental, copperline]

    public static func profile(for business: BusinessSummary) -> BusinessProfile {
        let category: BusinessCategory
        switch business.displayName {
        case "Harbor Bank": category = .banking
        case "Northfield Market": category = .retail
        case "Juniper Air": category = .airline
        case "Linden Dental": category = .healthcare
        default: category = .foodAndDrink
        }
        return BusinessProfile(id: business.id, displayName: business.displayName, legalName: business.displayName + " Inc.",
                               handle: business.handle, code: business.code, verificationStatus: business.verificationStatus,
                               verifiedAt: Date(timeIntervalSince1970: 1_760_000_000), category: category,
                               websiteURL: URL(string: "https://example.com"))
    }

    public static func relationship(_ business: BusinessSummary, source: ConnectSource = .code,
                                    connectedAt: Date = Date(timeIntervalSince1970: 1_760_000_000)) -> Relationship {
        Relationship(id: RelationshipID(), consumerId: consumerId, business: business, status: .active, source: source,
                     connectedAt: connectedAt)
    }

    private static func scope(_ relationship: RelationshipID, account: String? = nil) -> RelationshipScope {
        RelationshipScope(consumerId: consumerId, relationshipId: relationship, accountReference: account)
    }

    // MARK: Interactions

    /// "$285.28 at Northfield Market in or near Mesa, Arizona. Is this you?"
    public static func authorize(now: Date = Date(), sensitivity: Sensitivity = .high, expiresIn: TimeInterval = 600,
                                 amount: String = "285.28", business: BusinessSummary = northfield,
                                 relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let money = try? MoneyAmount(string: amount, currency: .usd)
        let payload = AuthorizePayload(
            actionDescription: "Card purchase", amount: money, merchant: business.displayName,
            location: "in or near Mesa, Arizona", effectOfApproval: "The purchase will go through.",
            riskIndicators: [RiskIndicator(code: "unusual_location", label: "Far from your usual location", severity: .warning)])
        let interaction = Interaction(
            businessId: business.id, scope: scope(relationship, account: "Card ••4821"), purpose: .security,
            payload: .authorize(payload),
            requestedActions: [RequestedAction(id: "approve", label: "Approve", role: .approve),
                               RequestedAction(id: "deny", label: "Deny", role: .deny)],
            priority: .high, sensitivity: sensitivity, createdAt: now, expiresAt: now.addingTimeInterval(expiresIn),
            idempotencyKey: UUID().uuidString)
        return InteractionEnvelope(interaction: interaction, business: business, status: .pending)
    }

    public static func authenticate(now: Date = Date(), sensitivity: Sensitivity = .standard, expiresIn: TimeInterval = 480,
                                    business: BusinessSummary = harborBank, relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let payload = AuthenticatePayload(
            service: "Online Banking", device: "Chrome on macOS", approximateLocation: "Lisbon, Portugal", ipRegion: "Portugal",
            attemptedAt: now.addingTimeInterval(-20),
            riskIndicators: [RiskIndicator(code: "new_device", label: "New device", severity: .warning)])
        let interaction = Interaction(
            businessId: business.id, scope: scope(relationship), purpose: .security, payload: .authenticate(payload),
            priority: .urgent, sensitivity: sensitivity, createdAt: now, expiresAt: now.addingTimeInterval(expiresIn),
            idempotencyKey: UUID().uuidString)
        return InteractionEnvelope(interaction: interaction, business: business, status: .pending)
    }

    public static func choose(now: Date = Date(), business: BusinessSummary = lindenDental,
                              relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let payload = ChoosePayload(prompt: "Which time works for your cleaning?", options: [
            ChoiceOption(id: "tue_9", label: "Tue 9:00"), ChoiceOption(id: "wed_14", label: "Wed 2:30"),
            ChoiceOption(id: "fri_11", label: "Fri 11:15")])
        let interaction = Interaction(
            businessId: business.id, scope: scope(relationship), purpose: .transactional, payload: .choose(payload),
            sensitivity: .low, createdAt: now, expiresAt: now.addingTimeInterval(86_400), idempotencyKey: UUID().uuidString)
        return InteractionEnvelope(interaction: interaction, business: business, status: .pending)
    }

    public static func confirm(now: Date = Date(), business: BusinessSummary = copperline,
                               relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let payload = ConfirmPayload(title: "Pick up your order at 4:30 PM", details: "Order 1042, two items", reference: "1042")
        let interaction = Interaction(
            businessId: business.id, scope: scope(relationship), purpose: .transactional, payload: .confirm(payload),
            sensitivity: .low, createdAt: now, expiresAt: now.addingTimeInterval(3_600), idempotencyKey: UUID().uuidString)
        return InteractionEnvelope(interaction: interaction, business: business, status: .pending)
    }

    public static func flightStatus(now: Date = Date(), business: BusinessSummary = juniperAir,
                                    relationship: RelationshipID = RelationshipID()) -> InteractionEnvelope {
        let flight = FlightActivityState(
            flightNumber: "JA 482", departureAirport: "PHX", arrivalAirport: "SEA", stage: .delayed,
            scheduledDeparture: now.addingTimeInterval(7_200), estimatedDeparture: now.addingTimeInterval(8_700), gate: "B12")
        let payload = StatusPayload(title: "Flight JA 482 delayed", body: "Now departing at 6:05 PM from gate B12.",
                                    liveActivity: .flight(flight))
        let interaction = Interaction(
            businessId: business.id, scope: scope(relationship), purpose: .transactional, payload: .status(payload),
            priority: .high, sensitivity: .low, createdAt: now, expiresAt: now.addingTimeInterval(21_600),
            idempotencyKey: UUID().uuidString)
        return InteractionEnvelope(interaction: interaction, business: business, status: .delivered)
    }

    // MARK: Conversations

    public static func conversation(for business: BusinessSummary = lindenDental, now: Date = Date()) -> (ConversationSummary, [ConversationMessage]) {
        let session = SessionID()
        func message(_ text: String, _ direction: MessageDirection, minutesAgo: Double, interaction: InteractionID? = nil) -> ConversationMessage {
            let attribution = direction == .consumerToBusiness
                ? MessageAttribution(senderType: .consumer, displayName: "You")
                : MessageAttribution(senderType: .agent, displayName: business.displayName, agentName: "Maya")
            return ConversationMessage(id: MessageID(), sessionId: session, businessId: business.id, direction: direction,
                                       attribution: attribution, body: text, channel: .inApp,
                                       createdAt: now.addingTimeInterval(-minutesAgo * 60), deliveryStatus: .delivered,
                                       interactionId: interaction)
        }
        let messages = [
            message("Hi, this is Maya at Linden Dental. Your cleaning is coming up.", .businessToConsumer, minutesAgo: 42),
            message("Can I move it to later in the week?", .consumerToBusiness, minutesAgo: 30),
            message("Of course. Pick whichever time suits you.", .businessToConsumer, minutesAgo: 28),
        ]
        let summary = ConversationSummary(id: session, business: business, state: .open,
                                          lastMessagePreview: messages.last?.body, lastMessageAt: messages.last?.createdAt, unreadCount: 1)
        return (summary, messages)
    }
}
