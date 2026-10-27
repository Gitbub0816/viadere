import Foundation
@testable import ViadereCore

enum Fixtures {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)

    static func business(_ name: String, handle: String?, code: String, status: VerificationStatus = .verified,
                         id: BusinessID = BusinessID()) -> BusinessSummary {
        BusinessSummary(id: id, displayName: name, handle: handle.flatMap { BusinessHandle(parsing: $0) },
                        code: BusinessCode(parsing: code) ?? BusinessCode.generate(), verificationStatus: status)
    }

    static let walmart = business("Walmart", handle: "walmart", code: "WM2345")

    static func scope() -> RelationshipScope {
        RelationshipScope(consumerId: ConsumerID(), relationshipId: RelationshipID())
    }

    static func interaction(_ payload: InteractionPayload, sensitivity: Sensitivity = .standard,
                            purpose: InteractionPurpose = .transactional,
                            channels: [Channel] = [.nativePush, .inApp, .sms, .rcs, .web],
                            lifetime: TimeInterval = 300, businessId: BusinessID = walmart.id) -> Interaction {
        Interaction(businessId: businessId, scope: scope(), purpose: purpose, payload: payload,
                    sensitivity: sensitivity, allowedChannels: channels, createdAt: now,
                    expiresAt: now.addingTimeInterval(lifetime), idempotencyKey: "idem-\(UUID().uuidString)")
    }

    static var mesaAuthorize: AuthorizePayload {
        AuthorizePayload(actionDescription: "Card purchase",
                         amount: try? MoneyAmount(string: "285.28", currency: .usd),
                         merchant: "Walmart", location: "in or near Mesa, Arizona",
                         effectOfApproval: "The purchase will be completed.",
                         riskIndicators: [RiskIndicator(code: "new_merchant", label: "First purchase here", severity: .info)])
    }

    static var loginPayload: AuthenticatePayload {
        AuthenticatePayload(service: "Online Banking", device: "Chrome on macOS", approximateLocation: "Mesa, AZ",
                            ipRegion: "Arizona, US", attemptedAt: now)
    }

    static var choosePayload: ChoosePayload {
        ChoosePayload(prompt: "Pick a delivery window", options: [
            ChoiceOption(id: "am", label: "Morning"), ChoiceOption(id: "pm", label: "Afternoon"),
            ChoiceOption(id: "eve", label: "Evening"),
        ])
    }

    /// One sample payload per known kind.
    static var allPayloads: [InteractionPayload] {
        [
            .authenticate(loginPayload),
            .authorize(mesaAuthorize),
            .confirm(ConfirmPayload(title: "Table for 2 at 7pm", details: "Main St location", reference: "R-1234")),
            .choose(choosePayload),
            .acknowledge(AcknowledgePayload(title: "Estimate", body: "Repair estimate $120", documentVersion: "v1")),
            .reply(ReplyPayload(prompt: "Any delivery instructions?", suggestedReplies: ["Leave at door"])),
            .status(StatusPayload(title: "Out for delivery", body: "3 stops away",
                                  liveActivity: .delivery(DeliveryActivityState(trackingReference: "1Z", stage: .outForDelivery)))),
            .reward(RewardPayload(rewardId: RewardID(), title: "Free coffee Tuesday")),
            .ticket(TicketPayload(title: "Flight 123 boarding pass", ticketType: "boarding_pass")),
            .message(MessagePayload(text: "Your order shipped")),
        ]
    }
}
