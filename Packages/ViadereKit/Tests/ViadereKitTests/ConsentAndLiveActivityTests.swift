import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

@Suite("Acknowledgments")
@MainActor
struct AcknowledgmentTests {
    private func envelope() -> InteractionEnvelope { PreviewData.acknowledge(now: tuesdayNoon) }
    private func payload(_ e: InteractionEnvelope) -> AcknowledgePayload {
        if case .acknowledge(let p) = e.interaction.payload { return p }
        return AcknowledgePayload(title: "", body: "")
    }

    @Test func copyNeverClaimsALegalSignature() {
        let text = (AcknowledgmentPresentation.disclaimer + AcknowledgmentPresentation.recordNote).lowercased()
        #expect(text.contains("isn't a legal signature"))
        for banned in ["e-sign", "esign", "legally binding", "signed by you", "your signature", "digitally signed"] {
            #expect(!text.contains(banned), "copy must not contain \(banned)")
        }
        #expect(AcknowledgmentPresentation.resultTitle(acknowledged: true) == "Acknowledged")
        #expect(!AcknowledgmentPresentation.resultMessage(acknowledged: true, business: "Harbor Hotel").lowercased().contains("sign"))
    }

    @Test func summaryVersionAndDocumentLinks() {
        let e = envelope()
        let p = payload(e)
        let summary = AcknowledgmentPresentation.summary(p, limit: 100)
        #expect(summary.count <= 101 && AcknowledgmentPresentation.isTruncated(p, limit: 100))
        #expect(AcknowledgmentPresentation.summary(AcknowledgePayload(title: "t", body: "Short."), limit: 100) == "Short.")
        #expect(AcknowledgmentPresentation.versionLabel(p) == "Version 2026-10")
        #expect(AcknowledgmentPresentation.versionLabel(AcknowledgePayload(title: "t", body: "b")) == nil)
        #expect(AcknowledgmentPresentation.documentURL(p)?.absoluteString == "https://example.com/estimates/5520")
        for bad in ["http://example.com/x", "javascript:alert(1)", "file:///etc/passwd", "viadere://x", "tel:123"] {
            let q = AcknowledgePayload(title: "t", body: "b", documentURL: URL(string: bad))
            #expect(AcknowledgmentPresentation.documentURL(q) == nil, "\(bad) must not be opened")
        }
    }

    @Test func documentRowsShowWhoWhatAndVersion() {
        let e = envelope()
        let rows = AcknowledgmentPresentation.documentRows(e, payload: payload(e), now: tuesdayNoon)
        #expect(rows.map(\.label) == ["From", "Document", "Version", "Account", "Sent"])
        #expect(rows.first { $0.label == "From" }?.value == "Harbor Hotel")
    }

    @Test func receiptUsesTheServersTimestamp() {
        let e = envelope()
        let serverTime = tuesdayNoon.addingTimeInterval(42)
        let outcome = InteractionOutcome(interactionId: e.id, businessId: e.business.id, status: .acknowledged, decision: .acknowledge, decidedAt: serverTime)
        let rows = AcknowledgmentPresentation.receiptRows(e, payload: payload(e), outcome: outcome, fallback: Date.distantPast,
                                                          timeZone: TimeZone(identifier: "UTC") ?? .gmt)
        let recorded = rows.first { $0.label == "Recorded" }
        #expect(recorded?.emphasized == true)
        #expect(recorded?.value == AcknowledgmentPresentation.timestamp(serverTime, timeZone: TimeZone(identifier: "UTC") ?? .gmt))
        #expect(rows.first { $0.label == "Reference" }?.value.hasPrefix("VD-") == true)
        // without an outcome the fallback is used
        let fallback = AcknowledgmentPresentation.receiptRows(e, payload: payload(e), outcome: nil, fallback: tuesdayNoon, timeZone: TimeZone(identifier: "UTC") ?? .gmt)
        #expect(fallback.first { $0.label == "Recorded" }?.value == AcknowledgmentPresentation.timestamp(tuesdayNoon, timeZone: TimeZone(identifier: "UTC") ?? .gmt))
    }

    @Test func acknowledgingProducesADeviceSignedDecisionAndAServerRecord() async throws {
        let (services, api) = await p3World()
        let e = envelope()
        await api.add(e)
        let model = ApprovalViewModel(envelope: e, device: try await services.records.load(), services: services)
        await model.load()
        await model.approve()   // acknowledge
        #expect(model.phase == .done(.acknowledge, .acknowledged))
        #expect(model.outcome?.decidedAt == tuesdayNoon)
        #expect(await api.decisionLog.last?.1 == .acknowledge)

        let list = AcknowledgmentsViewModel(services: services)
        await list.load()
        let record = try #require(list.records.first { $0.id == e.id })
        #expect(record.acknowledged && record.documentVersion == "2026-10" && record.recordedAt == tuesdayNoon)
        #expect(list.records.count == 3)
        #expect(list.subtitle(record).hasPrefix("Acknowledged · v2026-10 ·"))
    }

    @Test func decliningIsRecordedAsDeclined() async throws {
        let (services, api) = await p3World()
        let e = envelope()
        await api.add(e)
        let model = ApprovalViewModel(envelope: e, device: try await services.records.load(), services: services)
        await model.load()
        await model.deny()
        #expect(model.phase == .done(.decline, .declined))
        let list = AcknowledgmentsViewModel(services: services)
        await list.load()
        #expect(list.records.first { $0.id == e.id }?.acknowledged == false)
    }

    @Test func historyLoads() async throws {
        let (services, _) = await p3World()
        let model = AcknowledgmentsViewModel(services: services)
        await model.load()
        #expect(model.phase == .loaded && model.records.count == 2)
        #expect(model.records[0].recordedAt > model.records[1].recordedAt)   // newest first
    }
}

@Suite("Live Activity layout copy")
struct LiveActivityLayoutTests {
    private let now = tuesdayNoon

    @Test func ongoingActivitiesHaveANextStepAndFinishedOnesDont() {
        let preparing = LiveActivityPresentation(status: .order(OrderActivityState(orderReference: "1", stage: .preparing, estimatedReadyAt: now.addingTimeInterval(480))),
                                                 businessName: "Juniper Coffee", now: now)
        #expect(preparing.nextStep == "Next: we'll tell you when it's ready")
        let done = LiveActivityPresentation(status: .order(OrderActivityState(orderReference: "1", stage: .completed)), businessName: "Juniper Coffee", now: now)
        #expect(done.nextStep == nil)
        for status in sampleStatuses(now) where !status.isTerminal {
            #expect(LiveActivityPresentation(status: status, businessName: "x", now: now).nextStep != nil)
        }
        for status in sampleStatuses(now) where status.isTerminal {
            #expect(LiveActivityPresentation(status: status, businessName: "x", now: now).nextStep == nil)
        }
    }

    @Test func trailingShowsACountdownWhenCloseAndAStatusWordOtherwise() {
        let soon = LiveActivityPresentation(status: .order(OrderActivityState(orderReference: "1", stage: .preparing, estimatedReadyAt: now.addingTimeInterval(480))),
                                            businessName: "x", now: now)
        #expect(soon.trailing == .countdown(to: now.addingTimeInterval(480)))
        let far = LiveActivityPresentation(status: .order(OrderActivityState(orderReference: "1", stage: .preparing, estimatedReadyAt: now.addingTimeInterval(3 * 3_600))),
                                           businessName: "x", now: now)
        #expect(far.trailing == .text("Prep"))
        let past = LiveActivityPresentation(status: .order(OrderActivityState(orderReference: "1", stage: .preparing, estimatedReadyAt: now.addingTimeInterval(-60))),
                                            businessName: "x", now: now)
        #expect(past.trailing == .text("Prep"))
        // alerts and finished activities show words, not a ticking clock
        let delayed = LiveActivityPresentation(status: .flight(FlightActivityState(flightNumber: "NW 482", departureAirport: "PHX", arrivalAirport: "SEA", stage: .delayed,
                                                                                   scheduledDeparture: now.addingTimeInterval(1_800), estimatedDeparture: now.addingTimeInterval(2_400), gate: "B12")),
                                               businessName: "x", now: now)
        if case .countdown = delayed.trailing { Issue.record("alerts must not tick") }
        let delivered = LiveActivityPresentation(status: .delivery(DeliveryActivityState(trackingReference: "1", stage: .delivered, estimatedDeliveryAt: now.addingTimeInterval(60))),
                                                 businessName: "x", now: now)
        #expect(delivered.trailing == .text("Done"))
    }

    private func sampleStatuses(_ now: Date) -> [LiveActivityStatus] {
        [
            .order(OrderActivityState(orderReference: "1", stage: .placed)), .order(OrderActivityState(orderReference: "1", stage: .ready)),
            .order(OrderActivityState(orderReference: "1", stage: .completed)), .order(OrderActivityState(orderReference: "1", stage: .cancelled)),
            .delivery(DeliveryActivityState(trackingReference: "1", stage: .inTransit)), .delivery(DeliveryActivityState(trackingReference: "1", stage: .outForDelivery)),
            .delivery(DeliveryActivityState(trackingReference: "1", stage: .delivered)),
            .flight(FlightActivityState(flightNumber: "NW 1", departureAirport: "PHX", arrivalAirport: "SEA", stage: .boarding, scheduledDeparture: now)),
            .flight(FlightActivityState(flightNumber: "NW 1", departureAirport: "PHX", arrivalAirport: "SEA", stage: .landed, scheduledDeparture: now)),
            .appointment(AppointmentActivityState(title: "x", startsAt: now, stage: .checkInOpen)),
            .appointment(AppointmentActivityState(title: "x", startsAt: now, stage: .completed)),
        ]
    }
}
