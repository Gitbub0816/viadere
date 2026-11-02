import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// Phone linking by one text sent from the phone (ADR-0027, UX_COPY S-PH-01 to S-PH-06). The app never receives or types a code.
@Suite("Phone link by text")
@MainActor
struct PhoneLinkViewModelTests {
    /// A clock the tests move.
    final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        // Starts at the real now: the mock API stamps its challenges with the real clock.
        private var value = Date()
        var now: Date { lock.lock(); defer { lock.unlock() }; return value }
        func advance(_ seconds: TimeInterval) { lock.lock(); value = value.addingTimeInterval(seconds); lock.unlock() }
    }

    private func make(api: MockViadereAPI = MockViadereAPI(seed: false), clock: Clock = Clock(),
                      onSleep: @escaping @Sendable (TimeInterval) -> Void = { _ in }) async -> (PhoneLinkViewModel, MockViadereAPI, Clock) {
        var services = await ViadereServices.mock(api: api)
        services.clock = { clock.now }
        let model = PhoneLinkViewModel(services: services, sleep: { onSleep($0) })
        return (model, api, clock)
    }

    @Test func theCopyIsTheApprovedWording() {
        #expect(PhoneLinkViewModel.introText == "Link your number to your Viadere account on this phone by sending one text from it. We never send you codes by text.")
        #expect(PhoneLinkViewModel.waitingText(masked: "+1 ••• 0123") == "Waiting for your text from +1 ••• 0123…")
        #expect(PhoneLinkViewModel.notReceivedText(masked: "+1 ••• 0123") == "We didn't receive your text from +1 ••• 0123. Make sure you send it from that phone line.")
        #expect(PhoneLinkViewModel.manualText(prefill: "Link my number to my Viadere app VDR-7K3M9Q2X", sendTo: "+15550001111")
                == "Send this text from the phone with that number: \"Link my number to my Viadere app VDR-7K3M9Q2X\" to +15550001111.")
        #expect(PhoneLinkViewModel.updateNeededText == "Update Viadere to link your number.")
        // No string offers a code or a text as a sign-in method.
        for text in [PhoneLinkViewModel.introText, PhoneLinkViewModel.updateNeededText] { #expect(!text.lowercased().contains("enter the code")) }
    }

    @Test func beginShowsTheChallengeAndTheComposeRequestWithoutAnythingBeingSentToThePhone() async throws {
        let (model, api, _) = await make()
        #expect(!model.canBegin)
        model.setPhone("4805550123")
        #expect(model.raw == "(480) 555-0123" && model.canBegin)
        await model.begin()
        guard case .waiting(let challenge) = model.stage else { Issue.record("expected waiting"); return }
        #expect(challenge.maskedNumber == PhoneNumber("+14805550123")!.masked)
        #expect(challenge.sendTo == MockViadereAPI.mockSendTo)
        #expect(challenge.prefill == PhoneLinkMO.prefill(nonce: String(challenge.prefill.suffix(12))))
        #expect(model.composeRequest == .init(recipient: challenge.sendTo, body: challenge.prefill))
        #expect(model.manualInstructions == PhoneLinkViewModel.manualText(prefill: challenge.prefill, sendTo: challenge.sendTo))
        #expect(model.statusText == PhoneLinkViewModel.waitingText(masked: challenge.maskedNumber))
        #expect(await api.beginRequests == [PhoneNumber("+14805550123")!])
        // The nonce is shown only on this screen: it is not stored anywhere in the model beyond the challenge.
        #expect(model.errorMessage == nil)
    }

    @Test func aDismissedComposeSheetNeverConcludesThatTheTextWasNotSent() async throws {
        let (model, _, _) = await make()
        model.setPhone("4805550123")
        await model.begin()
        model.composeDismissed(sent: false)
        if case .waiting = model.stage {} else { Issue.record("the app cannot know: keep waiting") }
        model.composeUnavailable()
        #expect(model.showCopyInstead)
        #expect(PhoneLinkViewModel.copyTextTitle == "Copy text")
    }

    @Test func theLinkedStageSaysWhenBusinessesCanReachTheNumberAndThatApprovalsNeverHappenByText() async throws {
        let (model, api, _) = await make()
        model.setPhone("4805550123")
        await model.begin()
        guard case .waiting(let challenge) = model.stage else { return }
        var linked: PhoneLink?
        model.onLinked = { linked = $0 }
        await api.sentText(for: challenge.phoneLinkId)
        await model.waitForText()
        guard case .linked(let link) = model.stage else { Issue.record("expected linked"); return }
        #expect(linked == link)
        #expect(link.assurance == PhoneLinkMO.assuranceLabel)
        let text = try #require(model.statusText)
        #expect(text.hasPrefix("Number linked. Businesses can reach you by text there from "))
        #expect(text.hasSuffix(" Approvals never happen by text."))
    }

    @Test func notReceivedAppearsOnlyAtExpiryNeverBefore() async throws {
        let clock = Clock()
        let (model, _, _) = await make(clock: clock, onSleep: { _ in })
        model.setPhone("4805550123")
        await model.begin()
        guard case .waiting(let challenge) = model.stage else { return }
        clock.advance(PhoneLinkMO.ttl - 60)
        await model.poll()
        if case .waiting = model.stage {} else { Issue.record("still inside the ten minutes") }
        // The server answers `expired` (the sweep removed the challenge): now, and only now.
        clock.advance(120)
        await model.poll()
        #expect(model.stage == .notReceived(maskedNumber: challenge.maskedNumber))
        #expect(model.statusText == PhoneLinkViewModel.notReceivedText(masked: challenge.maskedNumber))
        model.startOver()
        #expect(model.stage == .entry && model.raw == "(480) 555-0123")
    }

    @Test func waitingStopsWhenTheTaskIsCancelledAndPollsAtTheInterval() async throws {
        let clock = Clock()
        let sleeps = LockedCounter()
        let (model, api, _) = await make(clock: clock, onSleep: { _ in sleeps.increment() })
        model.setPhone("4805550123")
        await model.begin()
        guard case .waiting(let challenge) = model.stage else { return }
        let task = Task { @MainActor in await model.waitForText() }
        var spins = 0
        while sleeps.value < 2, spins < 400 { try await Task.sleep(for: .milliseconds(5)); spins += 1 }
        task.cancel()
        await api.sentText(for: challenge.phoneLinkId)
        await task.value
        #expect(PhoneLinkViewModel.pollInterval == 3)
        #expect(sleeps.value >= 2)
    }

    @Test func aRetiredRouteOnAnOldBuildReadsAsUpdateNeeded() async throws {
        // The server answers `410 gone` to the retired routes with this wording; the model shows it as the update prompt.
        #expect(PhoneLinkViewModel.updateNeededText == "Update Viadere to link your number.")
    }

    @Test func cancellingLeavesNoNumberBehind() async throws {
        let (model, _, _) = await make()
        model.setPhone("4805550123")
        await model.begin()
        model.cancel()
        #expect(model.stage == .entry && model.raw.isEmpty && model.composeRequest == nil)
    }
}

final class LockedCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var value: Int { lock.lock(); defer { lock.unlock() }; return count }
    func increment() { lock.lock(); count += 1; lock.unlock() }
}
