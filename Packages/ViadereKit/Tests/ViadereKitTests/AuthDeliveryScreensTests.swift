import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

actor RecordingAnswering: ApprovalAnswering {
    private(set) var answers: [(AuthAnswer, [String])] = []
    var error: (any Error)?
    func failWith(_ error: (any Error)?) { self.error = error }
    func answer(_ answer: AuthAnswer, requestIds: [String]) async throws {
        answers.append((answer, requestIds))
        if let error { throw error }
    }
}

struct StubVerifier: DestinationVerifying {
    var result: DestinationCheck
    func verify(_ display: AuthLinkDisplay) async -> DestinationCheck { result }
}

@MainActor
final class RecordingOpener: SystemURLOpening {
    private(set) var opened: [URL] = []
    func open(_ url: URL) async -> Bool { opened.append(url); return true }
}

@Suite("Number matching (ADR-0022 §2)")
@MainActor
struct NumberMatchTests {
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    func requirement(_ codes: String...) -> NumberMatchRequirement {
        NumberMatchRequirement(digits: codes[0].count, candidates: codes.enumerated().map { .init(requestId: "r\($0.offset + 1)", code: $0.element) })
    }

    func model(_ requirement: NumberMatchRequirement?, kind: NumberMatchKind = .signIn, requiresNumber: Bool = true, fatigue: Bool = false,
               deviceCanApprove: Bool = true, answering: RecordingAnswering = RecordingAnswering(), expiresIn: TimeInterval = 300) -> (NumberMatchApprovalViewModel, RecordingAnswering) {
        let now = self.now
        let ids = requirement?.candidates.map(\.requestId) ?? ["r1"]
        let context = NumberMatchApprovalContext(business: "Acme", kind: kind, expiresAt: now.addingTimeInterval(expiresIn), requirement: requirement,
                                                 requiresNumber: requiresNumber, openRequestCount: ids.count, requestsInWindow: 4, showFatigueWarning: fatigue,
                                                 deviceCanApprove: deviceCanApprove, groupRequestIds: ids, singleRequestId: ids.first)
        return (NumberMatchApprovalViewModel(context: context, answering: answering, clock: { now }), answering)
    }

    func type(_ text: String, into model: NumberMatchApprovalViewModel) {
        for character in text { model.edit(model.entry + String(character)) }
    }

    // MARK: The field

    @Test func theFieldRefusesPasteAutoFillAndNonDigits() {
        #expect(NumberMatcher.applyEdit(previous: "", proposed: "4", digits: 2) == "4")
        #expect(NumberMatcher.applyEdit(previous: "4", proposed: "47", digits: 2) == "47")
        // Paste or AutoFill of the whole number in one edit, a replacement of the selection, a non-digit, a leading zero, too long.
        #expect(NumberMatcher.applyEdit(previous: "", proposed: "47", digits: 2) == "")
        #expect(NumberMatcher.applyEdit(previous: "4", proposed: "73", digits: 2) == "4")
        #expect(NumberMatcher.applyEdit(previous: "", proposed: "x", digits: 2) == "")
        #expect(NumberMatcher.applyEdit(previous: "", proposed: "\u{0664}", digits: 2) == "", "Arabic-Indic digits are not accepted")
        #expect(NumberMatcher.applyEdit(previous: "", proposed: "0", digits: 2) == "")
        #expect(NumberMatcher.applyEdit(previous: "47", proposed: "471", digits: 2) == "47")
        // Deleting works.
        #expect(NumberMatcher.applyEdit(previous: "47", proposed: "4", digits: 2) == "4")
        #expect(NumberMatcher.applyEdit(previous: "4", proposed: "", digits: 2) == "")
    }

    @Test func theFieldTraitsTurnOffEveryAutofillRoute() {
        let traits = NumberFieldTraits.required
        #expect(traits.numericKeypad && traits.textContentTypeIsUnset && !traits.allowsPaste && !traits.autocorrection && !traits.prefilled)
        #expect(traits.announcesWrongEntryToVoiceOver)
        let (m, _) = model(requirement("47"))
        #expect(m.traits == traits)
        #expect(m.entry.isEmpty, "never prefilled")
    }

    @Test func comparisonIsAgainstEveryOpenRequest() {
        let r = requirement("47", "58", "63")
        #expect(NumberMatcher.evaluate(entry: "58", requirement: r) == .match(requestId: "r2"))
        #expect(NumberMatcher.evaluate(entry: "59", requirement: r) == .noMatch)
        #expect(NumberMatcher.evaluate(entry: "5", requirement: r) == .noMatch)
        let clash = NumberMatchRequirement(digits: 2, candidates: [.init(requestId: "a", code: "47"), .init(requestId: "b", code: "47")])
        #expect(NumberMatcher.evaluate(entry: "47", requirement: clash) == .ambiguous)
    }

    @Test("Review: the compare never treats a length that differs by a multiple of 256 as equal")
    func lengthDifferencesAreNeverTruncatedAway() {
        let code = Array("47".utf8)
        #expect(!NumberMatcher.constantTimeEqual(code + [UInt8](repeating: 0, count: 256), code))
        #expect(!NumberMatcher.constantTimeEqual(code, code + [UInt8](repeating: 0, count: 512)))
        #expect(NumberMatcher.constantTimeEqual(code, Array("47".utf8)))
        #expect(NumberMatcher.evaluate(entry: "47" + String(repeating: "\u{0}", count: 256), requirement: requirement("47")) == .noMatch)
    }

    @Test func requirementsAreValidated() {
        #expect(requirement("47").isWellFormed)
        #expect(requirement("473").isWellFormed)
        #expect(!NumberMatchRequirement(digits: 2, candidates: []).isWellFormed)
        #expect(!NumberMatchRequirement(digits: 2, candidates: [.init(requestId: "a", code: "07")]).isWellFormed)
        #expect(!NumberMatchRequirement(digits: 2, candidates: [.init(requestId: "a", code: "473")]).isWellFormed)
        #expect(!NumberMatchRequirement(digits: 4, candidates: [.init(requestId: "a", code: "4731")]).isWellFormed)
        #expect(NumberMatchRequirement.digits(forPayment: true, requested: 2) == 3)
        #expect(NumberMatchRequirement.digits(forPayment: false, requested: nil) == 2)
        #expect(NumberMatchRequirement.digits(forPayment: false, requested: 3) == 3)
    }

    // MARK: Buttons: equal prominence, Deny first

    @Test func denyAndApproveAreOneComponentWithDenyFirstAndApproveDisabledNotHidden() {
        let (m, _) = model(requirement("47"))
        #expect(m.buttons.map(\.role) == [.deny, .approve])
        #expect(Set(m.buttons.map(\.style)).count == 1, "identical style: no red Deny, no filled Approve")
        #expect(m.buttons[0].isEnabled && !m.buttons[1].isEnabled)
        #expect(m.buttons.map(\.title) == ["Deny", "Approve"])
        #expect(m.notMeButton.title == "This wasn't me" && m.notMeButton.isEnabled)
        type("4", into: m)
        #expect(!m.canApprove)
        type("7", into: m)
        #expect(m.canApprove && m.buttons[1].isEnabled)
    }

    @Test func titlesHelperAndLinesUseTheApprovedCopy() {
        let (m, _) = model(requirement("47"))
        #expect(m.title == "Approve sign-in to \u{2068}Acme\u{2069}?")
        #expect(m.subtitle == "Only approve if you started this.")
        #expect(m.fieldLabel == "Number on \u{2068}Acme\u{2069}")
        #expect(m.helper.contains("Enter the 2-digit number") && m.helper.contains("No number there, or someone gave it to you? Tap Deny."))
        #expect(m.denyLine == "Deny says no. This wasn't me also reports it.")
        let (pay, _) = model(requirement("473"), kind: .payment(payee: "Pier 9"))
        #expect(pay.digits == 3 && pay.title.contains("Pier 9") && pay.helper.contains("checkout screen"))
    }

    // MARK: Answers

    @Test func denyAnswersEveryOpenRequestOfTheGroupOnce() async {
        let (m, answering) = model(requirement("47", "58"))
        await m.deny()
        #expect(m.phase == .denied)
        let sent = await answering.answers
        #expect(sent.count == 1 && sent[0].0 == .deny(reason: nil) && sent[0].1 == ["r1", "r2"])
        #expect(m.resultLine == "Request denied. We told \u{2068}Acme\u{2069}. If that was a mistake, start again on \u{2068}Acme\u{2069}.")
    }

    @Test func thisWasntMeReportsAndOffersAPause() async {
        let answering = RecordingAnswering()
        let now = self.now
        let context = NumberMatchApprovalContext(business: "Acme", expiresAt: now.addingTimeInterval(60), requirement: requirement("47"), groupRequestIds: ["r1"])
        let m = NumberMatchApprovalViewModel(context: context, answering: answering, pauser: { true }, clock: { now })
        await m.reportNotMe()
        #expect(m.phase == .reported && m.offersPause)
        #expect(await answering.answers.first?.0 == .report)
        #expect(await m.pauseRequests())
    }

    @Test func approveSignsTheMatchedRequestOnlyAndOnlyAfterTheRelayAccepts() async {
        let (m, answering) = model(requirement("47", "58"))
        type("58", into: m)
        await m.approve()
        #expect(m.phase == .approved)
        let sent = await answering.answers
        #expect(sent.count == 1 && sent[0].0 == .approve(match: "58") && sent[0].1 == ["r2"])
        #expect(m.resultLine == "Approved. Your answer was sent to \u{2068}Acme\u{2069}.")
    }

    @Test func approvedIsNeverShownWhenTheSendFails() async {
        let answering = RecordingAnswering()
        await answering.failWith(AuthDeliveryError.offline)
        let (m, _) = model(requirement("47"), answering: answering)
        type("47", into: m)
        await m.approve()
        #expect(m.phase == .entering && m.resultLine == nil)
        #expect(m.notice == "Your answer wasn't sent. Check your connection and try again. \u{2068}Acme\u{2069} hasn't received anything yet.")
    }

    @Test func aWrongNumberIsAnnouncedAndThreeWrongEntriesDenyTheGroup() async {
        let (m, answering) = model(requirement("47", "58"))
        for _ in 0..<2 {
            type("99", into: m)
            await m.approve()
            #expect(m.phase == .entering && m.notice == AuthDeliveryCopy.wrongNumber && m.announcement == AuthDeliveryCopy.wrongNumber)
            #expect(m.entry.isEmpty)
        }
        #expect(await answering.answers.isEmpty, "nothing is signed for a wrong entry")
        type("99", into: m)
        await m.approve()
        #expect(m.phase == .autoDenied)
        let sent = await answering.answers
        #expect(sent.count == 1 && sent[0].0 == .deny(reason: .numberMismatch) && sent[0].1 == ["r1", "r2"])
        #expect(m.resultLine == "The number didn't match, so we denied this request. If you're signing in, start again on \u{2068}Acme\u{2069}.")
    }

    @Test("Review: after three wrong entries Approve stays off even when the automatic denial was not sent")
    func aFailedAutomaticDenialNeverReopensApprove() async {
        let answering = RecordingAnswering()
        let (m, _) = model(requirement("47", "58"), answering: answering)
        for _ in 0..<2 {
            type("99", into: m)
            await m.approve()
        }
        // The automatic denial fails (Face ID cancelled, offline): the screen returns to entering with the "not sent" notice.
        await answering.failWith(AuthDeliveryError.offline)
        type("99", into: m)
        await m.approve()
        #expect(m.phase == .entering && m.wrongEntries == 3)
        await answering.failWith(nil)
        // A fourth try with the right number must not approve anything.
        type("47", into: m)
        #expect(!m.canApprove)
        await m.approve()
        let afterApprove = await answering.answers
        #expect(!afterApprove.contains { if case .approve = $0.0 { return true } else { return false } }, "no approve after the third wrong entry")
        // Deny retries the number_mismatch denial of the whole group.
        await m.deny()
        #expect(m.phase == .autoDenied)
        let last = await answering.answers.last
        #expect(last?.0 == .deny(reason: .numberMismatch) && last?.1 == ["r1", "r2"])
    }

    @Test func twoMatchingRequestsSignNothing() async {
        let clash = NumberMatchRequirement(digits: 2, candidates: [.init(requestId: "a", code: "47"), .init(requestId: "b", code: "47")])
        let (m, answering) = model(clash)
        type("47", into: m)
        await m.approve()
        #expect(m.phase == .entering && m.notice == AuthDeliveryCopy.numberMatchesSeveral)
        #expect(await answering.answers.isEmpty)
    }

    @Test func withoutAUsableRequirementApproveStaysOffButDenyWorks() async {
        let (missing, _) = model(nil)
        #expect(!missing.canApprove, "number matching required and absent: fail closed")
        await missing.deny()
        #expect(missing.phase == .denied)
        let malformed = NumberMatchRequirement(digits: 2, candidates: [.init(requestId: "a", code: "7")])
        let (bad, _) = model(malformed)
        type("7", into: bad)
        #expect(!bad.canApprove)
        // A request created before number matching (not required) can be approved without a number.
        let (legacy, answering) = model(nil, requiresNumber: false)
        #expect(legacy.canApprove)
        await legacy.approve()
        #expect(await answering.answers.first?.0 == .approve(match: nil))
    }

    @Test func fatigueNeedsTheAcknowledgementBeforeApproveEnables() {
        let (m, _) = model(requirement("47"), fatigue: true)
        #expect(m.fatigueLine == "There have been 4 sign-in requests for \u{2068}Acme\u{2069} in the last hour. If you didn't start them, tap This wasn't me.")
        type("47", into: m)
        #expect(!m.canApprove)
        m.acknowledgeFatigue()
        #expect(m.canApprove)
    }

    @Test func screenCaptureAndExpiryBlockApproveNotDeny() async {
        let (m, _) = model(requirement("47"))
        type("47", into: m)
        m.isScreenCaptured = true
        #expect(!m.canApprove && m.buttons[0].isEnabled)
        let (old, answering) = model(requirement("47"), expiresIn: -1)
        type("47", into: old)
        #expect(!old.canApprove)
        await old.deny()
        #expect(old.phase == .expired && old.resultLine == AuthDeliveryCopy.answerExpired)
        #expect(await answering.answers.isEmpty)
    }

    @Test func aPaymentFromAnUntrustedDeviceCanOnlyBeDenied() async {
        let (m, _) = model(requirement("473"), kind: .payment(payee: "Pier 9"), deviceCanApprove: false)
        type("473", into: m)
        #expect(!m.canApprove)
        #expect(m.deviceBlockLine == AuthDeliveryCopy.paymentDeviceNotTrusted)
        #expect(m.buttons[0].isEnabled)
    }

    @Test func groupLineShowsWhenSeveralRequestsAreOpen() {
        let (m, _) = model(requirement("47", "58", "63"))
        #expect(m.groupLine == "3 open sign-in requests from \u{2068}Acme\u{2069}. Enter the number shown where you're signing in. Only that request is approved.")
        let (one, _) = model(requirement("47"))
        #expect(one.groupLine == nil)
    }
}

@Suite("Confirm before open (ADR-0021 §4, ADR-0031 §4)")
@MainActor
struct LinkConfirmationTests {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let id = UUID()

    func display(host: String = "login.acme.com", state: AuthLinkDisplay.State = .open, expiresIn: TimeInterval = 600) -> AuthLinkDisplay {
        AuthLinkDisplay(deliveryId: id, business: "Acme", businessVerified: true, host: host, expiresAt: now.addingTimeInterval(expiresIn), state: state)
    }

    func make(_ verdict: DestinationCheck, display shown: AuthLinkDisplay? = nil, url: String = "https://login.acme.com/finish#t=1")
        async -> (LinkConfirmationViewModel, MockAuthDeliveryAPI, RecordingOpener) {
        let api = MockAuthDeliveryAPI()
        await api.add(shown ?? display(), url: URL(string: url)!)
        let opener = RecordingOpener()
        let now = self.now
        return (LinkConfirmationViewModel(deliveryId: id, api: api, verifier: StubVerifier(result: verdict), opener: opener, clock: { now }), api, opener)
    }

    @Test func loadingNeverRedeemsOrOpens() async {
        let (m, api, opener) = await make(.verified(host: "login.acme.com"))
        await m.load()
        #expect(m.phase == .reviewing && m.canContinue)
        #expect(await api.openCalls.isEmpty)
        #expect(opener.opened.isEmpty, "nothing is consumed or opened before an explicit tap")
    }

    @Test func continueOpensTheVerifiedHostOnce() async {
        let (m, api, opener) = await make(.verified(host: "login.acme.com"))
        await m.load()
        await m.proceed()
        #expect(m.phase == .opened(host: "login.acme.com"))
        #expect(opener.opened == [URL(string: "https://login.acme.com/finish#t=1")!])
        #expect(await api.openCalls == [id])
        #expect(m.message == "Opened \u{2068}login.acme.com\u{2069}. Finish signing in there.")
    }

    @Test func screenShowsBusinessHostAndExpiryWithEqualButtonsSafeFirst() async {
        let (m, _, _) = await make(.verified(host: "login.acme.com"))
        await m.load()
        #expect(m.title == "\u{2068}Acme\u{2069} sign-in link")
        #expect(m.body == "Continue to sign in to \u{2068}Acme\u{2069}. This opens \u{2068}login.acme.com\u{2069}.")
        #expect(m.expiryLine { _ in "10:10 AM" } == "Expires at 10:10 AM")
        #expect(m.buttons.map(\.role) == [.notMe, .proceed])
        #expect(Set(m.buttons.map(\.style)).count == 1)
        #expect(m.buttons.map(\.title) == ["This wasn't me", "Continue"])
        #expect(m.continueAccessibilityLabel == "Continue to login.acme.com")
        #expect(m.host?.strong == "acme.com" && m.host?.prefix == "login.")
    }

    @Test func untilStage6EveryBusinessLinkFailsClosed() async {
        let api = MockAuthDeliveryAPI()
        await api.add(display(), url: URL(string: "https://login.acme.com/finish")!)
        let opener = RecordingOpener()
        let now = self.now
        let m = LinkConfirmationViewModel(deliveryId: id, api: api, opener: opener, clock: { now })
        await m.load()
        #expect(m.phase == .notOpened(.signatureFailed))
        #expect(!m.canContinue)
        #expect(m.message == "We couldn't confirm this link came from \u{2068}Acme\u{2069}. We didn't open it.")
        await m.proceed()
        #expect(await api.openCalls.isEmpty)
        #expect(opener.opened.isEmpty)
        #expect(await api.reduceCalls.isEmpty, "an unsupported check is not evidence of tampering: nothing is reported to the business")
        #expect(AuthDeliveryFlags.shipping.destinationVerification == false)
        #expect(m.buttons[0].isEnabled, "This wasn't me is still available")
    }

    @Test func failuresToVerifyNeverOpen() async {
        let cases: [(DestinationCheck, LinkConfirmationViewModel.Phase, String)] = [
            (.wrongDestination, .notOpened(.wrongDestination), "We didn't open this link because it doesn't go to a website \u{2068}Acme\u{2069} has verified."),
            (.signatureFailed, .notOpened(.signatureFailed), "We couldn't confirm this link came from \u{2068}Acme\u{2069}. We didn't open it."),
            (.unavailable, .cannotCheck(clock: false), AuthDeliveryCopy.linkCannotCheck),
            (.clockOutsideWindow, .cannotCheck(clock: true), AuthDeliveryCopy.linkClock),
        ]
        for (verdict, phase, message) in cases {
            let (m, api, opener) = await make(verdict)
            await m.load()
            #expect(m.phase == phase && m.message == message && !m.canContinue)
            await m.proceed()
            #expect(await api.openCalls.isEmpty)
            #expect(opener.opened.isEmpty)
        }
        let (m, _, _) = await make(.unavailable)
        await m.load()
        #expect(m.offersTryAgain)
    }

    @Test func anIntegrityFailureIsReportedAsDestinationUnverifiedButAnAvailabilityFailureIsNot() async {
        let (bad, badAPI, _) = await make(.signatureFailed)
        await bad.load()
        #expect(await badAPI.reduceCalls.map(\.1) == [.denyDestinationUnverified])
        let (stale, staleAPI, _) = await make(.unavailable)
        await stale.load()
        #expect(await staleAPI.reduceCalls.isEmpty, "nothing is sent to the business when the record could not be checked")
    }

    @Test func aVerifiedHostThatDiffersFromTheDisplayIsRefused() async {
        let (m, _, _) = await make(.verified(host: "evil.example"))
        await m.load()
        #expect(m.phase == .notOpened(.wrongDestination) && !m.canContinue)
    }

    @Test func theUrlTheServiceReturnsIsCheckedAgainOnTheDevice() async {
        for url in ["https://evil.example/finish", "http://login.acme.com/x", "https://user:pw@login.acme.com/x", "https://login.acme.com:8443/x",
                    "https://login.acme.com.evil.example/x"] {
            let (m, api, opener) = await make(.verified(host: "login.acme.com"), url: url)
            await m.load()
            await m.proceed()
            #expect(opener.opened.isEmpty, "\(url)")
            #expect(m.phase == .notOpened(.signatureFailed), "\(url)")
            #expect(await api.reduceCalls.map(\.1) == [.denyDestinationUnverified])
        }
    }

    @Test func expiredAndUsedLinksShowTheirOwnScreens() async {
        let (expired, _, _) = await make(.verified(host: "login.acme.com"), display: display(expiresIn: -5))
        await expired.load()
        #expect(expired.phase == .expired && expired.message == "This sign-in link has expired. Ask \u{2068}Acme\u{2069} for a new link.")
        let (used, _, _) = await make(.verified(host: "login.acme.com"), display: display(state: .used))
        await used.load()
        #expect(used.phase == .alreadyUsed)
        let (gone, _, _) = await make(.verified(host: "login.acme.com"), display: display(state: .cancelled))
        await gone.load()
        #expect(gone.message == "This request is no longer active.")
    }

    @Test func thisWasntMeReportsWithoutOpening() async {
        let (m, api, opener) = await make(.verified(host: "login.acme.com"))
        await m.load()
        await m.thisWasntMe()
        #expect(m.phase == .reported)
        #expect(await api.reduceCalls.map(\.1) == [.report])
        #expect(await api.openCalls.isEmpty)
        #expect(opener.opened.isEmpty)
        #expect(m.message?.hasPrefix("Thanks. We told") == true)
    }

    @Test func hostPresentationKeepsEveryLabelVisible() {
        let unusual = HostPresentation(host: "XN--acme-9ya.example.com")
        #expect(unusual.full == "xn--acme-9ya.example.com" && unusual.hasUnusualCharacters && unusual.strong == "example.com")
        let uk = HostPresentation(host: "login.acme.co.uk")
        #expect(uk.strong == "acme.co.uk" && uk.prefix == "login.")
        #expect(HostPresentation(host: "acme.com").prefix.isEmpty)
    }

    @Test func tryAgainReloads() async {
        let api = MockAuthDeliveryAPI()
        let opener = RecordingOpener()
        let now = self.now
        let m = LinkConfirmationViewModel(deliveryId: id, api: api, verifier: StubVerifier(result: .verified(host: "login.acme.com")), opener: opener, clock: { now })
        await m.load()
        #expect(m.phase == .gone)
        await api.add(display(), url: URL(string: "https://login.acme.com/x")!)
        await m.tryAgain()
        #expect(m.phase == .reviewing)
    }
}

@Suite("Device-add comparison code (ADR-0033 §4.1)")
@MainActor
struct DeviceAddTests {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let on = AuthDeliveryFlags(deviceAddComparison: true)

    func challenge(kids: [String] = ["ak_bbb", "ak_aaa"], account: String = "acc_1") -> DeviceAddChallenge {
        DeviceAddChallenge(env: "staging", nonce: "bm9uY2Utb25l", kids: kids, accountRef: account, reportedName: "Sam's iPhone", expiresAt: now.addingTimeInterval(300))
    }

    struct StubApprover: DeviceAddApproving {
        var results: [DeviceAddApprovalResult]
        func approve(match: String) async -> DeviceAddApprovalResult { results.first ?? .failed }
    }

    final class Sequenced: DeviceAddApproving, @unchecked Sendable {
        private var queue: [DeviceAddApprovalResult]
        init(_ results: [DeviceAddApprovalResult]) { queue = results }
        func approve(match: String) async -> DeviceAddApprovalResult { queue.isEmpty ? .failed : queue.removeFirst() }
    }

    @Test func codeDerivationMatchesTheSpecFormula() {
        // Independently computed with Python hashlib: sha256("VIADERE-DEVICE-ADD-V1\nstaging\nbm9uY2Utb25l\nak_aaa\nak_bbb"), first 8 bytes mod 10^6.
        #expect(DeviceAddCode.code(env: "staging", nonce: "bm9uY2Utb25l", kids: ["ak_bbb", "ak_aaa"]) == "166158")
        #expect(DeviceAddCode.code(env: "staging", nonce: "bm9uY2Utb25l", kids: ["ak_aaa", "ak_bbb"]) == "166158", "kids are sorted")
        #expect(DeviceAddCode.code(env: "production", nonce: "bm9uY2Utb25l", kids: ["ak_aaa"]) == "307464")
        #expect(DeviceAddCode.display("166158") == "166 158")
        #expect(DeviceAddCode.spoken("166158") == "1, 6, 6, 1, 5, 8")
        let zeros = DeviceAddCode.code(env: "e", nonce: "n", kids: ["k"])
        #expect(zeros.count == 6 && zeros.allSatisfy(\.isNumber))
    }

    @Test func theNewDeviceShowsTheCodeOnlyWhenTheChallengeListsExactlyItsKeys() {
        let ok = NewDeviceComparisonViewModel(challenge: challenge(), ownKids: ["ak_aaa", "ak_bbb"], flags: on, now: now)
        #expect(ok.phase == .showing(code: "166158"))
        #expect(ok.title == "Enter this number on your other device: 166 158")
        #expect(ok.detail == AuthDeliveryCopy.newDeviceCodeDetail)
        for kids in [["ak_aaa"], ["ak_aaa", "ak_bbb", "ak_evil"], ["ak_aaa", "ak_evil"], []] {
            let refused = NewDeviceComparisonViewModel(challenge: challenge(), ownKids: kids, flags: on, now: now)
            #expect(refused.phase == .refused && refused.title == nil && refused.refusal == AuthDeliveryCopy.deviceChallengeMismatch)
        }
        // A challenge that lists an extra attacker key is refused even though it contains this device's key.
        let substituted = NewDeviceComparisonViewModel(challenge: challenge(kids: ["ak_aaa", "ak_bbb", "ak_x"]), ownKids: ["ak_aaa", "ak_bbb"], flags: on, now: now)
        #expect(substituted.phase == .refused)
        let expired = NewDeviceComparisonViewModel(challenge: challenge(), ownKids: ["ak_aaa", "ak_bbb"], flags: on, now: now.addingTimeInterval(301))
        #expect(expired.phase == .refused)
    }

    @Test func everythingIsOffWhileTheFlagIsOff() {
        #expect(AuthDeliveryFlags.shipping.deviceAddComparison == false)
        #expect(NewDeviceComparisonViewModel(challenge: challenge(), ownKids: ["ak_aaa", "ak_bbb"], now: now).phase == .unavailable)
        let existing = ExistingDeviceApprovalViewModel(challenge: challenge(), ownAccountRef: "acc_1", approver: StubApprover(results: [.added]), now: now)
        #expect(existing.phase == .unavailable)
    }

    @Test func theExistingDeviceAsksForTheNumberAndNeverShowsIt() async {
        let m = ExistingDeviceApprovalViewModel(challenge: challenge(), ownAccountRef: "acc_1", approver: StubApprover(results: [.added]), flags: on, now: now)
        #expect(m.title == "Add a new device to your account?")
        #expect(m.nameRow == "Name chosen on the new device: \u{2068}Sam's iPhone\u{2069}")
        #expect(m.fieldLabel == "Number on the new device")
        #expect(m.helper.contains("Type the 6-digit number shown on the new device."))
        #expect(m.buttons.map(\.title) == ["This wasn't me", "Add device"] && Set(m.buttons.map(\.style)).count == 1)
        #expect(!m.buttons[1].isEnabled)
        // No stored property or description of this model carries the code.
        let mirror = Mirror(reflecting: m)
        let text = String(describing: mirror.children.map { "\($0.value)" })
        #expect(!text.contains("166158") && !text.contains("166 158"))
        for digit in "166158" { m.edit(m.entry + String(digit)) }
        #expect(m.isComplete && m.buttons[1].isEnabled)
        await m.add()
        #expect(m.phase == .added)
    }

    @Test func theDeviceCodeFieldRefusesPasteButKeepsLeadingZeros() {
        let m = ExistingDeviceApprovalViewModel(challenge: challenge(), ownAccountRef: "acc_1", approver: StubApprover(results: []), flags: on, now: now)
        m.edit("123456")
        #expect(m.entry.isEmpty, "pasted in one edit")
        m.edit("0")
        #expect(m.entry == "0")
        m.edit("0x")
        #expect(m.entry == "0")
        for digit in "0123456789" { m.edit(m.entry + String(digit)) }
        #expect(m.entry == "001234" && m.entry.count == 6, "capped at six numerals, leading zeros kept")
    }

    @Test func threeWrongNumbersEndTheEntry() async {
        let m = ExistingDeviceApprovalViewModel(challenge: challenge(), ownAccountRef: "acc_1",
                                                approver: Sequenced([.wrongNumber, .wrongNumber, .wrongNumber]), flags: on, now: now)
        for round in 1...3 {
            for digit in "111111" { m.edit(m.entry + String(digit)) }
            await m.add()
            if round < 3 {
                #expect(m.phase == .entering && m.notice == AuthDeliveryCopy.deviceWrongNumber && m.entry.isEmpty)
            }
        }
        #expect(m.phase == .ended && m.resultLine == "Nothing was added. Start again on the new device.")
    }

    @Test func aChallengeForAnotherAccountIsRefused() {
        let m = ExistingDeviceApprovalViewModel(challenge: challenge(account: "acc_other"), ownAccountRef: "acc_1", approver: StubApprover(results: []), flags: on, now: now)
        #expect(m.phase == .refused && m.refusal == AuthDeliveryCopy.deviceChallengeMismatch)
    }
}

@Suite("Live Activity disclosure (F-09)")
struct LiveActivityDisclosureTests {
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    func state() -> DecisionActivityState {
        var s = DecisionActivityState(interactionId: InteractionID(), kind: .confirm, expiresAt: now.addingTimeInterval(600))
        s.title = "Pay $120 to Acme Dental"
        s.detail = "Reference 4471"
        return s
    }

    @Test func theDefaultLockScreenIsNeutral() {
        let p = LiveDecisionPresentation(state: state(), businessName: "Acme Dental", now: now)
        #expect(p.headline == "Decision needed" && p.detail == "Open Viadere to see it.")
        #expect(p.business == "Viadere")
        #expect(p.buttons.isEmpty && p.showsOpen)
        let all = [p.business, p.headline, p.detail ?? "", p.compact]
        #expect(!all.joined().contains("Acme") && !all.joined().contains("$120") && !all.joined().contains("4471"))
        #expect(p.isEnriched == false)
    }

    @Test func neutralFinishedStagesStayNeutral() {
        var s = state()
        s.stage = .answered
        let p = LiveDecisionPresentation(state: s, businessName: "Acme Dental", now: now)
        #expect(p.stageText == "Answered" && p.buttons.isEmpty && !p.showsOpen && !p.business.contains("Acme"))
    }

    @Test func detailsAppearOnlyWhenThePersonOptedIn() {
        let prefs = InMemoryPreferences()
        #expect(LiveActivityDisclosure(preferences: prefs) == .neutral)
        prefs.setBool(true, for: .liveActivityLockScreenDetails)
        let disclosure = LiveActivityDisclosure(preferences: prefs)
        #expect(disclosure == .detailed)
        let p = LiveDecisionPresentation(state: state(), businessName: "Acme Dental", disclosure: disclosure, now: now)
        #expect(p.headline == "Pay $120 to Acme Dental" && p.business == "Acme Dental" && !p.buttons.isEmpty)
    }

    @Test func theStatusPresentationNamesNoBusinessByDefault() {
        let neutral = LiveActivityPresentation(status: .decision(state()), businessName: "Acme Dental", now: now)
        #expect(neutral.headline == "Decision needed" && !neutral.detail.contains("Acme"))
        let detailed = LiveActivityPresentation(status: .decision(state()), businessName: "Acme Dental", disclosure: .detailed, now: now)
        #expect(detailed.detail == "Acme Dental needs a quick decision")
    }
}
