import Foundation
import Testing
@testable import ViadereKit
import ViadereCore

extension FakeRelay {
    func clearRequests() { requests.removeAll() }

    /// An end-to-end auth approval whose business-signed request carries `number_match` (ADR-0022 §2.2).
    func deliverNumberMatched(to enrolled: LocalApprovalKey, code: String, requestId: String) async throws -> ApproveDeviceRequest {
        let details = ApprovalSubject.authentication(AuthenticationDetails(actionDisplay: "Sign in to Northwind", matchDigits: code.count))
        let content = ApprovalRequestContent(businessId: businessId, subject: subject, requestId: requestId, challenge: ChallengeNonce.generate().value, details: details,
                                             toKid: enrolled.kid, issuedAt: now, expiresAt: now.addingTimeInterval(300),
                                             numberMatch: ApprovalNumberMatch(digits: code.count, code: code))
        let plaintext = try await content.sealedPlaintext(signedWith: requestKey)
        let hpke = try ApprovalEnrollmentStatement.verify(enrolled.statement).hpkePublicKey
        let envelope = try E2EE.seal(plaintext, to: hpke, context: E2EEContext(purpose: "approve.request", requestId: requestId, sender: "biz_" + businessId.description,
                                                                                 recipient: "ak_" + enrolled.kid, expiresAt: now.addingTimeInterval(300)))
        let request = ApproveDeviceRequest(id: UUID(), requestId: requestId, business: summary, subjectRef: subject, capability: .authChallenge, kid: enrolled.kid,
                                           protection: .endToEnd, status: .pending, createdAt: now, expiresAt: now.addingTimeInterval(300), envelope: envelope,
                                           numberMatch: AuthApprovalNumberMatch(digits: code.count))
        requests.append(request)
        return request
    }

    /// A server-visible auth approval: the relay holds the code; the requirement is in the digest (`match_digits`).
    func deliverServerVisibleNumberMatched(to enrolled: LocalApprovalKey, code: String?, digits: Int = 2, stripped: Bool = false) -> ApproveDeviceRequest {
        let request = ApproveDeviceRequest(id: UUID(), requestId: "req_server_visible_nm", business: summary, subjectRef: subject, capability: .authChallenge, kid: enrolled.kid,
                                           protection: .serverVisible, status: .pending, createdAt: now, expiresAt: now.addingTimeInterval(300),
                                           challenge: ChallengeNonce.generate().value, authentication: AuthenticationDetails(actionDisplay: "Sign in", matchDigits: digits),
                                           numberMatch: stripped ? nil : AuthApprovalNumberMatch(digits: digits, code: code))
        requests.append(request)
        return request
    }
}

/// Stage 5 device side: R4-04 (the number reaches the screen and the typed `match` is inside the signed result), R4-02 (the wrong-entry count persists),
/// R4-03 (the staging flag), and ST-MFA-01 / ST-MFA-13 on the shipping path.
@Suite("Number matching on the device (Stage 5)")
@MainActor
struct NumberMatchStage5Tests {
    @Test func anEndToEndNumberMatchedRequestRequiresTheNumberAndSignsTheTypedMatch() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        _ = try await relay.deliverNumberMatched(to: key, code: "47", requestId: "req_number_match_01")
        let prompt = try #require(try await phone.handler.load().prompts.first)
        #expect(prompt.content.numberMatch?.code == "47")
        let context = NumberMatchApprovalContext(group: [prompt])
        #expect(context.requiresNumber)
        #expect(context.requirement?.candidates == [NumberMatchRequirement.Candidate(requestId: "req_number_match_01", code: "47")])
        // The answer is v2 with the typed number inside the signature, which the business verifies against its own code.
        let answer = ApproveControllerAnswering.numberMatchAnswer(.approve(match: "47"), prompt: prompt, wrongEntries: 1)
        #expect(answer == ApprovalNumberMatchAnswer(match: "47", denyReason: nil, invalidMatchAttempts: 1))
        #expect(try await phone.handler.answer(prompt, decision: .approve, numberMatch: answer) == .approved)
        let (_, jws) = try #require(await relay.submitted.first)
        let enrolled = EnrolledApprovalKey(kid: key.kid, publicKey: try ApprovalEnrollmentStatement.verify(key.statement).publicKey, subject: key.subject, assurance: .biometric)
        let expectation = ApprovalExpectation(audience: key.businessId, subject: key.subject, requestId: prompt.content.requestId, challenge: prompt.content.challenge,
                                              subjectDetails: prompt.content.details, numberMatch: .required(code: "47"), minimumAMR: .biometric)
        let verified = try ApprovalResultVerifier.verify(jws, expecting: expectation, keys: [enrolled], now: relay.now)
        #expect(verified.claims.match == "47" && verified.claims.invalidMatchAttempts == 1)
        // Without the typed number the device never signs an approve of a number-matched request.
        await #expect(throws: (any Error).self) { _ = try await phone.handler.answer(prompt, decision: .approve) }
    }

    @Test func requiresNumberComesFromSignedPolicyNotFromTheRelay() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        // A payment always needs a number, whatever the relay sent (R4-04): with no requirement Approve stays disabled.
        _ = await relay.deliverServerVisible(to: key)
        let payment = try #require(try await phone.handler.load().prompts.first)
        #expect(NumberMatchApprovalContext.requiresNumber(payment))
        let vm = NumberMatchApprovalViewModel(context: NumberMatchApprovalContext(prompt: payment), answering: RecordingAnswering(), clock: { relay.now })
        #expect(!vm.canApprove)
        // A relay that strips the code of a server-visible authentication whose digest names `match_digits` gets the request hidden, not shown without a number.
        await relay.clearRequests()
        _ = await relay.deliverServerVisibleNumberMatched(to: key, code: nil, stripped: true)
        let loaded = try await phone.handler.load()
        #expect(loaded.prompts.isEmpty && loaded.rejected.first?.reason == "malformed_number_match")
        // With the code: the screen requires it.
        await relay.clearRequests()
        _ = await relay.deliverServerVisibleNumberMatched(to: key, code: "52")
        let prompt = try #require(try await phone.handler.load().prompts.first)
        #expect(NumberMatchApprovalContext(group: [prompt]).requirement?.candidates.first?.code == "52")
    }

    @Test func theWrongEntryCountSurvivesANewScreenForTheSameRequest() async throws {
        let attempts = InMemoryNumberMatchAttempts()
        let requirement = NumberMatchRequirement(digits: 2, candidates: [.init(requestId: "r1", code: "47")])
        let context = NumberMatchApprovalContext(business: "Northwind", expiresAt: Date().addingTimeInterval(300), requirement: requirement, groupRequestIds: ["r1"])
        let answering = RecordingAnswering()
        let first = NumberMatchApprovalViewModel(context: context, answering: answering, attempts: attempts)
        for _ in 0..<2 { first.edit("1"); first.edit("12"); await first.approve() }
        #expect(first.wrongEntries == 2 && first.confirmsBeforeLeaving)
        // Dismissed and reopened (or relaunched): the new screen starts at the stored count; one more wrong entry is the third and denies.
        let stored = await attempts.wrongEntries(requestIds: ["r1"])
        let second = NumberMatchApprovalViewModel(context: context, answering: answering, initialWrongEntries: stored, attempts: attempts)
        #expect(second.wrongEntries == 2)
        second.edit("1"); second.edit("13"); await second.approve()
        #expect(second.phase == .autoDenied)
        #expect(await answering.answers.last?.0 == .deny(reason: .numberMismatch))
    }

    @Test func theApprovalStorePersistsWrongEntriesPerBusinessAndRequest() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        _ = try await relay.deliverNumberMatched(to: key, code: "47", requestId: "req_number_match_02")
        let prompt = try #require(try await phone.handler.load().prompts.first)
        let recorder = phone.handler.attemptRecorder(for: prompt.key.businessId)
        #expect(await recorder.recordWrongEntry(requestIds: ["req_number_match_02"]) == 1)
        #expect(await recorder.recordWrongEntry(requestIds: ["req_number_match_02"]) == 2)
        #expect(await recorder.wrongEntries(requestIds: ["req_number_match_02"]) == 2)
        // S5-06: another business that happens to use the same request id has its own counter.
        let other = phone.handler.attemptRecorder(for: BusinessID())
        #expect(await other.wrongEntries(requestIds: ["req_number_match_02"]) == 0)
    }

    /// S5-06 exploit: a relay that omits the request from one listing (or one that fails verification once) used to reset the count to 0.
    @Test func aListingThatOmitsTheRequestDoesNotResetTheThreeStrikes() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        _ = try await relay.deliverNumberMatched(to: key, code: "47", requestId: "req_number_match_03")
        let prompt = try #require(try await phone.handler.load().prompts.first)
        let recorder = phone.handler.attemptRecorder(for: prompt.key.businessId)
        await recorder.recordWrongEntry(requestIds: ["req_number_match_03"])
        await recorder.recordWrongEntry(requestIds: ["req_number_match_03"])
        await relay.clearRequests()
        #expect(try await phone.handler.load().prompts.isEmpty)
        #expect(await recorder.wrongEntries(requestIds: ["req_number_match_03"]) == 2, "an omitted request keeps its count")
    }

    @Test func nothingBelowTheScreenSignsAnApproveAfterThreeWrongEntries() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        _ = try await relay.deliverNumberMatched(to: key, code: "47", requestId: "req_number_match_04")
        let prompt = try #require(try await phone.handler.load().prompts.first)
        let recorder = phone.handler.attemptRecorder(for: prompt.key.businessId)
        for _ in 0..<3 { await recorder.recordWrongEntry(requestIds: ["req_number_match_04"]) }
        // The right number, offered directly to the handler (a reopened sheet whose count was still loading): refused, nothing sent.
        let answer = ApprovalNumberMatchAnswer(match: "47", denyReason: nil, invalidMatchAttempts: 3)
        await #expect(throws: ApproveError.requestRejected("wrong_entry_limit")) { _ = try await phone.handler.answer(prompt, decision: .approve, numberMatch: answer) }
        #expect(await relay.submitted.isEmpty)
        // A refusal is still accepted, and the terminal answer clears the count.
        _ = try await phone.handler.answer(prompt, decision: .deny, numberMatch: ApprovalNumberMatchAnswer(match: nil, denyReason: .numberMismatch, invalidMatchAttempts: 3))
        #expect(await recorder.wrongEntries(requestIds: ["req_number_match_04"]) == 0)
    }

    /// S5-04 / INB-01: a request delivered without an alert says so in the list.
    @Test func aSilentSignInCarriesTheInboxLine() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        _ = try await relay.deliverNumberMatched(to: key, code: "47", requestId: "req_number_match_05")
        var prompt = try #require(try await phone.handler.load().prompts.first)
        #expect(prompt.inboxLine == nil)
        prompt.request.silent = true
        #expect(prompt.inboxLine == "You have a pending sign-in from \u{2068}Harbor Bank\u{2069}.")
    }

    @Test func approveStaysOffUntilTheStoredCountIsLoaded() {
        let requirement = NumberMatchRequirement(digits: 2, candidates: [.init(requestId: "r1", code: "47")])
        let context = NumberMatchApprovalContext(business: "Northwind", expiresAt: Date().addingTimeInterval(300), requirement: requirement, groupRequestIds: ["r1"])
        let vm = NumberMatchApprovalViewModel(context: context, answering: RecordingAnswering())
        vm.holdApproveUntilRestored()
        vm.edit("4"); vm.edit("47")
        #expect(!vm.canApprove, "the sheet has not loaded the stored count yet")
        vm.restoreWrongEntries(3)
        #expect(!vm.canApprove && vm.wrongEntryLimitReached)
        let fresh = NumberMatchApprovalViewModel(context: context, answering: RecordingAnswering())
        fresh.holdApproveUntilRestored()
        fresh.edit("4"); fresh.edit("47")
        fresh.restoreWrongEntries(0)
        #expect(fresh.canApprove)
    }

    @Test func theNotificationDenyIsOnForStagingAndOffForProduction() {
        #expect(AuthDeliveryFlags.shipping.notificationDeny == false)
        #expect(AuthDeliveryFlags.staging.notificationDeny)
        let deny = AuthNotificationCategory.approveCategory(flags: .staging).actions.map(\.identifier)
        #expect(deny.contains(AuthNotificationCategory.denyAction))
        #expect(!AuthNotificationCategory.approveCategory(flags: .shipping).actions.map(\.identifier).contains(AuthNotificationCategory.denyAction))
    }
}
