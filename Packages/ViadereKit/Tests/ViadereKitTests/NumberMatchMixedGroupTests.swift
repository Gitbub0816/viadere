import Foundation
import Testing
@testable import ViadereKit
import ViadereCore

/// Stage 5 review S5-01 and S5-02: a group may mix 2- and 3-digit codes, and a group answer is one refusal.
@Suite("Number matching: mixed-length groups and group answers (S5-01, S5-02)")
@MainActor
struct NumberMatchMixedGroupTests {
    func type(_ text: String, into model: NumberMatchApprovalViewModel) {
        for character in text { model.edit(model.entry + String(character)) }
    }

    /// A controller on a relay with two business-signed number-matched requests: `attacker` (3 digits) and `victim` (2 digits).
    func controllerWithMixedGroup(attackerCode: String = "470", victimCode: String = "52") async throws
        -> (controller: ApproveController, relay: FakeRelay, victim: ApprovalPrompt, group: [ApprovalPrompt]) {
        let relay = try await makeRelay()
        let now = relay.now
        let secrets = InMemorySecretStore()
        let environment = ApproveEnvironment(api: relay, vault: SoftwareApprovalKeyVault(), store: SecretApproveLocalStore(secrets: secrets), logKeys: [await relay.logPublicKey],
                                             keys: SoftwareDeviceKeyStore(secrets: secrets), records: SecretDeviceRecordStore(secrets: secrets), clock: { now })
        let controller = ApproveController(environment: environment)
        await controller.lookup(code: "ABCD2345", expectedRootKid: nil, secret: testSecret)
        #expect(await controller.confirmEnrollment())
        try await relay.businessConfirms()
        await controller.refresh()
        let key = try #require(controller.keys.first)
        _ = try await relay.deliverNumberMatched(to: key, code: attackerCode, requestId: "req_attacker_3d")
        _ = try await relay.deliverNumberMatched(to: key, code: victimCode, requestId: "req_victim_2d")
        await controller.refresh()
        let victim = try #require(controller.prompts.first { $0.request.requestId == "req_victim_2d" })
        return (controller, relay, victim, controller.numberMatchGroup(for: victim))
    }

    @Test func aMixedGroupKeepsEachCodesOwnLengthAndTheFieldFitsTheLongest() async throws {
        let (_, _, _, group) = try await controllerWithMixedGroup()
        #expect(group.count == 2)
        let context = NumberMatchApprovalContext(group: group)
        let requirement = try #require(context.requirement)
        #expect(requirement.digits == 3)
        #expect(requirement.codeLengths == [2, 3] && requirement.hasMixedLengths)
        #expect(requirement.isWellFormed)
        // A code longer than the field, a one-digit code, or a leading zero is still malformed.
        #expect(!NumberMatchRequirement(digits: 2, candidates: [.init(requestId: "a", code: "470")]).isWellFormed)
        #expect(!NumberMatchRequirement(digits: 3, candidates: [.init(requestId: "a", code: "5")]).isWellFormed)
        #expect(!NumberMatchRequirement(digits: 3, candidates: [.init(requestId: "a", code: "052")]).isWellFormed)
    }

    @Test func theVictimApprovesTheirOwnTwoDigitRequestNextToAThreeDigitOne() async throws {
        let (controller, relay, victim, group) = try await controllerWithMixedGroup()
        let answering = ApproveControllerAnswering(controller: controller, group: group, attempts: controller.attemptRecorder(for: group[0]))
        let vm = NumberMatchApprovalViewModel(context: NumberMatchApprovalContext(group: group), answering: answering, clock: { relay.now })
        #expect(!vm.canApprove)
        type("5", into: vm)
        #expect(!vm.canApprove, "one digit is no code of the group")
        type("2", into: vm)
        #expect(vm.canApprove, "an entry as long as the victim's own code can be sent")
        await vm.approve()
        #expect(vm.phase == .approved)
        let submitted = await relay.submitted
        #expect(submitted.count == 1 && submitted[0].0 == victim.id)
        // The signed result carries the typed number and verifies against the victim's own code; the attacker's request is untouched.
        let key = try #require(controller.keys.first)
        let enrolled = EnrolledApprovalKey(kid: key.kid, publicKey: try ApprovalEnrollmentStatement.verify(key.statement).publicKey, subject: key.subject, assurance: .biometric)
        let expectation = ApprovalExpectation(audience: key.businessId, subject: key.subject, requestId: victim.content.requestId, challenge: victim.content.challenge,
                                              subjectDetails: victim.content.details, numberMatch: .required(code: "52"), minimumAMR: .biometric)
        #expect(try ApprovalResultVerifier.verify(submitted[0].1, expecting: expectation, keys: [enrolled], now: relay.now).claims.match == "52")
    }

    @Test func theThreeDigitRequestStillApproves() async throws {
        let (controller, relay, _, group) = try await controllerWithMixedGroup()
        let attacker = try #require(group.first { $0.request.requestId == "req_attacker_3d" })
        let answering = ApproveControllerAnswering(controller: controller, group: group, attempts: controller.attemptRecorder(for: group[0]))
        let vm = NumberMatchApprovalViewModel(context: NumberMatchApprovalContext(group: group), answering: answering, clock: { relay.now })
        type("470", into: vm)
        #expect(vm.canApprove)
        await vm.approve()
        let submitted = await relay.submitted
        #expect(submitted.count == 1 && submitted[0].0 == attacker.id)
    }

    @Test func aWrongEntryOfEitherLengthIsCountedAndThreeOfThemDenyTheGroupOnce() async throws {
        let (controller, relay, _, group) = try await controllerWithMixedGroup()
        let attempts = InMemoryNumberMatchAttempts()
        let answering = ApproveControllerAnswering(controller: controller, group: group, attempts: attempts)
        let vm = NumberMatchApprovalViewModel(context: NumberMatchApprovalContext(group: group), answering: answering, clock: { relay.now }, attempts: attempts)
        // Approve is enabled for any entry of a candidate's length, hit or miss: the button never says whether the digits are right.
        type("99", into: vm)
        #expect(vm.canApprove)
        await vm.approve()
        #expect(vm.wrongEntries == 1 && vm.entry.isEmpty && vm.phase == .entering)
        type("999", into: vm)
        #expect(vm.canApprove)
        await vm.approve()
        #expect(vm.wrongEntries == 2)
        type("88", into: vm)
        await vm.approve()
        #expect(vm.phase == .autoDenied)
        // The automatic deny answered both requests, and counts as one refusal: both results share one group id (S5-02).
        let groups = await relay.submittedGroups
        #expect(groups.count == 2)
        let shared = try #require(groups[0])
        #expect(ApprovalAnswerGroup.isValid(shared) && groups[1] == shared)
    }

    @Test func aGroupDenyIsOneAnswerForTheWholeGroup() async throws {
        let answering = RecordingAnswering()
        let requirement = NumberMatchRequirement(digits: 2, candidates: [.init(requestId: "a", code: "21"), .init(requestId: "b", code: "22"), .init(requestId: "c", code: "23")])
        let context = NumberMatchApprovalContext(business: "Northwind", expiresAt: Date().addingTimeInterval(300), requirement: requirement, groupRequestIds: ["a", "b", "c"])
        let vm = NumberMatchApprovalViewModel(context: context, answering: answering)
        await vm.deny()
        #expect(await answering.answers.count == 1)
        #expect(try #require(await answering.answers.last).1 == ["a", "b", "c"])
    }

    @Test func everyResultOfOneGroupDenyCarriesTheSameGroupIdAndAnApproveCarriesNone() async throws {
        let (controller, relay, _, group) = try await controllerWithMixedGroup()
        let answering = ApproveControllerAnswering(controller: controller, group: group, attempts: controller.attemptRecorder(for: group[0]))
        let vm = NumberMatchApprovalViewModel(context: NumberMatchApprovalContext(group: group), answering: answering, clock: { relay.now })
        await vm.deny()
        #expect(vm.phase == .denied)
        let groups = await relay.submittedGroups
        #expect(groups.count == 2)
        let shared = try #require(groups[0])
        #expect(ApprovalAnswerGroup.isValid(shared) && groups[1] == shared)

        let (controller2, relay2, _, group2) = try await controllerWithMixedGroup()
        let approving = NumberMatchApprovalViewModel(context: NumberMatchApprovalContext(group: group2),
                                                     answering: ApproveControllerAnswering(controller: controller2, group: group2), clock: { relay2.now })
        type("52", into: approving)
        await approving.approve()
        #expect(await relay2.submittedGroups == [nil])
    }

    @Test func aSingleRequestDenyNeedsNoGroupId() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        _ = try await relay.deliverNumberMatched(to: key, code: "47", requestId: "req_single_01")
        let prompt = try #require(try await phone.handler.load().prompts.first)
        _ = try await phone.handler.answer(prompt, decision: .deny)
        #expect(await relay.submittedGroups == [nil])
    }

    @Test func theWireCarriesAnswerGroupAsAnOptionalMember() throws {
        let json = try ViadereJSON.encode(SubmitApprovalResultRequest(result: "a.b.c", answerGroup: "AAAAAAAAAAAAAAAAAAAAAA"))
        #expect(String(decoding: json, as: UTF8.self).contains("\"answer_group\":\"AAAAAAAAAAAAAAAAAAAAAA\""))
        let plain = try ViadereJSON.encode(SubmitApprovalResultRequest(result: "a.b.c"))
        #expect(!String(decoding: plain, as: UTF8.self).contains("answer_group"))
        #expect(!ApprovalAnswerGroup.isValid("short") && !ApprovalAnswerGroup.isValid(String(repeating: "A", count: 23)))
    }
}
