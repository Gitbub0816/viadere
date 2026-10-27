import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

@Suite("Approvals")
struct ApprovalTests {
    func world(unsupported: Set<DeviceKeyPurpose> = []) async -> (ViadereServices, MockViadereAPI) {
        let api = MockViadereAPI(seed: false)
        return (await ViadereServices.mock(api: api, unsupportedKeys: unsupported), api)
    }

    @Test func enrollmentRegistersProvenKeys() async throws {
        let (services, api) = await world()
        let devices = try await api.devices()
        let device = try #require(devices.first)
        #expect(Set(device.keys.map(\.purpose)) == Set(DeviceKeyPurpose.allCases))
        #expect(device.maxAssurance == .biometric)
        let record = try #require(try await services.records.load())
        #expect(record.deviceId == device.id)
        // software keys are never reported as hardware-backed
        #expect(device.keys.allSatisfy { !$0.hardwareBacked })
    }

    @Test func criticalAuthorizeIsSignedWithBiometricKey() async throws {
        let (services, api) = await world()
        let envelope = PreviewData.authorize(sensitivity: .high)
        await api.add(envelope)
        let outcome = try await services.approvals.submit(envelope, decision: .approve)
        #expect(outcome.status == .approved)
        #expect(outcome.assurance == .biometric)
        #expect(await api.decisionLog.first?.2 == .biometric)
    }

    @Test func standardAuthenticateUsesUserPresenceKey() async throws {
        let (services, api) = await world()
        let envelope = PreviewData.authenticate(sensitivity: .standard)
        await api.add(envelope)
        let outcome = try await services.approvals.submit(envelope, decision: .approve)
        #expect(outcome.assurance == .devicePasscode)
    }

    @Test func userPresenceFallsBackToBiometricKey() async throws {
        let (services, api) = await world(unsupported: [.approvalUserPresence])
        let envelope = PreviewData.authenticate(sensitivity: .standard)
        await api.add(envelope)
        let outcome = try await services.approvals.submit(envelope, decision: .approve)
        #expect(outcome.assurance == .biometric)
    }

    @Test func deviceWithoutBiometricsCannotApproveHighRisk() async throws {
        let (services, api) = await world(unsupported: [.approvalBiometric])
        let envelope = PreviewData.authorize(sensitivity: .critical)
        await api.add(envelope)
        let record = try await services.records.load()
        #expect(ApprovalPolicy.availability(of: envelope, device: record, now: Date()) == .needsStrongerDevice(.deviceBoundBiometric))
        await #expect(throws: ApprovalError.deviceCannotSatisfy(.deviceBoundBiometric)) {
            _ = try await services.approvals.submit(envelope, decision: .approve)
        }
        #expect(await api.decisionLog.isEmpty)
    }

    @Test func rejectsExpiredAndDecidedInteractions() async throws {
        let (services, api) = await world()
        let expired = PreviewData.authorize(now: Date().addingTimeInterval(-1_000), expiresIn: 600)
        await api.add(expired)
        await #expect(throws: ApprovalError.expired) { _ = try await services.approvals.submit(expired, decision: .approve) }

        let fresh = PreviewData.authorize()
        await api.add(fresh)
        _ = try await services.approvals.submit(fresh, decision: .deny)
        // Same stale envelope again: the request is already decided, and the sheet is told what happened to it.
        await #expect(throws: ApprovalError.notActionable(.denied)) { _ = try await services.approvals.submit(fresh, decision: .approve) }
        let handled = try await api.interaction(fresh.id)
        #expect(handled.status == .denied)
        await #expect(throws: ApprovalError.notActionable(.denied)) { _ = try await services.approvals.submit(handled, decision: .approve) }
    }

    @Test func decisionKindIsValidated() async throws {
        let (services, api) = await world()
        let envelope = PreviewData.authorize()
        await api.add(envelope)
        await #expect(throws: ApprovalError.decisionNotAllowed) { _ = try await services.approvals.submit(envelope, decision: .confirm) }
        let choose = PreviewData.choose()
        await api.add(choose)
        await #expect(throws: ApprovalError.invalidSelection) { _ = try await services.approvals.submit(choose, decision: .select, selectedOptionIds: ["nope"]) }
        await #expect(throws: ApprovalError.invalidSelection) { _ = try await services.approvals.submit(choose, decision: .select, selectedOptionIds: ["tue_9", "wed_14"]) }
        let ok = try await services.approvals.submit(choose, decision: .select, selectedOptionIds: ["wed_14"])
        #expect(ok.selectedOptionIds == ["wed_14"])
        #expect(ok.status == .selected)
    }

    @Test func promptReasonNamesBusinessAndAmount() {
        let envelope = PreviewData.authorize()
        let reason = ApprovalPolicy.promptReason(for: envelope, decision: .approve)
        #expect(reason == "Approve $285.28 at Northfield Market")
        #expect(ApprovalPolicy.promptReason(for: envelope, decision: .deny).contains("Northfield Market"))
        #expect(ApprovalPolicy.promptReason(for: PreviewData.authenticate(), decision: .approve).contains("Harbor Bank"))
    }

    @Test func planSelectionFollowsAssurancePolicy() {
        #expect(SigningPlan.plan(for: .channelReply).assurance == .none)
        #expect(SigningPlan.plan(for: .deviceSignature).purpose == .request)
        #expect(SigningPlan.plan(for: .userVerified).purpose == .approvalUserPresence)
        #expect(SigningPlan.plan(for: .deviceBoundBiometric).purpose == .approvalBiometric)
        #expect(SigningPlan.plan(for: .deviceBoundBiometric).requiresBiometrics)
        #expect(!SigningPlan.plan(for: .deviceSignature).requiresUserVerification)
    }

    @Test func slideToApproveForMoneyAndHighRisk() {
        #expect(ApprovalPolicy.usesSlideToApprove(PreviewData.authorize().interaction))
        #expect(!ApprovalPolicy.usesSlideToApprove(PreviewData.authenticate(sensitivity: .standard).interaction))
        #expect(ApprovalPolicy.usesSlideToApprove(PreviewData.authenticate(sensitivity: .high).interaction))
        #expect(!ApprovalPolicy.usesSlideToApprove(PreviewData.choose().interaction))
    }

    @Test func unknownKindsAreNeverActionable() {
        let unknown = Interaction(
            businessId: PreviewData.northfield.id,
            scope: RelationshipScope(consumerId: PreviewData.consumerId, relationshipId: RelationshipID()),
            purpose: .security, payload: .unknown(.null), createdAt: Date(), expiresAt: Date().addingTimeInterval(60),
            idempotencyKey: "k", kind: .unknown("teleport"))
        let envelope = InteractionEnvelope(interaction: unknown, business: PreviewData.northfield, status: .pending)
        let record = DeviceRecord(deviceId: DeviceID(), consumerId: PreviewData.consumerId, name: "x", purposes: DeviceKeyPurpose.allCases, enrolledAt: Date())
        #expect(ApprovalPolicy.availability(of: envelope, device: record, now: Date()) == .unsupported)
    }
}

@Suite("Presentation")
struct PresentationTests {
    @Test func questionMatchesSpecExample() {
        let q = InteractionPresentation.question(PreviewData.authorize().interaction)
        #expect(q == "Someone is trying to spend $285.28 at Northfield Market in or near Mesa, Arizona. Is this you?")
    }

    @Test func countdownFormats() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        #expect(InteractionPresentation.countdown(until: now.addingTimeInterval(272), now: now) == "Expires in 4:32")
        #expect(InteractionPresentation.countdown(until: now.addingTimeInterval(9), now: now) == "Expires in 0:09")
        #expect(InteractionPresentation.countdown(until: now.addingTimeInterval(7_500), now: now) == "Expires in 2 h 5 min")
        #expect(InteractionPresentation.countdown(until: now, now: now) == "Expired")
    }

    @Test func detailsIncludeAmountLocationAndDevice() {
        let auth = InteractionPresentation.details(PreviewData.authorize())
        #expect(auth.contains { $0.label == "Amount" && $0.value == "$285.28 USD" })
        #expect(auth.contains { $0.label == "Location" && $0.value.contains("Mesa") })
        let signIn = InteractionPresentation.details(PreviewData.authenticate())
        #expect(signIn.contains { $0.label == "Device" && $0.value == "Chrome on macOS" })
        #expect(signIn.contains { $0.label == "Location" })
        #expect(InteractionPresentation.riskIndicators(PreviewData.authorize().interaction).count == 1)
    }

    @Test func headlines() {
        #expect(InteractionPresentation.headline(PreviewData.authorize().interaction) == "$285.28 at Northfield Market")
        #expect(InteractionPresentation.headline(PreviewData.authenticate().interaction) == "Sign in to Online Banking")
    }
}

@Suite("Approval view model")
@MainActor
struct ApprovalViewModelTests {
    @Test func approveFlowCompletes() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let envelope = PreviewData.authorize()
        await api.add(envelope)
        let model = ApprovalViewModel(envelope: envelope, services: services)
        await model.load()
        #expect(model.availability.isActionable)
        #expect(model.plan?.requiresBiometrics == true)
        #expect(model.usesSlideToApprove)
        var finished: InteractionOutcome?
        model.onFinished = { finished = $0 }
        await model.approve()
        #expect(model.phase == .done(.approve, .approved))
        #expect(finished?.status == .approved)
    }

    @Test func screenCaptureBlocksApprovalButNotDenial() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let envelope = PreviewData.authorize()
        await api.add(envelope)
        let model = ApprovalViewModel(envelope: envelope, services: services)
        await model.load()
        model.isScreenBeingCaptured = true
        #expect(model.approvalBlockedByCapture)
        await model.approve()
        #expect(model.phase == .ready)
        #expect(await api.decisionLog.isEmpty)
        await model.deny()
        #expect(model.phase == .done(.deny, .denied))
    }

    @Test func expiresAsTimeAdvances() async throws {
        let services = await ViadereServices.mock(api: MockViadereAPI(seed: false))
        let envelope = PreviewData.authorize(expiresIn: 60)
        let model = ApprovalViewModel(envelope: envelope, device: try await services.records.load(), services: services)
        #expect(model.availability.isActionable)
        model.tick(Date().addingTimeInterval(120))
        #expect(model.availability == .expired)
        #expect(model.countdown == "Expired")
    }

    @Test func alreadyHandledElsewhereShowsStaleState() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let envelope = PreviewData.authorize()
        await api.add(envelope)
        let other = try await services.approvals.submit(envelope, decision: .deny)
        #expect(other.status == .denied)
        let model = ApprovalViewModel(envelope: envelope, services: services)
        await model.load()
        #expect(model.availability == .alreadyHandled(.denied))
    }

    @Test func biometricDeviceChangeForcesReenrollment() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let envelope = PreviewData.authorize()
        await api.add(envelope)
        let model = ApprovalViewModel(envelope: envelope, services: services)
        await model.load()
        // Simulate `.biometryCurrentSet` invalidation: the key disappears.
        try await services.keys.deleteKey(for: .approvalBiometric)
        var flagged = false
        model.onKeyInvalidated = { flagged = true }
        await model.approve()
        #expect(flagged)
        #expect(model.phase == .failed(.keyInvalidated(.approvalBiometric)))
        #expect(await services.account.health() == .needsReenrollment(missing: [.approvalBiometric]))
    }
}
