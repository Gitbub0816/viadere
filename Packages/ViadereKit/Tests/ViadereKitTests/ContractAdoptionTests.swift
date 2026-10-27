import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

/// Records passkey assertions (and what happened around them), delegating to the mock authenticator.
final class RecordingPasskeys: PasskeyService, @unchecked Sendable {
    private let lock = NSLock()
    private var _events: [String] = []
    private let inner = MockPasskeyService()
    var events: [String] { lock.lock(); defer { lock.unlock() }; return _events }
    var assertions: Int { events.filter { $0 == "assert" }.count }
    func note(_ event: String) { lock.lock(); _events.append(event); lock.unlock() }
    func register(options: PasskeyRegistrationOptions) async throws -> PasskeyRegistrationCredential { try await inner.register(options: options) }
    func assert(options: PasskeyAssertionOptions) async throws -> PasskeyAssertionCredential {
        note("assert")
        return try await inner.assert(options: options)
    }
}

private func tamperedAmount(_ envelope: InteractionEnvelope, to amount: String) -> InteractionEnvelope {
    var changed = envelope
    if case .authorize(var payload) = changed.interaction.payload {
        payload.amount = try? MoneyAmount(string: amount, currency: .usd)
        changed.interaction.payload = .authorize(payload)
    }
    return changed
}

private func payload(of outcome: InteractionOutcome) throws -> DecisionPayload {
    try DecisionVerifier().decodeUnverified(try #require(outcome.signedDecision))
}

// MARK: - Passkey-bound enrollment

@Suite("Passkey-bound enrollment")
struct PasskeyEnrollmentTests {
    @Test func aFreshSignInMayEnrollOnceWithoutAnAssertion() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let log = await api.enrollmentLog
        #expect(log.count == 1 && log[0].hadAssertion == false)
        // The allowance is single use: the next enrollment needs the assertion.
        let challenge = try await api.beginDeviceEnrollment()
        #expect(challenge.assertionOptional == false)
        #expect(challenge.assertion?.challenge == challenge.challenge)
        #expect(challenge.assertion?.userVerification == "required")
        _ = services
    }

    @Test func enrollmentWithoutAnAssertionIsRefusedWhenNotOptional() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let challenge = try await api.beginDeviceEnrollment()
        let provisioned = try await DeviceKeyProvisioner(store: services.keys).provision(
            consumerId: api.consumerId, challenge: challenge.challenge, purposes: [.request])
        await #expect(throws: APIError.self) {
            _ = try await api.enrollDevice(DeviceEnrollRequest(name: "x", platform: .iOS, challenge: challenge.challenge, keys: provisioned.registrations))
        }
        do {
            _ = try await api.enrollDevice(DeviceEnrollRequest(name: "x", platform: .iOS, challenge: challenge.challenge, keys: provisioned.registrations))
            Issue.record("expected passkey_assertion_required")
        } catch let error as APIError {
            #expect(error.code == .passkeyAssertionRequired)
            #expect(error.userMessage == "Confirm with your passkey to add this device.")
        }
    }

    @Test func aNotFreshSessionPerformsTheAssertionAfterTheExplanation() async throws {
        let api = MockViadereAPI(seed: false)
        var services = await ViadereServices.mock(api: api)
        let passkeys = RecordingPasskeys()
        services.passkeys = passkeys
        try await services.records.clear()
        let explained = Box<[PasskeyExplanation]>([])
        let record = try await services.account.enrollThisDevice(name: "Second") { explanation in
            passkeys.note("explain")
            explained.value.append(explanation)
            return true
        }
        #expect(passkeys.events == ["explain", "assert"])
        #expect(explained.value.first?.context == .addDevice)
        #expect(explained.value.first?.title == "Confirm it's you")
        let log = await api.enrollmentLog
        #expect(log.last?.deviceId == record.deviceId && log.last?.hadAssertion == true)
    }

    @Test func reenrollmentAlwaysRequiresThePasskeyAssertion() async throws {
        for serverClaimsOptional in [false, true] {
            let api = MockViadereAPI(seed: false)
            var services = await ViadereServices.mock(api: api)
            let passkeys = RecordingPasskeys()
            services.passkeys = passkeys
            #expect(await api.enrollmentLog.count == 1)
            await api.setAssertionOptional(serverClaimsOptional)
            let old = try #require(try await services.records.load())

            let record = try await services.account.reenrollThisDevice(name: "iPhone") { _ in passkeys.note("explain"); return true }

            #expect(passkeys.events == ["explain", "assert"], "server claimed optional: \(serverClaimsOptional)")
            let log = await api.enrollmentLog
            #expect(log.count == 2 && log[1].hadAssertion, "the re-enrollment carried an assertion")
            #expect(record.deviceId != old.deviceId)
            let devices = try await api.devices()
            #expect(devices.first { $0.id == old.deviceId }?.revokedAt != nil)
            #expect(devices.first { $0.id == record.deviceId }?.revokedAt == nil)
        }
    }

    @Test func decliningTheExplanationChangesNothing() async throws {
        let api = MockViadereAPI(seed: false)
        var services = await ViadereServices.mock(api: api)
        let passkeys = RecordingPasskeys()
        services.passkeys = passkeys
        let before = try #require(try await services.records.load())
        await #expect(throws: PasskeyError.cancelled) {
            _ = try await services.account.reenrollThisDevice(name: "iPhone") { _ in false }
        }
        #expect(passkeys.assertions == 0)
        #expect(try await services.records.load() == before)
        #expect(await services.keys.availablePurposes() == Set(DeviceKeyPurpose.allCases))
        #expect(try await api.devices().allSatisfy { $0.revokedAt == nil })
    }

    @Test func aCancelledSystemSheetCreatesNoDevice() async throws {
        let api = MockViadereAPI(seed: false)
        var services = await ViadereServices.mock(api: api)
        services.passkeys = MockPasskeyService(fail: .cancelled)
        try await services.records.clear()
        let before = try await api.devices().count
        await #expect(throws: PasskeyError.cancelled) { _ = try await services.account.enrollThisDevice(name: "x") }
        #expect(try await api.devices().count == before)
    }

    @Test func theAppClipUsesCoresClientKindAndTheClipExplanation() async throws {
        let api = MockViadereAPI(seed: false)
        // A fresh session, but an earlier device was enrolled: the clip's enrollment needs the assertion.
        _ = await ViadereServices.mock(api: api)
        var clip = await ViadereServices.mock(api: api, signedIn: false)
        clip.isAppClip = true
        try await clip.sessions.set(TokenSet(consumerId: api.consumerId, accessToken: "t", accessExpiresAt: Date().addingTimeInterval(900)))
        let contexts = Box<[PasskeyExplanation.Context]>([])
        let record = try await clip.account.enrollThisDevice(name: "iPhone") { explanation in contexts.value.append(explanation.context); return true }
        #expect(contexts.value == [.appClip])
        let device = try #require(try await api.devices().first { $0.id == record.deviceId })
        #expect(device.clipDevice && device.approvalsLockedUntil == nil && device.expiresAt != nil)
    }

    @Test func aPasskeyAssertionRequiredResponseIsNotMistakenForAnExpiredSession() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { _, _ in json(401, errorBody("passkey_assertion_required", "Confirm with your passkey to add this device.")) }
        let refresher = CountingRefresher()
        let (client, _) = env.client(transport: transport, refresher: refresher)
        do {
            let _: Device = try await client.call(APIRoutes.deviceEnroll, body: DeviceEnrollRequest(name: "x", platform: .iOS, challenge: "c", keys: []))
            Issue.record("expected an error")
        } catch let error as APIError {
            #expect(error.code == .passkeyAssertionRequired)
        }
        #expect(await refresher.calls == 0)
        #expect(transport.requests.count == 1)
    }
}

final class Box<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value
    init(_ value: Value) { stored = value }
    var value: Value {
        get { lock.lock(); defer { lock.unlock() }; return stored }
        set { lock.lock(); stored = newValue; lock.unlock() }
    }
}

// MARK: - v2 decisions

@MainActor @Suite("Decisions are bound to what was displayed") @MainActor
struct DisplayedContextTests {
    func world() async -> (ViadereServices, MockViadereAPI) {
        let api = MockViadereAPI(seed: false)
        return (await ViadereServices.mock(api: api), api)
    }

    @Test func everyDecisionIsAV2PayloadWhoseDigestIsTheDisplayedInteractions() async throws {
        let (services, api) = await world()
        for (decision, envelope) in [(Decision.approve, PreviewData.authorize(sensitivity: .high)),
                                     (.deny, PreviewData.authorize(sensitivity: .high)),
                                     (.approve, PreviewData.authenticate(sensitivity: .standard)),
                                     (.select, PreviewData.choose())] {
            await api.add(envelope)
            let selected = decision == .select ? [try #require(({ () -> String? in
                if case .choose(let choose) = envelope.interaction.payload { return choose.options.first?.id }; return nil })())] : nil
            let outcome = try await services.approvals.submit(envelope, decision: decision, selectedOptionIds: selected)
            let signed = try payload(of: outcome)
            #expect(signed.payloadVersion == DecisionPayload.versionWithContext)
            #expect(signed.contextDigest == envelope.interaction.displayContextDigest())
            #expect(Interaction.isValidContextDigest(signed.contextDigest ?? ""))
        }
    }

    @Test func theViewModelSignsTheDigestOfTheInteractionItDisplayed() async throws {
        let (services, api) = await world()
        let envelope = PreviewData.authorize(sensitivity: .high)
        await api.add(envelope)
        let model = ApprovalViewModel(envelope: envelope, services: services)
        await model.load()
        let displayed = model.interaction
        await model.approve()
        let outcome = try #require(model.outcome)
        #expect(try payload(of: outcome).contextDigest == displayed.displayContextDigest())
    }

    @Test func aChangedRequestIsRefreshedAndNeverSigned() async throws {
        let (services, api) = await world()
        let displayed = PreviewData.authorize(sensitivity: .high, amount: "285.28")
        await api.add(tamperedAmount(displayed, to: "1999.00"))
        await #expect {
            _ = try await services.approvals.submit(displayed, decision: .approve)
        } throws: { error in
            guard case .contextChanged(let fresh?) = error as? ApprovalError else { return false }
            return fresh.interaction.displayContextDigest() != displayed.interaction.displayContextDigest()
        }
        #expect(await api.decideAttempts == 0, "nothing was signed or sent")
        #expect(await api.decisionLog.isEmpty)
    }

    @Test func serverContextMismatchRefreshesAndDoesNotRetry() async throws {
        let (services, api) = await world()
        let displayed = PreviewData.authorize(sensitivity: .high, amount: "285.28")
        // The request changes after the client's own freshness check would have run (race): skip that check.
        await api.add(tamperedAmount(displayed, to: "1999.00"))
        do {
            _ = try await services.approvals.submit(displayed, decision: .approve, verifyFresh: false)
            Issue.record("expected context_mismatch")
        } catch let error as ApprovalError {
            guard case .contextChanged(let fresh?) = error else { Issue.record("wrong error \(error)"); return }
            #expect(fresh.interaction.displayContextDigest() == tamperedAmount(displayed, to: "1999.00").interaction.displayContextDigest())
        }
        #expect(await api.decideAttempts == 1, "exactly one signature was attempted and it was not retried")
        #expect(await api.decisionLog.isEmpty)
    }

    @Test func theSheetShowsTheCurrentDetailsAndOnlyThenSignsWhatItShows() async throws {
        let (services, api) = await world()
        let displayed = PreviewData.authorize(sensitivity: .high, amount: "285.28")
        await api.add(displayed)
        let model = ApprovalViewModel(envelope: displayed, services: services)
        // The business changes the amount while the sheet is open.
        let changed = tamperedAmount(displayed, to: "1999.00")
        await api.add(changed)
        await model.approve()
        #expect(model.phase == .ready)
        #expect(model.showsChangedNotice)
        #expect(model.contextRevision == 1)
        #expect(model.headline.contains("1,999.00"))
        #expect(await api.decisionLog.isEmpty, "no signature without a new, explicit decision")

        await model.approve()
        let outcome = try #require(model.outcome)
        #expect(try payload(of: outcome).contextDigest == changed.interaction.displayContextDigest())
        #expect(await api.decideAttempts == 1)
    }

    @Test func theMockVerifiesLikeTheServer() async throws {
        let (services, api) = await world()
        let envelope = PreviewData.authorize(sensitivity: .high)
        await api.add(envelope)
        let record = try #require(try await services.records.load())
        let key = try await services.keys.requireKey(for: .approvalBiometric)
        func signed(_ digest: String?) async throws -> DecideInteractionRequest {
            let payload = DecisionPayload(interactionId: envelope.id, businessId: envelope.interaction.businessId, decision: .approve,
                                          challenge: envelope.interaction.challenge, signedAt: Date(), deviceId: record.deviceId,
                                          assurance: .biometric, contextDigest: digest)
            return DecideInteractionRequest(signedDecision: try await DecisionSigner(key: key).sign(payload), channel: .inApp)
        }
        // v1 for an approval: the digest is required.
        do { _ = try await api.decide(envelope.id, try await signed(nil)); Issue.record("v1 approval accepted") } catch let error as APIError {
            #expect(error.code == .contextDigestRequired)
        }
        // A wrong digest: mismatch.
        do { _ = try await api.decide(envelope.id, try await signed(String(repeating: "0", count: 64))); Issue.record("wrong digest accepted") } catch let error as APIError {
            #expect(error.code == .contextMismatch)
        }
        // The right one is accepted.
        let outcome = try await api.decide(envelope.id, try await signed(envelope.interaction.displayContextDigest()))
        #expect(outcome.status == .approved)
    }
}

// MARK: - New-device cool-down

@MainActor @Suite("New-device cool-down")
struct CoolDownTests {
    /// A trusted phone and a second one added later (which the mock, like the server, puts into the 24-hour cool-down).
    func twoPhones() async -> (trusted: ViadereServices, added: ViadereServices, api: MockViadereAPI) {
        let api = MockViadereAPI(seed: false)
        let trusted = await ViadereServices.mock(api: api)
        let added = await ViadereServices.mock(api: api)
        return (trusted, added, api)
    }

    @Test func aSecondDeviceStartsInTheCoolDownAndTheFirstDoesNot() async throws {
        let (trusted, added, api) = await twoPhones()
        let devices = try await api.devices()
        let firstId = try #require(try await trusted.records.load()?.deviceId)
        let secondId = try #require(try await added.records.load()?.deviceId)
        let first = try #require(devices.first { $0.id == firstId })
        let second = try #require(devices.first { $0.id == secondId })
        #expect(first.approvalsLockedUntil == nil)
        let until = try #require(second.approvalsLockedUntil)
        #expect(second.isCoolingDown(at: Date()) && until.timeIntervalSinceNow > 23 * 3_600)
    }

    @Test func denyAndReportWorkButHighRiskApprovalIsPaused() async throws {
        let (_, added, api) = await twoPhones()
        let high = PreviewData.authorize(sensitivity: .high)
        let other = PreviewData.authorize(sensitivity: .critical)
        let report = PreviewData.authorize(sensitivity: .high)
        for envelope in [high, other, report] { await api.add(envelope) }

        do { _ = try await added.approvals.submit(high, decision: .approve); Issue.record("approved while cooling down") } catch let error as ApprovalError {
            guard case .deviceCoolingDown(let until?) = error else { Issue.record("wrong error \(error)"); return }
            #expect(until > Date())
            #expect(error.userMessage.hasPrefix("For your security, this iPhone can approve high-risk requests after "))
            #expect(error.userMessage.hasSuffix(", or confirm it from your other device."))
        }
        #expect(await api.decideAttempts == 0, "paused before any Face ID prompt or network decision")

        let denied = try await added.approvals.submit(other, decision: .deny)
        #expect(denied.status == .denied)
        let reported = try await added.approvals.submit(report, decision: .report)
        #expect(reported.decision == .report)
    }

    @Test func lowerRiskApprovalsAreNotPaused() async throws {
        let (_, added, api) = await twoPhones()
        let standard = PreviewData.authenticate(sensitivity: .standard)
        await api.add(standard)
        let outcome = try await added.approvals.submit(standard, decision: .approve)
        #expect(outcome.status == .approved)
    }

    @Test func theServersDeviceCoolDownAnswerIsHandledToo() async throws {
        let (_, added, api) = await twoPhones()
        let high = PreviewData.authorize(sensitivity: .high)
        await api.add(high)
        await api.setDeviceListUnavailable(true) // the client can't pre-check; the server decides
        await #expect(throws: ApprovalError.deviceCoolingDown(until: nil)) {
            _ = try await added.approvals.submit(high, decision: .approve)
        }
        #expect(await api.decideAttempts == 1, "one attempt, never retried")
        #expect(await api.decisionLog.isEmpty)
    }

    @Test func theSheetPausesApprovingButStillDenies() async throws {
        let (_, added, api) = await twoPhones()
        let high = PreviewData.authorize(sensitivity: .high)
        await api.add(high)
        let model = ApprovalViewModel(envelope: high, services: added)
        await model.load()
        #expect(model.approvalPausedByCoolDown)
        #expect(model.coolDownMessage.contains("or confirm it from your other device"))
        await model.approve()
        #expect(model.phase == .ready && model.outcome == nil)
        #expect(await api.decideAttempts == 0)
        await model.deny()
        #expect(model.phase == .done(.deny, .denied))
    }

    @Test func homeExplainsTheCoolDownOnlyOnTheNewDevice() async throws {
        let (trusted, added, api) = await twoPhones()
        await api.add(PreviewData.authorize(sensitivity: .high))
        let newHome = HomeViewModel(services: added)
        await newHome.load()
        let notice = try #require(newHome.coolDownNotice)
        #expect(notice.contains("this iPhone can approve high-risk requests after"))
        let envelope = try #require(newHome.content.pending.first)
        #expect(newHome.isPausedByCoolDown(envelope))
        let oldHome = HomeViewModel(services: trusted)
        await oldHome.load()
        #expect(oldHome.coolDownNotice == nil)
    }

    @Test func messageWording() {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let locale = Locale(identifier: "en_US_POSIX")
        let now = Date(timeIntervalSince1970: 1_800_000_000) // 2027-01-15 08:00 UTC
        let later = now.addingTimeInterval(3 * 3_600)
        let tomorrow = now.addingTimeInterval(24 * 3_600)
        #expect(CoolDownPolicy.timeText(later, now: now, calendar: calendar, locale: locale) == "11:00 AM")
        #expect(CoolDownPolicy.timeText(tomorrow, now: now, calendar: calendar, locale: locale) == "tomorrow at 8:00 AM")
        #expect(CoolDownPolicy.message(until: later, now: now, calendar: calendar, locale: locale)
                == "For your security, this iPhone can approve high-risk requests after 11:00 AM, or confirm it from your other device.")
        #expect(CoolDownPolicy.restricts(.approve, on: PreviewData.authorize(sensitivity: .critical).interaction))
        #expect(!CoolDownPolicy.restricts(.deny, on: PreviewData.authorize(sensitivity: .critical).interaction))
        #expect(!CoolDownPolicy.restricts(.approve, on: PreviewData.authenticate(sensitivity: .standard).interaction))
    }
}

// MARK: - Confirmation proofs

@MainActor @Suite("Confirming a new device or phone")
struct ConfirmationTests {
    func twoPhones() async -> (trusted: ViadereServices, added: ViadereServices, api: MockViadereAPI, addedDevice: Device) {
        let api = MockViadereAPI(seed: false)
        let trusted = await ViadereServices.mock(api: api)
        let added = await ViadereServices.mock(api: api)
        let id = try? await added.records.load()?.deviceId
        let devices = (try? await api.devices()) ?? []
        return (trusted, added, api, devices.first { $0.id == id }!)
    }

    @Test func theProofIsSignedWithTheBiometricApprovalKeyOverTheSpecifiedInput() async throws {
        let (trusted, _, api, target) = await twoPhones()
        let record = try #require(try await trusted.records.load())
        let proof = try await trusted.confirmations.makeProof(subject: .device, subjectId: target.id.description, reason: "Confirm")
        #expect(proof.subject == .device && proof.assurance == .biometric && proof.deviceId == record.deviceId)
        #expect(proof.subjectId == target.id.description.lowercased())
        #expect(proof.requiredKeyPurpose == .approvalBiometric)
        let expectedInput = "VIADERE-CONFIRM-V1\ndevice\n\(target.id.description.lowercased())\n\(record.deviceId)\n\(ViadereDate.format(proof.signedAt))\nbiometric"
        #expect(proof.signingInput() == Data(expectedInput.utf8))
        let devices = try await api.devices()
        let key = try #require(devices.first { $0.id == record.deviceId }?.key(for: .approvalBiometric)?.publicKey)
        try proof.verify(subject: .device, subjectId: target.id.description, publicKey: key, now: Date())
        #expect(throws: ConfirmationProof.Failure.self) {
            try proof.verify(subject: .phoneLink, subjectId: target.id.description, publicKey: key, now: Date())
        }
    }

    @Test func withoutABiometricKeyThePasscodeKeySigns() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api, unsupportedKeys: [.approvalBiometric])
        let proof = try await services.confirmations.makeProof(subject: .phoneLink, subjectId: UUID().uuidString, reason: "Confirm")
        #expect(proof.assurance == .devicePasscode && proof.requiredKeyPurpose == .approvalUserPresence)
    }

    @Test func aRequestKeyOnlyDeviceCannotConfirm() async throws {
        let api = MockViadereAPI(seed: false)
        var clip = await ViadereServices.mock(api: api, signedIn: false)
        clip.isAppClip = true
        try await clip.sessions.set(TokenSet(consumerId: api.consumerId, accessToken: "t", accessExpiresAt: Date().addingTimeInterval(900)))
        _ = try await clip.account.enrollThisDevice(name: "iPhone")
        await #expect(throws: ConfirmationError.cannotConfirm) {
            _ = try await clip.confirmations.makeProof(subject: .device, subjectId: UUID().uuidString, reason: "Confirm")
        }
    }

    @Test func aTrustedDeviceLiftsTheCoolDownAndThenApprovalsWork() async throws {
        let (trusted, added, api, target) = await twoPhones()
        let high = PreviewData.authorize(sensitivity: .high)
        await api.add(high)
        await #expect(throws: ApprovalError.self) { _ = try await added.approvals.submit(high, decision: .approve) }

        let settings = SecuritySettingsViewModel(services: trusted)
        await settings.load()
        let listed = try #require(settings.devices.first { $0.id == target.id })
        #expect(settings.canConfirm(listed))
        #expect(settings.coolDownNote(for: listed)?.hasPrefix("New device. High-risk approvals unlock") == true)
        await settings.confirm(listed)
        #expect(settings.errorMessage == nil)
        #expect(settings.devices.first { $0.id == target.id }?.approvalsLockedUntil == nil)
        #expect(await api.confirmationLog.map(\.id) == [target.id.description])

        let outcome = try await added.approvals.submit(high, decision: .approve)
        #expect(outcome.status == .approved)
    }

    @Test func theNewDeviceCannotConfirmItselfOrAnythingElse() async throws {
        let (trusted, added, api, target) = await twoPhones()
        let selfProof = try await added.confirmations.makeProof(subject: .device, subjectId: target.id.description, reason: "Confirm")
        await #expect(throws: APIError.self) { _ = try await api.confirmDevice(target.id, proof: selfProof) }

        let settings = SecuritySettingsViewModel(services: added)
        await settings.load()
        #expect(!settings.canConfirmOthers)
        #expect(settings.thisDeviceLockedUntil != nil)
        let trustedId = try #require(try await trusted.records.load()?.deviceId)
        #expect(!settings.canConfirm(try #require(settings.devices.first { $0.id == trustedId })))
        #expect(await api.confirmationLog.isEmpty)
    }

    @Test func aProofWorksOnlyOnce() async throws {
        let (trusted, _, api, target) = await twoPhones()
        let proof = try await trusted.confirmations.makeProof(subject: .device, subjectId: target.id.description, reason: "Confirm")
        _ = try await api.confirmDevice(target.id, proof: proof)
        await api.setApprovalsLockedUntil(Date().addingTimeInterval(3_600), for: target.id)
        do { _ = try await api.confirmDevice(target.id, proof: proof); Issue.record("a proof was reused") } catch let error as APIError {
            #expect(error.code == .replayDetected)
        }
    }

    @Test func aProofForAnotherSubjectIsRefused() async throws {
        let (trusted, _, api, target) = await twoPhones()
        let proof = try await trusted.confirmations.makeProof(subject: .device, subjectId: UUID().uuidString, reason: "Confirm")
        do { _ = try await api.confirmDevice(target.id, proof: proof); Issue.record("wrong subject accepted") } catch let error as APIError {
            #expect(error.code == .signatureInvalid)
        }
        #expect(try await api.devices().first { $0.id == target.id }?.approvalsLockedUntil != nil)
    }

    @Test func linkFlowSendsBothConfirmationsAndShowsWhenThePhoneStartsWorking() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let settings = SecuritySettingsViewModel(services: services)
        await settings.load()
        await settings.loadAccountLinkPreview(token: "tok_abcdefghijklmnop")
        guard case .ready(let preview) = settings.accountLinkPhase else { Issue.record("no preview"); return }
        #expect(preview.maskedPhone == "+1 ••• ••• 0123" && preview.last4 == "0123")
        #expect(await settings.redeemAccountLink(token: "tok_abcdefghijklmnop", confirmedOwnPhone: false) == false)
        #expect(await settings.redeemAccountLink(token: "tok_abcdefghijklmnop", confirmedOwnPhone: true))

        let request = try #require(await api.redeemRequests.first)
        #expect(request.token == "tok_abcdefghijklmnop" && request.confirmPhoneLast4 == "0123" && request.confirmMaskedPhone == preview.maskedPhone)
        let phone = try #require(settings.lastLinkedPhone)
        let usableFrom = try #require(phone.usableFrom)
        #expect(usableFrom.timeIntervalSinceNow > 23 * 3_600)
        #expect(settings.accountLinkResultMessage?.contains("starts working") == true)
        #expect(settings.coolDownNote(for: phone)?.hasPrefix("Messages start working") == true)

        // The only device is trusted, so it can confirm the phone now.
        #expect(settings.canConfirm(phone))
        await settings.confirm(phone)
        #expect(settings.errorMessage == nil)
        #expect(settings.phones.first { $0.id == phone.id }?.usableFrom == nil)
        #expect(await api.confirmationLog.map(\.subject) == [.phoneLink])
    }

    @Test func aWrongConfirmationIsRefusedByTheLinkRedemption() async throws {
        let api = MockViadereAPI(seed: false)
        _ = await ViadereServices.mock(api: api)
        do {
            _ = try await api.redeemSMSLink(SMSLinkRedeemRequest(token: "tok_abcdefghijklmnop", confirmPhoneLast4: "9999", confirmMaskedPhone: "+1 ••• ••• 0123"))
            Issue.record("accepted a wrong confirmation")
        } catch let error as APIError { #expect(error.code == .forbidden) }
        #expect(await api.redeemRequests.isEmpty)
    }

    @Test func linkPreviewUsesCoresRouteAndDto() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { _, _ in
            json(#"{"maskedPhone":"+1 ••• ••• 4821","expiresAt":"2027-01-15T08:00:00.000Z"}"#)
        }
        let (client, _) = env.client(transport: transport)
        let live = LiveViadereAPI(client: client)
        let preview = try await live.previewPhoneLink(token: "tok_abcdefghijklmnop")
        #expect(preview.last4 == "4821")
        let request = try #require(transport.requests.first)
        #expect(request.method == .GET && pathAndQuery(request.url) == "/v1/sms/link-tokens/tok_abcdefghijklmnop/preview")
    }
}

// MARK: - Untrusted text vs. the shared sanitizer

@Suite("Untrusted text agrees with ViadereCore")
struct SanitizerConsistencyTests {
    @Test func everyScalarCoreDisallowsIsDroppedHere() {
        var leaked: [UInt32] = []
        for value in UInt32(0)...0x2FFFF {
            guard let scalar = Unicode.Scalar(value), DisplayTextSanitizer.isDisallowed(scalar, allowNewlines: true) else { continue }
            let cleaned = UntrustedText.clean("a\(scalar)b")
            if cleaned.unicodeScalars.contains(scalar) { leaked.append(value) }
        }
        #expect(leaked.isEmpty, "survived UntrustedText.clean: \(leaked.prefix(10).map { String($0, radix: 16) })")
    }

    @Test func outputIsAlwaysCleanByCoresDefinition() {
        let hostile = "Pay\u{202E}ment\u{200B}\n\u{2028}Amount\u{FFFC}\u{FE01}x\u{0301}\u{0301}\u{0301}\u{0301}"
        let cleaned = UntrustedText.line(hostile, max: 80)
        #expect(!DisplayTextSanitizer.containsDisallowedScalars(cleaned))
        #expect(DisplayTextSanitizer.sanitize(hostile, maxCharacters: 80).unicodeScalars.allSatisfy { !DisplayTextSanitizer.isDisallowed($0) })
        #expect(!cleaned.contains("\n"))
    }

    @Test func whatCoreCallsImpersonationIsImpersonationHere() {
        for sample in ["Viadere", "V I A D E R E Security", "Ｖｉａｄｅｒｅ", "vіаdеrе", "[Viadere] Support", "The Viadere team", "V1ADERE", "Viadere"] {
            #expect(UntrustedText.looksLikeViadere(sample), "\(sample)")
        }
        for sample in ["Northfield Market", "Harbor Bank", "Via Dere Street"] {
            #expect(!UntrustedText.looksLikeViadere(sample) || DisplayTextSanitizer.impersonatesViadere(sample, anywhere: true), "\(sample)")
        }
        #expect(UntrustedText.name("Viadere Security").impersonatesViadere)
    }
}
