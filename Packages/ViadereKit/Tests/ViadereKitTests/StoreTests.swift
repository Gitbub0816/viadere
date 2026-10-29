import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

@Suite("Home content")
struct HomeContentTests {
    @Test func ordersPendingSecurityFirstThenByExpiry() {
        let now = Date()
        let auth = PreviewData.authorize(now: now)
        let signIn = PreviewData.authenticate(now: now)
        let choose = PreviewData.choose(now: now)
        let confirm = PreviewData.confirm(now: now)
        let content = HomeContent.build(interactions: [confirm, choose, auth, signIn], relationships: [], now: now)
        #expect(content.pending.count == 4)
        // urgent sign-in (priority urgent) outranks high-priority authorize; both before everything else
        #expect(content.pending[0].id == signIn.id)
        #expect(content.pending[1].id == auth.id)
        #expect(content.pending.suffix(2).map(\.id).contains(confirm.id))
    }

    @Test func dropsExpiredDecidedAndNonActionable() {
        let now = Date()
        var decided = PreviewData.authorize(now: now)
        decided.status = .approved
        let expired = PreviewData.authorize(now: now.addingTimeInterval(-1_000), expiresIn: 600)
        let status = PreviewData.flightStatus(now: now)
        let content = HomeContent.build(interactions: [decided, expired, status], relationships: [], now: now)
        #expect(content.pending.isEmpty)
        #expect(content.statuses.count == 1)
    }

    @Test func recentBusinessesByActivity() {
        let now = Date()
        let a = PreviewData.relationship(PreviewData.harborBank, connectedAt: now.addingTimeInterval(-900))
        let b = PreviewData.relationship(PreviewData.northfield, connectedAt: now.addingTimeInterval(-800))
        var disconnected = PreviewData.relationship(PreviewData.copperline, connectedAt: now)
        disconnected.status = .disconnected
        let activity = PreviewData.authenticate(now: now, business: PreviewData.harborBank)
        let content = HomeContent.build(interactions: [activity], relationships: [b, a, disconnected], now: now)
        #expect(content.recent.map(\.business.id) == [PreviewData.harborBank.id, PreviewData.northfield.id])
        #expect(!content.isEmpty)
        #expect(HomeContent.build(interactions: [], relationships: [], now: now).isEmpty)
    }
}

@Suite("Permission copy")
struct PermissionCopyTests {
    @Test func essentialRowsAreLockedOn() {
        let rows = PermissionCopy.rows(supported: InteractionPurpose.allCases, granted: [.marketing: true, .security: false])
        #expect(rows.map(\.purpose) == [.security, .accountService, .transactional, .support, .marketing, .rewards])
        #expect(rows[0].isLocked && rows[0].isOn)
        #expect(rows[1].isLocked && rows[1].isOn)
        #expect(!rows[2].isLocked && rows[2].isOn)
        #expect(rows[4].isOn)           // granted
        #expect(!rows[5].isOn)          // marketing-like purposes default off
    }

    @Test func unsupportedOptionalPurposesAreHidden() {
        let rows = PermissionCopy.rows(supported: [.security, .transactional], granted: [:])
        #expect(rows.map(\.purpose) == [.security, .accountService, .transactional])
    }
}

@Suite("Connect flow")
@MainActor
struct ConnectViewModelTests {
    func make() async -> (ConnectViewModel, MockViadereAPI) {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        return (ConnectViewModel(services: services), api)
    }

    @Test func handleEntryToConnectedWithOptIn() async throws {
        let (model, api) = await make()
        model.setInput("@HarborBank")
        #expect(model.state.kind == .handle)
        await model.submit()
        guard case .review(let profile) = model.phase else { Issue.record("expected review, got \(model.phase)"); return }
        #expect(profile.displayName == "Harbor Bank")
        model.toggleOptIn(.marketing)
        model.toggleOptIn(.security) // not an opt-in: ignored
        #expect(model.optIns == [.marketing])
        await model.connect()
        guard case .connected(let relationship) = model.phase else { Issue.record("expected connected"); return }
        #expect(relationship.business.id == PreviewData.harborBank.id)
        #expect(relationship.source == .handle)
        let consents = try await api.consents(for: relationship.id)
        #expect(consents.first { $0.purpose == .marketing }?.granted == true)
        #expect(consents.first { $0.purpose == .security }?.granted == true)
        #expect(consents.first { $0.purpose == .rewards }?.granted == false)
    }

    @Test func codeEntryNormalizesAndResolves() async throws {
        let (model, _) = await make()
        model.setInput("hb7k29")
        #expect(model.input == "HB-7K29")
        #expect(model.state.canSubmit)
        await model.submit()
        guard case .review(let profile) = model.phase else { Issue.record("expected review"); return }
        #expect(profile.code.canonical == "HB7K29")
    }

    @Test func nameSearchAndSelection() async throws {
        let (model, _) = await make()
        model.setInput("copper")
        await model.refreshSuggestions()
        #expect(model.suggestions.map(\.displayName) == ["Copperline Coffee"])
        await model.submit()
        guard case .review(let profile) = model.phase else { Issue.record("single match goes straight to review"); return }
        #expect(profile.displayName == "Copperline Coffee")
    }

    @Test func ambiguousNameOffersChoices() async throws {
        let (model, _) = await make()
        model.setInput("or") // Northfield, Harbor... several contain "or"
        await model.submit()
        if case .choose(let matches) = model.phase { #expect(matches.count > 1) } else { Issue.record("expected choices, got \(model.phase)") }
    }

    @Test func unknownCodeFailsGracefully() async throws {
        let (model, _) = await make()
        model.setInput("ZZ9999")
        await model.submit()
        #expect(model.phase == .failed("We couldn't find a verified business for that."))
        model.setInput("ZZ99991")
        #expect(model.phase == .entry)
    }

    @Test func scannedQRCodes() async throws {
        let (model, _) = await make()
        await model.handleScanned("https://viadere.com/c/NM4P82")
        guard case .review(let profile) = model.phase else { Issue.record("expected review"); return }
        #expect(profile.displayName == "Northfield Market")
        model.reset()
        await model.handleScanned("https://evil.example.com/c/NM4P82")
        #expect(model.scanError == "That QR code isn't from Viadere.")
        #expect(model.phase == .entry)
        await model.handleScanned("just some text")
        #expect(model.scanError != nil)
    }

    @Test func incomingLinkOpensReview() async throws {
        let (model, _) = await make()
        let code = try #require(BusinessCode(parsing: "LD2R56"))
        await model.open(code: code, link: ConnectLink(code: code), source: .qr)
        guard case .review = model.phase else { Issue.record("expected review"); return }
        await model.connect()
        guard case .connected(let relationship) = model.phase else { Issue.record("expected connected"); return }
        #expect(relationship.source == .qr)
    }
}

@Suite("Onboarding")
@MainActor
struct OnboardingTests {
    @Test func resumePoints() {
        #expect(OnboardingFlow.resume(hasSession: false, hasDevice: false, primingShown: false, complete: false) == .welcome)
        #expect(OnboardingFlow.resume(hasSession: true, hasDevice: false, primingShown: false, complete: false) == .device)
        #expect(OnboardingFlow.resume(hasSession: true, hasDevice: true, primingShown: false, complete: false) == .notifications)
        #expect(OnboardingFlow.resume(hasSession: true, hasDevice: true, primingShown: true, protectionShown: false, complete: false) == .protect)
        #expect(OnboardingFlow.resume(hasSession: true, hasDevice: true, primingShown: true, protectionShown: true, complete: false) == .phone)
        #expect(OnboardingFlow.resume(hasSession: true, hasDevice: true, primingShown: true, complete: true) == .done)
    }

    /// Device-first: consent, this iPhone creates the account (no name, email, phone or passkey), notifications, optional protection,
    /// optional phone.
    @Test func fullFlow() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api, signedIn: false)
        let model = OnboardingViewModel(services: services, deviceName: "Ana's iPhone")
        #expect(model.canCreateAccount, "nothing personal is needed")
        model.begin()
        #expect(model.step == .device)
        await model.enrollDevice()
        #expect(model.step == .notifications)
        #expect(model.errorMessage == nil)
        #expect(await services.sessions.isSignedIn)
        #expect(model.maxAssurance == .biometric)
        let created = try #require(await api.accountCreateRequests.first)
        #expect(created.deviceName == "Ana's iPhone")
        #expect(created.integrity?.format == .appleAppAttest)
        #expect(await api.enrollmentLog.isEmpty, "no passkey enrollment")
        #expect(try await api.devices().first?.trustTier == .d1)

        await model.allowNotifications()
        #expect(model.step == .protect)
        #expect(services.preferences.bool(.notificationPrimingShown))

        // Recovery codes: this iPhone's Face ID proves it; the codes are shown once, then back to the protect step.
        await model.makeRecoveryCodes()
        #expect(model.step == .recoveryCodes)
        #expect(model.recoveryCodes?.codes?.codes.count == RecoveryPolicy.codeCount)
        model.recoveryCodesSaved()
        #expect(model.step == .recoveryCodes, "not without the confirmation")
        model.recoveryCodes?.confirmedSaved = true
        model.recoveryCodesSaved()
        #expect(model.step == .protect)
        #expect(model.hasRecoveryCodes)
        // A passkey as well.
        await model.addPasskey()
        #expect(model.hasPasskey)
        #expect(model.errorMessage == nil)
        model.continueFromProtection()
        #expect(model.step == .phone)
        #expect(services.preferences.bool(.protectionPromptShown))

        model.setPhone("4805550123")
        #expect(model.phoneRaw == "(480) 555-0123")
        #expect(model.canSendCode)
        await model.sendCode()
        #expect(model.phoneStage == .verify)
        model.setOTP("12a3-45")
        #expect(model.otp == "12345")
        #expect(!model.canVerify)
        model.setOTP("000000")
        await model.verifyCode()
        #expect(model.errorMessage != nil)
        model.setOTP("123456")
        await model.verifyCode()
        if case .linked = model.phoneStage {} else { Issue.record("expected linked") }

        var finished = false
        model.onFinished = { finished = true }
        model.finish()
        #expect(finished)
        #expect(services.preferences.bool(.onboardingComplete))
    }

    @Test func skippingProtectionNeedsTheHonestWarningFirst() async throws {
        let services = await ViadereServices.mock(api: MockViadereAPI(seed: false), signedIn: false)
        let model = OnboardingViewModel(services: services, start: .protect)
        model.skipProtection()
        #expect(model.step == .protect, "the first tap only shows the warning")
        #expect(model.showsSkipWarning)
        #expect(OnboardingViewModel.skipWarning.contains("can't be recovered"))
        model.cancelSkip()
        #expect(!model.showsSkipWarning)
        model.skipProtection()
        model.confirmSkipProtection()
        #expect(model.step == .phone)
        #expect(services.preferences.bool(.protectionPromptShown))
    }

    @Test func deviceWithoutBiometricsStillCreatesTheAccountAndCanMakeCodes() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api, signedIn: false, unsupportedKeys: [.approvalBiometric])
        let model = OnboardingViewModel(services: services)
        model.begin()
        await model.enrollDevice()
        #expect(model.step == .notifications)
        #expect(model.maxAssurance == .devicePasscode)
        #expect(model.skippedKeys == [.approvalBiometric])
        model.skipNotifications()
        await model.makeRecoveryCodes()
        #expect(model.step == .recoveryCodes, "the passcode key proves it when Face ID isn't set up")
    }

    @Test func anExistingAccountSignsInWithItsPasskeyAndEnrollsThisDevice() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api, signedIn: false)
        let model = OnboardingViewModel(services: services)
        await model.signIn()
        #expect(model.step == .device)
        await model.enrollDevice()
        #expect(model.step == .notifications)
        #expect(await api.accountCreateRequests.isEmpty, "an existing account is not created again")
        #expect(await api.enrollmentLog.count == 1)
    }

    @Test func aFailedAccountCreationLeavesNothingBehind() async throws {
        let api = MockViadereAPI(seed: false)
        await api.setRequiresAttestation(true)
        let services = await ViadereServices.mock(api: api, signedIn: false, appAttest: UnavailableAppAttest())
        let model = OnboardingViewModel(services: services)
        model.begin()
        await model.enrollDevice()
        #expect(model.step == .device)
        #expect(model.errorMessage != nil)
        #expect(!(await services.sessions.isSignedIn))
        #expect((try? await services.records.load()) == nil)
    }
}

@Suite("App model")
@MainActor
struct AppModelTests {
    @Test func bootstrapPhases() async throws {
        let fresh = AppModel(services: await ViadereServices.mock(api: MockViadereAPI(seed: false), signedIn: false))
        await fresh.bootstrap()
        #expect(fresh.phase == .onboarding(.welcome))

        let ready = AppModel(services: await ViadereServices.mock())
        await ready.bootstrap()
        #expect(ready.phase == .ready)
        #expect(!ready.home.content.pending.isEmpty)
        #expect(!ready.isLocked)
    }

    @Test func lostKeysForceReenrollment() async throws {
        let services = await ViadereServices.mock()
        try await services.keys.deleteKey(for: .approvalBiometric)
        let model = AppModel(services: services)
        await model.bootstrap()
        #expect(model.phase == .needsReenrollment)
        // The person is told why a passkey is needed before the system sheet; here they continue.
        let work = Task { @MainActor in try await model.reenroll(deviceName: "iPhone") }
        while model.passkeyGate.pending == nil { await Task.yield() }
        #expect(model.passkeyGate.pending?.context == .setUpAgain)
        model.passkeyGate.resolve(true)
        try await work.value
        #expect(model.phase == .ready)
        #expect(await services.account.health() == .healthy)
    }

    @Test func decliningTheSetUpAgainExplanationLeavesTheAppWhereItWas() async throws {
        let services = await ViadereServices.mock()
        try await services.keys.deleteKey(for: .approvalBiometric)
        let model = AppModel(services: services)
        await model.bootstrap()
        let work = Task { @MainActor in try await model.reenroll(deviceName: "iPhone") }
        while model.passkeyGate.pending == nil { await Task.yield() }
        model.passkeyGate.resolve(false)
        await #expect(throws: PasskeyError.cancelled) { try await work.value }
        #expect(model.phase == .needsReenrollment)
    }

    @Test func appLockOnColdLaunchAndAfterGracePeriod() async throws {
        let services = await ViadereServices.mock()
        services.preferences.setBool(true, for: .appLockEnabled)
        let model = AppModel(services: services)
        await model.bootstrap()
        #expect(model.isLocked)
        await model.unlock()
        #expect(!model.isLocked)
        model.sceneDidEnterBackground()
        await model.sceneWillEnterForeground() // immediately back: inside the grace period
        #expect(!model.isLocked)
        #expect(AppLockPolicy(enabled: true, gracePeriod: 15).shouldLock(backgroundedAt: Date().addingTimeInterval(-60), now: Date(), isColdLaunch: false))
        #expect(!AppLockPolicy(enabled: false).shouldLock(backgroundedAt: nil, now: Date(), isColdLaunch: true))
    }

    @Test func deepLinksRouteAndQueueUntilReady() async throws {
        let services = await ViadereServices.mock()
        let model = AppModel(services: services)
        let code = try #require(BusinessCode(parsing: "AF2345"))
        await model.handle(.connect(code: code, link: nil)) // before bootstrap: queued
        #expect(model.pendingConnect == nil)
        await model.bootstrap()
        #expect(model.pendingConnect?.code == code)
        #expect(model.selectedTab == .connect)
        await model.handle(.settings)
        #expect(model.selectedTab == .settings)
        let session = SessionID()
        await model.handle(.conversation(session))
        #expect(model.conversationToOpen == session)
    }

    @Test func notificationTapPresentsApprovalSheet() async throws {
        let api = MockViadereAPI()
        let services = await ViadereServices.mock(api: api)
        let model = AppModel(services: services)
        await model.bootstrap()
        let pending = try #require(model.home.content.pending.first)
        await model.apply(.requiresApp(pending.id))
        #expect(model.presentedApproval?.envelope.id == pending.id)
        await model.presentedApproval?.deny()
        #expect(!model.home.content.pending.contains { $0.id == pending.id })
        await model.apply(.stale(pending.id, .denied))
        #expect(model.toast == "That was already handled.")
    }

    @Test func signOutWipesEverything() async throws {
        let services = await ViadereServices.mock()
        #expect(await services.sessions.isSignedIn)
        let model = AppModel(services: services)
        await model.bootstrap()
        await model.signOut()
        #expect(model.phase == .onboarding(.welcome))
        #expect(!(await services.sessions.isSignedIn))
        #expect(try await services.records.load() == nil)
        #expect(await services.keys.availablePurposes().isEmpty)
        #expect(!services.preferences.bool(.onboardingComplete))
        #expect((services.secrets as? InMemorySecretStore)?.count == 0)
    }

    @Test func deviceRevocationWipesAndExplains() async throws {
        let services = await ViadereServices.mock()
        let model = AppModel(services: services)
        await model.bootstrap()
        await model.deviceWasRevoked()
        #expect(model.phase == .onboarding(.welcome))
        #expect(model.toast == "This device was removed from your account.")
        #expect(await services.keys.availablePurposes().isEmpty)
    }
}

@Suite("Business detail, messages and settings")
@MainActor
struct DetailStoreTests {
    @Test func consentToggleOptimisticWithRollback() async throws {
        let api = MockViadereAPI()
        let services = await ViadereServices.mock(api: api)
        let relationship = try #require(try await api.relationships().first)
        let model = BusinessDetailViewModel(relationship: relationship, services: services)
        await model.load()
        #expect(model.rows.first { $0.purpose == .security }?.isLocked == true)
        await model.setConsent(.marketing, granted: true)
        #expect(model.consents[.marketing] == true)
        await model.setConsent(.security, granted: false) // ignored: not revocable
        #expect(model.consents[.security] != false)
        await model.disconnect()
        #expect(model.isDisconnected)
        #expect(try await api.relationships().count == 3)
    }

    @Test func conversationShowsChoiceChipsAndSends() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let business = PreviewData.lindenDental
        let conversation = try await api.startConversation(with: business.id)
        let model = ConversationViewModel(conversation: conversation, services: services)
        model.draft = "  Hello  "
        #expect(model.canSend)
        await model.send()
        #expect(model.rows.last?.message.body == "Hello")
        #expect(model.draft.isEmpty)
        model.draft = String(repeating: "a", count: 1_601)
        #expect(!model.canSend)

        let choose = PreviewData.choose()
        await api.add(choose)
        let message = ConversationMessage(id: MessageID(), sessionId: conversation.id, businessId: business.id, direction: .businessToConsumer,
                                          attribution: MessageAttribution(senderType: .agent, displayName: business.displayName),
                                          body: "Pick a time", channel: .inApp, createdAt: Date(), deliveryStatus: .delivered,
                                          interactionId: choose.id)
        let row = MessageRow(message: message, choice: choose)
        #expect(row.openOptions(now: Date()).count == 3)
        var answered = row
        answered.choice?.status = .selected
        #expect(answered.openOptions(now: Date()).isEmpty)
        await model.choose(ChoiceOption(id: "tue_9", label: "Tue 9:00"), in: row)
        #expect(try await api.interaction(choose.id).status == .selected)
    }

    @Test func settingsAppLockRequiresAuthentication() async throws {
        let services = await ViadereServices.mock()
        let model = SecuritySettingsViewModel(services: services)
        await model.setAppLock(true)
        #expect(model.appLockEnabled)
        #expect(services.preferences.bool(.appLockEnabled))
        await model.setAppLock(false)
        #expect(!model.appLockEnabled)

        var denied = services
        denied.appLock = MockAppLockAuthenticator(succeeds: false)
        let model2 = SecuritySettingsViewModel(services: denied)
        await model2.setAppLock(true)
        #expect(!model2.appLockEnabled)
    }

    @Test func addingAndRedeemingPhones() async throws {
        let services = await ViadereServices.mock()
        let model = SecuritySettingsViewModel(services: services)
        await model.startAddPhone("123")
        if case .failed = model.addPhoneStage {} else { Issue.record("expected failure for a short number") }
        await model.startAddPhone("(480) 555-0123")
        #expect(model.addPhoneStage == .awaitingCode)
        await model.verifyAddPhone(code: "000000")
        if case .failed = model.addPhoneStage {} else { Issue.record("expected failure for a wrong code") }
        await model.startAddPhone("(480) 555-0123")
        await model.verifyAddPhone(code: "123456")
        #expect(model.addPhoneStage == .idle)
        #expect(model.phones.count == 1)
        let token = String(repeating: "A", count: 43)
        // The link needs a preview and an explicit "This is my phone" before anything is linked.
        #expect(!(await model.redeemAccountLink(token: token, confirmedOwnPhone: true)))
        await model.loadAccountLinkPreview(token: token)
        #expect(!(await model.redeemAccountLink(token: token, confirmedOwnPhone: false)))
        #expect(model.phones.count == 1)
        #expect(await model.redeemAccountLink(token: token, confirmedOwnPhone: true))
        #expect(model.phones.count == 2)
    }

    @Test func settingsListsDevicesAndConsentHistory() async throws {
        let services = await ViadereServices.mock()
        let model = SecuritySettingsViewModel(services: services)
        await model.load()
        #expect(model.devices.count == 1)
        #expect(model.currentDeviceId == model.devices.first?.id)
        await model.revoke(model.devices[0]) // current device can't be revoked from here
        #expect(model.devices[0].revokedAt == nil)
        #expect(!model.consentHistory.isEmpty)
        #expect(model.sessions.count == 1)
    }
}
