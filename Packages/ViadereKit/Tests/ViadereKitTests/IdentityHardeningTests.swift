import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

/// A passkey service that can be told to cancel once (the person dismisses the sheet) and then succeed.
final class FlakyPasskeys: PasskeyService, @unchecked Sendable {
    private let lock = NSLock()
    private var _cancelNext: Bool
    private let inner = MockPasskeyService()
    init(cancelFirstRegistration: Bool = false) { _cancelNext = cancelFirstRegistration }
    func register(options: PasskeyRegistrationOptions) async throws -> PasskeyRegistrationCredential {
        if takeCancel() { throw PasskeyError.cancelled }
        return try await inner.register(options: options)
    }
    private func takeCancel() -> Bool {
        lock.lock(); defer { lock.unlock() }
        let cancel = _cancelNext
        _cancelNext = false
        return cancel
    }
    func assert(options: PasskeyAssertionOptions) async throws -> PasskeyAssertionCredential { try await inner.assert(options: options) }
}

private func authSessionJSON(access: String = "fresh-access", refresh: String = "fresh-refresh") throws -> String {
    let session = AuthSession(consumerId: PreviewData.consumerId, accessToken: access, expiresAt: Date().addingTimeInterval(900),
                              refreshToken: refresh, refreshExpiresAt: Date().addingTimeInterval(86_400))
    return String(decoding: try ViadereJSON.encode(session), as: UTF8.self)
}

/// Every string the app could have stored (Keychain items ever written, preferences) must not contain any of `secrets`.
private func assertNeverStored(_ secrets: [String], in services: ViadereServices, sourceLocation: SourceLocation = #_sourceLocation) {
    let store = services.secrets as? InMemorySecretStore
    let written = (store?.everWritten ?? []).map { String(decoding: $0, as: UTF8.self) }
    let prefs = (services.preferences as? InMemoryPreferences)?.allValues ?? []
    for secret in secrets {
        #expect(!written.contains { $0.contains(secret) }, "a recovery code reached the keychain store", sourceLocation: sourceLocation)
        #expect(!prefs.contains { $0.contains(secret) }, "a recovery code reached preferences", sourceLocation: sourceLocation)
    }
}

@Suite("App Attest at enrollment")
struct AppAttestEnrollmentTests {
    @Test func theAttestationNamesExactlyTheKeysThatAreSent() async throws {
        let api = MockViadereAPI(seed: false)
        let attest = MockAppAttest()
        let services = await ViadereServices.mock(api: api, appAttest: attest)
        let request = try #require(await api.enrollRequests.last)
        let evidence = try #require(request.appAttest)
        let attested = try #require(attest.attested.last)
        #expect(request.keys.count == DeviceKeyPurpose.allCases.count)
        // keys sent == keys attested: the clientDataHash is recomputed over the request's own key list.
        let expected = AppAttestBinding.clientDataHash(consumerId: PreviewData.consumerId, challenge: request.challenge, keys: request.keys)
        #expect(attested.clientDataHash == expected)
        #expect(attested.keyId == evidence.keyId)
        #expect(Base64URL.decode(evidence.attestation) == Data("mock-attestation:".utf8) + expected)
        _ = services
    }

    @Test func theAppClipAttestsItsRequestKeyOnly() async throws {
        let api = MockViadereAPI(seed: false)
        let attest = MockAppAttest()
        var services = await ViadereServices.mock(api: api, signedIn: false, appAttest: attest)
        services.isAppClip = true
        try await services.sessions.set(TokenSet(consumerId: PreviewData.consumerId, accessToken: "t", accessExpiresAt: Date().addingTimeInterval(900)))
        _ = try await services.account.enrollThisDevice(name: "Clip")
        let request = try #require(await api.enrollRequests.last)
        #expect(request.keys.map(\.purpose) == [.request])
        #expect(request.effectiveClientKind == .appClip)
        let hash = AppAttestBinding.clientDataHash(consumerId: PreviewData.consumerId, challenge: request.challenge, keys: request.keys)
        #expect(attest.attested.last?.clientDataHash == hash)
    }

    @Test func everyEnrollmentUsesANewAppAttestKey() async throws {
        let api = MockViadereAPI(seed: false)
        let attest = MockAppAttest()
        let services = await ViadereServices.mock(api: api, appAttest: attest)
        _ = try await services.account.reenrollThisDevice(name: "Again")
        let ids = await api.enrollRequests.compactMap { $0.appAttest?.keyId }
        #expect(ids.count == 2 && Set(ids).count == 2)
        #expect(attest.generatedKeyCount == 2)
    }

    @Test func anAttestationOverOtherKeysIsRefused() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api, signedIn: false)
        try await services.sessions.set(TokenSet(consumerId: PreviewData.consumerId, accessToken: "t", accessExpiresAt: Date().addingTimeInterval(900)))
        let challenge = try await api.beginDeviceEnrollment()
        let provisioned = try await DeviceKeyProvisioner(store: services.keys).provision(
            consumerId: PreviewData.consumerId, challenge: challenge.challenge, purposes: DeviceKeyPurpose.allCases)
        // Vouches for only the request key, while all three keys are sent.
        let wrong = AppAttestBinding.clientDataHash(consumerId: PreviewData.consumerId, challenge: challenge.challenge,
                                                    keys: provisioned.registrations.filter { $0.purpose == .request })
        let evidence = AppAttestEvidence(keyId: "k", attestation: Base64URL.encode(Data("mock-attestation:".utf8) + wrong))
        await #expect(throws: APIError.self) {
            _ = try await api.enrollDevice(DeviceEnrollRequest(name: "x", platform: .iOS, challenge: challenge.challenge,
                                                               keys: provisioned.registrations, appAttest: evidence))
        }
    }

    @Test func unsupportedHardwareSkipsInDebugAndFailsInRelease() async throws {
        let api = MockViadereAPI(seed: false)
        let unsupported = MockAppAttest(isSupported: false)
        // DEBUG (the simulator): enrolls without evidence.
        let debug = await ViadereServices.mock(api: api, signedIn: false, appAttest: unsupported)
        try await debug.sessions.set(TokenSet(consumerId: PreviewData.consumerId, accessToken: "t", accessExpiresAt: Date().addingTimeInterval(900)))
        _ = try await AccountService(api: debug.api, sessions: debug.sessions, passkeys: debug.passkeys, keys: debug.keys, records: debug.records,
                                     preferences: debug.preferences, secrets: debug.secrets, appAttest: unsupported,
                                     skipsAttestationWhenUnsupported: true).enrollThisDevice(name: "Sim")
        #expect(await api.enrollRequests.last?.appAttest == nil)
        // Release: the error is reported and nothing is enrolled.
        let release = await ViadereServices.mock(api: MockViadereAPI(seed: false), signedIn: false, appAttest: unsupported)
        try await release.sessions.set(TokenSet(consumerId: PreviewData.consumerId, accessToken: "t", accessExpiresAt: Date().addingTimeInterval(900)))
        let strict = AccountService(api: release.api, sessions: release.sessions, passkeys: release.passkeys, keys: release.keys,
                                    records: release.records, preferences: release.preferences, secrets: release.secrets,
                                    appAttest: unsupported, skipsAttestationWhenUnsupported: false)
        await #expect(throws: AppAttestError.unsupported) { _ = try await strict.enrollThisDevice(name: "Sim") }
        #expect(try await release.records.load() == nil)
    }

    @MainActor
    @Test func attestationRequiredIsExplainedCalmly() async throws {
        let api = MockViadereAPI(seed: false)
        await api.setRequiresAttestation(true)
        let services = await ViadereServices.mock(api: api, signedIn: false, appAttest: MockAppAttest(isSupported: false))
        let model = OnboardingViewModel(services: services, start: .device)
        try await services.sessions.set(TokenSet(consumerId: PreviewData.consumerId, accessToken: "t", accessExpiresAt: Date().addingTimeInterval(900)))
        await model.enrollDevice()
        #expect(model.errorMessage == "This iPhone couldn't be verified. Make sure you're using the App Store version of Viadere.")
        #expect(model.step == .device)
        #expect(APIError.server(status: 403, code: .attestationRequired, message: "raw").userMessage == AttestationMessage.notVerified)
        #expect(AppAttestError.unsupported.userMessage == AttestationMessage.notVerified)
    }
}

@Suite("Signed refresh")
struct SignedRefreshTests {
    private func executor(_ env: ClientEnv, _ transport: FakeTransport) -> RequestExecutor {
        RequestExecutor(baseURL: URL(string: "http://localhost:8080")!, transport: transport,
                        signer: DeviceRequestSigner(records: env.records, keys: env.keys))
    }

    @Test func theRefreshRequestIsSignedWithTheRequestKeyAndHasNoBearer() async throws {
        let env = try await ClientEnv()
        let body = try authSessionJSON()
        let transport = FakeTransport { _, _ in json(body) }
        let refresher = APITokenRefresher(executor: executor(env, transport))
        let tokens = try await refresher.refresh(current: TokenSet(consumerId: env.consumerId, accessToken: "old",
                                                                  accessExpiresAt: Date(), refreshToken: "r-old"))
        #expect(tokens.accessToken == "fresh-access")
        let request = try #require(transport.requests.first)
        #expect(request.url.path == "/v1/auth/refresh" && request.method == .POST)
        #expect(request.headers["Authorization"] == nil, "no bearer on a refresh")
        let signed = try SignedRequestHeaders(headers: request.headers)
        #expect(signed.deviceId == env.deviceId)
        let publicKey = try await env.keys.requireKey(for: .request).publicKey
        // The signature covers this exact request: method, path and the body bytes that carry the refresh token.
        try RequestVerifier().verify(method: "POST", pathAndQuery: "/v1/auth/refresh", body: try #require(request.body), headers: signed,
                                     publicKey: publicKey, now: Date())
        #expect(String(decoding: try #require(request.body), as: UTF8.self).contains("r-old"))
    }

    @Test func withoutAnEnrolledDeviceTheRefreshGoesOutUnsigned() async throws {
        let secrets = InMemorySecretStore()
        let transport = FakeTransport { _, _ in json(try! authSessionJSON()) }
        let signer = DeviceRequestSigner(records: SecretDeviceRecordStore(secrets: secrets), keys: SoftwareDeviceKeyStore(secrets: InMemorySecretStore()))
        let refresher = APITokenRefresher(executor: RequestExecutor(baseURL: URL(string: "http://localhost:8080")!, transport: transport, signer: signer))
        _ = try await refresher.refresh(current: TokenSet(consumerId: PreviewData.consumerId, accessToken: "o", accessExpiresAt: Date(), refreshToken: "r"))
        let request = try #require(transport.requests.first)
        #expect(request.headers[ViadereHeader.signature] == nil && request.headers[ViadereHeader.device] == nil)
        #expect(request.headers["Authorization"] == nil)
    }

    @Test func aSkewedClockOrReplayedNonceIsRetriedOnceWithAFreshSignature() async throws {
        let env = try await ClientEnv()
        let ok = try authSessionJSON()
        let transport = FakeTransport { _, index in index == 0 ? json(401, errorBody("clock_skew")) : json(ok) }
        let refresher = APITokenRefresher(executor: executor(env, transport))
        _ = try await refresher.refresh(current: TokenSet(consumerId: env.consumerId, accessToken: "o", accessExpiresAt: Date(), refreshToken: "r"))
        #expect(transport.requests.count == 2)
        let nonces = try transport.requests.map { try SignedRequestHeaders(headers: $0.headers).nonce }
        #expect(Set(nonces).count == 2)
    }

    @Test func aRejectedSignatureDoesNotThrowTheSessionAway() async throws {
        let env = try await ClientEnv()
        try await env.tokens.save(TokenSet(consumerId: env.consumerId, accessToken: "old", accessExpiresAt: Date().addingTimeInterval(-10), refreshToken: "r-keep"))
        let transport = FakeTransport { _, _ in json(401, errorBody("signature_invalid")) }
        let sessions = SessionManager(store: env.tokens, refresher: APITokenRefresher(executor: executor(env, transport)))
        await #expect(throws: APIError.self) { _ = try await sessions.validAccessToken() }
        #expect(try await env.tokens.load()?.refreshToken == "r-keep")
        // A refused refresh token, by contrast, ends the session.
        let refused = FakeTransport { _, _ in json(401, errorBody("unauthorized")) }
        let sessions2 = SessionManager(store: env.tokens, refresher: APITokenRefresher(executor: executor(env, refused)))
        await #expect(throws: APIError.sessionExpired) { _ = try await sessions2.validAccessToken() }
    }

    @Test func theNotificationExtensionRefreshesWithTheSharedRequestKey() async throws {
        // The app enrolled (device record + request key live in the shared Keychain group). The extension is a separate process
        // with its own SessionManager over the same stores, and its expired access token forces a refresh.
        let env = try await ClientEnv()
        try await env.tokens.save(TokenSet(consumerId: env.consumerId, accessToken: "old", accessExpiresAt: Date().addingTimeInterval(-10), refreshToken: "r-ext"))
        let body = try authSessionJSON(access: "ext-access")
        let transport = FakeTransport { request, _ in
            request.url.path == "/v1/auth/refresh" ? json(body) : json(#"{"id":"\#(UUID().uuidString.lowercased())"}"#)
        }
        let extensionExecutor = executor(env, transport)
        let sessions = SessionManager(store: env.tokens, refresher: APITokenRefresher(executor: extensionExecutor))
        let token = try await sessions.validAccessToken()
        #expect(token == "ext-access")
        let refresh = try #require(transport.requests.first)
        #expect(refresh.headers["Authorization"] == nil)
        let signed = try SignedRequestHeaders(headers: refresh.headers)
        #expect(signed.deviceId == env.deviceId)
        let publicKey = try await env.keys.requireKey(for: .request).publicKey
        try RequestVerifier().verify(method: "POST", pathAndQuery: "/v1/auth/refresh", body: try #require(refresh.body), headers: signed,
                                     publicKey: publicKey, now: Date())
    }
}

@MainActor
@Suite("Recovery codes at registration and in Settings")
struct RecoveryCodesTests {
    @Test func theProtectStepShowsTheCodesOnceAndNeverStoresThem() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api, signedIn: false)
        let model = OnboardingViewModel(services: services)
        model.begin()
        await model.enrollDevice()
        model.skipNotifications()
        #expect(model.step == .protect)
        await model.makeRecoveryCodes()
        let set = try #require(model.recoveryCodes?.codes)
        #expect(model.step == .recoveryCodes && set.codes.count == RecoveryPolicy.codeCount)
        #expect(set.codes.allSatisfy { RecoveryCodeFormat.normalizeCode($0) != nil })
        #expect(RecoveryCodeFormat.normalizeRecoveryID(set.recoveryId) != nil)
        // While they are on screen...
        assertNeverStored(set.codes + [set.recoveryId], in: services)
        #expect(model.recoveryCodes?.exportText?.contains(set.recoveryId) == true)
        // ...and after: the confirmation is required, then they are released.
        model.recoveryCodesSaved()
        #expect(model.step == .recoveryCodes)
        model.recoveryCodes?.confirmedSaved = true
        model.recoveryCodesSaved()
        #expect(model.step == .protect && model.recoveryCodes == nil)
        assertNeverStored(set.codes + [set.recoveryId], in: services)
        // The token store keeps tokens only.
        let stored = String(decoding: try ViadereJSON.encode(try #require(await services.sessions.tokens())), as: UTF8.self)
        #expect(!stored.contains("recoveryCodes"))
    }

    @Test func theCodesViewModelHidesWhileCapturedAndReleasesWhenAsked() {
        let set = RecoveryCodeSet(recoveryId: "ABCD-EFGH-JKMN", codes: ["AAAAA-BBBBB"], issuedAt: Date())
        let model = RecoveryCodesViewModel(codes: set)
        #expect(model.visibleCodes == ["AAAAA-BBBBB"])
        model.isScreenBeingCaptured = true
        #expect(model.visibleCodes == nil)
        model.isScreenBeingCaptured = false
        model.noteScreenshot()
        #expect(model.screenshotTaken)
        #expect(!model.canContinue && !model.finish())
        model.release()
        #expect(model.codes == nil && model.exportText == nil && model.visibleCodes == nil)
        #expect(RecoveryCodesViewModel.exportText(for: set).contains("ABCD-EFGH-JKMN"))
    }

    @Test func settingsShowsStatusAndRegeneratesWithThisDevicesOwnProof() async throws {
        let api = MockViadereAPI(seed: false)
        let passkeys = RecordingPasskeys()
        var services = await ViadereServices.mock(api: api)
        services.passkeys = passkeys
        await api.setRecoveryCodes(RecoveryCodeSet(recoveryId: "AAAA-BBBB-CCCC", codes: ["AAAAA-AAAAA", "BBBBB-BBBBB"], issuedAt: Date()))
        let vm = SecuritySettingsViewModel(services: services)
        await vm.load()
        #expect(vm.recoveryInfo?.remainingCodes == 2)
        #expect(vm.recoveryStatusLine == "2 unused codes")
        #expect(vm.canRegenerateRecoveryCodes)

        await vm.regenerateRecoveryCodes()
        let fresh = try #require(vm.newRecoveryCodes?.codes)
        #expect(passkeys.assertions == 0, "no passkey is needed: this device's user-verified key proves it (§2.5a)")
        #expect(fresh.codes.count == RecoveryPolicy.codeCount && fresh.recoveryId != "AAAA-BBBB-CCCC")
        #expect(await api.activeRecoveryCodes == fresh, "the old codes died")
        #expect(vm.recoveryInfo?.remainingCodes == RecoveryPolicy.codeCount)
        assertNeverStored(fresh.codes, in: services)
        vm.finishRecoveryCodes()
        #expect(vm.newRecoveryCodes == nil)
    }

    @Test func settingsAddsAPasskeyOnlyWhenThereIsNone() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let vm = SecuritySettingsViewModel(services: services)
        await vm.load()
        await vm.loadRecovery()
        #expect(vm.canAddPasskey)
        await vm.addRecoveryPasskey()
        #expect(vm.recoveryMessage == nil)
        #expect(await api.passkeyCount == 1)
        #expect(vm.recoveryInfo?.passkeyCount == 1)
        #expect(!vm.canAddPasskey, "one is enough to offer from Settings")
    }

    @Test func settingsShowsEveryPendingRecoveryAndCancelsAllOfThemWithoutAHomeNotice() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        await api.setRecoveryCodes(RecoveryCodeSet(recoveryId: "AAAA-BBBB-CCCC", codes: ["AAAAA-AAAAA"], issuedAt: Date()))
        let first = await api.addHoldingRecovery()
        let second = await api.addHoldingRecovery()
        let vm = SecuritySettingsViewModel(services: services)
        await vm.load()
        // No notice was ever loaded: the control is driven by RecoveryInfo alone.
        #expect(vm.pendingRecoveries.map(\.id) == [first, second])
        #expect(vm.recoveryStatusLine == "Recovery in progress. You can cancel it here.")
        await vm.cancelPendingRecoveries()
        #expect(Set(await api.cancelledRecoveryIds) == [first, second], "one cancel request per pending recovery")
        #expect(vm.pendingRecoveries.isEmpty)
        #expect(vm.recoveryMessage == SecurityNoticesViewModel.recoveryCancelledMessage)
    }

    @Test func cancellingARecoveryFromSettingsNeedsATrustedDevice() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let id = await api.addHoldingRecovery()
        let vm = SecuritySettingsViewModel(services: services)
        await vm.load()
        await api.setDismissNeedsTrustedDevice(true)
        await vm.cancelPendingRecoveries()
        #expect(vm.recoveryMessage == SecurityNoticesViewModel.coolDownActionMessage)
        #expect(vm.pendingRecoveries.map(\.id) == [id], "still pending: nothing was cancelled")
    }

    @Test func regeneratingCodesClosesPendingRecoveries() async throws {
        let api = MockViadereAPI(seed: false)
        let passkeys = RecordingPasskeys()
        var services = await ViadereServices.mock(api: api)
        services.passkeys = passkeys
        await api.setRecoveryCodes(RecoveryCodeSet(recoveryId: "AAAA-BBBB-CCCC", codes: ["AAAAA-AAAAA"], issuedAt: Date()))
        await api.addHoldingRecovery()
        let vm = SecuritySettingsViewModel(services: services)
        await vm.load()
        #expect(vm.pendingRecoveries.count == 1)
        await vm.regenerateRecoveryCodes()
        #expect(vm.pendingRecoveries.isEmpty)
    }

    @Test func recoveryInfoDecodesOldAndNewServers() throws {
        let id = RecoveryID()
        let old = Data(#"{"remainingCodes":3,"pending":{"id":"\#(id)","startedAt":"2026-01-01T00:00:00Z","activatesAt":"2026-01-04T00:00:00Z"}}"#.utf8)
        let decoded = try ViadereJSON.decode(RecoveryInfo.self, from: old)
        #expect(decoded.pendingRecoveries.map(\.id) == [id] && decoded.pending?.id == id)
        let none = try ViadereJSON.decode(RecoveryInfo.self, from: Data(#"{"remainingCodes":0}"#.utf8))
        #expect(none.pendingRecoveries.isEmpty && none.pending == nil)
        let round = try ViadereJSON.decode(RecoveryInfo.self, from: try ViadereJSON.encode(decoded))
        #expect(round == decoded)
    }

    @Test func recoveryCompletedAndDelegationEndedNoticesHaveTheirOwnCopy() async {
        let model = SecurityNoticesViewModel(services: await ViadereServices.mock(api: MockViadereAPI(seed: false)))
        func make(_ kind: String) -> SecurityNotice { SecurityNotice(id: UUID(), rawKind: kind, message: "", createdAt: Date()) }
        #expect(model.headline(for: make("recoveryCompleted")).contains("recovered"))
        #expect(model.headline(for: make("delegationEnded")).contains("Household access"))
        #expect(model.prompt(for: make("recoveryCompleted")).contains("Confirm your phone numbers"))
    }

    @Test func aDeviceThatIsNotTrustedYetCannotRegenerate() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let vm = SecuritySettingsViewModel(services: services)
        await vm.load()
        // The server refuses (this device is cooling down); the person is told calmly and no codes appear.
        await api.setDismissNeedsTrustedDevice(true)
        await vm.regenerateRecoveryCodes()
        #expect(vm.newRecoveryCodes == nil)
        #expect(vm.recoveryMessage == SecurityNoticesViewModel.coolDownActionMessage)
        // Locally, a cooling-down device is stopped before any request.
        let deviceId = try #require(try await services.records.load()?.deviceId)
        await api.setDismissNeedsTrustedDevice(false)
        await api.setApprovalsLockedUntil(Date().addingTimeInterval(3_600), for: deviceId)
        await vm.load()
        #expect(!vm.canRegenerateRecoveryCodes)
    }
}

@MainActor
@Suite("Account recovery flow")
struct AccountRecoveryFlowTests {
    /// An account with codes, and a fresh phone that has nothing but the recovery ID and one code.
    private func world() async throws -> (api: MockViadereAPI, set: RecoveryCodeSet, phone: ViadereServices) {
        let api = MockViadereAPI(seed: false)
        let original = await ViadereServices.mock(api: api, signedIn: false)
        let set = try #require(try await original.account.signUp(displayName: "Ana"))
        let phone = await ViadereServices.mock(api: api, signedIn: false)
        return (api, set, phone)
    }

    @Test func beginPasskeyHoldCompleteThenCodesShownOnce() async throws {
        let (api, set, phone) = try await world()
        let vm = AccountRecoveryViewModel(services: phone)
        var signedIn = false
        vm.onSignedIn = { signedIn = true }
        #expect(vm.phase == .entry && !vm.canSubmit)

        // Typed the way people type it: lower case, spaces.
        vm.recoveryIdText = set.recoveryId.lowercased().replacingOccurrences(of: "-", with: " ")
        vm.codeText = set.codes[0].lowercased()
        #expect(vm.canSubmit)
        await vm.submit()

        guard case .holding(let hold) = vm.phase else { Issue.record("expected the hold, got \(vm.phase)"); return }
        #expect(abs(hold.activatesAt.timeIntervalSince(hold.startedAt) - RecoveryPolicy.holdSeconds) < 1)
        #expect(await api.activeRecoveryCodes?.codes.count == RecoveryPolicy.codeCount - 1, "one code was spent")
        #expect(RecoveryHoldStore(secrets: phone.secrets).load() == hold, "the status token survives a relaunch")
        #expect(vm.codeText.isEmpty)
        // Every existing device was told.
        let notices = try await api.securityNotices()
        #expect(notices.contains { $0.topic == .recoveryStarted && $0.action == .cancelRecovery })

        // Still holding.
        await vm.checkStatus(force: true)
        #expect(vm.phase == .holding(hold) && vm.statusMessage != nil && vm.codes == nil)

        // The 72 hours pass.
        await api.elapseRecoveryHold()
        await vm.checkStatus(force: true)
        #expect(vm.phase == .codes)
        let codes = try #require(vm.codes)
        let fresh = try #require(codes.codes)
        #expect(fresh.codes.count == RecoveryPolicy.codeCount && fresh.recoveryId != set.recoveryId)

        // Shown once: the server never returns them again.
        let again = try await api.completeRecovery(RecoveryCompleteRequest(recoveryId: hold.recoveryId, statusToken: hold.statusToken))
        #expect(again.state == .activated && again.recoveryCodes == nil)

        // "I saved these" is required, then they are released and the new passkey signs in.
        await vm.confirmCodesSaved()
        #expect(vm.phase == .codes && !signedIn)
        codes.confirmedSaved = true
        await vm.confirmCodesSaved()
        #expect(vm.phase == .done && signedIn)
        #expect(vm.codes == nil && codes.codes == nil)
        #expect(await phone.sessions.isSignedIn)
        #expect(RecoveryHoldStore(secrets: phone.secrets).load() == nil)
        assertNeverStored(fresh.codes + [fresh.recoveryId] + set.codes, in: phone)
    }

    @Test func everyRefusalReadsTheSame() async throws {
        let (_, set, phone) = try await world()
        let vm = AccountRecoveryViewModel(services: phone)
        vm.recoveryIdText = "ZZZZ-ZZZZ-ZZZZ"
        vm.codeText = set.codes[0]
        await vm.submit()
        let wrongId = vm.errorMessage
        vm.recoveryIdText = set.recoveryId
        vm.codeText = "ZZZZZ-ZZZZZ"
        await vm.submit()
        #expect(wrongId == AccountRecoveryViewModel.notRecognizedMessage && vm.errorMessage == wrongId)
        #expect(vm.phase == .entry)
        vm.codeText = "short"
        #expect(!vm.canSubmit)
    }

    @Test func aDismissedPasskeySheetCanBeRetriedWithoutSpendingAnotherCode() async throws {
        let (api, set, base) = try await world()
        var phone = base
        phone.passkeys = FlakyPasskeys(cancelFirstRegistration: true)
        let vm = AccountRecoveryViewModel(services: phone)
        vm.recoveryIdText = set.recoveryId
        vm.codeText = set.codes[0]
        await vm.submit()
        #expect(vm.phase == .passkeyNeeded && vm.errorMessage == nil)
        await vm.registerPasskey()
        if case .holding = vm.phase {} else { Issue.record("expected the hold") }
        #expect(await api.activeRecoveryCodes?.codes.count == RecoveryPolicy.codeCount - 1)
    }

    @Test func statusChecksAreThrottledAndResumeAfterARelaunch() async throws {
        let (api, set, phone) = try await world()
        let vm = AccountRecoveryViewModel(services: phone)
        vm.recoveryIdText = set.recoveryId
        vm.codeText = set.codes[0]
        await vm.submit()
        await vm.checkStatus()
        await vm.checkStatus()
        await vm.checkStatus()
        #expect(await api.recoveryCompleteCalls == 1, "opening or foregrounding repeatedly is not a poll loop")
        await vm.checkStatus(force: true)
        #expect(await api.recoveryCompleteCalls == 2)

        // The app was closed; the next launch resumes the hold from the Keychain.
        let relaunched = OnboardingFlow.resume(hasSession: false, hasDevice: false, primingShown: false, complete: false, recoveryPending: true)
        #expect(relaunched == .recovery)
        let model = AccountRecoveryViewModel(services: phone)
        await model.resumeIfPending()
        if case .holding = model.phase {} else { Issue.record("expected the hold after relaunch") }
    }

    @Test func aCancelledRecoveryEndsTheHold() async throws {
        let (api, set, phone) = try await world()
        let vm = AccountRecoveryViewModel(services: phone)
        vm.recoveryIdText = set.recoveryId
        vm.codeText = set.codes[0]
        await vm.submit()
        guard case .holding(let hold) = vm.phase else { Issue.record("expected the hold"); return }
        _ = try await api.cancelRecovery(hold.recoveryId)
        await vm.checkStatus(force: true)
        #expect(vm.phase == .ended(.cancelled))
        #expect(RecoveryHoldStore(secrets: phone.secrets).load() == nil)
        #expect(await api.activeRecoveryCodes?.codes.isEmpty == true, "cancelling invalidates the remaining codes")
    }

    @Test func onboardingHostsRecoveryAndThenEnrollsThisDevice() async throws {
        let (api, set, phone) = try await world()
        let model = OnboardingViewModel(services: phone, deviceName: "Ana's iPhone")
        model.beginRecovery()
        #expect(model.step == .recovery)
        let recovery = try #require(model.recovery)
        recovery.recoveryIdText = set.recoveryId
        recovery.codeText = set.codes[0]
        await recovery.submit()
        await api.elapseRecoveryHold()
        await recovery.checkStatus(force: true)
        recovery.codes?.confirmedSaved = true
        await recovery.confirmCodesSaved()
        while model.step == .recovery { await Task.yield() }
        #expect(model.step == .device && model.recovery == nil)
        await model.enrollDevice()
        #expect(model.step == .notifications)
        #expect(await api.enrollRequests.last?.appAttest != nil)
    }
}

@MainActor
@Suite("Pending device replacement")
struct PendingReplacementTests {
    @Test func theReplacementSessionBecomesTheSession() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let before = try #require(await services.sessions.tokens())
        let record = try await services.account.reenrollThisDevice(name: "New phone")
        let issued = try #require(await api.replacementSessions.last)
        let after = try #require(await services.sessions.tokens())
        #expect(after.accessToken == issued.accessToken && after.refreshToken == issued.refreshToken)
        #expect(after.accessToken != before.accessToken)
        #expect(try await services.records.load()?.deviceId == record.deviceId)
    }

    @Test func aReplacementOfARevokedDeviceMovesNothing() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let old = try #require(try await services.records.load())
        try await api.revokeDevice(old.deviceId)
        let before = try #require(await services.sessions.tokens())
        _ = try await services.account.reenrollThisDevice(name: "New phone")
        #expect(await api.replacementSessions.isEmpty)
        #expect(await services.sessions.tokens() == before)
    }

    /// The old device (in hand) and a new iPhone replacing it.
    private func twoDevices() async throws -> (api: MockViadereAPI, old: ViadereServices, oldId: DeviceID, newId: DeviceID, new: ViadereServices) {
        let api = MockViadereAPI(seed: false)
        let old = await ViadereServices.mock(api: api)
        let oldId = try #require(try await old.records.load()?.deviceId)
        let new = await ViadereServices.mock(api: api, signedIn: false)
        try await new.sessions.set(TokenSet(consumerId: PreviewData.consumerId, accessToken: "t", accessExpiresAt: Date().addingTimeInterval(900)))
        let record = try await new.account.enrollThisDevice(name: "New phone", purpose: .setUpAgain, replacing: oldId)
        return (api, old, oldId, record.deviceId, new)
    }

    @Test func theOldDeviceSeesAndCancelsThePendingReplacement() async throws {
        let (api, old, oldId, newId, _) = try await twoDevices()
        let vm = SecuritySettingsViewModel(services: old)
        await vm.load()
        let oldRow = try #require(vm.devices.first { $0.id == oldId })
        let newRow = try #require(vm.devices.first { $0.id == newId })
        #expect(oldRow.pendingReplacementBy == newId && oldRow.pendingReplacementAt != nil)
        if case .beingReplaced(let thisIPhone, _)? = vm.replacementState(for: oldRow) { #expect(thisIPhone) } else { Issue.record("old row state") }
        #expect(vm.replacementState(for: newRow) == .pendingReplacement)
        #expect(vm.replacementTitle(for: vm.replacementState(for: oldRow)!) == "Replacing this iPhone")
        #expect(vm.replacementTitle(for: .pendingReplacement) == "Pending replacement")
        #expect(vm.canCancelReplacement(oldRow) && vm.canCancelReplacement(newRow))

        // The notice on the old device routes to the cancel call for the NEW device.
        let notices = SecurityNoticesViewModel(services: old)
        await notices.load()
        let notice = try #require(notices.notices.first { $0.action == .cancelDeviceReplacement })
        #expect(notice.topic == .devicePendingReplacement && notice.kind == .unknown)
        #expect(notices.headline(for: notice) == "A new iPhone is replacing this one.")
        #expect(notices.actionTitle(for: notice) == "Cancel" && notices.prompt(for: notice) == "Not you? Cancel.")
        #expect(await notices.perform(notice))
        #expect(await api.cancelledReplacementIds == [newId])
        await vm.load()
        #expect(vm.devices.first { $0.id == newId }?.isRevoked == true)
        #expect(vm.devices.first { $0.id == oldId }?.pendingReplacementBy == nil)
        #expect(vm.replacementState(for: vm.devices.first { $0.id == oldId }!) == nil)
    }

    @Test func theNewDeviceCannotCancelItsOwnReplacement() async throws {
        let (_, _, oldId, newId, new) = try await twoDevices()
        let vm = SecuritySettingsViewModel(services: new)   // seen from the new iPhone
        await vm.load()
        let newRow = try #require(vm.devices.first { $0.id == newId })
        let oldRow = try #require(vm.devices.first { $0.id == oldId })
        #expect(vm.currentDeviceId == newId)
        #expect(vm.replacementTarget(for: newRow) == newId && vm.replacementTarget(for: oldRow) == newId)
        #expect(!vm.canCancelReplacement(newRow) && !vm.canCancelReplacement(oldRow))
    }
}

@MainActor
@Suite("Security notice routing")
struct NoticeRoutingTests {
    private func notice(_ raw: String, action: SecurityNoticeAction?, subject: String? = nil) -> SecurityNotice {
        SecurityNotice(id: UUID(), rawKind: raw, message: "Server text", createdAt: Date().addingTimeInterval(-60), subjectId: subject, action: action)
    }

    @Test func recoveryStartedOffersCancelRecoveryAndCallsTheRecoveryRoute() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        // A real recovery from another phone.
        let set = RecoveryCodeSet(recoveryId: "ABCD-EFGH-JKMN", codes: [RecoveryCodeFormat.generateCode()], issuedAt: Date())
        await api.setRecoveryCodes(set)
        let other = await ViadereServices.mock(api: api, signedIn: false)
        let recovery = AccountRecoveryViewModel(services: other)
        recovery.recoveryIdText = set.recoveryId
        recovery.codeText = set.codes[0]
        await recovery.submit()

        let model = SecurityNoticesViewModel(services: services)
        await model.load()
        let started = try #require(model.notices.first { $0.topic == .recoveryStarted })
        #expect(started.kind == .unknown && started.action == .cancelRecovery)
        #expect(model.headline(for: started).hasPrefix("Account recovery was started"))
        #expect(model.actionTitle(for: started) == "Cancel recovery")
        #expect(model.prompt(for: started) == "Not you? Cancel recovery.")
        #expect(await model.perform(started))
        #expect(await api.cancelledRecoveryIds.count == 1)
        #expect(model.notices.isEmpty)
        #expect(model.message == SecurityNoticesViewModel.recoveryCancelledMessage)
    }

    @Test func aDeviceThatIsNotTrustedYetIsToldCalmly() async throws {
        let api = MockViadereAPI(seed: false)
        await api.setDismissNeedsTrustedDevice(true)
        let model = SecurityNoticesViewModel(services: await ViadereServices.mock(api: api))
        let n = notice("recoveryStarted", action: .cancelRecovery, subject: RecoveryID().description)
        await api.setSecurityNotices([n])
        await model.load()
        #expect(await !model.perform(n))
        #expect(model.message == SecurityNoticesViewModel.coolDownActionMessage)
        #expect(model.notices == [n], "the notice stays")
    }

    @Test func aBadSubjectIsRefusedBeforeAnyRequest() async {
        let model = SecurityNoticesViewModel(services: await ViadereServices.mock(api: MockViadereAPI(seed: false)))
        #expect(await !model.perform(notice("recoveryStarted", action: .cancelRecovery, subject: "not-an-id")))
        #expect(await !model.perform(notice("newDevice", action: nil)))
        #expect(await !model.perform(notice("whatever", action: .unknown)))
    }

    @Test func copyFollowsTheTopicWithGenericFallbacks() async {
        let model = SecurityNoticesViewModel(services: await ViadereServices.mock(api: MockViadereAPI(seed: false)))
        #expect(model.headline(for: notice("devicePendingReplacement", action: .cancelDeviceReplacement)).contains("replacing this one"))
        #expect(model.headline(for: notice("recoveryCancelled", action: nil)).contains("cancelled"))
        #expect(model.headline(for: notice("recoveryAttemptsLocked", action: nil)).contains("recovery is paused"))
        #expect(model.headline(for: notice("newDevice", action: nil)).contains("new device"))
        // A kind from the future: the server's plain text, or a generic line.
        #expect(model.headline(for: notice("someFutureKind", action: nil)).contains("Server text"))
        let blank = SecurityNotice(id: UUID(), rawKind: "someFutureKind", message: "", createdAt: Date())
        #expect(model.headline(for: blank).hasPrefix("Something changed on your account"))
        #expect(model.actionTitle(for: blank) == nil)
    }

    @Test func theSecurityPushHasItsCategoryAndOpensTheAppForReview() async throws {
        let category = try #require(NotificationEnricher.registeredCategorySpecs().first { $0.identifier == "viadere.security.cancel" })
        let action = try #require(category.actions.first)
        #expect(category.actions.count == 1 && action.title == "Review")
        #expect(action.opensApp && action.requiresAuthentication)
        // The renderer's static list is unchanged.
        #expect(!NotificationEnricher.staticCategorySpecs().contains { $0.identifier == "viadere.security.cancel" })

        let services = await ViadereServices.mock()
        let handler = services.notificationHandler
        let tapped = await handler.handle(NotificationResponseInfo(actionIdentifier: action.identifier, categoryIdentifier: "viadere.security.cancel", userInfo: [:]))
        #expect(tapped == .open(nil))
        let defaultTap = await handler.handle(NotificationResponseInfo(actionIdentifier: NotificationActionID.systemDefaultTap,
                                                                       categoryIdentifier: "viadere.security.cancel", userInfo: [:]))
        #expect(defaultTap == .open(nil))
    }

    @Test func openingFromTheSecurityPushFetchesTheNotices() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let model = AppModel(services: services)
        await model.bootstrap()
        #expect(model.securityNotices.current == nil)
        await api.setSecurityNotices([notice("recoveryStarted", action: .cancelRecovery, subject: RecoveryID().description)])
        await model.apply(.open(nil))
        #expect(model.securityNotices.current?.topic == .recoveryStarted)
        #expect(model.selectedTab == .alerts)
    }
}
