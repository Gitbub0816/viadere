import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// The QR form of a pairing code (`https://{link domain}/p/{XXXX-XXXX-XXXX}`, SECURITY.md §2.107). The trusted device shows it under the code;
/// only a new device's pairing entry reads it, and only to fill the code in. Every other place refuses it, and the pairing entry refuses every
/// other code.
@Suite("Pairing code QR")
@MainActor
struct PairingCodeScanTests {
    static let code = "AB12-CD34-EF56"
    static let link = "https://viadere.io/p/AB12-CD34-EF56"

    private func decide(_ payload: String, _ context: ScanContext, _ symbology: ScannedSymbology = .qr) -> ScannedCodeDecision {
        ScannedCodePolicy.evaluate(payload, symbology: symbology, domain: .production, context: context)
    }

    @Test func theExactLinkRoutesToThePairingCase() throws {
        #expect(DeepLinkRouter.route(try #require(URL(string: Self.link)), domain: .production) == .devicePairing(code: Self.code))
        #expect(decide(Self.link, .newDevicePairing) == .open(.devicePairing(code: Self.code)))
        #expect(DevicePairingLink.build(code: Self.code, domain: .production) == Self.link)
    }

    @Test func everyAlteredFormIsRefusedInThePairingEntry() {
        let refused = [
            // Lookalike hosts and the www alias.
            "https://viadere.io.evil.example/p/AB12-CD34-EF56", "https://vladere.io/p/AB12-CD34-EF56", "https://www.viadere.io/p/AB12-CD34-EF56",
            "https://VIADERE.IO/p/AB12-CD34-EF56", "https://viadere.io:8443/p/AB12-CD34-EF56", "https://a@viadere.io/p/AB12-CD34-EF56",
            "http://viadere.io/p/AB12-CD34-EF56", "viadere://p/AB12-CD34-EF56",
            // Extra path, query, fragment.
            "https://viadere.io/p/AB12-CD34-EF56/", "https://viadere.io/p/AB12-CD34-EF56/extra", "https://viadere.io/pp/AB12-CD34-EF56",
            "https://viadere.io/p/AB12-CD34-EF56?ref=1", "https://viadere.io/p/AB12-CD34-EF56#frag",
            // Case: the code is printed in upper case only; the path prefix is lower case.
            "https://viadere.io/p/ab12-cd34-ef56", "https://viadere.io/p/Ab12-CD34-EF56", "https://viadere.io/P/AB12-CD34-EF56",
            // Length, dashes and the alphabet.
            "https://viadere.io/p/AB12-CD34-EF5", "https://viadere.io/p/AB12-CD34-EF567", "https://viadere.io/p/AB12CD34EF56",
            "https://viadere.io/p/AB12-CD34-EFI6", "https://viadere.io/p/AB12-CD34-EFO6", "https://viadere.io/p/AB12-CD34-EFU6",
            "https://viadere.io/p/AB12-CD34-EF5%36",
        ]
        for payload in refused {
            if case .open = decide(payload, .newDevicePairing) { Issue.record("opened \(payload)") }
            if case .open(.devicePairing) = decide(payload, .app) { Issue.record("routed \(payload)") }
        }
        // A plain code (what a person would type) is not a scan: the scanner takes only the link.
        #expect(decide(Self.code, .newDevicePairing) == .rejected(.notAPairingCode))
    }

    @Test func thePairingEntryAcceptsNothingButAPairingCode() {
        for payload in ["https://viadere.io/c/AF2345", "https://viadere.io/v/K7QFM2XA", OIDCChallengeLink.build(challengeId: ScannedCodeTests.ach, domain: .production),
                        "@northwind", "https://example.com", ScannedCodeTests.foreignSafeAction] {
            #expect(decide(payload, .newDevicePairing, .qr) == .rejected(.notAPairingCode), "\(payload)")
        }
        #expect(ScanRejection.notAPairingCode.message == "That isn't a code for adding this device. Scan the code on your other device's screen.")
    }

    @Test func theAppScannerOfAnEnrolledDeviceRefusesItWithAFixedMessage() {
        #expect(decide(Self.link, .app) == .rejected(.pairingOnEnrolledDevice))
        #expect(decide(Self.link, .app, .ckey) == .rejected(.pairingOnEnrolledDevice))
        // The default context is the app's.
        #expect(ScannedCodePolicy.evaluate(Self.link, symbology: .qr, domain: .production) == .rejected(.pairingOnEnrolledDevice))
        let message = ScanRejection.pairingOnEnrolledDevice.message
        #expect(message == "This code adds a new device to an account. Scan it with the device you're adding. Nothing was opened.")
        #expect(!message.contains(Self.code), "the scanned text is never repeated")
    }

    // MARK: The pairing entry

    @Test func aScannedCodeFillsTheEntryAndStartsNothing() async {
        let env = DevicePairingKitTests.NewDeviceEnv()
        let vm = NewDevicePairingViewModel(pairing: env.pairing, now: { DevicePairingKitTests.now }, sleep: { _ in })
        #expect(await vm.scanned(Self.link, symbology: .qr, domain: .production) == nil)
        #expect(vm.entry == Self.code && vm.canContinue && vm.phase == .enteringCode)
        #expect(await env.api.startRequests.isEmpty, "the person still taps Continue")
        // Another code in the same entry: refused, the entry is unchanged.
        #expect(await vm.scanned("https://viadere.io/c/AF2345", symbology: .qr, domain: .production) == .notAPairingCode)
        #expect(vm.entry == Self.code)
    }

    @Test func anEnrolledDeviceRefusesTheScannedOrOpenedCodeAndNeverStarts() async throws {
        let env = DevicePairingKitTests.NewDeviceEnv()
        try await env.records.save(DeviceRecord(deviceId: DeviceID(), consumerId: ConsumerID(), name: "iPhone", purposes: [.request],
                                                enrolledAt: DevicePairingKitTests.now))
        #expect(await env.pairing.isEnrolled())
        let vm = NewDevicePairingViewModel(pairing: env.pairing, now: { DevicePairingKitTests.now }, sleep: { _ in })
        #expect(await vm.scanned(Self.link, symbology: .qr, domain: .production) == .pairingOnEnrolledDevice)
        #expect(vm.entry.isEmpty && vm.notice == PairingCopy.alreadyEnrolled)
        await vm.prefill(code: Self.code)
        #expect(vm.entry.isEmpty)
        // Typed by hand: Continue refuses too, before any key is made or anything is sent.
        vm.edit(Self.code)
        await vm.start()
        #expect(vm.phase == .enteringCode && vm.notice == PairingCopy.alreadyEnrolled)
        #expect(await env.api.startRequests.isEmpty)
        await #expect(throws: DevicePairingError.alreadyEnrolled) { _ = try await env.pairing.start(code: Self.code, deviceName: nil) }
    }

    @Test func aSignedInDeviceCountsAsEnrolled() async throws {
        let env = DevicePairingKitTests.NewDeviceEnv()
        try await env.sessions.set(TokenSet(consumerId: ConsumerID(), accessToken: "a", accessExpiresAt: DevicePairingKitTests.now.addingTimeInterval(600)))
        #expect(await env.pairing.isEnrolled())
    }

    @Test func prefillTakesOnlyTheDisplayedForm() async {
        let env = DevicePairingKitTests.NewDeviceEnv()
        let vm = NewDevicePairingViewModel(pairing: env.pairing, now: { DevicePairingKitTests.now }, sleep: { _ in })
        for bad in ["ab12-cd34-ef56", "AB12CD34EF56", "AB12-CD34-EFI6", "AB12-CD34-EF5", ""] {
            await vm.prefill(code: bad)
            #expect(vm.entry.isEmpty, "\(bad)")
        }
    }

    // MARK: Opened as a universal link

    @Test func anOpenedLinkReachesOnlyTheOnboardingPairingEntry() async throws {
        let text = try #require(DevicePairingLink.build(code: Self.code, domain: .current))
        let url = try #require(URL(string: text))

        // A device that is not enrolled, in onboarding: the code waits for the pairing entry.
        let fresh = AppModel(services: await ViadereServices.mock(api: MockViadereAPI(seed: false), signedIn: false))
        await fresh.bootstrap()
        #expect(fresh.phase == .onboarding(.welcome))
        await fresh.open(url: url)
        #expect(fresh.pendingDevicePairingCode == Self.code && fresh.toast == nil)

        // The onboarding view model opens the entry with the code filled in; nothing is started.
        let onboarding = OnboardingViewModel(services: fresh.services)
        await onboarding.openPairing(prefilled: Self.code)
        #expect(onboarding.pairing?.entry == Self.code && onboarding.pairing?.phase == .enteringCode)

        // An enrolled device: refused with the fixed message, nothing kept, nothing queued for later.
        let ready = AppModel(services: await ViadereServices.mock())
        await ready.bootstrap()
        #expect(ready.phase == .ready)
        await ready.open(url: url)
        #expect(ready.pendingDevicePairingCode == nil)
        #expect(ready.toast == ScanRejection.pairingOnEnrolledDevice.message)
        #expect(ready.pendingConnect == nil && ready.pendingOIDCSignIn == nil)
        // And through the in-app scanner.
        #expect(ready.scanned(url.absoluteString, symbology: .qr) == .pairingOnEnrolledDevice)
    }
}
