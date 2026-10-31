import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

@Suite("Wallet passes screen")
@MainActor
struct WalletPassesTests {
    private func model(available: Bool = true) async -> (WalletPassesViewModel, MockViadereAPI, MockWalletLibrary, WalletPassCoordinator) {
        let (services, api) = await p3World()
        let library = MockWalletLibrary(isAvailable: available)
        let wallet = WalletPassCoordinator(services: services, library: library)
        return (WalletPassesViewModel(services: services, wallet: wallet), api, library, wallet)
    }

    @Test func listsEveryPassAndSplitsCurrentFromPast() async throws {
        let (model, api, _, _) = await model()
        await model.load()
        #expect(model.hasLoaded && model.errorMessage == nil)
        #expect(model.passes.count == 4)
        #expect(model.past.isEmpty)
        // The business voids one and checks another in: they move to "past" and lose their code.
        var voided = try #require(model.pass(PreviewData.eventPassId))
        voided.voided = true
        voided.scanCode = nil
        await api.setWalletPass(voided)
        var used = try #require(model.pass(PreviewData.reservationPassId))
        used.usedAt = tuesdayNoon.addingTimeInterval(-600)
        await api.setWalletPass(used)
        await model.load()
        #expect(Set(model.past.map(\.id)) == [PreviewData.eventPassId, PreviewData.reservationPassId])
        #expect(model.current.count == 2)
        let gone = model.presentation(for: try #require(model.pass(PreviewData.eventPassId)), businessName: "Lumen Theater")
        #expect(gone.status == .voided && gone.scanCode == nil && gone.statusText == "No longer valid")
        let checkedIn = model.presentation(for: try #require(model.pass(PreviewData.reservationPassId)), businessName: "Harbor Hotel")
        #expect(checkedIn.status == .checkedIn(tuesdayNoon.addingTimeInterval(-600)))
        #expect(checkedIn.scanCode == nil, "a used ticket shows no code to scan again")
        #expect(checkedIn.statusText.hasPrefix("Checked in"))
    }

    @Test func addAndAlreadyAddedStatesComeFromPassKit() async throws {
        let (model, _, library, wallet) = await model()
        await model.load()
        let card = try #require(model.pass(PreviewData.loyaltyPassId))
        let before = model.presentation(for: card, businessName: "Juniper Coffee")
        #expect(before.status == .readyToAdd && before.statusText == "Not in Wallet yet")
        library.simulateAdd(WalletPassIdentity(passTypeIdentifier: card.passTypeIdentifier, serialNumber: card.serialNumber))
        wallet.refresh([card])
        let after = model.presentation(for: card, businessName: "Juniper Coffee")
        #expect(after.status == .inWallet && after.statusText == "In Wallet")
        #expect(after.scanCode == card.scanCode, "the same code as the pass, for showing from the app")
        #expect(after.accessibilityLabel == "Loyalty card from Juniper Coffee. In Wallet.")
    }

    @Test func withoutWalletTheAppShowsTheCode() async throws {
        let (model, _, _, _) = await model(available: false)
        await model.load()
        let ticket = model.presentation(for: try #require(model.pass(PreviewData.eventPassId)), businessName: "Lumen Theater")
        #expect(ticket.status == .appOnly)
        #expect(ticket.scanCode != nil)
        #expect(ticket.codeInstructions == "Show this at the entrance. It admits once.")
        #expect(ticket.kindTitle == "Ticket" && ticket.symbol == "ticket")
    }

    @Test func malformedOrMissingCodesAreNeverDrawn() async throws {
        let (model, api, _, _) = await model()
        await model.load()
        var pass = try #require(model.pass(PreviewData.loyaltyPassId))
        pass.scanCode = "javascript:alert(1)"
        await api.setWalletPass(pass)
        await model.load()
        let presentation = model.presentation(for: try #require(model.pass(PreviewData.loyaltyPassId)), businessName: nil)
        #expect(presentation.scanCode == nil && presentation.codeInstructions == nil)
        #expect(presentation.businessName == "A business you're connected to")
    }

    @Test func kindsHaveTitlesAndNoShieldSymbols() {
        for kind in WalletPassKind.allCases {
            #expect(!WalletPassPresentation.kindTitle(kind).isEmpty)
            #expect(!WalletPassPresentation.symbol(kind).contains("shield"))
        }
        #expect(WalletPassPresentation.kindTitle(.generic) == "Reservation")
    }

    @Test func loadErrorsAreCalmAndKeepThePreviousList() async throws {
        let (model, api, _, _) = await model()
        await model.load()
        await api.setWalletPassesFailure(APIError.server(status: 503, code: .unavailable, message: "Try later."))
        await model.load()
        #expect(model.errorMessage != nil)
        #expect(model.passes.count == 4, "the last good list stays on screen")
    }

    @Test func betaLabelIsConfigurable() async {
        let (services, _) = await p3World()
        let wallet = WalletPassCoordinator(services: services, library: MockWalletLibrary())
        #expect(WalletPassesViewModel(services: services, wallet: wallet).showsBetaLabel, "on by default")
        #expect(!WalletPassesViewModel(services: services, wallet: wallet, showsBetaLabel: false).showsBetaLabel)
        #expect(ViadereConfiguration.resolve(info: [:], allowLocalHTTP: false).walletBetaLabel)
        #expect(!ViadereConfiguration.resolve(info: ["ViadereWalletBetaLabel": "NO"], allowLocalHTTP: false).walletBetaLabel)
        #expect(!ViadereConfiguration.resolve(info: ["ViadereWalletBetaLabel": false], allowLocalHTTP: false).walletBetaLabel)
        #expect(ViadereConfiguration.resolve(info: ["ViadereWalletBetaLabel": "$(VIADERE_WALLET_BETA_LABEL)"], allowLocalHTTP: false).walletBetaLabel)
    }

    @Test func mockCodesAreWellFormedSoPreviewsMatchTheServerShape() {
        #expect(WalletScanCode.isWellFormed(PreviewData.mockScanCode(PreviewData.loyaltyPassId)))
    }
}
