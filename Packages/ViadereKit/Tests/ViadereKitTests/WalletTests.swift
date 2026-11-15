import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

/// A library whose behavior the test dictates.
private struct StubLibrary: WalletLibrary {
    var isAvailable = true
    var identity: WalletPassIdentity?
    func containsPass(passTypeIdentifier: String, serialNumber: String) -> Bool { false }
    func validatedIdentity(of passData: Data) throws -> WalletPassIdentity {
        guard let identity else { throw WalletPassError.invalidPass }
        return identity
    }
}

@Suite("Apple Wallet")
@MainActor
struct WalletTests {
    private func loyaltyPass(_ api: MockViadereAPI) async throws -> WalletPassMetadata {
        try #require(try await api.walletPasses().first { $0.id == PreviewData.loyaltyPassId })
    }

    @Test func fetchValidateAndShowInWalletState() async throws {
        let (services, api) = await p3World()
        let library = MockWalletLibrary()
        let coordinator = WalletPassCoordinator(services: services, library: library)
        let pass = try await loyaltyPass(api)
        #expect(coordinator.state(for: pass) == .notInWallet)
        let prepared = try await coordinator.prepare(pass)
        #expect(prepared.identity.serialNumber == pass.serialNumber && !prepared.data.isEmpty)
        // Apple's sheet adds it; the coordinator then reports "In Wallet"
        library.simulateAdd(prepared.identity)
        coordinator.refresh([pass])
        #expect(coordinator.state(for: pass) == .inWallet)
    }

    @Test func passesThatAreVoidedOrUnsupportedAreNeverFetched() async throws {
        let (services, api) = await p3World()
        var pass = try await loyaltyPass(api)
        let unsupported = WalletPassCoordinator(services: services, library: MockWalletLibrary(isAvailable: false))
        #expect(unsupported.state(for: pass) == .unavailable)
        await #expect(throws: WalletPassError.unavailable) { _ = try await unsupported.prepare(pass) }
        pass.voided = true
        let coordinator = WalletPassCoordinator(services: services, library: MockWalletLibrary())
        #expect(coordinator.state(for: pass) == .voided)
        await #expect(throws: WalletPassError.voided) { _ = try await coordinator.prepare(pass) }
        #expect(coordinator.lastError == WalletPassError.voided.userMessage)
    }

    @Test func rejectsBundlesPassKitRefusesOrThatDontMatchTheMetadata() async throws {
        let (services, api) = await p3World()
        let pass = try await loyaltyPass(api)
        // PKPass(data:) throws
        let broken = WalletPassCoordinator(services: services, library: StubLibrary(identity: nil))
        await #expect(throws: WalletPassError.invalidPass) { _ = try await broken.prepare(pass) }
        // a valid pass, but not the one the server's metadata described
        let other = WalletPassIdentity(passTypeIdentifier: pass.passTypeIdentifier, serialNumber: "SOMETHING-ELSE")
        let mismatch = WalletPassCoordinator(services: services, library: StubLibrary(identity: other))
        await #expect(throws: WalletPassError.mismatchedPass) { _ = try await mismatch.prepare(pass) }
    }

    @Test func serverErrorsSurfaceCalmly() async throws {
        let (services, _) = await p3World()
        let ghost = WalletPassMetadata(id: WalletPassID(), businessId: PreviewData.juniperCoffee.id, kind: .storeCard,
                                       passTypeIdentifier: "pass.x", serialNumber: "1", updatedAt: tuesdayNoon)
        let coordinator = WalletPassCoordinator(services: services, library: MockWalletLibrary())
        do {
            _ = try await coordinator.prepare(ghost)
            Issue.record("expected a failure")
        } catch let error as WalletPassError {
            guard case .api(let api) = error else { Issue.record("expected an API error"); return }
            #expect(api.code == .notFound)
        }
    }

    @Test func issuingAPassIsAServerRequestAndLinksTheLoyaltyCard() async throws {
        let (_, api) = await p3World()
        let pass = try await api.issueWalletPass(WalletPassIssueRequest(kind: .storeCard, businessId: PreviewData.harborHotel.id))
        #expect(pass.kind == .storeCard && pass.passTypeIdentifier == PreviewData.passTypeLoyalty)
        let program = try await api.loyaltyProgram(business: PreviewData.harborHotel.id)
        #expect(program.account?.walletPass?.id == pass.id)
    }

    @Test func oversizedBundlesAreRefusedBeforeParsing() {
        #expect(WalletPassCoordinator.maximumPassSize == 5 * 1024 * 1024)
    }
}
