import Foundation
import ViadereCore

/// Wallet presentment for a **profile** verification: one sheet asking for every element of `ProfileVerificationBegin.walletPlans`. Viadere
/// keeps none of the values (the server compares the name in memory and keeps only booleans), so every element is declared `willNotStore`.
public protocol ProfileWalletPresenter: Sendable {
    func present(plans: [WalletElementPlan.Request], nonce: Data, merchantIdentifier: String) async throws -> Data
}

public struct UnavailableProfileWalletPresenter: ProfileWalletPresenter {
    public init() {}
    public func present(plans: [WalletElementPlan.Request], nonce: Data, merchantIdentifier: String) async throws -> Data { throw WalletPresentationError.unavailable }
}

extension ProfileVerificationViewModel {
    /// Begin → Wallet sheet → complete. A cancelled sheet returns to choosing; the attempt simply expires on the server.
    public func verifyWithWallet(presenter: any ProfileWalletPresenter) async {
        await begin(.wallet)
        guard case .started(let start) = phase, let rawNonce = start.nonce, let nonce = Base64URL.decode(rawNonce), let merchant = start.merchantIdentifier else { return }
        do {
            let envelope = try await presenter.present(plans: ProfileVerificationBegin.walletPlans(for: keep.sorted { $0.rawValue < $1.rawValue }),
                                                       nonce: nonce, merchantIdentifier: merchant)
            await complete(envelope: Base64URL.encode(envelope))
        } catch WalletPresentationError.cancelled {
            reset()
        } catch {
            failVerification("Your ID in Wallet isn't available right now.")
        }
    }

    /// Begin → provider flow → complete (the server re-fetches the decision itself).
    public func verifyWithDocument(service: any DocumentVerificationService) async {
        await begin(.document)
        guard case .started(let start) = phase, let token = start.sessionToken else { return }
        switch await service.verify(sessionToken: token) {
        case .finished: await complete(envelope: nil)
        case .cancelled: reset()
        case .failed: failVerification("The ID check didn't finish. You can try again.")
        }
    }
}

#if canImport(PassKit) && os(iOS)
import PassKit

public struct PassKitProfileWalletPresenter: ProfileWalletPresenter {
    public init() {}

    public func present(plans: [WalletElementPlan.Request], nonce: Data, merchantIdentifier: String) async throws -> Data {
        let descriptor = PKIdentityDriversLicenseDescriptor()
        for plan in plans {
            switch plan {
            case .ageAtLeast(let years): descriptor.addElements([.age(atLeast: years)], intentToStore: .willNotStore)
            case .givenAndFamilyName: descriptor.addElements([.givenName, .familyName], intentToStore: .willNotStore)
            case .residentAddress: break // never asked for by a profile verification
            case .documentPresented: descriptor.addElements([.issuingAuthority], intentToStore: .willNotStore)
            }
        }
        let request = PKIdentityRequest()
        request.descriptor = descriptor
        request.merchantIdentifier = merchantIdentifier
        request.nonce = nonce
        let controller = PKIdentityAuthorizationController()
        do {
            return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                controller.requestDocument(request) { document, error in
                    if let error { continuation.resume(throwing: error) } else if let document { continuation.resume(returning: document.encryptedData) } else {
                        continuation.resume(throwing: WalletPresentationError.unavailable)
                    }
                }
            }
        } catch let error as PKIdentityError {
            throw error.code == .cancelled ? WalletPresentationError.cancelled : WalletPresentationError.unavailable
        } catch {
            throw WalletPresentationError.unavailable
        }
    }
}
#endif
