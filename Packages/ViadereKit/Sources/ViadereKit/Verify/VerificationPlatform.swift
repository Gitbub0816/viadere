import Foundation
import ViadereCore

/// Whether an ID in Apple Wallet can answer a request. Availability is **not** proofing: it only decides whether the option is shown
/// first (VER-003). The person still consents to every presentation.
public enum WalletAvailability: Sendable, Equatable {
    case available
    /// No eligible ID in Wallet, an unsupported device or OS, or the app lacks the entitlement.
    case unavailable
}

/// What Wallet returned for one presentment, or why it did not.
public enum WalletPresentationError: Error, Sendable, Equatable {
    /// The person closed the Wallet sheet.
    case cancelled
    /// Wallet could not provide the document (none eligible, not entitled, another request in progress).
    case unavailable
}

/// Apple Wallet identity presentment (`PKIdentityAuthorizationController`). The app implements it with PassKit; tests use a fake.
public protocol WalletIdentityService: Sendable {
    /// Whether the described document can be requested right now (`checkCanRequestDocument`). Never throws: unknown means unavailable.
    func availability(for request: WalletElementPlan.Request) async -> WalletAvailability
    /// Shows Wallet's own sheet and returns the encrypted response bytes (`PKIdentityDocument.encryptedData`) exactly as produced.
    /// `nonce` is the server's single-use nonce (raw bytes) and goes into `PKIdentityRequest.nonce`.
    func present(_ request: WalletElementPlan.Request, nonce: Data, merchantIdentifier: String) async throws -> Data
}

/// What the document verification flow ended with. The provider's own result is advisory: the server re-fetches the decision itself.
public enum DocumentFlowResult: Sendable, Equatable {
    /// The flow reached an end (approved, declined or in review); the server decides.
    case finished
    case cancelled
    case failed
}

/// The provider's SDK flow (Didit): camera, liveness and document capture run in the provider's own screens, themed for Viadere, with a
/// session token from our server. Images and biometrics go from the device to the provider; Viadere never receives them.
public protocol DocumentVerificationService: Sendable {
    func verify(sessionToken: String) async -> DocumentFlowResult
}

/// A service that is never available (previews, extensions, platforms without the SDK).
public struct UnavailableWalletIdentity: WalletIdentityService {
    public init() {}
    public func availability(for request: WalletElementPlan.Request) async -> WalletAvailability { .unavailable }
    public func present(_ request: WalletElementPlan.Request, nonce: Data, merchantIdentifier: String) async throws -> Data { throw WalletPresentationError.unavailable }
}

public struct UnavailableDocumentVerification: DocumentVerificationService {
    public init() {}
    public func verify(sessionToken: String) async -> DocumentFlowResult { .failed }
}

#if canImport(PassKit) && os(iOS)
import PassKit

/// Wallet IDs through `PKIdentityAuthorizationController` (iOS 16+; entitlement `com.apple.developer.in-app-identity-presentment`, usage
/// string `NSIdentityUsageDescription`). Requests exactly the elements `WalletElementPlan` names: `age(atLeast:)` for a threshold (never
/// the birthdate), the name elements for a name, `address` for an address, and `issuingAuthority` alone for "has a verified ID".
public struct PassKitWalletIdentity: WalletIdentityService {
    public init() {}

    private func descriptor(for request: WalletElementPlan.Request) -> PKIdentityDriversLicenseDescriptor {
        let descriptor = PKIdentityDriversLicenseDescriptor()
        switch request {
        case .ageAtLeast(let years): descriptor.addElements([.age(atLeast: years)], intentToStore: .willNotStore)
        case .givenAndFamilyName: descriptor.addElements([.givenName, .familyName], intentToStore: .willNotStore)
        case .residentAddress: descriptor.addElements([.address], intentToStore: .willNotStore)
        case .documentPresented: descriptor.addElements([.issuingAuthority], intentToStore: .willNotStore)
        }
        return descriptor
    }

    public func availability(for request: WalletElementPlan.Request) async -> WalletAvailability {
        let controller = PKIdentityAuthorizationController()
        return await controller.checkCanRequestDocument(descriptor(for: request)) ? .available : .unavailable
    }

    public func present(_ plan: WalletElementPlan.Request, nonce: Data, merchantIdentifier: String) async throws -> Data {
        let controller = PKIdentityAuthorizationController()
        let request = PKIdentityRequest()
        request.descriptor = descriptor(for: plan)
        request.merchantIdentifier = merchantIdentifier
        request.nonce = nonce
        do {
            return try await controller.requestDocument(request).encryptedData
        } catch let error as PKIdentityError {
            switch error.code {
            case .cancelled: throw WalletPresentationError.cancelled
            default: throw WalletPresentationError.unavailable
            }
        } catch {
            throw WalletPresentationError.unavailable
        }
    }
}
#endif
