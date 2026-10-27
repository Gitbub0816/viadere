import Foundation

#if canImport(PassKit)
import PassKit

/// `WalletLibrary` over PassKit. Reading Wallet state needs no entitlement for passes this app added; seeing passes
/// added by other means requires the `com.apple.developer.pass-type-identifiers` entitlement (not requested).
public struct PassKitWalletLibrary: WalletLibrary {
    public init() {}

    public var isAvailable: Bool { PKPassLibrary.isPassLibraryAvailable() }

    public func containsPass(passTypeIdentifier: String, serialNumber: String) -> Bool {
        PKPassLibrary().pass(withPassTypeIdentifier: passTypeIdentifier, serialNumber: serialNumber) != nil
    }

    /// `PKPass(data:)` rejects bundles that aren't well-formed, correctly signed passes.
    public func validatedIdentity(of passData: Data) throws -> WalletPassIdentity {
        let pass = try PKPass(data: passData)
        return WalletPassIdentity(passTypeIdentifier: pass.passTypeIdentifier, serialNumber: pass.serialNumber,
                                  organizationName: pass.organizationName)
    }
}
#endif
