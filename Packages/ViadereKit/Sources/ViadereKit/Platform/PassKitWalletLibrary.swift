import Foundation

#if canImport(PassKit) && !os(watchOS)
import PassKit

/// `WalletLibrary` over PassKit. Adding a pass needs no entitlement, but reading Wallet does: `pass(withPassTypeIdentifier:serialNumber:)`
/// returns nil unless the app holds `com.apple.developer.pass-type-identifiers` for that Pass Type ID (Apple documentation, checked
/// 2026-10-31). The app requests the server's Pass Type ID (`VIADERE_PASS_TYPE_IDENTIFIER`).
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
