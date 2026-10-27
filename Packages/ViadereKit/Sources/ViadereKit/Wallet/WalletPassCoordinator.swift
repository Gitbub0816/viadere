import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// The identity inside a `.pkpass`, as read by `PKPass(data:)`.
public struct WalletPassIdentity: Equatable, Sendable {
    public var passTypeIdentifier: String
    public var serialNumber: String
    public var organizationName: String?

    public init(passTypeIdentifier: String, serialNumber: String, organizationName: String? = nil) {
        self.passTypeIdentifier = passTypeIdentifier
        self.serialNumber = serialNumber
        self.organizationName = organizationName
    }
}

/// The bridge to PassKit. The platform implementation (`PassKitWalletLibrary`) wraps `PKPassLibrary` and `PKPass`;
/// tests and previews use `MockWalletLibrary`.
public protocol WalletLibrary: Sendable {
    /// `PKPassLibrary.isPassLibraryAvailable()`: false on devices that can't hold passes.
    var isAvailable: Bool { get }
    /// Whether a pass with this identity is in the person's Wallet.
    func containsPass(passTypeIdentifier: String, serialNumber: String) -> Bool
    /// Parses and validates the bundle (`PKPass(data:)`). Throws when it isn't a well-formed, signed pass.
    func validatedIdentity(of passData: Data) throws -> WalletPassIdentity
}

/// What the Wallet button shows for a pass.
public enum WalletPassState: Equatable, Sendable {
    /// This device can't add passes (or the Wallet library is unavailable).
    case unavailable
    case notInWallet
    case inWallet
    /// The business voided it: it can no longer be added.
    case voided
}

public enum WalletPassError: Error, Equatable, Sendable {
    case unavailable
    case voided
    /// The server sent bytes PassKit rejects. The app never repairs or re-signs a pass.
    case invalidPass
    /// The bundle isn't the pass the server's metadata promised (wrong type id or serial).
    case mismatchedPass
    case api(APIError)

    public var userMessage: String {
        switch self {
        case .unavailable: "This iPhone can't add passes to Wallet."
        case .voided: "This pass is no longer valid."
        case .invalidPass, .mismatchedPass: "We couldn't verify that pass. It wasn't added."
        case .api(let error): error.userMessage
        }
    }
}

/// A validated pass bundle ready for `PKAddPassesViewController`. Held in memory only for the duration of the
/// presentation; never written to disk by the app.
public struct PreparedPass: Equatable, Sendable {
    public var metadata: WalletPassMetadata
    public var data: Data
    public var identity: WalletPassIdentity
}

/// Fetches signed passes from the server, validates them, and answers "is it in Wallet?".
///
/// The app never creates or signs a pass: the server does, with the Pass Type ID certificate. The app only checks the
/// bundle is what the server's metadata said it would be before showing Apple's add-pass sheet.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class WalletPassCoordinator {
    public private(set) var inWallet: Set<WalletPassID> = []
    public private(set) var isPreparing: Set<WalletPassID> = []
    public private(set) var lastError: String?

    private let services: ViadereServices
    private let library: any WalletLibrary
    private var known: [WalletPassID: WalletPassMetadata] = [:]

    public init(services: ViadereServices, library: any WalletLibrary) {
        self.services = services
        self.library = library
    }

    public var canAddPasses: Bool { library.isAvailable }

    public func state(for metadata: WalletPassMetadata) -> WalletPassState {
        if metadata.voided { return .voided }
        guard library.isAvailable else { return .unavailable }
        return inWallet.contains(metadata.id) ? .inWallet : .notInWallet
    }

    /// Re-reads Wallet for the given passes (call on appear and after the add sheet closes).
    public func refresh(_ passes: [WalletPassMetadata]) {
        for pass in passes { known[pass.id] = pass }
        guard library.isAvailable else { inWallet = []; return }
        inWallet = Set(known.values.filter {
            library.containsPass(passTypeIdentifier: $0.passTypeIdentifier, serialNumber: $0.serialNumber)
        }.map(\.id))
    }

    /// Downloads, validates and returns the pass; the caller presents `PKAddPassesViewController`.
    public func prepare(_ metadata: WalletPassMetadata) async throws -> PreparedPass {
        lastError = nil
        guard !metadata.voided else { throw fail(.voided) }
        guard library.isAvailable else { throw fail(.unavailable) }
        isPreparing.insert(metadata.id)
        defer { isPreparing.remove(metadata.id) }
        let data: Data
        do { data = try await services.api.walletPass(metadata.id) } catch let error as APIError { throw fail(.api(error)) } catch { throw fail(.invalidPass) }
        guard !data.isEmpty, data.count <= Self.maximumPassSize else { throw fail(.invalidPass) }
        let identity: WalletPassIdentity
        do { identity = try library.validatedIdentity(of: data) } catch { throw fail(.invalidPass) }
        guard identity.passTypeIdentifier == metadata.passTypeIdentifier, identity.serialNumber == metadata.serialNumber else {
            throw fail(.mismatchedPass)
        }
        return PreparedPass(metadata: metadata, data: data, identity: identity)
    }

    /// Passes are small (a few hundred KB at most). Anything larger is refused before parsing.
    public static let maximumPassSize = 5 * 1024 * 1024

    private func fail(_ error: WalletPassError) -> WalletPassError {
        lastError = error.userMessage
        return error
    }

    public func clearError() { lastError = nil }
}

/// A library for devices (and builds) with no Wallet: nothing is available, nothing is "in Wallet".
public struct UnavailableWalletLibrary: WalletLibrary {
    public init() {}
    public var isAvailable: Bool { false }
    public func containsPass(passTypeIdentifier: String, serialNumber: String) -> Bool { false }
    public func validatedIdentity(of passData: Data) throws -> WalletPassIdentity { throw WalletPassError.unavailable }
}

// MARK: - Test and preview double

/// In-memory Wallet. Its "passes" are small JSON documents (the mock server's stand-in for a signed `.pkpass`).
public final class MockWalletLibrary: WalletLibrary, @unchecked Sendable {
    private let lock = NSLock()
    private var contents: Set<String> = []
    public let isAvailable: Bool

    public init(isAvailable: Bool = true) { self.isAvailable = isAvailable }

    public func containsPass(passTypeIdentifier: String, serialNumber: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return contents.contains(passTypeIdentifier + "|" + serialNumber)
    }

    /// Simulates the person tapping Add in Apple's sheet.
    public func simulateAdd(_ identity: WalletPassIdentity) {
        lock.lock(); defer { lock.unlock() }
        contents.insert(identity.passTypeIdentifier + "|" + identity.serialNumber)
    }

    public func validatedIdentity(of passData: Data) throws -> WalletPassIdentity {
        struct Stub: Decodable { var passTypeIdentifier: String; var serialNumber: String; var organizationName: String? }
        guard let stub = try? JSONDecoder().decode(Stub.self, from: passData) else { throw WalletPassError.invalidPass }
        return WalletPassIdentity(passTypeIdentifier: stub.passTypeIdentifier, serialNumber: stub.serialNumber, organizationName: stub.organizationName)
    }
}
