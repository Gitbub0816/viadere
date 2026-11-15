import Crypto
import Foundation
import ViadereCore
#if canImport(DeviceCheck)
import DeviceCheck
#endif

/// Apple App Attest, behind a protocol so enrollment is testable and the Simulator (which has no App Attest) degrades predictably.
///
/// A **new key per enrollment**: the server accepts one App Attest key for one device, and the attestation is bound to the enrollment
/// (`AppAttestBinding`), so a key is never reused.
public protocol AppAttestProviding: Sendable {
    /// `false` on the Simulator, on devices without App Attest and in processes that cannot use it.
    var isSupported: Bool { get }
    /// `DCAppAttestService.generateKey`: the key identifier (base64).
    func generateKey() async throws -> String
    /// `DCAppAttestService.attestKey(_:clientDataHash:)`: the CBOR attestation object.
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data
    /// `DCAppAttestService.generateAssertion(_:clientDataHash:)`: the CBOR assertion made with the attested key (WP-C2).
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data
}

public enum AppAttestError: Error, Equatable, Sendable {
    /// This device cannot attest (Simulator, unsupported hardware) and the build does not allow skipping it.
    case unsupported
    /// Apple's service failed or was unreachable.
    case failed

    public var userMessage: String {
        switch self {
        case .unsupported: "This iPhone couldn't be verified. Make sure you're using the App Store version of Viadere."
        case .failed: "We couldn't verify this iPhone just now. Check your connection and try again."
        }
    }
}

/// The copy for `403 attestation_required`.
public enum AttestationMessage {
    public static let notVerified = "This iPhone couldn't be verified. Make sure you're using the App Store version of Viadere."
}

/// Reports "not supported" (extensions, release builds on the Simulator, Linux).
public struct UnavailableAppAttest: AppAttestProviding {
    public init() {}
    public var isSupported: Bool { false }
    public func generateKey() async throws -> String { throw AppAttestError.unsupported }
    public func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data { throw AppAttestError.unsupported }
    public func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data { throw AppAttestError.unsupported }
}

/// A scriptable stand-in: records the `clientDataHash` of every attestation so tests can check what was vouched for.
public final class MockAppAttest: AppAttestProviding, @unchecked Sendable {
    private let lock = NSLock()
    private var _attested: [(keyId: String, clientDataHash: Data)] = []
    private var _generated = 0
    public let isSupported: Bool
    public var failure: AppAttestError?

    public init(isSupported: Bool = true, failure: AppAttestError? = nil) {
        self.isSupported = isSupported
        self.failure = failure
    }

    public var attested: [(keyId: String, clientDataHash: Data)] { lock.lock(); defer { lock.unlock() }; return _attested }
    public var generatedKeyCount: Int { lock.lock(); defer { lock.unlock() }; return _generated }

    public func generateKey() async throws -> String {
        if let failure { throw failure }
        return nextKeyId()
    }

    public func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        if let failure { throw failure }
        record(keyId, clientDataHash)
        return Data("mock-attestation:".utf8) + clientDataHash
    }

    public func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        if let failure { throw failure }
        recordAssertion(keyId, clientDataHash)
        return Data("mock-assertion:".utf8) + clientDataHash
    }

    private var _asserted: [(keyId: String, clientDataHash: Data)] = []
    public var asserted: [(keyId: String, clientDataHash: Data)] { lock.lock(); defer { lock.unlock() }; return _asserted }
    private func recordAssertion(_ keyId: String, _ hash: Data) {
        lock.lock(); defer { lock.unlock() }
        _asserted.append((keyId, hash))
    }

    private func nextKeyId() -> String {
        lock.lock(); defer { lock.unlock() }
        _generated += 1
        return Data("mock-app-attest-key-\(_generated)".utf8).base64EncodedString()
    }

    private func record(_ keyId: String, _ hash: Data) {
        lock.lock(); defer { lock.unlock() }
        _attested.append((keyId, hash))
    }
}

#if canImport(DeviceCheck)
/// The real thing. App Attest keys live in the Secure Enclave and are scoped to this app (the Clip has its own).
public struct DeviceCheckAppAttest: AppAttestProviding {
    public init() {}

    public var isSupported: Bool { DCAppAttestService.shared.isSupported }

    public func generateKey() async throws -> String {
        guard DCAppAttestService.shared.isSupported else { throw AppAttestError.unsupported }
        do { return try await DCAppAttestService.shared.generateKey() } catch { throw AppAttestError.failed }
    }

    public func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        guard DCAppAttestService.shared.isSupported else { throw AppAttestError.unsupported }
        do { return try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash) } catch { throw AppAttestError.failed }
    }

    public func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        guard DCAppAttestService.shared.isSupported else { throw AppAttestError.unsupported }
        do { return try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash) } catch { throw AppAttestError.failed }
    }
}
#endif

/// Builds the `appAttest` evidence for exactly the keys being sent.
struct EnrollmentAttester: Sendable {
    let provider: any AppAttestProviding
    /// DEBUG builds may skip attestation when it is unsupported (Simulator); Release reports the error.
    let skipsWhenUnsupported: Bool

    func evidence(consumerId: ConsumerID, challenge: String, keys: [DeviceKeyRegistration]) async throws -> AppAttestEvidence? {
        guard provider.isSupported else {
            if skipsWhenUnsupported { return nil }
            throw AppAttestError.unsupported
        }
        let keyId = try await provider.generateKey()
        let hash = AppAttestBinding.clientDataHash(consumerId: consumerId, challenge: challenge, keys: keys)
        let attestation = try await provider.attestKey(keyId, clientDataHash: hash)
        return AppAttestEvidence(keyId: keyId, attestation: Base64URL.encode(attestation))
    }
}

public enum AppAttestPolicy {
    /// DEBUG builds may enroll without App Attest where it is unsupported (the Simulator); Release builds never do.
    #if DEBUG
    public static let skipsWhenUnsupported = true
    #else
    public static let skipsWhenUnsupported = false
    #endif
}

/// App Attest assertions for the requests that decide something (WP-C2): an approval result and a link completion. Uses the App Attest key this
/// device was enrolled with (`DeviceRecord.appAttestKeyId`); `nil` when the device has none or the service fails (the server's
/// `APP_ATTEST_ASSERTION_MODE` decides whether that is acceptable).
public struct DeviceAssertions: Sendable {
    let provider: any AppAttestProviding
    let records: any DeviceRecordStore

    public init(provider: any AppAttestProviding, records: any DeviceRecordStore) {
        self.provider = provider
        self.records = records
    }

    /// base64url of the CBOR assertion over `SHA-256(clientData)`.
    public func assertion(over clientData: Data) async -> String? {
        guard provider.isSupported, let keyId = try? await records.load()?.appAttestKeyId else { return nil }
        guard let assertion = try? await provider.generateAssertion(keyId, clientDataHash: Data(SHA256.hash(data: clientData))) else { return nil }
        return Base64URL.encode(assertion)
    }

    public var source: AssertionSource { { clientData in await assertion(over: clientData) } }
}
