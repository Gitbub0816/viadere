import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// The consumer's copy of their data (LEG-PR-004, GDPR Art. 15/20). The device asks (a device-signed request), the server builds the export in a
/// background job and **seals it to a key that only this device holds**; the app downloads the sealed chunks and opens them locally. Nothing is
/// emailed and the server keeps nothing it can read.
public protocol AccountExportAPI: Sendable {
    func create(_ request: AccountExportRequest) async throws -> AccountExportStatus
    func status(id: String) async throws -> AccountExportStatus
    func download(id: String) async throws -> AccountExportBundle
}

/// `AccountExportAPI` over HTTP through the app's signed `APIClient`.
public struct LiveAccountExportAPI: AccountExportAPI {
    private let client: APIClient
    public init(client: APIClient) { self.client = client }

    public func create(_ request: AccountExportRequest) async throws -> AccountExportStatus { try await client.call(APIRoutes.accountExportCreate, body: request) }
    public func status(id: String) async throws -> AccountExportStatus { try await client.call(APIRoutes.accountExportGet, params: ["exportId": id]) }
    public func download(id: String) async throws -> AccountExportBundle { try await client.call(APIRoutes.accountExportDownload, params: ["exportId": id]) }
}

extension LiveAccountExportAPI {
    /// A client that shares the app's session, device keys and certificate pinning. Never used by extensions or the App Clip.
    public static func make(services: ViadereServices) -> LiveAccountExportAPI {
        let transport = URLSessionTransport(configuration: services.configuration)
        let signer = DeviceRequestSigner(records: services.records, keys: services.keys, clock: services.clock)
        let executor = RequestExecutor(baseURL: services.configuration.apiBaseURL, transport: transport, signer: signer)
        let revocation = services.revocation
        return LiveAccountExportAPI(client: APIClient(executor: executor, sessions: services.sessions, onDeviceRejected: { revocation.notify() }))
    }
}

public enum AccountExportError: Error, Equatable, Sendable {
    /// The server has not finished building it (or it expired).
    case notReady
    /// The key that opens this export is not on this device (another device asked, or the app was reinstalled).
    case keyUnavailable
    /// A chunk did not open: wrong key, altered in transit, or a different export.
    case decryptionFailed
    case malformed
}

/// Requests an export with a fresh one-time key pair, keeps the private key in the secret store (Keychain) until the export is fetched, and opens the
/// sealed chunks. The key is deleted as soon as the export was read or the person discards it.
public struct AccountExportService: Sendable {
    private let api: any AccountExportAPI
    private let secrets: any SecretStore
    private let records: any DeviceRecordStore
    private let clock: @Sendable () -> Date

    public init(api: any AccountExportAPI, secrets: any SecretStore, records: any DeviceRecordStore, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.secrets = secrets
        self.records = records
        self.clock = clock
    }

    private static func slot(_ id: String) -> String { "account-export.key." + id }
    private static let pendingSlot = "account-export.key.pending"

    /// Asks the server for an export. The returned status is `queued`; poll `status(id:)` until `ready`.
    public func request() async throws -> AccountExportStatus {
        let key = SoftwareE2EEPrivateKey()
        try secrets.write(key.rawRepresentation, account: Self.pendingSlot)
        do {
            let status = try await api.create(AccountExportRequest(recipientKey: key.publicKey.base64URL))
            try secrets.write(key.rawRepresentation, account: Self.slot(status.exportId))
            try? secrets.delete(Self.pendingSlot)
            return status
        } catch {
            try? secrets.delete(Self.pendingSlot)
            throw error
        }
    }

    public func status(id: String) async throws -> AccountExportStatus { try await api.status(id: id) }

    /// Downloads and opens a ready export; returns the JSON document (`viadere-export-v1`). The private key is deleted afterwards.
    public func fetch(id: String) async throws -> Data {
        guard let raw = try secrets.read(Self.slot(id)), let key = try? SoftwareE2EEPrivateKey(rawRepresentation: raw) else { throw AccountExportError.keyUnavailable }
        guard let device = try await records.load() else { throw AccountExportError.keyUnavailable }
        let status = try await api.status(id: id)
        guard status.status == "ready", status.downloadPath != nil else { throw AccountExportError.notReady }
        let bundle = try await api.download(id: id)
        guard bundle.exportId == id, bundle.format == "viadere-export-v1", !bundle.envelopes.isEmpty else { throw AccountExportError.malformed }
        let expectation = E2EEExpectation(purpose: "account-export", requestId: id, sender: "viadere", recipient: "device-" + device.deviceId.description)
        var document = Data()
        for chunk in bundle.envelopes {
            guard let bytes = Base64URL.decode(chunk), let envelope = try? E2EEEnvelope.parse(bytes) else { throw AccountExportError.malformed }
            do { document += try E2EE.open(envelope, using: key, expecting: expectation, now: clock()) } catch { throw AccountExportError.decryptionFailed }
        }
        guard (try? JSONSerialization.jsonObject(with: document)) != nil else { throw AccountExportError.malformed }
        try? secrets.delete(Self.slot(id))
        return document
    }

    /// Forgets the key of an export the person no longer wants (the server copy expires on its own).
    public func discard(id: String) { try? secrets.delete(Self.slot(id)) }
}

/// State of the "Download my data" screen.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class AccountExportViewModel {
    public enum Phase: Equatable { case idle, requesting, waiting(String), ready(Data), failed(String) }

    public private(set) var phase: Phase = .idle
    private let service: AccountExportService
    private let pollInterval: Duration
    private let maxPolls: Int

    public init(service: AccountExportService, pollInterval: Duration = .seconds(3), maxPolls: Int = 100) {
        self.service = service
        self.pollInterval = pollInterval
        self.maxPolls = maxPolls
    }

    public func start() async {
        guard phase == .idle || { if case .failed = phase { return true } else { return false } }() else { return }
        phase = .requesting
        do {
            let status = try await service.request()
            phase = .waiting(status.exportId)
            await poll(id: status.exportId)
        } catch let error as APIError {
            phase = .failed(Self.message(error))
        } catch {
            phase = .failed("We could not start your export. Try again in a moment.")
        }
    }

    private func poll(id: String) async {
        for _ in 0..<maxPolls {
            do {
                let status = try await service.status(id: id)
                if status.status == "ready" {
                    phase = .ready(try await service.fetch(id: id))
                    return
                }
                if status.status == "expired" { phase = .failed("This export expired. Start a new one."); return }
            } catch {
                phase = .failed("We could not fetch your export. Try again in a moment.")
                return
            }
            try? await Task.sleep(for: pollInterval)
        }
        phase = .failed("Your export is taking longer than usual. Open this screen again later.")
    }

    public func reset() { phase = .idle }

    private static func message(_ error: APIError) -> String {
        error.code == .rateLimited
            ? "You asked for several exports today. Try again tomorrow."
            : "We could not start your export. This device may still be getting set up; try again in a day."
    }
}
