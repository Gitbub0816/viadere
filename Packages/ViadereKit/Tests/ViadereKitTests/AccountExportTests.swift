import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// The device side of the consumer data export (LEG-PR-004): a one-time key pair, the sealed chunks opened locally, nothing readable in transit.
@Suite("Account export")
struct AccountExportTests {
    final class Records: DeviceRecordStore, @unchecked Sendable {
        var record: DeviceRecord?
        init(_ record: DeviceRecord?) { self.record = record }
        func load() async throws -> DeviceRecord? { record }
        func save(_ record: DeviceRecord) async throws { self.record = record }
        func clear() async throws { record = nil }
    }

    /// A server in a box: remembers the key it was given, seals a document to it when the "job" runs.
    actor FakeServer: AccountExportAPI {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let deviceId: DeviceID
        var recipient: E2EEPublicKey?
        var exportId = UUID().uuidString.lowercased()
        var ready = false
        var envelopes: [String] = []
        var requests = 0
        var tamper = false
        var asAnotherExport = false

        init(deviceId: DeviceID) { self.deviceId = deviceId }

        func create(_ request: AccountExportRequest) async throws -> AccountExportStatus {
            requests += 1
            recipient = try E2EEPublicKey(base64URL: request.recipientKey)
            return AccountExportStatus(exportId: exportId, status: "queued", createdAt: now, readyAt: nil, expiresAt: now.addingTimeInterval(7 * 86_400), downloadPath: nil)
        }

        func runJob(document: Data) throws {
            let context = E2EEContext(purpose: "account-export", requestId: asAnotherExport ? UUID().uuidString.lowercased() : exportId, sender: "viadere",
                                      recipient: "device-" + deviceId.description, expiresAt: now.addingTimeInterval(7 * 86_400))
            var out: [String] = []
            var offset = 0
            while offset < document.count {
                let end = min(offset + 100, document.count)
                let envelope = try E2EE.seal(document.subdata(in: offset..<end), to: recipient!, context: context)
                var bytes = try envelope.serialized()
                if tamper, offset == 0 { bytes[bytes.count - 1] ^= 0x01 }
                out.append(Base64URL.encode(bytes))
                offset = end
            }
            envelopes = out
            ready = true
        }

        func status(id: String) async throws -> AccountExportStatus {
            AccountExportStatus(exportId: id, status: ready ? "ready" : "queued", createdAt: now, readyAt: ready ? now : nil, expiresAt: now.addingTimeInterval(7 * 86_400),
                                downloadPath: ready ? "/v1/account/exports/\(id)/download" : nil)
        }

        func download(id: String) async throws -> AccountExportBundle { AccountExportBundle(exportId: id, envelopes: envelopes) }
    }

    static func device() -> DeviceRecord {
        DeviceRecord(deviceId: DeviceID(), consumerId: ConsumerID(), name: "Test iPhone", purposes: [.request], enrolledAt: Date(timeIntervalSince1970: 1_700_000_000))
    }

    static let document = Data(#"{"format":"viadere-export-v1","account":{"displayName":"Pat"},"messages":[{"text":"Private note QZ4417"}]}"#.utf8)

    @Test func theExportIsSealedToTheDeviceKeyAndOpensOnlyThere() async throws {
        let device = Self.device()
        let server = FakeServer(deviceId: device.deviceId)
        let secrets = InMemorySecretStore()
        let service = AccountExportService(api: server, secrets: secrets, records: Records(device), clock: { Date(timeIntervalSince1970: 1_800_000_100) })
        let status = try await service.request()
        #expect(status.status == "queued")
        // The private key is on the device (in the secret store) and the server only has the public half.
        #expect(try secrets.read("account-export.key.\(status.exportId)") != nil)
        #expect(try secrets.read("account-export.key.pending") == nil)
        // Not ready yet.
        await #expect(throws: AccountExportError.notReady) { try await service.fetch(id: status.exportId) }
        try await server.runJob(document: Self.document)
        let opened = try await service.fetch(id: status.exportId)
        #expect(opened == Self.document)
        let text = String(decoding: opened, as: UTF8.self)
        #expect(text.contains("QZ4417"))
        // What the server had was ciphertext only.
        let sealed = await server.envelopes.joined()
        #expect(!sealed.contains("QZ4417"))
        #expect(!sealed.contains("Private"))
        // The key is gone once the export was read.
        #expect(try secrets.read("account-export.key.\(status.exportId)") == nil)
        await #expect(throws: AccountExportError.keyUnavailable) { try await service.fetch(id: status.exportId) }
    }

    @Test func aTamperedChunkAnotherDevicesKeyAndAnotherExportsContextAreRejected() async throws {
        let device = Self.device()
        // Altered in transit.
        let tampered = FakeServer(deviceId: device.deviceId)
        let service = AccountExportService(api: tampered, secrets: InMemorySecretStore(), records: Records(device), clock: { Date(timeIntervalSince1970: 1_800_000_100) })
        let status = try await service.request()
        await tampered.setTamper()
        try await tampered.runJob(document: Self.document)
        do { _ = try await service.fetch(id: status.exportId); Issue.record("a tampered chunk must not open") } catch let error as AccountExportError {
            #expect(error == .decryptionFailed || error == .malformed)
        }
        // Sealed under the context of another export: refused although the key is right.
        let swapped = FakeServer(deviceId: device.deviceId)
        let service2 = AccountExportService(api: swapped, secrets: InMemorySecretStore(), records: Records(device), clock: { Date(timeIntervalSince1970: 1_800_000_100) })
        let status2 = try await service2.request()
        await swapped.setAnotherExport()
        try await swapped.runJob(document: Self.document)
        await #expect(throws: AccountExportError.decryptionFailed) { try await service2.fetch(id: status2.exportId) }
        // A different device (different recipient binding) cannot open what was sealed for this one.
        let server = FakeServer(deviceId: device.deviceId)
        let secrets = InMemorySecretStore()
        let service3 = AccountExportService(api: server, secrets: secrets, records: Records(Self.device()), clock: { Date(timeIntervalSince1970: 1_800_000_100) })
        let status3 = try await service3.request()
        try await server.runJob(document: Self.document)
        await #expect(throws: AccountExportError.decryptionFailed) { try await service3.fetch(id: status3.exportId) }
        // After the validity window the envelopes are expired.
        let late = AccountExportService(api: server, secrets: InMemorySecretStore(), records: Records(device), clock: { Date(timeIntervalSince1970: 1_800_000_100 + 8 * 86_400) })
        let status4 = try await late.request()
        try await server.runJob(document: Self.document)
        await #expect(throws: AccountExportError.decryptionFailed) { try await late.fetch(id: status4.exportId) }
    }

    @Test func aFailedRequestLeavesNoKeyBehind() async throws {
        struct Failing: AccountExportAPI {
            func create(_ request: AccountExportRequest) async throws -> AccountExportStatus { throw APIError.transport("offline") }
            func status(id: String) async throws -> AccountExportStatus { throw APIError.transport("offline") }
            func download(id: String) async throws -> AccountExportBundle { throw APIError.transport("offline") }
        }
        let secrets = InMemorySecretStore()
        let service = AccountExportService(api: Failing(), secrets: secrets, records: Records(Self.device()))
        await #expect(throws: APIError.self) { try await service.request() }
        #expect(try secrets.read("account-export.key.pending") == nil)
    }

    @MainActor @Test func theViewModelRequestsPollsAndDeliversTheDocument() async throws {
        let device = Self.device()
        let server = FakeServer(deviceId: device.deviceId)
        let service = AccountExportService(api: server, secrets: InMemorySecretStore(), records: Records(device), clock: { Date(timeIntervalSince1970: 1_800_000_100) })
        let model = AccountExportViewModel(service: service, pollInterval: .milliseconds(5), maxPolls: 50)
        let running = Task { await model.start() }
        // The job finishes a little later.
        try await Task.sleep(for: .milliseconds(40))
        try await server.runJob(document: Self.document)
        await running.value
        guard case .ready(let data) = model.phase else { Issue.record("not ready: \(model.phase)"); return }
        #expect(data == Self.document)
        model.reset()
        #expect(model.phase == .idle)
        // Giving up politely when the job never finishes.
        let slow = FakeServer(deviceId: device.deviceId)
        let slowModel = AccountExportViewModel(service: AccountExportService(api: slow, secrets: InMemorySecretStore(), records: Records(device)), pollInterval: .milliseconds(1), maxPolls: 3)
        await slowModel.start()
        guard case .failed = slowModel.phase else { Issue.record("expected failure: \(slowModel.phase)"); return }
    }
}

extension AccountExportTests.FakeServer {
    func setTamper() { tamper = true }
    func setAnotherExport() { asAnotherExport = true }
}
