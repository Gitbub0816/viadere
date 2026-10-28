import Crypto
import Foundation
import ViadereCore

/// The vault-sync calls (`/v1/vault/...`). Separate from `ViadereAPI` so the credential-provider extension, which never syncs, can be built
/// without any of it.
public protocol VaultSyncAPI: Sendable {
    func status() async throws -> VaultStatus
    func put(_ request: VaultPutRequest) async throws -> VaultStatus
    func deleteVault() async throws
    func manifests(after: UInt64) async throws -> VaultManifestsResponse
    func blobs(_ ids: [UUID]) async throws -> [VaultBlobDTO]
    func envelope() async throws -> VaultEnvelopeResponse
    func recoveryEnvelope() async throws -> VaultEnvelopeResponse
    /// Starts the 72 h hold before the recovery envelope is released to this device (M2). Idempotent for the requesting device.
    func requestRecoveryRelease() async throws -> VaultRecoveryRelease
    /// "Not you? Cancel" (a vault device or a trusted account device).
    func cancelRecoveryRelease(_ releaseId: UUID) async throws -> VaultRecoveryRelease
    func devices() async throws -> [VaultDeviceInfo]
    func removeDevice(_ memberId: String) async throws
    func createJoin(_ joinId: String) async throws -> VaultJoinState
    func join(_ joinId: String) async throws -> VaultJoinState
    func submitJoinRequest(_ joinId: String, sealed: String) async throws -> VaultJoinState
    func cancelJoin(_ joinId: String) async throws
}

/// `VaultSyncAPI` over HTTP through the app's signed `APIClient`.
public struct LiveVaultSyncAPI: VaultSyncAPI {
    private let client: APIClient
    public init(client: APIClient) { self.client = client }

    public func status() async throws -> VaultStatus { try await client.call(APIRoutes.vaultStatus) }
    public func put(_ request: VaultPutRequest) async throws -> VaultStatus { try await client.call(APIRoutes.vaultPut, body: request) }
    public func deleteVault() async throws { _ = try await client.call(APIRoutes.vaultDelete) }
    public func manifests(after: UInt64) async throws -> VaultManifestsResponse {
        try await client.call(APIRoutes.vaultManifests, query: [("after", String(after)), ("limit", "100")])
    }
    public func blobs(_ ids: [UUID]) async throws -> [VaultBlobDTO] {
        var out: [VaultBlobDTO] = []
        var index = 0
        while index < ids.count {
            let chunk = Array(ids[index..<min(index + 100, ids.count)])
            out += try await client.call(APIRoutes.vaultBlobs, body: VaultBlobsRequest(itemIds: chunk)).blobs
            index += 100
        }
        return out
    }
    public func envelope() async throws -> VaultEnvelopeResponse { try await client.call(APIRoutes.vaultEnvelope) }
    public func recoveryEnvelope() async throws -> VaultEnvelopeResponse { try await client.call(APIRoutes.vaultRecoveryEnvelope) }
    public func requestRecoveryRelease() async throws -> VaultRecoveryRelease { try await client.call(APIRoutes.vaultRecoveryReleaseRequest) }
    public func cancelRecoveryRelease(_ releaseId: UUID) async throws -> VaultRecoveryRelease {
        try await client.call(APIRoutes.vaultRecoveryReleaseCancel, params: ["releaseId": releaseId.uuidString.lowercased()])
    }
    public func devices() async throws -> [VaultDeviceInfo] { try await client.call(APIRoutes.vaultDevices) }
    public func removeDevice(_ memberId: String) async throws { _ = try await client.call(APIRoutes.vaultDeviceRemove, params: ["memberId": memberId]) }
    public func createJoin(_ joinId: String) async throws -> VaultJoinState { try await client.call(APIRoutes.vaultJoinCreate, params: ["joinId": joinId]) }
    public func join(_ joinId: String) async throws -> VaultJoinState { try await client.call(APIRoutes.vaultJoinGet, params: ["joinId": joinId]) }
    public func submitJoinRequest(_ joinId: String, sealed: String) async throws -> VaultJoinState {
        try await client.call(APIRoutes.vaultJoinRequest, params: ["joinId": joinId], body: VaultJoinRequestBody(request: sealed))
    }
    public func cancelJoin(_ joinId: String) async throws { _ = try await client.call(APIRoutes.vaultJoinCancel, params: ["joinId": joinId]) }
}

extension LiveVaultSyncAPI {
    /// A vault-sync client that shares the app's session, device keys and certificate pinning (`ViadereServices`). Never used by the credential-provider
    /// extension: it has no session and no network.
    public static func make(services: ViadereServices) -> LiveVaultSyncAPI {
        let transport = URLSessionTransport(configuration: services.configuration)
        let signer = DeviceRequestSigner(records: services.records, keys: services.keys, clock: services.clock)
        let executor = RequestExecutor(baseURL: services.configuration.apiBaseURL, transport: transport, signer: signer)
        let revocation = services.revocation
        return LiveVaultSyncAPI(client: APIClient(executor: executor, sessions: services.sessions, onDeviceRejected: { revocation.notify() }))
    }
}

/// An in-memory vault server for previews and tests. It enforces the same rules as the real one where they matter to the client logic:
/// version compare-and-swap, the Core chain verifier, device binding, blob and envelope hashes, joins. Several `InMemoryVaultSyncAPI`
/// values (one per simulated account device) share one server. It stores ciphertext only, like the real thing.
public final class InMemoryVaultServer: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var vaultId: UUID?
    private(set) var chain: [SignedVaultManifest] = []
    private var head: VerifiedManifest?
    private var blobs: [UUID: Data] = [:]
    private var envelopes: [String: Data] = [:]
    private var bound: [String: String] = [:]            // account device -> member id
    private var removed: Set<String> = []
    private var joins: [String: Join] = [:]
    private var releases: [UUID: Release] = [:]
    private var skew: TimeInterval = 0
    public private(set) var requestLog: [String] = []
    public var available = true
    /// Fail the next `put` with a conflict (simulates another device winning a race).
    public var failNextPutWithConflict = false

    struct Release { var device: String; var requestedAt: Date; var releaseAt: Date; var expiresAt: Date; var state = "pending" }

    /// Test hook: time passes (the 72 h hold and the 24 h window run on this clock).
    public func advance(by seconds: TimeInterval) { lock.withLock { skew += seconds } }
    private var now: Date { Date().addingTimeInterval(skew) }

    struct Join { var requester: String?; var request: Data?; var approval: Data?; var approvedMember: String?; var approvedVersion: UInt64? }

    public init() {}

    /// Everything stored, concatenated (tests assert that no plaintext is in it).
    public var storedBytes: Data {
        lock.withLock {
            var out = Data()
            for manifest in chain { out += manifest.manifestBytes + manifest.signature }
            for blob in blobs.values { out += blob }
            for envelope in envelopes.values { out += envelope }
            return out
        }
    }

    public var version: UInt64 { lock.withLock { head?.manifest.version ?? 0 } }
    public var blobCount: Int { lock.withLock { blobs.count } }

    /// Test hook: replaces the stored history (a malicious or rolled-back server).
    public func rewind(toVersion version: Int) {
        lock.withLock {
            chain = Array(chain.prefix(version))
            head = chain.last.flatMap { try? VaultChainVerifier.restore($0) }
        }
    }

    fileprivate func perform<T>(_ name: String, _ body: () throws -> T) throws -> T {
        try lock.withLock {
            requestLog.append(name)
            guard available else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
            return try body()
        }
    }

    fileprivate func fail(_ status: Int, _ code: APIErrorCode) -> APIError { .server(status: status, code: code, message: "") }

    fileprivate func memberId(of device: String) -> String? { bound[device].flatMap { removed.contains($0) ? nil : $0 } }

    fileprivate func statusLocked(_ device: String) -> VaultStatus {
        guard let head, let vaultId else { return VaultStatus(exists: false) }
        let m = head.manifest
        let mine = memberId(of: device)
        return VaultStatus(exists: true, vaultId: vaultId, version: m.version, epoch: m.epoch, bound: mine != nil, memberId: mine,
                           deviceCount: m.devices.filter { !removed.contains($0.id) }.count, recoveryConfigured: m.recoveryMember != nil,
                           recoveryRelease: openRelease().map { releaseDTO($0.key, $0.value, device) })
    }

    // The recovery-envelope release, as the real server does it: a 72 h hold, then 24 h for the requesting device only.
    fileprivate func openRelease() -> (key: UUID, value: Release)? {
        releases.filter { $0.value.state == "pending" && $0.value.expiresAt > now }.max { $0.value.requestedAt < $1.value.requestedAt }
    }

    fileprivate func releaseDTO(_ id: UUID, _ r: Release, _ device: String) -> VaultRecoveryRelease {
        let state: VaultRecoveryRelease.State = r.state == "cancelled" ? .cancelled : r.state == "consumed" ? .consumed : (now < r.releaseAt ? .holding : (now < r.expiresAt ? .released : .expired))
        return VaultRecoveryRelease(releaseId: id, state: state, requestedAt: r.requestedAt, releaseAt: r.releaseAt, expiresAt: r.expiresAt, requestedByThisDevice: r.device == device)
    }

    /// The device's open window (hold passed, 24 h not): the only thing that lets a non-member read.
    fileprivate func requireWindow(_ device: String) throws -> UUID {
        guard let open = openRelease(), open.value.device == device, open.value.releaseAt <= now else { throw fail(403, .forbidden) }
        return open.key
    }

    fileprivate func requestRelease(device: String) throws -> VaultRecoveryRelease {
        try perform("release-request") {
            guard head?.manifest.recoveryMember != nil else { throw fail(404, .notFound) }
            guard memberId(of: device) == nil else { throw fail(409, .conflict) }
            if let open = openRelease() {
                guard open.value.device == device else { throw fail(409, .conflict) }
                return releaseDTO(open.key, open.value, device)
            }
            let id = UUID()
            let release = Release(device: device, requestedAt: now, releaseAt: now.addingTimeInterval(VaultRecoveryRelease.holdSeconds),
                                  expiresAt: now.addingTimeInterval(VaultRecoveryRelease.holdSeconds + VaultRecoveryRelease.windowSeconds))
            releases[id] = release
            return releaseDTO(id, release, device)
        }
    }

    fileprivate func cancelRelease(_ id: UUID, device: String) throws -> VaultRecoveryRelease {
        try perform("release-cancel") {
            guard var release = releases[id] else { throw fail(404, .notFound) }
            for key in releases.keys where releases[key]?.state == "pending" { releases[key]?.state = "cancelled" }
            release.state = "cancelled"
            return releaseDTO(id, release, device)
        }
    }

    fileprivate func put(_ request: VaultPutRequest, device: String) throws -> VaultStatus {
        try perform("put") {
            if failNextPutWithConflict { failNextPutWithConflict = false; throw fail(409, .conflict) }
            guard let signed = request.manifest.signed else { throw fail(422, .validationFailed) }
            let verified: VerifiedManifest
            var consumeWindow: UUID?
            if request.expectedVersion == 0 {
                guard head == nil else { throw fail(409, .conflict) }
                verified = try validated { try VaultChainVerifier.verifyGenesis(signed) }
            } else {
                guard let head else { throw fail(404, .notFound) }
                guard head.manifest.version == request.expectedVersion else { throw fail(409, .conflict) }
                verified = try validated { try VaultChainVerifier.verify(signed, after: head) }
                if signed.recoveryAuthorization == nil {
                    guard memberId(of: device) == verified.manifest.signerId else { throw fail(403, .forbidden) }
                } else {
                    consumeWindow = try requireWindow(device)
                }
            }
            let m = verified.manifest
            var newBlobs: [UUID: Data] = [:]
            for entry in request.blobs { newBlobs[entry.itemId] = Base64URL.decode(entry.blob) }
            for ref in m.items {
                if let blob = newBlobs[ref.itemId] { guard Data(SHA256.hash(data: blob)) == ref.blobHash else { throw fail(422, .validationFailed) } }
                else { guard let stored = blobs[ref.itemId], Data(SHA256.hash(data: stored)) == ref.blobHash else { throw fail(422, .validationFailed) } }
            }
            for member in m.members {
                let prior = head?.manifest.member(member.id)
                if prior == nil || prior?.envelopeHash != member.envelopeHash {
                    guard let text = request.envelopes.first(where: { $0.memberId == member.id })?.envelope, let envelope = Base64URL.decode(text),
                          VaultEnvelope.hash(envelope) == member.envelopeHash else { throw fail(422, .validationFailed) }
                    envelopes[member.id] = envelope
                }
            }
            let priorIds = Set(head?.manifest.members.map(\.id) ?? [])
            for gone in priorIds where m.member(gone) == nil { removed.insert(gone); envelopes[gone] = nil; bound = bound.filter { $0.value != gone } }
            if request.expectedVersion == 0 || signed.recoveryAuthorization != nil {
                guard request.bindMemberId == m.signerId else { throw fail(422, .validationFailed) }
                bound[device] = m.signerId
            }
            if let joinId = request.joinId {
                guard var join = joins[joinId], join.request != nil, join.approval == nil, let memberId = request.joinMemberId, let requester = join.requester,
                      let approval = request.joinApproval.flatMap(Base64URL.decode) else { throw fail(422, .validationFailed) }
                join.approval = approval
                join.approvedMember = memberId
                join.approvedVersion = m.version
                joins[joinId] = join
                bound[requester] = memberId
            }
            for (id, blob) in newBlobs { blobs[id] = blob }
            for id in blobs.keys where !m.items.contains(where: { $0.itemId == id }) { blobs[id] = nil }
            if let consumeWindow { releases[consumeWindow]?.state = "consumed" }
            vaultId = m.vaultId
            chain.append(signed)
            head = verified
            return statusLocked(device)
        }
    }

    private func validated<T>(_ body: () throws -> T) throws -> T {
        do { return try body() } catch { throw fail(422, .validationFailed) }
    }

    fileprivate func requireBound(_ device: String) throws -> String {
        guard head != nil else { throw fail(404, .notFound) }
        guard let member = memberId(of: device) else { throw fail(403, .forbidden) }
        return member
    }

    fileprivate func status(_ device: String) throws -> VaultStatus { try perform("status") { statusLocked(device) } }

    fileprivate func deleteVault(device: String) throws {
        try perform("delete") {
            _ = try requireBound(device)
            vaultId = nil; chain = []; head = nil; blobs = [:]; envelopes = [:]; bound = [:]; removed = []; joins = [:]; releases = [:]
        }
    }

    fileprivate func manifests(after: UInt64, device: String) throws -> VaultManifestsResponse {
        try perform("manifests") {
            guard head != nil else { throw fail(404, .notFound) }
            if memberId(of: device) == nil { _ = try requireWindow(device) }
            let rows = chain.filter { (try? VaultManifest.decode($0.manifestBytes).version) ?? 0 > after }
            return VaultManifestsResponse(manifests: rows.prefix(100).map(VaultManifestDTO.init), latestVersion: head?.manifest.version ?? 0)
        }
    }

    fileprivate func blobs(_ ids: [UUID], device: String) throws -> [VaultBlobDTO] {
        try perform("blobs") {
            if memberId(of: device) == nil { _ = try requireWindow(device) }
            return ids.compactMap { id in blobs[id].map { VaultBlobDTO(itemId: id, blob: Base64URL.encode($0)) } } }
    }

    fileprivate func envelope(device: String, recovery: Bool) throws -> VaultEnvelopeResponse {
        try perform(recovery ? "recovery-envelope" : "envelope") {
            guard let head else { throw fail(404, .notFound) }
            if recovery { _ = try requireWindow(device) }
            let id = recovery ? head.manifest.recoveryMember?.id : try requireBound(device)
            guard let id, let envelope = envelopes[id] else { throw fail(404, .notFound) }
            return VaultEnvelopeResponse(memberId: id, envelope: Base64URL.encode(envelope))
        }
    }

    fileprivate func devices(device: String) throws -> [VaultDeviceInfo] {
        try perform("devices") {
            guard let head else { throw fail(404, .notFound) }
            return head.manifest.members.filter { !removed.contains($0.id) }.map { member in
                VaultDeviceInfo(memberId: member.id, role: member.role == .device ? "device" : "recovery", addedAt: Date(timeIntervalSince1970: TimeInterval(member.addedAt)),
                                accountDeviceId: nil, accountDeviceActive: bound.values.contains(member.id), removed: false)
            }
        }
    }

    fileprivate func removeDevice(_ member: String, device: String) throws {
        try perform("remove-device") {
            let own = try requireBound(device)
            guard member != own else { throw fail(404, .notFound) }
            removed.insert(member); envelopes[member] = nil; bound = bound.filter { $0.value != member }
        }
    }

    fileprivate func joinState(_ id: String) -> VaultJoinState {
        let join = joins[id]
        return VaultJoinState(joinId: id, expiresAt: Date.distantFuture, request: join?.request.map { Base64URL.encode($0) }, approval: join?.approval.map { Base64URL.encode($0) },
                              approvedMemberId: join?.approvedMember, approvedVersion: join?.approvedVersion)
    }

    fileprivate func createJoin(_ id: String, device: String) throws -> VaultJoinState {
        try perform("join-create") { _ = try requireBound(device); joins[id] = joins[id] ?? Join(); return joinState(id) }
    }

    fileprivate func join(_ id: String) throws -> VaultJoinState {
        try perform("join-get") { guard joins[id] != nil else { throw fail(404, .notFound) }; return joinState(id) }
    }

    fileprivate func submitJoin(_ id: String, sealed: String, device: String) throws -> VaultJoinState {
        try perform("join-request") {
            guard var join = joins[id] else { throw fail(404, .notFound) }
            guard join.request == nil, let bytes = Base64URL.decode(sealed) else { throw fail(409, .conflict) }
            join.request = bytes; join.requester = device
            joins[id] = join
            return joinState(id)
        }
    }

    fileprivate func cancelJoin(_ id: String) throws { try perform("join-cancel") { joins[id] = nil } }
}

public struct InMemoryVaultSyncAPI: VaultSyncAPI {
    let server: InMemoryVaultServer
    /// The simulated account device.
    let device: String

    public init(server: InMemoryVaultServer, device: String = UUID().uuidString) {
        self.server = server
        self.device = device
    }

    public func status() async throws -> VaultStatus { try server.status(device) }
    public func put(_ request: VaultPutRequest) async throws -> VaultStatus { try server.put(request, device: device) }
    public func deleteVault() async throws { try server.deleteVault(device: device) }
    public func manifests(after: UInt64) async throws -> VaultManifestsResponse { try server.manifests(after: after, device: device) }
    public func blobs(_ ids: [UUID]) async throws -> [VaultBlobDTO] { try server.blobs(ids, device: device) }
    public func envelope() async throws -> VaultEnvelopeResponse { try server.envelope(device: device, recovery: false) }
    public func recoveryEnvelope() async throws -> VaultEnvelopeResponse { try server.envelope(device: device, recovery: true) }
    public func requestRecoveryRelease() async throws -> VaultRecoveryRelease { try server.requestRelease(device: device) }
    public func cancelRecoveryRelease(_ releaseId: UUID) async throws -> VaultRecoveryRelease { try server.cancelRelease(releaseId, device: device) }
    public func devices() async throws -> [VaultDeviceInfo] { try server.devices(device: device) }
    public func removeDevice(_ memberId: String) async throws { try server.removeDevice(memberId, device: device) }
    public func createJoin(_ joinId: String) async throws -> VaultJoinState { try server.createJoin(joinId, device: device) }
    public func join(_ joinId: String) async throws -> VaultJoinState { try server.join(joinId) }
    public func submitJoinRequest(_ joinId: String, sealed: String) async throws -> VaultJoinState { try server.submitJoin(joinId, sealed: sealed, device: device) }
    public func cancelJoin(_ joinId: String) async throws { try server.cancelJoin(joinId) }
}
