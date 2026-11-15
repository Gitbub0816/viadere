import Foundation
import ViadereCore

// Device pairing (WP-D1, SECURITY.md §2.105): the device's calls, kept behind a protocol so the screens are testable without a server.

public enum DevicePairingError: Error, Equatable, Sendable {
    /// This build has no pairing client (extensions, the App Clip).
    case unavailable
    case offline
    /// The pairing code is wrong, used, expired, or this ceremony is gone (one answer for all of them).
    case invalidCode
    /// The account has no device that could approve a new one: the way back is account recovery.
    case noTrustedDevice
    case attestationRequired
    case expired
    /// The number typed on the approving device is not the one the new device shows.
    case wrongNumber
    /// The request does not match the new device (substituted keys, a changed request).
    case mismatch
    /// This device is not trusted enough (D0) or has no Face ID / Touch ID key.
    case notTrusted
    /// Already answered, or another device is being added right now.
    case conflict
    case rateLimited
    case failed

    static func from(_ error: any Error) -> DevicePairingError {
        if let error = error as? DevicePairingError { return error }
        guard let error = error as? APIError else { return .offline }
        if case .transport = error { return .offline }
        switch error.code {
        case .unauthorized?: return .invalidCode
        case .noTrustedDevice?: return .noTrustedDevice
        case .attestationRequired?: return .attestationRequired
        case .expired?, .gone?: return .expired
        case .comparisonMismatch?: return .wrongNumber
        case .pairingMismatch?: return .mismatch
        case .deviceCoolDown?, .forbidden?, .insufficientAssurance?: return .notTrusted
        case .conflict?, .replayDetected?: return .conflict
        case .rateLimited?: return .rateLimited
        default: return .failed
        }
    }
}

public protocol DevicePairingAPI: Sendable {
    /// Trusted device: a new pairing code (`POST /v1/device-pairings/invitations`).
    func invite() async throws -> DevicePairingInvitation
    /// New device (public).
    func begin() async throws -> DevicePairingBeginResponse
    func start(_ id: DevicePairingID, _ request: DevicePairingStartRequest) async throws -> DevicePairingStartResponse
    func status(_ id: DevicePairingID, token: String) async throws -> DevicePairingStatus
    func cancel(_ id: DevicePairingID, token: String) async throws -> DevicePairingStatus
    /// Trusted device (device-signed).
    func pending() async throws -> [DevicePairingRequest]
    func approve(_ id: DevicePairingID, _ approval: DevicePairingApproval) async throws -> DevicePairingApproveResponse
    func deny(_ id: DevicePairingID, report: Bool) async throws
}

/// The live client over the shared route catalog. Errors become `DevicePairingError`.
public struct LiveDevicePairingAPI: DevicePairingAPI {
    let client: APIClient
    public init(client: APIClient) { self.client = client }

    private func mapped<T>(_ work: () async throws -> T) async throws -> T {
        do { return try await work() } catch { throw DevicePairingError.from(error) }
    }

    public func invite() async throws -> DevicePairingInvitation { try await mapped { try await client.call(APIRoutes.devicePairingInvite) } }
    public func begin() async throws -> DevicePairingBeginResponse { try await mapped { try await client.call(APIRoutes.devicePairingBegin) } }
    public func start(_ id: DevicePairingID, _ request: DevicePairingStartRequest) async throws -> DevicePairingStartResponse {
        try await mapped { try await client.call(APIRoutes.devicePairingStart, params: ["pairingId": id.description], body: request) }
    }
    public func status(_ id: DevicePairingID, token: String) async throws -> DevicePairingStatus {
        try await mapped { try await client.call(APIRoutes.devicePairingStatus, params: ["pairingId": id.description], body: DevicePairingStatusRequest(statusToken: token)) }
    }
    public func cancel(_ id: DevicePairingID, token: String) async throws -> DevicePairingStatus {
        try await mapped { try await client.call(APIRoutes.devicePairingCancel, params: ["pairingId": id.description], body: DevicePairingStatusRequest(statusToken: token)) }
    }
    public func pending() async throws -> [DevicePairingRequest] { try await mapped { try await client.call(APIRoutes.devicePairingsPending) } }
    public func approve(_ id: DevicePairingID, _ approval: DevicePairingApproval) async throws -> DevicePairingApproveResponse {
        try await mapped { try await client.call(APIRoutes.devicePairingApprove, params: ["pairingId": id.description], body: DevicePairingApproveRequest(approval: approval)) }
    }
    public func deny(_ id: DevicePairingID, report: Bool) async throws {
        let _: EmptyBody = try await mapped {
            try await client.call(APIRoutes.devicePairingDeny, params: ["pairingId": id.description], body: DevicePairingDenyRequest(report: report ? true : nil))
        }
    }
}

/// Every call fails closed.
public struct UnavailableDevicePairingAPI: DevicePairingAPI {
    public init() {}
    public func invite() async throws -> DevicePairingInvitation { throw DevicePairingError.unavailable }
    public func begin() async throws -> DevicePairingBeginResponse { throw DevicePairingError.unavailable }
    public func start(_ id: DevicePairingID, _ request: DevicePairingStartRequest) async throws -> DevicePairingStartResponse { throw DevicePairingError.unavailable }
    public func status(_ id: DevicePairingID, token: String) async throws -> DevicePairingStatus { throw DevicePairingError.unavailable }
    public func cancel(_ id: DevicePairingID, token: String) async throws -> DevicePairingStatus { throw DevicePairingError.unavailable }
    public func pending() async throws -> [DevicePairingRequest] { throw DevicePairingError.unavailable }
    public func approve(_ id: DevicePairingID, _ approval: DevicePairingApproval) async throws -> DevicePairingApproveResponse { throw DevicePairingError.unavailable }
    public func deny(_ id: DevicePairingID, report: Bool) async throws { throw DevicePairingError.unavailable }
}

/// A scripted, recording fake for tests and previews. It plays the server's part honestly: it computes the code from the keys it was sent.
public actor MockDevicePairingAPI: DevicePairingAPI {
    public var invitation = DevicePairingInvitation(code: "ABCD-EFGH-JKMN", expiresAt: Date(timeIntervalSince1970: 1_800_000_600))
    public var inviteError: DevicePairingError?
    public var startError: DevicePairingError?
    public var approveErrors: [DevicePairingError] = []
    public var statuses: [DevicePairingState] = []
    public var statusDevice: Device?
    public var statusSession: AuthSession?
    /// Overrides the nonce the mock hands out (to simulate a server that lies about it).
    public var nonce = Base64URL.encode(Data(repeating: 7, count: 32))
    public var requests: [DevicePairingRequest] = []
    public private(set) var startRequests: [DevicePairingStartRequest] = []
    public private(set) var approvals: [DevicePairingApproval] = []
    public private(set) var denials: [(DevicePairingID, Bool)] = []
    public private(set) var cancels = 0
    public nonisolated let pairingId = DevicePairingID()
    public nonisolated let challenge = Base64URL.encode(Data(repeating: 3, count: 32))

    public init() {}

    public func set(startError: DevicePairingError?) { self.startError = startError }
    public func set(inviteError: DevicePairingError?) { self.inviteError = inviteError }
    public func set(approveErrors: [DevicePairingError]) { self.approveErrors = approveErrors }
    public func set(statuses: [DevicePairingState], device: Device? = nil, session: AuthSession? = nil) {
        self.statuses = statuses
        statusDevice = device
        statusSession = session
    }

    public func invite() async throws -> DevicePairingInvitation {
        if let inviteError { throw inviteError }
        return invitation
    }
    public func begin() async throws -> DevicePairingBeginResponse {
        DevicePairingBeginResponse(pairingId: pairingId, challenge: challenge, expiresAt: Date(timeIntervalSince1970: 1_800_000_300),
                                   integrity: IntegrityRequirement(required: [], accepted: [.appleAppAttest]))
    }
    public func start(_ id: DevicePairingID, _ request: DevicePairingStartRequest) async throws -> DevicePairingStartResponse {
        startRequests.append(request)
        if let startError { throw startError }
        return DevicePairingStartResponse(pairingId: id, nonce: nonce, expiresAt: Date(timeIntervalSince1970: 1_800_000_300), statusToken: "status-token")
    }
    public func status(_ id: DevicePairingID, token: String) async throws -> DevicePairingStatus {
        let state = statuses.isEmpty ? .pending : statuses.removeFirst()
        let final = state == .approved
        return DevicePairingStatus(pairingId: id, state: state, expiresAt: Date(timeIntervalSince1970: 1_800_000_300),
                                   device: final ? statusDevice : nil, session: final ? statusSession : nil)
    }
    public func cancel(_ id: DevicePairingID, token: String) async throws -> DevicePairingStatus {
        cancels += 1
        return DevicePairingStatus(pairingId: id, state: .cancelled, expiresAt: Date(timeIntervalSince1970: 1_800_000_300))
    }
    public func pending() async throws -> [DevicePairingRequest] { requests }
    public func approve(_ id: DevicePairingID, _ approval: DevicePairingApproval) async throws -> DevicePairingApproveResponse {
        approvals.append(approval)
        if !approveErrors.isEmpty { throw approveErrors.removeFirst() }
        let device = Device(id: DeviceID(), consumerId: approval.accountId, name: "New iPhone", platform: .iOS, keys: [], createdAt: approval.signedAt)
        return DevicePairingApproveResponse(pairingId: id, state: .approved, device: device)
    }
    public func deny(_ id: DevicePairingID, report: Bool) async throws { denials.append((id, report)) }
}
