import Foundation
import ViadereCore

/// The consumer side of Verify (`/v1/verifications/...`). Separate from `ViadereAPI` so only the screens that verify depend on it.
public protocol VerifyAPI: Sendable {
    func list() async throws -> VerificationListResponse
    func prompt(_ id: VerificationRequestID) async throws -> VerificationPrompt
    func consent(_ id: VerificationRequestID, displayDigest: String) async throws -> VerificationPrompt
    func decline(_ id: VerificationRequestID) async throws
    func revoke(_ id: VerificationRequestID) async throws -> VerificationHistoryItem
    func beginWallet(_ id: VerificationRequestID) async throws -> WalletAttemptStart
    func completeWallet(_ id: VerificationRequestID, attemptId: UUID, envelope: Data) async throws -> VerificationAttemptOutcome
    func beginDocument(_ id: VerificationRequestID) async throws -> DocumentAttemptStart
    func completeDocument(_ id: VerificationRequestID, attemptId: UUID) async throws -> VerificationAttemptOutcome
}

/// `VerifyAPI` over HTTP through the app's signed `APIClient`.
public struct LiveVerifyAPI: VerifyAPI {
    private let client: APIClient
    public init(client: APIClient) { self.client = client }

    private func params(_ id: VerificationRequestID) -> [String: String] { ["requestId": id.description] }

    public func list() async throws -> VerificationListResponse { try await client.call(APIRoutes.verificationsList) }
    public func prompt(_ id: VerificationRequestID) async throws -> VerificationPrompt { try await client.call(APIRoutes.verificationGet, params: params(id)) }
    public func consent(_ id: VerificationRequestID, displayDigest: String) async throws -> VerificationPrompt {
        try await client.call(APIRoutes.verificationConsent, params: params(id), body: VerificationConsentRequest(displayDigest: displayDigest))
    }
    public func decline(_ id: VerificationRequestID) async throws { _ = try await client.call(APIRoutes.verificationDecline, params: params(id)) }
    public func revoke(_ id: VerificationRequestID) async throws -> VerificationHistoryItem { try await client.call(APIRoutes.verificationRevoke, params: params(id)) }
    public func beginWallet(_ id: VerificationRequestID) async throws -> WalletAttemptStart { try await client.call(APIRoutes.verificationWalletBegin, params: params(id)) }
    public func completeWallet(_ id: VerificationRequestID, attemptId: UUID, envelope: Data) async throws -> VerificationAttemptOutcome {
        try await client.call(APIRoutes.verificationWalletComplete, params: params(id), body: WalletAttemptComplete(attemptId: attemptId, envelope: Base64URL.encode(envelope)))
    }
    public func beginDocument(_ id: VerificationRequestID) async throws -> DocumentAttemptStart { try await client.call(APIRoutes.verificationDocumentBegin, params: params(id)) }
    public func completeDocument(_ id: VerificationRequestID, attemptId: UUID) async throws -> VerificationAttemptOutcome {
        try await client.call(APIRoutes.verificationDocumentComplete, params: params(id), body: DocumentAttemptComplete(attemptId: attemptId))
    }
}

extension LiveVerifyAPI {
    /// A Verify client that shares the app's session, device keys and certificate pinning (`ViadereServices`).
    public static func make(services: ViadereServices) -> LiveVerifyAPI {
        let transport = URLSessionTransport(configuration: services.configuration)
        let signer = DeviceRequestSigner(records: services.records, keys: services.keys, clock: services.clock)
        let executor = RequestExecutor(baseURL: services.configuration.apiBaseURL, transport: transport, signer: signer)
        let revocation = services.revocation
        return LiveVerifyAPI(client: APIClient(executor: executor, sessions: services.sessions, onDeviceRejected: { revocation.notify() }))
    }
}
