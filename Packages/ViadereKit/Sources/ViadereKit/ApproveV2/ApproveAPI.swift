import Foundation
import ViadereCore

/// The Approve v2 calls (`/v1/approve/...`) and the public key directory. Separate from `ViadereAPI` so extensions and the App Clip, which
/// never hold approval keys, build without any of it.
public protocol ApproveAPI: Sendable {
    func lookupEnrollment(code: String) async throws -> ApproveEnrollmentPreview
    func completeEnrollment(id: UUID, statement: SignedStatement, bindingTag: String?) async throws -> ApproveKey
    func keys() async throws -> [ApproveKey]
    func revokeKey(kid: String) async throws -> ApproveKey
    func requests() async throws -> [ApproveDeviceRequest]
    func request(id: UUID) async throws -> ApproveDeviceRequest
    func submitResult(id: UUID, result: String) async throws -> SubmitApprovalResultResponse
    func freezeState() async throws -> ApproveFreezeState
    func setFreeze(_ request: ApproveFreezeRequest) async throws -> ApproveFreezeState
    /// `GET /v1/key-directory/businesses/{id}?since=`: public; the caller verifies everything in it.
    func keyDirectory(businessId: BusinessID, since: Int?) async throws -> KeyDirectoryResponse
    /// The result with an App Attest assertion over it (WP-C2). Default: without one.
    func submitResult(id: UUID, result: String, appAttestAssertion: String?) async throws -> SubmitApprovalResultResponse
}

extension ApproveAPI {
    public func submitResult(id: UUID, result: String, appAttestAssertion: String?) async throws -> SubmitApprovalResultResponse {
        try await submitResult(id: id, result: result)
    }
}

/// `ApproveAPI` over HTTP through the app's signed `APIClient`.
public struct LiveApproveAPI: ApproveAPI {
    let client: APIClient
    public init(client: APIClient) { self.client = client }

    public func lookupEnrollment(code: String) async throws -> ApproveEnrollmentPreview {
        try await client.call(APIRoutes.approveEnrollmentLookup, body: ApproveEnrollmentLookupRequest(code: code))
    }
    public func completeEnrollment(id: UUID, statement: SignedStatement, bindingTag: String?) async throws -> ApproveKey {
        // The binding tag is what lets the business tell this phone's statement from a forged one (§2.53): it must reach the relay.
        try await client.call(APIRoutes.approveEnrollmentComplete, params: ["enrollmentId": id.uuidString.lowercased()],
                              body: CompleteApproveEnrollmentRequest(statement: statement, bindingTag: bindingTag))
    }
    public func keys() async throws -> [ApproveKey] { try await client.call(APIRoutes.approveKeys) }
    public func revokeKey(kid: String) async throws -> ApproveKey { try await client.call(APIRoutes.approveKeyRevoke, params: ["kid": kid]) }
    public func requests() async throws -> [ApproveDeviceRequest] { try await client.call(APIRoutes.approveRequests) }
    public func request(id: UUID) async throws -> ApproveDeviceRequest { try await client.call(APIRoutes.approveRequestGet, params: ["approvalId": id.uuidString.lowercased()]) }
    public func submitResult(id: UUID, result: String) async throws -> SubmitApprovalResultResponse {
        try await submitResult(id: id, result: result, appAttestAssertion: nil)
    }
    public func submitResult(id: UUID, result: String, appAttestAssertion: String?) async throws -> SubmitApprovalResultResponse {
        try await client.call(APIRoutes.approveRequestResult, params: ["approvalId": id.uuidString.lowercased()],
                              body: SubmitApprovalResultRequest(result: result, appAttestAssertion: appAttestAssertion))
    }
    public func freezeState() async throws -> ApproveFreezeState { try await client.call(APIRoutes.approveFreezeGet) }
    public func setFreeze(_ request: ApproveFreezeRequest) async throws -> ApproveFreezeState { try await client.call(APIRoutes.approveFreezeSet, body: request) }
    public func keyDirectory(businessId: BusinessID, since: Int?) async throws -> KeyDirectoryResponse {
        try await client.call(APIRoutes.keyDirectoryBusiness, params: ["businessId": businessId.description], query: since.map { [("since", String($0))] } ?? [])
    }
}

extension LiveApproveAPI {
    /// An Approve client that shares the app's session, device keys and certificate pinning. Never used by extensions or the App Clip.
    public static func make(services: ViadereServices) -> LiveApproveAPI {
        let transport = URLSessionTransport(configuration: services.configuration)
        let signer = DeviceRequestSigner(records: services.records, keys: services.keys, clock: services.clock)
        let executor = RequestExecutor(baseURL: services.configuration.apiBaseURL, transport: transport, signer: signer)
        let revocation = services.revocation
        return LiveApproveAPI(client: APIClient(executor: executor, sessions: services.sessions, onDeviceRejected: { revocation.notify() }))
    }
}
