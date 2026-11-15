import Foundation
import ViadereCore

/// Result of creating a verification request.
public struct CreatedVerificationRequest: Sendable, Equatable {
    public var request: VerificationRequestResource
    /// `false` when the idempotency key was already used and the original request was returned.
    public var wasCreated: Bool
}

extension ViadereBusinessClient {
    private func decodeVerify<T: Decodable>(_ type: T.Type, _ response: BusinessHTTPResponse) throws -> T {
        do { return try ViadereJSON.decode(type, from: response.body) } catch { throw ViadereSDKError.decodingFailed(String(describing: T.self)) }
    }

    /// Asks a connected customer to verify something (`POST /v1/verification-requests`). Needs the capability (`age.minimum`, `identity.name`,
    /// `identity.address` or `identity.verified`) on **both** the key and your business's entitlements. The customer is shown who you are,
    /// the purpose, exactly what will be shared and the expiry, and decides. `callbackId` is the id of one of your **registered** webhook
    /// endpoints (subscribed to `verification.completed`), never a URL. Idempotent on `idempotencyKey`.
    public func createVerificationRequest(_ request: CreateVerificationRequest, idempotencyKey: String = IdempotencyKey.generate(prefix: "verify")) async throws -> CreatedVerificationRequest {
        let response = try await perform(APIRoutes.verificationRequestCreate.descriptor, body: request, idempotencyKey: idempotencyKey)
        return CreatedVerificationRequest(request: try decodeVerify(VerificationRequestResource.self, response), wasCreated: response.status == 201)
    }

    /// The state of one of your requests: `pending`, or `completed` with a `resultRef`.
    public func verificationRequest(id: VerificationRequestID) async throws -> VerificationRequestResource {
        try decodeVerify(VerificationRequestResource.self, try await perform(APIRoutes.verificationRequestGet.descriptor, parameters: ["requestId": id.description]))
    }

    /// Retrieves a result **once** (`GET /v1/verification-results/{result_ref}`). The reference comes from the `verification.completed` webhook
    /// or from `verificationRequest(id:)`. The result is bound to your business and the request, expires after a short validity, and a second
    /// retrieval answers `410`. `outcome` is `verified` or `not_verified`; `not_verified` never says why (an underage customer, a customer who
    /// declined and a failed check look the same). Store what you need from it: it cannot be fetched again.
    public func verificationResult(ref: VerificationResultRef) async throws -> VerificationResult {
        try decodeVerify(VerificationResult.self, try await perform(APIRoutes.verificationResultGet.descriptor, parameters: ["resultRef": ref.rawValue]))
    }
}
