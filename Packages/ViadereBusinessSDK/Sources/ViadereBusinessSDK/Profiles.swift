import Foundation
import ViadereCore

/// Result of creating a profile request.
public struct CreatedProfileRequest: Sendable, Equatable {
    public var request: ProfileRequestResource
    /// `false` when the idempotency key was already used and the original request was returned.
    public var wasCreated: Bool
}

/// Customer profiles (docs/PROFILES.md). Every call needs a key with scope `profiles:read`. You can only ask for (and read) fields whose
/// category Viadere allowed your organization; nothing is allowed by default (ask in the console under Organization > Customer profile
/// access). Each customer then decides field by field and can revoke at any time; a revocation takes effect on your next read and is
/// announced with a `profile.access_revoked` webhook (keys only).
extension ViadereBusinessClient {
    /// Asks a connected customer for profile fields (`POST /v1/business/profile-requests`). `purpose` is shown to the customer as written and
    /// must pass the display-text rules. A field outside your allowed categories is `403 not_entitled`. Idempotent on `idempotencyKey`.
    public func createProfileRequest(_ request: CreateProfileRequest, idempotencyKey: String = IdempotencyKey.generate(prefix: "profile")) async throws -> CreatedProfileRequest {
        let response = try await perform(APIRoutes.businessProfileRequestCreate.descriptor, body: request, idempotencyKey: idempotencyKey)
        return CreatedProfileRequest(request: try decode(ProfileRequestResource.self, response), wasCreated: response.status == 201)
    }

    /// One of your requests: `pending`, `answered` (with the approved keys, possibly fewer than asked), `declined`, `expired` or `cancelled`.
    public func profileRequest(id: ProfileRequestID) async throws -> ProfileRequestResource {
        try decode(ProfileRequestResource.self, try await perform(APIRoutes.businessProfileRequestGet.descriptor, parameters: ["requestId": id.description]))
    }

    /// The customer's public name and the fields they currently grant you (`GET /v1/business/profiles/{subjectRef}`). Do not cache beyond your
    /// own need: what the customer revokes disappears from the next response.
    public func profile(subjectRef: SubjectRef) async throws -> BusinessProfileView {
        try decode(BusinessProfileView.self, try await perform(APIRoutes.businessProfileGet.descriptor, parameters: ["subjectRef": subjectRef.rawValue]))
    }
}
