import Foundation

/// Customer profiles with selective sharing (docs/PROFILES.md; SECURITY.md §2.97). Customer routes are device-signed and always act on the
/// authenticated account; a `{businessId}` is checked against the caller's own connections (`404` otherwise). Business routes need scope
/// `profiles:read` and the category entitlement of every field involved.
extension APIRoutes {
    public static let profileGet = Endpoint<EmptyBody, CustomerProfile>(
        "profile.get", .GET, "/v1/profile", auth: .deviceSignedBearer)
    public static let profilePut = Endpoint<ProfileUpdateRequest, CustomerProfile>(
        "profile.put", .PUT, "/v1/profile", auth: .deviceSignedBearer)
    public static let profileAccessGet = Endpoint<EmptyBody, ProfileAccessView>(
        "profile.access.get", .GET, "/v1/businesses/{businessId}/profile-access", auth: .deviceSignedBearer)
    /// Replaces the set of granted keys for that business (empty = revoke all). Revocation takes effect on the business's next read.
    public static let profileAccessPut = Endpoint<ProfileAccessUpdate, ProfileAccessView>(
        "profile.access.put", .PUT, "/v1/businesses/{businessId}/profile-access", auth: .deviceSignedBearer)
    /// Query: `status=pending` (default all, newest first, ≤ 50).
    public static let profileRequestsList = Endpoint<EmptyBody, [ProfileRequestPrompt]>(
        "profile.requests.list", .GET, "/v1/profile/requests", auth: .deviceSignedBearer)
    public static let profileRequestGet = Endpoint<EmptyBody, ProfileRequestPrompt>(
        "profile.requests.get", .GET, "/v1/profile/requests/{requestId}", auth: .deviceSignedBearer)
    public static let profileRequestAnswer = Endpoint<ProfileRequestAnswer, ProfileRequestPrompt>(
        "profile.requests.answer", .POST, "/v1/profile/requests/{requestId}/answer", auth: .deviceSignedBearer)
    public static let profileReceiptsList = Endpoint<EmptyBody, [ProfileDisclosureReceipt]>(
        "profile.receipts.list", .GET, "/v1/profile/receipts", auth: .deviceSignedBearer)
    /// Behind the Verify release gate (`404` while `VERIFY_ENABLED` is off).
    public static let profileVerificationBegin = Endpoint<ProfileVerificationBegin, ProfileVerificationStart>(
        "profile.verification.begin", .POST, "/v1/profile/verification", auth: .deviceSignedBearer)
    public static let profileVerificationComplete = Endpoint<ProfileVerificationComplete, ProfileVerificationOutcome>(
        "profile.verification.complete", .POST, "/v1/profile/verification/{attemptId}/complete", auth: .deviceSignedBearer)
    public static let profileVerificationRemove = Endpoint<ProfileVerifiedFactsRemove, CustomerProfile>(
        "profile.verification.remove", .POST, "/v1/profile/verification/remove", auth: .deviceSignedBearer)

    /// Business: ask a connected customer for fields, with a stated purpose. Requires `Idempotency-Key`.
    public static let businessProfileRequestCreate = Endpoint<CreateProfileRequest, ProfileRequestResource>(
        "business.profileRequests.create", .POST, "/v1/business/profile-requests", auth: .businessAPIKey)
    public static let businessProfileRequestGet = Endpoint<EmptyBody, ProfileRequestResource>(
        "business.profileRequests.get", .GET, "/v1/business/profile-requests/{requestId}", auth: .businessAPIKey)
    /// Business: the public name and the currently granted fields of one of its customers.
    public static let businessProfileGet = Endpoint<EmptyBody, BusinessProfileView>(
        "business.profiles.get", .GET, "/v1/business/profiles/{subjectRef}", auth: .businessAPIKey)

    /// Appended to `APIRoutes.all`.
    public static let profileEndpoints: [AnyEndpoint] = [
        profileGet.descriptor, profilePut.descriptor, profileAccessGet.descriptor, profileAccessPut.descriptor, profileRequestsList.descriptor,
        profileRequestGet.descriptor, profileRequestAnswer.descriptor, profileReceiptsList.descriptor, profileVerificationBegin.descriptor,
        profileVerificationComplete.descriptor, profileVerificationRemove.descriptor,
        businessProfileRequestCreate.descriptor, businessProfileRequestGet.descriptor, businessProfileGet.descriptor,
    ]
}
