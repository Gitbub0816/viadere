import Crypto
import Foundation

/// The Verify endpoints (spec §14.1). Business routes are authorized by **capability** (`age.minimum`, `identity.*`), not by an
/// operational scope: a messaging key cannot reach them (acceptance 1). Consumer routes are device-signed.
extension APIRoutes {
    // MARK: Business

    /// Creates a verification request for a connected customer (`subject_ref`). Idempotent (`Idempotency-Key`).
    public static let verificationRequestCreate = Endpoint<CreateVerificationRequest, VerificationRequestResource>(
        "business.verification.requests.create", .POST, "/v1/verification-requests", auth: .businessAPIKey)
    public static let verificationRequestGet = Endpoint<EmptyBody, VerificationRequestResource>(
        "business.verification.requests.get", .GET, "/v1/verification-requests/{requestId}", auth: .businessAPIKey)
    /// Authenticated, recipient-bound, single-use retrieval of a result (`result_ref` from the `verification.completed` webhook).
    public static let verificationResultGet = Endpoint<EmptyBody, VerificationResult>(
        "business.verification.results.get", .GET, "/v1/verification-results/{resultRef}", auth: .businessAPIKey)

    // MARK: Consumer (app)

    public static let verificationsList = Endpoint<EmptyBody, VerificationListResponse>(
        "verifications.list", .GET, "/v1/verifications", auth: .deviceSignedBearer)
    public static let verificationGet = Endpoint<EmptyBody, VerificationPrompt>(
        "verifications.get", .GET, "/v1/verifications/{requestId}", auth: .deviceSignedBearer)
    /// Granular consent for exactly this disclosure: creates the `DisclosureReceipt`. The body must quote the prompt's `displayDigest`.
    public static let verificationConsent = Endpoint<VerificationConsentRequest, VerificationPrompt>(
        "verifications.consent", .POST, "/v1/verifications/{requestId}/consent", auth: .deviceSignedBearer)
    public static let verificationDecline = Endpoint<EmptyBody, EmptyBody>(
        "verifications.decline", .POST, "/v1/verifications/{requestId}/decline", auth: .deviceSignedBearer)
    /// Withdraws a receipt that has not been used yet.
    public static let verificationRevoke = Endpoint<EmptyBody, VerificationHistoryItem>(
        "verifications.revoke", .POST, "/v1/verifications/{requestId}/revoke", auth: .deviceSignedBearer)
    public static let verificationWalletBegin = Endpoint<EmptyBody, WalletAttemptStart>(
        "verifications.wallet.begin", .POST, "/v1/verifications/{requestId}/wallet/begin", auth: .deviceSignedBearer)
    public static let verificationWalletComplete = Endpoint<WalletAttemptComplete, VerificationAttemptOutcome>(
        "verifications.wallet.complete", .POST, "/v1/verifications/{requestId}/wallet/complete", auth: .deviceSignedBearer)
    public static let verificationDocumentBegin = Endpoint<EmptyBody, DocumentAttemptStart>(
        "verifications.document.begin", .POST, "/v1/verifications/{requestId}/document/begin", auth: .deviceSignedBearer)
    public static let verificationDocumentComplete = Endpoint<DocumentAttemptComplete, VerificationAttemptOutcome>(
        "verifications.document.complete", .POST, "/v1/verifications/{requestId}/document/complete", auth: .deviceSignedBearer)

    // MARK: Provider

    /// Didit `status.updated` webhook, authenticated by `X-Signature-V2` / `X-Signature` plus `X-Timestamp`.
    public static let providerDiditWebhook = Endpoint<Data, EmptyBody>(
        "providers.didit.webhook", .POST, "/v1/providers/didit/webhook", auth: .providerSignature)

    /// Every Verify endpoint (appended to `APIRoutes.all`).
    public static let verifyEndpoints: [AnyEndpoint] = [
        verificationRequestCreate.descriptor, verificationRequestGet.descriptor, verificationResultGet.descriptor,
        verificationsList.descriptor, verificationGet.descriptor, verificationConsent.descriptor, verificationDecline.descriptor,
        verificationRevoke.descriptor, verificationWalletBegin.descriptor, verificationWalletComplete.descriptor,
        verificationDocumentBegin.descriptor, verificationDocumentComplete.descriptor, providerDiditWebhook.descriptor,
    ]
}

extension VerificationPrompt {
    /// The digest of what the prompt displays, over canonical JSON of exactly: request, recipient (id and name), capability, parameters,
    /// purpose, the disclosed fields and the expiry. Consent quotes it; the server recomputes it from its own record, so consent can only
    /// be given to what the server will release.
    public static func displayDigest(requestId: VerificationRequestID, businessId: BusinessID, recipientName: String, capability: Capability,
                                     parameters: [String: JSONValue], purposeCode: String, fields: [String], expiresAt: Date) -> String {
        let value: JSONValue = .object([
            "v": .integer(1),
            "requestId": .string(requestId.description),
            "businessId": .string(businessId.description),
            "recipient": .string(recipientName),
            "capability": .string(capability.rawValue),
            "parameters": .object(parameters),
            "purpose": .string(purposeCode),
            "fields": .array(fields.sorted().map(JSONValue.string)),
            "expiresAt": .string(ViadereDate.format(ViadereDate.truncatedToMilliseconds(expiresAt))),
        ])
        let bytes = (try? CanonicalJSON.serialize(value)) ?? Data()
        return "sha256:" + Hex.encode(SHA256.hash(data: Data("VIADERE-VERIFY-CONSENT-V1\n".utf8) + bytes))
    }
}
