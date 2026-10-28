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
    /// The digest of **what the prompt displays**, computed from the fields themselves (version 2): the request, the recipient exactly as
    /// shown (id, name, handle, whether it is shown as verified), the capability and parameters, the purpose, every disclosure line (field,
    /// title and detail text), every "not disclosed" line, the metadata lines and the expiry.
    ///
    /// The **app** computes this from the prompt it is about to render and quotes the result when the person consents; the server computes
    /// it from its own record and compares. Nothing in the app echoes a digest the server supplied, so consent is bound to the text the
    /// person actually saw: a prompt whose displayed text was altered on the way (or differs from what the server will release) yields a
    /// digest the server does not hold, and the consent is refused. `displayDigest` and `methods`/`status` are not part of it.
    public func renderedDigest() -> String {
        let value: JSONValue = .object([
            "v": .integer(2),
            "requestId": .string(id.description),
            "businessId": .string(businessId.description),
            "recipient": .object([
                "name": .string(recipientName),
                "handle": recipientHandle.map(JSONValue.string) ?? .null,
                "verified": .bool(recipientVerified),
            ]),
            "capability": .string(capability.rawValue),
            "parameters": .object(parameters),
            "purpose": .string(purposeCode),
            "disclosure": .array(disclosure.map { .object(["field": .string($0.field), "title": .string($0.title), "detail": .string($0.detail)]) }),
            "notDisclosed": .array(notDisclosed.map(JSONValue.string)),
            "metadata": .array(includedMetadata.map(JSONValue.string)),
            "expiresAt": .string(ViadereDate.format(ViadereDate.truncatedToMilliseconds(expiresAt))),
        ])
        let bytes = (try? CanonicalJSON.serialize(value)) ?? Data()
        return "sha256:" + Hex.encode(SHA256.hash(data: Data("VIADERE-VERIFY-CONSENT-V2\n".utf8) + bytes))
    }

    /// This prompt with `displayDigest` set to `renderedDigest()` (what a server sends).
    public func withRenderedDigest() -> VerificationPrompt {
        var copy = self
        copy.displayDigest = renderedDigest()
        return copy
    }
}
