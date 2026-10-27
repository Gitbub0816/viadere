import Foundation

/// The identifier of a verification request: `req_` plus 22 base64url characters (a random 128-bit value). Opaque to businesses
/// (spec §14.3 `request_id`).
public struct VerificationRequestID: Hashable, Sendable, Codable, CustomStringConvertible, LosslessStringConvertible {
    public static let prefix = "req_"
    public let uuid: UUID

    public init(_ uuid: UUID) { self.uuid = uuid }
    public init() { uuid = UUID() }

    public init?(_ string: String) {
        guard string.hasPrefix(Self.prefix), string.count == Self.prefix.count + 22,
              let bytes = Base64URL.decode(String(string.dropFirst(Self.prefix.count))), bytes.count == 16 else { return nil }
        let b = Array(bytes)
        uuid = UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]))
    }

    public var description: String {
        let u = uuid.uuid
        return Self.prefix + Base64URL.encode(Data([u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]))
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        guard let value = Self(try container.decode(String.self)) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid request id")
        }
        self = value
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

/// The opaque reference of a result (`res_` plus 43 base64url characters, 256 random bits). Retrieval is authenticated and bound to the
/// business that owns the request; the reference alone retrieves nothing.
public struct VerificationResultRef: Hashable, Sendable, Codable, CustomStringConvertible, LosslessStringConvertible {
    public static let prefix = "res_"
    public let rawValue: String

    public init?(_ string: String) {
        guard string.hasPrefix(Self.prefix), Base64URL.isValid(String(string.dropFirst(Self.prefix.count)), minLength: 43, maxLength: 43) else { return nil }
        rawValue = string
    }

    public static func generate() -> VerificationResultRef { VerificationResultRef(prefix + Base64URL.encode(SecureToken.randomBytes(32)))! }
    public var description: String { rawValue }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        guard let value = Self(try container.decode(String.self)) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid result reference")
        }
        self = value
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

// MARK: - Business API (`/v1/verification-requests`, spec §14.1, snake_case on the wire)

/// `POST /v1/verification-requests`. `callback_id` names a **registered** webhook endpoint of the business; a URL in the body is never
/// accepted (the field is an identifier and anything that is not one is refused).
public struct CreateVerificationRequest: Codable, Sendable, Hashable {
    public var subjectRef: SubjectRef
    public var capability: Capability
    public var parameters: [String: JSONValue]?
    public var purposeCode: String
    public var callbackId: String?
    public var expiresInSeconds: Int?

    public init(subjectRef: SubjectRef, capability: Capability, parameters: [String: JSONValue]? = nil, purposeCode: String, callbackId: String? = nil,
                expiresInSeconds: Int? = nil) {
        self.subjectRef = subjectRef
        self.capability = capability
        self.parameters = parameters
        self.purposeCode = purposeCode
        self.callbackId = callbackId
        self.expiresInSeconds = expiresInSeconds
    }

    enum CodingKeys: String, CodingKey {
        case subjectRef = "subject_ref", capability, parameters, purposeCode = "purpose_code", callbackId = "callback_id", expiresInSeconds = "expires_in_seconds"
    }
}

/// What a business may learn about a request. Pending, or finished: a result exists (`result_ref`) and says `verified` or `not_verified`.
/// There is no "declined", "underage", "expired" or "failed" here: a denial never reveals whether the person is under the threshold, unable
/// or unwilling (AGE-005).
public enum BusinessVerificationStatus: String, Sendable, Codable, Hashable, CaseIterable {
    case pending
    case completed
}

public struct VerificationRequestResource: Codable, Sendable, Hashable {
    public var requestId: VerificationRequestID
    public var capability: Capability
    public var subjectRef: SubjectRef
    public var purposeCode: String
    public var status: BusinessVerificationStatus
    public var createdAt: Date
    public var expiresAt: Date
    /// Present once the request is `completed`.
    public var resultRef: VerificationResultRef?

    public init(requestId: VerificationRequestID, capability: Capability, subjectRef: SubjectRef, purposeCode: String, status: BusinessVerificationStatus,
                createdAt: Date, expiresAt: Date, resultRef: VerificationResultRef? = nil) {
        self.requestId = requestId
        self.capability = capability
        self.subjectRef = subjectRef
        self.purposeCode = purposeCode
        self.status = status
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.resultRef = resultRef
    }

    enum CodingKeys: String, CodingKey {
        case requestId = "request_id", capability, subjectRef = "subject_ref", purposeCode = "purpose_code", status, createdAt = "created_at",
             expiresAt = "expires_at", resultRef = "result_ref"
    }
}

public enum VerificationOutcome: String, Sendable, Codable, Hashable, CaseIterable {
    case verified
    /// Everything else: below the threshold, declined, abandoned, expired, unsupported document, provider outage. One value (AGE-005).
    case notVerified = "not_verified"
}

/// `GET /v1/verification-results/{result_ref}`: single use, audience-bound, expiring (AGE-004). `result` holds the capability's output
/// fields (acceptance 6) and is empty for `not_verified`.
///
/// **End-to-end encrypted identity attributes.** When the business has published an `hpke-encryption` key in the authenticated key
/// directory, the personal-data fields of `identity.name` / `identity.address` are not in `result`: they are in `encrypted_result`, an
/// `E2EEEnvelope` (RFC 9180 HPKE, purpose `verify.result`, bound to this request, to Viadere as sender and to the business as recipient)
/// that only the business's private key opens, so a database compromise at Viadere reveals none of them. `result` then carries the
/// non-personal fields (assurance, validity, audience) and `encrypted_result_kid` names the key.
public struct VerificationResult: Codable, Sendable, Hashable {
    public var resultRef: VerificationResultRef
    public var requestId: VerificationRequestID
    public var capability: Capability
    public var subjectRef: SubjectRef
    public var parameters: [String: JSONValue]
    public var createdAt: Date
    public var outcome: VerificationOutcome
    public var result: [String: JSONValue]
    /// Base64url `E2EEEnvelope` holding the personal-data fields, when the business has a published encryption key.
    public var encryptedResult: String?
    public var encryptedResultKid: String?

    public init(resultRef: VerificationResultRef, requestId: VerificationRequestID, capability: Capability, subjectRef: SubjectRef,
                parameters: [String: JSONValue], createdAt: Date, outcome: VerificationOutcome, result: [String: JSONValue],
                encryptedResult: String? = nil, encryptedResultKid: String? = nil) {
        self.resultRef = resultRef
        self.requestId = requestId
        self.capability = capability
        self.subjectRef = subjectRef
        self.parameters = parameters
        self.createdAt = createdAt
        self.outcome = outcome
        self.result = result
        self.encryptedResult = encryptedResult
        self.encryptedResultKid = encryptedResultKid
    }

    enum CodingKeys: String, CodingKey {
        case resultRef = "result_ref", requestId = "request_id", capability, subjectRef = "subject_ref", parameters, createdAt = "created_at", outcome, result,
             encryptedResult = "encrypted_result", encryptedResultKid = "encrypted_result_kid"
    }

    /// The top-level members of a result response: the shared envelope (`CapabilityCatalog.resultEnvelopeFields`) plus the reference, the
    /// outcome and the optional encrypted part.
    public static let topLevelFields: Set<String> = Set(CapabilityCatalog.resultEnvelopeFields).union(["result_ref", "outcome", "result", "encrypted_result", "encrypted_result_kid"])

    /// The E2EE purpose and the sender name of an encrypted result.
    public static let e2eePurpose = "verify.result"
    public static let e2eeSender = "viadere"
    public static func e2eeRecipient(_ businessId: BusinessID) -> String { "biz_" + businessId.description }
}

/// Data of the `verification.completed` webhook. Opaque: it names the request and the result and nothing else (spec §14.3). The result
/// itself is fetched through the authenticated, recipient-bound retrieval.
public struct VerificationCompletedEventData: Codable, Sendable, Hashable {
    public var requestId: VerificationRequestID
    public var resultRef: VerificationResultRef
    public init(requestId: VerificationRequestID, resultRef: VerificationResultRef) {
        self.requestId = requestId
        self.resultRef = resultRef
    }
    enum CodingKeys: String, CodingKey { case requestId = "request_id", resultRef = "result_ref" }
}

extension WebhookEventType {
    public static let verificationCompleted = WebhookEventType(rawValue: "verification.completed")
}

// MARK: - Consumer API (the app; camelCase like the rest of the consumer API)

/// The consumer-side state of a request (the person's own view: it does name declined and expired).
public enum ConsumerVerificationStatus: String, Sendable, Codable, Hashable, CaseIterable {
    /// Waiting for the person to review and consent.
    case pendingConsent = "pending_consent"
    /// Consent given; the person has not finished a verification yet.
    case consented
    /// Finished and released to the business as verified.
    case released
    /// Finished and released to the business as not verified (the person is not told more than the business is).
    case notVerified = "not_verified"
    case declined
    case expired
    case cancelled
    /// The person withdrew consent before the disclosure.
    case revoked

    public var isOpen: Bool { self == .pendingConsent || self == .consented }
}

/// How a person can verify.
public enum VerificationMethodKind: String, Sendable, Codable, Hashable, CaseIterable {
    case wallet
    case document
}

public struct VerificationMethodOption: Codable, Sendable, Hashable {
    public var kind: VerificationMethodKind
    /// The server offers the method for this request right now (configured, not killed).
    public var available: Bool
    public init(kind: VerificationMethodKind, available: Bool) {
        self.kind = kind
        self.available = available
    }
}

/// One line of "exactly what will be disclosed".
public struct VerificationDisclosureItem: Codable, Sendable, Hashable, Identifiable {
    public var id: String { field }
    public var field: String
    public var title: String
    public var detail: String
    public init(field: String, title: String, detail: String) {
        self.field = field
        self.title = title
        self.detail = detail
    }
}

/// Everything the person sees before consenting (spec §6.4): the verified business, the purpose, exactly what is disclosed, the
/// recipient and the expiry.
public struct VerificationPrompt: Codable, Sendable, Hashable, Identifiable {
    public var id: VerificationRequestID
    public var status: ConsumerVerificationStatus
    public var businessId: BusinessID
    /// The recipient exactly as the person is shown it and as the receipt records it.
    public var recipientName: String
    public var recipientHandle: String?
    public var recipientVerified: Bool
    public var capability: Capability
    public var parameters: [String: JSONValue]
    public var purposeCode: String
    /// What is disclosed: the claim fields only.
    public var disclosure: [VerificationDisclosureItem]
    /// What is **not** disclosed, stated plainly (no birthdate, no name, no document number for an age threshold).
    public var notDisclosed: [String]
    /// The validity metadata that travels with the claim.
    public var includedMetadata: [String]
    public var methods: [VerificationMethodOption]
    public var createdAt: Date
    public var expiresAt: Date
    /// SHA-256 over what this prompt displays (`displayDigest(...)`): consent must quote it, so the person consents to exactly this.
    public var displayDigest: String
    public var receiptId: UUID?

    public init(id: VerificationRequestID, status: ConsumerVerificationStatus, businessId: BusinessID, recipientName: String, recipientHandle: String?,
                recipientVerified: Bool, capability: Capability, parameters: [String: JSONValue], purposeCode: String, disclosure: [VerificationDisclosureItem],
                notDisclosed: [String], includedMetadata: [String], methods: [VerificationMethodOption], createdAt: Date, expiresAt: Date,
                displayDigest: String, receiptId: UUID? = nil) {
        self.id = id
        self.status = status
        self.businessId = businessId
        self.recipientName = recipientName
        self.recipientHandle = recipientHandle
        self.recipientVerified = recipientVerified
        self.capability = capability
        self.parameters = parameters
        self.purposeCode = purposeCode
        self.disclosure = disclosure
        self.notDisclosed = notDisclosed
        self.includedMetadata = includedMetadata
        self.methods = methods
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.displayDigest = displayDigest
        self.receiptId = receiptId
    }
}

/// One entry of the verification history (Settings).
public struct VerificationHistoryItem: Codable, Sendable, Hashable, Identifiable {
    public var id: VerificationRequestID
    public var recipientName: String
    public var capability: Capability
    public var purposeCode: String
    public var status: ConsumerVerificationStatus
    public var requestedAt: Date
    public var decidedAt: Date?
    public var receiptId: UUID?
    /// The receipt can still be withdrawn (consent given, nothing disclosed yet).
    public var revocable: Bool
    /// What was disclosed (field names), once released.
    public var disclosedFields: [String]
    /// The label of the evidence that backed it, once released.
    public var label: VerificationLabel?

    public init(id: VerificationRequestID, recipientName: String, capability: Capability, purposeCode: String, status: ConsumerVerificationStatus, requestedAt: Date,
                decidedAt: Date?, receiptId: UUID?, revocable: Bool, disclosedFields: [String], label: VerificationLabel?) {
        self.id = id
        self.recipientName = recipientName
        self.capability = capability
        self.purposeCode = purposeCode
        self.status = status
        self.requestedAt = requestedAt
        self.decidedAt = decidedAt
        self.receiptId = receiptId
        self.revocable = revocable
        self.disclosedFields = disclosedFields
        self.label = label
    }
}

public struct VerificationListResponse: Codable, Sendable, Hashable {
    public var pending: [VerificationPrompt]
    public var history: [VerificationHistoryItem]
    public init(pending: [VerificationPrompt], history: [VerificationHistoryItem]) {
        self.pending = pending
        self.history = history
    }
}

public struct VerificationConsentRequest: Codable, Sendable, Hashable {
    /// `VerificationPrompt.displayDigest` of the prompt the person saw.
    public var displayDigest: String
    public init(displayDigest: String) { self.displayDigest = displayDigest }
}

public struct WalletAttemptStart: Codable, Sendable, Hashable {
    public var attemptId: UUID
    /// Single-use, base64url. Goes into `PKIdentityRequest.nonce` as the raw bytes.
    public var nonce: String
    public var merchantIdentifier: String
    public var expiresAt: Date
    public init(attemptId: UUID, nonce: String, merchantIdentifier: String, expiresAt: Date) {
        self.attemptId = attemptId
        self.nonce = nonce
        self.merchantIdentifier = merchantIdentifier
        self.expiresAt = expiresAt
    }
}

public struct WalletAttemptComplete: Codable, Sendable, Hashable {
    public var attemptId: UUID
    /// The `PKIdentityDocument.encryptedData` bytes, base64url, exactly as Wallet produced them.
    public var envelope: String
    public init(attemptId: UUID, envelope: String) {
        self.attemptId = attemptId
        self.envelope = envelope
    }
}

public struct DocumentAttemptStart: Codable, Sendable, Hashable {
    public var attemptId: UUID
    /// The provider's short-lived session token for the SDK. Treat as a secret; never log it.
    public var sessionToken: String
    public var expiresAt: Date
    public init(attemptId: UUID, sessionToken: String, expiresAt: Date) {
        self.attemptId = attemptId
        self.sessionToken = sessionToken
        self.expiresAt = expiresAt
    }
}

public struct DocumentAttemptComplete: Codable, Sendable, Hashable {
    public var attemptId: UUID
    public init(attemptId: UUID) { self.attemptId = attemptId }
}

/// What the person is told when an attempt ends. Deliberately minimal: the same wording whether the person is under the threshold or
/// the check could not be completed (AGE-005).
public struct VerificationAttemptOutcome: Codable, Sendable, Hashable {
    public var status: ConsumerVerificationStatus
    public var label: VerificationLabel?
    public var receiptId: UUID?
    /// The person may try again (attempts remain and the request is open).
    public var canRetry: Bool
    public init(status: ConsumerVerificationStatus, label: VerificationLabel?, receiptId: UUID?, canRetry: Bool) {
        self.status = status
        self.label = label
        self.receiptId = receiptId
        self.canRetry = canRetry
    }
}

// MARK: - What a prompt shows

public enum VerificationPromptContent {
    /// Human-readable disclosure lines for a capability (exactly the claim fields).
    public static func disclosure(for capability: Capability, parameters: [String: JSONValue]) -> [VerificationDisclosureItem] {
        switch capability {
        case .ageMinimum:
            var years = ""
            if case .integer(let n)? = parameters["years"] { years = String(n) }
            return [VerificationDisclosureItem(field: "meets_threshold", title: "Whether you are \(years) or older",
                                               detail: "A yes or no. Your date of birth and your age are not shared.")]
        case .identityName:
            return [VerificationDisclosureItem(field: "given_name", title: "Your first name", detail: "As it appears on your verified ID."),
                    VerificationDisclosureItem(field: "family_name", title: "Your last name", detail: "As it appears on your verified ID.")]
        case .identityAddress:
            return [VerificationDisclosureItem(field: "address", title: "Your postal address", detail: "As it appears on your verified ID.")]
        case .identityVerified:
            return [VerificationDisclosureItem(field: "verified", title: "Whether you have a verified identity", detail: "A yes or no. No name, address or ID number is shared.")]
        default: return []
        }
    }

    /// What the standard result never contains, per capability (acceptance 6).
    public static func notDisclosed(for capability: Capability) -> [String] {
        switch capability {
        case .ageMinimum, .identityVerified: ["Your date of birth", "Your age", "Your name", "Your address", "Your ID number", "Your photo"]
        case .identityName: ["Your date of birth", "Your address", "Your ID number", "Your photo"]
        case .identityAddress: ["Your date of birth", "Your name", "Your ID number", "Your photo"]
        default: []
        }
    }

    public static let metadata = ["How the check was done", "When it was issued and when it expires", "That it is only for this business and this request"]

    /// Readable form of a snake_case purpose code (shown with the raw code, never as free text from the business).
    public static func purposeText(_ code: String) -> String {
        switch code {
        case "age_restricted_access": "Access to age-restricted content or services"
        case "age_restricted_purchase": "Purchase of an age-restricted product"
        default: code.replacingOccurrences(of: "_", with: " ").capitalized
        }
    }
}
