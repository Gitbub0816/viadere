import Foundation

// MARK: - Consumer Loop API (WP-3.3, WP-3.5; SECURITY.md §2.98). camelCase members like the rest of the consumer API.
//
// Every route is device-signed (`deviceSignedBearer`): bearer session **and** a `VIADERE-SIG-V1` signature by a device of the same account
// over method, path, body digest, time and nonce. The tenant is always the authenticated account; an instance id or business id is a lookup
// handle the server checks against the caller (`404` for anything that is not theirs, so it is never an existence oracle).

/// The consent text as shown to the customer. The correct answers are not included: the server checks them.
public struct LoopConsentText: Codable, Sendable, Hashable {
    public struct Check: Codable, Sendable, Hashable {
        public var id: String
        public var question: String
        public var options: [LoopComprehensionCheck.Option]
    }

    public var version: Int
    /// `sha256:<hex>` of the full catalog entry (`LoopConsentTextVersion.digest`). Echo it back when agreeing.
    public var digest: String
    public var title: String
    public var paragraphs: [String]
    public var checks: [Check]
    /// `{business}` is replaced on the device with the verified display name of the business being authorized.
    public var businessAuthorization: String
    public var agreeLabel: String

    public init(_ entry: LoopConsentTextVersion) {
        version = entry.version
        digest = entry.digest
        title = entry.title
        paragraphs = entry.paragraphs
        checks = entry.checks.map { Check(id: $0.id, question: $0.question, options: $0.options) }
        businessAuthorization = entry.businessAuthorization
        agreeLabel = entry.agreeLabel
    }
}

/// A recorded grant (global or for one business).
public struct LoopConsentGrantView: Codable, Sendable, Hashable {
    /// `nil` for the global enablement.
    public var businessId: BusinessID?
    public var textVersion: Int
    public var textDigest: String
    public var grantedAt: Date
    /// At the current text version (an older grant authorizes nothing until the customer agrees again).
    public var current: Bool

    public init(businessId: BusinessID?, textVersion: Int, textDigest: String, grantedAt: Date, current: Bool) {
        self.businessId = businessId
        self.textVersion = textVersion
        self.textDigest = textDigest
        self.grantedAt = grantedAt
        self.current = current
    }
}

/// `GET /v1/loops/consent`.
public struct LoopConsentStatus: Codable, Sendable, Hashable {
    /// Loops are offered at all right now (the platform `loops` switch is off when this is false; core features are unaffected).
    public var available: Bool
    /// The global enablement exists, is unrevoked and is at the current text version.
    public var enabled: Bool
    public var text: LoopConsentText
    public var global: LoopConsentGrantView?
    /// Unrevoked per-business authorizations.
    public var businesses: [LoopConsentGrantView]

    public init(available: Bool, enabled: Bool, text: LoopConsentText, global: LoopConsentGrantView?, businesses: [LoopConsentGrantView]) {
        self.available = available
        self.enabled = enabled
        self.text = text
        self.global = global
        self.businesses = businesses
    }
}

/// `PUT /v1/loops/consent`: the global enablement, after the non-skippable education.
public struct LoopGlobalConsentRequest: Codable, Sendable, Hashable {
    public var textVersion: Int
    public var textDigest: String
    /// Comprehension answers: check id → option id. All checks, all correct.
    public var answers: [String: String]
    /// Must be `true` (explicit agreement).
    public var agree: Bool

    public init(textVersion: Int, textDigest: String, answers: [String: String], agree: Bool) {
        self.textVersion = textVersion
        self.textDigest = textDigest
        self.answers = answers
        self.agree = agree
    }
}

/// `PUT /v1/loops/consent/businesses/{businessId}`: the separate authorization of one connected business (requires the global grant).
public struct LoopBusinessConsentRequest: Codable, Sendable, Hashable {
    public var textVersion: Int
    public var textDigest: String
    public var agree: Bool

    public init(textVersion: Int, textDigest: String, agree: Bool) {
        self.textVersion = textVersion
        self.textDigest = textDigest
        self.agree = agree
    }
}

/// One Loop the customer may start (`GET /v1/loops/available`).
public struct LoopSummary: Codable, Sendable, Hashable {
    public var publicationId: LoopPublicationID
    public var businessId: BusinessID
    public var revision: Int64
    /// Business text, sanitized; shown under the "Built by" attribution, never instead of it.
    public var title: String
    public var entryPoints: [LoopEntryPoint]
    /// The customer authorized this business for Loops (otherwise starting one asks for the authorization first).
    public var authorized: Bool

    public init(publicationId: LoopPublicationID, businessId: BusinessID, revision: Int64, title: String, entryPoints: [LoopEntryPoint], authorized: Bool) {
        self.publicationId = publicationId
        self.businessId = businessId
        self.revision = revision
        self.title = title
        self.entryPoints = entryPoints
        self.authorized = authorized
    }
}

/// `POST /v1/loops/instances`.
public struct LoopInstanceCreateRequest: Codable, Sendable, Hashable {
    public var publicationId: LoopPublicationID
    public var entryPoint: LoopEntryPoint

    public init(publicationId: LoopPublicationID, entryPoint: LoopEntryPoint) {
        self.publicationId = publicationId
        self.entryPoint = entryPoint
    }
}

/// One recorded action of an instance. `outcome` is present for actions that deliver to the business (`pending` at first); actions that
/// only advance the flow have none.
public struct LoopActionEventView: Codable, Sendable, Hashable {
    public var id: LoopActionEventID
    public var stepId: String
    public var actionId: String
    public var actionType: String
    public var outcome: LoopActionOutcome?
    public var outcomeAt: Date?
    public var createdAt: Date

    public init(id: LoopActionEventID, stepId: String, actionId: String, actionType: String, outcome: LoopActionOutcome?, outcomeAt: Date?, createdAt: Date) {
        self.id = id
        self.stepId = stepId
        self.actionId = actionId
        self.actionType = actionType
        self.outcome = outcome
        self.outcomeAt = outcomeAt
        self.createdAt = createdAt
    }
}

/// `GET /v1/loops/instances/{instanceId}` and the body of the create and action responses. The device renders it with
/// `PresentationBuilder` from `manifest` (verified against the pinned `loop-publication` keys), `definition` (whose hash must equal the
/// manifest's `definition_hash`) and its own verified directory record of `businessId`.
public struct LoopInstanceView: Codable, Sendable, Hashable {
    public var id: LoopInstanceID
    public var businessId: BusinessID
    public var publicationId: LoopPublicationID
    public var revision: Int64
    public var state: LoopInstanceState
    public var currentStepId: String
    public var entryPoint: LoopEntryPoint
    public var expiresAt: Date
    public var createdAt: Date
    public var updatedAt: Date
    public var publicationStatus: LoopPublicationStatus
    /// Nothing is actionable right now (platform switch, business switch or suspended publication): show the neutral paused state.
    public var paused: Bool
    /// Compact JWS (`viadere-loop-publication+jws`, SECURITY.md §2.92).
    public var manifest: String
    /// The definition in canonical form (`LoopDefinition.parse`).
    public var definition: JSONValue
    public var events: [LoopActionEventView]
    /// The Brand Kit key pinned when the instance started (the kit the reviewed definition names, if it was live in the business's signed
    /// manifest then), or `nil` for neutral styling. Fixed for the life of the instance: withdrawing, taking down or rescheduling the kit
    /// later does not change it. The device still renders a kit only from a manifest it verified itself. Additive: absent from older servers.
    public var brandKitId: String?

    public init(id: LoopInstanceID, businessId: BusinessID, publicationId: LoopPublicationID, revision: Int64, state: LoopInstanceState,
                currentStepId: String, entryPoint: LoopEntryPoint, expiresAt: Date, createdAt: Date, updatedAt: Date,
                publicationStatus: LoopPublicationStatus, paused: Bool, manifest: String, definition: JSONValue, events: [LoopActionEventView],
                brandKitId: String? = nil) {
        self.id = id
        self.businessId = businessId
        self.publicationId = publicationId
        self.revision = revision
        self.state = state
        self.currentStepId = currentStepId
        self.entryPoint = entryPoint
        self.expiresAt = expiresAt
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.publicationStatus = publicationStatus
        self.paused = paused
        self.manifest = manifest
        self.definition = definition
        self.events = events
        self.brandKitId = brandKitId
    }
}

/// `POST /v1/loops/instances/{instanceId}/actions`. The request digest (`LoopActionSubmission.requestDigest`) binds `idempotencyKey` to
/// the exact step, action and inputs: the same key with the same content returns the stored result; with other content it is `409`.
public struct LoopActionRequest: Codable, Sendable, Hashable {
    public var stepId: String
    public var actionId: String
    public var inputs: [String: JSONValue]
    public var idempotencyKey: String

    public init(stepId: String, actionId: String, inputs: [String: JSONValue] = [:], idempotencyKey: String) {
        self.stepId = stepId
        self.actionId = actionId
        self.inputs = inputs
        self.idempotencyKey = idempotencyKey
    }
}

public struct LoopActionResult: Codable, Sendable, Hashable {
    public var event: LoopActionEventView
    public var instance: LoopInstanceView
    /// A repeated idempotency key: nothing new was recorded.
    public var replayed: Bool

    public init(event: LoopActionEventView, instance: LoopInstanceView, replayed: Bool) {
        self.event = event
        self.instance = instance
        self.replayed = replayed
    }
}

/// `POST /v1/loops/instances/{instanceId}/report`.
public struct LoopReportRequest: Codable, Sendable, Hashable {
    public var reason: LoopReportReason

    public init(reason: LoopReportReason) { self.reason = reason }
}

/// `GET /v1/loops/keys`: the public `loop-publication` keys a device pins to verify publication manifests.
public struct LoopPublicationKeySet: Codable, Sendable, Hashable {
    public struct Key: Codable, Sendable, Hashable {
        public var kid: String
        /// Base64url X9.63 (65 bytes).
        public var publicKey: String

        public init(kid: String, publicKey: String) {
            self.kid = kid
            self.publicKey = publicKey
        }

        public var pinned: PinnedManifestKey? {
            guard let bytes = Base64URL.decode(publicKey), let key = try? DevicePublicKey(bytes: bytes) else { return nil }
            return PinnedManifestKey(kid: kid, publicKey: key)
        }
    }

    public var keys: [Key]

    public init(keys: [Key]) { self.keys = keys }
}

extension APIRoutes {
    /// Consent status and the current text.
    public static let loopConsentGet = Endpoint<EmptyBody, LoopConsentStatus>(
        "loops.consent.get", .GET, "/v1/loops/consent", auth: .deviceSignedBearer)
    /// Global enablement. `422` for a stale version or digest, a missing or wrong comprehension answer, or `agree != true`.
    public static let loopConsentPut = Endpoint<LoopGlobalConsentRequest, LoopConsentStatus>(
        "loops.consent.put", .PUT, "/v1/loops/consent", auth: .deviceSignedBearer)
    /// Turns Loops off: revokes the global grant and every business authorization, cancels open instances (history is kept).
    public static let loopConsentDelete = Endpoint<EmptyBody, LoopConsentStatus>(
        "loops.consent.delete", .DELETE, "/v1/loops/consent", auth: .deviceSignedBearer)
    /// Authorizes one actively connected business (`404` otherwise). Requires the current global grant (`409`).
    public static let loopBusinessConsentPut = Endpoint<LoopBusinessConsentRequest, LoopConsentStatus>(
        "loops.consent.business.put", .PUT, "/v1/loops/consent/businesses/{businessId}", auth: .deviceSignedBearer)
    /// Revokes one business's authorization and cancels its open instances.
    public static let loopBusinessConsentDelete = Endpoint<EmptyBody, LoopConsentStatus>(
        "loops.consent.business.delete", .DELETE, "/v1/loops/consent/businesses/{businessId}", auth: .deviceSignedBearer)
    /// Loops the caller may start. Query: `business_id` (optional filter, checked against the caller's connections).
    public static let loopsAvailable = Endpoint<EmptyBody, [LoopSummary]>(
        "loops.available", .GET, "/v1/loops/available", auth: .deviceSignedBearer)
    public static let loopInstanceCreate = Endpoint<LoopInstanceCreateRequest, LoopInstanceView>(
        "loops.instances.create", .POST, "/v1/loops/instances", auth: .deviceSignedBearer)
    public static let loopInstanceGet = Endpoint<EmptyBody, LoopInstanceView>(
        "loops.instances.get", .GET, "/v1/loops/instances/{instanceId}", auth: .deviceSignedBearer)
    public static let loopInstanceAction = Endpoint<LoopActionRequest, LoopActionResult>(
        "loops.instances.action", .POST, "/v1/loops/instances/{instanceId}/actions", auth: .deviceSignedBearer)
    /// Customer report (one per account and publication counts toward the automatic suspension).
    public static let loopInstanceReport = Endpoint<LoopReportRequest, EmptyBody>(
        "loops.instances.report", .POST, "/v1/loops/instances/{instanceId}/report", auth: .deviceSignedBearer)
    /// Public keys for manifest verification (no personal data; still device-signed like the rest of the consumer API).
    public static let loopKeys = Endpoint<EmptyBody, LoopPublicationKeySet>(
        "loops.keys", .GET, "/v1/loops/keys", auth: .deviceSignedBearer)

    /// Appended to `APIRoutes.all`.
    public static let loopEndpoints: [AnyEndpoint] = [
        loopConsentGet.descriptor, loopConsentPut.descriptor, loopConsentDelete.descriptor, loopBusinessConsentPut.descriptor,
        loopBusinessConsentDelete.descriptor, loopsAvailable.descriptor, loopInstanceCreate.descriptor, loopInstanceGet.descriptor,
        loopInstanceAction.descriptor, loopInstanceReport.descriptor, loopKeys.descriptor,
    ]
}
