import Foundation

/// The signed publication manifest of a Loop revision (spec A6a.4, plan section 4.4, `SECURITY.md` §2.92; schema
/// `docs/protocol/schemas/publication-manifest-v1.schema.json`).
///
/// Compact JWS ES256 over canonical JSON, `typ` `viadere-loop-publication+jws`, signed by the server with the dedicated KMS key
/// `loop-publication` (no other use) **only after** `LoopPublicationGate` returned `.publishable` for exactly `definitionHash`. Publisher
/// fields come from the server's business record, never from the definition or the client.
public struct LoopPublicationManifest: Sendable, Hashable {
    public static let version: Int64 = 1
    public static let jwsType = "viadere-loop-publication+jws"
    public static let maxBytes = 4096
    /// Longest `not_after - valid_from` (the server re-signs active publications before expiry).
    public static let maxLifetime: Int64 = 90 * 24 * 3600

    public var publisherType: LoopPublisherType
    /// Present exactly when `publisherType == .business`.
    public var publisherBusinessId: BusinessID?
    public var publishedDefinitionId: LoopPublicationID
    public var revision: Int64
    public var attributionPolicyVersion: Int64
    public var definitionHash: String
    public var rolloutPercent: Int64
    public var validFrom: Int64
    public var notAfter: Int64
    public var kid: String

    public init(publisherType: LoopPublisherType, publisherBusinessId: BusinessID?, publishedDefinitionId: LoopPublicationID, revision: Int64,
                attributionPolicyVersion: Int64 = LoopStringCatalog.attributionPolicyVersion, definitionHash: String, rolloutPercent: Int64 = 100,
                validFrom: Int64, notAfter: Int64, kid: String) {
        self.publisherType = publisherType
        self.publisherBusinessId = publisherBusinessId
        self.publishedDefinitionId = publishedDefinitionId
        self.revision = revision
        self.attributionPolicyVersion = attributionPolicyVersion
        self.definitionHash = definitionHash
        self.rolloutPercent = rolloutPercent
        self.validFrom = validFrom
        self.notAfter = notAfter
        self.kid = kid
    }

    static let members: Set<String> = ["v", "publisher_type", "publisher_business_id", "published_definition_id", "revision",
                                       "attribution_policy_version", "definition_hash", "rollout", "valid_from", "not_after", "kid"]

    public var jsonValue: JSONValue {
        var o: [String: JSONValue] = [
            "v": .integer(Self.version), "publisher_type": .string(publisherType.rawValue), "published_definition_id": .string(publishedDefinitionId.description),
            "revision": .integer(revision), "attribution_policy_version": .integer(attributionPolicyVersion), "definition_hash": .string(definitionHash),
            "rollout": .object(["percent": .integer(rolloutPercent)]), "valid_from": .integer(validFrom), "not_after": .integer(notAfter), "kid": .string(kid),
        ]
        if let publisherBusinessId { o["publisher_business_id"] = .string(publisherBusinessId.description) }
        return .object(o)
    }

    /// Signs (server: KMS key `loop-publication`; tests: a software key). Refuses an inconsistent manifest.
    public func sign(with key: any DeviceSigningKey) async throws -> String {
        guard Self.structurallyValid(self) else { throw ManifestVerificationError.malformed("manifest") }
        guard case .object(let payload) = jsonValue else { throw ManifestVerificationError.malformed("payload") }
        return try await ManifestJWS.sign(payload: payload, type: Self.jwsType, kid: kid, with: key)
    }

    static func structurallyValid(_ m: LoopPublicationManifest) -> Bool {
        let publisherOK = (m.publisherType == .business) == (m.publisherBusinessId != nil)
        return publisherOK && m.revision >= 1 && ContractHash.isValid(m.definitionHash) && (1...100).contains(m.rolloutPercent)
            && m.notAfter > m.validFrom && ManifestJWS.isValidKid(m.kid) && m.attributionPolicyVersion >= 1
    }

    /// Verifies signature (pinned key set), `typ`, canonical encoding, exact member set, version, publisher consistency and the validity
    /// window. Binding to a definition, a business and an attribution policy is checked by `PresentationBuilder`.
    public static func verify(_ compact: String?, keys: [PinnedManifestKey], now: Date, maxClockSkew: Int64 = 300) throws(ManifestVerificationError) -> LoopPublicationManifest {
        let o = try ManifestJWS.verify(compact, type: jwsType, maxBytes: maxBytes, keys: keys)
        guard case .integer(let v)? = o["v"] else { throw .malformed("v") }
        guard v == version else { throw .unsupportedVersion }
        let required: Set<String> = members.subtracting(["publisher_business_id"])
        guard required.isSubset(of: Set(o.keys)), Set(o.keys).isSubset(of: members) else { throw .malformed("members") }
        guard let type = o["publisher_type"]?.stringValue.flatMap(LoopPublisherType.init(rawValue:)),
              let pub = o["published_definition_id"]?.stringValue.flatMap(LoopPublicationID.init),
              case .integer(let revision)? = o["revision"], case .integer(let policy)? = o["attribution_policy_version"],
              let hash = o["definition_hash"]?.stringValue, case .object(let rollout)? = o["rollout"], Set(rollout.keys) == ["percent"],
              case .integer(let percent)? = rollout["percent"], case .integer(let validFrom)? = o["valid_from"],
              case .integer(let notAfter)? = o["not_after"], let kid = o["kid"]?.stringValue else { throw .malformed("values") }
        var business: BusinessID?
        if let raw = o["publisher_business_id"] {
            guard let id = raw.stringValue.flatMap(BusinessID.init) else { throw .malformed("publisher_business_id") }
            business = id
        }
        let manifest = LoopPublicationManifest(publisherType: type, publisherBusinessId: business, publishedDefinitionId: pub, revision: revision,
                                               attributionPolicyVersion: policy, definitionHash: hash, rolloutPercent: percent,
                                               validFrom: validFrom, notAfter: notAfter, kid: kid)
        guard structurallyValid(manifest) else { throw .malformed("values") }
        guard notAfter - validFrom <= maxLifetime else { throw .lifetimeTooLong }
        let t = Int64(now.timeIntervalSince1970.rounded(.down))
        guard t + maxClockSkew >= validFrom else { throw .notYetValid }
        guard t < notAfter else { throw .expired }
        return manifest
    }
}
