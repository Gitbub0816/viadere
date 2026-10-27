import Crypto
import Foundation

/// The consumer's decision on an interaction.
public enum Decision: String, Sendable, Codable, CaseIterable {
    case approve, deny, confirm, decline, select, reply, acknowledge
    /// "This wasn't me" — deny and report as suspicious.
    case report

    /// Decisions that make sense for a kind. Unknown kinds accept none.
    public static func allowed(for kind: InteractionKind) -> Set<Decision> {
        switch kind {
        case .authenticate, .authorize: [.approve, .deny, .report]
        case .confirm: [.confirm, .decline, .report]
        case .choose: [.select, .decline]
        case .acknowledge: [.acknowledge, .decline]
        case .reply, .message: [.reply, .decline]
        case .status, .reward, .ticket: [.acknowledge]
        case .unknown: []
        }
    }
}

/// The signed statement a device produces when the consumer decides on an interaction.
///
/// Canonical JSON (see `CanonicalJSON`) with these members (absent optionals omitted):
/// `assurance`, `businessId`, `challenge`, `decision`, `deviceId`, `interactionId`,
/// `reply`, `selectedOptionIds`, `signedAt`, `v` (= 1).
///
/// Signature input: UTF-8 `"VIADERE-DECISION-V1\n"` followed by the canonical JSON bytes.
/// Algorithm: ECDSA P-256 / SHA-256, raw r||s, base64url.
public struct DecisionPayload: Sendable, Hashable, Codable {
    public static let version: Int64 = 1
    public static let domain = "VIADERE-DECISION-V1\n"
    /// Max reply length inside a decision.
    public static let maxReplyLength = 1000

    public var interactionId: InteractionID
    public var businessId: BusinessID
    public var decision: Decision
    public var selectedOptionIds: [String]?
    public var reply: String?
    public var challenge: ChallengeNonce
    /// Truncated to milliseconds so it survives the wire round trip.
    public var signedAt: Date
    public var deviceId: DeviceID
    public var assurance: DecisionAssurance

    public init(interactionId: InteractionID, businessId: BusinessID, decision: Decision, selectedOptionIds: [String]? = nil,
                reply: String? = nil, challenge: ChallengeNonce, signedAt: Date, deviceId: DeviceID, assurance: DecisionAssurance) {
        self.interactionId = interactionId
        self.businessId = businessId
        self.decision = decision
        self.selectedOptionIds = selectedOptionIds
        self.reply = reply
        self.challenge = challenge
        self.signedAt = ViadereDate.truncatedToMilliseconds(signedAt)
        self.deviceId = deviceId
        self.assurance = assurance
    }

    /// Canonical JSON bytes.
    public func canonicalJSON() throws -> Data {
        var object: [String: JSONValue] = [
            "v": .integer(Self.version),
            "interactionId": .string(interactionId.description),
            "businessId": .string(businessId.description),
            "decision": .string(decision.rawValue),
            "challenge": .string(challenge.value),
            "signedAt": .string(ViadereDate.format(signedAt)),
            "deviceId": .string(deviceId.description),
            "assurance": .string(assurance.rawValue),
        ]
        if let selectedOptionIds { object["selectedOptionIds"] = .array(selectedOptionIds.map(JSONValue.string)) }
        if let reply { object["reply"] = .string(reply) }
        return try CanonicalJSON.serialize(.object(object))
    }

    /// Bytes that are signed: domain prefix + canonical JSON.
    public func signingInput() throws -> Data {
        Data(Self.domain.utf8) + (try canonicalJSON())
    }

    /// Strictly decodes canonical bytes; fails if the bytes are not exactly canonical.
    public static func decodeCanonical(_ data: Data) throws -> DecisionPayload {
        guard case .object(let o) = try JSONDecoder().decode(JSONValue.self, from: data) else {
            throw DecisionVerificationError.malformedPayload
        }
        let allowed: Set<String> = ["v", "interactionId", "businessId", "decision", "challenge", "signedAt", "deviceId",
                                    "assurance", "selectedOptionIds", "reply"]
        guard Set(o.keys).isSubset(of: allowed), o["v"] == .integer(version),
              let interactionId = o["interactionId"]?.stringValue.flatMap(InteractionID.init),
              let businessId = o["businessId"]?.stringValue.flatMap(BusinessID.init),
              let decision = o["decision"]?.stringValue.flatMap(Decision.init(rawValue:)),
              let challenge = o["challenge"]?.stringValue.flatMap(ChallengeNonce.init),
              let signedAt = o["signedAt"]?.stringValue.flatMap(ViadereDate.parse),
              let deviceId = o["deviceId"]?.stringValue.flatMap(DeviceID.init),
              let assurance = o["assurance"]?.stringValue.flatMap(DecisionAssurance.init(rawValue:))
        else { throw DecisionVerificationError.malformedPayload }
        var selected: [String]?
        if let raw = o["selectedOptionIds"] {
            guard case .array(let items) = raw else { throw DecisionVerificationError.malformedPayload }
            let strings = items.compactMap(\.stringValue)
            guard strings.count == items.count else { throw DecisionVerificationError.malformedPayload }
            selected = strings
        }
        var reply: String?
        if let raw = o["reply"] {
            guard let s = raw.stringValue, s.count <= maxReplyLength else { throw DecisionVerificationError.malformedPayload }
            reply = s
        }
        let payload = DecisionPayload(interactionId: interactionId, businessId: businessId, decision: decision,
                                      selectedOptionIds: selected, reply: reply, challenge: challenge, signedAt: signedAt,
                                      deviceId: deviceId, assurance: assurance)
        guard try payload.canonicalJSON() == data else { throw DecisionVerificationError.nonCanonicalPayload }
        return payload
    }
}

/// Wire form of a signed decision: `{"payload":"<base64url canonical JSON>","signature":"<base64url raw r||s>"}`.
public struct SignedDecision: Codable, Sendable, Hashable {
    public var payload: String
    public var signature: String

    public init(payload: String, signature: String) {
        self.payload = payload
        self.signature = signature
    }
}

/// Decision verification failures.
public enum DecisionVerificationError: Error, Sendable, Equatable {
    case malformedPayload
    case nonCanonicalPayload
    case malformedSignature
    case badSignature
    case interactionMismatch
    case businessMismatch
    case deviceMismatch
    case challengeMismatch
    case expired
    case signedInFuture
    case stale
    case insufficientAssurance
    case invalidSelection
    case invalidDecision
    case replayed
}

/// Produces `SignedDecision`s on the device.
public struct DecisionSigner: Sendable {
    public let key: any DeviceSigningKey

    public init(key: any DeviceSigningKey) { self.key = key }

    public func sign(_ payload: DecisionPayload) async throws -> SignedDecision {
        let canonical = try payload.canonicalJSON()
        let signature = try await key.signature(for: Data(DecisionPayload.domain.utf8) + canonical)
        return SignedDecision(payload: Base64URL.encode(canonical), signature: ViadereSignatureEncoding.encode(signature))
    }
}

/// Verifies `SignedDecision`s on the server.
public struct DecisionVerifier: Sendable {
    /// Max tolerated future skew for `signedAt`.
    public var allowedFutureSkew: TimeInterval
    /// Max age of `signedAt` at verification time.
    public var maxAge: TimeInterval

    public init(allowedFutureSkew: TimeInterval = 60, maxAge: TimeInterval = 300) {
        self.allowedFutureSkew = allowedFutureSkew
        self.maxAge = maxAge
    }

    /// Verifies the signature only, returning the decoded payload. `publicKey` must be the
    /// device key whose purpose is `DeviceKeyPurpose.required(for: payload.assurance)` — use
    /// `decodeUnverified` first to learn the device id and claimed assurance.
    public func verifySignature(_ signed: SignedDecision, publicKey: DevicePublicKey) throws -> DecisionPayload {
        let payload = try decodeUnverified(signed)
        guard let bytes = Base64URL.decode(signed.payload) else { throw DecisionVerificationError.malformedPayload }
        guard let signature = ViadereSignatureEncoding.decode(signed.signature) else {
            throw DecisionVerificationError.malformedSignature
        }
        guard let key = try? publicKey.signingKey(),
              key.isValidSignature(signature, for: Data(DecisionPayload.domain.utf8) + bytes) else {
            throw DecisionVerificationError.badSignature
        }
        return payload
    }

    /// Decodes the payload WITHOUT verifying (to select the device and key). Never trust the result alone.
    public func decodeUnverified(_ signed: SignedDecision) throws -> DecisionPayload {
        guard signed.payload.count <= 8192, let bytes = Base64URL.decode(signed.payload) else {
            throw DecisionVerificationError.malformedPayload
        }
        return try DecisionPayload.decodeCanonical(bytes)
    }

    /// Full verification against the interaction: signature, binding (interaction, business,
    /// device, challenge), freshness, expiry, assurance policy, and option validity.
    /// Callers must also consume the challenge via `ReplayGuard` (scope `decision`) to make it single-use.
    public func verify(_ signed: SignedDecision, for interaction: Interaction, deviceId: DeviceID,
                       publicKey: DevicePublicKey, channel: Channel, now: Date) throws -> DecisionPayload {
        let payload = try verifySignature(signed, publicKey: publicKey)
        guard payload.interactionId == interaction.id else { throw DecisionVerificationError.interactionMismatch }
        guard payload.businessId == interaction.businessId else { throw DecisionVerificationError.businessMismatch }
        guard payload.deviceId == deviceId else { throw DecisionVerificationError.deviceMismatch }
        guard Decision.allowed(for: interaction.kind).contains(payload.decision) else {
            throw DecisionVerificationError.invalidDecision
        }
        guard ConstantTime.equals(payload.challenge.value, interaction.challenge.value) else {
            throw DecisionVerificationError.challengeMismatch
        }
        guard !interaction.isExpired(at: now) else { throw DecisionVerificationError.expired }
        guard payload.signedAt <= now.addingTimeInterval(allowedFutureSkew) else { throw DecisionVerificationError.signedInFuture }
        guard now.timeIntervalSince(payload.signedAt) <= maxAge else { throw DecisionVerificationError.stale }
        guard AssurancePolicy.canSatisfy(interaction, channel: channel, provided: .deviceSignature(payload.assurance)) else {
            throw DecisionVerificationError.insufficientAssurance
        }
        if case .choose(let choose) = interaction.payload {
            let valid = Set(choose.options.map(\.id))
            let selected = payload.selectedOptionIds ?? []
            if payload.decision == .select {
                guard !selected.isEmpty, Set(selected).count == selected.count, Set(selected).isSubset(of: valid),
                      choose.allowsMultiple || selected.count == 1 else { throw DecisionVerificationError.invalidSelection }
            }
        }
        if let reply = payload.reply, case .reply(let r) = interaction.payload, reply.count > r.maxLength {
            throw DecisionVerificationError.invalidSelection
        }
        return payload
    }

    /// `verify` plus single-use challenge consumption through `replayGuard`.
    public func verify(_ signed: SignedDecision, for interaction: Interaction, deviceId: DeviceID, publicKey: DevicePublicKey,
                       channel: Channel, now: Date, replayGuard: any ReplayGuard) async throws -> DecisionPayload {
        let payload = try verify(signed, for: interaction, deviceId: deviceId, publicKey: publicKey, channel: channel, now: now)
        let fresh = try await replayGuard.registerIfFresh(nonce: payload.challenge.value, scope: "decision:\(interaction.id)",
                                                          expiresAt: interaction.expiresAt.addingTimeInterval(maxAge), now: now)
        guard fresh else { throw DecisionVerificationError.replayed }
        return payload
    }
}
