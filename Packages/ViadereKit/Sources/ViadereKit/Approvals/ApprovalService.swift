import Foundation
import ViadereCore

public enum ApprovalError: Error, Equatable, Sendable {
    case expired
    case notActionable(InteractionStatus)
    case unsupportedKind
    case decisionNotAllowed
    case notEnrolled
    /// No key on this device can meet the required assurance.
    case deviceCannotSatisfy(RequiredAssurance)
    /// A key was invalidated (biometrics changed): the device must be re-enrolled.
    case keyInvalidated(DeviceKeyPurpose)
    /// The keychain can't be read right now (device locked, early boot). Retry; nothing is wrong with the key.
    case keysUnavailable
    case userCancelled
    case authenticationFailed
    case invalidSelection
    case replyTooLong
    case api(APIError)
}

/// Builds, signs and submits decisions.
///
/// 1. Checks the interaction is still pending, unexpired and the decision is allowed for its kind.
/// 2. Chooses the key from `AssurancePolicy` (never weaker than required).
/// 3. Signs `DecisionPayload` (canonical JSON, `VIADERE-DECISION-V1`) with that key; Face ID / Touch ID / passcode
///    appears for the approval keys, with a reason that names the business and amount.
/// 4. Submits `DecideInteractionRequest`.
public struct ApprovalService: Sendable {
    private let api: any ViadereAPI
    private let keys: any DeviceKeyStore
    private let records: any DeviceRecordStore
    private let clock: @Sendable () -> Date

    public init(api: any ViadereAPI, keys: any DeviceKeyStore, records: any DeviceRecordStore,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.keys = keys
        self.records = records
        self.clock = clock
    }

    /// - Parameter assuranceOverride: a deliberately lower claim (used only for inline `deny`/`report` from a
    ///   notification, where no biometric UI can appear). The server decides whether that is acceptable.
    public func submit(_ envelope: InteractionEnvelope, decision: Decision, selectedOptionIds: [String]? = nil, reply: String? = nil,
                       channel: Channel = .inApp, assuranceOverride: DecisionAssurance? = nil,
                       onBehalfOf: String? = nil) async throws -> InteractionOutcome {
        let interaction = envelope.interaction
        let now = clock()
        guard !interaction.kind.isUnknown else { throw ApprovalError.unsupportedKind }
        guard envelope.status == .pending else { throw ApprovalError.notActionable(envelope.status) }
        guard !interaction.isExpired(at: now) else { throw ApprovalError.expired }
        guard Decision.allowed(for: interaction.kind).contains(decision) else { throw ApprovalError.decisionNotAllowed }
        try Self.validate(decision: decision, selectedOptionIds: selectedOptionIds, reply: reply, payload: interaction.payload)

        let record: DeviceRecord
        do {
            guard let loaded = try await records.load() else { throw ApprovalError.notEnrolled }
            record = loaded
        } catch let error as ApprovalError { throw error } catch { throw ApprovalError.notEnrolled }

        let plan: SigningPlan
        if let assuranceOverride {
            plan = SigningPlan(assurance: assuranceOverride)
        } else if let planned = ApprovalPolicy.plan(for: interaction, device: record) {
            plan = planned
        } else {
            throw ApprovalError.deviceCannotSatisfy(AssurancePolicy.requiredAssurance(for: interaction))
        }

        let key: any ManagedSigningKey
        do { key = try await keys.requireKey(for: plan.purpose) } catch let error as KeyStoreError { throw Self.map(error) } catch { throw ApprovalError.notEnrolled }

        let payload = DecisionPayload(
            interactionId: interaction.id, businessId: interaction.businessId, decision: decision,
            selectedOptionIds: selectedOptionIds, reply: reply, challenge: interaction.challenge,
            signedAt: now, deviceId: record.deviceId, assurance: plan.assurance)
        let prompt = SigningPrompt(reason: ApprovalPolicy.promptReason(for: envelope, decision: decision, onBehalfOf: onBehalfOf))
        let signed: SignedDecision
        do {
            signed = try await DecisionSigner(key: PromptBoundKey(key, prompt: prompt)).sign(payload)
        } catch let error as KeyStoreError {
            throw Self.map(error)
        } catch {
            throw ApprovalError.authenticationFailed
        }
        do {
            return try await api.decide(interaction.id, DecideInteractionRequest(signedDecision: signed, channel: channel))
        } catch let error as APIError {
            throw Self.map(error)
        }
    }

    static func validate(decision: Decision, selectedOptionIds: [String]?, reply: String?, payload: InteractionPayload) throws {
        if decision == .select {
            guard case .choose(let choose) = payload, let selected = selectedOptionIds, !selected.isEmpty,
                  Set(selected).count == selected.count,
                  Set(selected).isSubset(of: Set(choose.options.map(\.id))),
                  choose.allowsMultiple || selected.count == 1 else { throw ApprovalError.invalidSelection }
        }
        if decision == .reply {
            guard let reply, !reply.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw ApprovalError.invalidSelection }
            var limit = DecisionPayload.maxReplyLength
            if case .reply(let p) = payload { limit = min(limit, p.maxLength) }
            guard reply.count <= limit else { throw ApprovalError.replyTooLong }
        }
    }

    static func map(_ error: KeyStoreError) -> ApprovalError {
        switch error {
        case .userCancelled: .userCancelled
        case .authenticationFailed: .authenticationFailed
        case .keyInvalidated(let purpose): .keyInvalidated(purpose)
        case .keyNotFound(let purpose): .keyInvalidated(purpose)
        case .temporarilyUnavailable: .keysUnavailable
        default: .authenticationFailed
        }
    }

    static func map(_ error: APIError) -> ApprovalError {
        switch error {
        case .server(_, .expired, _), .server(_, .gone, _): .expired
        case .server(_, .conflict, _): .notActionable(.approved)
        case .server(_, .insufficientAssurance, _): .deviceCannotSatisfy(.deviceBoundBiometric)
        case .notEnrolled: .notEnrolled
        default: .api(error)
        }
    }
}

extension ApprovalError {
    /// Calm, specific copy for the approval sheet.
    public var userMessage: String {
        switch self {
        case .expired: "This request has expired."
        case .notActionable: "This was already handled."
        case .unsupportedKind: "Update Viadere to view this request."
        case .decisionNotAllowed, .invalidSelection: "That option isn't available."
        case .notEnrolled: "Set up this device to approve requests."
        case .deviceCannotSatisfy: "This request needs Face ID or Touch ID, which isn't available on this device."
        case .keyInvalidated: "Your device security changed. Set this device up again to approve requests."
        case .keysUnavailable: "Your keys aren't available right now. Unlock your iPhone and try again."
        case .userCancelled: "Not approved. You can try again."
        case .authenticationFailed: "We couldn't verify it's you. Try again."
        case .replyTooLong: "That reply is too long."
        case .api(let error): error.userMessage
        }
    }
}
