import Crypto
import Foundation

/// Phantom tags for Loop identifiers (kept beside the Loop code rather than in `IDTag`, so this module stays additive).
public enum LoopIDTag {
    public enum Definition {}
    public enum Revision {}
    public enum Publication {}
    public enum Instance {}
    public enum ActionEvent {}
}

public typealias LoopDefinitionID = TypedID<LoopIDTag.Definition>
public typealias LoopRevisionID = TypedID<LoopIDTag.Revision>
/// `published_definition_id` of the publication manifest.
public typealias LoopPublicationID = TypedID<LoopIDTag.Publication>
public typealias LoopInstanceID = TypedID<LoopIDTag.Instance>
public typealias LoopActionEventID = TypedID<LoopIDTag.ActionEvent>

/// The outcome of a Loop action event (spec A7.5, plan section 4.5, `SECURITY.md` §2.94). Modeled separately so delivered-to-Viadere is
/// never shown as delivered-to-business, and no state implies an external outcome that did not happen (INV-8).
public enum LoopActionOutcome: String, Sendable, Codable, CaseIterable, Hashable {
    /// The business confirmed.
    case accepted
    /// The business declined.
    case rejected
    /// Received by Viadere, not yet confirmed by the business. The **only** state set at submission.
    case pending
    /// No answer by the deadline.
    case timedOut = "timed_out"
    /// Delivery to the business could not be confirmed (connected-mode failure, dead letter).
    case unknown

    public var isFinal: Bool { self == .accepted || self == .rejected }
}

/// Who recorded an outcome.
public enum LoopOutcomeSource: String, Sendable, Codable, CaseIterable, Hashable {
    /// A staff member in the hosted inbox.
    case staff
    /// The business's connected endpoint (Phase 4), through the authenticated outcome callback.
    case webhook
    /// Viadere itself: the timeout job and the dead-letter handler.
    case system
}

/// The outcome state machine. Outcomes are appended as new rows (`loop_action_outcomes`), never updated in place; this decides which
/// appends are legal.
public enum LoopOutcomeMachine {
    public enum Refusal: Error, Sendable, Hashable {
        /// `accepted` and `rejected` are final.
        case alreadyFinal
        case illegalTransition(from: LoopActionOutcome, to: LoopActionOutcome)
        /// The source may not set that outcome (only the business decides; only Viadere times out or marks unknown).
        case sourceNotAllowed(LoopOutcomeSource, LoopActionOutcome)
    }

    /// The state of a new event.
    public static let initial = LoopActionOutcome.pending

    public static func transition(from current: LoopActionOutcome, to next: LoopActionOutcome, source: LoopOutcomeSource) throws(Refusal) -> LoopActionOutcome {
        if current.isFinal { throw .alreadyFinal }
        switch next {
        case .accepted, .rejected:
            guard source == .staff || source == .webhook else { throw .sourceNotAllowed(source, next) }
        case .timedOut, .unknown:
            guard source == .system else { throw .sourceNotAllowed(source, next) }
        case .pending:
            // Only a connected business confirming receipt after an `unknown` (late delivery confirmation).
            guard source == .webhook else { throw .sourceNotAllowed(source, next) }
        }
        let legal: Bool = switch (current, next) {
        case (.pending, .accepted), (.pending, .rejected), (.pending, .timedOut), (.pending, .unknown): true
        // A late answer is honest: the business did answer after the deadline or after a lost delivery.
        case (.timedOut, .accepted), (.timedOut, .rejected): true
        case (.unknown, .accepted), (.unknown, .rejected), (.unknown, .pending): true
        default: false
        }
        guard legal else { throw .illegalTransition(from: current, to: next) }
        return next
    }
}

/// A customer's action submission (`POST /v1/loops/instances/{id}/actions`). The request digest binds the idempotency key to the exact
/// request: a replay with the same key and digest returns the stored result; the same key with a different digest is a conflict.
public struct LoopActionSubmission: Sendable, Hashable {
    public static let maxIdempotencyKeyLength = 128

    public var instanceId: LoopInstanceID
    public var stepId: String
    public var actionId: String
    public var inputs: [String: JSONValue]
    public var idempotencyKey: String

    public init(instanceId: LoopInstanceID, stepId: String, actionId: String, inputs: [String: JSONValue], idempotencyKey: String) {
        self.instanceId = instanceId
        self.stepId = stepId
        self.actionId = actionId
        self.inputs = inputs
        self.idempotencyKey = idempotencyKey
    }

    public static func isValidIdempotencyKey(_ key: String) -> Bool {
        !key.isEmpty && key.utf8.count <= maxIdempotencyKeyLength
            && key.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "_.:-".unicodeScalars.contains($0)) }
    }

    /// The signed-content object: `{"v":1,"instance_id","step_id","action_id","inputs"}` (the idempotency key is the lookup handle, not content).
    public var digestObject: JSONValue {
        .object(["v": .integer(1), "instance_id": .string(instanceId.description), "step_id": .string(stepId), "action_id": .string(actionId),
                 "inputs": .object(inputs)])
    }

    /// `sha256:<hex>` of the canonical JSON of `digestObject`.
    public func requestDigest() throws -> String { try ContractHash.sha256(digestObject) }
}

/// Idempotency decision for a submission against the stored event with the same `(instance_id, idempotency_key)`.
public enum LoopIdempotency {
    public enum Decision: Sendable, Hashable {
        /// No stored event: insert one (unique constraint on `(instance_id, idempotency_key)` makes concurrent inserts collapse to one).
        case insert
        /// Same key, same request: return the stored event and its current outcome; insert nothing.
        case replay(LoopActionEventID)
        /// Same key, different request: refuse (`409`).
        case conflict
    }

    public static func decide(storedEvent: LoopActionEventID?, storedDigest: String?, submission: LoopActionSubmission) throws -> Decision {
        guard let storedEvent, let storedDigest else { return .insert }
        return ConstantTime.equals(storedDigest, try submission.requestDigest()) ? .replay(storedEvent) : .conflict
    }
}

/// Validates a submission's inputs against the step's registered fields (plan section 4.5 step 2: "input matches the registered
/// schema"). Unknown fields are refused; values are typed.
public enum LoopInputValidator {
    public static func issues(_ inputs: [String: JSONValue], step: LoopStep) -> [ContractIssue] {
        var issues: [ContractIssue] = []
        for key in inputs.keys.sorted() where !step.fields.contains(where: { $0.id == key }) {
            issues.append(ContractIssue(code: ContractIssue.unknownMember, path: "inputs.\(key)"))
        }
        for field in step.fields {
            let path = "inputs.\(field.id)"
            guard let value = inputs[field.id] else {
                if field.required == true { issues.append(ContractIssue(code: ContractIssue.missingMember, path: path)) }
                continue
            }
            let optionIds = Set((field.options ?? []).map(\.id))
            let ok: Bool = switch (field.type, value) {
            case (.singleChoice, .string(let s)), (.timeSlot, .string(let s)): optionIds.contains(s)
            case (.multiChoice, .array(let items)):
                !items.isEmpty && items.allSatisfy { $0.stringValue.map(optionIds.contains) ?? false }
                    && Set(items.compactMap(\.stringValue)).count == items.count
            case (.shortText, .string(let s)):
                !s.trimmingCharacters(in: .whitespaces).isEmpty
                    && DisplayTextSanitizer.isWithinLimits(s, maxCharacters: min(field.maxLength ?? LoopLimits.maxShortTextLength, LoopLimits.maxShortTextLength))
                    && !DisplayTextSanitizer.containsDisallowedScalars(s)
            case (.date, .string(let s)): isCalendarDate(s)
            case (.yesNo, .bool): true
            case (.acknowledgement, .bool(let b)): b
            default: false
            }
            if !ok { issues.append(ContractIssue(code: ContractIssue.invalidValue, path: path)) }
        }
        return issues
    }

    /// `YYYY-MM-DD`, a real Gregorian date.
    static func isCalendarDate(_ s: String) -> Bool {
        let parts = s.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0].count == 4, parts[1].count == 2, parts[2].count == 2,
              parts.allSatisfy({ $0.allSatisfy { $0.isASCII && $0.isNumber } }),
              let y = Int(parts[0]), let m = Int(parts[1]), let d = Int(parts[2]), (1...12).contains(m), d >= 1 else { return false }
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
        let days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]
        return d <= days
    }
}

/// The ids-only queue envelope of Loop deliveries (plan section 4.5 step 4; ADR-0014 rule: an unknown `type` or `v` is dead-lettered,
/// never executed). Wire: canonical JSON `{"id":"<outbox id>","ref":"<event or instance id>","type":"…","v":1}`.
public struct LoopDeliveryEnvelope: Sendable, Hashable {
    public enum MessageType: String, Sendable, Codable, CaseIterable, Hashable {
        /// Deliver an action event to the hosted inbox / connected endpoint (queue `loop-delivery`).
        case deliver = "loop.action.deliver"
        /// A response deadline or instance expiry was reached (queue `loop-timeout`).
        case timeout = "loop.instance.timeout"
    }

    public static let version: Int64 = 1
    public var type: MessageType
    public var id: UUID
    public var ref: UUID

    public init(type: MessageType, id: UUID, ref: UUID) {
        self.type = type
        self.id = id
        self.ref = ref
    }

    public func encoded() throws -> Data {
        try CanonicalJSON.serialize(.object(["v": .integer(Self.version), "type": .string(type.rawValue),
                                             "id": .string(id.uuidString.lowercased()), "ref": .string(ref.uuidString.lowercased())]))
    }

    /// Strict parse: exactly `{v, type, id, ref}`, `v == 1`, a known type, UUID ids. `nil` means dead-letter.
    public static func parse(_ data: Data) -> LoopDeliveryEnvelope? {
        guard data.count <= 512, case .object(let o)? = JSONValue.parseContract(data), Set(o.keys) == ["v", "type", "id", "ref"],
              case .integer(let v)? = o["v"], v == version, let type = o["type"]?.stringValue.flatMap(MessageType.init(rawValue:)),
              let id = o["id"]?.stringValue.flatMap(UUID.init(uuidString:)), let ref = o["ref"]?.stringValue.flatMap(UUID.init(uuidString:)) else { return nil }
        return LoopDeliveryEnvelope(type: type, id: id, ref: ref)
    }
}
