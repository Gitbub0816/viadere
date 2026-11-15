import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// The approval sheet's brain: availability (pending / expired / stale), the signing plan, the countdown and
/// the decision flow (sign with the right key, submit, report the result).
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class ApprovalViewModel: Identifiable {
    public enum Phase: Equatable, Sendable {
        case ready
        case signing(Decision)
        case done(Decision, InteractionStatus)
        case failed(ApprovalError)
    }

    public private(set) var envelope: InteractionEnvelope
    public private(set) var phase: Phase = .ready
    public private(set) var now: Date
    public private(set) var device: DeviceRecord?
    /// The recorded outcome once a decision is accepted (carries the server's timestamp).
    public private(set) var outcome: InteractionOutcome?
    /// Set when this request belongs to someone who delegated to the signed-in person ("Alex Morgan").
    public private(set) var onBehalfOf: String?
    /// End of this device's new-device cool-down, if it is in one (high and critical approvals are paused until then).
    public private(set) var approvalsLockedUntil: Date?
    /// True after the request changed while it was open: the details on screen are the current ones and the person must look again.
    public private(set) var showsChangedNotice = false
    /// Bumped whenever the displayed request is replaced by a changed one, so the view can drop selections made on the old one.
    public private(set) var contextRevision = 0
    /// Set by the view when the screen is being recorded or mirrored.
    public var isScreenBeingCaptured = false
    /// Called once a decision has been recorded (home refreshes, sheet dismisses).
    public var onFinished: (@MainActor (InteractionOutcome) -> Void)?
    /// Called when a key was invalidated and the device must be re-enrolled.
    public var onKeyInvalidated: (@MainActor () -> Void)?

    private let services: ViadereServices

    public init(envelope: InteractionEnvelope, device: DeviceRecord? = nil, services: ViadereServices) {
        self.id = envelope.id
        self.envelope = envelope
        self.device = device
        self.services = services
        self.now = services.clock()
    }

    /// Stable identity (the interaction id) so the model can drive `.sheet(item:)`.
    public nonisolated let id: InteractionID
    public var interaction: Interaction { envelope.interaction }

    public var availability: ApprovalAvailability {
        ApprovalPolicy.availability(of: envelope, device: device, now: now)
    }

    public var plan: SigningPlan? {
        if case .actionable(let plan) = availability { return plan }
        return nil
    }

    public var headline: String { InteractionPresentation.question(interaction) }
    public var title: String { InteractionPresentation.kindLabel(interaction) }
    public var details: [PresentedDetail] {
        var rows = InteractionPresentation.details(envelope, now: now)
        if let onBehalfOf { rows.insert(PresentedDetail(label: "On behalf of", value: UntrustedText.line(onBehalfOf, max: 40), emphasized: true), at: min(1, rows.count)) }
        return rows
    }
    public var risks: [RiskIndicator] { InteractionPresentation.riskIndicators(interaction) }
    public var effect: String? { InteractionPresentation.effectOfApproval(interaction) }
    public var countdown: String { InteractionPresentation.countdown(until: interaction.expiresAt, now: now) }
    public var verificationLabel: String? { InteractionPresentation.verificationLabel(plan) }
    public var usesSlideToApprove: Bool { ApprovalPolicy.usesSlideToApprove(interaction) }
    public var isBusy: Bool { if case .signing = phase { return true } else { return false } }

    /// Seconds left; drives the countdown ring.
    public var remaining: TimeInterval { max(0, interaction.expiresAt.timeIntervalSince(now)) }
    public var totalLifetime: TimeInterval { max(1, interaction.expiresAt.timeIntervalSince(interaction.createdAt)) }

    /// The new-device cool-down pauses approving this request (deny and report still work).
    public var approvalPausedByCoolDown: Bool {
        CoolDownPolicy.pauses(approveDecision, on: interaction, until: approvalsLockedUntil, now: now)
    }
    public var coolDownMessage: String { CoolDownPolicy.message(until: approvalsLockedUntil, now: now) }
    public var coolDownStillAvailable: String { CoolDownPolicy.stillAvailable }

    /// Approving is blocked while the screen is being recorded (the notice explains why). Denying is never blocked.
    public var approvalBlockedByCapture: Bool { isScreenBeingCaptured && interaction.kind.isSecuritySensitive }

    // MARK: Lifecycle

    /// Loads this device's record and refreshes the interaction (it may have been handled elsewhere).
    public func load() async {
        device = try? await services.records.load()
        await resolveDelegation()
        if let fresh = try? await services.api.interaction(interaction.id) { replace(with: fresh) }
        now = services.clock()
        approvalsLockedUntil = CoolDownPolicy.restricts(approveDecision, on: interaction) ? await services.approvalsLockedUntil() : nil
    }

    public func tick(_ date: Date) { now = date }

    /// Re-renders from `fresh`. If what the person sees changed, they are told, and no earlier choice carries over.
    private func replace(with fresh: InteractionEnvelope) {
        if fresh.interaction.displayContextDigest() != interaction.displayContextDigest() {
            showsChangedNotice = true
            contextRevision += 1
        }
        envelope = fresh
    }

    /// An interaction scoped to another consumer reached this person through a delegation: label it "on behalf of".
    private func resolveDelegation() async {
        guard let consumerId = device?.consumerId, interaction.scope.consumerId != consumerId else { onBehalfOf = nil; return }
        let received = (try? await services.api.household())?.received ?? []
        onBehalfOf = DelegationScopePolicy.onBehalfOfName(scopeConsumerId: interaction.scope.consumerId, myConsumerId: consumerId, received: received)
    }

    // MARK: Decisions

    public func approve() async { await submit(approveDecision) }
    public func deny() async { await submit(denyDecision) }
    public func report() async { await submit(.report) }

    public var approveDecision: Decision {
        switch interaction.kind {
        case .confirm: .confirm
        case .acknowledge: .acknowledge
        default: .approve
        }
    }

    public var denyDecision: Decision { interaction.kind == .authenticate || interaction.kind == .authorize ? .deny : .decline }

    public func submit(_ decision: Decision, selected: [String]? = nil, reply: String? = nil) async {
        guard !isBusy else { return }
        if decision == .approve || decision == .confirm, approvalBlockedByCapture { return }
        // Paused by the new-device cool-down: say so instead of prompting for Face ID (deny and report are never paused).
        if CoolDownPolicy.pauses(decision, on: interaction, until: approvalsLockedUntil, now: services.clock()) { return }
        showsChangedNotice = false
        phase = .signing(decision)
        do {
            let outcome = try await services.approvals.submit(envelope, decision: decision, selectedOptionIds: selected, reply: reply,
                                                              channel: .inApp, onBehalfOf: onBehalfOf)
            self.outcome = outcome
            envelope.status = outcome.status
            phase = .done(decision, outcome.status)
            onFinished?(outcome)
        } catch let error as ApprovalError {
            handle(error)
        } catch {
            phase = .failed(.api(.transport("unknown")))
        }
    }

    private func handle(_ error: ApprovalError) {
        switch error {
        case .userCancelled:
            phase = .ready
        case .keyInvalidated:
            phase = .failed(error)
            onKeyInvalidated?()
        case .expired:
            now = max(now, interaction.expiresAt)
            phase = .ready
        case .notActionable(let status):
            envelope.status = status
            phase = .ready
        case .contextChanged(let fresh):
            // Never sign again on our own: show what the request says now and let the person decide on that.
            if let fresh { envelope = fresh }
            contextRevision += 1
            showsChangedNotice = true
            phase = .ready
        case .deviceCoolingDown(let until):
            // If the server didn't say until when, pause for a few minutes; the server stays the authority either way.
            approvalsLockedUntil = until ?? approvalsLockedUntil ?? services.clock().addingTimeInterval(300)
            phase = .ready
        default:
            phase = .failed(error)
        }
    }

    public func clearError() {
        if case .failed = phase { phase = .ready }
    }
}
