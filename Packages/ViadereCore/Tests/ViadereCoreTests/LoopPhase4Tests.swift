import Foundation
import Testing
@testable import ViadereCore

/// Loops Phase 4 contract (WP-4.1 connected mode, WP-4.4 binding `approve_estimate`; SECURITY.md §2.115). The exploit paths first: a
/// forged or replayed approval, an approval over another amount, an approval with a weaker key, a challenge the server swapped, a
/// reference of the wrong kind, a callback body with extra members.
struct LoopPhase4Tests {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    static let business = BusinessID()
    static let device = DeviceID()

    static var binding: LoopActionBinding {
        LoopActionBinding(id: "approve", action: "approve_estimate", label: "approve_estimate", next: "done", routing: LoopRouting(mode: .hosted),
                          params: ["amount": .object(["value": .string("285.28"), "currency": .string("USD")]),
                                   "terms": .string("Parts and labor, valid for 7 days"), "reference": .string("EST-1042")])
    }

    static func interaction(amount: String = "285.28", challenge: ChallengeNonce = .generate(), id: InteractionID = InteractionID()) throws -> Interaction {
        let terms = LoopEstimateTerms(amount: try MoneyAmount(string: amount, currency: CurrencyCode("USD")!), terms: "Parts and labor, valid for 7 days", reference: "EST-1042")
        return LoopEstimateApproval.interaction(approvalId: id, consumerId: ConsumerID(), relationshipId: nil, businessId: business, businessName: "Juniper Auto",
                                                terms: terms, challenge: challenge, createdAt: now, expiresAt: now.addingTimeInterval(LoopEstimateApproval.lifetime))
    }

    static func sign(_ interaction: Interaction, key: SoftwareP256SigningKey, assurance: DecisionAssurance = .biometric, decision: Decision = .approve,
                     digestOf other: Interaction? = nil) async throws -> SignedDecision {
        let payload = DecisionPayload(interactionId: interaction.id, businessId: interaction.businessId, decision: decision, challenge: interaction.challenge,
                                      signedAt: now, deviceId: device, assurance: assurance, contextDigest: (other ?? interaction).displayContextDigest())
        return try await DecisionSigner(key: key).sign(payload)
    }

    // MARK: WP-4.4

    @Test func estimateApprovalRequiresADeviceBoundBiometricSignature() throws {
        let i = try Self.interaction()
        #expect(i.kind == .authorize && i.sensitivity == .high && i.purpose == .transactional)
        #expect(AssurancePolicy.requiredAssurance(for: i) == .deviceBoundBiometric)
        guard case .authorize(let p) = i.payload else { Issue.record("not authorize"); return }
        #expect(p.effectOfApproval == "This approves the estimate. It does not charge you.")
        #expect(p.merchant == "Juniper Auto" && p.amount?.formatted.contains("285.28") == true)
    }

    @Test func aSignatureOverAnotherAmountOrWithAWeakerKeyOrReplayedIsRefused() async throws {
        let key = SoftwareP256SigningKey()
        let passcode = SoftwareP256SigningKey()
        let challenge = ChallengeNonce.generate()
        let id = InteractionID()
        let shown = try Self.interaction(challenge: challenge, id: id)
        let verifier = DecisionVerifier()
        // The device was shown a smaller amount: the signed context digest is not the server's.
        let smaller = try Self.interaction(amount: "28.52", challenge: challenge, id: id)
        let mismatched = try await Self.sign(shown, key: key, digestOf: smaller)
        #expect(throws: DecisionVerificationError.contextMismatch) {
            try verifier.verify(mismatched, for: shown, deviceId: Self.device, publicKey: key.publicKey, channel: .inApp, now: Self.now)
        }
        // A passcode-level signature never meets `high`.
        let weak = try await Self.sign(shown, key: passcode, assurance: .devicePasscode)
        #expect(throws: DecisionVerificationError.insufficientAssurance) {
            try verifier.verify(weak, for: shown, deviceId: Self.device, publicKey: passcode.publicKey, channel: .inApp, now: Self.now)
        }
        // Another key than the device's biometric key.
        let forged = try await Self.sign(shown, key: SoftwareP256SigningKey())
        #expect(throws: DecisionVerificationError.badSignature) {
            try verifier.verify(forged, for: shown, deviceId: Self.device, publicKey: key.publicKey, channel: .inApp, now: Self.now)
        }
        // The genuine one verifies once; the challenge is single use.
        let good = try await Self.sign(shown, key: key)
        let guardian = InMemoryReplayGuard()
        _ = try await verifier.verify(good, for: shown, deviceId: Self.device, publicKey: key.publicKey, channel: .inApp, now: Self.now, replayGuard: guardian)
        await #expect(throws: DecisionVerificationError.replayed) {
            try await verifier.verify(good, for: shown, deviceId: Self.device, publicKey: key.publicKey, channel: .inApp, now: Self.now, replayGuard: guardian)
        }
        // A signature for one approval does not satisfy another (other id, other challenge).
        let other = try Self.interaction()
        #expect(throws: DecisionVerificationError.interactionMismatch) {
            try verifier.verify(good, for: other, deviceId: Self.device, publicKey: key.publicKey, channel: .inApp, now: Self.now)
        }
        // After the lifetime it is expired.
        #expect(throws: DecisionVerificationError.expired) {
            try verifier.verify(good, for: shown, deviceId: Self.device, publicKey: key.publicKey, channel: .inApp, now: Self.now.addingTimeInterval(601))
        }
    }

    @Test func theDeviceNeverSignsAChallengeThatDiffersFromWhatItRendered() throws {
        let instance = LoopInstanceID()
        let i = try Self.interaction()
        let challenge = LoopApprovalChallenge(approvalId: i.id.description, instanceId: instance, stepId: "review", actionId: "approve", interaction: i, expiresAt: i.expiresAt)
        let ok = { (c: LoopApprovalChallenge, binding: LoopActionBinding) in
            LoopEstimateApproval.matches(c, instanceId: instance, stepId: "review", binding: binding, businessId: Self.business, businessName: "Juniper Auto", now: Self.now)
        }
        #expect(ok(challenge, Self.binding))
        // Another amount, other terms, another business name, another business, another instance or step, a lower sensitivity, expired.
        var swapped = challenge
        swapped.interaction = try Self.interaction(amount: "2852.80", id: i.id)
        #expect(!ok(swapped, Self.binding))
        var binding = Self.binding
        binding.params?["terms"] = .string("Parts only")
        #expect(!ok(challenge, binding))
        #expect(!LoopEstimateApproval.matches(challenge, instanceId: instance, stepId: "review", binding: Self.binding, businessId: Self.business, businessName: "Juniper Autos", now: Self.now))
        #expect(!LoopEstimateApproval.matches(challenge, instanceId: instance, stepId: "review", binding: Self.binding, businessId: BusinessID(), businessName: "Juniper Auto", now: Self.now))
        #expect(!LoopEstimateApproval.matches(challenge, instanceId: LoopInstanceID(), stepId: "review", binding: Self.binding, businessId: Self.business, businessName: "Juniper Auto", now: Self.now))
        var lowered = challenge
        lowered.interaction.sensitivity = .standard
        #expect(!ok(lowered, Self.binding))
        var renamed = challenge
        renamed.approvalId = InteractionID().description
        #expect(!ok(renamed, Self.binding))
        #expect(!LoopEstimateApproval.matches(challenge, instanceId: instance, stepId: "review", binding: Self.binding, businessId: Self.business, businessName: "Juniper Auto",
                                              now: Self.now.addingTimeInterval(601)))
        // Only `approve_estimate` binds; `review_estimate` (read-only) never asks for a signature.
        binding = Self.binding
        binding.action = "review_estimate"
        #expect(!ok(challenge, binding))
        // A binding without a reference cannot produce an approval.
        binding = Self.binding
        binding.params?.removeValue(forKey: "reference")
        #expect(LoopEstimateTerms(binding) == nil)
    }

    @Test func theRegistryBindsOnlyApproveEstimateAndOnlyFromPhase4() {
        let binding = LoopActionRegistry.v1.definitions.filter(\.bindsApproval).map(\.actionType)
        #expect(binding == ["approve_estimate"])
        guard case .registered(let approve) = LoopActionRegistry.v1.resolve("approve_estimate") else { Issue.record("not registered"); return }
        #expect(approve.confirmation?.effect == LoopEstimateApproval.effect)
        #expect(approve.parameters.contains { $0.name == "reference" && $0.required })
        #expect(!approve.isAvailable(in: .hosted) && approve.isAvailable(in: .connected))
    }

    @Test func actionRequestsWithoutAnApprovalStillDecode() throws {
        let legacy = Data(#"{"stepId":"s1","actionId":"a","inputs":{},"idempotencyKey":"k"}"#.utf8)
        #expect(try ViadereJSON.decode(LoopActionRequest.self, from: legacy).approval == nil)
    }

    // MARK: WP-4.1

    @Test func businessReferencesAreStrictAndTyped() {
        let event = LoopActionEventID()
        let ref = LoopBusinessRef.event(event)
        #expect(LoopBusinessRef.parseEvent(ref) == event)
        // An instance reference never parses as an event and the reverse; no uppercase, padding, missing prefix or bare UUID.
        #expect(LoopBusinessRef.parseInstance(ref) == nil)
        #expect(LoopBusinessRef.parseEvent(LoopBusinessRef.instance(LoopInstanceID())) == nil)
        for bad in [ref.uppercased(), "lev_" + event.description.uppercased(), event.description, ref + " ", " " + ref, "lev_", "lev_x", ref + "0"] {
            #expect(LoopBusinessRef.parseEvent(bad) == nil, "\(bad)")
        }
    }

    @Test func outcomeCallbacksAreStrictAndKeyed() throws {
        let ok = Data(#"{"outcome":"accepted","idempotency_key":"ans-1"}"#.utf8)
        let request = try #require(LoopOutcomeCallbackRequest.decodeStrict(ok))
        #expect(request.outcome.outcome == .accepted)
        for bad in [#"{"outcome":"accepted"}"#, #"{"outcome":"timed_out","idempotency_key":"k"}"#, #"{"outcome":"unknown","idempotency_key":"k"}"#,
                    #"{"outcome":"accepted","idempotency_key":"has space"}"#, #"{"outcome":"accepted","idempotency_key":"k","note":"x"}"#, "[]"] {
            #expect(LoopOutcomeCallbackRequest.decodeStrict(Data(bad.utf8)) == nil, "\(bad)")
        }
        // The key is bound to the event and the outcome.
        let a = try request.digest(eventRef: "lev_a"), b = try request.digest(eventRef: "lev_b")
        #expect(a != b)
        #expect(try LoopOutcomeCallbackRequest(outcome: .rejected, idempotencyKey: "ans-1").digest(eventRef: "lev_a") != a)
    }

    @Test func connectedEventsAreOpaqueOnly() {
        for event in WebhookEventType.loopEvents { #expect(WebhookEventType.opaqueEvents.contains(event)) }
        #expect(APIRoutes.all.contains { $0.name == "business.loops.events.outcome" && $0.auth == .businessAPIKey })
        #expect(APIRoutes.all.contains { $0.name == "loops.instances.approvals.start" && $0.auth == .deviceSignedBearer })
    }

    @Test func aConnectedOutcomeNeverReachesTimedOutOrUnknown() throws {
        // A business can only answer; `timed_out` and `unknown` are Viadere's (system) and the connected source can't set them.
        #expect(throws: LoopOutcomeMachine.Refusal.self) { try LoopOutcomeMachine.transition(from: .pending, to: .unknown, source: .webhook) }
        #expect(throws: LoopOutcomeMachine.Refusal.self) { try LoopOutcomeMachine.transition(from: .accepted, to: .rejected, source: .webhook) }
        #expect(try LoopOutcomeMachine.transition(from: .unknown, to: .accepted, source: .webhook) == .accepted)
        #expect(Set(LoopConnectedOutcome.allCases.map(\.outcome)) == [.accepted, .rejected, .pending])
    }
}
