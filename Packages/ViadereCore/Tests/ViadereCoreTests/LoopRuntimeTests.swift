import Foundation
import Testing
@testable import ViadereCore

/// Review gate (FX-3), outcome states, idempotency, input validation, queue envelopes and the consent/access gate (D3.T3, D3.T6 at model level).
@Suite("Loop review gate and runtime rules")
struct LoopRuntimeTests {
    var passing: LoopValidationReport { LoopPolicyValidator.validate(FX.pickup, context: FX.context()) }
    var highRisk: LoopValidationReport { LoopPolicyValidator.validate(FX.estimate, context: FX.context(kits: ["spring"])) }

    // MARK: Publication gate

    @Test func hardGateFailureCannotBeOverriddenByReviewers() throws {
        var health = FX.pickup
        health.title = "Describe your symptoms"
        let report = LoopPolicyValidator.validate(health, context: FX.context())
        let hash = try health.definitionHash()
        let approvals = [LoopReview(reviewerId: "op-1", decision: .approve, definitionHash: hash),
                         LoopReview(reviewerId: "op-2", decision: .approve, definitionHash: hash),
                         LoopReview(reviewerId: "op-3", decision: .approve, definitionHash: hash)]
        let verdict = LoopPublicationGate.evaluate(report: report, definitionHash: hash, authorIds: ["author"], reviews: approvals)
        guard case .refused(.hardGate(let failure)) = verdict else { Issue.record("expected hard gate refusal, got \(verdict)"); return }
        #expect(failure.hits.contains { $0.rule == .healthContent })
        #expect(!verdict.isPublishable)
    }

    @Test func everyRevisionNeedsAHumanApproval() throws {
        let hash = try FX.pickup.definitionHash()
        #expect(LoopPublicationGate.evaluate(report: passing, definitionHash: hash, authorIds: ["a"], reviews: [])
            == .awaitingReview(required: .single, approvals: 0, needed: 1))
        let one = [LoopReview(reviewerId: "op-1", decision: .approve, definitionHash: hash)]
        #expect(LoopPublicationGate.evaluate(report: passing, definitionHash: hash, authorIds: ["a"], reviews: one)
            == .publishable(definitionHash: hash, reviewers: ["op-1"]))
    }

    @Test func highRiskNeedsTwoDistinctReviewers() throws {
        let hash = try FX.estimate.definitionHash()
        let same = [LoopReview(reviewerId: "op-1", decision: .approve, definitionHash: hash),
                    LoopReview(reviewerId: "op-1", decision: .approve, definitionHash: hash)]
        #expect(LoopPublicationGate.evaluate(report: highRisk, definitionHash: hash, authorIds: ["a"], reviews: same)
            == .awaitingReview(required: .twoPerson, approvals: 1, needed: 2))
        let two = same.prefix(1) + [LoopReview(reviewerId: "op-2", decision: .approve, definitionHash: hash)]
        #expect(LoopPublicationGate.evaluate(report: highRisk, definitionHash: hash, authorIds: ["a"], reviews: Array(two)).isPublishable)
    }

    @Test func authorsCannotReviewAndReviewsBindToTheExactHash() throws {
        let hash = try FX.pickup.definitionHash()
        #expect(LoopPublicationGate.evaluate(report: passing, definitionHash: hash, authorIds: ["op-1"],
                                             reviews: [LoopReview(reviewerId: "op-1", decision: .approve, definitionHash: hash)]) == .refused(.selfReview))
        // An approval of an earlier revision does not carry over.
        let old = [LoopReview(reviewerId: "op-2", decision: .approve, definitionHash: "sha256:" + String(repeating: "0", count: 64))]
        #expect(LoopPublicationGate.evaluate(report: passing, definitionHash: hash, authorIds: ["a"], reviews: old)
            == .awaitingReview(required: .single, approvals: 0, needed: 1))
        // A report produced for another definition is stale: validate again.
        var edited = FX.pickup
        edited.title = "Schedule your pickup today"
        #expect(LoopPublicationGate.evaluate(report: passing, definitionHash: try edited.definitionHash(), authorIds: ["a"], reviews: [])
            == .refused(.validationStale))
        // Any rejection or change request blocks, even next to an approval.
        let mixed = [LoopReview(reviewerId: "op-2", decision: .approve, definitionHash: hash),
                     LoopReview(reviewerId: "op-3", decision: .requestChanges, definitionHash: hash)]
        #expect(LoopPublicationGate.evaluate(report: passing, definitionHash: hash, authorIds: ["a"], reviews: mixed) == .refused(.changesRequested))
        let rejected = mixed + [LoopReview(reviewerId: "op-4", decision: .reject, definitionHash: hash)]
        #expect(LoopPublicationGate.evaluate(report: passing, definitionHash: hash, authorIds: ["a"], reviews: rejected) == .refused(.rejected))
    }

    // MARK: Outcomes

    @Test func outcomeStateMachine() throws {
        #expect(LoopOutcomeMachine.initial == .pending)
        #expect(try LoopOutcomeMachine.transition(from: .pending, to: .accepted, source: .staff) == .accepted)
        #expect(try LoopOutcomeMachine.transition(from: .pending, to: .timedOut, source: .system) == .timedOut)
        #expect(try LoopOutcomeMachine.transition(from: .timedOut, to: .rejected, source: .webhook) == .rejected)
        #expect(try LoopOutcomeMachine.transition(from: .unknown, to: .pending, source: .webhook) == .pending)
        // Final states stay final; only the business decides; only Viadere times out or marks unknown.
        #expect(throws: LoopOutcomeMachine.Refusal.alreadyFinal) { try LoopOutcomeMachine.transition(from: .accepted, to: .rejected, source: .staff) }
        #expect(throws: LoopOutcomeMachine.Refusal.sourceNotAllowed(.system, .accepted)) { try LoopOutcomeMachine.transition(from: .pending, to: .accepted, source: .system) }
        #expect(throws: LoopOutcomeMachine.Refusal.sourceNotAllowed(.webhook, .timedOut)) { try LoopOutcomeMachine.transition(from: .pending, to: .timedOut, source: .webhook) }
        #expect(throws: LoopOutcomeMachine.Refusal.illegalTransition(from: .timedOut, to: .unknown)) { try LoopOutcomeMachine.transition(from: .timedOut, to: .unknown, source: .system) }
        #expect(throws: LoopOutcomeMachine.Refusal.illegalTransition(from: .pending, to: .pending)) { try LoopOutcomeMachine.transition(from: .pending, to: .pending, source: .webhook) }
    }

    @Test func outcomeWordingIsNeverPromissory() {
        let pending = LoopStringCatalog.outcomeText(.pending, business: "Juniper Salon")
        #expect(pending == "Sent to Juniper Salon. Waiting for them to confirm.")
        for outcome in [LoopActionOutcome.pending, .timedOut, .unknown] {
            let text = LoopStringCatalog.outcomeText(outcome, business: "Juniper Salon").lowercased()
            for word in ["confirmed", "delivered", "done", "complete", "booked", "guaranteed"] { #expect(!text.contains(word), "\(outcome): \(word)") }
        }
        #expect(Set(LoopActionOutcome.allCases.map { LoopStringCatalog.outcomeText($0, business: "B") }).count == 5)
    }

    // MARK: Idempotency and inputs

    @Test func idempotencyReplayAndConflict() throws {
        let instance = LoopInstanceID()
        let submission = LoopActionSubmission(instanceId: instance, stepId: "s1", actionId: "confirm", inputs: ["slot": .string("am")], idempotencyKey: "k-1")
        let event = LoopActionEventID()
        let digest = try submission.requestDigest()
        #expect(try LoopIdempotency.decide(storedEvent: nil, storedDigest: nil, submission: submission) == .insert)
        #expect(try LoopIdempotency.decide(storedEvent: event, storedDigest: digest, submission: submission) == .replay(event))
        var changed = submission
        changed.inputs["slot"] = .string("pm")
        #expect(try LoopIdempotency.decide(storedEvent: event, storedDigest: digest, submission: changed) == .conflict)
        // The digest binds the instance (an event of another instance never replays here).
        var other = submission
        other.instanceId = LoopInstanceID()
        #expect(try other.requestDigest() != digest)
        #expect(LoopActionSubmission.isValidIdempotencyKey("abc_123:x-y.z"))
        #expect(!LoopActionSubmission.isValidIdempotencyKey(""))
        #expect(!LoopActionSubmission.isValidIdempotencyKey("a b"))
        #expect(!LoopActionSubmission.isValidIdempotencyKey(String(repeating: "a", count: 129)))
    }

    @Test func inputsMatchTheStepSchema() {
        let step = LoopStep(id: "s", type: .form, fields: [
            LoopField(id: "slot", type: .singleChoice, label: "Time", required: true, options: [LoopOption(id: "am", label: "AM"), LoopOption(id: "pm", label: "PM")]),
            LoopField(id: "extras", type: .multiChoice, label: "Extras", options: [LoopOption(id: "a", label: "A"), LoopOption(id: "b", label: "B")]),
            LoopField(id: "note", type: .shortText, label: "Note", maxLength: 10),
            LoopField(id: "day", type: .date, label: "Day"),
            LoopField(id: "ok", type: .acknowledgement, label: "I understand"),
            LoopField(id: "yes", type: .yesNo, label: "Gift wrap?"),
        ], actions: [])
        #expect(LoopInputValidator.issues(["slot": .string("am"), "extras": .array([.string("a")]), "note": .string("hi"), "day": .string("2026-02-28"),
                                           "ok": .bool(true), "yes": .bool(false)], step: step).isEmpty)
        let bad = LoopInputValidator.issues(["slot": .string("night"), "extras": .array([.string("a"), .string("a")]), "note": .string("01234567890"),
                                             "day": .string("2026-02-30"), "ok": .bool(false), "yes": .string("yes"), "card": .string("4111")], step: step)
        #expect(Set(bad.map(\.path)) == ["inputs.slot", "inputs.extras", "inputs.note", "inputs.day", "inputs.ok", "inputs.yes", "inputs.card"])
        #expect(LoopInputValidator.issues([:], step: step).map(\.code) == [ContractIssue.missingMember])
        #expect(!LoopInputValidator.issues(["slot": .string("am"), "note": .string("a\u{202E}b")], step: step).isEmpty)
        #expect(LoopInputValidator.isCalendarDate("2028-02-29") && !LoopInputValidator.isCalendarDate("2100-02-29"))
    }

    @Test func deliveryEnvelopeIsIdsOnlyAndStrict() throws {
        let envelope = LoopDeliveryEnvelope(type: .deliver, id: UUID(uuidString: "11111111-2222-4333-8444-555555555555")!,
                                            ref: UUID(uuidString: "66666666-7777-4888-9999-000000000000")!)
        let data = try envelope.encoded()
        #expect(String(decoding: data, as: UTF8.self)
            == #"{"id":"11111111-2222-4333-8444-555555555555","ref":"66666666-7777-4888-9999-000000000000","type":"loop.action.deliver","v":1}"#)
        #expect(LoopDeliveryEnvelope.parse(data) == envelope)
        // Unknown type or version, extra members, payload smuggling: dead-letter (nil), never executed.
        for bad in [#"{"id":"11111111-2222-4333-8444-555555555555","ref":"66666666-7777-4888-9999-000000000000","type":"loop.action.execute","v":1}"#,
                    #"{"id":"11111111-2222-4333-8444-555555555555","ref":"66666666-7777-4888-9999-000000000000","type":"loop.action.deliver","v":2}"#,
                    #"{"id":"11111111-2222-4333-8444-555555555555","inputs":{"card":"4111"},"ref":"66666666-7777-4888-9999-000000000000","type":"loop.action.deliver","v":1}"#,
                    #"{"id":"x","ref":"66666666-7777-4888-9999-000000000000","type":"loop.action.deliver","v":1}"#] {
            #expect(LoopDeliveryEnvelope.parse(Data(bad.utf8)) == nil)
        }
    }

    // MARK: Access and consent (D3.T6, D3.T3, D3.T8 at model level)

    var allowedInput: LoopAccessInput {
        LoopAccessInput(consent: LoopConsentState(globalTextVersion: 2, businessTextVersion: 2), currentConsentTextVersion: 2, relationshipActive: true,
                        businessStatus: .verified, businessCategory: .retail, publicationStatus: .active)
    }

    @Test func accessRequiresBothConsentsAtTheCurrentVersion() {
        #expect(LoopAccessPolicy.evaluate(.createInstance, allowedInput) == .allowed)
        var i = allowedInput
        i.consent = .none
        #expect(LoopAccessPolicy.evaluate(.createInstance, i) == .denied(.globalConsentMissing))
        i.consent = LoopConsentState(globalTextVersion: 2)
        #expect(LoopAccessPolicy.evaluate(.act, i) == .denied(.businessConsentMissing))
        i.consent = LoopConsentState(globalTextVersion: 2, businessTextVersion: 2, businessRevoked: true)
        #expect(LoopAccessPolicy.evaluate(.resume, i) == .denied(.businessConsentMissing))
        i.consent = LoopConsentState(globalTextVersion: 2, globalRevoked: true, businessTextVersion: 2)
        #expect(LoopAccessPolicy.evaluate(.act, i) == .denied(.globalConsentMissing))
        i.consent = LoopConsentState(globalTextVersion: 2, businessTextVersion: 2)
        i.currentConsentTextVersion = 3
        #expect(LoopAccessPolicy.evaluate(.act, i) == .denied(.consentOutdated))
    }

    @Test func exhaustiveConsentBypassSearchFindsNoAllowedStateWithoutConsent() {
        // Every combination of the boolean inputs: `.allowed` implies both consents present, unrevoked and current.
        for bits in 0..<(1 << 10) {
            func b(_ i: Int) -> Bool { bits & (1 << i) != 0 }
            let input = LoopAccessInput(
                consent: LoopConsentState(globalTextVersion: b(0) ? 1 : nil, globalRevoked: b(1), businessTextVersion: b(2) ? (b(3) ? 1 : 0) : nil, businessRevoked: b(4)),
                currentConsentTextVersion: 1, relationshipActive: b(5), businessStatus: b(6) ? .verified : .suspended, businessCategory: .retail,
                publicationStatus: b(7) ? .active : .suspended, businessLoopsSwitchedOff: b(8), platformLoopsOff: b(9))
            for op in LoopAccessOperation.allCases where LoopAccessPolicy.evaluate(op, input) == .allowed {
                #expect(b(0) && !b(1) && b(2) && b(3) && !b(4) && b(5) && b(6) && b(7) && !b(8) && !b(9))
            }
        }
    }

    @Test func accessRefusalsForRevokedBusinessesPublicationsAndForeignInstances() {
        var i = allowedInput
        i.businessStatus = .revoked
        #expect(LoopAccessPolicy.evaluate(.act, i) == .denied(.businessNotVerified))
        i = allowedInput
        i.relationshipActive = false
        #expect(LoopAccessPolicy.evaluate(.createInstance, i) == .denied(.relationshipInactive))
        i = allowedInput
        i.publicationStatus = .revoked
        #expect(LoopAccessPolicy.evaluate(.act, i) == .denied(.publicationNotActive))
        i = allowedInput
        i.businessLoopsSwitchedOff = true
        #expect(LoopAccessPolicy.evaluate(.act, i) == .denied(.businessSwitchedOff))
        i = allowedInput
        i.platformLoopsOff = true
        #expect(LoopAccessPolicy.evaluate(.createInstance, i) == .denied(.platformOff))
        i = allowedInput
        i.instanceExpired = true
        #expect(LoopAccessPolicy.evaluate(.act, i) == .denied(.expired))
        i = allowedInput
        i.instanceOwnedByCaller = false
        #expect(LoopAccessPolicy.evaluate(.act, i) == .denied(.notFound))
        i = allowedInput
        i.businessCategory = .healthcare
        #expect(LoopAccessPolicy.evaluate(.createInstance, i) == .denied(.categoryRefused))
    }
}
