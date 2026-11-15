import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// WP-4.4 on the device (SECURITY.md §2.115): an `approve_estimate` button sends a biometric approval only for a challenge that matches what
/// the device rendered from its own verified definition and directory record, and never without one.
@Suite("Loop estimate approvals (WP-4.4)")
@MainActor
struct LoopApprovalKitTests {
    static var estimate: LoopDefinition {
        LoopDefinition(key: "estimate-approval", title: "Approve your repair estimate", entryPoints: [.businessPage], appearance: .standard,
                       steps: [
                        LoopStep(id: "s1", type: .summary, body: "Brake pads and rotors", actions: [
                            LoopActionBinding(id: "approve", action: "approve_estimate", label: "approve_estimate", next: "done", routing: LoopRouting(mode: .hosted),
                                              params: ["amount": .object(["value": .string("285.28"), "currency": .string("USD")]),
                                                       "terms": .string("Parts and labor, valid for 7 days"), "reference": .string("EST-1042")]),
                        ]),
                        LoopStep(id: "done", type: .result, showOutcome: true),
                       ], limits: LoopLimits(expiresInSeconds: 86_400))
    }

    /// The mock server plus approval challenges; `amount` lets a test play a server that swapped the amount after display.
    actor ApprovingAPI: LoopsAPI {
        let inner: MockLoopsAPI
        let businessName: String
        var amount = "285.28"
        private(set) var approvals: [LoopActionApproval?] = []
        private(set) var challenges = 0

        init(_ inner: MockLoopsAPI, businessName: String) {
            self.inner = inner
            self.businessName = businessName
        }

        func swapAmount(_ value: String) { amount = value }

        func consentStatus() async throws -> LoopConsentStatus { try await inner.consentStatus() }
        func enableLoops(_ r: LoopGlobalConsentRequest) async throws -> LoopConsentStatus { try await inner.enableLoops(r) }
        func disableLoops() async throws -> LoopConsentStatus { try await inner.disableLoops() }
        func authorizeBusiness(_ b: BusinessID, _ r: LoopBusinessConsentRequest) async throws -> LoopConsentStatus { try await inner.authorizeBusiness(b, r) }
        func revokeBusiness(_ b: BusinessID) async throws -> LoopConsentStatus { try await inner.revokeBusiness(b) }
        func availableLoops(business: BusinessID?) async throws -> [LoopSummary] { try await inner.availableLoops(business: business) }
        func startInstance(_ r: LoopInstanceCreateRequest) async throws -> LoopInstanceView { try await inner.startInstance(r) }
        func instance(_ id: LoopInstanceID) async throws -> LoopInstanceView { try await inner.instance(id) }
        func report(_ id: LoopInstanceID, _ r: LoopReportRequest) async throws { try await inner.report(id, r) }
        func publicationKeys() async throws -> LoopPublicationKeySet { try await inner.publicationKeys() }
        func submitAction(_ id: LoopInstanceID, _ r: LoopActionRequest) async throws -> LoopActionResult {
            approvals.append(r.approval)
            return try await inner.submitAction(id, r)
        }
        func startApproval(_ id: LoopInstanceID, _ request: LoopApprovalStartRequest) async throws -> LoopApprovalChallenge {
            challenges += 1
            let view = try await inner.instance(id)
            let now = Date()
            let terms = LoopEstimateTerms(amount: try MoneyAmount(string: amount, currency: .usd), terms: "Parts and labor, valid for 7 days", reference: "EST-1042")
            let approvalId = InteractionID()
            let interaction = LoopEstimateApproval.interaction(approvalId: approvalId, consumerId: ConsumerID(), relationshipId: nil, businessId: view.businessId,
                                                               businessName: businessName, terms: terms, challenge: .generate(), createdAt: now, expiresAt: now.addingTimeInterval(600))
            return LoopApprovalChallenge(approvalId: approvalId.description, instanceId: id, stepId: request.stepId, actionId: request.actionId, interaction: interaction,
                                         expiresAt: interaction.expiresAt)
        }
    }

    final class Signer: @unchecked Sendable {
        private let lock = NSLock()
        private var _signed: [Interaction] = []
        var signed: [Interaction] { lock.withLock { _signed } }
        func sign(_ interaction: Interaction, _ name: String) -> SignedDecision {
            lock.withLock { _signed.append(interaction) }
            return SignedDecision(payload: "p", signature: "s")
        }
    }

    func model(signer: Signer?, tamperAmount: String? = nil) async throws -> (LoopInstanceViewModel, ApprovingAPI) {
        let inner = MockLoopsAPI()
        try await LP.consented(inner)
        let summary = await inner.publish(Self.estimate, business: LP.business.id)
        await inner.setConnected([LP.business.id])
        let api = ApprovingAPI(inner, businessName: LoopEstimateApproval.merchantName(LP.business.displayName)!)
        if let tamperAmount { await api.swapAmount(tamperAmount) }
        let view = try await api.startInstance(LoopInstanceCreateRequest(publicationId: summary.publicationId, entryPoint: .businessPage))
        var context = LP.context(status: try await inner.consentStatus())
        if let signer { context.signApproval = { interaction, name in signer.sign(interaction, name) } }
        let model = LoopInstanceViewModel(instanceId: view.id, api: api, context: context, initial: view)
        return (model, api)
    }

    func confirmAndApprove(_ model: LoopInstanceViewModel) async {
        await model.perform(actionId: "approve")
        // The protected confirmation panel comes first ("This approves the estimate. It does not charge you.").
        let panel = model.tree.nodes.contains { if case .confirmationPanel = $0 { true } else { false } }
        #expect(panel, "\(model.tree)")
        if let confirm = model.actions.first(where: { !$0.system }) { await model.perform(confirm) }
    }

    @Test func anApprovalIsSignedForTheRenderedAmountAndSent() async throws {
        let signer = Signer()
        let (model, api) = try await model(signer: signer)
        #expect(model.tree.origin != .unavailable, "the Phase 4 Loop renders on the device")
        await confirmAndApprove(model)
        #expect(signer.signed.count == 1)
        guard case .authorize(let p)? = signer.signed.first?.payload else { Issue.record("nothing signed"); return }
        #expect(p.amount?.decimalString == "285.28" && p.effectOfApproval == LoopEstimateApproval.effect)
        let sent = await api.approvals
        #expect(sent.count == 1 && sent.first??.signedDecision.signature == "s")
        #expect(model.view?.state == .submitted)
    }

    @Test func aChallengeOverAnotherAmountIsNeverSignedOrSent() async throws {
        let signer = Signer()
        let (model, api) = try await model(signer: signer, tamperAmount: "2852.80")
        await confirmAndApprove(model)
        #expect(signer.signed.isEmpty)
        #expect(await api.approvals.isEmpty)
        #expect(model.errorMessage == "This estimate changed. Nothing was approved.")
    }

    @Test func withoutABiometricSignerNothingIsSent() async throws {
        let (model, api) = try await model(signer: nil)
        await confirmAndApprove(model)
        #expect(await api.challenges == 0)
        #expect(await api.approvals.isEmpty)
        #expect(model.errorMessage == "This device can't approve estimates. Nothing was approved.")
    }

    @Test func theSignerUsesTheBiometricKeyOverTheChallengesDigest() async throws {
        let keys = SoftwareDeviceKeyStore()
        let biometric = try await keys.createKey(for: .approvalBiometric)
        _ = try await keys.createKey(for: .approvalUserPresence)
        let record = DeviceRecord(deviceId: DeviceID(), consumerId: ConsumerID(), name: "Test", purposes: DeviceKeyPurpose.allCases, enrolledAt: Date())
        let signer = LoopApprovalSigner(keys: keys, records: AccountExportTests.Records(record))
        let now = Date()
        let interaction = LoopEstimateApproval.interaction(approvalId: InteractionID(), consumerId: record.consumerId, relationshipId: nil, businessId: LP.business.id,
                                                           businessName: "Northfield", terms: LoopEstimateTerms(LoopApprovalKitTests.estimate.steps[0].actions[0])!,
                                                           challenge: .generate(), createdAt: now, expiresAt: now.addingTimeInterval(600))
        let signed = try await signer.sign(interaction, businessName: "Northfield")
        let payload = try DecisionVerifier().verify(signed, for: interaction, deviceId: record.deviceId, publicKey: biometric.publicKey, channel: .inApp, now: Date())
        #expect(payload.assurance == .biometric && payload.decision == .approve)
        // Only an authorize of sensitivity high is signed here.
        var lowered = interaction
        lowered.sensitivity = .standard
        await #expect(throws: LoopApprovalSigner.Failure.notAnEstimateApproval) { _ = try await signer.sign(lowered, businessName: "Northfield") }
        // A device without the biometric key can't.
        let noBiometric = LoopApprovalSigner(keys: keys, records: AccountExportTests.Records(DeviceRecord(deviceId: DeviceID(), consumerId: ConsumerID(), name: "Old",
                                                                                                          purposes: [.request, .approvalUserPresence], enrolledAt: Date())))
        await #expect(throws: LoopApprovalSigner.Failure.deviceCannotSatisfy) { _ = try await noBiometric.sign(interaction, businessName: "Northfield") }
        #expect(LoopApprovalSigner.promptReason(businessName: "Northfield", interaction: interaction).contains("doesn't charge you"))
    }
}
