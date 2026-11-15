import Foundation
import ViadereCore

/// Signs the binding approval of an `approve_estimate` Loop action (WP-4.4, SECURITY.md §2.115) with the device's own keys: decision
/// `approve`, a v2 payload whose context digest is the digest of the challenge's interaction (the amount, the terms and the business name the
/// customer just saw on the protected confirmation panel), and the key `AssurancePolicy` requires for a `high` authorization: the device-bound
/// biometric key. Face ID or Touch ID appears with Viadere's own sentence naming the business and the amount, and saying it doesn't charge.
///
/// Callers check the challenge against their own verified definition (`LoopEstimateApproval.matches`) **before** calling this; this type
/// refuses anything that is not an `authorize` of sensitivity `high`.
public struct LoopApprovalSigner: Sendable {
    public enum Failure: Error, Equatable, Sendable {
        case notEnrolled
        case notAnEstimateApproval
        case deviceCannotSatisfy
        case userCancelled
        case authenticationFailed
    }

    private let keys: any DeviceKeyStore
    private let records: any DeviceRecordStore
    private let clock: @Sendable () -> Date

    public init(keys: any DeviceKeyStore, records: any DeviceRecordStore, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.keys = keys
        self.records = records
        self.clock = clock
    }

    /// The Face ID / Touch ID reason: Viadere's words, the sanitized name and the formatted amount only.
    public static func promptReason(businessName: String, interaction: Interaction) -> String {
        let name = UntrustedText.name(businessName, max: 30, attribution: nil).text
        guard case .authorize(let payload) = interaction.payload, let amount = payload.amount else { return "Approve the estimate from \(name). It doesn't charge you." }
        return "Approve the estimate from \(name) for \(amount.formatted). It doesn't charge you."
    }

    public func sign(_ interaction: Interaction, businessName: String) async throws -> SignedDecision {
        guard interaction.kind == .authorize, interaction.sensitivity == .high, case .authorize = interaction.payload else { throw Failure.notAnEstimateApproval }
        let record: DeviceRecord
        do {
            guard let loaded = try await records.load() else { throw Failure.notEnrolled }
            record = loaded
        } catch let error as Failure { throw error } catch { throw Failure.notEnrolled }
        guard let plan = ApprovalPolicy.plan(for: interaction, device: record), plan.assurance == .biometric else { throw Failure.deviceCannotSatisfy }
        let key: any ManagedSigningKey
        do { key = try await keys.requireKey(for: plan.purpose) } catch { throw Failure.deviceCannotSatisfy }
        let payload = DecisionPayload(interactionId: interaction.id, businessId: interaction.businessId, decision: .approve, challenge: interaction.challenge,
                                      signedAt: clock(), deviceId: record.deviceId, assurance: plan.assurance, contextDigest: interaction.displayContextDigest())
        do {
            return try await DecisionSigner(key: PromptBoundKey(key, prompt: SigningPrompt(reason: Self.promptReason(businessName: businessName, interaction: interaction)))).sign(payload)
        } catch let error as KeyStoreError {
            if case .userCancelled = error { throw Failure.userCancelled }
            throw Failure.authenticationFailed
        } catch {
            throw Failure.authenticationFailed
        }
    }
}
