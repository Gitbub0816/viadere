import Foundation
import ViadereCore

/// Freezing and unfreezing approvals (APP-007). Freezing is one tap and needs no Face ID (it only ever makes the account safer);
/// unfreezing needs a trusted device and a fresh biometric proof from it.
public struct ApproveFreezeFlow: Sendable {
    private let api: any ApproveAPI
    private let keys: any DeviceKeyStore
    private let records: any DeviceRecordStore
    private let clock: @Sendable () -> Date

    public init(api: any ApproveAPI, keys: any DeviceKeyStore, records: any DeviceRecordStore, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.keys = keys
        self.records = records
        self.clock = clock
    }

    public func state() async throws -> ApproveFreezeState {
        do { return try await api.freezeState() } catch let error as APIError { throw ApproveError.api(error) }
    }

    public func freeze(scope: ApproveFreezeScope, relationshipId: RelationshipID? = nil) async throws -> ApproveFreezeState {
        do { return try await api.setFreeze(ApproveFreezeRequest(scope: scope, relationshipId: relationshipId, frozen: true)) } catch let error as APIError { throw ApproveError.api(error) }
    }

    public func unfreeze(scope: ApproveFreezeScope, relationshipId: RelationshipID? = nil) async throws -> ApproveFreezeState {
        guard let record = try await records.load() else { throw ApproveError.notEnrolled }
        let key: any ManagedSigningKey
        do { key = try await keys.requireKey(for: .approvalBiometric) } catch { throw ApproveError.deviceCannotSatisfy }
        let proof = ApproveFreezeProof(scope: scope, relationshipId: relationshipId, deviceId: record.deviceId, signedAt: clock())
        let signed: SignedStatement
        do {
            signed = try await proof.sign(with: PromptBoundKey(key, prompt: SigningPrompt(reason: "Turn approvals back on")))
        } catch let error as KeyStoreError {
            switch error {
            case .userCancelled: throw ApproveError.userCancelled
            case .authenticationFailed: throw ApproveError.authenticationFailed
            default: throw ApproveError.keysUnavailable
            }
        }
        do { return try await api.setFreeze(ApproveFreezeRequest(scope: scope, relationshipId: relationshipId, frozen: false, proof: signed)) } catch let error as APIError { throw ApproveError.api(error) }
    }
}
