import Fluent
import Foundation
import ViadereCore

/// App Attest **assertions** on the requests that decide something (WP-C2): an approval result (`POST /v1/approve/requests/{id}/result`) and a
/// link completion (`POST /v1/link-sessions/{id}/complete`). Only a device that enrolled with an attested key is asked; its assertion must verify
/// with that key over the request's client data (`ApprovalAppAttest`, `LinkAppAttest`) with a counter strictly above the last one, advanced by
/// compare-and-swap (`AppAttestAssertions`), so a replayed or reordered assertion is refused.
///
/// `APP_ATTEST_ASSERTION_MODE`: `off` (development, tests) checks nothing; `report` (the staging and production default during rollout) verifies a
/// present assertion and records a missing or failing one (`device.assertion_missing`, `device.assertion_failed`) without refusing the request;
/// `require` refuses both with `401 signature_invalid`.
struct AppAttestAssertionPolicy {
    let db: any Database
    let ctx: ServerContext

    func check(device: DeviceRecord, assertion: String?, clientData: Data, purpose: String, principal: ConsumerPrincipal) async throws {
        let mode = ctx.config.approve.assertionMode
        guard mode != .off, let deviceId = device.id,
              try await AppAttestKeyRecord.query(on: db).filter(\.$deviceId == deviceId).count() > 0 else { return }
        let refused = APIError(.unauthorized, .signatureInvalid, "The device integrity check failed. Update Viadere and try again.")
        guard let assertion, assertion.utf8.count <= 4096, let data = AppAttestVerifier.decodeBase64(assertion) else {
            _ = try? await AuditService(db: db, ctx: ctx).record("device.assertion_missing", outcome: mode == .require ? .denied : .success, principal: principal,
                                                                metadata: ["purpose": purpose, "mode": mode.rawValue])
            if mode == .require { throw refused }
            return
        }
        do {
            try await AppAttestAssertions(db: db, ctx: ctx).verify(deviceId: deviceId, assertion: data, clientData: clientData)
        } catch {
            // `AppAttestAssertions` has audited the failure (`device.assertion_failed`).
            if mode == .require { throw refused }
            _ = try? await AuditService(db: db, ctx: ctx).record("device.assertion_reported", outcome: .denied, principal: principal,
                                                                metadata: ["purpose": purpose, "mode": mode.rawValue])
        }
    }
}
