@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP-C2 approval hardening. Every test reproduces the exploit path first (it failed before the fix) and then shows the control.
final class ApprovalHardeningTests: XCTestCase {
    private func pendingRequest(_ h: TestHarness, _ f: ApproveFixture) async throws -> (CreateApprovalRequest, ApproveDeviceRequest) {
        let (created, body) = try await h.createRequest(f)
        XCTAssertEqual(created.status, .created, created.text)
        let pending = try await h.pendingRequests(f.phone.consumer)
        let request = try XCTUnwrap(pending.first { $0.requestId == body.requestId })
        return (body, request)
    }

    // MARK: Attempt lock

    /// Exploit: a stolen session (or a buggy client) can try result after result against one pending request: forged signatures, other keys,
    /// stale timestamps. Before: unlimited tries. Now: the request locks after five invalid submissions and accepts nothing more.
    func testTheSixthInvalidSubmissionOnOneRequestIsLocked() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let (body, request) = try await pendingRequest(h, f)
            let forger = TestApprovalDevice(consumer: f.phone.consumer, approvalKey: SoftwareP256SigningKey(), hpke: SoftwareE2EEPrivateKey(), assurance: .biometric)
            for attempt in 1...5 {
                let forged = try await h.answer(forger, request)          // signed by a key that is not the enrolled one
                let refused = try await h.submit(f.phone, deliveryId: request.id, result: forged)
                XCTAssertTrue([.forbidden, .unauthorized, .badRequest].contains(refused.status), "attempt \(attempt): \(refused.text)")
            }
            // The sixth submission, even a genuine one, is refused: the request is locked.
            let genuine = try await h.answer(f.phone, request)
            let locked = try await h.submit(f.phone, deliveryId: request.id, result: genuine)
            XCTAssertEqual(locked.status, .locked, locked.text)
            XCTAssertEqual(locked.errorCode, .requestLocked)
            aeq(try await h.requestView(f, body.requestId).status, .locked)
            atrue(try await h.pendingRequests(f.phone.consumer).isEmpty, "a locked request is never shown again")
            atrue(try await h.approvalAudit("approve.request_locked").count == 1)
            // The business learns it ended (opaque event) and can start over with a new request.
            let (fresh, _) = try await h.createRequest(f)
            XCTAssertEqual(fresh.status, .created, fresh.text)
        }
    }

    func testValidSubmissionsAndRefusalsThatAreNotTheDevicesFaultDoNotCount() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let (_, request) = try await pendingRequest(h, f)
            // A frozen relationship refuses approvals; that is the customer's own state, not an invalid result.
            for _ in 0..<6 {
                _ = try await h.signedPost(f.phone.consumer, APIRoutes.approveFreezeSet.template,
                                           ApproveFreezeRequest(scope: .relationship, relationshipId: f.relationship.id, frozen: true))
            }
            let record = try await XCTUnwrapAsync(try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == request.requestId).first())
            XCTAssertEqual(record.attempts, 0)
        }
    }

    // MARK: App Attest assertions

    /// Exploit: an attacker with the session and request keys of an attested device (malware, a cloned keychain) answers from somewhere else.
    /// Before: no assertion was asked for. Now (`require`): an attested device must assert over the exact result, with a fresh counter.
    func testAReplayedAppAttestAssertionCounterIsRefused() async throws {
        try await withAttestHarness(mode: .off, { $0.approve.assertionMode = .require }) { h, _ in
            let f = try await h.approveFixture()
            let attestKey = P256.Signing.PrivateKey()
            let deviceId = try XCTUnwrap(f.phone.consumer.device).id.uuid
            try await AppAttestKeyRecord(deviceId: deviceId, consumerId: f.phone.consumer.id.uuid, keyId: Hex.encode(SHA256.hash(data: attestKey.publicKey.x963Representation)),
                                         publicKey: Base64URL.encode(attestKey.publicKey.x963Representation), counter: 0, environment: "production", now: h.clock.now()).create(on: h.db)
            // No assertion at all: refused.
            let (_, first) = try await pendingRequest(h, f)
            let jws = try await h.answer(f.phone, first)
            let missing = try await h.submit(f.phone, deliveryId: first.id, result: jws)
            XCTAssertEqual(missing.status, .unauthorized, missing.text)
            // A genuine assertion over this result: accepted.
            let assertion = try TestAppAttestPKI.assertion(key: attestKey, clientData: ApprovalAppAttest.clientData(deliveryId: first.id, result: jws), counter: 1)
            let ok = try await h.signedPost(f.phone.consumer, "/v1/approve/requests/\(first.id.uuidString.lowercased())/result",
                                            SubmitApprovalResultRequest(result: jws, appAttestAssertion: Base64URL.encode(assertion)))
            XCTAssertEqual(ok.status, .ok, ok.text)
            // The same counter again (a replayed assertion), on the next request: refused.
            let (_, second) = try await pendingRequest(h, f)
            let jws2 = try await h.answer(f.phone, second)
            let replayed = try TestAppAttestPKI.assertion(key: attestKey, clientData: ApprovalAppAttest.clientData(deliveryId: second.id, result: jws2), counter: 1)
            let refused = try await h.signedPost(f.phone.consumer, "/v1/approve/requests/\(second.id.uuidString.lowercased())/result",
                                                 SubmitApprovalResultRequest(result: jws2, appAttestAssertion: Base64URL.encode(replayed)))
            XCTAssertEqual(refused.status, .unauthorized, refused.text)
            // An assertion made for another result (moved from one request to another): refused.
            let moved = try await h.signedPost(f.phone.consumer, "/v1/approve/requests/\(second.id.uuidString.lowercased())/result",
                                               SubmitApprovalResultRequest(result: jws2, appAttestAssertion: Base64URL.encode(assertion)))
            XCTAssertEqual(moved.status, .unauthorized, moved.text)
            let fresh = try TestAppAttestPKI.assertion(key: attestKey, clientData: ApprovalAppAttest.clientData(deliveryId: second.id, result: jws2), counter: 2)
            let accepted = try await h.signedPost(f.phone.consumer, "/v1/approve/requests/\(second.id.uuidString.lowercased())/result",
                                                  SubmitApprovalResultRequest(result: jws2, appAttestAssertion: Base64URL.encode(fresh)))
            XCTAssertEqual(accepted.status, .ok, accepted.text)
        }
    }

    func testReportModeRecordsAMissingAssertionWithoutRefusing() async throws {
        try await withAttestHarness(mode: .off, { $0.approve.assertionMode = .report }) { h, _ in
            let f = try await h.approveFixture()
            let attestKey = P256.Signing.PrivateKey()
            let deviceId = try XCTUnwrap(f.phone.consumer.device).id.uuid
            try await AppAttestKeyRecord(deviceId: deviceId, consumerId: f.phone.consumer.id.uuid, keyId: Hex.encode(SHA256.hash(data: attestKey.publicKey.x963Representation)),
                                         publicKey: Base64URL.encode(attestKey.publicKey.x963Representation), counter: 0, environment: "production", now: h.clock.now()).create(on: h.db)
            let (_, request) = try await pendingRequest(h, f)
            let result = try await h.submit(f.phone, deliveryId: request.id, result: try await h.answer(f.phone, request))
            XCTAssertEqual(result.status, .ok, result.text)
            atrue(try await h.approvalAudit("device.assertion_missing").count == 1)
        }
    }

    func testAssertionModeIsConfiguredAndOffIsRefusedInStrictEnvironments() throws {
        XCTAssertEqual(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development"]).approve.assertionMode, .off)
        XCTAssertEqual(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development", "APP_ATTEST_ASSERTION_MODE": "require"]).approve.assertionMode, .require)
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development", "APP_ATTEST_ASSERTION_MODE": "sometimes"]))
    }

    // MARK: relationshipId sunset

    /// The business API addresses customers by `subject_ref` (alias `connection_id`) only. Before: `relationshipId` worked forever. Now it is
    /// deprecated with a date, answered with `Deprecation`/`Sunset` headers until then and refused afterwards.
    func testABusinessUsingRelationshipIdAfterTheSunsetIsRefused() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            let before = try await h.issue(b, relationship: rel, payload: .confirm(ConfirmPayload(title: "Confirm order")), purpose: .transactional)
            XCTAssertEqual(before.status, .created, before.text)
            XCTAssertEqual(before.headers.first(name: "Deprecation"), "true")
            XCTAssertNotNil(before.headers.first(name: "Sunset"))

            h.clock.set(BusinessAddressing.relationshipIdSunset.addingTimeInterval(60))
            let after = try await h.issue(b, relationship: rel, payload: .confirm(ConfirmPayload(title: "Confirm order")), purpose: .transactional)
            XCTAssertEqual(after.status, .badRequest, after.text)
            XCTAssertEqual(after.errorCode, .relationshipIdSunset)
            // `subject_ref`, and its alias `connection_id`, keep working.
            let subject = h.subjectRef(b, consumer)
            let bySubject = IssueInteractionRequest(relationshipId: .unaddressed, purpose: .transactional, payload: .confirm(ConfirmPayload(title: "Confirm order")),
                                                    ttlSeconds: 300, idempotencyKey: UUID().uuidString, subjectRef: subject)
            let ok = try await h.businessPost(b, APIRoutes.businessIssueInteraction.template, bySubject)
            XCTAssertEqual(ok.status, .created, ok.text)
            XCTAssertNil(ok.headers.first(name: "Deprecation"))
            var json = try XCTUnwrap(JSONSerialization.jsonObject(with: try ViadereJSON.encode(bySubject)) as? [String: Any])
            json["connectionId"] = json.removeValue(forKey: "subjectRef")
            json["idempotencyKey"] = UUID().uuidString
            let byConnection = try await h.business(b, .POST, APIRoutes.businessIssueInteraction.template, body: try JSONSerialization.data(withJSONObject: json))
            XCTAssertEqual(byConnection.status, .created, byConnection.text)
        }
    }

    // MARK: Legacy approval sunset

    /// Before: with the Approve v2 gate off (production today) the legacy path stayed open past its sunset, whatever was granted.
    func testLegacyApprovalIsRefusedAfterTheSunsetEvenWithTheApproveGateOff() async throws {
        try await withHarness({ $0.approve.enabled = false }) { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            aeq(try await h.issue(b, relationship: rel, payload: .authorize(.sample())).status, .created, "before the sunset, with the gate off, nothing changes")
            h.clock.set(LegacyApproval.sunset.addingTimeInterval(60))
            let refused = try await h.issue(b, relationship: rel, payload: .authorize(.sample()))
            XCTAssertEqual(refused.status, .forbidden, refused.text)
            atrue(try await h.approvalAudit("interaction.legacy_approval_refused").count == 1)
        }
    }

    // MARK: Device policy

    func testSingleDevicePolicyKeepsOneKeyAndRecordsThePolicy() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let settings = try await h.business(f.business, .GET, APIRoutes.businessApproveSettingsGet.template)
            XCTAssertEqual(settings.status, .ok, settings.text)
            XCTAssertEqual(try settings.json(ApproveBusinessSettings.self).devicePolicy, .anyEnrolled)
            let put = try await h.business(f.business, .PUT, APIRoutes.businessApproveSettingsPut.template, body: try ViadereJSON.encode(ApproveBusinessSettings(devicePolicy: .singleDevice)))
            XCTAssertEqual(put.status, .ok, put.text)
            atrue(try await h.approvalAudit("approve.settings_changed").count == 1)
            // A second key for the same customer: the first is revoked when the second is confirmed.
            let second = try await h.enrollApproval(f.phone.consumer, business: f.business, keys: f.keys)
            let keys = try await ApproveKeyRecord.query(on: h.db).filter(\.$relationshipId == f.relationship.id.uuid).all()
            XCTAssertEqual(keys.filter(\.isActive).map(\.kid), [second.kid])
            XCTAssertEqual(keys.first { $0.kid == f.phone.kid }?.revokeReason, "single_device_policy")
            XCTAssertEqual(keys.first { $0.kid == second.kid }?.devicePolicy, "single_device")
            // A request records the policy and goes to that one key.
            let (created, body) = try await h.createRequest(f)
            XCTAssertEqual(created.status, .created, created.text)
            let record = try await XCTUnwrapAsync(try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == body.requestId).first())
            XCTAssertEqual(record.devicePolicy, "single_device")
            aeq(try await ApproveDeliveryRecord.query(on: h.db).filter(\.$requestId == record.id!).all().map(\.kid), [second.kid])
        }
    }

    func testSettingsAreTenantScoped() async throws {
        try await withHarness { h in
            let a = try await h.approveFixture()
            let b = try await h.approveFixture(name: "Contoso Bank", handle: "contosobank")
            let put = try await h.business(a.business, .PUT, APIRoutes.businessApproveSettingsPut.template, body: try ViadereJSON.encode(ApproveBusinessSettings(devicePolicy: .singleDevice)))
            XCTAssertEqual(put.status, .ok, put.text)
            // A body cannot name another tenant: there is nothing to name, and B's policy is untouched.
            aeq(try await h.business(b.business, .GET, APIRoutes.businessApproveSettingsGet.template).json(ApproveBusinessSettings.self).devicePolicy, .anyEnrolled)
            var smuggled = try XCTUnwrap(JSONSerialization.jsonObject(with: try ViadereJSON.encode(ApproveBusinessSettings(devicePolicy: .anyEnrolled))) as? [String: Any])
            smuggled["business_id"] = b.business.id.description
            let refused = try await h.business(a.business, .PUT, APIRoutes.businessApproveSettingsPut.template, body: try JSONSerialization.data(withJSONObject: smuggled))
            XCTAssertEqual(refused.status, .badRequest, "unknown members are refused, never interpreted: \(refused.text)")
            aeq(try await h.business(b.business, .GET, APIRoutes.businessApproveSettingsGet.template).json(ApproveBusinessSettings.self).devicePolicy, .anyEnrolled)
        }
    }
}
