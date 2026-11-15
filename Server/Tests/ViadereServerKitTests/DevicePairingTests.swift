@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import SQLKit
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

// MARK: - Helpers: the new device (B) and the trusted device (A), the way the apps do it

extension TestHarness {
    struct PairingDevice {
        var begin: DevicePairingBeginResponse
        var keys: [DeviceKeyPurpose: SoftwareP256SigningKey]
        var registrations: [DeviceKeyRegistration]
        var result: HTTPResult
        var started: DevicePairingStartResponse?

        /// The code B shows: computed from its OWN keys, the pairing id and the nonce.
        var code: String? {
            started.flatMap { DevicePairing.code(comparisonDigest: DevicePairing.comparisonDigest(pairingId: begin.pairingId, nonce: $0.nonce, keys: registrations)) }
        }
    }

    func pairingInvite(_ consumer: TestConsumer) async throws -> HTTPResult {
        try await signed(consumer, .POST, APIRoutes.devicePairingInvite.template, body: Data("{}".utf8))
    }

    func pairingCode(_ consumer: TestConsumer) async throws -> String {
        let result = try await pairingInvite(consumer)
        XCTAssertEqual(result.status, .created, result.text)
        return try result.json(DevicePairingInvitation.self).code
    }

    func beginPairing(headers: [String: String] = [:]) async throws -> HTTPResult {
        try await request(.POST, APIRoutes.devicePairingBegin.template, headers: headers, body: Data("{}".utf8))
    }

    /// B: begin, create keys with proofs over the pairing id, start with `code`.
    func startPairing(code: String, purposes: [DeviceKeyPurpose] = DeviceKeyPurpose.allCases, begin existing: DevicePairingBeginResponse? = nil,
                      integrity: ([DeviceKeyRegistration], String, ConsumerID) throws -> IntegrityEvidence? = { _, _, _ in nil },
                      extra: [String: Any] = [:], headers: [String: String] = [:]) async throws -> PairingDevice {
        let opened: DevicePairingBeginResponse
        if let existing { opened = existing } else {
            let response = try await beginPairing(headers: headers)
            XCTAssertEqual(response.status, .ok, response.text)
            opened = try response.json(DevicePairingBeginResponse.self)
        }
        var keys: [DeviceKeyPurpose: SoftwareP256SigningKey] = [:]
        var registrations: [DeviceKeyRegistration] = []
        for purpose in purposes {
            let key = SoftwareP256SigningKey()
            keys[purpose] = key
            registrations.append(try await DeviceEnrollment.register(key: key, purpose: purpose, hardwareBacked: true, consumerId: opened.proofSubject,
                                                                    challenge: opened.challenge))
        }
        let request = DevicePairingStartRequest(challenge: opened.challenge, pairingCode: code, platform: .iOS, deviceName: "New iPhone", keys: registrations,
                                                integrity: try integrity(registrations, opened.challenge, opened.proofSubject))
        var body = try ViadereJSON.encode(request)
        if !extra.isEmpty, var object = try JSONSerialization.jsonObject(with: body) as? [String: Any] {
            for (key, value) in extra { object[key] = value }
            body = try JSONSerialization.data(withJSONObject: object)
        }
        let result = try await self.request(.POST, "/v1/device-pairings/\(opened.pairingId)/start", headers: headers, body: body)
        return PairingDevice(begin: opened, keys: keys, registrations: registrations, result: result,
                             started: result.status == .created ? try result.json(DevicePairingStartResponse.self) : nil)
    }

    func firstPending(_ consumer: TestConsumer, file: StaticString = #filePath, line: UInt = #line) async throws -> DevicePairingRequest {
        let pending = try await pendingPairings(consumer)
        return try XCTUnwrap(pending.first, "no pending pairing", file: file, line: line)
    }

    func pendingPairings(_ consumer: TestConsumer) async throws -> [DevicePairingRequest] {
        let result = try await signed(consumer, .GET, APIRoutes.devicePairingsPending.template)
        XCTAssertEqual(result.status, .ok, result.text)
        return try result.json([DevicePairingRequest].self)
    }

    /// A signs (biometric key) and posts an approval with `match`.
    func approvePairing(_ approver: TestConsumer, request: DevicePairingRequest, match: String, key: SoftwareP256SigningKey? = nil,
                        route: DevicePairingID? = nil, mutate: (inout DevicePairingApproval) -> Void = { _ in }) async throws -> HTTPResult {
        let signer = key ?? approver.device!.biometricKey
        var approval = try await DevicePairingApproval.sign(request: request, approverDeviceId: approver.device!.id, match: match, key: signer, now: clock.now())
        mutate(&approval)
        // Re-signed after any change, so a mutated field is a genuine signature over the changed statement.
        approval.signature = ViadereSignatureEncoding.encode(try await signer.signature(for: approval.signingInput()))
        return try await postApproval(approver, approval: approval, route: route ?? request.pairingId)
    }

    func postApproval(_ approver: TestConsumer, approval: DevicePairingApproval, route: DevicePairingID) async throws -> HTTPResult {
        try await signedPost(approver, "/v1/device-pairings/\(route)/approve", DevicePairingApproveRequest(approval: approval))
    }

    func pairingStatus(_ device: PairingDevice, token: String? = nil) async throws -> HTTPResult {
        try await request(.POST, "/v1/device-pairings/\(device.begin.pairingId)/status",
                          body: try ViadereJSON.encode(DevicePairingStatusRequest(statusToken: token ?? device.started!.statusToken)))
    }

    func denyPairing(_ consumer: TestConsumer, _ id: DevicePairingID, report: Bool = false) async throws -> HTTPResult {
        try await signedPost(consumer, "/v1/device-pairings/\(id)/deny", DevicePairingDenyRequest(report: report))
    }

    /// Another live app device of `consumer`'s account with its own bound session, stored directly with the given tier (a D0 device the account
    /// already has, for example one signed in with a passkey and never approved).
    func extraDevice(of consumer: TestConsumer, tier: DeviceTrustTier) async throws -> TestConsumer {
        let request = SoftwareP256SigningKey(), passcode = SoftwareP256SigningKey(), biometric = SoftwareP256SigningKey()
        let device = DeviceRecord(consumerId: consumer.id.uuid, name: "Other iPhone", platform: .iOS, now: clock.now())
        device.enrollmentMethod = "test"
        device.trustTier = tier.rawValue
        try await device.create(on: db)
        for (purpose, key) in [(DeviceKeyPurpose.request, request), (.approvalUserPresence, passcode), (.approvalBiometric, biometric)] {
            try await DeviceKeyRecord(deviceId: device.id!, purpose: purpose, publicKey: key.publicKey, hardwareBacked: true, now: clock.now()).create(on: db)
        }
        let issued = try await ConsumerTokenService(db: db, ctx: ctx).startSession(consumerId: consumer.id.uuid, origin: "test")
        try await TokenFamilyRecord.query(on: db).filter(\.$id == issued.familyId).set(\.$deviceId, to: device.id!).set(\.$enrollUntil, to: nil).update()
        device.familyId = issued.familyId
        try await device.update(on: db)
        let session = AuthSession(consumerId: consumer.id, accessToken: issued.accessToken, expiresAt: issued.accessExpiresAt, refreshToken: issued.refreshToken,
                                  refreshExpiresAt: issued.refreshExpiresAt)
        return TestConsumer(id: consumer.id, session: session, device: TestDevice(id: DeviceID(device.id!), requestKey: request, passcodeKey: passcode, biometricKey: biometric))
    }

    func pairingRecord(_ id: DevicePairingID) async throws -> DevicePairingRecord? { try await DevicePairingRecord.find(id.uuid, on: db) }

    func auditActions(prefix: String) async throws -> [String] {
        try await AuditEventRecord.query(on: db).sort(\.$seq).all().map(\.action).filter { $0.hasPrefix(prefix) }
    }

    func devices(of consumer: ConsumerID) async throws -> [DeviceRecord] {
        try await DeviceRecord.query(on: db).filter(\.$consumerId == consumer.uuid).all()
    }
}

/// WP-D1 device pairing (SECURITY.md §2.107), server side. Each exploit-path test names the attack it closes; every one fails without the check
/// it names (verified by disabling the check while writing it).
final class DevicePairingTests: XCTestCase {
    // MARK: The happy path

    func testATrustedDeviceAddsANewDeviceWhichBecomesD1AndGetsItsOwnBoundSession() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let registered = try await h.signedPost(a, "/v1/push/apns-token", APNsTokenRegistration(token: String(repeating: "ab", count: 32), environment: .sandbox,
                                                                                         bundleId: h.config.appBundleID))
            XCTAssertEqual(registered.status, .ok, registered.text)
            let code = try await h.pairingCode(a)
            let b = try await h.startPairing(code: code)
            XCTAssertEqual(b.result.status, .created, b.result.text)
            let started = try XCTUnwrap(b.started)
            XCTAssertTrue(DevicePairing.isNonce(started.nonce), "a 256-bit nonce")
            XCTAssertLessThanOrEqual(started.expiresAt.timeIntervalSince(h.clock.now()), 300, "five minutes at most")
            // A is alerted (lock-screen safe: no name, code or number), and sees the request only in its own session.
            let push = try XCTUnwrap(h.push.sent.last { $0.category == DevicePairingService.pushCategory })
            XCTAssertFalse(push.body.contains(b.code!), "no code in the push")
            XCTAssertFalse(push.body.contains("New iPhone"))
            let pending = try await h.pendingPairings(a)
            XCTAssertEqual(pending.count, 1)
            let request = try XCTUnwrap(pending.first)
            XCTAssertTrue(request.isConsistent)
            XCTAssertEqual(request.accountId, a.id)
            XCTAssertEqual(request.deviceName, "New iPhone")
            XCTAssertEqual(request.keys.count, 3)
            XCTAssertEqual(request.attemptsRemaining, 3)
            let raw = try await h.signed(a, .GET, APIRoutes.devicePairingsPending.template).text
            XCTAssertFalse(raw.contains("\"\(b.code!)\""), "the approving device never receives the code")
            // B is still pending, without a session.
            let waiting = try await h.pairingStatus(b).json(DevicePairingStatus.self)
            XCTAssertEqual(waiting.state, .pending)
            XCTAssertNil(waiting.session)

            let approved = try await h.approvePairing(a, request: request, match: b.code!)
            XCTAssertEqual(approved.status, .ok, approved.text)
            let response = try approved.json(DevicePairingApproveResponse.self)
            XCTAssertEqual(response.device.trustTier, .d1, "approved by a D1 device and meets every D1 condition")
            let record = try await XCTUnwrapAsync(try await DeviceRecord.find(response.device.id.uuid, on: h.db))
            XCTAssertEqual(record.consumerId, a.id.uuid)
            XCTAssertEqual(record.elevatedBy, TrustElevation.trustedDeviceApproval.rawValue)
            XCTAssertEqual(record.enrollmentMethod, "device_pairing")
            XCTAssertNil(record.approvalsLockedUntil)

            // B collects its session exactly once; it is bound to B (device-signed requests work).
            let done = try await h.pairingStatus(b).json(DevicePairingStatus.self)
            XCTAssertEqual(done.state, .approved)
            let session = try XCTUnwrap(done.session)
            XCTAssertEqual(done.device?.id, response.device.id)
            let again = try await h.pairingStatus(b).json(DevicePairingStatus.self)
            XCTAssertNil(again.session, "the session is handed over once")
            let bConsumer = TestConsumer(id: a.id, session: session, device: TestDevice(id: response.device.id, requestKey: b.keys[.request]!,
                                                                                        passcodeKey: b.keys[.approvalUserPresence]!, biometricKey: b.keys[.approvalBiometric]!))
            let list = try await h.signed(bConsumer, .GET, "/v1/devices")
            XCTAssertEqual(list.status, .ok, list.text)
            try await eq(try await h.tier(of: bConsumer), .d1)
            // A gets the "new device" notice; B (the new device) does not.
            let notices = try await h.signed(a, .GET, "/v1/security-notices").json([SecurityNotice].self)
            XCTAssertTrue(notices.contains { $0.topic == .newDevice && $0.subjectId == response.device.id.description })
            let own = try await h.signed(bConsumer, .GET, "/v1/security-notices").json([SecurityNotice].self)
            XCTAssertFalse(own.contains { $0.topic == .newDevice && $0.subjectId == response.device.id.description })
            // Every state change is audited.
            try await eq(try await h.auditActions(prefix: "device_pairing."),
                         ["device_pairing.invited", "device_pairing.started", "device_pairing.shown", "device_pairing.approved", "device_pairing.completed"])
            // And the new device can be removed afterwards from the trusted device.
            try await eq(try await h.signed(a, .DELETE, "/v1/devices/\(response.device.id)").status, .ok)
            try await eq(try await h.signed(bConsumer, .GET, "/v1/devices").status, .unauthorized)
        }
    }

    // MARK: Exploit paths (each must fail before its check exists)

    func testAReplayedApprovalIsRefused() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let b = try await h.startPairing(code: try await h.pairingCode(a))
            let request = try await h.firstPending(a)
            let approval = try await DevicePairingApproval.sign(request: request, approverDeviceId: a.device!.id, match: b.code!, key: a.device!.biometricKey,
                                                                now: h.clock.now())
            try await eq(try await h.postApproval(a, approval: approval, route: request.pairingId).status, .ok)
            let replay = try await h.postApproval(a, approval: approval, route: request.pairingId)
            XCTAssertEqual(replay.status, .unauthorized, replay.text)
            XCTAssertEqual(replay.errorCode, .replayDetected)
            // A fresh statement for the same, already approved pairing does not add a second device either.
            h.clock.advance(by: 1)
            let second = try await h.approvePairing(a, request: request, match: b.code!)
            XCTAssertEqual(second.status, .conflict, second.text)
            try await eq(try await h.devices(of: a.id).count, 2)
        }
    }

    func testAnApprovalOverAnotherAccountsNonceIsRefused() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let other = try await h.deviceFirstConsumer()
            let mine = try await h.startPairing(code: try await h.pairingCode(a))
            let theirs = try await h.startPairing(code: try await h.pairingCode(other))
            let request = try await h.firstPending(a)
            let foreign = try await h.firstPending(other)
            XCTAssertNotEqual(request.nonce, foreign.nonce)
            // A signs its own pairing but with the other account's nonce (and the digest that nonce gives).
            var swapped = request
            swapped.nonce = foreign.nonce
            swapped.comparisonDigest = DevicePairing.comparisonDigest(pairingId: request.pairingId, nonce: foreign.nonce, keyListDigest: request.newDeviceKeys)
            let refused = try await h.approvePairing(a, request: swapped, match: mine.code!)
            XCTAssertEqual(refused.status, .conflict, refused.text)
            XCTAssertEqual(refused.errorCode, .pairingMismatch)
            // Or the other account's whole pairing: it does not exist for A.
            let cross = try await h.approvePairing(a, request: foreign, match: theirs.code!)
            XCTAssertEqual(cross.status, .notFound, cross.text)
            try await eq(try await h.devices(of: a.id).count, 1)
            try await eq(try await h.devices(of: other.id).count, 1)
            try await eq(try await h.pairingRecord(request.pairingId)?.state, "pending")
            try await eq(try await h.pairingRecord(foreign.pairingId)?.state, "pending")
        }
    }

    func testAD0DeviceCanNeverApproveButCanDeny() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let d0 = try await h.extraDevice(of: a, tier: .d0)
            let b = try await h.startPairing(code: try await h.pairingCode(a))
            let request = try await h.firstPending(a)
            try await eq(try await h.pendingPairings(d0).count, 0, "a D0 device is not shown requests it cannot approve")
            // A D0 device of the same account: refused before anything else, whatever it signs.
            let refused = try await h.approvePairing(d0, request: request, match: b.code!)
            XCTAssertEqual(refused.status, .forbidden, refused.text)
            XCTAssertEqual(refused.errorCode, .deviceCoolDown)
            // A D0 device cannot make a pairing code either.
            try await eq(try await h.pairingInvite(d0).status, .forbidden)
            try await eq(try await h.devices(of: a.id).count, 2)
            // Saying no is always safe.
            try await eq(try await h.denyPairing(d0, request.pairingId).status, .ok)
            try await eq(try await h.pairingRecord(request.pairingId)?.state, "denied")
            try await eq(try await h.pairingStatus(b).json(DevicePairingStatus.self).state, .denied)
        }
    }

    func testADeviceOfAnotherAccountCannotApprove() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let stranger = try await h.deviceFirstConsumer()
            let b = try await h.startPairing(code: try await h.pairingCode(a))
            let request = try await h.firstPending(a)
            // The stranger's D1 device signs the victim's request exactly (account id included) and posts it with its own session.
            let refused = try await h.approvePairing(stranger, request: request, match: b.code!)
            XCTAssertEqual(refused.status, .notFound, refused.text)
            // ... or names its own account in the statement.
            var relabelled = request
            relabelled.accountId = stranger.id
            try await eq(try await h.approvePairing(stranger, request: relabelled, match: b.code!).status, .notFound)
            // The stranger also never sees the request.
            try await eq(try await h.pendingPairings(stranger).count, 0)
            try await eq(try await h.devices(of: a.id).count, 1)
            try await eq(try await h.devices(of: stranger.id).count, 1)
        }
    }

    func testAnApprovalAfterExpiryIsRefused() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let b = try await h.startPairing(code: try await h.pairingCode(a))
            let request = try await h.firstPending(a)
            h.clock.advance(by: DevicePairing.pairingTTL + 1)
            let late = try await h.approvePairing(a, request: request, match: b.code!)
            XCTAssertEqual(late.status, .gone, late.text)
            XCTAssertEqual(late.errorCode, .expired)
            try await eq(try await h.pairingRecord(request.pairingId)?.state, "expired")
            try await eq(try await h.pairingStatus(b).json(DevicePairingStatus.self).state, .expired)
            try await eq(try await h.devices(of: a.id).count, 1)
            try await eq(try await h.auditActions(prefix: "device_pairing.").contains("device_pairing.expired"), true)
            // A statement that claims a later expiry than the server's is not bound to this pairing.
            let b2 = try await h.startPairing(code: try await h.pairingCode(a))
            let fresh = try await h.firstPending(a)
            var stretched = fresh
            stretched.expiresAt = fresh.expiresAt.addingTimeInterval(3600)
            try await eq(try await h.approvePairing(a, request: stretched, match: b2.code!).errorCode, .pairingMismatch)
        }
    }

    func testAComparisonDigestOverSubstitutedKeysIsRefused() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let b = try await h.startPairing(code: try await h.pairingCode(a))
            let request = try await h.firstPending(a)
            // A device shown a substituted key list (a relay's keys under B's pairing) signs a digest over those keys.
            var substituted = request
            substituted.keys = [DevicePairingKey(purpose: .request, publicKey: SoftwareP256SigningKey().publicKey),
                                DevicePairingKey(purpose: .approvalBiometric, publicKey: SoftwareP256SigningKey().publicKey)]
            substituted.newDeviceKeys = DevicePairing.keyListDigest(substituted.keys)
            substituted.comparisonDigest = DevicePairing.comparisonDigest(pairingId: request.pairingId, nonce: request.nonce, keyListDigest: substituted.newDeviceKeys)
            let code = DevicePairing.code(comparisonDigest: substituted.comparisonDigest)!
            let refused = try await h.approvePairing(a, request: substituted, match: code)
            XCTAssertEqual(refused.status, .conflict, refused.text)
            XCTAssertEqual(refused.errorCode, .pairingMismatch)
            try await eq(try await h.devices(of: a.id).count, 1)
            // The genuine request still works afterwards.
            try await eq(try await h.approvePairing(a, request: request, match: b.code!).status, .ok)
        }
    }

    func testARelayThatRegistersItsOwnKeysNeverMatchesTheNumberOnTheRealDevice() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let code = try await h.pairingCode(a)
            // The relay saw the code over the owner's shoulder and used it first, with its own keys.
            let relay = try await h.startPairing(code: code)
            XCTAssertEqual(relay.result.status, .created)
            let genuine = try await h.startPairing(code: code)
            XCTAssertEqual(genuine.result.status, .unauthorized, "a code works once")
            let request = try await h.firstPending(a)
            XCTAssertEqual(request.pairingId, relay.begin.pairingId)
            // The owner types what their real device would show for this pairing and nonce (its own keys): never the relay's code.
            let owner = DevicePairing.code(comparisonDigest: DevicePairing.comparisonDigest(pairingId: request.pairingId, nonce: request.nonce,
                                                                                            keys: genuine.registrations))!
            XCTAssertNotEqual(owner, relay.code, "regenerate if the 1-in-a-million collision ever happens")
            for attempt in 1...3 {
                h.clock.advance(by: 1)
                let wrong = try await h.approvePairing(a, request: request, match: owner)
                XCTAssertEqual(wrong.status, .conflict, wrong.text)
                XCTAssertEqual(wrong.errorCode, .comparisonMismatch)
                XCTAssertEqual(try wrong.json(APIErrorResponse.self).error.details?["remaining"], String(3 - attempt))
            }
            try await eq(try await h.pairingRecord(request.pairingId)?.state, "failed", "three wrong numbers end the pairing")
            try await eq(try await h.pairingStatus(relay).json(DevicePairingStatus.self).state, .failed)
            // Even the right number cannot revive it.
            h.clock.advance(by: 1)
            try await eq(try await h.approvePairing(a, request: request, match: relay.code!).status, .conflict)
            try await eq(try await h.devices(of: a.id).count, 1)
            try await eq(try await h.auditActions(prefix: "device_pairing.").contains("device_pairing.failed"), true)
        }
    }

    func testTwoConcurrentApprovalsAddExactlyOneDevice() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let b = try await h.startPairing(code: try await h.pairingCode(a))
            let request = try await h.firstPending(a)
            // Distinct statements (different signing times), so the replay guard does not decide: the compare-and-swap does.
            var approvals: [DevicePairingApproval] = []
            for offset in 0..<4 {
                approvals.append(try await DevicePairingApproval.sign(request: request, approverDeviceId: a.device!.id, match: b.code!, key: a.device!.biometricKey,
                                                                      now: h.clock.now().addingTimeInterval(-Double(offset))))
            }
            let statuses = try await withThrowingTaskGroup(of: HTTPStatus.self) { group in
                for approval in approvals { group.addTask { try await h.postApproval(a, approval: approval, route: request.pairingId).status } }
                var out: [HTTPStatus] = []
                for try await status in group { out.append(status) }
                return out
            }
            XCTAssertEqual(statuses.filter { $0 == .ok }.count, 1, "\(statuses)")
            XCTAssertTrue(statuses.filter { $0 != .ok }.allSatisfy { $0 == .conflict }, "\(statuses)")
            try await eq(try await h.devices(of: a.id).count, 2)
        }
    }

    func testTheNewDeviceCannotClaimATierOrAnAccount() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let elsewhere = try await h.deviceFirstConsumer()
            // B registers a request key only (no user-verified approval key) and claims D1, an elevation and another account.
            let b = try await h.startPairing(code: try await h.pairingCode(a), purposes: [.request],
                                             extra: ["trustTier": "d1", "elevatedBy": "trusted_device_approval", "accountId": elsewhere.id.description,
                                                     "consumerId": elsewhere.id.description])
            XCTAssertEqual(b.result.status, .created, b.result.text)
            try await eq(try await h.pendingPairings(elsewhere).count, 0, "the account comes from the code, never from the body")
            let request = try await h.firstPending(a)
            let approved = try await h.approvePairing(a, request: request, match: b.code!)
            XCTAssertEqual(approved.status, .ok, approved.text)
            let device = try approved.json(DevicePairingApproveResponse.self).device
            XCTAssertEqual(device.trustTier, .d0, "no user-verified approval key: an approval cannot make it D1")
            XCTAssertEqual(device.consumerId, a.id)
            let record = try await XCTUnwrapAsync(try await DeviceRecord.find(device.id.uuid, on: h.db))
            XCTAssertEqual(record.trustTier, "d0")
            XCTAssertNil(record.elevatedBy)
        }
    }

    func testAPairingForAnAccountWithoutAD1DeviceIsRefusedWithTheRecoveryPath() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let code = try await h.pairingCode(a)
            // The account's only D1 device stops being D1 (removed, or never approved) before the new device starts.
            try await DeviceRecord.query(on: h.db).filter(\.$id == a.device!.id.uuid).set(\.$trustTier, to: "d0").update()
            let refused = try await h.startPairing(code: code)
            XCTAssertEqual(refused.result.status, .conflict, refused.result.text)
            XCTAssertEqual(refused.result.errorCode, .noTrustedDevice)
            XCTAssertEqual(try refused.result.json(APIErrorResponse.self).error.details?["recovery"], "account_recovery")
            XCTAssertTrue(try refused.result.json(APIErrorResponse.self).error.message.contains("recovery"))
            // Nothing was created or alerted, and the device that is left cannot make a code either (same answer).
            try await eq(try await h.pairingRecord(refused.begin.pairingId)?.consumerId, nil)
            let invite = try await h.pairingInvite(a)
            XCTAssertEqual(invite.status, .conflict, invite.text)
            XCTAssertEqual(invite.errorCode, .noTrustedDevice)
            try await eq(try await h.auditActions(prefix: "device_pairing.").contains("device_pairing.refused"), true)
        }
    }

    // MARK: Ceremony, code and status token

    func testTheCeremonyTheCodeAndTheStatusTokenAreSingleUseAndBound() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let first = try await h.startPairing(code: try await h.pairingCode(a))
            XCTAssertEqual(first.result.status, .created)
            // The same ceremony cannot start twice, even with a fresh code.
            let again = try await h.startPairing(code: try await h.pairingCode(a), begin: first.begin)
            XCTAssertEqual(again.result.status, .unauthorized, again.result.text)
            // Proofs made for another pairing id do not verify.
            let opened = try await h.beginPairing().json(DevicePairingBeginResponse.self)
            var foreign = opened
            foreign.pairingId = first.begin.pairingId
            let key = SoftwareP256SigningKey()
            let wrongSubject = try await DeviceEnrollment.register(key: key, purpose: .request, hardwareBacked: true, consumerId: a.id, challenge: opened.challenge)
            let body = try ViadereJSON.encode(DevicePairingStartRequest(challenge: opened.challenge, pairingCode: try await h.pairingCode(a), platform: .iOS,
                                                                        deviceName: nil, keys: [wrongSubject], integrity: nil))
            try await eq(try await h.request(.POST, "/v1/device-pairings/\(opened.pairingId)/start", body: body).status, .unauthorized)
            // A made-up code, and an expired one.
            try await eq(try await h.startPairing(code: "ABCD-EFGH-JKMN").result.status, .unauthorized)
            let stale = try await h.pairingCode(a)
            h.clock.advance(by: DevicePairing.invitationTTL + 1)
            try await eq(try await h.startPairing(code: stale).result.status, .unauthorized)
            // A wrong status token learns nothing.
            try await eq(try await h.pairingStatus(first, token: SecureToken.generate()).status, .unauthorized)
            // A newer code revokes the older one.
            let older = try await h.pairingCode(a)
            _ = try await h.pairingCode(a)
            try await eq(try await h.startPairing(code: older).result.status, .unauthorized)
        }
    }

    // MARK: Abuse controls

    func testStartsAreBudgetedPerAccountAndPerNetworkAndFailClosed() async throws {
        try await withHarness({ config in
            config.rateLimits.devicePairingInvitePerAccount = .perHour(100, burst: 100)
            config.trustedProxyCount = 1
        }) { h in
            let a = try await h.deviceFirstConsumer()
            for index in 0..<5 {
                let started = try await h.startPairing(code: try await h.pairingCode(a), headers: ["X-Forwarded-For": "198.51.100.\(index)"])
                XCTAssertEqual(started.result.status, .created, started.result.text)
            }
            let sixth = try await h.startPairing(code: try await h.pairingCode(a), headers: ["X-Forwarded-For": "198.51.100.77"])
            XCTAssertEqual(sixth.result.status, .tooManyRequests, "five pairings per account per day: \(sixth.result.text)")
        }
        try await withHarness({ $0.rateLimits.devicePairingStartPerIP = .perHour(2, burst: 2) }) { h in
            let a = try await h.deviceFirstConsumer()
            _ = try await h.startPairing(code: try await h.pairingCode(a))
            _ = try await h.startPairing(code: try await h.pairingCode(a))
            try await eq(try await h.startPairing(code: try await h.pairingCode(a)).result.status, .tooManyRequests)
        }
        for namespace in ["device-pairing-begin", "device-pairing-start", "device-pairing-account", "device-pairing-invite", "device-pairing-approve",
                          "device-pairing-status"] {
            XCTAssertTrue(DatabaseRateLimitStore.defaultFailClosed.contains { namespace.hasPrefix($0) }, namespace)
        }
    }

    func testANewPairingCancelsTheOpenOne() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let first = try await h.startPairing(code: try await h.pairingCode(a))
            let firstRequest = try await h.firstPending(a)
            let second = try await h.startPairing(code: try await h.pairingCode(a))
            XCTAssertEqual(second.result.status, .created)
            let pending = try await h.pendingPairings(a)
            XCTAssertEqual(pending.map(\.pairingId), [second.begin.pairingId], "at most one open pairing per account")
            try await eq(try await h.pairingStatus(first).json(DevicePairingStatus.self).state, .cancelled)
            try await eq(try await h.approvePairing(a, request: firstRequest, match: first.code!).status, .conflict)
            let cancelled = try await AuditEventRecord.query(on: h.db).filter(\.$action == "device_pairing.cancelled").all()
            XCTAssertEqual(cancelled.count, 1)
            XCTAssertTrue(cancelled[0].metadataJSON.contains("superseded"))
        }
    }

    func testRepeatedPairingsWarnAndAfterThreeDenialsArriveSilently() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            _ = try await h.signedPost(a, "/v1/push/apns-token", APNsTokenRegistration(token: String(repeating: "cd", count: 32), environment: .sandbox,
                                                                                         bundleId: h.config.appBundleID))
            func pushes() -> Int { h.push.sent.filter { $0.category == DevicePairingService.pushCategory }.count }
            var warnings: [Bool] = []
            for _ in 0..<3 {
                _ = try await h.startPairing(code: try await h.pairingCode(a))
                let request = try await h.firstPending(a)
                warnings.append(request.fatigueWarning)
                try await eq(try await h.denyPairing(a, request.pairingId).status, .ok)
                h.clock.advance(by: 60)
            }
            XCTAssertEqual(warnings, [false, false, true], "the third in an hour shows the warning")
            XCTAssertEqual(pushes(), 3)
            // Paused after three denials: the fourth is still created (the owner can find it) but nobody is woken up.
            let fourth = try await h.startPairing(code: try await h.pairingCode(a))
            XCTAssertEqual(fourth.result.status, .created)
            XCTAssertEqual(pushes(), 3, "no alert while paused")
            try await eq(try await h.pendingPairings(a).first?.fatigueWarning, true)
            try await eq(try await h.pairingRecord(fourth.begin.pairingId)?.silent, true)
        }
    }

    func testThisWasntMeEndsThePairingAndTellsEveryDevice() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let other = try await h.extraDevice(of: a, tier: .d1)
            let b = try await h.startPairing(code: try await h.pairingCode(a))
            let request = try await h.firstPending(a)
            try await eq(try await h.denyPairing(a, request.pairingId, report: true).status, .ok)
            try await eq(try await h.pairingStatus(b).json(DevicePairingStatus.self).state, .denied)
            for device in [a, other] {
                let notices = try await h.signed(device, .GET, "/v1/security-notices").json([SecurityNotice].self)
                XCTAssertTrue(notices.contains { $0.topic == .devicePairingReported }, "every device is told")
            }
            // Answering again changes nothing; approving afterwards is refused.
            try await eq(try await h.denyPairing(a, request.pairingId).status, .ok)
            try await eq(try await h.approvePairing(a, request: request, match: b.code!).status, .conflict)
            try await eq(try await h.pairingRecord(request.pairingId)?.endReason, "report")
            try await eq(try await h.auditActions(prefix: "device_pairing.").contains("device_pairing.reported"), true)
        }
    }

    func testAPasscodeOrRequestKeySignatureNeverApproves() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let b = try await h.startPairing(code: try await h.pairingCode(a))
            let request = try await h.firstPending(a)
            // Signed with the passcode key and labelled as such.
            let passcode = try await h.approvePairing(a, request: request, match: b.code!, key: a.device!.passcodeKey) { $0.assurance = .devicePasscode }
            XCTAssertEqual(passcode.status, .forbidden, passcode.text)
            // Signed with the request key but labelled biometric: the key is not the registered biometric key.
            let requestKey = try await h.approvePairing(a, request: request, match: b.code!, key: a.device!.requestKey)
            XCTAssertEqual(requestKey.status, .unauthorized, requestKey.text)
            // Signed by the right key but naming another approver device.
            let other = try await h.approvePairing(a, request: request, match: b.code!) { $0.approverDeviceId = DeviceID() }
            XCTAssertEqual(other.status, .forbidden, other.text)
            try await eq(try await h.devices(of: a.id).count, 1)
        }
    }

    func testAnApprovedDeviceThatNeverCollectsItsSessionIsRevoked() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let b = try await h.startPairing(code: try await h.pairingCode(a))
            let request = try await h.firstPending(a)
            let device = try await h.approvePairing(a, request: request, match: b.code!).json(DevicePairingApproveResponse.self).device
            h.clock.advance(by: DevicePairing.sessionPickupWindow + 1)
            try await eq(try await h.pairingStatus(b).json(DevicePairingStatus.self).session == nil, true, "too late to collect")
            try await IdentityMaintenance(db: h.db, ctx: h.ctx).run()
            let record = try await XCTUnwrapAsync(try await DeviceRecord.find(device.id.uuid, on: h.db))
            XCTAssertNotNil(record.revokedAt)
            try await eq(try await h.auditActions(prefix: "device_pairing.").contains("device_pairing.unclaimed"), true)
        }
    }

    func testInRequireModeTheNewDeviceMustAttestOverThisPairing() async throws {
        try await withAttestHarness(mode: .require) { h, pki in
            let a = try await h.deviceFirstConsumer(integrity: genuineIntegrity(pki, clock: h.clock))
            let unattested = try await h.startPairing(code: try await h.pairingCode(a))
            XCTAssertEqual(unattested.result.errorCode, .attestationRequired)
            // An attestation over another subject (an account id instead of this pairing id) does not count.
            let wrongBinding = try await h.startPairing(code: try await h.pairingCode(a),
                                                        integrity: genuineIntegrity(pki, clock: h.clock, bindTo: { challenge, _ in (challenge, a.id) }))
            XCTAssertEqual(wrongBinding.result.errorCode, .attestationRequired)
            let b = try await h.startPairing(code: try await h.pairingCode(a), integrity: genuineIntegrity(pki, clock: h.clock))
            XCTAssertEqual(b.result.status, .created, b.result.text)
            let request = try await h.firstPending(a)
            XCTAssertTrue(request.integrityVerified)
            let device = try await h.approvePairing(a, request: request, match: b.code!).json(DevicePairingApproveResponse.self).device
            XCTAssertEqual(device.trustTier, .d1)
            XCTAssertTrue(device.keys.allSatisfy(\.attested))
        }
    }
}

extension TestHarness {
    /// A device-first consumer created with integrity evidence (attest harnesses).
    func deviceFirstConsumer(integrity: @escaping ([DeviceKeyRegistration], String, ConsumerID) throws -> IntegrityEvidence?) async throws -> TestConsumer {
        let created = try await createAccount(integrity: integrity)
        XCTAssertEqual(created.result.status, .created, created.result.text)
        return try XCTUnwrap(created.consumer)
    }
}
