import Fluent
import Foundation
import ViadereCore
import XCTest
@testable import ViadereServerKit

final class DeviceAuthTests: XCTestCase {
    func testSignedRequestSucceedsAndListsDeviceWithKeys() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let response = try await h.signed(consumer, .GET, "/v1/devices")
            XCTAssertEqual(response.status, .ok, response.text)
            let devices = try response.json([Device].self)
            XCTAssertEqual(devices.count, 1)
            XCTAssertEqual(devices[0].keys.count, 3)
            XCTAssertEqual(devices[0].maxAssurance, .biometric)
            XCTAssertNil(devices[0].revokedAt)
        }
    }

    func testBearerAloneIsNotEnoughOnDeviceSignedRoutes() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let response = try await h.request(.GET, "/v1/devices", headers: ["Authorization": "Bearer \(consumer.token)"])
            XCTAssertEqual(response.status, .unauthorized)
            XCTAssertEqual(response.errorCode, .signatureInvalid)
        }
    }

    func testSignatureAloneIsNotEnough() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            var headers = try await h.signedHeaders(consumer, .GET, "/v1/devices", body: Data())
            headers["Authorization"] = nil
            let response = try await h.request(.GET, "/v1/devices", headers: headers)
            XCTAssertEqual(response.status, .unauthorized)
            XCTAssertEqual(response.errorCode, .unauthorized)
        }
    }

    func testBadSignatureIsRejected() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            // Signed with a key that is not the device's request key (e.g. the biometric key).
            let wrongKey = try await h.signed(consumer, .GET, "/v1/devices", signWithKey: consumer.device!.biometricKey)
            XCTAssertEqual(wrongKey.status, .unauthorized)
            XCTAssertEqual(wrongKey.errorCode, .signatureInvalid)
            // Signature over a different path than the one requested.
            let wrongPath = try await h.signed(consumer, .GET, "/v1/devices", signedPath: "/v1/relationships")
            XCTAssertEqual(wrongPath.status, .unauthorized)
            // Signature over a different body.
            let body = Data(#"{"a":1}"#.utf8)
            let headers = try await h.signedHeaders(consumer, .POST, "/v1/relationships", body: Data(#"{"a":2}"#.utf8))
            let wrongBody = try await h.request(.POST, "/v1/relationships", headers: headers, body: body)
            XCTAssertEqual(wrongBody.status, .unauthorized)
            // Garbage signature value.
            var garbage = try await h.signedHeaders(consumer, .GET, "/v1/devices", body: Data())
            garbage["Viadere-Signature"] = String(repeating: "A", count: 86)
            let bad = try await h.request(.GET, "/v1/devices", headers: garbage)
            XCTAssertEqual(bad.status, .unauthorized)
        }
    }

    func testClockSkewIsRejectedBothWays() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let past = try await h.signed(consumer, .GET, "/v1/devices", at: h.clock.now().addingTimeInterval(-400))
            XCTAssertEqual(past.status, .unauthorized)
            XCTAssertEqual(past.errorCode, .clockSkew)
            let future = try await h.signed(consumer, .GET, "/v1/devices", at: h.clock.now().addingTimeInterval(400))
            XCTAssertEqual(future.errorCode, .clockSkew)
            // Within tolerance is fine.
            let ok = try await h.signed(consumer, .GET, "/v1/devices", at: h.clock.now().addingTimeInterval(-200))
            XCTAssertEqual(ok.status, .ok)
        }
    }

    func testReplayedNonceIsRejected() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let headers = try await h.signedHeaders(consumer, .GET, "/v1/devices", body: Data())
            let first = try await h.request(.GET, "/v1/devices", headers: headers)
            XCTAssertEqual(first.status, .ok)
            let replay = try await h.request(.GET, "/v1/devices", headers: headers)
            XCTAssertEqual(replay.status, .unauthorized)
            XCTAssertEqual(replay.errorCode, .replayDetected)
            // Even a captured request replayed on a different path fails (signature covers the path).
            let other = try await h.request(.GET, "/v1/relationships", headers: headers)
            XCTAssertEqual(other.status, .unauthorized)
        }
    }

    func testRevokedDeviceIsRejectedImmediately() async throws {
        try await withHarness { h in
            let first = try await h.readyConsumer()
            // Enroll a second device for the same consumer.
            let second = try await h.enrollDevice(first, name: "iPad")
            let revoke = try await h.signed(first, .DELETE, "/v1/devices/\(second.device!.id)")
            XCTAssertEqual(revoke.status, .ok, revoke.text)
            let rejected = try await h.signed(second, .GET, "/v1/devices")
            XCTAssertEqual(rejected.status, .unauthorized)
            XCTAssertEqual(rejected.errorCode, .signatureInvalid)
            // The first device still works, and sees the revocation.
            let list = try await h.signed(first, .GET, "/v1/devices")
            let devices = try list.json([Device].self)
            XCTAssertEqual(devices.count, 2)
            XCTAssertEqual(devices.filter(\.isRevoked).count, 1)
            let audit = try await AuditEventRecord.query(on: h.db).filter(\.$action == "device.revoked").count()
            XCTAssertEqual(audit, 1)
        }
    }

    func testDeviceMustBelongToTheTokensConsumer() async throws {
        try await withHarness { h in
            let alice = try await h.readyConsumer(name: "Alice")
            let bob = try await h.readyConsumer(name: "Bob")
            var headers = try await h.signedHeaders(bob, .GET, "/v1/devices", body: Data())
            headers["Authorization"] = "Bearer \(alice.token)"
            let response = try await h.request(.GET, "/v1/devices", headers: headers)
            XCTAssertEqual(response.status, .forbidden)
            // A consumer cannot revoke someone else's device either.
            let steal = try await h.signed(alice, .DELETE, "/v1/devices/\(bob.device!.id)")
            XCTAssertEqual(steal.status, .notFound)
        }
    }

    func testEnrollmentRequiresProofOfPossessionAndSingleUseChallenge() async throws {
        try await withHarness { h in
            let consumer = try await h.registerConsumer()
            let auth = ["Authorization": "Bearer \(consumer.token)"]
            let challenge = try await h.request(.POST, "/v1/devices/enroll/begin", headers: auth).json(DeviceEnrollmentChallenge.self).challenge
            let otherChallenge = try await h.request(.POST, "/v1/devices/enroll/begin", headers: auth).json(DeviceEnrollmentChallenge.self).challenge
            let key = SoftwareP256SigningKey()
            // Proof made over a different challenge.
            let forged = try await DeviceEnrollment.register(key: key, purpose: .request, hardwareBacked: true, consumerId: consumer.id, challenge: otherChallenge)
            let bad = try await h.post("/v1/devices", DeviceEnrollRequest(name: "x", platform: .iOS, challenge: challenge, keys: [forged]), headers: auth)
            XCTAssertEqual(bad.status, .unauthorized)
            // Proof by a different key than the one being registered.
            let honest = try await DeviceEnrollment.register(key: key, purpose: .request, hardwareBacked: true, consumerId: consumer.id, challenge: challenge)
            var swapped = honest
            swapped.publicKey = SoftwareP256SigningKey().publicKey
            let swappedResponse = try await h.post("/v1/devices", DeviceEnrollRequest(name: "x", platform: .iOS, challenge: challenge, keys: [swapped]), headers: auth)
            XCTAssertEqual(swappedResponse.status, .unauthorized)
            // A request key is mandatory.
            let approvalOnly = try await DeviceEnrollment.register(key: key, purpose: .approvalBiometric, hardwareBacked: true, consumerId: consumer.id, challenge: challenge)
            let noRequest = try await h.post("/v1/devices", DeviceEnrollRequest(name: "x", platform: .iOS, challenge: challenge, keys: [approvalOnly]), headers: auth)
            XCTAssertEqual(noRequest.status, .unprocessableEntity)
            // The honest enrollment works once, then the challenge is spent.
            let good = try await h.post("/v1/devices", DeviceEnrollRequest(name: "x", platform: .iOS, challenge: challenge, keys: [honest]), headers: auth)
            XCTAssertEqual(good.status, .created, good.text)
            let again = try await h.post("/v1/devices", DeviceEnrollRequest(name: "x", platform: .iOS, challenge: challenge, keys: [honest]), headers: auth)
            XCTAssertEqual(again.status, .unauthorized)
            // A challenge minted for another consumer is useless.
            let mallory = try await h.registerConsumer(name: "Mallory")
            let stolen = try await DeviceEnrollment.register(key: key, purpose: .request, hardwareBacked: true, consumerId: mallory.id, challenge: otherChallenge)
            let cross = try await h.post("/v1/devices", DeviceEnrollRequest(name: "x", platform: .iOS, challenge: otherChallenge, keys: [stolen]),
                                         headers: ["Authorization": "Bearer \(mallory.token)"])
            XCTAssertEqual(cross.status, .unauthorized)
        }
    }

    func testEnrollmentChallengeExpires() async throws {
        try await withHarness { h in
            let consumer = try await h.registerConsumer()
            let auth = ["Authorization": "Bearer \(consumer.token)"]
            let challenge = try await h.request(.POST, "/v1/devices/enroll/begin", headers: auth).json(DeviceEnrollmentChallenge.self).challenge
            let key = SoftwareP256SigningKey()
            let registration = try await DeviceEnrollment.register(key: key, purpose: .request, hardwareBacked: true, consumerId: consumer.id, challenge: challenge)
            h.clock.advance(by: 6 * 60)
            // Access token (15 min) is still valid, but the challenge (5 min) is not.
            let response = try await h.post("/v1/devices", DeviceEnrollRequest(name: "x", platform: .iOS, challenge: challenge, keys: [registration]), headers: auth)
            XCTAssertEqual(response.status, .unauthorized)
        }
    }

    func testReplayGuardIsAtomicUnderConcurrency() async throws {
        try await withHarness { h in
            let guardian = DatabaseReplayGuard(db: h.db)
            let now = h.clock.now()
            let results = try await withThrowingTaskGroup(of: Bool.self) { group -> [Bool] in
                for _ in 0..<8 {
                    group.addTask { try await guardian.registerIfFresh(nonce: "same-nonce-value-0001", scope: "test", expiresAt: now.addingTimeInterval(60), now: now) }
                }
                var out: [Bool] = []
                for try await value in group { out.append(value) }
                return out
            }
            XCTAssertEqual(results.filter { $0 }.count, 1, "exactly one concurrent registration may win")
            // After expiry the nonce is usable again.
            let later = now.addingTimeInterval(120)
            let again = try await guardian.registerIfFresh(nonce: "same-nonce-value-0001", scope: "test", expiresAt: later.addingTimeInterval(60), now: later)
            XCTAssertTrue(again)
        }
    }
}
