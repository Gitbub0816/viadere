@preconcurrency import Crypto
import Foundation
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// A scripted Didit: records what the adapter sends and returns canned decisions. No network.
final class FakeDidit: DiditAPI, @unchecked Sendable {
    private let lock = NSLock()
    private var _created: [(workflow: String, vendorData: String)] = []
    private var _deleted: [(session: String, instruction: String)] = []
    private var _usersDeleted: [String] = []
    private var _decisions: [String: [String: JSONValue]] = [:]
    private var _sessionByVendor: [String: String] = [:]
    private var createFailures = 0
    private var decisionFailures = 0
    private var deleteFailures = 0
    private var decisionFetches = 0
    private var _deleteCalls = 0

    var created: [(workflow: String, vendorData: String)] { lock.withLock { _created } }
    var deleted: [(session: String, instruction: String)] { lock.withLock { _deleted } }
    var usersDeleted: [String] { lock.withLock { _usersDeleted } }
    /// Every `deleteSession` call, failed or not.
    var deleteCalls: Int { lock.withLock { _deleteCalls } }
    var fetches: Int { lock.withLock { decisionFetches } }
    func failCreate(_ n: Int) { lock.withLock { createFailures = n } }
    func failDecision(_ n: Int) { lock.withLock { decisionFailures = n } }
    func failDelete(_ n: Int) { lock.withLock { deleteFailures = n } }
    func setDecision(_ session: String, _ decision: [String: JSONValue]) { lock.withLock { _decisions[session] = decision } }
    func session(forVendorData vendor: String) -> String? { lock.withLock { _sessionByVendor[vendor] } }

    func createSession(workflowId: String, vendorData: String) async throws -> DiditSession {
        try lock.withLock {
            if createFailures > 0 {
                createFailures -= 1
                throw DiditError.unavailable
            }
            _created.append((workflowId, vendorData))
            let id = UUID().uuidString.lowercased()
            _sessionByVendor[vendorData] = id
            return DiditSession(sessionId: id, sessionToken: "tok_" + id.prefix(8))
        }
    }

    func decision(sessionId: String) async throws -> [String: JSONValue] {
        try lock.withLock {
            decisionFetches += 1
            if decisionFailures > 0 {
                decisionFailures -= 1
                throw DiditError.unavailable
            }
            guard let decision = _decisions[sessionId] else { return ["session_id": .string(sessionId), "status": .string("In Progress")] }
            return decision
        }
    }

    func deleteSession(sessionId: String, instructionId: String) async throws {
        try lock.withLock {
            _deleteCalls += 1
            if deleteFailures > 0 {
                deleteFailures -= 1
                throw DiditError.unavailable
            }
            _deleted.append((sessionId, instructionId))
        }
    }

    func deleteUser(vendorData: String) async throws { lock.withLock { _usersDeleted.append(vendorData) } }

    /// A decision in Didit's V3 shape, with the personal data the real one carries.
    static func decision(session: String, vendorData: String, status: String = "Approved", dob: String = "1990-01-01", first: String = "Jane", last: String = "Doe",
                         document: String = "Approved", liveness: String? = "Approved", face: String? = "Approved", expires: String = "2031-06-02", age: Double? = 24.3) -> [String: JSONValue] {
        var liveCheck: [String: JSONValue] = ["node_id": .string("feature_liveness_1"), "status": .string(liveness ?? ""), "score": .number(89.92),
                                              "video_url": .string("https://media.example/video.mp4"), "reference_image": .string("https://media.example/ref.jpg")]
        if let age { liveCheck["age_estimation"] = .number(age) }
        var object: [String: JSONValue] = [
            "session_id": .string(session), "vendor_data": .string(vendorData), "status": .string(status),
            "id_verifications": .array([.object([
                "node_id": .string("feature_ocr_1"), "status": .string(document), "document_type": .string("Driver License"), "document_number": .string("D1234567"),
                "portrait_image": .string("https://media.example/portrait.jpg"), "front_image": .string("https://media.example/front.jpg"),
                "date_of_birth": .string(dob), "age": .integer(36), "expiration_date": .string(expires), "issuing_state": .string("USA"),
                "first_name": .string(first), "last_name": .string(last), "formatted_address": .string("1 Main Street, Mesa, AZ 85201"),
            ])]),
        ]
        if liveness != nil { object["liveness_checks"] = .array([.object(liveCheck)]) }
        if let face { object["face_matches"] = .array([.object(["node_id": .string("feature_face_match_1"), "status": .string(face), "score": .number(94.1)])]) }
        return object
    }
}

/// Webhook verification against vectors generated with Didit's documented algorithm (Python `json.dumps`), so the check is independent of
/// our own canonicalization.
final class DiditWebhookTests: XCTestCase {
    static let secret = "whsec_test_secret"
    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    /// `json.dumps(body, sort_keys=True, separators=(",", ":"))` (what Didit transmits; ASCII escapes, floats as Python prints them).
    static let rawBody = #"{"created_at":1799999994,"decision":{"big":1e+16,"n":12345678901,"neg":-0.5,"ratio":0.1,"score":87.5,"small":1e-05},"event_id":"9c0c8b8a-1111-4222-9333-444444444444","metadata":{"a":[1,2.5,95.0,null,true,false],"b":1,"nom":"Jos\u00e9 \"Q\" \\ \u0001 \t\n","z":{"10":4,"9":5,"Z":3,"e":2,"\u00e9":1,"\ud83d\ude00":6}},"session_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","status":"Approved","timestamp":1800000000,"vendor_data":"v-1","webhook_type":"status.updated"}"#
    static let canonical = #"{"created_at":1799999994,"decision":{"big":10000000000000000,"n":12345678901,"neg":-0.5,"ratio":0.1,"score":87.5,"small":1e-05},"event_id":"9c0c8b8a-1111-4222-9333-444444444444","metadata":{"a":[1,2.5,95,null,true,false],"b":1,"nom":"José \"Q\" \\ \u0001 \t\n","z":{"10":4,"9":5,"Z":3,"e":2,"é":1,"😀":6}},"session_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","status":"Approved","timestamp":1800000000,"vendor_data":"v-1","webhook_type":"status.updated"}"#
    static let v2 = "34bbeb2b7b42593d33c074107a36e9a8641d36813a14d722ddc2634899ce094a"
    static let raw = "71e2e787aa7f6b909b6e60a54e7d2b4f47c04255b715094744012dc43afda2a9"

    func verifier(_ secrets: [String] = [secret], tolerance: TimeInterval = 300) -> DiditWebhookVerifier { DiditWebhookVerifier(secrets: secrets, tolerance: tolerance) }
    var body: Data { Data(Self.rawBody.utf8) }
    func headers(v2: String? = v2, v2Previous: String? = nil, raw: String? = nil, rawPrevious: String? = nil, timestamp: String? = "1800000000") -> DiditWebhookVerifier.Headers {
        .init(signatureV2: v2, signatureV2Previous: v2Previous, signature: raw, signaturePrevious: rawPrevious, timestamp: timestamp)
    }

    func testOurCanonicalFormIsByteForByteDidits() throws {
        let parsed = try JSONDecoder().decode(JSONValue.self, from: body)
        XCTAssertEqual(String(decoding: DiditCanonicalJSON.serialize(parsed), as: UTF8.self), Self.canonical)
        let mac = Hex.encode(HMAC<SHA256>.authenticationCode(for: DiditCanonicalJSON.serialize(parsed), using: SymmetricKey(data: Data(Self.secret.utf8))))
        XCTAssertEqual(mac, Self.v2)
    }

    func testAValidV2SignatureVerifies() throws {
        let object = try verifier().verify(body: body, headers: headers(), now: Self.now)
        XCTAssertEqual(object["session_id"], .string("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
    }

    func testTheRawBodySignatureVerifiesAndIsIndependentOfV2() throws {
        XCTAssertNoThrow(try verifier().verify(body: body, headers: headers(v2: nil, raw: Self.raw), now: Self.now))
        // The raw signature does not verify a re-encoded body.
        let reencoded = try JSONEncoder().encode(try JSONDecoder().decode(JSONValue.self, from: body))
        XCTAssertThrowsError(try verifier().verify(body: reencoded, headers: headers(v2: nil, raw: Self.raw), now: Self.now))
        // ...but V2 still does (middleware-safe), because it signs the canonical form.
        XCTAssertNoThrow(try verifier().verify(body: reencoded, headers: headers(), now: Self.now))
    }

    func testInvalidTamperedAndMissingSignaturesAreRefused() throws {
        func fails(_ headers: DiditWebhookVerifier.Headers, body: Data? = nil, _ expected: DiditWebhookVerifier.Failure, secrets: [String] = [Self.secret]) {
            XCTAssertThrowsError(try verifier(secrets).verify(body: body ?? self.body, headers: headers, now: Self.now)) { XCTAssertEqual($0 as? DiditWebhookVerifier.Failure, expected) }
        }
        fails(headers(v2: String(repeating: "0", count: 64)), .badSignature)
        fails(headers(v2: Self.v2.uppercased().replacingOccurrences(of: "3", with: "4")), .badSignature)
        fails(headers(v2: nil), .noSignature)
        fails(headers(), .noSecret, secrets: [])
        fails(headers(), .badSignature, secrets: ["whsec_other"])
        // A changed decision under an unchanged signature.
        let forged = Self.rawBody.replacingOccurrences(of: "\"status\":\"Approved\"", with: "\"status\":\"Declined\"")
        fails(headers(), body: Data(forged.utf8), .badSignature)
        // Not JSON, and not an object.
        fails(headers(), body: Data("nope".utf8), .malformedBody)
        fails(headers(), body: Data("[1]".utf8), .malformedBody)
    }

    func testTheDeprecatedSimpleSignatureIsNeverAccepted() throws {
        // X-Signature-Simple signs only "{timestamp}:{session_id}:{status}:{webhook_type}"; there is no way to present it.
        let simple = Hex.encode(HMAC<SHA256>.authenticationCode(for: Data("1800000000:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:Approved:status.updated".utf8),
                                                                using: SymmetricKey(data: Data(Self.secret.utf8))))
        XCTAssertThrowsError(try verifier().verify(body: body, headers: headers(v2: simple), now: Self.now))
        XCTAssertThrowsError(try verifier().verify(body: body, headers: headers(v2: nil, raw: simple), now: Self.now))
    }

    func testStaleAndMissingTimestampsAreRefused() {
        for timestamp in ["1799999699", "1800000301", "0"] {
            XCTAssertThrowsError(try verifier().verify(body: body, headers: headers(timestamp: timestamp), now: Self.now)) { XCTAssertEqual($0 as? DiditWebhookVerifier.Failure, .staleTimestamp) }
        }
        for timestamp in [nil, "", "abc", "-5", "1800000000000000"] {
            XCTAssertThrowsError(try verifier().verify(body: body, headers: headers(timestamp: timestamp), now: Self.now)) { XCTAssertEqual($0 as? DiditWebhookVerifier.Failure, .missingTimestamp) }
        }
        XCTAssertNoThrow(try verifier().verify(body: body, headers: headers(timestamp: "1799999700"), now: Self.now), "exactly at the tolerance")
        XCTAssertNoThrow(try verifier().verify(body: body, headers: headers(timestamp: "1800000300"), now: Self.now))
    }

    func testSecretRotationAcceptsThePreviousSignatureForTheOverlap() throws {
        // After a rotation Didit signs with the new secret and adds *-Previous headers made with the old one.
        let newSecret = "whsec_rotated_new"
        let newMac = Hex.encode(HMAC<SHA256>.authenticationCode(for: DiditCanonicalJSON.serialize(try JSONDecoder().decode(JSONValue.self, from: body)), using: SymmetricKey(data: Data(newSecret.utf8))))
        // We still hold only the old secret: the -Previous header (old secret) matches.
        XCTAssertNoThrow(try verifier([Self.secret]).verify(body: body, headers: headers(v2: newMac, v2Previous: Self.v2), now: Self.now))
        // We deployed the new secret: the regular header matches (the previous header is ignored).
        XCTAssertNoThrow(try verifier([newSecret]).verify(body: body, headers: headers(v2: newMac, v2Previous: Self.v2), now: Self.now))
        // During the overlap we may hold both secrets.
        XCTAssertNoThrow(try verifier([newSecret, Self.secret]).verify(body: body, headers: headers(v2: newMac, v2Previous: Self.v2), now: Self.now))
        // The raw-body previous header works too.
        XCTAssertNoThrow(try verifier([Self.secret]).verify(body: body, headers: headers(v2: nil, raw: "0" + String(Self.raw.dropFirst()), rawPrevious: Self.raw), now: Self.now))
        // Neither matches: refused.
        XCTAssertThrowsError(try verifier(["whsec_unrelated"]).verify(body: body, headers: headers(v2: newMac, v2Previous: Self.v2), now: Self.now))
    }

    // MARK: Decision mapping (taxonomy)

    func map(_ decision: [String: JSONValue], session: String = "s1", attempt: String = "a1") -> DiditDecisionMapper.Mapped {
        DiditDecisionMapper.map(decision: decision, expectedSession: session, expectedAttempt: attempt, now: Self.now)
    }

    func testAnApprovedDocumentLivenessAndFaceMatchIsAVerifiedIdentity() throws {
        let mapped = map(FakeDidit.decision(session: "s1", vendorData: "a1"))
        XCTAssertEqual(mapped.state, .approved)
        let claims = try XCTUnwrap(mapped.claims)
        XCTAssertEqual(claims.method, .diditDocumentLiveness)
        XCTAssertEqual(claims.issuer, "didit:USA")
        XCTAssertEqual(ClaimsBuilder.meetsThreshold(claims, years: 21, now: Self.now), true)
        XCTAssertEqual([claims.givenName, claims.familyName], ["Jane", "Doe"])
        // The labels this method may establish, and nothing else.
        let built = try XCTUnwrap(ClaimsBuilder.build(capability: .ageMinimum, parameters: ["years": .integer(21)], claims: claims, audience: BusinessID(), now: Self.now))
        XCTAssertEqual(built.label, .verifiedAgeThreshold)
        XCTAssertEqual(built.provenance.assurance.evidence, .documentWithBiometricMatch)
        XCTAssertEqual(built.provenance.assurance.issuerTrust, .providerAttested)
    }

    func testAnyMissingOrWeakerCheckIsNotVerified() {
        for decision in [FakeDidit.decision(session: "s1", vendorData: "a1", liveness: nil), FakeDidit.decision(session: "s1", vendorData: "a1", face: nil),
                         FakeDidit.decision(session: "s1", vendorData: "a1", document: "Declined"), FakeDidit.decision(session: "s1", vendorData: "a1", liveness: "In Review"),
                         FakeDidit.decision(session: "s1", vendorData: "a1", face: "Declined")] {
            let mapped = map(decision)
            XCTAssertNil(mapped.claims)
            XCTAssertEqual(mapped.state, .notApproved(reason: mapped.estimatedAgeOnly ? "estimate_only" : "incomplete_checks"))
        }
    }

    func testASelfieAgeEstimateIsNeverAVerifiedAge() throws {
        // Liveness with an age estimate, but no approved document and no face match: an estimate, recorded as such.
        var decision = FakeDidit.decision(session: "s1", vendorData: "a1", document: "Not Finished", face: nil)
        decision["id_verifications"] = nil
        let mapped = map(decision)
        XCTAssertNil(mapped.claims)
        XCTAssertTrue(mapped.estimatedAgeOnly)
        XCTAssertEqual(mapped.state, .notApproved(reason: "estimate_only"))
        // And even an estimate claim dressed up as a verified one cannot be built or become evidence.
        let estimate = VerificationAssuranceMapper.Observation(method: .diditAgeEstimation, validatedAgeStatement: true, estimatedAgeOnly: true)
        XCTAssertEqual(VerificationAssuranceMapper.labels(for: estimate), [.estimatedAge])
        XCTAssertNil(VerificationProvenance(method: .diditAgeEstimation, issuer: "didit:USA", label: .estimatedAge,
                                            assurance: VerificationAssuranceMapper.providerDimensions(verifiedAt: Self.now, validUntil: Self.now, risk: .high),
                                            expiresAt: Self.now, revocation: .notApplicable).evidenceHolding())
    }

    func testTheDecisionMustBeForTheSessionAndAttemptWeCreated() {
        XCTAssertEqual(map(FakeDidit.decision(session: "other", vendorData: "a1")).state, .notApproved(reason: "binding_mismatch"))
        XCTAssertEqual(map(FakeDidit.decision(session: "s1", vendorData: "someone-else")).state, .notApproved(reason: "binding_mismatch"))
    }

    func testStatesAndExpiredDocuments() {
        XCTAssertEqual(DiditDecisionMapper.state(of: ["status": .string("Declined")]), .notApproved(reason: "declined"))
        XCTAssertEqual(DiditDecisionMapper.state(of: ["status": .string("In Review")]), .notApproved(reason: "in_review"))
        XCTAssertEqual(DiditDecisionMapper.state(of: ["status": .string("Abandoned")]), .notApproved(reason: "abandoned"))
        XCTAssertEqual(DiditDecisionMapper.state(of: ["status": .string("Expired")]), .notApproved(reason: "expired"))
        for pending in ["In Progress", "Not Started", "Awaiting User", "Resubmitted", "something new"] {
            XCTAssertEqual(DiditDecisionMapper.state(of: ["status": .string(pending)]), .inProgress, pending)
        }
        XCTAssertEqual(map(FakeDidit.decision(session: "s1", vendorData: "a1", expires: "2020-01-01")).state, .notApproved(reason: "document_expired"))
    }
}
