import Crypto
import Foundation
import Testing
import ViadereBusinessSDK
import ViadereCore

/// Stage 5 business SDK: number-matched push approvals (ADR-0022), the transparent redraw (ST-MFA-11), the per-requester throttle default (C-14), and the
/// verifier against `docs/protocol/vectors/approval-result-v2.json` (ST-MFA-02 B/V, ST-MFA-03 B).
@Suite("Auth approvals SDK")
struct AuthApprovalSDKTests {
    static let subject = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 7, count: 32)))!
    static let keys = AuthApprovalKeys(sdkSecret: SymmetricKey(data: Data(repeating: 9, count: 32)))

    static func view(_ requestId: String) -> ApprovalRequestView {
        ApprovalRequestView(requestId: requestId, subjectRef: subject, capability: .authChallenge, status: .pending, protection: .serverVisible,
                            expiresAt: Fixtures.now.addingTimeInterval(120), createdAt: Fixtures.now)
    }

    static func draft(_ id: String = "req_0123456789abcdef") -> AuthApprovalDraft {
        AuthApprovalDraft(requestId: id, subject: subject, details: .authentication(AuthenticationDetails(actionDisplay: "Sign in to Example Bank")))
    }

    static func sent(_ request: BusinessHTTPRequest) throws -> AuthApprovalCreateRequest { try ViadereJSON.decode(AuthApprovalCreateRequest.self, from: try #require(request.body)) }

    @Test func theSdkRedrawsOnInUseAndEscalatesToThreeDigitsWithANewIdempotencyKey() async throws {
        let transport = MockTransport()
        try transport.enqueue(status: 409, json: APIErrorResponse(code: .matchCodeInUse, message: "in use"))
        try transport.enqueue(status: 409, json: APIErrorResponse(code: .matchDigitsRequired, message: "3", details: ["digits": "3"]))
        try transport.enqueue(status: 201, json: Self.view("req_0123456789abcdef"))
        let created = try await Fixtures.client(transport).createAuthApproval(Self.draft(), keys: Self.keys, requester: SignInRequester(account: "acct1", clientAddress: "203.0.113.9"),
                                                                             throttle: SignInTriggerThrottle(), now: Fixtures.now)
        let requests = transport.requests
        #expect(requests.count == 3)
        #expect(requests.allSatisfy { $0.url.path == "/v1/business/auth-approvals" })
        #expect(Set(requests.compactMap { $0.headers["Idempotency-Key"] }).count == 3)
        let bodies = try requests.map(Self.sent)
        #expect(bodies[0].numberMatch.digits == 2 && bodies[2].numberMatch.digits == 3)
        #expect(created.code.count == 3 && bodies[2].numberMatch.code == created.code)
        #expect(bodies[2].matchTag == AuthMatchTags.tags(key: AuthSDKKeys.derive(secret: SymmetricKey(data: Data(repeating: 9, count: 32)), label: AuthSDKKeys.matchTagLabel),
                                                         subjectRef: Self.subject, code: created.code)?.tag)
        #expect(bodies[2].matchPrefixTag != nil)
        #expect(bodies[2].authentication?.matchDigits == 3)
        // The pending record the business keeps requires exactly this code.
        #expect(created.pending.numberMatch == .required(code: created.code))
    }

    @Test func twentyCollisionsEndInATypedError() async throws {
        let transport = MockTransport()
        for _ in 0..<20 { try transport.enqueue(status: 409, json: APIErrorResponse(code: .matchCodeInUse, message: "in use")) }
        await #expect(throws: AuthApprovalError.noFreeCode) {
            _ = try await Fixtures.client(transport).createAuthApproval(Self.draft(), keys: Self.keys, requester: SignInRequester(account: "a", clientAddress: "198.51.100.1"),
                                                                       throttle: SignInTriggerThrottle(), now: Fixtures.now)
        }
        #expect(transport.requests.count == 20)
    }

    @Test func thePerRequesterThrottleIsOnByDefault() async throws {
        let throttle = SignInTriggerThrottle()
        #expect(throttle.maxOpen == 3)
        let transport = MockTransport()
        for i in 0..<3 { try transport.enqueue(status: 201, json: Self.view("req_0123456789abcde\(i)")) }
        let client = try Fixtures.client(transport)
        let attacker = SignInRequester(account: "victim-account", clientAddress: "203.0.113.7")
        for i in 0..<3 { _ = try await client.createAuthApproval(Self.draft("req_0123456789abcde\(i)"), keys: Self.keys, requester: attacker, throttle: throttle, now: Fixtures.now) }
        // A fourth trigger from the same /24 for the same account is stopped before any request is sent.
        await #expect(throws: AuthApprovalError.throttled) {
            _ = try await client.createAuthApproval(Self.draft("req_0123456789abcdez"), keys: Self.keys,
                                                    requester: SignInRequester(account: "victim-account", clientAddress: "203.0.113.200"), throttle: throttle, now: Fixtures.now)
        }
        #expect(transport.requests.count == 3)
        // The victim on another network is not affected.
        _ = try await throttle.acquire(SignInRequester(account: "victim-account", clientAddress: "2001:db8:1::1"), now: Fixtures.now)
        #expect(SignInRequester(account: "a", clientAddress: "2001:db8:abcd:12ff::1").networkPrefix == SignInRequester(account: "a", clientAddress: "2001:0db8:abcd:1200::9").networkPrefix)
    }

    @Test func theVerifierAgreesWithEveryVector() async throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        let v = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: url.appendingPathComponent("docs/protocol/vectors/approval-result-v2.json"))) as? [String: Any])
        let context = v["context"] as! [String: Any]
        let device = v["device_key"] as! [String: Any]
        let business = BusinessID(context["aud"] as! String)!
        let subject = SubjectRef(context["sub"] as! String)!
        let key = EnrolledApprovalKey(kid: device["kid"] as! String, publicKey: try DevicePublicKey(base64URL: device["public_x963_b64url"] as! String), subject: subject, assurance: .biometric)
        let store = InMemoryApprovalKeyStore()
        await store.add(key)
        let now = Date(timeIntervalSince1970: TimeInterval(v["now"] as! Int))
        let details = ApprovalSubject.authentication(AuthenticationDetails(actionDisplay: "Sign in to Example Bank", matchDigits: 2))
        for vector in v["cases"] as! [[String: Any]] {
            let verifier = ApprovalVerifier(businessId: business, keys: store, replayCache: InMemoryReplayGuard(), clock: { now })
            let pending = PendingApproval(requestId: context["request_id"] as! String, subject: subject, challenge: context["challenge"] as! String, details: details,
                                          numberMatch: vector["expectation"] as? String == "required" ? .required(code: context["code"] as! String) : .notRequested,
                                          expiresAt: now.addingTimeInterval(120))
            do {
                let decision = try await verifier.decision(of: vector["jws"] as! String, for: pending)
                #expect(decision.rawValue == vector["outcome"] as? String, "\(vector["name"]!)")
            } catch {
                let expected = vector["error"] as? String
                #expect(expected != nil && String(describing: error).hasPrefix(expected!), "\(vector["name"]!): \(error)")
            }
        }
        // ST-MFA-03: verify consumes once.
        let verifier = ApprovalVerifier(businessId: business, keys: store, replayCache: InMemoryReplayGuard(), clock: { now })
        let first = (v["cases"] as! [[String: Any]])[0]["jws"] as! String
        let pending = PendingApproval(requestId: context["request_id"] as! String, subject: subject, challenge: context["challenge"] as! String, details: details,
                                      numberMatch: .required(code: "47"), expiresAt: now.addingTimeInterval(120))
        _ = try await verifier.verify(result: first, for: pending)
        await #expect(throws: ApprovalVerificationError.replayed) { _ = try await verifier.verify(result: first, for: pending) }
    }

    @Test func sessionHandlesFollowTheVectors() throws {
        let keys = AuthApprovalKeys(sdkSecret: SymmetricKey(data: Data(0..<32)))
        #expect(keys.sessionHandle(for: "sess-1f2e3d").count == 43)
        #expect(keys.sessionHandle(for: "a") != keys.sessionHandle(for: "b"))
    }
}
