import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

struct ClientEnv {
    let secrets = InMemorySecretStore()
    let keys: SoftwareDeviceKeyStore
    let records: SecretDeviceRecordStore
    let tokens: SecretTokenStore
    let deviceId = DeviceID()
    let consumerId = PreviewData.consumerId

    init() async throws {
        keys = SoftwareDeviceKeyStore(secrets: InMemorySecretStore())
        records = SecretDeviceRecordStore(secrets: secrets)
        tokens = SecretTokenStore(secrets: secrets)
        _ = try await keys.createKey(for: .request)
        try await records.save(DeviceRecord(deviceId: deviceId, consumerId: consumerId, name: "Test", purposes: [.request], enrolledAt: Date()))
        try await tokens.save(TokenSet(consumerId: consumerId, accessToken: "tok-1", accessExpiresAt: Date().addingTimeInterval(900)))
    }

    func client(transport: FakeTransport, refresher: any TokenRefresher = CountingRefresher(),
                onRejected: @escaping @Sendable () -> Void = {}) -> (APIClient, SessionManager) {
        let signer = DeviceRequestSigner(records: records, keys: keys)
        let executor = RequestExecutor(baseURL: URL(string: "http://localhost:8080")!, transport: transport, signer: signer)
        let sessions = SessionManager(store: tokens, refresher: refresher)
        return (APIClient(executor: executor, sessions: sessions, onDeviceRejected: onRejected), sessions)
    }
}

@Suite("API client")
struct APIClientTests {
    @Test func signsDeviceSignedRequestsPerSpec() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { _, _ in json("[]") }
        let (client, _) = env.client(transport: transport)

        let _: [Device] = try await client.call(APIRoutes.devicesList)
        let request = try #require(transport.requests.first)
        #expect(request.headers["Authorization"] == "Bearer tok-1")
        #expect(request.body == nil)

        let signed = try SignedRequestHeaders(headers: request.headers)
        #expect(signed.deviceId == env.deviceId)
        let publicKey = try #require(try await env.keys.requireKey(for: .request).publicKey as DevicePublicKey?)
        try RequestVerifier().verify(method: "GET", pathAndQuery: pathAndQuery(request.url), body: Data(), headers: signed,
                                     publicKey: publicKey, now: Date())
    }

    @Test func signatureCoversPathQueryAndBodyBytes() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { _, _ in json(#"{"items":[]}"#) }
        let (client, _) = env.client(transport: transport)
        let _: Page<InteractionEnvelope> = try await client.call(APIRoutes.interactionsList, query: [("limit", "30"), ("status", "pending")])
        let request = try #require(transport.requests.first)
        #expect(pathAndQuery(request.url) == "/v1/interactions?limit=30&status=pending")
        let signed = try SignedRequestHeaders(headers: request.headers)
        let publicKey = try await env.keys.requireKey(for: .request).publicKey
        let verifier = RequestVerifier()
        try verifier.verify(method: "GET", pathAndQuery: "/v1/interactions?limit=30&status=pending", body: Data(), headers: signed, publicKey: publicKey, now: Date())
        #expect(throws: RequestVerificationError.self) {
            try verifier.verify(method: "GET", pathAndQuery: "/v1/interactions?limit=30&status=approved", body: Data(), headers: signed, publicKey: publicKey, now: Date())
        }

        // POST body: signed over the exact bytes sent.
        let post = FakeTransport { _, _ in json(#"{"interactionId":"\#(InteractionID())","businessId":"\#(BusinessID())","status":"approved"}"#) }
        let (client2, _) = env.client(transport: post)
        let signedDecision = SignedDecision(payload: "abc", signature: "def")
        let id = InteractionID()
        _ = try await client2.call(APIRoutes.interactionDecide, params: ["interactionId": id.description],
                                   body: DecideInteractionRequest(signedDecision: signedDecision, channel: .inApp))
        let sent = try #require(post.requests.first)
        let body = try #require(sent.body)
        let headers = try SignedRequestHeaders(headers: sent.headers)
        try verifier.verify(method: "POST", pathAndQuery: "/v1/interactions/\(id)/decision", body: body, headers: headers, publicKey: publicKey, now: Date())
        #expect(sent.headers["Content-Type"] == "application/json")
    }

    @Test func publicRoutesCarryNoCredentials() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { _, _ in json(#"{"items":[]}"#) }
        let (client, _) = env.client(transport: transport)
        let _: Page<BusinessSummary> = try await client.call(APIRoutes.directorySearch, query: [("q", "cafe")])
        let request = try #require(transport.requests.first)
        #expect(request.headers["Authorization"] == nil)
        #expect(request.headers[ViadereHeader.signature] == nil)
    }

    @Test func emptyPostBodiesSendEmptyObject() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { _, _ in HTTPResponse(status: 204) }
        let (client, _) = env.client(transport: transport)
        let _: EmptyBody = try await client.call(APIRoutes.logout)
        #expect(transport.requests.first?.body == Data("{}".utf8))
    }

    @Test func unauthorizedTriggersOneRefreshAndRetry() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { request, _ in
            request.headers["Authorization"] == "Bearer tok-1" ? json(401, errorBody("unauthorized")) : json("[]")
        }
        let refresher = CountingRefresher()
        let (client, _) = env.client(transport: transport, refresher: refresher)
        let _: [Device] = try await client.call(APIRoutes.devicesList)
        #expect(await refresher.calls == 1)
        #expect(transport.requests.count == 2)
        #expect(transport.requests.last?.headers["Authorization"] == "Bearer fresh-1")
        // retry is re-signed with a new nonce
        #expect(transport.requests[0].headers[ViadereHeader.nonce] != transport.requests[1].headers[ViadereHeader.nonce])
    }

    @Test func concurrentUnauthorizedRequestsShareOneRefresh() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { request, _ in
            request.headers["Authorization"] == "Bearer tok-1" ? json(401, errorBody("unauthorized")) : json("[]")
        }
        let refresher = CountingRefresher(delay: .milliseconds(150))
        let (client, sessions) = env.client(transport: transport, refresher: refresher)
        try await withThrowingTaskGroup(of: Int.self) { group in
            for _ in 0..<8 { group.addTask { let d: [Device] = try await client.call(APIRoutes.devicesList); return d.count } }
            for try await _ in group {}
        }
        #expect(await refresher.calls == 1)
        #expect(await sessions.refreshCount == 1)
        #expect(await sessions.tokens()?.accessToken == "fresh-1")
    }

    @Test func expiredTokenRefreshesProactively() async throws {
        let env = try await ClientEnv()
        try await env.tokens.save(TokenSet(consumerId: env.consumerId, accessToken: "old", accessExpiresAt: Date().addingTimeInterval(5)))
        let transport = FakeTransport { _, _ in json("[]") }
        let refresher = CountingRefresher()
        let (client, _) = env.client(transport: transport, refresher: refresher)
        let _: [Device] = try await client.call(APIRoutes.devicesList)
        #expect(await refresher.calls == 1)
        #expect(transport.requests.first?.headers["Authorization"] == "Bearer fresh-1")
    }

    @Test func failedRefreshClearsSession() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { _, _ in json(401, errorBody("unauthorized")) }
        let (client, sessions) = env.client(transport: transport, refresher: FailingRefresher())
        await #expect(throws: APIError.sessionExpired) { let _: [Device] = try await client.call(APIRoutes.devicesList) }
        #expect(await sessions.tokens() == nil)
    }

    @Test func serverErrorsMapToTypedErrors() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { _, _ in json(429, errorBody("rate_limited", "slow down")) }
        let (client, _) = env.client(transport: transport)
        do {
            let _: [Device] = try await client.call(APIRoutes.devicesList)
            Issue.record("expected throw")
        } catch let error as APIError {
            #expect(error.code == .rateLimited)
            #expect(error.userMessage.contains("Too many"))
        }
    }

    @Test func repeatedSignatureRejectionMeansDeviceRevoked() async throws {
        let env = try await ClientEnv()
        let flag = Flag()
        let transport = FakeTransport { _, _ in json(401, errorBody("signature_invalid")) }
        let (client, _) = env.client(transport: transport, onRejected: { flag.set() })
        await #expect(throws: APIError.deviceRejected) { let _: [Device] = try await client.call(APIRoutes.devicesList) }
        #expect(flag.value)
        #expect(transport.requests.count == 2)
    }

    @Test func notEnrolledWithoutDeviceRecord() async throws {
        let env = try await ClientEnv()
        try await env.records.clear()
        let transport = FakeTransport { _, _ in json("[]") }
        let (client, _) = env.client(transport: transport)
        await #expect(throws: APIError.notEnrolled) { let _: [Device] = try await client.call(APIRoutes.devicesList) }
        #expect(transport.requests.isEmpty)
    }

    @Test func apiRefresherRotatesThroughPublicRoute() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { request, _ in
            #expect(request.url.path == "/v1/auth/refresh")
            #expect(request.headers["Authorization"] == nil)      // the refresh token is the credential
            #expect(request.headers[ViadereHeader.signature] == nil)
            return json(#"{"consumerId":"\#(PreviewData.consumerId)","accessToken":"new","tokenType":"Bearer","expiresAt":"2099-10-27T12:00:00.000Z","refreshToken":"r2"}"#)
        }
        let executor = RequestExecutor(baseURL: URL(string: "http://localhost:8080")!, transport: transport, signer: nil)
        let refreshed = try await APITokenRefresher(executor: executor).refresh(
            current: TokenSet(consumerId: env.consumerId, accessToken: "old", accessExpiresAt: Date(), refreshToken: "r1"))
        #expect(refreshed.accessToken == "new")
        #expect(refreshed.refreshToken == "r2")
        let sent = try #require(transport.requests.first?.body)
        #expect(String(decoding: sent, as: UTF8.self) == #"{"refreshToken":"r1"}"#)
    }

    @Test func refreshWithoutRefreshTokenOrAfterRejectionMeansSignIn() async throws {
        let transport = FakeTransport { _, _ in json(401, errorBody("unauthorized")) }
        let executor = RequestExecutor(baseURL: URL(string: "http://localhost:8080")!, transport: transport, signer: nil)
        let refresher = APITokenRefresher(executor: executor)
        await #expect(throws: APIError.sessionExpired) { _ = try await refresher.refresh(current: nil) }
        let noRefresh = TokenSet(consumerId: PreviewData.consumerId, accessToken: "a", accessExpiresAt: Date())
        await #expect(throws: APIError.sessionExpired) { _ = try await refresher.refresh(current: noRefresh) }
        #expect(transport.requests.isEmpty)
        let withRefresh = TokenSet(consumerId: PreviewData.consumerId, accessToken: "a", accessExpiresAt: Date(), refreshToken: "r")
        await #expect(throws: APIError.sessionExpired) { _ = try await refresher.refresh(current: withRefresh) }
    }

    @Test func rotatedRefreshTokensAreNeverReusedAcrossProcesses() async throws {
        // Two "processes" (two SessionManagers sharing one token store and one file lock) both see an expired token.
        // Refresh tokens are single-use, so the second must adopt the first's result instead of refreshing again.
        let env = try await ClientEnv()
        try await env.tokens.save(TokenSet(consumerId: env.consumerId, accessToken: "old", accessExpiresAt: Date().addingTimeInterval(-10), refreshToken: "r0"))
        let lockURL = FileManager.default.temporaryDirectory.appendingPathComponent("viadere-lock-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: lockURL) }
        let refresher = CountingRefresher(delay: .milliseconds(120))
        let a = SessionManager(store: env.tokens, refresher: refresher, lock: FileCrossProcessLock(url: lockURL))
        let b = SessionManager(store: env.tokens, refresher: refresher, lock: FileCrossProcessLock(url: lockURL))
        async let ta = a.validAccessToken()
        async let tb = b.validAccessToken()
        let (x, y) = try await (ta, tb)
        #expect(x == y)
        #expect(await refresher.calls == 1)
    }
}

final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false
    func set() { lock.lock(); flag = true; lock.unlock() }
    var value: Bool { lock.lock(); defer { lock.unlock() }; return flag }
}
