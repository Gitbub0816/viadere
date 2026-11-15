import Foundation
import ViadereCore
@testable import ViadereBusinessSDK

/// A scripted transport: returns queued responses (or throws queued errors) and records every request.
final class MockTransport: BusinessTransport, @unchecked Sendable {
    enum Step { case response(BusinessHTTPResponse), failure(any Error) }

    private let lock = NSLock()
    private var steps: [Step] = []
    private var recorded: [BusinessHTTPRequest] = []

    var requests: [BusinessHTTPRequest] { lock.withLock { recorded } }

    func enqueue(_ steps: Step...) { lock.withLock { self.steps.append(contentsOf: steps) } }

    func enqueue(status: Int, json: some Encodable, headers: [String: String] = [:]) throws {
        let body = try ViadereJSON.encode(json)
        enqueue(.response(BusinessHTTPResponse(status: status, headers: headers, body: body)))
    }

    func enqueue(status: Int, raw: String = "", headers: [String: String] = [:]) {
        enqueue(.response(BusinessHTTPResponse(status: status, headers: headers, body: Data(raw.utf8))))
    }

    func send(_ request: BusinessHTTPRequest) async throws -> BusinessHTTPResponse {
        let step: Step? = lock.withLock {
            recorded.append(request)
            return steps.isEmpty ? nil : steps.removeFirst()
        }
        switch step {
        case .response(let response): return response
        case .failure(let error): throw error
        case nil: return BusinessHTTPResponse(status: 500, body: Data("{}".utf8))
        }
    }
}

struct NetworkDown: Error {}

/// Records the delays the client asked to sleep instead of sleeping.
final class RecordedSleeps: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [TimeInterval] = []
    var delays: [TimeInterval] { lock.withLock { values } }
    func record(_ delay: TimeInterval) { lock.withLock { values.append(delay) } }
}

enum Fixtures {
    static let key = "vdk_test_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
    static let relationship = RelationshipID(UUID(uuidString: "11111111-2222-4333-8444-555555555555")!)
    static let now = Date(timeIntervalSince1970: 1_800_000_000)

    static func client(_ transport: MockTransport, retry: RetryPolicy = RetryPolicy(maxAttempts: 3, baseDelay: 0.5, maxDelay: 30),
                       sleeps: RecordedSleeps = RecordedSleeps(), baseURL: URL = URL(string: "https://viadere.com")!) throws -> ViadereBusinessClient {
        try ViadereBusinessClient(apiKey: key, baseURL: baseURL, transport: transport, retry: retry, sleep: { sleeps.record($0) })
    }

    static func confirm(key: String = "order-1042-confirm") -> IssueInteractionRequest {
        IssueInteractionRequest(relationshipId: relationship, purpose: .transactional, payload: .confirm(ConfirmPayload(title: "Confirm pickup")),
                                allowedChannels: [.nativePush, .inApp], ttlSeconds: 600, idempotencyKey: key)
    }

    static func interaction(from request: IssueInteractionRequest) -> Interaction {
        request.makeInteraction(businessId: BusinessID(), consumerId: ConsumerID(), now: now)
    }

    static func errorBody(_ code: APIErrorCode, _ message: String = "No.", requestId: String = "req-1") -> APIErrorResponse {
        APIErrorResponse(code: code, message: message, requestId: requestId)
    }
}
