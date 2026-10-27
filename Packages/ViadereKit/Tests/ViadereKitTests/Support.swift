import Foundation
import ViadereCore
@testable import ViadereKit

/// Scriptable transport that records every request.
final class FakeTransport: HTTPTransport, @unchecked Sendable {
    typealias Handler = @Sendable (HTTPRequest, Int) async throws -> HTTPResponse
    private let lock = NSLock()
    private var _requests: [HTTPRequest] = []
    private let handler: Handler

    init(_ handler: @escaping Handler) { self.handler = handler }

    var requests: [HTTPRequest] { lock.lock(); defer { lock.unlock() }; return _requests }

    private func record(_ request: HTTPRequest) -> Int {
        lock.lock(); defer { lock.unlock() }
        _requests.append(request)
        return _requests.count - 1
    }

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        let index = record(request)
        return try await handler(request, index)
    }
}

actor CountingRefresher: TokenRefresher {
    private(set) var calls = 0
    let delay: Duration
    let consumerId: ConsumerID
    init(consumerId: ConsumerID = PreviewData.consumerId, delay: Duration = .milliseconds(50)) {
        self.consumerId = consumerId
        self.delay = delay
    }
    func refresh(current: TokenSet?) async throws -> TokenSet {
        calls += 1
        try await Task.sleep(for: delay)
        return TokenSet(consumerId: consumerId, accessToken: "fresh-\(calls)",
                        accessExpiresAt: Date().addingTimeInterval(900), refreshToken: "r\(calls)")
    }
}

func json(_ body: String) -> HTTPResponse { json(200, body) }

func json(_ status: Int, _ body: String) -> HTTPResponse {
    HTTPResponse(status: status, headers: ["content-type": "application/json"], body: Data(body.utf8))
}

func errorBody(_ code: String, _ message: String = "nope") -> String {
    "{\"error\":{\"code\":\"\(code)\",\"message\":\"\(message)\"}}"
}

/// "/v1/x?y=1" from a full URL, exactly as it appears on the request line.
func pathAndQuery(_ url: URL) -> String {
    var out = url.path
    if let query = url.query { out += "?" + query }
    return out
}

func utcNow() -> Date { Date() }
