import Foundation
import ViadereCore

public struct HTTPRequest: Sendable {
    public var method: HTTPMethod
    public var url: URL
    public var headers: [String: String]
    public var body: Data?

    public init(method: HTTPMethod, url: URL, headers: [String: String] = [:], body: Data? = nil) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    }
}

public struct HTTPResponse: Sendable {
    public var status: Int
    public var headers: [String: String]
    public var body: Data

    public init(status: Int, headers: [String: String] = [:], body: Data = Data()) {
        self.status = status
        self.headers = headers
        self.body = body
    }
}

/// The only place bytes leave the process. `URLSessionTransport` in production, a fake in tests.
public protocol HTTPTransport: Sendable {
    func send(_ request: HTTPRequest) async throws -> HTTPResponse
}

/// Client-side API failures. Messages never include tokens or request bodies.
public enum APIError: Error, Sendable, Equatable {
    /// No network, TLS/pinning failure, timeout.
    case transport(String)
    /// Non-2xx with the server's structured error.
    case server(status: Int, code: APIErrorCode, message: String)
    case decoding(String)
    /// This installation has no enrolled device yet (device-signed routes need one).
    case notEnrolled
    /// No usable session: sign in again.
    case sessionExpired
    /// The server rejected our device signature repeatedly: the device was probably revoked.
    case deviceRejected
    case invalidRequest(String)

    public var code: APIErrorCode? {
        if case .server(_, let code, _) = self { return code }
        return nil
    }

    /// A short message suitable for UI. Never leaks internals.
    public var userMessage: String {
        switch self {
        case .transport: "Can't reach Viadere right now. Check your connection and try again."
        case .server(_, let code, let message):
            switch code {
            case .rateLimited: "Too many attempts. Please wait a moment."
            case .expired, .gone: "This request has expired."
            case .insufficientAssurance: "This request needs stronger verification on this device."
            case .notFound: "We couldn't find that."
            case .conflict: "This was already handled."
            default: message.isEmpty ? "Something went wrong. Please try again." : message
            }
        case .decoding: "Viadere sent something unexpected. Please update the app."
        case .notEnrolled: "This device isn't set up yet."
        case .sessionExpired: "Please sign in again."
        case .deviceRejected: "This device is no longer trusted. Please sign in again."
        case .invalidRequest: "That doesn't look right."
        }
    }
}
