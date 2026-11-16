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

    /// Transport reasons that are **not** a missing network: the request never left this device for another cause (a refused TLS or pin
    /// check, the shared container that holds the refresh lock, locked credentials). Screens must not call these "offline".
    public static let localTransportReasons: Set<String> = [
        TransportReason.secureConnection, "refresh-lock-unavailable", "refresh-lock-timeout", "refresh-busy", "credentials-locked", "non-http",
    ]

    public enum TransportReason {
        /// The system refused the server's certificate, or the pin check cancelled the connection.
        public static let secureConnection = "secure-connection"
        /// No route to Viadere: no network, DNS, timeout, connection lost.
        public static let offline = "offline"
    }

    /// True when the failure means "no network" (the only case a screen may call offline).
    public var isConnectivityFailure: Bool {
        if case .transport(let reason) = self { return !Self.localTransportReasons.contains(reason) }
        return false
    }

    /// The transport reason for a `URLError`: a refused secure connection (a pin mismatch cancels the challenge), or connectivity.
    public static func transportReason(for error: URLError) -> String {
        switch error.code {
        case .cancelled, .secureConnectionFailed, .serverCertificateUntrusted, .serverCertificateHasBadDate, .serverCertificateHasUnknownRoot,
             .serverCertificateNotYetValid, .clientCertificateRejected, .clientCertificateRequired, .appTransportSecurityRequiresSecureConnection:
            return TransportReason.secureConnection
        default:
            return TransportReason.offline
        }
    }

    /// A short message suitable for UI. Never leaks internals.
    public var userMessage: String {
        switch self {
        case .transport(TransportReason.secureConnection):
            "Viadere couldn't make a secure connection, so nothing was sent. If this keeps happening, update the app."
        case .transport(let reason) where Self.localTransportReasons.contains(reason):
            "Viadere couldn't finish this on this device. Please try again; if it keeps happening, reinstall the app."
        case .transport: "Can't reach Viadere right now. Check your connection and try again."
        case .server(_, let code, let message):
            switch code {
            case .rateLimited: "Too many attempts. Please wait a moment."
            case .expired, .gone: "This request has expired."
            case .insufficientAssurance: "This request needs stronger verification on this device."
            case .passkeyAssertionRequired: "Confirm with your passkey to add this device."
            case .deviceCoolDown: "For your security, this iPhone can't approve high-risk requests yet. You can still deny or report them."
            case .contextMismatch, .contextDigestRequired: "This request changed. Review the updated details."
            case .approvalsFrozen: "Approvals are frozen. Unfreeze them in Approvals to continue."
            case .approvalsPaused: "Requests from this business are paused because several were declined."
            case .attestationRequired: AttestationMessage.notVerified
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
