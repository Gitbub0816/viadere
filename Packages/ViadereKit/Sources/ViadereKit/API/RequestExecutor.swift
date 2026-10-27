import Foundation
import ViadereCore

/// Signs outgoing requests with the device's `request` key (`VIADERE-SIG-V1`).
public protocol RequestSigning: Sendable {
    func headers(method: String, pathAndQuery: String, body: Data) async throws -> SignedRequestHeaders
}

public struct DeviceRequestSigner: RequestSigning {
    private let records: any DeviceRecordStore
    private let keys: any DeviceKeyStore
    private let clock: @Sendable () -> Date

    public init(records: any DeviceRecordStore, keys: any DeviceKeyStore, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.records = records
        self.keys = keys
        self.clock = clock
    }

    public func headers(method: String, pathAndQuery: String, body: Data) async throws -> SignedRequestHeaders {
        guard let record = try await records.load() else { throw APIError.notEnrolled }
        let key: any ManagedSigningKey
        do { key = try await keys.requireKey(for: .request) } catch { throw APIError.notEnrolled }
        return try await RequestSigner(deviceId: record.deviceId, key: key)
            .sign(method: method, pathAndQuery: pathAndQuery, body: body, now: clock())
    }
}

/// Builds, authenticates, signs and sends one request. No retry logic (see `APIClient`).
public struct RequestExecutor: Sendable {
    public let baseURL: URL
    public let transport: any HTTPTransport
    public let signer: (any RequestSigning)?
    public let userAgent: String

    public init(baseURL: URL, transport: any HTTPTransport, signer: (any RequestSigning)?, userAgent: String = "Viadere-iOS/1") {
        self.baseURL = baseURL
        self.transport = transport
        self.signer = signer
        self.userAgent = userAgent
    }

    /// `pathAndQuery` is used **verbatim** both on the request line and in the signature string.
    public func run(_ endpoint: AnyEndpoint, pathAndQuery: String, body: Data?, bearer: String?) async throws -> HTTPResponse {
        var base = baseURL.absoluteString
        while base.hasSuffix("/") { base.removeLast() }
        guard pathAndQuery.hasPrefix("/"), let url = URL(string: base + pathAndQuery) else {
            throw APIError.invalidRequest("url")
        }
        var headers: [String: String] = ["Accept": "application/json", "User-Agent": userAgent]
        if body != nil { headers["Content-Type"] = "application/json" }

        switch endpoint.auth {
        case .bearer, .deviceSignedBearer:
            guard let bearer else { throw APIError.sessionExpired }
            headers["Authorization"] = "Bearer " + bearer
        default:
            break
        }
        switch endpoint.auth {
        case .deviceSigned, .deviceSignedBearer:
            guard let signer else { throw APIError.notEnrolled }
            let signed = try await signer.headers(method: endpoint.method.rawValue, pathAndQuery: pathAndQuery, body: body ?? Data())
            headers.merge(signed.fields) { _, new in new }
        default:
            break
        }
        do {
            return try await transport.send(HTTPRequest(method: endpoint.method, url: url, headers: headers, body: body))
        } catch let error as APIError {
            throw error
        } catch {
            throw APIError.transport(String(describing: type(of: error)))
        }
    }

    /// Maps a non-2xx response to `APIError`.
    static func error(from response: HTTPResponse) -> APIError {
        if let parsed = try? ViadereJSON.decode(APIErrorResponse.self, from: response.body) {
            return .server(status: response.status, code: parsed.error.code, message: parsed.error.message)
        }
        return .server(status: response.status, code: .unknown, message: "")
    }
}
