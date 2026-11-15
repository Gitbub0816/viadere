import Foundation
import Vapor
import ViadereCore

/// An error that maps to the uniform `APIErrorResponse`. Messages are written for clients and never
/// contain internals, identifiers of other tenants, or secrets.
public struct APIError: Error, Sendable {
    public var status: HTTPStatus
    public var code: APIErrorCode
    public var message: String
    public var details: [String: String]?
    public var headers: [String: String]

    public init(_ status: HTTPStatus, _ code: APIErrorCode, _ message: String, details: [String: String]? = nil,
                headers: [String: String] = [:]) {
        self.status = status
        self.code = code
        self.message = message
        self.details = details
        self.headers = headers
    }

    public static func badRequest(_ message: String = "Malformed request.") -> APIError { .init(.badRequest, .badRequest, message) }
    public static func validation(_ message: String = "The request failed validation.", details: [String: String]? = nil) -> APIError {
        .init(.unprocessableEntity, .validationFailed, message, details: details)
    }
    public static var unauthorized: APIError { .init(.unauthorized, .unauthorized, "Authentication required.") }
    public static var signatureInvalid: APIError { .init(.unauthorized, .signatureInvalid, "Request signature is invalid.") }
    public static var forbidden: APIError { .init(.forbidden, .forbidden, "You do not have access to this resource.") }
    public static var notFound: APIError { .init(.notFound, .notFound, "Not found.") }
    public static func conflict(_ message: String = "The request conflicts with the current state.") -> APIError {
        .init(.conflict, .conflict, message)
    }
    public static func gone(_ message: String = "This is no longer available.") -> APIError { .init(.gone, .gone, message) }
    public static func rateLimited(retryAfter: Int) -> APIError {
        .init(.tooManyRequests, .rateLimited, "Too many requests. Try again later.", headers: ["Retry-After": String(max(1, retryAfter))])
    }
    public static var internalError: APIError { .init(.internalServerError, .internalError, "An internal error occurred.") }
    public static func unavailable(_ message: String = "This feature is not available yet.") -> APIError {
        .init(.notImplemented, .unavailable, message)
    }
}

extension Request {
    /// Stable per-request id, echoed in `X-Request-Id` and error bodies.
    public var requestID: String {
        if let existing = storage[RequestIDKey.self] { return existing }
        let id = UUID().uuidString.lowercased()
        storage[RequestIDKey.self] = id
        return id
    }
}

struct RequestIDKey: StorageKey { typealias Value = String }

/// Converts every thrown error into the uniform error body. Unknown errors become a generic 500;
/// the real cause is logged (redacted) but never returned.
public struct APIErrorMiddleware: AsyncMiddleware {
    public init() {}

    public func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let response: Response
        do {
            response = try await next.respond(to: request)
        } catch let error as APIError {
            response = Self.render(error, request: request)
        } catch let error as any AbortError {
            response = Self.render(Self.map(error), request: request)
        } catch {
            request.logger.error("unhandled error", metadata: ["type": "\(type(of: error))", "requestId": "\(request.requestID)"])
            request.logger.debug("unhandled error detail", metadata: ["error": "\(String(describing: error).prefix(300))"])
            response = Self.render(.internalError, request: request)
        }
        response.headers.replaceOrAdd(name: "X-Request-Id", value: request.requestID)
        return response
    }

    static func map(_ error: any AbortError) -> APIError {
        switch error.status {
        case .notFound: return .notFound
        case .payloadTooLarge: return .init(.payloadTooLarge, .badRequest, "Request body is too large.")
        case .unsupportedMediaType: return .init(.unsupportedMediaType, .badRequest, "Content-Type must be application/json.")
        case .methodNotAllowed: return .init(.methodNotAllowed, .badRequest, "Method not allowed.")
        case .unauthorized: return .unauthorized
        case .forbidden: return .forbidden
        case .tooManyRequests: return .rateLimited(retryAfter: 1)
        case .badRequest, .unprocessableEntity: return .badRequest()
        default:
            if error.status.code >= 500 { return .internalError }
            return .init(error.status, .badRequest, "Request could not be processed.")
        }
    }

    static func render(_ error: APIError, request: Request) -> Response {
        let body = APIErrorResponse(code: error.code, message: error.message, requestId: request.requestID, details: error.details)
        let response = Response(status: error.status)
        if let data = try? ViadereJSON.encode(body) {
            response.body = .init(data: data)
        }
        response.headers.contentType = .json
        for (name, value) in error.headers { response.headers.replaceOrAdd(name: name, value: value) }
        return response
    }
}

extension Request {
    /// Decodes a JSON body with `ViadereJSON`, mapping failures to a uniform 400 without echoing input.
    public func decodeBody<T: Decodable>(_ type: T.Type = T.self) throws -> T {
        guard let buffer = body.data, buffer.readableBytes > 0 else { throw APIError.badRequest("A JSON body is required.") }
        do {
            return try ViadereJSON.decode(type, from: Data(buffer.readableBytesView))
        } catch {
            throw APIError.badRequest("The request body is not valid.")
        }
    }

    /// Raw body bytes (empty if none).
    public var bodyBytes: Data {
        guard let buffer = body.data else { return Data() }
        return Data(buffer.readableBytesView)
    }

    /// Responds with a `ViadereJSON` body.
    public func jsonResponse<T: Encodable>(_ value: T, status: HTTPStatus = .ok) throws -> Response {
        let response = Response(status: status)
        response.body = .init(data: try ViadereJSON.encode(value))
        response.headers.contentType = .json
        return response
    }

    public func uuidParameter<Tag>(_ name: String, as: TypedID<Tag>.Type = TypedID<Tag>.self) throws -> TypedID<Tag> {
        guard let raw = parameters.get(name), let id = TypedID<Tag>(raw) else { throw APIError.notFound }
        return id
    }
}
