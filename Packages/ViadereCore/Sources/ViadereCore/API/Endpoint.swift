import Foundation

/// HTTP methods used by the API.
public enum HTTPMethod: String, Sendable, Codable, CaseIterable {
    case GET, POST, PUT, PATCH, DELETE
}

/// How an endpoint is authenticated.
public enum AuthRequirement: String, Sendable, Codable, CaseIterable {
    /// Public (rate-limited by IP / ceremony).
    case none
    /// `Authorization: Bearer <session token>` only (device enrollment, web link redemption).
    case bearer
    /// `VIADERE-SIG-V1` device signature headers only.
    case deviceSigned
    /// Bearer session token **and** a device signature from a device of the same consumer.
    case deviceSignedBearer
    /// Business API key: `Authorization: Bearer vk_…`; POSTs require `Idempotency-Key`.
    case businessAPIKey
    /// Messaging-provider webhook signature (provider-specific, verified by the server adapter).
    case providerSignature
}

/// A path segment of an endpoint template.
public enum PathSegment: Sendable, Hashable {
    case constant(String)
    case parameter(String)
}

/// Errors building a concrete path.
public enum EndpointError: Error, Sendable, Equatable {
    case missingParameter(String)
    case emptyParameter(String)
}

/// Placeholder body for endpoints without a request or response body.
public struct EmptyBody: Codable, Sendable, Hashable {
    public init() {}
}

/// A type-erased endpoint description (for route registration and documentation).
public struct AnyEndpoint: Sendable, Hashable {
    public let name: String
    public let method: HTTPMethod
    /// Template such as `/v1/interactions/{interactionId}`.
    public let template: String
    public let auth: AuthRequirement

    public var segments: [PathSegment] {
        template.split(separator: "/").map { part in
            if part.hasPrefix("{") && part.hasSuffix("}") { return .parameter(String(part.dropFirst().dropLast())) }
            return .constant(String(part))
        }
    }

    /// Vapor-style path components: constants verbatim, parameters as `:name`.
    public var vaporPathComponents: [String] {
        segments.map {
            switch $0 {
            case .constant(let c): c
            case .parameter(let p): ":" + p
            }
        }
    }

    /// Parameter names in order.
    public var parameterNames: [String] {
        segments.compactMap { if case .parameter(let p) = $0 { p } else { nil } }
    }

    /// Builds a concrete path (percent-encoding parameters) plus an optional query in the given order.
    /// The exact returned string must be used both on the request line and in the request signature.
    public func path(_ parameters: [String: String] = [:], query: [(String, String)] = []) throws -> String {
        var out = ""
        for segment in segments {
            switch segment {
            case .constant(let c):
                out += "/" + c
            case .parameter(let name):
                guard let value = parameters[name] else { throw EndpointError.missingParameter(name) }
                guard !value.isEmpty else { throw EndpointError.emptyParameter(name) }
                out += "/" + Self.encode(value)
            }
        }
        if !query.isEmpty {
            out += "?" + query.map { Self.encode($0.0) + "=" + Self.encode($0.1) }.joined(separator: "&")
        }
        return out
    }

    /// RFC 3986 unreserved characters pass through; everything else is percent-encoded (uppercase hex).
    static func encode(_ value: String) -> String {
        var out = ""
        for byte in value.utf8 {
            switch byte {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "0")...UInt8(ascii: "9"),
                 UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "~"):
                out.append(Character(Unicode.Scalar(byte)))
            default:
                out += String(format: "%%%02X", byte)
            }
        }
        return out
    }
}

/// A typed endpoint: `Request` is the JSON body type (`EmptyBody` for none), `Response` the
/// decoded JSON response (`Data` for binary responses such as `.pkpass`).
public struct Endpoint<Request: Sendable, Response: Sendable>: Sendable, Hashable {
    public let descriptor: AnyEndpoint

    public init(_ name: String, _ method: HTTPMethod, _ template: String, auth: AuthRequirement) {
        descriptor = AnyEndpoint(name: name, method: method, template: template, auth: auth)
    }

    public var name: String { descriptor.name }
    public var method: HTTPMethod { descriptor.method }
    public var template: String { descriptor.template }
    public var auth: AuthRequirement { descriptor.auth }

    /// See `AnyEndpoint.path(_:query:)`.
    public func path(_ parameters: [String: String] = [:], query: [(String, String)] = []) throws -> String {
        try descriptor.path(parameters, query: query)
    }

    public static func == (lhs: Self, rhs: Self) -> Bool { lhs.descriptor == rhs.descriptor }
    public func hash(into hasher: inout Hasher) { hasher.combine(descriptor) }
}
