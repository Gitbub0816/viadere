import Foundation
import Testing
@testable import ViadereCore

/// The auth-delivery contract artifacts (`contracts/openapi/auth-delivery-v1.yaml`, `contracts/schemas/*.json`) and the route catalog / Core enums cannot
/// drift (like `OpenAPIParityTests` for the business API): a route, an enum member or a schema member that exists on one side only fails here.
@Suite("Auth delivery contract parity")
struct AuthDeliveryContractParityTests {
    static var root: URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        return url
    }

    static func text(_ path: String) throws -> String { try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8) }

    static func documentedRoutes() throws -> Set<String> {
        var current: String?
        var out = Set<String>()
        var inPaths = false
        for line in try text("contracts/openapi/auth-delivery-v1.yaml").split(separator: "\n", omittingEmptySubsequences: false) {
            if line == "paths:" { inPaths = true; continue }
            if inPaths, !line.isEmpty, !line.hasPrefix(" ") { break }
            if line.hasPrefix("  /"), line.hasSuffix(":") { current = String(line.dropFirst(2).dropLast()); continue }
            if let path = current, line.hasPrefix("    "), !line.hasPrefix("     "), line.hasSuffix(":") {
                let method = line.trimmingCharacters(in: .whitespaces).dropLast().uppercased()
                if ["GET", "POST", "PUT", "PATCH", "DELETE"].contains(method) { out.insert("\(method) \(path)") }
            }
        }
        return out
    }

    @Test func everyAuthRouteIsDocumentedAndEveryDocumentedRouteExists() throws {
        let documented = try Self.documentedRoutes()
        let catalog = Set(APIRoutes.authDeliveryEndpoints.map { "\($0.method.rawValue) \($0.template)" })
        #expect(documented == catalog, "only in contract: \(documented.subtracting(catalog).sorted()); only in catalog: \(catalog.subtracting(documented).sorted())")
        let all = Set(APIRoutes.all.map { "\($0.method.rawValue) \($0.template)" })
        #expect(catalog.isSubset(of: all))
    }

    /// Reads `enum: [a, b, c]` of a named schema in the OpenAPI document.
    static func yamlEnum(_ schema: String) throws -> [String] {
        let lines = try text("contracts/openapi/auth-delivery-v1.yaml").split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard let start = lines.firstIndex(of: "    \(schema):") else { throw ParityError.missing(schema) }
        for line in lines[(start + 1)...] {
            if line.hasPrefix("    ") && !line.hasPrefix("     ") { break }
            if let range = line.range(of: "enum: [") {
                return line[range.upperBound...].dropLast().split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            }
        }
        throw ParityError.missing(schema)
    }

    enum ParityError: Error { case missing(String) }

    @Test func openAPIEnumsMatchCore() throws {
        #expect(try Self.yamlEnum("Method") == AuthDeliveryMethod.allCases.map(\.rawValue))
        #expect(try Self.yamlEnum("Purpose") == AuthDeliveryPurpose.allCases.map(\.rawValue))
        #expect(try Self.yamlEnum("Channel") == AuthDeliveryChannel.allCases.map(\.rawValue))
        #expect(try Self.yamlEnum("Status") == AuthDeliveryStatus.allCases.map(\.rawValue))
    }

    static func schema(_ name: String) throws -> [String: Any] {
        let data = try Data(contentsOf: root.appendingPathComponent("contracts/schemas/\(name)"))
        return try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    @Test func createRequestSchemaMatchesTheDecoder() throws {
        let schema = try Self.schema("auth-delivery-create-request-v1.schema.json")
        let properties = Set((schema["properties"] as? [String: Any] ?? [:]).keys)
        #expect(properties == AuthDeliveryCreateRequest.memberNames)
        #expect(schema["additionalProperties"] as? Bool == false)
        #expect(Set(schema["required"] as? [String] ?? []) == ["method", "request_id", "subject_ref", "purpose", "template"])
        // tenant_id and audience are not members of the contract.
        #expect(!properties.contains("tenant_id") && !properties.contains("audience"))
        let method = (schema["properties"] as? [String: Any])?["method"] as? [String: Any]
        #expect(method?["enum"] as? [String] == AuthDeliveryMethod.allCases.map(\.rawValue))
        let channels = ((schema["properties"] as? [String: Any])?["channels"] as? [String: Any])?["items"] as? [String: Any]
        #expect(channels?["enum"] as? [String] == AuthDeliveryChannel.allCases.map(\.rawValue))
    }

    @Test func displaySchemaMatchesTheEncodedDisplayObject() throws {
        let schema = try Self.schema("auth-delivery-display-v1.schema.json")
        let display = AuthDeliveryDisplay(id: AuthDeliveryID(), method: .magicLink, purpose: .signIn, template: "auth.sign_in_link.v1", status: .queued, businessId: BusinessID(),
                                          businessName: "Northwind", expiresAt: Date(), createdAt: Date(), requestId: "r", destinationHost: "login.example.com",
                                          destinationStatement: "a.b.c", codeKind: .otp, variables: ["reference": "x"], silent: false)
        let encoded = try #require(JSONSerialization.jsonObject(with: try ViadereJSON.encode(display)) as? [String: Any])
        #expect(Set(encoded.keys) == Set((schema["properties"] as? [String: Any] ?? [:]).keys))
        #expect(Set(schema["required"] as? [String] ?? []).isSubset(of: Set(encoded.keys)))
        // There is no secret member in the display object: no url, no code.
        #expect(encoded["url"] == nil && encoded["code"] == nil)
    }

    @Test func eventSchemaMatchesTheEnvelopeAndTheEventNames() throws {
        let schema = try Self.schema("auth-delivery-event-v1.schema.json")
        let type = (schema["properties"] as? [String: Any])?["type"] as? [String: Any]
        #expect(type?["enum"] as? [String] == AuthDeliveryEventName.allCases.map(\.rawValue))
        let envelope = WebhookEnvelopeV2(id: "evt_x", type: AuthDeliveryEventName.opened.rawValue, tenantId: "ten_x", requestId: AuthDeliveryID().description, occurredAt: Date(), resultRef: nil)
        let encoded = try #require(JSONSerialization.jsonObject(with: try ViadereJSON.encode(envelope)) as? [String: Any])
        let properties = Set((schema["properties"] as? [String: Any] ?? [:]).keys)
        #expect(Set(encoded.keys).isSubset(of: properties))
        #expect(schema["additionalProperties"] as? Bool == false)
        // Every transition that emits an event has a schema name, and the webhook types are all v2-only (`auth.` family).
        for status in AuthDeliveryStatus.allCases { if let name = AuthDeliveryEventName.forTransition(into: status) { #expect(WebhookEventType(rawValue: name.rawValue).isAuthEvent) } }
        #expect(WebhookEventType.authEvents.allSatisfy { $0.isAuthEvent })
        // No opaque envelope member can carry a secret: the envelope has no free-form member at all.
        #expect(Set(encoded.keys).isSubset(of: ["id", "type", "version", "tenant_id", "request_id", "occurred_at", "result_ref"]))
    }

    /// The business API document links to the auth-delivery contract, and the existing parity test keeps covering every other business route.
    @Test func theBusinessAPIDocumentPointsToTheContract() throws {
        #expect(try Self.text("docs/openapi.yaml").contains("contracts/openapi/auth-delivery-v1.yaml"))
    }
}
