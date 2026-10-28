import Foundation
import Testing
@testable import ViadereCore

/// The published OpenAPI description (`docs/openapi.yaml`) and the route catalog cannot drift: every business-API route is documented with its method,
/// and every documented business path exists in the catalog (SEC-API-008).
@Suite("OpenAPI parity")
struct OpenAPIParityTests {
    private static func documented() throws -> Set<String> {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        let text = try String(contentsOf: url.appendingPathComponent("docs/openapi.yaml"), encoding: .utf8)
        var current: String?
        var out = Set<String>()
        var inPaths = false
        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
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

    @Test func everyBusinessAPIKeyRouteIsDocumentedAndNothingDocumentedIsMissingFromTheCatalog() throws {
        let documented = try Self.documented()
        #expect(documented.count > 30)
        let business = APIRoutes.all.filter { $0.auth == .businessAPIKey }
        #expect(business.count > 30)
        var missing: [String] = []
        for route in business where !documented.contains("\(route.method.rawValue) \(route.template)") { missing.append("\(route.method.rawValue) \(route.template)") }
        #expect(missing == [], "undocumented business routes: \(missing)")
        let catalog = Set(APIRoutes.all.map { "\($0.method.rawValue) \($0.template)" })
        let extra = documented.subtracting(catalog)
        #expect(extra.isEmpty, "documented but not in the route catalog: \(extra.sorted())")
        for route in ["POST /v1/business/webhooks/{webhookId}/verify", "POST /v1/business/webhooks/{webhookId}/test",
                      "POST /v1/business/webhooks/{webhookId}/pause", "POST /v1/business/webhooks/{webhookId}/resume"] {
            #expect(documented.contains(route), "\(route)")
            #expect(catalog.contains(route), "\(route)")
        }
    }
}
