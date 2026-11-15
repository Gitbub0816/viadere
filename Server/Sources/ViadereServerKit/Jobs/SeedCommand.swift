import Fluent
import Foundation
import Vapor
import ViadereCore

/// `ViadereServer seed` — creates clearly fictional demo businesses for **local development only**.
/// Refuses to run when `ENVIRONMENT=production`.
public struct SeedCommand: AsyncCommand {
    public struct Signature: CommandSignature {
        public init() {}
    }

    public let signature = Signature()
    public let help = "Creates fictional, verified demo businesses and API keys for local development (never in production)."

    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        let app = context.application
        let ctx = app.ctx
        guard !ctx.config.isStrict, app.environment != .production,
              (ProcessInfo.processInfo.environment["ENVIRONMENT"] ?? "").lowercased() != "production" else {
            context.console.error("Refusing to seed: ENVIRONMENT=production.")
            throw Abort(.forbidden)
        }
        let result = try await Seeder(db: app.db, ctx: ctx).seed()
        context.console.print("Seeded demo businesses (fictional; local development only):")
        for demo in result {
            context.console.print("  \(demo.name)  \(demo.handle)  code \(demo.code)")
            context.console.print("    business id : \(demo.businessId)")
            context.console.print("    test API key: \(demo.testKey)")
        }
        context.console.print("Keys are shown once. Re-running seed leaves existing businesses untouched.")
    }
}

struct Seeder {
    let db: any Database
    let ctx: ServerContext

    struct Seeded {
        var name: String
        var handle: String
        var code: String
        var businessId: String
        var testKey: String
    }

    static let demos: [(name: String, legal: String, handle: String, category: BusinessCategory)] = [
        ("Northwind Air", "Northwind Air Demo Ltd (fictional)", "northwindair", .airline),
        ("Juniper Coffee", "Juniper Coffee Demo Co (fictional)", "junipercoffee", .foodAndDrink),
    ]

    func seed() async throws -> [Seeded] {
        var out: [Seeded] = []
        for demo in Self.demos {
            guard let handle = BusinessHandle(parsing: demo.handle) else { continue }
            if let existing = try await BusinessHandleRecord.query(on: db).filter(\.$handle == handle.value).first() {
                _ = existing
                continue
            }
            let registry = BusinessRegistry(db: db, ctx: ctx)
            let business = try await registry.register(displayName: demo.name, legalName: demo.legal, handle: demo.handle,
                                                       category: demo.category, status: .verified)
            let key = try await BusinessAPIKeys.issue(businessId: business.id!, name: "Demo test key", live: false,
                                                      scopes: BusinessAPIKeys.Scope.all, now: ctx.now, on: db)
            let code = try await BusinessCodeRecord.query(on: db).filter(\.$businessId == business.id!).first()
            out.append(Seeded(name: demo.name, handle: "@\(demo.handle)", code: code.flatMap { BusinessCode(parsing: $0.canonical)?.display } ?? "",
                              businessId: BusinessID(business.id!).description, testKey: key.key))
        }
        return out
    }
}
