import Fluent
import Foundation
import Vapor
import ViadereCore

/// `ViadereServer staging-demo [--issue-key]` — **staging only**: a fictional "Atlas Demo" business that sends real interactions (messages,
/// sign-in and transaction approvals) through the normal API, push and rendering pipeline, so the app can be tried end to end without the
/// production onboarding (email-verified signup, domain proof, legal-entity review, contracts, go-live).
///
/// Run it inside the api container (`az containerapp exec`): the output goes to the caller's terminal only, never to the container logs.
/// - Without options: makes sure the business exists and lists the connected customers' `subjectRef`s.
/// - `--issue-key`: revokes every earlier live key of the demo business and prints a new one, once.
///
/// What it grants is what an operator would grant a reviewed business (Tier A, `auth.challenge`, `transaction.approve`, the expiring legacy
/// approval entitlement while Approve v2 is off), recorded as `system:staging-demo` in the audit log. Every other control applies unchanged:
/// the customer must connect to the business, the key is checked on every call, policy and rate limits run as usual.
public struct StagingDemoCommand: AsyncCommand {
    public struct Signature: CommandSignature {
        @Flag(name: "issue-key") var issueKey: Bool
        public init() {}
    }

    public let signature = Signature()
    public let help = "Staging only: a fictional demo business with a live API key for end-to-end notification tests."

    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        let app = context.application
        let demo: StagingDemo
        do { demo = try StagingDemo(db: app.db, ctx: app.ctx, environment: app.ctx.config.environment) } catch {
            context.console.error("Refusing: staging-demo runs only with ENVIRONMENT=staging.")
            throw Abort(.forbidden)
        }
        let business = try await demo.ensureBusiness()
        let code = try await BusinessCodeRecord.query(on: app.db).filter(\.$businessId == business.id!).first()
            .flatMap { BusinessCode(parsing: $0.canonical)?.display } ?? "-"
        context.console.print("\(StagingDemo.displayName)  @\(StagingDemo.handle)  code \(code)")
        context.console.print("Connect from the app: Businesses > search \"@\(StagingDemo.handle)\" > Connect.")
        if signature.issueKey {
            let key = try await demo.issueLiveKey(businessId: business.id!)
            context.console.print("")
            context.console.print("Live API key (shown once; earlier demo keys are revoked):")
            context.console.print("  \(key)")
        }
        let connections = try await demo.connections(businessId: business.id!)
        context.console.print("")
        if connections.isEmpty {
            context.console.print("No customer is connected yet.")
        } else {
            context.console.print("Connected customers (address them with subjectRef):")
            for connection in connections {
                context.console.print("  \(connection.subjectRef)  connected \(ViadereDate.format(connection.connectedAt))")
            }
        }
    }
}

struct StagingDemo {
    static let displayName = "Atlas Demo"
    static let handle = "atlasdemo"
    static let actor = "system:staging-demo"
    static let justification = "Staging demo business for end-to-end notification and approval testing (fictional, staging only)."

    enum Refusal: Error, Equatable { case notStaging }

    let db: any Database
    let ctx: ServerContext

    /// Refuses everywhere but staging: production must never hold a business that skipped onboarding, and development has `seed`.
    init(db: any Database, ctx: ServerContext, environment: DeploymentEnvironment) throws {
        guard environment == .staging else { throw Refusal.notStaging }
        self.db = db
        self.ctx = ctx
    }

    /// The demo business, created verified on first use, with the approval entitlements. Idempotent.
    func ensureBusiness() async throws -> BusinessRecord {
        let business: BusinessRecord
        if let row = try await BusinessHandleRecord.query(on: db).filter(\.$handle == Self.handle).first(),
           let existing = try await BusinessRecord.find(row.businessId, on: db) {
            business = existing
        } else {
            business = try await BusinessRegistry(db: db, ctx: ctx).register(
                displayName: Self.displayName, legalName: "Atlas Demo (fictional, staging only)", handle: Self.handle,
                category: .retail, status: .verified)
        }
        let id = business.id!
        let entitlements = EntitlementService(db: db, ctx: ctx)
        let actor = EntitlementActor.system("staging-demo")
        try await entitlements.grant(businessId: id, tier: .a, actor: actor, justification: Self.justification)
        try await entitlements.grant(businessId: id, capability: .authChallenge, actor: actor, justification: Self.justification)
        try await entitlements.grant(businessId: id, capability: .transactionApprove, actor: actor, justification: Self.justification)
        // Approve v2 is off on staging: approvals are decided on relay status, which needs the (expiring) legacy entitlement.
        let now = ctx.now
        if now < LegacyApproval.sunset, try await !entitlements.snapshot(businessId: id).legacyApproval {
            let expires = min(LegacyApproval.sunset, now.addingTimeInterval(LegacyApproval.maximumGrant))
            try await entitlements.grantLegacyApproval(businessId: id, actor: actor,
                                                       justification: Self.justification + " Migrates with the platform to Approve v2.", expiresAt: expires)
        }
        return business
    }

    /// Revokes every earlier live key of the demo business and issues a new one (messaging plus the approval capabilities).
    func issueLiveKey(businessId: UUID) async throws -> String {
        try await APIKeyLifecycle(db: db, ctx: ctx).revokeAll(businessId: businessId, live: true, reason: "replaced by staging-demo --issue-key",
                                                             actor: .system(Self.actor))
        let issued = try await BusinessAPIKeys.issue(businessId: businessId, name: "Staging demo key", live: true, scopes: BusinessAPIKeys.Scope.all,
                                                     capabilities: Capability.messaging + [.authChallenge, .transactionApprove], now: ctx.now, on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("staging_demo.key_issued", actor: AuditActor(kind: .system, id: Self.actor),
                                                           businessId: BusinessID(businessId), subjectType: "api_key",
                                                           subjectId: issued.record.id?.uuidString.lowercased(), metadata: ["kid": issued.record.kid ?? "-"])
        return issued.key
    }

    /// Connected customers of the demo business, newest first, by their business-facing `subjectRef`.
    func connections(businessId: UUID) async throws -> [(subjectRef: String, connectedAt: Date)] {
        let rows = try await RelationshipRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$disconnectedAt == nil)
            .sort(\.$connectedAt, .descending).all()
        let resolver = SubjectResolver(db: db, ctx: ctx)
        return rows.map { (resolver.ref(for: $0).rawValue, $0.connectedAt) }
    }
}
