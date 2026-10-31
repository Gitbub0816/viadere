import Fluent
import Foundation
import Vapor
import ViadereCore

/// `ViadereServer staging-demo [--issue-key] [--console-owner <email> [--name <name>]] [--seed-brand-kit] [--seed-loop] [--status]` —
/// **staging only**: a fictional "Atlas Demo" business that sends real interactions (messages, sign-in and transaction approvals) through
/// the normal API, push and rendering pipeline, so the app can be tried end to end without the production onboarding (email-verified
/// signup, domain proof, legal-entity review, contracts, go-live).
///
/// Run it inside the api container (`az containerapp exec`): the output goes to the caller's terminal only, never to the container logs.
/// - Without options: makes sure the business exists and lists the connected customers' `subjectRef`s.
/// - `--issue-key`: revokes every earlier live key of the demo business and prints a new one, once.
/// - `--console-owner <email> [--name <display name>]`: makes sure that address is an active Owner of the Atlas Demo console (the email code
///   step of sign-up is skipped: staging has no mail delivery) and prints a one-time, one-hour passkey enrollment link (earlier links are
///   revoked). Refused for an address that belongs to an operator, an unverified or disabled account, or a member of another organization.
/// - `--seed-brand-kit`: uploads a generated logo through the real ingestion pipeline and saves the `atlas` kit; both wait for operator
///   review at `/operator/brand`.
/// - `--seed-loop`: creates a Loop Studio draft from the `pickup_time` template (naming the `atlas` kit once it is approved) and submits it
///   through the Studio into the Loop review pipeline (`/operator/loops`; the reviewer needs `loop_reviewer`).
/// - `--status`: the review state of the seeded kit, logo and Loop, and the publication id once published.
///
/// What it grants is what an operator would grant a reviewed business (Tier A, `auth.challenge`, `transaction.approve`, the expiring legacy
/// approval entitlement while Approve v2 is off), recorded as `system:staging-demo` in the audit log. Every other control applies unchanged:
/// the customer must connect to the business, the key is checked on every call, policy and rate limits run as usual. Nothing here approves,
/// publishes or signs a Brand Kit, an image or a Loop: a Viadere operator reviews each of them as usual.
public struct StagingDemoCommand: AsyncCommand {
    public struct Signature: CommandSignature {
        @Flag(name: "issue-key") var issueKey: Bool
        @Option(name: "console-owner") var consoleOwner: String?
        @Option(name: "name") var name: String?
        @Flag(name: "seed-brand-kit") var seedBrandKit: Bool
        @Flag(name: "seed-loop") var seedLoop: Bool
        @Flag(name: "status") var status: Bool
        public init() {}
    }

    public let signature = Signature()
    public let help = "Staging only: a fictional demo business with a live API key, a console owner and seeded (unreviewed) Brand Kit and Loop."

    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        let app = context.application
        let demo: StagingDemo
        do { demo = try StagingDemo(db: app.db, ctx: app.ctx, environment: app.ctx.config.environment) } catch {
            context.console.error("Refusing: staging-demo runs only with ENVIRONMENT=staging.")
            throw Abort(.forbidden)
        }
        let business = try await demo.ensureBusiness()
        let businessId = business.id!
        let code = try await BusinessCodeRecord.query(on: app.db).filter(\.$businessId == businessId).first()
            .flatMap { BusinessCode(parsing: $0.canonical)?.display } ?? "-"
        context.console.print("\(StagingDemo.displayName)  @\(StagingDemo.handle)  code \(code)")
        context.console.print("Connect from the app: Businesses > search \"@\(StagingDemo.handle)\" > Connect.")
        if signature.issueKey {
            let key = try await demo.issueLiveKey(businessId: businessId)
            context.console.print("")
            context.console.print("Live API key (shown once; earlier demo keys are revoked):")
            context.console.print("  \(key)")
        }
        if let email = signature.consoleOwner {
            try await Self.consoleOwner(demo, businessId: businessId, email: email, name: signature.name, context: context)
        }
        if signature.seedBrandKit { try await Self.seedBrandKit(demo, businessId: businessId, runtime: app.brandKits, context: context) }
        if signature.seedLoop { try await Self.seedLoop(demo, businessId: businessId, context: context) }
        if signature.status || signature.seedBrandKit || signature.seedLoop { try await Self.printStatus(demo, businessId: businessId, context: context) }
        let connections = try await demo.connections(businessId: businessId)
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

    /// A refusal is printed as one line and ends the command with a non-zero status; nothing else is printed.
    private static func refusal(_ error: any Error, _ context: CommandContext) -> any Error {
        if let refusal = error as? StagingDemo.ConsoleRefusal {
            context.console.error("Refusing: \(refusal.description)")
            return Abort(.badRequest)
        }
        if let api = error as? APIError {
            context.console.error("Refusing: \(api.message)")
            return Abort(api.status)
        }
        return error
    }

    static func consoleOwner(_ demo: StagingDemo, businessId: UUID, email: String, name: String?, context: CommandContext) async throws {
        let owner: (user: DashboardUserRecord, created: Bool)
        do { owner = try await demo.ensureConsoleOwner(businessId: businessId, email: email, displayName: name) } catch { throw refusal(error, context) }
        let link = try await demo.issueConsoleEnrollment(userId: owner.user.id!, businessId: businessId)
        context.console.print("")
        context.console.print(owner.created ? "Console owner created (Owner of \(StagingDemo.displayName))." : "Console owner already exists (Owner of \(StagingDemo.displayName)).")
        context.console.print("One-time passkey enrollment link (valid 1 hour, shown once; earlier links are revoked):")
        context.console.print("  \(link)")
        context.console.print("Open it, create a passkey, then sign in at \(demo.ctx.config.publicBaseURL)/dashboard/login.")
    }

    static func seedBrandKit(_ demo: StagingDemo, businessId: UUID, runtime: BrandKitRuntime, context: CommandContext) async throws {
        if !demo.ctx.config.brandKits.signingAvailable {
            context.console.warning("Brand manifest signing is not configured: an approved kit will not reach devices until it is.")
        }
        let seed: StagingDemo.BrandSeed
        do { seed = try await demo.seedBrandKit(businessId: businessId, runtime: runtime) } catch { throw refusal(error, context) }
        context.console.print("")
        context.console.print(seed.createdKit ? "Brand Kit \"\(StagingDemo.kitKey)\" saved and sent for Viadere review."
                                              : "Brand Kit \"\(StagingDemo.kitKey)\" already exists (left unchanged).")
        context.console.print("Operator review (any operator, fresh passkey): \(demo.ctx.config.publicBaseURL)\(OperatorBrand.path)")
        context.console.print("  1. Approve the logo image (asset \(seed.asset.id!.uuidString.lowercased())).")
        context.console.print("  2. Approve the kit (kit \(seed.kit.id!.uuidString.lowercased())); a kit can only be approved after its images.")
    }

    static func seedLoop(_ demo: StagingDemo, businessId: UUID, context: CommandContext) async throws {
        guard let owner = try await demo.consoleOwner(businessId: businessId) else { throw refusal(StagingDemo.ConsoleRefusal.noOwner, context) }
        let seed: StagingDemo.LoopSeed
        do { seed = try await demo.seedLoop(businessId: businessId, authorId: owner.id!) } catch { throw refusal(error, context) }
        context.console.print("")
        let look = seed.appearance == .standard
            ? "neutral styling; approve the \(StagingDemo.kitKey) kit, then run --seed-loop again for a branded revision" : "the \(StagingDemo.kitKey) Brand Kit"
        if let revision = seed.submitted {
            context.console.print("Loop \"\(seed.draft.loopKey)\" (template \(StagingDemo.loopTemplate), \(look)) submitted: revision \(revision.revision), "
                                  + "state \(revision.state), review \(revision.requiredReview).")
            context.console.print("Operator review: \(demo.ctx.config.publicBaseURL)\(OperatorLoops.base)/revisions/\(revision.id!.uuidString.lowercased())")
        } else {
            context.console.print("Loop \"\(seed.draft.loopKey)\" (\(look)) is already waiting for review or published; nothing submitted.")
        }
        context.console.print("Reviewers need loop_reviewer: ViadereServer grant-operator-permission --email <operator email> --permission loop_reviewer")
    }

    static func printStatus(_ demo: StagingDemo, businessId: UUID, context: CommandContext) async throws {
        let status = try await demo.status(businessId: businessId)
        let base = demo.ctx.config.publicBaseURL
        context.console.print("")
        context.console.print("Status")
        if let kit = status.kit {
            context.console.print("  Brand Kit \(kit.kitKey): \(kit.status), version \(kit.version)\(kit.approvedVersion.map { ", version \($0) approved" } ?? "")")
        } else {
            context.console.print("  Brand Kit: not seeded (--seed-brand-kit)")
        }
        if let logo = status.logo { context.console.print("  Logo image: \(logo.state)") }
        if status.kit != nil { context.console.print("  Brand review: \(base)\(OperatorBrand.path)") }
        guard let draft = status.draft else {
            context.console.print("  Loop: not seeded (--seed-loop)")
            return
        }
        if let revision = status.revision {
            context.console.print("  Loop \(draft.loopKey): revision \(revision.revision) \(revision.state) (risk \(revision.riskClass), review \(revision.requiredReview))")
            if revision.stateValue == .inReview { context.console.print("  Loop review: \(base)\(OperatorLoops.base)/revisions/\(revision.id!.uuidString.lowercased())") }
        } else {
            context.console.print("  Loop \(draft.loopKey): draft, not submitted")
        }
        if let publication = status.publication {
            context.console.print("  Published: publication id \(publication.id!.uuidString.lowercased()), revision \(publication.revision), rollout \(publication.rolloutPercent)%")
            if publication.rolloutPercent < 100 {
                context.console.print("  Customers can start it only inside the rollout; set it at \(base)\(OperatorLoops.base)/publications/\(publication.id!.uuidString.lowercased())")
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
