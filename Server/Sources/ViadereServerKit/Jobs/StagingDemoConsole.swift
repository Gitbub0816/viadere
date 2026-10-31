import Fluent
import Foundation
import Vapor
import ViadereCore

/// Staging demo, console half: an Owner for the Atlas Demo console with a one-time passkey enrollment link, and a seeded Brand Kit and Loop
/// that go through the **normal** review pipelines. Nothing here approves, publishes or signs anything: the kit, its image and the Loop
/// revision wait for a Viadere operator exactly like a business's own submissions (operator review is never bypassed).
///
/// Every function is on `StagingDemo`, whose initializer refuses any environment but staging, so none of this is reachable in production,
/// and none of it is reachable over HTTP (the command runs through `az containerapp exec`; its output goes to the caller's terminal only).
extension StagingDemo {
    enum ConsoleRefusal: Error, Equatable, CustomStringConvertible {
        case invalidEmail
        case invalidName
        /// The address already belongs to an operator, an unverified sign-up, a disabled account or a member of another organization: the
        /// command never hands a passkey enrollment link for an account that reaches anything but Atlas Demo.
        case accountInUse
        /// Seeding a Loop needs an Atlas Demo owner as its author (the reviewer must be someone else).
        case noOwner

        var description: String {
            switch self {
            case .invalidEmail: "Enter a valid email address."
            case .invalidName: "Enter a display name of 1 to 64 characters."
            case .accountInUse: "That address belongs to another console or operator account. Use a dedicated address for the demo owner."
            case .noOwner: "Atlas Demo has no console owner yet. Run staging-demo --console-owner <email> first."
            }
        }
    }

    static let defaultOwnerName = "Atlas Demo Owner"

    // MARK: Console owner

    /// The Atlas Demo Owner for `email`, created on first use: an **active** business console user (the email-verification step of
    /// normal sign-up is skipped: staging has no mail delivery, and this account can only reach Atlas Demo) with a live `owner`
    /// membership. Idempotent: the same address returns the same user and never a second membership.
    func ensureConsoleOwner(businessId: UUID, email rawEmail: String, displayName rawName: String?) async throws -> (user: DashboardUserRecord, created: Bool) {
        let auth = DashboardAuthService(db: db, ctx: ctx)
        guard let email = DashboardAuthService.normalizeEmail(rawEmail) else { throw ConsoleRefusal.invalidEmail }
        guard let name = auth.cleanName(rawName ?? Self.defaultOwnerName, max: 64) else { throw ConsoleRefusal.invalidName }
        let hash = auth.emailHash(email)
        let audit = AuditService(db: db, ctx: ctx)
        let system = AuditActor(kind: .system, id: Self.actor)
        if let existing = try await DashboardUserRecord.query(on: db).filter(\.$emailHash == hash).first() {
            guard existing.kind == "business", existing.status == "active", let userId = existing.id else { throw ConsoleRefusal.accountInUse }
            // Only an account that has only ever belonged to Atlas Demo (in practice: one this command created) is reused. A dormant account
            // whose memberships elsewhere were removed is still someone else's: no enrollment link is handed out for it.
            let history = try await OrgMembershipRecord.query(on: db).filter(\.$userId == userId).all()
            guard !history.isEmpty, history.allSatisfy({ $0.businessId == businessId }) else { throw ConsoleRefusal.accountInUse }
            let memberships = history.filter { $0.removedAt == nil }
            if let membership = memberships.first {
                if membership.role != OrgRole.owner.rawValue {
                    membership.role = OrgRole.owner.rawValue
                    try await membership.update(on: db)
                    _ = try await audit.record("staging_demo.console_owner_role_set", actor: system, businessId: BusinessID(businessId),
                                               subjectType: "user", subjectId: userId.uuidString.lowercased(), metadata: ["role": OrgRole.owner.rawValue])
                }
            } else {
                try await addOwner(userId: userId, businessId: businessId, on: db)
            }
            return (existing, false)
        }
        let userId = UUID()
        let user = DashboardUserRecord()
        user.id = userId
        user.kind = "business"
        user.emailHash = hash
        user.emailCiphertext = try ctx.cipher.seal(email, context: "dashboard_users.email", rowId: userId)
        user.displayName = name
        user.userHandle = SecureToken.generate(byteCount: 32)
        user.status = "active"
        user.createdAt = ctx.now
        try await db.transaction { tx in
            try await user.create(on: tx)
            try await addOwner(userId: userId, businessId: businessId, on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("staging_demo.console_owner_created", actor: system, businessId: BusinessID(businessId),
                                                               subjectType: "user", subjectId: userId.uuidString.lowercased(), metadata: ["role": OrgRole.owner.rawValue])
        }
        return (user, true)
    }

    private func addOwner(userId: UUID, businessId: UUID, on db: any Database) async throws {
        let membership = OrgMembershipRecord()
        membership.id = UUID()
        membership.businessId = businessId
        membership.userId = userId
        membership.role = OrgRole.owner.rawValue
        membership.createdAt = ctx.now
        try await membership.create(on: db)
    }

    /// A one-time, one-hour passkey enrollment link for `userId` on Atlas Demo: a random token, only its hash stored. Earlier open links
    /// for the user are revoked, so at most one link works at a time. The **only** place a console enrollment is created.
    func issueConsoleEnrollment(userId: UUID, businessId: UUID) async throws -> String {
        let token = SecureToken.generate()
        let now = ctx.now
        try await db.transaction { tx in
            try await ConsoleEnrollmentRecord.query(on: tx).filter(\.$userId == userId).filter(\.$state == "open").set(\.$state, to: "revoked").update()
            let enrollment = ConsoleEnrollmentRecord()
            enrollment.id = UUID()
            enrollment.userId = userId
            enrollment.businessId = businessId
            enrollment.tokenHash = SecureToken.hash(token)
            enrollment.state = "open"
            enrollment.createdAt = now
            enrollment.expiresAt = now.addingTimeInterval(ConsoleEnrollmentRecord.lifetime)
            try await enrollment.create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("staging_demo.console_enrollment_issued", actor: AuditActor(kind: .system, id: Self.actor),
                businessId: BusinessID(businessId), subjectType: "user", subjectId: userId.uuidString.lowercased(),
                metadata: ["expires_at": ViadereDate.format(enrollment.expiresAt)])
        }
        // The passkey ceremony runs on the dashboard origin (the RP ID's host), not the API host.
        return (ctx.config.dashboardOrigin ?? ctx.config.relyingPartyOrigin) + ConsoleEnrollmentRoutes.pagePrefix + token
    }

    /// The live Atlas Demo owner (the first one), if any.
    func consoleOwner(businessId: UUID) async throws -> DashboardUserRecord? {
        for membership in try await OrgMembershipRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$removedAt == nil)
            .filter(\.$role == OrgRole.owner.rawValue).sort(\.$createdAt, .ascending).all() {
            if let user = try await DashboardUserRecord.find(membership.userId, on: db), user.kind == "business", user.status == "active" { return user }
        }
        return nil
    }

    // MARK: Brand Kit seed

    static let kitKey = "atlas"
    static let kitName = "Atlas"
    /// Deep teal on ivory with a champagne accent. Every role passes `ContrastPolicy` in light and dark mode (primary 4.95:1 under ivory
    /// text, 3.11:1 on the dark background; accent 3.21:1 and 5.0:1), so the Studio shows no contrast warnings.
    static let kitTokens = BrandTokens(primary: BrandColor("#227470")!, accent: BrandColor("#A88545")!, surface: BrandColor("#FAF7F0")!,
                                       radius: .medium, border: .hairline, typeScale: .standard)
    static let actorAudit = AuditActor(kind: .system, id: actor)

    struct BrandSeed {
        var asset: BrandAssetRecord
        var kit: BrandKitRecord
        var createdKit: Bool
    }

    /// Uploads the generated logo through the real ingestion pipeline (`BrandAssetService.ingest`: rate limits, quotas, decode, re-encode,
    /// review state) and saves the kit through `BrandKitService.save` (validation, `pending_review`). Both wait for operator review.
    /// Idempotent: the same logo bytes return the same asset, and an existing `atlas` kit is left as it is (saving it again would start a
    /// new review).
    func seedBrandKit(businessId: UUID, runtime: BrandKitRuntime) async throws -> BrandSeed {
        let asset = try await BrandAssetService(db: db, ctx: ctx, runtime: runtime)
            .ingest(businessId: businessId, data: Self.demoLogoPNG(), declaredContentType: "image/png", slot: .logo, actor: Self.actorAudit)
        let service = BrandKitService(db: db, ctx: ctx)
        if let existing = try await BrandKitRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$kitKey == Self.kitKey).first() {
            return BrandSeed(asset: asset, kit: existing, createdKit: false)
        }
        let kit = try await service.save(businessId: businessId, kitId: nil, draft: .init(kitKey: Self.kitKey, name: Self.kitName, tokens: Self.kitTokens,
                                                                                          frameId: nil, assets: [.logo: asset.id!]), actor: Self.actorAudit)
        return BrandSeed(asset: asset, kit: kit, createdKit: true)
    }

    /// A 512 × 512 logo drawn in code: a deep-teal rounded square with an ivory "A" (two legs and a crossbar), transparent corners. Pure
    /// geometry, no font or external file; the bytes are deterministic, so re-running finds the same asset.
    static func demoLogoPNG() -> Data {
        let size = 512
        var rgba = [UInt8](repeating: 0, count: size * size * 4)
        let teal: (UInt8, UInt8, UInt8) = (0x22, 0x74, 0x70)
        let ivory: (UInt8, UInt8, UInt8) = (0xFA, 0xF7, 0xF0)
        func inRoundedSquare(_ x: Double, _ y: Double) -> Bool {
            let (lo, hi, r) = (32.0, 480.0, 96.0)
            guard x >= lo, x <= hi, y >= lo, y <= hi else { return false }
            let cx = min(max(x, lo + r), hi - r), cy = min(max(y, lo + r), hi - r)
            return (x - cx) * (x - cx) + (y - cy) * (y - cy) <= r * r
        }
        func distance(_ px: Double, _ py: Double, _ ax: Double, _ ay: Double, _ bx: Double, _ by: Double) -> Double {
            let (dx, dy) = (bx - ax, by - ay)
            let t = max(0, min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
            let (qx, qy) = (ax + t * dx - px, ay + t * dy - py)
            return (qx * qx + qy * qy).squareRoot()
        }
        for y in 0..<size {
            for x in 0..<size {
                let (px, py) = (Double(x) + 0.5, Double(y) + 0.5)
                guard inRoundedSquare(px, py) else { continue }
                let legs = min(distance(px, py, 256, 128, 160, 392), distance(px, py, 256, 128, 352, 392))
                let bar = distance(px, py, 200, 300, 312, 300)
                let color = legs <= 22 || bar <= 18 ? ivory : teal
                let i = (y * size + x) * 4
                (rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3]) = (color.0, color.1, color.2, 255)
            }
        }
        return BrandImagePipeline.encodePNG(BrandImagePipeline.Pixels(width: size, height: size, rgba: rgba)) ?? Data()
    }

    // MARK: Loop seed

    /// One reviewer suffices for this template (low risk, no review flags), so a single operator can approve it.
    static let loopTemplate = "pickup_time"

    struct LoopSeed {
        var draft: LoopStudioDraftRecord
        /// The revision this run submitted, or `nil` when one was already in review or published as wanted.
        var submitted: LoopRevisionRecord?
        var appearance: LoopAppearance
    }

    /// Creates (once) a Loop Studio draft from the `pickup_time` template and submits it **through `LoopStudioService.submit`**, the
    /// console's own path into `LoopPublicationService.submit` (hard gate, human review, signing after approval). The draft names the
    /// `atlas` kit when an operator has approved it, else it stays neutral. Nothing is submitted while a revision waits for review, or
    /// when the published revision already has the wanted appearance; after a rejection or a change of kit approval it submits again.
    func seedLoop(businessId: UUID, authorId: UUID) async throws -> LoopSeed {
        let studio = LoopStudioService(db: db, ctx: ctx)
        let draft: LoopStudioDraftRecord
        if let existing = try await LoopStudioDraftRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$templateKey == Self.loopTemplate)
            .sort(\.$createdAt, .ascending).first() {
            draft = existing
        } else {
            draft = try await studio.create(businessId: businessId, authorId: authorId, templateKey: Self.loopTemplate)
        }
        let kits = try await LoopPublicationService.approvedBrandKitKeys(businessId: businessId, on: db)
        let appearance: LoopAppearance = kits.contains(Self.kitKey) ? .brandKit(Self.kitKey) : .standard
        let revisions = try await studio.revisions(businessId: businessId, loopKey: draft.loopKey, limit: 50)
        if revisions.contains(where: { $0.stateValue == .inReview }) { return LoopSeed(draft: draft, submitted: nil, appearance: appearance) }
        if let live = revisions.first(where: { $0.stateValue == .published }),
           LoopDefinition.parse(Data(live.definitionJSON.utf8)).definition?.appearance == appearance {
            return LoopSeed(draft: draft, submitted: nil, appearance: appearance)
        }
        guard var definition = LoopStudioService.definition(draft) else { throw APIError.validation("The demo draft could not be read.") }
        var current = draft
        if definition.appearance != appearance {
            definition.appearance = appearance
            current = try await studio.save(businessId: businessId, id: draft.id!, expectedVersion: draft.version, definition: definition, authorId: authorId)
        }
        let revision = try await studio.submit(businessId: businessId, id: current.id!, expectedVersion: current.version, authorId: authorId)
        _ = try await AuditService(db: db, ctx: ctx).record("staging_demo.loop_submitted", actor: Self.actorAudit, businessId: BusinessID(businessId),
            subjectType: "loop_revision", subjectId: revision.id!.uuidString.lowercased(), metadata: ["template": Self.loopTemplate])
        return LoopSeed(draft: current, submitted: revision, appearance: appearance)
    }

    // MARK: Status

    struct Status {
        var kit: BrandKitRecord?
        var logo: BrandAssetRecord?
        var draft: LoopStudioDraftRecord?
        var revision: LoopRevisionRecord?
        var publication: LoopPublicationRecord?
    }

    func status(businessId: UUID) async throws -> Status {
        let kit = try await BrandKitRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$kitKey == Self.kitKey).first()
        var logo: BrandAssetRecord?
        if let kit, let id = BrandKitService.draftAssetIds(kit)[.logo] { logo = try await BrandAssetRecord.find(id, on: db) }
        let draft = try await LoopStudioDraftRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$templateKey == Self.loopTemplate)
            .sort(\.$createdAt, .ascending).first()
        var revision: LoopRevisionRecord?
        var publication: LoopPublicationRecord?
        if let draft {
            let revisions = try await LoopStudioService(db: db, ctx: ctx).revisions(businessId: businessId, loopKey: draft.loopKey, limit: 50)
            revision = revisions.first
            let ids = revisions.compactMap(\.id)
            if !ids.isEmpty {
                publication = try await LoopPublicationRecord.query(on: db).filter(\.$revisionId ~~ ids).filter(\.$status == LoopPublicationStatus.active.rawValue)
                    .sort(\.$revision, .descending).first()
            }
        }
        return Status(kit: kit, logo: logo, draft: draft, revision: revision, publication: publication)
    }
}
