import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// `staging-demo --console-owner / --seed-brand-kit / --seed-loop / --status`: refused outside staging; the console enrollment link is
/// hashed, single use, one hour, origin-checked and minted by no HTTP route; the owner reaches Atlas Demo only; seeding goes through the
/// real pipelines and leaves everything waiting for an operator (never approved or published by the command); re-runs do not duplicate.
final class StagingDemoConsoleTests: XCTestCase {
    static let ownerEmail = "demo-owner@viadere.test"

    func testConsoleOwnerAndSeedingAreRefusedOutsideStaging() async throws {
        try await withHarness { h in
            for environment in [DeploymentEnvironment.development, .testing, .production] {
                // Every console and seeding function hangs off `StagingDemo`, which cannot be made outside staging.
                XCTAssertThrowsError(try StagingDemo(db: h.db, ctx: h.ctx, environment: environment)) {
                    XCTAssertEqual($0 as? StagingDemo.Refusal, .notStaging)
                }
            }
            try await eq(try await ConsoleEnrollmentRecord.query(on: h.db).count(), 0)
            try await eq(try await DashboardUserRecord.query(on: h.db).count(), 0)
            try await eq(try await BrandKitRecord.query(on: h.db).count(), 0)
            try await eq(try await LoopStudioDraftRecord.query(on: h.db).count(), 0)
        }
    }

    func testEnrollmentLinkIsHashedSingleUseOriginCheckedAndSignsInToAtlasDemoOnly() async throws {
        try await withHarness { h in
            let demo = try StagingDemo(db: h.db, ctx: h.ctx, environment: .staging)
            let atlas = try await demo.ensureBusiness().id!
            let (owner, created) = try await demo.ensureConsoleOwner(businessId: atlas, email: Self.ownerEmail, displayName: nil)
            XCTAssertTrue(created)
            XCTAssertEqual(owner.status, "active")
            XCTAssertEqual(owner.kind, "business")
            // Re-running returns the same user and never a second membership.
            let (again, createdAgain) = try await demo.ensureConsoleOwner(businessId: atlas, email: " Demo-Owner@Viadere.test ", displayName: "Other")
            XCTAssertFalse(createdAgain)
            XCTAssertEqual(again.id, owner.id)
            try await eq(try await DashboardUserRecord.query(on: h.db).count(), 1)
            let memberships = try await OrgMembershipRecord.query(on: h.db).filter(\.$userId == owner.id!).all()
            XCTAssertEqual(memberships.map(\.businessId), [atlas])
            XCTAssertEqual(memberships.map(\.role), [OrgRole.owner.rawValue])

            let link = try await demo.issueConsoleEnrollment(userId: owner.id!, businessId: atlas)
            XCTAssertTrue(link.hasPrefix(h.ctx.config.publicBaseURL + "/dashboard/enroll/"))
            let token = String(link.split(separator: "/").last!)
            let stored = try await ConsoleEnrollmentRecord.query(on: h.db).first()!
            XCTAssertEqual(stored.tokenHash, SecureToken.hash(token))
            XCTAssertNotEqual(stored.tokenHash, token)
            XCTAssertEqual(stored.expiresAt, h.clock.now().addingTimeInterval(3600))
            try await eq(try await h.page("/dashboard/enroll/\(token)", nil).status, .ok)

            // A cross-site page cannot drive the ceremony.
            let foreign = try await h.request(.POST, ConsoleEnrollmentRoutes.beginPath, headers: ["Origin": "https://evil.example"],
                                              body: try ViadereJSON.encode(EnrollBeginBody(token: token)))
            XCTAssertEqual(foreign.status, .forbidden)
            // The operator realm does not accept a console token, and the console realm does not accept an operator token.
            try await eq(try await h.jsonPost("/operator/auth/enroll/begin", EnrollBeginBody(token: token)).status, .unprocessableEntity)
            let opLink = try await DashboardAuthService(db: h.db, ctx: h.ctx).createOperator(email: "ops@viadere.test", displayName: "Ops")
            try await eq(try await h.jsonPost(ConsoleEnrollmentRoutes.beginPath, EnrollBeginBody(token: String(opLink.split(separator: "/").last!))).status,
                         .unprocessableEntity)

            let begin = try await h.request(.POST, ConsoleEnrollmentRoutes.beginPath, headers: ["Origin": h.origin], body: try ViadereJSON.encode(EnrollBeginBody(token: token)))
            XCTAssertEqual(begin.status, .ok, begin.text)
            let options = try begin.json(PasskeyRegistrationOptions.self)
            let credentialId = SecureToken.generate(byteCount: 16)
            let publicKey = SecureToken.generate(byteCount: 32)
            let finish = try await h.jsonPost(ConsoleEnrollmentRoutes.finishPath,
                PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: h.registrationCredential(for: options, credentialId: credentialId, publicKey: publicKey)))
            XCTAssertEqual(finish.status, .ok, finish.text)
            let cookie = try XCTUnwrap(h.sessionCookie(finish, realm: .business))
            let session = DashSession(token: cookie.value, realm: .business)
            try await eq(try await ConsoleEnrollmentRecord.query(on: h.db).first()?.state, "used")
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == "dashboard.console_enrolled").count(), 1)

            // Single use: the page, a new ceremony and a replayed finish all fail.
            try await eq(try await h.page("/dashboard/enroll/\(token)", nil).status, .gone)
            try await eq(try await h.jsonPost(ConsoleEnrollmentRoutes.beginPath, EnrollBeginBody(token: token)).status, .unprocessableEntity)
            let replay = try await h.jsonPost(ConsoleEnrollmentRoutes.finishPath,
                PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: h.registrationCredential(for: options, credentialId: "second", publicKey: publicKey)))
            XCTAssertEqual(replay.status, .unauthorized)
            try await eq(try await DashboardPasskeyRecord.query(on: h.db).filter(\.$userId == owner.id!).count(), 1)

            // The console works for Brand Kit Studio and Loop Studio, and the normal passkey sign-in lands in Atlas Demo.
            for path in ["/dashboard", ConsoleBrandStudio.path, ConsoleLoopStudio.path] { try await eq(try await h.get(session, path), .ok, path) }
            let account = DashAccount(email: Self.ownerEmail, credentialId: credentialId, publicKey: publicKey, userId: owner.id!, businessId: atlas)
            let (login, result) = try await h.dashLogin(account)
            XCTAssertNotNil(login, result.text)
            try await eq(try await DashboardSessionRecord.query(on: h.db).filter(\.$userId == owner.id!).filter(\.$revokedAt == nil).all().map(\.businessId).allSatisfy { $0 == atlas }, true)

            // Atlas Demo only: switching to another organization is refused, and its owner's address cannot be taken over.
            let other = try await h.verifiedOwner(email: "owner@acme.test")
            let switched = try await h.formPost("/dashboard/switch", session, [("businessId", other.businessId.uuidString)])
            XCTAssertEqual(switched.status, .forbidden)
            do { _ = try await demo.ensureConsoleOwner(businessId: atlas, email: "owner@acme.test", displayName: nil); XCTFail("takeover") } catch {
                XCTAssertEqual(error as? StagingDemo.ConsoleRefusal, .accountInUse)
            }
            do { _ = try await demo.ensureConsoleOwner(businessId: atlas, email: "ops@viadere.test", displayName: nil); XCTFail("operator") } catch {
                XCTAssertEqual(error as? StagingDemo.ConsoleRefusal, .accountInUse)
            }
            // A dormant account (its only membership elsewhere was removed) is still someone else's.
            try await OrgMembershipRecord.query(on: h.db).filter(\.$businessId == other.businessId).set(\.$removedAt, to: h.clock.now()).update()
            do { _ = try await demo.ensureConsoleOwner(businessId: atlas, email: "owner@acme.test", displayName: nil); XCTFail("dormant takeover") } catch {
                XCTAssertEqual(error as? StagingDemo.ConsoleRefusal, .accountInUse)
            }
            try await eq(try await OrgMembershipRecord.query(on: h.db).filter(\.$businessId == atlas).count(), 1)
        }
    }

    func testEnrollmentLinksExpireAfterAnHourAndANewLinkRevokesTheOldOne() async throws {
        try await withHarness { h in
            let demo = try StagingDemo(db: h.db, ctx: h.ctx, environment: .staging)
            let atlas = try await demo.ensureBusiness().id!
            let owner = try await demo.ensureConsoleOwner(businessId: atlas, email: Self.ownerEmail, displayName: "Demo Owner").user
            let first = String(try await demo.issueConsoleEnrollment(userId: owner.id!, businessId: atlas).split(separator: "/").last!)
            let second = String(try await demo.issueConsoleEnrollment(userId: owner.id!, businessId: atlas).split(separator: "/").last!)
            try await eq(try await h.page("/dashboard/enroll/\(first)", nil).status, .gone, "a newer link revokes the older one")
            try await eq(try await h.page("/dashboard/enroll/\(second)", nil).status, .ok)
            // A ceremony begun before expiry cannot finish after it.
            let begin = try await h.jsonPost(ConsoleEnrollmentRoutes.beginPath, EnrollBeginBody(token: second))
            let options = try begin.json(PasskeyRegistrationOptions.self)
            h.clock.advance(by: 3601)
            try await eq(try await h.page("/dashboard/enroll/\(second)", nil).status, .gone)
            try await eq(try await h.jsonPost(ConsoleEnrollmentRoutes.beginPath, EnrollBeginBody(token: second)).status, .unprocessableEntity)
            let late = try await h.jsonPost(ConsoleEnrollmentRoutes.finishPath,
                PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: h.registrationCredential(for: options, credentialId: "late", publicKey: "pk")))
            XCTAssertEqual(late.status, .unauthorized)
            // A removed member's link is dead too.
            let third = String(try await demo.issueConsoleEnrollment(userId: owner.id!, businessId: atlas).split(separator: "/").last!)
            try await OrgMembershipRecord.query(on: h.db).filter(\.$userId == owner.id!).set(\.$removedAt, to: h.clock.now()).update()
            try await eq(try await h.page("/dashboard/enroll/\(third)", nil).status, .gone)
            try await eq(try await DashboardPasskeyRecord.query(on: h.db).count(), 0)
            // Garbage.
            try await eq(try await h.page("/dashboard/enroll/short", nil).status, .gone)
        }
    }

    /// No route creates a console enrollment: the only `enroll` routes open, begin or finish one, and a sweep of every POST route of the
    /// console and the operator console (signed in as the Atlas owner and as an operator, with valid CSRF tokens) mints nothing.
    func testNoHTTPRouteMintsConsoleEnrollmentLinks() async throws {
        try await withHarness { h in
            let consoleRoutes = h.app.routes.all.filter { ["dashboard", "operator"].contains($0.path.first.map { "\($0)" } ?? "") }
            let enrollRoutes = Set(consoleRoutes.filter { $0.path.contains { "\($0)".contains("enroll") } }
                .map { "\($0.method.rawValue) /" + $0.path.map { "\($0)" }.joined(separator: "/") })
            XCTAssertEqual(enrollRoutes, ["GET /dashboard/enroll/:token", "POST /dashboard/auth/enroll/begin", "POST /dashboard/auth/enroll/finish",
                                          "GET /operator/enroll/:token", "POST /operator/auth/enroll/begin", "POST /operator/auth/enroll/finish"])
            let demo = try StagingDemo(db: h.db, ctx: h.ctx, environment: .staging)
            let atlas = try await demo.ensureBusiness().id!
            let owner = try await demo.ensureConsoleOwner(businessId: atlas, email: Self.ownerEmail, displayName: nil).user
            let token = String(try await demo.issueConsoleEnrollment(userId: owner.id!, businessId: atlas).split(separator: "/").last!)
            let options = try await h.jsonPost(ConsoleEnrollmentRoutes.beginPath, EnrollBeginBody(token: token)).json(PasskeyRegistrationOptions.self)
            let finish = try await h.jsonPost(ConsoleEnrollmentRoutes.finishPath,
                PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: h.registrationCredential(for: options, credentialId: "c1", publicKey: "pk1")))
            let session = DashSession(token: try XCTUnwrap(h.sessionCookie(finish)).value, realm: .business)
            let (op, _) = try await h.makeOperator()
            let before = try await ConsoleEnrollmentRecord.query(on: h.db).count()
            let posts = consoleRoutes.filter { $0.method == .POST }.map { $0.path.map { "\($0)" } }.filter { !$0.contains("logout") }
            XCTAssertGreaterThan(posts.count, 20)
            let fields = [("email", Self.ownerEmail), ("userId", owner.id!.uuidString), ("businessId", atlas.uuidString), ("token", token)]
            for components in posts {
                let path = "/" + components.map { $0.hasPrefix(":") ? owner.id!.uuidString.lowercased() : $0 }.joined(separator: "/")
                for actor in [session, op] where components.first == (actor.realm == .business ? "dashboard" : "operator") {
                    _ = try await h.formPost(path, actor, fields)
                }
                _ = try await h.jsonPost(path, ["email": Self.ownerEmail, "token": token])
            }
            try await eq(try await ConsoleEnrollmentRecord.query(on: h.db).count(), before)
        }
    }

    // MARK: Seeding

    func testSeededBrandKitAndLoopWaitForOperatorReviewAndReRunsDoNotDuplicate() async throws {
        try await withHarness { h in
            let demo = try StagingDemo(db: h.db, ctx: h.ctx, environment: .staging)
            let atlas = try await demo.ensureBusiness().id!
            let owner = try await demo.ensureConsoleOwner(businessId: atlas, email: Self.ownerEmail, displayName: nil).user

            // The generated logo passes the real pipeline; the tokens pass the contrast policy without warnings.
            XCTAssertTrue(BrandPreview.contrastWarnings(StagingDemo.kitTokens).isEmpty, BrandPreview.contrastWarnings(StagingDemo.kitTokens).joined())
            guard case .success(let processed) = BrandImagePipeline.process(StagingDemo.demoLogoPNG(), declaredContentType: "image/png", slot: .logo) else {
                return XCTFail("the demo logo must pass ingestion")
            }
            XCTAssertEqual(processed.width, 512)
            let seed = try await demo.seedBrandKit(businessId: atlas, runtime: h.app.brandKits)
            XCTAssertTrue(seed.createdKit)
            XCTAssertEqual(seed.asset.state, BrandKitService.AssetState.pendingReview.rawValue)
            XCTAssertEqual(seed.kit.status, BrandKitService.KitStatus.pendingReview.rawValue)
            XCTAssertNil(seed.kit.approvedJSON)
            let rerun = try await demo.seedBrandKit(businessId: atlas, runtime: h.app.brandKits)
            XCTAssertFalse(rerun.createdKit)
            XCTAssertEqual(rerun.kit.id, seed.kit.id)
            XCTAssertEqual(rerun.asset.id, seed.asset.id)
            try await eq(try await BrandAssetRecord.query(on: h.db).count(), 1)
            try await eq(try await BrandKitRecord.query(on: h.db).count(), 1)
            try await eq(try await BrandManifestRecord.query(on: h.db).count(), 0, "nothing is published before review")

            // The Loop goes through the Studio into review; one reviewer suffices; nothing is published by the command.
            let loop = try await demo.seedLoop(businessId: atlas, authorId: owner.id!)
            let revision = try XCTUnwrap(loop.submitted)
            XCTAssertEqual(revision.stateValue, .inReview, revision.ruleHitsJSON)
            XCTAssertEqual(revision.requiredReview, LoopReviewLevel.single.rawValue)
            XCTAssertEqual(revision.templateKey, StagingDemo.loopTemplate)
            XCTAssertEqual(loop.appearance, .standard, "the kit is not approved yet")
            let loopRerun = try await demo.seedLoop(businessId: atlas, authorId: owner.id!)
            XCTAssertNil(loopRerun.submitted)
            try await eq(try await LoopStudioDraftRecord.query(on: h.db).count(), 1)
            try await eq(try await LoopRevisionRecord.query(on: h.db).count(), 1)
            try await eq(try await LoopPublicationRecord.query(on: h.db).count(), 0)
            var status = try await demo.status(businessId: atlas)
            XCTAssertEqual(status.revision?.id, revision.id)
            XCTAssertNil(status.publication)

            // An operator approves the image, then the kit, through the normal review pages (fresh passkey).
            let (op, account) = try await h.makeOperator()
            try await eq(try await h.dashReauth(op, account).status, .ok)
            try await eq(try await h.formPost("/operator/brand/kits/\(seed.kit.id!.uuidString.lowercased())/approve", op).status, .conflict,
                         "a kit cannot be approved before its image")
            try await eq(try await h.formPost("/operator/brand/assets/\(seed.asset.id!.uuidString.lowercased())/approve", op).status, .seeOther)
            try await eq(try await h.formPost("/operator/brand/kits/\(seed.kit.id!.uuidString.lowercased())/approve", op).status, .seeOther)
            try await eq(try await BrandKitRecord.find(seed.kit.id!, on: h.db)?.status, BrandKitService.KitStatus.approved.rawValue)

            // The Loop needs `loop_reviewer`: refused without it, published by one reviewer with it.
            let decide = "/operator/loops/revisions/\(revision.id!.uuidString.lowercased())/decide"
            let pairs = [("decision", "approve"), ("reason", "Demo pickup Loop checked.")]
            try await eq(try await h.formPost(decide, op, pairs).status, .forbidden)
            try await OperatorPermissions(db: h.db, ctx: h.ctx).set(email: "ops@viadere.test", permission: .loopReviewer, granted: true)
            try await eq(try await h.formPost(decide, op, pairs).status, .seeOther)
            try await eq(try await LoopRevisionRecord.find(revision.id!, on: h.db)?.stateValue, .published)
            status = try await demo.status(businessId: atlas)
            let publication = try XCTUnwrap(status.publication)
            XCTAssertEqual(publication.revisionId, revision.id)

            // With the kit approved, a re-run submits a branded revision for review (it does not publish it).
            let branded = try await demo.seedLoop(businessId: atlas, authorId: owner.id!)
            XCTAssertEqual(branded.appearance, .brandKit(StagingDemo.kitKey))
            XCTAssertEqual(try XCTUnwrap(branded.submitted).stateValue, .inReview)
            let settled = try await demo.seedLoop(businessId: atlas, authorId: owner.id!)
            XCTAssertNil(settled.submitted, "a branded revision is already waiting for review")
            try await eq(try await LoopRevisionRecord.query(on: h.db).count(), 2)
            try await eq(try await LoopPublicationRecord.query(on: h.db).count(), 1)
            try await eq(try await LoopStudioDraftRecord.query(on: h.db).count(), 1)
        }
    }
}
