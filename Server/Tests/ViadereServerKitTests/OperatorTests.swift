import Fluent
import Foundation
import ViadereCore
import Vapor
import XCTest
@testable import ViadereServerKit

final class OperatorTests: XCTestCase {
    // MARK: Enrollment and session policy

    func testOperatorEnrollmentLinksAreSingleUseShortLivedAndStoredHashed() async throws {
        try await withHarness { h in
            let link = try await DashboardAuthService(db: h.db, ctx: h.ctx).createOperator(email: "ops@viadere.test", displayName: "Ops")
            let token = String(link.split(separator: "/").last!)
            let enrollment = try await OperatorEnrollmentRecord.query(on: h.db).first()!
            XCTAssertEqual(enrollment.tokenHash, SecureToken.hash(token))
            XCTAssertNotEqual(enrollment.tokenHash, token)
            try await eq(try await h.page("/operator/enroll/\(token)", nil).status, .ok)
            // A pending operator cannot sign in before enrolling.
            try await eq(try await DashboardUserRecord.query(on: h.db).filter(\.$kind == "operator").first()?.status, "pending")
            let begin = try await h.jsonPost("/operator/auth/enroll/begin", EnrollBeginBody(token: token))
            let options = try begin.json(PasskeyRegistrationOptions.self)
            let cred = h.registrationCredential(for: options, credentialId: "op-cred", publicKey: SecureToken.generate(byteCount: 32))
            let finish = try await h.jsonPost("/operator/auth/enroll/finish", PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: cred))
            XCTAssertEqual(finish.status, .ok, finish.text)
            XCTAssertEqual(h.sessionCookie(finish, realm: .operator)?.name, "__Host-vd_operator")
            // The token is dead afterwards.
            try await eq(try await h.page("/operator/enroll/\(token)", nil).status, .gone)
            try await eq(try await h.jsonPost("/operator/auth/enroll/begin", EnrollBeginBody(token: token)).status, .unprocessableEntity)
            // Expiry.
            let link2 = try await DashboardAuthService(db: h.db, ctx: h.ctx).createOperator(email: "ops2@viadere.test", displayName: "Ops2")
            let token2 = String(link2.split(separator: "/").last!)
            h.clock.advance(by: 3601)
            try await eq(try await h.page("/operator/enroll/\(token2)", nil).status, .gone)
            // Garbage.
            try await eq(try await h.page("/operator/enroll/short", nil).status, .gone)
        }
    }

    func testOperatorSessionsAreShorterAndEveryMutationNeedsFreshReauth() async throws {
        try await withHarness { h in
            let (op, account) = try await h.makeOperator()
            let (_, _, businessId) = try await {
                let (s, a, _) = try await h.dashSignup()
                return (s, a, a.businessId!)
            }()
            try await eq(try await h.page("/operator", op).status, .ok)
            // Re-auth lapses after 5 minutes: the approve button asks for the passkey instead of acting.
            h.clock.advance(by: 6 * 60)
            try await eq(try await h.page("/operator", op).status, .ok)
            let denied = try await h.formPost("/operator/applications/\(businessId.uuidString.lowercased())/approve", op)
            XCTAssertEqual(denied.status, .forbidden)
            XCTAssertTrue(denied.text.contains("Confirm with passkey"))
            XCTAssertTrue(denied.text.contains("/operator/auth/reauth/begin"))
            try await eq(try await BusinessRecord.find(businessId, on: h.db)?.status, .pending)
            let reauth = try await h.dashReauth(op, account)
            XCTAssertEqual(reauth.status, .ok)
            try await eq(try await h.formPost("/operator/applications/\(businessId.uuidString.lowercased())/approve", op).status, .seeOther)
            try await eq(try await BusinessRecord.find(businessId, on: h.db)?.status, .verified)
            // Operators time out after 15 idle minutes (business users get 30).
            h.clock.advance(by: 16 * 60)
            try await eq(try await h.page("/operator", op).status, .seeOther)
            // No CSRF token, no action.
            let (op2, _) = try await h.dashLogin(account, realm: .operator)
            let fresh = try XCTUnwrap(op2)
            try await eq(try await h.formPost("/operator/logout", fresh, includeCSRF: false).status, .forbidden)
        }
    }

    // MARK: Verification workflow

    func testApplicationIsReviewedThenVerifiedAndOnlyThenGetsAHandleAndCode() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            let (owner, _, _) = try await h.dashSignup(org: "Acme Roasters", handle: "acmeroasters")
            let businessId = try await BusinessRecord.query(on: h.db).first()!.id!
            // The operator sees the application, including the owner's contact and requested handle.
            let queue = try await h.page("/operator", op).text
            XCTAssertTrue(queue.contains("Acme Roasters"))
            XCTAssertTrue(queue.contains("@acmeroasters"))
            let detail = try await h.page("/operator/applications/\(businessId.uuidString.lowercased())", op).text
            XCTAssertTrue(detail.contains("owner@example.com"))
            XCTAssertTrue(detail.contains("Verify business"))
            // Before approval: nothing public, nothing issued.
            try await eq(try await BusinessHandleRecord.query(on: h.db).count(), 0)
            try await eq(try await BusinessCodeRecord.query(on: h.db).count(), 0)
            let approve = try await h.formPost("/operator/applications/\(businessId.uuidString.lowercased())/approve", op, [("note", "Documents checked")])
            XCTAssertEqual(approve.status, .seeOther)
            let business = try await XCTUnwrapAsync(await BusinessRecord.find(businessId, on: h.db))
            XCTAssertEqual(business.status, .verified)
            XCTAssertNotNil(business.verifiedAt)
            let handle = try await XCTUnwrapAsync(await BusinessHandleRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            XCTAssertEqual(handle.handle, "acmeroasters")
            let code = try await XCTUnwrapAsync(await BusinessCodeRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            // Now discoverable by handle, code and name.
            let byHandle = try await h.request(.GET, "/v1/directory/handles/@acmeroasters")
            XCTAssertEqual(byHandle.status, .ok)
            try await eq(try await h.request(.GET, "/v1/directory/codes/\(code.canonical)").status, .ok)
            try await eq(try await h.request(.GET, "/v1/directory/search?q=acme").json(Page<BusinessSummary>.self).items.count, 1)
            // The application is closed, audited by the operator, and cannot be decided twice.
            let app = try await XCTUnwrapAsync(await BusinessApplicationRecord.query(on: h.db).first())
            XCTAssertEqual(app.state, "approved")
            XCTAssertEqual(app.decisionNote, "Documents checked")
            let audit = try await XCTUnwrapAsync(await AuditEventRecord.query(on: h.db).filter(\.$action == "business.verified").first())
            XCTAssertEqual(audit.actorKind, "operator")
            XCTAssertEqual(audit.businessId, businessId)
            try await eq(try await h.formPost("/operator/applications/\(businessId.uuidString.lowercased())/approve", op).status, .conflict)
            try await eq(try await h.formPost("/operator/applications/\(businessId.uuidString.lowercased())/reject", op).status, .conflict)
            // The organization's own dashboard now shows the identity and unlocks keys.
            let org = try await h.page("/dashboard/organization", owner).text
            XCTAssertTrue(org.contains("@acmeroasters"))
            XCTAssertTrue(org.contains(code.canonical.prefix(2)))
            try await eq(try await h.formPost("/dashboard/api-keys", owner, [("name", "k"), ("mode", "test"), ("scopes[]", "interactions:read")]).status, .ok)
        }
    }

    func testHandleConflictsRollBackTheApprovalAndAnOverrideResolvesThem() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            let (_, _, _) = try await h.dashSignup(email: "a@example.com", org: "First Co", handle: "samehandle")
            let (_, second, _) = try await h.dashSignup(email: "b@example.com", org: "Second Co", handle: "samehandle")
            let first = try await BusinessRecord.query(on: h.db).filter(\.$displayName == "First Co").first()!.id!
            let secondId = second.businessId!
            try await eq(try await h.formPost("/operator/applications/\(first.uuidString.lowercased())/approve", op).status, .seeOther)
            // The handle is now taken; the second approval fails as a whole.
            try await eq(try await h.formPost("/operator/applications/\(secondId.uuidString.lowercased())/approve", op).status, .conflict)
            try await eq(try await BusinessRecord.find(secondId, on: h.db)?.status, .pending)
            try await eq(try await BusinessCodeRecord.query(on: h.db).filter(\.$businessId == secondId).count(), 0)
            try await eq(try await BusinessHandleRecord.query(on: h.db).filter(\.$businessId == secondId).count(), 0)
            // A look-alike is refused as well (confusable skeletons are unique).
            try await eq(try await h.formPost("/operator/applications/\(secondId.uuidString.lowercased())/approve", op, [("handle", "sarnehandle")]).status, .conflict)
            // The operator picks another handle.
            try await eq(try await h.formPost("/operator/applications/\(secondId.uuidString.lowercased())/approve", op, [("handle", "secondco")]).status, .seeOther)
            try await eq(try await BusinessHandleRecord.query(on: h.db).filter(\.$businessId == secondId).first()?.handle, "secondco")
        }
    }

    func testDeclinedApplicationsStayPendingShowTheReasonAndCanApplyAgain() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            let (owner, account, _) = try await h.dashSignup()
            let id = account.businessId!
            try await eq(try await h.formPost("/operator/applications/\(id.uuidString.lowercased())/reject", op, [("note", "Please add your registered company name")]).status, .seeOther)
            try await eq(try await BusinessRecord.find(id, on: h.db)?.status, .pending)
            try await eq(try await BusinessCodeRecord.query(on: h.db).count(), 0)
            try await eq(try await h.page("/operator", op).text.contains("Acme Roasters"), false, "no longer in the pending queue")
            let org = try await h.page("/dashboard/organization", owner).text
            XCTAssertTrue(org.contains("Please add your registered company name"))
            XCTAssertTrue(org.contains("Apply again"))
            try await eq(try await h.formPost("/dashboard/organization", owner, [("legalName", "Acme Roasters Ltd"), ("website", "https://acme.example.com"), ("requestedHandle", "acmeroasters2"), ("description", "Updated")]).status, .seeOther)
            let app = try await XCTUnwrapAsync(await BusinessApplicationRecord.query(on: h.db).first())
            XCTAssertEqual(app.state, "pending")
            XCTAssertEqual(app.requestedHandle, "acmeroasters2")
            try await isTrue(try await h.page("/operator", op).text.contains("Acme Roasters"))
            // A pending (not declined) application cannot be edited by the applicant.
            try await eq(try await h.formPost("/dashboard/organization", owner, [("legalName", "X")]).status, .conflict)
            try await eq(try await h.formPost("/operator/applications/\(id.uuidString.lowercased())/approve", op).status, .seeOther)
            try await eq(try await BusinessHandleRecord.query(on: h.db).first()?.handle, "acmeroasters2")
        }
    }

    func testUnverifiedOrganizationsCannotIssueInteractionsByAnyRoute() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let (_, account, _) = try await h.dashSignup()
            let id = account.businessId!
            // Even with a key minted directly in the database, a pending business is refused at the API...
            let key = try await BusinessAPIKeys.issue(businessId: id, name: "sneaky", live: true, scopes: BusinessAPIKeys.Scope.all, now: h.clock.now(), on: h.db)
            let request = IssueInteractionRequest(relationshipId: RelationshipID(), purpose: .transactional, payload: .confirm(ConfirmPayload(title: "t")),
                                                  allowedChannels: [.nativePush], ttlSeconds: 300, idempotencyKey: "x")
            let viaAPI = try await h.request(.POST, "/v1/business/interactions", headers: ["Authorization": "Bearer \(key.key)", "Idempotency-Key": "x"], body: try ViadereJSON.encode(request))
            XCTAssertEqual(viaAPI.status, .forbidden)
            // ...the service refuses on its own (defence in depth behind the middleware)...
            let principal = BusinessPrincipal(businessId: BusinessID(id), keyId: key.record.id!, livemode: true, scopes: Set(BusinessAPIKeys.Scope.all), businessName: "x")
            do {
                _ = try await InteractionService(db: h.db, ctx: h.ctx).issue(principal: principal, request: request, headerKey: "x")
                XCTFail("issued for an unverified business")
            } catch let error as APIError {
                XCTAssertEqual(error.status, .forbidden)
            }
            // ...consumers cannot connect to it, and it is invisible in the directory.
            let connect = try await h.signedPost(consumer, APIRoutes.relationshipConnect.template, ConnectRequest(businessId: BusinessID(id), source: .code))
            XCTAssertEqual(connect.status, .notFound)
            try await eq(try await h.request(.GET, "/v1/directory/search?q=acme").json(Page<BusinessSummary>.self).items.count, 0)
            try await eq(try await InteractionRecord.query(on: h.db).count(), 0)
        }
    }

    // MARK: Suspension

    func testSuspendingABusinessBlocksItsAPIKeysAndInteractionsImmediately() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            let (_, ownerAccount, businessId) = try await h.verifiedOwner()
            let business = try await h.testBusiness(businessId)
            let consumer = try await h.readyConsumer()
            let relationship = try await h.connect(consumer, to: business)
            let issued = try await h.issue(business, relationship: relationship, payload: .confirm(ConfirmPayload(title: "Pending one")), purpose: .transactional, key: "s1")
            XCTAssertEqual(issued.status, .created)
            let interaction = try issued.json(Interaction.self)
            try await eq(try await h.business(business, .GET, "/v1/business/webhooks").status, .ok)
            // The operator suspends it with a reason.
            let suspend = try await h.formPost("/operator/businesses/\(businessId.uuidString.lowercased())/suspend", op, [("reason", "Complaints under review")])
            XCTAssertEqual(suspend.status, .seeOther)
            try await eq(try await BusinessRecord.find(businessId, on: h.db)?.status, .suspended)
            // No restart, no cache: the very next calls are refused.
            let after = try await h.issue(business, relationship: relationship, payload: .confirm(ConfirmPayload(title: "Nope")), purpose: .transactional, key: "s2")
            XCTAssertEqual(after.status, .forbidden)
            try await eq(try await h.business(business, .GET, "/v1/business/webhooks").status, .forbidden)
            try await eq(try await h.business(business, .GET, "/v1/business/interactions/\(interaction.id)").status, .forbidden)
            // Pending interactions were cancelled and can no longer be decided.
            try await eq(try await InteractionRecord.find(interaction.id.uuid, on: h.db)?.statusValue, .cancelled)
            let consumerView = try await h.consumerInteraction(consumer, id: interaction.id)
            let signed = try await h.decision(consumer, interaction: consumerView, decision: .confirm, assurance: .devicePasscode)
            try await neq(try await h.decide(consumer, id: interaction.id, signed: signed).status, .ok)
            // It disappears from the directory and cannot receive new connections or SMS routing.
            try await eq(try await h.request(.GET, "/v1/directory/search?q=acme").json(Page<BusinessSummary>.self).items.count, 0)
            let other = try await h.readyConsumer(name: "Other")
            try await eq(try await h.signedPost(other, APIRoutes.relationshipConnect.template, ConnectRequest(businessId: business.id, source: .code)).status, .notFound)
            // The business's own dashboard says so and blocks actions that need verification.
            let relogin = try await h.dashLogin(ownerAccount)
            let page = try await h.page("/dashboard/api-keys", try XCTUnwrap(relogin.session)).text
            XCTAssertTrue(page.contains("suspended"))
            XCTAssertFalse(page.contains("Create a key"))
            // Audited by the operator; reinstating restores access.
            let events = try await AuditEventRecord.query(on: h.db).filter(\.$action == "business.suspended").all()
            XCTAssertEqual(events.count, 1)
            XCTAssertEqual(events[0].actorKind, "operator")
            try await eq(try await h.formPost("/operator/businesses/\(businessId.uuidString.lowercased())/unsuspend", op).status, .seeOther)
            try await eq(try await h.business(business, .GET, "/v1/business/webhooks").status, .ok)
            try await eq(try await h.issue(business, relationship: relationship, payload: .confirm(ConfirmPayload(title: "Back")), purpose: .transactional, key: "s3").status, .created)
            // Only verified businesses can be suspended; suspended ones cannot be suspended again.
            try await eq(try await h.formPost("/operator/businesses/\(businessId.uuidString.lowercased())/suspend", op, [("reason", "again")]).status, .seeOther)
            try await eq(try await h.formPost("/operator/businesses/\(businessId.uuidString.lowercased())/suspend", op, [("reason", "twice")]).status, .conflict)
        }
    }

    func testBusinessSessionsCannotReachTheOperatorConsole() async throws {
        try await withHarness { h in
            let (owner, _, id) = try await h.verifiedOwner()
            for path in ["/operator", "/operator/businesses", "/operator/abuse", "/operator/businesses/\(id.uuidString.lowercased())"] {
                try await eq(try await h.page(path, DashSession(token: owner.token, realm: .operator)).status, .seeOther, path)
                try await eq(try await h.page(path, owner).status, .seeOther, path)
            }
            let suspend = try await h.formPost("/operator/businesses/\(id.uuidString.lowercased())/suspend", DashSession(token: owner.token, realm: .operator), [("reason", "x")])
            XCTAssertEqual(suspend.status, .seeOther)
            try await eq(try await BusinessRecord.find(id, on: h.db)?.status, .verified)
        }
    }

    // MARK: Trust overrides (downward only) and the Trust Engine invariant

    func testOperatorCeilingsOnlyEverLowerPriorityAndCannotBeRaisedByAnyone() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            let (_, _, businessId) = try await h.verifiedOwner()
            let business = try await h.testBusiness(businessId)
            let consumer = try await h.readyConsumer()
            let relationship = try await h.connect(consumer, to: business)
            func priority(_ key: String, requested: InteractionPriority) async throws -> InteractionPriority {
                let r = try await h.issue(business, relationship: relationship, payload: .confirm(ConfirmPayload(title: "t")), purpose: .security, priority: requested, key: key)
                XCTAssertEqual(r.status, .created, r.text)
                return try r.json(Interaction.self).priority
            }
            let base = "/operator/businesses/\(businessId.uuidString.lowercased())"
            try await eq(try await priority("p1", requested: .high), .high)
            try await eq(try await h.formPost("\(base)/ceiling", op, [("ceiling", "normal")]).status, .seeOther)
            try await eq(try await priority("p2", requested: .high), .normal)
            try await eq(try await priority("p3", requested: .low), .low, "a ceiling never raises")
            try await eq(try await h.formPost("\(base)/ceiling", op, [("ceiling", "low")]).status, .seeOther)
            try await eq(try await priority("p4", requested: .normal), .low)
            // There is no way to grant more than the Trust Engine allows: urgent is not an accepted ceiling.
            try await eq(try await h.formPost("\(base)/ceiling", op, [("ceiling", "urgent")]).status, .unprocessableEntity)
            try await eq(try await h.formPost("\(base)/ceiling", op, [("ceiling", "supreme")]).status, .unprocessableEntity)
            try await eq(try await BusinessControls.load(businessId, on: h.db)?.priorityCeiling, "low")
            // Removing the cap only restores the default clamp (marketing still cannot exceed normal, etc.).
            try await eq(try await h.formPost("\(base)/ceiling", op, [("ceiling", "none")]).status, .seeOther)
            try await eq(try await priority("p5", requested: .urgent), .high, "non-security-kind urgent is clamped to high")
            XCTAssertEqual(BusinessControls.applyCeiling(.urgent, controls: nil), .urgent)
            // Unit: a ceiling is always min().
            let record = BusinessControlRecord()
            record.priorityCeiling = "normal"
            for requested in InteractionPriority.allCases {
                XCTAssertLessThanOrEqual(BusinessControls.applyCeiling(requested, controls: record), requested)
                XCTAssertLessThanOrEqual(BusinessControls.applyCeiling(requested, controls: record), .normal)
            }
            // The business cannot change its own controls: no dashboard route exists for it.
            let (owner, _, _) = try await h.dashSignup(email: "other@example.com", org: "Other Co", handle: nil)
            try await eq(try await h.formPost("\(base)/ceiling", owner, [("ceiling", "none")]).status, .seeOther)
            try await eq(try await BusinessControls.load(businessId, on: h.db)?.priorityCeiling, nil)
        }
    }

    func testPayingNeverChangesSecurityPriorityOrBypassesConsent() async throws {
        try await withHarness { h in
            let free = try await h.makeBusiness(name: "Free Fruit", handle: "freefruit", tier: "free", quota: 1000)
            let paid = try await h.makeBusiness(name: "Paid Pears", handle: "paidpears", tier: "paid", quota: 1_000_000)
            let consumer = try await h.readyConsumer()
            let relFree = try await h.connect(consumer, to: free)
            let relPaid = try await h.connect(consumer, to: paid)
            XCTAssertEqual(paid.record.tier, "paid")
            let combos: [(InteractionPurpose, InteractionPayload)] = [
                (.marketing, .message(MessagePayload(text: "Sale"))), (.transactional, .confirm(ConfirmPayload(title: "t"))),
                (.support, .confirm(ConfirmPayload(title: "t"))), (.security, .confirm(ConfirmPayload(title: "t"))),
                (.security, .authorize(AuthorizePayload.sample())),
            ]
            var n = 0
            for (purpose, payload) in combos {
                for requested in InteractionPriority.allCases {
                    n += 1
                    let sensitivity: Sensitivity = payload.kind == .authorize ? .high : .standard
                    let a = try await h.issue(free, relationship: relFree, payload: payload, purpose: purpose, priority: requested, sensitivity: sensitivity, key: "a\(n)")
                    let b = try await h.issue(paid, relationship: relPaid, payload: payload, purpose: purpose, priority: requested, sensitivity: sensitivity, key: "b\(n)")
                    XCTAssertEqual(a.status, b.status, "\(purpose) \(requested)")
                    if a.status == .created {
                        let pa = try a.json(Interaction.self).priority, pb = try b.json(Interaction.self).priority
                        XCTAssertEqual(pa, pb, "tier must not matter: \(purpose) \(requested)")
                        XCTAssertEqual(pa, TrustEngine.clampPriority(requested: requested, kind: payload.kind!, purpose: purpose))
                        if purpose == .marketing { XCTAssertLessThanOrEqual(pb, .normal) }
                    } else {
                        // Marketing needs opt-in consent: both tiers are refused the same way.
                        XCTAssertEqual(purpose, .marketing)
                        XCTAssertEqual(a.errorCode, .consentRequired)
                        XCTAssertEqual(b.errorCode, .consentRequired)
                    }
                }
            }
            // Urgent stays reserved for security authorize/authenticate, for everyone.
            XCTAssertEqual(TrustEngine.clampPriority(requested: .urgent, kind: .authorize, purpose: .security), .urgent)
            XCTAssertEqual(TrustEngine.clampPriority(requested: .urgent, kind: .confirm, purpose: .security), .high)
            XCTAssertEqual(TrustEngine.clampPriority(requested: .urgent, kind: .message, purpose: .marketing), .normal)
            // Security-kind sensitivity cannot be lowered by a paying customer either.
            let lowered = try await h.issue(paid, relationship: relPaid, payload: .authorize(AuthorizePayload.sample()), purpose: .security, sensitivity: .low, key: "lowered")
            XCTAssertEqual(try lowered.json(Interaction.self).sensitivity >= .standard, true)
        }
    }

    func testTheTrustPathNeverReadsTheBillingTier() throws {
        // Structural guard: priority, consent and routing code must not even reference the tier column.
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/ViadereServerKit")
        for file in ["Services/InteractionService.swift", "Platform/BusinessControls.swift", "Channels/ChannelRouter.swift", "Platform/AbuseService.swift",
                     "Platform/BusinessOnboarding.swift", "Channels/RCSInbound.swift", "Services/RelationshipService.swift"] {
            let text = try String(contentsOf: root.appendingPathComponent(file), encoding: .utf8)
            XCTAssertNil(text.range(of: "\\.tier\\b|\"tier\"|\\btier:", options: .regularExpression), "\(file) must not read the billing tier")
        }
    }

    // MARK: Abuse thresholds and automatic throttling

    func testComplaintRateAboveTheThresholdThrottlesAutomaticallyAndLiftsWhenItRecovers() async throws {
        try await withHarness({ $0.abuse.minimumSample = 5; $0.abuse.complaintRate = 0.02 }) { h in
            let b = try await h.makeBusiness(name: "Noisy Co", handle: "noisyco", quota: 8)
            var consumers: [TestConsumer] = []
            var interactions: [Interaction] = []
            for i in 0..<6 {
                h.clock.advance(by: 30) // consumer registration is rate limited per IP
                let c = try await h.readyConsumer(name: "C\(i)")
                let rel = try await h.connect(c, to: b)
                let r = try await h.issue(b, relationship: rel, payload: .confirm(ConfirmPayload(title: "t")), purpose: .transactional, key: "n\(i)", ttl: 7200)
                XCTAssertEqual(r.status, .created)
                consumers.append(c)
                interactions.append(try r.json(Interaction.self))
            }
            let service = AbuseService(db: h.db, ctx: h.ctx)
            // 0 reports: fine.
            let initial = try await service.evaluate(businessId: b.id.uuid)
            XCTAssertEqual(initial, .ok)
            // One "I don't recognize this" report out of six is 16.7% > 2%.
            let view = try await h.consumerInteraction(consumers[0], id: interactions[0].id)
            let report = try await h.decision(consumers[0], interaction: view, decision: .report, assurance: .none)
            try await eq(try await h.decide(consumers[0], id: view.id, signed: report).status, .ok)
            let metrics = try await service.metrics(for: b.id.uuid)
            XCTAssertEqual(metrics.reports, 1)
            XCTAssertEqual(metrics.issued, 6)
            XCTAssertEqual(metrics.complaintRate, 1.0 / 6.0, accuracy: 0.0001)
            let verdict = try await service.evaluate(businessId: b.id.uuid)
            XCTAssertEqual(verdict, .throttled(reason: "complaint_rate"))
            let controls = try await XCTUnwrapAsync(await BusinessControls.load(b.id.uuid, on: h.db))
            XCTAssertTrue(controls.throttled)
            XCTAssertEqual(controls.throttleSource, "auto")
            // Throttled: the daily quota (8) is cut to a quarter (2) and 6 are already used.
            let rel = try await h.connect(consumers[1], to: b)
            let blocked = try await h.issue(b, relationship: rel, payload: .confirm(ConfirmPayload(title: "more")), purpose: .transactional, key: "more")
            XCTAssertEqual(blocked.status, .tooManyRequests)
            // Evaluating again changes nothing; it is audited exactly once.
            let again = try await service.evaluate(businessId: b.id.uuid)
            XCTAssertEqual(again, .unchanged)
            let audits = try await AuditEventRecord.query(on: h.db).filter(\.$action == "abuse.auto_throttled").all()
            XCTAssertEqual(audits.count, 1)
            XCTAssertEqual(audits[0].actorKind, "system")
            // Once the window has passed with no complaints, the automatic throttle lifts itself.
            h.clock.advance(by: 8 * 86_400)
            let lifted = try await service.evaluate(businessId: b.id.uuid)
            XCTAssertEqual(lifted, .lifted)
            try await eq(try await BusinessControls.load(b.id.uuid, on: h.db)?.throttled, false)
            try await eq(try await h.issue(b, relationship: rel, payload: .confirm(ConfirmPayload(title: "ok again")), purpose: .transactional, key: "again").status, .created)
        }
    }

    func testOptOutRateThrottlesAndAnOperatorPinnedThrottleIsNotLiftedAutomatically() async throws {
        try await withHarness({ $0.abuse.minimumSample = 5; $0.abuse.optOutRate = 0.10 }) { h in
            let (op, _) = try await h.makeOperator()
            let b = try await h.makeBusiness(name: "Pushy Co", handle: "pushyco")
            var rels: [(TestConsumer, Relationship)] = []
            for i in 0..<6 {
                h.clock.advance(by: 30)
                let c = try await h.readyConsumer(name: "C\(i)")
                rels.append((c, try await h.connect(c, to: b)))
            }
            let service = AbuseService(db: h.db, ctx: h.ctx)
            let initial = try await service.evaluate(businessId: b.id.uuid)
            XCTAssertEqual(initial, .ok)
            // One disconnect among six relationships is 16.7% > 10%.
            let (consumer, rel) = rels[0]
            try await eq(try await h.signed(consumer, .DELETE, "/v1/relationships/\(rel.id)").status, .ok)
            let m = try await service.metrics(for: b.id.uuid)
            XCTAssertEqual(m.optOuts, 1)
            XCTAssertEqual(m.activeRelationships, 6)
            let verdict = try await service.evaluate(businessId: b.id.uuid)
            XCTAssertEqual(verdict, .throttled(reason: "opt_out_rate"))
            // An operator takes over: clears it, re-applies it as their own (pinned) decision.
            let base = "/operator/businesses/\(b.id.uuid.uuidString.lowercased())"
            try await eq(try await h.formPost("\(base)/throttle", op, [("throttled", "off")]).status, .seeOther)
            try await eq(try await BusinessControls.load(b.id.uuid, on: h.db)?.throttled, false)
            try await eq(try await h.formPost("\(base)/throttle", op, [("throttled", "on"), ("reason", "manual review")]).status, .seeOther)
            let pinned = try await XCTUnwrapAsync(await BusinessControls.load(b.id.uuid, on: h.db))
            XCTAssertTrue(pinned.throttled)
            XCTAssertEqual(pinned.throttleSource, "operator")
            h.clock.advance(by: 30 * 86_400)
            let after = try await service.evaluate(businessId: b.id.uuid)
            XCTAssertEqual(after, .unchanged, "operator throttles are only lifted by an operator")
            try await eq(try await BusinessControls.load(b.id.uuid, on: h.db)?.throttled, true)
        }
    }

    func testThrottledBusinessesGetAFractionOfTheirAPIRateAndRateLimitHitsAreCounted() async throws {
        try await withHarness({ $0.rateLimits.business = .perMinute(8, burst: 8) }) { h in
            let (op, _) = try await h.makeOperator()
            let b = try await h.makeBusiness(name: "Fast Co", handle: "fastco")
            let base = "/operator/businesses/\(b.id.uuid.uuidString.lowercased())"
            // Unthrottled: 8 quick calls pass, the 9th is limited and counted.
            for _ in 0..<8 { try await eq(try await h.business(b, .GET, "/v1/business/webhooks").status, .ok) }
            try await eq(try await h.business(b, .GET, "/v1/business/webhooks").status, .tooManyRequests)
            let hits = try await AbuseSignalRecord.query(on: h.db).filter(\.$businessId == b.id.uuid).filter(\.$kind == "rate_limited").all()
            XCTAssertEqual(hits.reduce(0) { $0 + $1.count }, 1)
            try await eq(try await h.formPost("\(base)/throttle", op, [("throttled", "on"), ("reason", "test")]).status, .seeOther)
            h.clock.advance(by: 120)
            // Throttled: capacity 8 × 0.25 = 2.
            try await eq(try await h.business(b, .GET, "/v1/business/webhooks").status, .ok)
            try await eq(try await h.business(b, .GET, "/v1/business/webhooks").status, .ok)
            try await eq(try await h.business(b, .GET, "/v1/business/webhooks").status, .tooManyRequests)
            let page = try await h.page("/operator/abuse", op).text
            XCTAssertTrue(page.contains("Fast Co"))
            XCTAssertTrue(page.contains("Throttled"))
            let detail = try await h.page(base, op).text
            XCTAssertTrue(detail.contains(">2</div><div class=\"l\">Rate-limit hits"))
        }
    }

    func testTheBackgroundJobEvaluatesThresholdsWithoutAnyRequest() async throws {
        try await withHarness({ $0.abuse.minimumSample = 3 }) { h in
            let b = try await h.makeBusiness(name: "Job Co", handle: "jobco")
            var views: [(TestConsumer, Interaction)] = []
            for i in 0..<4 {
                h.clock.advance(by: 30)
                let c = try await h.readyConsumer(name: "C\(i)")
                let rel = try await h.connect(c, to: b)
                let r = try await h.issue(b, relationship: rel, payload: .confirm(ConfirmPayload(title: "t")), purpose: .transactional, key: "j\(i)", ttl: 7200)
                views.append((c, try r.json(Interaction.self)))
            }
            let view = try await h.consumerInteraction(views[0].0, id: views[0].1.id)
            let report = try await h.decision(views[0].0, interaction: view, decision: .report, assurance: .none)
            try await eq(try await h.decide(views[0].0, id: view.id, signed: report).status, .ok)
            try await h.runJobs()
            try await eq(try await BusinessControls.load(b.id.uuid, on: h.db)?.throttled, true)
        }
    }
}
