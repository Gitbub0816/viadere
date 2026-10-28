import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP2: capability scopes, entitlement ceiling, policy engine, kill switches, per-request consent receipts and pairwise
/// `subject_ref` (SECURITY-TRUST-PLATFORM-SPEC §3.2, §4.3 SEC-API-003, §6.4, §8.2, acceptance 1, 2 and 6).
final class PolicyWP2Tests: XCTestCase {
    // MARK: Helpers

    func authorize() -> InteractionPayload { .authorize(.sample()) }
    func authenticate(_ h: TestHarness) -> InteractionPayload { .authenticate(AuthenticatePayload(service: "Northwind portal", device: "Chrome on Mac", attemptedAt: h.clock.now())) }
    func confirm() -> InteractionPayload { .confirm(ConfirmPayload(title: "Confirm pickup")) }

    func key(_ h: TestHarness, _ b: TestBusiness, capabilities: [Capability], live: Bool = true, scopes: [String] = BusinessAPIKeys.Scope.all) async throws -> String {
        try await BusinessAPIKeys.issue(businessId: b.record.id!, name: "k", live: live, scopes: scopes, capabilities: capabilities, now: h.clock.now(), on: h.db).key
    }

    func details(_ result: HTTPResult) -> [String: String] { (try? result.json(APIErrorResponse.self).error.details) ?? [:] }

    func auditEvents(_ h: TestHarness, _ action: String) async throws -> [AuditEventRecord] {
        try await AuditEventRecord.query(on: h.db).filter(\.$action == action).all()
    }

    func principal(_ b: TestBusiness, capabilities: Set<Capability>, live: Bool = true) -> BusinessPrincipal {
        BusinessPrincipal(businessId: b.id, keyId: UUID(), livemode: live, scopes: [], businessName: b.record.displayName, capabilities: capabilities)
    }

    // MARK: Acceptance 1: a compromised messaging key cannot approve or verify

    func testAMessagingKeyCannotIssueApprovalsEvenWhenTheBusinessIsEntitled() async throws {
        try await withHarness { h in
            // The business holds approvals (tier A); the compromised key was only ever a messaging key.
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let messaging = try await key(h, b, capabilities: Capability.messaging)
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            // It still does its job.
            let sent = try await h.businessPost(b, "/v1/business/interactions",
                IssueInteractionRequest(relationshipId: rel.id, purpose: .transactional, payload: confirm(), allowedChannels: [.nativePush], ttlSeconds: 300, idempotencyKey: "c1"), key: messaging)
            XCTAssertEqual(sent.status, .created, sent.text)
            // Exploit: the same key tries a transaction approval and a sign-in challenge.
            for (index, payload) in [authorize(), authenticate(h)].enumerated() {
                let denied = try await h.businessPost(b, "/v1/business/interactions",
                    IssueInteractionRequest(relationshipId: rel.id, purpose: .security, payload: payload, allowedChannels: [.nativePush], ttlSeconds: 300, idempotencyKey: "a\(index)"), key: messaging)
                XCTAssertEqual(denied.status, .forbidden)
                XCTAssertEqual(denied.errorCode, .insufficientScope, denied.text)
                XCTAssertEqual(details(denied)["capability"], index == 0 ? "transaction.approve" : "auth.challenge")
            }
            try await eq(try await InteractionRecord.query(on: h.db).filter(\.$kind ~~ ["authorize", "authenticate"]).count(), 0, "nothing was created or delivered")
            // Denied attempts are audited with the key as actor.
            let denials = try await auditEvents(h, "policy.denied")
            XCTAssertEqual(denials.count, 2)
            XCTAssertTrue(denials.allSatisfy { $0.outcome == "denied" && $0.actorKind == "businessAPIKey" && $0.businessId == b.record.id })
            // The approval-capable key of the same business works, and the messaging key cannot read, cancel or replay it either.
            let issued = try await h.issue(b, relationship: rel, payload: authorize())
            XCTAssertEqual(issued.status, .created, issued.text)
            let interaction = try issued.json(Interaction.self)
            let outcome = try await h.business(b, .GET, "/v1/business/interactions/\(interaction.id)", key: messaging)
            XCTAssertEqual(outcome.errorCode, .insufficientScope)
            let cancel = try await h.business(b, .POST, "/v1/business/interactions/\(interaction.id)/cancel", key: messaging)
            XCTAssertEqual(cancel.errorCode, .insufficientScope)
            try await eq(try await InteractionRecord.find(interaction.id.uuid, on: h.db)?.status, "pending", "the approval was not cancelled by the messaging key")
            // Replaying the approval's idempotency key with the messaging key does not return it either.
            let replay = try await h.businessPost(b, "/v1/business/interactions",
                IssueInteractionRequest(relationshipId: rel.id, purpose: .security, payload: authorize(), allowedChannels: [.nativePush, .inApp], ttlSeconds: 300,
                                        idempotencyKey: interaction.idempotencyKey), key: messaging)
            XCTAssertEqual(replay.errorCode, .insufficientScope)
        }
    }

    func testVerificationCapabilitiesAreDeniedToAMessagingKeyAndUnentitledBusinesses() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair", capabilities: Capability.messaging)
            let policy = PolicyService(db: h.db, ctx: h.ctx)
            let years: [String: JSONValue] = ["years": .integer(18)]
            // A messaging key: no scope.
            var decision = try await policy.decide(PolicyInput(.ageMinimum, parameters: years, purpose: "age_restricted_access"),
                                                   principal: principal(b, capabilities: Set(Capability.messaging)))
            XCTAssertFalse(decision.allowed)
            XCTAssertEqual(decision.primaryReason, .insufficientScope)
            // A key that carries age.minimum while the business has no entitlement: still denied (the entitlement is the ceiling).
            decision = try await policy.decide(PolicyInput(.ageMinimum, parameters: years, purpose: "age_restricted_access"),
                                               principal: principal(b, capabilities: [.ageMinimum]))
            XCTAssertEqual(decision.primaryReason, .notEntitled)
            XCTAssertTrue(decision.reasons.contains(.tierRequired))
            // The denial is audited and carries no subject data.
            let audit = try await auditEvents(h, "policy.denied")
            XCTAssertEqual(audit.count, 2)
            XCTAssertTrue(audit.allSatisfy { $0.metadataJSON.contains("age.minimum") && !$0.metadataJSON.contains("birth") })
            // Through the HTTP surface: the effective list never lists it.
            let caps = try await h.business(b, .GET, "/v1/business/capabilities").json(BusinessCapabilitiesResponse.self)
            XCTAssertEqual(caps.tiers, [.m])
            XCTAssertEqual(Set(caps.entitlements), Set(Capability.messaging))
            XCTAssertEqual(Set(caps.effective), Set(Capability.messaging))
            XCTAssertEqual(caps.environment, .live)
            XCTAssertEqual(caps.catalog, CapabilityCatalog.definitions)
        }
    }

    func testStatusAndMessageRoutesNeedTheMessagingCapability() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            // An approvals-only key (no message.send) cannot send messages or statuses, though its legacy scopes allow the routes.
            let approvalsOnly = try await key(h, b, capabilities: [.authChallenge, .transactionApprove])
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b, optIn: [.support])
            let message = try await h.businessPost(b, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: rel.id, body: "hello", idempotencyKey: "m1"), key: approvalsOnly)
            XCTAssertEqual(message.errorCode, .insufficientScope, message.text)
            let status = try await h.businessPost(b, "/v1/business/statuses",
                BusinessStatusUpdateRequest(relationshipId: rel.id, purpose: .transactional, status: StatusPayload(title: "Shipped"), activityKey: "o1", idempotencyKey: "s1"), key: approvalsOnly)
            XCTAssertEqual(status.errorCode, .insufficientScope, status.text)
            let ok = try await h.businessPost(b, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: rel.id, body: "hello", idempotencyKey: "m2"))
            XCTAssertEqual(ok.status, .created, ok.text)
        }
    }

    // MARK: Entitlement ceiling at use time

    func testRevokingAnEntitlementTakesTheCapabilityFromAnExistingKeyOnItsNextRequest() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            try await eq(try await h.issue(b, relationship: rel, payload: authorize()).status, .created)
            // An operator revokes transaction.approve (the key is untouched).
            let entitlements = EntitlementService(db: h.db, ctx: h.ctx)
            try await entitlements.revoke(businessId: b.record.id!, capability: .transactionApprove, actor: .system("test"), justification: "Incident review: approvals suspended")
            let denied = try await h.issue(b, relationship: rel, payload: authorize())
            XCTAssertEqual(denied.status, .forbidden)
            XCTAssertEqual(denied.errorCode, .notEntitled, denied.text)
            // The key's other capabilities are intact, and the capability listing says so.
            try await eq(try await h.issue(b, relationship: rel, payload: authenticate(h)).status, .created)
            let caps = try await h.business(b, .GET, "/v1/business/capabilities").json(BusinessCapabilitiesResponse.self)
            XCTAssertTrue(caps.keyScopes.contains(.transactionApprove) && !caps.effective.contains(.transactionApprove))
            XCTAssertTrue(caps.effective.contains(.authChallenge))
            // Revoking the tier removes everything that needs it, in one step.
            try await entitlements.revoke(businessId: b.record.id!, tier: .a, actor: .system("test"), justification: "Annual review failed")
            try await eq(try await h.issue(b, relationship: rel, payload: authenticate(h)).errorCode, .notEntitled)
            try await eq(try await h.issue(b, relationship: rel, payload: confirm()).status, .created, "messaging is untouched")
            // Both revocations are audited with who and why.
            let revoked = try await auditEvents(h, "entitlement.capability_revoked") + auditEvents(h, "entitlement.tier_revoked")
            XCTAssertEqual(revoked.count, 2)
            XCTAssertTrue(revoked.allSatisfy { $0.actorKind == "system" && $0.metadataJSON.contains("justification") })
            // A fresh grant restores it (and is recorded as a new row; history is kept).
            try await entitlements.grant(businessId: b.record.id!, tier: .a, actor: .system("test"), justification: "Review passed: incident response contact verified")
            try await entitlements.grant(businessId: b.record.id!, capability: .transactionApprove, actor: .system("test"), justification: "Review passed: approvals re-enabled")
            try await eq(try await h.issue(b, relationship: rel, payload: authorize()).status, .created)
            let historyCount = try await entitlements.history(businessId: b.record.id!).count
            XCTAssertGreaterThanOrEqual(historyCount, 5, "history is kept: revoked rows stay")
        }
    }

    func testAKeyCreatedBeforeTheEntitlementExistsCannotUseItUntilGranted() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Plain Co", handle: "plainco", capabilities: Capability.messaging)
            let overScoped = try await key(h, b, capabilities: [.authChallenge, .transactionApprove] + Capability.messaging)
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            let request = IssueInteractionRequest(relationshipId: rel.id, purpose: .security, payload: authorize(), allowedChannels: [.nativePush], ttlSeconds: 300, idempotencyKey: "x1")
            let denied = try await h.businessPost(b, "/v1/business/interactions", request, key: overScoped)
            XCTAssertEqual(denied.errorCode, .notEntitled, denied.text)
            try await h.entitle(b.record.id!, [.transactionApprove])
            try await eq(try await h.businessPost(b, "/v1/business/interactions", request, key: overScoped).status, .created)
        }
    }

    func testEnvironmentIsBoundToTheKey() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let testKey = try await key(h, b, capabilities: Capability.operational, live: false)
            let consumer = try await h.readyConsumer()
            let real = try await h.connect(consumer, to: b)
            // A test key never reaches a real customer, whatever its capabilities (existing sandbox rule, kept).
            let live = try await h.businessPost(b, "/v1/business/interactions",
                IssueInteractionRequest(relationshipId: real.id, purpose: .security, payload: authorize(), allowedChannels: [.nativePush], ttlSeconds: 300, idempotencyKey: "e1"), key: testKey)
            XCTAssertEqual(live.status, .forbidden)
            // The test key sees test-environment capabilities.
            let caps = try await h.business(b, .GET, "/v1/business/capabilities", key: testKey).json(BusinessCapabilitiesResponse.self)
            XCTAssertEqual(caps.environment, .test)
            // And the engine itself refuses a request whose environment is not the key's.
            let decision = PolicyEngine.evaluate(PolicyRequest(capability: .messageSend, businessId: b.id, environment: .live, now: h.clock.now()),
                business: BusinessPolicyFacts(active: true, tiers: [.m], entitlements: Set(Capability.messaging), keyScopes: Set(Capability.messaging), keyEnvironment: .test))
            XCTAssertEqual(decision.primaryReason, .environmentMismatch)
        }
    }

    // MARK: Entitlements: defaults, justification, no category grants

    func testEveryVerifiedBusinessGetsTierMOnlyAndACategoryNeverGrantsAnything() async throws {
        try await withHarness { h in
            for (index, category) in [BusinessCategory.banking, .airline, .other, .foodAndDrink].enumerated() {
                let record = try await BusinessRegistry(db: h.db, ctx: h.ctx).register(displayName: "Biz \(index)", handle: "biz\(index)", category: category, status: .verified,
                                                                                         tier: "paid", dailyQuota: nil)
                let snapshot = try await EntitlementService(db: h.db, ctx: h.ctx).snapshot(businessId: record.id!)
                XCTAssertEqual(snapshot.tiers, [.m], "\(category)")
                XCTAssertEqual(snapshot.capabilities, Set(Capability.messaging), "\(category) and a paid plan grant nothing beyond messaging")
            }
            try await eq(try await BusinessEntitlementRecord.query(on: h.db).count(), 0, "defaults are implicit: no rows, no operator action")
        }
    }

    func testGrantsNeedAJustificationTheirTierAndForIdentityAttributesAReviewReference() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair", capabilities: Capability.messaging)
            let id = b.record.id!
            let service = EntitlementService(db: h.db, ctx: h.ctx)
            let actor = EntitlementActor.system("test")
            func fails(_ message: String, _ body: () async throws -> Void) async throws {
                do { try await body(); XCTFail("expected a refusal: \(message)") } catch let error as APIError { XCTAssertTrue([.unprocessableEntity, .conflict].contains(error.status), message) }
            }
            // A capability needs its tier first.
            try await fails("tier first") { try await service.grant(businessId: id, capability: .transactionApprove, actor: actor, justification: "Needed for step-up on wire transfers") }
            // A justification is required, and it must say something.
            try await fails("no justification") { try await service.grant(businessId: id, tier: .a, actor: actor, justification: "") }
            try await fails("too short") { try await service.grant(businessId: id, tier: .a, actor: actor, justification: "ok") }
            try await fails("baseline") { try await service.grant(businessId: id, tier: .m, actor: actor, justification: "Tier M is the default for everyone") }
            try await fails("baseline capability") { try await service.grant(businessId: id, capability: .messageSend, actor: actor, justification: "Messaging is the default for everyone") }
            try await fails("unknown") { try await service.grant(businessId: id, capability: .unknown("payment.initiate"), actor: actor, justification: "A capability that does not exist yet") }
            try await service.grant(businessId: id, tier: .a, actor: actor, justification: "Incident-response contact verified; approvals reviewed 2026-10-20")
            try await service.grant(businessId: id, capability: .transactionApprove, actor: actor, justification: "Needed for step-up on wire transfers; reviewed by risk")
            // Identity attributes need tier V, a justification and the heightened review reference (AGE-007).
            try await fails("tier V first") { try await service.grant(businessId: id, capability: .identityName, actor: actor, justification: "KYC for account opening", reviewReference: "REV-1") }
            try await service.grant(businessId: id, tier: .v, actor: actor, justification: "Purpose assessment and retention rules approved by privacy review")
            try await fails("review reference") { try await service.grant(businessId: id, capability: .identityName, actor: actor, justification: "Name check for regulated account opening") }
            try await service.grant(businessId: id, capability: .identityName, actor: actor, justification: "Name check for regulated account opening", reviewReference: "REV-2026-114")
            try await service.grant(businessId: id, capability: .ageMinimum, actor: actor, justification: "Age-gate for alcohol delivery in launch markets")
            let snapshot = try await service.snapshot(businessId: id)
            XCTAssertEqual(snapshot.tiers, [.m, .a, .v])
            XCTAssertTrue(snapshot.capabilities.isSuperset(of: [.transactionApprove, .identityName, .ageMinimum]))
            XCTAssertFalse(snapshot.capabilities.contains(.identityAddress), "granting one identity attribute grants no other")
            // Idempotent: granting what is held changes nothing.
            let before = try await service.history(businessId: id).count
            try await service.grant(businessId: id, tier: .a, actor: actor, justification: "Incident-response contact verified; approvals reviewed 2026-10-20")
            try await eq(try await service.history(businessId: id).count, before)
            // Audited with the actor and the justification.
            let granted = try await auditEvents(h, "entitlement.capability_granted")
            XCTAssertTrue(granted.contains { $0.metadataJSON.contains("REV-2026-114") })
            XCTAssertTrue(granted.allSatisfy { $0.actorId == "system:test" })
        }
    }

    func testOnlyVerifiedBusinessesCanBeGrantedAnything() async throws {
        try await withHarness { h in
            let pending = try await h.makeBusiness(name: "Pending Co", handle: "pendingco", status: .pending)
            do {
                try await EntitlementService(db: h.db, ctx: h.ctx).grant(businessId: pending.record.id!, tier: .a, actor: .system("test"), justification: "Should not be possible while pending")
                XCTFail("granted to an unverified business")
            } catch let error as APIError { XCTAssertEqual(error.status, .conflict) }
            // A suspended business loses everything at once: its keys are refused before any capability is considered.
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            try await BusinessOnboarding(db: h.db, ctx: h.ctx).suspend(businessId: b.record.id!, operatorId: UUID(), reason: "test")
            try await eq(try await h.business(b, .GET, "/v1/business/capabilities").status, .forbidden)
        }
    }

    // MARK: Operator console

    func testOperatorGrantsAndRevokesEntitlementsWithReauthAJustificationAndAnAuditTrail() async throws {
        try await withHarness { h in
            let (op, account) = try await h.makeOperator()
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair", capabilities: Capability.messaging)
            let base = "/operator/businesses/\(b.record.id!.uuidString.lowercased())/entitlements"
            let page = try await h.page(base, op)
            XCTAssertEqual(page.status, .ok)
            XCTAssertTrue(page.text.contains("never grants anything else"), "the console says a category or badge grants nothing")
            // Fresh passkey required: after it lapses the form asks for it instead of acting.
            h.clock.advance(by: 6 * 60)
            let lapsed = try await h.formPost("\(base)/grant", op, [("kind", "tier"), ("value", "A"), ("justification", "Approvals reviewed and incident contact verified")])
            XCTAssertEqual(lapsed.status, .forbidden)
            XCTAssertTrue(lapsed.text.contains("Confirm with passkey"))
            try await eq(try await EntitlementService(db: h.db, ctx: h.ctx).snapshot(businessId: b.record.id!).tiers, [.m])
            _ = try await h.dashReauth(op, account)
            // Without CSRF nothing happens.
            try await eq(try await h.formPost("\(base)/grant", op, [("kind", "tier"), ("value", "A"), ("justification", "Approvals reviewed and incident contact verified")], includeCSRF: false).status, .forbidden)
            // A grant without a real justification is refused.
            try await eq(try await h.formPost("\(base)/grant", op, [("kind", "tier"), ("value", "A"), ("justification", "ok")]).status, .unprocessableEntity)
            // Tier first, then the capability.
            try await eq(try await h.formPost("\(base)/grant", op, [("kind", "tier"), ("value", "A"), ("justification", "Approvals reviewed and incident contact verified")]).status, .seeOther)
            try await eq(try await h.formPost("\(base)/grant", op, [("kind", "capability"), ("value", "transaction.approve"), ("justification", "Step-up approvals for wire transfers; reviewed")]).status, .seeOther)
            let snapshot = try await EntitlementService(db: h.db, ctx: h.ctx).snapshot(businessId: b.record.id!)
            XCTAssertEqual(snapshot.tiers, [.m, .a])
            XCTAssertTrue(snapshot.capabilities.contains(.transactionApprove))
            let grants = try await auditEvents(h, "entitlement.capability_granted")
            XCTAssertEqual(grants.count, 1)
            XCTAssertEqual(grants.first?.actorKind, "operator")
            XCTAssertEqual(grants.first?.actorId, account.userId.uuidString.lowercased())
            try await isTrue(try await h.page(base, op).text.contains("Step-up approvals for wire transfers"), "history shows the justification")
            try await isTrue(try await h.page("/operator/businesses/\(b.record.id!.uuidString.lowercased())", op).text.contains("Tier A"), "the business page summarizes it")
            // Revoke with a reason.
            try await eq(try await h.formPost("\(base)/revoke", op, [("kind", "capability"), ("value", "transaction.approve"), ("justification", "Incident review in progress")]).status, .seeOther)
            let after = try await EntitlementService(db: h.db, ctx: h.ctx).snapshot(businessId: b.record.id!)
            XCTAssertFalse(after.capabilities.contains(.transactionApprove))
            // Business users cannot reach any of it.
            let (owner, _, _) = try await h.verifiedOwner(email: "o2@example.com", org: "Other Co", handle: "otherco")
            try await eq(try await h.page(base, owner).status, .seeOther)
            try await eq(try await h.formPost("\(base)/grant", owner, [("kind", "tier"), ("value", "V"), ("justification", "I would like this please and thank you")]).status, .seeOther)
            try await eq(try await EntitlementService(db: h.db, ctx: h.ctx).snapshot(businessId: b.record.id!).tiers, [.m, .a], "nothing changed")
        }
    }

    func testOperatorKillSwitchRulesAndTheirAudit() async throws {
        try await withHarness { h in
            let (op, account) = try await h.makeOperator()
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            try await eq(try await h.issue(b, relationship: rel, payload: confirm()).status, .created)
            _ = account
            let off = try await h.formPost("/operator/policy/switch", op, [("capability", "message.send"), ("disabled", "on"), ("reason", "Provider incident INC-42")])
            XCTAssertEqual(off.status, .seeOther, off.text)
            // On the next request, no waiting for the cache.
            let denied = try await h.issue(b, relationship: rel, payload: confirm(), key: "k2")
            XCTAssertEqual(denied.status, .forbidden)
            XCTAssertEqual(denied.errorCode, .capabilityDisabled)
            try await isTrue(try await h.page("/operator/policy", op).text.contains("Provider incident INC-42"))
            // A reason is mandatory.
            try await eq(try await h.formPost("/operator/policy/switch", op, [("capability", "message.send"), ("disabled", "off"), ("reason", "")]).status, .unprocessableEntity)
            try await eq(try await h.formPost("/operator/policy/switch", op, [("capability", "message.send"), ("disabled", "off"), ("reason", "Incident resolved")]).status, .seeOther)
            try await eq(try await h.issue(b, relationship: rel, payload: confirm(), key: "k3").status, .created)
            let events = try await auditEvents(h, "policy.capability_disabled") + auditEvents(h, "policy.capability_enabled")
            XCTAssertEqual(events.count, 2)
            XCTAssertTrue(events.allSatisfy { $0.actorKind == "operator" && $0.subjectId == "message.send" })
            // A rule: age.minimum only in US and CA.
            let rule = try await h.formPost("/operator/policy/rules", op, [("capability", "age.minimum"), ("kind", "jurisdiction_allow_only"), ("jurisdictions", "us, ca"), ("reason", "Launch markets only")])
            XCTAssertEqual(rule.status, .seeOther, rule.text)
            try await eq(try await PolicyRuleRecord.query(on: h.db).first()?.jurisdictions, "US,CA")
            try await eq(try await h.formPost("/operator/policy/rules", op, [("capability", "age.minimum"), ("kind", "jurisdiction_block"), ("jurisdictions", "Atlantis"), ("reason", "Not a region")]).status, .unprocessableEntity)
            let ruleId = try await PolicyRuleRecord.query(on: h.db).first()!.id!
            try await eq(try await h.formPost("/operator/policy/rules/\(ruleId.uuidString.lowercased())/remove", op, [("reason", "Market expanded")]).status, .seeOther)
            try await eq(try await PolicyRuleRecord.query(on: h.db).filter(\.$active == true).count(), 0)
            // Without a fresh passkey: asks for it.
            h.clock.advance(by: 6 * 60)
            try await eq(try await h.formPost("/operator/policy/switch", op, [("capability", "message.send"), ("disabled", "on"), ("reason", "Should not apply")]).status, .forbidden)
            try await eq(try await h.issue(b, relationship: rel, payload: confirm(), key: "k4").status, .created)
        }
    }

    // MARK: Kill switches and law/policy at the engine

    func testAKillSwitchStopsACapabilityGloballyOrForOneBusinessAndIsCachedBriefly() async throws {
        try await withHarness { h in
            let a = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let b = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
            let consumer = try await h.readyConsumer()
            let relA = try await h.connect(consumer, to: a)
            let relB = try await h.connect(consumer, to: b)
            let admin = PolicyAdmin(db: h.db, ctx: h.ctx)
            // One business only.
            try await admin.setSwitch(capability: .transactionApprove, businessId: a.record.id!, disabled: true, reason: "Fraud investigation FR-7", actor: .system("test"))
            try await eq(try await h.issue(a, relationship: relA, payload: authorize()).errorCode, .capabilityDisabled)
            try await eq(try await h.issue(a, relationship: relA, payload: confirm()).status, .created, "other capabilities of that business are unaffected")
            try await eq(try await h.issue(b, relationship: relB, payload: authorize()).status, .created, "other businesses are unaffected")
            // Globally.
            try await admin.setSwitch(capability: .transactionApprove, disabled: true, reason: "Signing-key incident INC-9", actor: .system("test"))
            try await eq(try await h.issue(b, relationship: relB, payload: authorize(), key: "g1").errorCode, .capabilityDisabled)
            let caps = try await h.business(b, .GET, "/v1/business/capabilities").json(BusinessCapabilitiesResponse.self)
            XCTAssertFalse(caps.effective.contains(.transactionApprove))
            // Re-enable: immediate on this instance.
            try await admin.setSwitch(capability: .transactionApprove, disabled: false, reason: "Incident closed", actor: .system("test"))
            try await eq(try await h.issue(b, relationship: relB, payload: authorize(), key: "g2").status, .created)
            // Another instance's change (written straight to the table) is picked up within the cache window, not before.
            try await CapabilitySwitchRecord(capability: Capability.transactionApprove.rawValue, scope: CapabilitySwitchRecord.globalScope, disabled: true,
                                             reason: "other instance", updatedBy: "x", now: h.clock.now()).update(onConflictLike: h.db)
            try await eq(try await h.issue(b, relationship: relB, payload: authorize(), key: "g3").status, .created, "served from the short-lived cache")
            h.clock.advance(by: PolicyService.cacheTTL + 1)
            try await eq(try await h.issue(b, relationship: relB, payload: authorize(), key: "g4").errorCode, .capabilityDisabled)
            // Every toggle is audited.
            let disabled = try await auditEvents(h, "policy.capability_disabled")
            XCTAssertEqual(disabled.count, 2)
            XCTAssertTrue(disabled.allSatisfy { $0.metadataJSON.contains("reason") })
            // Unknown capabilities cannot be switched.
            do { try await admin.setSwitch(capability: .unknown("x.y"), disabled: true, reason: "A reason that is long enough", actor: .system("test")); XCTFail() } catch let e as APIError { XCTAssertEqual(e.status, .unprocessableEntity) }
        }
    }

    func testJurisdictionRulesAreEvaluatedFromTheStoredRuleSet() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair", capabilities: Capability.messaging)
            try await h.entitle(b.record.id!, [.ageMinimum])
            let admin = PolicyAdmin(db: h.db, ctx: h.ctx)
            let rule = try await admin.addRule(capability: .ageMinimum, kind: .jurisdictionBlock, jurisdictions: ["XX"], reason: "No lawful basis in XX", actor: .system("test"))
            let policy = PolicyService(db: h.db, ctx: h.ctx)
            let p = principal(b, capabilities: [.ageMinimum])
            func decide(_ j: String?) async throws -> PolicyDecision {
                try await policy.decide(PolicyInput(.ageMinimum, parameters: ["years": .integer(21)], purpose: "age_restricted_access", jurisdiction: j), principal: p)
            }
            try await eq(try await decide("US").allowed, true)
            try await eq(try await decide("xx").primaryReason, .jurisdictionBlocked)
            try await admin.deactivateRule(id: rule.id!, reason: "Counsel cleared XX", actor: .system("test"))
            try await eq(try await decide("XX").allowed, true)
            _ = try await admin.addRule(capability: .ageMinimum, kind: .jurisdictionAllowOnly, jurisdictions: ["US"], reason: "Launch market only", actor: .system("test"))
            try await eq(try await decide(nil).primaryReason, .jurisdictionBlocked)
            try await eq(try await decide("US").allowed, true)
            try await eq(try await auditEvents(h, "policy.rule_added").count, 2)
            try await eq(try await auditEvents(h, "policy.rule_removed").count, 1)
            // Invalid parameters never reach the rules.
            let bad = try await policy.decide(PolicyInput(.ageMinimum, parameters: ["years": .integer(17)], purpose: "age_restricted_access", jurisdiction: "US"), principal: p)
            XCTAssertEqual(bad.primaryReason, .invalidParameters)
            XCTAssertEqual(bad.apiError?.status, .unprocessableEntity)
        }
    }

    // MARK: Per-request consent receipts (§6.4)

    func testAnIdentityDisclosureNeedsAReceiptForExactlyThatRequestAndEveryUseIsAudited() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair", capabilities: Capability.messaging)
            try await h.entitle(b.record.id!, [.identityName])
            let other = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee", capabilities: Capability.messaging)
            try await h.entitle(other.record.id!, [.identityName])
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b, optIn: InteractionPurpose.allCases)   // every purpose: the broadest consent there is
            let relRecord = try await XCTUnwrapAsync(await RelationshipRecord.find(rel.id.uuid, on: h.db))
            let ref = SubjectResolver(db: h.db, ctx: h.ctx).ref(for: relRecord)
            let policy = PolicyService(db: h.db, ctx: h.ctx)
            let p = principal(b, capabilities: [.identityName])
            let evidence = [EvidenceHolding(kind: .verifiedIdentity, verifiedAt: h.clock.now().addingTimeInterval(-3600))]
            func input(_ requestId: String = "vr_1", purpose: String = "account_opening") -> PolicyInput { PolicyInput(.identityName, subjectRef: ref, purpose: purpose, requestId: requestId) }

            // Blanket consent does not count: every relationship purpose is on, and there is still no receipt.
            var decision = try await policy.authorizeDisclosure(input(), principal: p, relationship: relRecord, evidence: evidence)
            XCTAssertEqual(decision.primaryReason, .consentRequired)
            XCTAssertEqual(decision.details["receipt"], "missing")

            // The customer confirms this one disclosure in the app.
            let receipts = DisclosureReceiptService(db: h.db, ctx: h.ctx)
            let receipt = try await receipts.grant(consumer: consumer.id, relationshipId: rel.id, capability: .identityName, purpose: "account_opening", requestId: "vr_1")
            XCTAssertEqual(receipt.fields, ["given_name", "family_name"])
            XCTAssertEqual(receipt.businessId, b.id)
            XCTAssertEqual(receipt.subjectRef, ref)
            XCTAssertEqual(receipt.expiresAt.timeIntervalSince(receipt.grantedAt), DisclosureReceipt.maxLifetime)
            let granted = try await auditEvents(h, "consent.disclosure_granted")
            XCTAssertEqual(granted.count, 1)
            XCTAssertEqual(granted.first?.actorKind, "consumer")
            XCTAssertTrue(granted.first!.metadataJSON.contains("account_opening") && granted.first!.metadataJSON.contains("given_name"))
            // Exactly one receipt per request.
            do { _ = try await receipts.grant(consumer: consumer.id, relationshipId: rel.id, capability: .identityName, purpose: "account_opening", requestId: "vr_1"); XCTFail() }
            catch let e as APIError { XCTAssertEqual(e.status, .conflict) }

            // It does not authorize another purpose, another request, another business or another capability.
            decision = try await policy.authorizeDisclosure(input(purpose: "marketing_profile"), principal: p, relationship: relRecord, evidence: evidence)
            XCTAssertEqual(decision.details["receipt"], "wrong_purpose")
            decision = try await policy.authorizeDisclosure(input("vr_2"), principal: p, relationship: relRecord, evidence: evidence)
            XCTAssertEqual(decision.details["receipt"], "missing")
            let otherPrincipal = self.principal(other, capabilities: [.identityName])
            let otherRel = try await h.connect(consumer, to: other)
            let otherRecord = try await XCTUnwrapAsync(await RelationshipRecord.find(otherRel.id.uuid, on: h.db))
            decision = try await policy.authorizeDisclosure(PolicyInput(.identityName, subjectRef: ref, purpose: "account_opening", requestId: "vr_1"), principal: otherPrincipal, relationship: otherRecord, evidence: evidence)
            XCTAssertFalse(decision.allowed, "another business, even with the right ref and request id, has no receipt")
            // Without verified-identity evidence the receipt is not enough.
            decision = try await policy.authorizeDisclosure(input(), principal: p, relationship: relRecord, evidence: [])
            XCTAssertEqual(decision.primaryReason, .evidenceInsufficient)
            try await eq(try await DisclosureReceiptRecord.query(on: h.db).filter(\.$consumedAt != nil).count(), 0, "a denied decision does not spend the receipt")
            // With evidence: allowed once, then spent.
            decision = try await policy.authorizeDisclosure(input(), principal: p, relationship: relRecord, evidence: evidence)
            XCTAssertTrue(decision.allowed, "\(decision.reasons) \(decision.details)")
            decision = try await policy.authorizeDisclosure(input(), principal: p, relationship: relRecord, evidence: evidence)
            XCTAssertEqual(decision.details["receipt"], "already_used")
            let allowed = try await auditEvents(h, "policy.allowed")
            XCTAssertEqual(allowed.count, 1)
            XCTAssertTrue(allowed.first!.metadataJSON.contains(receipt.id.uuidString.lowercased()), "the decision names the receipt it relied on")
            XCTAssertFalse(allowed.first!.metadataJSON.contains("given_name"), "no personal data in the decision audit")

            // Expiry and revocation.
            _ = try await receipts.grant(consumer: consumer.id, relationshipId: rel.id, capability: .identityName, purpose: "account_opening", requestId: "vr_3")
            h.clock.advance(by: DisclosureReceipt.maxLifetime + 1)
            decision = try await policy.authorizeDisclosure(input("vr_3"), principal: p, relationship: relRecord, evidence: evidence)
            XCTAssertEqual(decision.details["receipt"], "expired")
            let fresh = try await receipts.grant(consumer: consumer.id, relationshipId: rel.id, capability: .identityName, purpose: "account_opening", requestId: "vr_4")
            try await receipts.revoke(consumer: consumer.id, receiptId: fresh.id)
            decision = try await policy.authorizeDisclosure(input("vr_4"), principal: p, relationship: relRecord, evidence: evidence)
            XCTAssertEqual(decision.details["receipt"], "revoked")
            // Only the consumer's own receipt can be revoked.
            let stranger = try await h.readyConsumer(name: "Stranger")
            do { try await receipts.revoke(consumer: stranger.id, receiptId: fresh.id); XCTFail() } catch let e as APIError { XCTAssertEqual(e.status, .notFound) }
        }
    }

    func testAReceiptIsOnlyIssuedForTheCustomersOwnActiveRelationshipAndADisclosureCapability() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let alice = try await h.readyConsumer(name: "Alice")
            let bob = try await h.readyConsumer(name: "Bob")
            let rel = try await h.connect(alice, to: b)
            let receipts = DisclosureReceiptService(db: h.db, ctx: h.ctx)
            // Bob cannot mint a receipt on Alice's relationship.
            do { _ = try await receipts.grant(consumer: bob.id, relationshipId: rel.id, capability: .ageMinimum, purpose: "age_restricted_access", requestId: "r1"); XCTFail() }
            catch let e as APIError { XCTAssertEqual(e.status, .notFound) }
            // Messaging capabilities do not use receipts.
            do { _ = try await receipts.grant(consumer: alice.id, relationshipId: rel.id, capability: .messageSend, purpose: "age_restricted_access", requestId: "r2"); XCTFail() }
            catch let e as APIError { XCTAssertEqual(e.status, .unprocessableEntity) }
            // Not after disconnecting.
            _ = try await h.signed(alice, .DELETE, "/v1/relationships/\(rel.id)")
            do { _ = try await receipts.grant(consumer: alice.id, relationshipId: rel.id, capability: .ageMinimum, purpose: "age_restricted_access", requestId: "r3"); XCTFail() }
            catch let e as APIError { XCTAssertEqual(e.status, .notFound) }
        }
    }

    func testTwoConcurrentRequestsCannotBothSpendOneReceipt() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair", capabilities: Capability.messaging)
            try await h.entitle(b.record.id!, [.ageMinimum])
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            let record = try await XCTUnwrapAsync(await RelationshipRecord.find(rel.id.uuid, on: h.db))
            let ref = SubjectResolver(db: h.db, ctx: h.ctx).ref(for: record)
            _ = try await DisclosureReceiptService(db: h.db, ctx: h.ctx).grant(consumer: consumer.id, relationshipId: rel.id, capability: .ageMinimum, purpose: "age_restricted_access", requestId: "vr_race")
            let p = principal(b, capabilities: [.ageMinimum])
            let input = PolicyInput(.ageMinimum, subjectRef: ref, parameters: ["years": .integer(21)], purpose: "age_restricted_access", requestId: "vr_race")
            let evidence = [EvidenceHolding(kind: .verifiedAgeThreshold, verifiedAt: h.clock.now().addingTimeInterval(-60))]
            let ctx = h.ctx, db = h.db
            let results = await withTaskGroup(of: Bool.self) { group -> [Bool] in
                for _ in 0..<4 {
                    group.addTask {
                        (try? await DB.retryingTransient { try await PolicyService(db: db, ctx: ctx).authorizeDisclosure(input, principal: p, relationship: record, evidence: evidence).allowed }) ?? false
                    }
                }
                var out: [Bool] = []
                for await value in group { out.append(value) }
                return out
            }
            XCTAssertEqual(results.filter { $0 }.count, 1, "exactly one concurrent request wins the receipt: \(results)")
        }
    }

    // MARK: Pairwise subject_ref (§3.2)

    func testSubjectRefIsPairwiseStableNonEnumerableAndUnlinkableAcrossBusinesses() async throws {
        try await withHarness { h in
            let a = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let b = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
            let consumer = try await h.readyConsumer()
            let relA = try await h.connect(consumer, to: a)
            let relB = try await h.connect(consumer, to: b)
            let interactionA = try await h.issue(a, relationship: relA, payload: confirm()).json(Interaction.self)
            let interactionB = try await h.issue(b, relationship: relB, payload: confirm()).json(Interaction.self)
            let refA = try XCTUnwrap(interactionA.scope.subjectRef)
            let refB = try XCTUnwrap(interactionB.scope.subjectRef)
            // The same person, two businesses: unrelated values, neither containing any identifier.
            XCTAssertNotEqual(refA, refB)
            for ref in [refA, refB] {
                XCTAssertTrue(ref.rawValue.hasPrefix("sub_") && ref.rawValue.count == 47)
                XCTAssertFalse(ref.rawValue.contains(consumer.id.description) || ref.rawValue.contains(a.id.description))
            }
            let shared = Set(refA.rawValue.dropFirst(4).split(separator: "-")).intersection(refB.rawValue.dropFirst(4).split(separator: "-"))
            XCTAssertTrue(shared.count < 3)
            // It is exactly the specified construction under the dedicated key.
            XCTAssertEqual(refA, SubjectRefDeriver(key: h.config.subjectRefKey).subjectRef(businessId: a.id, consumerId: consumer.id))
            XCTAssertEqual(SubjectRefDeriver.domain, "VIADERE-SUBJECT-V1")
            // Stable per business: a second interaction, a re-connect and the stored column all agree.
            let again = try await h.issue(a, relationship: relA, payload: confirm()).json(Interaction.self)
            XCTAssertEqual(again.scope.subjectRef, refA)
            _ = try await h.signed(consumer, .DELETE, "/v1/relationships/\(relA.id)")
            let reconnected = try await h.connect(consumer, to: a)
            XCTAssertEqual(reconnected.id, relA.id)
            try await eq(try await RelationshipRecord.find(relA.id.uuid, on: h.db)?.subjectRef, refA.rawValue)
            // The legacy pseudonym is a different value derived under a different key: it is not the subject_ref.
            XCTAssertNotEqual(interactionA.scope.consumerId.description, refA.rawValue)
            XCTAssertNotEqual(interactionA.scope.consumerId, consumer.id)
            // A different key (a different deployment) yields unrelated references: the ref is not derivable without the key.
            XCTAssertNotEqual(SubjectRefDeriver(key: h.config.dataEncryptionKey).subjectRef(businessId: a.id, consumerId: consumer.id), refA)
            // The consumer's own copy never carries a business-facing reference.
            let mine = try await h.consumerInteraction(consumer, id: interactionB.id)
            XCTAssertNil(mine.scope.subjectRef)
            // Unique per business in the database.
            let row = try await XCTUnwrapAsync(await RelationshipRecord.find(relB.id.uuid, on: h.db))
            let duplicate = RelationshipRecord(consumerId: UUID(), businessId: b.record.id!, source: .link, now: h.clock.now())
            duplicate.subjectRef = row.subjectRef
            do { try await duplicate.create(on: h.db); XCTFail("two relationships of one business share a subject_ref") } catch { XCTAssertTrue(error.isConstraintViolation) }
        }
    }

    func testBusinessApisAcceptSubjectRefAndKeepRelationshipIdWorking() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b, optIn: [.support])
            let ref = SubjectRefDeriver(key: h.config.subjectRefKey).subjectRef(businessId: b.id, consumerId: consumer.id)
            // Issue by ref; the same request by relationshipId is the same idempotent request.
            let byRef = IssueInteractionRequest(subjectRef: ref, purpose: .transactional, payload: confirm(), allowedChannels: [.nativePush], ttlSeconds: 300, idempotencyKey: "ord-1")
            let first = try await h.businessPost(b, "/v1/business/interactions", byRef)
            XCTAssertEqual(first.status, .created, first.text)
            XCTAssertEqual(try first.json(Interaction.self).scope.relationshipId, rel.id)
            let byId = IssueInteractionRequest(relationshipId: rel.id, purpose: .transactional, payload: confirm(), allowedChannels: [.nativePush], ttlSeconds: 300, idempotencyKey: "ord-1")
            let replay = try await h.businessPost(b, "/v1/business/interactions", byId)
            XCTAssertEqual(replay.status, .ok, "same logical request, however addressed: a replay, not a conflict")
            // Both given and agreeing; both given and disagreeing.
            let both = IssueInteractionRequest(relationshipId: rel.id, purpose: .transactional, payload: confirm(), allowedChannels: [.nativePush], ttlSeconds: 300, idempotencyKey: "ord-2", subjectRef: ref)
            try await eq(try await h.businessPost(b, "/v1/business/interactions", both).status, .created)
            let consumer2 = try await h.readyConsumer(name: "Second")
            let rel2 = try await h.connect(consumer2, to: b)
            let disagree = IssueInteractionRequest(relationshipId: rel2.id, purpose: .transactional, payload: confirm(), allowedChannels: [.nativePush], ttlSeconds: 300, idempotencyKey: "ord-3", subjectRef: ref)
            try await eq(try await h.businessPost(b, "/v1/business/interactions", disagree).status, .notFound)
            // Messages and statuses by ref.
            let message = try await h.businessPost(b, "/v1/business/messages", BusinessSendMessageRequest(subjectRef: ref, body: "Your gate changed", idempotencyKey: "m-1"))
            XCTAssertEqual(message.status, .created, message.text)
            let status = try await h.businessPost(b, "/v1/business/statuses",
                BusinessStatusUpdateRequest(subjectRef: ref, purpose: .transactional, status: StatusPayload(title: "Boarding"), activityKey: "flight-1", idempotencyKey: "s-1"))
            XCTAssertEqual(status.status, .created, status.text)
            // Rewards by ref.
            let reward = try await h.businessPost(b, "/v1/business/rewards", IssueRewardRequest(title: "Free coffee", idempotencyKey: "rw-1", subjectRef: ref))
            XCTAssertEqual(reward.status, .created, reward.text)
            // Neither: refused. Malformed ref: refused, never ignored.
            try await eq(try await h.business(b, .POST, "/v1/business/messages", body: Data(#"{"body":"x","idempotencyKey":"m-2"}"#.utf8)).status, .badRequest)
            try await eq(try await h.business(b, .POST, "/v1/business/messages", body: Data(#"{"subjectRef":"sub_nope","body":"x","idempotencyKey":"m-3"}"#.utf8)).status, .badRequest)
        }
    }

    // MARK: Acceptance 2: changing an identifier never crosses tenants

    func testChangingAnIdentifierNeverCrossesTenantsIncludingSubjectRef() async throws {
        try await withHarness { h in
            let a = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let b = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
            let alice = try await h.readyConsumer(name: "Alice")
            let relA = try await h.connect(alice, to: a, optIn: [.support, .rewards])
            let refA = SubjectRefDeriver(key: h.config.subjectRefKey).subjectRef(businessId: a.id, consumerId: alice.id)
            let interactionA = try await h.issue(a, relationship: relA, payload: authorize()).json(Interaction.self)
            _ = try await h.businessPost(a, "/v1/business/messages", BusinessSendMessageRequest(subjectRef: refA, body: "private", idempotencyKey: "pm-1"))
            let before = try await InteractionRecord.query(on: h.db).count()
            // B holds neither a relationship with Alice nor her ref; every probe is the same plain 404.
            let probes: [(String, Data)] = [
                ("/v1/business/interactions", try ViadereJSON.encode(IssueInteractionRequest(subjectRef: refA, purpose: .transactional, payload: confirm(), allowedChannels: [.nativePush], ttlSeconds: 300, idempotencyKey: "x1"))),
                ("/v1/business/interactions", try ViadereJSON.encode(IssueInteractionRequest(relationshipId: relA.id, purpose: .transactional, payload: confirm(), allowedChannels: [.nativePush], ttlSeconds: 300, idempotencyKey: "x2"))),
                ("/v1/business/messages", try ViadereJSON.encode(BusinessSendMessageRequest(subjectRef: refA, body: "hi", idempotencyKey: "x3"))),
                ("/v1/business/messages", try ViadereJSON.encode(BusinessSendMessageRequest(relationshipId: relA.id, body: "hi", idempotencyKey: "x4"))),
                ("/v1/business/statuses", try ViadereJSON.encode(BusinessStatusUpdateRequest(subjectRef: refA, purpose: .transactional, status: StatusPayload(title: "s"), activityKey: "k", idempotencyKey: "x5"))),
                ("/v1/business/rewards", try ViadereJSON.encode(IssueRewardRequest(title: "Gift", idempotencyKey: "x6", subjectRef: refA))),
                ("/v1/business/rewards", try ViadereJSON.encode(IssueRewardRequest(relationshipId: relA.id, title: "Gift", idempotencyKey: "x7"))),
                ("/v1/business/loyalty/points", try ViadereJSON.encode(AdjustLoyaltyPointsRequest(subjectRef: refA, delta: 10, idempotencyKey: "x8"))),
                ("/v1/business/loyalty/points", try ViadereJSON.encode(AdjustLoyaltyPointsRequest(relationshipId: relA.id, delta: 10, idempotencyKey: "x9"))),
            ]
            for (path, body) in probes {
                let result = try await h.business(b, .POST, path, body: body)
                XCTAssertEqual(result.status, .notFound, "\(path): \(result.text)")
            }
            // Mixing A's ref with B's own relationship id is no better.
            let consumerB = try await h.readyConsumer(name: "Bea")
            let relB = try await h.connect(consumerB, to: b)
            let mixed = try ViadereJSON.encode(BusinessSendMessageRequest(relationshipId: relB.id, body: "hi", idempotencyKey: "x10", subjectRef: refA))
            try await eq(try await h.business(b, .POST, "/v1/business/messages", body: mixed).status, .notFound)
            // A real-looking but unknown ref is indistinguishable from A's.
            let ghost = SubjectRefDeriver(key: h.config.subjectRefKey).subjectRef(businessId: b.id, consumerId: ConsumerID())
            let ghostResult = try await h.business(b, .POST, "/v1/business/messages", body: try ViadereJSON.encode(BusinessSendMessageRequest(subjectRef: ghost, body: "hi", idempotencyKey: "x11")))
            XCTAssertEqual(ghostResult.status, .notFound)
            // And B cannot read, cancel or enumerate A's interaction.
            try await eq(try await h.business(b, .GET, "/v1/business/interactions/\(interactionA.id)").status, .notFound)
            try await eq(try await h.business(b, .POST, "/v1/business/interactions/\(interactionA.id)/cancel").status, .notFound)
            try await eq(try await InteractionRecord.query(on: h.db).count(), before, "nothing was created for either tenant")
            try await eq(try await InteractionRecord.find(interactionA.id.uuid, on: h.db)?.status, "pending")
            // A receipt id or a ref of A is meaningless to B.
            try await eq(try await DisclosureReceiptService(db: h.db, ctx: h.ctx).receipt(businessId: b.id, subjectRef: refA, capability: .ageMinimum, requestId: "any"), nil)
        }
    }

    func testSandboxRelationshipsReturnASubjectRefThatAddressesThem() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair", live: false)
            let created = try await h.business(b, .POST, "/v1/business/sandbox/relationships")
            let sandbox = try created.json(SandboxRelationship.self)
            let ref = try XCTUnwrap(sandbox.subjectRef)
            let sent = try await h.businessPost(b, "/v1/business/messages", BusinessSendMessageRequest(subjectRef: ref, body: "test", idempotencyKey: "t1"))
            XCTAssertEqual(sent.status, .created, sent.text)
        }
    }

    func testWebhookEventsCarryTheSubjectRefNeverTheConsumerId() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            _ = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/v")!, events: [.relationshipConnected, .consentUpdated]))
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            _ = try await h.signed(consumer, .PUT, "/v1/relationships/\(rel.id)/consents",
                                   body: try ViadereJSON.encode(ConsentUpdateRequest(changes: [ConsentChange(purpose: .support, granted: false)], policyVersion: ConsentService.currentPolicyVersion)))
            try await h.runJobs()
            let ref = SubjectRefDeriver(key: h.config.subjectRefKey).subjectRef(businessId: b.id, consumerId: consumer.id)
            let events = try h.webhooks.received.map { try ViadereJSON.decode(WebhookEvent.self, from: $0.body) }
            XCTAssertFalse(events.isEmpty)
            for event in events {
                XCTAssertEqual(event.data.objectValue?["subjectRef"]?.stringValue, ref.rawValue, event.type.rawValue)
            }
            let raw = h.webhooks.received.map { String(decoding: $0.body, as: UTF8.self) }.joined()
            XCTAssertFalse(raw.contains(consumer.id.description), "the global consumer id never leaves Viadere")
        }
    }

    func testBackfillGivesOlderRelationshipsTheirSubjectRef() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b, optIn: [.support])
            // A relationship from before subject_ref existed.
            try await RelationshipRecord.query(on: h.db).filter(\.$id == rel.id.uuid).set(\.$subjectRef, to: nil).update()
            let ref = SubjectRefDeriver(key: h.config.subjectRefKey).subjectRef(businessId: b.id, consumerId: consumer.id)
            try await eq(try await h.businessPost(b, "/v1/business/messages", BusinessSendMessageRequest(subjectRef: ref, body: "x", idempotencyKey: "bf-1")).status, .notFound)
            try await h.runJobs()
            try await eq(try await RelationshipRecord.find(rel.id.uuid, on: h.db)?.subjectRef, ref.rawValue)
            try await eq(try await h.businessPost(b, "/v1/business/messages", BusinessSendMessageRequest(subjectRef: ref, body: "x", idempotencyKey: "bf-2")).status, .created)
        }
    }

    // MARK: Configuration

    func testSubjectRefKeyIsRequiredInProductionAndMustBeDistinct() throws {
        var env = [
            "ENVIRONMENT": "production", "DATABASE_URL": "postgres://u:p@db/viadere", "CONNECT_LINK_SIGNING_KEY": SecureToken.generate(), "SERVER_PEPPER": SecureToken.generate(),
            "DATA_ENCRYPTION_KEY": SecureToken.generate(), "AUDIT_CHAIN_KEY": SecureToken.generate(), "SUBJECT_REF_KEY": SecureToken.generate(), "KEY_DIRECTORY_LOG_KEY": SecureToken.generate(), "EDGE_TOKEN": SecureToken.generate(),
            "APNS_KEY_P8": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "APNS_KEY_ID": "ABC123DEFG", "APNS_TEAM_ID": "TEAM123456",
            "TWILIO_ACCOUNT_SID": "AC1", "TWILIO_AUTH_TOKEN": "tok", "TWILIO_FROM_NUMBER": "+15550001111", "APPLE_TEAM_ID": "TEAM123456",
            "EMAIL_API_URL": "https://mail.example.com/v1/send", "EMAIL_API_KEY": "key_123", "EMAIL_FROM_ADDRESS": "no-reply@viadere.com",
        ]
        XCTAssertNoThrow(try ServerConfig.fromEnvironment(env))
        var missing = env
        missing["SUBJECT_REF_KEY"] = nil
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(missing), "SUBJECT_REF_KEY is required in production")
        for other in ["SERVER_PEPPER", "DATA_ENCRYPTION_KEY", "AUDIT_CHAIN_KEY", "CONNECT_LINK_SIGNING_KEY"] {
            var reused = env
            reused["SUBJECT_REF_KEY"] = env[other]
            XCTAssertThrowsError(try ServerConfig.fromEnvironment(reused), "SUBJECT_REF_KEY must differ from \(other)")
        }
        env["SUBJECT_REF_KEY"] = "short"
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(env))
        // Never an ephemeral key with a real database.
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development", "DATABASE_URL": "postgres://u:p@localhost/v", "CONNECT_LINK_SIGNING_KEY": SecureToken.generate(),
                                                              "SERVER_PEPPER": SecureToken.generate(), "DATA_ENCRYPTION_KEY": SecureToken.generate(), "AUDIT_CHAIN_KEY": SecureToken.generate()]))
    }

    // MARK: Migration of existing keys

    func testMigrationGivesExistingKeysMessagingAndApprovalsOnlyWhereTheBusinessAlreadyIssuedThem() async throws {
        try await withHarness { h in
            // Business 1 already issues approvals; business 2 only sends messages; business 3 has a webhook-only key.
            let approver = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let messenger = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee", capabilities: Capability.messaging)
            let hooks = try await h.makeBusiness(name: "Hook Co", handle: "hookco", scopes: [BusinessAPIKeys.Scope.webhooksManage], capabilities: [])
            let consumer = try await h.readyConsumer()
            let relA = try await h.connect(consumer, to: approver)
            let relM = try await h.connect(consumer, to: messenger)
            try await eq(try await h.issue(approver, relationship: relA, payload: authorize()).status, .created)
            try await eq(try await h.issue(approver, relationship: relA, payload: authenticate(h), key: "au-1").status, .created)
            try await eq(try await h.issue(messenger, relationship: relM, payload: confirm()).status, .created)
            // Put the database back in its pre-migration state: no capabilities, no entitlements.
            try await BusinessAPIKeyRecord.query(on: h.db).set(\.$capabilities, to: "").update()
            try await BusinessEntitlementRecord.query(on: h.db).delete()
            try await CreatePolicyWP2Schema.grandfatherExistingKeys(on: h.db, now: h.clock.now())
            func capabilities(_ b: TestBusiness) async throws -> Set<Capability> {
                try await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == b.record.id!).first()!.capabilitySet
            }
            let approverCaps = try await capabilities(approver)
            XCTAssertEqual(approverCaps, Set(Capability.messaging + [.authChallenge, .transactionApprove]))
            try await eq(try await capabilities(messenger), Set(Capability.messaging), "a messaging business gets no approval scopes")
            try await eq(try await capabilities(hooks), [], "a webhook-only key never could send")
            // The approving business is grandfathered with a recorded reason for operator review; the others get no rows.
            let rows = try await BusinessEntitlementRecord.query(on: h.db).all()
            XCTAssertEqual(Set(rows.map(\.businessId)), [approver.record.id!])
            XCTAssertEqual(Set(rows.map(\.value)), ["A", "auth.challenge", "transaction.approve"])
            XCTAssertTrue(rows.allSatisfy { $0.grantedBy == CreatePolicyWP2Schema.migrationActor && $0.justification.contains("Grandfathered") })
            // And what it could do before it still can.
            try await eq(try await h.issue(approver, relationship: relA, payload: authorize(), key: "after").status, .created)
            // Idempotent.
            try await CreatePolicyWP2Schema.grandfatherExistingKeys(on: h.db, now: h.clock.now())
            try await eq(try await BusinessEntitlementRecord.query(on: h.db).count(), 3)
        }
    }

    // MARK: Dashboard key creation within entitlements

    func testDashboardKeysCanOnlyCarryCapabilitiesTheOrganizationIsEntitledTo() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            // The form offers what the organization has and marks the rest unavailable.
            let page = try await h.page("/dashboard/api-keys", owner).text
            XCTAssertTrue(page.contains("value=\"message.send\" checked"))
            XCTAssertTrue(page.contains("value=\"transaction.approve\" disabled"))
            XCTAssertTrue(page.contains("not enabled for your organization"))
            // Asking for more than the entitlement is refused; nothing is created.
            let tooMuch = try await h.formPost("/dashboard/api-keys", owner, [("name", "k"), ("mode", "test"), ("scopes[]", "interactions:write"), ("capabilitiesChosen", "1"),
                                                                               ("capabilities[]", "message.send"), ("capabilities[]", "transaction.approve")])
            XCTAssertEqual(tooMuch.status, .unprocessableEntity)
            try await eq(try await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == businessId).count(), 0)
            try await eq(try await h.formPost("/dashboard/api-keys", owner, [("name", "k"), ("mode", "test"), ("scopes[]", "interactions:write"), ("capabilitiesChosen", "1"),
                                                                              ("capabilities[]", "age.minimum")]).status, .unprocessableEntity)
            // Within the entitlements it works and is recorded and shown.
            let ok = try await h.formPost("/dashboard/api-keys", owner, [("name", "msg"), ("mode", "test"), ("scopes[]", "interactions:write"), ("capabilitiesChosen", "1"), ("capabilities[]", "message.send")])
            XCTAssertEqual(ok.status, .ok, ok.text)
            try await eq(try await BusinessAPIKeyRecord.query(on: h.db).filter(\.$name == "msg").first()?.capabilitySet, [.messageSend])
            // Leaving every box unticked means none; leaving the field out means the messaging default for a key that can send.
            _ = try await h.formPost("/dashboard/api-keys", owner, [("name", "none"), ("mode", "test"), ("scopes[]", "interactions:read"), ("capabilitiesChosen", "1")])
            try await eq(try await BusinessAPIKeyRecord.query(on: h.db).filter(\.$name == "none").first()?.capabilitySet, [])
            _ = try await h.formPost("/dashboard/api-keys", owner, [("name", "default"), ("mode", "test"), ("scopes[]", "interactions:write")])
            try await eq(try await BusinessAPIKeyRecord.query(on: h.db).filter(\.$name == "default").first()?.capabilitySet, Set(Capability.messaging))
            _ = try await h.formPost("/dashboard/api-keys", owner, [("name", "hooks"), ("mode", "test"), ("scopes[]", "webhooks:manage")])
            try await eq(try await BusinessAPIKeyRecord.query(on: h.db).filter(\.$name == "hooks").first()?.capabilitySet, [])
            let created = try await auditEvents(h, "apikey.created")
            XCTAssertTrue(created.contains { $0.metadataJSON.contains("message.send") })
            try await isTrue(try await h.page("/dashboard/api-keys", owner).text.contains("<code>message.send</code>"))
            // Once the operator grants approvals, the same form can offer them.
            try await h.entitle(businessId, [.transactionApprove])
            try await isTrue(try await h.page("/dashboard/api-keys", owner).text.contains("value=\"transaction.approve\""))
            try await isFalse(try await h.page("/dashboard/api-keys", owner).text.contains("value=\"transaction.approve\" disabled"))
            let approve = try await h.formPost("/dashboard/api-keys", owner, [("name", "approve"), ("mode", "test"), ("scopes[]", "interactions:write"), ("capabilitiesChosen", "1"),
                                                                               ("capabilities[]", "message.send"), ("capabilities[]", "transaction.approve")])
            XCTAssertEqual(approve.status, .ok, approve.text)
        }
    }
}

extension CapabilitySwitchRecord {
    /// Inserts the row, or updates the existing one for the same (capability, scope): what another instance's operator action would do.
    func update(onConflictLike db: any Database) async throws {
        if let existing = try await CapabilitySwitchRecord.query(on: db).filter(\.$capability == capability).filter(\.$scope == scope).first() {
            existing.disabled = disabled
            existing.reason = reason
            try await existing.update(on: db)
        } else {
            try await create(on: db)
        }
    }
}
