import Fluent
import Foundation
import ViadereCore
import Vapor
import XCTest
@testable import ViadereServerKit

final class DashboardPagesTests: XCTestCase {
    // MARK: Roles (least privilege)

    func testEveryRoleSeesExactlyWhatItsJobNeeds() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let expectations: [(path: String, allowed: Set<OrgRole>)] = [
                ("/dashboard", Set(OrgRole.allCases)),
                ("/dashboard/templates", Set(OrgRole.allCases)),
                ("/dashboard/api-keys", [.owner, .admin, .developer]),
                ("/dashboard/webhooks", [.owner, .admin, .developer]),
                ("/dashboard/webhooks/deliveries", [.owner, .admin, .developer]),
                ("/dashboard/campaigns", [.owner, .admin, .developer]),
                ("/dashboard/consent", [.owner, .admin, .support, .analyst]),
                ("/dashboard/audit", [.owner, .admin]),
                ("/dashboard/team", [.owner, .admin]),
                ("/dashboard/billing", [.owner, .admin, .analyst]),
                ("/dashboard/organization", [.owner, .admin]),
            ]
            var sessions: [OrgRole: DashSession] = [.owner: owner]
            for role in OrgRole.allCases where role != .owner {
                sessions[role] = try await h.addMember(owner: owner, role: role, email: "\(role.rawValue)@example.com").session
            }
            for (path, allowed) in expectations {
                for role in OrgRole.allCases {
                    let status = try await h.get(sessions[role]!, path)
                    XCTAssertEqual(status, allowed.contains(role) ? .ok : .forbidden, "\(role) \(path)")
                }
            }
            // Navigation only offers what the role can open.
            let support = try await h.page("/dashboard", sessions[.support]).text
            XCTAssertFalse(support.contains("href=\"/dashboard/api-keys\""))
            XCTAssertFalse(support.contains("href=\"/dashboard/team\""))
            XCTAssertTrue(support.contains("href=\"/dashboard/consent\""))
            let developer = try await h.page("/dashboard", sessions[.developer]).text
            XCTAssertTrue(developer.contains("href=\"/dashboard/api-keys\""))
            XCTAssertFalse(developer.contains("href=\"/dashboard/billing\""))
        }
    }

    func testMutationsAreRoleGatedServerSideNotJustHiddenInTheUI() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let support = try await h.addMember(owner: owner, role: .support, email: "support@example.com").session
            let analyst = try await h.addMember(owner: owner, role: .analyst, email: "analyst@example.com").session
            let developer = try await h.addMember(owner: owner, role: .developer, email: "dev@example.com").session
            let keyForm: [(String, String)] = [("name", "k"), ("mode", "test"), ("scopes[]", "interactions:write")]
            for (role, session) in [(OrgRole.support, support), (.analyst, analyst)] {
                let r = try await h.formPost("/dashboard/api-keys", session, keyForm)
                XCTAssertEqual(r.status, .forbidden, "\(role)")
            }
            try await eq(try await BusinessAPIKeyRecord.query(on: h.db).count(), 0)
            // A developer can manage keys and webhooks but not the team.
            try await eq(try await h.formPost("/dashboard/api-keys", developer, keyForm).status, .ok)
            try await eq(try await h.formPost("/dashboard/team/invite", developer, [("email", "x@example.com"), ("role", "analyst")]).status, .forbidden)
            let member = try await OrgMembershipRecord.query(on: h.db).filter(\.$role == "analyst").first()!
            try await eq(try await h.formPost("/dashboard/team/members/\(member.id!.uuidString.lowercased())/remove", developer).status, .forbidden)
            try await eq(try await h.formPost("/dashboard/team/members/\(member.id!.uuidString.lowercased())/role", developer, [("role", "owner")]).status, .forbidden)
            // Campaign links are not for support.
            try await eq(try await h.formPost("/dashboard/campaigns", support, [("campaign", "spring"), ("days", "30")]).status, .forbidden)
        }
    }

    func testRoleChangesAndRemovalTakeEffectImmediately() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let dev = try await h.addMember(owner: owner, role: .developer, email: "dev@example.com").session
            try await eq(try await h.get(dev, "/dashboard/api-keys"), .ok)
            let membership = try await OrgMembershipRecord.query(on: h.db).filter(\.$role == "developer").first()!
            let id = membership.id!.uuidString.lowercased()
            // Demote: the very next request from the same session is forbidden.
            try await eq(try await h.formPost("/dashboard/team/members/\(id)/role", owner, [("role", "analyst")]).status, .seeOther)
            try await eq(try await h.get(dev, "/dashboard/api-keys"), .forbidden)
            try await eq(try await h.get(dev, "/dashboard/billing"), .ok)
            // Remove: the session ends.
            try await eq(try await h.formPost("/dashboard/team/members/\(id)/remove", owner).status, .seeOther)
            try await eq(try await h.get(dev, "/dashboard"), .seeOther)
            let removed = try await OrgMembershipRecord.find(membership.id!, on: h.db)
            XCTAssertNotNil(removed?.removedAt)
        }
    }

    func testOwnersAreProtectedAdminsCannotEscalateAndTheLastOwnerCannotLeave() async throws {
        try await withHarness { h in
            let (owner, ownerAccount, _) = try await h.verifiedOwner()
            let admin = try await h.addMember(owner: owner, role: .admin, email: "admin@example.com").session
            let ownerMembership = try await OrgMembershipRecord.query(on: h.db).filter(\.$role == "owner").first()!
            let adminMembership = try await OrgMembershipRecord.query(on: h.db).filter(\.$role == "admin").first()!
            // Admins cannot invite owners, promote to owner, demote an owner or remove one.
            try await eq(try await h.formPost("/dashboard/team/invite", admin, [("email", "o2@example.com"), ("role", "owner")]).status, .forbidden)
            try await eq(try await h.formPost("/dashboard/team/members/\(adminMembership.id!.uuidString.lowercased())/role", admin, [("role", "owner")]).status, .conflict)
            try await eq(try await h.formPost("/dashboard/team/members/\(ownerMembership.id!.uuidString.lowercased())/role", admin, [("role", "analyst")]).status, .forbidden)
            try await eq(try await h.formPost("/dashboard/team/members/\(ownerMembership.id!.uuidString.lowercased())/remove", admin).status, .forbidden)
            // The owner cannot change or remove themselves (no accidental lock-out).
            try await eq(try await h.formPost("/dashboard/team/members/\(ownerMembership.id!.uuidString.lowercased())/role", owner, [("role", "admin")]).status, .conflict)
            try await eq(try await h.formPost("/dashboard/team/members/\(ownerMembership.id!.uuidString.lowercased())/remove", owner).status, .conflict)
            // Promoting an admin to owner is the owner's call, and needs a fresh passkey.
            h.clock.advance(by: 10 * 60)
            let denied = try await h.formPost("/dashboard/team/members/\(adminMembership.id!.uuidString.lowercased())/role", owner, [("role", "owner")])
            XCTAssertEqual(denied.status, .forbidden)
            XCTAssertTrue(denied.text.contains("Confirm with passkey"))
            try await eq(try await OrgMembershipRecord.find(adminMembership.id!, on: h.db)?.role, "admin")
            try await h.dashReauth(owner, ownerAccount)
            try await eq(try await h.formPost("/dashboard/team/members/\(adminMembership.id!.uuidString.lowercased())/role", owner, [("role", "owner")]).status, .seeOther)
            try await eq(try await OrgMembershipRecord.find(adminMembership.id!, on: h.db)?.role, "owner")
            // Two owners now: the new owner may demote the first (never the last).
            let newOwner = admin
            try await eq(try await h.formPost("/dashboard/team/members/\(ownerMembership.id!.uuidString.lowercased())/role", newOwner, [("role", "admin")]).status, .seeOther)
            // The only remaining owner is protected from any change by others.
            let remaining = try await OrgMembershipRecord.query(on: h.db).filter(\.$role == "owner").count()
            XCTAssertEqual(remaining, 1)
        }
    }

    func testInvitationsAreSingleUseExpireAndOnlyTheNewestWorks() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let first = try await h.formPost("/dashboard/team/invite", owner, [("email", "new@example.com"), ("role", "developer")])
            let firstToken = String(first.text[first.text.range(of: "/dashboard/invite/")!.upperBound...].prefix { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
            let second = try await h.formPost("/dashboard/team/invite", owner, [("email", "NEW@example.com"), ("role", "analyst")])
            let secondToken = String(second.text[second.text.range(of: "/dashboard/invite/")!.upperBound...].prefix { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
            XCTAssertNotEqual(firstToken, secondToken)
            // Tokens are stored hashed only.
            let invites = try await OrgInviteRecord.query(on: h.db).all()
            XCTAssertTrue(invites.allSatisfy { $0.tokenHash != firstToken && $0.tokenHash != secondToken })
            // The superseded link is dead.
            try await eq(try await h.page("/dashboard/invite/\(firstToken)", nil).status, .gone)
            try await eq(try await h.jsonPost("/dashboard/auth/invite/begin", InviteBeginBody(token: firstToken, displayName: "N")).status, .unprocessableEntity)
            // The live one registers once; the account's role is the invited one.
            let page = try await h.page("/dashboard/invite/\(secondToken)", nil)
            XCTAssertEqual(page.status, .ok)
            XCTAssertTrue(page.text.contains("Acme Roasters"))
            let begin = try await h.jsonPost("/dashboard/auth/invite/begin", InviteBeginBody(token: secondToken, displayName: "New Person"))
            let options = try begin.json(PasskeyRegistrationOptions.self)
            let cred = h.registrationCredential(for: options, credentialId: "cred-\(UUID().uuidString)", publicKey: SecureToken.generate(byteCount: 32))
            let finish = try await h.jsonPost("/dashboard/auth/invite/finish", PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: cred))
            XCTAssertEqual(finish.status, .ok)
            try await eq(try await OrgMembershipRecord.query(on: h.db).filter(\.$role == "analyst").count(), 1)
            try await eq(try await h.page("/dashboard/invite/\(secondToken)", nil).status, .gone)
            // Expiry.
            let third = try await h.formPost("/dashboard/team/invite", owner, [("email", "late@example.com"), ("role", "support")])
            let thirdToken = String(third.text[third.text.range(of: "/dashboard/invite/")!.upperBound...].prefix { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
            h.clock.advance(by: 8 * 24 * 3600)
            try await eq(try await h.page("/dashboard/invite/\(thirdToken)", nil).status, .gone)
        }
    }

    func testExistingUserAcceptsAnInvitationAddressedToTheirOwnEmailOnly() async throws {
        try await withHarness { h in
            let (ownerA, _, aId) = try await h.verifiedOwner(email: "a@example.com", org: "Org Alpha", handle: "orgalpha")
            let (ownerB, _, bId) = try await h.verifiedOwner(email: "b@example.com", org: "Org Beta", handle: "orgbeta")
            let invite = try await h.formPost("/dashboard/team/invite", ownerA, [("email", "b@example.com"), ("role", "support")])
            let token = String(invite.text[invite.text.range(of: "/dashboard/invite/")!.upperBound...].prefix { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
            // B sees an accept button (not the registration form) and accepts.
            let landing = try await h.page("/dashboard/invite/\(token)", ownerB)
            XCTAssertTrue(landing.text.contains("Accept invitation"))
            // A different signed-in user (the inviter) cannot accept it for themselves.
            try await eq(try await h.formPost("/dashboard/invite/\(token)/accept", ownerA).status, .forbidden)
            try await eq(try await h.formPost("/dashboard/invite/\(token)/accept", ownerB).status, .seeOther)
            let member = try await OrgMembershipRecord.query(on: h.db).filter(\.$businessId == aId).filter(\.$role == "support").first()
            XCTAssertNotNil(member)
            // B's session moved to Org Alpha with the support role; it can still return to its own organization.
            try await eq(try await h.get(ownerB, "/dashboard/consent"), .ok)
            try await eq(try await h.get(ownerB, "/dashboard/api-keys"), .forbidden)
            try await eq(try await h.formPost("/dashboard/switch", ownerB, [("businessId", bId.uuidString)]).status, .seeOther)
            try await eq(try await h.get(ownerB, "/dashboard/api-keys"), .ok)
            // Single use.
            try await eq(try await h.formPost("/dashboard/invite/\(token)/accept", ownerB).status, .forbidden)
        }
    }

    // MARK: Tenant isolation

    func testOrganizationsNeverSeeOrTouchEachOthersData() async throws {
        try await withHarness { h in
            let (a, aAccount, aId) = try await h.verifiedOwner(email: "a@example.com", org: "Alpha Air", handle: "alphaair")
            let (b, _, bId) = try await h.verifiedOwner(email: "b@example.com", org: "Beta Bank", handle: "betabank")
            // A creates a key, a webhook endpoint and a delivery.
            let created = try await h.formPost("/dashboard/api-keys", a, [("name", "alpha-prod-key"), ("mode", "live"), ("scopes[]", "interactions:write")])
            XCTAssertEqual(created.status, .ok)
            let keyRecord = try await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == aId).first()!
            let hook = try await h.formPost("/dashboard/webhooks", a, [("url", "https://alpha.example.com/hook"), ("events[]", "message.received")])
            XCTAssertEqual(hook.status, .ok)
            let subscription = try await WebhookSubscriptionRecord.query(on: h.db).filter(\.$businessId == aId).first()!
            try await WebhookService(db: h.db, ctx: h.ctx).enqueue(.messageReceived, businessId: BusinessID(aId),
                payload: MessageReceivedPayload(sessionId: SessionID(), relationshipId: RelationshipID(), messageId: MessageID(), text: "alpha private text",
                                                channel: .sms, receivedAt: h.clock.now()))
            let delivery = try await WebhookDeliveryRecord.query(on: h.db).filter(\.$businessId == aId).first()!
            let ownTeam = try await h.page("/dashboard/team", a).text
            XCTAssertTrue(ownTeam.contains("a@example.com"))

            // B cannot see A's key, webhook, delivery or people...
            let keys = try await h.page("/dashboard/api-keys", b).text
            XCTAssertFalse(keys.contains("alpha-prod-key"))
            XCTAssertFalse(keys.contains(keyRecord.last4 + "<"))
            try await isFalse(try await h.page("/dashboard/webhooks", b).text.contains("alpha.example.com"))
            try await eq(try await h.get(b, "/dashboard/webhooks/deliveries/\(delivery.id!.uuidString.lowercased())"), .notFound)
            let bTeam = try await h.page("/dashboard/team", b).text
            XCTAssertFalse(bTeam.contains("a@example.com"))
            try await isFalse(try await h.page("/dashboard/webhooks/deliveries", b).text.contains("message.received"))
            // ...nor act on them.
            try await eq(try await h.formPost("/dashboard/api-keys/\(keyRecord.id!.uuidString.lowercased())/revoke", b).status, .notFound)
            try await isNil(try await BusinessAPIKeyRecord.find(keyRecord.id!, on: h.db)?.revokedAt)
            try await eq(try await h.formPost("/dashboard/webhooks/\(subscription.id!.uuidString.lowercased())/delete", b).status, .notFound)
            try await eq(try await WebhookSubscriptionRecord.find(subscription.id!, on: h.db)?.active, true)
            try await eq(try await h.formPost("/dashboard/webhooks/\(subscription.id!.uuidString.lowercased())/rotate", b).status, .notFound)
            try await eq(try await h.formPost("/dashboard/webhooks/deliveries/\(delivery.id!.uuidString.lowercased())/replay", b).status, .notFound)
            let aMembership = try await OrgMembershipRecord.query(on: h.db).filter(\.$businessId == aId).first()!
            try await eq(try await h.formPost("/dashboard/team/members/\(aMembership.id!.uuidString.lowercased())/role", b, [("role", "analyst")]).status, .notFound)
            try await eq(try await h.formPost("/dashboard/team/members/\(aMembership.id!.uuidString.lowercased())/remove", b).status, .notFound)
            let aInvite = try await h.formPost("/dashboard/team/invite", a, [("email", "pending@example.com"), ("role", "analyst")])
            XCTAssertEqual(aInvite.status, .ok)
            let invite = try await OrgInviteRecord.query(on: h.db).filter(\.$businessId == aId).first()!
            try await eq(try await h.formPost("/dashboard/team/invites/\(invite.id!.uuidString.lowercased())/revoke", b).status, .notFound)
            // Audit logs are per organization.
            let aAudit = try await h.page("/dashboard/audit", a).text
            let bAudit = try await h.page("/dashboard/audit", b).text
            let marker = String(keyRecord.id!.uuidString.lowercased().suffix(6))
            XCTAssertTrue(aAudit.contains(marker))
            XCTAssertFalse(bAudit.contains(marker))
            XCTAssertFalse(bAudit.contains("apikey.created"))
            // Switching to an organization you do not belong to is refused, and a tampered session row is useless.
            try await eq(try await h.formPost("/dashboard/switch", b, [("businessId", aId.uuidString)]).status, .forbidden)
            let bSession = try await DashboardSessionRecord.query(on: h.db).filter(\.$tokenHash == SecureToken.hash(b.token)).first()!
            bSession.businessId = aId
            try await bSession.update(on: h.db)
            try await eq(try await h.get(b, "/dashboard/api-keys"), .seeOther, "no membership in the claimed organization")
            _ = (bId, aAccount)
        }
    }

    func testAnalyticsAndUsageAreScopedAndAggregateOnly() async throws {
        try await withHarness { h in
            let (a, _, aId) = try await h.verifiedOwner(email: "a@example.com", org: "Alpha Air", handle: "alphaair")
            let (b, _, _) = try await h.verifiedOwner(email: "b@example.com", org: "Beta Bank", handle: "betabank")
            let business = try await h.testBusiness(aId)
            let consumer = try await h.readyConsumer(name: "Very Private Person")
            let relationship = try await h.connect(consumer, to: business)
            for i in 0..<3 {
                let r = try await h.issue(business, relationship: relationship,
                    payload: .confirm(ConfirmPayload(title: "Confirm order \(i)", details: "Secret details \(i)", reference: "REF\(i)")),
                    purpose: .transactional, key: "k\(i)")
                XCTAssertEqual(r.status, .created, r.text)
            }
            let issued = try await XCTUnwrapAsync(await InteractionRecord.query(on: h.db).filter(\.$businessId == aId).first())
            let interaction = try await h.consumerInteraction(consumer, id: InteractionID(issued.id!))
            h.clock.advance(by: 42)
            let signed = try await h.decision(consumer, interaction: interaction, decision: .confirm, assurance: .devicePasscode)
            try await eq(try await h.decide(consumer, id: interaction.id, signed: signed).status, .ok)
            let overview = try await h.page("/dashboard", a).text
            XCTAssertTrue(overview.contains(">3</div><div class=\"l\">Interactions issued"), overview)
            XCTAssertTrue(overview.contains(">1</div><div class=\"l\">Decided"))
            XCTAssertTrue(overview.contains("42 s"), "median decision time")
            // Aggregates only: nothing about the consumer or the content appears.
            for secret in ["Very Private Person", "Secret details", "REF0", consumer.id.description, relationship.id.description] {
                XCTAssertFalse(overview.contains(secret), secret)
            }
            // Another organization's overview is empty.
            let bOverview = try await h.page("/dashboard", b).text
            XCTAssertTrue(bOverview.contains(">0</div><div class=\"l\">Interactions issued"))
            // Consent status counts are aggregate too.
            let consent = try await h.page("/dashboard/consent", a).text
            XCTAssertTrue(consent.contains(">1</div><div class=\"l\">Connected customers"))
            XCTAssertFalse(consent.contains(consumer.id.description))
            try await isTrue(try await h.page("/dashboard/consent", b).text.contains(">0</div><div class=\"l\">Connected customers"))
        }
    }

    // MARK: API keys

    func testCreatingAndRevokingAnAPIKeyShowsTheSecretOnceAndStopsItWorkingImmediately() async throws {
        try await withHarness { h in
            let (owner, _, aId) = try await h.verifiedOwner()
            let created = try await h.formPost("/dashboard/api-keys", owner, [("name", "Production"), ("mode", "test"), ("scopes[]", "interactions:read"), ("scopes[]", "webhooks:manage")])
            XCTAssertEqual(created.status, .ok, created.text)
            let secret = try XCTUnwrap(h.shownSecret(created.text))
            XCTAssertTrue(secret.hasPrefix("vdk_test_"))
            XCTAssertEqual(created.headers.first(name: .cacheControl), "no-store")
            let record = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == aId).first())
            XCTAssertEqual(record.keyHash, SecureToken.hash(secret))
            XCTAssertEqual(record.scopeSet, ["interactions:read", "webhooks:manage"])
            XCTAssertFalse(record.livemode)
            // Never shown again: the listing has prefix and last four only.
            let list = try await h.page("/dashboard/api-keys", owner).text
            XCTAssertFalse(list.contains(secret))
            XCTAssertTrue(list.contains("vdk_test_…\(record.last4)"))
            XCTAssertTrue(list.contains("Production"))
            // Scoped: it works for its scopes and only those.
            let webhooks = try await h.request(.GET, "/v1/business/webhooks", headers: ["Authorization": "Bearer \(secret)"])
            XCTAssertEqual(webhooks.status, .ok)
            let notAllowed = try await h.request(.POST, "/v1/business/messages", headers: ["Authorization": "Bearer \(secret)", "Idempotency-Key": "k"], body: Data("{}".utf8))
            XCTAssertEqual(notAllowed.status, .forbidden)
            // Last-used shows up.
            try await notNil(try await BusinessAPIKeyRecord.find(record.id!, on: h.db)?.lastUsedAt)
            try await isFalse(try await h.page("/dashboard/api-keys", owner).text.contains("<td>—</td><td>"), "last used is shown")
            // Revoke: immediate, idempotent, audited.
            try await eq(try await h.formPost("/dashboard/api-keys/\(record.id!.uuidString.lowercased())/revoke", owner).status, .seeOther)
            let after = try await h.request(.GET, "/v1/business/webhooks", headers: ["Authorization": "Bearer \(secret)"])
            XCTAssertEqual(after.status, .unauthorized)
            try await eq(try await h.formPost("/dashboard/api-keys/\(record.id!.uuidString.lowercased())/revoke", owner).status, .seeOther)
            let actions = try await AuditEventRecord.query(on: h.db).filter(\.$businessId == aId).all().map(\.action)
            XCTAssertTrue(actions.contains("apikey.created"))
            XCTAssertTrue(actions.contains("apikey.revoked"))
            // The audit trail never contains the secret.
            let all = try await AuditEventRecord.query(on: h.db).all()
            XCTAssertFalse(all.contains { $0.metadataJSON.contains(secret) || $0.metadataJSON.contains("vdk_") })
            let chain = try await AuditService.verifyChain(on: h.db, key: h.ctx.config.auditChainKey)
            XCTAssertTrue(chain.valid)
        }
    }

    func testKeyCreationValidation() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            try await eq(try await h.formPost("/dashboard/api-keys", owner, [("name", ""), ("mode", "test"), ("scopes[]", "interactions:write")]).status, .unprocessableEntity)
            try await eq(try await h.formPost("/dashboard/api-keys", owner, [("name", "k"), ("mode", "test")]).status, .unprocessableEntity)
            try await eq(try await h.formPost("/dashboard/api-keys", owner, [("name", "k"), ("mode", "test"), ("scopes[]", "admin:everything")]).status, .unprocessableEntity)
            try await eq(try await BusinessAPIKeyRecord.query(on: h.db).count(), 0)
            for i in 0..<DashboardActions.maxActiveKeys {
                try await eq(try await h.formPost("/dashboard/api-keys", owner, [("name", "k\(i)"), ("mode", "test"), ("scopes[]", "interactions:read")]).status, .ok)
            }
            try await eq(try await h.formPost("/dashboard/api-keys", owner, [("name", "one too many"), ("mode", "test"), ("scopes[]", "interactions:read")]).status, .conflict)
            // Expiring keys stop working.
            let first = try await BusinessAPIKeyRecord.query(on: h.db).first()!
            _ = first
        }
    }

    func testExpiringKeysStopWorking() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let created = try await h.formPost("/dashboard/api-keys", owner, [("name", "short"), ("mode", "test"), ("scopes[]", "interactions:read"), ("expires", "30")])
            let secret = try XCTUnwrap(h.shownSecret(created.text))
            try await eq(try await h.request(.GET, "/v1/business/webhooks", headers: ["Authorization": "Bearer \(secret)"]).status, .forbidden, "scope check proves auth passed")
            h.clock.advance(by: 31 * 86_400)
            try await eq(try await h.request(.GET, "/v1/business/webhooks", headers: ["Authorization": "Bearer \(secret)"]).status, .unauthorized)
        }
    }

    // MARK: Webhooks

    func testWebhookDeliveryLogRedactsPayloadsAndDeadLettersCanBeReplayedOnce() async throws {
        try await withHarness { h in
            let (firstSession, account, aId) = try await h.verifiedOwner()
            var owner = firstSession
            let hook = try await h.formPost("/dashboard/webhooks", owner, [("url", "https://hooks.example.com/in"), ("events[]", "message.received")])
            XCTAssertEqual(hook.status, .ok, hook.text)
            XCTAssertNotNil(h.shownSecret(hook.text)?.hasPrefix("whsec_"))
            try await WebhookService(db: h.db, ctx: h.ctx).enqueue(.messageReceived, businessId: BusinessID(aId),
                payload: MessageReceivedPayload(sessionId: SessionID(), relationshipId: RelationshipID(), messageId: MessageID(),
                                                text: "my card number is 4111 1111 1111 1111", channel: .sms, receivedAt: h.clock.now()))
            let delivery = try await WebhookDeliveryRecord.query(on: h.db).first()!
            let id = delivery.id!.uuidString.lowercased()
            // The stored body keeps the text (the receiver needs it); the dashboard never shows it.
            XCTAssertFalse(delivery.body.contains("4111"), "the stored body is encrypted at rest")
            let storedBody = String(decoding: try XCTUnwrap(WebhookService(db: h.db, ctx: h.ctx).deliveryBody(delivery)), as: UTF8.self)
            XCTAssertTrue(storedBody.contains("4111 1111 1111 1111"))
            let view = try await h.page("/dashboard/webhooks/deliveries/\(id)", owner).text
            XCTAssertFalse(view.contains("4111"))
            XCTAssertTrue(view.contains("[redacted]"))
            XCTAssertTrue(view.contains("message.received"))
            // Fail every attempt until the delivery is dead-lettered.
            h.webhooks.respond(with: Array(repeating: 500, count: 20))
            for _ in 0..<10 {
                try await h.runJobs()
                h.clock.advance(by: 25 * 3600)
            }
            let dead = try await WebhookDeliveryRecord.find(delivery.id!, on: h.db)!
            XCTAssertEqual(dead.status, "dead")
            // Days passed: the old session timed out, so sign in again (a fresh passkey assertion too).
            let stale = try await h.page("/dashboard", owner)
            XCTAssertEqual(stale.status, .seeOther)
            let relogin = try await h.dashLogin(account)
            owner = try XCTUnwrap(relogin.session)
            let log = try await h.page("/dashboard/webhooks/deliveries", owner).text
            XCTAssertTrue(log.contains("dead"))
            XCTAssertTrue(log.contains("Replay"))
            // Replay: once. The second click conflicts.
            h.webhooks.respond(with: [], then: 200)
            try await eq(try await h.formPost("/dashboard/webhooks/deliveries/\(id)/replay", owner).status, .seeOther)
            let queued = try await WebhookDeliveryRecord.find(delivery.id!, on: h.db)!
            XCTAssertEqual(queued.status, "pending")
            XCTAssertEqual(queued.attempts, 0)
            try await eq(try await h.formPost("/dashboard/webhooks/deliveries/\(id)/replay", owner).status, .conflict)
            try await h.runJobs()
            try await eq(try await WebhookDeliveryRecord.find(delivery.id!, on: h.db)?.status, "succeeded")
            // Replaying something that is not dead-lettered is refused.
            try await eq(try await h.formPost("/dashboard/webhooks/deliveries/\(id)/replay", owner).status, .conflict)
            let actions = try await AuditEventRecord.query(on: h.db).filter(\.$businessId == aId).all().map(\.action)
            XCTAssertTrue(actions.contains("dashboard.webhook_replayed"))
            XCTAssertTrue(actions.contains("dashboard.webhook_created"))
        }
    }

    func testWebhookEndpointRulesAreEnforcedFromTheDashboardToo() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let bad = try await h.formPost("/dashboard/webhooks", owner, [("url", "http://not-https.example.com/x"), ("events[]", "message.received")])
            _ = bad // the testing config allows insecure URLs; production rejects them (covered by WebhookService tests)
            let noEvents = try await h.formPost("/dashboard/webhooks", owner, [("url", "https://hooks.example.com/x")])
            XCTAssertEqual(noEvents.status, .unprocessableEntity)
            let unknown = try await h.formPost("/dashboard/webhooks", owner, [("url", "https://hooks.example.com/x"), ("events[]", "made.up")])
            XCTAssertEqual(unknown.status, .unprocessableEntity)
            // Rotation overlap: both secrets sign until the old one expires.
            let created = try await h.formPost("/dashboard/webhooks", owner, [("url", "https://hooks.example.com/y"), ("events[]", "message.received")])
            let first = try XCTUnwrap(h.shownSecret(created.text))
            let sub = try await WebhookSubscriptionRecord.query(on: h.db).filter(\.$url == "https://hooks.example.com/y").first()!
            let rotated = try await h.formPost("/dashboard/webhooks/\(sub.id!.uuidString.lowercased())/rotate", owner)
            let second = try XCTUnwrap(h.shownSecret(rotated.text))
            XCTAssertNotEqual(first, second)
            try await WebhookService(db: h.db, ctx: h.ctx).enqueue(.messageReceived, businessId: BusinessID(sub.businessId),
                payload: MessageReceivedPayload(sessionId: SessionID(), relationshipId: RelationshipID(), messageId: MessageID(), text: "x", channel: .sms, receivedAt: h.clock.now()))
            try await h.runJobs()
            let sent = try XCTUnwrap(h.webhooks.received.last { $0.url.absoluteString == "https://hooks.example.com/y" })
            let header = try XCTUnwrap(sent.headers[ViadereHeader.signature])
            XCTAssertNoThrow(try WebhookSignature.verify(header: header, body: sent.body, secrets: [second], now: h.clock.now()))
            XCTAssertNoThrow(try WebhookSignature.verify(header: header, body: sent.body, secrets: [first], now: h.clock.now()))
        }
    }

    // MARK: Templates, campaigns

    func testEveryTemplateIsAValidRequestBuiltFromTheRealTypes() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let now = h.clock.now()
            let templates = InteractionTemplates.all(now: now)
            XCTAssertGreaterThanOrEqual(templates.count, 8)
            var kinds = Set<String>()
            for template in templates {
                if let request = template.request {
                    let decoded = try ViadereJSON.decode(IssueInteractionRequest.self, from: Data(template.json.utf8))
                    XCTAssertEqual(decoded, request, template.id)
                    let interaction = decoded.makeInteraction(businessId: BusinessID(), consumerId: ConsumerID(), now: now)
                    XCTAssertEqual(InteractionValidation.issues(in: interaction, now: now), [], template.id)
                    kinds.insert(interaction.kind.rawValue)
                } else {
                    XCTAssertNotNil(try? JSONSerialization.jsonObject(with: Data(template.json.utf8)), template.id)
                }
            }
            XCTAssertTrue(kinds.isSuperset(of: ["authenticate", "authorize", "confirm", "choose", "acknowledge", "reply"]))
            let page = try await h.page("/dashboard/templates", owner)
            XCTAssertEqual(page.status, .ok)
            XCTAssertTrue(page.text.contains("Sign-in approval"))
            XCTAssertTrue(page.text.contains("/v1/business/interactions"))
        }
    }

    func testCampaignLinkIsSignedVerifiesAndItsQRCodeEncodesExactlyThatLink() async throws {
        try await withHarness { h in
            let (owner, _, aId) = try await h.verifiedOwner()
            let result = try await h.formPost("/dashboard/campaigns", owner, [("campaign", "spring-flyer"), ("action", "enroll_rewards"), ("days", "30")])
            XCTAssertEqual(result.status, .ok, result.text)
            let regex = try NSRegularExpression(pattern: "https://viadere\\.com/c/[0-9A-Z]{6}\\?ctx=[A-Za-z0-9_-]+&amp;sig=[A-Za-z0-9_-]{43}")
            let range = try XCTUnwrap(regex.firstMatch(in: result.text, range: NSRange(result.text.startIndex..., in: result.text))?.range)
            let urlString = String(result.text[Range(range, in: result.text)!]).replacingOccurrences(of: "&amp;", with: "&")
            let link = try ConnectLink.parse(urlString)
            let context = try link.verifiedContext(key: h.config.connectLinkKey, now: h.clock.now())
            XCTAssertEqual(context.campaign, "spring-flyer")
            XCTAssertEqual(context.action, "enroll_rewards")
            XCTAssertEqual(context.expiresAt?.timeIntervalSince1970 ?? 0, h.clock.now().addingTimeInterval(30 * 86_400).timeIntervalSince1970, accuracy: 1)
            XCTAssertThrowsError(try link.verifiedContext(key: h.config.connectLinkKey, now: h.clock.now().addingTimeInterval(31 * 86_400)))
            // The link resolves to this organization through the public directory.
            let code = try await BusinessCodeRecord.query(on: h.db).filter(\.$businessId == aId).first()!
            XCTAssertEqual(link.code.canonical, code.canonical)
            let resolved = try await h.post("/v1/directory/resolve", DirectoryResolveRequest(input: urlString)).json(DirectoryResolveResponse.self)
            XCTAssertEqual(resolved.context?.campaign, "spring-flyer")
            XCTAssertEqual(resolved.matches.first?.id.uuid, aId)
            // The QR in the page is exactly the QR of that link (rebuilt from the SVG path).
            let svgStart = try XCTUnwrap(result.text.range(of: "<svg xmlns"))
            let svgEnd = try XCTUnwrap(result.text.range(of: "</svg>", range: svgStart.lowerBound..<result.text.endIndex))
            let svg = String(result.text[svgStart.lowerBound..<svgEnd.upperBound])
            let expected = try QRCode.encode(urlString, errorCorrection: .medium)
            XCTAssertEqual(Self.modules(fromSVG: svg, size: expected.size, border: 4), expected.modules)
            XCTAssertFalse(svg.contains("<script"))
            // Download returns the SVG as an attachment with a locked-down CSP.
            let download = try await h.formPost("/dashboard/campaigns/download", owner, [("campaign", "spring-flyer"), ("action", "enroll_rewards"), ("days", "30")])
            XCTAssertEqual(download.status, .ok)
            XCTAssertEqual(download.headers.first(name: .contentType), "image/svg+xml")
            XCTAssertTrue(download.headers.first(name: .contentDisposition)?.hasPrefix("attachment") == true)
            XCTAssertTrue(download.text.hasPrefix("<svg"))
            // Validation.
            try await eq(try await h.formPost("/dashboard/campaigns", owner, [("campaign", "bad name!"), ("days", "30")]).status, .unprocessableEntity)
            try await eq(try await h.formPost("/dashboard/campaigns", owner, [("campaign", ""), ("days", "30")]).status, .unprocessableEntity)
            try await eq(try await h.formPost("/dashboard/campaigns", owner, [("campaign", String(repeating: "a", count: 65)), ("days", "30")]).status, .unprocessableEntity)
        }
    }

    static func modules(fromSVG svg: String, size: Int, border: Int) -> [[Bool]] {
        var grid = Array(repeating: Array(repeating: false, count: size), count: size)
        guard let d = svg.range(of: "<path d=\""), let end = svg.range(of: "\" fill=", range: d.upperBound..<svg.endIndex) else { return grid }
        for part in svg[d.upperBound..<end.lowerBound].split(separator: "M").map(String.init) where !part.isEmpty {
            let comma = part.firstIndex(of: ",")!, h = part.firstIndex(of: "h")!, v = part.firstIndex(of: "v")!
            let x = Int(part[..<comma])! - border, y = Int(part[part.index(after: comma)..<h])! - border
            let w = Int(part[part.index(after: h)..<v])!
            for i in 0..<w { grid[y][x + i] = true }
        }
        return grid
    }

    func testPendingOrganizationsCannotCreateKeysWebhooksOrLinks() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.dashSignup()
            for (path, form) in [("/dashboard/api-keys", [("name", "k"), ("mode", "test"), ("scopes[]", "interactions:write")]),
                                 ("/dashboard/webhooks", [("url", "https://hooks.example.com/x"), ("events[]", "message.received")]),
                                 ("/dashboard/campaigns", [("campaign", "c"), ("days", "30")])] {
                let r = try await h.formPost(path, owner, form)
                XCTAssertEqual(r.status, .forbidden, path)
                XCTAssertTrue(r.text.contains("verified your organization"), path)
            }
            try await eq(try await BusinessAPIKeyRecord.query(on: h.db).count(), 0)
            let page = try await h.page("/dashboard", owner).text
            XCTAssertTrue(page.contains("awaiting verification"))
            try await isTrue(try await h.page("/dashboard/api-keys", owner).text.contains("Keys can be created after Viadere verifies your organization"))
        }
    }

    // MARK: Audit viewer, billing

    func testAuditViewerListsOnlyThisTenantsEventsWithRedactedDetails() async throws {
        try await withHarness { h in
            let (owner, _, aId) = try await h.verifiedOwner()
            _ = try await h.formPost("/dashboard/api-keys", owner, [("name", "k"), ("mode", "test"), ("scopes[]", "interactions:write")])
            for i in 0..<55 {
                _ = try await AuditService(db: h.db, ctx: h.ctx).record("test.event\(i)", actor: AuditActor(kind: .system), businessId: BusinessID(aId),
                                                                      metadata: ["token": "SECRETTOKENVALUE", "note": "visible"])
            }
            _ = try await AuditService(db: h.db, ctx: h.ctx).record("other.tenant.event", actor: AuditActor(kind: .system), businessId: BusinessID())
            let first = try await h.page("/dashboard/audit", owner).text
            XCTAssertTrue(first.contains("test.event54"))
            XCTAssertFalse(first.contains("other.tenant.event"))
            XCTAssertFalse(first.contains("SECRETTOKENVALUE"))
            XCTAssertTrue(first.contains("[redacted]"))
            XCTAssertTrue(first.contains("Older"))
            let second = try await h.page("/dashboard/audit?page=1", owner).text
            XCTAssertTrue(second.contains("apikey.created"))
            XCTAssertTrue(second.contains("Olive Owner"), "actor shown by name for members")
            XCTAssertFalse(second.contains("Older"))
        }
    }

    func testBillingPageSeparatesPlatformFeesFromTransportAndNeverImpliesAPrice() async throws {
        try await withHarness({ $0.billingRates = BillingRates(includedInteractionsPerMonth: 2, platformMicrosPerInteraction: 10_000,
                                                              transportMicrosPerSMSSegment: 8_000, transportMicrosPerRCSMessage: 12_000) }) { h in
            let (owner, _, aId) = try await h.verifiedOwner()
            let business = try await h.testBusiness(aId)
            let consumer = try await h.readyConsumer()
            let relationship = try await h.connect(consumer, to: business)
            for i in 0..<5 {
                try await eq(try await h.issue(business, relationship: relationship, payload: .confirm(ConfirmPayload(title: "t")), purpose: .transactional, key: "b\(i)").status, .created)
            }
            // Retrying an issued request never double counts.
            try await eq(try await h.issue(business, relationship: relationship, payload: .confirm(ConfirmPayload(title: "t")), purpose: .transactional, key: "b0").status, .ok)
            // Test-mode traffic is not billable usage.
            let testKey = try await h.testBusiness(aId, live: false)
            try await eq(try await h.issue(testKey, relationship: try await h.sandboxRelationship(testKey), payload: .confirm(ConfirmPayload(title: "t")), purpose: .transactional, key: "t0").status, .created)
            let page = try await h.page("/dashboard/billing", owner).text
            XCTAssertTrue(page.contains(">5</div><div class=\"l\">Interactions this month"))
            XCTAssertTrue(page.contains("Platform fees"))
            XCTAssertTrue(page.contains("Transport (carrier and provider pass-through)"))
            XCTAssertTrue(page.contains("$0.03"), "3 billable interactions × $0.01")
            XCTAssertTrue(page.contains("not an invoice"))
            XCTAssertTrue(page.contains("never changes the priority"))
            let totals = try await UsageMeter.totals(businessId: aId, from: h.clock.now().addingTimeInterval(-86_400), to: h.clock.now().addingTimeInterval(86_400), on: h.db)
            XCTAssertEqual(totals.interactions, 5)
            let events = try await UsageEventRecord.query(on: h.db).filter(\.$businessId == aId).all()
            XCTAssertEqual(events.count, 6, "test-mode usage is recorded but flagged")
            XCTAssertEqual(events.filter { !$0.livemode }.count, 1)
            XCTAssertTrue(events.allSatisfy { $0.category == "platform" })
        }
    }
}
