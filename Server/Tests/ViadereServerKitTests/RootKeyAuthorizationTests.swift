@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Condition 4 of the Phase 2 gate: a business root key is registered or replaced only with a dashboard passkey step-up and a verified domain,
/// never with a `keydirectory:manage` API key alone (a stolen key could otherwise squat the root for good).
final class RootKeyAuthorizationTests: XCTestCase {
    private func rootEntry(_ business: TestBusiness, _ key: SoftwareP256SigningKey, at h: TestHarness) async throws -> KeyLogEntry {
        try await KeyLogEntry.sign(.root(RootRegistration(businessId: business.id, publicKey: key.publicKey, createdAt: h.clock.now())), rootKey: key)
    }

    func testAStolenApiKeyCannotRegisterARootAndSquatItsOwnerOut() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            try await h.ensureVerifiedDomain(b.id.uuid)
            let attacker = SoftwareP256SigningKey()
            let squat = try await h.publishEntry(b, try await rootEntry(b, attacker, at: h), authorized: false)
            aeq(squat.status, .forbidden, squat.text)
            atrue(squat.text.contains("dashboard_step_up_required"))
            aeq(try await KDLogEntryRecord.query(on: h.db).count(), 0, "nothing reached the append-only log")
            atrue(try await h.approvalAudit("keydirectory.root_refused").count == 1)
            // The owner, who authorizes in the dashboard, can still register: the attacker did not squat the business.
            let legitimate = SoftwareP256SigningKey()
            aeq(try await h.publishEntry(b, try await rootEntry(b, legitimate, at: h)).status, .created)
        }
    }

    func testAnAuthorizationIsForOneKeyOneUseAndFifteenMinutes() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let intended = SoftwareP256SigningKey()
            let other = SoftwareP256SigningKey()
            let kid = KeyIdentifier.make(try intended.publicKey.signingKey())
            try await h.authorizeRoot(b, kid: kid)
            // Authorizing one key id does not authorize another.
            aeq(try await h.publishEntry(b, try await rootEntry(b, other, at: h), authorized: false).status, .forbidden)
            // It expires.
            h.clock.advance(by: 901)
            aeq(try await h.publishEntry(b, try await rootEntry(b, intended, at: h), authorized: false).status, .forbidden)
            // A fresh one works once...
            try await h.authorizeRoot(b, kid: kid)
            let entry = try await rootEntry(b, intended, at: h)
            aeq(try await h.publishEntry(b, entry, authorized: false).status, .created)
            aeq(try await KeyRootAuthorizationRecord.query(on: h.db).filter(\.$consumedAt != nil).count(), 1)
            // ...and a rejected entry does not burn it (the consumption rolls back with the entry).
            let next = SoftwareP256SigningKey()
            let nextKid = KeyIdentifier.make(try next.publicKey.signingKey())
            try await h.authorizeRoot(b, kid: nextKid)
            let badSuccession = try await KeyLogEntry.sign(.succession(RootSuccession(businessId: b.id, oldRootKid: kid, newPublicKey: next.publicKey, createdAt: h.clock.now())), rootKey: other, newRootKey: next)
            aeq(try await h.publishEntry(b, badSuccession, authorized: false).status, .unprocessableEntity)
            aeq(try await KeyRootAuthorizationRecord.query(on: h.db).filter(\.$rootKid == nextKid).filter(\.$consumedAt == nil).count(), 1, "still usable")
        }
    }

    func testChangingTheRootNeedsTheStepUpToo() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b)
            let next = SoftwareP256SigningKey()
            let succession = try await KeyLogEntry.sign(.succession(RootSuccession(businessId: b.id, oldRootKid: keys.rootKid, newPublicKey: next.publicKey, createdAt: h.clock.now())),
                                                       rootKey: keys.root, newRootKey: next)
            // A thief holding the API key and (somehow) the old root key: still refused without a person in the dashboard.
            let refused = try await h.publishEntry(b, succession, authorized: false)
            aeq(refused.status, .forbidden, refused.text)
            aeq(try await h.publishEntry(b, succession).status, .created)
        }
    }

    func testARootNeedsAVerifiedDomain() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let key = SoftwareP256SigningKey()
            let kid = KeyIdentifier.make(try key.publicKey.signingKey())
            // The dashboard step-up itself refuses without a verified domain...
            do { _ = try await RootAuthorization(db: h.db, ctx: h.ctx).authorize(businessId: b.id.uuid, user: UUID(), rootKid: kid); XCTFail("no domain") } catch {
                aeq((error as? APIError)?.status, .forbidden)
            }
            // ...and so does the publish, even with an authorization row (defense in depth).
            let row = KeyRootAuthorizationRecord()
            row.id = UUID(); row.businessId = b.id.uuid; row.kind = "register"; row.rootKid = kid; row.authorizedBy = UUID().uuidString.lowercased()
            row.createdAt = h.clock.now(); row.expiresAt = h.clock.now().addingTimeInterval(900)
            try await row.create(on: h.db)
            let result = try await h.publishEntry(b, try await rootEntry(b, key, at: h), authorized: false)
            aeq(result.status, .forbidden, result.text)
            atrue(result.text.contains("verified_domain_required"))
        }
    }

    func testTheDashboardAuthorizationNeedsAPasskeyStepUpTheSecurityRoleAndAVerifiedDomain() async throws {
        try await withHarness { h in
            let (owner, account, businessId) = try await h.verifiedOwner()
            let key = SoftwareP256SigningKey()
            let kid = KeyIdentifier.make(try key.publicKey.signingKey())
            let path = "/dashboard/approve/root-authorizations"
            // No verified domain yet.
            try await h.dashReauth(owner, account)
            _ = try await h.formPost(path, owner, [("rootKid", kid)])
            aeq(try await KeyRootAuthorizationRecord.query(on: h.db).count(), 0, "no verified domain, no authorization")
            try await h.verifyDomain(owner, businessId: businessId)
            // A stale session (no fresh passkey assertion) cannot authorize.
            h.clock.advance(by: 400)
            _ = try await h.formPost(path, owner, [("rootKid", kid)])
            aeq(try await KeyRootAuthorizationRecord.query(on: h.db).count(), 0, "a stale session needs a fresh passkey assertion first")
            // With the step-up it works, once recorded, audited, and bound to the key id.
            try await h.dashReauth(owner, account)
            let ok = try await h.formPost(path, owner, [("rootKid", kid)])
            aeq(ok.status, .seeOther, ok.text)
            let row = try unwrap(try await KeyRootAuthorizationRecord.query(on: h.db).first())
            aeq(row.rootKid, kid)
            aeq(row.kind, "register")
            aeq(row.businessId, businessId)
            aeq(row.expiresAt.timeIntervalSince(row.createdAt), 900)
            atrue(try await h.auditActions(businessId).contains("keydirectory.root_authorized"))
            // A malformed key id is refused.
            try await h.dashReauth(owner, account)
            _ = try await h.formPost(path, owner, [("rootKid", "nope")])
            aeq(try await KeyRootAuthorizationRecord.query(on: h.db).count(), 1, "a malformed key id authorizes nothing")
        }
    }

    func testOnlyASecurityAdminOrOwnerMayAuthorizeARoot() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            try await h.verifyDomain(owner, businessId: businessId)
            let (developer, devAccount) = try await h.addMember(owner: owner, role: .developer, email: "dev@example.com")
            try await h.dashReauth(developer, devAccount)
            let kid = KeyIdentifier.make(try SoftwareP256SigningKey().publicKey.signingKey())
            let result = try await h.formPost("/dashboard/approve/root-authorizations", developer, [("rootKid", kid)])
            aeq(result.status, .forbidden, result.text)
            aeq(try await KeyRootAuthorizationRecord.query(on: h.db).count(), 0)
        }
    }
}
