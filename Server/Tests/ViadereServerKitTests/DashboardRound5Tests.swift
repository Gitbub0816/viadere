import Fluent
import Foundation
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Round-4 re-review: the unverified-sign-up purge race, the sign-up wipe DoS and the per-address verification guess cap.
final class DashboardRound5Tests: XCTestCase {
    private func resend(_ h: TestHarness, _ email: String) async throws -> HTTPResult {
        try await h.request(.POST, "/dashboard/verify/resend", headers: ["Origin": h.origin], body: formBody([("email", email)]),
                            contentType: "application/x-www-form-urlencoded")
    }

    /// Exploit (before): the purge took a snapshot of unverified users, deleted their passkeys and sessions, and only then checked the
    /// status, so an owner who entered the code in between became an active account with no passkey.
    func testPurgeNeverTouchesAnAccountThatWasVerifiedAfterTheSnapshot() async throws {
        try await withHarness { h in
            let (account, _) = try await h.dashSignupUnverified(email: "owner@acme.test")
            let snapshot = try await DashboardUserRecord.query(on: h.db).filter(\.$status == "unverified").all()
            XCTAssertEqual(snapshot.count, 1)
            // The owner verifies after the purge job read its list...
            try await eq(try await h.dashVerifyEmail("owner@acme.test").status, .ok)
            // ...and the purge then removes "its" accounts.
            try await EmailVerificationService.removeUnverified(snapshot, on: h.db)
            try await eq(try await DashboardUserRecord.find(account.userId, on: h.db)?.status, "active")
            try await eq(try await DashboardPasskeyRecord.query(on: h.db).filter(\.$userId == account.userId).count(), 1, "the passkey survived")
            let (session, _) = try await h.dashLogin(account)
            XCTAssertNotNil(session, "the verified owner can still sign in")
            // The same with the by-address variant.
            try await EmailVerificationService.removeUnverified(emailHash: snapshot[0].emailHash, on: h.db)
            try await eq(try await DashboardPasskeyRecord.query(on: h.db).filter(\.$userId == account.userId).count(), 1)
        }
    }

    func testRealUnverifiedAccountsAreStillPurgedWithTheirChildren() async throws {
        try await withHarness { h in
            let (account, _) = try await h.dashSignupUnverified(email: "owner@acme.test")
            h.clock.advance(by: 24 * 3600 + 1)
            try await h.runJobs()
            try await eq(try await DashboardUserRecord.find(account.userId, on: h.db) == nil, true)
            try await eq(try await DashboardPasskeyRecord.query(on: h.db).count(), 0)
            try await eq(try await DashboardEmailCodeRecord.query(on: h.db).count(), 0)
        }
    }

    /// Exploit (before): anyone could sign up with a victim's address and wipe the victim's in-progress sign-up (and its code), over and
    /// over, and the attempts used up the address's budget so the victim could not even ask for a new code.
    func testASignUpForAnAddressWithAFreshPendingSignUpDoesNotWipeItOrSpendItsBudget() async throws {
        try await withHarness { h in
            let (victim, _) = try await h.dashSignupUnverified(email: "victim@acme.test", org: "Victim Org", handle: nil)
            let code = try XCTUnwrap(h.emails.lastCode(to: "victim@acme.test"))
            let sent = h.emails.sent.count
            for _ in 0..<4 {
                let attack = try await h.dashSignupUnverified(email: "victim@acme.test", org: "Attacker Org", handle: nil)
                XCTAssertEqual(attack.result.status, .ok, "the same answer as any other sign-up")
            }
            try await eq(try await DashboardUserRecord.find(victim.userId, on: h.db)?.status, "unverified", "the victim's sign-up is still there")
            try await eq(try await DashboardUserRecord.query(on: h.db).count(), 1)
            try await eq(try await DashboardPasskeyRecord.query(on: h.db).filter(\.$userId == victim.userId).count(), 1)
            XCTAssertEqual(h.emails.sent.count, sent, "nothing was mailed")
            // The victim's own budget is untouched: all five resends work.
            for _ in 0..<5 { try await eq(try await resend(h, "victim@acme.test").status, .ok) }
            XCTAssertEqual(h.emails.sent.count, sent + 5)
            let fresh = try XCTUnwrap(h.emails.lastCode(to: "victim@acme.test"))
            XCTAssertNotEqual(fresh, code)
            // And the victim finishes the sign-up.
            try await eq(try await h.dashVerifyEmail("victim@acme.test", code: fresh).status, .ok)
            try await eq(try await DashboardUserRecord.find(victim.userId, on: h.db)?.status, "active")
        }
    }

    func testAStaleUnverifiedSignUpIsStillReplacedAfterFifteenMinutes() async throws {
        try await withHarness { h in
            let (first, _) = try await h.dashSignupUnverified(email: "someone@acme.test", org: "First Org", handle: nil)
            h.clock.advance(by: 16 * 60)
            let (second, _) = try await h.dashSignupUnverified(email: "someone@acme.test", org: "Second Org", handle: nil)
            try await eq(try await DashboardUserRecord.find(first.userId, on: h.db) == nil, true, "an address is never held by someone who has not proven it")
            try await eq(try await DashboardUserRecord.find(second.userId, on: h.db)?.status, "unverified")
            XCTAssertNotNil(h.emails.lastCode(to: "someone@acme.test"))
        }
    }

    /// Exploit (before): every new code came with five fresh guesses, so one address could be guessed at indefinitely (5 per code, a
    /// code per resend).
    func testWrongGuessesPerAddressAreCappedPerDayAndANewCodeDoesNotResetThem() async throws {
        try await withHarness { h in
            let (account, _) = try await h.dashSignupUnverified(email: "owner@acme.test")
            var wrongFor: String { "000000" }
            for round in 0..<2 {
                let code = try XCTUnwrap(h.emails.lastCode(to: "owner@acme.test"))
                let wrong = code == wrongFor ? "111111" : wrongFor
                for _ in 0..<5 { try await eq(try await h.dashVerifyEmail("owner@acme.test", code: wrong).status, .unprocessableEntity) }
                h.clock.advance(by: 3600)
                try await eq(try await resend(h, "owner@acme.test").status, .ok, "round \(round)")
            }
            // Ten wrong guesses are spent: the right code of the newest email is refused as well.
            let latest = try XCTUnwrap(h.emails.lastCode(to: "owner@acme.test"))
            let refused = try await h.dashVerifyEmail("owner@acme.test", code: latest)
            XCTAssertNotEqual(refused.status, .ok, refused.text)
            try await eq(try await DashboardUserRecord.find(account.userId, on: h.db)?.status, "unverified")
            // After the window the address can be verified again.
            h.clock.advance(by: 24 * 3600)
            try await eq(try await resend(h, "owner@acme.test").status, .ok)
            let fresh = try XCTUnwrap(h.emails.lastCode(to: "owner@acme.test"))
            try await eq(try await h.dashVerifyEmail("owner@acme.test", code: fresh).status, .ok)
        }
    }

    func testASuccessfulVerificationDoesNotCountAgainstTheDailyCap() async throws {
        try await withHarness { h in
            _ = try await h.dashSignupUnverified(email: "owner@acme.test")
            try await eq(try await h.dashVerifyEmail("owner@acme.test", code: "000000").status, .unprocessableEntity)
            try await eq(try await h.dashVerifyEmail("owner@acme.test").status, .ok)
            // One wrong guess cost a token; the right code was given its token back: nine are left.
            let hash = h.ctx.hasher.hmacHex("dashboard-email", "owner@acme.test")
            let nine = await h.ctx.limiter.allow("dashboard-verify-failures", key: hash, rule: EmailVerificationService.dailyFailureRule, cost: 9)
            XCTAssertTrue(nine)
        }
    }
}
