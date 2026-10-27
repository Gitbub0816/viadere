import Fluent
import Foundation
import ViadereCore
import XCTest
@testable import ViadereServerKit

final class DashboardAuthTests: XCTestCase {
    // MARK: Cookies and sessions

    func testSignupSetsAHardenedHostCookieAndCreatesAPendingOrganizationWithoutHandleOrCode() async throws {
        try await withHarness { h in
            let (session, account, result) = try await h.dashSignup()
            let cookie = try XCTUnwrap(h.sessionCookie(result))
            XCTAssertEqual(cookie.name, "__Host-vd_session")
            XCTAssertTrue(cookie.has("Secure"))
            XCTAssertTrue(cookie.has("HttpOnly"))
            XCTAssertEqual(cookie.value(of: "SameSite")?.lowercased(), "strict")
            XCTAssertEqual(cookie.value(of: "Path"), "/")
            XCTAssertNil(cookie.value(of: "Domain"), "__Host- cookies must not carry a Domain")
            XCTAssertNotNil(cookie.value(of: "Max-Age"))
            XCTAssertTrue(session.token.hasPrefix("vds_"))
            // Only the hash of the cookie value is stored.
            let stored = try await DashboardSessionRecord.query(on: h.db).all()
            XCTAssertEqual(stored.count, 1)
            XCTAssertEqual(stored[0].tokenHash, SecureToken.hash(session.token))
            XCTAssertNotEqual(stored[0].tokenHash, session.token)
            // The organization is pending: no handle, no code, no directory presence.
            let business = try await XCTUnwrapAsync(await BusinessRecord.find(account.businessId!, on: h.db))
            XCTAssertEqual(business.status, .pending)
            try await eq(try await BusinessHandleRecord.query(on: h.db).filter(\.$businessId == business.id!).count(), 0)
            try await eq(try await BusinessCodeRecord.query(on: h.db).filter(\.$businessId == business.id!).count(), 0)
            let search = try await h.request(.GET, "/v1/directory/search?q=acme")
            XCTAssertEqual(try search.json(Page<BusinessSummary>.self).items.count, 0)
            let app = try await XCTUnwrapAsync(await BusinessApplicationRecord.query(on: h.db).filter(\.$businessId == business.id!).first())
            XCTAssertEqual(app.state, "pending")
            XCTAssertEqual(app.requestedHandle, "acmeroasters")
        }
    }

    func testPagesRequireASessionAndBadCookiesAreRejectedAndCleared() async throws {
        try await withHarness { h in
            for path in ["/dashboard", "/dashboard/api-keys", "/dashboard/team", "/dashboard/audit", "/dashboard/billing"] {
                let r = try await h.page(path, nil)
                XCTAssertEqual(r.status, .seeOther, path)
                XCTAssertEqual(r.headers.first(name: .location), "/dashboard/login")
            }
            let forged = DashSession(token: "vds_" + SecureToken.generate(), realm: .business)
            let r = try await h.page("/dashboard", forged)
            XCTAssertEqual(r.status, .seeOther)
            let cleared = try XCTUnwrap(h.sessionCookie(r))
            XCTAssertEqual(cleared.value, "")
            // Unauthenticated JSON endpoints answer 401, not a redirect.
            let json = try await h.jsonPost("/dashboard/auth/reauth/begin", EmptyBody())
            XCTAssertEqual(json.status, .unauthorized)
        }
    }

    func testLoginRotatesTheSessionAndRevokesThePresentedOne() async throws {
        try await withHarness { h in
            let (first, account, _) = try await h.dashSignup()
            let (second, result) = try await h.dashLogin(account, previous: first)
            XCTAssertEqual(result.status, .ok, result.text)
            let rotated = try XCTUnwrap(second)
            XCTAssertNotEqual(rotated.token, first.token)
            // The old cookie is dead the moment a new login presented it.
            try await eq(try await h.page("/dashboard", first).status, .seeOther)
            try await eq(try await h.page("/dashboard", rotated).status, .ok)
        }
    }

    func testIdleAndAbsoluteTimeouts() async throws {
        try await withHarness { h in
            let (session, account, _) = try await h.dashSignup()
            try await eq(try await h.page("/dashboard", session).status, .ok)
            // Activity within the idle window keeps the session alive...
            h.clock.advance(by: 20 * 60)
            try await eq(try await h.page("/dashboard", session).status, .ok)
            h.clock.advance(by: 20 * 60)
            try await eq(try await h.page("/dashboard", session).status, .ok)
            // ...but 31 idle minutes end it.
            h.clock.advance(by: 31 * 60)
            try await eq(try await h.page("/dashboard", session).status, .seeOther)
            // The absolute timeout applies however active the session is.
            let (fresh, _) = try await h.dashLogin(account)
            let live = try XCTUnwrap(fresh)
            var elapsed = 0.0
            while elapsed + 25 * 60 < 12 * 3600 - 60 {
                h.clock.advance(by: 25 * 60)
                elapsed += 25 * 60
                try await eq(try await h.page("/dashboard", live).status, .ok, "at \(elapsed)")
            }
            h.clock.advance(by: 25 * 60)
            try await eq(try await h.page("/dashboard", live).status, .seeOther, "absolute timeout")
        }
    }

    func testLogoutRevokesTheSessionServerSide() async throws {
        try await withHarness { h in
            let (session, _, _) = try await h.dashSignup()
            let out = try await h.formPost("/dashboard/logout", session)
            XCTAssertEqual(out.status, .seeOther)
            try await eq(try await h.page("/dashboard", session).status, .seeOther)
            let record = try await DashboardSessionRecord.query(on: h.db).first()!
            XCTAssertNotNil(record.revokedAt)
        }
    }

    func testBusinessCookieDoesNotWorkInTheOperatorRealmAndViceVersa() async throws {
        try await withHarness { h in
            let (business, _, _) = try await h.dashSignup()
            let (op, _) = try await h.makeOperator()
            // A business token presented as an operator cookie, and an operator token as a business cookie.
            try await eq(try await h.page("/operator", DashSession(token: business.token, realm: .operator)).status, .seeOther)
            try await eq(try await h.page("/dashboard", DashSession(token: op.token, realm: .business)).status, .seeOther)
            try await eq(try await h.page("/operator", op).status, .ok)
        }
    }

    func testConsumerPasskeysAndBusinessPasskeysAreSeparateWorlds() async throws {
        try await withHarness { h in
            // A consumer registers a passkey; the same credential cannot sign in to the dashboard.
            let consumer = try await h.registerConsumer()
            let credential = try await PasskeyCredentialRecord.query(on: h.db).filter(\.$consumerId == consumer.id.uuid).first()!
            let account = DashAccount(email: "x@example.com", credentialId: credential.credentialId, publicKey: "", userId: UUID(), businessId: nil)
            let (session, result) = try await h.dashLogin(account)
            XCTAssertNil(session)
            XCTAssertEqual(result.status, .unauthorized)
            // And a dashboard passkey cannot log in as a consumer.
            let (_, owner, _) = try await h.dashSignup()
            let begin = try await h.post(APIRoutes.loginBegin.template, PasskeyLoginBeginRequest())
            let options = try begin.json(PasskeyAssertionOptions.self)
            let finish = try await h.post(APIRoutes.loginFinish.template, PasskeyLoginFinishRequest(
                ceremonyId: options.ceremonyId, credential: h.assertion(for: options, credentialId: owner.credentialId)))
            XCTAssertEqual(finish.status, .unauthorized)
        }
    }

    func testOperatorCredentialCannotSignInToTheBusinessDashboard() async throws {
        try await withHarness { h in
            let (_, operatorAccount) = try await h.makeOperator()
            let (session, result) = try await h.dashLogin(operatorAccount, realm: .business)
            XCTAssertNil(session)
            XCTAssertEqual(result.status, .unauthorized)
        }
    }

    func testCeremoniesAreSingleUseAndFailuresAreGeneric() async throws {
        try await withHarness { h in
            let (_, account, _) = try await h.dashSignup()
            let begin = try await h.jsonPost("/dashboard/auth/login/begin", EmptyBody())
            let options = try begin.json(PasskeyAssertionOptions.self)
            let good = PasskeyLoginFinishRequest(ceremonyId: options.ceremonyId, credential: h.assertion(for: options, credentialId: account.credentialId))
            try await eq(try await h.jsonPost("/dashboard/auth/login/finish", good).status, .ok)
            // Replaying the same ceremony fails.
            try await eq(try await h.jsonPost("/dashboard/auth/login/finish", good).status, .unauthorized)
            // A bad signature and an unknown credential look identical.
            let b2 = try await h.jsonPost("/dashboard/auth/login/begin", EmptyBody()).json(PasskeyAssertionOptions.self)
            let bad = try await h.jsonPost("/dashboard/auth/login/finish", PasskeyLoginFinishRequest(
                ceremonyId: b2.ceremonyId, credential: h.assertion(for: b2, credentialId: account.credentialId, signature: "forged")))
            let b3 = try await h.jsonPost("/dashboard/auth/login/begin", EmptyBody()).json(PasskeyAssertionOptions.self)
            let unknown = try await h.jsonPost("/dashboard/auth/login/finish", PasskeyLoginFinishRequest(
                ceremonyId: b3.ceremonyId, credential: h.assertion(for: b3, credentialId: "nope")))
            XCTAssertEqual(bad.status, .unauthorized)
            XCTAssertEqual(unknown.status, .unauthorized)
            XCTAssertEqual(try bad.json(APIErrorResponse.self).error.message, try unknown.json(APIErrorResponse.self).error.message)
            // Expired ceremony.
            let b4 = try await h.jsonPost("/dashboard/auth/login/begin", EmptyBody()).json(PasskeyAssertionOptions.self)
            h.clock.advance(by: 6 * 60)
            try await eq(try await h.jsonPost("/dashboard/auth/login/finish", PasskeyLoginFinishRequest(
                ceremonyId: b4.ceremonyId, credential: h.assertion(for: b4, credentialId: account.credentialId))).status, .unauthorized)
        }
    }

    func testSignupValidationDuplicateEmailsAndHandleRules() async throws {
        try await withHarness { h in
            for bad in [SignupBeginBody(email: "nope", displayName: "A", organizationName: "Org Name"),
                        SignupBeginBody(email: "a@b.co", displayName: "", organizationName: "Org Name"),
                        SignupBeginBody(email: "a@b.co", displayName: "A", organizationName: "x"),
                        SignupBeginBody(email: "a@b.co", displayName: "A", organizationName: "Org Name", website: "http://insecure.example.com"),
                        SignupBeginBody(email: "a@b.co", displayName: "A", organizationName: "Org Name", requestedHandle: "viaderesupport"),
                        SignupBeginBody(email: "a@b.co", displayName: "A", organizationName: "Org Name", requestedHandle: "x")] {
                try await eq(try await h.jsonPost("/dashboard/auth/signup/begin", bad).status, .unprocessableEntity)
            }
            try await h.dashSignup(email: "dup@example.com")
            let again = try await h.jsonPost("/dashboard/auth/signup/begin", SignupBeginBody(email: "DUP@example.com", displayName: "B", organizationName: "Other Org"))
            // Not an oracle for which addresses exist: the same answer as for a free address (the duplicate fails later, generically).
            XCTAssertEqual(again.status, .ok)
        }
    }

    // MARK: CSRF

    func testStateChangingRequestsNeedAMatchingCSRFTokenAndOrigin() async throws {
        try await withHarness { h in
            let (session, _, _) = try await h.dashSignup()
            // The token is embedded in forms and matches the session.
            let team = try await h.page("/dashboard/team", session)
            XCTAssertEqual(h.pageCSRF(team.text), h.csrf(session))
            XCTAssertNotEqual(h.csrf(session), h.csrf(DashSession(token: "vds_other", realm: .business)))
            // Missing, wrong, and another session's token are all rejected.
            let missing = try await h.formPost("/dashboard/team/invite", session, [("email", "a@example.com"), ("role", "analyst")], includeCSRF: false)
            XCTAssertEqual(missing.status, .forbidden)
            let wrong = try await h.formPost("/dashboard/team/invite", session, [("email", "a@example.com"), ("role", "analyst")], csrf: "AAAA")
            XCTAssertEqual(wrong.status, .forbidden)
            let (other, _, _) = try await h.dashSignup(email: "other@example.com", org: "Other Org", handle: nil)
            let foreign = try await h.formPost("/dashboard/team/invite", session, [("email", "a@example.com"), ("role", "analyst")], csrf: h.csrf(other))
            XCTAssertEqual(foreign.status, .forbidden)
            // A cross-site Origin is rejected even with a valid token.
            let crossSite = try await h.formPost("/dashboard/team/invite", session, [("email", "a@example.com"), ("role", "analyst")], origin: "https://evil.example")
            XCTAssertEqual(crossSite.status, .forbidden)
            // Nothing was created by any rejected request; the legitimate one works.
            try await eq(try await OrgInviteRecord.query(on: h.db).count(), 0)
            let ok = try await h.formPost("/dashboard/team/invite", session, [("email", "a@example.com"), ("role", "analyst")])
            XCTAssertEqual(ok.status, .ok, ok.text)
            // Logout is state-changing too.
            let logout = try await h.formPost("/dashboard/logout", session, includeCSRF: false)
            XCTAssertEqual(logout.status, .forbidden)
            try await eq(try await h.page("/dashboard", session).status, .ok)
        }
    }

    func testJSONReauthEndpointsRequireTheCSRFHeader() async throws {
        try await withHarness { h in
            let (session, _, _) = try await h.dashSignup()
            let noHeader = try await h.jsonPost("/dashboard/auth/reauth/begin", EmptyBody(), session: session, csrf: false)
            XCTAssertEqual(noHeader.status, .forbidden)
            let ok = try await h.jsonPost("/dashboard/auth/reauth/begin", EmptyBody(), session: session, csrf: true)
            XCTAssertEqual(ok.status, .ok)
        }
    }

    // MARK: Re-authentication

    func testSensitiveActionsNeedAFreshPasskeyAssertion() async throws {
        try await withHarness { h in
            let (session, account, _) = try await h.verifiedOwner()
            let form: [(String, String)] = [("name", "Server"), ("mode", "test"), ("scopes[]", "interactions:write")]
            // The login itself counts as a fresh assertion.
            let first = try await h.formPost("/dashboard/api-keys", session, form)
            XCTAssertEqual(first.status, .ok, first.text)
            // After the window lapses the same action asks for the passkey again and creates nothing.
            h.clock.advance(by: 6 * 60)
            let before = try await BusinessAPIKeyRecord.query(on: h.db).count()
            let denied = try await h.formPost("/dashboard/api-keys", session, form)
            XCTAssertEqual(denied.status, .forbidden)
            XCTAssertTrue(denied.text.contains("Confirm with passkey"))
            XCTAssertTrue(denied.text.contains("data-passkey=\"reauth\""))
            try await eq(try await BusinessAPIKeyRecord.query(on: h.db).count(), before)
            // A passkey that belongs to someone else does not satisfy it.
            let (_, intruder, _) = try await h.dashSignup(email: "intruder@example.com", org: "Intruder Org", handle: nil)
            let wrong = try await h.dashReauth(session, account, credentialId: intruder.credentialId)
            XCTAssertEqual(wrong.status, .unauthorized)
            try await eq(try await h.formPost("/dashboard/api-keys", session, form).status, .forbidden)
            // The owner's own passkey does.
            let good = try await h.dashReauth(session, account)
            XCTAssertEqual(good.status, .ok, good.text)
            try await eq(try await h.formPost("/dashboard/api-keys", session, form).status, .ok)
            try await eq(try await BusinessAPIKeyRecord.query(on: h.db).count(), before + 1)
            // Rotating a webhook secret and adding an owner are gated the same way.
            h.clock.advance(by: 6 * 60)
            let hook = try await h.formPost("/dashboard/webhooks", session, [("url", "https://hooks.example.com/a"), ("events[]", "interaction.decided")])
            XCTAssertEqual(hook.status, .forbidden)
            XCTAssertTrue(hook.text.contains("Confirm with passkey"))
            let ownerInvite = try await h.formPost("/dashboard/team/invite", session, [("email", "co@example.com"), ("role", "owner")])
            XCTAssertEqual(ownerInvite.status, .forbidden)
            XCTAssertTrue(ownerInvite.text.contains("Confirm with passkey"))
            // A non-owner invite does not need it.
            let analyst = try await h.formPost("/dashboard/team/invite", session, [("email", "an@example.com"), ("role", "analyst")])
            XCTAssertEqual(analyst.status, .ok)
            try await h.dashReauth(session, account)
            let rotate = try await h.formPost("/dashboard/webhooks", session, [("url", "https://hooks.example.com/a"), ("events[]", "interaction.decided")])
            XCTAssertEqual(rotate.status, .ok, rotate.text)
            let subscription = try await WebhookSubscriptionRecord.query(on: h.db).first()!
            h.clock.advance(by: 6 * 60)
            let rotateDenied = try await h.formPost("/dashboard/webhooks/\(subscription.id!.uuidString.lowercased())/rotate", session)
            XCTAssertEqual(rotateDenied.status, .forbidden)
            XCTAssertTrue(rotateDenied.text.contains("Confirm with passkey"))
            try await h.dashReauth(session, account)
            let rotated = try await h.formPost("/dashboard/webhooks/\(subscription.id!.uuidString.lowercased())/rotate", session)
            XCTAssertEqual(rotated.status, .ok, rotated.text)
            XCTAssertTrue(rotated.text.contains("whsec_"))
        }
    }

    // MARK: Page security headers

    func testPagesCarryAStrictCSPWithHashesAndNoThirdPartyAssets() async throws {
        try await withHarness { h in
            let (session, _, _) = try await h.dashSignup()
            let overview = try await h.page("/dashboard", session)
            let csp = try XCTUnwrap(overview.headers.first(name: "Content-Security-Policy"))
            XCTAssertTrue(csp.contains("default-src 'none'"))
            XCTAssertTrue(csp.contains("style-src 'sha256-\(DashboardUI.sha256Base64(DashboardUI.css))'"))
            XCTAssertFalse(csp.contains("script-src"), "signed-in pages without passkey prompts load no script")
            XCTAssertFalse(csp.contains("unsafe-inline"))
            XCTAssertFalse(csp.contains("unsafe-eval"))
            XCTAssertTrue(csp.contains("frame-ancestors 'none'"))
            XCTAssertTrue(csp.contains("form-action 'self'"))
            XCTAssertFalse(overview.text.contains("<script"))
            XCTAssertFalse(overview.text.contains(" style=\""), "inline style attributes would violate the CSP")
            XCTAssertFalse(overview.text.contains(" onclick="))
            XCTAssertNil(overview.text.range(of: "https?://[^\"' <]*", options: .regularExpression).flatMap { r -> String? in
                let url = String(overview.text[r])
                return url.contains("viadere.com") || url.contains("www.w3.org") ? nil : url
            }, "no third-party URL may appear in a dashboard page")
            XCTAssertEqual(overview.headers.first(name: .cacheControl), "no-store")
            // The sign-in page carries exactly one script, pinned by hash.
            let login = try await h.page("/dashboard/login", nil)
            let loginCSP = try XCTUnwrap(login.headers.first(name: "Content-Security-Policy"))
            XCTAssertTrue(loginCSP.contains("script-src 'sha256-\(DashboardUI.sha256Base64(DashboardUI.script))'"))
            XCTAssertEqual(login.text.components(separatedBy: "<script").count - 1, 1)
            XCTAssertFalse(login.text.contains("src=\""), "no external script or image")
            XCTAssertTrue(login.text.contains("data-passkey=\"login\""))
        }
    }

    func testDashboardScriptHasNoThirdPartyCallsAndOnlyNavigatesToLocalPaths() {
        let js = DashboardUI.script
        XCTAssertFalse(js.contains("http://") || js.contains("https://"))
        XCTAssertFalse(js.contains("eval(") || js.contains("innerHTML") || js.contains("document.write"))
        XCTAssertTrue(js.contains("charAt(0)==='/'&&p.charAt(1)!=='/'"), "redirects are restricted to same-origin paths")
        XCTAssertLessThan(js.utf8.count, 4096)
    }

    func testRateLimitingOnCeremonies() async throws {
        try await withHarness { h in
            var statuses: [HTTPStatus] = []
            for _ in 0..<40 { statuses.append(try await h.jsonPost("/dashboard/auth/login/begin", EmptyBody()).status) }
            XCTAssertTrue(statuses.contains(.tooManyRequests))
        }
    }
}

import Vapor
