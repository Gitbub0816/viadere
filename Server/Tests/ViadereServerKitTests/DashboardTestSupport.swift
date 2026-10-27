@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// A signed-up dashboard (or operator) user with a fake passkey.
struct DashAccount {
    var email: String
    var credentialId: String
    var publicKey: String
    var userId: UUID
    var businessId: UUID?
}

struct DashSession {
    var token: String
    var realm: DashboardRealm
}

struct CookieInfo {
    var name: String
    var value: String
    var attributes: [String]
    func has(_ attribute: String) -> Bool { attributes.contains { $0.lowercased() == attribute.lowercased() } }
    func value(of key: String) -> String? {
        attributes.first { $0.lowercased().hasPrefix(key.lowercased() + "=") }.map { String($0.dropFirst(key.count + 1)) }
    }
}

func formBody(_ pairs: [(String, String)]) -> Data {
    func enc(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")) ?? ""
    }
    return Data(pairs.map { "\(enc($0.0))=\(enc($0.1))" }.joined(separator: "&").utf8)
}

extension TestHarness {
    var origin: String { "https://viadere.com" }

    func csrf(_ session: DashSession) -> String { DashboardSessionStore.csrfToken(sessionToken: session.token, hasher: ctx.hasher) }

    func cookies(in result: HTTPResult) -> [CookieInfo] {
        result.headers[.setCookie].compactMap { line in
            let parts = line.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }
            guard let first = parts.first, let eq = first.firstIndex(of: "=") else { return nil }
            return CookieInfo(name: String(first[..<eq]), value: String(first[first.index(after: eq)...]), attributes: Array(parts.dropFirst()))
        }
    }

    func sessionCookie(_ result: HTTPResult, realm: DashboardRealm = .business) -> CookieInfo? {
        cookies(in: result).first { $0.name == realm.cookieName }
    }

    func cookieHeaders(_ session: DashSession?, extra: [String: String] = [:]) -> [String: String] {
        var headers = extra
        if let session { headers["Cookie"] = "\(session.realm.cookieName)=\(session.token)" }
        return headers
    }

    func page(_ path: String, _ session: DashSession?) async throws -> HTTPResult {
        try await request(.GET, path, headers: cookieHeaders(session))
    }

    /// A browser-like form POST: cookie, matching Origin, CSRF token unless overridden.
    func formPost(_ path: String, _ session: DashSession?, _ pairs: [(String, String)] = [], csrf override: String? = nil,
                  includeCSRF: Bool = true, origin: String? = nil) async throws -> HTTPResult {
        var fields = pairs
        if includeCSRF, let session { fields.append(("_csrf", override ?? csrf(session))) }
        var headers = cookieHeaders(session)
        headers["Origin"] = origin ?? self.origin
        return try await request(.POST, path, headers: headers, body: formBody(fields), contentType: "application/x-www-form-urlencoded")
    }

    func jsonPost<T: Encodable>(_ path: String, _ value: T, session: DashSession? = nil, csrf include: Bool = false) async throws -> HTTPResult {
        var headers = cookieHeaders(session)
        if include, let session { headers["X-CSRF-Token"] = csrf(session) }
        return try await request(.POST, path, headers: headers, body: try ViadereJSON.encode(value))
    }

    // MARK: Sign up / sign in

    func registrationCredential(for options: PasskeyRegistrationOptions, credentialId: String, publicKey: String) -> PasskeyRegistrationCredential {
        PasskeyRegistrationCredential(id: credentialId, rawId: credentialId, attestationObject: publicKey, clientDataJSON: options.challenge)
    }

    func assertion(for options: PasskeyAssertionOptions, credentialId: String, signature: String = "valid") -> PasskeyAssertionCredential {
        PasskeyAssertionCredential(id: credentialId, rawId: credentialId, authenticatorData: "AAAA", clientDataJSON: options.challenge,
                                   signature: signature, userHandle: nil)
    }

    /// Sign-up through the passkey ceremony only: the account exists but is **unverified** (no session, no organization).
    @discardableResult
    func dashSignupUnverified(email: String = "owner@example.com", name: String = "Olive Owner", org: String = "Acme Roasters", handle: String? = "acmeroasters",
                              category: String = "retail") async throws -> (account: DashAccount, result: HTTPResult) {
        let body = SignupBeginBody(email: email, displayName: name, organizationName: org, category: category, legalName: "Acme Roasters Ltd",
                                   website: "https://acme.example.com", requestedHandle: handle, description: "Sign-in approvals")
        let begin = try await jsonPost("/dashboard/auth/signup/begin", body)
        XCTAssertEqual(begin.status, .ok, begin.text)
        let options = try begin.json(PasskeyRegistrationOptions.self)
        let credentialId = SecureToken.generate(byteCount: 16)
        let publicKey = SecureToken.generate(byteCount: 32)
        let finish = try await jsonPost("/dashboard/auth/signup/finish",
            PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: registrationCredential(for: options, credentialId: credentialId, publicKey: publicKey)))
        XCTAssertEqual(finish.status, .ok, finish.text)
        let user = try await DashboardUserRecord.query(on: db).filter(\.$emailHash == ctx.hasher.hmacHex("dashboard-email", email)).first()!
        return (DashAccount(email: email, credentialId: credentialId, publicKey: publicKey, userId: user.id!, businessId: nil), finish)
    }

    /// Enters the emailed code on the public verification page.
    @discardableResult
    func dashVerifyEmail(_ email: String, code: String? = nil) async throws -> HTTPResult {
        let code = code ?? emails.lastCode(to: email) ?? "000000"
        return try await request(.POST, "/dashboard/verify", headers: ["Origin": origin], body: formBody([("email", email), ("code", code)]),
                                 contentType: "application/x-www-form-urlencoded")
    }

    /// Sign-up, email verification and the first passkey sign-in: a verified owner of a *pending* organization with a live session.
    @discardableResult
    func dashSignup(email: String = "owner@example.com", name: String = "Olive Owner", org: String = "Acme Roasters", handle: String? = "acmeroasters",
                    category: String = "retail") async throws -> (session: DashSession, account: DashAccount, result: HTTPResult) {
        var (account, _) = try await dashSignupUnverified(email: email, name: name, org: org, handle: handle, category: category)
        let verified = try await dashVerifyEmail(email)
        XCTAssertEqual(verified.status, .ok, verified.text)
        let (session, login) = try await dashLogin(account)
        guard let session else {
            XCTFail("no session after verification: \(login.text)")
            throw XCTSkip("no session")
        }
        let membership = try await OrgMembershipRecord.query(on: db).filter(\.$userId == account.userId).first()
        account.businessId = membership?.businessId
        return (session, account, login)
    }

    func dashLogin(_ account: DashAccount, realm: DashboardRealm = .business, previous: DashSession? = nil) async throws -> (session: DashSession?, result: HTTPResult) {
        let prefix = realm == .business ? "/dashboard" : "/operator"
        let begin = try await jsonPost("\(prefix)/auth/login/begin", EmptyBody())
        XCTAssertEqual(begin.status, .ok, begin.text)
        let options = try begin.json(PasskeyAssertionOptions.self)
        var headers = cookieHeaders(previous)
        headers["Content-Type"] = "application/json"
        let finish = try await request(.POST, "\(prefix)/auth/login/finish", headers: headers,
            body: try ViadereJSON.encode(PasskeyLoginFinishRequest(ceremonyId: options.ceremonyId, credential: assertion(for: options, credentialId: account.credentialId))))
        guard finish.status == .ok, let cookie = sessionCookie(finish, realm: realm) else { return (nil, finish) }
        return (DashSession(token: cookie.value, realm: realm), finish)
    }

    /// Passkey re-authentication for a signed-in session.
    @discardableResult
    func dashReauth(_ session: DashSession, _ account: DashAccount, credentialId override: String? = nil) async throws -> HTTPResult {
        let prefix = session.realm == .business ? "/dashboard" : "/operator"
        let begin = try await jsonPost("\(prefix)/auth/reauth/begin", EmptyBody(), session: session, csrf: true)
        XCTAssertEqual(begin.status, .ok, begin.text)
        let options = try begin.json(PasskeyAssertionOptions.self)
        return try await jsonPost("\(prefix)/auth/reauth/finish",
            PasskeyLoginFinishRequest(ceremonyId: options.ceremonyId, credential: assertion(for: options, credentialId: override ?? account.credentialId)),
            session: session, csrf: true)
    }

    // MARK: Operators

    func makeOperator(email: String = "ops@viadere.test", name: String = "Ops Olive") async throws -> (session: DashSession, account: DashAccount) {
        let link = try await DashboardAuthService(db: db, ctx: ctx).createOperator(email: email, displayName: name)
        let token = String(link.split(separator: "/").last!)
        let begin = try await jsonPost("/operator/auth/enroll/begin", EnrollBeginBody(token: token))
        XCTAssertEqual(begin.status, .ok, begin.text)
        let options = try begin.json(PasskeyRegistrationOptions.self)
        let credentialId = SecureToken.generate(byteCount: 16)
        let publicKey = SecureToken.generate(byteCount: 32)
        let finish = try await jsonPost("/operator/auth/enroll/finish",
            PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: registrationCredential(for: options, credentialId: credentialId, publicKey: publicKey)))
        XCTAssertEqual(finish.status, .ok, finish.text)
        let cookie = sessionCookie(finish, realm: .operator)!
        let user = try await DashboardUserRecord.query(on: db).filter(\.$kind == "operator").first()!
        return (DashSession(token: cookie.value, realm: .operator),
                DashAccount(email: email, credentialId: credentialId, publicKey: publicKey, userId: user.id!, businessId: nil))
    }

    /// Verifies an organization the way an operator does (handle and code are issued here).
    @discardableResult
    func verifyOrganization(_ businessId: UUID) async throws -> BusinessRecord {
        try await BusinessOnboarding(db: db, ctx: ctx).approve(businessId: businessId, operatorId: UUID(), handleOverride: nil, note: nil)
    }

    /// Reads a hidden CSRF input out of an HTML page.
    func pageCSRF(_ html: String) -> String? {
        guard let r = html.range(of: "name=\"_csrf\" value=\"") else { return nil }
        return String(html[r.upperBound...].prefix { $0 != "\"" })
    }

    /// Creates a verified organization with a signed-in owner (fresh re-authentication).
    func verifiedOwner(email: String = "owner@example.com", org: String = "Acme Roasters", handle: String? = "acmeroasters") async throws -> (session: DashSession, account: DashAccount, businessId: UUID) {
        let (session, account, _) = try await dashSignup(email: email, org: org, handle: handle)
        let businessId = account.businessId!
        try await verifyOrganization(businessId)
        return (session, account, businessId)
    }

    /// The invitee asks for the emailed code on the invitation page; returns it.
    func inviteCode(token: String, email: String) async throws -> String {
        let response = try await request(.POST, "/dashboard/invite/\(token)/code", headers: ["Origin": origin], body: Data(), contentType: "application/x-www-form-urlencoded")
        XCTAssertEqual(response.status, .ok, response.text)
        return try XCTUnwrap(emails.lastCode(to: email), "no invite code mailed")
    }

    /// Adds a team member the way the product does: invitation email -> emailed code -> passkey registration.
    func addMember(owner: DashSession, role: OrgRole, email: String, name: String = "Teammate") async throws -> (session: DashSession, account: DashAccount) {
        let invite = try await formPost("/dashboard/team/invite", owner, [("email", email), ("role", role.rawValue)])
        XCTAssertEqual(invite.status, .ok, invite.text)
        guard let token = emails.lastInviteToken(to: email) else { throw XCTSkip("no invite email: \(invite.text.prefix(300))") }
        XCTAssertFalse(invite.text.contains(token), "the inviter never sees the token")
        let code = try await inviteCode(token: token, email: email)
        let begin = try await jsonPost("/dashboard/auth/invite/begin", InviteBeginBody(token: token, displayName: name, code: code))
        XCTAssertEqual(begin.status, .ok, begin.text)
        let options = try begin.json(PasskeyRegistrationOptions.self)
        let credentialId = SecureToken.generate(byteCount: 16)
        let publicKey = SecureToken.generate(byteCount: 32)
        let finish = try await jsonPost("/dashboard/auth/invite/finish",
            PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: registrationCredential(for: options, credentialId: credentialId, publicKey: publicKey)))
        XCTAssertEqual(finish.status, .ok, finish.text)
        let cookie = sessionCookie(finish)!
        let user = try await DashboardUserRecord.query(on: db).filter(\.$emailHash == ctx.hasher.hmacHex("dashboard-email", email)).first()!
        return (DashSession(token: cookie.value, realm: .business),
                DashAccount(email: email, credentialId: credentialId, publicKey: publicKey, userId: user.id!, businessId: owner.realm == .business ? nil : nil))
    }
}

/// `XCTUnwrap` for async optionals.
func XCTUnwrapAsync<T>(_ value: @autoclosure () async throws -> T?, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) async throws -> T {
    let resolved = try await value()
    return try XCTUnwrap(resolved, message, file: file, line: line)
}

extension TestHarness {
    /// A `TestBusiness` handle (API key included) for an organization created through the dashboard.
    func testBusiness(_ businessId: UUID, live: Bool = true, scopes: [String] = BusinessAPIKeys.Scope.all) async throws -> TestBusiness {
        let record = try await XCTUnwrapAsync(await BusinessRecord.find(businessId, on: db))
        let key = try await BusinessAPIKeys.issue(businessId: businessId, name: "test", live: live, scopes: scopes, now: clock.now(), on: db)
        let summary = try await XCTUnwrapAsync(await DirectoryService(db: db).summary(for: record))
        return TestBusiness(record: record, key: key.key, summary: summary)
    }

    /// Pulls the one-time secret out of a "copy it now" page.
    func shownSecret(_ html: String) -> String? {
        guard let r = html.range(of: "class=\"secret mono\">") else { return nil }
        return String(html[r.upperBound...].prefix { $0 != "<" })
    }

    func get(_ session: DashSession, _ path: String) async throws -> HTTPStatus { try await page(path, session).status }
}

// Async-friendly assertions (XCTest autoclosures cannot `await`).
func isTrue(_ value: @autoclosure () async throws -> Bool, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) async throws {
    let v = try await value()
    XCTAssertTrue(v, message, file: file, line: line)
}
func isFalse(_ value: @autoclosure () async throws -> Bool, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) async throws {
    let v = try await value()
    XCTAssertFalse(v, message, file: file, line: line)
}
func isNil<T>(_ value: @autoclosure () async throws -> T?, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) async throws {
    let v = try await value()
    XCTAssertNil(v, message, file: file, line: line)
}
func notNil<T>(_ value: @autoclosure () async throws -> T?, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) async throws {
    let v = try await value()
    XCTAssertNotNil(v, message, file: file, line: line)
}

func neq<T: Equatable>(_ actual: @autoclosure () async throws -> T, _ other: @autoclosure () throws -> T, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) async throws {
    let value = try await actual()
    XCTAssertNotEqual(value, try other(), message, file: file, line: line)
}
