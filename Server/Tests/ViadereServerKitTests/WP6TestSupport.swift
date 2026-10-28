@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Scripted answers for domain verification: what DNS and the well-known file say.
final class FakeDomainChecker: DomainChecker, @unchecked Sendable {
    private let lock = NSLock()
    private var texts: [String: [String]] = [:]
    private var files: [String: String] = [:]
    private var down = false

    func publishTXT(domain: String, token: String, value: String? = nil) {
        lock.withLock { texts[DomainControl.recordName(for: domain), default: []].append(value ?? DomainControl.expectedValue(token: token)) }
    }

    func removeTXT(domain: String) { lock.withLock { texts[DomainControl.recordName(for: domain)] = nil } }

    func publishFile(domain: String, token: String) { lock.withLock { files[domain] = DomainControl.expectedValue(token: token) } }

    func removeFile(domain: String) { lock.withLock { files[domain] = nil } }

    func setResolverDown(_ value: Bool) { lock.withLock { down = value } }

    func txtRecords(name: String) async throws -> [String] {
        try lock.withLock {
            if down { throw DomainCheckError.unavailable }
            return texts[name] ?? []
        }
    }

    func wellKnown(domain: String) async throws -> String? {
        try lock.withLock {
            if down { throw DomainCheckError.unavailable }
            return files[domain]
        }
    }
}

/// Records and answers the calls of the audit-head export (token exchange, KMS, Cloud Storage, R2).
final class RecordingOutboundHTTP: OutboundHTTP, @unchecked Sendable {
    struct Call: Sendable {
        var method: NIOHTTP1.HTTPMethod
        var url: String
        var headers: [String: String]
        var body: Data?
    }

    private let lock = NSLock()
    private var recorded: [Call] = []
    private var failStorage = false
    var calls: [Call] { lock.withLock { recorded } }
    func failStorageWrites(_ value: Bool) { lock.withLock { failStorage = value } }

    func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data) {
        let failing = lock.withLock { () -> Bool in
            recorded.append(Call(method: method, url: url, headers: headers, body: body))
            return failStorage
        }
        func json(_ object: [String: Any]) -> Data { (try? JSONSerialization.data(withJSONObject: object)) ?? Data() }
        if url.hasPrefix("https://sts.googleapis.com/") { return (200, json(["access_token": "federated-token"])) }
        if url.contains("iamcredentials.googleapis.com") { return (200, json(["accessToken": "service-account-token"])) }
        if url.contains("cloudkms.googleapis.com") { return (200, json(["signature": Data("kms-signature".utf8).base64EncodedString()])) }
        if url.contains("storage.googleapis.com") || url.contains("r2.cloudflarestorage.com") { return failing ? (503, Data()) : (200, json(["name": "ok"])) }
        return (404, Data())
    }
}

extension TestHarness {
    /// Answers the ownership challenge of every webhook verification request the way a correct receiver does: with the HMAC proof made from the
    /// signing secret of the endpoint the challenge is for (and 200 for every other delivery).
    func echoWebhookChallenges() {
        let db = self.db
        let ctx = self.ctx
        webhooks.respondAsync { request in
            guard let object = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any], object["type"] as? String == "webhook.verification",
                  let challenge = object["challenge"] as? String, let endpoint = (object["endpointId"] as? String).flatMap(UUID.init(uuidString:)),
                  let record = try await WebhookSubscriptionRecord.find(endpoint, on: db),
                  let secret = try? ctx.cipher.openString(record.secretCiphertext, context: "webhook_subscriptions.secret", rowId: endpoint) else { return nil }
            let proof = WebhookSignature.verificationResponse(secret: secret, challenge: challenge)
            return WebhookHTTPResponse(statusCode: 200, body: Data("{\"challenge_response\":\"\(proof)\"}".utf8))
        }
    }

    /// A signed-in owner of a **pending** organization (application not yet approved), with the account that owns it.
    func pendingOwner(email: String = "owner@example.com", org: String = "Acme Roasters", handle: String? = "acmeroasters", category: String = "retail")
        async throws -> (session: DashSession, account: DashAccount, businessId: UUID) {
        let (session, account, _) = try await dashSignup(email: email, org: org, handle: handle, category: category)
        return (session, account, account.businessId!)
    }

    /// Adds a domain through the console and publishes its token in the fake DNS, then runs the check. Returns the domain.
    @discardableResult
    func verifyDomain(_ session: DashSession, businessId: UUID, domain: String = "acme.example.com", method: String = "dns") async throws -> String {
        let add = try await formPost("/dashboard/organization/domains", session, [("domain", domain)])
        XCTAssertEqual(add.status, .seeOther, add.text)
        let found = try await BusinessDomainRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$domain == domain).first()
        let record = try XCTUnwrap(found)
        if method == "dns" { domainChecker.publishTXT(domain: domain, token: record.token) } else { domainChecker.publishFile(domain: domain, token: record.token) }
        let check = try await formPost("/dashboard/organization/domains/\(record.id!.uuidString.lowercased())/check", session)
        XCTAssertEqual(check.status, .seeOther, check.text)
        return domain
    }

    func onboardingRow(_ businessId: UUID) async throws -> BusinessOnboardingRecord {
        try await OnboardingService(db: db, ctx: ctx).row(businessId)
    }

    func onboardingState(_ businessId: UUID) async throws -> OnboardingState {
        try await OnboardingService(db: db, ctx: ctx).state(businessId: businessId)
    }

    /// Creates a key through the console and returns the one-time secret.
    func createKey(_ session: DashSession, name: String = "k", mode: String = "test", scopes: [String] = ["interactions:write", "messages:write"],
                   extra: [(String, String)] = []) async throws -> (status: HTTPStatus, secret: String?, text: String) {
        let response = try await formPost("/dashboard/api-keys", session, [("name", name), ("mode", mode)] + scopes.map { ("scopes[]", $0) } + extra)
        return (response.status, shownSecret(response.text), response.text)
    }

    /// Creates a key through the console, asserts it worked and returns the one-time secret.
    func newKey(_ session: DashSession, name: String = "k", mode: String = "test", scopes: [String] = ["interactions:write", "messages:write"],
                extra: [(String, String)] = []) async throws -> String {
        let result = try await createKey(session, name: name, mode: mode, scopes: scopes, extra: extra)
        XCTAssertEqual(result.status, .ok, result.text)
        return try XCTUnwrap(result.secret)
    }

    func apiGet(_ key: String, _ path: String, headers: [String: String] = [:]) async throws -> HTTPResult {
        var all = ["Authorization": "Bearer \(key)"]
        for (name, value) in headers { all[name] = value }
        return try await request(.GET, path, headers: all)
    }

    func apiPost(_ key: String, _ path: String, json: Data? = nil, headers: [String: String] = [:]) async throws -> HTTPResult {
        var all = ["Authorization": "Bearer \(key)", "Idempotency-Key": UUID().uuidString]
        for (name, value) in headers { all[name] = value }
        return try await request(.POST, path, headers: all, body: json ?? Data("{}".utf8))
    }

    /// Accepts every required agreement through the console.
    func acceptAllContracts(_ session: DashSession, businessId: UUID) async throws {
        for document in try await ContractService(db: db, ctx: ctx).required(businessId: businessId) {
            let response = try await formPost("/dashboard/compliance/accept", session, [("slug", document.slug), ("version", document.version), ("confirm", "1")])
            XCTAssertEqual(response.status, .seeOther, response.text)
        }
    }

    func auditActions(_ businessId: UUID? = nil) async throws -> [String] {
        var query = AuditEventRecord.query(on: db).sort(\.$seq, .ascending)
        if let businessId { query = query.filter(\.$businessId == businessId) }
        return try await query.all().map(\.action)
    }

    /// Every email body mailed so far, concatenated (for secret-leak greps).
    var allMailText: String { emails.sent.map { $0.subject + "\n" + $0.text }.joined(separator: "\n----\n") }
}
