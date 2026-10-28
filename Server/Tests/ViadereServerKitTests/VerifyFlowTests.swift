@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import SQLKit
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Verify (WP3) end to end through the HTTP surface: requests, consent, the Wallet and document methods, one-time results, webhooks,
/// policy, privacy (no evidence at rest) and the release gate.
final class VerifyFlowTests: XCTestCase {
    let pki = TestMDocPKI()
    let merchantKey = P256.KeyAgreement.PrivateKey()
    static let verifyCapabilities: [Capability] = [.ageMinimum, .identityName, .identityAddress, .identityVerified]
    static let personalValues = ["1990-01-01", "Jane", "Doe", "D1234567", "Mesa", "media.example", "89.92", "94.1", "24.3", "1 Main Street", "tok_"]

    // MARK: Async-friendly assertions (XCTest autoclosures cannot await)

    func unwrap<T>(_ value: T?, file: StaticString = #filePath, line: UInt = #line) throws -> T { try XCTUnwrap(value, file: file, line: line) }
    func expectNil(_ value: Any?, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) { XCTAssertNil(value, message, file: file, line: line) }
    func expectNotNil(_ value: Any?, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) { XCTAssertNotNil(value, message, file: file, line: line) }

    func subjectRef(_ h: TestHarness, _ relationship: Relationship) async throws -> SubjectRef {
        let record = try await unwrap(RelationshipRecord.find(relationship.id.uuid, on: h.db))
        return try XCTUnwrap(SubjectRef(try XCTUnwrap(record.subjectRef)))
    }

    // MARK: Rig

    struct Rig {
        var h: TestHarness
        var b: TestBusiness
        var consumer: TestConsumer
        var relationship: Relationship
        var ref: SubjectRef
        var didit: FakeDidit
        var hook: UUID
        var hookSecret: String
    }

    func withVerify(enabled: Bool = true, wallet: Bool = true, didit: Bool = true, _ body: (TestHarness, FakeDidit) async throws -> Void) async throws {
        try await withHarness({ config in
            config.verify.enabled = enabled
            if wallet {
                config.verify.walletMerchantIdentifier = TestWalletSealer.merchant
                config.verify.walletEncryptionKeyPaths = ["test-only"]
                config.verify.walletIACADirectory = "test-only"
            }
            if didit {
                config.verify.diditAPIKey = "test-api-key"
                config.verify.diditWorkflowIdentity = "workflow-identity"
                config.verify.diditWebhookSecrets = [DiditWebhookTests.secret]
            }
            config.verify.diditWebhookTolerance = 300
        }) { h in
            let fake = FakeDidit()
            h.app.verify.didit = didit ? fake : nil
            if wallet {
                h.app.verify.trust = pki.trustStore()
                h.app.verify.walletKeys = LocalWalletEncryptionKeys([merchantKey])
            }
            try await body(h, fake)
        }
    }

    func rig(_ h: TestHarness, _ fake: FakeDidit, capabilities: [Capability]? = nil, name: String = "Northwind Spirits", handle: String = "northwindspirits") async throws -> Rig {
        let caps = capabilities ?? (Capability.operational + Self.verifyCapabilities)
        let b = try await h.makeBusiness(name: name, handle: handle, capabilities: caps)
        let consumer = try await h.readyConsumer()
        let relationship = try await h.connect(consumer, to: b)
        let record = try await unwrap(RelationshipRecord.find(relationship.id.uuid, on: h.db))
        let ref = try XCTUnwrap(SubjectRef(try XCTUnwrap(record.subjectRef)))
        let hook = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/verify")!, events: [.verificationCompleted]))
        XCTAssertEqual(hook.status, .created, hook.text)
        let created = try hook.json(WebhookSecretResponse.self)
        return Rig(h: h, b: b, consumer: consumer, relationship: relationship, ref: ref, didit: fake, hook: created.subscription.id.uuid, hookSecret: created.secret)
    }

    // MARK: Calls

    func create(_ r: Rig, years: Int64 = 21, capability: Capability = .ageMinimum, parameters: [String: JSONValue]? = nil, purpose: String = "age_restricted_access",
                callback: Bool = true, expires: Int? = 300, key: String = UUID().uuidString, bizKey: String? = nil) async throws -> HTTPResult {
        let params = parameters ?? (capability == .ageMinimum ? ["years": .integer(years)] : [:])
        return try await r.h.businessPost(r.b, "/v1/verification-requests",
            CreateVerificationRequest(subjectRef: r.ref, capability: capability, parameters: params, purposeCode: purpose,
                                      callbackId: callback ? r.hook.uuidString.lowercased() : nil, expiresInSeconds: expires), key: bizKey, idempotencyKey: key)
    }

    func createdID(_ r: Rig, years: Int64 = 21, capability: Capability = .ageMinimum, expires: Int? = 300) async throws -> VerificationRequestID {
        let response = try await create(r, years: years, capability: capability, expires: expires)
        XCTAssertEqual(response.status, .created, response.text)
        return try response.json(VerificationRequestResource.self).requestId
    }

    func prompt(_ r: Rig, _ id: VerificationRequestID) async throws -> VerificationPrompt {
        let response = try await r.h.signed(r.consumer, .GET, "/v1/verifications/\(id)")
        XCTAssertEqual(response.status, .ok, response.text)
        return try response.json(VerificationPrompt.self)
    }

    @discardableResult
    func consent(_ r: Rig, _ id: VerificationRequestID) async throws -> VerificationPrompt {
        let shown = try await prompt(r, id)
        let response = try await r.h.signedPost(r.consumer, "/v1/verifications/\(id)/consent", VerificationConsentRequest(displayDigest: shown.displayDigest))
        XCTAssertEqual(response.status, .ok, response.text)
        return try response.json(VerificationPrompt.self)
    }

    func walletBegin(_ r: Rig, _ id: VerificationRequestID) async throws -> HTTPResult {
        try await r.h.signedPost(r.consumer, "/v1/verifications/\(id)/wallet/begin", EmptyBody())
    }

    /// Wallet: begin, then answer as Wallet would for `elements`.
    func wallet(_ r: Rig, _ id: VerificationRequestID, elements: [String: [(String, CBORValue)]], flaws: TestMDoc.Flaws = .init()) async throws -> (start: WalletAttemptStart, result: HTTPResult) {
        let begin = try await walletBegin(r, id)
        XCTAssertEqual(begin.status, .ok, begin.text)
        let start = try begin.json(WalletAttemptStart.self)
        var doc = TestMDoc(pki: pki, elements: elements)
        doc.flaws = flaws
        let envelope = try TestWalletSealer.seal(doc, nonce: try XCTUnwrap(Base64URL.decode(start.nonce)), recipient: merchantKey.publicKey)
        return (start, try await submit(r, id, attempt: start.attemptId, envelope: envelope))
    }

    func submit(_ r: Rig, _ id: VerificationRequestID, attempt: UUID, envelope: Data) async throws -> HTTPResult {
        try await r.h.signedPost(r.consumer, "/v1/verifications/\(id)/wallet/complete", WalletAttemptComplete(attemptId: attempt, envelope: Base64URL.encode(envelope)))
    }

    func resource(_ r: Rig, _ id: VerificationRequestID) async throws -> VerificationRequestResource {
        let response = try await r.h.business(r.b, .GET, "/v1/verification-requests/\(id)")
        XCTAssertEqual(response.status, .ok, response.text)
        return try response.json(VerificationRequestResource.self)
    }

    func result(_ r: Rig, _ ref: VerificationResultRef, key: String? = nil, business: TestBusiness? = nil) async throws -> HTTPResult {
        try await r.h.business(business ?? r.b, .GET, "/v1/verification-results/\(ref)", key: key)
    }

    func attemptOutcome(_ response: HTTPResult) throws -> VerificationAttemptOutcome { try response.json(VerificationAttemptOutcome.self) }

    func ageOver(_ years: Int, _ value: Bool = true, extra: [(String, CBORValue)] = []) -> [String: [(String, CBORValue)]] { TestMDoc.ageOver(years, value, extra: extra) }

    /// Everything a table or log could hold of the request, as one string.
    func storedText(_ h: TestHarness) async throws -> String {
        var out = ""
        if let sql = h.db as? any SQLDatabase {
            for table in ["verification_requests", "verification_attempts", "verification_results", "verification_provider_events", "disclosure_receipts"] {
                for row in try await sql.raw(SQLQueryString("SELECT * FROM \(unsafeRaw: table)")).all() {
                    for column in row.allColumns { if let text = try? row.decode(column: column, as: String.self) { out += "\(column)=\(text)\n" } }
                }
            }
        }
        for event in try await AuditEventRecord.query(on: h.db).all() { out += event.action + " " + event.metadataJSON + "\n" }
        for delivery in try await WebhookDeliveryRecord.query(on: h.db).all() { out += String(decoding: WebhookService(db: h.db, ctx: h.ctx).storedBody(delivery) ?? Data(), as: UTF8.self) + "\n" }
        return out
    }

    func assertNoEvidence(_ h: TestHarness, except allowed: [String] = [], file: StaticString = #filePath, line: UInt = #line) async throws {
        let text = try await storedText(h)
        for value in Self.personalValues where !allowed.contains(value) { XCTAssertFalse(text.contains(value), "\(value) must not be stored", file: file, line: line) }
    }

    func resultPayloadErased(_ h: TestHarness, _ id: VerificationRequestID) async throws -> Bool {
        let row = try await VerificationResultRecord.query(on: h.db).filter(\.$requestId == id.uuid).first()
        return row?.payload == nil
    }

    // MARK: Release gate

    func testEveryVerifyRouteIsClosedWhileTheGateIsOff() async throws {
        try await withVerify(enabled: false) { h, fake in
            let r = try await rig(h, fake)
            let create = try await create(r)
            XCTAssertEqual(create.status, .notFound)
            let id = VerificationRequestID()
            for path in ["/v1/verification-requests/\(id)", "/v1/verification-results/\(VerificationResultRef.generate())"] {
                try await eq(try await h.business(r.b, .GET, path).status, .notFound)
            }
            try await eq(try await h.signed(r.consumer, .GET, "/v1/verifications").status, .notFound)
            try await eq(try await h.signedPost(r.consumer, "/v1/verifications/\(id)/consent", VerificationConsentRequest(displayDigest: "sha256:x")).status, .notFound)
            try await eq(try await h.signedPost(r.consumer, "/v1/verifications/\(id)/wallet/begin", EmptyBody()).status, .notFound)
            // The provider webhook is also unusable when neither the gate nor the provider is configured.
            try await withVerify(enabled: false, didit: false) { h2, _ in
                try await eq(try await h2.request(.POST, "/v1/providers/didit/webhook", body: Data("{}".utf8)).status, .forbidden)
            }
        }
    }

    func testTheGateDefaultsOffAndNeedsARecordedDecisionInStagingAndProduction() throws {
        XCTAssertFalse(ServerConfig.testing().verify.enabled)
        var production = ServerConfig.testing()
        production.environment = .production
        XCTAssertThrowsError(try production.applyVerifyEnvironment(["VERIFY_ENABLED": "true"], production: true), "no gate reference")
        XCTAssertThrowsError(try production.applyVerifyEnvironment(["VERIFY_ENABLED": "true", "VERIFY_GATE_REFERENCE": "GATE-3-2027-01"], production: true), "no configured method")
        let wallet = ["WALLET_MERCHANT_ID": "merchant.com.viadere", "WALLET_ENCRYPTION_KEY_WRAPPED": "AAAA", "WALLET_IACA_DIR": "/etc/viadere/iaca"]
        XCTAssertThrowsError(try production.applyVerifyEnvironment(["VERIFY_ENABLED": "true", "VERIFY_GATE_REFERENCE": "GATE-3"].merging(wallet) { a, _ in a }, production: true), "pinning required")
        let pinned = ["WALLET_IACA_SHA256": String(repeating: "ab", count: 32)]
        XCTAssertNoThrow(try production.applyVerifyEnvironment(["VERIFY_ENABLED": "true", "VERIFY_GATE_REFERENCE": "GATE-3"].merging(wallet) { a, _ in a }.merging(pinned) { a, _ in a }, production: true))
        XCTAssertTrue(production.verify.enabled)
        // A key file is development only.
        var file = ServerConfig.testing()
        file.environment = .production
        XCTAssertThrowsError(try file.applyVerifyEnvironment(["VERIFY_ENABLED": "true", "VERIFY_GATE_REFERENCE": "G", "WALLET_MERCHANT_ID": "m", "WALLET_ENCRYPTION_KEY_PATHS": "/k.pem",
                                                              "WALLET_IACA_DIR": "/d", "WALLET_IACA_SHA256": pinned["WALLET_IACA_SHA256"]!], production: true))
        // Unset: off, whatever else is configured.
        var off = ServerConfig.testing()
        try off.applyVerifyEnvironment(["DIDIT_API_KEY": "k"], production: true)
        XCTAssertFalse(off.verify.enabled)
        XCTAssertThrowsError(try off.applyVerifyEnvironment(["DIDIT_API_BASE": "http://evil.example"], production: true), "the API key is only ever sent over https in production")
        XCTAssertThrowsError(try off.applyVerifyEnvironment(["WALLET_IACA_SHA256": "xyz"], production: false))
    }

    // MARK: Acceptance 1: capability, not the credential

    func testAMessagingKeyCannotCreateOrReadVerifications() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let messaging = try await BusinessAPIKeys.issue(businessId: r.b.record.id!, name: "m", live: true, scopes: BusinessAPIKeys.Scope.all, capabilities: Capability.messaging,
                                                            now: h.clock.now(), on: h.db).key
            let denied = try await create(r, bizKey: messaging)
            XCTAssertEqual(denied.status, .forbidden)
            XCTAssertEqual(denied.errorCode, .insufficientScope, denied.text)
            // Nothing was created, and the denial is audited without any subject data beyond the pseudonymous reference.
            try await eq(try await VerificationRequestRecord.query(on: h.db).count(), 0)
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == "policy.denied").count(), 1)
            // The entitled key makes one; the messaging key can neither read nor retrieve it.
            let id = try await createdID(r)
            try await eq(try await h.business(r.b, .GET, "/v1/verification-requests/\(id)", key: messaging).errorCode, .insufficientScope)
            try await eq(try await h.business(r.b, .GET, "/v1/verification-results/\(VerificationResultRef.generate())", key: messaging).status, .notFound,
                         "an unknown reference is a plain 404 whatever the credential")
        }
    }

    func testAnUnentitledBusinessCannotCreateEvenWithTheScope() async throws {
        try await withVerify { h, fake in
            let b = try await h.makeBusiness(name: "Plain Shop", handle: "plainshop", capabilities: Capability.messaging)
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            let ref = try await subjectRef(h, rel)
            let key = try await BusinessAPIKeys.issue(businessId: b.record.id!, name: "k", live: true, scopes: BusinessAPIKeys.Scope.all, capabilities: [.ageMinimum], now: h.clock.now(), on: h.db).key
            let response = try await h.businessPost(b, "/v1/verification-requests", CreateVerificationRequest(subjectRef: ref, capability: .ageMinimum, parameters: ["years": .integer(18)],
                                                                                                             purposeCode: "age_restricted_access"), key: key, idempotencyKey: "k1")
            XCTAssertEqual(response.errorCode, .notEntitled, response.text)
        }
    }

    // MARK: Creation

    func testCreationValidatesEverythingBeforeTouchingTheCustomer() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            // A URL (or anything that is not a registered endpoint) is never a callback.
            for callback in ["https://evil.example/hook", "5d1b2a60-0000-4000-8000-000000000001", "x", UUID().uuidString.lowercased()] {
                let response = try await h.businessPost(r.b, "/v1/verification-requests", CreateVerificationRequest(subjectRef: r.ref, capability: .ageMinimum, parameters: ["years": .integer(21)],
                                                                                                                 purposeCode: "age_restricted_access", callbackId: callback), idempotencyKey: UUID().uuidString)
                XCTAssertEqual(response.status, .unprocessableEntity, "\(callback): \(response.text)")
            }
            for expires in [29, 601, 0, -5] { try await eq(try await create(r, expires: expires).status, .unprocessableEntity, "expires \(expires)") }
            try await eq(try await create(r, years: 17).status, .unprocessableEntity)
            try await eq(try await create(r, purpose: "Not A Code").status, .unprocessableEntity)
            try await eq(try await create(r, parameters: ["years": .integer(21), "birthdate": .string("1990-01-01")]).status, .unprocessableEntity, "unknown parameters are refused")
            try await eq(try await create(r, capability: .messageSend, parameters: [:]).status, .unprocessableEntity)
            try await eq(try await create(r, capability: .transactionApprove, parameters: [:]).status, .unprocessableEntity)
            // A subject_ref of another business or an invented one is a plain 404.
            let other = try await h.makeBusiness(name: "Other Co", handle: "otherco", capabilities: Capability.operational + Self.verifyCapabilities)
            let theirs = try await h.connect(try await h.readyConsumer(), to: other)
            let theirRef = try await subjectRef(h, theirs)
            for ref in [theirRef, SubjectRef("sub_" + Base64URL.encode(Data(repeating: 5, count: 32)))!] {
                let response = try await h.businessPost(r.b, "/v1/verification-requests", CreateVerificationRequest(subjectRef: ref, capability: .ageMinimum, parameters: ["years": .integer(21)],
                                                                                                                 purposeCode: "age_restricted_access"), idempotencyKey: UUID().uuidString)
                XCTAssertEqual(response.status, .notFound)
            }
            // The Idempotency-Key is required.
            let missing = try await h.request(.POST, "/v1/verification-requests", headers: ["Authorization": "Bearer \(r.b.key)"],
                                              body: try ViadereJSON.encode(CreateVerificationRequest(subjectRef: r.ref, capability: .ageMinimum, parameters: ["years": .integer(21)], purposeCode: "age_restricted_access")))
            XCTAssertEqual(missing.status, .unprocessableEntity)
            try await eq(try await VerificationRequestRecord.query(on: h.db).count(), 0)
        }
    }

    func testCreationIsIdempotentAndBoundedPerCustomer() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let first = try await create(r, key: "same")
            XCTAssertEqual(first.status, .created)
            let again = try await create(r, key: "same")
            XCTAssertEqual(again.status, .ok)
            XCTAssertEqual(try first.json(VerificationRequestResource.self).requestId, try again.json(VerificationRequestResource.self).requestId)
            let conflicting = try await create(r, years: 18, key: "same")
            XCTAssertEqual(conflicting.status, .conflict)
            try await eq(try await VerificationRequestRecord.query(on: h.db).count(), 1)
            // Prompt fatigue: at most three open requests per business and customer.
            _ = try await createdID(r)
            _ = try await createdID(r)
            let fourth = try await create(r)
            XCTAssertEqual(fourth.status, .tooManyRequests)
            // The business-facing resource names no more than it should.
            let body = try first.json(JSONValue.self).objectValue ?? [:]
            XCTAssertEqual(Set(body.keys), ["request_id", "capability", "subject_ref", "purpose_code", "status", "created_at", "expires_at"])
            XCTAssertEqual(body["status"], .string("pending"))
        }
    }

    // MARK: The consumer's view and consent

    func testThePersonSeesTheBusinessThePurposeTheExactDisclosureAndTheExpiry() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r, years: 21, expires: 240)
            let shown = try await prompt(r, id)
            XCTAssertEqual(shown.recipientName, "Northwind Spirits")
            XCTAssertTrue(shown.recipientVerified)
            XCTAssertEqual(shown.recipientHandle?.contains("northwindspirits"), true)
            XCTAssertEqual(shown.purposeCode, "age_restricted_access")
            XCTAssertEqual(shown.capability, .ageMinimum)
            XCTAssertEqual(shown.status, .pendingConsent)
            XCTAssertEqual(shown.expiresAt, h.clock.now().addingTimeInterval(240))
            XCTAssertEqual(shown.disclosure.map(\.field), ["meets_threshold"])
            XCTAssertTrue(shown.disclosure[0].title.contains("21"))
            XCTAssertTrue(shown.notDisclosed.contains("Your date of birth") && shown.notDisclosed.contains("Your name"))
            XCTAssertEqual(shown.methods.map(\.kind), [.wallet, .document])
            XCTAssertEqual(shown.methods.map(\.available), [true, true])
            // The list shows it as pending; the history is empty.
            let list = try await h.signed(r.consumer, .GET, "/v1/verifications").json(VerificationListResponse.self)
            XCTAssertEqual(list.pending.map(\.id), [id])
            XCTAssertTrue(list.history.isEmpty)
        }
    }

    func testConsentNeedsTheDigestOfWhatWasShown() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            let other = try await createdID(r, years: 18)
            let wrong = try await h.signedPost(r.consumer, "/v1/verifications/\(id)/consent", VerificationConsentRequest(displayDigest: try await prompt(r, other).displayDigest))
            XCTAssertEqual(wrong.status, .conflict, "another request's digest cannot consent to this one")
            try await eq(try await h.signedPost(r.consumer, "/v1/verifications/\(id)/consent", VerificationConsentRequest(displayDigest: "sha256:00")).status, .conflict)
            try await eq(try await DisclosureReceiptRecord.query(on: h.db).count(), 0)
            // Wallet and document attempts need the consent first.
            try await eq(try await walletBegin(r, id).status, .conflict)
            try await eq(try await h.signedPost(r.consumer, "/v1/verifications/\(id)/document/begin", EmptyBody()).status, .conflict)
            // The real digest creates exactly one receipt bound to this business, purpose and request.
            let consented = try await consent(r, id)
            XCTAssertEqual(consented.status, .consented)
            let receipt = try unwrap(try await DisclosureReceiptRecord.query(on: h.db).first())
            XCTAssertEqual(receipt.requestId, id.description)
            XCTAssertEqual(receipt.businessId, r.b.record.id)
            XCTAssertEqual(receipt.purpose, "age_restricted_access")
            XCTAssertEqual(receipt.fields, "meets_threshold")
            XCTAssertEqual(receipt.recipientName, "Northwind Spirits")
            // Consenting twice does not create a second receipt.
            let twice = try await h.signedPost(r.consumer, "/v1/verifications/\(id)/consent", VerificationConsentRequest(displayDigest: consented.displayDigest))
            XCTAssertEqual(twice.status, .conflict)
            try await eq(try await DisclosureReceiptRecord.query(on: h.db).count(), 1)
        }
    }

    func testAnotherPersonCannotSeeOrActOnARequest() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            let stranger = try await h.readyConsumer(name: "Stranger")
            let shown = try await prompt(r, id)
            for (method, path, body) in [(NIOHTTP1.HTTPMethod.GET, "/v1/verifications/\(id)", Data?.none),
                                         (.POST, "/v1/verifications/\(id)/consent", try ViadereJSON.encode(VerificationConsentRequest(displayDigest: shown.displayDigest))),
                                         (.POST, "/v1/verifications/\(id)/decline", try ViadereJSON.encode(EmptyBody())),
                                         (.POST, "/v1/verifications/\(id)/wallet/begin", try ViadereJSON.encode(EmptyBody()))] {
                let response = try await h.signed(stranger, method, path, body: body)
                XCTAssertEqual(response.status, .notFound, "\(method) \(path)")
            }
            let list = try await h.signed(stranger, .GET, "/v1/verifications").json(VerificationListResponse.self)
            XCTAssertTrue(list.pending.isEmpty && list.history.isEmpty)
            try await eq(try await resource(r, id).status, .pending)
        }
    }

    func testABusinessCannotReadAnotherBusinessesRequestOrResult() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let rival = try await h.makeBusiness(name: "Rival Co", handle: "rivalco", capabilities: Capability.operational + Self.verifyCapabilities)
            let id = try await createdID(r)
            try await consent(r, id)
            let released = try await wallet(r, id, elements: ageOver(21))
            XCTAssertEqual(released.result.status, .ok, released.result.text)
            let ref = try await resource(r, id).resultRef!
            // Acceptance 2: changing the identifier does not reach another tenant's request or result.
            try await eq(try await h.business(rival, .GET, "/v1/verification-requests/\(id)").status, .notFound)
            try await eq(try await h.business(rival, .GET, "/v1/verification-results/\(ref)").status, .notFound)
            // And the failed attempt did not spend the owner's one retrieval.
            try await eq(try await result(r, ref).status, .ok)
        }
    }

    // MARK: Wallet: the whole flow

    func testAWalletAgeVerificationEndToEnd() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r, years: 21)
            try await consent(r, id)
            // The document carries more than was requested; none of it is read.
            let extra: [(String, CBORValue)] = [("family_name", .text("Doe")), ("given_name", .text("Jane")), ("birth_date", .tagged(1004, .text("1990-01-01"))),
                                                ("document_number", .text("D1234567")), ("resident_city", .text("Mesa"))]
            let done = try await wallet(r, id, elements: ageOver(21, true, extra: extra))
            XCTAssertEqual(done.result.status, .ok, done.result.text)
            let outcome = try attemptOutcome(done.result)
            XCTAssertEqual(outcome.status, .released)
            XCTAssertEqual(outcome.label, .verifiedAgeThreshold)
            XCTAssertFalse(outcome.canRetry)

            // The business sees a finished request and an opaque reference; nothing else.
            let finished = try await resource(r, id)
            XCTAssertEqual(finished.status, .completed)
            let ref = try XCTUnwrap(finished.resultRef)
            // The webhook is opaque: ids only (acceptance: spec 14.3).
            let delivery = try unwrap(try await WebhookDeliveryRecord.query(on: h.db).filter(\.$eventType == "verification.completed").first())
            let event = try ViadereJSON.decode(WebhookEvent.self, from: try XCTUnwrap(WebhookService(db: h.db, ctx: h.ctx).deliveryBody(delivery)))
            XCTAssertEqual(Set(try XCTUnwrap(event.data.objectValue).keys), ["request_id", "result_ref"])
            XCTAssertEqual(event.data.objectValue?["result_ref"], .string(ref.rawValue))
            XCTAssertEqual(event.type, .verificationCompleted)

            // Retrieval: authenticated and recipient-bound; discloses only meets_threshold + assurance, issued_at, expires_at, audience (acceptance 6).
            let fetched = try await result(r, ref)
            XCTAssertEqual(fetched.status, .ok, fetched.text)
            XCTAssertEqual(fetched.headers.first(name: .cacheControl), "no-store")
            let body = try fetched.json(JSONValue.self).objectValue ?? [:]
            XCTAssertTrue(Set(body.keys).isSubset(of: VerificationResult.topLevelFields), "top level: \(body.keys)")
            let claims = try XCTUnwrap(body["result"]?.objectValue)
            XCTAssertEqual(Set(claims.keys), Set(CapabilityCatalog.definition(for: .ageMinimum)!.output.fieldNames))
            XCTAssertEqual(claims["meets_threshold"], .bool(true))
            XCTAssertEqual(claims["assurance"], .string("issuer_signed_credential_device_bound"))
            XCTAssertEqual(claims["audience"], .string(r.b.id.description))
            XCTAssertEqual(CapabilityCatalog.definition(for: .ageMinimum)!.violations(in: claims), [])
            for banned in CapabilityCatalog.personalDataFieldNames { XCTAssertNil(body[banned]); XCTAssertNil(claims[banned], banned) }
            XCTAssertTrue(fetched.text.contains("\"outcome\":\"verified\""))
            let parsed = try fetched.json(VerificationResult.self)
            XCTAssertEqual(parsed.requestId, id)
            XCTAssertEqual(parsed.subjectRef, r.ref)
            XCTAssertEqual(parsed.parameters["years"], .integer(21))
            // expires_at is within the result validity.
            let expires = try XCTUnwrap(ViadereDate.parse(try XCTUnwrap(claims["expires_at"]?.stringValue)))
            XCTAssertLessThanOrEqual(expires.timeIntervalSince(h.clock.now()), VerifyPolicy.resultValidity)

            // Single use: a second retrieval, even by the owner, is gone; the payload was erased.
            try await eq(try await result(r, ref).status, .gone)
            try await eq(try await resultPayloadErased(h, id), true)
            // The receipt was consumed by the disclosure; the person's history shows it.
            expectNotNil(try await DisclosureReceiptRecord.query(on: h.db).first()?.consumedAt)
            let history = try await h.signed(r.consumer, .GET, "/v1/verifications").json(VerificationListResponse.self).history
            XCTAssertEqual(history.first?.status, .released)
            XCTAssertEqual(history.first?.disclosedFields, ["meets_threshold"])
            XCTAssertEqual(history.first?.label, .verifiedAgeThreshold)
            XCTAssertEqual(history.first?.revocable, false)

            // Nothing about the person's document is anywhere (requests, attempts, results, receipts, audit, webhook bodies).
            try await assertNoEvidence(h)
            // The decision is audited with the method, label and policy version, not the data.
            let audit = try await AuditEventRecord.query(on: h.db).filter(\.$action == "verification.completed").first()
            XCTAssertTrue(audit?.metadataJSON.contains("wallet_mdoc") == true && audit?.metadataJSON.contains(VerifyPolicy.version) == true)
            // The provenance record names the method, issuer, assurance and policy version (VER-007) and holds no personal data.
            let provenance = try ViadereJSON.decode(VerificationProvenance.self, from: Data(try unwrap(try await VerificationResultRecord.query(on: h.db).first()?.provenance).utf8))
            XCTAssertEqual(provenance.method, .walletMdoc)
            XCTAssertEqual(provenance.label, .verifiedAgeThreshold)
            XCTAssertEqual(provenance.issuer, String(pki.fingerprint.prefix(16)))
            XCTAssertEqual(provenance.revocation, .notChecked)
            XCTAssertEqual(provenance.policyVersion, VerifyPolicy.version)
            XCTAssertEqual(provenance.assurance.issuerTrust, .configuredTrustAnchor)
            XCTAssertEqual(provenance.assurance.presentationBinding, .deviceSignatureOverTranscript)
            XCTAssertEqual(provenance.assurance.transactionRisk, .high)
        }
    }

    func testTheWalletNonceIsSingleUseAndAnEnvelopeCannotBeReplayed() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            try await consent(r, id)
            let begin = try await walletBegin(r, id).json(WalletAttemptStart.self)
            let nonce = try XCTUnwrap(Base64URL.decode(begin.nonce))
            let doc = TestMDoc(pki: pki, elements: ageOver(21))
            let envelope = try TestWalletSealer.seal(doc, nonce: nonce, recipient: merchantKey.publicKey)
            let first = try await submit(r, id, attempt: begin.attemptId, envelope: envelope)
            XCTAssertEqual(try attemptOutcome(first).status, .released)
            // Replaying the very same envelope: the nonce is spent, nothing happens, no second result.
            let replay = try await submit(r, id, attempt: begin.attemptId, envelope: envelope)
            XCTAssertEqual(replay.status, .ok)
            XCTAssertEqual(try attemptOutcome(replay).status, .released, "the person-facing state is unchanged")
            try await eq(try await VerificationResultRecord.query(on: h.db).count(), 1)
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == "verification.attempt_replayed").count(), 1)
            // The nonce is gone from the database as soon as it is consumed.
            expectNil(try await VerificationAttemptRecord.query(on: h.db).first()?.nonce)
        }
    }

    func testAnEnvelopeForAnotherRequestOrAttemptDoesNotVerify() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let a = try await createdID(r)
            let b = try await createdID(r, years: 18)
            try await consent(r, a)
            try await consent(r, b)
            let beginA = try await walletBegin(r, a).json(WalletAttemptStart.self)
            let beginB = try await walletBegin(r, b).json(WalletAttemptStart.self)
            // Wallet answered B's nonce; it is submitted for A's attempt: the transcript differs, so it cannot open.
            let envelopeForB = try TestWalletSealer.seal(TestMDoc(pki: pki, elements: ageOver(21)), nonce: try XCTUnwrap(Base64URL.decode(beginB.nonce)), recipient: merchantKey.publicKey)
            let swapped = try await submit(r, a, attempt: beginA.attemptId, envelope: envelopeForB)
            let state = try attemptOutcome(swapped)
            XCTAssertEqual(state.status, .consented)
            XCTAssertTrue(state.canRetry)
            try await eq(try await VerificationResultRecord.query(on: h.db).count(), 0)
            try await eq(try await VerificationAttemptRecord.query(on: h.db).filter(\.$id == beginA.attemptId).first()?.failureReason, "transcript_mismatch")
            // An attempt of one request cannot be completed through another request's path.
            let cross = try await submit(r, a, attempt: beginB.attemptId, envelope: envelopeForB)
            XCTAssertEqual(cross.status, .notFound)
            // A new nonce is needed after a failure (the spent one is dead).
            let again = try await submit(r, a, attempt: beginA.attemptId, envelope: envelopeForB)
            XCTAssertEqual(try attemptOutcome(again).status, .consented)
            try await eq(try await VerificationResultRecord.query(on: h.db).count(), 0)
        }
    }

    func testBadPresentationsNeverDisclose() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            try await consent(r, id)
            var flaws = TestMDoc.Flaws()
            flaws.tamperElement = (WalletElementPlan.isoNamespace, "age_over_21", .bool(true))
            // The issuer said "no"; the response was edited to say "yes": digest mismatch, nothing disclosed.
            let tampered = try await wallet(r, id, elements: ageOver(21, false), flaws: flaws)
            XCTAssertEqual(try attemptOutcome(tampered.result).status, .consented)
            try await eq(try await VerificationAttemptRecord.query(on: h.db).filter(\.$id == tampered.start.attemptId).first()?.failureReason, "digest_mismatch")
            try await eq(try await resource(r, id).status, .pending)
            expectNil(try await DisclosureReceiptRecord.query(on: h.db).first()?.consumedAt, "a failed attempt leaves the consent unspent")
            // Unknown issuer.
            var stranger = TestMDoc.Flaws()
            stranger.otherPKI = TestMDocPKI(now: h.clock.now(), name: "Unknown IACA")
            let foreign = try await wallet(r, id, elements: ageOver(21), flaws: stranger)
            XCTAssertEqual(try attemptOutcome(foreign.result).status, .consented)
            try await eq(try await VerificationAttemptRecord.query(on: h.db).filter(\.$id == foreign.start.attemptId).first()?.failureReason, "untrusted_issuer")
            // The third failed attempt ends the request as not_verified (three attempts per request).
            var expired = TestMDoc.Flaws()
            expired.validUntil = h.clock.now().addingTimeInterval(-60)
            let last = try await wallet(r, id, elements: ageOver(21), flaws: expired)
            XCTAssertEqual(try attemptOutcome(last.result).status, .notVerified)
            let end = try await resource(r, id)
            XCTAssertEqual(end.status, .completed)
            let fetched = try await result(r, try XCTUnwrap(end.resultRef)).json(VerificationResult.self)
            XCTAssertEqual(fetched.outcome, .notVerified)
            XCTAssertTrue(fetched.result.isEmpty)
            // No more attempts.
            try await eq(try await walletBegin(r, id).status, .conflict)
        }
    }

    func testAnUnderageAnswerAndEveryOtherFailureLookTheSameToTheBusiness() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            // A: the issuer says the person is under 21 (three tries with the document), B: the person declines, C: the request expires,
            // D: consent withdrawn, E: the credential is expired.
            let a = try await createdID(r), b = try await createdID(r), c = try await createdID(r)
            try await consent(r, a)
            for _ in 0..<3 { _ = try await wallet(r, a, elements: ageOver(21, false)) }
            try await eq(try await h.signedPost(r.consumer, "/v1/verifications/\(b)/decline", EmptyBody()).status, .ok)
            h.clock.advance(by: 301)
            try await h.runJobs()
            _ = c
            var shapes: [String: [String]] = [:]
            for (name, id) in [("underage", a), ("declined", b), ("expired", c)] {
                let finished = try await resource(r, id)
                XCTAssertEqual(finished.status, .completed, name)
                let body = try await result(r, try XCTUnwrap(finished.resultRef))
                XCTAssertEqual(body.status, .ok, name)
                let object = try body.json(JSONValue.self).objectValue ?? [:]
                XCTAssertEqual(object["outcome"], .string("not_verified"), name)
                XCTAssertEqual(object["result"], .object([:]), name)
                shapes[name] = object.keys.sorted()
            }
            XCTAssertEqual(Set(shapes.values).count, 1, "same fields for every non-positive end")
            // The person's own history keeps the reasons (and only the person sees them).
            let history = try await h.signed(r.consumer, .GET, "/v1/verifications").json(VerificationListResponse.self).history
            XCTAssertEqual(Set(history.map(\.status)), [.notVerified, .declined, .expired])
        }
    }

    func testWithdrawingConsentBeforeTheDisclosureStopsIt() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            try await consent(r, id)
            let history = try await h.signedPost(r.consumer, "/v1/verifications/\(id)/revoke", EmptyBody())
            XCTAssertEqual(history.status, .ok, history.text)
            XCTAssertEqual(try history.json(VerificationHistoryItem.self).status, .revoked)
            let ended = try await resource(r, id)
            XCTAssertEqual(ended.status, .completed)
            try await eq(try await result(r, try XCTUnwrap(ended.resultRef)).json(VerificationResult.self).outcome, .notVerified)
            // A presentation after the withdrawal finds nothing to authorize.
            try await eq(try await walletBegin(r, id).status, .conflict)
            // A disclosure that already happened cannot be "withdrawn".
            let second = try await createdID(r)
            try await consent(r, second)
            _ = try await wallet(r, second, elements: ageOver(21))
            try await eq(try await h.signedPost(r.consumer, "/v1/verifications/\(second)/revoke", EmptyBody()).status, .conflict)
        }
    }

    func testAReceiptRevokedMidFlowDeniesTheDisclosure() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            try await consent(r, id)
            let begin = try await walletBegin(r, id).json(WalletAttemptStart.self)
            // The receipt is revoked after the person tapped but before the server concluded (a race with the Settings screen).
            let receipt = try unwrap(try await DisclosureReceiptRecord.query(on: h.db).first())
            receipt.revokedAt = h.clock.now()
            try await receipt.update(on: h.db)
            let envelope = try TestWalletSealer.seal(TestMDoc(pki: pki, elements: ageOver(21)), nonce: try XCTUnwrap(Base64URL.decode(begin.nonce)), recipient: merchantKey.publicKey)
            let response = try await submit(r, id, attempt: begin.attemptId, envelope: envelope)
            XCTAssertEqual(try attemptOutcome(response).status, .notVerified)
            let ended = try await resource(r, id)
            try await eq(try await result(r, try XCTUnwrap(ended.resultRef)).json(VerificationResult.self).outcome, .notVerified)
            let denial = try await AuditEventRecord.query(on: h.db).filter(\.$action == "policy.denied").first()
            XCTAssertTrue(denial?.metadataJSON.contains("revoked") == true, denial?.metadataJSON ?? "")
        }
    }

    func testARevokedKeyOrWithdrawnEntitlementOrKillSwitchCannotReleaseARequestedDisclosure() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            // (1) The creating key is revoked after the request.
            let one = try await createdID(r)
            try await consent(r, one)
            let key = try unwrap(try await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == r.b.record.id!).all().first { $0.capabilitySet.contains(.ageMinimum) })
            key.revokedAt = h.clock.now()
            try await key.update(on: h.db)
            let revoked = try await wallet(r, one, elements: ageOver(21))
            XCTAssertEqual(try attemptOutcome(revoked.result).status, .notVerified)
            // (2) The entitlement is withdrawn.
            key.revokedAt = nil
            try await key.update(on: h.db)
            let two = try await createdID(r)
            try await consent(r, two)
            try await EntitlementService(db: h.db, ctx: h.ctx).revoke(businessId: r.b.record.id!, capability: .ageMinimum, actor: .system("test"), justification: "Withdrawn in test.")
            let withdrawn = try await wallet(r, two, elements: ageOver(21))
            XCTAssertEqual(try attemptOutcome(withdrawn.result).status, .notVerified)
            try await eq(try await create(r).errorCode, .notEntitled)
            // (3) The per-capability kill switch (WP2).
            try await EntitlementService(db: h.db, ctx: h.ctx).grant(businessId: r.b.record.id!, capability: .ageMinimum, actor: .system("test"), justification: "Re-granted in test fixture.", reviewReference: "TEST-REVIEW-2")
            let three = try await createdID(r)
            try await consent(r, three)
            try await CapabilitySwitchRecord(capability: "age.minimum", scope: CapabilitySwitchRecord.globalScope, disabled: true, reason: "incident", updatedBy: "operator", now: h.clock.now()).create(on: h.db)
            await h.ctx.policyCache.invalidate()
            let killed = try await wallet(r, three, elements: ageOver(21))
            XCTAssertEqual(try attemptOutcome(killed.result).status, .notVerified)
            try await eq(try await create(r).errorCode, .capabilityDisabled)
            // None of the three disclosed anything.
            try await eq(try await VerificationResultRecord.query(on: h.db).filter(\.$outcome == "verified").count(), 0)
        }
    }

    func testJurisdictionPolicyRulesApply() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let rule = PolicyRule(capability: .ageMinimum, kind: .jurisdictionAllowOnly, jurisdictions: ["US-CA"], reason: "Pilot market only")
            try await PolicyRuleRecord(rule: rule, createdBy: "operator", now: h.clock.now()).create(on: h.db)
            await h.ctx.policyCache.invalidate()
            // No jurisdiction is known for the request, and an allow-only rule fails closed.
            try await eq(try await create(r).errorCode, .policyDenied)
        }
    }

    func testIdentityAttributesAreReleasedOnlyAfterTheirOwnConsentAndNeverFromAnAgeResult() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r, capability: .identityName)
            let shown = try await prompt(r, id)
            XCTAssertEqual(shown.disclosure.map(\.field), ["given_name", "family_name"])
            XCTAssertFalse(shown.notDisclosed.contains("Your name"))
            try await consent(r, id)
            // An age-only credential (no names) cannot answer a name request.
            let none = try await wallet(r, id, elements: ageOver(21))
            XCTAssertEqual(try attemptOutcome(none.result).status, .consented)
            let named = try await wallet(r, id, elements: [WalletElementPlan.isoNamespace: [("given_name", .text("Jane")), ("family_name", .text("Doe")), ("birth_date", .tagged(1004, .text("1990-01-01")))]])
            XCTAssertEqual(try attemptOutcome(named.result).label, .verifiedIdentity)
            let finished = try await resource(r, id)
            let fetched = try await result(r, try XCTUnwrap(finished.resultRef)).json(VerificationResult.self)
            XCTAssertEqual(fetched.result["given_name"], .string("Jane"))
            XCTAssertEqual(fetched.result["family_name"], .string("Doe"))
            XCTAssertNil(fetched.result["birth_date"])
            XCTAssertEqual(CapabilityCatalog.definition(for: .identityName)!.violations(in: fetched.result), [])
            // After the one retrieval nothing of the name remains anywhere.
            try await assertNoEvidence(h)
            try await eq(try await resultPayloadErased(h, id), true)
        }
    }

    func testIdentityAddressAndVerifiedFlags() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let address = try await createdID(r, capability: .identityAddress)
            try await consent(r, address)
            let doc: [String: [(String, CBORValue)]] = [WalletElementPlan.isoNamespace: [("resident_address", .text("1 Main St")), ("resident_city", .text("Mesa")), ("resident_state", .text("AZ")),
                                                                                         ("resident_postal_code", .text("85201")), ("issuing_authority", .text("AZ MVD"))]]
            try await eq(try attemptOutcome(try await wallet(r, address, elements: doc).result).status, .released)
            let fetched = try await result(r, try unwrap(try await resource(r, address).resultRef)).json(VerificationResult.self)
            XCTAssertEqual(fetched.result["address"]?.objectValue?["locality"], .string("Mesa"))
            let verified = try await createdID(r, capability: .identityVerified)
            try await consent(r, verified)
            try await eq(try attemptOutcome(try await wallet(r, verified, elements: doc).result).status, .released)
            let flag = try await result(r, try unwrap(try await resource(r, verified).resultRef)).json(VerificationResult.self)
            XCTAssertEqual(flag.result["verified"], .bool(true))
            XCTAssertNil(flag.result["address"])
            XCTAssertNil(flag.result["given_name"])
        }
    }

    func testTheWalletMethodIsOfferedOnlyWhenItCanRun() async throws {
        try await withVerify(wallet: false) { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            let shown = try await prompt(r, id)
            XCTAssertEqual(shown.methods.map(\.available), [false, true])
            try await consent(r, id)
            try await eq(try await walletBegin(r, id).status, .serviceUnavailable)
        }
        try await withVerify(didit: false) { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            try await eq(try await prompt(r, id).methods.map(\.available), [true, false])
            try await consent(r, id)
            try await eq(try await h.signedPost(r.consumer, "/v1/verifications/\(id)/document/begin", EmptyBody()).status, .serviceUnavailable)
        }
    }

    // MARK: Document method (Didit)

    func signedWebhook(_ r: Rig, session: String, status: String = "Approved", eventId: String = UUID().uuidString.lowercased(), at: Date? = nil, secret: String = DiditWebhookTests.secret,
                       previous: String? = nil, decisionInBody: Bool = false) async throws -> HTTPResult {
        let now = at ?? r.h.clock.now()
        var object: [String: JSONValue] = ["event_id": .string(eventId), "webhook_type": .string("status.updated"), "timestamp": .integer(Int64(now.timeIntervalSince1970)),
                                           "session_id": .string(session), "status": .string(status), "application_id": .string(UUID().uuidString.lowercased()), "environment": .string("live")]
        if decisionInBody { object["decision"] = .object(["status": .string("Approved"), "id_verifications": .array([.object(["first_name": .string("Forged"), "date_of_birth": .string("1900-01-01")])])]) }
        let parsed = JSONValue.object(object)
        let body = try JSONEncoder().encode(parsed)
        func mac(_ key: String) -> String { Hex.encode(HMAC<SHA256>.authenticationCode(for: DiditCanonicalJSON.serialize(parsed), using: SymmetricKey(data: Data(key.utf8)))) }
        var headers = ["X-Signature-V2": mac(secret), "X-Timestamp": String(Int64(now.timeIntervalSince1970))]
        if let previous { headers["X-Signature-V2-Previous"] = mac(previous) }
        return try await r.h.request(.POST, "/v1/providers/didit/webhook", headers: headers, body: body)
    }

    func beginDocument(_ r: Rig, _ id: VerificationRequestID) async throws -> (start: DocumentAttemptStart, session: String) {
        let response = try await r.h.signedPost(r.consumer, "/v1/verifications/\(id)/document/begin", EmptyBody())
        XCTAssertEqual(response.status, .ok, response.text)
        let start = try response.json(DocumentAttemptStart.self)
        let session = try XCTUnwrap(r.didit.session(forVendorData: start.attemptId.uuidString.lowercased()))
        return (start, session)
    }

    func testADocumentVerificationEndToEndMinimizesThenPurges() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r, years: 21)
            try await consent(r, id)
            let (start, session) = try await beginDocument(r, id)
            // The session is created for the configured workflow with an opaque vendor_data: the attempt id, never personal data.
            XCTAssertEqual(fake.created.count, 1)
            XCTAssertEqual(fake.created[0].workflow, "workflow-identity")
            XCTAssertEqual(fake.created[0].vendorData, start.attemptId.uuidString.lowercased())
            XCTAssertTrue(start.sessionToken.hasPrefix("tok_"))
            // The provider finishes; the webhook only says which session changed. The decision is re-fetched, whatever the body claims.
            fake.setDecision(session, FakeDidit.decision(session: session, vendorData: start.attemptId.uuidString.lowercased()))
            let hook = try await signedWebhook(r, session: session, decisionInBody: true)
            XCTAssertEqual(hook.status, .ok, hook.text)
            XCTAssertEqual(fake.fetches, 1, "the decision is always re-fetched")
            let finished = try await resource(r, id)
            XCTAssertEqual(finished.status, .completed)
            let fetched = try await result(r, try XCTUnwrap(finished.resultRef)).json(VerificationResult.self)
            XCTAssertEqual(fetched.outcome, .verified)
            XCTAssertEqual(fetched.result["meets_threshold"], .bool(true))
            XCTAssertEqual(fetched.result["assurance"], .string("document_and_biometric_match"))
            XCTAssertNil(fetched.result["given_name"])
            // Minimize-then-purge: the session and the user are deleted with privacy_erasure and the deletion is recorded.
            XCTAssertEqual(fake.deleted.map(\.session), [session])
            XCTAssertEqual(fake.deleted.first?.instruction, "viadere-" + start.attemptId.uuidString.lowercased())
            XCTAssertEqual(fake.usersDeleted, [start.attemptId.uuidString.lowercased()])
            let attempt = try unwrap(try await VerificationAttemptRecord.query(on: h.db).first())
            XCTAssertEqual(attempt.purgeStatus, "done")
            XCTAssertNotNil(attempt.purgedAt)
            XCTAssertEqual(attempt.status, "succeeded")
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == "verification.provider_purged").count(), 1)
            // No document field, score, URL or token is in the database or the audit log.
            try await assertNoEvidence(h)
            let provenance = try ViadereJSON.decode(VerificationProvenance.self, from: Data(try unwrap(try await VerificationResultRecord.query(on: h.db).first()?.provenance).utf8))
            XCTAssertEqual(provenance.method, .diditDocumentLiveness)
            XCTAssertEqual(provenance.verifier, "didit")
            XCTAssertEqual(provenance.issuer, "didit:USA")
            XCTAssertEqual(provenance.revocation, .notApplicable)
            XCTAssertEqual(provenance.assurance.evidence, .documentWithBiometricMatch)
            // A duplicate delivery (same event_id) and a later app call change nothing and fetch nothing.
            let eventCount = try await VerificationProviderEventRecord.query(on: h.db).count()
            XCTAssertEqual(eventCount, 1)
            let app = try await h.signedPost(r.consumer, "/v1/verifications/\(id)/document/complete", DocumentAttemptComplete(attemptId: start.attemptId))
            XCTAssertEqual(try attemptOutcome(app).status, .released)
            XCTAssertEqual(fake.fetches, 1)
            XCTAssertEqual(fake.deleted.count, 1)
            try await eq(try await VerificationResultRecord.query(on: h.db).count(), 1)
        }
    }

    func testADuplicateWebhookDeliveryIsIdempotent() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            try await consent(r, id)
            let (start, session) = try await beginDocument(r, id)
            fake.setDecision(session, FakeDidit.decision(session: session, vendorData: start.attemptId.uuidString.lowercased()))
            let eventId = "evt-1"
            for _ in 0..<3 { try await eq(try await signedWebhook(r, session: session, eventId: eventId).status, .ok) }
            XCTAssertEqual(fake.fetches, 1)
            XCTAssertEqual(fake.deleted.count, 1)
            try await eq(try await VerificationResultRecord.query(on: h.db).count(), 1)
            try await eq(try await WebhookDeliveryRecord.query(on: h.db).filter(\.$eventType == "verification.completed").count(), 1, "the business is told once")
        }
    }

    func testWebhookAuthenticationIsEnforcedOnTheRoute() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            try await consent(r, id)
            let (start, session) = try await beginDocument(r, id)
            fake.setDecision(session, FakeDidit.decision(session: session, vendorData: start.attemptId.uuidString.lowercased()))
            // Wrong secret, stale timestamp, no signature: all the same 403, none fetches or concludes anything.
            try await eq(try await signedWebhook(r, session: session, secret: "whsec_wrong").status, .forbidden)
            try await eq(try await signedWebhook(r, session: session, at: h.clock.now().addingTimeInterval(-301)).status, .forbidden)
            try await eq(try await h.request(.POST, "/v1/providers/didit/webhook", body: Data("{\"session_id\":\"\(session)\"}".utf8)).status, .forbidden)
            XCTAssertEqual(fake.fetches, 0)
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == "verification.webhook_rejected").count(), 3)
            try await eq(try await resource(r, id).status, .pending)
            // A rotated secret: the old one in the -Previous header is accepted during the overlap.
            let rotated = try await signedWebhook(r, session: session, secret: "whsec_new_secret", previous: DiditWebhookTests.secret)
            XCTAssertEqual(rotated.status, .ok, rotated.text)
            try await eq(try await resource(r, id).status, .completed)
            // An unknown session is acknowledged without saying so.
            try await eq(try await signedWebhook(r, session: UUID().uuidString.lowercased()).status, .ok)
        }
    }

    func testADeclinedOrIncompleteDocumentCheckIsNotVerifiedAndStillPurged() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            try await consent(r, id)
            var sessions: [(DocumentAttemptStart, String)] = []
            for variant in 0..<3 {
                let (start, session) = try await beginDocument(r, id)
                let vendor = start.attemptId.uuidString.lowercased()
                switch variant {
                case 0: fake.setDecision(session, FakeDidit.decision(session: session, vendorData: vendor, status: "Declined"))
                case 1: fake.setDecision(session, FakeDidit.decision(session: session, vendorData: vendor, face: nil)) // approved overall, no face match
                default: fake.setDecision(session, FakeDidit.decision(session: session, vendorData: vendor, dob: "2015-01-01"))   // approved, but under 21
                }
                try await eq(try await signedWebhook(r, session: session).status, .ok)
                sessions.append((start, session))
            }
            // Every session was purged whatever the decision.
            XCTAssertEqual(Set(fake.deleted.map(\.session)), Set(sessions.map(\.1)))
            try await eq(try await VerificationAttemptRecord.query(on: h.db).filter(\.$purgeStatus == "done").count(), 3)
            // Three failures end the request; the business sees only not_verified.
            let ended = try await resource(r, id)
            XCTAssertEqual(ended.status, .completed)
            try await eq(try await result(r, try XCTUnwrap(ended.resultRef)).json(VerificationResult.self).outcome, .notVerified)
            try await assertNoEvidence(h)
        }
    }

    func testASelfieAgeEstimateIsNotAVerifiedAge() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            try await consent(r, id)
            let (start, session) = try await beginDocument(r, id)
            var decision = FakeDidit.decision(session: session, vendorData: start.attemptId.uuidString.lowercased(), face: nil, age: 31.0)
            decision["id_verifications"] = nil
            fake.setDecision(session, decision)
            try await eq(try await signedWebhook(r, session: session).status, .ok)
            let attempt = try unwrap(try await VerificationAttemptRecord.query(on: h.db).first())
            XCTAssertEqual(attempt.failureReason, "estimate_only")
            try await eq(try await VerificationResultRecord.query(on: h.db).filter(\.$outcome == "verified").count(), 0)
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == "verification.document_rejected").first()?.metadataJSON.contains("\"estimate_only\":\"true\""), true)
            try await eq(try await VerificationRequestRecord.find(id.uuid, on: h.db)?.status, "consented", "the person may try another method")
            try await assertNoEvidence(h)
        }
    }

    func testAProviderOutageFailsCleanly() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            try await consent(r, id)
            // Session creation fails: a clean 503, a failed attempt, nothing collected, nothing disclosed.
            fake.failCreate(1)
            let down = try await h.signedPost(r.consumer, "/v1/verifications/\(id)/document/begin", EmptyBody())
            XCTAssertEqual(down.status, .serviceUnavailable)
            try await eq(try await VerificationAttemptRecord.query(on: h.db).first()?.status, "failed")
            try await eq(try await VerificationAttemptRecord.query(on: h.db).first()?.failureReason, "provider_unavailable")
            try await eq(try await VerificationResultRecord.query(on: h.db).count(), 0)
            expectNil(try await DisclosureReceiptRecord.query(on: h.db).first()?.consumedAt)
            // The decision cannot be fetched: the webhook answers 5xx (Didit retries), the attempt is still open, nothing was disclosed.
            let (start, session) = try await beginDocument(r, id)
            fake.setDecision(session, FakeDidit.decision(session: session, vendorData: start.attemptId.uuidString.lowercased()))
            fake.failDecision(1)
            try await eq(try await signedWebhook(r, session: session, eventId: "e1").status, .serviceUnavailable)
            try await eq(try await VerificationAttemptRecord.query(on: h.db).filter(\.$id == start.attemptId).first()?.status, "issued")
            try await eq(try await VerificationResultRecord.query(on: h.db).count(), 0)
            try await eq(try await VerificationProviderEventRecord.query(on: h.db).count(), 0, "a failed delivery is not recorded as handled")
            // The retry succeeds.
            try await eq(try await signedWebhook(r, session: session, eventId: "e1").status, .ok)
            try await eq(try await resource(r, id).status, .completed)
        }
    }

    func testAFailedProviderPurgeIsRetriedUntilItSucceeds() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            try await consent(r, id)
            let (start, session) = try await beginDocument(r, id)
            fake.setDecision(session, FakeDidit.decision(session: session, vendorData: start.attemptId.uuidString.lowercased()))
            fake.failDelete(2)
            try await eq(try await signedWebhook(r, session: session).status, .ok)
            var attempt = try unwrap(try await VerificationAttemptRecord.query(on: h.db).first())
            XCTAssertEqual(attempt.purgeStatus, "failed")
            try await eq(try await resource(r, id).status, .completed, "the result stands; the purge is retried separately")
            h.clock.advance(by: 31)
            try await h.runJobs()
            attempt = try unwrap(try await VerificationAttemptRecord.query(on: h.db).first())
            XCTAssertEqual(attempt.purgeStatus, "failed", "one more failure")
            h.clock.advance(by: 61)
            try await h.runJobs()
            attempt = try unwrap(try await VerificationAttemptRecord.query(on: h.db).first())
            XCTAssertEqual(attempt.purgeStatus, "done")
            XCTAssertEqual(fake.deleted.map(\.session), [session])
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == "verification.provider_purge_failed").count(), 2)
        }
    }

    func testAbandonedProviderSessionsArePurgedWhenTheRequestExpires() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            try await consent(r, id)
            let (_, session) = try await beginDocument(r, id)
            h.clock.advance(by: 301 + 61)
            try await h.runJobs()
            // The request ended as not_verified, the business was told, the abandoned session was deleted.
            let ended = try await resource(r, id)
            XCTAssertEqual(ended.status, .completed)
            try await eq(try await result(r, try XCTUnwrap(ended.resultRef)).json(VerificationResult.self).outcome, .notVerified)
            XCTAssertEqual(fake.deleted.map(\.session), [session])
            let hooks = try await WebhookDeliveryRecord.query(on: h.db).filter(\.$eventType == "verification.completed").all()
            XCTAssertEqual(hooks.count, 1)
            let event = try ViadereJSON.decode(WebhookEvent.self, from: try XCTUnwrap(WebhookService(db: h.db, ctx: h.ctx).deliveryBody(hooks[0])))
            XCTAssertEqual(Set(try XCTUnwrap(event.data.objectValue).keys), ["request_id", "result_ref"], "an expiry is announced exactly like any other end")
        }
    }

    func testDocumentBeginForTheDocumentMethodNeedsAnOpenConsentedRequest() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            try await consent(r, id)
            for _ in 0..<VerifyPolicy.maxAttemptsPerRequest { _ = try await beginDocument(r, id) }
            try await eq(try await h.signedPost(r.consumer, "/v1/verifications/\(id)/document/begin", EmptyBody()).status, .tooManyRequests)
            XCTAssertEqual(fake.created.count, VerifyPolicy.maxAttemptsPerRequest)
        }
    }

    // MARK: Results: window, expiry and the sandbox

    func testAResultExpiresAndIsErased() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            try await consent(r, id)
            _ = try await wallet(r, id, elements: ageOver(21))
            let ref = try await resource(r, id).resultRef!
            h.clock.advance(by: VerifyPolicy.resultValidity + 1)
            try await eq(try await result(r, ref).status, .gone)
            try await h.runJobs()
            try await eq(try await resultPayloadErased(h, id), true)
        }
    }

    func testSandboxRequestsCompleteWithASimulatedResultAndNeverReachRealPeople() async throws {
        try await withVerify { h, fake in
            let live = try await rig(h, fake)
            let test = try await h.makeBusiness(name: "Sandbox Shop", handle: "sandboxshop", live: false, capabilities: Capability.operational + Self.verifyCapabilities)
            let sandbox = try await h.sandboxRelationship(test)
            let ref = try await subjectRef(h, sandbox)
            let response = try await h.businessPost(test, "/v1/verification-requests", CreateVerificationRequest(subjectRef: ref, capability: .ageMinimum, parameters: ["years": .integer(21)],
                                                                                                             purposeCode: "age_restricted_access"), idempotencyKey: "s1")
            XCTAssertEqual(response.status, .created, response.text)
            let resource = try response.json(VerificationRequestResource.self)
            XCTAssertEqual(resource.status, .completed)
            let fetched = try await h.business(test, .GET, "/v1/verification-results/\(try XCTUnwrap(resource.resultRef))").json(VerificationResult.self)
            XCTAssertEqual(fetched.outcome, .verified)
            XCTAssertEqual(fetched.result["assurance"], .string("sandbox_simulated"))
            XCTAssertEqual(fetched.result["meets_threshold"], .bool(true))
            // A test-mode key cannot address a real customer, and a live key cannot address a sandbox customer.
            let real = try await h.businessPost(test, "/v1/verification-requests", CreateVerificationRequest(subjectRef: live.ref, capability: .ageMinimum, parameters: ["years": .integer(21)],
                                                                                                         purposeCode: "age_restricted_access"), idempotencyKey: "s2")
            XCTAssertEqual(real.status, .notFound)
            let sandboxViaLive = try await h.businessPost(live.b, "/v1/verification-requests", CreateVerificationRequest(subjectRef: ref, capability: .ageMinimum, parameters: ["years": .integer(21)],
                                                                                                                       purposeCode: "age_restricted_access"), idempotencyKey: "s3")
            XCTAssertEqual(sandboxViaLive.status, .notFound)
            // A simulated result can never conclude a live request.
            let id = try await createdID(live)
            try await consent(live, id)
            let record = try unwrap(try await VerificationRequestRecord.find(id.uuid, on: h.db))
            let service = VerifyService(db: h.db, ctx: h.ctx, runtime: h.app.verify)
            let fake = EvidenceClaims(method: .sandbox, issuer: "sandbox", verifiedAt: h.clock.now(), validUntil: h.clock.now().addingTimeInterval(600), revocation: .notApplicable, ageOver: [21: true])
            let outcome = try await service.conclude(record, claims: fake, source: "test")
            XCTAssertNotEqual(outcome.status, .released)
        }
    }

    func testTheBuiltResultNeverCarriesAnythingOutsideTheCatalog() throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        var claims = EvidenceClaims(method: .walletMdoc, issuer: "00112233aabbccdd", verifiedAt: now, validUntil: now.addingTimeInterval(3600), revocation: .notChecked)
        claims.ageOver = [21: true]
        claims.birthDate = AgeThreshold.Day(isoDate: "1980-01-01")
        claims.givenName = "Jane"
        claims.familyName = "Doe"
        claims.address = ["street": .string("1 Main")]
        claims.documentPresented = true
        for (capability, years) in [(Capability.ageMinimum, Int64(21)), (.identityName, 0), (.identityAddress, 0), (.identityVerified, 0)] {
            let params: [String: JSONValue] = capability == .ageMinimum ? ["years": .integer(years)] : [:]
            let built = try XCTUnwrap(ClaimsBuilder.build(capability: capability, parameters: params, claims: claims, audience: BusinessID(), now: now), "\(capability)")
            let definition = try XCTUnwrap(capability.definition)
            XCTAssertEqual(Set(built.values.keys), Set(definition.output.fieldNames), "\(capability) discloses exactly its output schema")
            XCTAssertEqual(definition.violations(in: built.values), [])
            if capability == .ageMinimum || capability == .identityVerified {
                for banned in CapabilityCatalog.personalDataFieldNames { XCTAssertNil(built.values[banned], "\(capability) must not carry \(banned)") }
            }
        }
        // An estimate or a method that cannot establish the claim builds nothing.
        var estimate = claims
        estimate.method = .diditAgeEstimation
        XCTAssertNil(ClaimsBuilder.build(capability: .ageMinimum, parameters: ["years": .integer(21)], claims: estimate, audience: BusinessID(), now: now))
        var contact = claims
        contact.method = .contactCode
        XCTAssertNil(ClaimsBuilder.build(capability: .identityName, parameters: [:], claims: contact, audience: BusinessID(), now: now))
        // Underage, and evidence that cannot answer, build nothing.
        var under = claims
        under.ageOver = [21: false]
        XCTAssertNil(ClaimsBuilder.build(capability: .ageMinimum, parameters: ["years": .integer(21)], claims: under, audience: BusinessID(), now: now))
        var silent = claims
        silent.ageOver = [:]
        silent.birthDate = nil
        XCTAssertNil(ClaimsBuilder.build(capability: .ageMinimum, parameters: ["years": .integer(21)], claims: silent, audience: BusinessID(), now: now))
        // Expired evidence builds nothing.
        var stale = claims
        stale.validUntil = now
        XCTAssertNil(ClaimsBuilder.build(capability: .ageMinimum, parameters: ["years": .integer(21)], claims: stale, audience: BusinessID(), now: now))
    }

    // MARK: End-to-end encrypted identity attributes (acceptance 4)

    func testIdentityAttributesAreSealedToTheBusinessKeyThePublishedInTheDirectory() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let keys = try await h.publishDirectory(r.b, hpke: true, signing: false)
            let id = try await createdID(r, capability: .identityName)
            try await consent(r, id)
            let names: [String: [(String, CBORValue)]] = [WalletElementPlan.isoNamespace: [("given_name", .text("Jane")), ("family_name", .text("Doe"))]]
            try await eq(try attemptOutcome(try await wallet(r, id, elements: names).result).status, .released)
            // At rest, Viadere holds no readable name: the clear payload has only the non-personal fields and the names are ciphertext.
            let row = try await unwrap(VerificationResultRecord.query(on: h.db).first())
            let clear = try ViadereJSON.decode(JSONValue.self, from: try h.ctx.cipher.open(try XCTUnwrap(row.payload), context: "verification_results.payload", rowId: row.id!))
            XCTAssertEqual(Set(try XCTUnwrap(clear.objectValue).keys), ["assurance", "issued_at", "expires_at", "audience"])
            XCTAssertFalse(try XCTUnwrap(row.encryptedPayload).contains("Jane"))
            XCTAssertEqual(row.encryptedKid, keys.hpke.publicKey.kid)
            try await assertNoEvidence(h)
            // The business retrieves the envelope and opens it with its own key.
            let ref = try await unwrap(resource(r, id).resultRef)
            let fetched = try await result(r, ref).json(VerificationResult.self)
            XCTAssertNil(fetched.result["given_name"])
            XCTAssertEqual(fetched.encryptedResultKid, keys.hpke.publicKey.kid)
            let envelope = try E2EEEnvelope.parse(try XCTUnwrap(Base64URL.decode(try XCTUnwrap(fetched.encryptedResult))))
            let opened = try E2EE.open(envelope, using: keys.hpke, expecting: E2EEExpectation(purpose: VerificationResult.e2eePurpose, requestId: id.description,
                                                                                            sender: VerificationResult.e2eeSender, recipient: VerificationResult.e2eeRecipient(r.b.id)), now: h.clock.now())
            let sensitive = try XCTUnwrap(try ViadereJSON.decode(JSONValue.self, from: opened).objectValue)
            XCTAssertEqual(sensitive["given_name"], .string("Jane"))
            XCTAssertEqual(sensitive["family_name"], .string("Doe"))
            XCTAssertEqual(CapabilityCatalog.definition(for: .identityName)!.violations(in: fetched.result), [])
            // Another business's key (or another request) cannot open it.
            XCTAssertThrowsError(try E2EE.open(envelope, using: SoftwareE2EEPrivateKey(), expecting: E2EEExpectation(purpose: VerificationResult.e2eePurpose), now: h.clock.now()))
            XCTAssertThrowsError(try E2EE.open(envelope, using: keys.hpke, expecting: E2EEExpectation(purpose: VerificationResult.e2eePurpose, requestId: VerificationRequestID().description), now: h.clock.now()))
            // After the one retrieval both parts are erased.
            let after = try await unwrap(VerificationResultRecord.query(on: h.db).first())
            XCTAssertNil(after.payload)
            XCTAssertNil(after.encryptedPayload)
            try await assertNoEvidence(h)
            try await eq(try await result(r, ref).status, .gone)
        }
    }

    func testWithoutAPublishedKeyIdentityIsAuthenticatedRetrievalAndCanBeRequiredToBeEncrypted() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let id = try await createdID(r, capability: .identityName)
            try await consent(r, id)
            _ = try await wallet(r, id, elements: [WalletElementPlan.isoNamespace: [("given_name", .text("Jane")), ("family_name", .text("Doe"))]])
            let fetched = try await result(r, try await unwrap(resource(r, id).resultRef)).json(VerificationResult.self)
            XCTAssertEqual(fetched.result["given_name"], .string("Jane"))
            XCTAssertNil(fetched.encryptedResult)
        }
        try await withHarness({ config in
            config.verify.enabled = true
            config.verify.requireEncryptedIdentity = true
        }) { h in
            let r = try await rig(h, FakeDidit())
            // Identity attributes are refused until the business has a published encryption key; an age threshold needs none.
            let refused = try await create(r, capability: .identityName)
            XCTAssertEqual(refused.status, .unprocessableEntity, refused.text)
            try await eq(try await create(r).status, .created)
            _ = try await h.publishDirectory(r.b, hpke: true, signing: false)
            try await eq(try await create(r, capability: .identityName).status, .created)
        }
    }

    // MARK: Dashboard card (counts by outcome only)

    func testTheDashboardShowsCountsByOutcomeAndNothingElse() async throws {
        try await withVerify { h, fake in
            let owner = try await h.verifiedOwner(email: "verify-owner@example.com", org: "Spirits Co", handle: "spiritsco")
            try await h.entitle(owner.businessId, Self.verifyCapabilities)
            let b = try await h.testBusiness(owner.businessId)
            let key = try await BusinessAPIKeys.issue(businessId: owner.businessId, name: "v", live: true, scopes: BusinessAPIKeys.Scope.all, capabilities: Capability.operational + Self.verifyCapabilities, now: h.clock.now(), on: h.db).key
            let consumer = try await h.readyConsumer()
            let relationship = try await h.connect(consumer, to: b)
            let hook = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/v")!, events: [.verificationCompleted]), key: key)
            let rig = Rig(h: h, b: TestBusiness(record: b.record, key: key, summary: b.summary), consumer: consumer, relationship: relationship,
                          ref: try await subjectRef(h, relationship), didit: fake, hook: try hook.json(WebhookSecretResponse.self).subscription.id.uuid, hookSecret: "")
            let a = try await createdID(rig), declined = try await createdID(rig), pending = try await createdID(rig)
            try await consent(rig, a)
            try await eq(try attemptOutcome(try await wallet(rig, a, elements: ageOver(21), flaws: .init()).result).status, .released)
            try await eq(try await h.signedPost(consumer, "/v1/verifications/\(declined)/decline", EmptyBody()).status, .ok)
            _ = pending
            let counts = try await VerifyDashboard.counts(db: h.db, ctx: h.ctx, businessId: owner.businessId, days: 30)
            XCTAssertEqual(counts.map(\.capability), [.ageMinimum])
            XCTAssertEqual(counts.first?.counts, VerifyDashboard.Counts(verified: 1, notVerified: 1, pending: 1))
            let page = try await h.page("/dashboard", owner.session).text
            XCTAssertTrue(page.contains("Verify"), "the entitled business sees the card")
            XCTAssertTrue(page.contains(">3</div><div class=\"l\">Verification requests"), page)
            XCTAssertTrue(page.contains(">1</div><div class=\"l\">Verified"))
            // Counts only: no reference, no id, no purpose of any customer.
            for secret in [rig.ref.rawValue, a.description, consumer.id.description, "age_restricted_access"] { XCTAssertFalse(page.contains(secret), secret) }
        }
        try await withVerify { h, _ in
            let owner = try await h.verifiedOwner(email: "plain-owner@example.com", org: "Plain Co", handle: "plainco")
            let page = try await h.page("/dashboard", owner.session).text
            XCTAssertFalse(page.contains("Verification requests"), "no Verify capability, no Verify card")
        }
    }

    // MARK: Account deletion

    func testAccountDeletionRemovesVerificationDataAndStillPurgesTheProvider() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let done = try await createdID(r)
            try await consent(r, done)
            _ = try await wallet(r, done, elements: ageOver(21))
            let open = try await createdID(r, years: 18)
            try await consent(r, open)
            let (_, session) = try await beginDocument(r, open)
            try await eq(try await h.signed(r.consumer, .DELETE, "/v1/account").status, .ok)
            try await eq(try await VerificationRequestRecord.query(on: h.db).count(), 0)
            try await eq(try await VerificationResultRecord.query(on: h.db).count(), 0)
            // The open provider session survives only as an opaque attempt that still has to be deleted at the provider.
            let attempts = try await VerificationAttemptRecord.query(on: h.db).all()
            XCTAssertEqual(attempts.count, 1)
            XCTAssertEqual(attempts.first?.providerSessionId, session)
            try await h.runJobs()
            XCTAssertEqual(fake.deleted.map(\.session), [session])
            try await h.runJobs()
            try await eq(try await VerificationAttemptRecord.query(on: h.db).count(), 0)
        }
    }
}
