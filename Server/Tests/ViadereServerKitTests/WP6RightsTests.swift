@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Rights workflows (LEG-PR-004): the consumer data export (device-signed, asynchronous, sealed to the device, nothing by email) and the tenant
/// export and deletion requests.
final class WP6RightsTests: XCTestCase {
    private func request(_ h: TestHarness, _ consumer: TestConsumer, key: SoftwareE2EEPrivateKey) async throws -> HTTPResult {
        try await h.signedPost(consumer, APIRoutes.accountExportCreate.template, AccountExportRequest(recipientKey: key.publicKey.base64URL))
    }

    /// The same device after time passed: a fresh access token (they live minutes).
    private func renewed(_ h: TestHarness, _ consumer: TestConsumer) async throws -> TestConsumer {
        var next = consumer
        let result = try await h.refresh(consumer)
        XCTAssertEqual(result.status, .ok, result.text)
        next.session = try result.json(AuthSession.self)
        return next
    }

    // MARK: Consumer export

    func testConsumerExportIsDeviceSignedAsynchronousSealedToTheDeviceAndNeverEmailed() async throws {
        try await withHarness { h in
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let original = try await h.readyConsumer()
            let consumer0 = original
            let relationship = try await h.connect(consumer0, to: business)
            _ = try await h.businessPost(business, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: relationship.id, body: "Private note QZ4417", idempotencyKey: "m1"))
            let key = SoftwareE2EEPrivateKey()
            // A device inside its new-device cool-down cannot ask (the same bar as deleting the account).
            let secondDevice = try await h.enrollDevice(consumer0, name: "Second phone")
            let cooling = try await request(h, secondDevice, key: key)
            XCTAssertEqual(cooling.status, .forbidden, cooling.text)
            h.clock.advance(by: 25 * 3600)
            let consumer = try await renewed(h, consumer0)
            // Not signed by the device: refused.
            let unsigned = try await h.request(.POST, APIRoutes.accountExportCreate.template, headers: ["Authorization": "Bearer \(consumer.token)"],
                                               body: try ViadereJSON.encode(AccountExportRequest(recipientKey: key.publicKey.base64URL)))
            XCTAssertEqual(unsigned.status, .unauthorized)
            let badKey = try await h.signedPost(consumer, APIRoutes.accountExportCreate.template, AccountExportRequest(recipientKey: "AAAA"))
            XCTAssertEqual(badKey.status, .unprocessableEntity)
            let created = try await request(h, consumer, key: key)
            XCTAssertEqual(created.status, .accepted, created.text)
            let status = try created.json(AccountExportStatus.self)
            XCTAssertEqual(status.status, "queued")
            XCTAssertNil(status.downloadPath)
            // One at a time.
            let second = try await request(h, consumer, key: key)
            XCTAssertEqual(second.status, .conflict)
            // Not downloadable until the job ran.
            let early = try await h.signed(consumer, .GET, "/v1/account/exports/\(status.exportId)/download")
            XCTAssertEqual(early.status, .gone)
            let mailBefore = h.emails.sent.count
            let built = try await ConsumerExports(db: h.db, ctx: h.ctx).processQueued()
            XCTAssertEqual(built, 1)
            XCTAssertEqual(h.emails.sent.count, mailBefore, "no export, link or content goes by email")
            let ready = try await h.signed(consumer, .GET, "/v1/account/exports/\(status.exportId)")
            let readyStatus = try ready.json(AccountExportStatus.self)
            XCTAssertEqual(readyStatus.status, "ready")
            let download = try await h.signed(consumer, .GET, try XCTUnwrap(readyStatus.downloadPath))
            XCTAssertEqual(download.status, .ok, download.text)
            // What the server stored and sent is ciphertext: the message text is nowhere in it.
            XCTAssertFalse(download.text.contains("QZ4417"))
            let stored = try await XCTUnwrapAsync(await ConsumerExportRecord.find(UUID(uuidString: status.exportId)!, on: h.db))
            XCTAssertFalse((stored.bundle ?? "").contains("QZ4417"))
            // Only the device's own key opens it, and the context pins purpose, request and sender.
            let bundle = try download.json(AccountExportBundle.self)
            var plaintext = Data()
            for chunk in bundle.envelopes {
                let envelope = try E2EEEnvelope.parse(try XCTUnwrap(Base64URL.decode(chunk)))
                plaintext += try E2EE.open(envelope, using: key, expecting: E2EEExpectation(purpose: "account-export", requestId: status.exportId, sender: "viadere"), now: h.clock.now())
                XCTAssertThrowsError(try E2EE.open(envelope, using: SoftwareE2EEPrivateKey(), expecting: E2EEExpectation(purpose: "account-export"), now: h.clock.now()))
                XCTAssertThrowsError(try E2EE.open(envelope, using: key, expecting: E2EEExpectation(purpose: "approve.request"), now: h.clock.now()))
            }
            let document = try XCTUnwrap(try JSONSerialization.jsonObject(with: plaintext) as? [String: Any])
            XCTAssertEqual(document["format"] as? String, "viadere-export-v1")
            let text = String(decoding: plaintext, as: UTF8.self)
            XCTAssertTrue(text.contains("QZ4417"), "the person's own message text is in their export")
            XCTAssertTrue(text.contains("Northwind Air"))
            for secret in [consumer.session.accessToken, consumer.session.refreshToken ?? "-", "signature", "tokenHash", "passkey"] { XCTAssertFalse(text.contains(secret), secret) }
            // Another consumer, and another device of the same account, cannot read the status or the bundle: a plain 404.
            let other = try await h.readyConsumer(name: "Someone Else")
            for who in [other] {
                let s = try await h.signed(who, .GET, "/v1/account/exports/\(status.exportId)")
                let d = try await h.signed(who, .GET, "/v1/account/exports/\(status.exportId)/download")
                XCTAssertEqual(s.status, .notFound)
                XCTAssertEqual(d.status, .notFound)
            }
            let otherDevice = try await renewed(h, secondDevice)
            let viaOtherDevice = try await h.signed(otherDevice, .GET, "/v1/account/exports/\(status.exportId)/download")
            XCTAssertEqual(viaOtherDevice.status, .notFound, "only the requesting device")
            // Downloads are limited, the bundle expires after seven days and is erased.
            for _ in 0..<4 { _ = try await h.signed(consumer, .GET, "/v1/account/exports/\(status.exportId)/download") }
            let tooMany = try await h.signed(consumer, .GET, "/v1/account/exports/\(status.exportId)/download")
            XCTAssertEqual(tooMany.status, .gone)
            h.clock.advance(by: 8 * 86_400)
            _ = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            let erased = try await ConsumerExportRecord.find(stored.id!, on: h.db)
            XCTAssertNil(erased?.bundle, "the sealed bundle is erased at expiry")
            let audit = try await h.auditActions()
            XCTAssertTrue(audit.contains("account.export_requested") && audit.contains("account.export_ready") && audit.contains("account.export_downloaded"))
        }
    }

    func testConsumerExportIsRateLimitedPerDay() async throws {
        try await withHarness { h in
            let first = try await h.readyConsumer()
            h.clock.advance(by: 25 * 3600)
            let consumer = try await renewed(h, first)
            let key = SoftwareE2EEPrivateKey()
            var statuses: [HTTPStatus] = []
            for _ in 0..<4 {
                statuses.append(try await request(h, consumer, key: key).status)
                _ = try await ConsumerExports(db: h.db, ctx: h.ctx).processQueued()
            }
            XCTAssertEqual(statuses, [.accepted, .accepted, .accepted, .tooManyRequests])
        }
    }

    // MARK: Tenant export and deletion

    func testTenantExportIsSealedExpiresAndContainsNoSecretsOrCustomerData() async throws {
        try await withHarness { h in
            let (owner, account, businessId) = try await h.verifiedOwner()
            let key = try await h.newKey(owner, name: "prod key", scopes: ["webhooks:manage"])
            let hook = try await h.apiPost(key, "/v1/business/webhooks", json: try ViadereJSON.encode(CreateWebhookRequest(url: URL(string: "https://hooks.acme.example/in")!, events: [.messageReceived])))
            let hookSecret = try hook.json(WebhookSecretResponse.self).secret
            let consumer = try await h.readyConsumer(name: "Pat Customer")
            // Roles: only an Owner or Organization Admin may ask; an analyst cannot even see the page.
            let analyst = try await h.addMember(owner: owner, role: .analyst, email: "analyst@example.com").session
            let refused = try await h.formPost("/dashboard/compliance/requests/export", analyst)
            XCTAssertEqual(refused.status, .forbidden)
            try await h.dashReauth(owner, account)
            let requested = try await h.formPost("/dashboard/compliance/requests/export", owner)
            XCTAssertEqual(requested.status, .seeOther, requested.text)
            let record = try await XCTUnwrapAsync(await DataRequestRecord.query(on: h.db).filter(\.$businessId == businessId).filter(\.$kind == "export").first())
            XCTAssertEqual(record.status, "ready")
            XCTAssertFalse((record.artifact ?? "").contains("prod key"), "sealed at rest")
            try await h.dashReauth(owner, account)
            let download = try await h.formPost("/dashboard/compliance/requests/\(record.id!.uuidString.lowercased())/download", owner)
            XCTAssertEqual(download.status, .ok, download.text)
            XCTAssertEqual(download.headers.first(name: .contentType)?.hasPrefix("application/json"), true)
            XCTAssertEqual(download.headers.first(name: .contentDisposition)?.hasPrefix("attachment"), true)
            XCTAssertTrue(download.headers.first(name: "Content-Security-Policy")?.contains("sandbox") ?? false)
            let text = download.text
            XCTAssertTrue(text.contains("prod key"), "credential metadata is included")
            for secret in [key, hookSecret, SecureToken.hash(key), "Pat Customer", consumer.token] { XCTAssertFalse(text.contains(secret), "export leaks \(secret.prefix(8))")}
            XCTAssertFalse(text.contains("vdk_"))
            // Expires after 24 hours and cannot be fetched again; the retention job erases the artifact.
            h.clock.advance(by: 25 * 3600)
            let relogin = try await h.dashLogin(account)
            let owner2 = try XCTUnwrap(relogin.session)
            let late = try await h.formPost("/dashboard/compliance/requests/\(record.id!.uuidString.lowercased())/download", owner2)
            XCTAssertEqual(late.status, .gone)
            _ = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            let after = try await XCTUnwrapAsync(await DataRequestRecord.find(record.id!, on: h.db))
            XCTAssertNil(after.artifact)
            // Another organization cannot fetch it by guessing the id.
            let (other, otherAccount, _) = try await h.verifiedOwner(email: "o2@example.net", org: "Other Co", handle: "otherco")
            try await h.dashReauth(other, otherAccount)
            let cross = try await h.formPost("/dashboard/compliance/requests/\(record.id!.uuidString.lowercased())/download", other)
            XCTAssertNotEqual(cross.status, .ok)
        }
    }

    func testTenantDeletionIsRequestedByTheOwnerAndCarriedOutByAnOperatorAfterReview() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            let (owner, account, businessId) = try await h.verifiedOwner()
            let key = try await h.newKey(owner, scopes: ["webhooks:manage"])
            let admin = try await h.addMember(owner: owner, role: .orgAdmin, email: "admin@example.com")
            // Typing the word is required, and only an Owner may ask.
            try await h.dashReauth(owner, account)
            let wrong = try await h.formPost("/dashboard/compliance/requests/delete", owner, [("confirmation", "delete please")])
            XCTAssertNotEqual(wrong.status, .seeOther)
            let byAdmin = try await h.formPost("/dashboard/compliance/requests/delete", admin.session, [("confirmation", "DELETE")])
            XCTAssertNotEqual(byAdmin.status, .seeOther, "deleting the organization is the Owner's decision")
            let asked = try await h.formPost("/dashboard/compliance/requests/delete", owner, [("confirmation", "DELETE")])
            XCTAssertEqual(asked.status, .seeOther, asked.text)
            let twice = try await h.formPost("/dashboard/compliance/requests/delete", owner, [("confirmation", "DELETE")])
            XCTAssertNotEqual(twice.status, .seeOther)
            let request = try await XCTUnwrapAsync(await DataRequestRecord.query(on: h.db).filter(\.$kind == "delete").first())
            XCTAssertEqual(request.status, "requested")
            // Nothing happens until an operator decides: the key still works.
            let still = try await h.apiGet(key, "/v1/business/webhooks")
            XCTAssertEqual(still.status, .ok)
            // An operator can reject with a note, or complete it.
            let rejected = try await h.formPost("/operator/data-requests/\(request.id!.uuidString.lowercased())/reject", op, [("note", "Please confirm with the account owner by phone")])
            XCTAssertEqual(rejected.status, .seeOther, rejected.text)
            let afterReject = try await XCTUnwrapAsync(await DataRequestRecord.find(request.id!, on: h.db))
            XCTAssertEqual(afterReject.status, "rejected")
            try await h.dashReauth(owner, account)
            _ = try await h.formPost("/dashboard/compliance/requests/delete", owner, [("confirmation", "DELETE")])
            let second = try await XCTUnwrapAsync(await DataRequestRecord.query(on: h.db).filter(\.$kind == "delete").filter(\.$status == "requested").first())
            let done = try await h.formPost("/operator/data-requests/\(second.id!.uuidString.lowercased())/complete", op)
            XCTAssertEqual(done.status, .seeOther, done.text)
            // Keys revoked, the team signed out, the organization ended, the public identity stays reserved.
            let revokedKey = try await h.apiGet(key, "/v1/business/webhooks")
            XCTAssertEqual(revokedKey.status, .unauthorized)
            let ownerAfter = try await h.page("/dashboard", owner)
            XCTAssertNotEqual(ownerAfter.status, .ok)
            let business = try await XCTUnwrapAsync(await BusinessRecord.find(businessId, on: h.db))
            XCTAssertEqual(business.status, .revoked)
            XCTAssertEqual(business.displayName, "Deleted business")
            let handles = try await BusinessHandleRecord.query(on: h.db).filter(\.$businessId == businessId).count()
            XCTAssertEqual(handles, 1, "handles are never released")
            let actions = try await h.auditActions(businessId)
            XCTAssertTrue(actions.contains("tenant.deletion_requested"))
        }
    }
}
