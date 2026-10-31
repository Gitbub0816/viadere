import Fluent
import SQLKit
import Foundation
import Vapor
import XCTVapor
import XCTest
@testable import ViadereCore
@testable import ViadereServerKit

/// Customer profiles with selective sharing (docs/PROFILES.md, SECURITY.md §2.97). Each test reproduces an exploit path or a privacy promise.
final class ProfileTests: XCTestCase {
    // MARK: Fixtures

    /// A verified business allowed `categories` by an operator (as `ProfileCategoryService.decide` would, via `EntitlementService`).
    private func business(_ h: TestHarness, _ name: String, _ handle: String, categories: [ProfileCategory], live: Bool = true) async throws -> TestBusiness {
        let b = try await h.makeBusiness(name: name, handle: handle, live: live)
        for category in categories {
            try await EntitlementService(db: h.db, ctx: h.ctx).grant(businessId: b.id.uuid, profileCategory: category, actor: .system("test"),
                                                                     justification: "Test fixture: profile category \(category.rawValue).", reviewReference: "TEST-REVIEW-1")
        }
        return b
    }

    private func put<T: Encodable>(_ h: TestHarness, _ c: TestConsumer, _ path: String, _ body: T) async throws -> HTTPResult {
        try await h.signed(c, .PUT, path, body: try ViadereJSON.encode(body))
    }

    private func setProfile(_ h: TestHarness, _ c: TestConsumer, _ entries: [ProfileFieldEntry]) async throws {
        let result = try await put(h, c, APIRoutes.profilePut.template, ProfileUpdateRequest(set: entries))
        XCTAssertEqual(result.status, .ok, result.text)
    }

    private func subject(_ h: TestHarness, _ b: TestBusiness, _ c: TestConsumer) -> SubjectRef {
        h.ctx.subjects.subjectRef(businessId: b.id, consumerId: c.id)
    }

    private func read(_ h: TestHarness, _ b: TestBusiness, _ ref: SubjectRef, key: String? = nil) async throws -> HTTPResult {
        try await h.business(b, .GET, "/v1/business/profiles/\(ref.rawValue)", key: key)
    }

    private func grant(_ h: TestHarness, _ c: TestConsumer, _ b: TestBusiness, _ keys: [String]) async throws -> HTTPResult {
        try await put(h, c, "/v1/businesses/\(b.id)/profile-access", ProfileAccessUpdate(grantedKeys: keys))
    }

    private func request(_ h: TestHarness, _ b: TestBusiness, _ ref: SubjectRef, _ keys: [String], purpose: String = "To send your booking confirmations.",
                         key: String? = nil) async throws -> HTTPResult {
        try await h.businessPost(b, APIRoutes.businessProfileRequestCreate.template, CreateProfileRequest(subjectRef: ref, fieldKeys: keys, purpose: purpose),
                                 key: key, idempotencyKey: UUID().uuidString)
    }

    private let sample: [ProfileFieldEntry] = [
        ProfileFieldEntry(key: "personal.given_name", value: .text("Jane")), ProfileFieldEntry(key: "personal.family_name", value: .text("Doe")),
        ProfileFieldEntry(key: "contact.email", value: .text("jane.secret@example.com")),
        ProfileFieldEntry(key: "travel.frequent_flyer", entry: "ua", value: .text("UA778899")),
        ProfileFieldEntry(key: "birthdate.date", value: .text("1990-05-04")),
    ]

    // MARK: Access

    func testWithoutAGrantABusinessReadsOnlyThePublicName() async throws {
        try await withHarness { h in
            let b = try await self.business(h, "Northwind Air", "northwindair", categories: [.contact, .personal, .travel])
            let jane = try await h.readyConsumer(name: "Jane Doe")
            try await self.setProfile(h, jane, self.sample)
            try await h.connect(jane, to: b)
            let result = try await self.read(h, b, self.subject(h, b, jane))
            XCTAssertEqual(result.status, .ok, result.text)
            XCTAssertEqual(result.headers.first(name: .cacheControl), "no-store")
            let view = try result.json(BusinessProfileView.self)
            XCTAssertEqual(view.publicName, "Jane D.")
            XCTAssertTrue(view.fields.isEmpty)
            XCTAssertFalse(result.text.contains("jane.secret"))
            XCTAssertFalse(result.text.contains("UA778899"))
            XCTAssertFalse(result.text.contains("Doe"))
        }
    }

    func testAGrantToBusinessANeverExposesDataToBusinessB() async throws {
        try await withHarness { h in
            let a = try await self.business(h, "Northwind Air", "northwindair", categories: [.contact])
            let other = try await self.business(h, "Southwind Air", "southwindair", categories: [.contact])
            let jane = try await h.readyConsumer(name: "Jane Doe")
            try await self.setProfile(h, jane, self.sample)
            try await h.connect(jane, to: a)
            try await h.connect(jane, to: other)
            try await eq(try await self.grant(h, jane, a, ["contact.email"]).status, .ok)
            let viewA = try await self.read(h, a, self.subject(h, a, jane)).json(BusinessProfileView.self)
            XCTAssertEqual(viewA.fields.map(\.value), [.text("jane.secret@example.com")])
            // B sees nothing beyond the public name, and A's subject_ref means nothing to B.
            let viewB = try await self.read(h, other, self.subject(h, other, jane))
            XCTAssertFalse(viewB.text.contains("jane.secret"))
            XCTAssertTrue(try viewB.json(BusinessProfileView.self).fields.isEmpty)
            XCTAssertNotEqual(self.subject(h, a, jane), self.subject(h, other, jane))
            try await eq(try await self.read(h, other, self.subject(h, a, jane)).status, .notFound)
        }
    }

    func testRevocationIsImmediateAndTheWebhookCarriesNoValues() async throws {
        try await withHarness { h in
            let b = try await self.business(h, "Northwind Air", "northwindair", categories: [.contact])
            let hook = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/p")!,
                                                                                               events: [.profileAccessGranted, .profileAccessRevoked]))
            XCTAssertEqual(hook.status, .created, hook.text)
            try await WebhookSubscriptionRecord.query(on: h.db).filter(\.$businessId == b.id.uuid).set(\.$verifiedAt, to: h.clock.now()).update()
            let jane = try await h.readyConsumer(name: "Jane Doe")
            try await self.setProfile(h, jane, self.sample)
            try await h.connect(jane, to: b)
            _ = try await self.grant(h, jane, b, ["contact.email"])
            let ref = self.subject(h, b, jane)
            try await eq(try await self.read(h, b, ref).json(BusinessProfileView.self).fields.count, 1)
            // Revoke all: the very next read has nothing.
            let revoked = try await self.grant(h, jane, b, [])
            XCTAssertEqual(revoked.status, .ok, revoked.text)
            try await isTrue(try await self.read(h, b, ref).json(BusinessProfileView.self).fields.isEmpty)
            let deliveries = try await WebhookDeliveryRecord.query(on: h.db).filter(\.$businessId == b.id.uuid).all()
            let types = Set(deliveries.map(\.eventType))
            XCTAssertTrue(types.contains("profile.access_revoked"))
            XCTAssertTrue(types.contains("profile.access_granted"))
            for delivery in deliveries {
                let body = String(decoding: WebhookService(db: h.db, ctx: h.ctx).deliveryBody(delivery) ?? Data(), as: UTF8.self)
                XCTAssertTrue(body.contains("contact.email"))
                XCTAssertFalse(body.contains("jane.secret"), body)
            }
            // The customer has a receipt for both.
            let receipts = try await h.signed(jane, .GET, APIRoutes.profileReceiptsList.template).json([ProfileDisclosureReceipt].self)
            XCTAssertEqual(Set(receipts.map(\.action)), [.granted, .revoked])
            XCTAssertTrue(receipts.allSatisfy { $0.fieldKeys == ["contact.email"] && $0.businessName == "Northwind Air" })
        }
    }

    func testDisconnectEndsEveryGrant() async throws {
        try await withHarness { h in
            let b = try await self.business(h, "Northwind Air", "northwindair", categories: [.contact])
            let jane = try await h.readyConsumer(name: "Jane Doe")
            try await self.setProfile(h, jane, self.sample)
            let rel = try await h.connect(jane, to: b)
            _ = try await self.grant(h, jane, b, ["contact.email"])
            try await eq(try await h.signed(jane, .DELETE, "/v1/relationships/\(rel.id)").status, .ok)
            try await eq(try await ProfileGrantRecord.query(on: h.db).filter(\.$revokedAt == nil).count(), 0)
            try await eq(try await self.read(h, b, self.subject(h, b, jane)).status, .notFound)
        }
    }

    // MARK: Category entitlements (no category by default, request and read time)

    func testNoCategoryIsAllowedByDefaultAndRequestsOutsideGrantedCategoriesAreRejected() async throws {
        try await withHarness { h in
            let plain = try await self.business(h, "Plain Shop", "plainshop", categories: [])
            let contactOnly = try await self.business(h, "Contact Shop", "contactshop", categories: [.contact])
            let jane = try await h.readyConsumer(name: "Jane Doe")
            try await h.connect(jane, to: plain)
            try await h.connect(jane, to: contactOnly)
            let denied = try await self.request(h, plain, self.subject(h, plain, jane), ["contact.email"])
            XCTAssertEqual(denied.status, .forbidden, denied.text)
            XCTAssertEqual(denied.errorCode, .notEntitled)
            // Not entitled is decided before the subject is looked up: an unknown subject is the same 403.
            let unknownSubject = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 7, count: 32)))!
            try await eq(try await self.request(h, plain, unknownSubject, ["contact.email"]).status, .forbidden)
            let travel = try await self.request(h, contactOnly, self.subject(h, contactOnly, jane), ["contact.email", "travel.frequent_flyer"])
            XCTAssertEqual(travel.status, .forbidden, travel.text)
            XCTAssertTrue(travel.text.contains("travel.frequent_flyer"))
            // Unknown and banned keys are refused by the catalog.
            for key in ["health.allergies", "identity.ssn", "payment.card_number", "personal.religion"] {
                let refused = try await self.request(h, contactOnly, self.subject(h, contactOnly, jane), [key])
                XCTAssertEqual(refused.status, .unprocessableEntity, key)
            }
            try await eq(try await ProfileRequestRecord.query(on: h.db).count(), 0)
            // The customer cannot grant outside the business's categories either.
            let customer = try await self.grant(h, jane, contactOnly, ["travel.frequent_flyer"])
            XCTAssertEqual(customer.status, .unprocessableEntity, customer.text)
        }
    }

    func testAReadAfterTheOperatorRevokesTheCategoryReturnsNothingFromIt() async throws {
        try await withHarness { h in
            let b = try await self.business(h, "Northwind Air", "northwindair", categories: [.contact, .travel])
            let jane = try await h.readyConsumer(name: "Jane Doe")
            try await self.setProfile(h, jane, self.sample)
            try await h.connect(jane, to: b)
            _ = try await self.grant(h, jane, b, ["contact.email", "travel.frequent_flyer"])
            let ref = self.subject(h, b, jane)
            try await eq(Set(try await self.read(h, b, ref).json(BusinessProfileView.self).fields.map(\.key)), ["contact.email", "travel.frequent_flyer"])
            try await EntitlementService(db: h.db, ctx: h.ctx).revoke(businessId: b.id.uuid, profileCategory: .travel, actor: .system("test"),
                                                                      justification: "Travel use case ended.")
            let after = try await self.read(h, b, ref)
            XCTAssertEqual(try after.json(BusinessProfileView.self).fields.map(\.key), ["contact.email"])
            XCTAssertFalse(after.text.contains("UA778899"))
            // And it can no longer even ask for it.
            try await eq(try await self.request(h, b, ref, ["travel.seat_preference"]).status, .forbidden)
        }
    }

    func testOnboardingCannotSelfGrantACategory() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let b = try await h.testBusiness(businessId)
            let jane = try await h.readyConsumer(name: "Jane Doe")
            try await h.connect(jane, to: b)
            // The console step only records requests; a justification is required for travel.
            let page = try await h.page(ProfileConsole.path, owner)
            XCTAssertEqual(page.status, .ok, page.text)
            let missing = try await h.formPost(ProfileConsole.path, owner, [("categories[]", "travel")])
            XCTAssertNotEqual(missing.status, .seeOther, missing.text)
            let sent = try await h.formPost(ProfileConsole.path, owner, [("categories[]", "contact"), ("categories[]", "travel"),
                                                                         ("travel", "We book flights and need frequent-flyer numbers to credit miles.")])
            XCTAssertEqual(sent.status, .seeOther, sent.text)
            try await eq(try await ProfileCategoryRequestRecord.query(on: h.db).filter(\.$status == "pending").count(), 2)
            try await isTrue(try await EntitlementService(db: h.db, ctx: h.ctx).snapshot(businessId: businessId).profileCategories.isEmpty)
            try await eq(try await self.request(h, b, self.subject(h, b, jane), ["contact.email"]).status, .forbidden)
            // An operator decides; it can allow fewer than asked.
            let requests = try await ProfileCategoryService(db: h.db, ctx: h.ctx).requests(businessId: businessId)
            let contact = requests.first { $0.category == "contact" }!
            let travel = requests.first { $0.category == "travel" }!
            let operatorId = UUID()
            try await ProfileCategoryService(db: h.db, ctx: h.ctx).decide(businessId: businessId, requestId: contact.id!, approve: true, operatorId: operatorId,
                                                                          justification: "Contact details for booking confirmations.", reviewReference: nil)
            try await ProfileCategoryService(db: h.db, ctx: h.ctx).decide(businessId: businessId, requestId: travel.id!, approve: false, operatorId: operatorId,
                                                                          justification: "Not needed for this use case.", reviewReference: nil)
            try await eq(try await EntitlementService(db: h.db, ctx: h.ctx).snapshot(businessId: businessId).profileCategories, [.contact])
            let row = try await BusinessEntitlementRecord.query(on: h.db).filter(\.$kind == BusinessEntitlementRecord.profileCategoryKind).first()
            XCTAssertEqual(row?.grantedBy, operatorId.uuidString.lowercased())
            try await eq(try await self.request(h, b, self.subject(h, b, jane), ["contact.email"]).status, .created)
            // A decided request cannot be decided again, and a category nobody asked for cannot be decided at all.
            do {
                try await ProfileCategoryService(db: h.db, ctx: h.ctx).decide(businessId: businessId, requestId: travel.id!, approve: true, operatorId: operatorId,
                                                                              justification: "Changed my mind about travel access.", reviewReference: nil)
                XCTFail("decided twice")
            } catch let error as APIError { XCTAssertEqual(error.code, .conflict) }
            do {
                try await ProfileCategoryService(db: h.db, ctx: h.ctx).decide(businessId: businessId, requestId: UUID(), approve: true, operatorId: operatorId,
                                                                              justification: "Granting something never asked for.", reviewReference: nil)
                XCTFail("decided an unknown request")
            } catch let error as APIError { XCTAssertEqual(error.code, .notFound) }
        }
    }

    // MARK: Requests

    func testFieldByFieldApprovalOfARequestShownInAlerts() async throws {
        try await withHarness { h in
            let b = try await self.business(h, "Northwind Air", "northwindair", categories: [.contact, .travel])
            let jane = try await h.readyConsumer(name: "Jane Doe")
            try await self.setProfile(h, jane, self.sample)
            try await h.connect(jane, to: b)
            let ref = self.subject(h, b, jane)
            let created = try await self.request(h, b, ref, ["contact.email", "travel.frequent_flyer"], purpose: "To credit your miles.")
            XCTAssertEqual(created.status, .created, created.text)
            let resource = try created.json(ProfileRequestResource.self)
            let alerts = try await h.signed(jane, .GET, "/v1/alerts").json(AlertPage.self)
            XCTAssertTrue(alerts.items.contains { $0.source == .profileRequest && $0.target?.id == resource.id.description })
            let prompt = try await h.signed(jane, .GET, "/v1/profile/requests/\(resource.id)").json(ProfileRequestPrompt.self)
            XCTAssertEqual(prompt.purpose, "To credit your miles.")
            XCTAssertEqual(prompt.fields.map(\.key), ["contact.email", "travel.frequent_flyer"])
            // Approving something not requested is refused; partial approval works.
            try await eq(try await h.signedPost(jane, "/v1/profile/requests/\(resource.id)/answer", ProfileRequestAnswer(approvedKeys: ["work.title"])).status,
                         .unprocessableEntity)
            let answered = try await h.signedPost(jane, "/v1/profile/requests/\(resource.id)/answer", ProfileRequestAnswer(approvedKeys: ["travel.frequent_flyer"]))
            XCTAssertEqual(answered.status, .ok, answered.text)
            try await eq(try await h.signedPost(jane, "/v1/profile/requests/\(resource.id)/answer", ProfileRequestAnswer(approvedKeys: [])).status, .conflict)
            let status = try await h.business(b, .GET, "/v1/business/profile-requests/\(resource.id)").json(ProfileRequestResource.self)
            XCTAssertEqual(status.status, .answered)
            XCTAssertEqual(status.approvedKeys, ["travel.frequent_flyer"])
            let view = try await self.read(h, b, ref).json(BusinessProfileView.self)
            XCTAssertEqual(view.fields, [BusinessProfileField(key: "travel.frequent_flyer", entry: "UA", value: .text("UA778899"))])
        }
    }

    func testEveryBusinessSuppliedPurposeIsDisplayTextValidated() async throws {
        try await withHarness { h in
            let b = try await self.business(h, "Northwind Air", "northwindair", categories: [.contact])
            let jane = try await h.readyConsumer(name: "Jane Doe")
            try await h.connect(jane, to: b)
            let ref = self.subject(h, b, jane)
            for hostile in ["Pay now\u{202E}gnp.exe", "Line one\nAmount: $0", "Viadere security check", "V1ADERE: confirm", String(repeating: "x", count: 201),
                            "zero\u{200B}width", "   "] {
                let result = try await self.request(h, b, ref, ["contact.email"], purpose: hostile)
                XCTAssertEqual(result.status, .unprocessableEntity, "\(hostile.debugDescription): \(result.text)")
            }
            try await eq(try await ProfileRequestRecord.query(on: h.db).count(), 0)
            // Clients sanitize again: an older stored row with hostile text is cleaned on the way out.
            let ok = try await self.request(h, b, ref, ["contact.email"], purpose: "Receipts")
            let id = try ok.json(ProfileRequestResource.self).id
            try await ProfileRequestRecord.query(on: h.db).filter(\.$id == id.uuid).set(\.$purpose, to: "Hi\u{202E}there\nnow").update()
            let prompt = try await h.signed(jane, .GET, "/v1/profile/requests/\(id)").json(ProfileRequestPrompt.self)
            XCTAssertEqual(prompt.purpose, "Hithere now")
        }
    }

    // MARK: Public name

    func testPublicNameDefaultsImpersonationIsRejectedAndItIsSentWithTheConnection() async throws {
        try await withHarness { h in
            let b = try await self.business(h, "Northwind Air", "northwindair", categories: [])
            let hook = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/r")!, events: [.relationshipConnected]))
            XCTAssertEqual(hook.status, .created)
            try await WebhookSubscriptionRecord.query(on: h.db).filter(\.$businessId == b.id.uuid).set(\.$verifiedAt, to: h.clock.now()).update()
            let jane = try await h.readyConsumer(name: "Jane Doe")
            for hostile in ["Viadere Support", "V1adere", "Official Account", "Security Team", "jane@example.com", "Ja\u{202E}ne"] {
                let result = try await self.put(h, jane, APIRoutes.profilePut.template, ProfileUpdateRequest(customPublicName: hostile))
                XCTAssertEqual(result.status, .unprocessableEntity, hostile)
            }
            let profile = try await h.signed(jane, .GET, APIRoutes.profileGet.template).json(CustomerProfile.self)
            XCTAssertEqual(profile.publicName, "Jane D.")
            let custom = try await self.put(h, jane, APIRoutes.profilePut.template, ProfileUpdateRequest(customPublicName: "  JD  Traveler "))
            XCTAssertEqual(try custom.json(CustomerProfile.self).publicName, "JD Traveler")
            try await h.connect(jane, to: b)
            let delivery = try await WebhookDeliveryRecord.query(on: h.db).filter(\.$eventType == "relationship.connected").first()
            let body = String(decoding: WebhookService(db: h.db, ctx: h.ctx).deliveryBody(try XCTUnwrap(delivery)) ?? Data(), as: UTF8.self)
            XCTAssertTrue(body.contains("\"publicName\":\"JD Traveler\""), body)
            XCTAssertTrue(body.contains("subjectRef"))
            // The custom name is encrypted at rest.
            let row = try await ConsumerProfileRecord.find(jane.id.uuid, on: h.db)
            XCTAssertFalse(row?.publicName?.contains("Traveler") ?? true)
            let reset = try await self.put(h, jane, APIRoutes.profilePut.template, ProfileUpdateRequest(useDerivedPublicName: true))
            XCTAssertEqual(try reset.json(CustomerProfile.self).publicName, "Jane D.")
        }
    }

    // MARK: Environment

    func testTestModeKeysOnlySeeSandboxProfiles() async throws {
        try await withHarness { h in
            let live = try await self.business(h, "Northwind Air", "northwindair", categories: [.contact, .verified])
            let test = try await BusinessAPIKeys.issue(businessId: live.id.uuid, name: "test", live: false, scopes: BusinessAPIKeys.Scope.all,
                                                       capabilities: Capability.messaging, now: h.clock.now(), on: h.db)
            let jane = try await h.readyConsumer(name: "Jane Doe")
            try await self.setProfile(h, jane, self.sample)
            try await h.connect(jane, to: live)
            _ = try await self.grant(h, jane, live, ["contact.email"])
            // A test key cannot see a real customer (plain 404) or ask them anything.
            try await eq(try await self.read(h, live, self.subject(h, live, jane), key: test.key).status, .notFound)
            try await eq(try await self.request(h, live, self.subject(h, live, jane), ["contact.email"], key: test.key).status, .notFound)
            // A sandbox customer answers at once with simulated values; a live key cannot see it.
            let created = try await h.business(live, .POST, "/v1/business/sandbox/relationships", key: test.key)
            let sandbox = try created.json(SandboxRelationship.self)
            let ref = try XCTUnwrap(sandbox.subjectRef)
            let answered = try await self.request(h, live, ref, ["contact.email", "verified.identity"], key: test.key)
            XCTAssertEqual(answered.status, .created, answered.text)
            XCTAssertEqual(try answered.json(ProfileRequestResource.self).status, .answered)
            let view = try await self.read(h, live, ref, key: test.key).json(BusinessProfileView.self)
            XCTAssertFalse(view.livemode)
            XCTAssertTrue(view.fields.contains { $0.value == .text("sandbox.customer@example.com") })
            XCTAssertEqual(view.fields.first { $0.key == "verified.identity" }?.verification?.assurance, "sandbox_simulated")
            try await eq(try await self.read(h, live, ref).status, .notFound)
        }
    }

    // MARK: Audit, encryption, export, deletion

    func testAuditAndStorageHoldNoValues() async throws {
        try await withHarness { h in
            let b = try await self.business(h, "Northwind Air", "northwindair", categories: [.contact, .travel])
            let jane = try await h.readyConsumer(name: "Jane Doe")
            try await self.setProfile(h, jane, self.sample)
            try await h.connect(jane, to: b)
            _ = try await self.grant(h, jane, b, ["contact.email", "travel.frequent_flyer"])
            _ = try await self.read(h, b, self.subject(h, b, jane))
            let events = try await AuditEventRecord.query(on: h.db).all()
            let reads = events.filter { $0.action == "profile.read" }
            XCTAssertEqual(reads.count, 1)
            XCTAssertTrue(reads[0].metadataJSON.contains("contact.email"))
            for event in events {
                for secret in ["jane.secret", "UA778899", "1990-05-04"] { XCTAssertFalse(event.metadataJSON.contains(secret), "\(event.action) leaks \(secret)") }
            }
            for row in try await ProfileValueRecord.query(on: h.db).all() {
                XCTAssertTrue(FieldCipher.isSealed(row.value))
                for secret in ["jane.secret", "UA778899", "1990-05-04", "Jane"] { XCTAssertFalse(row.value.contains(secret)) }
            }
            // A sealed value moved to another row does not open (row binding).
            let rows = try await ProfileValueRecord.query(on: h.db).all()
            XCTAssertThrowsError(try h.ctx.cipher.open(rows[0].value, context: ProfileValueRecord.valueContext, rowId: rows[1].id!))
        }
    }

    func testExportIncludesTheProfile() async throws {
        try await withHarness { h in
            let b = try await self.business(h, "Northwind Air", "northwindair", categories: [.contact])
            let jane = try await h.readyConsumer(name: "Jane Doe")
            try await self.setProfile(h, jane, self.sample)
            try await h.connect(jane, to: b)
            _ = try await self.grant(h, jane, b, ["contact.email"])
            let document = try await ConsumerExports(db: h.db, ctx: h.ctx).document(for: jane.id.uuid)
            let profile = try XCTUnwrap(document["profile"] as? [String: Any])
            XCTAssertEqual(profile["publicName"] as? String, "Jane D.")
            let text = String(decoding: try JSONSerialization.data(withJSONObject: profile), as: UTF8.self)
            XCTAssertTrue(text.contains("jane.secret@example.com"))
            XCTAssertTrue(text.contains("UA778899"))
            XCTAssertEqual((profile["grants"] as? [[String: Any]])?.count, 1)
            XCTAssertEqual((profile["receipts"] as? [[String: Any]])?.count, 1)
        }
    }

    func testAccountDeletionErasesTheProfileAndEndsGrants() async throws {
        try await withHarness { h in
            let b = try await self.business(h, "Northwind Air", "northwindair", categories: [.contact])
            let jane = try await h.readyConsumer(name: "Jane Doe")
            try await self.setProfile(h, jane, self.sample)
            _ = try await self.put(h, jane, APIRoutes.profilePut.template, ProfileUpdateRequest(customPublicName: "JD"))
            try await h.connect(jane, to: b)
            _ = try await self.grant(h, jane, b, ["contact.email"])
            _ = try await self.request(h, b, self.subject(h, b, jane), ["contact.email"])
            let deleted = try await h.signed(jane, .DELETE, "/v1/account")
            XCTAssertEqual(deleted.status, .ok, deleted.text)
            try await eq(try await ProfileValueRecord.query(on: h.db).count(), 0)
            try await eq(try await ConsumerProfileRecord.query(on: h.db).count(), 0)
            try await eq(try await ProfileRequestRecord.query(on: h.db).count(), 0)
            try await eq(try await ProfileVerifiedFactRecord.query(on: h.db).count(), 0)
            try await eq(try await ProfileGrantRecord.query(on: h.db).filter(\.$revokedAt == nil).count(), 0)
            try await eq(try await self.read(h, b, self.subject(h, b, jane)).status, .notFound)
        }
    }

    // MARK: Verified profile

    func testVerifiedFactsCarryProvenanceAndKeepOnlyWhatTheMethodEstablishes() async throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        var wallet = EvidenceClaims(method: .walletMdoc, issuer: "0123456789abcdef", verifiedAt: now, validUntil: now.addingTimeInterval(900), revocation: .notChecked)
        wallet.documentPresented = true
        wallet.givenName = "JANE"
        wallet.familyName = "Doé"
        wallet.ageOver[21] = true
        let kept = ProfileVerificationService.facts(from: wallet, keep: [.identity, .legalName, .ageOver18, .ageOver21], profileGiven: "Jane", profileFamily: "Doe", now: now)
        XCTAssertEqual(Set(kept), [.identity, .legalName, .ageOver18, .ageOver21])
        // Only what was chosen is kept; a different name is not a match; an under-age answer keeps nothing.
        XCTAssertEqual(ProfileVerificationService.facts(from: wallet, keep: [.identity], profileGiven: "Jane", profileFamily: "Doe", now: now), [.identity])
        XCTAssertEqual(ProfileVerificationService.facts(from: wallet, keep: [.legalName], profileGiven: "Janet", profileFamily: "Doe", now: now), [])
        var minor = wallet
        minor.ageOver = [18: false]
        XCTAssertEqual(ProfileVerificationService.facts(from: minor, keep: [.ageOver18, .ageOver21], profileGiven: nil, profileFamily: nil, now: now), [])
        // A selfie age estimate establishes neither identity nor a verified age (no promotion).
        var estimate = wallet
        estimate.method = .diditAgeEstimation
        XCTAssertEqual(ProfileVerificationService.facts(from: estimate, keep: [.identity, .ageOver18, .legalName], profileGiven: "Jane", profileFamily: "Doe", now: now), [])
        // The stored record has provenance columns only: no document number, name, birth date or image can be written.
        try await withHarness { h in
            let b = try await self.business(h, "Northwind Air", "northwindair", categories: [.verified])
            let test = try await BusinessAPIKeys.issue(businessId: b.id.uuid, name: "test", live: false, scopes: BusinessAPIKeys.Scope.all,
                                                       capabilities: Capability.messaging, now: h.clock.now(), on: h.db)
            let sandbox = try await h.business(b, .POST, "/v1/business/sandbox/relationships", key: test.key).json(SandboxRelationship.self)
            _ = try await self.request(h, b, try XCTUnwrap(sandbox.subjectRef), ["verified.identity"], key: test.key)
            let fact = try await XCTUnwrapAsync(try await ProfileVerifiedFactRecord.query(on: h.db).first())
            XCTAssertEqual(fact.dto?.method, .sandbox)
            XCTAssertEqual(fact.policyVersion, VerifyPolicy.version)
            if let sql = h.db as? any SQLDatabase, !DB.isPostgres(h.db) {
                let columns = try await sql.raw("PRAGMA table_info(profile_verified_facts)").all().map { try $0.decode(column: "name", as: String.self) }
                XCTAssertEqual(Set(columns), ["id", "consumer_id", "fact", "method", "assurance", "policy_version", "verified_at"])
            }
        }
    }

    func testProfileVerificationIsBehindTheVerifyGate() async throws {
        try await withHarness { h in
            let jane = try await h.readyConsumer(name: "Jane Doe")
            let result = try await h.signedPost(jane, APIRoutes.profileVerificationBegin.template, ProfileVerificationBegin(method: .wallet, keep: [.identity]))
            XCTAssertEqual(result.status, h.config.verify.enabled ? .serviceUnavailable : .notFound, result.text)
        }
    }

    func testEditingTheNameForgetsAVerifiedLegalNameMatch() async throws {
        try await withHarness { h in
            let jane = try await h.readyConsumer(name: "Jane Doe")
            try await self.setProfile(h, jane, self.sample)
            for kind in [ProfileVerifiedFactKind.identity, .legalName] {
                let fact = ProfileVerifiedFactRecord()
                fact.id = UUID(); fact.consumerId = jane.id.uuid; fact.fact = kind.rawValue; fact.method = "wallet_mdoc"
                fact.assurance = "issuer_signed_credential_device_bound"; fact.policyVersion = VerifyPolicy.version; fact.verifiedAt = h.clock.now()
                try await fact.create(on: h.db)
            }
            try await self.setProfile(h, jane, [ProfileFieldEntry(key: "personal.family_name", value: .text("Smith"))])
            let profile = try await h.signed(jane, .GET, APIRoutes.profileGet.template).json(CustomerProfile.self)
            XCTAssertEqual(profile.verified.map(\.fact), [.identity])
            XCTAssertTrue(profile.isVerified)
        }
    }

    func testInvalidValuesAreRefusedAtomically() async throws {
        try await withHarness { h in
            let jane = try await h.readyConsumer(name: "Jane Doe")
            let result = try await self.put(h, jane, APIRoutes.profilePut.template, ProfileUpdateRequest(set: [
                ProfileFieldEntry(key: "contact.email", value: .text("ok@example.com")),
                ProfileFieldEntry(key: "home.access_notes", value: .text("SSN 123-45-6789")),
            ]))
            XCTAssertEqual(result.status, .unprocessableEntity, result.text)
            try await eq(try await ProfileValueRecord.query(on: h.db).count(), 0)
            let unknown = try await self.put(h, jane, APIRoutes.profilePut.template, ProfileUpdateRequest(set: [ProfileFieldEntry(key: "health.blood_type", value: .text("O+"))]))
            XCTAssertEqual(unknown.status, .unprocessableEntity)
        }
    }

    func testOperatorReviewNeedsAFreshPasskeyAndIsAudited() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            _ = try await h.formPost(ProfileConsole.path, owner, [("categories[]", "verified"),
                                                                  ("verified", "Age-restricted tickets: we must know the buyer is a verified adult.")])
            let request = try await XCTUnwrapAsync(try await ProfileCategoryRequestRecord.query(on: h.db).first())
            let (ops, account) = try await h.makeOperator()
            let base = "/operator/businesses/\(businessId.uuidString.lowercased())/profile-categories"
            let page = try await h.page(base, ops)
            XCTAssertEqual(page.status, .ok, page.text)
            XCTAssertTrue(page.text.contains("Age-restricted tickets"))
            // No fresh passkey: nothing is granted.
            _ = try await h.formPost("\(base)/\(request.id!.uuidString.lowercased())/decide", ops, [("decision", "approve"), ("justification", "Ticketing use case reviewed and approved.")])
            try await isTrue(try await EntitlementService(db: h.db, ctx: h.ctx).snapshot(businessId: businessId).profileCategories.isEmpty)
            _ = try await h.dashReauth(ops, account)
            // `verified` needs the heightened-review reference as well.
            let noReference = try await h.formPost("\(base)/\(request.id!.uuidString.lowercased())/decide", ops,
                                                   [("decision", "approve"), ("justification", "Ticketing use case reviewed and approved.")])
            XCTAssertNotEqual(noReference.status, .seeOther)
            try await isTrue(try await EntitlementService(db: h.db, ctx: h.ctx).snapshot(businessId: businessId).profileCategories.isEmpty)
            let approved = try await h.formPost("\(base)/\(request.id!.uuidString.lowercased())/decide", ops,
                                                [("decision", "approve"), ("justification", "Ticketing use case reviewed and approved."), ("reviewReference", "HR-2026-44")])
            XCTAssertEqual(approved.status, .seeOther, approved.text)
            try await eq(try await EntitlementService(db: h.db, ctx: h.ctx).snapshot(businessId: businessId).profileCategories, [.verified])
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == "entitlement.profile_category_granted").count(), 1)
        }
    }
}
