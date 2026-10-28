import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Onboarding state machine (spec §8.1), the §9.4 acceptance flow, contract acceptance and ongoing assurance.
final class WP6OnboardingTests: XCTestCase {
    private func ownershipRequired(_ config: inout ServerConfig) { config.operations.webhookOwnershipVerification = true }

    // MARK: Pure state machine

    func testTheMachineRefusesToSkipStages() throws {
        var state = OnboardingState()
        XCTAssertEqual(state.stage, .control)
        // A later event cannot be applied before its predecessors.
        XCTAssertThrowsError(try OnboardingStateMachine.apply(.legalSubmitted, to: state))
        XCTAssertThrowsError(try OnboardingStateMachine.apply(.sandboxKeyIssued, to: state))
        XCTAssertThrowsError(try OnboardingStateMachine.apply(.goLiveRequested, to: state))
        XCTAssertThrowsError(try OnboardingStateMachine.apply(.goLiveApproved, to: state))
        state = try OnboardingStateMachine.apply(.domainVerified, to: state)
        XCTAssertThrowsError(try OnboardingStateMachine.apply(.legalApproved, to: state), "approval needs a submission")
        state = try OnboardingStateMachine.apply(.legalSubmitted, to: state)
        state = try OnboardingStateMachine.apply(.legalApproved, to: state)
        XCTAssertEqual(state.stage, .identity)
        state = try OnboardingStateMachine.apply(.identityVerified, to: state)
        XCTAssertEqual(state.stage, .contracts)
        state.contractsCurrent = true
        XCTAssertEqual(state.stage, .integration)
        for event in [OnboardingEvent.sandboxKeyIssued, .sandboxRelationshipCreated, .testEventSent] { state = try OnboardingStateMachine.apply(event, to: state) }
        XCTAssertEqual(state.stage, .goLive)
        // The request is blocked until the operational contact exists, and approval cannot come before a request.
        XCTAssertThrowsError(try OnboardingStateMachine.apply(.goLiveRequested, to: state)) { error in
            XCTAssertEqual(error as? OnboardingError, .blocked([.securityContact]))
        }
        state = try OnboardingStateMachine.apply(.securityContactSet, to: state)
        XCTAssertThrowsError(try OnboardingStateMachine.apply(.goLiveApproved, to: state))
        state = try OnboardingStateMachine.apply(.goLiveRequested, to: state)
        state = try OnboardingStateMachine.apply(.goLiveApproved, to: state)
        XCTAssertEqual(state.stage, .live)
        // Sensitive categories add a review that must pass before the request.
        var sensitive = OnboardingState()
        sensitive = try OnboardingStateMachine.apply(.domainVerified, to: sensitive)
        sensitive = try OnboardingStateMachine.apply(.enhancedRequired, to: sensitive)
        XCTAssertFalse(sensitive.controlComplete)
        XCTAssertTrue(sensitive.requestBlockers.contains(.enhancedReview))
    }

    /// The contract catalog and the public legal pages cannot drift: the slug, the version and the page itself must agree (spec 18.11).
    func testTheContractCatalogMatchesThePublicLegalPages() throws {
        let legal = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Site/content/legal")
        for document in LegalCatalog.documents {
            let page = legal.appendingPathComponent(document.slug).appendingPathComponent("index.md")
            let text = try String(contentsOf: page, encoding: .utf8)
            let front = try XCTUnwrap(text.components(separatedBy: "---\n").dropFirst().first, document.slug)
            let version = front.split(separator: "\n").first { $0.hasPrefix("version:") }.map { $0.dropFirst("version:".count).trimmingCharacters(in: .whitespaces) }
            XCTAssertEqual(version, document.version, "\(document.slug): the catalog version must be the version of the published page")
            XCTAssertTrue(front.contains("counsel_review:"), "\(document.slug) carries its review status")
            XCTAssertLessThanOrEqual(LegalCatalog.compare(document.materialSince, document.version), 0)
        }
        XCTAssertEqual(Set(LegalCatalog.documents.map(\.slug)).count, LegalCatalog.documents.count)
        XCTAssertEqual(LegalCatalog.compare("0.10.0", "0.9.0"), 1)
        XCTAssertEqual(LegalCatalog.compare("1.0", "1.0.0"), 0)
    }

    // MARK: §9.4 acceptance flow

    /// A legitimate low-risk messaging business: workspace -> verify control -> sandbox key -> send a test message -> configure a signed webhook ->
    /// receive a test reply -> request production approval, without any VPN or private network.
    func testSection94BusinessIntegrationFlow() async throws {
        try await withHarness(ownershipRequired) { h in
            h.echoWebhookChallenges()
            let (op, _) = try await h.makeOperator()
            let (owner, account, businessId) = try await h.pendingOwner()
            let businessPath = "/operator/businesses/\(businessId.uuidString.lowercased())"
            var state = try await h.onboardingState(businessId)
            XCTAssertEqual(state.stage, .control)

            // Nothing in the sandbox before control of a domain is proven.
            let early = try await h.createKey(owner)
            XCTAssertEqual(early.status, .forbidden, early.text)

            // 2. Prove control (DNS TXT), then the legal-entity step reviewed by an operator (references only, no documents).
            try await h.verifyDomain(owner, businessId: businessId)
            state = try await h.onboardingState(businessId)
            XCTAssertTrue(state.domainVerified)
            XCTAssertEqual(state.stage, .control)
            let legal = try await h.formPost("/dashboard/organization/legal-entity", owner, [("registryNumber", "12345678"), ("jurisdiction", "US-DE"),
                                                                                           ("registryName", "Acme Roasters Ltd"), ("evidence", "https://registry.example/acme")])
            XCTAssertEqual(legal.status, .seeOther, legal.text)
            let reviewed = try await h.formPost("\(businessPath)/legal-entity", op, [("decision", "approve"), ("note", "Registry record matches")])
            XCTAssertEqual(reviewed.status, .seeOther, reviewed.text)
            state = try await h.onboardingState(businessId)
            XCTAssertEqual(state.stage, .identity)

            // 3. Public identity: the operator approves the application (handle and permanent code).
            let approve = try await h.formPost("/operator/applications/\(businessId.uuidString.lowercased())/approve", op, [("note", "ok")])
            XCTAssertEqual(approve.status, .seeOther, approve.text)
            state = try await h.onboardingState(businessId)
            XCTAssertEqual(state.stage, .contracts)

            // 4. Versioned contract acceptance: only the catalog's current version can be accepted.
            let stale = try await h.formPost("/dashboard/compliance/accept", owner, [("slug", "business-services-agreement"), ("version", "0.0.1"), ("confirm", "1")])
            XCTAssertEqual(stale.status, .conflict, stale.text)
            let unconfirmed = try await h.formPost("/dashboard/compliance/accept", owner, [("slug", "business-services-agreement"), ("version", "0.2.0")])
            XCTAssertNotEqual(unconfirmed.status, .seeOther)
            try await h.acceptAllContracts(owner, businessId: businessId)
            let acceptances = try await ContractAcceptanceRecord.query(on: h.db).filter(\.$businessId == businessId).all()
            XCTAssertEqual(Set(acceptances.map(\.slug)), Set(LegalCatalog.documents.filter { $0.requirement == .always }.map(\.slug)))
            for acceptance in acceptances {
                XCTAssertEqual(acceptance.version, "0.2.0")
                XCTAssertEqual(acceptance.acceptedBy, account.userId)
                XCTAssertFalse(acceptance.ipHash.isEmpty)
                XCTAssertFalse(acceptance.uaHash.isEmpty)
                XCTAssertFalse(acceptance.ipHash.contains("127.0.0.1"), "an address hash, never the address")
            }
            state = try await h.onboardingState(businessId)
            XCTAssertEqual(state.stage, .integration)

            // 5. Integration: a sandbox key, a test customer, a test message, a signed webhook that proves it is ours, a simulated reply.
            try await h.dashReauth(owner, account)
            let key = try await h.createKey(owner, name: "sandbox", mode: "test", scopes: ["interactions:write", "messages:write", "webhooks:manage"])
            XCTAssertEqual(key.status, .ok, key.text)
            let secret = try XCTUnwrap(key.secret)
            XCTAssertTrue(secret.hasPrefix("vdk_test_"))
            let customer = try await h.apiPost(secret, "/v1/business/sandbox/relationships")
            XCTAssertEqual(customer.status, .created, customer.text)
            let relationship = try XCTUnwrap(try JSONSerialization.jsonObject(with: customer.body) as? [String: Any])["relationshipId"] as? String
            let sent = try await h.apiPost(secret, "/v1/business/messages", json: try JSONSerialization.data(withJSONObject: [
                "relationshipId": try XCTUnwrap(relationship), "body": "Your order is ready", "idempotencyKey": "m-1"]), headers: ["Idempotency-Key": "m-1"])
            XCTAssertEqual(sent.status, .created, sent.text)

            let created = try await h.apiPost(secret, "/v1/business/webhooks", json: try ViadereJSON.encode(
                CreateWebhookRequest(url: URL(string: "https://hooks.acme.example/viadere")!, events: [.messageReceived])))
            XCTAssertEqual(created.status, .created, created.text)
            let hook = try created.json(WebhookSecretResponse.self)
            // Until it proves ownership an endpoint receives nothing, not even a test event.
            let early2 = try await h.apiPost(secret, "/v1/business/webhooks/\(hook.subscription.id)/test")
            XCTAssertEqual(early2.status, .conflict, early2.text)
            let proven = try await h.apiPost(secret, "/v1/business/webhooks/\(hook.subscription.id)/verify")
            XCTAssertEqual(proven.status, .ok, proven.text)
            XCTAssertTrue(try proven.json(WebhookVerificationResult.self).verified)
            XCTAssertEqual(h.webhooks.received.last.map { $0.headers[ViadereHeader.eventType] }, "webhook.verification")

            let reply = try await h.formPost("/dashboard/developers/sandbox/reply", owner, [("relationshipId", try XCTUnwrap(relationship)), ("text", "Thanks!")])
            XCTAssertEqual(reply.status, .seeOther, reply.text)
            _ = try await WebhookService(db: h.db, ctx: h.ctx).deliverDue()
            let delivered = try XCTUnwrap(h.webhooks.received.last)
            XCTAssertEqual(delivered.headers[ViadereHeader.eventType], "message.received")
            XCTAssertNotNil(delivered.headers[ViadereHeader.signature])
            XCTAssertNotNil(delivered.headers[ViadereHeader.keyId], "versioned key id")
            XCTAssertNotNil(delivered.headers["Viadere-Delivery-Id"], "delivery id")
            // The business verifies the signature with the secret it was shown once.
            XCTAssertNoThrow(try WebhookSignature.verify(header: try XCTUnwrap(delivered.headers[ViadereHeader.signature]), body: delivered.body, secrets: [hook.secret], now: h.clock.now()))

            // 6. Go-live: blocked until a security contact exists; then requested by the business and decided by an operator.
            let tooSoon = try await h.formPost("/dashboard/organization/go-live", owner, [("useCase", "Order-ready notifications for our cafes"), ("volume", "2,000 per month")])
            XCTAssertEqual(tooSoon.status, .conflict, tooSoon.text)
            let contact = try await h.formPost("/dashboard/security/alerts", owner, [("contacts", "security@acme.example"), ("topics", "key_events")])
            XCTAssertEqual(contact.status, .seeOther, contact.text)
            state = try await h.onboardingState(businessId)
            XCTAssertEqual(state.stage, .goLive)
            XCTAssertEqual(state.requestBlockers, [])
            let notYet = try await h.formPost("\(businessPath)/go-live", op, [("decision", "approve")])
            XCTAssertEqual(notYet.status, .conflict, "an operator cannot approve what was never requested")
            let request = try await h.formPost("/dashboard/organization/go-live", owner, [("useCase", "Order-ready notifications for our cafes"), ("volume", "2,000 per month")])
            XCTAssertEqual(request.status, .seeOther, request.text)
            // No production key while the review is open.
            try await h.dashReauth(owner, account)
            let liveEarly = try await h.createKey(owner, name: "live", mode: "live")
            XCTAssertNotEqual(liveEarly.status, .ok)
            let decided = try await h.formPost("\(businessPath)/go-live", op, [("decision", "approve"), ("note", "Use case approved")])
            XCTAssertEqual(decided.status, .seeOther, decided.text)
            state = try await h.onboardingState(businessId)
            XCTAssertEqual(state.stage, .live)
            try await h.dashReauth(owner, account)
            let live = try await h.createKey(owner, name: "live", mode: "live")
            XCTAssertEqual(live.status, .ok, live.text)
            XCTAssertTrue(try XCTUnwrap(live.secret).hasPrefix("vdk_live_"))

            // The whole path is on the audit trail, in order, and carries no secret.
            let actions = try await h.auditActions(businessId)
            for expected in ["onboarding.domainVerified", "onboarding.legalSubmitted", "onboarding.legalApproved", "onboarding.identityVerified", "contract.accepted",
                             "webhook.verified", "onboarding.goLiveRequested", "onboarding.goLiveApproved"] {
                XCTAssertTrue(actions.contains(expected), "\(expected) missing from \(actions)")
            }
            let audit = try await AuditEventRecord.query(on: h.db).filter(\.$businessId == businessId).all().map { $0.action + $0.metadataJSON }.joined()
            XCTAssertFalse(audit.contains(secret))
            XCTAssertFalse(audit.contains(hook.secret))
            XCTAssertFalse(h.allMailText.contains(secret))
        }
    }

    // MARK: Domain control

    func testDomainControlAcceptsDNSOrWellKnownRechecksAndSuspendsAfterTheGrace() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.pendingOwner()
            // A wrong value in DNS proves nothing; the token must match.
            let add = try await h.formPost("/dashboard/organization/domains", owner, [("domain", "acme.example.com")])
            XCTAssertEqual(add.status, .seeOther)
            let record = try await XCTUnwrapAsync(await BusinessDomainRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            h.domainChecker.publishTXT(domain: "acme.example.com", token: "not-the-token")
            let wrong = try await h.formPost("/dashboard/organization/domains/\(record.id!.uuidString.lowercased())/check", owner)
            XCTAssertEqual(wrong.status, .ok, "stays on the page with a notice")
            var row = try await h.onboardingRow(businessId)
            XCTAssertNil(row.controlVerifiedAt)
            // The well-known file works as the alternative method.
            h.domainChecker.publishFile(domain: "acme.example.com", token: record.token)
            let ok = try await h.formPost("/dashboard/organization/domains/\(record.id!.uuidString.lowercased())/check", owner)
            XCTAssertEqual(ok.status, .seeOther, ok.text)
            row = try await h.onboardingRow(businessId)
            XCTAssertNotNil(row.controlVerifiedAt)
            XCTAssertEqual(row.controlMethod, "wellknown")

            // A second organization cannot claim a domain someone else verified.
            let (other, _, otherId) = try await h.pendingOwner(email: "mallory@example.net", org: "Mallory Coffee", handle: "mallorycoffee")
            _ = try await h.formPost("/dashboard/organization/domains", other, [("domain", "acme.example.com")])
            let theirs = try await XCTUnwrapAsync(await BusinessDomainRecord.query(on: h.db).filter(\.$businessId == otherId).first())
            h.domainChecker.publishFile(domain: "acme.example.com", token: theirs.token)
            _ = try await h.formPost("/dashboard/organization/domains/\(theirs.id!.uuidString.lowercased())/check", other)
            let otherRow = try await h.onboardingRow(otherId)
            XCTAssertNil(otherRow.controlVerifiedAt)
        }
    }

    func testOngoingAssuranceRechecksDomainsAndSuspendsOnlyAfterTheGracePeriod() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.pendingOwner()
            try await h.verifyDomain(owner, businessId: businessId)
            try await h.acceptAllContracts(owner, businessId: businessId)
            _ = try await h.verifyOrganization(businessId)
            let assurance = OnboardingAssurance(db: h.db, ctx: h.ctx)
            func status() async throws -> VerificationStatus {
                let record = try await BusinessRecord.find(businessId, on: h.db)
                return try XCTUnwrap(record).status
            }
            // The record disappears, but a resolver outage alone is never evidence against the business.
            h.domainChecker.removeTXT(domain: "acme.example.com")
            h.domainChecker.setResolverDown(true)
            h.clock.advance(by: 31 * 86_400)
            _ = try await assurance.run()
            var current = try await status()
            XCTAssertEqual(current, .verified, "an unavailable resolver is not a failed check")
            let graceRow = try await h.onboardingRow(businessId)
            XCTAssertNil(graceRow.assuranceGraceStartedAt)
            // The resolver answers and the record is gone: the grace period starts and the owners are told. Nothing is suspended yet.
            h.domainChecker.setResolverDown(false)
            h.clock.advance(by: 2 * 86_400)
            let mailBefore = h.emails.sent.count
            var report = try await assurance.run()
            XCTAssertEqual(report.graceStarted, 1)
            current = try await status()
            XCTAssertEqual(current, .verified)
            XCTAssertGreaterThan(h.emails.sent.count, mailBefore)
            XCTAssertFalse(h.allMailText.contains("vdk_"))
            // Inside the grace period nothing more happens; after it the system suspends, with an audit record.
            h.clock.advance(by: 7 * 86_400)
            report = try await assurance.run()
            XCTAssertEqual(report.suspended, 0)
            h.clock.advance(by: 8 * 86_400)
            report = try await assurance.run()
            XCTAssertEqual(report.suspended, 1)
            current = try await status()
            XCTAssertEqual(current, .suspended)
            // Fixing the cause lifts the suspension the assurance caused.
            let domainRecord = try await XCTUnwrapAsync(await BusinessDomainRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            h.domainChecker.publishTXT(domain: "acme.example.com", token: domainRecord.token)
            h.clock.advance(by: 2 * 86_400)
            report = try await assurance.run()
            XCTAssertEqual(report.recovered, 1)
            current = try await status()
            XCTAssertEqual(current, .verified)
            let actions = try await h.auditActions(businessId)
            XCTAssertTrue(actions.contains("assurance.grace_started"))
            XCTAssertTrue(actions.contains("business.suspended"))
            XCTAssertTrue(actions.contains("assurance.recovered"))
        }
    }

    /// A material change of an agreement needs re-acceptance (spec §9.3); an editorial one does not.
    func testReacceptanceIsRequiredWhenAnAcceptedVersionPredatesTheMaterialChange() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.pendingOwner()
            try await h.acceptAllContracts(owner, businessId: businessId)
            let service = ContractService(db: h.db, ctx: h.ctx)
            var outstanding = try await service.outstanding(businessId: businessId)
            XCTAssertEqual(outstanding, [])
            // Simulate the catalog having moved on: the stored acceptance is of a version before the last material change.
            let accepted = try await ContractAcceptanceRecord.query(on: h.db).filter(\.$slug == "data-processing-addendum").first()!
            accepted.version = "0.0.9"
            try await accepted.update(on: h.db)
            outstanding = try await service.outstanding(businessId: businessId)
            XCTAssertEqual(outstanding.map(\.slug), ["data-processing-addendum"])
            let state = try await h.onboardingState(businessId)
            XCTAssertFalse(state.contractsCurrent)
            // Re-accepting the current version records a new row (the history is kept) and clears the requirement.
            let again = try await h.formPost("/dashboard/compliance/accept", owner, [("slug", "data-processing-addendum"), ("version", "0.2.0"), ("confirm", "1")])
            XCTAssertEqual(again.status, .seeOther, again.text)
            outstanding = try await service.outstanding(businessId: businessId)
            XCTAssertEqual(outstanding, [])
            let history = try await service.history(businessId: businessId).filter { $0.slug == "data-processing-addendum" }
            XCTAssertEqual(Set(history.map(\.version)), ["0.0.9", "0.2.0"])
            // Only a member with the right may accept: an analyst's attempt is refused.
            let analyst = try await h.addMember(owner: owner, role: .analyst, email: "analyst@example.com").session
            let refused = try await h.formPost("/dashboard/compliance/accept", analyst, [("slug", "acceptable-use-policy"), ("version", "0.2.0"), ("confirm", "1")])
            XCTAssertEqual(refused.status, .forbidden)
        }
    }

    /// A sensitive category adds a review that must pass before a go-live request (spec 8.1 step 2); the category alone never grants or denies access.
    func testASensitiveCategoryNeedsTheAdditionalReviewBeforeGoLive() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            let (owner, account, businessId) = try await h.pendingOwner(email: "bank@example.com", org: "Harbor Bank", handle: "harborbank", category: "banking")
            let path = "/operator/businesses/\(businessId.uuidString.lowercased())"
            var state = try await h.onboardingState(businessId)
            XCTAssertEqual(state.enhanced, .pending)
            try await h.verifyDomain(owner, businessId: businessId)
            _ = try await h.formPost("/dashboard/organization/legal-entity", owner, [("registryNumber", "B-1234"), ("jurisdiction", "US"), ("registryName", "Harbor Bank NA"), ("evidence", "https://registry.example/b-1234")])
            _ = try await h.formPost("\(path)/legal-entity", op, [("decision", "approve"), ("note", "ok")])
            state = try await h.onboardingState(businessId)
            XCTAssertTrue(state.domainVerified && state.legalEntity == .approved)
            XCTAssertFalse(state.controlComplete, "control is not complete until the additional review passes")
            XCTAssertEqual(state.stage, .control)
            XCTAssertTrue(state.requestBlockers.contains(.enhancedReview))
            // The review needs a recorded reference; with one it passes, and a rejection blocks again.
            let noReference = try await h.formPost("\(path)/enhanced-review", op, [("decision", "approve")])
            XCTAssertNotEqual(noReference.status, .seeOther)
            let rejected = try await h.formPost("\(path)/enhanced-review", op, [("decision", "reject"), ("reference", "REV-2027-001")])
            XCTAssertEqual(rejected.status, .seeOther, rejected.text)
            state = try await h.onboardingState(businessId)
            XCTAssertEqual(state.enhanced, .rejected)
            XCTAssertFalse(state.controlComplete)
            // Another, ordinary business can also be put under review by an operator; a rejected review can be redone.
            let approved = try await h.formPost("\(path)/enhanced-review", op, [("decision", "approve"), ("reference", "REV-2027-002")])
            XCTAssertEqual(approved.status, .seeOther, approved.text)
            state = try await h.onboardingState(businessId)
            XCTAssertEqual(state.enhanced, .approved)
            XCTAssertTrue(state.controlComplete)
            let audit = try await h.auditActions(businessId)
            XCTAssertTrue(audit.contains("onboarding.enhancedApproved") && audit.contains("onboarding.enhancedRejected"))
            _ = account
        }
    }
}
