import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore
import struct ViadereCore.Page
import XCTest
@testable import ViadereServerKit

final class HouseholdTests: XCTestCase {
    private func harness(_ adjust: @escaping (inout ServerConfig) -> Void = { _ in }, _ body: (TestHarness) async throws -> Void) async throws {
        try await withHarness({ config in
            config.accessTokenTTL = 90 * 86_400
            // Generous by default so tests can make many calls; the brute-force tests set the real limits explicitly.
            config.rateLimits.inviteCreatePerConsumer = .perHour(1000, burst: 1000)
            config.rateLimits.inviteAttemptPerConsumer = .perHour(1000, burst: 1000)
            config.rateLimits.inviteAttemptGlobal = .perMinute(10_000, burst: 10_000)
            adjust(&config)
        }, body)
    }

    private struct Scene {
        var northwind: TestBusiness
        var juniper: TestBusiness
        var alex: TestConsumer
        var sam: TestConsumer
        var alexNorthwind: Relationship
        var alexJuniper: Relationship
    }

    private func scene(_ h: TestHarness) async throws -> Scene {
        let northwind = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
        let juniper = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
        let alex = try await h.readyConsumer(name: "Alex")
        let sam = try await h.readyConsumer(name: "Sam Rivera")
        let a = try await h.connect(alex, to: northwind)
        let b = try await h.connect(alex, to: juniper)
        return Scene(northwind: northwind, juniper: juniper, alex: alex, sam: sam, alexNorthwind: a, alexJuniper: b)
    }

    private func preview(_ h: TestHarness, _ c: TestConsumer, _ code: String) async throws -> HTTPResult {
        try await h.signedPost(c, "/v1/household/invitations/preview", DelegationInvitationRedeemRequest(code: code))
    }

    private func accept(_ h: TestHarness, _ c: TestConsumer, _ code: String) async throws -> HTTPResult {
        try await h.signedPost(c, "/v1/household/invitations/accept", DelegationInvitationRedeemRequest(code: code))
    }

    // MARK: Invitations

    func testInvitationLifecycleWithAHashedSingleUseCode() async throws {
        try await harness { h in
            let s = try await scene(h)
            let request = h.invitation(label: "Sam", role: .manager, purposes: [.transactional, .rewards], businesses: [s.northwind, s.juniper])
            let created = try await h.invite(s.alex, request)
            XCTAssertEqual(created.status, .created, created.text)
            let invitation = try created.json(DelegationInvitation.self)
            XCTAssertNotNil(invitation.code.range(of: #"^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$"#, options: .regularExpression))
            XCTAssertEqual(invitation.inviteExpiresAt, h.clock.now().addingTimeInterval(24 * 3600))
            // Stored hashed; the label is encrypted; neither appears in the row.
            let row = try await DelegationInvitationRecord.query(on: h.db).first().unwrap()
            XCTAssertEqual(row.codeHash.count, 64)
            XCTAssertFalse(row.codeHash.contains(invitation.code.replacingOccurrences(of: "-", with: "").lowercased()))
            XCTAssertFalse(row.labelCiphertext.contains("Sam"))
            XCTAssertEqual(try h.ctx.cipher.openString(row.labelCiphertext, context: "delegation.label"), "Sam")
            // The inviter sees a pending grant under their own label for the delegate.
            let pending = try await h.household(s.alex)
            XCTAssertEqual(pending.given.count, 1)
            XCTAssertEqual(pending.given[0].status, .pending)
            XCTAssertEqual(pending.given[0].counterpartName, "Sam")
            XCTAssertEqual(Set(pending.given[0].businessNames), ["Northwind Air", "Juniper Coffee"])
            XCTAssertEqual(pending.given[0].grant.id, invitation.id)
            XCTAssertTrue(pending.received.isEmpty)
            // The invitee previews, then accepts (case, dashes and spaces don't matter).
            let previewed = try await preview(h, s.sam, invitation.code.lowercased())
            XCTAssertEqual(previewed.status, .ok, previewed.text)
            let shown = try previewed.json(DelegationInvitationPreview.self)
            XCTAssertEqual(shown.grantorName, "Alex")
            XCTAssertEqual(shown.role, .manager)
            XCTAssertEqual(Set(shown.purposes), [.transactional, .rewards])
            XCTAssertEqual(Set(shown.businessNames), ["Northwind Air", "Juniper Coffee"])
            XCTAssertEqual(shown.expiresAt, request.expiresAt)
            let accepted = try await accept(h, s.sam, invitation.code.replacingOccurrences(of: "-", with: " "))
            XCTAssertEqual(accepted.status, .ok, accepted.text)
            let grant = try accepted.json(HouseholdGrant.self)
            XCTAssertEqual(grant.status, .active)
            XCTAssertEqual(grant.counterpartName, "Alex")
            XCTAssertEqual(grant.grant.id, invitation.id)
            XCTAssertEqual(grant.grant.grantorId, s.alex.id)
            XCTAssertEqual(grant.grant.delegateId, s.sam.id)
            XCTAssertTrue(grant.grant.isValid)
            let alexView = try await h.household(s.alex)
            XCTAssertEqual(alexView.given.count, 1)
            XCTAssertEqual(alexView.given[0].status, .active)
            XCTAssertEqual(alexView.given[0].counterpartName, "Sam")
            let samView = try await h.household(s.sam)
            XCTAssertEqual(samView.received.map(\.counterpartName), ["Alex"])
            XCTAssertTrue(samView.given.isEmpty)
            // Single use: the same code can never be accepted again, by anyone.
            let lee = try await h.readyConsumer(name: "Lee")
            try await eq(try await accept(h, lee, invitation.code).status, .gone)
            try await eq(try await accept(h, s.sam, invitation.code).status, .gone)
            try await eq(try await preview(h, lee, invitation.code).status, .gone)
            let grants = try await DelegationGrantRecord.query(on: h.db).count()
            XCTAssertEqual(grants, 1)
        }
    }

    func testInvitationsExpireAfter24HoursAndCannotBeAcceptedByTheirOwner() async throws {
        try await harness { h in
            let s = try await scene(h)
            let code = try await h.invite(s.alex, h.invitation(purposes: [.support], businesses: [s.northwind], lifetimeDays: 10)).json(DelegationInvitation.self).code
            try await eq(try await preview(h, s.alex, code).status, .notFound, "your own code is not yours to accept")
            try await eq(try await accept(h, s.alex, code).status, .notFound)
            h.clock.advance(by: 24 * 3600 - 1)
            try await eq(try await preview(h, s.sam, code).status, .ok)
            h.clock.advance(by: 2)
            try await eq(try await preview(h, s.sam, code).status, .gone)
            try await eq(try await accept(h, s.sam, code).status, .gone)
            try await eq(try await h.household(s.alex).given.first?.status, .expired)
            let grants = try await DelegationGrantRecord.query(on: h.db).count()
            XCTAssertEqual(grants, 0)
            // A grant whose end date passed before it was accepted is not created either.
            let short = try await h.invite(s.alex, h.invitation(purposes: [.support], businesses: [s.northwind], lifetimeDays: 1.5 / 24)).json(DelegationInvitation.self).code
            h.clock.advance(by: 2 * 3600)
            try await eq(try await accept(h, s.sam, short).status, .gone)
        }
    }

    func testUnknownMalformedAndRevokedCodesAreIndistinguishable() async throws {
        try await harness { h in
            let s = try await scene(h)
            let created = try await h.invite(s.alex, h.invitation(purposes: [.support], businesses: [s.northwind])).json(DelegationInvitation.self)
            for bad in ["", "K7M2", "K7M2-9QXP-AAAA", "ÜÜÜÜ-ÜÜÜÜ", "AAAA-AAAA", String(repeating: "Z", count: 300)] {
                try await eq(try await preview(h, s.sam, bad).status, .notFound, bad)
            }
            // The inviter cancels a pending invitation: the code stops working.
            let revoked = try await h.signed(s.alex, .DELETE, "/v1/delegations/\(created.id)")
            XCTAssertEqual(revoked.status, .ok)
            try await eq(try await accept(h, s.sam, created.code).status, .gone)
            try await eq(try await h.household(s.alex).given.first?.status, .revoked)
            // Only the inviter can cancel it.
            let other = try await h.invite(s.alex, h.invitation(purposes: [.support], businesses: [s.northwind])).json(DelegationInvitation.self)
            try await eq(try await h.signed(s.sam, .DELETE, "/v1/delegations/\(other.id)").status, .notFound)
        }
    }

    // MARK: Brute force

    func testInvitationGuessingIsRateLimitedPerConsumerAndGlobally() async throws {
        try await harness({ $0.rateLimits.inviteAttemptPerConsumer = .perHour(3, burst: 3); $0.rateLimits.inviteAttemptGlobal = .perMinute(5, burst: 5) }) { h in
            let s = try await scene(h)
            let code = try await h.invite(s.alex, h.invitation(purposes: [.support], businesses: [s.northwind])).json(DelegationInvitation.self).code
            // Three guesses, then the budget is gone: even the right code is refused until it refills.
            for guess in ["AAAA-AAAB", "AAAA-AAAC", "AAAA-AAAD"] { try await eq(try await preview(h, s.sam, guess).status, .notFound) }
            let limited = try await preview(h, s.sam, code)
            XCTAssertEqual(limited.status, .tooManyRequests)
            XCTAssertNotNil(limited.headers.first(name: "Retry-After"))
            try await eq(try await accept(h, s.sam, code).status, .tooManyRequests)
            h.clock.advance(by: 3600 / 3 + 1)
            try await eq(try await preview(h, s.sam, code).status, .ok, "one token refilled")
            // A swarm of accounts shares a global budget (the per-consumer buckets above are separate): 5 total per minute.
            let a = try await h.readyConsumer(name: "A"), b = try await h.readyConsumer(name: "B")
            h.clock.advance(by: 120)
            var statuses: [HTTPStatus] = []
            for who in [a, a, b, b, a, b] { statuses.append(try await preview(h, who, "BBBB-BBBB").status) }
            XCTAssertTrue(statuses.contains(.tooManyRequests), "\(statuses)")
        }
    }

    func testAnInvitationLocksAfterTooManyAttemptsEvenWithAGenerousRateLimit() async throws {
        try await harness({ $0.rateLimits.inviteAttemptPerConsumer = .perHour(1000, burst: 1000); $0.rateLimits.inviteAttemptGlobal = .perMinute(1000, burst: 1000) }) { h in
            let s = try await scene(h)
            let code = try await h.invite(s.alex, h.invitation(purposes: [.support], businesses: [s.northwind])).json(DelegationInvitation.self).code
            for _ in 0..<HouseholdService.maxAttemptsPerInvitation { try await eq(try await preview(h, s.sam, code).status, .ok) }
            try await eq(try await preview(h, s.sam, code).status, .gone, "the cap was reached")
            try await eq(try await accept(h, s.sam, code).status, .gone, "a locked invitation can't be accepted")
            let row = try await DelegationInvitationRecord.query(on: h.db).first().unwrap()
            XCTAssertEqual(row.state, "locked")
            try await eq(try await h.household(s.alex).given.first?.status, .expired)
        }
    }

    func testCreatingInvitationsIsBoundedPerPersonAndPendingCap() async throws {
        try await harness({ $0.rateLimits.inviteCreatePerConsumer = .perHour(30, burst: 30) }) { h in
            let s = try await scene(h)
            for _ in 0..<HouseholdService.maxOpenInvitations {
                try await eq(try await h.invite(s.alex, h.invitation(purposes: [.support], businesses: [s.northwind])).status, .created)
            }
            try await eq(try await h.invite(s.alex, h.invitation(purposes: [.support], businesses: [s.northwind])).status, .conflict)
        }
        try await harness({ $0.rateLimits.inviteCreatePerConsumer = .perHour(2, burst: 2) }) { h in
            let s = try await scene(h)
            try await eq(try await h.invite(s.alex, h.invitation(purposes: [.support], businesses: [s.northwind])).status, .created)
            try await eq(try await h.invite(s.alex, h.invitation(purposes: [.support], businesses: [s.northwind])).status, .created)
            try await eq(try await h.invite(s.alex, h.invitation(purposes: [.support], businesses: [s.northwind])).status, .tooManyRequests)
        }
    }

    // MARK: Validation

    func testInvitationScopeIsValidatedByTheServer() async throws {
        try await harness { h in
            let s = try await scene(h)
            let unconnected = try await h.makeBusiness(name: "Unconnected Co", handle: "unconnectedco")
            func status(_ mutate: (inout DelegationInvitationRequest) -> Void) async throws -> HTTPStatus {
                var request = h.invitation(purposes: [.support], businesses: [s.northwind])
                mutate(&request)
                return try await h.invite(s.alex, request).status
            }
            try await eq(try await status { _ in }, .created)
            try await eq(try await status { $0.purposes = [.marketing] }, .unprocessableEntity)
            try await eq(try await status { $0.purposes = [.support, .marketing] }, .unprocessableEntity, "offers and news can't be delegated")
            try await eq(try await status { $0.purposes = [] }, .unprocessableEntity)
            try await eq(try await status { $0.purposes = [.support, .support] }, .unprocessableEntity)
            try await eq(try await status { $0.businessIds = [] }, .unprocessableEntity)
            try await eq(try await status { $0.businessIds = [unconnected.id] }, .unprocessableEntity, "only businesses you are connected to")
            try await eq(try await status { $0.businessIds = [s.northwind.id, s.northwind.id] }, .unprocessableEntity)
            try await eq(try await status { $0.delegateLabel = "   " }, .unprocessableEntity)
            try await eq(try await status { $0.delegateLabel = String(repeating: "x", count: 41) }, .unprocessableEntity)
            try await eq(try await status { $0.delegateLabel = "bad\u{0007}label" }, .unprocessableEntity)
            try await eq(try await status { $0.expiresAt = h.clock.now().addingTimeInterval(1800) }, .unprocessableEntity, "at least an hour")
            try await eq(try await status { $0.expiresAt = h.clock.now().addingTimeInterval(366 * 86_400) }, .unprocessableEntity, "at most a year")
            try await eq(try await status { $0.expiresAt = h.clock.now().addingTimeInterval(300 * 86_400) }, .created)
            // A disconnected business can no longer be shared.
            _ = try await h.signed(s.alex, .DELETE, "/v1/relationships/\(s.alexJuniper.id)")
            try await eq(try await status { $0.businessIds = [s.juniper.id] }, .unprocessableEntity)
        }
    }

    // MARK: Step-up

    func testSensitiveSharingRequiresAFreshSingleUseBiometricProofBoundToTheScope() async throws {
        try await harness { h in
            let s = try await scene(h)
            let sensitive = h.invitation(purposes: [.security, .transactional], businesses: [s.northwind], lifetimeDays: 7)
            // No proof, and a client that lies about not being sensitive, are both refused.
            let missing = try await h.invite(s.alex, sensitive)
            XCTAssertEqual(missing.status, .forbidden)
            XCTAssertEqual(missing.errorCode, .insufficientAssurance)
            var lying = sensitive
            lying.includesSensitiveScope = false
            try await eq(try await h.invite(s.alex, lying).errorCode, .insufficientAssurance)
            // Valid proof from the biometric key.
            var good = sensitive
            good.stepUp = try await h.stepUp(s.alex, for: good)
            let created = try await h.invite(s.alex, good)
            XCTAssertEqual(created.status, .created, created.text)
            // Reusing the very same proof is refused: single use.
            let replay = try await h.invite(s.alex, good)
            XCTAssertEqual(replay.status, .conflict)
            XCTAssertEqual(replay.errorCode, .replayDetected)
            // Wrong key purpose: a passcode-gated key is not Face ID.
            var passcode = h.invitation(purposes: [.accountService], businesses: [s.northwind])
            passcode.stepUp = try await h.stepUp(s.alex, for: passcode, key: s.alex.device!.passcodeKey)
            let wrongKey = try await h.invite(s.alex, passcode)
            XCTAssertEqual(wrongKey.status, .unauthorized)
            XCTAssertEqual(wrongKey.errorCode, .signatureInvalid)
            var requestKey = h.invitation(purposes: [.accountService], businesses: [s.northwind])
            requestKey.stepUp = try await h.stepUp(s.alex, for: requestKey, key: s.alex.device!.requestKey)
            try await eq(try await h.invite(s.alex, requestKey).errorCode, .signatureInvalid)
            // Scope mismatch: a proof for a narrow grant can't be attached to a wider one.
            let narrow = h.invitation(purposes: [.security], businesses: [s.northwind])
            var widened = h.invitation(purposes: [.security, .accountService], businesses: [s.northwind, s.juniper])
            widened.expiresAt = narrow.expiresAt
            widened.stepUp = try await h.stepUp(s.alex, for: narrow)
            let mismatch = try await h.invite(s.alex, widened)
            XCTAssertEqual(mismatch.status, .forbidden)
            var otherLabel = narrow
            otherLabel.delegateLabel = "Someone else"
            otherLabel.stepUp = try await h.stepUp(s.alex, for: narrow)
            try await eq(try await h.invite(s.alex, otherLabel).status, .forbidden)
            // Too old / from the future.
            var stale = h.invitation(purposes: [.security], businesses: [s.northwind])
            stale.stepUp = try await h.stepUp(s.alex, for: stale, at: h.clock.now().addingTimeInterval(-301))
            let tooOld = try await h.invite(s.alex, stale)
            XCTAssertEqual(tooOld.status, .gone)
            var recent = h.invitation(purposes: [.security], businesses: [s.northwind])
            recent.stepUp = try await h.stepUp(s.alex, for: recent, at: h.clock.now().addingTimeInterval(-290))
            try await eq(try await h.invite(s.alex, recent).status, .created)
            var future = h.invitation(purposes: [.security], businesses: [s.northwind], lifetimeDays: 6)
            future.stepUp = try await h.stepUp(s.alex, for: future, at: h.clock.now().addingTimeInterval(120))
            try await eq(try await h.invite(s.alex, future).errorCode, .clockSkew)
            // A proof naming another device, or garbage signatures.
            var elsewhere = h.invitation(purposes: [.security], businesses: [s.northwind], lifetimeDays: 5)
            elsewhere.stepUp = try await h.stepUp(s.alex, for: elsewhere, device: DeviceID())
            try await eq(try await h.invite(s.alex, elsewhere).status, .forbidden)
            var garbage = h.invitation(purposes: [.security], businesses: [s.northwind], lifetimeDays: 4)
            garbage.stepUp = DelegationStepUpProof(deviceId: s.alex.device!.id, signedAt: ViadereDate.truncatedToMilliseconds(h.clock.now()),
                                                   scopeDigest: DelegationScopePolicy.scopeDigest(of: garbage), signature: "AAAA")
            try await eq(try await h.invite(s.alex, garbage).status, .badRequest)
            // Another person's device can't use Alex's proof.
            var stolen = h.invitation(purposes: [.security], businesses: [s.northwind], lifetimeDays: 3)
            stolen.stepUp = try await h.stepUp(s.alex, for: stolen)
            _ = try await h.connect(s.sam, to: s.northwind)
            try await eq(try await h.invite(s.sam, stolen).status, .forbidden)
            // Rejections are audited as denied, without the proof.
            let denied = try await AuditEventRecord.query(on: h.db).filter(\.$action == "delegation.stepup_rejected").all()
            XCTAssertGreaterThanOrEqual(denied.count, 8)
            XCTAssertTrue(denied.allSatisfy { $0.outcome == "denied" })
        }
    }

    func testSensitiveGrantsAreCappedAtThirtyDaysAndNeedABiometricKey() async throws {
        try await harness { h in
            let s = try await scene(h)
            var long = h.invitation(purposes: [.security], businesses: [s.northwind], lifetimeDays: 31)
            long.stepUp = try await h.stepUp(s.alex, for: long)
            let refused = try await h.invite(s.alex, long)
            XCTAssertEqual(refused.status, .unprocessableEntity)
            var thirty = h.invitation(purposes: [.accountService], businesses: [s.northwind], lifetimeDays: 29.9)
            thirty.stepUp = try await h.stepUp(s.alex, for: thirty)
            try await eq(try await h.invite(s.alex, thirty).status, .created)
            // The same length is fine when nothing sensitive is shared.
            try await eq(try await h.invite(s.alex, h.invitation(purposes: [.transactional], businesses: [s.northwind], lifetimeDays: 90)).status, .created)
            // A device that never enrolled a biometric key can't share anything sensitive.
            let noBiometrics = try await h.enrollDevice(try await h.registerConsumer(name: "Pat"), purposes: [.request, .approvalUserPresence])
            _ = try await h.connect(noBiometrics, to: s.northwind)
            var request = h.invitation(purposes: [.security], businesses: [s.northwind])
            request.stepUp = try await h.stepUp(noBiometrics, for: request, key: noBiometrics.device!.passcodeKey)
            let result = try await h.invite(noBiometrics, request)
            XCTAssertEqual(result.status, .forbidden)
            XCTAssertEqual(result.errorCode, .insufficientAssurance)
        }
    }

    // MARK: Delegated access

    private func confirm(_ h: TestHarness, _ business: TestBusiness, _ relationship: Relationship, purpose: InteractionPurpose = .transactional, title: String = "Confirm pickup") async throws -> Interaction {
        let response = try await h.issue(business, relationship: relationship, payload: .confirm(ConfirmPayload(title: title)), purpose: purpose, ttl: 3600)
        XCTAssertEqual(response.status, .created, response.text)
        return try response.json(Interaction.self)
    }

    func testDelegatesSeeAndAnswerOnlyWhatTheirGrantCovers() async throws {
        try await harness { h in
            let s = try await scene(h)
            _ = try await h.shareAccess(from: s.alex, to: s.sam, purposes: [.transactional], businesses: [s.northwind])
            let inScope = try await confirm(h, s.northwind, s.alexNorthwind, title: "In scope")
            let otherPurpose = try await confirm(h, s.northwind, s.alexNorthwind, purpose: .support, title: "Wrong purpose")
            let otherBusiness = try await confirm(h, s.juniper, s.alexJuniper, title: "Wrong business")
            let authorize = try await h.issue(s.northwind, relationship: s.alexNorthwind, payload: .authorize(.sample())).json(Interaction.self)
            // Sam's own list shows exactly the in-scope item; the grantor's id is carried in the scope.
            let page = try await h.signed(s.sam, .GET, "/v1/interactions").json(Page<InteractionEnvelope>.self)
            XCTAssertEqual(page.items.map(\.id), [inScope.id])
            XCTAssertEqual(page.items[0].interaction.scope.consumerId, s.alex.id)
            XCTAssertEqual(page.items[0].business.id, s.northwind.id)
            for hidden in [otherPurpose.id, otherBusiness.id, authorize.id] {
                try await eq(try await h.signed(s.sam, .GET, "/v1/interactions/\(hidden)").status, .notFound)
                let signed = try await h.decision(s.sam, interaction: otherPurpose, decision: .confirm, assurance: .biometric)
                try await eq(try await h.decide(s.sam, id: hidden, signed: signed).status, .notFound)
            }
            try await eq(try await h.signed(s.sam, .GET, "/v1/interactions/\(inScope.id)").status, .ok)
            // Alex still sees all four; a stranger sees none.
            let alexPage = try await h.signed(s.alex, .GET, "/v1/interactions").json(Page<InteractionEnvelope>.self)
            XCTAssertEqual(alexPage.items.count, 4)
            let lee = try await h.readyConsumer(name: "Lee")
            try await eq(try await h.signed(lee, .GET, "/v1/interactions").json(Page<InteractionEnvelope>.self).items.isEmpty, true)
            try await eq(try await h.signed(lee, .GET, "/v1/interactions/\(inScope.id)").status, .notFound)
            // The manager confirms on Alex's behalf with Sam's own device key.
            let real = try await h.signed(s.sam, .GET, "/v1/interactions/\(inScope.id)").json(InteractionEnvelope.self).interaction
            let decision = try await h.decision(s.sam, interaction: real, decision: .confirm, assurance: .biometric)
            let decided = try await h.decide(s.sam, id: inScope.id, signed: decision)
            XCTAssertEqual(decided.status, .ok, decided.text)
            XCTAssertEqual(try decided.json(InteractionOutcome.self).status, .confirmed)
            let record = try await DecisionRecord.query(on: h.db).filter(\.$interactionId == inScope.id.uuid).first().unwrap()
            XCTAssertEqual(record.consumerId, s.alex.id.uuid, "the decision is Alex's")
            XCTAssertEqual(record.deviceId, s.sam.device!.id.uuid, "…made on Sam's device")
            let used = try await AuditEventRecord.query(on: h.db).filter(\.$action == "delegation.used").all()
            XCTAssertEqual(used.count, 1)
            XCTAssertEqual(used[0].consumerId, s.alex.id.uuid)
            XCTAssertEqual(used[0].actorId, s.sam.id.description)
            XCTAssertEqual(used[0].businessId, s.northwind.id.uuid)
            // Single use still holds: Alex can't decide it again.
            let again = try await h.decision(s.alex, interaction: real, decision: .confirm)
            try await eq(try await h.decide(s.alex, id: inScope.id, signed: again).status, .conflict)
        }
    }

    func testADelegateCanNeverApproveAnAuthorizeOrAuthenticateAndDenialsAreAudited() async throws {
        try await harness { h in
            let s = try await scene(h)
            // Alex gives Sam security + transactional access, with a manager role, via the sensitive (Face ID) path.
            _ = try await h.shareAccess(from: s.alex, to: s.sam, purposes: [.security, .transactional], businesses: [s.northwind])
            let authorize = try await h.issue(s.northwind, relationship: s.alexNorthwind, payload: .authorize(.sample())).json(Interaction.self)
            let authenticate = try await h.issue(s.northwind, relationship: s.alexNorthwind, payload: .authenticate(AuthenticatePayload(service: "Northwind portal", device: "Chrome on Mac", attemptedAt: h.clock.now())),
                                                 ttl: 600).json(Interaction.self)
            // Sam can see both (that is what security access means)…
            let seen = try await h.signed(s.sam, .GET, "/v1/interactions").json(Page<InteractionEnvelope>.self).items.map(\.id)
            XCTAssertEqual(Set(seen), [authorize.id, authenticate.id])
            // …but no decision on them is ever accepted: approve, deny and report, at every assurance level.
            for interaction in [authorize, authenticate] {
                let real = try await h.signed(s.sam, .GET, "/v1/interactions/\(interaction.id)").json(InteractionEnvelope.self).interaction
                for decision in [Decision.approve, .deny, .report] {
                    for assurance in [DecisionAssurance.biometric, .devicePasscode] {
                        let signed = try await h.decision(s.sam, interaction: real, decision: decision, assurance: assurance)
                        let result = try await h.decide(s.sam, id: interaction.id, signed: signed)
                        XCTAssertEqual(result.status, .forbidden, "\(interaction.kind) \(decision) \(assurance): \(result.text)")
                    }
                }
                let envelope = try await h.signed(s.alex, .GET, "/v1/interactions/\(interaction.id)").json(InteractionEnvelope.self)
                XCTAssertEqual(envelope.status, .pending, "nothing was recorded")
            }
            let decisions = try await DecisionRecord.query(on: h.db).count()
            XCTAssertEqual(decisions, 0)
            let denied = try await AuditEventRecord.query(on: h.db).filter(\.$action == "delegation.denied").all()
            XCTAssertEqual(denied.count, 12)
            XCTAssertTrue(denied.allSatisfy { $0.outcome == "denied" && $0.actorId == s.sam.id.description && $0.consumerId == s.alex.id.uuid })
            // The owner still can, on her own device.
            let owner = try await h.consumerInteraction(s.alex, id: authorize.id)
            let approve = try await h.decision(s.alex, interaction: owner, decision: .approve, assurance: .biometric)
            try await eq(try await h.decide(s.alex, id: authorize.id, signed: approve).status, .ok)
            // The grantor's household feed shows each blocked attempt.
            let feed = try await h.signed(s.alex, .GET, "/v1/household/audit").json([HouseholdAuditEntry].self)
            XCTAssertEqual(feed.filter { $0.action == "delegation.denied" }.count, 12)
            let first = try XCTUnwrap(feed.first { $0.action == "delegation.denied" })
            XCTAssertEqual(first.outcome, .denied)
            XCTAssertEqual(first.actorName, "Sam")
            XCTAssertEqual(first.businessName, "Northwind Air")
            XCTAssertEqual(first.onBehalfOfName, "you")
        }
    }

    func testViewersCannotRespondAndManagersCannotAcknowledgeOrReply() async throws {
        try await harness { h in
            let s = try await scene(h)
            let lee = try await h.readyConsumer(name: "Lee")
            _ = try await h.shareAccess(from: s.alex, to: lee, purposes: [.transactional], businesses: [s.northwind], role: .viewer)
            _ = try await h.shareAccess(from: s.alex, to: s.sam, purposes: [.transactional, .support], businesses: [s.northwind], role: .manager)
            let item = try await confirm(h, s.northwind, s.alexNorthwind)
            // A viewer sees it but can't answer.
            try await eq(try await h.signed(lee, .GET, "/v1/interactions").json(Page<InteractionEnvelope>.self).items.count, 1)
            let real = try await h.consumerInteraction(s.alex, id: item.id)
            let viewerTry = try await h.decide(lee, id: item.id, signed: try await h.decision(lee, interaction: real, decision: .confirm))
            XCTAssertEqual(viewerTry.status, .forbidden)
            // A manager may confirm, decline and choose, but not acknowledge terms or send free text for someone else.
            let ack = try await h.issue(s.northwind, relationship: s.alexNorthwind, payload: .acknowledge(AcknowledgePayload(title: "Terms", body: "Please read")), purpose: .support).json(Interaction.self)
            let ackReal = try await h.consumerInteraction(s.alex, id: ack.id)
            let managerAck = try await h.decide(s.sam, id: ack.id, signed: try await h.decision(s.sam, interaction: ackReal, decision: .acknowledge))
            XCTAssertEqual(managerAck.status, .forbidden)
            let reply = try await h.issue(s.northwind, relationship: s.alexNorthwind, payload: .reply(ReplyPayload(prompt: "Any notes?")), purpose: .support).json(Interaction.self)
            let replyReal = try await h.consumerInteraction(s.alex, id: reply.id)
            let managerReply = try await h.decide(s.sam, id: reply.id, signed: try await h.decision(s.sam, interaction: replyReal, decision: .reply, reply: "ok"))
            XCTAssertEqual(managerReply.status, .forbidden)
            let decline = try await h.decide(s.sam, id: item.id, signed: try await h.decision(s.sam, interaction: real, decision: .decline))
            XCTAssertEqual(decline.status, .ok, decline.text)
            let denials = try await AuditEventRecord.query(on: h.db).filter(\.$action == "delegation.denied").count()
            XCTAssertEqual(denials, 3)
        }
    }

    func testExpiredAndRevokedGrantsStopWorkingImmediately() async throws {
        try await harness { h in
            let s = try await scene(h)
            let grant = try await h.shareAccess(from: s.alex, to: s.sam, purposes: [.transactional], businesses: [s.northwind], lifetimeDays: 2)
            let item = try await confirm(h, s.northwind, s.alexNorthwind)
            let real = try await h.consumerInteraction(s.alex, id: item.id)
            try await eq(try await h.signed(s.sam, .GET, "/v1/interactions").json(Page<InteractionEnvelope>.self).items.count, 1)
            // The delegate may end their own access; a stranger may not touch it; repeats are harmless.
            let lee = try await h.readyConsumer(name: "Lee")
            try await eq(try await h.signed(lee, .DELETE, "/v1/delegations/\(grant.id)").status, .notFound)
            try await eq(try await h.signed(s.sam, .DELETE, "/v1/delegations/\(grant.id)").status, .ok)
            try await eq(try await h.signed(s.sam, .DELETE, "/v1/delegations/\(grant.id)").status, .ok)
            try await eq(try await h.signed(s.sam, .GET, "/v1/interactions").json(Page<InteractionEnvelope>.self).items.isEmpty, true)
            try await eq(try await h.signed(s.sam, .GET, "/v1/interactions/\(item.id)").status, .notFound)
            try await eq(try await h.decide(s.sam, id: item.id, signed: try await h.decision(s.sam, interaction: real, decision: .confirm)).status, .notFound)
            try await eq(try await h.household(s.alex).given.first?.status, .revoked)
            try await eq(try await h.household(s.sam).received.first?.status, .revoked)
            // A fresh grant that simply runs out.
            let second = try await h.shareAccess(from: s.alex, to: s.sam, purposes: [.transactional], businesses: [s.northwind], lifetimeDays: 2)
            try await eq(try await h.signed(s.sam, .GET, "/v1/interactions").json(Page<InteractionEnvelope>.self).items.count, 1)
            h.clock.advance(by: 2 * 86_400 + 1)
            let late = try await confirm(h, s.northwind, s.alexNorthwind, title: "Later")
            try await eq(try await h.signed(s.sam, .GET, "/v1/interactions").json(Page<InteractionEnvelope>.self).items.isEmpty, true)
            try await eq(try await h.signed(s.sam, .GET, "/v1/interactions/\(late.id)").status, .notFound)
            try await eq(try await h.household(s.sam).received.first { $0.grant.id == second.grant.id }?.status, .expired, "status is computed by the server")
            // Expiry is written to the household audit exactly once.
            try await h.runJobs()
            try await h.runJobs()
            let expired = try await AuditEventRecord.query(on: h.db).filter(\.$action == "delegation.expired").all()
            XCTAssertEqual(expired.count, 1)
            XCTAssertEqual(expired[0].subjectId, second.grant.id.description)
        }
    }

    func testHouseholdAuditFeedNamesWhoDidWhatForWhomAndNothingElse() async throws {
        try await harness { h in
            let s = try await scene(h)
            let grant = try await h.shareAccess(from: s.alex, to: s.sam, purposes: [.transactional], businesses: [s.northwind])
            let item = try await confirm(h, s.northwind, s.alexNorthwind)
            let real = try await h.consumerInteraction(s.alex, id: item.id)
            h.clock.advance(by: 60)
            try await eq(try await h.decide(s.sam, id: item.id, signed: try await h.decision(s.sam, interaction: real, decision: .confirm)).status, .ok)
            h.clock.advance(by: 60)
            try await eq(try await h.signed(s.alex, .DELETE, "/v1/delegations/\(grant.id)").status, .ok)
            let lee = try await h.readyConsumer(name: "Lee")
            try await eq(try await h.signed(lee, .GET, "/v1/household/audit").json([HouseholdAuditEntry].self).isEmpty, true, "strangers see nothing")
            // Alex (grantor): newest first.
            let alexFeed = try await h.signed(s.alex, .GET, "/v1/household/audit").json([HouseholdAuditEntry].self)
            XCTAssertEqual(alexFeed.map(\.action), ["delegation.revoked", "delegation.used", "delegation.accepted", "delegation.created"])
            XCTAssertEqual(alexFeed.map(\.actorName), ["You", "Sam", "Sam", "You"], "Alex sees the delegate by the label she chose")
            XCTAssertEqual(alexFeed[1].businessName, "Northwind Air")
            XCTAssertEqual(alexFeed[1].onBehalfOfName, "you")
            XCTAssertNil(alexFeed[0].onBehalfOfName)
            XCTAssertTrue(alexFeed.allSatisfy { $0.outcome == .success })
            XCTAssertTrue(zip(alexFeed, alexFeed.dropFirst()).allSatisfy { $0.occurredAt >= $1.occurredAt })
            // Sam (delegate): his own actions, with the grantor's real name.
            let samFeed = try await h.signed(s.sam, .GET, "/v1/household/audit").json([HouseholdAuditEntry].self)
            XCTAssertEqual(samFeed.map(\.action), ["delegation.used", "delegation.accepted"])
            XCTAssertEqual(samFeed.map(\.actorName), ["You", "You"])
            XCTAssertEqual(samFeed[0].onBehalfOfName, "Alex")
            // No codes, labels or ids leak through the feed or the underlying audit rows.
            let raw = String(decoding: try ViadereJSON.encode(alexFeed + samFeed), as: UTF8.self)
            XCTAssertFalse(raw.contains(s.sam.id.description))
            for event in try await AuditEventRecord.query(on: h.db).filter(\.$subjectType == "delegation").all() {
                XCTAssertFalse(event.metadataJSON.contains("Sam"))
            }
            let chain = try await AuditService.verifyChain(on: h.db)
            XCTAssertTrue(chain.valid)
        }
    }

    func testListingDirectCreationAndAccountDeletion() async throws {
        try await harness { h in
            let s = try await scene(h)
            let grant = try await h.shareAccess(from: s.alex, to: s.sam, purposes: [.transactional], businesses: [s.northwind])
            let listed = try await h.signed(s.sam, .GET, "/v1/delegations").json([DelegationGrant].self)
            XCTAssertEqual(listed.map(\.id), [grant.grant.id])
            // Granting by account id is not a thing: the delegate has to accept.
            let direct = try await h.signedPost(s.alex, "/v1/delegations", CreateDelegationRequest(delegateId: s.sam.id, role: .manager, purposes: [.transactional],
                                                                                              businessIds: [s.northwind.id], expiresAt: h.clock.now().addingTimeInterval(86_400)))
            XCTAssertEqual(direct.status, .gone)
            // Deleting the grantor's account ends every grant and cancels open invitations.
            let open = try await h.invite(s.alex, h.invitation(purposes: [.support], businesses: [s.northwind])).json(DelegationInvitation.self)
            try await eq(try await h.signed(s.alex, .DELETE, "/v1/account").status, .ok)
            let record = try await DelegationGrantRecord.query(on: h.db).first().unwrap()
            XCTAssertNotNil(record.revokedAt)
            try await eq(try await accept(h, s.sam, open.code).status, .gone)
            try await eq(try await h.household(s.sam).received.first?.status, .revoked)
            try await eq(try await h.household(s.sam).received.first?.counterpartName, "Deleted account")
        }
    }

    func testStepUpDoesNotApplyToOrdinaryScopesAndTheClientFlagCannotWeakenAnything() async throws {
        try await harness { h in
            let s = try await scene(h)
            var request = h.invitation(purposes: [.transactional, .support, .rewards], businesses: [s.northwind])
            request.includesSensitiveScope = true   // harmless: the server recomputes sensitivity from the purposes
            try await eq(try await h.invite(s.alex, request).status, .created)
            XCTAssertFalse(DelegationScopePolicy.includesSensitiveScope(purposes: request.purposes))
        }
    }
}
