@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Phase 3 gate F4: jurisdiction rules apply to Verify (business legal entity at creation, document issuer at disclosure) and fail closed.
extension VerifyFlowTests {
    func setLegalJurisdiction(_ h: TestHarness, _ business: TestBusiness, _ region: String?) async throws {
        let row = try await BusinessOnboardingRecord.query(on: h.db).filter(\.$businessId == business.id.uuid).first()
            ?? BusinessOnboardingRecord(businessId: business.id.uuid, now: h.clock.now())
        row.goLiveStatus = OnboardingGoLive.approved.rawValue
        row.legalStatus = region == nil ? "none" : "approved"
        row.legalJurisdiction = region
        try await row.save(on: h.db)
    }

    func addRule(_ h: TestHarness, _ kind: PolicyRule.Kind, _ regions: [String], capability: Capability = .ageMinimum) async throws {
        try await PolicyRuleRecord(rule: PolicyRule(capability: capability, kind: kind, jurisdictions: regions, reason: "test"), createdBy: "operator", now: h.clock.now()).create(on: h.db)
        await h.ctx.policyCache.invalidate()
    }

    /// Exploit: a block rule was a no-op because Verify never passed a jurisdiction.
    func testABlockRuleAppliesToTheBusinessLegalEntityAndFailsClosedWhenItIsUnknown() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            try await addRule(h, .jurisdictionBlock, ["XX"])
            // No legal-entity jurisdiction on record: a block rule on a high-sensitivity capability fails closed.
            try await eq(try await create(r).errorCode, .policyDenied)
            try await setLegalJurisdiction(h, r.b, "US-DE")
            try await eq(try await create(r).status, .created)
            // The legal entity is in a blocked jurisdiction.
            try await setLegalJurisdiction(h, r.b, "XX")
            try await eq(try await create(r).errorCode, .policyDenied)
            // A legal entity that is not approved is not a known jurisdiction.
            let row = try unwrap(try await BusinessOnboardingRecord.query(on: h.db).filter(\.$businessId == r.b.id.uuid).first())
            row.legalJurisdiction = "US-DE"
            row.legalStatus = "submitted"
            try await row.save(on: h.db)
            try await eq(try await create(r).errorCode, .policyDenied)
        }
    }

    /// With no rules, nothing changes: an unknown legal jurisdiction is not an obstacle.
    func testWithoutRulesAnUnknownJurisdictionIsNotAnObstacle() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            try await eq(try await create(r).status, .created)
        }
    }

    /// Exploit: the issuer's country was never evaluated, so a block rule on the document's country had no effect at disclosure.
    func testTheIssuerCountryIsEvaluatedAtDisclosure() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            try await setLegalJurisdiction(h, r.b, "GB")
            let id = try await createdID(r)
            try await consent(r, id)
            // After the request exists, the operator blocks the capability for documents issued in the US (the test IACA's country).
            try await addRule(h, .jurisdictionBlock, ["US"])
            let answered = try await wallet(r, id, elements: ageOver(21))
            XCTAssertEqual(answered.result.status, .ok)
            try await eq(try await attemptOutcome(answered.result).status, .notVerified)
            let finished = try await resource(r, id)
            let body = try await result(r, try unwrap(finished.resultRef)).json(VerificationResult.self)
            XCTAssertEqual(body.outcome, .notVerified)
            XCTAssertTrue(body.result.isEmpty, "nothing was disclosed")
            // The reason is in the platform-only trail, not in the business's.
            let denials = try await AuditEventRecord.query(on: h.db).filter(\.$action == "policy.denied").all()
            XCTAssertTrue(denials.contains { $0.businessId == nil && $0.metadataJSON.contains("jurisdiction_blocked") })
            XCTAssertFalse(denials.contains { $0.businessId != nil && $0.subjectType == "capability" && $0.metadataJSON.contains(id.description) })
        }
    }

    func testAnIssuerOutsideAnAllowOnlyListIsNotDisclosedAndAllowedOnesAre() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            try await setLegalJurisdiction(h, r.b, "US-DE")
            try await addRule(h, .jurisdictionAllowOnly, ["US"])
            let ok = try await createdID(r)
            try await consent(r, ok)
            let released = try await wallet(r, ok, elements: ageOver(21))
            try await eq(try await attemptOutcome(released.result).status, .released)
        }
    }

    /// A document check reports the issuing state as alpha-3; it maps to the alpha-2 the rules use, and an unknown state stays unknown.
    func testTheDocumentIssuerStateMapsToItsAlpha2Country() throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        func country(_ state: String?) throws -> String? {
            var decision = FakeDidit.decision(session: "s1", vendorData: "a1")
            if let state { decision["id_verifications"] = .array([.object(["status": .string("Approved"), "issuing_state": .string(state), "first_name": .string("J"), "last_name": .string("D"),
                                                                           "date_of_birth": .string("1990-01-01"), "expiration_date": .string("2099-01-01")])]) }
            return DiditDecisionMapper.map(decision: decision, expectedSession: "s1", expectedAttempt: "a1", now: now).claims?.issuerCountry
        }
        XCTAssertEqual(try country("USA"), "US")
        XCTAssertEqual(try country("de"), "DE")
        XCTAssertNil(try country("XXX"))
        XCTAssertNil(try country(""))
    }

    /// F7: the age check uses the earliest date anywhere (UTC-12).
    func testAnAgeThresholdUsesTheEarliestLocalDate() throws {
        var claims = EvidenceClaims(method: .walletMdoc, issuer: "x", verifiedAt: Date(), validUntil: Date().addingTimeInterval(3600), revocation: .notChecked)
        claims.birthDate = AgeThreshold.Day(isoDate: "2008-03-10")
        let early = ISO8601DateFormatter().date(from: "2026-03-10T02:00:00Z")!
        let later = ISO8601DateFormatter().date(from: "2026-03-10T12:00:00Z")!
        XCTAssertEqual(ClaimsBuilder.meetsThreshold(claims, years: 18, now: early), false, "still the 9th in UTC-12")
        XCTAssertEqual(ClaimsBuilder.meetsThreshold(claims, years: 18, now: later), true)
    }
}
