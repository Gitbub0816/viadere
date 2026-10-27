import Crypto
import Foundation
import Testing
@testable import ViadereCore

@Suite("P3 contract")
struct P3ContractTests {
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func request(purposes: [InteractionPurpose] = [.security], lifetime: TimeInterval = 7 * 86_400,
                         label: String = "Sam") -> DelegationInvitationRequest {
        DelegationInvitationRequest(delegateLabel: label, role: .manager, purposes: purposes,
                                    businessIds: [BusinessID("22222222-2222-4222-8222-222222222222")!, BusinessID("11111111-1111-4111-8111-111111111111")!],
                                    expiresAt: ViadereDate.truncatedToMilliseconds(now.addingTimeInterval(lifetime)),
                                    includesSensitiveScope: true)
    }

    private func proof(for request: DelegationInvitationRequest, deviceId: DeviceID, key: SoftwareP256SigningKey, signedAt: Date) async throws -> DelegationStepUpProof {
        var proof = DelegationStepUpProof(deviceId: deviceId, signedAt: ViadereDate.truncatedToMilliseconds(signedAt),
                                          scopeDigest: DelegationScopePolicy.scopeDigest(of: request), signature: "")
        proof.signature = ViadereSignatureEncoding.encode(try await key.signature(for: proof.signingInput()))
        return proof
    }

    // MARK: Canonicalization

    @Test("Canonical scope is order independent, labelled, and pinned")
    func canonicalScope() {
        let a = request(purposes: [.security, .accountService])
        var b = a
        b.purposes = [.accountService, .security]
        b.businessIds = a.businessIds.reversed()
        #expect(DelegationScopePolicy.canonicalScope(of: a) == DelegationScopePolicy.canonicalScope(of: b))
        #expect(DelegationScopePolicy.scopeDigest(of: a) == DelegationScopePolicy.scopeDigest(of: b))
        let text = DelegationScopePolicy.canonicalScope(of: a)
        #expect(text == """
            role=manager
            purposes=accountService,security
            businesses=11111111-1111-4111-8111-111111111111,22222222-2222-4222-8222-222222222222
            expires=\(ViadereDate.format(a.expiresAt))
            label=Sam
            """)
        #expect(DelegationScopePolicy.scopeDigest(of: a).count == 64)
        var other = a
        other.delegateLabel = "Sam "
        #expect(DelegationScopePolicy.scopeDigest(of: other) != DelegationScopePolicy.scopeDigest(of: a))
    }

    @Test("Sensitive purposes and lifetimes")
    func sensitive() {
        #expect(DelegationScopePolicy.includesSensitiveScope(purposes: [InteractionPurpose.rewards, .security]))
        #expect(!DelegationScopePolicy.includesSensitiveScope(purposes: [InteractionPurpose.rewards, .support]))
        #expect(DelegationScopePolicy.maximumLifetime(includesSensitive: true) == 30 * 86_400)
        #expect(DelegationScopePolicy.maximumLifetime(includesSensitive: false) == DelegationGrant.maxLifetime)
    }

    @Test("Delegates can never decide authenticate or authorize; viewers decide nothing")
    func delegateDecisions() {
        for decision in Decision.allCases {
            #expect(!DelegationScopePolicy.delegateMayDecide(role: .manager, kind: .authenticate, decision: decision))
            #expect(!DelegationScopePolicy.delegateMayDecide(role: .manager, kind: .authorize, decision: decision))
            #expect(!DelegationScopePolicy.delegateMayDecide(role: .viewer, kind: .confirm, decision: decision))
        }
        #expect(DelegationScopePolicy.delegateMayDecide(role: .manager, kind: .confirm, decision: .confirm))
        #expect(DelegationScopePolicy.delegateMayDecide(role: .manager, kind: .choose, decision: .select))
        #expect(!DelegationScopePolicy.delegateMayDecide(role: .manager, kind: .acknowledge, decision: .acknowledge))
    }

    // MARK: Step-up verification

    @Test("A fresh proof from the biometric key verifies")
    func stepUpOK() async throws {
        let key = SoftwareP256SigningKey()
        let device = DeviceID()
        let req = request()
        let p = try await proof(for: req, deviceId: device, key: key, signedAt: now)
        try DelegationStepUpVerifier.verify(p, for: req, deviceId: device, publicKey: key.publicKey, now: now.addingTimeInterval(5))
    }

    @Test("Wrong key, wrong device, other scope, stale, future and missing proofs are rejected")
    func stepUpRejections() async throws {
        let key = SoftwareP256SigningKey()
        let other = SoftwareP256SigningKey()
        let device = DeviceID()
        let req = request()
        let good = try await proof(for: req, deviceId: device, key: key, signedAt: now)
        func check(_ p: DelegationStepUpProof?, _ request: DelegationInvitationRequest, _ failure: DelegationStepUpVerifier.Failure,
                   key verifyKey: SoftwareP256SigningKey? = nil, device d: DeviceID? = nil, at: Date? = nil) {
            #expect(throws: failure) {
                try DelegationStepUpVerifier.verify(p, for: request, deviceId: d ?? device, publicKey: (verifyKey ?? key).publicKey, now: at ?? now)
            }
        }
        check(nil, req, .missing)
        check(good, req, .badSignature, key: other)                 // signed by a different purpose key
        check(good, req, .deviceMismatch, device: DeviceID())
        var widened = req
        widened.purposes = [.security, .accountService]
        check(good, widened, .scopeMismatch)                        // scope changed after signing
        check(good, req, .tooOld, at: now.addingTimeInterval(301))
        check(good, req, .signedInFuture, at: now.addingTimeInterval(-61))
        var forged = good
        forged.signature = String(repeating: "A", count: 86)
        check(forged, req, .badSignature)
        var short = good
        short.signature = "abc"
        check(short, req, .malformedSignature)
        var tampered = good
        tampered.signedAt = tampered.signedAt.addingTimeInterval(1)
        check(tampered, req, .badSignature)                         // signature covers signedAt
    }

    @Test("A proof is single use through the replay guard")
    func stepUpReplay() async throws {
        let key = SoftwareP256SigningKey()
        let device = DeviceID()
        let req = request()
        let p = try await proof(for: req, deviceId: device, key: key, signedAt: now)
        let guardian = InMemoryReplayGuard()
        try await DelegationStepUpVerifier.verify(p, for: req, deviceId: device, publicKey: key.publicKey, now: now, replayGuard: guardian)
        await #expect(throws: DelegationStepUpVerifier.Failure.replayed) {
            try await DelegationStepUpVerifier.verify(p, for: req, deviceId: device, publicKey: key.publicKey, now: now, replayGuard: guardian)
        }
    }

    @Test("Signing input pins the domain, device, time and digest")
    func signingInput() {
        let device = DeviceID("33333333-3333-4333-8333-333333333333")!
        let p = DelegationStepUpProof(deviceId: device, signedAt: Date(timeIntervalSince1970: 1_800_000_000.123), scopeDigest: "ab12", signature: "")
        #expect(String(decoding: p.signingInput(), as: UTF8.self)
                == "VIADERE-DELEGATION-STEPUP-V1\n33333333-3333-4333-8333-333333333333\n2027-01-15T08:00:00.123Z\nab12")
    }

    // MARK: DTO compatibility

    @Test("TicketPayload gains venue, seat and startsAt and still decodes older payloads")
    func ticketCompatibility() throws {
        let legacy = Data(#"{"title":"Concert","ticketType":"event"}"#.utf8)
        let old = try ViadereJSON.decode(TicketPayload.self, from: legacy)
        #expect(old.venue == nil && old.seat == nil && old.startsAt == nil)
        let full = TicketPayload(title: "Concert", ticketType: "event", venue: "Orpheum", seat: "Row F · 12", startsAt: now)
        let round = try ViadereJSON.decode(TicketPayload.self, from: ViadereJSON.encode(full))
        #expect(round == full)
        #expect(String(decoding: try ViadereJSON.encode(old), as: UTF8.self).contains("venue") == false)
    }

    @Test("Acknowledge payload digest must be lowercase hex")
    func acknowledgeDigest() {
        func issues(_ digest: String?) -> [InteractionValidation.Issue] {
            let payload = AcknowledgePayload(title: "Terms", body: "Please read", documentVersion: "2026-10", documentDigest: digest)
            let interaction = Fixtures.interaction(.acknowledge(payload), purpose: .support)
            return InteractionValidation.issues(in: interaction, now: Fixtures.now)
        }
        #expect(issues(nil).isEmpty)
        #expect(issues(String(repeating: "a", count: 64)).isEmpty)
        #expect(issues(String(repeating: "A", count: 64)).contains { $0.field == "payload.documentDigest" })
        #expect(issues("abc").contains { $0.field == "payload.documentDigest" })
    }

    @Test("Eligibility, action and kind decode unknown values defensively")
    func defensiveDecoding() throws {
        let json = Data(#"{"state":"somethingNew","nextAction":"teleport","checkedAt":"2027-01-15T08:00:00.000Z"}"#.utf8)
        let e = try ViadereJSON.decode(RewardEligibility.self, from: json)
        #expect(e.state == .unavailable && e.nextAction == RewardEligibility.Action.none)
        #expect(try ViadereJSON.decode(RewardKind.self, from: Data(#""mystery""#.utf8)) == .perk)
        let status = try ViadereJSON.decode(HouseholdGrant.Status.self, from: Data(#""frozen""#.utf8))
        #expect(status == .expired)
    }

    @Test("RewardRedemption decodes without the new server-time fields")
    func redemptionCompatibility() throws {
        let reward = Reward(id: RewardID(), business: Fixtures.walmart, title: "Coffee", status: .available)
        let value = RewardRedemption(reward: reward, redemptionCode: "ABCDE-FGHJK", expiresAt: now, validForSeconds: 120, serverTime: now)
        #expect(try ViadereJSON.decode(RewardRedemption.self, from: ViadereJSON.encode(value)) == value)
        let encoded = try ViadereJSON.encode(value)
        var object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        object.removeValue(forKey: "validForSeconds")
        object.removeValue(forKey: "serverTime")
        let old = try ViadereJSON.decode(RewardRedemption.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(old.validForSeconds == nil && old.serverTime == nil)
    }

    @Test("P3 routes are in the catalog with the contract's auth")
    func routes() {
        let all = Dictionary(uniqueKeysWithValues: APIRoutes.all.map { ($0.name, $0) })
        for name in ["rewards.overview", "loyalty.program", "loyalty.enroll", "rewards.claim", "rewards.redeem", "wallet.passes.list",
                     "wallet.passes.issue", "wallet.pass", "household.overview", "household.invitations.create",
                     "household.invitations.preview", "household.invitations.accept", "household.audit", "acknowledgments.list"] {
            #expect(all[name]?.auth == .deviceSignedBearer, "\(name)")
        }
        for name in ["business.rewards.issue", "business.rewards.list", "business.rewards.revoke", "business.loyalty.program.get",
                     "business.loyalty.program.put", "business.loyalty.points", "business.redemptions.consume"] {
            #expect(all[name]?.auth == .businessAPIKey, "\(name)")
        }
        #expect(APIRoutes.householdInvitationAccept.template == "/v1/household/invitations/accept")
        #expect(APIRoutes.businessConsumeRedemption.method == .POST)
    }

    @Test("Status updates carry an optional correlation id")
    func statusCorrelation() throws {
        let legacy = BusinessStatusUpdateRequest(relationshipId: RelationshipID(), purpose: .transactional, status: StatusPayload(title: "Ready"),
                                                 activityKey: "order-1", idempotencyKey: "k")
        #expect(legacy.correlationId == nil)
        let encoded = try ViadereJSON.encode(legacy)
        var object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        object["correlationId"] = "order-1"
        let decoded = try ViadereJSON.decode(BusinessStatusUpdateRequest.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(decoded.correlationId == "order-1")
    }
}
