@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Shared helpers for the P3 (rewards, Wallet, Live Activity, household) tests.
extension TestHarness {
    // MARK: Business: program and rewards

    @discardableResult
    func saveProgram(_ b: TestBusiness, timeZone: String = "America/Phoenix", terms: String = "v1",
                     tiers: [LoyaltyTier] = [LoyaltyTier(name: "Silver", minimumPoints: 100), LoyaltyTier(name: "Gold", minimumPoints: 500)]) async throws -> BusinessLoyaltyProgram {
        let body = UpsertLoyaltyProgramRequest(programName: "\(b.summary.displayName) Club", summary: "Earn points on every visit.", termsVersion: terms,
                                               timeZone: timeZone, tiers: tiers)
        let response = try await business(b, .PUT, "/v1/business/loyalty/program", body: try ViadereJSON.encode(body))
        XCTAssertEqual(response.status, .ok, response.text)
        return try response.json(BusinessLoyaltyProgram.self)
    }

    func createReward(_ b: TestBusiness, _ request: IssueRewardRequest) async throws -> HTTPResult {
        try await businessPost(b, "/v1/business/rewards", request, idempotencyKey: request.idempotencyKey)
    }

    func reward(_ b: TestBusiness, title: String = "Free coffee", kind: RewardKind = .perk, relationship: Relationship? = nil,
                recurrence: RewardRecurrence? = nil, pointsCost: Int? = nil, validFrom: Date? = nil, validUntil: Date? = nil,
                key: String = UUID().uuidString) async throws -> Reward {
        let response = try await createReward(b, IssueRewardRequest(relationshipId: relationship?.id, title: title, kind: kind, validFrom: validFrom,
                                                                    validUntil: validUntil, recurrence: recurrence, pointsCost: pointsCost, idempotencyKey: key))
        XCTAssertEqual(response.status, .created, response.text)
        return try response.json(Reward.self)
    }

    @discardableResult
    func adjustPoints(_ b: TestBusiness, _ relationship: Relationship, _ delta: Int, key: String = UUID().uuidString) async throws -> HTTPResult {
        try await businessPost(b, "/v1/business/loyalty/points", AdjustLoyaltyPointsRequest(relationshipId: relationship.id, delta: delta, reason: "purchase", idempotencyKey: key),
                               idempotencyKey: key)
    }

    func consume(_ b: TestBusiness, code: String, location: String? = nil) async throws -> HTTPResult {
        try await businessPost(b, "/v1/business/redemptions/consume", ConsumeRedemptionRequest(code: code, locationCode: location))
    }

    // MARK: Consumer

    func overview(_ consumer: TestConsumer) async throws -> RewardsOverview {
        let response = try await signed(consumer, .GET, "/v1/rewards/overview")
        XCTAssertEqual(response.status, .ok, response.text)
        return try response.json(RewardsOverview.self)
    }

    func entry(_ consumer: TestConsumer, _ rewardId: RewardID) async throws -> RewardEntry {
        let found = try await overview(consumer).rewards.first { $0.id == rewardId }
        return try XCTUnwrap(found)
    }

    @discardableResult
    func enroll(_ consumer: TestConsumer, _ b: TestBusiness, terms: String = "v1", reference: String? = nil) async throws -> HTTPResult {
        try await signedPost(consumer, "/v1/loyalty/\(b.id)/enroll", LoyaltyEnrollRequest(existingMemberReference: reference, acceptedTermsVersion: terms))
    }

    func redeem(_ consumer: TestConsumer, _ rewardId: RewardID, location: String? = nil) async throws -> HTTPResult {
        try await signedPost(consumer, "/v1/rewards/\(rewardId)/redeem", RedeemRewardRequest(locationCode: location))
    }

    func claim(_ consumer: TestConsumer, _ rewardId: RewardID) async throws -> HTTPResult {
        try await signed(consumer, .POST, "/v1/rewards/\(rewardId)/claim", body: Data("{}".utf8))
    }

    // MARK: Time

    /// Sets the manual clock to a wall-clock moment in a zone, e.g. `at("2027-01-12 09:30", "America/Phoenix")`.
    func setClock(_ text: String, _ zone: String) {
        clock.set(Self.date(text, zone))
    }

    static func date(_ text: String, _ zone: String) -> Date {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: zone)
        formatter.dateFormat = "yyyy-MM-dd HH:mm"
        return formatter.date(from: text)!
    }

    // MARK: Household

    /// A signed delegation invitation request with a valid (or deliberately altered) biometric step-up.
    func invitation(label: String = "Sam", role: DelegationGrant.Role = .manager, purposes: [InteractionPurpose], businesses: [TestBusiness],
                    lifetimeDays: Double = 7) -> DelegationInvitationRequest {
        DelegationInvitationRequest(
            delegateLabel: label, role: role, purposes: purposes, businessIds: businesses.map(\.id),
            expiresAt: ViadereDate.truncatedToMilliseconds(clock.now().addingTimeInterval(lifetimeDays * 86_400)),
            includesSensitiveScope: DelegationScopePolicy.includesSensitiveScope(purposes: purposes))
    }

    func stepUp(_ consumer: TestConsumer, for request: DelegationInvitationRequest, key: SoftwareP256SigningKey? = nil, at: Date? = nil,
                device: DeviceID? = nil) async throws -> DelegationStepUpProof {
        let device = device ?? consumer.device!.id
        var proof = DelegationStepUpProof(deviceId: device, signedAt: ViadereDate.truncatedToMilliseconds(at ?? clock.now()),
                                          scopeDigest: DelegationScopePolicy.scopeDigest(of: request), signature: "")
        let signer = key ?? consumer.device!.biometricKey
        proof.signature = ViadereSignatureEncoding.encode(try await signer.signature(for: proof.signingInput()))
        return proof
    }

    func invite(_ consumer: TestConsumer, _ request: DelegationInvitationRequest) async throws -> HTTPResult {
        try await signedPost(consumer, "/v1/household/invitations", request)
    }

    func household(_ consumer: TestConsumer) async throws -> HouseholdOverview {
        let response = try await signed(consumer, .GET, "/v1/household")
        XCTAssertEqual(response.status, .ok, response.text)
        return try response.json(HouseholdOverview.self)
    }

    /// Grantor invites, delegate accepts. Returns the active grant.
    func shareAccess(from grantor: TestConsumer, to delegate: TestConsumer, purposes: [InteractionPurpose], businesses: [TestBusiness],
                     role: DelegationGrant.Role = .manager, lifetimeDays: Double = 7) async throws -> HouseholdGrant {
        var request = invitation(role: role, purposes: purposes, businesses: businesses, lifetimeDays: lifetimeDays)
        if request.includesSensitiveScope { request.stepUp = try await stepUp(grantor, for: request) }
        let created = try await invite(grantor, request)
        XCTAssertEqual(created.status, .created, created.text)
        let code = try created.json(DelegationInvitation.self).code
        let accepted = try await signedPost(delegate, "/v1/household/invitations/accept", DelegationInvitationRedeemRequest(code: code))
        XCTAssertEqual(accepted.status, .ok, accepted.text)
        return try accepted.json(HouseholdGrant.self)
    }
}

/// Collects the entries of a `.pkpass` for assertions.
struct PKPassContents {
    var files: [String: Data]
    var passJSON: [String: Any]
    var manifest: [String: String]

    init(_ data: Data) throws {
        let entries = try ZipArchive.read(data)
        files = Dictionary(entries.map { ($0.name, $0.data) }, uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(files.count, entries.count, "no duplicate names")
        passJSON = try XCTUnwrap(JSONSerialization.jsonObject(with: try XCTUnwrap(files["pass.json"])) as? [String: Any])
        manifest = try XCTUnwrap(JSONSerialization.jsonObject(with: try XCTUnwrap(files["manifest.json"])) as? [String: String])
    }

    func sha1(_ name: String) -> String { Hex.encode(Insecure.SHA1.hash(data: files[name] ?? Data())) }
}
