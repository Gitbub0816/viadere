import Crypto
import Foundation
import ViadereCore

/// The P3 half of the in-memory server: loyalty, rewards (with server-side eligibility), Wallet passes, household
/// delegation and acknowledgment records. The mock plays the *server*, so it computes eligibility here and refuses
/// claims and redemptions that aren't eligible, exactly as the real backend must.
struct MockP3State {
    struct StoredReward {
        var reward: Reward
        var kind: RewardKind
        var pointsCost: Int?
        var requiresClaim: Bool
        var claimedAt: Date?
        /// Redemptions reserved per calendar day in the business time zone ("yyyy-MM-dd").
        var usedPerDay: [String: Int] = [:]
    }

    var programs: [BusinessID: (name: String, summary: String, terms: String)] = [:]
    var accounts: [BusinessID: LoyaltyAccount] = [:]
    var rewards: [RewardID: StoredReward] = [:]
    var rewardOrder: [RewardID] = []
    var passes: [WalletPassID: WalletPassMetadata] = [:]
    var household = HouseholdOverview()
    var invitations: [String: (request: DelegationInvitationRequest, id: DelegationID)] = [:]
    var audit: [HouseholdAuditEntry] = []
    var acknowledgments: [AcknowledgmentRecord] = []
    var issuedRedemptionCodes: [String: RewardID] = [:]
}

extension MockViadereAPI {
    // MARK: Server-side eligibility

    private static func dayKey(_ date: Date, zone: String) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: zone) ?? .current
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
    }

    func eligibility(of stored: MockP3State.StoredReward, now: Date) -> RewardEligibility {
        let reward = stored.reward
        func verdict(_ state: RewardEligibility.State, action: RewardEligibility.Action = .none, next: Date? = nil, short: Int? = nil) -> RewardEligibility {
            RewardEligibility(state: state, nextAction: action, checkedAt: now, nextEligibleAt: next, pointsShortfall: short)
        }
        switch reward.status {
        case .redeemed: return verdict(.redeemed)
        case .revoked: return verdict(.revoked)
        case .expired: return verdict(.expired)
        case .available: break
        }
        if let until = reward.validUntil, now >= until { return verdict(.expired) }
        if let from = reward.validFrom, now < from { return verdict(.notYetValid, next: from) }
        if let cost = stored.pointsCost {
            let balance = p3.accounts[reward.business.id]?.pointsBalance ?? 0
            if balance < cost { return verdict(.insufficientPoints, short: cost - balance) }
        }
        if let recurrence = reward.recurrence {
            if !recurrence.isEligible(on: now) {
                // next eligible day within a week
                let next = (1...7).compactMap { offset -> Date? in
                    let candidate = now.addingTimeInterval(Double(offset) * 86_400)
                    return recurrence.isEligible(on: candidate) ? candidate : nil
                }.first
                return verdict(.notToday, next: next)
            }
            if (stored.usedPerDay[Self.dayKey(now, zone: recurrence.timeZone)] ?? 0) >= recurrence.perDayLimit {
                return verdict(.limitReached, next: now.addingTimeInterval(86_400))
            }
        }
        if stored.requiresClaim && stored.claimedAt == nil { return verdict(.eligible, action: .claim) }
        return verdict(.eligible, action: .redeem)
    }

    func entry(for stored: MockP3State.StoredReward, now: Date) -> RewardEntry {
        RewardEntry(reward: stored.reward, kind: stored.kind, eligibility: eligibility(of: stored, now: now),
                    pointsCost: stored.pointsCost, claimedAt: stored.claimedAt)
    }

    // MARK: Rewards & loyalty

    public func rewardsOverview() async throws -> RewardsOverview {
        await pause()
        let now = clock()
        let accounts = p3.accounts.values.sorted { $0.business.displayName < $1.business.displayName }
        let entries = p3.rewardOrder.compactMap { p3.rewards[$0] }.map { entry(for: $0, now: now) }
        return RewardsOverview(accounts: accounts, rewards: entries)
    }

    public func loyaltyProgram(business: BusinessID) async throws -> LoyaltyProgramOverview {
        await pause()
        guard let program = p3.programs[business] else { throw Self.notFoundError() }
        let now = clock()
        let entries = p3.rewardOrder.compactMap { p3.rewards[$0] }.filter { $0.reward.business.id == business }.map { entry(for: $0, now: now) }
        return LoyaltyProgramOverview(programName: program.name, summary: program.summary, termsVersion: program.terms,
                                      account: p3.accounts[business], rewards: entries)
    }

    public func enrollLoyalty(business: BusinessID, _ request: LoyaltyEnrollRequest) async throws -> LoyaltyAccount {
        await pause()
        guard let program = p3.programs[business], let summary = directoryBusiness(business) else { throw Self.notFoundError() }
        guard request.acceptedTermsVersion == program.terms else {
            throw APIError.server(status: 409, code: .conflict, message: "These terms have changed. Review them and try again.")
        }
        if let existing = p3.accounts[business] { return existing }
        let account = LoyaltyAccount(
            business: summary, programName: program.name, pointsBalance: request.existingMemberReference == nil ? 0 : 320,
            statusName: "Member", nextStatusName: "Silver", pointsToNextStatus: 500, memberSince: clock(),
            memberReference: request.existingMemberReference.map { "••" + $0.suffix(4) })
        p3.accounts[business] = account
        return account
    }

    public func claimReward(_ id: RewardID) async throws -> RewardEntry {
        await pause()
        guard var stored = p3.rewards[id] else { throw Self.notFoundError() }
        let now = clock()
        let verdict = eligibility(of: stored, now: now)
        guard verdict.state == .eligible, verdict.nextAction == .claim else {
            throw APIError.server(status: 409, code: .conflict, message: "This reward can't be claimed right now.")
        }
        stored.claimedAt = now
        p3.rewards[id] = stored
        return entry(for: stored, now: now)
    }

    public func redeemReward(_ id: RewardID, _ request: RedeemRewardRequest) async throws -> RewardRedemption {
        await pause()
        guard var stored = p3.rewards[id] else { throw Self.notFoundError() }
        let now = clock()
        let verdict = eligibility(of: stored, now: now)
        guard verdict.state == .eligible, verdict.nextAction == .redeem else {
            throw APIError.server(status: 409, code: .conflict, message: "This reward isn't available right now.")
        }
        if let recurrence = stored.reward.recurrence {
            stored.usedPerDay[Self.dayKey(now, zone: recurrence.timeZone), default: 0] += 1
        } else {
            stored.reward.status = .redeemed
            stored.reward.redeemedAt = now
        }
        if let cost = stored.pointsCost, var account = p3.accounts[stored.reward.business.id] {
            account.pointsBalance -= cost
            p3.accounts[stored.reward.business.id] = account
        }
        p3.rewards[id] = stored
        let alphabet = Array("ABCDEFGHJKMNPQRSTUVWXYZ23456789")
        let code = String((0..<8).map { _ in alphabet[Int.random(in: 0..<alphabet.count)] })
        p3.issuedRedemptionCodes[code] = id
        return RewardRedemption(reward: stored.reward, redemptionCode: code, expiresAt: now.addingTimeInterval(120))
    }

    // MARK: Wallet

    public func walletPasses() async throws -> [WalletPassMetadata] { p3.passes.values.sorted { $0.updatedAt > $1.updatedAt } }

    public func issueWalletPass(_ request: WalletPassIssueRequest) async throws -> WalletPassMetadata {
        let id = WalletPassID()
        let pass = WalletPassMetadata(id: id, businessId: request.businessId, kind: request.kind,
                                      passTypeIdentifier: request.kind == .storeCard || request.kind == .coupon ? PreviewData.passTypeLoyalty : PreviewData.passTypeTicket,
                                      serialNumber: "SN-" + id.description.prefix(8).uppercased(), updatedAt: clock())
        p3.passes[id] = pass
        if request.kind == .storeCard, var account = p3.accounts[request.businessId] {
            account.walletPass = pass
            p3.accounts[request.businessId] = account
        }
        return pass
    }

    /// The mock's stand-in for a signed `.pkpass`: a JSON stub that `MockWalletLibrary` understands.
    public func walletPass(_ id: WalletPassID) async throws -> Data {
        guard let pass = p3.passes[id] else { throw Self.notFoundError() }
        if pass.voided { throw APIError.server(status: 410, code: .gone, message: "This pass is no longer valid.") }
        let stub = ["passTypeIdentifier": pass.passTypeIdentifier, "serialNumber": pass.serialNumber, "organizationName": "Mock"]
        return (try? JSONSerialization.data(withJSONObject: stub, options: [.sortedKeys])) ?? Data()
    }

    // MARK: Household

    public func household() async throws -> HouseholdOverview { p3.household }

    public func createDelegationInvitation(_ request: DelegationInvitationRequest) async throws -> DelegationInvitation {
        await pause()
        let now = clock()
        let issues = DelegationScopePolicy.validate(
            DelegationDraft(delegateLabel: request.delegateLabel, role: request.role, purposes: Set(request.purposes),
                            businessIds: Set(request.businessIds), expiresAt: request.expiresAt), now: now)
        guard issues.isEmpty else { throw APIError.server(status: 400, code: .validationFailed, message: issues[0].message) }
        let sensitive = !Set(request.purposes).isDisjoint(with: DelegationScopePolicy.sensitivePurposes)
        guard request.includesSensitiveScope == sensitive else {
            throw APIError.server(status: 400, code: .validationFailed, message: "Scope flag doesn't match the purposes.")
        }
        if sensitive {
            guard let proof = request.stepUp,
                  proof.scopeDigest == DelegationScopePolicy.scopeDigest(of: request),
                  abs(proof.signedAt.timeIntervalSince(now)) <= 300,
                  let key = deviceKeys[proof.deviceId]?[.approvalBiometric],
                  deviceList.first(where: { $0.id == proof.deviceId })?.isRevoked == false,
                  let signature = ViadereSignatureEncoding.decode(proof.signature),
                  let verifying = try? key.signingKey(), verifying.isValidSignature(signature, for: proof.signingInput()) else {
                throw APIError.server(status: 403, code: .insufficientAssurance, message: "Face ID is required to share this access.")
            }
        }
        let id = DelegationID()
        let alphabet = Array("ABCDEFGHJKMNPQRSTUVWXYZ23456789")
        let raw = String((0..<8).map { _ in alphabet[Int.random(in: 0..<alphabet.count)] })
        let code = raw.prefix(4) + "-" + raw.suffix(4)
        p3.invitations[String(code)] = (request, id)
        let names = request.businessIds.compactMap { directoryBusiness($0)?.displayName }
        let grant = DelegationGrant(id: id, grantorId: consumerId, delegateId: ConsumerID(), role: request.role, purposes: request.purposes,
                                    businessIds: request.businessIds, createdAt: now, expiresAt: request.expiresAt)
        p3.household.given.insert(HouseholdGrant(grant: grant, counterpartName: request.delegateLabel, businessNames: names, status: .pending), at: 0)
        p3.audit.insert(HouseholdAuditEntry(occurredAt: now, action: "delegation.created", actorName: "You"), at: 0)
        return DelegationInvitation(id: id, code: String(code), inviteExpiresAt: now.addingTimeInterval(86_400))
    }

    public func previewDelegationInvitation(code: String) async throws -> DelegationInvitationPreview {
        guard let invitation = p3.invitations[code.uppercased()] else { throw Self.notFoundError() }
        let r = invitation.request
        return DelegationInvitationPreview(grantorName: "Jordan Lee", role: r.role, purposes: r.purposes,
                                           businessNames: r.businessIds.compactMap { directoryBusiness($0)?.displayName }, expiresAt: r.expiresAt)
    }

    public func acceptDelegationInvitation(code: String) async throws -> HouseholdGrant {
        guard let invitation = p3.invitations.removeValue(forKey: code.uppercased()) else { throw Self.notFoundError() }
        let r = invitation.request
        let grant = DelegationGrant(id: invitation.id, grantorId: ConsumerID(), delegateId: consumerId, role: r.role, purposes: r.purposes,
                                    businessIds: r.businessIds, createdAt: clock(), expiresAt: r.expiresAt)
        let received = HouseholdGrant(grant: grant, counterpartName: "Jordan Lee",
                                      businessNames: r.businessIds.compactMap { directoryBusiness($0)?.displayName }, status: .active)
        p3.household.received.insert(received, at: 0)
        p3.audit.insert(HouseholdAuditEntry(occurredAt: clock(), action: "delegation.accepted", actorName: "You"), at: 0)
        return received
    }

    public func revokeDelegation(_ id: DelegationID) async throws {
        let now = clock()
        var found = false
        for index in p3.household.given.indices where p3.household.given[index].id == id {
            p3.household.given[index].status = .revoked
            p3.household.given[index].grant.revokedAt = now
            found = true
        }
        for index in p3.household.received.indices where p3.household.received[index].id == id {
            p3.household.received[index].status = .revoked
            p3.household.received[index].grant.revokedAt = now
            found = true
        }
        guard found else { throw Self.notFoundError() }
        p3.audit.insert(HouseholdAuditEntry(occurredAt: now, action: "delegation.revoked", actorName: "You"), at: 0)
    }

    public func householdAudit() async throws -> [HouseholdAuditEntry] { p3.audit.sorted { $0.occurredAt > $1.occurredAt } }

    // MARK: Acknowledgments

    public func acknowledgments() async throws -> [AcknowledgmentRecord] { p3.acknowledgments.sorted { $0.recordedAt > $1.recordedAt } }

    func recordAcknowledgment(for envelope: InteractionEnvelope, decision: Decision, at date: Date) {
        guard case .acknowledge(let payload) = envelope.interaction.payload else { return }
        p3.acknowledgments.insert(
            AcknowledgmentRecord(id: envelope.id, business: envelope.business, title: payload.title, documentVersion: payload.documentVersion,
                                 acknowledged: decision == .acknowledge, recordedAt: date), at: 0)
    }

    // MARK: Helpers

    func directoryBusiness(_ id: BusinessID) -> BusinessSummary? { PreviewData.allBusinesses.first { $0.id == id } }
    static func notFoundError() -> APIError { .server(status: 404, code: .notFound, message: "Not found") }

    // MARK: Seed

    /// Loyalty accounts, rewards, Wallet passes, P3 interactions, household and acknowledgment history.
    static func makeP3Seed(now: Date, consumerId: ConsumerID, relationships: inout [Relationship],
                           consents: inout [RelationshipID: [ConsentGrant]]) -> (state: MockP3State, envelopes: [InteractionEnvelope]) {
        var state = MockP3State()
        for business in PreviewData.p3Businesses {
            let relationship = PreviewData.relationship(business, connectedAt: now.addingTimeInterval(-86_400 * 21))
            relationships.append(relationship)
            consents[relationship.id] = InteractionPurpose.allCases.map { purpose in
                ConsentGrant(id: ConsentGrantID(), consumerId: consumerId, businessId: business.id, relationshipId: relationship.id,
                             purpose: purpose, granted: purpose.isGrantedByDefault || purpose == .rewards, version: 1, policyVersion: "2026-10",
                             source: .app, channels: [.nativePush, .inApp], createdAt: now, updatedAt: now)
            }
        }
        func rel(_ b: BusinessSummary) -> RelationshipID { relationships.first { $0.business.id == b.id }?.id ?? RelationshipID() }

        // Wallet passes
        let loyaltyPass = PreviewData.walletPass(PreviewData.loyaltyPassId, business: PreviewData.juniperCoffee, kind: .storeCard, now: now)
        let boarding = PreviewData.walletPass(PreviewData.boardingPassId, business: PreviewData.northwindAir, kind: .boardingPass, now: now)
        let event = PreviewData.walletPass(PreviewData.eventPassId, business: PreviewData.lumenTheater, kind: .eventTicket, now: now)
        let stay = PreviewData.walletPass(PreviewData.reservationPassId, business: PreviewData.harborHotel, kind: .generic, now: now)
        for pass in [loyaltyPass, boarding, event, stay] { state.passes[pass.id] = pass }

        // Juniper Coffee loyalty
        let coffee = PreviewData.juniperCoffee
        state.programs[coffee.id] = ("Juniper Rewards", "Earn a point for every dollar. Free coffee every Tuesday for members.", "2026-10")
        state.accounts[coffee.id] = LoyaltyAccount(
            business: coffee, programName: "Juniper Rewards", pointsBalance: 1_240, statusName: "Silver", nextStatusName: "Gold",
            pointsToNextStatus: 260, memberSince: now.addingTimeInterval(-86_400 * 140), memberReference: "••4821", walletPass: loyaltyPass)
        let tuesday = RewardRecurrence(weekdays: [2], perDayLimit: 1, timeZone: "America/Phoenix")
        func reward(_ title: String, _ details: String?, status: Reward.Status = .available, from: Date? = nil, until: Date? = nil,
                    recurrence: RewardRecurrence? = nil, kind: RewardKind, cost: Int? = nil, requiresClaim: Bool = false,
                    claimed: Date? = nil, pass: WalletPassMetadata? = nil, business: BusinessSummary = coffee) {
            let r = Reward(id: RewardID(), business: business, title: title, details: details, status: status, validFrom: from,
                           validUntil: until, recurrence: recurrence, walletPass: pass)
            state.rewards[r.id] = MockP3State.StoredReward(reward: r, kind: kind, pointsCost: cost, requiresClaim: requiresClaim, claimedAt: claimed)
            state.rewardOrder.append(r.id)
        }
        reward("Free coffee on Tuesdays", "Any size, hot or iced.", recurrence: tuesday, kind: .perk)
        reward("Pastry with any drink", "Valid on weekdays before 11 AM.", until: now.addingTimeInterval(86_400 * 12), kind: .coupon, requiresClaim: true)
        reward("Free bag of beans", "Any 12 oz bag.", kind: .pointsReward, cost: 1_500)
        reward("Birthday drink", "On us during your birthday week.", from: now.addingTimeInterval(86_400 * 40), until: now.addingTimeInterval(86_400 * 47), kind: .perk)
        reward("Welcome cookie", nil, status: .redeemed, kind: .offer)
        state.rewards[state.rewardOrder.last ?? RewardID()]?.reward.redeemedAt = now.addingTimeInterval(-86_400 * 30)

        // Harbor Hotel loyalty (no points yet: an enrollment example is Lumen Theater, which has a program but no account)
        let hotel = PreviewData.harborHotel
        state.programs[hotel.id] = ("Harbor Club", "Member rates, late check-out and a welcome drink on every stay.", "2026-10")
        state.accounts[hotel.id] = LoyaltyAccount(
            business: hotel, programName: "Harbor Club", pointsBalance: 3_800, statusName: "Gold", memberSince: now.addingTimeInterval(-86_400 * 400),
            memberReference: "••7702")
        reward("Late check-out", "Until 2 PM on your next stay.", kind: .perk, requiresClaim: true, business: hotel)

        let theater = PreviewData.lumenTheater
        state.programs[theater.id] = ("Lumen Circle", "Early access to tickets and a free drink at every show.", "2026-10")
        reward("Intermission drink", "One drink per ticket.", kind: .coupon, requiresClaim: true, business: theater)
        state.rewards[state.rewardOrder.last ?? RewardID()]?.reward.status = .available

        // Interactions
        let envelopes: [InteractionEnvelope] = [
            PreviewData.orderStatus(now: now, relationship: rel(PreviewData.juniperCoffee)),
            PreviewData.deliveryStatus(now: now, relationship: rel(PreviewData.northfield)),
            PreviewData.appointmentStatus(now: now, relationship: rel(PreviewData.lindenDental)),
            PreviewData.appointmentCheckIn(now: now, relationship: rel(PreviewData.lindenDental)),
            PreviewData.appointmentReschedule(now: now, relationship: rel(PreviewData.lindenDental)),
            PreviewData.northwindFlight(now: now, relationship: rel(PreviewData.northwindAir)),
            PreviewData.rebookOffer(now: now, relationship: rel(PreviewData.northwindAir)),
            PreviewData.boardingPass(now: now, relationship: rel(PreviewData.northwindAir)),
            PreviewData.hotelReservation(now: now, relationship: rel(PreviewData.harborHotel)),
            PreviewData.acknowledge(now: now, relationship: rel(PreviewData.harborHotel)),
            PreviewData.eventTicket(now: now, relationship: rel(PreviewData.lumenTheater)),
            PreviewData.eventScheduleChange(now: now, relationship: rel(PreviewData.lumenTheater)),
        ]

        // Household
        let samGrant = DelegationGrant(id: DelegationID(), grantorId: consumerId, delegateId: ConsumerID(), role: .viewer, purposes: [.transactional, .rewards],
                                       businessIds: [coffee.id], createdAt: now.addingTimeInterval(-86_400 * 9), expiresAt: now.addingTimeInterval(86_400 * 51))
        let alexGrant = DelegationGrant(id: DelegationID(), grantorId: ConsumerID(), delegateId: consumerId, role: .manager, purposes: [.transactional, .support],
                                        businessIds: [PreviewData.lindenDental.id], createdAt: now.addingTimeInterval(-86_400 * 3), expiresAt: now.addingTimeInterval(86_400 * 27))
        state.household = HouseholdOverview(
            given: [HouseholdGrant(grant: samGrant, counterpartName: "Sam Rivera", businessNames: [coffee.displayName], status: .active)],
            received: [HouseholdGrant(grant: alexGrant, counterpartName: "Alex Morgan", businessNames: [PreviewData.lindenDental.displayName], status: .active)])
        state.audit = [
            HouseholdAuditEntry(occurredAt: now.addingTimeInterval(-3_600 * 5), action: "delegation.used", actorName: "Sam Rivera", businessName: coffee.displayName),
            HouseholdAuditEntry(occurredAt: now.addingTimeInterval(-86_400 * 3), action: "delegation.accepted", actorName: "You"),
            HouseholdAuditEntry(occurredAt: now.addingTimeInterval(-86_400 * 9), action: "delegation.created", actorName: "You"),
            HouseholdAuditEntry(occurredAt: now.addingTimeInterval(-86_400 * 2), action: "delegation.denied", actorName: "Sam Rivera", businessName: coffee.displayName,
                                outcome: .denied),
        ]

        // Acknowledgment history
        state.acknowledgments = [
            AcknowledgmentRecord(id: InteractionID(), business: PreviewData.harborBank, title: "Updated privacy notice", documentVersion: "2026-09",
                                 acknowledged: true, recordedAt: now.addingTimeInterval(-86_400 * 5)),
            AcknowledgmentRecord(id: InteractionID(), business: PreviewData.lindenDental, title: "Treatment estimate", documentVersion: "v3",
                                 acknowledged: true, recordedAt: now.addingTimeInterval(-86_400 * 40)),
        ]
        return (state, envelopes)
    }
}
