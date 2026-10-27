import Fluent
import Foundation
import ViadereCore

/// Loyalty accounts, rewards, claims and single-use redemption codes.
///
/// * Eligibility is computed here and nowhere else (`RewardEligibilityEvaluator`); the app only displays it.
/// * A redemption code reserves its per-day (or lifetime) slot and any points **when it is issued**. A unique index on
///   `(reward, consumer, window, slot)` decides concurrent attempts, and the reservation is released if the code expires unused.
/// * The business consumes a code with one compare-and-swap, so of any number of concurrent validations exactly one succeeds.
struct RewardsService {
    let db: any Database
    let ctx: ServerContext

    /// How long a redemption code stays valid.
    static let codeTTL: TimeInterval = 120
    private static let codeAlphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    private static let maxPoints = 1_000_000_000

    /// A lost optimistic race inside a reservation; the caller retries from scratch.
    private struct RetryReservation: Error {}

    // MARK: - Codes

    /// 50 random bits as `XXXXX-XXXXX` in an unambiguous alphabet (no I, L, O, U).
    static func generateCode() -> String {
        let bytes = SecureToken.randomBytes(10)
        let chars = bytes.map { codeAlphabet[Int($0) & 31] }
        return String(chars[0..<5]) + "-" + String(chars[5..<10])
    }

    /// Uppercases and strips separators; maps the look-alikes I/L → 1 and O → 0. `nil` if it can't be a code.
    static func normalizeCode(_ raw: String) -> String? {
        let cleaned = raw.uppercased().filter { !$0.isWhitespace && $0 != "-" }
        guard cleaned.count == 10 else { return nil }
        let mapped = cleaned.map { ch -> Character in
            switch ch {
            case "I", "L": "1"
            case "O": "0"
            default: ch
            }
        }
        guard mapped.allSatisfy({ codeAlphabet.contains($0) }) else { return nil }
        return String(mapped)
    }

    /// A till or store code: up to 64 characters of `A-Z a-z 0-9 _ . - :`, or nil.
    static func validatedLocation(_ raw: String?) throws -> String? {
        guard let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else { return nil }
        guard trimmed.count <= 64, trimmed.unicodeScalars.allSatisfy({ $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "_.-:".unicodeScalars.contains($0)) }) else {
            throw APIError.validation("The location code is not valid.", details: ["locationCode": "invalid"])
        }
        return trimmed
    }

    func codeHash(_ normalized: String) -> String { ctx.hasher.hmacHex("reward-redemption", normalized) }

    // MARK: - Reading

    private struct ConsumerState {
        var accountsByBusiness: [UUID: LoyaltyAccountRecord] = [:]
        var claims: [UUID: RewardClaimRecord] = [:]
        var redemptions: [UUID: [RewardRedemptionRecord]] = [:]
        var passes: [UUID: WalletPassRecord] = [:]
    }

    private func loadState(consumer: UUID, rewardIds: [UUID], businessIds: [UUID], on db: any Database) async throws -> ConsumerState {
        var state = ConsumerState()
        if !businessIds.isEmpty {
            for account in try await LoyaltyAccountRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$businessId ~~ businessIds).all() {
                state.accountsByBusiness[account.businessId] = account
            }
        }
        guard !rewardIds.isEmpty else { return state }
        for claim in try await RewardClaimRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$rewardId ~~ rewardIds).all() {
            state.claims[claim.rewardId] = claim
        }
        for row in try await RewardRedemptionRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$rewardId ~~ rewardIds).all() {
            state.redemptions[row.rewardId, default: []].append(row)
        }
        for pass in try await WalletPassRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$rewardId ~~ rewardIds)
            .filter(\.$voided == false).all() {
            if let rewardId = pass.rewardId { state.passes[rewardId] = pass }
        }
        return state
    }

    private func facts(_ reward: RewardRecord, state: ConsumerState, now: Date) -> RewardFacts {
        let zone = TimeZone(identifier: reward.timeZone) ?? TimeZone(identifier: "UTC")!
        let rows = state.redemptions[reward.id!] ?? []
        var facts = RewardFacts(kind: reward.kindValue, revoked: reward.isRevoked, validFrom: reward.validFrom, validUntil: reward.validUntil,
                                weekdays: reward.weekdays, timeZone: zone, perDayLimit: reward.perDayLimit, pointsCost: reward.pointsCost,
                                claimedAt: state.claims[reward.id!]?.claimedAt, lifetimeRedeemed: false, usageInWindow: 0,
                                earliestHeldCodeExpiry: nil, pointsBalance: state.accountsByBusiness[reward.businessId]?.pointsBalance)
        let window = RewardEligibilityEvaluator.windowKey(for: facts, now: now)
        let rule = RewardEligibilityEvaluator.limit(kind: facts.kind, recurring: !facts.weekdays.isEmpty, perDayLimit: facts.perDayLimit)
        if rule?.scope == .lifetime { facts.lifetimeRedeemed = rows.contains { $0.status == "consumed" } }
        // Rows that stopped counting (expired or released) never count; an issued code counts only until it expires.
        let counting = rows.filter { $0.windowKey == window && ($0.status == "consumed" || ($0.status == "issued" && $0.expiresAt > now)) }
        if rule != nil { facts.usageInWindow = counting.count }
        facts.earliestHeldCodeExpiry = rows.filter { $0.status == "issued" && $0.expiresAt > now }.map(\.expiresAt).min()
        return facts
    }

    private func entry(_ reward: RewardRecord, business: BusinessSummary, state: ConsumerState, now: Date) -> RewardEntry {
        let facts = facts(reward, state: state, now: now)
        let eligibility = RewardEligibilityEvaluator.evaluate(facts, now: now)
        return RewardEntry(reward: dto(reward, business: business, eligibility: eligibility, state: state), kind: reward.kindValue,
                           eligibility: eligibility, pointsCost: reward.pointsCost, claimedAt: facts.claimedAt)
    }

    private func dto(_ reward: RewardRecord, business: BusinessSummary, eligibility: RewardEligibility?, state: ConsumerState?) -> Reward {
        var status = Reward.Status.available
        var redeemedAt: Date?
        if reward.isRevoked { status = .revoked }
        if let eligibility {
            switch eligibility.state {
            case .revoked: status = .revoked
            case .expired: status = .expired
            case .redeemed:
                status = .redeemed
                redeemedAt = state?.redemptions[reward.id!]?.compactMap(\.consumedAt).max()
            default: break
            }
        }
        let recurrence = reward.isRecurring ? RewardRecurrence(weekdays: reward.weekdays, perDayLimit: reward.perDayLimit ?? 1, timeZone: reward.timeZone) : nil
        let pass = state?.passes[reward.id!].flatMap { WalletService.metadata($0) }
        return Reward(id: RewardID(reward.id!), business: business, title: reward.title, details: reward.details, status: status,
                      validFrom: reward.validFrom, validUntil: reward.validUntil, recurrence: recurrence, redeemedAt: redeemedAt, walletPass: pass)
    }

    private func summaries(_ ids: [UUID]) async throws -> [UUID: BusinessSummary] {
        guard !ids.isEmpty else { return [:] }
        let businesses = try await BusinessRecord.query(on: db).filter(\.$id ~~ ids).all()
        let summaries = try await DirectoryService(db: db).summaries(for: businesses)
        return Dictionary(summaries.map { ($0.id.uuid, $0) }, uniquingKeysWith: { first, _ in first })
    }

    private func activeBusinessIds(consumer: UUID) async throws -> [UUID] {
        try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$status == "active").all().map(\.businessId)
    }

    private func account(_ record: LoyaltyAccountRecord, program: LoyaltyProgramRecord, business: BusinessSummary,
                         pass: WalletPassRecord?) -> LoyaltyAccount {
        let tiers = program.tiers
        let current = tiers.last { $0.minimumPoints <= record.pointsBalance }
        let next = tiers.first { $0.minimumPoints > record.pointsBalance }
        return LoyaltyAccount(business: business, programName: program.programName, pointsBalance: record.pointsBalance,
                              statusName: current?.name, nextStatusName: next?.name,
                              pointsToNextStatus: next.map { $0.minimumPoints - record.pointsBalance }, memberSince: record.memberSince,
                              memberReference: record.memberReferenceMasked, walletPass: pass.flatMap { WalletService.metadata($0) })
    }

    /// Rewards a consumer may see at the given businesses: program-wide ones plus those issued to them. Revoked rewards stay
    /// visible only if the consumer claimed or redeemed them (so history makes sense); long-expired ones are dropped.
    private func visibleRewards(consumer: UUID, businessIds: [UUID], now: Date) async throws -> [RewardRecord] {
        guard !businessIds.isEmpty else { return [] }
        // Program-wide rewards and the ones issued to this consumer, filtered in the database so a busy program can't crowd them out.
        let all = try await RewardRecord.query(on: db).filter(\.$businessId ~~ businessIds).group(.or) { or in
            or.filter(\.$consumerId == nil)
            or.filter(\.$consumerId == consumer)
        }.sort(\.$createdAt, .descending).limit(300).all()
        let revokedIds = all.filter(\.isRevoked).compactMap(\.id)
        var kept = Set<UUID>()
        if !revokedIds.isEmpty {
            for c in try await RewardClaimRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$rewardId ~~ revokedIds).all() { kept.insert(c.rewardId) }
            for r in try await RewardRedemptionRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$rewardId ~~ revokedIds).all() { kept.insert(r.rewardId) }
        }
        return all.filter { reward in
            if reward.isRevoked { return kept.contains(reward.id!) }
            if let until = reward.validUntil, until < now.addingTimeInterval(-30 * 86_400) { return false }
            return true
        }
    }

    func overview(consumer: ConsumerID) async throws -> RewardsOverview {
        let now = ctx.now
        let businessIds = try await activeBusinessIds(consumer: consumer.uuid)
        let rewards = try await visibleRewards(consumer: consumer.uuid, businessIds: businessIds, now: now)
        let state = try await loadState(consumer: consumer.uuid, rewardIds: rewards.compactMap(\.id), businessIds: businessIds, on: db)
        let summaryById = try await summaries(businessIds)
        let programs = try await LoyaltyProgramRecord.query(on: db).filter(\.$businessId ~~ businessIds).all()
        let programByBusiness = Dictionary(programs.map { ($0.businessId, $0) }, uniquingKeysWith: { a, _ in a })
        let storePasses = try await WalletPassRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$kind == WalletPassKind.storeCard.rawValue)
            .filter(\.$voided == false).all()
        let storePassByBusiness = Dictionary(storePasses.map { ($0.businessId, $0) }, uniquingKeysWith: { a, _ in a })
        var accounts: [LoyaltyAccount] = []
        for (businessId, record) in state.accountsByBusiness.sorted(by: { $0.value.memberSince < $1.value.memberSince }) {
            guard let program = programByBusiness[businessId], let summary = summaryById[businessId] else { continue }
            accounts.append(account(record, program: program, business: summary, pass: storePassByBusiness[businessId]))
        }
        let entries = rewards.compactMap { reward in summaryById[reward.businessId].map { entry(reward, business: $0, state: state, now: now) } }
        return RewardsOverview(accounts: accounts, rewards: entries)
    }

    /// The bare reward list (no eligibility) kept for older clients.
    func list(consumer: ConsumerID) async throws -> [Reward] { try await overview(consumer: consumer).rewards.map(\.reward) }

    func programOverview(consumer: ConsumerID, businessId: BusinessID) async throws -> LoyaltyProgramOverview {
        guard try await DirectoryService(db: db).verified(id: businessId.uuid) != nil,
              let program = try await LoyaltyProgramRecord.query(on: db).filter(\.$businessId == businessId.uuid).first(),
              let summary = try await summaries([businessId.uuid])[businessId.uuid] else { throw APIError.notFound }
        let now = ctx.now
        let connected = try await activeBusinessIds(consumer: consumer.uuid).contains(businessId.uuid)
        let rewards = connected ? try await visibleRewards(consumer: consumer.uuid, businessIds: [businessId.uuid], now: now) : []
        let state = try await loadState(consumer: consumer.uuid, rewardIds: rewards.compactMap(\.id), businessIds: [businessId.uuid], on: db)
        let pass = try await WalletPassRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$subjectKey == "storeCard:\(businessId)")
            .filter(\.$voided == false).first()
        return LoyaltyProgramOverview(
            programName: program.programName, summary: program.summary, termsVersion: program.termsVersion,
            account: state.accountsByBusiness[businessId.uuid].map { account($0, program: program, business: summary, pass: pass) },
            rewards: rewards.map { entry($0, business: summary, state: state, now: now) })
    }

    // MARK: - Enroll

    func enroll(principal: ConsumerPrincipal, businessId: BusinessID, request: LoyaltyEnrollRequest) async throws -> (account: LoyaltyAccount, created: Bool) {
        let consumer = principal.consumerId
        guard try await DirectoryService(db: db).verified(id: businessId.uuid) != nil,
              let program = try await LoyaltyProgramRecord.query(on: db).filter(\.$businessId == businessId.uuid).first(),
              let summary = try await summaries([businessId.uuid])[businessId.uuid] else { throw APIError.notFound }
        guard try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$businessId == businessId.uuid)
            .filter(\.$status == "active").count() > 0 else {
            throw APIError.conflict("Connect to this business before joining its program.")
        }
        guard ConstantTime.equals(request.acceptedTermsVersion, program.termsVersion) else {
            throw APIError(.conflict, .conflict, "The program terms changed. Review the current terms and try again.",
                           details: ["termsVersion": program.termsVersion])
        }
        var reference: String?
        if let raw = request.existingMemberReference?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty {
            guard raw.count <= 64, !raw.contains(where: \.isNewline) else {
                throw APIError.validation("The member reference is not valid.", details: ["existingMemberReference": "invalid"])
            }
            reference = raw
        }
        let now = ctx.now
        if let existing = try await LoyaltyAccountRecord.query(on: db).filter(\.$businessId == businessId.uuid).filter(\.$consumerId == consumer.uuid).first() {
            return (account(existing, program: program, business: summary, pass: nil), false)
        }
        let record = LoyaltyAccountRecord()
        record.id = UUID()
        record.businessId = businessId.uuid
        record.consumerId = consumer.uuid
        record.programId = program.id!
        record.pointsBalance = 0
        record.acceptedTermsVersion = program.termsVersion
        if let reference {
            record.memberReferenceCiphertext = try ctx.cipher.seal(reference, context: "loyalty_accounts.member_reference", rowId: record.id!)
            record.memberReferenceMasked = "••" + String(reference.suffix(4))
        }
        record.memberSince = now
        record.updatedAt = now
        do {
            try await db.transaction { tx in
                try await record.create(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("loyalty.enrolled", principal: principal, businessId: businessId,
                    subjectType: "loyalty_account", subjectId: record.id?.uuidString.lowercased(), metadata: ["termsVersion": program.termsVersion])
            }
        } catch {
            // A concurrent enrollment won the unique index: that is the account.
            if error.isConstraintViolation, let existing = try await LoyaltyAccountRecord.query(on: db).filter(\.$businessId == businessId.uuid)
                .filter(\.$consumerId == consumer.uuid).first() {
                return (account(existing, program: program, business: summary, pass: nil), false)
            }
            throw error
        }
        return (account(record, program: program, business: summary, pass: nil), true)
    }

    // MARK: - Claim

    /// The reward, if this consumer may see it: connected to the business, the business is verified and the reward is theirs or program-wide.
    private func visible(_ id: RewardID, consumer: ConsumerID, on db: any Database) async throws -> (RewardRecord, BusinessSummary) {
        guard let reward = try await RewardRecord.find(id.uuid, on: db), reward.consumerId == nil || reward.consumerId == consumer.uuid,
              try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$businessId == reward.businessId)
                .filter(\.$status == "active").count() > 0,
              let business = try await DirectoryService(db: db).verified(id: reward.businessId),
              let summary = try await DirectoryService(db: db).summary(for: business) else { throw APIError.notFound }
        return (reward, summary)
    }

    private func currentEntry(_ reward: RewardRecord, business: BusinessSummary, consumer: ConsumerID, on db: any Database) async throws -> RewardEntry {
        let state = try await loadState(consumer: consumer.uuid, rewardIds: [reward.id!], businessIds: [reward.businessId], on: db)
        return entry(reward, business: business, state: state, now: ctx.now)
    }

    func claim(principal: ConsumerPrincipal, rewardId: RewardID) async throws -> RewardEntry {
        let consumer = principal.consumerId
        let (reward, summary) = try await visible(rewardId, consumer: consumer, on: db)
        let current = try await currentEntry(reward, business: summary, consumer: consumer, on: db)
        // Already saved and still usable: claiming again is a no-op, not an error.
        if current.claimedAt != nil, current.eligibility.state == .eligible { return current }
        guard current.eligibility.state == .eligible, current.eligibility.nextAction == .claim else {
            throw APIError(.conflict, .conflict, "This reward can't be claimed right now.", details: ["state": current.eligibility.state.rawValue])
        }
        let claim = RewardClaimRecord()
        claim.id = UUID()
        claim.rewardId = rewardId.uuid
        claim.consumerId = consumer.uuid
        claim.claimedAt = ctx.now
        do {
            try await db.transaction { tx in
                try await claim.create(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("reward.claimed", principal: principal, businessId: BusinessID(reward.businessId),
                    subjectType: "reward", subjectId: rewardId.description)
            }
        } catch {
            if !error.isConstraintViolation { throw error }
        }
        return try await currentEntry(reward, business: summary, consumer: consumer, on: db)
    }

    // MARK: - Redeem

    func redeem(principal: ConsumerPrincipal, rewardId: RewardID, request: RedeemRewardRequest) async throws -> RewardRedemption {
        let consumer = principal.consumerId
        try await ctx.limiter.enforce("reward-redeem", key: consumer.description, rule: ctx.config.rateLimits.rewardRedeem)
        let (reward, summary) = try await visible(rewardId, consumer: consumer, on: db)
        let location = try Self.validatedLocation(request.locationCode)
        // Free the slot and points of this person's expired codes first, so they don't block a fresh one.
        try await releaseExpired(rewardId: rewardId.uuid, consumerId: consumer.uuid)
        for _ in 0..<6 {
            do {
                let result: (RewardRedemptionRecord, String, RewardEntry) = try await DB.retryingTransient {
                    try await db.transaction { tx in
                        try await reserve(on: tx, reward: reward, summary: summary, principal: principal, location: location)
                    }
                }
                let now = ctx.now
                let issued = RewardEntry(reward: result.2.reward, kind: result.2.kind, eligibility: result.2.eligibility,
                                         pointsCost: result.2.pointsCost, claimedAt: result.2.claimedAt)
                return RewardRedemption(reward: issued.reward, redemptionCode: result.1, expiresAt: result.0.expiresAt,
                                        validForSeconds: Int(Self.codeTTL), serverTime: now)
            } catch is RetryReservation {
                continue
            } catch {
                // Losing the unique-index race for a slot or a code: re-evaluate from scratch (the verdict may now be "limit reached").
                if error.isConstraintViolation { continue }
                throw error
            }
        }
        throw APIError.conflict("This reward can't be redeemed right now. Try again.")
    }

    private func reserve(on tx: any Database, reward: RewardRecord, summary: BusinessSummary, principal: ConsumerPrincipal,
                         location: String?) async throws -> (RewardRedemptionRecord, String, RewardEntry) {
        let consumer = principal.consumerId
        let now = ctx.now
        let state = try await loadState(consumer: consumer.uuid, rewardIds: [reward.id!], businessIds: [reward.businessId], on: tx)
        let facts = facts(reward, state: state, now: now)
        let eligibility = RewardEligibilityEvaluator.evaluate(facts, now: now)
        guard eligibility.state == .eligible else {
            throw APIError(.conflict, .conflict, "This reward can't be redeemed right now.", details: ["state": eligibility.state.rawValue])
        }
        guard eligibility.nextAction == .redeem else {
            throw APIError(.conflict, .conflict, "Claim this reward first.", details: ["state": "needsClaim"])
        }
        let window = RewardEligibilityEvaluator.windowKey(for: facts, now: now)
        let rule = RewardEligibilityEvaluator.limit(kind: facts.kind, recurring: !facts.weekdays.isEmpty, perDayLimit: facts.perDayLimit)
        var slot: Int?
        if let rule {
            let taken = Set(try await RewardRedemptionRecord.query(on: tx).filter(\.$rewardId == reward.id!).filter(\.$consumerId == consumer.uuid)
                .filter(\.$windowKey == window).all().compactMap(\.slot))
            guard let free = (1...rule.max).first(where: { !taken.contains($0) }) else {
                throw APIError(.conflict, .conflict, "This reward can't be redeemed right now.", details: ["state": "limitReached"])
            }
            slot = free
        }
        var held = 0
        if facts.kind == .pointsReward, let cost = reward.pointsCost {
            guard let account = state.accountsByBusiness[reward.businessId], account.pointsBalance >= cost else {
                throw APIError(.conflict, .conflict, "Not enough points.", details: ["state": "insufficientPoints"])
            }
            // Optimistic compare-and-swap on the balance: a concurrent change makes this attempt retry.
            guard try await DB.swap(tx, table: LoyaltyAccountRecord.schema, id: account.id!, column: "points_balance",
                                    expected: account.pointsBalance, newValue: account.pointsBalance - cost) else { throw RetryReservation() }
            held = cost
        }
        let code = Self.generateCode()
        let record = RewardRedemptionRecord()
        record.id = UUID()
        record.rewardId = reward.id!
        record.businessId = reward.businessId
        record.consumerId = consumer.uuid
        record.codeHash = codeHash(Self.normalizeCode(code)!)
        record.status = "issued"
        record.windowKey = window
        record.slot = slot
        record.pointsHeld = held
        record.locationCode = location
        record.issuedAt = now
        record.expiresAt = now.addingTimeInterval(Self.codeTTL)
        try await record.create(on: tx)
        _ = try await AuditService(db: tx, ctx: ctx).record("reward.redemption_issued", principal: principal, businessId: BusinessID(reward.businessId),
            subjectType: "reward", subjectId: reward.id!.uuidString.lowercased(), metadata: ["window": window, "points": String(held)])
        var refreshed = state
        refreshed.redemptions[reward.id!, default: []].append(record)
        let view = entry(reward, business: summary, state: refreshed, now: now)
        return (record, code, view)
    }

    // MARK: - Expiry (release reservations)

    /// Expires issued codes whose time is up, frees their slot and returns held points. Safe to run concurrently: each code is
    /// released by exactly one compare-and-swap.
    @discardableResult
    func releaseExpired(rewardId: UUID? = nil, consumerId: UUID? = nil, limit: Int = 200) async throws -> Int {
        var query = RewardRedemptionRecord.query(on: db).filter(\.$status == "issued").filter(\.$expiresAt <= ctx.now)
        if let rewardId { query = query.filter(\.$rewardId == rewardId) }
        if let consumerId { query = query.filter(\.$consumerId == consumerId) }
        var count = 0
        for row in try await query.limit(limit).all() where try await release(row) { count += 1 }
        return count
    }

    /// issued → expired, slot freed, points returned. `false` if someone else (the business or another sweep) got there first.
    @discardableResult
    func release(_ row: RewardRedemptionRecord) async throws -> Bool {
        let now = ctx.now
        return try await DB.retryingTransient { try await db.transaction { tx in
            guard try await DB.swap(tx, table: RewardRedemptionRecord.schema, id: row.id!, column: "status", expected: "issued",
                                    newValue: "expired", extra: [("released_at", now)]) else { return false }
            try await RewardRedemptionRecord.query(on: tx).filter(\.$id == row.id!).set(\.$slot, to: nil).update()
            if row.pointsHeld > 0 {
                try await Self.adjustBalance(on: tx, businessId: row.businessId, consumerId: row.consumerId, delta: row.pointsHeld, now: now)
            }
            return true
        } }
    }

    /// Atomic balance change by compare-and-swap with a few retries. Throws if the balance would go negative.
    @discardableResult
    static func adjustBalance(on db: any Database, businessId: UUID, consumerId: UUID, delta: Int, now: Date) async throws -> Int {
        for _ in 0..<8 {
            guard let account = try await LoyaltyAccountRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$consumerId == consumerId).first() else {
                throw APIError.conflict("The member is not enrolled in the program.")
            }
            let next = account.pointsBalance + delta
            guard next >= 0, next <= maxPoints else { throw APIError.conflict("The points balance would be out of range.") }
            if try await DB.swap(db, table: LoyaltyAccountRecord.schema, id: account.id!, column: "points_balance", expected: account.pointsBalance,
                                 newValue: next, extra: [("updated_at", now)]) { return next }
        }
        throw APIError.conflict("The balance changed. Try again.")
    }

    // MARK: - Business: program

    private func validateText(_ value: String, field: String, max: Int) throws -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= max, !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw APIError.validation("\(field) is not valid.", details: [field: "invalid"])
        }
        return trimmed
    }

    func programDTO(_ program: LoyaltyProgramRecord) async throws -> BusinessLoyaltyProgram {
        let members = try await LoyaltyAccountRecord.query(on: db).filter(\.$businessId == program.businessId).count()
        return BusinessLoyaltyProgram(programName: program.programName, summary: program.summary, termsVersion: program.termsVersion,
                                      timeZone: program.timeZone, tiers: program.tiers, memberCount: members, updatedAt: program.updatedAt)
    }

    func program(principal: BusinessPrincipal) async throws -> BusinessLoyaltyProgram {
        guard let program = try await LoyaltyProgramRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid).first() else { throw APIError.notFound }
        return try await programDTO(program)
    }

    func upsertProgram(principal: BusinessPrincipal, request: UpsertLoyaltyProgramRequest) async throws -> BusinessLoyaltyProgram {
        // The program is shared by every real member: test-mode keys never edit it.
        try Sandbox.requireLive(principal, "change the loyalty program")
        let name = try validateText(request.programName, field: "programName", max: 60)
        let summary = try validateText(request.summary, field: "summary", max: 280)
        let terms = try validateText(request.termsVersion, field: "termsVersion", max: 32)
        guard TimeZone(identifier: request.timeZone) != nil, request.timeZone.count <= 64 else {
            throw APIError.validation("timeZone must be an IANA time zone identifier.", details: ["timeZone": "invalid"])
        }
        guard request.tiers.count <= 10, Set(request.tiers.map(\.name)).count == request.tiers.count,
              request.tiers.allSatisfy({ !$0.name.trimmingCharacters(in: .whitespaces).isEmpty && $0.name.count <= 30 && (0...Self.maxPoints).contains($0.minimumPoints) }) else {
            throw APIError.validation("The tiers are not valid.", details: ["tiers": "invalid"])
        }
        let tiersJSON = String(decoding: try ViadereJSON.encode(request.tiers.sorted { $0.minimumPoints < $1.minimumPoints }), as: UTF8.self)
        let now = ctx.now
        let businessId = principal.businessId.uuid
        func apply(_ program: LoyaltyProgramRecord) {
            program.programName = name
            program.summary = summary
            program.termsVersion = terms
            program.timeZone = request.timeZone
            program.tiersJSON = tiersJSON
            program.updatedAt = now
        }
        let saved: LoyaltyProgramRecord
        if let existing = try await LoyaltyProgramRecord.query(on: db).filter(\.$businessId == businessId).first() {
            apply(existing)
            try await existing.update(on: db)
            saved = existing
        } else {
            let created = LoyaltyProgramRecord()
            created.id = UUID()
            created.businessId = businessId
            created.createdAt = now
            apply(created)
            do {
                try await created.create(on: db)
                saved = created
            } catch {
                // A concurrent first write won; update that row instead.
                guard error.isConstraintViolation, let existing = try await LoyaltyProgramRecord.query(on: db).filter(\.$businessId == businessId).first() else { throw error }
                apply(existing)
                try await existing.update(on: db)
                saved = existing
            }
        }
        _ = try await AuditService(db: db, ctx: ctx).record("loyalty.program_updated", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
            businessId: principal.businessId, subjectType: "loyalty_program", subjectId: saved.id?.uuidString.lowercased(), metadata: ["termsVersion": terms])
        return try await programDTO(saved)
    }

    // MARK: - Business: rewards

    private func businessSummary(_ principal: BusinessPrincipal) async throws -> BusinessSummary {
        guard let summary = try await summaries([principal.businessId.uuid])[principal.businessId.uuid] else { throw APIError.notFound }
        return summary
    }

    func createReward(principal: BusinessPrincipal, request: IssueRewardRequest, headerKey: String?) async throws -> (reward: Reward, created: Bool) {
        if let headerKey, headerKey != request.idempotencyKey { throw APIError.badRequest("Idempotency-Key header does not match the request body.") }
        guard !request.idempotencyKey.isEmpty, request.idempotencyKey.count <= 128 else {
            throw APIError.validation("idempotencyKey is required.", details: ["idempotencyKey": "invalid"])
        }
        let hash = SecureToken.sha256Hex(try ViadereJSON.encode(request))
        let businessId = principal.businessId.uuid
        let summary = try await businessSummary(principal)
        func replay(_ existing: RewardRecord) throws -> (Reward, Bool) {
            guard ConstantTime.equals(existing.requestHash, hash) else {
                throw APIError(.conflict, .idempotencyConflict, "This Idempotency-Key was already used with a different request.")
            }
            return (dto(existing, business: summary, eligibility: nil, state: nil), false)
        }
        if let existing = try await RewardRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$idempotencyKey == request.idempotencyKey).first() {
            return try replay(existing)
        }
        let now = ctx.now
        let title = try validateText(request.title, field: "title", max: 80)
        var details: String?
        if let raw = request.details?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty {
            guard raw.count <= 300 else { throw APIError.validation("details is too long.", details: ["details": "tooLong"]) }
            details = raw
        }
        let kind = request.kind ?? .perk
        if let from = request.validFrom, let until = request.validUntil, until <= from {
            throw APIError.validation("validUntil must be after validFrom.", details: ["validUntil": "invalid"])
        }
        if let until = request.validUntil, until <= now { throw APIError.validation("validUntil is in the past.", details: ["validUntil": "invalid"]) }
        var cost: Int?
        if kind == .pointsReward {
            guard let value = request.pointsCost, (1...Self.maxPoints).contains(value) else {
                throw APIError.validation("pointsCost is required for a points reward.", details: ["pointsCost": "invalid"])
            }
            cost = value
        }
        let program = try await LoyaltyProgramRecord.query(on: db).filter(\.$businessId == businessId).first()
        var zone = program?.timeZone ?? "UTC"
        var weekdays: [Int] = []
        var perDay: Int?
        if let recurrence = request.recurrence {
            let days = Array(Set(recurrence.weekdays)).sorted()
            guard !days.isEmpty, days.allSatisfy({ (1...7).contains($0) }), (1...20).contains(recurrence.perDayLimit),
                  TimeZone(identifier: recurrence.timeZone) != nil else {
                throw APIError.validation("The recurrence is not valid.", details: ["recurrence": "invalid"])
            }
            weekdays = days
            perDay = recurrence.perDayLimit
            zone = recurrence.timeZone
        } else if kind == .pointsReward, program == nil {
            // A points reward needs a program (members and balances live there).
            throw APIError.conflict("Create a loyalty program before offering points rewards.")
        }
        var targetConsumer: UUID?
        if let relationshipId = request.relationshipId {
            // Tenant isolation: only this business's own, active relationships.
            guard let relationship = try await RelationshipRecord.query(on: db).filter(\.$id == relationshipId.uuid)
                .filter(\.$businessId == businessId).first() else { throw APIError.notFound }
            guard relationship.isActive else { throw APIError.conflict("The consumer is not connected to your business.") }
            try await Sandbox(db: db).requireMatching(relationship: relationship, livemode: principal.livemode)
            targetConsumer = relationship.consumerId
        } else {
            // A reward for every member reaches real people: a test-mode key can only target a sandbox relationship.
            try Sandbox.requireLive(principal, "issue rewards to every member")
        }
        let consumerId = targetConsumer
        let record = RewardRecord()
        record.id = UUID()
        record.businessId = businessId
        record.consumerId = consumerId
        record.kind = kind.rawValue
        record.title = title
        record.details = details
        record.status = "active"
        record.validFrom = request.validFrom
        record.validUntil = request.validUntil
        record.recurrenceWeekdays = weekdays.map(String.init).joined(separator: ",")
        record.perDayLimit = perDay
        record.timeZone = zone
        record.pointsCost = cost
        record.issueWalletPass = request.issueWalletPass
        record.idempotencyKey = request.idempotencyKey
        record.requestHash = hash
        record.createdAt = now
        do {
            try await db.transaction { tx in
                try await record.create(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("reward.created", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                    consumerId: consumerId.map { ConsumerID($0) }, businessId: principal.businessId, subjectType: "reward",
                    subjectId: record.id?.uuidString.lowercased(), metadata: ["kind": kind.rawValue, "targeted": consumerId == nil ? "false" : "true"])
            }
        } catch {
            if error.isConstraintViolation, let existing = try await RewardRecord.query(on: db).filter(\.$businessId == businessId)
                .filter(\.$idempotencyKey == request.idempotencyKey).first() { return try replay(existing) }
            throw error
        }
        // A reward issued to one person can come with a Wallet pass. Best effort: the reward exists either way.
        if request.issueWalletPass, principal.livemode, let consumerId, ctx.passSigner != nil {
            _ = try? await WalletService(db: db, ctx: ctx).issue(consumer: ConsumerID(consumerId), request:
                WalletPassIssueRequest(kind: .coupon, businessId: principal.businessId, rewardId: RewardID(record.id!)))
        }
        return (dto(record, business: summary, eligibility: nil, state: nil), true)
    }

    func listRewards(principal: BusinessPrincipal) async throws -> [Reward] {
        let summary = try await businessSummary(principal)
        return try await RewardRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid).sort(\.$createdAt, .descending).limit(200).all()
            .map { dto($0, business: summary, eligibility: nil, state: nil) }
    }

    func revokeReward(principal: BusinessPrincipal, id: RewardID) async throws -> Reward {
        guard let reward = try await RewardRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$businessId == principal.businessId.uuid).first() else {
            throw APIError.notFound
        }
        // A reward for one person is that person's: test keys revoke only sandbox rewards, live keys only real ones (broadcast rewards are live).
        if let target = reward.consumerId {
            guard try await Sandbox(db: db).matches(consumerId: target, livemode: principal.livemode) else { throw APIError.notFound }
        } else if !principal.livemode { throw APIError.notFound }
        let summary = try await businessSummary(principal)
        if !reward.isRevoked {
            try await db.transaction { tx in
                guard try await DB.swap(tx, table: RewardRecord.schema, id: id.uuid, column: "status", expected: "active", newValue: "revoked") else { return }
                reward.status = "revoked"
                for pass in try await WalletPassRecord.query(on: tx).filter(\.$rewardId == id.uuid).filter(\.$voided == false).all() {
                    try await WalletService(db: tx, ctx: ctx).void(pass)
                }
                _ = try await AuditService(db: tx, ctx: ctx).record("reward.revoked", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                    businessId: principal.businessId, subjectType: "reward", subjectId: id.description)
            }
            // Outstanding codes are refused at validation; release their reservations now so points come back.
            try await releaseOutstanding(rewardId: id.uuid)
        }
        reward.status = "revoked"
        return dto(reward, business: summary, eligibility: nil, state: nil)
    }

    private func releaseOutstanding(rewardId: UUID) async throws {
        for row in try await RewardRedemptionRecord.query(on: db).filter(\.$rewardId == rewardId).filter(\.$status == "issued").all() { try await release(row) }
    }

    // MARK: - Business: points

    func adjustPoints(principal: BusinessPrincipal, request: AdjustLoyaltyPointsRequest, headerKey: String?) async throws -> LoyaltyPointsResult {
        if let headerKey, headerKey != request.idempotencyKey { throw APIError.badRequest("Idempotency-Key header does not match the request body.") }
        guard !request.idempotencyKey.isEmpty, request.idempotencyKey.count <= 128 else {
            throw APIError.validation("idempotencyKey is required.", details: ["idempotencyKey": "invalid"])
        }
        guard request.delta != 0, abs(request.delta) <= 1_000_000 else {
            throw APIError.validation("delta must be non-zero and at most 1,000,000 in magnitude.", details: ["delta": "invalid"])
        }
        if let reason = request.reason, !(reason.count <= 40 && reason.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "_.-".unicodeScalars.contains($0)) }) {
            throw APIError.validation("reason is not valid.", details: ["reason": "invalid"])
        }
        let hash = SecureToken.sha256Hex(try ViadereJSON.encode(request))
        let businessId = principal.businessId.uuid
        guard let relationship = try await RelationshipRecord.query(on: db).filter(\.$id == request.relationshipId.uuid)
            .filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        try await Sandbox(db: db).requireMatching(relationship: relationship, livemode: principal.livemode)
        func result(applied: Bool) async throws -> LoyaltyPointsResult {
            guard let account = try await LoyaltyAccountRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$consumerId == relationship.consumerId).first(),
                  let program = try await LoyaltyProgramRecord.query(on: db).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
            let tier = program.tiers.last { $0.minimumPoints <= account.pointsBalance }
            return LoyaltyPointsResult(relationshipId: request.relationshipId, pointsBalance: account.pointsBalance, statusName: tier?.name, applied: applied)
        }
        if let existing = try await LoyaltyLedgerRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$idempotencyKey == request.idempotencyKey).first() {
            guard ConstantTime.equals(existing.requestHash, hash) else {
                throw APIError(.conflict, .idempotencyConflict, "This Idempotency-Key was already used with a different request.")
            }
            return try await result(applied: false)
        }
        guard relationship.isActive else { throw APIError.conflict("The consumer is not connected to your business.") }
        guard let account = try await LoyaltyAccountRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$consumerId == relationship.consumerId).first() else {
            throw APIError.conflict("The consumer has not joined your loyalty program.")
        }
        let now = ctx.now
        do {
            try await db.transaction { tx in
                let balance = try await Self.adjustBalance(on: tx, businessId: businessId, consumerId: relationship.consumerId, delta: request.delta, now: now)
                let ledger = LoyaltyLedgerRecord()
                ledger.id = UUID()
                ledger.businessId = businessId
                ledger.consumerId = relationship.consumerId
                ledger.accountId = account.id!
                ledger.delta = request.delta
                ledger.reason = request.reason
                ledger.idempotencyKey = request.idempotencyKey
                ledger.requestHash = hash
                ledger.balanceAfter = balance
                ledger.createdAt = now
                try await ledger.create(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("loyalty.points_adjusted", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                    consumerId: ConsumerID(relationship.consumerId), businessId: principal.businessId, subjectType: "loyalty_account",
                    subjectId: account.id?.uuidString.lowercased(), metadata: ["delta": String(request.delta)])
                try await WalletService(db: tx, ctx: ctx).touch(consumer: relationship.consumerId, businessId: businessId, kind: .storeCard)
            }
        } catch {
            if error.isConstraintViolation, try await LoyaltyLedgerRecord.query(on: db).filter(\.$businessId == businessId)
                .filter(\.$idempotencyKey == request.idempotencyKey).count() > 0 { return try await result(applied: false) }
            throw error
        }
        return try await result(applied: true)
    }

    // MARK: - Business: consume a redemption code

    func consume(principal: BusinessPrincipal, request: ConsumeRedemptionRequest) async throws -> RedemptionReceipt {
        // The 50-bit code space is only brute-forceable at the rate this allows.
        try await ctx.limiter.enforce("redemption-consume", key: principal.businessId.description, rule: ctx.config.rateLimits.redemptionConsume)
        let location = try Self.validatedLocation(request.locationCode)
        // Malformed, unknown and another business's codes are the same 404: nothing to learn from the difference.
        guard let normalized = Self.normalizeCode(request.code),
              let row = try await RewardRedemptionRecord.query(on: db).filter(\.$codeHash == codeHash(normalized))
                .filter(\.$businessId == principal.businessId.uuid).first(), let rowId = row.id,
              try await Sandbox(db: db).matches(consumerId: row.consumerId, livemode: principal.livemode) else { throw APIError.notFound }
        let now = ctx.now
        switch row.status {
        case "consumed":
            throw APIError(.conflict, .conflict, "This code was already used.",
                           details: row.consumedAt.map { ["redeemedAt": ViadereDate.format($0)] })
        case "expired":
            throw APIError.gone("This code has expired.")
        default:
            break
        }
        if row.expiresAt <= now {
            try await release(row)
            throw APIError.gone("This code has expired.")
        }
        guard let reward = try await RewardRecord.find(row.rewardId, on: db), !reward.isRevoked else {
            try await release(row)
            throw APIError.gone("This reward is no longer available.")
        }
        let receipt: RedemptionReceipt
        do {
            receipt = try await DB.retryingTransient { try await db.transaction { tx in
                // The single atomic step: only one caller flips issued → consumed.
                guard try await DB.swap(tx, table: RewardRedemptionRecord.schema, id: rowId, column: "status", expected: "issued",
                                        newValue: "consumed", extra: [("consumed_at", now)]) else { throw ConcurrencyConflict() }
                if let location { try await RewardRedemptionRecord.query(on: tx).filter(\.$id == rowId).set(\.$locationCode, to: location).update() }
                let receipt = RedemptionReceipt(
                    redemptionId: RedemptionID(rowId), rewardId: RewardID(reward.id!), rewardTitle: reward.title, kind: reward.kindValue,
                    consumerReference: ctx.hasher.consumerReference(businessId: principal.businessId, consumerId: ConsumerID(row.consumerId)),
                    redeemedAt: now, pointsSpent: row.pointsHeld > 0 ? row.pointsHeld : nil, locationCode: location ?? row.locationCode)
                try await UsageMeter.record(.rewardRedemption, businessId: principal.businessId.uuid, livemode: principal.livemode,
                                            ref: rowId.uuidString.lowercased(), at: now, on: tx)
                try await WebhookService(db: tx, ctx: ctx).enqueue(.rewardRedeemed, businessId: principal.businessId, payload: receipt)
                _ = try await AuditService(db: tx, ctx: ctx).record("reward.redeemed", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                    consumerId: ConsumerID(row.consumerId), businessId: principal.businessId, subjectType: "reward_redemption",
                    subjectId: rowId.uuidString.lowercased(), metadata: ["rewardId": reward.id!.uuidString.lowercased(), "points": String(row.pointsHeld)])
                // A lifetime coupon is spent: void its pass. A points reward changed the balance on the loyalty card.
                let walletService = WalletService(db: tx, ctx: ctx)
                if RewardEligibilityEvaluator.limit(kind: reward.kindValue, recurring: reward.isRecurring, perDayLimit: reward.perDayLimit)?.scope == .lifetime {
                    for pass in try await WalletPassRecord.query(on: tx).filter(\.$rewardId == reward.id!).filter(\.$consumerId == row.consumerId)
                        .filter(\.$voided == false).all() { try await walletService.void(pass) }
                }
                if row.pointsHeld > 0 { try await walletService.touch(consumer: row.consumerId, businessId: row.businessId, kind: .storeCard) }
                return receipt
            } }
        } catch is ConcurrencyConflict {
            throw APIError(.conflict, .conflict, "This code was already used.")
        }
        return receipt
    }
}
