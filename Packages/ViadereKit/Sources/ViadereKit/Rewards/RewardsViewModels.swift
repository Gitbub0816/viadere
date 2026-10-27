import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// Plain-language mapping of reward API failures. A `409` means the server's verdict changed since the screen loaded.
public enum RewardErrors {
    public static func message(for error: any Error) -> String {
        guard let api = error as? APIError else { return "Something went wrong. Please try again." }
        if case .server(_, let code, _) = api {
            switch code {
            case .conflict, .forbidden: return "That reward isn't available right now. We've refreshed the list."
            case .gone, .expired: return "That reward has expired."
            case .consentRequired: return "Turn on Rewards for this business to use it."
            default: break
            }
        }
        return api.userMessage
    }

    /// The server disagreed with what the screen showed: reload to show its current verdict.
    public static func isStaleVerdict(_ error: any Error) -> Bool {
        guard case .server(_, let code, _)? = error as? APIError else { return false }
        return code == .conflict || code == .forbidden || code == .gone || code == .expired
    }
}

/// The aggregated Rewards screen: memberships with points and status, then rewards across every business.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class RewardsViewModel {
    public enum Phase: Equatable, Sendable { case idle, loading, loaded, unavailable, failed(String) }

    public private(set) var overview = RewardsOverview()
    public private(set) var phase: Phase = .idle
    public private(set) var fetchedAt: Date?
    public private(set) var busyRewardId: RewardID?
    public private(set) var message: String?
    private let services: ViadereServices

    public init(services: ViadereServices, initial: RewardsOverview = RewardsOverview()) {
        self.services = services
        self.overview = initial
    }

    public func load() async {
        if overview.rewards.isEmpty, overview.accounts.isEmpty { phase = .loading }
        do {
            overview = try await services.api.rewardsOverview()
            fetchedAt = services.clock()
            phase = .loaded
        } catch let error as APIError {
            phase = error.code == .notFound ? .unavailable : .failed(error.userMessage)
        } catch {
            phase = .failed("Something went wrong.")
        }
    }

    public var accounts: [LoyaltyAccount] { overview.accounts }

    public func presentation(for entry: RewardEntry) -> RewardRowPresentation {
        RewardRowPresentation(entry, now: services.clock(), fetchedAt: fetchedAt ?? .distantPast)
    }

    /// Rewards the server says can be used now, then rewards that are waiting, then finished ones.
    public var sections: [RewardSection] { RewardSection.build(overview.rewards, presentation: presentation(for:)) }

    public var availableCount: Int { overview.rewards.filter { $0.eligibility.state == .eligible }.count }

    public func entry(_ id: RewardID) -> RewardEntry? { overview.rewards.first { $0.id == id } }

    public func claim(_ entry: RewardEntry) async {
        guard busyRewardId == nil else { return }
        busyRewardId = entry.id
        message = nil
        defer { busyRewardId = nil }
        do {
            let updated = try await services.api.claimReward(entry.id)
            if let index = overview.rewards.firstIndex(where: { $0.id == updated.id }) { overview.rewards[index] = updated }
            message = "Claimed. It's saved to your rewards."
        } catch {
            message = RewardErrors.message(for: error)
            if RewardErrors.isStaleVerdict(error) { await load() }
        }
    }

    /// A redemption session for a reward the server says is eligible. The code is requested only when the view starts it.
    public func redemption(for entry: RewardEntry) -> RedemptionViewModel {
        RedemptionViewModel(entry: entry, services: services) { [weak self] in await self?.load() }
    }

    public func clearMessage() { message = nil }
}

public struct RewardSection: Identifiable, Equatable, Sendable {
    public enum Kind: String, Sendable { case available, waiting, finished }
    public var kind: Kind
    public var entries: [RewardEntry]
    public var id: String { kind.rawValue }

    public var title: String {
        switch kind {
        case .available: "Ready to use"
        case .waiting: "Coming up"
        case .finished: "Used and expired"
        }
    }

    public static func build(_ rewards: [RewardEntry], presentation: (RewardEntry) -> RewardRowPresentation) -> [RewardSection] {
        var available: [RewardEntry] = [], waiting: [RewardEntry] = [], finished: [RewardEntry] = []
        for entry in rewards {
            switch presentation(entry).tone {
            case .available: available.append(entry)
            case .waiting: waiting.append(entry)
            case .finished: finished.append(entry)
            }
        }
        return [RewardSection(kind: .available, entries: available), RewardSection(kind: .waiting, entries: waiting),
                RewardSection(kind: .finished, entries: finished)].filter { !$0.entries.isEmpty }
    }
}

/// One business's rewards and the enrollment / account-linking flow, shown from Business detail.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class BusinessRewardsViewModel {
    public enum Phase: Equatable, Sendable { case idle, loading, loaded, noProgram, failed(String) }
    public enum Enrollment: Equatable, Sendable { case idle, enrolling, failed(String) }

    public let business: BusinessSummary
    public private(set) var program: LoyaltyProgramOverview?
    public private(set) var phase: Phase = .idle
    public private(set) var enrollment: Enrollment = .idle
    public private(set) var fetchedAt: Date?
    public private(set) var busyRewardId: RewardID?
    public private(set) var message: String?
    private let services: ViadereServices

    public init(business: BusinessSummary, services: ViadereServices) {
        self.business = business
        self.services = services
    }

    public func load() async {
        do {
            program = try await services.api.loyaltyProgram(business: business.id)
            fetchedAt = services.clock()
            phase = .loaded
        } catch let error as APIError {
            phase = error.code == .notFound ? .noProgram : .failed(error.userMessage)
        } catch {
            phase = .failed("Something went wrong.")
        }
    }

    public var account: LoyaltyAccount? { program?.account }
    public var rewards: [RewardEntry] { program?.rewards ?? [] }
    public var isEnrolled: Bool { account != nil }

    public func presentation(for entry: RewardEntry) -> RewardRowPresentation {
        RewardRowPresentation(entry, now: services.clock(), fetchedAt: fetchedAt ?? .distantPast)
    }

    /// Joins the program (optionally linking an existing membership). The person accepts the terms version shown.
    @discardableResult
    public func enroll(existingMemberReference: String?) async -> Bool {
        guard let program, enrollment != .enrolling else { return false }
        enrollment = .enrolling
        let trimmed = existingMemberReference?.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            let account = try await services.api.enrollLoyalty(
                business: business.id,
                LoyaltyEnrollRequest(existingMemberReference: (trimmed?.isEmpty ?? true) ? nil : String(trimmed?.prefix(64) ?? ""),
                                     acceptedTermsVersion: program.termsVersion))
            self.program?.account = account
            enrollment = .idle
            await load()
            return true
        } catch {
            enrollment = .failed(RewardErrors.message(for: error))
            return false
        }
    }

    public func clearEnrollmentError() { if case .failed = enrollment { enrollment = .idle } }

    public func claim(_ entry: RewardEntry) async {
        guard busyRewardId == nil else { return }
        busyRewardId = entry.id
        message = nil
        defer { busyRewardId = nil }
        do {
            _ = try await services.api.claimReward(entry.id)
            message = "Claimed. It's saved to your rewards."
            await load()
        } catch {
            message = RewardErrors.message(for: error)
            if RewardErrors.isStaleVerdict(error) { await load() }
        }
    }

    public func redemption(for entry: RewardEntry) -> RedemptionViewModel {
        RedemptionViewModel(entry: entry, services: services) { [weak self] in await self?.load() }
    }

    public func clearMessage() { message = nil }
}
