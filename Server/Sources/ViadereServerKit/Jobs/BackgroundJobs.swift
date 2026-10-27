import Fluent
import Foundation
import Vapor

/// Maintenance and delivery jobs. State lives in the database, so any number of instances can run them
/// safely (claims are compare-and-swap). `runOnce` is also what tests call directly.
struct BackgroundJobs {
    let app: Application

    struct Report: Equatable, Sendable {
        var webhooksAttempted = 0
        var smsSent = 0
        var interactionsExpired = 0
        var channelMessages = 0
        var redemptionsReleased = 0
        var passPushes = 0
    }

    @discardableResult
    func runOnce() async throws -> Report {
        let db = app.db
        let ctx = app.ctx
        var report = Report()
        report.interactionsExpired = try await InteractionService(db: db, ctx: ctx).expireDue()
        report.smsSent = try await OutboundSMS(db: db, ctx: ctx).sendDue()
        report.channelMessages = try await ChannelRouter(db: db, ctx: ctx).deliverDue()
        report.webhooksAttempted = try await WebhookService(db: db, ctx: ctx).deliverDue()
        // Redemption codes that expired unused give their per-day slot and points back.
        report.redemptionsReleased = try await RewardsService(db: db, ctx: ctx).releaseExpired()
        report.passPushes = try await WalletService(db: db, ctx: ctx).deliverDue()
        try await HouseholdService(db: db, ctx: ctx).recordExpired()
        // Complaint / opt-out thresholds are evaluated at most once a minute per instance.
        if await ctx.limiter.allow("abuse-sweep", key: "all", rule: .perMinute(1, burst: 1)) {
            try await AbuseService(db: db, ctx: ctx).sweep()
        }
        if await ctx.limiter.allow("dashboard-purge", key: "all", rule: .perMinute(1, burst: 1)) {
            try await DashboardSessionStore.purge(on: db, now: ctx.now)
            try await WalletService(db: db, ctx: ctx).purge()
        }
        if await ctx.limiter.allow("retention-purge", key: "all", rule: .perMinute(1, burst: 1)) {
            try await RetentionService(db: db, ctx: ctx).purge()
        }
        try await DatabaseReplayGuard.purge(on: db, now: ctx.now)
        let now = ctx.now
        let staleCeremonies = PasskeyCeremonyRecord.query(on: db).filter(\.$expiresAt < now.addingTimeInterval(-3600))
        if try await staleCeremonies.count() > 0 {
            try await PasskeyCeremonyRecord.query(on: db).filter(\.$expiresAt < now.addingTimeInterval(-3600)).delete()
        }
        return report
    }
}

/// Runs `BackgroundJobs` on a fixed cadence for the life of the application.
final class BackgroundJobRunner: LifecycleHandler, @unchecked Sendable {
    private let lock = NSLock()
    private var task: Task<Void, Never>?
    let interval: Duration

    init(interval: Duration = .seconds(5)) { self.interval = interval }

    func didBoot(_ application: Application) throws { start(application) }

    func didBootAsync(_ application: Application) async throws { start(application) }

    /// Starts the loop once (Vapor may call either boot hook depending on how the app is driven).
    private func start(_ application: Application) {
        let interval = self.interval
        let logger = application.logger
        lock.withLock {
            guard task == nil else { return }
            task = Task { [application] in
                while !Task.isCancelled {
                    do { try await BackgroundJobs(app: application).runOnce() } catch {
                        logger.warning("background job failed", metadata: ["error": "\(type(of: error))"])
                    }
                    try? await Task.sleep(for: interval)
                }
            }
        }
    }

    func shutdown(_ application: Application) {
        lock.withLock {
            task?.cancel()
            task = nil
        }
    }

    func shutdownAsync(_ application: Application) async {
        let current = lock.withLock { () -> Task<Void, Never>? in
            let t = task
            task = nil
            return t
        }
        current?.cancel()
        await current?.value
    }
}
