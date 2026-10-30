import Fluent
import Foundation
import Vapor

/// Maintenance and delivery jobs. State lives in the database, so any number of instances can run them safely (claims are compare-and-swap).
///
/// The work is split into the task groups the Azure scheduled jobs run (`ViadereServer maintenance <task>`, plan 5.7):
/// - `maintenance` (every 5 minutes): expiries, the delivery sweeps (the safety net behind the queues), purges and retention;
/// - `hourly`: Verify maintenance, API-key lifecycle, onboarding assurance, pending changes;
/// - `audit-export`: the signed audit-head export.
///
/// `runOnce` (the in-process loop on Fly and in development, and what tests call) runs all three plus one pass of the queue pipeline, with the same
/// once-a-minute gates as before, so its behaviour is unchanged.
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

    enum Task: String, CaseIterable, Sendable {
        case maintenance, hourly
        case auditExport = "audit-export"
    }

    @discardableResult
    func runOnce() async throws -> Report {
        let report = try await maintenance(gated: true)
        try await hourly(gated: true)
        try await auditExport(gated: true)
        await QueuePump(app: app).runOnce()
        app.ctx.metrics.jobRan(at: app.ctx.now, failed: false)
        return report
    }

    /// Runs one task group once (`ViadereServer maintenance <task>`). Ungated: the scheduler runs it at its own cadence, one execution at a time.
    func run(_ task: Task) async throws {
        switch task {
        case .maintenance: _ = try await maintenance(gated: false)
        case .hourly: try await hourly(gated: false)
        case .auditExport: try await auditExport(gated: false)
        }
        app.ctx.metrics.jobRan(at: app.ctx.now, failed: false)
    }

    /// Runs `body` when ungated, or when this instance's once-a-minute limiter for `name` allows it.
    private func gate(_ name: String, _ gated: Bool) async -> Bool {
        guard gated else { return true }
        return await app.ctx.limiter.allow(name, key: "all", rule: .perMinute(1, burst: 1))
    }

    /// Each WP6 task is isolated, so one failing integration (the cloud store, a resolver) never stops delivery or the other tasks.
    private func guarded(_ name: String, _ body: () async throws -> Void) async {
        do { try await body() } catch {
            app.logger.warning("background task failed", metadata: ["task": "\(name)", "type": "\(type(of: error))"])
            app.ctx.metrics.jobRan(at: app.ctx.now, failed: true)
        }
    }

    private func maintenance(gated: Bool) async throws -> Report {
        let db = app.db
        let ctx = app.ctx
        var report = Report()
        report.interactionsExpired = try await InteractionService(db: db, ctx: ctx).expireDue()
        // Delivery sweeps: the queue messages do this work as it falls due; the sweep catches anything whose message was lost or dead-lettered.
        report.smsSent = try await OutboundSMS(db: db, ctx: ctx).sendDue()
        report.channelMessages = try await ChannelRouter(db: db, ctx: ctx).deliverDue()
        report.webhooksAttempted = try await WebhookService(db: db, ctx: ctx).deliverDue()
        // Redemption codes that expired unused give their per-day slot and points back.
        report.redemptionsReleased = try await RewardsService(db: db, ctx: ctx).releaseExpired()
        report.passPushes = try await WalletService(db: db, ctx: ctx).deliverDue()
        try await HouseholdService(db: db, ctx: ctx).recordExpired()
        // Approve v2: overdue requests end with one opaque event each; stale enrollments expire.
        if ctx.config.approve.enabled { try await ApproveRequestService(db: db, ctx: ctx).expireDue() }
        try await IdentityMaintenance(db: db, ctx: ctx).run()
        // Complaint / opt-out thresholds are evaluated at most once a minute per instance.
        if await gate("abuse-sweep", gated) {
            try await AbuseService(db: db, ctx: ctx).sweep()
        }
        if await gate("dashboard-purge", gated) {
            try await DashboardSessionStore.purge(on: db, now: ctx.now)
            try await WalletService(db: db, ctx: ctx).purge()
            // Dashboard sign-ups still unverified after 24 hours, and spent codes: the address is free again.
            try await EmailVerificationService.purge(on: db, now: ctx.now)
            // Rate-limit buckets that have fully refilled carry no state (shared store only).
            await ctx.limiter.store.purgeExpired(now: ctx.now)
            // Published outbox rows and old idempotency markers.
            try await QueuePump.purge(on: db, now: ctx.now)
        }
        if await gate("retention-purge", gated) {
            try await RetentionService(db: db, ctx: ctx).purge()
        }
        await guarded("operator-notices") { _ = try await OperatorNotices(db: db, ctx: ctx).deliverDue() }
        await guarded("consumer-exports") { _ = try await ConsumerExports(db: db, ctx: ctx).processQueued() }
        try await DatabaseReplayGuard.purge(on: db, now: ctx.now)
        let now = ctx.now
        let staleCeremonies = PasskeyCeremonyRecord.query(on: db).filter(\.$expiresAt < now.addingTimeInterval(-3600))
        if try await staleCeremonies.count() > 0 {
            try await PasskeyCeremonyRecord.query(on: db).filter(\.$expiresAt < now.addingTimeInterval(-3600)).delete()
        }
        return report
    }

    private func hourly(gated: Bool) async throws {
        let db = app.db
        let ctx = app.ctx
        // Verify: finish expired requests, purge provider sessions, erase spent results (runs even while Verify is switched off).
        try await VerifyService(db: db, ctx: ctx, runtime: app.verify).runMaintenance()
        // Relationships created before `subject_ref` existed get theirs (a read first; nothing to do once all have one).
        try await SubjectResolver.backfill(db: db, ctx: ctx)
        await guarded("api-key-sweep") { _ = try await APIKeyLifecycle(db: db, ctx: ctx).sweep() }
        if await gate("assurance-run", gated) {
            await guarded("assurance") { _ = try await OnboardingAssurance(db: db, ctx: ctx).run() }
            await guarded("pending-changes") { try await PendingChanges(db: db, ctx: ctx).expireDue() }
        }
    }

    private func auditExport(gated: Bool) async throws {
        let ctx = app.ctx
        if ctx.config.operations.auditExport != nil, await gate("audit-export", gated) {
            if gated {
                await guarded("audit-export") { _ = try await AuditHeadExporter(db: app.db, ctx: ctx).runIfDue() }
            } else {
                // The scheduled job's failure is the alert (plan 5.7): let it fail.
                _ = try await AuditHeadExporter(db: app.db, ctx: ctx).runIfDue()
            }
        }
    }
}

/// Runs `BackgroundJobs` on a fixed cadence for the life of the application (Fly, development, and the lean profile before a worker exists).
final class BackgroundJobRunner: LifecycleHandler, @unchecked Sendable {
    private let lock = NSLock()
    private var task: _Concurrency.Task<Void, Never>?
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
            task = _Concurrency.Task { [application] in
                while !_Concurrency.Task.isCancelled {
                    do { try await BackgroundJobs(app: application).runOnce() } catch {
                        logger.warning("background job failed", metadata: ["error": "\(type(of: error))"])
                    }
                    try? await _Concurrency.Task.sleep(for: interval)
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
        let current = lock.withLock { () -> _Concurrency.Task<Void, Never>? in
            let t = task
            task = nil
            return t
        }
        current?.cancel()
        await current?.value
    }
}

/// `ViadereServer maintenance <maintenance|hourly|audit-export>`: one run of a task group, for the Container Apps scheduled jobs.
public struct MaintenanceCommand: AsyncCommand {
    public struct Signature: CommandSignature {
        @Argument(name: "task") var task: String
        public init() {}
    }
    public let signature = Signature()
    public let help = "Runs one maintenance task group once: maintenance, hourly or audit-export."
    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        guard let task = BackgroundJobs.Task(rawValue: signature.task) else {
            context.console.error("Unknown task. Use one of: \(BackgroundJobs.Task.allCases.map(\.rawValue).joined(separator: ", ")).")
            throw Abort(.badRequest)
        }
        try await BackgroundJobs(app: context.application).run(task)
        context.console.print("Ran \(task.rawValue).")
    }
}
