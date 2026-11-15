import Fluent
import Foundation
import SQLKit
import ViadereCore

/// One aggregate count of one business for one UTC day (G21). Only counts that `DashboardAnalytics` shows: no customer, relationship or
/// interaction identifier, no content, nothing below the business. `metric` is a fixed vocabulary (`AnalyticsRollup.Metric`).
final class BusinessDailyStatRecord: Model, @unchecked Sendable {
    static let schema = "business_daily_stats"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    /// UTC midnight starting the day.
    @Field(key: "day") var day: Date
    @Field(key: "metric") var metric: String
    @Field(key: "count") var count: Int
    init() {}
}

/// A UTC day the rollup has written for **every** business. A closed day without a marker is read from the raw rows instead, so a day the job
/// missed is never shown as zero.
final class AnalyticsRollupDayRecord: Model, @unchecked Sendable {
    static let schema = "analytics_rollup_days"
    @ID(key: .id) var id: UUID?
    @Field(key: "day") var day: Date
    @Field(key: "completed_at") var completedAt: Date
    init() {}
}

/// `AnalyticsRollup.v1` (additive).
struct CreateAnalyticsRollupSchema: AsyncMigration {
    var name: String { "AnalyticsRollup.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(BusinessDailyStatRecord.schema).id()
            .field("business_id", .uuid, .required, .references("businesses", "id", onDelete: .cascade))
            .field("day", .datetime, .required)
            .field("metric", .string, .required)
            .field("count", .int, .required)
            .unique(on: "business_id", "day", "metric")
            .create()
        try await db.schema(AnalyticsRollupDayRecord.schema).id()
            .field("day", .datetime, .required)
            .field("completed_at", .datetime, .required)
            .unique(on: "day")
            .create()
        guard let sql = db as? any SQLDatabase else { return }
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_business_daily_stats_day ON business_daily_stats (day)").run()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(AnalyticsRollupDayRecord.schema).delete()
        try await db.schema(BusinessDailyStatRecord.schema).delete()
    }
}

/// The daily analytics rollup (G21; runs in the `hourly` task group under the `analytics-rollup` lease). For each closed UTC day it counts,
/// per business, what the overview shows, and replaces that day's rows in one transaction (so a re-run is idempotent). The last
/// `settleDays` days are recomputed on every run (an interaction created at 23:59 may be decided after midnight; a webhook retries for a day),
/// older days only when their marker is missing (the job did not run): up to `backfillDays` back.
struct AnalyticsRollup {
    let db: any Database
    let ctx: ServerContext

    static let lease = "analytics-rollup"
    static let leaseTTL: TimeInterval = 600
    static let settleDays = 3
    static let backfillDays = 90
    /// Rollups outlive the raw rows (aggregates only) but not forever.
    static let keepDays = 400

    enum Metric {
        static func issued(_ kind: String) -> String { "issued.\(kind)" }
        static func decided(_ kind: String) -> String { "decided.\(kind)" }
        static let webhookSucceeded = "webhook.succeeded"
        static let webhookDead = "webhook.dead"
        static let channelDelivered = "channel.delivered"
        static let channelFailed = "channel.failed"
        static let disconnects = "disconnects"
    }

    static var calendar: Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar
    }

    static func startOfDay(_ date: Date) -> Date { calendar.startOfDay(for: date) }
    static func day(_ date: Date, plus days: Int) -> Date { calendar.date(byAdding: .day, value: days, to: date)! }

    /// Counts per business for `[from, to)`, from the raw rows. `businessId` restricts it to one tenant (the live part of the overview).
    func rawCounts(from: Date, to: Date, businessId: UUID? = nil) async throws -> [UUID: [String: Int]] {
        var out: [UUID: [String: Int]] = [:]
        func add(_ business: UUID, _ metric: String, _ n: Int = 1) { out[business, default: [:]][metric, default: 0] += n }
        let known = Set(InteractionKind.known.map(\.rawValue))
        var interactions = InteractionRecord.query(on: db).filter(\.$livemode == true).filter(\.$createdAt >= from).filter(\.$createdAt < to)
        if let businessId { interactions = interactions.filter(\.$businessId == businessId) }
        for row in try await interactions.field(\.$businessId).field(\.$kind).field(\.$decidedAt).all() where known.contains(row.kind) {
            add(row.businessId, Metric.issued(row.kind))
            if row.decidedAt != nil { add(row.businessId, Metric.decided(row.kind)) }
        }
        var hooks = WebhookDeliveryRecord.query(on: db).filter(\.$createdAt >= from).filter(\.$createdAt < to).filter(\.$status ~~ ["succeeded", "dead"])
        if let businessId { hooks = hooks.filter(\.$businessId == businessId) }
        for row in try await hooks.field(\.$businessId).field(\.$status).all() {
            add(row.businessId, row.status == "succeeded" ? Metric.webhookSucceeded : Metric.webhookDead)
        }
        var channel = ChannelOutboundRecord.query(on: db).filter(\.$createdAt >= from).filter(\.$createdAt < to).filter(\.$status ~~ ["sent", "delivered", "failed"])
        if let businessId { channel = channel.filter(\.$businessId == businessId) }
        for row in try await channel.field(\.$businessId).field(\.$status).all() {
            add(row.businessId, row.status == "failed" ? Metric.channelFailed : Metric.channelDelivered)
        }
        var gone = RelationshipRecord.query(on: db).filter(\.$disconnectedAt >= from).filter(\.$disconnectedAt < to)
        if let businessId { gone = gone.filter(\.$businessId == businessId) }
        for row in try await gone.field(\.$businessId).all() { add(row.businessId, Metric.disconnects) }
        return out
    }

    /// Writes one day for every business: the day's rows are replaced and its marker set, in one transaction.
    func rollUp(day: Date) async throws {
        let start = Self.startOfDay(day)
        let counts = try await rawCounts(from: start, to: Self.day(start, plus: 1))
        let now = ctx.now
        try await db.transaction { tx in
            try await BusinessDailyStatRecord.query(on: tx).filter(\.$day == start).delete()
            var rows: [BusinessDailyStatRecord] = []
            for (business, metrics) in counts {
                for (metric, count) in metrics where count > 0 {
                    let row = BusinessDailyStatRecord()
                    row.id = UUID()
                    row.businessId = business
                    row.day = start
                    row.metric = metric
                    row.count = count
                    rows.append(row)
                }
            }
            for chunk in stride(from: 0, to: rows.count, by: 200) { try await Array(rows[chunk..<min(rows.count, chunk + 200)]).create(on: tx) }
            try await AnalyticsRollupDayRecord.query(on: tx).filter(\.$day == start).delete()
            let marker = AnalyticsRollupDayRecord()
            marker.id = UUID()
            marker.day = start
            marker.completedAt = now
            try await marker.create(on: tx)
        }
    }

    /// One run: the settle window always, older days only when missing; then the purge. Returns the days written. Skips when another run holds
    /// the lease (the work is idempotent anyway; the lease only saves duplicate work).
    @discardableResult
    func run() async throws -> Int {
        let holder = UUID()
        guard try await JobLease.acquire(Self.lease, holder: holder, ttl: Self.leaseTTL, on: db, now: ctx.now) else { return 0 }
        var written = 0
        do {
            let today = Self.startOfDay(ctx.now)
            let earliest = Self.day(today, plus: -Self.backfillDays)
            let done = Set(try await AnalyticsRollupDayRecord.query(on: db).filter(\.$day >= earliest).all().map { $0.day.timeIntervalSince1970 })
            for offset in 1...Self.backfillDays {
                let day = Self.day(today, plus: -offset)
                guard offset <= Self.settleDays || !done.contains(day.timeIntervalSince1970) else { continue }
                try await rollUp(day: day)
                written += 1
            }
            let cutoff = Self.day(today, plus: -Self.keepDays)
            try await BusinessDailyStatRecord.query(on: db).filter(\.$day < cutoff).delete()
            try await AnalyticsRollupDayRecord.query(on: db).filter(\.$day < cutoff).delete()
        } catch {
            try? await JobLease.release(Self.lease, holder: holder, on: db)
            throw error
        }
        try await JobLease.release(Self.lease, holder: holder, on: db)
        return written
    }

    /// The counts of one business for the closed days `[from, to)` (`from`, `to` UTC midnights): rolled-up days from the rollup, any day
    /// without a marker from the raw rows. Per day, for the chart.
    func closedDays(businessId: UUID, from: Date, to: Date) async throws -> [(day: Date, counts: [String: Int])] {
        guard from < to else { return [] }
        let rolled = Set(try await AnalyticsRollupDayRecord.query(on: db).filter(\.$day >= from).filter(\.$day < to).all().map { $0.day.timeIntervalSince1970 })
        let rows = try await BusinessDailyStatRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$day >= from).filter(\.$day < to).all()
        var byDay: [TimeInterval: [String: Int]] = [:]
        for row in rows { byDay[row.day.timeIntervalSince1970, default: [:]][row.metric, default: 0] += row.count }
        var out: [(Date, [String: Int])] = []
        var day = from
        while day < to {
            let next = Self.day(day, plus: 1)
            if rolled.contains(day.timeIntervalSince1970) {
                out.append((day, byDay[day.timeIntervalSince1970] ?? [:]))
            } else {
                out.append((day, try await rawCounts(from: day, to: next, businessId: businessId)[businessId] ?? [:]))
            }
            day = next
        }
        return out
    }
}
