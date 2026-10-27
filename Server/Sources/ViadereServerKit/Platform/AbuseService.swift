import Fluent
import Foundation
import ViadereCore

/// Per-business complaint and opt-out tracking with automatic throttling. Everything here is aggregate: counts and
/// rates, never consumer identifiers.
struct AbuseService {
    let db: any Database
    let ctx: ServerContext

    struct Metrics: Equatable {
        var businessId: UUID
        var windowStart: Date
        var issued = 0
        /// "Not me / I don't recognize this" reports.
        var reports = 0
        var activeRelationships = 0
        /// Consent revocations plus disconnects in the window.
        var optOuts = 0
        var rateLimitHits = 0

        var complaintRate: Double { issued == 0 ? 0 : Double(reports) / Double(issued) }
        var optOutRate: Double { activeRelationships == 0 ? 0 : Double(optOuts) / Double(activeRelationships) }
    }

    enum Evaluation: Equatable {
        case ok
        case throttled(reason: String)
        case lifted
        case unchanged
    }

    // MARK: Signals

    /// Counts one signal in a minute bucket. Best effort: it must never break the request that triggered it.
    static func recordSignal(_ kind: String, businessId: UUID, now: Date, on db: any Database) async {
        let bucket = Int(now.timeIntervalSince1970 / 60)
        do {
            if let existing = try await AbuseSignalRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$kind == kind)
                .filter(\.$bucket == bucket).first(), let id = existing.id {
                _ = try await DB.swap(db, table: AbuseSignalRecord.schema, id: id, column: "count", expected: existing.count, newValue: existing.count + 1)
                return
            }
            let record = AbuseSignalRecord()
            record.id = UUID()
            record.businessId = businessId
            record.kind = kind
            record.bucket = bucket
            record.count = 1
            try await record.create(on: db)
        } catch {
            // Lost a race or the table is unavailable: a missing count is acceptable, a failed request is not.
        }
    }

    // MARK: Metrics

    func metrics(for businessId: UUID) async throws -> Metrics {
        try await metrics(for: businessId, window: ctx.config.abuse.window)
    }

    func metrics(for businessId: UUID, window: TimeInterval) async throws -> Metrics {
        let now = ctx.now
        let start = now.addingTimeInterval(-window)
        var m = Metrics(businessId: businessId, windowStart: start)
        m.issued = try await InteractionRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$livemode == true)
            .filter(\.$createdAt >= start).count()
        m.reports = try await InteractionRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$livemode == true)
            .filter(\.$createdAt >= start).filter(\.$status == InteractionStatus.reported.rawValue).count()
        m.activeRelationships = try await RelationshipRecord.query(on: db).filter(\.$businessId == businessId)
            .group(.or) { group in
                group.filter(\.$disconnectedAt == nil)
                group.filter(\.$disconnectedAt >= start)
            }.count()
        let revocations = try await ConsentGrantRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$granted == false)
            .filter(\.$version > 1).filter(\.$createdAt >= start).count()
        let disconnects = try await RelationshipRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$disconnectedAt >= start).count()
        m.optOuts = revocations + disconnects
        let startBucket = Int(start.timeIntervalSince1970 / 60)
        m.rateLimitHits = try await AbuseSignalRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$kind == "rate_limited")
            .filter(\.$bucket >= startBucket).all().reduce(0) { $0 + $1.count }
        return m
    }

    // MARK: Auto-throttle

    /// Throttles a business whose complaint or opt-out rate exceeds the configured thresholds (given a minimum
    /// sample) and lifts an *automatic* throttle once both rates fall below half the thresholds. An operator-pinned
    /// throttle is never lifted automatically.
    @discardableResult
    func evaluate(businessId: UUID) async throws -> Evaluation {
        let settings = ctx.config.abuse
        let m = try await metrics(for: businessId)
        var exceeded: String?
        if m.issued >= settings.minimumSample, m.complaintRate > settings.complaintRate { exceeded = "complaint_rate" }
        else if m.activeRelationships >= settings.minimumSample, m.optOutRate > settings.optOutRate { exceeded = "opt_out_rate" }
        let controls = try await BusinessControls.load(businessId, on: db)
        let now = ctx.now
        let audit = AuditService(db: db, ctx: ctx)
        if let reason = exceeded {
            guard controls?.throttled != true else { return .unchanged }
            let record = try await BusinessControls.loadOrCreate(businessId, now: now, on: db)
            record.throttled = true
            record.throttleSource = "auto"
            record.throttleReason = reason
            record.throttledAt = now
            record.updatedAt = now
            try await record.update(on: db)
            _ = try await audit.record("abuse.auto_throttled", outcome: .denied, actor: AuditActor(kind: .system), businessId: BusinessID(businessId),
                metadata: ["reason": reason, "complaint_rate": String(format: "%.4f", m.complaintRate), "opt_out_rate": String(format: "%.4f", m.optOutRate)])
            return .throttled(reason: reason)
        }
        if let controls, controls.throttled, controls.throttleSource == "auto",
           m.complaintRate <= settings.complaintRate / 2, m.optOutRate <= settings.optOutRate / 2 {
            controls.throttled = false
            controls.throttleSource = nil
            controls.throttleReason = nil
            controls.updatedAt = now
            try await controls.update(on: db)
            _ = try await audit.record("abuse.throttle_lifted", actor: AuditActor(kind: .system), businessId: BusinessID(businessId))
            return .lifted
        }
        return controls?.throttled == true ? .unchanged : .ok
    }

    /// Evaluates every verified business that issued anything in the window. Safe to run on any instance.
    @discardableResult
    func sweep(limit: Int = 500) async throws -> Int {
        let start = ctx.now.addingTimeInterval(-ctx.config.abuse.window)
        let active = try await InteractionRecord.query(on: db).filter(\.$createdAt >= start).unique().limit(limit).all(\.$businessId)
        let throttled = try await BusinessControlRecord.query(on: db).filter(\.$throttled == true).all().map(\.businessId)
        var count = 0
        for id in Set(active).union(throttled) {
            guard try await BusinessRecord.find(id, on: db)?.isVerified == true else { continue }
            try await evaluate(businessId: id)
            count += 1
        }
        return count
    }
}
