import Fluent
import Foundation
import ViadereCore

/// Ongoing assurance (spec §8.1 step 7): a business in production is re-checked periodically. A verified domain must still prove control
/// (the DNS record or the file is looked up again every `DOMAIN_RECHECK_DAYS`), and every required contract must be accepted at its current
/// material version. A failure starts a grace period (`ASSURANCE_GRACE_DAYS`, default 14) and mails the owners; if it is not fixed by the end of
/// it, the system suspends the business. Fixing it lifts a suspension that the assurance caused (and only that one).
struct OnboardingAssurance {
    let db: any Database
    let ctx: ServerContext

    static let batch = 50

    struct Report: Equatable {
        var checked = 0
        var graceStarted = 0
        var suspended = 0
        var recovered = 0
    }

    func run() async throws -> Report {
        var report = Report()
        let now = ctx.now
        let interval = min(ctx.config.operations.domainRecheckInterval, 86_400)
        let due = try await BusinessOnboardingRecord.query(on: db).filter(\.$goLiveStatus == OnboardingGoLive.approved.rawValue)
            .group(.or) { $0.filter(\.$assuranceCheckedAt == nil); $0.filter(\.$assuranceCheckedAt <= now.addingTimeInterval(-interval)) }
            .sort(\.$assuranceCheckedAt, .ascending).limit(Self.batch).all()
        for row in due {
            try await check(row, now: now, report: &report)
        }
        return report
    }

    /// One business. Public to the tests so a single business can be driven with the clock.
    func check(_ row: BusinessOnboardingRecord, now: Date, report: inout Report) async throws {
        guard let business = try await BusinessRecord.find(row.businessId, on: db), business.status == .verified || business.status == .suspended else { return }
        report.checked += 1
        var failures: [String] = []
        // 1. Domain control, from the stored result of the periodic probe.
        let domains = try await BusinessDomainRecord.query(on: db).filter(\.$businessId == row.businessId).filter(\.$verifiedDomain != nil).all()
        var anyControl = false
        for domain in domains {
            if let next = domain.nextCheckAt, next > now, domain.status == "verified" { anyControl = true; continue }
            let outcome = await DomainControl(db: db, ctx: ctx).probe(domain)
            domain.lastCheckedAt = now
            switch outcome {
            case .verified(let method):
                domain.status = "verified"
                domain.method = method
                domain.failures = 0
                domain.lastError = nil
                domain.nextCheckAt = now.addingTimeInterval(ctx.config.operations.domainRecheckInterval)
                anyControl = true
            case .notFound, .unavailable, .claimedElsewhere:
                // A resolver outage must not suspend anybody: only a definite "the record is gone" counts as a failed control check.
                domain.failures += 1
                domain.lastError = outcome == .notFound ? "token_not_found" : "lookup_failed"
                if outcome == .notFound { domain.status = "failed" } else if domain.status == "verified" { anyControl = true }
            }
            try await domain.update(on: db)
        }
        if !anyControl, !domains.isEmpty || row.controlVerifiedAt != nil { failures.append("domain_control") }
        // 2. Contract currency.
        let outstanding = try await ContractService(db: db, ctx: ctx).outstanding(businessId: row.businessId)
        if !outstanding.isEmpty {
            let deadline = row.contractsDueAt ?? .distantPast
            if now >= deadline { failures.append("contracts_outdated") }
        }
        row.assuranceCheckedAt = now
        if failures.isEmpty {
            try await recover(row, business: business, now: now, report: &report)
            try await row.update(on: db)
            return
        }
        ctx.metrics.count(.assuranceFailed)
        row.assuranceFailure = failures.joined(separator: " ")
        let started = row.assuranceGraceStartedAt ?? now
        if row.assuranceGraceStartedAt == nil {
            row.assuranceGraceStartedAt = now
            report.graceStarted += 1
            _ = try await AuditService(db: db, ctx: ctx).record("assurance.grace_started", outcome: .failure, actor: AuditActor(kind: .system), businessId: BusinessID(row.businessId),
                subjectType: "onboarding", subjectId: row.businessId.uuidString.lowercased(), metadata: ["failures": row.assuranceFailure ?? ""])
            await Notifier(db: db, ctx: ctx).notifyBusiness(row.businessId, roles: [.owner, .orgAdmin, .securityAdmin], topic: .assurance,
                subject: "Action needed to keep your Viadere organization active",
                text: Self.explanation(failures) + "\n\nFix this by \(DashboardFormat.date(started.addingTimeInterval(ctx.config.operations.assuranceGrace))) or Viadere will suspend your organization. Open the console under Organization > Onboarding.",
                kind: "assurance-grace")
        }
        if business.status == .verified, now >= started.addingTimeInterval(ctx.config.operations.assuranceGrace) {
            try await BusinessOnboarding(db: db, ctx: ctx).suspend(businessId: row.businessId, actor: AuditActor(kind: .system, id: "assurance"), updatedBy: nil,
                                                                   reason: "Ongoing assurance failed: " + failures.joined(separator: ", "))
            row.assuranceSuspended = true
            report.suspended += 1
        }
        try await row.update(on: db)
    }

    private func recover(_ row: BusinessOnboardingRecord, business: BusinessRecord, now: Date, report: inout Report) async throws {
        guard row.assuranceGraceStartedAt != nil || row.assuranceSuspended else { row.assuranceFailure = nil; return }
        if row.assuranceSuspended, business.status == .suspended {
            // Lift only the suspension the assurance itself caused; an operator's suspension stays until an operator lifts it.
            let controls = try await BusinessControls.load(row.businessId, on: db)
            if controls?.suspensionReason?.hasPrefix("Ongoing assurance failed") == true {
                try await BusinessOnboarding(db: db, ctx: ctx).unsuspend(businessId: row.businessId, actor: AuditActor(kind: .system, id: "assurance"), updatedBy: nil)
            }
        }
        row.assuranceSuspended = false
        row.assuranceGraceStartedAt = nil
        row.assuranceFailure = nil
        report.recovered += 1
        _ = try await AuditService(db: db, ctx: ctx).record("assurance.recovered", actor: AuditActor(kind: .system), businessId: BusinessID(row.businessId),
                                                          subjectType: "onboarding", subjectId: row.businessId.uuidString.lowercased())
        await Notifier(db: db, ctx: ctx).notifyBusiness(row.businessId, roles: [.owner, .orgAdmin, .securityAdmin], topic: .assurance,
            subject: "Your Viadere organization is in good standing", text: "Your domain and agreements are current again. No further action is needed.", kind: "assurance-ok")
    }

    static func explanation(_ failures: [String]) -> String {
        var lines: [String] = []
        if failures.contains("domain_control") { lines.append("We could no longer find the verification record for your domain. Publish it again (or serve the verification file) and run the check.") }
        if failures.contains("contracts_outdated") { lines.append("A Viadere agreement changed in substance and needs your acceptance of the new version.") }
        return lines.joined(separator: "\n")
    }
}
