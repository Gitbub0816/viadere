import Fluent
import Foundation
import ViadereCore

/// The Verify card on the business dashboard overview (read-only; WP6 expands the console). **Counts by outcome only**: no customer, no
/// reference, no attribute, no timestamp finer than the period. Shown only to a business that holds a Verify capability.
enum VerifyDashboard {
    struct Counts: Equatable {
        var verified = 0
        var notVerified = 0
        var pending = 0
        var total: Int { verified + notVerified + pending }
    }

    /// Per capability, over the last `days` days. Outcomes are the ones the business itself can see (`verified`, `not_verified`, `pending`):
    /// the dashboard never shows more than the API does, so it cannot reveal why a check failed (AGE-005).
    static func counts(db: any Database, ctx: ServerContext, businessId: UUID, days: Int) async throws -> [(capability: Capability, counts: Counts)] {
        let now = ctx.now
        let since = now.addingTimeInterval(-TimeInterval(days) * 86_400)
        let rows = try await VerificationRequestRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$livemode == true).filter(\.$createdAt >= since).all()
        var byCapability: [String: Counts] = [:]
        for row in rows {
            var counts = byCapability[row.capability] ?? Counts()
            switch row.consumerStatus {
            case .released: counts.verified += 1
            case .pendingConsent, .consented: if row.expiresAt > now { counts.pending += 1 } else { counts.notVerified += 1 }
            default: counts.notVerified += 1
            }
            byCapability[row.capability] = counts
        }
        return VerifyService.supportedCapabilities.compactMap { capability in byCapability[capability.rawValue].map { (capability, $0) } }
    }

    /// The card's HTML, or an empty string when the business holds no Verify capability.
    static func card(db: any Database, ctx: ServerContext, businessId: UUID, days: Int) async throws -> String {
        let entitled = try await EntitlementService(db: db, ctx: ctx).snapshot(businessId: businessId)
        guard !entitled.capabilities.isDisjoint(with: VerifyService.supportedCapabilities) else { return "" }
        guard ctx.config.verify.enabled else {
            return "<div class=\"card\"><h2>Verify</h2><p class=\"mu sm\">Verify is not enabled for the platform yet. Nothing has been requested.</p></div>"
        }
        let counts = try await counts(db: db, ctx: ctx, businessId: businessId, days: days)
        let total = counts.reduce(Counts()) { Counts(verified: $0.verified + $1.counts.verified, notVerified: $0.notVerified + $1.counts.notVerified, pending: $0.pending + $1.counts.pending) }
        let tiles = "<div class=\"grid\">\(DashboardFormat.stat(String(total.total), "Verification requests"))\(DashboardFormat.stat(String(total.verified), "Verified"))\(DashboardFormat.stat(String(total.notVerified), "Not verified"))\(DashboardFormat.stat(String(total.pending), "Waiting for the customer"))</div>"
        let rows = counts.map { [DashboardUI.esc($0.capability.rawValue), String($0.counts.verified), String($0.counts.notVerified), String($0.counts.pending)] }
        let table = rows.isEmpty ? "<p class=\"mu sm\">No verification requests in this period.</p>" : DashboardFormat.table(["Capability", "Verified", "Not verified", "Pending"], rows, caption: "Verification requests by capability")
        return "<div class=\"card\"><h2>Verify</h2>\(tiles)\(table)<p class=\"mu sm\">Counts only. \"Not verified\" covers every way a request can end without a positive result, including a customer who declined: Viadere does not tell you why, and neither does this page.</p></div>"
    }
}
