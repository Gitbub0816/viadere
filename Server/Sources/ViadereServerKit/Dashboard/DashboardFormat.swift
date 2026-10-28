import Foundation
import Vapor
import ViadereCore

/// Display helpers (UTC, locale-independent).
enum DashboardFormat {
    static func date(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "d MMM yyyy, HH:mm 'UTC'"
        return formatter.string(from: date)
    }

    static func day(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "d MMM"
        return formatter.string(from: date)
    }

    static func duration(_ seconds: TimeInterval?) -> String {
        guard let seconds else { return "—" }
        let s = Int(seconds.rounded())
        if s < 60 { return "\(s) s" }
        if s < 3600 { return "\(s / 60) min \(s % 60) s" }
        return "\(s / 3600) h \((s % 3600) / 60) min"
    }

    static func percent(_ value: Double?) -> String {
        guard let value else { return "—" }
        return String(format: "%.1f%%", value * 100)
    }

    static func optional(_ date: Date?) -> String { date.map(self.date) ?? "—" }

    static let flash: [String: String] = [
        "revoked": "API key revoked.", "deleted": "Webhook deleted.", "replayed": "Delivery queued for replay.",
        "invited": "Invitation created.", "role": "Role updated.", "removed": "Member removed.", "invite-revoked": "Invitation revoked.",
        "joined": "You joined the organization.", "switched": "Switched organization.", "applied": "Application resubmitted.",
        "approved": "Business verified. Its handle and code have been issued.", "rejected": "Application declined.",
        "suspended": "Business suspended. Its API keys and interactions are blocked.", "unsuspended": "Business reinstated.",
        "ceiling": "Priority ceiling updated.", "throttle": "Throttle updated.",
        "domain-added": "Domain added. Publish the record, then check it.", "domain-verified": "Domain verified.", "domain-removed": "Domain removed.",
        "legal": "Legal entity submitted for review.", "accepted": "Agreement accepted.", "golive": "Production access requested. A Viadere reviewer will respond.",
        "rotated": "Key rotated. The old key keeps working until the overlap ends.", "pending": "Waiting for a second person to approve it.",
        "paused": "Endpoint paused.", "resumed": "Endpoint resumed.", "verified": "Endpoint verified.", "test": "Test event queued.",
        "sandbox": "Sandbox customer created.", "reply": "Simulated reply queued.", "saved": "Saved.", "session": "Session signed out.",
        "approved-change": "Approved.", "rejected-change": "Rejected.", "cancelled": "Cancelled.", "ticket": "Ticket received.", "requested": "Request received.",
        "cert": "Certificate saved.", "cert-removed": "Certificate removed.", "switch": "Switch updated.", "frozen": "Account frozen and signed out.",
        "unfrozen": "Account unfrozen.", "notice": "Notice queued for delivery.", "revoked-all": "Keys revoked.", "hold": "Legal hold recorded.",
        "root-authorized": "Root key change authorized for 15 minutes. Publish the signed entry from your tooling now.", "golive-approved": "Production access approved.", "golive-rejected": "Request declined.", "reviewed": "Review recorded.",
    ]

    static func flash(_ request: Request) -> String? { request.query[String.self, at: "m"].flatMap { flash[$0] } }

    static func badge(_ text: String, _ kind: String = "") -> String { "<span class=\"badge \(kind)\">\(DashboardUI.esc(text))</span>" }

    static func statusBadge(_ status: VerificationStatus) -> String {
        switch status {
        case .verified: badge("Verified", "ok")
        case .pending: badge("Pending", "")
        case .suspended: badge("Suspended", "dg")
        case .revoked: badge("Revoked", "dg")
        }
    }

    /// A data table. `caption` names it for screen-reader users (visually hidden); header cells carry `scope="col"`; an empty header cell (an
    /// actions column) is labelled "Actions".
    static func table(_ headers: [String], _ rows: [[String]], empty: String = "Nothing here yet.", caption: String? = nil) -> String {
        guard !rows.isEmpty else { return "<p class=\"mu\">\(DashboardUI.esc(empty))</p>" }
        let head = headers.map { $0.isEmpty ? "<th scope=\"col\"><span class=\"vh\">Actions</span></th>" : "<th scope=\"col\">\(DashboardUI.esc($0))</th>" }.joined()
        let body = rows.map { "<tr>" + $0.map { "<td>\($0)</td>" }.joined() + "</tr>" }.joined()
        let cap = caption.map { "<caption class=\"vh\">\(DashboardUI.esc($0))</caption>" } ?? ""
        return "<div class=\"tw\"><table>\(cap)<thead><tr>\(head)</tr></thead><tbody>\(body)</tbody></table></div>"
    }

    static func stat(_ value: String, _ label: String) -> String {
        "<div class=\"stat\"><div class=\"n\">\(DashboardUI.esc(value))</div><div class=\"l\">\(DashboardUI.esc(label))</div></div>"
    }

    /// Inline-SVG bar chart (no script, no external asset).
    static func barChart(_ points: [(day: Date, count: Int)], label: String) -> String {
        guard !points.isEmpty else { return "" }
        let width = 640, height = 140, top = 8, bottom = 22
        let maximum = max(1, points.map(\.count).max() ?? 1)
        let slot = Double(width) / Double(points.count)
        var bars = ""
        for (index, point) in points.enumerated() {
            let barHeight = Double(height - top - bottom) * Double(point.count) / Double(maximum)
            let x = Double(index) * slot + slot * 0.15
            let y = Double(height - bottom) - barHeight
            bars += "<rect class=\"b\" x=\"\(String(format: "%.1f", x))\" y=\"\(String(format: "%.1f", y))\" width=\"\(String(format: "%.1f", slot * 0.7))\" height=\"\(String(format: "%.1f", max(barHeight, point.count > 0 ? 1 : 0)))\" rx=\"2\"><title>\(day(point.day)): \(point.count)</title></rect>"
        }
        let first = day(points.first!.day), last = day(points.last!.day)
        return """
        <svg class="bars" viewBox="0 0 \(width) \(height)" role="img" aria-label="\(DashboardUI.esc(label))" width="100%">\
        <rect class="t" x="0" y="\(height - bottom)" width="\(width)" height="1"/>\(bars)\
        <text x="0" y="\(height - 6)">\(first)</text><text x="\(width)" y="\(height - 6)" text-anchor="end">\(last)</text></svg>
        """
    }
}

extension DashboardPrincipal {
    func require(_ permission: DashboardPermission) throws {
        guard can(permission) else { throw APIError.forbidden }
    }
}

extension Request {
    /// Business principal with an active organization.
    var businessDashboard: (principal: DashboardPrincipal, businessId: UUID) {
        get throws {
            let p = try dashboard
            guard p.realm == .business, let id = p.business?.id else { throw APIError.forbidden }
            return (p, id)
        }
    }

    func uuid(_ name: String) throws -> UUID {
        guard let raw = parameters.get(name), let id = UUID(uuidString: raw) else { throw APIError.notFound }
        return id
    }
}
