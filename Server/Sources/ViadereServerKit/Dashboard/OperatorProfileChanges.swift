import Fluent
import Foundation
import Vapor
import ViadereCore

private struct ProfileDecisionForm: Content {
    var note: String?
}

/// Operator review of business profile changes (G20, docs/SECURITY.md §2.111): a queue, a detail page that compares what customers see now
/// with what was asked for and shows the automated checks run again live, and two-operator approval. Every decision needs a fresh passkey.
enum OperatorProfileChanges {
    static let path = "/operator/profile-changes"

    private static func principal(_ req: Request) throws -> DashboardPrincipal {
        let p = try req.dashboard
        guard p.realm == .operator else { throw APIError.forbidden }
        return p
    }

    static func register(_ pages: any RoutesBuilder) {
        pages.get("operator", "profile-changes") { req in try await queuePage(req) }
        pages.get("operator", "profile-changes", ":id") { req in try await detailPage(req) }
        pages.post("operator", "profile-changes", ":id", "approve") { req -> Response in
            let p = try principal(req)
            let id = try req.uuid("id")
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: "\(path)/\(id.uuidString.lowercased())") }
            let form = try req.content.decode(ProfileDecisionForm.self)
            let outcome = try await BusinessProfileChanges(db: req.db, ctx: req.ctx).approve(id: id, operatorId: p.user.id!, note: form.note)
            return DashboardResponses.redirect("\(path)?m=\(outcome == .applied ? "profile-applied" : "profile-first")")
        }
        pages.post("operator", "profile-changes", ":id", "reject") { req -> Response in
            let p = try principal(req)
            let id = try req.uuid("id")
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: "\(path)/\(id.uuidString.lowercased())") }
            let form = try req.content.decode(ProfileDecisionForm.self)
            try await BusinessProfileChanges(db: req.db, ctx: req.ctx).reject(id: id, operatorId: p.user.id!, note: form.note ?? "")
            return DashboardResponses.redirect("\(path)?m=profile-rejected")
        }
    }

    static func openCount(_ db: any Database) async throws -> Int {
        try await BusinessProfileChangeRecord.query(on: db).filter(\.$status ~~ BusinessProfileChangeRecord.openStatuses).count()
    }

    private static func fieldsSummary(_ c: BusinessProfileChangeRecord) -> String {
        var parts: [String] = []
        if c.displayName != nil { parts.append("Name") }
        if c.handle != nil { parts.append("Handle") }
        if c.website != nil { parts.append("Website") }
        return parts.joined(separator: ", ")
    }

    private static func queuePage(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let open = try await BusinessProfileChanges(db: req.db, ctx: req.ctx).queue()
        let names = Dictionary(try await BusinessRecord.query(on: req.db).filter(\.$id ~~ open.map(\.businessId)).all().compactMap { b in b.id.map { ($0, b.displayName) } },
                               uniquingKeysWith: { a, _ in a })
        let rows = open.map { c -> [ConsoleUI.Cell] in
            let id = c.id!.uuidString.lowercased()
            let name = names[c.businessId] ?? "—"
            let stage = c.status == "first_approved" ? ConsoleUI.pill("1 of 2 approvals", .warning) : ConsoleUI.pill("Waiting", .accent)
            let mine = c.firstReviewer == p.user.id ? " " + ConsoleUI.pill("You approved", .neutral) : ""
            return [ConsoleUI.Cell(html: "<a href=\"\(path)/\(id)\">\(DashboardUI.esc(name))</a>", sort: .text(name)), .text(fieldsSummary(c)),
                    ConsoleUI.Cell(html: stage + mine, sort: .text(c.status)), .date(c.requestedAt),
                    ConsoleUI.Cell(html: ConsoleUI.linkButton("Review", href: "\(path)/\(id)", small: true, ariaLabel: "Review the change of \(name)"))]
        }
        let body = ConsoleUI.callout(.accent, title: "Two different operators", "<p class=\"sm\">A change to a verified organization's name, handle or website goes live only after two different operators approve it. The checks run again at each approval, so a name that became too close to another organization's in the meantime is refused.</p>")
            + ConsoleUI.card("Open profile changes", description: "Oldest first.",
                ConsoleUI.table([ConsoleUI.Column("Organization", key: "org"), ConsoleUI.Column("Changes"), ConsoleUI.Column("Stage", key: "stage"),
                                 ConsoleUI.Column("Requested", key: "requested"), ConsoleUI.Column("", actions: true)], rows, caption: "Open profile changes",
                                state: ConsoleUI.TableState(req, id: "pc", defaultSort: "requested"), empty: "No profile changes waiting",
                                emptyMessage: "Verified organizations' name, handle and website changes appear here."))
        return DashboardUI.operatorPage(p, title: "Profile changes", active: path, subtitle: "Changes to verified organizations' public identity.",
                                        flash: DashboardFormat.flash(req), body: body)
    }

    private static func detailPage(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let id = try req.uuid("id")
        let service = BusinessProfileChanges(db: req.db, ctx: req.ctx)
        guard let change = try await BusinessProfileChangeRecord.find(id, on: req.db), let business = try await BusinessRecord.find(change.businessId, on: req.db) else {
            throw APIError.notFound
        }
        let proposal = BusinessProfileChanges.proposal(of: change)
        // The checks, run again now (the page shows what an approval would decide).
        let issues = change.isOpen ? try await service.vet(businessId: change.businessId, proposal) : [:]
        var rows: [[String]] = []
        func row(_ label: String, _ before: String?, _ after: String?) {
            guard let after else { return }
            let issue = issues[label == "Display name" ? "displayName" : label.lowercased()]
            rows.append([DashboardUI.esc(label), DashboardUI.esc(before ?? "none"), "<strong>\(DashboardUI.esc(after))</strong>",
                         issue.map { ConsoleUI.pill("Fails", .danger) + " <span class=\"sm\">\(DashboardUI.esc($0))</span>" } ?? ConsoleUI.pill("Passes", .success)])
        }
        row("Display name", change.previousDisplayName, change.displayName)
        row("Handle", change.previousHandle.map { "@" + $0 }, change.handle.map { "@" + $0 })
        row("Website", change.previousWebsite, change.website)
        let comparison = ConsoleUI.card("Requested change", actions: DashboardFormat.statusBadge(business.status),
            DashboardFormat.table(["Field", "Customers see now", "Requested", "Automated checks"], rows, caption: "Requested profile change")
            + ConsoleUI.keyValues([("Organization", "<a href=\"/operator/businesses/\(business.id!.uuidString.lowercased())\">\(DashboardUI.esc(business.displayName))</a>"),
                                   ("Requested", DashboardFormat.date(change.requestedAt)), ("State", DashboardUI.esc(change.status.replacingOccurrences(of: "_", with: " "))),
                                   ("First approval", change.firstReviewedAt.map { DashboardFormat.date($0) + (change.firstReviewer == p.user.id ? " (you)" : "") } ?? "—")]))
        var similar = ""
        if let name = change.displayName, change.isOpen, let match = BusinessIdentityPolicy.similar(to: name, others: try await service.others(excluding: change.businessId)) {
            similar = ConsoleUI.callout(.danger, title: "Too close to a verified organization", urgent: true,
                "<p class=\"sm\">\(DashboardUI.esc(name)) is confusable with <a href=\"/operator/businesses/\(match.businessId.uuidString.lowercased())\">\(DashboardUI.esc(match.displayName))</a>.</p>")
        }
        var decide = ""
        if change.isOpen {
            let base = "\(path)/\(id.uuidString.lowercased())"
            let secondByMe = change.status == "first_approved" && change.firstReviewer == p.user.id
            let approve = ConsoleUI.card(change.status == "pending" ? "First approval" : "Second approval",
                description: change.status == "pending" ? "Records your review. A different operator applies it." : "Applies the change at once. The old handle is retired for good.",
                secondByMe ? ConsoleUI.callout(.warning, "<p class=\"sm\">You gave the first approval. A different operator has to give the second.</p>")
                    : ConsoleUI.form("\(base)/approve", csrf: DashboardUI.csrf(p),
                        ConsoleUI.textarea("note", label: "Note", id: "pa-note", help: "Recorded with your decision.", optional: true, attrs: ["maxlength": "300"])
                        + ConsoleUI.formActions(ConsoleUI.button(change.status == "pending" ? "Approve (1 of 2)" : "Approve and apply", passkey: true, disabled: !issues.isEmpty)
                                                + ConsoleUI.passkeyNote())))
            let reject = ConsoleUI.card("Decline", description: "The organization sees your reason; customers keep the current profile.", tone: .danger,
                ConsoleUI.form("\(base)/reject", csrf: DashboardUI.csrf(p),
                    ConsoleUI.reason(id: "pr-note", name: "note", label: "Reason", help: "Shown to the organization.", multiline: true)
                    + ConsoleUI.formActions(ConsoleUI.button("Decline", .danger, passkey: true))))
            decide = ConsoleUI.sectionTitle("Decision", description: "Every decision asks for your passkey and is audited with your name.") + "<div class=\"cols\">\(approve)\(reject)</div>"
        } else if let note = change.decisionNote, !note.isEmpty {
            decide = ConsoleUI.card("Decision", ConsoleUI.keyValues([("Decided", DashboardFormat.optional(change.decidedAt)), ("Note", DashboardUI.esc(note))]))
        }
        return DashboardUI.operatorPage(p, title: business.displayName, active: path, subtitle: "Profile change", flash: DashboardFormat.flash(req),
                                        breadcrumbs: [ConsoleUI.Crumb("Operator", "/operator"), ConsoleUI.Crumb("Profile changes", path), ConsoleUI.Crumb(business.displayName, nil)],
                                        body: similar + comparison + decide)
    }
}
