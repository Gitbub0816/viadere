import Fluent
import Foundation
import Vapor
import ViadereCore

private struct LoopDecisionForm: Content {
    var decision: String
    var reason: String?
}
private struct LoopStatusForm: Content {
    var status: String
    var reason: String?
}
private struct LoopRolloutForm: Content {
    var percent: String
    var reason: String?
    var consumer: String?
}
private struct LoopSwitchForm: Content {
    var state: String
    var reason: String?
}

/// The Viadere Loop review queue and publication controls (plan section 4.12, WP-3.2). Operator realm only; every mutation needs a fresh
/// passkey assertion, the `loop_reviewer` permission (checked in the service against the database) and a reason, and is audited with the
/// operator as actor. Reviewers see the same presentation tree customers will see (built by `PresentationBuilder` from a preview manifest
/// signed with a throwaway key, `LoopPreview`), rendered by `LoopWebRenderer` in a sandboxed iframe, and the diff to the previously
/// published revision.
enum OperatorLoops {
    static let base = "/operator/loops"

    static func register(_ pages: any RoutesBuilder) {
        pages.get("operator", "loops") { req in try await queue(req) }
        pages.get("operator", "loops", "revisions", ":id") { req in try await revision(req) }
        pages.post("operator", "loops", "revisions", ":id", "decide") { req -> Response in
            let p = try principal(req)
            let id = try req.uuid("id")
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: "\(base)/revisions/\(id.uuidString.lowercased())") }
            let form = try req.content.decode(LoopDecisionForm.self)
            guard let decision = LoopReview.Decision(rawValue: form.decision) else { throw APIError.validation("Choose approve, request changes or reject.") }
            let updated = try await LoopPublicationService(db: req.db, ctx: req.ctx).review(revisionId: id, reviewerId: p.user.id!, decision: decision, reason: form.reason)
            return DashboardResponses.redirect("\(base)/revisions/\(id.uuidString.lowercased())?lm=\(updated.state)")
        }
        pages.get("operator", "loops", "revisions", ":id", "preview") { req -> Response in
            _ = try principal(req)
            guard let revision = try await LoopRevisionRecord.find(try req.uuid("id"), on: req.db),
                  let business = try await BusinessRecord.find(revision.businessId, on: req.db) else { throw APIError.notFound }
            guard let definition = LoopDefinition.parse(Data(revision.definitionJSON.utf8)).definition else {
                return LoopWebRenderer.response(screens: [], notice: "The definition could not be read.")
            }
            // The business's own approved kit only (scoped by the revision's business), exactly as devices resolve it.
            let brand = try await LoopPreview.brand(for: definition, businessId: revision.businessId, on: req.db)
            let screens = await LoopPreview.screens(definition: definition, business: business, brand: brand, now: req.ctx.now)
            return LoopWebRenderer.response(screens: screens, entryPoints: definition.entryPoints)
        }
        pages.get("operator", "loops", "publications", ":id") { req in try await publication(req) }
        pages.post("operator", "loops", "publications", ":id", "status") { req -> Response in
            let p = try principal(req)
            let id = try req.uuid("id")
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: "\(base)/publications/\(id.uuidString.lowercased())") }
            let form = try req.content.decode(LoopStatusForm.self)
            guard let status = LoopPublicationStatus(rawValue: form.status) else { throw APIError.validation("Choose a status.") }
            try await LoopPublicationService(db: req.db, ctx: req.ctx).setStatus(publicationId: id, to: status, operatorId: p.user.id!, reason: form.reason)
            return DashboardResponses.redirect("\(base)/publications/\(id.uuidString.lowercased())?lm=\(status.rawValue)")
        }
        pages.post("operator", "loops", "publications", ":id", "rollout") { req -> Response in
            let p = try principal(req)
            let id = try req.uuid("id")
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: "\(base)/publications/\(id.uuidString.lowercased())") }
            let form = try req.content.decode(LoopRolloutForm.self)
            let service = LoopPublicationService(db: req.db, ctx: req.ctx)
            if let raw = form.consumer, !raw.isEmpty {
                guard let consumer = UUID(uuidString: raw) else { throw APIError.validation("Enter a customer account id.") }
                try await service.allowList(publicationId: id, consumerId: consumer, operatorId: p.user.id!)
            } else {
                guard let percent = Int(form.percent) else { throw APIError.validation("Enter a percentage.") }
                try await service.setRollout(publicationId: id, percent: percent, operatorId: p.user.id!, reason: form.reason)
            }
            return DashboardResponses.redirect("\(base)/publications/\(id.uuidString.lowercased())?lm=rollout")
        }
        pages.post("operator", "loops", "businesses", ":id", "switch") { req -> Response in
            let p = try principal(req)
            let id = try req.uuid("id")
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: base) }
            let form = try req.content.decode(LoopSwitchForm.self)
            try await LoopPublicationService(db: req.db, ctx: req.ctx).setBusinessSwitch(businessId: id, on: form.state == "on", operatorId: p.user.id!, reason: form.reason)
            return DashboardResponses.redirect("\(base)?lm=switch")
        }
    }

    private static func principal(_ req: Request) throws -> DashboardPrincipal {
        let p = try req.dashboard
        guard p.realm == .operator, p.user.id != nil else { throw APIError.forbidden }
        return p
    }

    private static func flash(_ req: Request) -> String? {
        req.query[String.self, at: "lm"].map { "Done: \($0.replacingOccurrences(of: "_", with: " "))." }
    }

    // MARK: Pages

    private static let crumbs = [ConsoleUI.Crumb("Operator", "/operator"), ConsoleUI.Crumb("Loops", base)]

    private static func queue(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let reviewer = try await OperatorPermission.holds(.loopReviewer, userId: p.user.id!, on: req.db)
        let waiting = try await LoopRevisionRecord.query(on: req.db).filter(\.$state == LoopRevisionState.inReview.rawValue).sort(\.$createdAt, .ascending).limit(200).all()
        let businesses = Dictionary(try await BusinessRecord.query(on: req.db).filter(\.$id ~~ Set(waiting.map(\.businessId)).map { $0 }).all().map { ($0.id!, $0) }, uniquingKeysWith: { a, _ in a })
        var rows: [[ConsoleUI.Cell]] = []
        for revision in waiting {
            let approvals = try await LoopReviewRecord.query(on: req.db).filter(\.$revisionId == revision.id!).filter(\.$decision == "approve").count()
            let needed = revision.requiredReview == LoopReviewLevel.twoPerson.rawValue ? 2 : 1
            let name = businesses[revision.businessId]?.displayName ?? "—"
            let link = "\(base)/revisions/\(revision.id!.uuidString.lowercased())"
            rows.append([ConsoleUI.Cell(html: "<a href=\"\(link)\">\(DashboardUI.esc(name)) · rev \(revision.revision)</a>", sort: .text(name)),
                         ConsoleUI.Cell(html: DashboardFormat.badge(revision.riskClass, revision.riskClass == "high" ? "dg" : (revision.riskClass == "medium" ? "wa" : "mu")), sort: .text(revision.riskClass)),
                         ConsoleUI.Cell(html: "\(approvals)/\(needed)", sort: .number(Double(approvals))), ConsoleUI.Cell(html: revision.templateKey == nil ? "" : DashboardFormat.badge("Template", "mu")),
                         .date(revision.createdAt), ConsoleUI.Cell(html: ConsoleUI.linkButton(reviewer ? "Review" : "Open", href: link, small: true, ariaLabel: "Review \(name) revision \(revision.revision)"))])
        }
        let publications = try await LoopPublicationRecord.query(on: req.db).filter(\.$status ~~ [LoopPublicationStatus.active.rawValue, LoopPublicationStatus.suspended.rawValue])
            .sort(\.$createdAt, .descending).limit(200).all()
        var pubRows: [[ConsoleUI.Cell]] = []
        for publication in publications {
            let reports = try await LoopReportRecord.query(on: req.db).filter(\.$publicationId == publication.id!).count()
            let instances = try await LoopInstanceRecord.query(on: req.db).filter(\.$publicationId == publication.id!).count()
            let business = try await BusinessRecord.find(publication.businessId, on: req.db)
            pubRows.append([ConsoleUI.Cell(html: "<a href=\"\(base)/publications/\(publication.id!.uuidString.lowercased())\">\(DashboardUI.esc(business?.displayName ?? "—")) · rev \(publication.revision)</a>", sort: .text(business?.displayName ?? "")),
                            ConsoleUI.Cell(html: DashboardFormat.badge(publication.status, publication.status == "active" ? "ok" : "dg"), sort: .text(publication.status)),
                            ConsoleUI.Cell(html: "\(publication.rolloutPercent)%", sort: .number(Double(publication.rolloutPercent))), .number(instances),
                            ConsoleUI.Cell(html: reports > 0 ? "<strong class=\"err\">\(reports)</strong>" : "0", sort: .number(Double(reports)))])
        }
        let switches = try await LoopSwitchRecord.query(on: req.db).filter(\.$clearedAt == nil).all()
        var switchRows: [[String]] = []
        for s in switches {
            let name = try await BusinessRecord.find(s.businessId, on: req.db)?.displayName ?? "—"
            switchRows.append([DashboardUI.esc(name), DashboardUI.esc(s.reason), DashboardFormat.date(s.setAt),
                    "<form method=\"post\" action=\"\(base)/businesses/\(s.businessId.uuidString.lowercased())/switch\" class=\"row\">\(DashboardUI.csrf(p))<input type=\"hidden\" name=\"state\" value=\"off\"><label for=\"r-\(s.businessId)\" class=\"vh\">Reason</label><input id=\"r-\(s.businessId)\" name=\"reason\" type=\"text\" maxlength=\"500\" required placeholder=\"Reason\"><button class=\"btn s sm\" type=\"submit\">\(ConsoleUI.icon(.key))Resume Loops</button></form>"])
        }
        let tiles = ConsoleUI.stats([ConsoleUI.Stat(String(waiting.count), "Waiting for review", tone: waiting.isEmpty ? nil : .accent), ConsoleUI.Stat(String(publications.count), "Published"),
                                     ConsoleUI.Stat(String(switches.count), "Businesses paused", tone: switches.isEmpty ? nil : .warning)])
        let body = (reviewer ? "" : ConsoleUI.callout(.neutral, title: "Read-only for you", "<p>You can see the queue but not decide: the loop_reviewer permission is granted with <code>ViadereServer grant-operator-permission</code>.</p>"))
            + tiles
            + ConsoleUI.card("Waiting for review", description: "Oldest first. High-risk revisions need two different reviewers.",
                             ConsoleUI.table([ConsoleUI.Column("Revision", key: "rev"), ConsoleUI.Column("Risk", key: "risk"), ConsoleUI.Column("Approvals", key: "approvals", numeric: true), ConsoleUI.Column("Kind"),
                                              ConsoleUI.Column("Submitted", key: "submitted"), ConsoleUI.Column("", actions: true)], rows, caption: "Loop revisions waiting for review",
                                             state: ConsoleUI.TableState(req, id: "w", defaultSort: "submitted"), empty: "Nothing to review", emptyMessage: "Submitted revisions appear here after the automated checks pass."))
            + ConsoleUI.card("Published Loops", ConsoleUI.table([ConsoleUI.Column("Publication", key: "pub"), ConsoleUI.Column("Status", key: "status"), ConsoleUI.Column("Rollout", key: "rollout", numeric: true),
                                                                ConsoleUI.Column("Instances", key: "instances", numeric: true), ConsoleUI.Column("Reports", key: "reports", numeric: true)], pubRows,
                                                               caption: "Published Loops", state: ConsoleUI.TableState(req, id: "p"), empty: "No published Loops."))
            + ConsoleUI.card("Businesses with Loops paused", description: "To pause every Loop of a business, open one of its publications and use \"Pause all Loops of this business\".",
                             DashboardFormat.table(["Business", "Reason", "Since", ""], switchRows, empty: "None.", caption: "Per-business Loop switches"))
        return DashboardUI.operatorPage(p, title: "Loops", active: base, subtitle: "Every Loop and every revision is reviewed before publication (FX-3).", flash: flash(req), body: body)
    }

    private static func revision(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let id = try req.uuid("id")
        guard let revision = try await LoopRevisionRecord.find(id, on: req.db), let business = try await BusinessRecord.find(revision.businessId, on: req.db) else { throw APIError.notFound }
        let reviewer = try await OperatorPermission.holds(.loopReviewer, userId: p.user.id!, on: req.db)
        let reviews = try await LoopReviewRecord.query(on: req.db).filter(\.$revisionId == id).sort(\.$at, .ascending).all()
        let history = reviews.map { r -> (titleHTML: String, meta: String, bodyHTML: String) in
            let note = r.notesSealed.flatMap { try? req.ctx.cipher.openString($0, context: "loop_reviews.notes", rowId: r.id!) } ?? ""
            let tone = ["approve", "pass"].contains(r.decision) ? "ok" : (r.decision == "request_changes" ? "wa" : "dg")
            return ("\(DashboardUI.esc(r.stage.replacingOccurrences(of: "_", with: " ").capitalized)) \(DashboardFormat.badge(r.decision.replacingOccurrences(of: "_", with: " "), tone))", DashboardFormat.date(r.at), DashboardUI.esc(note))
        }
        let hits = LoopPublicationService.hits(revision.ruleHitsJSON).map { [DashboardUI.esc($0.rule.rawValue), DashboardUI.esc($0.path), $0.rule.isReviewFlag ? DashboardFormat.badge("Review flag", "wa") : DashboardFormat.badge("Hard gate", "dg")] }
        let previous = try await LoopRevisionRecord.query(on: req.db).filter(\.$definitionId == revision.definitionId)
            .filter(\.$state ~~ [LoopRevisionState.published.rawValue, LoopRevisionState.superseded.rawValue]).filter(\.$revision < revision.revision)
            .sort(\.$revision, .descending).first()
        let changes = previous.map { Self.diff(old: $0.definitionJSON, new: revision.definitionJSON) } ?? []
        let diffView = ConsoleUI.diff(before: previous.map { ConsoleUI.jsonLines($0.definitionJSON) }, after: ConsoleUI.jsonLines(revision.definitionJSON),
                                      beforeTitle: previous.map { "Published revision \($0.revision)" } ?? "", afterTitle: "This revision (\(revision.revision))")
        let changeSummary = previous == nil ? "First revision: no published revision to compare." : (changes == ["No changes."] ? "No changes." : "\(changes.filter { $0.hasPrefix("- ") }.count) line(s) removed, \(changes.filter { $0.hasPrefix("+ ") }.count) added since the published revision.")
        var checklist = """
        <ul class="sm"><li>Wording matches the intent and makes no promise the business may not keep.</li>\
        <li>Data collected is necessary; nothing health-related, no secrets, card, bank or government id data (FX-4, FX-5).</li>\
        <li>The business is not a healthcare provider and the Loop is not about health services, symptoms, treatment, prescriptions, insurance or clinician appointments.</li>\
        <li>The downstream recipient is the business shown in "Built by".</li><li>No impersonation of Viadere, a bank, a government or another business.</li></ul>
        """
        if revision.templateKey != nil { checklist = "<p>\(DashboardFormat.badge("Locked template \(revision.templateKey ?? "")", "mu")) Structure pre-checked; still review the wording.</p>" + checklist }
        let twoPerson = revision.requiredReview == LoopReviewLevel.twoPerson.rawValue
        var decide = ""
        if revision.stateValue == .inReview {
            let form = reviewer ? ConsoleUI.form("\(base)/revisions/\(id.uuidString.lowercased())/decide", csrf: DashboardUI.csrf(p),
                ConsoleUI.choices("decision", legend: "", legendHTML: "Decision for hash <code>\(DashboardUI.esc(revision.definitionHash))</code>", [
                    ConsoleUI.Choice("approve", "Approve", help: twoPerson ? "Counts as one of two approvals." : "Publishes after signing."),
                    ConsoleUI.Choice("request_changes", "Request changes", help: "The business edits and submits a new revision."),
                    ConsoleUI.Choice("reject", "Reject", help: "Ends this revision.", tone: .danger),
                ], required: true)
                + ConsoleUI.textarea("reason", label: "Reason", id: "rr", help: "Shown to the business for changes and rejections.", required: true, attrs: ["maxlength": "500"])
                + ConsoleUI.formActions(ConsoleUI.button("Record decision", passkey: true) + ConsoleUI.passkeyNote("Requires your passkey. Automated failures cannot be overridden.")))
                : ConsoleUI.callout(.neutral, "<p class=\"sm\">You need the loop_reviewer permission to decide.</p>")
            decide = ConsoleUI.card("Decision", description: twoPerson ? "High risk: a second, different reviewer must also approve." : "One approval publishes.", tone: .warning,
                                    "<h3>Check before deciding</h3>" + checklist + form)
        }
        let summary = ConsoleUI.card("Revision \(revision.revision)", actions: DashboardFormat.badge(revision.state.replacingOccurrences(of: "_", with: " "), revision.stateValue == .published ? "ok" : "wa"), ConsoleUI.keyValues([
            ("Business", "<a href=\"/operator/businesses/\(business.id!.uuidString.lowercased())\">\(DashboardUI.esc(business.displayName))</a>"), ("Category", DashboardUI.esc(business.category)),
            ("Risk", DashboardUI.esc(revision.riskClass)), ("Review", DashboardUI.esc(revision.requiredReview)), ("Rule set", String(revision.ruleSetVersion)),
        ]) + "<h3>Automated checks</h3>" + DashboardFormat.table(["Rule", "Where", "Kind"], hits, empty: "No rule hits.", caption: "Automated checks"))
        let preview = ConsoleUI.card("Preview, not exactly what customers see", description: "Rendered by the web renderer from the same presentation tree devices build, with the business's own approved Brand Kit if the Loop names one.",
                                     ConsoleUI.preview(src: "\(base)/revisions/\(id.uuidString.lowercased())/preview", title: "Preview of revision \(revision.revision), not exactly what customers see", width: 420, height: 900))
        let diffCard = ConsoleUI.card("Changes since the published revision", description: changeSummary, diffView)
        let historyCard = ConsoleUI.card("Reviews", history.isEmpty ? "<p class=\"mu\">No reviews yet.</p>" : ConsoleUI.timeline(history, label: "Review history"))
        let body = "<div class=\"split wa\"><div>\(summary)\(diffCard)\(historyCard)</div><div>\(decide)\(preview)</div></div>"
        return DashboardUI.operatorPage(p, title: "Loop review", active: base, subtitle: "\(business.displayName) · revision \(revision.revision)", flash: flash(req),
                                        breadcrumbs: crumbs + [ConsoleUI.Crumb("\(business.displayName) · rev \(revision.revision)", nil)], body: body, frames: true)
    }

    private static func publication(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let id = try req.uuid("id")
        guard let publication = try await LoopPublicationRecord.find(id, on: req.db), let business = try await BusinessRecord.find(publication.businessId, on: req.db) else { throw APIError.notFound }
        let csrf = DashboardUI.csrf(p)
        let instances = try await LoopInstanceRecord.query(on: req.db).filter(\.$publicationId == id).all()
        let events = try await LoopActionEventRecord.query(on: req.db).filter(\.$instanceId ~~ instances.compactMap(\.id)).filter(\.$delivers == true).all()
        var outcomes: [String: Int] = [:]
        let runtime = LoopRuntimeService(db: req.db, ctx: req.ctx)
        for event in events { if let o = try await runtime.currentOutcome(eventId: event.id!) { outcomes[o.outcome, default: 0] += 1 } }
        let abandoned = instances.filter { $0.stateValue == .expired }.count
        let reports = try await LoopReportRecord.query(on: req.db).filter(\.$publicationId == id).all()
        let reportRows = Dictionary(grouping: reports, by: \.reason).map { [DashboardUI.esc($0.key), String($0.value.count)] }
        let tiles = ConsoleUI.stats([ConsoleUI.Stat(String(instances.count), "Instances"), ConsoleUI.Stat(String(abandoned), "Expired unfinished")]
            + LoopActionOutcome.allCases.map { ConsoleUI.Stat(String(outcomes[$0.rawValue] ?? 0), $0.rawValue.replacingOccurrences(of: "_", with: " ")) }
            + [ConsoleUI.Stat(String(reports.count), "Reports", tone: reports.isEmpty ? nil : .danger)])
        let statusOptions: [LoopPublicationStatus] = switch publication.statusValue {
        case .active: [.suspended, .retired, .revoked]
        case .suspended: [.active, .retired, .revoked]
        default: []
        }
        let statusForm = statusOptions.isEmpty ? "" : ConsoleUI.card("Change status", tone: .danger, ConsoleUI.form("\(base)/publications/\(id.uuidString.lowercased())/status", csrf: csrf,
            ConsoleUI.select("status", label: "New status", id: "st", options: statusOptions.map { ConsoleUI.Option($0.rawValue, $0 == .active ? "Resume" : $0 == .suspended ? "Suspend (kill switch)" : $0 == .revoked ? "Revoke (cancels open instances)" : "Retire (open instances may finish)") })
            + ConsoleUI.input("reason", label: "Reason", id: "sr", help: "Recorded in the audit log.", required: true, attrs: ["maxlength": "500"])
            + ConsoleUI.formActions(ConsoleUI.button("Apply", .danger, passkey: true))))
        let pauseAll = ConsoleUI.card("Pause all Loops of this business", tone: .danger, "<form method=\"post\" action=\"\(base)/businesses/\(publication.businessId.uuidString.lowercased())/switch\">\(csrf)<input type=\"hidden\" name=\"state\" value=\"on\">"
            + ConsoleUI.input("reason", label: "Pause all Loops of this business: reason", id: "bs", help: "Every Loop of \(business.displayName) shows a neutral paused state.", required: true, attrs: ["maxlength": "500"])
            + ConsoleUI.formActions(ConsoleUI.button("Pause all", .danger, passkey: true)) + "</form>")
        let rollout = ConsoleUI.card("Rollout", description: "Currently \(publication.rolloutPercent)% plus the allow-list.", "<div class=\"cols\">"
            + ConsoleUI.form("\(base)/publications/\(id.uuidString.lowercased())/rollout", csrf: csrf,
                ConsoleUI.input("percent", label: "Percentage of connected customers", id: "pc", type: "number", value: String(publication.rolloutPercent), attrs: ["min": "0", "max": "100"])
                + ConsoleUI.input("reason", label: "Reason", id: "pr", required: true, attrs: ["maxlength": "500"])
                + ConsoleUI.formActions(ConsoleUI.button("Set rollout", .secondary, passkey: true)))
            + ConsoleUI.form("\(base)/publications/\(id.uuidString.lowercased())/rollout", csrf: csrf, ConsoleUI.hidden("percent", "0")
                + ConsoleUI.input("consumer", label: "Allow-list a customer account id", id: "ac", required: true, attrs: ["maxlength": "36", "spellcheck": "false"])
                + ConsoleUI.formActions(ConsoleUI.button("Add", .secondary, passkey: true))) + "</div>")
        let summary = ConsoleUI.card("Publication", actions: DashboardFormat.badge(publication.status, publication.status == "active" ? "ok" : "dg"), ConsoleUI.keyValues([
            ("Business", "<a href=\"/operator/businesses/\(business.id!.uuidString.lowercased())\">\(DashboardUI.esc(business.displayName))</a>"), ("Revision", String(publication.revision)),
            ("Hash", "<code>\(DashboardUI.esc(publication.definitionHash))</code>"), ("Key id", "<code>\(DashboardUI.esc(publication.kid))</code>"), ("Valid until", DashboardFormat.date(publication.notAfter)),
        ] + (publication.statusReason.map { [("Reason", DashboardUI.esc($0))] } ?? [])))
        let body = tiles + "<div class=\"split\"><div>\(summary)\(rollout)\(ConsoleUI.card("Reports", DashboardFormat.table(["Reason", "Count"], reportRows, empty: "No reports.", caption: "Customer reports by reason")))</div>"
            + "<div>\(ConsoleUI.sectionTitle("Kill switches"))\(statusForm)\(pauseAll)</div></div>"
        return DashboardUI.operatorPage(p, title: "Published Loop", active: base, subtitle: "\(business.displayName) · revision \(publication.revision)", flash: flash(req),
                                        breadcrumbs: crumbs + [ConsoleUI.Crumb("\(business.displayName) · rev \(publication.revision)", nil)], body: body)
    }

    // MARK: Diff

    /// A line diff of the pretty-printed canonical JSON (good enough to spot what changed between two small documents).
    static func diff(old: String, new: String) -> [String] {
        let a = ConsoleUI.jsonLines(old), b = ConsoleUI.jsonLines(new)
        let removed = a.filter { !b.contains($0) }.map { "- " + $0 }
        let added = b.filter { !a.contains($0) }.map { "+ " + $0 }
        return removed.isEmpty && added.isEmpty ? ["No changes."] : removed + added
    }
}
