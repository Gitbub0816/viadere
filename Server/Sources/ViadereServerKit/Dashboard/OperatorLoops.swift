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
/// signed with a throwaway key) and the diff to the previously published revision.
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

    private static func queue(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let reviewer = try await OperatorPermission.holds(.loopReviewer, userId: p.user.id!, on: req.db)
        let waiting = try await LoopRevisionRecord.query(on: req.db).filter(\.$state == LoopRevisionState.inReview.rawValue).sort(\.$createdAt, .ascending).limit(200).all()
        let businesses = Dictionary(try await BusinessRecord.query(on: req.db).filter(\.$id ~~ Set(waiting.map(\.businessId)).map { $0 }).all().map { ($0.id!, $0) }, uniquingKeysWith: { a, _ in a })
        var rows: [[String]] = []
        for revision in waiting {
            let approvals = try await LoopReviewRecord.query(on: req.db).filter(\.$revisionId == revision.id!).filter(\.$decision == "approve").count()
            let needed = revision.requiredReview == LoopReviewLevel.twoPerson.rawValue ? 2 : 1
            rows.append(["<a href=\"\(base)/revisions/\(revision.id!.uuidString.lowercased())\">\(DashboardUI.esc(businesses[revision.businessId]?.displayName ?? "—")) · rev \(revision.revision)</a>",
                         DashboardUI.esc(revision.riskClass), "\(approvals)/\(needed)", revision.templateKey == nil ? "" : DashboardFormat.badge("Template", "mu"),
                         DashboardFormat.date(revision.createdAt)])
        }
        let publications = try await LoopPublicationRecord.query(on: req.db).filter(\.$status ~~ [LoopPublicationStatus.active.rawValue, LoopPublicationStatus.suspended.rawValue])
            .sort(\.$createdAt, .descending).limit(200).all()
        var pubRows: [[String]] = []
        for publication in publications {
            let reports = try await LoopReportRecord.query(on: req.db).filter(\.$publicationId == publication.id!).count()
            let instances = try await LoopInstanceRecord.query(on: req.db).filter(\.$publicationId == publication.id!).count()
            let business = try await BusinessRecord.find(publication.businessId, on: req.db)
            pubRows.append(["<a href=\"\(base)/publications/\(publication.id!.uuidString.lowercased())\">\(DashboardUI.esc(business?.displayName ?? "—")) · rev \(publication.revision)</a>",
                            DashboardUI.esc(publication.status), "\(publication.rolloutPercent)%", String(instances), String(reports)])
        }
        let switches = try await LoopSwitchRecord.query(on: req.db).filter(\.$clearedAt == nil).all()
        var switchRows: [[String]] = []
        for s in switches {
            let name = try await BusinessRecord.find(s.businessId, on: req.db)?.displayName ?? "—"
            switchRows.append([DashboardUI.esc(name), DashboardUI.esc(s.reason), DashboardFormat.date(s.setAt),
                    "<form method=\"post\" action=\"\(base)/businesses/\(s.businessId.uuidString.lowercased())/switch\">\(DashboardUI.csrf(p))<input type=\"hidden\" name=\"state\" value=\"off\"><label for=\"r-\(s.businessId)\" class=\"vh\">Reason</label><input id=\"r-\(s.businessId)\" name=\"reason\" type=\"text\" maxlength=\"500\" required placeholder=\"Reason\"><button class=\"btn s sm\" type=\"submit\">Resume Loops</button></form>"])
        }
        let body = """
        \(reviewer ? "" : "<div class=\"notice\" role=\"status\">You can see the queue but not decide: the loop_reviewer permission is granted with <code>ViadereServer grant-operator-permission</code>.</div>")\
        <div class="card"><h2>Waiting for review</h2>\(DashboardFormat.table(["Revision", "Risk", "Approvals", "", "Submitted"], rows, empty: "Nothing to review.", caption: "Loop revisions waiting for review"))</div>\
        <div class="card"><h2>Published Loops</h2>\(DashboardFormat.table(["Publication", "Status", "Rollout", "Instances", "Reports"], pubRows, empty: "No published Loops.", caption: "Published Loops"))</div>\
        <div class="card"><h2>Businesses with Loops paused</h2>\(DashboardFormat.table(["Business", "Reason", "Since", ""], switchRows, empty: "None.", caption: "Per-business Loop switches"))\
        <p class="mu sm">To pause every Loop of a business, open its publication and use "Pause all Loops of this business".</p></div>
        """
        return DashboardUI.operatorPage(p, title: "Loops", active: base, subtitle: "Every Loop and every revision is reviewed before publication (FX-3).", flash: flash(req), body: body)
    }

    private static func revision(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let id = try req.uuid("id")
        guard let revision = try await LoopRevisionRecord.find(id, on: req.db), let business = try await BusinessRecord.find(revision.businessId, on: req.db) else { throw APIError.notFound }
        let reviews = try await LoopReviewRecord.query(on: req.db).filter(\.$revisionId == id).sort(\.$at, .ascending).all()
        let reviewRows = reviews.map { r -> [String] in
            let note = r.notesSealed.flatMap { try? req.ctx.cipher.openString($0, context: "loop_reviews.notes", rowId: r.id!) } ?? ""
            return [DashboardUI.esc(r.stage), DashboardUI.esc(r.decision), DashboardUI.esc(note), DashboardFormat.date(r.at)]
        }
        let hits = LoopPublicationService.hits(revision.ruleHitsJSON).map { [DashboardUI.esc($0.rule.rawValue), DashboardUI.esc($0.path), $0.rule.isReviewFlag ? "Review flag" : "Hard gate"] }
        let previous = try await LoopRevisionRecord.query(on: req.db).filter(\.$definitionId == revision.definitionId)
            .filter(\.$state ~~ [LoopRevisionState.published.rawValue, LoopRevisionState.superseded.rawValue]).filter(\.$revision < revision.revision)
            .sort(\.$revision, .descending).first()
        let diff = previous.map { Self.diff(old: $0.definitionJSON, new: revision.definitionJSON) } ?? ["First revision: no published revision to compare."]
        let preview = await Self.preview(revision: revision, business: business)
        var checklist = """
        <ul class="plain sm"><li>Wording matches the intent and makes no promise the business may not keep.</li>\
        <li>Data collected is necessary; nothing health-related, no secrets, card, bank or government id data (FX-4, FX-5).</li>\
        <li>The business is not a healthcare provider and the Loop is not about health services, symptoms, treatment, prescriptions, insurance or clinician appointments.</li>\
        <li>The downstream recipient is the business shown in "Built by".</li><li>No impersonation of Viadere, a bank, a government or another business.</li></ul>
        """
        if revision.templateKey != nil { checklist = "<p class=\"badge mu\">Locked template \(DashboardUI.esc(revision.templateKey ?? "")): structure pre-checked; still review the wording.</p>" + checklist }
        let decide = revision.stateValue == .inReview ? """
        <div class="card"><h2>Decision</h2>\(checklist)<form method="post" action="\(base)/revisions/\(id.uuidString.lowercased())/decide">\(DashboardUI.csrf(p))\
        <fieldset><legend>Decision for hash <code>\(DashboardUI.esc(revision.definitionHash))</code></legend>\
        <label class="ck"><input type="radio" name="decision" value="approve" required> Approve</label>\
        <label class="ck"><input type="radio" name="decision" value="request_changes"> Request changes</label>\
        <label class="ck"><input type="radio" name="decision" value="reject"> Reject</label></fieldset>\
        <label for="rr">Reason (shown to the business for changes and rejections)</label><textarea id="rr" name="reason" maxlength="500" required></textarea>\
        <p class="mu sm">Requires your passkey. \(revision.requiredReview == LoopReviewLevel.twoPerson.rawValue ? "High risk: a second, different reviewer must also approve." : "One approval publishes.") Automated failures cannot be overridden.</p>\
        <button class="btn" type="submit">Record decision</button></form></div>
        """ : ""
        let body = """
        <div class="card"><h2>\(DashboardUI.esc(business.displayName)) · revision \(revision.revision) <span class="badge">\(DashboardUI.esc(revision.state))</span></h2>\
        <p class="sm">Category \(DashboardUI.esc(business.category)) · risk \(DashboardUI.esc(revision.riskClass)) · review \(DashboardUI.esc(revision.requiredReview)) · rule set \(revision.ruleSetVersion)</p>\
        \(DashboardFormat.table(["Rule", "Where", "Kind"], hits, empty: "No rule hits.", caption: "Automated checks"))</div>\
        <div class="card"><h2>Preview, not exactly what customers see</h2>\(preview)</div>\
        <div class="card"><h2>Changes since the published revision</h2><pre class="sm">\(DashboardUI.esc(diff.joined(separator: "\n")))</pre></div>\
        <div class="card"><h2>Reviews</h2>\(DashboardFormat.table(["Stage", "Decision", "Reason", "When"], reviewRows, caption: "Review history"))</div>\(decide)
        """
        return DashboardUI.operatorPage(p, title: "Loop review", active: base, flash: flash(req), body: body)
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
        let tiles = """
        <div class="grid">\(DashboardFormat.stat(String(instances.count), "Instances"))\(DashboardFormat.stat(String(abandoned), "Expired unfinished"))\
        \(LoopActionOutcome.allCases.map { DashboardFormat.stat(String(outcomes[$0.rawValue] ?? 0), $0.rawValue.replacingOccurrences(of: "_", with: " ")) }.joined())\
        \(DashboardFormat.stat(String(reports.count), "Reports"))</div>
        """
        let statusOptions: [LoopPublicationStatus] = switch publication.statusValue {
        case .active: [.suspended, .retired, .revoked]
        case .suspended: [.active, .retired, .revoked]
        default: []
        }
        let statusForm = statusOptions.isEmpty ? "" : """
        <form method="post" action="\(base)/publications/\(id.uuidString.lowercased())/status">\(csrf)<label for="st">Change status</label><select id="st" name="status">\
        \(statusOptions.map { "<option value=\"\($0.rawValue)\">\($0 == .active ? "Resume" : $0 == .suspended ? "Suspend (kill switch)" : $0 == .revoked ? "Revoke (cancels open instances)" : "Retire (open instances may finish)")</option>" }.joined())</select>\
        <label for="sr">Reason</label><input id="sr" name="reason" type="text" maxlength="500" required><button class="btn d" type="submit">Apply</button></form>
        """
        let body = """
        <div class="card"><h2>\(DashboardUI.esc(business.displayName)) · revision \(publication.revision) <span class="badge">\(DashboardUI.esc(publication.status))</span></h2>\
        <p class="sm">Hash <code>\(DashboardUI.esc(publication.definitionHash))</code> · kid <code>\(DashboardUI.esc(publication.kid))</code> · valid until \(DashboardFormat.date(publication.notAfter))\
        \(publication.statusReason.map { " · reason: \(DashboardUI.esc($0))" } ?? "")</p>\(tiles)</div>\
        <div class="card"><h2>Kill switches</h2><div class="cols">\(statusForm)\
        <form method="post" action="\(base)/businesses/\(publication.businessId.uuidString.lowercased())/switch">\(csrf)<input type="hidden" name="state" value="on">\
        <label for="bs">Pause all Loops of this business: reason</label><input id="bs" name="reason" type="text" maxlength="500" required><button class="btn d" type="submit">Pause all</button></form></div></div>\
        <div class="card"><h2>Rollout</h2><p class="sm">Currently \(publication.rolloutPercent)% plus the allow-list.</p><div class="cols">\
        <form method="post" action="\(base)/publications/\(id.uuidString.lowercased())/rollout">\(csrf)<label for="pc">Percentage of connected customers</label><input id="pc" name="percent" type="number" min="0" max="100" value="\(publication.rolloutPercent)">\
        <label for="pr">Reason</label><input id="pr" name="reason" type="text" maxlength="500" required><button class="btn s" type="submit">Set rollout</button></form>\
        <form method="post" action="\(base)/publications/\(id.uuidString.lowercased())/rollout">\(csrf)<input type="hidden" name="percent" value="0"><label for="ac">Allow-list a customer account id</label><input id="ac" name="consumer" type="text" maxlength="36" required><button class="btn s" type="submit">Add</button></form></div></div>\
        <div class="card"><h2>Reports</h2>\(DashboardFormat.table(["Reason", "Count"], reportRows, empty: "No reports.", caption: "Customer reports by reason"))</div>
        """
        return DashboardUI.operatorPage(p, title: "Published Loop", active: base, flash: flash(req), body: body)
    }

    // MARK: Preview and diff

    /// The tree customers would see for each step, from a preview manifest signed by a throwaway key that no device pins.
    static func preview(revision: LoopRevisionRecord, business: BusinessRecord) async -> String {
        guard let definition = LoopDefinition.parse(Data(revision.definitionJSON.utf8)).definition else { return "<p class=\"mu\">The definition could not be read.</p>" }
        let key = SoftwareP256SigningKey()
        guard let kid = try? KeyIdentifier.make(key.publicKey.signingKey()) else { return "" }
        let now = Date()
        let from = Int64(now.timeIntervalSince1970)
        let manifest = LoopPublicationManifest(publisherType: .business, publisherBusinessId: BusinessID(business.id!), publishedDefinitionId: LoopPublicationID(UUID()),
                                               revision: Int64(revision.revision), definitionHash: revision.definitionHash, validFrom: from, notAfter: from + 3600, kid: kid)
        guard let compact = try? await manifest.sign(with: key) else { return "" }
        let record = VerifiedBusinessRecord(id: BusinessID(business.id!), displayName: business.displayName, verificationStatus: business.status,
                                            category: BusinessCategory(rawValue: business.category))
        let context = LoopPresentationContext(manifest: compact, pinnedKeys: [PinnedManifestKey(kid: kid, publicKey: key.publicKey)], definition: definition,
                                              instanceBusinessId: BusinessID(business.id!), publisher: record, now: now)
        var html = ""
        for step in definition.steps {
            let tree = PresentationBuilder.build(context, phase: .step(step.id, outcome: step.type == .result ? .pending : nil))
            html += "<section aria-label=\"Step \(DashboardUI.esc(step.id))\" class=\"card\"><h3>Step \(DashboardUI.esc(step.id))</h3>\(render(tree.root))</section>"
            for action in step.actions {
                guard case .registered(let definition) = LoopActionRegistry.v1.resolve(action.action), definition.confirmation != nil else { continue }
                let confirm = PresentationBuilder.build(context, phase: .confirm(stepId: step.id, actionId: action.id))
                html += "<section aria-label=\"Confirmation \(DashboardUI.esc(action.id))\" class=\"card\"><h3>Confirmation for \(DashboardUI.esc(action.id))</h3>\(render(confirm.root))</section>"
            }
        }
        return html
    }

    static func render(_ node: PresentationNode) -> String {
        switch node {
        case .screen(let s): return "<div><p><strong>\(DashboardUI.esc(s.title))</strong></p>\(s.children.map(render).joined())</div>"
        case .header(let h): return "<h4>\(DashboardUI.esc(h.text))</h4>"
        case .attributionBar(let a): return "<p class=\"badge ok\">\(DashboardUI.esc(a.text))</p>"
        case .text(let t): return "<p>\(DashboardUI.esc(t.text))</p>"
        case .fieldGroup(let g): return "<div>\(g.children.map(render).joined())</div>"
        case .choice(let c): return "<p>\(DashboardUI.esc(c.label)): \(c.options.map { DashboardUI.esc($0.label) }.joined(separator: " / "))</p>"
        case .input(let i): return "<p>\(DashboardUI.esc(i.label)) [\(DashboardUI.esc(i.input))]</p>"
        case .actionBar(let b): return "<p>\(b.actions.map { "<span class=\"badge\">\(DashboardUI.esc($0.label))</span>" }.joined(separator: " "))</p>"
        case .confirmationPanel(let c): return "<p><strong>\(DashboardUI.esc(c.title))</strong> \(DashboardUI.esc(c.statement)) \(DashboardUI.esc(c.effect))</p>"
        case .outcomeStatus(let o): return "<p class=\"mu\">\(DashboardUI.esc(o.text))</p>"
        case .moduleSlot: return ""
        case .notice(let n): return "<p class=\"notice\">\(DashboardUI.esc(n.text))</p>"
        }
    }

    /// A line diff of the pretty-printed canonical JSON (good enough to spot what changed between two small documents).
    static func diff(old: String, new: String) -> [String] {
        func lines(_ json: String) -> [String] {
            guard let object = try? JSONSerialization.jsonObject(with: Data(json.utf8)),
                  let pretty = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]) else { return [json] }
            return String(decoding: pretty, as: UTF8.self).split(separator: "\n").map(String.init)
        }
        let a = lines(old), b = lines(new)
        let removed = a.filter { !b.contains($0) }.map { "- " + $0 }
        let added = b.filter { !a.contains($0) }.map { "+ " + $0 }
        return removed.isEmpty && added.isEmpty ? ["No changes."] : removed + added
    }
}
