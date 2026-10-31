import Fluent
import Foundation
import Vapor
import ViadereCore

/// Loop Studio v1 (WP-3.7; spec A, plan 4.3, 4.12, 5.3; SECURITY.md §2.99). Server-rendered like the rest of the console, with **no script**:
/// every edit is a form round trip (one form, several submit buttons), so the Studio is fully keyboard operable and keeps the console's CSP.
///
/// * Templates are locked starting definitions from Core (`LoopTemplateCatalog`); a business edits a draft copy.
/// * The editor is form-based over the closed schema: field types from the allowlist, actions from the registry, button labels from each
///   action's allowed set, next steps from the draft's own steps, Brand Kits from the business's own approved kits. There is no free schema
///   (JSON) editing, no AI and no publish button.
/// * Every save re-runs `LoopPolicyValidator` with the pipeline's own context and shows the report; "Submit for Viadere review" creates a
///   revision through `LoopPublicationService.submit` (hard gate, human review, signing). The status tracker shows the four stages.
/// * The preview is rendered by `LoopWebRenderer` into a sandboxed iframe with its own CSP (no script at all).
///
/// Permissions: `viewLoops` reads (drafts, report, preview, tracker); `submitLoops` edits and submits. The tenant is always the session's.
enum ConsoleLoopStudio {
    static let path = "/dashboard/loops/studio"

    static let flash: [String: String] = [
        "created": "Draft created from the template. Edit it, check the report, then submit it for Viadere review.",
        "saved": "Draft saved.",
        "submitted": "Submitted for Viadere review. Customers see nothing until Viadere approves and signs this revision.",
        "failed": "The automated checks failed on submission. Fix the problems and submit again.",
        "deleted": "Draft deleted.",
    ]

    // MARK: Routes

    static func register(_ pages: any RoutesBuilder) {
        pages.get("dashboard", "loops", "studio") { req in try await gallery(req) }
        pages.post("dashboard", "loops", "studio", "drafts") { req -> Response in
            let (_, businessId, userId) = try editor(req)
            let form = try req.content.decode([String: String].self)
            let draft = try await LoopStudioService(db: req.db, ctx: req.ctx).create(businessId: businessId, authorId: userId, templateKey: form["template"] ?? "")
            return DashboardResponses.redirect("\(path)/drafts/\(draft.id!.uuidString.lowercased())?sm=created")
        }
        pages.get("dashboard", "loops", "studio", "drafts", ":id") { req in try await draftPage(req) }
        pages.post("dashboard", "loops", "studio", "drafts", ":id") { req -> Response in
            let (_, businessId, userId) = try editor(req)
            let id = try req.uuid("id")
            let form = try req.content.decode([String: String].self)
            let service = LoopStudioService(db: req.db, ctx: req.ctx)
            _ = try await service.authoringBusiness(businessId)
            let record = try await service.draft(businessId: businessId, id: id)
            guard let base = LoopStudioService.definition(record) else { throw APIError.validation("This draft could not be read.") }
            guard let version = form["version"].flatMap(Int.init) else { throw APIError.validation("Reload the draft and try again.") }
            let kits = try await LoopPublicationService.approvedBrandKitKeys(businessId: businessId, on: req.db)
            var definition = try LoopStudioForm.apply(form, to: base, approvedKits: kits)
            let anchor = try LoopStudioForm.perform(form["op"] ?? "save", form: form, on: &definition)
            try await service.save(businessId: businessId, id: id, expectedVersion: version, definition: definition, authorId: userId)
            return DashboardResponses.redirect("\(path)/drafts/\(id.uuidString.lowercased())?sm=saved\(anchor.map { "#\($0)" } ?? "")")
        }
        pages.post("dashboard", "loops", "studio", "drafts", ":id", "submit") { req -> Response in
            let (_, businessId, userId) = try editor(req)
            let id = try req.uuid("id")
            let form = try req.content.decode([String: String].self)
            guard let version = form["version"].flatMap(Int.init) else { throw APIError.validation("Reload the draft and try again.") }
            let revision = try await LoopStudioService(db: req.db, ctx: req.ctx).submit(businessId: businessId, id: id, expectedVersion: version, authorId: userId)
            return DashboardResponses.redirect("\(path)/drafts/\(id.uuidString.lowercased())?sm=\(revision.stateValue == .inReview ? "submitted" : "failed")#status")
        }
        pages.post("dashboard", "loops", "studio", "drafts", ":id", "delete") { req -> Response in
            let (_, businessId, userId) = try editor(req)
            try await LoopStudioService(db: req.db, ctx: req.ctx).delete(businessId: businessId, id: try req.uuid("id"), authorId: userId)
            return DashboardResponses.redirect("\(path)?sm=deleted")
        }
        pages.get("dashboard", "loops", "studio", "drafts", ":id", "preview") { req -> Response in
            let (p, businessId) = try req.businessDashboard
            guard canView(p) else { throw APIError.forbidden }
            let service = LoopStudioService(db: req.db, ctx: req.ctx)
            let record = try await service.draft(businessId: businessId, id: try req.uuid("id"))
            guard let business = try await BusinessRecord.find(businessId, on: req.db), let definition = LoopStudioService.definition(record) else { throw APIError.notFound }
            return try await previewResponse(definition: definition, business: business, report: try await service.report(definition, business: business), now: req.ctx.now, db: req.db)
        }
    }

    // MARK: Access

    static func canView(_ p: DashboardPrincipal) -> Bool { p.can(.viewLoops) || p.can(.submitLoops) }

    /// Edits and submissions: `submitLoops` (CSRF is checked by the page middleware). Business roles never publish (FX-3).
    static func editor(_ req: Request) throws -> (DashboardPrincipal, UUID, UUID) {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.submitLoops), let userId = p.user.id else { throw APIError.forbidden }
        return (p, businessId, userId)
    }

    // MARK: Preview

    /// The sandboxed preview document. While the automated checks fail it shows a notice instead of screens (the builder refuses to render a
    /// definition that fails the hard gate, exactly as a device would).
    static func previewResponse(definition: LoopDefinition, business: BusinessRecord, report: LoopValidationReport, now: Date, db: any Database) async throws -> Response {
        guard report.gate.passed else {
            return LoopWebRenderer.response(screens: [], notice: "The preview appears when the automated checks pass. Fix the problems listed in the validation report.")
        }
        let brand = try await LoopPreview.brand(for: definition, businessId: business.id!, on: db)
        let screens = await LoopPreview.screens(definition: definition, business: business, brand: brand, now: now)
        return LoopWebRenderer.response(screens: screens, entryPoints: definition.entryPoints)
    }

    // MARK: Gallery

    static func gallery(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard canView(p) else { throw APIError.forbidden }
        guard let business = try await BusinessRecord.find(businessId, on: req.db) else { throw APIError.notFound }
        let flashText = req.query[String.self, at: "sm"].flatMap { flash[$0] }
        if let refusal = LoopStudioService.refusal(business) {
            return DashboardUI.businessPage(p, title: "Loop Studio", active: path, body: "<div class=\"notice dg\" role=\"status\">\(DashboardUI.esc(refusal))</div>")
        }
        let canEdit = p.can(.submitLoops)
        let csrf = DashboardUI.csrf(p)
        let drafts = try await LoopStudioService(db: req.db, ctx: req.ctx).drafts(businessId: businessId)
        var body = """
        <div class="card"><h2>How Loop Studio works</h2><p class="sm">Start from a template, adjust the wording, fields and buttons, and check the preview. \
        When the automated checks pass, submit the Loop for Viadere review: a Viadere reviewer (two for high-risk actions) approves it before it is \
        signed and customers can see it. You can't publish a Loop yourself, and every change is a new revision that is reviewed again.</p>\
        <p class="mu sm">Loops can't collect health information, passwords, card or bank details or government ids, and can't link anywhere.</p></div>
        """
        let templates = LoopTemplateCatalog.v1.map { template -> String in
            let steps = template.definition.steps.count
            let start = canEdit ? """
            <form method="post" action="\(path)/drafts">\(csrf)<input type="hidden" name="template" value="\(DashboardUI.esc(template.key))">\
            <button class="btn s sm" type="submit" aria-label="Start a draft from the \(DashboardUI.esc(template.name)) template">Start from this template</button></form>
            """ : ""
            return "<li><div><strong>\(DashboardUI.esc(template.name))</strong><p class=\"sm\">\(DashboardUI.esc(template.summary))</p><p class=\"mu sm\">\(steps) steps</p>\(start)</div></li>"
        }.joined()
        body += "<div class=\"card\"><h2>Templates</h2><ul class=\"steps\" aria-label=\"Templates\">\(templates)</ul></div>"
        var rows: [[String]] = []
        for draft in drafts {
            let definition = LoopStudioService.definition(draft)
            let latest = try await LoopStudioService(db: req.db, ctx: req.ctx).revisions(businessId: businessId, loopKey: draft.loopKey, limit: 1).first
            rows.append(["<a href=\"\(path)/drafts/\(draft.id!.uuidString.lowercased())\">\(DashboardUI.esc(definition?.title.isEmpty == false ? definition!.title : draft.loopKey))</a>",
                         "<code>\(DashboardUI.esc(draft.loopKey))</code>", DashboardUI.esc(draft.templateKey.flatMap { LoopTemplateCatalog.template($0)?.name } ?? "—"),
                         latest.map { "Revision \($0.revision): \(stateLabel($0.stateValue))" }.map(DashboardUI.esc) ?? "Not submitted", DashboardFormat.date(draft.updatedAt)])
        }
        body += "<div class=\"card\"><h2>Drafts</h2>\(DashboardFormat.table(["Loop", "Identifier", "Template", "Review", "Last saved"], rows, empty: "No drafts yet.", caption: "Loop drafts"))</div>"
        return DashboardUI.businessPage(p, title: "Loop Studio", active: path, subtitle: "Build a Loop from a template and send it to Viadere for review.",
                                        flash: flashText, body: body)
    }

    // MARK: Editor page

    static func draftPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard canView(p) else { throw APIError.forbidden }
        let service = LoopStudioService(db: req.db, ctx: req.ctx)
        let record = try await service.draft(businessId: businessId, id: try req.uuid("id"))
        guard let business = try await BusinessRecord.find(businessId, on: req.db) else { throw APIError.notFound }
        guard let definition = LoopStudioService.definition(record) else { throw APIError.validation("This draft could not be read.") }
        let refusal = LoopStudioService.refusal(business)
        let canEdit = p.can(.submitLoops) && refusal == nil && business.status != .suspended
        let report = try await service.report(definition, business: business)
        let kits = try await BrandKitRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$approvedJSON != nil).sort(\.$name, .ascending).all()
        let revisions = try await service.revisions(businessId: businessId, loopKey: record.loopKey)
        let id = record.id!.uuidString.lowercased()
        let draftPath = "\(path)/drafts/\(id)"
        var body = ""
        if let refusal { body += "<div class=\"notice dg\" role=\"status\">\(DashboardUI.esc(refusal))</div>" }
        if !p.can(.submitLoops) { body += "<div class=\"notice\" role=\"status\">You can read this draft. Editing and submitting need a role with the submitLoops permission.</div>" }
        let template = LoopTemplateCatalog.matching(definition, startedFrom: record.templateKey)
        body += "<p class=\"sm\">Loop <code>\(DashboardUI.esc(record.loopKey))</code> · draft version \(record.version)"
            + (record.templateKey.flatMap { LoopTemplateCatalog.template($0)?.name }.map { " · started from \(DashboardUI.esc($0))" } ?? "")
            + (template != nil ? " · " + DashboardFormat.badge("Template structure", "mu") : "") + "</p>"
        body += reportCard(report)
        body += "<div class=\"cols\"><div>\(editorForm(definition, record: record, kits: kits, canEdit: canEdit, csrf: DashboardUI.csrf(p), action: draftPath))</div>"
        body += """
        <div><div class="card"><h2 id="preview">Preview</h2><p class="mu sm">\(DashboardUI.esc(LoopWebRenderer.previewLabel)). It updates when you save.</p>\
        <iframe title="Preview of \(DashboardUI.esc(definition.title)), not exactly what customers see" src="\(draftPath)/preview?v=\(record.version)" sandbox="" \
        referrerpolicy="no-referrer" width="380" height="860" loading="lazy"></iframe></div></div></div>
        """
        body += submitCard(report: report, record: record, canEdit: canEdit, csrf: DashboardUI.csrf(p), action: draftPath)
        body += try await tracker(req, revisions: revisions, p: p)
        if canEdit {
            body += """
            <div class="card"><h2>Delete draft</h2><p class="mu sm">Deleting the draft does not withdraw or unpublish submitted revisions.</p>\
            <form method="post" action="\(draftPath)/delete">\(DashboardUI.csrf(p))<button class="btn d sm" type="submit">Delete draft</button></form></div>
            """
        }
        let flashText = req.query[String.self, at: "sm"].flatMap { flash[$0] }
        return DashboardUI.businessPage(p, title: definition.title.isEmpty ? "Loop draft" : "Loop: \(definition.title)", active: path,
                                        subtitle: "Loop Studio draft", flash: flashText, body: body, frames: true)
    }

    // MARK: Validation report

    static func reportCard(_ report: LoopValidationReport) -> String {
        let hard = report.hardGateHits
        let flags = report.reviewFlags
        var html = "<div class=\"card\" id=\"report\"><h2>Automated checks</h2>"
        if report.gate.passed {
            html += "<p role=\"status\">\(DashboardFormat.badge("Ready to submit", "ok")) All automated checks pass.</p>"
        } else {
            html += "<p role=\"status\">\(DashboardFormat.badge("\(hard.count) problem\(hard.count == 1 ? "" : "s") to fix", "dg")) Customers never see a Loop that fails these checks, and Viadere can't override them.</p>"
            html += "<ul>" + hard.map { "<li><strong>\(DashboardUI.esc(location($0.path)))</strong>: \(DashboardUI.esc(message($0)))</li>" }.joined() + "</ul>"
        }
        if !flags.isEmpty {
            html += "<p class=\"sm\">Needs a second Viadere reviewer:</p><ul class=\"sm\">"
                + flags.map { "<li><strong>\(DashboardUI.esc(location($0.path)))</strong>: \(DashboardUI.esc(message($0)))</li>" }.joined() + "</ul>"
        }
        html += "<p class=\"mu sm\">Risk: \(DashboardUI.esc(report.derivedRiskClass.rawValue)) · review by \(report.requiredReview == .twoPerson ? "two Viadere reviewers" : "one Viadere reviewer") · rule set \(report.ruleSetVersion)</p></div>"
        return html
    }

    /// "steps[1].actions[0].label" → "Step 2 › Button 1 › label".
    static func location(_ path: String) -> String {
        guard !path.isEmpty else { return "Loop" }
        let names = ["steps": "Step", "fields": "Field", "options": "Option", "actions": "Button"]
        let parts = path.split(separator: ".").map { part -> String in
            let s = String(part)
            if let open = s.firstIndex(of: "["), s.hasSuffix("]"), let index = Int(s[s.index(after: open)..<s.index(before: s.endIndex)]) {
                return "\(names[String(s[..<open])] ?? String(s[..<open])) \(index + 1)"
            }
            return s.replacingOccurrences(of: "_", with: " ")
        }
        return parts.joined(separator: " › ")
    }

    static func message(_ hit: LoopRuleHit) -> String {
        switch hit.rule {
        case .emptyText: "Enter some text."
        case .textTooLong: "This text is too long."
        case .disallowedCharacters: "Remove invisible or control characters."
        case .impersonation: "Text can't mention Viadere or look like it."
        case .healthContent: "Loops can't be about health, medical care or health information."
        case .sensitiveDataRequest: "Loops can't ask for passwords, codes, card or bank details or government ids."
        case .attributionSpoofing: "Text can't claim who built, verified or secured the Loop. Viadere shows that itself."
        case .linkNotAllowed: "Links, web addresses and e-mail addresses aren't allowed."
        case .healthAdjacentContent: "This wording is close to health topics."
        case .authorityClaim: "This wording mentions a government, a bank or an official notice."
        case .highRiskAction: "This button carries an amount, so two reviewers check it."
        case .unknownBrandKit: "Choose one of your approved Brand Kits."
        case .noSteps: "Add a step."
        case .tooManySteps: "A Loop has at most \(LoopLimits.maxSteps) steps."
        case .noFields: "Add at least one field to this form step."
        case .tooManyFields: "A step has at most \(LoopLimits.maxFieldsPerStep) fields."
        case .tooManyActions: "A step has at most \(LoopLimits.maxActionsPerStep) buttons."
        case .invalidOptions: "Give this field \(LoopLimits.minOptions) to \(LoopLimits.maxOptions) options."
        case .invalidLimit: "Choose an expiry between 1 hour and 30 days."
        case .labelNotAllowed: "Choose a button label from the list."
        case .customLabelNotAllowed: "This button can't have custom text."
        case .missingParameter: "Fill in this value."
        case .invalidParameter, .invalidValue: "Check this value."
        case .missingNext: "Choose the step this button leads to."
        case .unknownNextStep: "This button leads to a step that no longer exists."
        case .cycle: "Buttons can't lead back to an earlier step."
        case .unreachableStep: "No button leads to this step."
        case .noTerminalStep: "Add a result step to end the Loop."
        case .entryIsTerminal: "The first step can't be a result step."
        case .deadEnd: "Add a button to this step."
        case .missingEntryPoint: "Choose at least one place customers can open the Loop from."
        case .missingConfirmation: "This action needs a confirmation."
        case .freeTextInHighRisk: "Short text fields aren't allowed with amount-bearing buttons."
        case .actionNotAvailable: "This action isn't available yet."
        case .unregisteredAction, .reservedAction: "Choose an action from the list."
        case .publisherNotVerified: "Your organization must be verified before submitting Loops."
        case .categoryBanned: "Healthcare organizations can't use Loops on Viadere."
        case .categoryProhibited: "Organizations in this category can't use Loops on Viadere."
        case .duplicateId: "Two items share an identifier."
        default: "Rule \(hit.rule.rawValue)."
        }
    }

    // MARK: Editor form

    static let fieldTypeNames: [(LoopFieldType, String)] = [
        (.singleChoice, "Single choice"), (.multiChoice, "Multiple choice"), (.timeSlot, "Time slot"), (.shortText, "Short text"),
        (.date, "Date"), (.yesNo, "Yes or no"), (.acknowledgement, "Checkbox to acknowledge"),
    ]
    static let stepTypeNames: [(LoopStepType, String)] = [(.form, "Questions"), (.summary, "Summary with buttons"), (.result, "Result")]
    static let entryNames: [(LoopEntryPoint, String)] = [(.businessPage, "Your business page"), (.message, "A message"), (.alert, "An alert"), (.widget, "A widget")]

    static func typeName(_ type: LoopFieldType) -> String { fieldTypeNames.first { $0.0 == type }?.1 ?? type.rawValue }
    static func stepName(_ type: LoopStepType) -> String { stepTypeNames.first { $0.0 == type }?.1 ?? type.rawValue }

    /// Registered actions a hosted (Phase 3) Loop may use.
    static var availableActions: [LoopActionDefinition] { LoopActionRegistry.v1.definitions.filter { $0.isAvailable(in: .hosted) } }

    static func editorForm(_ d: LoopDefinition, record: LoopStudioDraftRecord, kits: [BrandKitRecord], canEdit: Bool, csrf: String, action: String) -> String {
        let esc = DashboardUI.esc
        let dis = canEdit ? "" : " disabled"
        func button(_ op: String, _ label: String, _ accessible: String? = nil, style: String = "s sm") -> String {
            canEdit ? "<button class=\"btn \(style)\" type=\"submit\" name=\"op\" value=\"\(esc(op))\"\(accessible.map { " aria-label=\"\(esc($0))\"" } ?? "")>\(esc(label))</button>" : ""
        }
        func input(_ name: String, _ label: String, _ value: String?, max: Int, hint: String? = nil) -> String {
            "<label for=\"\(name)\">\(esc(label))</label><input id=\"\(name)\" name=\"\(name)\" type=\"text\" maxlength=\"\(max)\" value=\"\(esc(value ?? ""))\"\(dis)\(hint.map { _ in " aria-describedby=\"\(name)-h\"" } ?? "")>"
                + (hint.map { "<p class=\"mu sm\" id=\"\(name)-h\">\(esc($0))</p>" } ?? "")
        }
        func checkbox(_ name: String, _ label: String, _ on: Bool) -> String {
            "<label class=\"ck\"><input type=\"checkbox\" name=\"\(name)\" value=\"1\"\(on ? " checked" : "")\(dis)> \(esc(label))</label>"
        }
        func select(_ name: String, _ label: String, _ options: [(String, String)], selected: String?) -> String {
            "<label for=\"\(name)\">\(esc(label))</label><select id=\"\(name)\" name=\"\(name)\"\(dis)>"
                + options.map { "<option value=\"\(esc($0.0))\"\($0.0 == selected ? " selected" : "")>\(esc($0.1))</option>" }.joined() + "</select>"
        }

        var html = "<form method=\"post\" action=\"\(action)\" class=\"card\" aria-label=\"Loop editor\">\(csrf)<input type=\"hidden\" name=\"version\" value=\"\(record.version)\">"
        html += "<h2>Editor</h2>"
        // The first submit button is the one Enter triggers: a plain save.
        if canEdit { html += "<p>\(button("save", "Save draft", style: ""))</p>" }
        html += "<fieldset><legend>Loop</legend>"
        html += input("title", "Title", d.title, max: LoopLimits.titleLength)
        html += input("description", "Description (optional)", d.description, max: LoopLimits.descriptionLength)
        html += "<fieldset><legend>Customers can open it from</legend>" + entryNames.map { checkbox("entry_\($0.0.rawValue)", $0.1, d.entryPoints.contains($0.0)) }.joined() + "</fieldset>"
        var appearance: [(String, String)] = [("standard", "Viadere's standard style")]
        var selectedAppearance = "standard"
        if case .brandKit(let key) = d.appearance {
            selectedAppearance = key
            if !kits.contains(where: { $0.kitKey == key }) { appearance.append((key, "\(key) (not an approved kit)")) }
        }
        appearance += kits.map { ($0.kitKey, "Brand Kit: \($0.name)") }
        html += select("appearance", "Appearance", appearance, selected: selectedAppearance)
        html += "<p class=\"mu sm\">Only your Brand Kits that Viadere approved are listed. The \"Built by\" line, confirmations and outcomes always use Viadere's style.</p>"
        html += "<label for=\"expires_hours\">Customers can finish it within (hours, 1 to 720)</label><input id=\"expires_hours\" name=\"expires_hours\" type=\"number\" min=\"1\" max=\"720\" value=\"\(max(1, d.limits.expiresInSeconds / 3600))\"\(dis)>"
        html += "</fieldset>"

        let stepTargets = d.steps.enumerated().map { ($0.element.id, "Step \($0.offset + 1): \($0.element.title ?? stepName($0.element.type))") }
        for (i, step) in d.steps.enumerated() {
            let sp = "s\(i)"
            html += "<fieldset id=\"step-\(i)\"><legend>Step \(i + 1): \(esc(stepName(step.type)))\(i == 0 ? " (first)" : "")</legend>"
            html += input("\(sp)_title", "Step title (optional)", step.title, max: LoopLimits.stepTitleLength)
            html += "<label for=\"\(sp)_body\">Text (optional)</label><textarea id=\"\(sp)_body\" name=\"\(sp)_body\" maxlength=\"\(LoopLimits.bodyLength)\"\(dis)>\(esc(step.body ?? ""))</textarea>"
            if step.type == .result { html += checkbox("\(sp)_show_outcome", "Show the customer your answer (confirmed, declined, waiting)", step.showOutcome == true) }
            if step.type == .form {
                for (j, field) in step.fields.enumerated() {
                    let fp = "\(sp)_f\(j)"
                    html += "<fieldset id=\"step-\(i)-field-\(j)\"><legend>Field \(j + 1): \(esc(typeName(field.type)))</legend>"
                    html += input("\(fp)_label", "Question", field.label, max: LoopLimits.fieldLabelLength)
                    html += checkbox("\(fp)_required", "Required", field.required == true)
                    if field.type == .shortText {
                        html += "<label for=\"\(fp)_max\">Maximum length (1 to \(LoopLimits.maxShortTextLength))</label><input id=\"\(fp)_max\" name=\"\(fp)_max\" type=\"number\" min=\"1\" max=\"\(LoopLimits.maxShortTextLength)\" value=\"\(field.maxLength.map(String.init) ?? "")\"\(dis)>"
                        html += "<p class=\"mu sm\">Customers see \"Don't share health details here.\" next to short text fields.</p>"
                    }
                    if let options = field.options {
                        html += "<fieldset><legend>Options</legend>"
                        for (k, option) in options.enumerated() {
                            html += "<div class=\"row\">\(input("\(fp)_o\(k)", "Option \(k + 1)", option.label, max: LoopLimits.optionLabelLength))"
                                + button("remove_option:\(i):\(j):\(k)", "Remove", "Remove option \(k + 1) of field \(j + 1) in step \(i + 1)") + "</div>"
                        }
                        if options.count < LoopLimits.maxOptions { html += button("add_option:\(i):\(j)", "Add option", "Add an option to field \(j + 1) in step \(i + 1)") }
                        html += "</fieldset>"
                    }
                    html += "<p>" + button("remove_field:\(i):\(j)", "Remove field", "Remove field \(j + 1) of step \(i + 1)") + "</p></fieldset>"
                }
                if canEdit && step.fields.count < LoopLimits.maxFieldsPerStep {
                    html += "<div class=\"row\">" + select("\(sp)_new_field", "New field type", fieldTypeNames.map { ($0.0.rawValue, $0.1) }, selected: nil)
                        + button("add_field:\(i)", "Add field", "Add a field to step \(i + 1)") + "</div>"
                }
            }
            if step.type == .form || step.type == .summary {
                for (k, binding) in step.actions.enumerated() {
                    let ap = "\(sp)_a\(k)"
                    let def: LoopActionDefinition? = if case .registered(let def) = LoopActionRegistry.v1.resolve(binding.action) { def } else { nil }
                    html += "<fieldset id=\"step-\(i)-button-\(k)\"><legend>Button \(k + 1)</legend>"
                    html += select("\(ap)_action", "What it does", availableActions.map { ($0.actionType, "\($0.title) (\($0.riskClass.rawValue) risk)") }, selected: binding.action)
                    html += select("\(ap)_label", "Label", (def?.allowedLabelKeys ?? []).map { ($0, LoopStringCatalog.actionLabels[$0] ?? $0) }, selected: binding.label)
                    if def?.customLabelAllowed == true {
                        html += input("\(ap)_custom", "Custom label (optional, replaces the label)", binding.customLabel, max: LoopLimits.customLabelLength)
                    }
                    html += select("\(ap)_next", "Leads to", [("", "Choose a step")] + stepTargets.filter { $0.0 != step.id }, selected: binding.next)
                    if def?.deliversToBusiness == true {
                        html += input("\(ap)_queue", "Inbox queue (optional)", binding.routing?.queue, max: 40, hint: "Requests arrive in your Viadere inbox under this queue.")
                    }
                    for parameter in def?.parameters ?? [] {
                        let pp = "\(ap)_p_\(parameter.name)"
                        switch parameter.kind {
                        case .money:
                            let money = binding.params?[parameter.name]
                            var value = "", currency = "USD"
                            if case .object(let o)? = money { value = o["value"]?.stringValue ?? ""; currency = o["currency"]?.stringValue ?? "USD" }
                            html += "<div class=\"cols\"><div>\(input("\(pp)_value", "\(parameter.name.capitalized) (for example 285.28)", value, max: 20))</div>"
                                + "<div>\(input("\(pp)_currency", "Currency (ISO code)", currency, max: 3))</div></div>"
                        case .text, .reference:
                            html += input(pp, parameter.name.capitalized + (parameter.required ? "" : " (optional)"), binding.params?[parameter.name]?.stringValue, max: parameter.maxLength)
                        }
                    }
                    html += "<p>" + button("remove_action:\(i):\(k)", "Remove button", "Remove button \(k + 1) of step \(i + 1)") + "</p></fieldset>"
                }
                if step.actions.count < LoopLimits.maxActionsPerStep { html += "<p>" + button("add_action:\(i)", "Add button", "Add a button to step \(i + 1)") + "</p>" }
            }
            html += "<p class=\"row\">" + (i > 0 ? button("up:\(i)", "Move up", "Move step \(i + 1) up") : "")
                + (i < d.steps.count - 1 ? button("down:\(i)", "Move down", "Move step \(i + 1) down") : "")
                + button("remove_step:\(i)", "Remove step", "Remove step \(i + 1)") + "</p></fieldset>"
        }
        if canEdit && d.steps.count < LoopLimits.maxSteps {
            html += "<div class=\"row\">" + select("new_step_type", "New step type", stepTypeNames.map { ($0.0.rawValue, $0.1) }, selected: nil) + button("add_step", "Add step") + "</div>"
        }
        if canEdit { html += "<p>\(button("save", "Save draft", style: ""))</p>" }
        html += "</form>"
        return html
    }

    // MARK: Submit and status

    static func submitCard(report: LoopValidationReport, record: LoopStudioDraftRecord, canEdit: Bool, csrf: String, action: String) -> String {
        guard canEdit else { return "" }
        let ready = report.gate.passed
        return """
        <div class="card"><h2>Submit for Viadere review</h2><p class="sm">Submitting creates a new revision of <code>\(DashboardUI.esc(record.loopKey))</code>. \
        Viadere runs the automated checks again, then \(report.requiredReview == .twoPerson ? "two different Viadere reviewers check" : "a Viadere reviewer checks") the wording, \
        the data collected and the preview. Only an approved revision is signed and shown to customers; the revision live today keeps serving until then.</p>\
        \(ready ? "" : "<p class=\"err sm\" role=\"status\">Fix the problems in the automated checks first.</p>")\
        <form method="post" action="\(action)/submit">\(csrf)<input type="hidden" name="version" value="\(record.version)">\
        <button class="btn" type="submit"\(ready ? "" : " disabled aria-disabled=\"true\"")>Submit for Viadere review</button></form></div>
        """
    }

    static func stateLabel(_ state: LoopRevisionState) -> String {
        switch state {
        case .draft: "Draft"
        case .validationFailed: "Automated checks failed"
        case .inReview: "Waiting for Viadere review"
        case .changesRequested: "Changes requested"
        case .rejected: "Rejected"
        case .approved: "Approved, signing"
        case .published: "Published"
        case .superseded: "Replaced by a newer revision"
        case .withdrawn: "Withdrawn"
        }
    }

    /// The four review stages (plan 4.12) for each revision of the draft's Loop, with reviewer messages.
    static func tracker(_ req: Request, revisions: [LoopRevisionRecord], p: DashboardPrincipal) async throws -> String {
        var html = "<div class=\"card\" id=\"status\"><h2>Review status</h2>"
        guard !revisions.isEmpty else { return html + "<p class=\"mu\">Not submitted yet.</p></div>" }
        for revision in revisions {
            let reviews = try await LoopReviewRecord.query(on: req.db).filter(\.$revisionId == revision.id!).filter(\.$businessId == revision.businessId).sort(\.$at, .ascending).all()
            let automated = reviews.first { $0.stage == LoopPublicationService.ReviewStage.automated.rawValue }
            let first = reviews.first { $0.stage == LoopPublicationService.ReviewStage.reviewer1.rawValue }
            let second = reviews.first { $0.stage == LoopPublicationService.ReviewStage.reviewer2.rawValue }
            let state = revision.stateValue
            func decision(_ r: LoopReviewRecord?, waiting: Bool) -> (String, Bool) {
                switch r?.decision {
                case "approve"?: ("Approved", true)
                case "request_changes"?: ("Changes requested", true)
                case "reject"?: ("Rejected", true)
                default: (waiting ? "Waiting for a Viadere reviewer" : (state == .withdrawn ? "Withdrawn" : "Not reached"), false)
                }
            }
            let checks = automated?.decision == "pass" ? ("Passed", true) : ("Failed", true)
            let reviewer1 = decision(first, waiting: state == .inReview && first == nil)
            let reviewer2: (String, Bool) = revision.requiredReview == LoopReviewLevel.twoPerson.rawValue
                ? decision(second, waiting: state == .inReview && first?.decision == "approve" && second == nil) : ("Not required for this revision", true)
            let published: (String, Bool) = switch state {
            case .published: ("Signed and published", true)
            case .superseded: ("Was published, now replaced by a newer revision", true)
            case .approved: ("Signing", false)
            default: ("Not published", false)
            }
            var messages = LoopPublicationService.hits(revision.ruleHitsJSON).filter { !$0.rule.isReviewFlag }.map { "\(location($0.path)): \(message($0))" }
            for review in [first, second].compactMap({ $0 }) where review.decision == "reject" || review.decision == "request_changes" {
                if let sealed = review.notesSealed, let text = try? req.ctx.cipher.openString(sealed, context: "loop_reviews.notes", rowId: review.id!) {
                    messages.append("Viadere reviewer: \(text)")
                }
            }
            func stage(_ n: Int, _ name: String, _ value: (String, Bool)) -> String {
                "<li\(value.1 ? " class=\"done\"" : "")><strong>\(n). \(DashboardUI.esc(name))</strong> <span>\(DashboardUI.esc(value.0))</span></li>"
            }
            html += "<section aria-label=\"Revision \(revision.revision)\"><h3>Revision \(revision.revision) · \(DashboardUI.esc(stateLabel(state))) · \(DashboardFormat.date(revision.createdAt))</h3>"
            html += "<ol class=\"steps\">\(stage(1, "Automated checks", checks))\(stage(2, "Viadere review", reviewer1))\(stage(3, "Second Viadere reviewer", reviewer2))\(stage(4, "Signed publication", published))</ol>"
            if !messages.isEmpty { html += "<ul class=\"sm\">" + messages.prefix(10).map { "<li>\(DashboardUI.esc($0))</li>" }.joined() + "</ul>" }
            if state == .inReview && p.can(.submitLoops) {
                html += "<form method=\"post\" action=\"\(ConsoleInbox.loopsPath)/revisions/\(revision.id!.uuidString.lowercased())/withdraw\">\(DashboardUI.csrf(p))<button class=\"btn s sm\" type=\"submit\">Withdraw revision \(revision.revision)</button></form>"
            }
            html += "</section>"
        }
        return html + "</div>"
    }
}

// MARK: - Form model

/// Turns the Studio editor form into a typed `LoopDefinition`. Structure (step, field, option and action identities and types) comes from the
/// **stored** draft, never from the form: the form supplies only editable values, each read from a known name and checked against the
/// closed schema (registered actions, allowed labels, the draft's own steps, the business's own approved Brand Kits). Anything else is a
/// validation error, never stored. Structural changes are explicit operations (`perform`).
enum LoopStudioForm {
    /// Generous cap on any single text value (the validator reports the real limits; this only bounds storage).
    static let maxTextLength = 1_000

    static func text(_ form: [String: String], _ key: String) throws -> String? {
        guard let raw = form[key] else { return nil }
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.count <= maxTextLength else { throw APIError.validation("A text is too long.", details: [key: "too_long"]) }
        return value.isEmpty ? nil : value
    }

    static func apply(_ form: [String: String], to base: LoopDefinition, approvedKits: Set<String>) throws -> LoopDefinition {
        var d = base
        d.title = try text(form, "title") ?? ""
        d.description = try text(form, "description")
        d.entryPoints = LoopEntryPoint.allCases.filter { form["entry_\($0.rawValue)"] == "1" }
        switch form["appearance"] ?? "standard" {
        case "standard": d.appearance = .standard
        case let key:
            // Only the business's own approved kits; a stale stored value may stay (the validator reports it), a new foreign one never.
            if approvedKits.contains(key) || base.appearance == .brandKit(key) { d.appearance = .brandKit(key) } else {
                throw APIError.validation("Choose one of your approved Brand Kits.", details: ["appearance": "unknown_brand_kit"])
            }
        }
        if let raw = form["expires_hours"], !raw.isEmpty {
            guard let hours = Int64(raw), (1...720).contains(hours) else { throw APIError.validation("Choose an expiry between 1 and 720 hours.", details: ["expires_hours": "invalid"]) }
            d.limits.expiresInSeconds = hours * 3600
        }
        let stepIds = Set(base.steps.map(\.id))
        let actionTypes = Set(ConsoleLoopStudio.availableActions.map(\.actionType))
        for (i, step) in base.steps.enumerated() {
            let sp = "s\(i)"
            var s = step
            s.title = try text(form, "\(sp)_title")
            s.body = try text(form, "\(sp)_body")
            if step.type == .result { s.showOutcome = form["\(sp)_show_outcome"] == "1" ? true : nil }
            for (j, field) in step.fields.enumerated() {
                let fp = "\(sp)_f\(j)"
                var f = field
                f.label = try text(form, "\(fp)_label") ?? ""
                f.required = form["\(fp)_required"] == "1" ? true : nil
                if field.type == .shortText {
                    if let raw = form["\(fp)_max"], !raw.isEmpty {
                        guard let max = Int(raw), (1...LoopLimits.maxShortTextLength).contains(max) else {
                            throw APIError.validation("Choose a maximum length between 1 and \(LoopLimits.maxShortTextLength).", details: ["\(fp)_max": "invalid"])
                        }
                        f.maxLength = max
                    } else { f.maxLength = nil }
                }
                if let options = field.options {
                    f.options = try options.enumerated().map { k, option in LoopOption(id: option.id, label: try text(form, "\(fp)_o\(k)") ?? "") }
                }
                s.fields[j] = f
            }
            for (k, binding) in step.actions.enumerated() {
                let ap = "\(sp)_a\(k)"
                var a = binding
                let type = form["\(ap)_action"] ?? binding.action
                guard actionTypes.contains(type), case .registered(let def) = LoopActionRegistry.v1.resolve(type) else {
                    throw APIError.validation("Choose an action from the list.", details: ["\(ap)_action": "unregistered_action"])
                }
                a.action = type
                let label = form["\(ap)_label"] ?? binding.label
                if def.allowedLabelKeys.contains(label) {
                    a.label = label
                } else if label.isEmpty || LoopStringCatalog.actionLabels[label] != nil {
                    a.label = def.allowedLabelKeys.first ?? label   // the action changed: start from its first allowed label
                } else {
                    throw APIError.validation("Choose a button label from the list.", details: ["\(ap)_label": "label_not_allowed"])
                }
                a.customLabel = def.customLabelAllowed ? try text(form, "\(ap)_custom") : nil
                let next = form["\(ap)_next"] ?? binding.next ?? ""
                if next.isEmpty { a.next = nil } else {
                    guard stepIds.contains(next) else { throw APIError.validation("Choose a step from the list.", details: ["\(ap)_next": "unknown_next_step"]) }
                    a.next = next
                }
                a.routing = def.deliversToBusiness ? LoopRouting(mode: .hosted, queue: try text(form, "\(ap)_queue")) : nil
                var params: [String: JSONValue] = [:]
                for parameter in def.parameters {
                    let pp = "\(ap)_p_\(parameter.name)"
                    switch parameter.kind {
                    case .money:
                        let value = try text(form, "\(pp)_value"), currency = try text(form, "\(pp)_currency")
                        if value != nil || currency != nil {
                            params[parameter.name] = .object(["value": .string(value ?? ""), "currency": .string((currency ?? "").uppercased())])
                        }
                    case .text, .reference:
                        if let value = try text(form, pp) { params[parameter.name] = .string(value) }
                    }
                }
                a.params = params.isEmpty ? nil : params
                s.actions[k] = a
            }
            d.steps[i] = s
        }
        return d
    }

    /// Applies one structural operation and returns the anchor to scroll back to. Bounds are the platform caps, so a draft can't grow beyond
    /// what the validator would accept.
    static func perform(_ op: String, form: [String: String], on d: inout LoopDefinition) throws -> String? {
        let parts = op.split(separator: ":").map(String.init)
        let ints = parts.dropFirst().compactMap { Int($0) }
        guard ints.count == parts.count - 1 else { throw APIError.validation("Unknown editor action.") }
        func step(_ i: Int) throws -> Int {
            guard d.steps.indices.contains(i) else { throw APIError.validation("That step no longer exists. Reload the draft.") }
            return i
        }
        func freeId(_ prefix: String, _ used: Set<String>) -> String {
            var n = 1
            while used.contains("\(prefix)\(n)") { n += 1 }
            return "\(prefix)\(n)"
        }
        switch (parts.first ?? "", ints.count) {
        case ("save", 0):
            return nil
        case ("add_step", 0):
            guard d.steps.count < LoopLimits.maxSteps else { throw APIError.validation("A Loop has at most \(LoopLimits.maxSteps) steps.") }
            guard let type = LoopStepType(rawValue: form["new_step_type"] ?? ""), type != .handoff else { throw APIError.validation("Choose a step type from the list.") }
            let used = Set(d.steps.map(\.id))
            let id = type == .result && !used.contains("done") ? "done" : freeId("s", used)
            let new = LoopStep(id: id, type: type, showOutcome: type == .result ? true : nil)
            let index = type == .result ? d.steps.count : (d.steps.firstIndex { $0.type == .result || $0.type == .handoff } ?? d.steps.count)
            d.steps.insert(new, at: index)
            return "step-\(index)"
        case ("remove_step", 1):
            let i = try step(ints[0])
            let removed = d.steps.remove(at: i).id
            for s in d.steps.indices { for a in d.steps[s].actions.indices where d.steps[s].actions[a].next == removed { d.steps[s].actions[a].next = nil } }
            return nil
        case ("up", 1), ("down", 1):
            let i = try step(ints[0])
            let j = parts[0] == "up" ? i - 1 : i + 1
            guard d.steps.indices.contains(j) else { return "step-\(i)" }
            d.steps.swapAt(i, j)
            return "step-\(j)"
        case ("add_field", 1):
            let i = try step(ints[0])
            guard d.steps[i].type == .form else { throw APIError.validation("Fields belong to question steps.") }
            guard d.steps[i].fields.count < LoopLimits.maxFieldsPerStep else { throw APIError.validation("A step has at most \(LoopLimits.maxFieldsPerStep) fields.") }
            let raw = form["s\(i)_new_field"] ?? ""
            guard let type = LoopFieldType(rawValue: raw) else {
                if LoopFieldType.prohibitionReason(raw) != nil {
                    throw APIError.validation("That kind of field isn't allowed. Loops can't collect health information, passwords or codes, card or bank details, government ids, files or long text.",
                                              details: ["s\(i)_new_field": "prohibited_field_type"])
                }
                throw APIError.validation("Choose a field type from the list.", details: ["s\(i)_new_field": "unknown_field_type"])
            }
            var field = LoopField(id: freeId("f", Set(d.steps[i].fields.map(\.id))), type: type, label: "")
            if type == .singleChoice || type == .multiChoice || type == .timeSlot { field.options = [LoopOption(id: "o1", label: ""), LoopOption(id: "o2", label: "")] }
            if type == .shortText { field.maxLength = 40 }
            d.steps[i].fields.append(field)
            return "step-\(i)-field-\(d.steps[i].fields.count - 1)"
        case ("remove_field", 2):
            let i = try step(ints[0])
            guard d.steps[i].fields.indices.contains(ints[1]) else { throw APIError.validation("That field no longer exists. Reload the draft.") }
            d.steps[i].fields.remove(at: ints[1])
            return "step-\(i)"
        case ("add_option", 2):
            let i = try step(ints[0]), j = ints[1]
            guard d.steps[i].fields.indices.contains(j), let options = d.steps[i].fields[j].options else { throw APIError.validation("That field has no options.") }
            guard options.count < LoopLimits.maxOptions else { throw APIError.validation("A field has at most \(LoopLimits.maxOptions) options.") }
            d.steps[i].fields[j].options?.append(LoopOption(id: freeId("o", Set(options.map(\.id))), label: ""))
            return "step-\(i)-field-\(j)"
        case ("remove_option", 3):
            let i = try step(ints[0]), j = ints[1], k = ints[2]
            guard d.steps[i].fields.indices.contains(j), let options = d.steps[i].fields[j].options, options.indices.contains(k) else {
                throw APIError.validation("That option no longer exists. Reload the draft.")
            }
            d.steps[i].fields[j].options?.remove(at: k)
            return "step-\(i)-field-\(j)"
        case ("add_action", 1):
            let i = try step(ints[0])
            guard d.steps[i].type == .form || d.steps[i].type == .summary else { throw APIError.validation("Result steps have no buttons.") }
            guard d.steps[i].actions.count < LoopLimits.maxActionsPerStep else { throw APIError.validation("A step has at most \(LoopLimits.maxActionsPerStep) buttons.") }
            let id = freeId("a", Set(d.steps.flatMap(\.actions).map(\.id)))
            let action = d.steps[i].type == .form
                ? LoopActionBinding(id: id, action: "select_option", label: "continue")
                : LoopActionBinding(id: id, action: "acknowledge", label: "send_request", routing: LoopRouting(mode: .hosted))
            d.steps[i].actions.append(action)
            return "step-\(i)-button-\(d.steps[i].actions.count - 1)"
        case ("remove_action", 2):
            let i = try step(ints[0])
            guard d.steps[i].actions.indices.contains(ints[1]) else { throw APIError.validation("That button no longer exists. Reload the draft.") }
            d.steps[i].actions.remove(at: ints[1])
            return "step-\(i)"
        default:
            throw APIError.validation("Unknown editor action.")
        }
    }
}
