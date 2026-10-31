import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP-3.7 Loop Studio and the Brand Kit wiring of Loop validation (SECURITY.md §2.99). Written before the Studio: viewers are read-only,
/// tenants never see each other's drafts or revisions, a definition can name only the business's own approved Brand Kit, the preview has no
/// script and its own sandbox CSP, templates pass the hard gate, prohibited field types and categories are refused in the editor, and a
/// submission takes the same review pipeline as every revision (no path publishes).
final class LoopStudioTests: XCTestCase {
    static let operatorActor = AuditActor(kind: .operator_, id: "operator-test")
    static let path = "/dashboard/loops/studio"

    // MARK: Helpers

    /// Starts a draft from `template` through the console and returns its id.
    static func createDraft(_ h: TestHarness, _ session: DashSession, template: String = "pickup_time") async throws -> UUID {
        let created = try await h.formPost("\(path)/drafts", session, [("template", template)])
        XCTAssertEqual(created.status, .seeOther, created.text)
        let location = try XCTUnwrap(created.headers.first(name: .location))
        let raw = try XCTUnwrap(location.split(separator: "/").last?.split(separator: "?").first)
        return try XCTUnwrap(UUID(uuidString: String(raw)))
    }

    static func unescape(_ s: String) -> String {
        s.replacingOccurrences(of: "&quot;", with: "\"").replacingOccurrences(of: "&#39;", with: "'").replacingOccurrences(of: "&lt;", with: "<")
            .replacingOccurrences(of: "&gt;", with: ">").replacingOccurrences(of: "&amp;", with: "&")
    }

    static func attribute(_ name: String, in tag: String) -> String? {
        guard let r = tag.range(of: " \(name)=\"") else { return nil }
        return unescape(String(tag[r.upperBound...].prefix { $0 != "\"" }))
    }

    static func matches(_ pattern: String, in text: String) -> [[String]] {
        let regex = try! NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators])
        let ns = text as NSString
        return regex.matches(in: text, range: NSRange(location: 0, length: ns.length)).map { m in
            (0..<m.numberOfRanges).map { m.range(at: $0).location == NSNotFound ? "" : ns.substring(with: m.range(at: $0)) }
        }
    }

    /// What a browser would submit from the editor form (text, hidden, number, checked boxes, selected options, textareas), minus `_csrf`.
    static func editorFields(_ html: String) -> [(String, String)] {
        guard let start = html.range(of: "aria-label=\"Loop editor\""), let end = html.range(of: "</form>", range: start.upperBound..<html.endIndex) else { return [] }
        let form = String(html[start.upperBound..<end.lowerBound])
        var out: [(String, String)] = []
        for m in matches("<input ([^>]*)>", in: form) {
            let tag = " " + m[1]
            guard let name = attribute("name", in: tag), name != "_csrf" else { continue }
            let type = attribute("type", in: tag) ?? "text"
            if type == "checkbox" { if tag.contains(" checked") { out.append((name, attribute("value", in: tag) ?? "on")) }; continue }
            out.append((name, attribute("value", in: tag) ?? ""))
        }
        for m in matches("<textarea ([^>]*)>(.*?)</textarea>", in: form) {
            if let name = attribute("name", in: " " + m[1]) { out.append((name, unescape(m[2]))) }
        }
        for m in matches("<select ([^>]*)>(.*?)</select>", in: form) {
            guard let name = attribute("name", in: " " + m[1]) else { continue }
            let options = matches("<option ([^>]*)>", in: m[2]).map { " " + $0[1] }
            let chosen = options.first { $0.contains(" selected") } ?? options.first
            out.append((name, chosen.flatMap { attribute("value", in: $0) } ?? ""))
        }
        return out
    }

    /// Loads the editor, applies `changes` over what the browser would send, and posts it with `op`.
    static func edit(_ h: TestHarness, _ session: DashSession, _ id: UUID, op: String = "save", _ changes: [String: String] = [:]) async throws -> HTTPResult {
        let page = try await h.page("\(path)/drafts/\(id.uuidString.lowercased())", session)
        XCTAssertEqual(page.status, .ok, page.text)
        var fields = editorFields(page.text).filter { changes[$0.0] == nil }
        for (k, v) in changes.sorted(by: { $0.key < $1.key }) { fields.append((k, v)) }
        fields.append(("op", op))
        return try await h.formPost("\(path)/drafts/\(id.uuidString.lowercased())", session, fields)
    }

    static func stored(_ h: TestHarness, _ id: UUID) async throws -> (LoopStudioDraftRecord, LoopDefinition) {
        let record = try await XCTUnwrapAsync(try await LoopStudioDraftRecord.find(id, on: h.db))
        return (record, try XCTUnwrap(LoopStudioService.definition(record)))
    }

    static func version(_ h: TestHarness, _ id: UUID) async throws -> String { String(try await stored(h, id).0.version) }

    @discardableResult
    static func approvedKit(_ h: TestHarness, business: UUID, key: String, primary: String) async throws -> BrandKitRecord {
        let service = BrandKitService(db: h.db, ctx: h.ctx)
        let kit = try await service.save(businessId: business, kitId: nil, draft: .init(kitKey: key, name: key.capitalized,
            tokens: BrandTokens(primary: BrandColor(primary)!), frameId: nil, assets: [:]), actor: AuditActor(kind: .system, id: "test"))
        try await service.approveKit(id: kit.id!, actor: operatorActor, note: nil)
        return try await BrandKitRecord.find(kit.id!, on: h.db)!
    }

    // MARK: Roles

    func testViewersReadButCannotCreateSaveSubmitOrDelete() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let id = try await Self.createDraft(h, owner)
            let draft = "\(Self.path)/drafts/\(id.uuidString.lowercased())"
            let auditor = try await h.addMember(owner: owner, role: .auditor, email: "auditor@example.com")
            for page in [Self.path, draft, "\(draft)/preview", "/dashboard/loops"] {
                let result = try await h.page(page, auditor.session)
                XCTAssertEqual(result.status, .ok, "\(page): \(result.text.prefix(300))")
            }
            let readOnly = try await h.page(draft, auditor.session)
            XCTAssertTrue(readOnly.text.contains("You can read this draft"))
            XCTAssertFalse(readOnly.text.contains("name=\"op\""), "no editor buttons for a viewer")
            XCTAssertFalse(readOnly.text.contains("Submit for Viadere review</button>"))
            let version = try await Self.version(h, id)
            for (target, fields) in [("\(Self.path)/drafts", [("template", "acknowledge")]), (draft, [("version", version), ("title", "Changed"), ("op", "save")]),
                                     ("\(draft)/submit", [("version", version)]), ("\(draft)/delete", [])] {
                let denied = try await h.formPost(target, auditor.session, fields)
                XCTAssertEqual(denied.status, .forbidden, "\(target): \(denied.text.prefix(200))")
            }
            try await eq(try await LoopStudioDraftRecord.query(on: h.db).count(), 1)
            try await eq(try await Self.stored(h, id).1.title, "Choose a pickup time")
            try await eq(try await LoopRevisionRecord.query(on: h.db).count(), 0)
            // A role with neither Loop permission can't even read.
            let analyst = try await h.addMember(owner: owner, role: .analyst, email: "analyst@example.com")
            for page in [Self.path, draft, "\(draft)/preview"] { try await eq(try await h.get(analyst.session, page), .forbidden) }
            XCTAssertTrue(DashboardPermission.viewLoops.roles.isDisjoint(with: [.analyst, .billingAdmin, .verificationAdmin, .securityAdmin]))
            XCTAssertFalse(DashboardPermission.allCases.contains { $0.rawValue.lowercased().contains("publish") })
        }
    }

    // MARK: Tenancy

    func testAnotherTenantsDraftsAndRevisionsAreInvisible() async throws {
        try await withHarness { h in
            let (alpha, _, alphaId) = try await h.verifiedOwner()
            let (beta, _, _) = try await h.verifiedOwner(email: "beta@example.com", org: "Birch Books", handle: "birchbooks")
            let id = try await Self.createDraft(h, alpha, template: "callback_request")
            let draft = "\(Self.path)/drafts/\(id.uuidString.lowercased())"
            let version = try await Self.version(h, id)
            for page in [draft, "\(draft)/preview"] { try await eq(try await h.get(beta, page), .notFound) }
            for (target, fields) in [(draft, [("version", version), ("title", "Hijacked"), ("op", "save")]), ("\(draft)/submit", [("version", version)]),
                                     ("\(draft)/delete", [])] {
                let refused = try await h.formPost(target, beta, fields)
                XCTAssertEqual(refused.status, .notFound, "\(target): \(refused.text.prefix(200))")
            }
            let betaGallery = try await h.page(Self.path, beta)
            XCTAssertFalse(betaGallery.text.contains(id.uuidString.lowercased()))
            XCTAssertFalse(betaGallery.text.contains("callback-request"))
            // Alpha submits; Beta sees neither the revision nor its review status, and can't withdraw it.
            let submitted = try await h.formPost("\(draft)/submit", alpha, [("version", version)])
            XCTAssertEqual(submitted.status, .seeOther, submitted.text)
            let revision = try await XCTUnwrapAsync(try await LoopRevisionRecord.query(on: h.db).filter(\.$businessId == alphaId).first())
            let betaLoops = try await h.page("/dashboard/loops", beta)
            XCTAssertFalse(betaLoops.text.contains("callback-request"))
            let withdraw = try await h.formPost("/dashboard/loops/revisions/\(revision.id!.uuidString.lowercased())/withdraw", beta, [])
            XCTAssertEqual(withdraw.status, .notFound, withdraw.text)
            try await eq(try await LoopRevisionRecord.find(revision.id!, on: h.db)?.stateValue, .inReview)
            try await eq(try await Self.stored(h, id).1.title, "Request a callback")
            // The service refuses a foreign id the same way.
            do { _ = try await LoopStudioService(db: h.db, ctx: h.ctx).draft(businessId: UUID(), id: id); XCTFail("foreign draft read") } catch let error as APIError {
                XCTAssertEqual(error.status, .notFound)
            }
        }
    }

    // MARK: Brand Kits

    func testADefinitionMayNameOnlyTheBusinesssOwnApprovedBrandKit() async throws {
        try await withHarness { h in
            let (alpha, account, alphaId) = try await h.verifiedOwner()
            let (_, _, betaId) = try await h.verifiedOwner(email: "beta@example.com", org: "Birch Books", handle: "birchbooks")
            try await Self.approvedKit(h, business: betaId, key: "autumn", primary: "#7A2E1F")
            try await Self.approvedKit(h, business: alphaId, key: "spring", primary: "#2F5D50")
            let id = try await Self.createDraft(h, alpha)
            // The editor offers only Alpha's approved kits, and refuses another business's kit key outright.
            let page = try await h.page("\(Self.path)/drafts/\(id.uuidString.lowercased())", alpha)
            XCTAssertTrue(page.text.contains("value=\"spring\""))
            XCTAssertFalse(page.text.contains("autumn"))
            let foreign = try await Self.edit(h, alpha, id, ["appearance": "autumn"])
            XCTAssertEqual(foreign.status, .unprocessableEntity, foreign.text)
            try await eq(try await Self.stored(h, id).1.appearance, .standard)
            let own = try await Self.edit(h, alpha, id, ["appearance": "spring"])
            XCTAssertEqual(own.status, .seeOther, own.text)
            try await eq(try await Self.stored(h, id).1.appearance, .brandKit("spring"))
            // The preview applies Alpha's own clamped kit colors.
            let preview = try await h.page("\(Self.path)/drafts/\(id.uuidString.lowercased())/preview", alpha)
            XCTAssertTrue(preview.text.contains("--p:#2F5D50"), preview.text.prefix(600).description)
            XCTAssertFalse(preview.text.contains("#7A2E1F"))
            // The pipeline: a submission naming another business's kit fails the hard gate; its own approved kit passes.
            var definition = try await Self.stored(h, id).1
            definition.appearance = .brandKit("autumn")
            let service = LoopPublicationService(db: h.db, ctx: h.ctx)
            let refused = try await service.submit(businessId: alphaId, authorId: account.userId, definition: try definition.canonicalJSON())
            XCTAssertEqual(refused.stateValue, .validationFailed)
            XCTAssertTrue(LoopPublicationService.hits(refused.ruleHitsJSON).contains { $0.rule == .unknownBrandKit })
            definition.appearance = .brandKit("spring")
            let accepted = try await service.submit(businessId: alphaId, authorId: account.userId, definition: try definition.canonicalJSON())
            XCTAssertEqual(accepted.stateValue, .inReview, accepted.ruleHitsJSON)
            // A kit that is not approved yet does not count either.
            let pending = try await BrandKitService(db: h.db, ctx: h.ctx).save(businessId: alphaId, kitId: nil, draft: .init(kitKey: "winter", name: "Winter",
                tokens: BrandTokens(primary: BrandColor("#1D3557")!), frameId: nil, assets: [:]), actor: AuditActor(kind: .system, id: "test"))
            XCTAssertNil(pending.approvedJSON)
            definition.appearance = .brandKit("winter")
            definition.key = "pickup-winter"
            try await eq(try await service.submit(businessId: alphaId, authorId: account.userId, definition: try definition.canonicalJSON()).stateValue, .validationFailed)
            try await eq(try await LoopPublicationService.approvedBrandKitKeys(businessId: alphaId, on: h.db), ["spring"])
            // The preview lookup is scoped by business: Beta's kit key never resolves for Alpha.
            var autumn = definition
            autumn.appearance = .brandKit("autumn")
            try await isNil(try await LoopPreview.brand(for: autumn, businessId: alphaId, on: h.db))
            try await notNil(try await LoopPreview.brand(for: autumn, businessId: betaId, on: h.db))
        }
    }

    // MARK: Preview isolation

    func testPreviewHasNoScriptAndIsServedWithItsOwnSandboxCSP() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let id = try await Self.createDraft(h, owner, template: "salon_check_in")
            let draft = "\(Self.path)/drafts/\(id.uuidString.lowercased())"
            let preview = try await h.page("\(draft)/preview", owner)
            XCTAssertEqual(preview.status, .ok, preview.text)
            let csp = try XCTUnwrap(preview.headers.first(name: "Content-Security-Policy"))
            for directive in ["default-src 'none'", "img-src 'none'", "form-action 'none'", "base-uri 'none'", "frame-ancestors 'self'", "sandbox"] {
                XCTAssertTrue(csp.contains(directive), "\(directive) in \(csp)")
            }
            XCTAssertFalse(csp.contains("script-src"), csp)
            XCTAssertFalse(csp.contains("unsafe"), csp)
            XCTAssertEqual(preview.headers.first(name: "X-Frame-Options"), "SAMEORIGIN")
            XCTAssertEqual(preview.headers.first(name: .cacheControl), "no-store")
            XCTAssertFalse(preview.text.lowercased().contains("<script"))
            XCTAssertTrue(Self.matches(" on[a-z]+=", in: preview.text).isEmpty, "no inline event handlers")
            // The stylesheet is exactly the one the CSP pins.
            let css = try XCTUnwrap(Self.matches("<style>(.*?)</style>", in: preview.text).first?[1])
            XCTAssertTrue(csp.contains("'sha256-\(DashboardUI.sha256Base64(css))'"))
            // Labeled as a preview; production-only chrome is drawn as placeholders; attribution comes first.
            XCTAssertTrue(preview.text.contains("Preview, not exactly what customers see"))
            XCTAssertTrue(preview.text.contains("Placeholder: status bar shown by iOS"))
            XCTAssertTrue(preview.text.contains("Placeholder: Face ID or passcode prompt"), "check-in has a confirmation")
            XCTAssertTrue(preview.text.contains("Placeholder: notification banner"))
            XCTAssertTrue(preview.text.contains("Built by Acme Roasters"))
            XCTAssertTrue(preview.text.contains("data-node=\"confirmation_panel\" data-protected=\"true\""))
            // The editor page frames it sandboxed, with a title, and its own CSP allows same-origin frames only.
            let page = try await h.page(draft, owner)
            let pageCSP = try XCTUnwrap(page.headers.first(name: "Content-Security-Policy"))
            XCTAssertTrue(pageCSP.contains("frame-src 'self'") && pageCSP.contains("frame-ancestors 'none'"), pageCSP)
            XCTAssertFalse(page.text.lowercased().contains("<script"), "the Studio itself runs no script")
            let iframe = try XCTUnwrap(Self.matches("<iframe ([^>]*)>", in: page.text).first?[0])
            XCTAssertTrue(iframe.contains("sandbox=\"\""), iframe)
            XCTAssertTrue(iframe.contains("title=\"Preview of Check in for your visit, not exactly what customers see\""), iframe)
            XCTAssertTrue(iframe.contains("referrerpolicy=\"no-referrer\""))
            // While the automated checks fail, the preview shows a notice and no business content (like a device would).
            let broken = try await Self.edit(h, owner, id, ["title": "Visit www.example.com"])
            XCTAssertEqual(broken.status, .seeOther, broken.text)
            let notice = try await h.page("\(draft)/preview", owner)
            XCTAssertTrue(notice.text.contains("The preview appears when the automated checks pass"))
            XCTAssertFalse(notice.text.contains("example.com"))
            XCTAssertFalse(notice.text.contains("data-node"))
            // The operator review shows the same renderer in the same kind of sandbox.
            let world = try await LoopWorld.build(h, name: "Corner Bakery", handle: "cornerbakery")
            let revision = try await world.submit()
            let (session, _) = try await h.makeOperator(email: "preview-reviewer@viadere.test")
            let review = try await h.page("/operator/loops/revisions/\(revision.id!.uuidString.lowercased())", session)
            XCTAssertTrue(review.text.contains("sandbox=\"\""), review.text.prefix(400).description)
            XCTAssertTrue(review.headers.first(name: "Content-Security-Policy")?.contains("frame-src 'self'") ?? false)
            let operatorPreview = try await h.page("/operator/loops/revisions/\(revision.id!.uuidString.lowercased())/preview", session)
            XCTAssertTrue(operatorPreview.headers.first(name: "Content-Security-Policy")?.contains("sandbox") ?? false)
            XCTAssertTrue(operatorPreview.text.contains("Built by Corner Bakery"))
            // A business session can't open the operator preview.
            let crossRealm = try await h.page("/operator/loops/revisions/\(revision.id!.uuidString.lowercased())/preview", owner)
            XCTAssertNotEqual(crossRealm.status, .ok)
        }
    }

    // MARK: Templates

    func testEveryTemplateStartsADraftThatPassesTheHardGate() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let business = try await XCTUnwrapAsync(try await BusinessRecord.find(businessId, on: h.db))
            let gallery = try await h.page(Self.path, owner)
            XCTAssertEqual(gallery.status, .ok, gallery.text)
            for template in LoopTemplateCatalog.v1 {
                XCTAssertTrue(gallery.text.contains(DashboardUI.esc(template.name)), template.key)
                let id = try await Self.createDraft(h, owner, template: template.key)
                let (record, definition) = try await Self.stored(h, id)
                XCTAssertEqual(record.templateKey, template.key)
                let report = try await LoopStudioService(db: h.db, ctx: h.ctx).report(definition, business: business)
                XCTAssertTrue(report.gate.passed, "\(template.key): \(report.hits)")
                let page = try await h.page("\(Self.path)/drafts/\(id.uuidString.lowercased())", owner)
                XCTAssertTrue(page.text.contains("Ready to submit"), template.key)
            }
            // A second draft from the same template gets its own Loop key (it would otherwise revise the first Loop).
            let again = try await Self.createDraft(h, owner, template: "pickup_time")
            try await eq(try await Self.stored(h, again).0.loopKey, "pickup-time-2")
            let unknown = try await h.formPost("\(Self.path)/drafts", owner, [("template", "medical_intake")])
            XCTAssertEqual(unknown.status, .unprocessableEntity, unknown.text)
        }
    }

    // MARK: Editor refusals

    func testProhibitedFieldTypesActionsAndCategoriesAreRefusedInTheEditor() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let id = try await Self.createDraft(h, owner, template: "repair_check_in")
            let before = try await Self.stored(h, id).0.definitionJSON
            for (op, changes) in [("add_field:0", ["s0_new_field": "medical"]), ("add_field:0", ["s0_new_field": "card_number"]),
                                  ("add_field:0", ["s0_new_field": "password"]), ("add_field:0", ["s0_new_field": "file"]),
                                  ("add_field:0", ["s0_new_field": "html"]), ("save", ["s1_a0_action": "payment.capture"]),
                                  ("save", ["s1_a0_action": "verify_age"]), ("save", ["s1_a0_action": "approve_estimate"]),
                                  ("save", ["s1_a0_label": "Approve and pay"]), ("save", ["s0_a0_next": "elsewhere"]),
                                  ("add_step", ["new_step_type": "handoff"])] {
                let refused = try await Self.edit(h, owner, id, op: op, changes)
                XCTAssertEqual(refused.status, .unprocessableEntity, "\(op) \(changes): \(refused.text.prefix(200))")
            }
            let health = try await Self.edit(h, owner, id, op: "add_field:0", ["s0_new_field": "medical"])
            XCTAssertTrue(health.text.contains("health information"), health.text.prefix(400).description)
            try await eq(try await Self.stored(h, id).0.definitionJSON, before, "nothing was stored")
            // Wording rules show in the report (and block submission) rather than being silently fixed.
            let worded = try await Self.edit(h, owner, id, ["s0_f0_label": "Describe your symptoms"])
            XCTAssertEqual(worded.status, .seeOther, worded.text)
            let page = try await h.page("\(Self.path)/drafts/\(id.uuidString.lowercased())", owner)
            XCTAssertTrue(page.text.contains("Loops can&#39;t be about health"), page.text.prefix(200).description)
            XCTAssertTrue(page.text.contains("Step 1 › Field 1 › label"))
            let submit = try await h.formPost("\(Self.path)/drafts/\(id.uuidString.lowercased())/submit", owner, [("version", try await Self.version(h, id))])
            XCTAssertEqual(submit.status, .unprocessableEntity, submit.text)
            try await eq(try await LoopRevisionRecord.query(on: h.db).count(), 0)
            // Healthcare and prohibited categories get no Studio (as the pipeline already refuses them).
            for category in ["healthcare", "gambling"] {
                try await BusinessRecord.query(on: h.db).filter(\.$id == businessId).set(\.$category, to: category).update()
                let gallery = try await h.page(Self.path, owner)
                XCTAssertTrue(gallery.text.contains("can&#39;t use Loops on Viadere"), category)
                XCTAssertFalse(gallery.text.contains("Start from this template"), category)
                let create = try await h.formPost("\(Self.path)/drafts", owner, [("template", "acknowledge")])
                XCTAssertEqual(create.status, .forbidden, category)
                let save = try await Self.edit(h, owner, id, ["s0_f0_label": "Vehicle"])
                XCTAssertEqual(save.status, .forbidden, category)
                let refused = try await h.formPost("\(Self.path)/drafts/\(id.uuidString.lowercased())/submit", owner, [("version", try await Self.version(h, id))])
                XCTAssertEqual(refused.status, .forbidden, category)
            }
            try await eq(try await LoopRevisionRecord.query(on: h.db).count(), 0)
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "loop.studio_draft_created").count() == 1)
        }
    }

    // MARK: Same pipeline

    func testSubmissionTakesTheReviewPipelineAndNothingPublishes() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let id = try await Self.createDraft(h, owner, template: "pickup_time")
            let draft = "\(Self.path)/drafts/\(id.uuidString.lowercased())"
            // Text changes keep the template fast path; the server decides it, not the form.
            let edited = try await Self.edit(h, owner, id, ["title": "Pick up your order", "s0_f0_o0": "Morning, 9 to noon", "template": "acknowledge"])
            XCTAssertEqual(edited.status, .seeOther, edited.text)
            // A stale form is refused.
            let stale = try await h.formPost(draft, owner, [("version", "1"), ("title", "Old tab"), ("op", "save")])
            XCTAssertEqual(stale.status, .conflict, stale.text)
            let version = try await Self.version(h, id)
            let submitted = try await h.formPost("\(draft)/submit", owner, [("version", version)])
            XCTAssertEqual(submitted.status, .seeOther, submitted.text)
            let revision = try await XCTUnwrapAsync(try await LoopRevisionRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            XCTAssertEqual(revision.stateValue, .inReview)
            XCTAssertEqual(revision.templateKey, "pickup_time")
            let storedHash = try await Self.stored(h, id).1.definitionHash()
            XCTAssertEqual(revision.definitionHash, storedHash)
            try await eq(try await LoopPublicationRecord.query(on: h.db).count(), 0, "submitting never publishes")
            for action in ["loop.submitted", "loop.studio_submitted", "loop.studio_draft_saved"] {
                try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == action).count() >= 1, action)
            }
            // The same document can't be queued twice; there is no publish route.
            let twice = try await h.formPost("\(draft)/submit", owner, [("version", version)])
            XCTAssertEqual(twice.status, .conflict, twice.text)
            let publish = try await h.formPost("\(draft)/publish", owner, [("version", version)])
            XCTAssertEqual(publish.status, .notFound)
            let rawJSON = try await h.formPost("/dashboard/loops", owner, [("definition", "{}")])
            XCTAssertEqual(rawJSON.status, .notFound, "no free-schema submission path")
            // The status tracker shows the four stages.
            let page = try await h.page(draft, owner)
            for stage in ["1. Automated checks", "2. Viadere review", "3. Second Viadere reviewer", "4. Signed publication", "Waiting for a Viadere reviewer"] {
                XCTAssertTrue(page.text.contains(stage), stage)
            }
            // Viadere's reviewer decides; the reviewer's message reaches the business through the tracker.
            let world = try await LoopWorld.build(h, business: try await h.testBusiness(businessId), tag: "studio")
            _ = try await world.publications.review(revisionId: revision.id!, reviewerId: world.reviewer1, decision: .requestChanges, reason: "Say which store to come to.")
            let tracked = try await h.page(draft, owner)
            XCTAssertTrue(tracked.text.contains("Viadere reviewer: Say which store to come to."))
            XCTAssertTrue(tracked.text.contains("Changes requested"))
            // A structural change leaves the fast path; the new revision is reviewed again and then published by Viadere only.
            let added = try await Self.edit(h, owner, id, op: "add_field:0", ["s0_new_field": "yes_no"])
            XCTAssertEqual(added.status, .seeOther, added.text)
            let labeled = try await Self.edit(h, owner, id, ["s0_f1_label": "Need a bag?", "s1_body": "We'll have it ready at the Main Street store."])
            XCTAssertEqual(labeled.status, .seeOther, labeled.text)
            let second = try await h.formPost("\(draft)/submit", owner, [("version", try await Self.version(h, id))])
            XCTAssertEqual(second.status, .seeOther, second.text)
            let latest = try await XCTUnwrapAsync(try await LoopRevisionRecord.query(on: h.db).filter(\.$businessId == businessId).sort(\.$revision, .descending).first())
            XCTAssertEqual(latest.revision, 2)
            XCTAssertNil(latest.templateKey)
            XCTAssertEqual(latest.stateValue, .inReview)
            let decided = try await world.publications.review(revisionId: latest.id!, reviewerId: world.reviewer1, decision: .approve, reason: "Clear and complete.")
            XCTAssertEqual(decided.stateValue, .published)
            let done = try await h.page(draft, owner)
            XCTAssertTrue(done.text.contains("Signed and published"))
        }
    }

    // MARK: Editor operations and accessibility

    func testEditorOperationsAreBoundedAndTheStudioIsKeyboardAccessible() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let id = try await Self.createDraft(h, owner, template: "acknowledge")
            for (op, changes) in [("add_step", ["new_step_type": "form"]), ("add_field:1", ["s1_new_field": "single_choice"]), ("add_option:1:0", [:]),
                                  ("add_action:1", [:]), ("down:0", [:])] {
                let result = try await Self.edit(h, owner, id, op: op, changes)
                XCTAssertEqual(result.status, .seeOther, "\(op): \(result.text.prefix(300))")
            }
            let (_, definition) = try await Self.stored(h, id)
            XCTAssertEqual(definition.steps.map(\.type), [.form, .summary, .result], "the new form step was inserted before the result, then moved first")
            XCTAssertEqual(definition.steps[0].fields.first?.type, .singleChoice)
            XCTAssertEqual(definition.steps[0].fields.first?.options?.count, 3)
            XCTAssertEqual(definition.steps[0].actions.first?.action, "select_option")
            // Caps: no more than the platform limits.
            for _ in 0..<LoopLimits.maxActionsPerStep { _ = try await Self.edit(h, owner, id, op: "add_action:0") }
            try await eq(try await Self.stored(h, id).1.steps[0].actions.count, LoopLimits.maxActionsPerStep)
            let tooMany = try await Self.edit(h, owner, id, op: "add_action:0")
            XCTAssertEqual(tooMany.status, .unprocessableEntity)
            let bogus = try await Self.edit(h, owner, id, op: "remove_step:99")
            XCTAssertEqual(bogus.status, .unprocessableEntity)
            // Every form control has a label; the page uses fieldsets with legends and no script.
            let page = try await h.page("\(Self.path)/drafts/\(id.uuidString.lowercased())", owner)
            let ids = Self.matches("<(?:input|select|textarea) [^>]*id=\"([^\"]+)\"", in: page.text).map { $0[1] }
            XCTAssertFalse(ids.isEmpty)
            for control in ids { XCTAssertTrue(page.text.contains("<label for=\"\(control)\""), "label for \(control)") }
            for m in Self.matches("<input ([^>]*)>", in: page.text) where (Self.attribute("type", in: " " + m[1]) ?? "text") == "checkbox" {
                XCTAssertTrue(page.text.contains("<label class=\"ck\"><input \(m[1])>"), "checkbox wrapped in its label")
            }
            XCTAssertTrue(page.text.contains("<legend>Step 1: Questions (first)</legend>"))
            XCTAssertTrue(page.text.contains("aria-label=\"Remove button 1 of step 1\""))
            XCTAssertFalse(page.text.lowercased().contains("<script"))
            XCTAssertTrue(page.text.contains("<h2 id=\"preview\">Preview</h2>"))
            // The first submit button (the one Enter triggers) saves.
            let firstButton = try XCTUnwrap(Self.matches("<button ([^>]*)>", in: String(page.text[page.text.range(of: "aria-label=\"Loop editor\"")!.upperBound...])).first?[1])
            XCTAssertTrue(firstButton.contains("value=\"save\""), firstButton)
        }
    }

    // MARK: WP-3.8 parity: the web renderer reproduces the golden landmarks

    static var goldenDirectory: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Packages/ViadereCore/Tests/ViadereCoreTests/Golden/presentation-trees", isDirectory: true)
    }

    struct Golden: Decodable {
        var name: String
        var tree: PresentationTree
        var landmarks: PresentationLandmarks
    }

    /// Landmarks read back from rendered HTML: node kinds and protected flags from `data-node` / `data-protected`, actions from
    /// `data-action`, visible text with every tag removed.
    static func landmarks(fromHTML html: String) -> (kinds: [String], protected: [String], actions: Int, text: String) {
        let nodes = matches("data-node=\"([a-z_]+)\"( data-protected=\"true\")?", in: html)
        let text = (try! NSRegularExpression(pattern: "<[^>]*>"))
            .stringByReplacingMatches(in: html, range: NSRange(location: 0, length: (html as NSString).length), withTemplate: "\u{1F}")
        return (nodes.map { $0[1] }, nodes.filter { !$0[2].isEmpty }.map { $0[1] }, matches("data-action=\"", in: html).count, text)
    }

    func testWebRendererReproducesTheGoldenTreeLandmarks() throws {
        let files = try FileManager.default.contentsOfDirectory(at: Self.goldenDirectory, includingPropertiesForKeys: nil).filter { $0.pathExtension == "json" }
        XCTAssertGreaterThanOrEqual(files.count, 17, "goldens from Packages/ViadereCore (WP-3.8)")
        var kinds = Set<String>()
        for file in files.sorted(by: { $0.path < $1.path }) {
            let golden = try JSONDecoder().decode(Golden.self, from: Data(contentsOf: file))
            // The file's landmarks are the tree's (the Core suite checks the tree against the builder).
            XCTAssertEqual(PresentationLandmarks(golden.tree), golden.landmarks, golden.name)
            let html = LoopWebRenderer.fragment(golden.tree)
            let found = Self.landmarks(fromHTML: html)
            XCTAssertEqual(found.kinds, golden.landmarks.nodeKinds, "\(golden.name): node order")
            XCTAssertEqual(found.protected, golden.landmarks.protectedKinds, "\(golden.name): protected nodes")
            XCTAssertEqual(found.actions, golden.landmarks.actionCount, "\(golden.name): action count")
            XCTAssertEqual(found.kinds.contains("attribution_bar"), golden.landmarks.attributionBar, "\(golden.name): attribution bar")
            XCTAssertEqual(found.kinds.dropFirst().first == "attribution_bar", golden.landmarks.attributionFirst, "\(golden.name): attribution first")
            // Every visible text, escaped, in reading order.
            var cursor = found.text.startIndex
            for text in golden.landmarks.texts {
                guard let range = found.text.range(of: DashboardUI.esc(text), range: cursor..<found.text.endIndex) else {
                    XCTFail("\(golden.name): \"\(text)\" missing or out of order"); break
                }
                cursor = range.upperBound
            }
            XCTAssertFalse(html.lowercased().contains("<script"))
            kinds.formUnion(found.kinds)
            // The whole document renders too, with brand values only from the (clamped) tree style.
            let document = LoopWebRenderer.document(screens: [LoopPreview.Screen(label: golden.name, tree: golden.tree, confirmation: false)])
            XCTAssertTrue(document.css.contains("--p:\(golden.tree.style.palette.light.primary.hex)"))
            XCTAssertTrue(document.html.contains(LoopWebRenderer.previewLabel))
        }
        XCTAssertEqual(kinds.count, 12, "every node kind rendered: \(kinds.sorted())")
    }
}
