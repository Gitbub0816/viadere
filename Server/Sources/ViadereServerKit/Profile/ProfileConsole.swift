import Fluent
import Foundation
import Vapor
import ViadereCore

/// The business console step "Customer profile access" (onboarding checklist and `Organization`): pick the profile categories to ask Viadere
/// for, with a justification where required. Submitting only records requests (`ProfileCategoryService.submit`); an operator decides.
private struct CategoryForm: Content {
    var categories: [String]?
    var contact: String?
    var personal: String?
    var birthdate: String?
    var travel: String?
    var memberships: String?
    var vehicle: String?
    var home: String?
    var work: String?
    var verified: String?

    func justification(for category: ProfileCategory) -> String? {
        switch category {
        case .contact: contact
        case .personal: personal
        case .birthdate: birthdate
        case .travel: travel
        case .memberships: memberships
        case .vehicle: vehicle
        case .home: home
        case .work: work
        case .verified: verified
        }
    }
}

private struct DecisionForm: Content {
    var decision: String
    var justification: String?
    var reviewReference: String?
}

private struct RevokeCategoryForm: Content {
    var category: String
    var justification: String?
}

enum ProfileConsole {
    static let path = "/dashboard/organization/profile-access"

    static func register(_ pages: any RoutesBuilder) {
        pages.get("dashboard", "organization", "profile-access") { req in try await page(req) }
        pages.post("dashboard", "organization", "profile-access") { req -> Response in
            let (p, businessId) = try req.businessDashboard
            guard p.can(.manageOrganization) else { throw APIError.forbidden }
            let form = try req.content.decode(CategoryForm.self)
            let chosen = (form.categories ?? []).compactMap(ProfileCategory.init(rawValue:))
            guard chosen.count == (form.categories ?? []).count else { throw APIError.validation("Unknown category.", details: ["categories": "invalid"]) }
            try await ProfileCategoryService(db: req.db, ctx: req.ctx).submit(businessId: businessId,
                selections: chosen.map { .init(category: $0, justification: form.justification(for: $0)) }, requestedBy: p.user.id)
            return DashboardResponses.redirect("\(path)?m=requested")
        }
        pages.post("dashboard", "organization", "profile-access", ":id", "withdraw") { req -> Response in
            let (p, businessId) = try req.businessDashboard
            guard p.can(.manageOrganization) else { throw APIError.forbidden }
            try await ProfileCategoryService(db: req.db, ctx: req.ctx).withdraw(businessId: businessId, requestId: try req.uuid("id"))
            return DashboardResponses.redirect("\(path)?m=withdrawn")
        }
    }

    /// One line for the onboarding checklist.
    static func checklistDetail(allowed: Set<ProfileCategory>, pending: Int) -> String {
        if !allowed.isEmpty {
            return "Allowed: \(DashboardUI.esc(allowed.sorted().map(\.title).joined(separator: ", ")))." + (pending > 0 ? " \(pending) awaiting review." : "")
                + " <a href=\"\(path)\">Review</a>"
        }
        if pending > 0 { return "\(pending) categor\(pending == 1 ? "y" : "ies") awaiting Viadere's review. <a href=\"\(path)\">Review</a>" }
        return "Optional. Choose which customer profile details you may ask customers to share. <a href=\"\(path)\">Choose categories</a>"
    }

    private static func page(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.viewOrganization) || p.can(.manageOrganization) else { throw APIError.forbidden }
        let allowed = try await EntitlementService(db: req.db, ctx: req.ctx).snapshot(businessId: businessId).profileCategories
        let requests = try await ProfileCategoryService(db: req.db, ctx: req.ctx).requests(businessId: businessId)
        let pending = Set(requests.filter { $0.status == "pending" }.compactMap(\.categoryValue))
        let canManage = p.can(.manageOrganization)
        let csrf = DashboardUI.csrf(p)
        let rows = ProfileCategory.allCases.map { category -> [String] in
            let state = allowed.contains(category) ? DashboardFormat.badge("Allowed", "ok") : (pending.contains(category) ? DashboardFormat.badge("Awaiting review", "wa") : DashboardFormat.badge("Not allowed", "mu"))
            let fields = ProfileCatalog.fields(in: category).map(\.title).joined(separator: ", ")
            return ["<strong>\(DashboardUI.esc(category.title))</strong><br><span class=\"mu sm\">\(DashboardUI.esc(fields))</span>",
                    category.requiresJustification ? "Written justification" : "Review only", state]
        }
        var body = """
        <div class="card"><h2>Customer profile access</h2>\
        <p>Customers can keep a profile in Viadere and choose, field by field, what each business may see. You can only ask for fields in the categories Viadere allows your organization. Nothing is allowed by default; every customer still decides for themselves and can revoke at any time.</p>\
        \(DashboardFormat.table(["Category", "Needs", "State"], rows, caption: "Profile categories"))</div>
        """
        let requestable = ProfileCategory.allCases.filter { !allowed.contains($0) && !pending.contains($0) }
        if canManage, !requestable.isEmpty {
            let boxes = requestable.map { category -> String in
                let note = category.requiresJustification
                    ? "<label for=\"j-\(category.rawValue)\">Why do you need \(DashboardUI.esc(category.title.lowercased()))? (required, 20+ characters)</label><textarea id=\"j-\(category.rawValue)\" name=\"\(category.rawValue)\" maxlength=\"1000\"></textarea>"
                    : "<label for=\"j-\(category.rawValue)\">Purpose (optional)</label><textarea id=\"j-\(category.rawValue)\" name=\"\(category.rawValue)\" maxlength=\"1000\"></textarea>"
                return "<fieldset><legend><label class=\"ck\"><input type=\"checkbox\" name=\"categories[]\" value=\"\(category.rawValue)\"> \(DashboardUI.esc(category.title))</label></legend><p class=\"mu sm\">\(DashboardUI.esc(category.summary))</p>\(note)</fieldset>"
            }.joined()
            body += "<div class=\"card\"><h2>Ask for categories</h2><form method=\"post\" action=\"\(path)\">\(csrf)\(boxes)<p><button class=\"btn\" type=\"submit\">Send for review</button></p></form>"
                + "<p class=\"mu sm\">Viadere reviews each category and may allow fewer than you ask for. Health, government ID, payment and other sensitive data can never be requested.</p></div>"
        }
        let history = requests.map { row -> [String] in
            let action = canManage && row.status == "pending"
                ? "<form method=\"post\" action=\"\(path)/\(row.id!.uuidString.lowercased())/withdraw\">\(csrf)<button class=\"btn s sm\" type=\"submit\">Withdraw</button></form>" : ""
            return [DashboardUI.esc(row.categoryValue?.title ?? row.category), DashboardUI.esc(row.status), DashboardFormat.date(row.createdAt),
                    DashboardUI.esc(row.decisionNote ?? ""), action]
        }
        body += "<div class=\"card\"><h2>Requests</h2>\(DashboardFormat.table(["Category", "Status", "Asked", "Viadere's note", ""], history, empty: "No requests yet.", caption: "Category requests"))</div>"
        let flash = ["requested": "Sent to Viadere for review.", "withdrawn": "Request withdrawn."][req.query[String.self, at: "m"] ?? ""]
        return DashboardUI.businessPage(p, title: "Customer profile access", active: "/dashboard/organization", subtitle: "Which profile details you may ask customers for.",
                                        flash: flash, body: body)
    }
}

/// Operator review of profile-category requests. Same realm and rules as the entitlements page: CSRF, a fresh passkey assertion for every
/// change, and every change audited with the operator as actor.
enum ProfileOperatorRoutes {
    static func register(_ app: Application) {
        let pages = app.routes.grouped(DashboardPageErrorMiddleware()).grouped(DashboardAuthMiddleware(realm: .operator))
        pages.get("operator", "businesses", ":id", "profile-categories") { req in try await page(req) }
        pages.post("operator", "businesses", ":id", "profile-categories", ":requestId", "decide") { req -> Response in
            let p = try operatorPrincipal(req)
            let id = try req.uuid("id")
            let next = "/operator/businesses/\(id.uuidString.lowercased())/profile-categories"
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: next) }
            let form = try req.content.decode(DecisionForm.self)
            guard ["approve", "deny"].contains(form.decision) else { throw APIError.validation("Choose approve or deny.", details: ["decision": "invalid"]) }
            try await ProfileCategoryService(db: req.db, ctx: req.ctx).decide(businessId: id, requestId: try req.uuid("requestId"), approve: form.decision == "approve",
                                                                              operatorId: p.user.id!, justification: form.justification ?? "", reviewReference: form.reviewReference)
            return DashboardResponses.redirect("\(next)?m=decided")
        }
        pages.post("operator", "businesses", ":id", "profile-categories", "revoke") { req -> Response in
            let p = try operatorPrincipal(req)
            let id = try req.uuid("id")
            let next = "/operator/businesses/\(id.uuidString.lowercased())/profile-categories"
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: next) }
            let form = try req.content.decode(RevokeCategoryForm.self)
            guard let category = ProfileCategory(rawValue: form.category) else { throw APIError.validation("Choose a category.", details: ["category": "invalid"]) }
            try await EntitlementService(db: req.db, ctx: req.ctx).revoke(businessId: id, profileCategory: category, actor: .operatorUser(p.user.id!),
                                                                          justification: form.justification ?? "")
            return DashboardResponses.redirect("\(next)?m=revoked")
        }
    }

    private static func operatorPrincipal(_ req: Request) throws -> DashboardPrincipal {
        let p = try req.dashboard
        guard p.realm == .operator else { throw APIError.forbidden }
        return p
    }

    private static func page(_ req: Request) async throws -> Response {
        let p = try operatorPrincipal(req)
        let id = try req.uuid("id")
        guard let business = try await BusinessRecord.find(id, on: req.db) else { throw APIError.notFound }
        let allowed = try await EntitlementService(db: req.db, ctx: req.ctx).snapshot(businessId: id).profileCategories
        let requests = try await ProfileCategoryService(db: req.db, ctx: req.ctx).requests(businessId: id)
        let base = "/operator/businesses/\(id.uuidString.lowercased())/profile-categories"
        let csrf = DashboardUI.csrf(p)
        let pendingRows = requests.filter { $0.status == "pending" }.map { row -> [String] in
            let category = row.categoryValue
            let reference = category?.requiresReviewReference == true
                ? "<label for=\"r-\(row.id!)\">Heightened review reference (required)</label><input id=\"r-\(row.id!)\" name=\"reviewReference\" type=\"text\" maxlength=\"120\">" : ""
            let form = "<form method=\"post\" action=\"\(base)/\(row.id!.uuidString.lowercased())/decide\">\(csrf)"
                + "<label for=\"j-\(row.id!)\">Your justification (approve: 20+ characters)</label><textarea id=\"j-\(row.id!)\" name=\"justification\" maxlength=\"1000\" required></textarea>\(reference)"
                + "<button class=\"btn sm\" name=\"decision\" value=\"approve\" type=\"submit\">Allow</button> <button class=\"btn d sm\" name=\"decision\" value=\"deny\" type=\"submit\">Deny</button></form>"
            return [DashboardUI.esc(category?.title ?? row.category), DashboardUI.esc(row.justification ?? "(none)"), DashboardFormat.date(row.createdAt), form]
        }
        let allowedRows = allowed.sorted().map { category -> [String] in
            [DashboardUI.esc(category.title), "<form method=\"post\" action=\"\(base)/revoke\">\(csrf)<input type=\"hidden\" name=\"category\" value=\"\(category.rawValue)\">"
                + "<input name=\"justification\" type=\"text\" maxlength=\"300\" required placeholder=\"Why is it revoked?\" aria-label=\"Revocation reason\"><button class=\"btn d sm\" type=\"submit\">Revoke</button></form>"]
        }
        let decided = requests.filter { $0.status != "pending" }.map { row -> [String] in
            [DashboardUI.esc(row.categoryValue?.title ?? row.category), DashboardUI.esc(row.status), DashboardUI.esc(row.decidedBy ?? ""), DashboardFormat.optional(row.decidedAt),
             DashboardUI.esc(row.decisionNote ?? "")]
        }
        let body = """
        <div class="card"><h2>\(DashboardUI.esc(business.displayName))</h2><p class="mu sm">A business may ask customers only for profile fields in the categories allowed here, and reads only what each customer granted. Nothing is allowed by default. You can only decide categories the business asked for, and may allow fewer than it asked. Every change needs your passkey and is audited.</p></div>\
        <div class="card"><h2>Awaiting review</h2>\(DashboardFormat.table(["Category", "Business justification", "Asked", ""], pendingRows, empty: "Nothing to review.", caption: "Pending category requests"))</div>\
        <div class="card"><h2>Allowed</h2>\(DashboardFormat.table(["Category", ""], allowedRows, empty: "No category is allowed.", caption: "Allowed profile categories"))</div>\
        <div class="card"><h2>Decided</h2>\(DashboardFormat.table(["Category", "Status", "By", "When", "Note"], decided, empty: "No decisions yet.", caption: "Decided category requests"))</div>
        """
        let flash = ["decided": "Decision recorded.", "revoked": "Category revoked. The business loses it on its next request."][req.query[String.self, at: "m"] ?? ""]
        return DashboardUI.operatorPage(p, title: "Profile categories", active: "/operator/businesses", subtitle: "Customer profile access for this business.", flash: flash, body: body)
    }
}
