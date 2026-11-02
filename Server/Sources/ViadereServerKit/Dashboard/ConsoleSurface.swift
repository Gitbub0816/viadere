import Fluent
import Foundation
import Vapor
import ViadereCore

/// "Your Viadere page" (WP-1.6): the business chooses which standard Viadere modules its neutral home shows and in what order. It cannot add
/// text, links, navigation, styling or code; the verified profile always comes first; Loops are not offered in this release (the registry slot
/// stays inactive) and the reserved Shop module is never offered.
enum ConsoleSurface {
    static let path = "/dashboard/organization/page"

    /// Modules a business may choose, in registry order (profile is fixed first; gated and reserved modules are not offered).
    static var choosable: [ModuleDescriptor] {
        ModuleRegistry.v1.modules.filter { $0.availability == .active && $0.id != "profile" }
    }

    static func register(_ pages: any RoutesBuilder) {
        pages.get("dashboard", "organization", "page") { req in try await page(req) }
        pages.post("dashboard", "organization", "page") { req -> Response in
            let (p, businessId) = try req.businessDashboard
            guard p.can(.manageOrganization) else { throw APIError.forbidden }
            let form = try req.content.decode([String: String].self)
            let layout = try layout(from: form)
            try await SurfaceService(db: req.db, ctx: req.ctx).publish(businessId: businessId, layout: layout,
                                                                       actor: AuditActor(kind: .business, id: p.user.id?.uuidString.lowercased()))
            return DashboardResponses.redirect(path + "?m=page-published")
        }
    }

    /// Builds the layout from the form: `show_<module>=1` and `order_<module>=<1…8>`. Unknown fields are ignored; unknown modules cannot be named
    /// because only registry ids are read. The layout is then validated by `SurfaceService.publish`.
    static func layout(from form: [String: String]) throws -> SurfaceLayout {
        var chosen: [(order: Int, index: Int, module: String)] = []
        for (index, module) in choosable.enumerated() where form["show_\(module.id)"] == "1" {
            guard let order = Int(form["order_\(module.id)"] ?? "\(index + 1)"), (1...PageTemplate.businessHome.maxModules).contains(order) else {
                throw APIError.validation("Choose a position from 1 to \(PageTemplate.businessHome.maxModules).", details: ["order": "invalid"])
            }
            chosen.append((order, index, module.id))
        }
        chosen.sort { $0.order != $1.order ? $0.order < $1.order : $0.index < $1.index }
        let placements = [ModulePlacement(module: "profile", size: .regular)] + chosen.map { ModulePlacement(module: $0.module, size: .regular) }
        return SurfaceLayout(template: PageTemplate.businessHome.id, modules: placements)
    }

    private static func page(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.viewOrganization) || p.can(.manageOrganization) else { throw APIError.forbidden }
        let (layout, version) = try await SurfaceService(db: req.db, ctx: req.ctx).current(businessId: businessId)
        let canManage = p.can(.manageOrganization)
        let placed = layout.modules.map(\.module)
        let rows = choosable.enumerated().map { index, module -> String in
            let position = placed.firstIndex(of: module.id)
            let checked = position != nil ? " checked" : ""
            let order = position ?? (index + 1)
            let disabled = canManage ? "" : " disabled"
            return """
            <tr><td><label class="ck"><input type="checkbox" name="show_\(module.id)" value="1"\(checked)\(disabled)> \(DashboardUI.esc(module.accessibility.headingLabel))</label></td>\
            <td class="num"><label class="vh" for="o-\(module.id)">Position of \(DashboardUI.esc(module.accessibility.headingLabel))</label>\
            <input id="o-\(module.id)" name="order_\(module.id)" type="number" min="1" max="\(PageTemplate.businessHome.maxModules)" value="\(order)"\(disabled)></td></tr>
            """
        }.joined()
        let preview = layout.modules.enumerated().map { i, placement in
            "<li><span class=\"dot\" aria-hidden=\"true\">\(i + 1)</span><div><p class=\"ct\">\(DashboardUI.esc(ModuleRegistry.v1.module(placement.module)?.accessibility.headingLabel ?? placement.module))</p>\(i == 0 ? "<p class=\"cd\">Always first</p>" : "")</div></li>"
        }.joined()
        let current = ConsoleUI.card("What customers see", description: version == 0 ? "Viadere's standard page: you have not published your own yet." : "Published version \(version).",
                                     "<ol class=\"checklist\" aria-label=\"Modules on your page, in order\">\(preview)</ol>")
        let chooser = ConsoleUI.card("Choose modules", description: "Viadere draws every module, its wording and its security checks; you choose which standard modules appear and in what order. Your verified profile always comes first.",
            ConsoleUI.form(path, csrf: DashboardUI.csrf(p), """
            <div class="tw"><table><caption class="vh">Modules on your page</caption><thead><tr><th scope="col">Module</th><th scope="col" class="num">Position</th></tr></thead><tbody>\(rows)</tbody></table></div>\
            \(canManage ? ConsoleUI.formActions(ConsoleUI.button("Publish page") + "<span class=\"mu sm\">Customers see the new order the next time they open your page.</span>") : ConsoleUI.callout(.neutral, "<p class=\"sm\">Only an Owner or an Organization Admin can change this page.</p>"))
            """))
        let body = "<div class=\"split\"><div>\(chooser)</div><div>\(current)</div></div>"
        return DashboardUI.businessPage(p, title: "Your Viadere page", active: path, subtitle: "The standard business home customers open in the Viadere app.",
                                        flash: DashboardFormat.flash(req), body: body)
    }
}
