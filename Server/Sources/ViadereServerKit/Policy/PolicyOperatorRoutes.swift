import Fluent
import Foundation
import Vapor
import ViadereCore

private struct EntitlementForm: Content {
    var kind: String
    var value: String
    var justification: String?
    var reviewReference: String?
}

private struct SwitchForm: Content {
    var capability: String
    var disabled: String
    var reason: String?
    var businessId: String?
}

private struct RuleForm: Content {
    var capability: String
    var kind: String
    var jurisdictions: String
    var reason: String?
}

private struct ReasonOnlyForm: Content { var reason: String? }

/// Operator console: business entitlements (grant and revoke capabilities and risk tiers with a recorded justification),
/// per-capability kill switches and law/policy rules. Same realm as the rest of the operator console: its own cookie and
/// passkeys, CSRF on every form, a **fresh passkey assertion for every change**, and every change audited with the operator as
/// actor.
enum PolicyOperatorRoutes {
    private static let flashes = [
        "granted": "Entitlement granted and recorded.", "revoked": "Entitlement revoked. Every key of the business loses it on its next request.",
        "switch": "Capability switch updated.", "rule": "Policy rule added.", "rule-removed": "Policy rule removed.",
    ]

    static func register(_ app: Application) {
        let pages = app.routes.grouped(DashboardPageErrorMiddleware()).grouped(DashboardAuthMiddleware(realm: .operator))

        pages.get("operator", "businesses", ":id", "entitlements") { req in try await entitlementsPage(req) }
        pages.post("operator", "businesses", ":id", "entitlements", "grant") { req -> Response in
            let (p, id, next) = try prepare(req, "/operator/businesses/%@/entitlements")
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: next) }
            let form = try req.content.decode(EntitlementForm.self)
            let service = EntitlementService(db: req.db, ctx: req.ctx)
            let actor = EntitlementActor.operatorUser(p.user.id!)
            switch form.kind {
            case BusinessEntitlementRecord.tierKind:
                guard let tier = BusinessRiskTier(rawValue: form.value) else { throw APIError.validation("Choose a tier.", details: ["value": "invalid"]) }
                try await service.grant(businessId: id, tier: tier, actor: actor, justification: form.justification ?? "")
            case BusinessEntitlementRecord.capabilityKind:
                try await service.grant(businessId: id, capability: Capability(rawValue: form.value), actor: actor,
                                        justification: form.justification ?? "", reviewReference: form.reviewReference)
            default: throw APIError.validation("Choose a tier or a capability.", details: ["kind": "invalid"])
            }
            return DashboardResponses.redirect("\(next)?m=granted")
        }
        pages.post("operator", "businesses", ":id", "entitlements", "revoke") { req -> Response in
            let (p, id, next) = try prepare(req, "/operator/businesses/%@/entitlements")
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: next) }
            let form = try req.content.decode(EntitlementForm.self)
            let service = EntitlementService(db: req.db, ctx: req.ctx)
            let actor = EntitlementActor.operatorUser(p.user.id!)
            switch form.kind {
            case BusinessEntitlementRecord.tierKind:
                guard let tier = BusinessRiskTier(rawValue: form.value) else { throw APIError.validation("Choose a tier.", details: ["value": "invalid"]) }
                try await service.revoke(businessId: id, tier: tier, actor: actor, justification: form.justification ?? "")
            case BusinessEntitlementRecord.capabilityKind:
                try await service.revoke(businessId: id, capability: Capability(rawValue: form.value), actor: actor, justification: form.justification ?? "")
            default: throw APIError.validation("Choose a tier or a capability.", details: ["kind": "invalid"])
            }
            return DashboardResponses.redirect("\(next)?m=revoked")
        }

        pages.get("operator", "policy") { req in try await policyPage(req) }
        pages.post("operator", "policy", "switch") { req -> Response in
            let p = try operatorPrincipal(req)
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: "/operator/policy") }
            let form = try req.content.decode(SwitchForm.self)
            let business = form.businessId.flatMap { $0.isEmpty ? nil : $0 }.flatMap(UUID.init(uuidString:))
            if let raw = form.businessId, !raw.isEmpty, business == nil { throw APIError.validation("Enter a business id.", details: ["businessId": "invalid"]) }
            try await PolicyAdmin(db: req.db, ctx: req.ctx).setSwitch(capability: Capability(rawValue: form.capability), businessId: business,
                                                                     disabled: form.disabled == "on", reason: form.reason ?? "", actor: .operatorUser(p.user.id!))
            return DashboardResponses.redirect("/operator/policy?m=switch")
        }
        pages.post("operator", "policy", "rules") { req -> Response in
            let p = try operatorPrincipal(req)
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: "/operator/policy") }
            let form = try req.content.decode(RuleForm.self)
            guard let kind = PolicyRule.Kind(rawValue: form.kind) else { throw APIError.validation("Choose a rule type.", details: ["kind": "invalid"]) }
            try await PolicyAdmin(db: req.db, ctx: req.ctx).addRule(capability: Capability(rawValue: form.capability), kind: kind,
                                                                    jurisdictions: form.jurisdictions.split(whereSeparator: { ", ;".contains($0) }).map(String.init),
                                                                    reason: form.reason ?? "", actor: .operatorUser(p.user.id!))
            return DashboardResponses.redirect("/operator/policy?m=rule")
        }
        pages.post("operator", "policy", "rules", ":id", "remove") { req -> Response in
            let p = try operatorPrincipal(req)
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: "/operator/policy") }
            let form = try req.content.decode(ReasonOnlyForm.self)
            try await PolicyAdmin(db: req.db, ctx: req.ctx).deactivateRule(id: try req.uuid("id"), reason: form.reason ?? "", actor: .operatorUser(p.user.id!))
            return DashboardResponses.redirect("/operator/policy?m=rule-removed")
        }
    }

    private static func operatorPrincipal(_ req: Request) throws -> DashboardPrincipal {
        let p = try req.dashboard
        guard p.realm == .operator else { throw APIError.forbidden }
        return p
    }

    private static func prepare(_ req: Request, _ template: String) throws -> (DashboardPrincipal, UUID, String) {
        let p = try operatorPrincipal(req)
        let id = try req.uuid("id")
        return (p, id, template.replacingOccurrences(of: "%@", with: id.uuidString.lowercased()))
    }

    // MARK: Pages

    private static func entitlementsPage(_ req: Request) async throws -> Response {
        let p = try operatorPrincipal(req)
        let id = try req.uuid("id")
        guard let business = try await BusinessRecord.find(id, on: req.db) else { throw APIError.notFound }
        let service = EntitlementService(db: req.db, ctx: req.ctx)
        let snapshot = try await service.snapshot(businessId: id)
        let history = try await service.history(businessId: id)
        let base = "/operator/businesses/\(id.uuidString.lowercased())/entitlements"
        let csrf = DashboardUI.csrf(p)
        let tiers = BusinessRiskTier.allCases.map { tier in
            DashboardFormat.badge("Tier \(tier.rawValue)", snapshot.tiers.contains(tier) ? "ok" : "mu")
        }.joined(separator: " ")
        let capabilityRows = CapabilityCatalog.definitions.map { definition -> [String] in
            let held = snapshot.capabilities.contains(definition.capability)
            let baseline = Capability.messaging.contains(definition.capability)
            var action = ""
            if held && !baseline {
                action = "<form method=\"post\" action=\"\(base)/revoke\">\(csrf)<input type=\"hidden\" name=\"kind\" value=\"capability\"><input type=\"hidden\" name=\"value\" value=\"\(definition.capability.rawValue)\">"
                    + "<input name=\"justification\" type=\"text\" maxlength=\"300\" required placeholder=\"Why is it revoked?\" aria-label=\"Revocation reason\"><button class=\"btn d sm\" type=\"submit\">Revoke</button></form>"
            }
            return ["<code>\(definition.capability.rawValue)</code>", "Tier \(definition.minimumTier.rawValue)", DashboardFormat.badge(baseline ? "Default" : (held ? "Granted" : "Not granted"), held ? "ok" : "mu"), action]
        }
        let capabilityOptions = CapabilityCatalog.definitions.filter { !Capability.messaging.contains($0.capability) }.map {
            "<option value=\"\($0.capability.rawValue)\">\($0.capability.rawValue) (tier \($0.minimumTier.rawValue))</option>"
        }.joined()
        let tierOptions = BusinessRiskTier.allCases.filter { !BusinessRiskTier.baseline.contains($0) }.map { "<option value=\"\($0.rawValue)\">Tier \($0.rawValue)</option>" }.joined()
        let revokeTierButtons = BusinessRiskTier.allCases.filter { snapshot.tiers.contains($0) && !BusinessRiskTier.baseline.contains($0) }.map { tier in
            "<form method=\"post\" action=\"\(base)/revoke\">\(csrf)<input type=\"hidden\" name=\"kind\" value=\"tier\"><input type=\"hidden\" name=\"value\" value=\"\(tier.rawValue)\">"
                + "<input name=\"justification\" type=\"text\" maxlength=\"300\" required placeholder=\"Why is tier \(tier.rawValue) revoked?\" aria-label=\"Revocation reason\"><button class=\"btn d sm\" type=\"submit\">Revoke tier \(tier.rawValue) and its capabilities</button></form>"
        }.joined()
        let historyRows = history.map { row -> [String] in
            [DashboardUI.esc("\(row.kind) \(row.value)"), DashboardUI.esc(row.grantedBy), DashboardFormat.date(row.grantedAt), DashboardUI.esc(row.justification),
             row.revokedAt.map { "Revoked \(DashboardFormat.date($0)): \(DashboardUI.esc(row.revokeJustification ?? ""))" } ?? DashboardFormat.badge("Active", "ok")]
        }
        let body = """
        <div class="card"><h2>\(DashboardUI.esc(business.displayName))</h2><p>\(tiers)</p>\
        <p class="mu sm">Every verified business holds Tier M and the three messaging capabilities. A category, a plan or a verified badge never grants anything else: only a justified grant below does, and every grant and revocation is audited. Changes need your passkey.</p>\
        \(revokeTierButtons)</div>\
        <div class="card"><h2>Capabilities</h2>\(DashboardFormat.table(["Capability", "Needs", "State", ""], capabilityRows, caption: "Capabilities of this business"))</div>\
        <div class="card"><h2>Grant</h2><form method="post" action="\(base)/grant">\(csrf)\
        <div class="cols"><div><label for="gk">Type</label><select id="gk" name="kind"><option value="tier">Risk tier</option><option value="capability">Capability</option></select></div>\
        <div><label for="gt">Tier</label><select id="gt" name="value" aria-describedby="gh"><optgroup label="Tier">\(tierOptions)</optgroup><optgroup label="Capability">\(capabilityOptions)</optgroup></select><p id="gh" class="mu sm">Pick a tier with type Risk tier, or a capability with type Capability. A capability needs its tier first.</p></div></div>\
        <label for="gj">Purpose justification (required, 20+ characters)</label><textarea id="gj" name="justification" maxlength="1000" required></textarea>\
        <label for="gr">Heightened review reference (identity name and address only)</label><input id="gr" name="reviewReference" type="text" maxlength="120">\
        <button class="btn" type="submit">Grant</button></form></div>\
        <div class="card"><h2>History</h2>\(DashboardFormat.table(["Entitlement", "By", "When", "Justification", "State"], historyRows, empty: "No grants: Tier M defaults only.", caption: "Entitlement history"))</div>
        """
        return DashboardUI.operatorPage(p, title: "Entitlements", active: "/operator/businesses", subtitle: "Risk tiers and capabilities.", flash: flash(req), body: body)
    }

    /// A card for the business page linking to its entitlements.
    static func summaryCard(businessId: UUID, snapshot: EntitlementSnapshot) -> String {
        let tiers = snapshot.tiers.sorted { $0.rawValue < $1.rawValue }.map { "Tier \($0.rawValue)" }.joined(separator: ", ")
        let extra = snapshot.capabilities.filter { !Capability.messaging.contains($0) }.map(\.rawValue).sorted()
        return "<div class=\"card\"><h2>Entitlements</h2><p>\(DashboardUI.esc(tiers))" + (extra.isEmpty ? "" : " · " + DashboardUI.esc(extra.joined(separator: ", ")))
            + "</p><p><a class=\"btn s sm\" href=\"/operator/businesses/\(businessId.uuidString.lowercased())/entitlements\">Review and change</a></p></div>"
    }

    private static func policyPage(_ req: Request) async throws -> Response {
        let p = try operatorPrincipal(req)
        let admin = PolicyAdmin(db: req.db, ctx: req.ctx)
        let csrf = DashboardUI.csrf(p)
        let switches = try await admin.switches()
        let switchRows = switches.map { row -> [String] in
            [DashboardUI.esc(row.capability), DashboardUI.esc(row.scope), DashboardFormat.badge(row.disabled ? "Disabled" : "Enabled", row.disabled ? "dg" : "ok"),
             DashboardUI.esc(row.reason), DashboardFormat.date(row.updatedAt)]
        }
        let capabilityOptions = Capability.known.map { "<option value=\"\($0.rawValue)\">\($0.rawValue)</option>" }.joined()
        let rules = try await admin.rules()
        let ruleRows = rules.map { row -> [String] in
            let action = row.active ? "<form method=\"post\" action=\"/operator/policy/rules/\(row.id?.uuidString.lowercased() ?? "")/remove\">\(csrf)<input name=\"reason\" type=\"text\" maxlength=\"300\" required placeholder=\"Why?\" aria-label=\"Reason\"><button class=\"btn d sm\" type=\"submit\">Remove</button></form>" : DashboardFormat.badge("Removed", "mu")
            return [DashboardUI.esc(row.capability), DashboardUI.esc(row.kind.replacingOccurrences(of: "_", with: " ")), DashboardUI.esc(row.jurisdictions),
                    DashboardUI.esc(row.reason), action]
        }
        let body = """
        <div class="card"><h2>Kill switches</h2><p class="mu sm">Turn one capability off for the whole platform, or for one business. It is enforced on the next request (other instances within \(Int(PolicyService.cacheTTL)) seconds). Sensitive capabilities also fail closed if this table cannot be read.</p>\
        \(DashboardFormat.table(["Capability", "Scope", "State", "Reason", "Changed"], switchRows, empty: "No switches have been set.", caption: "Capability switches"))\
        <form method="post" action="/operator/policy/switch">\(csrf)<div class="cols">\
        <div><label for="sc">Capability</label><select id="sc" name="capability">\(capabilityOptions)</select></div>\
        <div><label for="sd">Action</label><select id="sd" name="disabled"><option value="on">Disable</option><option value="off">Re-enable</option></select></div>\
        <div><label for="sb">Business id (blank = whole platform)</label><input id="sb" name="businessId" type="text" maxlength="36"></div></div>\
        <label for="sr">Reason (required)</label><input id="sr" name="reason" type="text" maxlength="300" required><button class="btn d" type="submit">Apply</button></form></div>\
        <div class="card"><h2>Law and policy rules</h2><p class="mu sm">Block a capability in listed jurisdictions, or allow it only in them (an unknown jurisdiction then fails closed).</p>\
        \(DashboardFormat.table(["Capability", "Rule", "Jurisdictions", "Reason", ""], ruleRows, empty: "No rules.", caption: "Jurisdiction rules"))\
        <form method="post" action="/operator/policy/rules">\(csrf)<div class="cols">\
        <div><label for="rc">Capability</label><select id="rc" name="capability">\(capabilityOptions)</select></div>\
        <div><label for="rk">Rule</label><select id="rk" name="kind"><option value="jurisdiction_block">Block in</option><option value="jurisdiction_allow_only">Allow only in</option></select></div>\
        <div><label for="rj">Jurisdictions (US, CA, US-CA)</label><input id="rj" name="jurisdictions" type="text" maxlength="400" required></div></div>\
        <label for="rr">Reason (required)</label><input id="rr" name="reason" type="text" maxlength="300" required><button class="btn" type="submit">Add rule</button></form></div>
        """
        return DashboardUI.operatorPage(p, title: "Capability policy", active: "/operator/policy", subtitle: "Kill switches and law/policy rules.", flash: flash(req), body: body)
    }

    private static func flash(_ req: Request) -> String? { req.query[String.self, at: "m"].flatMap { flashes[$0] } }
}
