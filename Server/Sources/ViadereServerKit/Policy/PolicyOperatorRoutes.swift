import Fluent
import Foundation
import Vapor
import ViadereCore

private struct EntitlementForm: Content {
    var kind: String
    var value: String
    var justification: String?
    var reviewReference: String?
    /// Legacy approval only: how long the grant lasts (1...180 days, never past the platform sunset).
    var expiresInDays: String?
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
        ProfileOperatorRoutes.register(app)
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
            case BusinessEntitlementRecord.legacyKind:
                guard let days = form.expiresInDays.flatMap({ Int($0) }), (1...180).contains(days) else {
                    throw APIError.validation("Choose how many days (1 to 180).", details: ["expiresInDays": "invalid"])
                }
                try await service.grantLegacyApproval(businessId: id, actor: actor, justification: form.justification ?? "",
                                                      expiresAt: req.ctx.now.addingTimeInterval(TimeInterval(days) * 86_400))
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
            case BusinessEntitlementRecord.legacyKind:
                try await service.revokeLegacyApproval(businessId: id, actor: actor, justification: form.justification ?? "")
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
                action = ConsoleUI.confirm("Revoke", ariaLabel: "Revoke \(definition.capability.rawValue)", "<form method=\"post\" action=\"\(base)/revoke\">\(csrf)<input type=\"hidden\" name=\"kind\" value=\"capability\"><input type=\"hidden\" name=\"value\" value=\"\(definition.capability.rawValue)\">"
                    + "<input name=\"justification\" type=\"text\" maxlength=\"300\" required placeholder=\"Why is it revoked?\" aria-label=\"Revocation reason\"><p class=\"help\">Every key of the business loses it on its next request.</p><button class=\"btn dd sm\" type=\"submit\">\(ConsoleUI.icon(.key))Revoke</button></form>")
            }
            return ["<code>\(definition.capability.rawValue)</code>", "Tier \(definition.minimumTier.rawValue)", DashboardFormat.badge(baseline ? "Default" : (held ? "Granted" : "Not granted"), held ? "ok" : "mu"), action]
        }
        let capabilityOptions = CapabilityCatalog.definitions.filter { !Capability.messaging.contains($0.capability) }.map {
            "<option value=\"\($0.capability.rawValue)\">\($0.capability.rawValue) (tier \($0.minimumTier.rawValue))</option>"
        }.joined()
        let tierOptions = BusinessRiskTier.allCases.filter { !BusinessRiskTier.baseline.contains($0) }.map { "<option value=\"\($0.rawValue)\">Tier \($0.rawValue)</option>" }.joined()
        let revokeTierButtons = BusinessRiskTier.allCases.filter { snapshot.tiers.contains($0) && !BusinessRiskTier.baseline.contains($0) }.map { tier in
            ConsoleUI.confirm("Revoke tier \(tier.rawValue)", "<form method=\"post\" action=\"\(base)/revoke\">\(csrf)<input type=\"hidden\" name=\"kind\" value=\"tier\"><input type=\"hidden\" name=\"value\" value=\"\(tier.rawValue)\">"
                + "<input name=\"justification\" type=\"text\" maxlength=\"300\" required placeholder=\"Why is tier \(tier.rawValue) revoked?\" aria-label=\"Revocation reason\"><p class=\"help\">Its capabilities go with it.</p><button class=\"btn dd sm\" type=\"submit\">\(ConsoleUI.icon(.key))Revoke tier \(tier.rawValue) and its capabilities</button></form>")
        }.joined()
        let historyRows = history.map { row -> [String] in
            [DashboardUI.esc("\(row.kind) \(row.value)"), DashboardUI.esc(row.grantedBy), DashboardFormat.date(row.grantedAt), DashboardUI.esc(row.justification),
             row.revokedAt.map { "Revoked \(DashboardFormat.date($0)): \(DashboardUI.esc(row.revokeJustification ?? ""))" } ?? DashboardFormat.badge("Active", "ok")]
        }
        let summary = ConsoleUI.card("Risk tiers", description: "Every verified business holds Tier M and the three messaging capabilities. A category, a plan or a verified badge never grants anything else: only a justified grant below does, and every grant and revocation is audited. Changes need your passkey.",
                                     "<p>\(tiers)</p>" + (revokeTierButtons.isEmpty ? "" : "<div class=\"row\">\(revokeTierButtons)</div>"))
        let grant = ConsoleUI.card("Grant", description: "A capability needs its tier first.",
            ConsoleUI.form("\(base)/grant", csrf: csrf, "<div class=\"cols\">"
                + ConsoleUI.select("kind", label: "Type", id: "gk", options: [ConsoleUI.Option("tier", "Risk tier"), ConsoleUI.Option("capability", "Capability")])
                + ConsoleUI.selectHTML("value", label: "Tier or capability", id: "gt", optionsHTML: "<optgroup label=\"Tier\">\(tierOptions)</optgroup><optgroup label=\"Capability\">\(capabilityOptions)</optgroup>",
                                       help: "Pick a tier with type Risk tier, or a capability with type Capability.") + "</div>"
                + ConsoleUI.textarea("justification", label: "Purpose justification", id: "gj", help: "At least 20 characters: the purpose and why this business needs it.", required: true, attrs: ["maxlength": "1000"])
                + ConsoleUI.input("reviewReference", label: "Heightened review reference", id: "gr", help: "Required for every identity capability.", optional: true, attrs: ["maxlength": "120"])
                + ConsoleUI.formActions(ConsoleUI.button("Grant", passkey: true) + ConsoleUI.passkeyNote())))
        let legacy = ConsoleUI.card("Legacy approval path", description: "Approve v2 is the only approval path whose result the business verifies itself. The legacy authorize and high-risk authenticate interactions trust the relay's status, so they are closed for live traffic unless this entitlement is granted: justified, audited, at most 180 days, and never past \(ISO8601DateFormatter().string(from: LegacyApproval.sunset)). The sandbox is not affected.",
                                    actions: DashboardFormat.badge(snapshot.legacyApproval ? "Granted" : "Closed", snapshot.legacyApproval ? "wa" : "ok"), tone: snapshot.legacyApproval ? .warning : nil,
            "<form method=\"post\" action=\"\(base)/\(snapshot.legacyApproval ? "revoke" : "grant")\">\(csrf)<input type=\"hidden\" name=\"kind\" value=\"legacy\"><input type=\"hidden\" name=\"value\" value=\"\(LegacyApproval.entitlementValue)\">"
            + (snapshot.legacyApproval ? "" : ConsoleUI.input("expiresInDays", label: "Days", id: "ld", type: "number", help: "1 to 180.", required: true, attrs: ["min": "1", "max": "180"]))
            + ConsoleUI.textarea("justification", label: "Justification: why, and the plan to move to Approve v2", id: "lj", help: "At least 20 characters.", required: true, attrs: ["maxlength": "1000"])
            + ConsoleUI.formActions(ConsoleUI.button(snapshot.legacyApproval ? "Revoke legacy approval" : "Grant legacy approval", snapshot.legacyApproval ? .danger : .primary, passkey: true)) + "</form>")
        let profile = ConsoleUI.card("Customer profile categories", actions: ConsoleUI.linkButton("Review requests", href: "/operator/businesses/\(id.uuidString.lowercased())/profile-categories", small: true),
                                     "<p>\(snapshot.profileCategories.isEmpty ? "None allowed." : DashboardUI.esc(snapshot.profileCategories.sorted().map(\.title).joined(separator: ", ")))</p>")
        let body = summary
            + "<div class=\"split\"><div>" + ConsoleUI.card("Capabilities", DashboardFormat.table(["Capability", "Needs", "State", ""], capabilityRows, caption: "Capabilities of this business")) + "</div><div>\(grant)\(profile)</div></div>"
            + legacy
            + ConsoleUI.card("History", DashboardFormat.table(["Entitlement", "By", "When", "Justification", "State"], historyRows, empty: "No grants: Tier M defaults only.", caption: "Entitlement history"))
        return DashboardUI.operatorPage(p, title: "Entitlements", active: "/operator/businesses", subtitle: "Risk tiers and capabilities of \(business.displayName).", flash: flash(req),
                                        breadcrumbs: [ConsoleUI.Crumb("Operator", "/operator"), ConsoleUI.Crumb("Businesses", "/operator/businesses"),
                                                      ConsoleUI.Crumb(business.displayName, "/operator/businesses/\(id.uuidString.lowercased())"), ConsoleUI.Crumb("Entitlements", nil)], body: body)
    }

    /// A card for the business page linking to its entitlements.
    static func summaryCard(businessId: UUID, snapshot: EntitlementSnapshot) -> String {
        let tiers = snapshot.tiers.sorted { $0.rawValue < $1.rawValue }.map { "Tier \($0.rawValue)" }.joined(separator: ", ")
        let extra = snapshot.capabilities.filter { !Capability.messaging.contains($0) }.map(\.rawValue).sorted()
        return ConsoleUI.card("Entitlements", actions: ConsoleUI.linkButton("Review and change", href: "/operator/businesses/\(businessId.uuidString.lowercased())/entitlements", small: true),
                              "<p>\(DashboardUI.esc(tiers))" + (extra.isEmpty ? "" : " · " + DashboardUI.esc(extra.joined(separator: ", "))) + "</p>")
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
        let capabilityOptions = Capability.known.map { ConsoleUI.Option($0.rawValue, $0.rawValue) }
        let rules = try await admin.rules()
        let ruleRows = rules.map { row -> [String] in
            let action = row.active
                ? ConsoleUI.confirm("Remove", ariaLabel: "Remove the \(row.capability) rule", "<form method=\"post\" action=\"/operator/policy/rules/\(row.id?.uuidString.lowercased() ?? "")/remove\">\(csrf)<input name=\"reason\" type=\"text\" maxlength=\"300\" required placeholder=\"Why?\" aria-label=\"Reason\"><button class=\"btn dd sm\" type=\"submit\">\(ConsoleUI.icon(.key))Remove</button></form>")
                : DashboardFormat.badge("Removed", "mu")
            return [DashboardUI.esc(row.capability), DashboardUI.esc(row.kind.replacingOccurrences(of: "_", with: " ")), DashboardUI.esc(row.jurisdictions),
                    DashboardUI.esc(row.reason), action]
        }
        let disabled = switches.filter(\.disabled).count
        let switchCard = ConsoleUI.card("Kill switches", description: "Turn one capability off for the whole platform, or for one business. It is enforced on the next request (other instances within \(Int(PolicyService.cacheTTL)) seconds). Sensitive capabilities also fail closed if this table cannot be read.",
                                        actions: disabled > 0 ? DashboardFormat.badge("\(disabled) disabled", "dg") : DashboardFormat.badge("All enabled", "ok"),
            DashboardFormat.table(["Capability", "Scope", "State", "Reason", "Changed"], switchRows, empty: "No switches have been set.", caption: "Capability switches")
            + "<h3>Change a switch</h3>" + ConsoleUI.form("/operator/policy/switch", csrf: csrf, "<div class=\"cols\">"
                + ConsoleUI.select("capability", label: "Capability", id: "sc", options: capabilityOptions)
                + ConsoleUI.select("disabled", label: "Action", id: "sd", options: [ConsoleUI.Option("on", "Disable"), ConsoleUI.Option("off", "Re-enable")])
                + ConsoleUI.input("businessId", label: "Business id", id: "sb", placeholder: "Whole platform", optional: true, attrs: ["maxlength": "36", "spellcheck": "false"]) + "</div>"
                + ConsoleUI.input("reason", label: "Reason", id: "sr", help: "Recorded in the audit log.", required: true, attrs: ["maxlength": "300"])
                + ConsoleUI.formActions(ConsoleUI.button("Apply", .danger, passkey: true) + ConsoleUI.passkeyNote())))
        let rulesCard = ConsoleUI.card("Law and policy rules", description: "Block a capability in listed jurisdictions, or allow it only in them (an unknown jurisdiction then fails closed).",
            DashboardFormat.table(["Capability", "Rule", "Jurisdictions", "Reason", ""], ruleRows, empty: "No rules.", caption: "Jurisdiction rules")
            + "<h3>Add a rule</h3>" + ConsoleUI.form("/operator/policy/rules", csrf: csrf, "<div class=\"cols\">"
                + ConsoleUI.select("capability", label: "Capability", id: "rc", options: capabilityOptions)
                + ConsoleUI.select("kind", label: "Rule", id: "rk", options: [ConsoleUI.Option("jurisdiction_block", "Block in"), ConsoleUI.Option("jurisdiction_allow_only", "Allow only in")])
                + ConsoleUI.input("jurisdictions", label: "Jurisdictions", id: "rj", placeholder: "US, CA, US-CA", help: "Country or region codes, separated by commas.", required: true, attrs: ["maxlength": "400"]) + "</div>"
                + ConsoleUI.input("reason", label: "Reason", id: "rr", help: "Recorded in the audit log.", required: true, attrs: ["maxlength": "300"])
                + ConsoleUI.formActions(ConsoleUI.button("Add rule", passkey: true))))
        return DashboardUI.operatorPage(p, title: "Capability policy", active: "/operator/policy", subtitle: "Kill switches and law/policy rules.", flash: flash(req), body: switchCard + rulesCard)
    }

    private static func flash(_ req: Request) -> String? { req.query[String.self, at: "m"].flatMap { flashes[$0] } }
}
