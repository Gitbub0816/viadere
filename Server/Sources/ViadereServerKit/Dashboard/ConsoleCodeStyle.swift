import Fluent
import Foundation
import Vapor
import ViadereCore

/// "Your code" in Brand Studio (docs/SECURITY.md §2.105; permission `manageBrandKits`, a fresh passkey to save).
///
/// A business chooses how its **own** connect and install codes look: the Viadere code, black on white, a custom CKey style, or a QR code
/// in its colours. The form has no script: "Preview" posts the form and the server draws the candidate without saving; "Save" stores it.
/// Core's validator decides both times, and its reason is shown when it refuses. Nothing here reaches sign-in, approval or verification
/// pages: they draw `ViadereCodeStyle`, a type this editor cannot produce.
enum ConsoleCodeStyle {
    static let savePath = "/dashboard/brand/code-style"
    static let previewPath = "/dashboard/brand/code-style/preview"
    static let anchor = "code-style"

    enum Outcome {
        case candidate(BusinessCodeStyle)
        case refused(String)
    }

    /// A submitted form and what the validator said about it.
    struct Draft {
        var form: [String: String]
        var outcome: Outcome
    }

    static func draft(_ form: [String: String]) -> Draft {
        do { return Draft(form: form, outcome: .candidate(try BusinessCodeStyleService.style(from: form))) } catch let error as APIError {
            return Draft(form: form, outcome: .refused(error.message))
        } catch {
            return Draft(form: form, outcome: .refused("That style can't be used."))
        }
    }

    static func register(_ pages: any RoutesBuilder) {
        // Preview: validates and draws, stores nothing. Limited to people who may edit, like the form itself.
        pages.post("dashboard", "brand", "code-style", "preview") { req -> Response in
            let (p, businessId) = try req.businessDashboard
            guard p.can(.manageBrandKits) else { throw APIError.forbidden }
            _ = try await BrandKitService(db: req.db, ctx: req.ctx).editableBusiness(businessId)
            return try await ConsoleBrandStudio.studio(req, codeDraft: draft(try req.content.decode([String: String].self)))
        }
        pages.post("dashboard", "brand", "code-style") { req -> Response in
            let (p, businessId) = try ConsoleBrandStudio.mutating(req, next: ConsoleBrandStudio.path)
            let submitted = draft(try req.content.decode([String: String].self))
            guard case .candidate(let style) = submitted.outcome else { return try await ConsoleBrandStudio.studio(req, codeDraft: submitted) }
            try await BusinessCodeStyleService(db: req.db, ctx: req.ctx).save(businessId: businessId, style: style, actor: ConsoleBrandStudio.actor(p))
            return DashboardResponses.redirect(ConsoleBrandStudio.path + "?m=code-saved#\(anchor)")
        }
    }

    /// The editor's field values for a stored style, with suggestions from the approved Brand Kit where nothing is stored.
    static func fields(for style: BusinessCodeStyle, tokens: BrandTokens?) -> [String: String] {
        var custom = BusinessCodeStyle.suggestedCustom(from: tokens)
        var qr = BusinessCodeStyle.suggestedQR(from: tokens)
        var look = "concept"
        switch style.choice {
        case .ckeyPreset(let preset): look = preset.rawValue
        case .ckeyCustom(let spec): look = "custom"; custom = spec
        case .qr(let dark, let light): look = "qr"; qr = (dark, light)
        }
        var out = ["look": look, "background": custom.background.hex, "background_edge": custom.backgroundEdge.hex, "ink": custom.ink.hex, "ink_shade": custom.inkShade.hex,
                   "accent_percent": String(custom.accents.isEmpty ? 15 : custom.accentPercent), "modules": custom.modules.rawValue, "rings": custom.rings.rawValue,
                   "rays": custom.rays.rawValue, "bevel": String(custom.bevel), "shadow": String(custom.shadow), "texture": String(custom.texture),
                   "qr_dark": qr.dark.hex, "qr_light": qr.light.hex]
        if custom.backgroundEdge != custom.background { out["use_edge"] = "1" }
        if custom.inkShade != custom.ink { out["use_shade"] = "1" }
        for (index, accent) in custom.accents.prefix(CKeyStyleSpec.maxAccents).enumerated() {
            out["use_accent\(index + 1)"] = "1"
            out["accent\(index + 1)"] = accent.hex
        }
        return out
    }

    /// A colour for an `<input type="color">` value: a validated `#rrggbb`, or the fallback. Submitted text never reaches an attribute raw.
    static func colorValue(_ raw: String?, fallback: String) -> String {
        guard let raw, raw.utf8.count == 7, raw.hasPrefix("#"), let color = BrandColor(raw) else { return fallback.lowercased() }
        return color.hex.lowercased()
    }

    static func card(_ req: Request, p: DashboardPrincipal, businessId: UUID, draft: Draft?) async throws -> String {
        let service = BusinessCodeStyleService(db: req.db, ctx: req.ctx)
        let stored = try await service.stored(businessId: businessId) ?? .standard
        let effective = try await service.effective(businessId: businessId)
        let canManage = p.can(.manageBrandKits)
        let values: [String: String]
        if let form = draft?.form { values = form } else { values = fields(for: stored, tokens: try await service.approvedTokens(businessId: businessId)) }
        let disabled = canManage ? "" : " disabled"

        var notice = ""
        var shown = effective
        switch draft?.outcome {
        case .candidate(let style)?:
            shown = style
            notice = ConsoleUI.callout(.accent, title: "Preview", "<p class=\"sm\">This is how your code would look. Nothing is saved until you choose Save.</p>")
        case .refused(let message)?:
            notice = ConsoleUI.callout(.danger, title: "This style can't be used", "<p>\(DashboardUI.esc(message))</p><p class=\"sm\">Your saved style is unchanged.</p>")
        case nil:
            if stored != effective { notice = ConsoleUI.callout(.warning, "<p class=\"sm\">Viadere has paused branding for your business, so your codes use the Viadere style for now.</p>") }
        }

        func color(_ key: String, _ label: String, fallback: String, toggle: String? = nil) -> String {
            let use = toggle.map { "<label class=\"ck\"><input type=\"checkbox\" name=\"\($0)\" value=\"1\"\(values[$0] == "1" ? " checked" : "")\(disabled)> Use a \(label.lowercased())</label>" } ?? ""
            return "<div class=\"field\"><label for=\"cs-\(key)\">\(label)</label>\(use)<input id=\"cs-\(key)\" name=\"\(key)\" type=\"color\" value=\"\(colorValue(values[key], fallback: fallback))\"\(disabled)></div>"
        }
        func amount(_ key: String, _ label: String, max: Int, help: String? = nil) -> String {
            let value = values[key].flatMap { Int($0) }.map { String(min(Swift.max($0, 0), 100)) } ?? "0"
            return ConsoleUI.input(key, label: label, id: "cs-\(key)", type: "number", value: value, help: help, disabled: !canManage, attrs: ["min": "0", "max": String(max)], cls: "n")
        }
        func select<E: RawRepresentable & CaseIterable>(_ key: String, _ label: String, _: E.Type) -> String where E.RawValue == String {
            ConsoleUI.select(key, label: label, id: "cs-\(key)", options: E.allCases.map { ConsoleUI.Option($0.rawValue, $0.rawValue.capitalized, selected: $0.rawValue == values[key]) }, disabled: !canManage)
        }
        let looks = ConsoleUI.choices("look", legend: "Style", [
            ConsoleUI.Choice("concept", "The Viadere code", help: "Cream marks on a dark field. The default."),
            ConsoleUI.Choice("plain", "Black on white", help: "A plain CKey for print."),
            ConsoleUI.Choice("custom", "Your colours", help: "A CKey in the colours and shapes below."),
            ConsoleUI.Choice("qr", "QR code in your colours", help: "For when customers scan with a phone camera only."),
        ], selected: ["concept", "plain", "custom", "qr"].contains(values["look"] ?? "") ? values["look"] : "concept", required: true, disabled: !canManage)
        let accents = (1...CKeyStyleSpec.maxAccents).map { color("accent\($0)", "Accent \($0)", fallback: "#8C7550", toggle: "use_accent\($0)") }.joined()
        let custom = ConsoleUI.fieldset("Your colours (CKey)", help: "Every mark colour needs a contrast of at least 3:1 against both background colours, and marks must be all lighter or all darker than the background. Viadere checks this when you preview or save.",
            "<div class=\"cols\">" + color("background", "Background", fallback: "#FFFFFF") + color("background_edge", "Background edge", fallback: "#FFFFFF", toggle: "use_edge")
            + color("ink", "Marks", fallback: "#000000") + color("ink_shade", "Sheen shade", fallback: "#000000", toggle: "use_shade") + accents
            + amount("accent_percent", "Accent share (%)", max: 100, help: "How many of the marks use an accent colour.")
            + select("modules", "Squares", CKeyStyleSpec.ModuleShape.self) + select("rings", "Rings", CKeyStyleSpec.RingStyle.self) + select("rays", "Ray ends", CKeyStyleSpec.RayCap.self)
            + amount("bevel", "Bevel", max: BusinessCodeStyle.maxBevel) + amount("shadow", "Shadow", max: BusinessCodeStyle.maxShadow) + amount("texture", "Texture", max: BusinessCodeStyle.maxTexture)
            + "</div>")
        let qr = ConsoleUI.fieldset("QR colours", help: "Dark squares on a light background, with a contrast of at least 4.5:1. The quiet margin around the code is fixed.",
            "<div class=\"cols\">" + color("qr_dark", "Squares", fallback: QRCodeColorPolicy.defaultDark.hex) + color("qr_light", "Background", fallback: QRCodeColorPolicy.defaultLight.hex) + "</div>")
        var actions = ""
        if canManage {
            actions = ConsoleUI.formActions("<button class=\"btn s\" type=\"submit\" formaction=\"\(previewPath)\">Preview</button>" + ConsoleUI.button("Save code style", passkey: true), sep: true)
                + ConsoleUI.passkeyNote("Saving asks for your passkey. Preview doesn't.")
        }
        let form = ConsoleUI.form(savePath, csrf: DashboardUI.csrf(p), ariaLabel: "Code style", looks + custom + qr + actions)

        // The preview encodes the business's own plain connect link when it has a code, else the link domain's home.
        var sample = "https://\(req.ctx.config.linkDomain.host)/"
        if let record = try await BusinessCodeRecord.query(on: req.db).filter(\.$businessId == businessId).first(), let code = BusinessCode(parsing: record.canonical) {
            sample = ConnectLink(code: code, domain: req.ctx.config.linkDomain).urlString
        }
        let preview = "<h3>\(draft == nil ? "Your code now" : "Preview")</h3>" + (try DashboardRoutes.codePair(link: sample, style: shown, what: "your Viadere connect link"))
            + "<p class=\"mu sm\">Both codes open <code>\(DashboardUI.esc(sample))</code>. The plain QR code is always shown beside yours.</p>"
        return ConsoleUI.card("Your code", id: anchor,
                              description: "How the code on your campaign links and Loop install links looks. It never changes sign-in, approvals or verification: those always show Viadere's own code. A logo in the centre isn't available yet.",
                              notice + "<div class=\"split wa\"><div>\(form)</div><div>\(preview)</div></div>")
    }
}
