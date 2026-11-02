import Fluent
import Foundation
import Vapor
import ViadereCore

/// Operator review of Brand Kits (WP-2.8; FX-3 applied to brand content): the queue of new and edited kits and of uploaded images, approval,
/// rejection, takedown, and the `brand_kits` kill switch (global or per business). Every mutation needs a fresh passkey assertion; rejections,
/// takedowns and switch changes need a recorded reason; everything is audited as `brandkit.*` / `platform.switch_*` with the operator as actor.
enum OperatorBrand {
    static let path = "/operator/brand"

    static let flash: [String: String] = ["reviewed": "Review recorded.", "taken-down": "Taken down. Customers see neutral styling at once.", "switch": "Switch updated."]

    private static func principal(_ req: Request) throws -> DashboardPrincipal {
        let p = try req.dashboard
        guard p.realm == .operator else { throw APIError.forbidden }
        return p
    }

    private static func mutating(_ req: Request) throws -> DashboardPrincipal {
        let p = try principal(req)
        guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: path) }
        return p
    }

    private static func actor(_ p: DashboardPrincipal) -> AuditActor { AuditActor(kind: .operator_, id: p.user.id?.uuidString.lowercased()) }

    /// 8 to 300 printable characters (the same rule as every operator reason).
    static func reason(_ raw: String?, required: Bool) throws -> String? {
        let trimmed = (raw ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty, !required { return nil }
        guard (8...300).contains(trimmed.count), !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw APIError.validation("Record the reason (8 to 300 characters).", details: ["reason": "required"])
        }
        return trimmed
    }

    static func register(_ pages: any RoutesBuilder) {
        pages.get("operator", "brand") { req in try await queue(req) }
        pages.get("operator", "brand", "assets", ":id", "image") { req -> Response in
            _ = try principal(req)
            guard let asset = try await BrandAssetRecord.find(try req.uuid("id"), on: req.db),
                  let data = try await BrandAssetService(db: req.db, ctx: req.ctx, runtime: req.brandKits).bytes(of: asset) else { throw APIError.notFound }
            return BrandAssetService.imageResponse(data, cache: "private, no-store")
        }
        pages.get("operator", "brand", "kits", ":id", "preview") { req -> Response in
            _ = try principal(req)
            guard let record = try await BrandKitRecord.find(try req.uuid("id"), on: req.db),
                  let business = try await BusinessRecord.find(record.businessId, on: req.db) else { throw APIError.notFound }
            return try await ConsoleBrandStudio.preview(req, record: record, businessName: business.displayName)
        }
        pages.post("operator", "brand", "kits", ":id", ":decision") { req -> Response in
            let p = try mutating(req)
            let id = try req.uuid("id")
            let form = try req.content.decode([String: String].self)
            let service = BrandKitService(db: req.db, ctx: req.ctx)
            switch req.parameters.get("decision") {
            case "approve": try await service.approveKit(id: id, actor: actor(p), note: try reason(form["reason"], required: false))
            case "reject": try await service.rejectKit(id: id, actor: actor(p), reason: try reason(form["reason"], required: true)!)
            case "takedown":
                try await service.takeDownKit(id: id, actor: actor(p), reason: try reason(form["reason"], required: true)!)
                return DashboardResponses.redirect(path + "?m=taken-down")
            default: throw APIError.notFound
            }
            return DashboardResponses.redirect(path + "?m=reviewed")
        }
        pages.post("operator", "brand", "assets", ":id", ":decision") { req -> Response in
            let p = try mutating(req)
            let id = try req.uuid("id")
            let form = try req.content.decode([String: String].self)
            let service = BrandKitService(db: req.db, ctx: req.ctx)
            switch req.parameters.get("decision") {
            case "approve": try await service.reviewAsset(id: id, approve: true, actor: actor(p), reason: try reason(form["reason"], required: false))
            case "reject": try await service.reviewAsset(id: id, approve: false, actor: actor(p), reason: try reason(form["reason"], required: true))
            case "takedown":
                try await service.takeDownAsset(id: id, actor: actor(p), reason: try reason(form["reason"], required: true)!)
                return DashboardResponses.redirect(path + "?m=taken-down")
            default: throw APIError.notFound
            }
            return DashboardResponses.redirect(path + "?m=reviewed")
        }
        pages.post("operator", "brand", "switch") { req -> Response in
            let p = try mutating(req)
            let form = try req.content.decode([String: String].self)
            var business: UUID?
            if let raw = form["businessId"]?.trimmingCharacters(in: .whitespaces), !raw.isEmpty {
                guard let id = UUID(uuidString: raw) else { throw APIError.validation("Enter a business id.", details: ["businessId": "invalid"]) }
                business = id
            }
            let flags = PlatformFlags(db: req.db, ctx: req.ctx)
            let who = EntitlementActor.operatorUser(p.user.id!)
            if form["action"] == "off" {
                try await flags.clear(.brandKits, businessId: business, reason: form["reason"] ?? "", actor: who)
            } else {
                try await flags.set(.brandKits, businessId: business, value: "on", reason: form["reason"] ?? "", actor: who)
            }
            return DashboardResponses.redirect(path + "?m=switch")
        }
    }

    private static func reasonField(_ id: String, required: Bool) -> String {
        ConsoleUI.reason(id: id, label: required ? "Reason (recorded)" : "Note", required: required, help: required ? "8 to 300 characters; shown to the business." : "Recorded with the approval.")
    }

    static func queue(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let csrf = DashboardUI.csrf(p)
        let pendingKits = try await BrandKitRecord.query(on: req.db).filter(\.$status == BrandKitService.KitStatus.pendingReview.rawValue)
            .sort(\.$updatedAt, .ascending).limit(50).all()
        let pendingAssets = try await BrandAssetRecord.query(on: req.db).filter(\.$state == BrandKitService.AssetState.pendingReview.rawValue)
            .sort(\.$createdAt, .ascending).limit(50).all()
        let liveKits = try await BrandKitRecord.query(on: req.db).filter(\.$approvedJSON != nil).sort(\.$reviewedAt, .descending).limit(50).all()
        let liveAssets = try await BrandAssetRecord.query(on: req.db).filter(\.$state == BrandKitService.AssetState.ready.rawValue)
            .sort(\.$reviewedAt, .descending).limit(50).all()
        var names: [UUID: String] = [:]
        for id in Set(pendingKits.map(\.businessId) + pendingAssets.map(\.businessId) + liveKits.map(\.businessId) + liveAssets.map(\.businessId)) {
            names[id] = try await BusinessRecord.find(id, on: req.db)?.displayName ?? "?"
        }
        func business(_ id: UUID) -> String { "<a href=\"/operator/businesses/\(id.uuidString.lowercased())\">\(DashboardUI.esc(names[id] ?? "?"))</a> <code class=\"sm\">\(id.uuidString.lowercased())</code>" }
        func decision(_ kind: String, _ id: String, label: String) -> String {
            "<div class=\"cols\">"
                + ConsoleUI.form("\(path)/\(kind)/\(id)/approve", csrf: csrf, reasonField("\(kind == "kits" ? "ka" : "aa")-\(id)", required: false) + ConsoleUI.formActions(ConsoleUI.button("Approve", small: true, ariaLabel: "Approve \(label)", passkey: true)))
                + ConsoleUI.form("\(path)/\(kind)/\(id)/reject", csrf: csrf, reasonField("\(kind == "kits" ? "kr" : "ar")-\(id)", required: true) + ConsoleUI.formActions(ConsoleUI.button("Reject", .danger, small: true, ariaLabel: "Reject \(label)", passkey: true)))
                + "</div>"
        }

        var body = ConsoleUI.callout(.accent, title: "Brand-content rules", "<p class=\"sm\">No impersonation of another organization or of Viadere, no security or payment imagery, no health content (healthcare businesses are refused outright), nothing that imitates a verified badge or approval buttons. Approving a kit requires its images to be approved first. Every decision asks for your passkey.</p>")
        body += ConsoleUI.stats([ConsoleUI.Stat(String(pendingKits.count), "Kits waiting", tone: pendingKits.isEmpty ? nil : .accent), ConsoleUI.Stat(String(pendingAssets.count), "Images waiting", tone: pendingAssets.isEmpty ? nil : .accent),
                                 ConsoleUI.Stat(String(liveKits.count), "Live kits"), ConsoleUI.Stat(String(liveAssets.count), "Live images")])

        body += ConsoleUI.sectionTitle("Kits waiting for review", description: "Oldest first. The preview is the business's draft rendered in a sandbox.")
        if pendingKits.isEmpty { body += ConsoleUI.empty("No kits waiting", nil, icon: .check) }
        for k in pendingKits {
            let id = k.id!.uuidString.lowercased()
            let tokens = BrandKitService.draftKit(k)?.tokens
            let warnings = tokens.map(BrandPreview.contrastWarnings) ?? []
            var colors: [(String, String)] = []
            if let tokens {
                colors.append(("Primary", tokens.primary.hex))
                if let c = tokens.secondary { colors.append(("Secondary", c.hex)) }
                if let c = tokens.accent { colors.append(("Accent", c.hex)) }
                if let c = tokens.surface { colors.append(("Background", c.hex)) }
            }
            let facts = ConsoleUI.keyValues([("Business", business(k.businessId)), ("Kit", "\(DashboardUI.esc(k.name)) <code>\(DashboardUI.esc(k.kitKey))</code> v\(k.version)")]
                + colors.map { ($0.0, ConsoleUI.swatch($0.1)) })
                + (tokens == nil ? ConsoleUI.callout(.danger, "<p>Unreadable tokens.</p>") : "")
                + (warnings.isEmpty ? "" : ConsoleUI.callout(.warning, title: "\(warnings.count) contrast override(s)", "<ul>\(warnings.map { "<li>\(DashboardUI.esc($0))</li>" }.joined())</ul>"))
            body += ConsoleUI.card("\(names[k.businessId] ?? "?") · \(k.name)", actions: DashboardFormat.badge("Waiting", "wa"),
                "<div class=\"split wa\"><div>\(facts)<h3>Decision</h3>\(decision("kits", id, label: k.name))</div><div>"
                + ConsoleUI.preview(src: "\(path)/kits/\(id)/preview", title: "Preview of \(k.name), not exactly what customers see", width: 420, height: 640)
                + "<p class=\"sm\"><a href=\"\(path)/kits/\(id)/preview\">Open the preview on its own</a></p></div></div>")
        }

        body += ConsoleUI.sectionTitle("Images waiting for review", description: "Re-encoded PNGs, already stripped of metadata.")
        if pendingAssets.isEmpty { body += ConsoleUI.empty("No images waiting", nil, icon: .check) }
        let assetCards = pendingAssets.map { a -> String in
            let id = a.id!.uuidString.lowercased()
            return ConsoleUI.card("\(names[a.businessId] ?? "?") · \(a.slot)", description: "\(a.width) × \(a.height) · \(a.bytes / 1024) KB",
                "<p><img src=\"\(path)/assets/\(id)/image\" alt=\"Uploaded \(DashboardUI.esc(a.slot)) image\" width=\"160\" height=\"160\"></p>\(ConsoleUI.keyValues([("Business", business(a.businessId))]))\(decision("assets", id, label: "\(a.slot) image"))")
        }.joined()
        if !assetCards.isEmpty { body += "<div class=\"cols\">\(assetCards)</div>" }

        let liveKitRows = liveKits.map { k -> [String] in
            let id = k.id!.uuidString.lowercased()
            return [business(k.businessId), "\(DashboardUI.esc(k.name)) <code>\(DashboardUI.esc(k.kitKey))</code> live v\(k.approvedVersion ?? 0)",
                    ConsoleUI.confirm("Take down", ariaLabel: "Take down \(k.name)", ConsoleUI.form("\(path)/kits/\(id)/takedown", csrf: csrf, reasonField("kt-\(id)", required: true)
                        + "<p>Customers see neutral styling at once.</p>" + ConsoleUI.button("Take down", .dangerSolid, small: true, passkey: true)))]
        }
        let liveAssetRows = liveAssets.map { a -> [String] in
            let id = a.id!.uuidString.lowercased()
            return [business(a.businessId), "<img src=\"\(path)/assets/\(id)/image\" alt=\"Live \(DashboardUI.esc(a.slot)) image\" width=\"56\" height=\"56\"> \(DashboardUI.esc(a.slot))",
                    ConsoleUI.confirm("Take down", ariaLabel: "Take down this \(a.slot) image", ConsoleUI.form("\(path)/assets/\(id)/takedown", csrf: csrf, reasonField("at-\(id)", required: true)
                        + ConsoleUI.button("Take down", .dangerSolid, small: true, passkey: true)))]
        }
        body += ConsoleUI.sectionTitle("Live", description: "Take down anything that breaks the rules; customers see neutral styling at once.")
        body += "<div class=\"cols\">" + ConsoleUI.card("Live kits", DashboardFormat.table(["Business", "Kit", ""], liveKitRows, empty: "No live kits.", caption: "Live kits"))
            + ConsoleUI.card("Live images", DashboardFormat.table(["Business", "Image", ""], liveAssetRows, empty: "No live images.", caption: "Live images")) + "</div>"

        let snapshot = await PlatformFlags(db: req.db, ctx: req.ctx).snapshot()
        let switches = snapshot.filter { $0.key.hasPrefix(PlatformFlag.brandKits.rawValue + "|") }
            .map { [DashboardUI.esc(String($0.key.split(separator: "|").last ?? "")), DashboardUI.esc($0.value.reason), DashboardFormat.date($0.value.updatedAt)] }
        body += ConsoleUI.card("Brand Kits kill switch", description: "While on, no brand manifest and no brand image is served for the scope; every app renders Viadere's neutral style at once. Leave the business id empty for the whole platform.",
                               actions: switches.isEmpty ? DashboardFormat.badge("Branding on", "ok") : DashboardFormat.badge("\(switches.count) off", "dg"), tone: switches.isEmpty ? nil : .danger,
            DashboardFormat.table(["Scope", "Reason", "Since"], switches, empty: "Brand Kits are on.", caption: "Brand Kits switches")
            + ConsoleUI.form("\(path)/switch", csrf: csrf,
                ConsoleUI.input("businessId", label: "Business id", id: "bk-b", placeholder: "Whole platform", optional: true, attrs: ["maxlength": "40", "spellcheck": "false"]) + reasonField("bk-r", required: true)
                + ConsoleUI.formActions(ConsoleUI.button("Switch branding off", .danger, name: "action", value: "on", passkey: true) + ConsoleUI.button("Switch branding back on", .secondary, name: "action", value: "off", passkey: true))))
        let flash = req.query[String.self, at: "m"].flatMap { Self.flash[$0] }
        return DashboardUI.operatorPage(p, title: "Brand review", active: path, subtitle: "New and changed Brand Kits and images wait here before customers see them.",
                                        flash: flash, body: body, frames: !pendingKits.isEmpty)
    }
}
