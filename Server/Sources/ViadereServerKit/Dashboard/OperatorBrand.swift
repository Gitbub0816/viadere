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
        "<label for=\"\(id)\">Reason\(required ? " (recorded)" : " (optional)")</label><input id=\"\(id)\" name=\"reason\" type=\"text\" \(required ? "minlength=\"8\" required " : "")maxlength=\"300\">"
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
        func business(_ id: UUID) -> String { "\(DashboardUI.esc(names[id] ?? "?")) <code class=\"sm\">\(id.uuidString.lowercased())</code>" }

        var body = "<div class=\"notice\">Check every kit and image against the brand-content rules: no impersonation of another organization or of Viadere, no security or payment imagery, no health content (healthcare businesses are refused outright), nothing that imitates a verified badge or approval buttons. Approving a kit requires its images to be approved first.</div>"
        let kitRows = pendingKits.map { k -> [String] in
            let id = k.id!.uuidString.lowercased()
            let tokens = BrandKitService.draftKit(k)?.tokens
            let warnings = tokens.map(BrandPreview.contrastWarnings) ?? []
            let summary = tokens.map { "primary \($0.primary.hex)" + ($0.accent.map { ", accent \($0.hex)" } ?? "") } ?? "unreadable tokens"
            return [business(k.businessId), "\(DashboardUI.esc(k.name)) <code>\(DashboardUI.esc(k.kitKey))</code> v\(k.version)",
                    DashboardUI.esc(summary) + (warnings.isEmpty ? "" : " " + DashboardFormat.badge("\(warnings.count) contrast override(s)", "mu")),
                    "<a href=\"\(path)/kits/\(id)/preview\">Preview</a>",
                    """
                    <form method="post" action="\(path)/kits/\(id)/approve">\(csrf)\(reasonField("ka-\(id)", required: false))<button class="btn sm" type="submit">Approve</button></form>\
                    <form method="post" action="\(path)/kits/\(id)/reject">\(csrf)\(reasonField("kr-\(id)", required: true))<button class="btn d sm" type="submit">Reject</button></form>
                    """]
        }
        body += "<div class=\"card\"><h2>Kits waiting for review</h2>\(DashboardFormat.table(["Business", "Kit", "Tokens", "Preview", ""], kitRows, empty: "No kits waiting.", caption: "Kits waiting for review"))</div>"
        let assetRows = pendingAssets.map { a -> [String] in
            let id = a.id!.uuidString.lowercased()
            return [business(a.businessId), "<img src=\"\(path)/assets/\(id)/image\" alt=\"Uploaded \(DashboardUI.esc(a.slot)) image\" width=\"96\" height=\"96\">",
                    "\(DashboardUI.esc(a.slot)) · \(a.width) × \(a.height) · \(a.bytes / 1024) KB",
                    """
                    <form method="post" action="\(path)/assets/\(id)/approve">\(csrf)\(reasonField("aa-\(id)", required: false))<button class="btn sm" type="submit">Approve</button></form>\
                    <form method="post" action="\(path)/assets/\(id)/reject">\(csrf)\(reasonField("ar-\(id)", required: true))<button class="btn d sm" type="submit">Reject</button></form>
                    """]
        }
        body += "<div class=\"card\"><h2>Images waiting for review</h2>\(DashboardFormat.table(["Business", "Image", "Details", ""], assetRows, empty: "No images waiting.", caption: "Images waiting for review"))</div>"
        let liveKitRows = liveKits.map { k -> [String] in
            let id = k.id!.uuidString.lowercased()
            return [business(k.businessId), "\(DashboardUI.esc(k.name)) <code>\(DashboardUI.esc(k.kitKey))</code> live v\(k.approvedVersion ?? 0)",
                    "<form method=\"post\" action=\"\(path)/kits/\(id)/takedown\">\(csrf)\(reasonField("kt-\(id)", required: true))<button class=\"btn d sm\" type=\"submit\">Take down</button></form>"]
        }
        let liveAssetRows = liveAssets.map { a -> [String] in
            let id = a.id!.uuidString.lowercased()
            return [business(a.businessId), "<img src=\"\(path)/assets/\(id)/image\" alt=\"Live \(DashboardUI.esc(a.slot)) image\" width=\"56\" height=\"56\"> \(DashboardUI.esc(a.slot))",
                    "<form method=\"post\" action=\"\(path)/assets/\(id)/takedown\">\(csrf)\(reasonField("at-\(id)", required: true))<button class=\"btn d sm\" type=\"submit\">Take down</button></form>"]
        }
        body += "<div class=\"card\"><h2>Live kits</h2>\(DashboardFormat.table(["Business", "Kit", ""], liveKitRows, empty: "No live kits.", caption: "Live kits"))</div>"
        body += "<div class=\"card\"><h2>Live images</h2>\(DashboardFormat.table(["Business", "Image", ""], liveAssetRows, empty: "No live images.", caption: "Live images"))</div>"

        let snapshot = await PlatformFlags(db: req.db, ctx: req.ctx).snapshot()
        let switches = snapshot.filter { $0.key.hasPrefix(PlatformFlag.brandKits.rawValue + "|") }
            .map { [DashboardUI.esc(String($0.key.split(separator: "|").last ?? "")), DashboardUI.esc($0.value.reason), DashboardFormat.date($0.value.updatedAt)] }
        body += """
        <div class="card"><h2>Brand Kits kill switch</h2><p class="mu sm">While on, no brand manifest and no brand image is served for the scope; every app renders Viadere's neutral style at once. Leave the business id empty for the whole platform.</p>\
        \(DashboardFormat.table(["Scope", "Reason", "Since"], switches, empty: "Brand Kits are on.", caption: "Brand Kits switches"))\
        <form method="post" action="\(path)/switch">\(csrf)<label for="bk-b">Business id (optional)</label><input id="bk-b" name="businessId" type="text" maxlength="40">\(reasonField("bk-r", required: true))\
        <div class="row"><button class="btn d" type="submit" name="action" value="on">Switch branding off</button><button class="btn s" type="submit" name="action" value="off">Switch branding back on</button></div></form></div>
        """
        let flash = req.query[String.self, at: "m"].flatMap { Self.flash[$0] }
        return DashboardUI.operatorPage(p, title: "Brand review", active: path, subtitle: "New and changed Brand Kits and images wait here before customers see them.",
                                        flash: flash, body: body)
    }
}
