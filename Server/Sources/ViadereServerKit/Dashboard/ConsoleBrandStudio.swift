import Fluent
import Foundation
import Vapor
import ViadereCore

/// Brand Kit Studio (WP-2.5; spec B3; permission `manageBrandKits`). Server-rendered like the rest of the console, keyboard operable, no
/// script beyond the console's hash-pinned passkey script (used only for the re-authentication button). Every change needs a fresh passkey
/// confirmation and waits for Viadere review before customers see it; previews render in a sandboxed iframe with their own CSP.
///
/// What a business can set is exactly Core's closed token schema (colors, radius, border, type scale), a registered frame, approved images
/// per slot and a schedule. There is no field for text, links, button labels, layout or anything shown on approvals.
enum ConsoleBrandStudio {
    static let path = "/dashboard/brand"
    static let uploadPath = "/dashboard/brand/assets"
    /// The 2 MB file plus multipart framing and the CSRF field.
    static let uploadBodyLimit = BrandAssetPolicy.maxUploadBytes + 64 * 1024

    static let flash: [String: String] = [
        "kit-saved": "Kit saved and sent to Viadere for review. Customers keep seeing the last approved version until then.",
        "kit-deleted": "Kit deleted.", "schedule-saved": "Schedule saved and published.",
        "uploaded": "Image processed and sent to Viadere for review.",
    ]

    private struct UploadForm: Content {
        var slot: String
        var file: File
    }

    // MARK: Routes

    static func register(_ pages: any RoutesBuilder) {
        pages.get("dashboard", "brand") { req in try await studio(req) }
        pages.get("dashboard", "brand", "kits", "new") { req in try await kitPage(req, kitId: nil) }
        pages.get("dashboard", "brand", "kits", ":id") { req in try await kitPage(req, kitId: try req.uuid("id")) }
        pages.post("dashboard", "brand", "kits") { req -> Response in
            let (p, businessId) = try mutating(req, next: path + "/kits/new")
            let form = try req.content.decode([String: String].self)
            let record = try await BrandKitService(db: req.db, ctx: req.ctx).save(businessId: businessId, kitId: nil, draft: try draft(form, kitKey: form["kit_id"] ?? ""),
                                                                                  actor: actor(p))
            return DashboardResponses.redirect("\(path)/kits/\(record.id!.uuidString.lowercased())?m=kit-saved")
        }
        pages.post("dashboard", "brand", "kits", ":id") { req -> Response in
            let id = try req.uuid("id")
            let (p, businessId) = try mutating(req, next: "\(path)/kits/\(id.uuidString.lowercased())")
            let service = BrandKitService(db: req.db, ctx: req.ctx)
            let existing = try await service.kit(businessId: businessId, id: id)
            let form = try req.content.decode([String: String].self)
            try await service.save(businessId: businessId, kitId: id, draft: try draft(form, kitKey: existing.kitKey), actor: actor(p))
            return DashboardResponses.redirect("\(path)/kits/\(id.uuidString.lowercased())?m=kit-saved")
        }
        pages.post("dashboard", "brand", "kits", ":id", "delete") { req -> Response in
            let id = try req.uuid("id")
            let (p, businessId) = try mutating(req, next: path)
            try await BrandKitService(db: req.db, ctx: req.ctx).delete(businessId: businessId, kitId: id, actor: actor(p))
            return DashboardResponses.redirect(path + "?m=kit-deleted")
        }
        pages.post("dashboard", "brand", "schedule") { req -> Response in
            let (p, businessId) = try mutating(req, next: path)
            let form = try req.content.decode([String: String].self)
            try await BrandKitService(db: req.db, ctx: req.ctx).saveSchedule(businessId: businessId, schedule: try schedule(form), actor: actor(p))
            return DashboardResponses.redirect(path + "?m=schedule-saved")
        }
        pages.get("dashboard", "brand", "assets", ":id", "image") { req -> Response in
            let (p, businessId) = try req.businessDashboard
            guard canView(p) else { throw APIError.forbidden }
            let id = try req.uuid("id")
            guard let asset = try await BrandAssetRecord.query(on: req.db).filter(\.$id == id).filter(\.$businessId == businessId).first(),
                  let data = try await BrandAssetService(db: req.db, ctx: req.ctx, runtime: req.brandKits).bytes(of: asset) else { throw APIError.notFound }
            return BrandAssetService.imageResponse(data, cache: "private, no-store")
        }
        pages.get("dashboard", "brand", "preview", ":id") { req -> Response in
            let (p, businessId) = try req.businessDashboard
            guard canView(p) else { throw APIError.forbidden }
            let record = try await BrandKitService(db: req.db, ctx: req.ctx).kit(businessId: businessId, id: try req.uuid("id"))
            return try await preview(req, record: record, businessName: p.business?.displayName ?? "")
        }
    }

    /// `POST /dashboard/brand/assets` (multipart), on its own route group that collects the bounded body before authentication.
    static func registerUpload(_ group: any RoutesBuilder) {
        group.on(.POST, "dashboard", "brand", "assets", body: .collect(maxSize: ByteCount(value: uploadBodyLimit))) { req -> Response in
            let (p, businessId) = try mutating(req, next: path)
            let form: UploadForm
            do { form = try req.content.decode(UploadForm.self) } catch { throw APIError.validation("Choose an image file and a slot.", details: ["file": "missing"]) }
            guard let slot = BrandAssetSlot(rawValue: form.slot) else { throw APIError.validation("Choose a slot.", details: ["slot": "invalid"]) }
            let declared = form.file.contentType.map { "\($0.type)/\($0.subType)" } ?? ""
            _ = try await BrandAssetService(db: req.db, ctx: req.ctx, runtime: req.brandKits)
                .ingest(businessId: businessId, data: Data(buffer: form.file.data), declaredContentType: declared, slot: slot, actor: actor(p))
            return DashboardResponses.redirect(path + "?m=uploaded")
        }
    }

    // MARK: Access

    static func canView(_ p: DashboardPrincipal) -> Bool { p.can(.manageBrandKits) || p.can(.viewOrganization) }

    /// Mutations: `manageBrandKits` and a fresh passkey confirmation (step-up, as for API keys).
    static func mutating(_ req: Request, next: String) throws -> (DashboardPrincipal, UUID) {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.manageBrandKits) else { throw APIError.forbidden }
        guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: next) }
        return (p, businessId)
    }

    static func actor(_ p: DashboardPrincipal) -> AuditActor { AuditActor(kind: .business, id: p.user.id?.uuidString.lowercased()) }

    // MARK: Form parsing (only known fields are read; everything is validated again by Core)

    static func color(_ form: [String: String], _ key: String, optional: Bool) throws -> BrandColor? {
        if optional, form["use_\(key)"] != "1" { return nil }
        guard let raw = form[key], raw.utf8.count == 7, let color = BrandColor(raw.uppercased()) else {
            throw APIError.validation("Choose a color as #RRGGBB.", details: [key: "invalid_color"])
        }
        return color
    }

    static func draft(_ form: [String: String], kitKey: String) throws -> BrandKitService.KitDraft {
        guard let primary = try color(form, "primary", optional: false) else { throw APIError.validation("Choose a primary color.", details: ["primary": "missing"]) }
        func pick<E: RawRepresentable>(_ key: String, _: E.Type) throws -> E? where E.RawValue == String {
            guard let raw = form[key], !raw.isEmpty else { return nil }
            guard let value = E(rawValue: raw) else { throw APIError.validation("Check \(key).", details: [key: "invalid"]) }
            return value
        }
        let tokens = BrandTokens(primary: primary, secondary: try color(form, "secondary", optional: true), accent: try color(form, "accent", optional: true),
                                 surface: try color(form, "surface", optional: true), radius: try pick("radius", BrandRadius.self),
                                 border: try pick("border", BrandBorder.self), typeScale: try pick("type_scale", BrandTypeScale.self))
        var assets: [BrandAssetSlot: UUID] = [:]
        for slot in BrandAssetSlot.allCases {
            guard let raw = form["asset_\(slot.rawValue)"], !raw.isEmpty else { continue }
            guard let id = UUID(uuidString: raw) else { throw APIError.validation("Choose an uploaded image.", details: ["asset_\(slot.rawValue)": "invalid"]) }
            assets[slot] = id
        }
        let frame = form["frame_id"].flatMap { $0.isEmpty ? nil : $0 }
        return BrandKitService.KitDraft(kitKey: kitKey.lowercased(), name: form["name"] ?? "", tokens: tokens, frameId: frame, assets: assets)
    }

    static let windowRows = 6

    static func schedule(_ form: [String: String]) throws -> BrandSchedule {
        let zone = (form["timezone"] ?? "").trimmingCharacters(in: .whitespaces)
        var schedule = BrandSchedule(timezone: zone, defaultKit: form["default_kit"].flatMap { $0.isEmpty ? nil : $0 })
        for i in 0..<windowRows {
            guard let kit = form["w\(i)_kit"], !kit.isEmpty else { continue }
            guard let start = form["w\(i)_start"].flatMap(LocalDateTime.init) else {
                throw APIError.validation("Window \(i + 1) needs a start date and time.", details: ["w\(i)_start": "invalid"])
            }
            var end: LocalDateTime?
            if let raw = form["w\(i)_end"], !raw.isEmpty {
                guard let parsed = LocalDateTime(raw) else { throw APIError.validation("Window \(i + 1) has an invalid end.", details: ["w\(i)_end": "invalid"]) }
                end = parsed
            }
            guard let priority = Int(form["w\(i)_priority"] ?? "0"), (0...1000).contains(priority) else {
                throw APIError.validation("Window \(i + 1): priority is 0 to 1000.", details: ["w\(i)_priority": "invalid"])
            }
            schedule.windows.append(BrandScheduleWindow(kit: kit, startsAt: start, endsAt: end, priority: priority))
        }
        for (key, value) in form.sorted(by: { $0.key < $1.key }) where key.hasPrefix("pool_") {
            guard let weight = Int(value), weight > 0 else { continue }
            schedule.randomPool.append(BrandPoolEntry(kit: String(key.dropFirst(5)), weight: weight))
        }
        return schedule
    }

    // MARK: Pages

    private static func reauthNotice(_ req: Request, _ p: DashboardPrincipal, next: String) -> (String, Bool) {
        guard p.can(.manageBrandKits), !p.hasFreshReauth(ctx: req.ctx) else { return ("", false) }
        return (ConsoleUI.callout(.accent, title: "Changes need a fresh passkey confirmation", """
        <p class="sm">Confirm once and you can save kits, images and the schedule for a few minutes.</p>\
        <p><button class="btn s sm" type="button" data-passkey="reauth" data-begin="/dashboard/auth/reauth/begin" data-finish="/dashboard/auth/reauth/finish" data-csrf="\(DashboardUI.esc(p.csrf))" \
        data-next="\(DashboardUI.esc(next))">\(ConsoleUI.icon(.key))Confirm with passkey</button></p><p id="pk-msg" class="sm err" role="alert"></p>
        """), true)
    }

    private static func statusBadge(_ status: String, approved: Bool) -> String {
        switch status {
        case "approved": DashboardFormat.badge("Approved", "ok")
        case "pending_review": DashboardFormat.badge(approved ? "Edit in review" : "In review", "wa")
        case "rejected": DashboardFormat.badge(approved ? "Edit declined" : "Declined", "dg")
        case "taken_down": DashboardFormat.badge("Taken down", "dg")
        default: DashboardFormat.badge(status, "mu")
        }
    }

    static func studio(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard canView(p) else { throw APIError.forbidden }
        guard let business = try await BusinessRecord.find(businessId, on: req.db) else { throw APIError.notFound }
        if BrandKitService.isBanned(business) {
            return DashboardUI.businessPage(p, title: "Brand Kits", active: path, body: ConsoleUI.callout(.neutral, "<p>Brand Kits are not available for this business category.</p>"))
        }
        let service = BrandKitService(db: req.db, ctx: req.ctx)
        let kits = try await service.kits(businessId: businessId)
        let assets = try await BrandAssetRecord.query(on: req.db).filter(\.$businessId == businessId).sort(\.$createdAt, .descending).limit(60).all()
        let schedule = try await service.schedule(businessId: businessId)
        let manifest = try await BrandManifestRecord.query(on: req.db).filter(\.$businessId == businessId).sort(\.$version, .descending).first()
        let stopped = await PlatformFlags(db: req.db, ctx: req.ctx).brandKitsStopped(businessId: businessId)
        let canManage = p.can(.manageBrandKits)
        let csrf = DashboardUI.csrf(p)
        let (reauth, script) = reauthNotice(req, p, next: path)
        var body = reauth

        let live: String
        let liveTone: ConsoleUI.Tone
        if stopped { live = "Viadere has paused branding for your business. Customers see Viadere's neutral style."; liveTone = .warning }
        else if !req.ctx.config.brandKits.signingAvailable { live = "Branding is not available right now. Customers see Viadere's neutral style."; liveTone = .warning }
        else if let manifest, manifest.status == "active" { live = "Live: version \(manifest.version), published \(DashboardFormat.date(manifest.createdAt))."; liveTone = .success }
        else { live = "Nothing is live yet. Customers see Viadere's neutral style until Viadere approves a kit."; liveTone = .neutral }
        body += ConsoleUI.callout(liveTone, title: "What customers see", "<p>\(DashboardUI.esc(live))</p><p class=\"sm\">Kits change colors, images and an optional Viadere frame on your business page, messages, offers and activity. They never change approvals, sign-in, verification, button wording or your verified badge. Every kit and image is reviewed by Viadere before customers see it.</p>")

        let kitRows = kits.map { k -> [ConsoleUI.Cell] in
            let approved = k.approvedJSON != nil
            return [ConsoleUI.Cell(html: "<a href=\"\(path)/kits/\(k.id!.uuidString.lowercased())\">\(DashboardUI.esc(k.name))</a>", sort: .text(k.name)), ConsoleUI.Cell(html: "<code>\(DashboardUI.esc(k.kitKey))</code>"),
                    .number(k.version), ConsoleUI.Cell(html: statusBadge(k.status, approved: approved) + (k.reviewNote.map { "<br><span class=\"mu sm\">\(DashboardUI.esc($0))</span>" } ?? ""))]
        }
        let canAdd = canManage && kits.count < req.ctx.config.brandKits.maxKitsPerBusiness
        let newKit = canAdd ? ConsoleUI.linkButton("New kit", href: "\(path)/kits/new", .primary, small: true, icon: .plus) : ""
        body += ConsoleUI.card("Kits", description: "Up to \(req.ctx.config.brandKits.maxKitsPerBusiness) kits. Customers keep seeing the last approved version of a kit while an edit is in review.", actions: newKit,
                               ConsoleUI.table([ConsoleUI.Column("Name", key: "name"), ConsoleUI.Column("Identifier"), ConsoleUI.Column("Version", numeric: true), ConsoleUI.Column("Status")], kitRows,
                                               caption: "Brand Kits", state: ConsoleUI.TableState(req, id: "k"), empty: "No kits yet", emptyMessage: "Create a kit with your colors, then add images."))

        let assetRows = assets.map { a -> [ConsoleUI.Cell] in
            let state: String
            switch a.state {
            case "ready": state = DashboardFormat.badge("Approved", "ok")
            case "pending_review": state = DashboardFormat.badge("In review", "wa")
            case "rejected": state = DashboardFormat.badge("Declined", "dg")
            default: state = DashboardFormat.badge("Taken down", "dg")
            }
            return [ConsoleUI.Cell(html: "<img src=\"\(path)/assets/\(a.id!.uuidString.lowercased())/image\" alt=\"\(DashboardUI.esc(a.slot)) image\" width=\"56\" height=\"56\">"),
                    .text(a.slot.capitalized), ConsoleUI.Cell(html: "\(a.width) × \(a.height)"), ConsoleUI.Cell(html: "\(a.bytes / 1024) KB"), ConsoleUI.Cell(html: state)]
        }
        var upload = ""
        if canManage {
            let slots = BrandAssetSlot.allCases.map { ConsoleUI.Option($0.rawValue, $0.rawValue.capitalized) }
            upload = ConsoleUI.form(uploadPath, csrf: csrf, multipart: true,
                "<div class=\"inline\">" + ConsoleUI.select("slot", label: "Slot", id: "slot", options: slots)
                + ConsoleUI.input("file", label: "Image file", id: "file", type: "file", help: "PNG or JPEG, up to 2 MB.", required: true, attrs: ["accept": "image/png,image/jpeg"])
                + "</div>" + ConsoleUI.formActions(ConsoleUI.button("Upload")))
        }
        body += ConsoleUI.card("Images", description: "Viadere re-encodes every image as a clean PNG (location, camera and color-profile data are removed) and resizes it to the slot: logo 512 px, mark 256 px, background and art 1600 px. SVG, animated and damaged files are refused.",
                               upload + ConsoleUI.table([ConsoleUI.Column("Image"), ConsoleUI.Column("Slot"), ConsoleUI.Column("Size"), ConsoleUI.Column("Stored", numeric: true), ConsoleUI.Column("Status")], assetRows,
                                                        caption: "Brand images", empty: "No images yet."))
        body += scheduleCard(kits: kits, schedule: schedule, csrf: csrf, canManage: canManage)
        let flash = req.query[String.self, at: "m"].flatMap { Self.flash[$0] }
        return DashboardUI.businessPage(p, title: "Brand Kits", active: path, subtitle: "Your business's look on Viadere's pages and widgets.", actions: canAdd ? ConsoleUI.linkButton("New kit", href: "\(path)/kits/new", .primary, icon: .plus) : "",
                                        flash: flash, body: body, script: script)
    }

    static func scheduleCard(kits: [BrandKitRecord], schedule: BrandSchedule?, csrf: String, canManage: Bool) -> String {
        guard !kits.isEmpty else { return "" }
        let disabled = canManage ? "" : " disabled"
        func kitOptions(_ selected: String?, none: String) -> String {
            "<option value=\"\">\(DashboardUI.esc(none))</option>" + kits.map {
                "<option value=\"\(DashboardUI.esc($0.kitKey))\"\($0.kitKey == selected ? " selected" : "")>\(DashboardUI.esc($0.name))</option>"
            }.joined()
        }
        let zones = ["America/New_York", "America/Chicago", "America/Denver", "America/Phoenix", "America/Los_Angeles", "America/Anchorage", "Pacific/Honolulu",
                     "America/Toronto", "America/Vancouver", "Europe/London", "Europe/Zurich", "UTC"]
        var rows = ""
        for i in 0..<windowRows {
            let w = schedule.flatMap { i < $0.windows.count ? $0.windows[i] : nil }
            rows += """
            <tr><td><label class="vh" for="w\(i)k">Window \(i + 1) kit</label><select id="w\(i)k" name="w\(i)_kit"\(disabled)>\(kitOptions(w?.kit, none: "Not used"))</select></td>\
            <td><label class="vh" for="w\(i)s">Window \(i + 1) start</label><input id="w\(i)s" name="w\(i)_start" type="datetime-local" value="\(w.map { $0.startsAt.description } ?? "")"\(disabled)></td>\
            <td><label class="vh" for="w\(i)e">Window \(i + 1) end (optional)</label><input id="w\(i)e" name="w\(i)_end" type="datetime-local" value="\(w?.endsAt.map { $0.description } ?? "")"\(disabled)></td>\
            <td class="num"><label class="vh" for="w\(i)p">Window \(i + 1) priority</label><input id="w\(i)p" name="w\(i)_priority" type="number" min="0" max="1000" value="\(w?.priority ?? 0)"\(disabled)></td></tr>
            """
        }
        let pool = kits.map { k -> String in
            let weight = schedule?.randomPool.first { $0.kit == k.kitKey }?.weight ?? 0
            return ConsoleUI.input("pool_\(k.kitKey)", label: "\(k.name) weight", id: "pool-\(k.kitKey)", type: "number", value: String(weight), help: "0 keeps it out of the rotation.",
                                   disabled: !canManage, attrs: ["min": "0", "max": "100"])
        }.joined()
        let basics = "<div class=\"cols\"><div class=\"field\"><label for=\"tz\">Time zone</label><input id=\"tz\" name=\"timezone\" type=\"text\" list=\"zones\" maxlength=\"64\" value=\"\(DashboardUI.esc(schedule?.timezone ?? "America/New_York"))\" required aria-describedby=\"tz-h\"\(disabled)>"
            + "<datalist id=\"zones\">\(zones.map { "<option value=\"\($0)\">" }.joined())</datalist><p class=\"help\" id=\"tz-h\">An IANA name; every time below is in this zone.</p></div>"
            + ConsoleUI.selectHTML("default_kit", label: "Default kit", id: "dk", optionsHTML: kitOptions(schedule?.defaultKit, none: "Viadere's neutral style"), help: "Used outside every window and the rotation.", disabled: !canManage) + "</div>"
        return ConsoleUI.card("Schedule", description: "When windows overlap, the higher priority wins; two overlapping windows with the same priority are refused. Outside every window, an optional rotation picks one kit per customer per day; otherwise the default kit is used. Requests already in progress keep the kit they started with.",
            ConsoleUI.form("\(path)/schedule", csrf: csrf, basics + """
            <fieldset><legend>Windows</legend><div class="tw"><table><caption class="vh">Windows</caption><thead><tr><th scope="col">Kit</th><th scope="col">Starts</th><th scope="col">Ends</th><th scope="col" class="num">Priority</th></tr></thead><tbody>\(rows)</tbody></table></div></fieldset>\
            <fieldset><legend>Daily rotation</legend><div class="cols">\(pool)</div></fieldset>\
            \(canManage ? ConsoleUI.formActions(ConsoleUI.button("Save schedule")) : "")
            """))
    }

    static func kitPage(_ req: Request, kitId: UUID?) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard canView(p) else { throw APIError.forbidden }
        guard let business = try await BusinessRecord.find(businessId, on: req.db), !BrandKitService.isBanned(business) else { throw APIError.forbidden }
        let service = BrandKitService(db: req.db, ctx: req.ctx)
        var record: BrandKitRecord?
        if let kitId { record = try await service.kit(businessId: businessId, id: kitId) }
        let canManage = p.can(.manageBrandKits)
        let draft = record.flatMap { BrandKitService.draftKit($0) }
        let assetIds = record.map(BrandKitService.draftAssetIds) ?? [:]
        let tokens = draft?.tokens
        let disabled = canManage ? "" : " disabled"
        let next = kitId.map { "\(path)/kits/\($0.uuidString.lowercased())" } ?? "\(path)/kits/new"
        let (reauth, script) = reauthNotice(req, p, next: next)
        var body = reauth
        if let tokens {
            let warnings = BrandPreview.contrastWarnings(tokens)
            if !warnings.isEmpty {
                body += ConsoleUI.callout(.danger, title: "Contrast warnings", "<ul>\(warnings.map { "<li>\(DashboardUI.esc($0))</li>" }.joined())</ul><p class=\"sm\">A color that fails contrast is replaced by Viadere's where it would be unreadable.</p>")
            }
        }
        func colorField(_ key: String, _ label: String, _ value: BrandColor?, optional: Bool) -> String {
            let use = optional ? "<label class=\"ck\"><input type=\"checkbox\" name=\"use_\(key)\" value=\"1\"\(value != nil ? " checked" : "")\(disabled)> Set a \(label.lowercased())</label>" : ""
            return "<div class=\"field\"><label for=\"c-\(key)\">\(label)</label>\(use)<input id=\"c-\(key)\" name=\"\(key)\" type=\"color\" value=\"\((value?.hex ?? "#8C7550").lowercased())\"\(disabled)></div>"
        }
        func select<E: RawRepresentable & CaseIterable>(_ key: String, _ label: String, _ type: E.Type, _ value: E?) -> String where E.RawValue == String {
            ConsoleUI.select(key, label: label, id: "s-\(key)", options: [ConsoleUI.Option("", "Viadere's default")] + E.allCases.map { ConsoleUI.Option($0.rawValue, $0.rawValue.capitalized, selected: $0.rawValue == value?.rawValue) },
                             disabled: !canManage)
        }
        let assets = try await BrandAssetRecord.query(on: req.db).filter(\.$businessId == businessId)
            .filter(\.$state ~~ [BrandKitService.AssetState.ready.rawValue, BrandKitService.AssetState.pendingReview.rawValue]).sort(\.$createdAt, .descending).all()
        let slotFields = BrandAssetSlot.allCases.map { slot -> String in
            let options = [ConsoleUI.Option("", "None")] + assets.filter { $0.slot == slot.rawValue }.map {
                ConsoleUI.Option($0.id!.uuidString.lowercased(), "\($0.width) × \($0.height) · \($0.state == "ready" ? "approved" : "in review") · \(DashboardFormat.date($0.createdAt))", selected: $0.id == assetIds[slot])
            }
            return ConsoleUI.select("asset_\(slot.rawValue)", label: "\(slot.rawValue.capitalized) image", id: "a-\(slot.rawValue)", options: options, disabled: !canManage)
        }.joined()
        let frames = [ConsoleUI.Option("", "No frame")] + FrameRegistry.v1.frames.map { f in
            let window = f.availableFrom.map { "from \(DashboardFormat.date(Date(timeIntervalSince1970: TimeInterval($0))))" } ?? "always"
            return ConsoleUI.Option(f.id, "\(f.id) (\(window))", selected: f.id == draft?.frameId)
        }
        let action = record.map { "\(path)/kits/\($0.id!.uuidString.lowercased())" } ?? "\(path)/kits"
        let keyField = record == nil
            ? ConsoleUI.input("kit_id", label: "Identifier", id: "kid", help: "Lowercase letters, digits, - and _. It cannot change later.", required: true, disabled: !canManage,
                              attrs: ["maxlength": "40", "pattern": "[a-z0-9][a-z0-9_-]*", "autocapitalize": "none", "spellcheck": "false"])
            : ""
        let form = ConsoleUI.form(action, csrf: DashboardUI.csrf(p),
            "<div class=\"cols\">" + keyField
            + ConsoleUI.input("name", label: "Name", id: "kname", value: draft?.name ?? "", help: "Only you and Viadere see it.", required: true, disabled: !canManage, attrs: ["maxlength": "40"]) + "</div>"
            + "<fieldset><legend>Colors</legend><p class=\"help\">Text colors are chosen by Viadere for legibility. A color that fails contrast is listed above and replaced by Viadere's.</p><div class=\"cols\">"
            + colorField("primary", "Primary", tokens?.primary, optional: false) + colorField("secondary", "Secondary", tokens?.secondary, optional: true)
            + colorField("accent", "Accent", tokens?.accent, optional: true) + colorField("surface", "Background", tokens?.surface, optional: true) + "</div></fieldset>"
            + "<fieldset><legend>Shape and type</legend><div class=\"cols\">" + select("radius", "Corner radius", BrandRadius.self, tokens?.radius) + select("border", "Borders", BrandBorder.self, tokens?.border)
            + select("type_scale", "Type size", BrandTypeScale.self, tokens?.typeScale) + "</div></fieldset>"
            + "<fieldset><legend>Images and frame</legend><p class=\"help\">The background image keeps clear of the safe area shown with a dashed outline in the preview; frames never cover the verified badge or actions.</p><div class=\"cols\">"
            + slotFields + ConsoleUI.select("frame_id", label: "Viadere frame", id: "frame", options: frames, disabled: !canManage) + "</div></fieldset>"
            + (canManage ? ConsoleUI.formActions(ConsoleUI.button("Save and send for review", passkey: true) + "<span class=\"mu sm\">Customers keep the approved version until Viadere approves this one.</span>", sep: true) : ""))
        let status = record.map { r in statusBadge(r.status, approved: r.approvedJSON != nil) + " <span class=\"mu sm\">Version \(r.version)\(r.approvedVersion.map { ", version \($0) is live" } ?? "")</span>" } ?? ""
        let editor = ConsoleUI.card(record == nil ? "New kit" : "Edit kit", actions: status, form)
        if let record {
            let preview = ConsoleUI.card("Preview", description: "Not exactly what customers see. It updates when you save.",
                                         ConsoleUI.preview(src: "\(path)/preview/\(record.id!.uuidString.lowercased())", title: "Preview of \(record.name), not exactly what customers see", width: 680, height: 640))
            body += "<div class=\"split\"><div>\(editor)</div><div>\(preview)</div></div>"
            if canManage {
                body += ConsoleUI.dangerZone("Delete this kit", description: "Customers who see this kit fall back to your default kit or Viadere's neutral style.",
                    ConsoleUI.confirm("Delete this kit", small: false, ConsoleUI.form("\(path)/kits/\(record.id!.uuidString.lowercased())/delete", csrf: DashboardUI.csrf(p),
                        "<p>This cannot be undone.</p>" + ConsoleUI.button("Delete \(record.name)", .dangerSolid, small: true, passkey: true))))
            }
        } else {
            body += editor
        }
        let flash = req.query[String.self, at: "m"].flatMap { Self.flash[$0] }
        return DashboardUI.businessPage(p, title: record.map { "Kit: \($0.name)" } ?? "New kit", active: path, flash: flash,
                                        breadcrumbs: [ConsoleUI.Crumb("Dashboard", "/dashboard"), ConsoleUI.Crumb("Organization", "/dashboard/organization"), ConsoleUI.Crumb("Brand Kits", path),
                                                      ConsoleUI.Crumb(record?.name ?? "New kit", nil)],
                                        body: body, script: script, frames: record != nil)
    }

    /// The sandboxed preview of a kit's **draft** (pending images included, inlined as `data:` URIs: the preview origin is opaque and loads
    /// nothing else).
    static func preview(_ req: Request, record: BrandKitRecord, businessName: String) async throws -> Response {
        let assets = BrandAssetService(db: req.db, ctx: req.ctx, runtime: req.brandKits)
        var images = BrandPreview.Images()
        let ids = BrandKitService.draftAssetIds(record)
        for (slot, id) in ids where slot == .logo || slot == .background {
            guard let asset = try await BrandAssetRecord.query(on: req.db).filter(\.$id == id).filter(\.$businessId == record.businessId).first(),
                  asset.state != BrandKitService.AssetState.takenDown.rawValue, asset.state != BrandKitService.AssetState.rejected.rawValue,
                  let data = try await assets.bytes(of: asset) else { continue }
            if slot == .logo { images.logo = data } else { images.background = data }
        }
        guard let kit = BrandKitService.draftKit(record) else { throw APIError.notFound }
        return BrandPreview.response(kit: kit, businessName: businessName, images: images, now: req.ctx.now)
    }
}
