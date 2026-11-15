import Fluent
import Foundation
import Vapor
import ViadereCore

private struct LoyaltyProgramForm: Content {
    var program_name: String
    var summary: String
    var terms_version: String
    var time_zone: String
    var tiers: String?
}

private struct CheckCodeForm: Content {
    var code: String
    var location: String?
}

/// Rewards, loyalty and Wallet pass pages (G6, docs/SECURITY.md §2.109). Every action calls the business API's own service function
/// (`RewardsService.upsertProgram`, `.listRewards`, `.revokeReward`, `.consume`; `WalletService.businessList`, `.businessVoid`, `.scan`) with
/// a console principal, so validation, tenant isolation, single use, test/live separation and audit are the API's.
///
/// * `viewBenefits` reads, `manageBenefits` acts; re-read on every request.
/// * Revoke, void and check-a-code change value: each needs a fresh passkey assertion (the console's `requireReauth`, the same step-up as
///   API keys, team changes and the Brand Kit submission).
/// * Test and live: the console acts in live mode only once the organization's production access is approved (`OnboardingGate`), exactly
///   like a live API key. Before that it acts in test mode, so it cannot edit the shared program, see or redeem a real customer's pass, or
///   consume a real customer's code.
enum ConsoleBenefits {
    static let path = "/dashboard/benefits"
    static let passesPath = "/dashboard/benefits/passes"
    static let checkPath = "/dashboard/benefits/check"

    static let messages: [String: String] = [
        "program": "Loyalty program saved.", "revoked": "Reward revoked. Outstanding codes no longer work and their points were returned.",
        "voided": "Pass voided. It stops working at your counter and updates in the customer's Wallet.",
    ]

    static func register(_ pages: any RoutesBuilder) {
        pages.get("dashboard", "benefits") { req in try await overview(req) }
        pages.get("dashboard", "benefits", "passes") { req in try await passes(req) }
        pages.get("dashboard", "benefits", "check") { req in try await check(req, result: nil) }
        pages.post("dashboard", "benefits", "program") { req -> Response in
            let (_, principal) = try await manage(req)
            let form = try req.content.decode(LoyaltyProgramForm.self)
            let request = UpsertLoyaltyProgramRequest(programName: form.program_name, summary: form.summary, termsVersion: form.terms_version,
                                                      timeZone: form.time_zone.trimmingCharacters(in: .whitespaces), tiers: try parseTiers(form.tiers ?? ""))
            _ = try await RewardsService(db: req.db, ctx: req.ctx).upsertProgram(principal: principal, request: request)
            return DashboardResponses.redirect("\(path)?bm=program")
        }
        pages.post("dashboard", "benefits", "rewards", ":id", "revoke") { req -> Response in
            let (p, principal) = try await manage(req)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).requireReauth(next: path)
            _ = try await RewardsService(db: req.db, ctx: req.ctx).revokeReward(principal: principal, id: RewardID(try req.uuid("id")))
            return DashboardResponses.redirect("\(path)?bm=revoked")
        }
        pages.post("dashboard", "benefits", "passes", ":id", "void") { req -> Response in
            let (p, principal) = try await manage(req)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).requireReauth(next: passesPath)
            _ = try await WalletService(db: req.db, ctx: req.ctx).businessVoid(principal: principal, id: WalletPassID(try req.uuid("id")))
            return DashboardResponses.redirect("\(passesPath)?bm=voided")
        }
        pages.post("dashboard", "benefits", "check") { req -> Response in
            let (p, principal) = try await manage(req)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).requireReauth(next: checkPath)
            let form = try req.content.decode(CheckCodeForm.self)
            let location = form.location.flatMap { $0.trimmingCharacters(in: .whitespaces).isEmpty ? nil : $0.trimmingCharacters(in: .whitespaces) }
            return try await check(req, result: try await ConsoleBenefitsService(db: req.db, ctx: req.ctx).check(principal: principal, code: form.code, location: location))
        }
    }

    /// The console acting through the business API's code path. `livemode` is what a key of this organization could be: live only once
    /// production access is approved, else test.
    static func principal(_ p: DashboardPrincipal, on db: any Database) async throws -> BusinessPrincipal {
        guard let business = p.business, let businessId = business.id, let staff = p.user.id else { throw APIError.forbidden }
        let live = try await OnboardingGate.allows(business: business, livemode: true, on: db)
        let test = try await OnboardingGate.allows(business: business, livemode: false, on: db)
        guard live || test else {
            throw APIError(.forbidden, .forbidden, "Verify a domain you control (Organization > Onboarding) to use rewards and passes.")
        }
        return BusinessPrincipal(businessId: BusinessID(businessId), keyId: ConsoleConversationService.consoleKeyId, livemode: live,
                                 scopes: [BusinessAPIKeys.Scope.rewardsWrite, BusinessAPIKeys.Scope.walletWrite], businessName: business.displayName,
                                 capabilities: [.messageSend], consoleUserId: staff)
    }

    private static func view(_ req: Request) async throws -> (DashboardPrincipal, BusinessPrincipal) {
        let (p, _) = try req.businessDashboard
        guard p.can(.viewBenefits) else { throw APIError.forbidden }
        return (p, try await principal(p, on: req.db))
    }

    private static func manage(_ req: Request) async throws -> (DashboardPrincipal, BusinessPrincipal) {
        let (p, _) = try req.businessDashboard
        guard p.can(.manageBenefits) else { throw APIError.forbidden }
        return (p, try await principal(p, on: req.db))
    }

    static func flash(_ req: Request) -> String? { req.query[String.self, at: "bm"].flatMap { messages[$0] } }

    /// Tiers as the form writes them: one `Name: minimum points` per line (or separated by `;`).
    static func parseTiers(_ raw: String) throws -> [LoyaltyTier] {
        let parts = raw.split(whereSeparator: { $0 == "\n" || $0 == ";" }).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        return try parts.map { part in
            guard let colon = part.lastIndex(of: ":"), let points = Int(part[part.index(after: colon)...].trimmingCharacters(in: .whitespaces)) else {
                throw APIError.validation("Write each tier as Name: points, for example Gold: 500.", details: ["tiers": "invalid"])
            }
            return LoyaltyTier(name: part[..<colon].trimmingCharacters(in: .whitespaces), minimumPoints: points)
        }
    }

    private static func modeNotice(_ principal: BusinessPrincipal) -> String {
        principal.livemode ? "" : ConsoleUI.callout(.warning, title: "Test mode", """
        <p class="sm">Your organization's production access isn't approved yet, so this page works in test mode: you can't change the loyalty program, \
        and only your sandbox customer's codes and rewards can be checked or revoked. Real customers' rewards and passes are never touched.</p>
        """)
    }

    // MARK: Pages

    private static func overview(_ req: Request) async throws -> Response {
        let (p, principal) = try await view(req)
        let rewards = RewardsService(db: req.db, ctx: req.ctx)
        let program = try? await rewards.program(principal: principal)
        let manage = p.can(.manageBenefits)
        let csrf = DashboardUI.csrf(p)
        var programHTML = program.map { program in
            ConsoleUI.keyValues([("Name", DashboardUI.esc(program.programName)), ("Summary", DashboardUI.esc(program.summary)),
                                 ("Terms version", DashboardUI.esc(program.termsVersion)), ("Time zone", DashboardUI.esc(program.timeZone)),
                                 ("Tiers", program.tiers.isEmpty ? "—" : DashboardUI.esc(program.tiers.map { "\($0.name) from \($0.minimumPoints)" }.joined(separator: ", "))),
                                 ("Members", String(program.memberCount)), ("Updated", DashboardFormat.date(program.updatedAt))])
        } ?? ConsoleUI.empty("No loyalty program yet", "Create one so customers can join, collect points and see their status.", icon: .store)
        if manage && principal.livemode {
            programHTML += ConsoleUI.more(program == nil ? "Create the program" : "Edit the program", ConsoleUI.form("\(path)/program", csrf: csrf,
                "<div class=\"cols\">"
                + ConsoleUI.input("program_name", label: "Program name", id: "pn", value: program?.programName, required: true, attrs: ["maxlength": "60"])
                + ConsoleUI.input("terms_version", label: "Terms version", id: "tv", value: program?.termsVersion, help: "Change it when the terms change; members see it.", required: true, attrs: ["maxlength": "32"])
                + ConsoleUI.input("time_zone", label: "Time zone", id: "tzn", value: program?.timeZone ?? "UTC", help: "An IANA name, for example America/Phoenix.", required: true, attrs: ["maxlength": "64"])
                + "</div>"
                + ConsoleUI.textarea("summary", label: "Summary", id: "ps", value: program?.summary, help: "What members get, in a sentence or two.", required: true, attrs: ["maxlength": "280"])
                + ConsoleUI.textarea("tiers", label: "Tiers", id: "pt", value: program.map { $0.tiers.map { "\($0.name): \($0.minimumPoints)" }.joined(separator: "\n") },
                                     help: "One per line as Name: minimum points, for example Gold: 500. Up to 10.", optional: true, attrs: ["maxlength": "600", "rows": "3"])
                + ConsoleUI.formActions(ConsoleUI.button("Save program"))))
        }
        let list = try await rewards.listRewards(principal: principal)
        let rows = list.map { reward -> [ConsoleUI.Cell] in
            var action = ""
            if manage && reward.status != .revoked {
                action = ConsoleUI.confirm("Revoke", ariaLabel: "Revoke \(reward.title)", ConsoleUI.form("\(path)/rewards/\(reward.id.uuid.uuidString.lowercased())/revoke", csrf: csrf,
                    "<p class=\"sm\">Outstanding codes stop working and held points are returned. This can't be undone.</p>" + ConsoleUI.passkeyNote()
                    + ConsoleUI.formActions(ConsoleUI.button("Revoke reward", .dangerSolid, small: true))))
            }
            return [.text(reward.title), ConsoleUI.Cell(html: statusBadge(reward.status), sort: .text(reward.status.rawValue)),
                    .date(reward.validUntil), ConsoleUI.Cell(html: action)]
        }
        let rewardsCard = ConsoleUI.card("Issued rewards", description: "Rewards your organization offered, newest first. Issue new rewards through the API.",
            ConsoleUI.table([ConsoleUI.Column("Reward", key: "title"), ConsoleUI.Column("Status", key: "status"), ConsoleUI.Column("Valid until"), ConsoleUI.Column("", actions: true)],
                            rows, caption: "Issued rewards", state: ConsoleUI.TableState(req, id: "r"), empty: "No rewards yet",
                            emptyMessage: "Rewards you issue with POST /v1/business/rewards appear here."))
        let body = modeNotice(principal) + ConsoleUI.card("Loyalty program", programHTML) + rewardsCard
        return DashboardUI.businessPage(p, title: "Rewards and passes", active: path, subtitle: "Your loyalty program, the rewards you issued and your customers' Wallet passes.",
                                        actions: manage ? ConsoleUI.linkButton("Check a code", href: checkPath, .primary) : "", flash: flash(req), body: body)
    }

    private static func passes(_ req: Request) async throws -> Response {
        let (p, principal) = try await view(req)
        let manage = p.can(.manageBenefits)
        let csrf = DashboardUI.csrf(p)
        let list = try await WalletService(db: req.db, ctx: req.ctx).businessList(principal: principal, limit: 200)
        let rows = list.map { pass -> [ConsoleUI.Cell] in
            var action = ""
            if manage && !pass.voided {
                action = ConsoleUI.confirm("Void", ariaLabel: "Void pass \(pass.id.uuid.uuidString.prefix(8))", ConsoleUI.form("\(passesPath)/\(pass.id.uuid.uuidString.lowercased())/void", csrf: csrf,
                    "<p class=\"sm\">The pass stops working and updates in the customer's Wallet. This can't be undone.</p>" + ConsoleUI.passkeyNote()
                    + ConsoleUI.formActions(ConsoleUI.button("Void pass", .dangerSolid, small: true))))
            }
            let state = pass.voided ? DashboardFormat.badge("Voided", "mu") : (pass.usedAt != nil ? DashboardFormat.badge("Used", "") : DashboardFormat.badge("Active", "ok"))
            return [.text(kindLabel(pass.kind)), ConsoleUI.Cell(html: pass.subjectRef.map { "<code class=\"mono\">\(DashboardUI.esc(ConsoleConversations.shortRef($0.rawValue)))</code>" } ?? "—"),
                    .text(pass.issuedBy == .business ? "You" : "Customer"), ConsoleUI.Cell(html: state, sort: .text(pass.voided ? "voided" : "active")),
                    .date(pass.createdAt), ConsoleUI.Cell(html: action)]
        }
        let body = modeNotice(principal) + ConsoleUI.card("Wallet passes", description: "Passes of your organization in customers' Apple Wallets. Customers appear by your reference only.",
            ConsoleUI.table([ConsoleUI.Column("Pass", key: "kind"), ConsoleUI.Column("Customer"), ConsoleUI.Column("Issued by"), ConsoleUI.Column("Status", key: "status"),
                             ConsoleUI.Column("Issued", key: "issued"), ConsoleUI.Column("", actions: true)],
                            rows, caption: "Wallet passes", state: ConsoleUI.TableState(req, id: "w", defaultSort: "issued", defaultAscending: false),
                            empty: "No passes yet", emptyMessage: principal.livemode ? "Passes customers add, and passes you issue through the API, appear here." : "Passes appear here once your production access is approved."))
        return DashboardUI.businessPage(p, title: "Wallet passes", active: passesPath, flash: flash(req), body: body)
    }

    private static func check(_ req: Request, result: ConsoleBenefitsService.CheckResult?) async throws -> Response {
        let (p, principal) = try await manage(req)
        var resultHTML = ""
        if let result {
            resultHTML = ConsoleUI.callout(result.ok ? .success : .danger, title: result.title, urgent: true,
                "<p>\(DashboardUI.esc(result.detail))</p>" + (result.subjectRef.map { "<p class=\"sm\">Customer <code class=\"mono\">\(DashboardUI.esc($0))</code></p>" } ?? ""))
        }
        let form = ConsoleUI.form(checkPath, csrf: DashboardUI.csrf(p),
            ConsoleUI.input("code", label: "Code", id: "cc", help: "The redemption code the customer shows, or the code under their Wallet pass's barcode.", required: true,
                            attrs: ["maxlength": "200", "autocomplete": "off", "autocapitalize": "characters", "spellcheck": "false"])
            + ConsoleUI.input("location", label: "Location", id: "cl", help: "Optional, for example store-12. Recorded with the redemption.", optional: true, attrs: ["maxlength": "40"])
            + ConsoleUI.passkeyNote("Checking a code uses it up. You'll confirm with your passkey.")
            + ConsoleUI.formActions(ConsoleUI.button("Check and redeem")))
        let body = modeNotice(principal) + resultHTML + ConsoleUI.card("Check a code", description: "Each code works once. A used, expired or unknown code is refused.", form)
        return DashboardUI.businessPage(p, title: "Check a code", active: checkPath, body: body, status: result.map { $0.ok ? .ok : .unprocessableEntity } ?? .ok)
    }

    static func statusBadge(_ status: Reward.Status) -> String {
        switch status {
        case .available: DashboardFormat.badge("Active", "ok")
        case .redeemed: DashboardFormat.badge("Redeemed")
        case .expired: DashboardFormat.badge("Expired", "mu")
        case .revoked: DashboardFormat.badge("Revoked", "dg")
        }
    }

    static func kindLabel(_ kind: WalletPassKind) -> String {
        switch kind {
        case .storeCard: "Loyalty card"
        case .coupon: "Coupon"
        case .eventTicket: "Event ticket"
        case .boardingPass: "Boarding pass"
        case .generic: "Reservation"
        }
    }
}

struct ConsoleBenefitsService {
    let db: any Database
    let ctx: ServerContext

    struct CheckResult {
        var ok: Bool
        var title: String
        var detail: String
        var subjectRef: String?
    }

    /// A Wallet pass scan code (signed, recognised by `WalletService.verifyScanCode`) goes to the pass scan path; anything else is a
    /// redemption code for `RewardsService.consume`. Both are single use and rate limited there. Refusals are shown, not thrown, so the person
    /// at the counter sees why.
    func check(principal: BusinessPrincipal, code: String, location: String?) async throws -> CheckResult {
        let trimmed = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= 200 else { throw APIError.validation("Enter the code.", details: ["code": "invalid"]) }
        let wallet = WalletService(db: db, ctx: ctx)
        do {
            if wallet.verifyScanCode(trimmed) != nil {
                // The API's capability check for scans (a test-mode principal is refused by `scan` itself, like a test key).
                if principal.livemode { try await PolicyService(db: db, ctx: ctx).enforce(PolicyInput(.messageSend), principal: principal, auditAllowed: false) }
                let scan = try await wallet.scan(principal: principal, request: WalletScanRequest(code: trimmed, locationCode: location))
                let what: String
                switch scan.outcome {
                case .redeemed: what = "Redeemed: \(scan.title ?? "coupon")."
                case .checkedIn: what = "Checked in: \(scan.title ?? "ticket")."
                case .member: what = "Loyalty member with \(scan.pointsBalance ?? 0) points."
                }
                return CheckResult(ok: true, title: "Valid", detail: what, subjectRef: scan.subjectRef?.rawValue)
            }
            let receipt = try await RewardsService(db: db, ctx: ctx).consume(principal: principal, request: ConsumeRedemptionRequest(code: trimmed, locationCode: location))
            return CheckResult(ok: true, title: "Redeemed", detail: "\(receipt.rewardTitle)\(receipt.pointsSpent.map { ", \($0) points" } ?? "").", subjectRef: receipt.subjectRef?.rawValue)
        } catch let error as APIError where [.notFound, .conflict, .gone].contains(error.status) {
            let detail: String
            switch error.status {
            case .conflict: detail = "This code was already used\((error.details?["redeemedAt"] ?? error.details?["usedAt"]).map { " (\($0))" } ?? "")."
            case .gone: detail = error.message
            default: detail = "This code isn't valid here."
            }
            return CheckResult(ok: false, title: "Not redeemed", detail: detail, subjectRef: nil)
        }
    }
}
