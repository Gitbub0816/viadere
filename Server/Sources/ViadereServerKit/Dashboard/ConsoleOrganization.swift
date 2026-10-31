import Fluent
import Foundation
import Vapor
import ViadereCore

private struct DomainForm: Content { var domain: String }
private struct LegalForm: Content {
    var registryNumber: String
    var jurisdiction: String
    var registryName: String
    var evidence: String
}
private struct GoLiveForm: Content {
    var useCase: String
    var volume: String
}

/// Organization section: profile, onboarding (spec §8.1) and domains. Onboarding is shown as the state machine's checklist; every step links to
/// where it is done.
enum ConsoleOrganization {
    static func register(_ pages: any RoutesBuilder) {
        pages.get("dashboard", "organization") { req in try await profilePage(req) }
        pages.get("dashboard", "organization", "domains") { req in try await domainsPage(req) }
        pages.post("dashboard", "organization", "domains") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(DomainForm.self)
            _ = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).addDomain(form.domain)
            return DashboardResponses.redirect("/dashboard/organization/domains?m=domain-added")
        }
        pages.post("dashboard", "organization", "domains", ":id", "check") { req -> Response in
            let (p, _) = try req.businessDashboard
            let outcome = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).checkDomain(id: try req.uuid("id"))
            switch outcome {
            case .verified: return DashboardResponses.redirect("/dashboard/organization/domains?m=domain-verified")
            default: return try await domainsPage(req, notice: Self.notice(for: outcome))
            }
        }
        pages.post("dashboard", "organization", "domains", ":id", "remove") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).removeDomain(id: try req.uuid("id"))
            return DashboardResponses.redirect("/dashboard/organization/domains?m=domain-removed")
        }
        pages.post("dashboard", "organization", "legal-entity") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(LegalForm.self)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).submitLegalEntity(
                registryNumber: form.registryNumber, jurisdiction: form.jurisdiction, registryName: form.registryName,
                evidence: form.evidence.split(whereSeparator: \.isNewline).map(String.init))
            return DashboardResponses.redirect("/dashboard/organization?m=legal")
        }
        pages.post("dashboard", "organization", "go-live") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(GoLiveForm.self)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).requestGoLive(useCase: form.useCase, volume: form.volume)
            return DashboardResponses.redirect("/dashboard/organization?m=golive")
        }
    }

    static func notice(for outcome: DomainControl.Outcome) -> String {
        switch outcome {
        case .verified: return "Verified."
        case .notFound: return "We could not find the verification record yet. DNS changes can take a while to spread; publish the record exactly as shown and check again."
        case .unavailable: return "We could not look the record up right now. Try again in a few minutes."
        case .claimedElsewhere: return "Another organization has already verified this domain. Contact Viadere support if it is yours."
        }
    }

    // MARK: Profile and onboarding

    private static func profilePage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.viewOrganization) || p.can(.manageOrganization) else { throw APIError.forbidden }
        guard let business = p.business else { throw APIError.notFound }
        let service = OnboardingService(db: req.db, ctx: req.ctx)
        let state = try await service.state(businessId: businessId)
        let row = try await service.row(businessId)
        let application = try await BusinessApplicationRecord.query(on: req.db).filter(\.$businessId == businessId).first()
        let canManage = p.can(.manageOrganization)

        var profile = "<div class=\"card\"><h2>\(DashboardUI.esc(business.displayName)) \(DashboardFormat.statusBadge(business.status))</h2>"
        if business.isVerified {
            let summary = try await DirectoryService(db: req.db).summary(for: business)
            profile += "<p>Handle: <strong>\(DashboardUI.esc(summary?.handle?.display ?? "none"))</strong> · Code: <strong>\(DashboardUI.esc(summary?.code.display ?? ""))</strong></p>"
            profile += "<p class=\"mu sm\">Verified \(DashboardFormat.optional(business.verifiedAt)). Your permanent code is never reassigned. Your public display name and your legal entity are kept separate: the legal entity is reviewed below and is not shown to customers.</p>"
        } else if let application {
            switch application.state {
            case "pending": profile += "<p>Your application was submitted \(DashboardFormat.date(application.submittedAt)) and is awaiting review. Handles and codes are issued only after verification.</p>"
            case "rejected":
                profile += "<div class=\"notice dg\" role=\"alert\">Your application was declined\(application.decisionNote.map { ": " + DashboardUI.esc($0) } ?? ".")</div>"
                if canManage {
                    profile += """
                    <form method="post" action="/dashboard/organization">\(DashboardUI.csrf(p))\
                    <label for="legalName">Legal name</label><input id="legalName" name="legalName" type="text" maxlength="120" value="\(DashboardUI.esc(application.legalName ?? ""))">\
                    <label for="website">Website (https)</label><input id="website" name="website" type="url" maxlength="200" value="\(DashboardUI.esc(application.website ?? ""))">\
                    <label for="requestedHandle">Requested handle</label><input id="requestedHandle" name="requestedHandle" type="text" maxlength="30" value="\(DashboardUI.esc(application.requestedHandle ?? ""))">\
                    <label for="description">What will you use Viadere for?</label><textarea id="description" name="description" maxlength="500">\(DashboardUI.esc(application.detail ?? ""))</textarea>\
                    <p><button class="btn" type="submit">Apply again</button></p></form>
                    """
                }
            default: profile += "<p>Status: \(DashboardUI.esc(application.state)).</p>"
            }
        } else {
            profile += "<p>This organization is \(DashboardUI.esc(business.verificationStatus)).</p>"
        }
        profile += "</div>"

        // The checklist: one row per stage, with what is open and where to do it.
        func item(_ done: Bool, _ title: String, _ detail: String) -> String {
            "<li class=\"\(done ? "done" : "")\"><span aria-hidden=\"true\">\(done ? "✓" : "○")</span><div><strong>\(DashboardUI.esc(title))</strong> <span class=\"vh\">\(done ? "done" : "to do")</span><br><span class=\"mu sm\">\(detail)</span></div></li>"
        }
        let outstanding = try await ContractService(db: req.db, ctx: req.ctx).outstanding(businessId: businessId)
        var steps = "<ol class=\"steps\">"
        steps += item(true, "1. Workspace", "Your account is verified by email and protected by a passkey.")
        steps += item(state.domainVerified, "2a. Domain control", state.domainVerified ? "Verified: \(DashboardUI.esc(row.controlDomain ?? "")) (\(DashboardUI.esc(row.controlMethod ?? ""))). Unlocks the sandbox." : "Publish a DNS record to prove you control your domain. <a href=\"/dashboard/organization/domains\">Verify a domain</a>")
        steps += item(state.legalEntity == .approved, "2b. Legal entity", legalEntityDetail(row: row, state: state))
        if state.enhanced != .notRequired {
            steps += item(state.enhanced == .approved, "2c. Additional review", state.enhanced == .approved ? "Approved." : (state.enhanced == .rejected ? "The additional review for your category was not approved. Contact Viadere support." : "Your category needs an additional review by Viadere. We will contact you."))
        }
        steps += item(state.identityVerified, "3. Public identity", state.identityVerified ? "Handle and code issued." : "Issued when Viadere approves your application.")
        steps += item(state.contractsCurrent, "4. Agreements", state.contractsCurrent ? "All required agreements are accepted at their current version." : "\(outstanding.count) to accept. <a href=\"/dashboard/compliance\">Open Compliance &gt; Agreements</a>")
        steps += item(state.integrationComplete, "5. Integration", "Sandbox key \(state.sandboxKey ? "✓" : "○"), test customer \(state.testCustomer ? "✓" : "○"), test event \(state.testEvent ? "✓" : "○"). <a href=\"/dashboard/developers/sandbox\">Open the sandbox</a>")
        let profileAllowed = try await EntitlementService(db: req.db, ctx: req.ctx).snapshot(businessId: businessId).profileCategories
        let profilePending = try await ProfileCategoryRequestRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$status == "pending").count()
        steps += item(!profileAllowed.isEmpty, "Customer profile access", ProfileConsole.checklistDetail(allowed: profileAllowed, pending: profilePending))
        steps += item(state.securityContact, "Security contact", state.securityContact ? "Set." : "Add an operational security contact. <a href=\"/dashboard/security/alerts\">Security &gt; Alerts and contacts</a>")
        steps += item(state.goLive == .approved, "6. Go-live review", goLiveDetail(row: row, state: state))
        steps += item(state.goLive == .approved && !state.suspended, "7. Ongoing assurance", assuranceDetail(row: row, state: state, grace: req.ctx.config.operations.assuranceGrace))
        steps += "</ol>"
        let onboarding = "<div class=\"card\"><h2>Onboarding</h2><p class=\"mu\">Stage: <strong>\(DashboardUI.esc(state.stage.rawValue))</strong></p>\(steps)</div>"

        var forms = ""
        if canManage, state.domainVerified, state.legalEntity == .none || state.legalEntity == .rejected {
            forms += """
            <div class="card"><h2>Legal entity</h2><p class="mu sm">A Viadere reviewer checks these details against the public registry. Give references to your evidence (a registry URL or record id). Do not upload documents here.</p>\
            <form method="post" action="/dashboard/organization/legal-entity">\(DashboardUI.csrf(p))\
            <div class="cols"><div><label for="registryName">Registered name</label><input id="registryName" name="registryName" type="text" maxlength="120" required value="\(DashboardUI.esc(row.legalRegistryName ?? business.legalName ?? ""))"></div>\
            <div><label for="registryNumber">Registry number</label><input id="registryNumber" name="registryNumber" type="text" maxlength="64" required value="\(DashboardUI.esc(row.legalRegistryNumber ?? ""))"></div>\
            <div><label for="jurisdiction">Jurisdiction (ISO region)</label><input id="jurisdiction" name="jurisdiction" type="text" maxlength="6" required placeholder="US-DE" value="\(DashboardUI.esc(row.legalJurisdiction ?? ""))"></div></div>\
            <label for="evidence">Evidence references (one per line, up to five)</label><textarea id="evidence" name="evidence" maxlength="800" required>\(DashboardUI.esc(row.evidenceReferences.joined(separator: "\n")))</textarea>\
            <p><button class="btn" type="submit">Submit for review</button></p></form></div>
            """
        }
        if canManage, state.goLive == .none || state.goLive == .rejected {
            let blockers = state.requestBlockers
            if blockers.isEmpty {
                forms += """
                <div class="card"><h2>Request production access</h2><p class="mu sm">Describe what you will send, to whom, and how much. An operator reviews the request; you confirm with your passkey.</p>\
                <form method="post" action="/dashboard/organization/go-live">\(DashboardUI.csrf(p))\
                <label for="useCase">Use case</label><textarea id="useCase" name="useCase" minlength="20" maxlength="1000" required></textarea>\
                <label for="volume">Expected volume</label><input id="volume" name="volume" type="text" maxlength="120" required placeholder="About 50,000 messages a month">\
                <p><button class="btn" type="submit">Request production access</button></p></form></div>
                """
            } else {
                forms += "<div class=\"card\"><h2>Request production access</h2><p>Complete these first:</p><ul>\(blockers.map { "<li>\(DashboardUI.esc($0.title))</li>" }.joined())</ul></div>"
            }
        }
        return DashboardUI.businessPage(p, title: "Organization", active: "/dashboard/organization", subtitle: "Your profile and the path to production.", flash: DashboardFormat.flash(req), body: profile + onboarding + forms)
    }

    private static func legalEntityDetail(row: BusinessOnboardingRecord, state: OnboardingState) -> String {
        switch state.legalEntity {
        case .none: return state.domainVerified ? "Submit your registration details below." : "Verify a domain first."
        case .submitted: return "Submitted \(DashboardFormat.optional(row.legalSubmittedAt)); waiting for a Viadere reviewer."
        case .approved: return "Approved \(DashboardFormat.optional(row.legalReviewedAt)) (\(DashboardUI.esc(row.legalJurisdiction ?? ""))). Your registry details are not shown to customers."
        case .rejected: return "Not approved\(row.legalNote.map { ": " + DashboardUI.esc($0) } ?? ".") Correct the details and submit again."
        }
    }

    private static func goLiveDetail(row: BusinessOnboardingRecord, state: OnboardingState) -> String {
        switch state.goLive {
        case .none: return state.requestBlockers.isEmpty ? "Ready: request production access below." : "Finish the steps above first."
        case .requested: return "Requested \(DashboardFormat.optional(row.goLiveRequestedAt)); an operator is reviewing it."
        case .approved: return "Approved \(DashboardFormat.optional(row.goLiveDecidedAt)). Live keys can be created."
        case .rejected: return "Not approved\(row.goLiveNote.map { ": " + DashboardUI.esc($0) } ?? ".") Address the points and request again."
        }
    }

    private static func assuranceDetail(row: BusinessOnboardingRecord, state: OnboardingState, grace: TimeInterval) -> String {
        guard state.goLive == .approved else { return "Starts when you are in production." }
        if state.suspended { return "Your organization is suspended\(row.assuranceSuspended ? " because a re-check failed. Fix it and the suspension lifts by itself." : ".")" }
        if let started = row.assuranceGraceStartedAt {
            return "A re-check failed (\(DashboardUI.esc(row.assuranceFailure ?? ""))). Fix it before \(DashboardFormat.date(started.addingTimeInterval(grace))) to stay active."
        }
        return "Your domain and agreements are re-checked periodically. Last check: \(DashboardFormat.optional(row.assuranceCheckedAt))."
    }

    // MARK: Domains

    private static func domainsPage(_ req: Request, notice: String? = nil) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.viewOrganization) || p.can(.manageOrganization) else { throw APIError.forbidden }
        let domains = try await DomainControl(db: req.db, ctx: req.ctx).domains(businessId: businessId)
        let canManage = p.can(.manageOrganization)
        let cards = domains.map { d -> String in
            let id = d.id?.uuidString.lowercased() ?? ""
            let status = d.status == "verified" ? DashboardFormat.badge("Verified", "ok") : (d.status == "failed" ? DashboardFormat.badge("Re-check failed", "dg") : DashboardFormat.badge("Not verified", ""))
            var out = "<div class=\"card\"><h2>\(DashboardUI.esc(d.domain)) \(status)</h2>"
            if d.status != "verified" {
                out += """
                <p>Publish <strong>one</strong> of these:</p>\
                <h3>DNS TXT record</h3><pre>Name:  \(DashboardUI.esc(DomainControl.recordName(for: d.domain)))\nType:  TXT\nValue: \(DashboardUI.esc(DomainControl.expectedValue(token: d.token)))</pre>\
                <h3>Or a file</h3><pre>https://\(DashboardUI.esc(d.domain))\(DomainControl.wellKnownPath)\nContent: \(DashboardUI.esc(DomainControl.expectedValue(token: d.token)))</pre>
                """
            } else {
                out += "<p class=\"mu sm\">Verified \(DashboardFormat.optional(d.verifiedAt)) by \(DashboardUI.esc(d.method ?? "")). Next re-check \(DashboardFormat.optional(d.nextCheckAt)). Keep the record in place: it is re-checked periodically.</p>"
            }
            if let error = d.lastError { out += "<p class=\"mu sm\">Last check: \(DashboardUI.esc(error.replacingOccurrences(of: "_", with: " "))).</p>" }
            if canManage {
                out += "<div class=\"row\"><form method=\"post\" action=\"/dashboard/organization/domains/\(id)/check\">\(DashboardUI.csrf(p))<button class=\"btn\" type=\"submit\">Check now</button></form>"
                    + "<form method=\"post\" action=\"/dashboard/organization/domains/\(id)/remove\">\(DashboardUI.csrf(p))<button class=\"btn d sm\" type=\"submit\" aria-label=\"Remove \(DashboardUI.esc(d.domain))\">Remove</button></form></div>"
            }
            return out + "</div>"
        }.joined()
        var add = ""
        if canManage {
            add = "<div class=\"card\"><h2>Add a domain</h2><form method=\"post\" action=\"/dashboard/organization/domains\">\(DashboardUI.csrf(p))<label for=\"domain\">Domain you control</label><input id=\"domain\" name=\"domain\" type=\"text\" maxlength=\"253\" required placeholder=\"example.com\"><p class=\"mu sm\">Verified domains are re-checked periodically. A domain can be verified by only one organization.</p><button class=\"btn\" type=\"submit\">Add domain</button></form></div>"
        }
        let note = notice.map { "<div class=\"notice dg\" role=\"alert\">\(DashboardUI.esc($0))</div>" } ?? ""
        return DashboardUI.businessPage(p, title: "Domains", active: "/dashboard/organization/domains", subtitle: "Prove that your organization controls its domain.", flash: DashboardFormat.flash(req),
                                        body: note + (cards.isEmpty ? "<p class=\"mu\">No domains yet.</p>" : cards) + add)
    }
}
