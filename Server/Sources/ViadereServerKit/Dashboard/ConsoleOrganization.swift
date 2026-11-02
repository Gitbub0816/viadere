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
        let csrf = DashboardUI.csrf(p)

        // Profile: who customers see, and where the application stands.
        var profileBody = ""
        if business.isVerified {
            let summary = try await DirectoryService(db: req.db).summary(for: business)
            profileBody += ConsoleUI.keyValues([
                ("Display name", DashboardUI.esc(business.displayName)),
                ("Handle", "<strong>\(DashboardUI.esc(summary?.handle?.display ?? "none"))</strong>"),
                ("Code", "<strong class=\"mono\">\(DashboardUI.esc(summary?.code.display ?? ""))</strong>"),
                ("Verified", DashboardFormat.optional(business.verifiedAt)),
            ])
            profileBody += "<p class=\"mu sm\">Your permanent code is never reassigned. Your public display name and your legal entity are kept separate: the legal entity is reviewed by Viadere and is not shown to customers.</p>"
        } else if let application {
            switch application.state {
            case "pending":
                profileBody += ConsoleUI.callout(.accent, title: "Application under review", "<p>Submitted \(DashboardFormat.date(application.submittedAt)). Handles and codes are issued only after verification; you can keep setting up in the meantime.</p>")
            case "rejected":
                profileBody += ConsoleUI.callout(.danger, title: "Application declined", urgent: true, "<p>\(application.decisionNote.map { DashboardUI.esc($0) } ?? "Viadere declined the application.") Correct the details below and apply again, or <a href=\"/dashboard/support/appeals\">appeal the decision</a>.</p>")
                if canManage {
                    profileBody += ConsoleUI.form("/dashboard/organization", csrf: csrf,
                        "<div class=\"cols\">"
                        + ConsoleUI.input("legalName", label: "Legal name", id: "legalName", value: application.legalName ?? "", attrs: ["maxlength": "120"])
                        + ConsoleUI.input("website", label: "Website", id: "website", type: "url", value: application.website ?? "", placeholder: "https://", attrs: ["maxlength": "200"])
                        + ConsoleUI.input("requestedHandle", label: "Requested handle", id: "requestedHandle", value: application.requestedHandle ?? "", attrs: ["maxlength": "30"])
                        + "</div>"
                        + ConsoleUI.textarea("description", label: "What will you use Viadere for?", id: "description", value: application.detail ?? "", attrs: ["maxlength": "500"])
                        + ConsoleUI.formActions(ConsoleUI.button("Apply again")))
                }
            default:
                profileBody += "<p>Status: \(DashboardUI.esc(application.state)).</p>"
            }
        } else {
            profileBody += "<p>This organization is \(DashboardUI.esc(business.verificationStatus)).</p>"
        }
        let profile = ConsoleUI.card(business.displayName, actions: DashboardFormat.statusBadge(business.status), profileBody)

        // The checklist: one row per stage, with what is open and where to do it.
        let outstanding = try await ContractService(db: req.db, ctx: req.ctx).outstanding(businessId: businessId)
        let profileAllowed = try await EntitlementService(db: req.db, ctx: req.ctx).snapshot(businessId: businessId).profileCategories
        let profilePending = try await ProfileCategoryRequestRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$status == "pending").count()
        func mark(_ done: Bool) -> String { done ? "done" : "to do" }
        var steps: [ConsoleUI.Step] = [
            ConsoleUI.Step(true, "Workspace", "Your account is verified by email and protected by a passkey."),
            ConsoleUI.Step(state.domainVerified, "Domain control", state.domainVerified
                ? "Verified: \(DashboardUI.esc(row.controlDomain ?? "")) (\(DashboardUI.esc(row.controlMethod ?? ""))). Unlocks the sandbox."
                : "Publish a DNS record to prove you control your domain. <a href=\"/dashboard/organization/domains\">Verify a domain</a>"),
            ConsoleUI.Step(state.legalEntity == .approved, "Legal entity", legalEntityDetail(row: row, state: state)),
        ]
        if state.enhanced != .notRequired {
            steps.append(ConsoleUI.Step(state.enhanced == .approved, "Additional review", state.enhanced == .approved ? "Approved."
                : (state.enhanced == .rejected ? "The additional review for your category was not approved. Contact Viadere support." : "Your category needs an additional review by Viadere. We will contact you.")))
        }
        steps += [
            ConsoleUI.Step(state.identityVerified, "Public identity", state.identityVerified ? "Handle and code issued." : "Issued when Viadere approves your application."),
            ConsoleUI.Step(state.contractsCurrent, "Agreements", state.contractsCurrent ? "All required agreements are accepted at their current version."
                : "\(outstanding.count) to accept. <a href=\"/dashboard/compliance\">Open Compliance &gt; Agreements</a>"),
            ConsoleUI.Step(state.integrationComplete, "Integration", "Sandbox key: \(mark(state.sandboxKey)) · test customer: \(mark(state.testCustomer)) · test event: \(mark(state.testEvent)). <a href=\"/dashboard/developers/sandbox\">Open the sandbox</a>"),
            ConsoleUI.Step(!profileAllowed.isEmpty, "Customer profile access", ProfileConsole.checklistDetail(allowed: profileAllowed, pending: profilePending)),
            ConsoleUI.Step(state.securityContact, "Security contact", state.securityContact ? "Set." : "Add an operational security contact. <a href=\"/dashboard/security/alerts\">Security &gt; Alerts and contacts</a>"),
            ConsoleUI.Step(state.goLive == .approved, "Go-live review", goLiveDetail(row: row, state: state)),
            ConsoleUI.Step(state.goLive == .approved && !state.suspended, "Ongoing assurance", assuranceDetail(row: row, state: state, grace: req.ctx.config.operations.assuranceGrace)),
        ]
        let onboarding = ConsoleUI.card("Onboarding", description: "The path from sign-up to production. Each step links to where it is done.",
                                        actions: ConsoleUI.pill("Stage: \(state.stage.rawValue)", state.goLive == .approved ? .success : .accent),
                                        ConsoleUI.checklist(steps, label: "Onboarding steps"))

        // The next action, where it is taken.
        var forms = ""
        if canManage, state.domainVerified, state.legalEntity == .none || state.legalEntity == .rejected {
            forms += ConsoleUI.card("Legal entity", description: "A Viadere reviewer checks these details against the public registry. Give references to your evidence (a registry URL or record id); do not upload documents here.",
                ConsoleUI.form("/dashboard/organization/legal-entity", csrf: csrf,
                    "<div class=\"cols\">"
                    + ConsoleUI.input("registryName", label: "Registered name", id: "registryName", value: row.legalRegistryName ?? business.legalName ?? "", required: true, attrs: ["maxlength": "120"])
                    + ConsoleUI.input("registryNumber", label: "Registry number", id: "registryNumber", value: row.legalRegistryNumber ?? "", required: true, attrs: ["maxlength": "64", "spellcheck": "false"])
                    + ConsoleUI.input("jurisdiction", label: "Jurisdiction", id: "jurisdiction", value: row.legalJurisdiction ?? "", placeholder: "US-DE", help: "ISO region code, for example US-DE.", required: true,
                                      attrs: ["maxlength": "6", "autocapitalize": "characters"])
                    + "</div>"
                    + ConsoleUI.textarea("evidence", label: "Evidence references", id: "evidence", value: row.evidenceReferences.joined(separator: "\n"), help: "One per line, up to five.", required: true, attrs: ["maxlength": "800"])
                    + ConsoleUI.formActions(ConsoleUI.button("Submit for review"))))
        }
        if canManage, state.goLive == .none || state.goLive == .rejected {
            let blockers = state.requestBlockers
            if blockers.isEmpty {
                forms += ConsoleUI.card("Request production access", description: "Describe what you will send, to whom, and how much. A Viadere operator reviews the request.",
                    ConsoleUI.form("/dashboard/organization/go-live", csrf: csrf,
                        ConsoleUI.textarea("useCase", label: "Use case", id: "useCase", help: "At least 20 characters: the messages, the audience and why customers expect them.", required: true,
                                           attrs: ["minlength": "20", "maxlength": "1000"])
                        + ConsoleUI.input("volume", label: "Expected volume", id: "volume", placeholder: "About 50,000 messages a month", required: true, attrs: ["maxlength": "120"])
                        + ConsoleUI.formActions(ConsoleUI.button("Request production access", passkey: true) + ConsoleUI.passkeyNote())))
            } else {
                forms += ConsoleUI.card("Request production access", description: "Available once these are done.",
                                        "<ul>\(blockers.map { "<li>\(DashboardUI.esc($0.title))</li>" }.joined())</ul>")
            }
        }
        let body = profile + (forms.isEmpty ? "" : ConsoleUI.sectionTitle("Your next step") + forms) + onboarding
        return DashboardUI.businessPage(p, title: "Organization", active: "/dashboard/organization", subtitle: "Your profile and the path to production.", flash: DashboardFormat.flash(req), body: body)
    }

    private static func legalEntityDetail(row: BusinessOnboardingRecord, state: OnboardingState) -> String {
        switch state.legalEntity {
        case .none: return state.domainVerified ? "Submit your registration details in the form above." : "Verify a domain first."
        case .submitted: return "Submitted \(DashboardFormat.optional(row.legalSubmittedAt)); waiting for a Viadere reviewer."
        case .approved: return "Approved \(DashboardFormat.optional(row.legalReviewedAt)) (\(DashboardUI.esc(row.legalJurisdiction ?? ""))). Your registry details are not shown to customers."
        case .rejected: return "Not approved\(row.legalNote.map { ": " + DashboardUI.esc($0) } ?? ".") Correct the details and submit again."
        }
    }

    private static func goLiveDetail(row: BusinessOnboardingRecord, state: OnboardingState) -> String {
        switch state.goLive {
        case .none: return state.requestBlockers.isEmpty ? "Ready: request production access above." : "Finish the steps above first."
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
            let status = d.status == "verified" ? DashboardFormat.badge("Verified", "ok") : (d.status == "failed" ? DashboardFormat.badge("Re-check failed", "dg") : DashboardFormat.badge("Not verified", "wa"))
            var out = ""
            if d.status != "verified" {
                out += """
                <p>Publish <strong>one</strong> of these, then choose <em>Check now</em>. DNS changes can take a while to spread.</p><div class="cols">\
                <div><h3>Option 1: DNS TXT record</h3><pre>Name:  \(DashboardUI.esc(DomainControl.recordName(for: d.domain)))\nType:  TXT\nValue: \(DashboardUI.esc(DomainControl.expectedValue(token: d.token)))</pre></div>\
                <div><h3>Option 2: a file on your site</h3><pre>https://\(DashboardUI.esc(d.domain))\(DomainControl.wellKnownPath)\nContent: \(DashboardUI.esc(DomainControl.expectedValue(token: d.token)))</pre></div></div>
                """
            } else {
                out += ConsoleUI.keyValues([("Verified", "\(DashboardFormat.optional(d.verifiedAt)) by \(DashboardUI.esc(d.method ?? ""))"), ("Next re-check", DashboardFormat.optional(d.nextCheckAt))])
                out += "<p class=\"mu sm\">Keep the record in place: it is re-checked periodically.</p>"
            }
            if let error = d.lastError { out += "<p class=\"mu sm\">Last check: \(DashboardUI.esc(error.replacingOccurrences(of: "_", with: " "))).</p>" }
            var actions = ""
            if canManage {
                actions = ConsoleUI.form("/dashboard/organization/domains/\(id)/check", csrf: DashboardUI.csrf(p), ConsoleUI.button("Check now", d.status == "verified" ? .secondary : .primary, small: true, ariaLabel: "Check \(d.domain) now"))
                    + ConsoleUI.confirm("Remove", ariaLabel: "Remove \(d.domain)", ConsoleUI.form("/dashboard/organization/domains/\(id)/remove", csrf: DashboardUI.csrf(p),
                        "<p>Removing \(DashboardUI.esc(d.domain)) may lock the sandbox and keys again if it is your only verified domain.</p>"
                        + ConsoleUI.button("Remove domain", .dangerSolid, small: true, ariaLabel: "Remove \(d.domain)", passkey: true) + ConsoleUI.passkeyNote()))
            }
            return ConsoleUI.card(d.domain, actions: status, out + (actions.isEmpty ? "" : "<div class=\"row\">\(actions)</div>"))
        }.joined()
        var add = ""
        if canManage {
            add = ConsoleUI.card("Add a domain", id: "add", description: "Verified domains are re-checked periodically. A domain can be verified by only one organization.",
                ConsoleUI.form("/dashboard/organization/domains", csrf: DashboardUI.csrf(p),
                    ConsoleUI.input("domain", label: "Domain you control", id: "domain", placeholder: "example.com", help: "No https:// and no path; just the domain.", required: true,
                                    attrs: ["maxlength": "253", "autocapitalize": "none", "spellcheck": "false"])
                    + ConsoleUI.formActions(ConsoleUI.button("Add domain"))))
        }
        let note = notice.map { ConsoleUI.callout(.danger, title: "Not verified yet", urgent: true, "<p>\(DashboardUI.esc($0))</p>") } ?? ""
        let list = cards.isEmpty ? ConsoleUI.empty("No domains yet", "Prove you control your domain to unlock the sandbox and API keys.", icon: .building,
                                                   action: canManage ? ConsoleUI.linkButton("Add a domain", href: "#add", .primary, small: true) : "") : cards
        return DashboardUI.businessPage(p, title: "Domains", active: "/dashboard/organization/domains", subtitle: "Prove that your organization controls its domain.", flash: DashboardFormat.flash(req),
                                        body: note + list + add)
    }
}
