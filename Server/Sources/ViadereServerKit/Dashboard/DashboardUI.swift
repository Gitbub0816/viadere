@preconcurrency import Crypto
import Foundation
import Vapor
import ViadereCore

/// Server-rendered HTML for the business dashboard and operator console. No framework, no third-party assets:
/// one stylesheet and (on sign-in pages only) one small passkey script, both pinned by SHA-256 in the CSP.
/// Visual language follows `Design/brand-guide.html`: charcoal / ivory / champagne, quiet and spacious.
enum DashboardUI {
    // MARK: Assets

    /// The console stylesheet (the design system lives in `ConsoleDesignSystem.swift`).
    static var css: String { ConsoleUI.css }

    static let script = """
    (function(){'use strict';
    function b2a(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';var b=atob(s),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer}
    function a2b(b){var a=new Uint8Array(b),s='';for(var i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')}
    function post(u,body,csrf){var h={'Content-Type':'application/json'};if(csrf)h['X-CSRF-Token']=csrf;return fetch(u,{method:'POST',headers:h,body:JSON.stringify(body||{}),credentials:'same-origin'}).then(function(r){return r.json().catch(function(){return null}).then(function(j){if(!r.ok)throw new Error(j&&j.error&&j.error.message||'Request failed');return j})})}
    function go(p){if(typeof p==='string'&&p.charAt(0)==='/'&&p.charAt(1)!=='/')location.assign(p)}
    function create(o){return navigator.credentials.create({publicKey:{challenge:b2a(o.challenge),rp:{id:o.relyingPartyId,name:o.relyingPartyName},user:{id:new TextEncoder().encode(o.userId),name:o.userName,displayName:o.userDisplayName},pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{residentKey:'required',userVerification:'required'},timeout:o.timeoutMilliseconds,attestation:'none'}}).then(function(c){return{id:c.id,rawId:a2b(c.rawId),attestationObject:a2b(c.response.attestationObject),clientDataJSON:a2b(c.response.clientDataJSON),transports:c.response.getTransports?c.response.getTransports():[]}})}
    function get(o){var pk={challenge:b2a(o.challenge),rpId:o.relyingPartyId,userVerification:'required',timeout:o.timeoutMilliseconds};if(o.allowCredentialIds&&o.allowCredentialIds.length)pk.allowCredentials=o.allowCredentialIds.map(function(i){return{type:'public-key',id:b2a(i)}});return navigator.credentials.get({publicKey:pk}).then(function(c){var r=c.response;return{id:c.id,rawId:a2b(c.rawId),authenticatorData:a2b(r.authenticatorData),clientDataJSON:a2b(r.clientDataJSON),signature:a2b(r.signature),userHandle:r.userHandle?a2b(r.userHandle):null}})}
    function run(el){var mode=el.getAttribute('data-passkey'),begin=el.getAttribute('data-begin'),fin=el.getAttribute('data-finish'),csrf=el.getAttribute('data-csrf'),next=el.getAttribute('data-next'),msg=document.getElementById('pk-msg');
    var body={};if(el.tagName==='FORM'){new FormData(el).forEach(function(v,k){if(k!=='_csrf')body[k]=v})}
    if(msg)msg.textContent='';
    el.setAttribute('aria-busy','true');
    post(begin,body,csrf).then(function(o){return(mode==='register'?create(o):get(o)).then(function(c){return post(fin,{ceremonyId:o.ceremonyId,credential:c},csrf)})}).then(function(r){go(next||(r&&r.redirect)||'/')}).catch(function(e){el.removeAttribute('aria-busy');if(msg)msg.textContent=e&&e.name==='NotAllowedError'?'Passkey prompt was cancelled.':(e&&e.message)||'Something went wrong.'})}
    document.addEventListener('submit',function(e){var f=e.target;if(f&&f.getAttribute&&f.getAttribute('data-passkey')){e.preventDefault();run(f)}});
    document.addEventListener('click',function(e){var b=e.target&&e.target.closest&&e.target.closest('button[data-passkey]');if(b&&!b.form){e.preventDefault();run(b)}});
    })();
    """

    static func sha256Base64(_ text: String) -> String { Data(SHA256.hash(data: Data(text.utf8))).base64EncodedString() }

    /// The pinned hashes, computed once (the stylesheet and the script are constants).
    static let styleHash = sha256Base64(ConsoleUI.css)
    static let scriptHash = sha256Base64(script)

    /// CSP for HTML pages. Scripts are allowed only where a page declares `needsScript` (passkey ceremonies).
    /// `frames`: the page embeds same-origin sandboxed previews (Brand Kit Studio WP-2.5, Loop Studio WP-3.7, operator Loop review).
    static func csp(script: Bool, frames: Bool = false) -> String {
        var parts = ["default-src 'none'", "style-src 'sha256-\(styleHash)'", "img-src 'self' data:", "font-src 'none'",
                     "form-action 'self'", "base-uri 'none'", "frame-ancestors 'none'"]
        if script { parts.append("script-src 'sha256-\(scriptHash)'"); parts.append("connect-src 'self'") }
        if frames { parts.append("frame-src 'self'") }
        return parts.joined(separator: "; ")
    }

    // MARK: Brand mark (single colour; from Design/svg/viadere-mark-mono-dark.svg)

    static let markSVG = """
    <svg viewBox="0 0 321.71 146" role="img" aria-label="Viadere" xmlns="http://www.w3.org/2000/svg"><path d="M0 46C31.34 46 52.61 53.08 58.62 61.38L88.74 102.99L115.22 66.49C130.87 44.9 156.4 45.68 170.7 68.18L189.31 97.44L215.59 61.52C231.34 40 256.71 40.99 270.74 63.66L321.71 146C290.37 146 271.7 141.91 268.73 137.12L240.79 91.98L213.57 129.17C198.67 149.53 174.45 148.74 160.91 127.45L141.09 96.28L116.14 130.69C101.32 151.11 76.1 151.1 61.31 130.67L0 46Z" fill="currentColor" opacity="0.62"/><path d="M0 46C31.34 46 52.61 53.08 58.62 61.38L88.74 102.99C101.18 120.16 102.65 139.14 118.23 127.81L116.14 130.69C101.32 151.11 76.1 151.1 61.31 130.67L0 46Z" fill="currentColor"/><path d="M113.12 69.37L115.22 66.49C130.87 44.9 156.4 45.68 170.7 68.18L189.31 97.44C200.84 115.58 199.82 137.73 215.67 126.3L213.57 129.17C198.67 149.53 174.45 148.74 160.91 127.45L141.09 96.28C129.64 78.27 128.81 57.95 113.12 69.37Z" fill="currentColor"/><path d="M213.49 64.4L215.59 61.52C231.34 40 256.71 40.99 270.74 63.66L321.71 146C290.37 146 271.7 141.91 268.73 137.12L240.79 91.98C229.56 73.83 229.23 53.05 213.49 64.4Z" fill="currentColor"/><circle cx="155.21" cy="20.5" r="20.5" fill="currentColor"/></svg>
    """

    static var brand: String { "<div class=\"brand\">\(markSVG)<div><b>via</b><span>dere</span></div></div>" }

    /// The brand as the home link of a signed-in shell, with the realm tag.
    static func brandLink(home: String, realm: String) -> String {
        "<a class=\"brand\" href=\"\(home)\">\(markSVG)<div><b>via</b><span>dere</span></div><span class=\"realm pill t-neutral\">\(esc(realm))</span></a>"
    }

    // MARK: Escaping

    static func esc(_ text: String) -> String { WebRoutes.escape(text) }

    // MARK: Navigation

    struct NavItem {
        var title: String
        var path: String
        /// Shown to a member holding **any** of these.
        var permissions: [DashboardPermission]

        func visible(to p: DashboardPrincipal) -> Bool { permissions.isEmpty || permissions.contains(where: p.can) }
    }

    /// A console section (spec §9.1). The landing page is `path`; `children` are the pages inside it, shown as tabs.
    struct NavSection {
        var title: String
        var path: String
        var permissions: [DashboardPermission]
        var children: [NavItem]
        /// Paths that belong to the section besides its landing page and children.
        var prefixes: [String] = []
        /// The sidebar group the section is listed under (nil: ungrouped, at the top).
        var group: String? = nil
        var icon: ConsoleUI.Icon = .home

        func visible(to p: DashboardPrincipal) -> Bool { permissions.isEmpty || permissions.contains(where: p.can) }
        func contains(_ path: String) -> Bool {
            ([self.path] + children.map(\.path) + prefixes).contains { path == $0 || (self.path != "/dashboard" && path.hasPrefix($0 + "/")) }
        }
    }

    /// Spec §9.1 order; groups only add headings in the sidebar, the order stays the spec's.
    static let sections: [NavSection] = [
        NavSection(title: "Dashboard", path: "/dashboard", permissions: [.viewOverview], children: [], icon: .home),
        NavSection(title: "Organization", path: "/dashboard/organization", permissions: [.viewOrganization, .viewTeam, .manageOrganization, .manageBrandKits], children: [
            NavItem(title: "Profile and onboarding", path: "/dashboard/organization", permissions: [.viewOrganization, .manageOrganization]),
            NavItem(title: "Domains", path: "/dashboard/organization/domains", permissions: [.viewOrganization, .manageOrganization]),
            NavItem(title: "Your Viadere page", path: "/dashboard/organization/page", permissions: [.viewOrganization, .manageOrganization]),
            NavItem(title: "Customer profile access", path: ProfileConsole.path, permissions: [.viewOrganization, .manageOrganization]),
            NavItem(title: "Brand Kits", path: "/dashboard/brand", permissions: [.viewOrganization, .manageBrandKits]),
            NavItem(title: "Team", path: "/dashboard/team", permissions: [.viewTeam]),
        ], group: "Set up", icon: .building),
        NavSection(title: "Developers", path: "/dashboard/developers", permissions: [.viewAPIKeys, .viewWebhooks, .viewTemplates], children: [
            NavItem(title: "Overview", path: "/dashboard/developers", permissions: []),
            NavItem(title: "API keys", path: "/dashboard/api-keys", permissions: [.viewAPIKeys]),
            NavItem(title: "Webhooks", path: "/dashboard/webhooks", permissions: [.viewWebhooks]),
            NavItem(title: "Sandbox", path: "/dashboard/developers/sandbox", permissions: [.viewWebhooks, .manageWebhooks]),
            NavItem(title: "Templates", path: "/dashboard/templates", permissions: [.viewTemplates]),
        ], group: "Set up", icon: .code),
        NavSection(title: "Messaging", path: "/dashboard/messaging", permissions: [.viewMessaging, .viewConsent, .manageCampaigns], children: [
            NavItem(title: "Overview", path: "/dashboard/messaging", permissions: []),
            NavItem(title: "Campaigns", path: "/dashboard/campaigns", permissions: [.manageCampaigns]),
            NavItem(title: "Consent", path: "/dashboard/consent", permissions: [.viewConsent]),
        ], group: "Customers", icon: .chat),
        NavSection(title: "Inbox", path: "/dashboard/inbox", permissions: [.viewInbox], children: [], group: "Customers", icon: .inbox),
        NavSection(title: "Loops", path: "/dashboard/loops", permissions: [.submitLoops, .viewLoops], children: [
            NavItem(title: "Your Loops", path: "/dashboard/loops", permissions: []),
            NavItem(title: "Loop Studio", path: "/dashboard/loops/studio", permissions: []),
        ], group: "Customers", icon: .loop),
        NavSection(title: "Verify", path: "/dashboard/verification", permissions: [.viewVerify], children: [], group: "Trust services", icon: .verify),
        NavSection(title: "Approve", path: "/dashboard/approve", permissions: [.viewApprove], children: [], group: "Trust services", icon: .approve),
        NavSection(title: "Security", path: "/dashboard/security", permissions: [.viewSecurity], children: [
            NavItem(title: "Overview", path: "/dashboard/security", permissions: []),
            NavItem(title: "Sessions", path: "/dashboard/security/sessions", permissions: []),
            NavItem(title: "Network", path: "/dashboard/security/network", permissions: []),
            NavItem(title: "Certificates", path: "/dashboard/security/certificates", permissions: []),
            NavItem(title: "Alerts and contacts", path: "/dashboard/security/alerts", permissions: []),
            NavItem(title: "Approvals", path: "/dashboard/security/approvals", permissions: []),
            NavItem(title: "Audit log", path: "/dashboard/audit", permissions: [.viewAudit]),
        ], group: "Governance", icon: .lock),
        NavSection(title: "Compliance", path: "/dashboard/compliance", permissions: [.viewCompliance], children: [
            NavItem(title: "Agreements", path: "/dashboard/compliance", permissions: []),
            NavItem(title: "Retention", path: "/dashboard/compliance/retention", permissions: []),
            NavItem(title: "Data requests", path: "/dashboard/compliance/requests", permissions: []),
        ], group: "Governance", icon: .document),
        NavSection(title: "Billing", path: "/dashboard/billing", permissions: [.viewBilling], children: [], group: "Governance", icon: .card),
        NavSection(title: "Support", path: "/dashboard/support", permissions: [.viewSupport], children: [
            NavItem(title: "Help and tickets", path: "/dashboard/support", permissions: []),
            NavItem(title: "Integration health", path: "/dashboard/support/health", permissions: []),
            NavItem(title: "Notices", path: "/dashboard/support/notices", permissions: []),
            NavItem(title: "Appeals", path: "/dashboard/support/appeals", permissions: []),
        ], group: "Help", icon: .help),
    ]

    static func section(for path: String) -> NavSection? {
        sections.first { $0.contains(path) && $0.path != "/dashboard" } ?? (path == "/dashboard" ? sections.first : nil)
    }

    struct OperatorNavItem {
        var title: String
        var path: String
        var group: String
        var icon: ConsoleUI.Icon
    }

    /// The operator console, grouped by job: what waits for a decision, the accounts, the safety controls, communication, data.
    static let operatorSections: [OperatorNavItem] = [
        OperatorNavItem(title: "Applications", path: "/operator", group: "Review", icon: .queue),
        OperatorNavItem(title: "Brand review", path: "/operator/brand", group: "Review", icon: .palette),
        OperatorNavItem(title: "Loops", path: "/operator/loops", group: "Review", icon: .loop),
        OperatorNavItem(title: "Businesses", path: "/operator/businesses", group: "Accounts", icon: .store),
        OperatorNavItem(title: "Consumer accounts", path: "/operator/consumers", group: "Accounts", icon: .users),
        OperatorNavItem(title: "Abuse signals", path: "/operator/abuse", group: "Trust and safety", icon: .alert),
        OperatorNavItem(title: "Capability policy", path: "/operator/policy", group: "Trust and safety", icon: .sliders),
        OperatorNavItem(title: "Platform switches", path: "/operator/switches", group: "Trust and safety", icon: .toggle),
        OperatorNavItem(title: "Notices", path: "/operator/notices", group: "Communication", icon: .megaphone),
        OperatorNavItem(title: "Support", path: "/operator/support", group: "Communication", icon: .help),
        OperatorNavItem(title: "Data and retention", path: "/operator/retention", group: "Data", icon: .archive),
    ]

    /// Title and path pairs (kept for callers that only need the list).
    static var operatorNav: [(String, String)] { operatorSections.map { ($0.title, $0.path) } }

    static func operatorItem(for path: String) -> OperatorNavItem? {
        operatorSections.first { $0.path == path || ($0.path != "/operator" && path.hasPrefix($0.path + "/")) }
            ?? (path.hasPrefix("/operator/applications/") ? operatorSections.first : nil)
    }

    // MARK: Responses

    static func response(_ html: String, status: HTTPStatus = .ok, script: Bool = false, frames: Bool = false) -> Response {
        let response = Response(status: status, body: .init(string: html))
        response.headers.contentType = .html
        response.headers.replaceOrAdd(name: "Content-Security-Policy", value: csp(script: script, frames: frames))
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        response.headers.replaceOrAdd(name: "X-Robots-Tag", value: "noindex")
        // `same-origin`, not `no-referrer`: under no-referrer browsers send `Origin: null` on form POSTs, which the CSRF origin check
        // (rightly) refuses. Nothing is sent to other sites either way.
        response.headers.replaceOrAdd(name: "Referrer-Policy", value: "same-origin")
        return response
    }

    private static func document(title: String, body: String, script: Bool) -> String {
        """
        <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\
        <meta name="referrer" content="same-origin"><meta name="robots" content="noindex"><meta name="color-scheme" content="light dark"><title>\(esc(title)) · Viadere</title>\
        <style>\(css)</style></head><body>\(body)\(script ? "<script>\(Self.script)</script>" : "")</body></html>
        """
    }

    /// Unauthenticated page (sign-in, sign-up, invitations). `footer` is markup shown under the card (links to the other flows).
    static func authPage(title: String, body: String, script: Bool = true, status: HTTPStatus = .ok, footer: String = "") -> Response {
        response(document(title: title, body: "<main id=\"main\" class=\"auth\">\(brand)<div class=\"card\">\(body)</div>\(footer.isEmpty ? "" : "<div class=\"foot\">\(footer)</div>")</main>", script: script),
                 status: status, script: script)
    }

    // MARK: Page chrome

    private static func breadcrumbs(_ crumbs: [ConsoleUI.Crumb]) -> String {
        let items = crumbs.enumerated().map { index, crumb -> String in
            let last = index == crumbs.count - 1
            guard !last, let href = crumb.href else { return "<li\(last ? " aria-current=\"page\"" : "")>\(esc(crumb.title))</li>" }
            return "<li><a href=\"\(esc(href))\">\(esc(crumb.title))</a></li>"
        }.joined()
        return "<nav class=\"crumbs\" aria-label=\"Breadcrumb\"><ol>\(items)</ol></nav>"
    }

    private static func pageHeader(title: String, subtitle: String?, actions: String) -> String {
        "<header class=\"ph\"><div><h1>\(esc(title))</h1>\(subtitle.map { "<p class=\"sub\">\(esc($0))</p>" } ?? "")</div>\(actions.isEmpty ? "" : "<div class=\"acts\">\(actions)</div>")</header>"
    }

    /// Default trail for a business page: Dashboard › section › tab › page (repeats collapsed).
    static func businessCrumbs(active: String, title: String) -> [ConsoleUI.Crumb] {
        var crumbs = [ConsoleUI.Crumb("Dashboard", "/dashboard")]
        if let section = section(for: active), section.path != "/dashboard" {
            crumbs.append(ConsoleUI.Crumb(section.title, section.path))
            if let child = section.children.first(where: { $0.path == active }), child.path != section.path { crumbs.append(ConsoleUI.Crumb(child.title, child.path)) }
        }
        if crumbs.last?.title != title { crumbs.append(ConsoleUI.Crumb(title, nil)) }
        return crumbs
    }

    /// Default trail for an operator page: Operator › nav item › page.
    static func operatorCrumbs(active: String, title: String) -> [ConsoleUI.Crumb] {
        var crumbs = [ConsoleUI.Crumb("Operator", "/operator")]
        if let item = operatorItem(for: active), item.path != "/operator" || title != item.title { crumbs.append(ConsoleUI.Crumb(item.title, item.path)) }
        if crumbs.last?.title != title { crumbs.append(ConsoleUI.Crumb(title, nil)) }
        return crumbs
    }

    /// Signed-in business page. Landmarks: skip link, `aside` with the console navigation, a top bar with the breadcrumb trail and the
    /// signed-in person, then `main` with the page header (h1, subtitle, primary actions), the section's tabs, banners, the flash and the body.
    static func businessPage(_ p: DashboardPrincipal, title: String, active: String, subtitle: String? = nil, actions: String = "",
                             flash: String? = nil, flashTone: ConsoleUI.Tone = .success, breadcrumbs crumbs: [ConsoleUI.Crumb]? = nil,
                             body: String, status: HTTPStatus = .ok, script: Bool = false, frames: Bool = false) -> Response {
        let current = section(for: active)
        var nav = ""
        var group: String? = "\u{0}"
        for section in sections where section.visible(to: p) {
            if section.group != group {
                if let heading = section.group { nav += "<p class=\"nav-g\" aria-hidden=\"true\">\(esc(heading))</p>" }
                group = section.group
            }
            nav += "<a href=\"\(section.path)\"\(section.path == current?.path ? " aria-current=\"page\"" : "")>\(ConsoleUI.icon(section.icon))\(esc(section.title))</a>"
        }
        var tabs = ""
        if let current, current.children.count > 1 {
            let links = current.children.filter { $0.visible(to: p) }
                .map { "<a href=\"\($0.path)\"\($0.path == active ? " aria-current=\"page\"" : "")>\(esc($0.title))</a>" }.joined()
            tabs = "<nav class=\"tabs\" aria-label=\"\(esc(current.title)) pages\">\(links)</nav>"
        }
        var banner = ""
        if let business = p.business, business.status != .verified {
            switch business.status {
            case .pending:
                banner = ConsoleUI.callout(.accent, title: "Your organization is awaiting verification", """
                <p>Verify a domain to unlock the sandbox; production keys unlock when Viadere approves your application and your go-live review. \
                You can invite your team in the meantime. <a href="/dashboard/organization">See what's left</a></p>
                """)
            case .suspended:
                banner = ConsoleUI.callout(.danger, title: "This organization is suspended",
                                           "<p>API keys and interactions are blocked. Contact Viadere support, or <a href=\"/dashboard/support/appeals\">appeal the decision</a>.</p>")
            default:
                banner = ConsoleUI.callout(.danger, title: "This organization is not active", "<p>Contact Viadere support.</p>")
            }
        }
        let orgName = p.business?.displayName ?? ""
        let role = p.role?.title ?? ""
        let side = """
        <aside class="side">\(brandLink(home: "/dashboard", realm: "Business"))<div class="org"><span class="k">Organization</span><strong>\(esc(orgName))</strong>\
        \(role.isEmpty ? "" : ConsoleUI.pill(role, .neutral))</div><nav aria-label="Console">\(nav)</nav>\
        <div class="side-foot"><a href="/dashboard/security/sessions">Your sessions</a><a href="/dashboard/support">Help and status</a></div></aside>
        """
        let top = """
        <div class="top">\(breadcrumbs(crumbs ?? businessCrumbs(active: active, title: title)))<div class="who"><span class="nm"><strong>\(esc(p.user.displayName))</strong> · \(esc(orgName))</span>\
        <form method="post" action="/dashboard/logout"><input type="hidden" name="_csrf" value="\(esc(p.csrf))"><button class="btn g sm" type="submit">\(ConsoleUI.icon(.signout))Sign out</button></form></div></div>
        """
        let toast = flash.map { ConsoleUI.toast($0, tone: flashTone) } ?? ""
        let main = "<main id=\"main\" tabindex=\"-1\">\(pageHeader(title: title, subtitle: subtitle, actions: actions))\(tabs)\(banner)\(toast)\(body)</main>"
        return response(document(title: title, body: "<a class=\"skip\" href=\"#main\">Skip to content</a><div class=\"shell\">\(side)<div class=\"frame\">\(top)\(main)</div></div>", script: script),
                        status: status, script: script, frames: frames)
    }

    /// Signed-in operator page: the same shell with an inverted (charcoal) sidebar, so staff always see which console they are in.
    static func operatorPage(_ p: DashboardPrincipal, title: String, active: String, subtitle: String? = nil, actions: String = "", flash: String? = nil,
                             flashTone: ConsoleUI.Tone = .success, breadcrumbs crumbs: [ConsoleUI.Crumb]? = nil,
                             body: String, status: HTTPStatus = .ok, script: Bool = false, frames: Bool = false) -> Response {
        let current = operatorItem(for: active)
        var nav = ""
        var group = ""
        for item in operatorSections {
            if item.group != group { nav += "<p class=\"nav-g\" aria-hidden=\"true\">\(esc(item.group))</p>"; group = item.group }
            nav += "<a href=\"\(item.path)\"\(item.path == current?.path ? " aria-current=\"page\"" : "")>\(ConsoleUI.icon(item.icon))\(esc(item.title))</a>"
        }
        let side = """
        <aside class="side">\(brandLink(home: "/operator", realm: "Operator"))<div class="org"><span class="k">Operator console</span><strong>\(esc(p.user.displayName))</strong>\
        \(ConsoleUI.pill("Viadere staff", .neutral))</div><nav aria-label="Operator">\(nav)</nav>\
        <div class="side-foot"><span>Every change needs your passkey, a reason, and is audited.</span></div></aside>
        """
        let top = """
        <div class="top">\(breadcrumbs(crumbs ?? operatorCrumbs(active: active, title: title)))<div class="who"><span class="nm"><strong>\(esc(p.user.displayName))</strong> · Operator</span>\
        <form method="post" action="/operator/logout"><input type="hidden" name="_csrf" value="\(esc(p.csrf))"><button class="btn g sm" type="submit">\(ConsoleUI.icon(.signout))Sign out</button></form></div></div>
        """
        let toast = flash.map { ConsoleUI.toast($0, tone: flashTone) } ?? ""
        let main = "<main id=\"main\" tabindex=\"-1\">\(pageHeader(title: title, subtitle: subtitle, actions: actions))\(toast)\(body)</main>"
        return response(document(title: title + " · Operator", body: "<a class=\"skip\" href=\"#main\">Skip to content</a><div class=\"shell op\">\(side)<div class=\"frame\">\(top)\(main)</div></div>", script: script),
                        status: status, script: script, frames: frames)
    }

    /// Error page inside the signed-in shell: what happened in plain words, which fields to check, and a way back (`back` is a validated
    /// same-console path from `ConsoleUI.backPath`).
    static func errorPage(_ p: DashboardPrincipal?, status: HTTPStatus, title: String, message: String, fields: [String] = [], back: String? = nil) -> Response {
        let home = p?.realm.home ?? "/dashboard"
        var detail = "<p>\(esc(message))</p>"
        if !fields.isEmpty { detail += "<p class=\"sm\">Check: \(fields.map { "<strong>\(esc($0))</strong>" }.joined(separator: ", ")).</p>" }
        let tone: ConsoleUI.Tone = status == .forbidden || status == .notFound || status == .tooManyRequests ? .warning : .danger
        var actions = ""
        if let back { actions += ConsoleUI.linkButton("Go back and fix it", href: back, .primary) }
        actions += ConsoleUI.linkButton("Back to the dashboard", href: home, back == nil ? .primary : .secondary)
        let body = ConsoleUI.callout(tone, title: "\(status.code) · \(status.reasonPhrase)", urgent: true, detail) + "<div class=\"row\">\(actions)</div>"
        if let p, p.realm == .business { return businessPage(p, title: title, active: "", body: body, status: status) }
        if let p { return operatorPage(p, title: title, active: "", body: body, status: status) }
        return authPage(title: title, body: "<h1>\(esc(title))</h1><p>\(esc(message))</p>", script: false, status: status)
    }

    /// Hidden CSRF input for forms.
    static func csrf(_ p: DashboardPrincipal) -> String { "<input type=\"hidden\" name=\"_csrf\" value=\"\(esc(p.csrf))\">" }

    static func reauthPage(_ p: DashboardPrincipal, next: String, minutes: Int) -> Response {
        let realmPath = p.realm == .business ? "/dashboard" : "/operator"
        let body = ConsoleUI.card("Confirm with your passkey", description: "This action is protected. Use the passkey on this device or on your phone.", """
        <p>For your security, confirm it's you before continuing. Confirming unlocks sensitive actions for <strong>\(minutes) minutes</strong>; \
        after that, or after a period without activity, you are asked again.</p>\
        <div class="form-actions"><button class="btn" type="button" data-passkey="reauth" data-begin="\(realmPath)/auth/reauth/begin" data-finish="\(realmPath)/auth/reauth/finish" \
        data-csrf="\(esc(p.csrf))" data-next="\(esc(next))">\(ConsoleUI.icon(.key))Confirm with passkey</button>\(ConsoleUI.linkButton("Cancel", href: realmPath, .ghost))</div>\
        <p id="pk-msg" class="sm err" role="alert"></p>
        """)
        return p.realm == .business
            ? businessPage(p, title: "Confirm it's you", active: "", body: body, status: .forbidden, script: true)
            : operatorPage(p, title: "Confirm it's you", active: "", body: body, status: .forbidden, script: true)
    }
}

extension ConsoleUI {
    /// One step of a breadcrumb trail; the last one is the current page (no link).
    struct Crumb: Sendable {
        var title: String
        var href: String?
        init(_ title: String, _ href: String?) { self.title = title; self.href = href }
    }
}
