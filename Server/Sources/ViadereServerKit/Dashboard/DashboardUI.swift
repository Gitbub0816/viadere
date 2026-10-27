@preconcurrency import Crypto
import Foundation
import Vapor
import ViadereCore

/// Server-rendered HTML for the business dashboard and operator console. No framework, no third-party assets:
/// one stylesheet and (on sign-in pages only) one small passkey script, both pinned by SHA-256 in the CSP.
/// Visual language follows `Design/brand-guide.html`: charcoal / ivory / champagne, quiet and spacious.
enum DashboardUI {
    // MARK: Assets

    static let css = """
    :root{color-scheme:light dark;--bg:#F5F2EC;--sf:#FCFBF8;--sr:#FFFFFF;--fg:#1F1E1C;--mu:#6B675F;--ac:#8C7550;--acs:rgba(194,174,142,.16);--hl:rgba(31,30,28,.10);--dg:#A3412E;--ok:#4C7458;--pf:#1F1E1C;--op:#F5F2EC}
    @media(prefers-color-scheme:dark){:root{--bg:#121211;--sf:#1C1B1A;--sr:#262523;--fg:#F3F0EA;--mu:#A29D94;--ac:#CDB993;--acs:rgba(205,185,147,.14);--hl:rgba(243,240,234,.12);--dg:#E08068;--ok:#8DBB98;--pf:#F3F0EA;--op:#1F1E1C}}
    *{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
    body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,"SF Pro Text","Segoe UI",system-ui,sans-serif;-webkit-font-smoothing:antialiased}
    a{color:var(--ac);text-decoration:none}a:hover{text-decoration:underline}
    h1{font-size:1.65rem;font-weight:300;letter-spacing:-.01em;margin:0 0 .25rem}h2{font-size:1.05rem;font-weight:600;margin:0 0 .75rem}h3{font-size:.8rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--mu);margin:0 0 .5rem}
    p{margin:.4rem 0 .9rem}.mu{color:var(--mu)}.sm{font-size:.86rem}.mono,code,pre{font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:.84rem}
    .shell{display:grid;grid-template-columns:232px 1fr;min-height:100vh}
    .side{padding:1.5rem 1.1rem;border-right:1px solid var(--hl);background:var(--sf);position:sticky;top:0;align-self:start;height:100vh;display:flex;flex-direction:column;gap:1.25rem}
    .brand{display:flex;align-items:center;gap:.6rem;color:var(--fg);font-size:1.25rem;letter-spacing:-.008em}.brand svg{width:34px;height:auto}.brand b{font-weight:600}.brand span{font-weight:300}
    .org{padding:.7rem .8rem;border:1px solid var(--hl);border-radius:12px;background:var(--bg)}.org strong{display:block;font-weight:600}
    nav{display:flex;flex-direction:column;gap:2px}nav a{padding:.5rem .7rem;border-radius:10px;color:var(--fg);font-size:.93rem}nav a:hover{background:var(--acs);text-decoration:none}nav a[aria-current=page]{background:var(--acs);color:var(--ac);font-weight:600}
    .side .foot{margin-top:auto}
    main{padding:2.25rem clamp(1rem,4vw,3rem) 4rem;max-width:1100px;width:100%}
    .head{display:flex;justify-content:space-between;align-items:flex-end;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem}
    .card{background:var(--sf);border:1px solid var(--hl);border-radius:16px;padding:1.25rem 1.4rem;margin-bottom:1.1rem}
    .grid{display:grid;gap:1rem;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));margin-bottom:1.1rem}
    .stat{background:var(--sf);border:1px solid var(--hl);border-radius:16px;padding:1.1rem 1.25rem}.stat .n{font-size:1.9rem;font-weight:300;letter-spacing:-.02em;line-height:1.1}.stat .l{font-size:.8rem;color:var(--mu);margin-top:.25rem}
    table{width:100%;border-collapse:collapse;font-size:.9rem}th{font-size:.74rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--mu);text-align:left;padding:.55rem .6rem;border-bottom:1px solid var(--hl)}td{padding:.65rem .6rem;border-bottom:1px solid var(--hl);vertical-align:top}tr:last-child td{border-bottom:0}.tw{overflow-x:auto}
    .btn{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;border:1px solid transparent;border-radius:999px;padding:.55rem 1.15rem;font:inherit;font-weight:600;font-size:.9rem;cursor:pointer;background:var(--pf);color:var(--op);text-decoration:none}.btn:hover{opacity:.9;text-decoration:none}.btn:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,a:focus-visible{outline:2px solid var(--ac);outline-offset:2px}
    .btn.s{background:transparent;color:var(--fg);border-color:var(--hl)}.btn.s:hover{background:var(--acs)}.btn.d{background:transparent;color:var(--dg);border-color:var(--dg)}.btn.sm{padding:.3rem .8rem;font-size:.82rem}
    label{display:block;font-size:.82rem;font-weight:600;margin:.8rem 0 .3rem}input[type=text],input[type=email],input[type=url],input[type=number],select,textarea{width:100%;padding:.6rem .8rem;border-radius:10px;border:1px solid var(--hl);background:var(--sr);color:var(--fg);font:inherit}textarea{min-height:5rem}
    .row{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}.row.end{justify-content:flex-end}.cols{display:grid;gap:1rem;grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}
    .ck{display:flex;align-items:center;gap:.5rem;font-weight:400;margin:.3rem 0}.ck input{width:auto}
    .badge{display:inline-block;padding:.12rem .6rem;border-radius:999px;font-size:.74rem;font-weight:600;background:var(--acs);color:var(--ac)}.badge.ok{color:var(--ok);background:rgba(76,116,88,.14)}.badge.dg{color:var(--dg);background:rgba(163,65,46,.12)}.badge.mu{color:var(--mu);background:var(--hl)}
    .notice{border:1px solid var(--hl);border-left:3px solid var(--ac);background:var(--sf);border-radius:12px;padding:.8rem 1rem;margin-bottom:1.1rem}.notice.dg{border-left-color:var(--dg)}.notice.ok{border-left-color:var(--ok)}
    pre{background:var(--sr);border:1px solid var(--hl);border-radius:12px;padding:.9rem 1rem;overflow:auto;white-space:pre-wrap;word-break:break-all;margin:.5rem 0}
    .secret{font-size:.95rem;padding:.9rem 1rem;border:1px dashed var(--ac);border-radius:12px;background:var(--acs);word-break:break-all;user-select:all}
    .qr{width:224px;height:224px;background:#fff;border-radius:12px;padding:8px;display:block}.qr svg{width:100%;height:100%;display:block}
    .bars rect.b{fill:var(--ac)}.bars rect.t{fill:var(--hl)}.bars text{fill:var(--mu);font:11px -apple-system,system-ui,sans-serif}
    .err{color:var(--dg)}.auth{max-width:30rem;margin:8vh auto;padding:0 1rem}.auth .card{padding:1.75rem}.auth .brand{margin-bottom:1.5rem;justify-content:center}
    @media(max-width:820px){.shell{grid-template-columns:1fr}.side{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;gap:.75rem;border-right:0;border-bottom:1px solid var(--hl)}.side nav{flex-direction:row;flex-wrap:wrap}.org{display:none}.side .foot{margin-top:0}main{padding-top:1.25rem}}
    """

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

    /// CSP for HTML pages. Scripts are allowed only where a page declares `needsScript` (passkey ceremonies).
    static func csp(script: Bool) -> String {
        var parts = ["default-src 'none'", "style-src 'sha256-\(sha256Base64(css))'", "img-src 'self' data:", "font-src 'none'",
                     "form-action 'self'", "base-uri 'none'", "frame-ancestors 'none'"]
        if script { parts.append("script-src 'sha256-\(sha256Base64(Self.script))'"); parts.append("connect-src 'self'") }
        return parts.joined(separator: "; ")
    }

    // MARK: Brand mark (single colour; from Design/svg/viadere-mark-mono-dark.svg)

    static let markSVG = """
    <svg viewBox="0 0 321.71 146" role="img" aria-label="Viadere" xmlns="http://www.w3.org/2000/svg"><path d="M0 46C31.34 46 52.61 53.08 58.62 61.38L88.74 102.99L115.22 66.49C130.87 44.9 156.4 45.68 170.7 68.18L189.31 97.44L215.59 61.52C231.34 40 256.71 40.99 270.74 63.66L321.71 146C290.37 146 271.7 141.91 268.73 137.12L240.79 91.98L213.57 129.17C198.67 149.53 174.45 148.74 160.91 127.45L141.09 96.28L116.14 130.69C101.32 151.11 76.1 151.1 61.31 130.67L0 46Z" fill="currentColor" opacity="0.62"/><path d="M0 46C31.34 46 52.61 53.08 58.62 61.38L88.74 102.99C101.18 120.16 102.65 139.14 118.23 127.81L116.14 130.69C101.32 151.11 76.1 151.1 61.31 130.67L0 46Z" fill="currentColor"/><path d="M113.12 69.37L115.22 66.49C130.87 44.9 156.4 45.68 170.7 68.18L189.31 97.44C200.84 115.58 199.82 137.73 215.67 126.3L213.57 129.17C198.67 149.53 174.45 148.74 160.91 127.45L141.09 96.28C129.64 78.27 128.81 57.95 113.12 69.37Z" fill="currentColor"/><path d="M213.49 64.4L215.59 61.52C231.34 40 256.71 40.99 270.74 63.66L321.71 146C290.37 146 271.7 141.91 268.73 137.12L240.79 91.98C229.56 73.83 229.23 53.05 213.49 64.4Z" fill="currentColor"/><circle cx="155.21" cy="20.5" r="20.5" fill="currentColor"/></svg>
    """

    static var brand: String { "<div class=\"brand\">\(markSVG)<div><b>via</b><span>dere</span></div></div>" }

    // MARK: Escaping

    static func esc(_ text: String) -> String { WebRoutes.escape(text) }

    // MARK: Pages

    struct NavItem {
        var title: String
        var path: String
        var permission: DashboardPermission?
    }

    static let businessNav: [NavItem] = [
        NavItem(title: "Overview", path: "/dashboard", permission: .viewOverview),
        NavItem(title: "API keys", path: "/dashboard/api-keys", permission: .viewAPIKeys),
        NavItem(title: "Webhooks", path: "/dashboard/webhooks", permission: .viewWebhooks),
        NavItem(title: "Templates", path: "/dashboard/templates", permission: .viewTemplates),
        NavItem(title: "Campaigns", path: "/dashboard/campaigns", permission: .manageCampaigns),
        NavItem(title: "Consent", path: "/dashboard/consent", permission: .viewConsent),
        NavItem(title: "Audit log", path: "/dashboard/audit", permission: .viewAudit),
        NavItem(title: "Team", path: "/dashboard/team", permission: .viewTeam),
        NavItem(title: "Organization", path: "/dashboard/organization", permission: .manageOrganization),
        NavItem(title: "Billing", path: "/dashboard/billing", permission: .viewBilling),
    ]

    static let operatorNav: [(String, String)] = [
        ("Applications", "/operator"), ("Businesses", "/operator/businesses"), ("Abuse signals", "/operator/abuse"),
    ]

    static func response(_ html: String, status: HTTPStatus = .ok, script: Bool = false) -> Response {
        let response = Response(status: status, body: .init(string: html))
        response.headers.contentType = .html
        response.headers.replaceOrAdd(name: "Content-Security-Policy", value: csp(script: script))
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        response.headers.replaceOrAdd(name: "X-Robots-Tag", value: "noindex")
        return response
    }

    private static func document(title: String, body: String, script: Bool) -> String {
        """
        <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\
        <meta name="referrer" content="no-referrer"><meta name="robots" content="noindex"><title>\(esc(title)) · Viadere</title>\
        <style>\(css)</style></head><body>\(body)\(script ? "<script>\(Self.script)</script>" : "")</body></html>
        """
    }

    /// Unauthenticated page (sign-in, sign-up, invitations).
    static func authPage(title: String, body: String, script: Bool = true, status: HTTPStatus = .ok) -> Response {
        response(document(title: title, body: "<div class=\"auth\">\(brand)<div class=\"card\">\(body)</div></div>", script: script), status: status, script: script)
    }

    /// Signed-in business page.
    static func businessPage(_ p: DashboardPrincipal, title: String, active: String, subtitle: String? = nil, actions: String = "",
                             flash: String? = nil, body: String, status: HTTPStatus = .ok, script: Bool = false) -> Response {
        let items = businessNav.filter { item in item.permission.map(p.can) ?? true }
            .map { "<a href=\"\($0.path)\"\($0.path == active ? " aria-current=\"page\"" : "")>\(esc($0.title))</a>" }.joined()
        var banner = ""
        if let business = p.business, business.status != .verified {
            let text: String
            switch business.status {
            case .pending: text = "Your organization is <strong>awaiting verification</strong>. API keys, webhooks and campaign links unlock when Viadere approves it. You can invite your team in the meantime."
            case .suspended: text = "This organization is <strong>suspended</strong>. API keys and interactions are blocked. Contact Viadere support."
            default: text = "This organization is <strong>not active</strong>."
            }
            banner = "<div class=\"notice\(business.status == .pending ? "" : " dg")\">\(text)</div>"
        }
        let flashHTML = flash.map { "<div class=\"notice ok\">\(esc($0))</div>" } ?? ""
        let side = """
        <aside class="side">\(brand)<div class="org"><span class="mu sm">Organization</span><strong>\(esc(p.business?.displayName ?? ""))</strong>\
        <span class="badge mu">\(esc(p.role?.title ?? ""))</span></div><nav aria-label="Dashboard">\(items)</nav>\
        <form class="foot" method="post" action="/dashboard/logout"><input type="hidden" name="_csrf" value="\(esc(p.csrf))"><button class="btn s sm" type="submit">Sign out</button></form></aside>
        """
        let head = "<div class=\"head\"><div><h1>\(esc(title))</h1>\(subtitle.map { "<p class=\"mu\">\(esc($0))</p>" } ?? "")</div><div class=\"row\">\(actions)</div></div>"
        return response(document(title: title, body: "<div class=\"shell\">\(side)<main>\(head)\(banner)\(flashHTML)\(body)</main></div>", script: script),
                        status: status, script: script)
    }

    /// Signed-in operator page.
    static func operatorPage(_ p: DashboardPrincipal, title: String, active: String, subtitle: String? = nil, flash: String? = nil,
                             body: String, status: HTTPStatus = .ok, script: Bool = false) -> Response {
        let items = operatorNav.map { "<a href=\"\($0.1)\"\($0.1 == active ? " aria-current=\"page\"" : "")>\(esc($0.0))</a>" }.joined()
        let side = """
        <aside class="side">\(brand)<div class="org"><span class="mu sm">Operator console</span><strong>\(esc(p.user.displayName))</strong></div>\
        <nav aria-label="Operator">\(items)</nav><form class="foot" method="post" action="/operator/logout">\
        <input type="hidden" name="_csrf" value="\(esc(p.csrf))"><button class="btn s sm" type="submit">Sign out</button></form></aside>
        """
        let flashHTML = flash.map { "<div class=\"notice ok\">\(esc($0))</div>" } ?? ""
        let head = "<div class=\"head\"><div><h1>\(esc(title))</h1>\(subtitle.map { "<p class=\"mu\">\(esc($0))</p>" } ?? "")</div></div>"
        return response(document(title: title + " · Operator", body: "<div class=\"shell\">\(side)<main>\(head)\(flashHTML)\(body)</main></div>", script: script), status: status, script: script)
    }

    /// Error page inside the signed-in shell.
    static func errorPage(_ p: DashboardPrincipal?, status: HTTPStatus, title: String, message: String) -> Response {
        let body = "<div class=\"notice dg\">\(esc(message))</div><p><a href=\"\(p?.realm.home ?? "/dashboard")\">Back to the dashboard</a></p>"
        if let p, p.realm == .business { return businessPage(p, title: title, active: "", body: body, status: status) }
        if let p { return operatorPage(p, title: title, active: "", body: body, status: status) }
        return authPage(title: title, body: "<h1>\(esc(title))</h1><p>\(esc(message))</p>", script: false, status: status)
    }

    /// Hidden CSRF input for forms.
    static func csrf(_ p: DashboardPrincipal) -> String { "<input type=\"hidden\" name=\"_csrf\" value=\"\(esc(p.csrf))\">" }

    static func reauthPage(_ p: DashboardPrincipal, next: String, minutes: Int) -> Response {
        let realmPath = p.realm == .business ? "/dashboard" : "/operator"
        let body = """
        <div class="notice">For your security, confirm it's you with your passkey before continuing. This unlocks sensitive actions for \
        \(minutes) minutes.</div>\
        <p><button class="btn" type="button" data-passkey="reauth" data-begin="\(realmPath)/auth/reauth/begin" data-finish="\(realmPath)/auth/reauth/finish" \
        data-csrf="\(esc(p.csrf))" data-next="\(esc(next))">Confirm with passkey</button></p><p id="pk-msg" class="sm err" role="alert"></p>
        """
        return p.realm == .business
            ? businessPage(p, title: "Confirm it's you", active: "", body: body, status: .forbidden, script: true)
            : operatorPage(p, title: "Confirm it's you", active: "", body: body, status: .forbidden, script: true)
    }
}
