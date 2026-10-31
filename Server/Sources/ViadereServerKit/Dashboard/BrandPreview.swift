@preconcurrency import Crypto
import Foundation
import Vapor
import ViadereCore

/// The Brand Kit Studio preview (WP-2.5; plan 5.3 option (a)): a static HTML document rendered by Swift from the kit and Core's contrast
/// policy, shown inside a sandboxed iframe. It has its own strict CSP: no script at all, its one stylesheet pinned by hash, images only as
/// inline `data:` URIs, `sandbox` (an opaque origin with no scripts, forms or navigation), and it may be framed only by the console itself.
///
/// What it shows mirrors the rules devices apply, so a business sees the same limits: brand colors pass through `ContrastPolicy.resolve`
/// (failing roles fall back to Viadere's), and the approval card is **always** neutral (`ProtectedPalette`): a kit can never restyle an
/// approval, its buttons, the risk wording or the verified badge (spec B2.4).
enum BrandPreview {
    struct Images {
        var logo: Data?
        var background: Data?
    }

    static func render(kit: BrandKit, businessName: String, images: Images, now: Date) -> (html: String, css: String) {
        let resolution = ContrastPolicy.resolve(kit.tokens)
        let frame = FrameRegistry.v1.resolve(kit.frameId, at: now)
        let radius: String
        switch kit.tokens.radius ?? .medium {
        case .none: radius = "0"
        case .small: radius = "6px"
        case .medium: radius = "12px"
        case .large: radius = "20px"
        }
        let border: String
        switch kit.tokens.border ?? .hairline {
        case .none: border = "0"
        case .hairline: border = "1px solid rgba(0,0,0,.12)"
        case .regular: border = "2px solid rgba(0,0,0,.18)"
        }
        let scale: String
        switch kit.tokens.typeScale ?? .standard {
        case .compact: scale = "14px"
        case .standard: scale = "15px"
        case .large: scale = "17px"
        }
        func vars(_ p: ResolvedPalette, _ q: ResolvedPalette) -> String {
            "--p:\(p.primary.hex);--op:\(p.onPrimary.hex);--s:\(p.secondary.hex);--a:\(p.accent.hex);--sf:\(p.surface.hex);--os:\(p.onSurface.hex);"
                + "--qp:\(q.primary.hex);--qop:\(q.onPrimary.hex);--qsf:\(q.surface.hex);--qos:\(q.onSurface.hex);--qa:\(q.accent.hex);"
        }
        let light = resolution.light, dark = resolution.dark
        let protectedLight = ProtectedPalette.palette(.light), protectedDark = ProtectedPalette.palette(.dark)
        let css = """
        *{box-sizing:border-box}body{margin:0;padding:16px;font:\(scale)/1.45 -apple-system,system-ui,sans-serif;background:#ECE8E1;color:#1F1E1C}
        .note{font-size:12px;color:#625D55;margin:0 0 12px}.row{display:flex;flex-wrap:wrap;gap:16px}
        .phone{width:300px;border-radius:36px;padding:14px;background:#1F1E1C}.screen{border-radius:24px;overflow:hidden;min-height:520px;padding:14px;background:var(--sf);color:var(--os)}
        .l{\(vars(light, protectedLight))}.d{\(vars(dark, protectedDark))}
        h2{font-size:13px;letter-spacing:.06em;text-transform:uppercase;margin:0 0 8px;color:#625D55}
        .head{display:flex;align-items:center;gap:10px;margin-bottom:12px}.logo{width:44px;height:44px;border-radius:\(radius);object-fit:contain;background:#fff}
        .name{font-weight:600}.badge{font-size:11px;padding:2px 8px;border-radius:999px;background:var(--qsf);color:var(--qos);border:1px solid rgba(0,0,0,.15)}
        .hero{height:90px;border-radius:\(radius);margin-bottom:12px;background:var(--p);object-fit:cover;width:100%;display:block}
        .card{border-radius:\(radius);border:\(border);padding:10px 12px;margin-bottom:10px;background:var(--sf)}
        .accent{border-left:4px solid var(--a)}.btn{display:inline-block;border-radius:\(radius);padding:8px 14px;background:var(--p);color:var(--op);font-weight:600}
        .muted{color:var(--s);font-size:13px}
        .protected{border-radius:12px;border:1px solid rgba(0,0,0,.2);padding:12px;background:var(--qsf);color:var(--qos)}
        .protected .btn{background:var(--qp);color:var(--qop);border-radius:999px}.protected .alt{background:transparent;color:var(--qos);border:1px solid var(--qos)}
        .frame{outline:3px double var(--a);outline-offset:-8px}.safe{outline:1px dashed rgba(0,0,0,.35)}
        """
        func esc(_ s: String) -> String { DashboardUI.esc(s) }
        func img(_ data: Data?, alt: String, cls: String) -> String {
            guard let data else { return "" }
            return "<img class=\"\(cls)\" alt=\"\(esc(alt))\" src=\"data:image/png;base64,\(data.base64EncodedString())\">"
        }
        func phone(_ cls: String, label: String) -> String {
            let hero = images.background.map { img($0, alt: "", cls: "hero safe") } ?? "<div class=\"hero\" role=\"presentation\"></div>"
            return """
            <section aria-label="\(esc(label))"><h2>\(esc(label))</h2><div class="phone \(cls)"><div class="screen\(frame != nil ? " frame" : "")">\
            <div class="head">\(img(images.logo, alt: "\(businessName) logo", cls: "logo"))<div><div class="name">\(esc(businessName))</div><span class="badge">Verified business</span></div></div>\
            \(hero)\
            <div class="card accent"><div class="name">Message</div><div class="muted">From \(esc(businessName)) · sender shown by Viadere</div><p>Your order is ready for pickup.</p></div>\
            <div class="card"><div class="name">Offer</div><p class="muted">10% off your next visit</p><span class="btn">View offer</span></div>\
            <div class="card"><div class="name">Recent activity</div><p class="muted">Pickup confirmed · today</p></div>\
            <div class="protected" aria-label="Approval, always shown in Viadere's style"><div class="name">Approve sign-in?</div>\
            <p>\(esc(businessName)) is asking you to approve a sign-in. Approvals always use Viadere's own style.</p>\
            <span class="btn">Approve</span> <span class="btn alt">Deny</span></div></div></div></section>
            """
        }
        let body = """
        <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Preview</title><style>\(css)</style></head><body>\
        <p class="note">Preview, not exactly what customers see. Colors that fail contrast are replaced by Viadere's. Approvals, sign-in and verification never use your kit.</p>\
        <div class="row">\(phone("l", label: "Light appearance"))\(phone("d", label: "Dark appearance"))</div></body></html>
        """
        return (body, css)
    }

    /// The preview document's own CSP (stricter than the console's: no script source at all, `sandbox`, framable only by the console).
    static func csp(css: String) -> String {
        "default-src 'none'; style-src 'sha256-\(DashboardUI.sha256Base64(css))'; img-src data:; font-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'; sandbox"
    }

    static func response(kit: BrandKit, businessName: String, images: Images, now: Date) -> Response {
        let (html, css) = render(kit: kit, businessName: businessName, images: images, now: now)
        let response = Response(status: .ok, body: .init(string: html))
        response.headers.contentType = .html
        response.headers.replaceOrAdd(name: "Content-Security-Policy", value: csp(css: css))
        response.headers.replaceOrAdd(name: "X-Frame-Options", value: "SAMEORIGIN")
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        response.headers.replaceOrAdd(name: "X-Robots-Tag", value: "noindex")
        return response
    }

    /// Text warnings for every role the contrast policy replaces (never color alone, WP-2.5 A11y).
    static func contrastWarnings(_ tokens: BrandTokens) -> [String] {
        let resolution = ContrastPolicy.resolve(tokens)
        func ratio(_ v: Int64) -> String { String(format: "%.2f:1", Double(v) / 100) }
        var out: [String] = []
        for (appearance, roles) in [("light", resolution.overriddenLight), ("dark", resolution.overriddenDark)] {
            let surface = appearance == "light" ? (tokens.surface.flatMap { resolution.overriddenLight.contains(.surface) ? nil : $0 } ?? NeutralPalette.palette(.light).surface)
                : NeutralPalette.palette(.dark).surface
            for role in roles {
                switch role {
                case .primary:
                    let fg = ContrastPolicy.bestForeground(on: tokens.primary)
                    out.append("Primary \(tokens.primary.hex) in \(appearance) mode: text on it reaches \(ratio(ContrastPolicy.ratioTimes100(fg, tokens.primary))) (needs 4.50:1) and it reaches \(ratio(ContrastPolicy.ratioTimes100(tokens.primary, surface))) against the background (needs 3.00:1). Viadere's color will be used.")
                case .secondary:
                    if let c = tokens.secondary { out.append("Secondary \(c.hex) in \(appearance) mode reaches \(ratio(ContrastPolicy.ratioTimes100(c, surface))) against the background (needs 4.50:1). Viadere's color will be used.") }
                case .accent:
                    if let c = tokens.accent { out.append("Accent \(c.hex) in \(appearance) mode reaches \(ratio(ContrastPolicy.ratioTimes100(c, surface))) against the background (needs 3.00:1). Viadere's color will be used.") }
                case .surface:
                    if let c = tokens.surface { out.append("Background \(c.hex): neither of Viadere's text colors reaches 4.50:1 on it. Viadere's background will be used.") }
                }
            }
        }
        return out
    }
}
