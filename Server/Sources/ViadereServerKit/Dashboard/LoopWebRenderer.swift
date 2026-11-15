@preconcurrency import Crypto
import Foundation
import Vapor
import ViadereCore

/// The Swift web renderer of `PresentationTree` (plan 4.4 and 5.3 option (a); WP-3.7 preview, WP-3.8 parity). **Preview only**: it is
/// never the production renderer and every document it produces says so.
///
/// The output is a static HTML document served inside a sandboxed iframe with its own CSP: no script source at all, one stylesheet pinned
/// by hash, no images, fonts, forms or navigation (`sandbox` gives it an opaque origin), and only the console may frame it. Every node is an
/// element carrying `data-node="<kind>"` (and `data-protected` when the node is protected), every action carries `data-action`, and visible
/// text appears in exactly the reading order of `PresentationLandmarks.texts`, so the parity harness can compare the HTML with the golden
/// trees in `Packages/ViadereCore/Tests/ViadereCoreTests/Golden`.
///
/// Styling follows the builder's contract: brand values come only from `tree.style` (already clamped by `ContrastPolicy`) and apply to
/// unprotected nodes; protected nodes (attribution bar, confirmation panel, outcome, notices, protected action bars) always use
/// `ProtectedPalette`. Production-only chrome (status bar, notification banner, Face ID) is drawn as labeled placeholders, outside the nodes.
enum LoopWebRenderer {
    static let previewLabel = "Preview, not exactly what customers see"

    // MARK: Nodes

    static func fragment(_ tree: PresentationTree) -> String { node(tree.root) }

    static func node(_ node: PresentationNode) -> String {
        let esc = DashboardUI.esc
        let attrs = "data-node=\"\(node.kind)\"" + (node.isProtected ? " data-protected=\"true\"" : "")
        switch node {
        case .screen(let n):
            return "<section class=\"scr\" \(attrs) aria-label=\"Screen: \(esc(n.title))\"><p class=\"nav\" dir=\"auto\">\(esc(n.title))</p>"
                + n.children.map(Self.node).joined() + "</section>"
        case .header(let n):
            return "<h2 class=\"hd \(n.role.rawValue)\" \(attrs) dir=\"auto\">\(esc(n.text))</h2>"
        case .attributionBar(let n):
            return "<div class=\"attr pr\" \(attrs) role=\"group\" aria-label=\"\(esc(n.accessibilityLabel))\"><span class=\"by\" dir=\"auto\">\(esc(n.text))</span>"
                + (n.verified ? " <span class=\"vb\">\(esc(n.verifiedLabel))</span>" : "") + "</div>"
        case .text(let n):
            return "<p class=\"tx \(n.role.rawValue)\" \(attrs) dir=\"auto\">\(esc(n.text))</p>"
        case .fieldGroup(let n):
            return "<div class=\"fg\" \(attrs)>" + n.children.map(Self.node).joined() + "</div>"
        case .choice(let n):
            let shape = n.multiple ? "sq" : "ci"
            return "<fieldset class=\"ch \(n.control == "time_slot" ? "slot" : "list")\" \(attrs)><legend dir=\"auto\">\(esc(n.label))\(n.required ? "<span class=\"rq\" aria-hidden=\"true\"> *</span>" : "")</legend>"
                + n.options.map { "<span class=\"op \(shape)\" dir=\"auto\">\(esc($0.label))</span>" }.joined() + "</fieldset>"
        case .input(let n):
            let control: String
            switch n.input {
            case "yes_no": control = "<span class=\"yn\">Yes</span><span class=\"yn\">No</span>"
            case "acknowledgement": control = "<span class=\"box\" aria-hidden=\"true\"></span>"
            case "date": control = "<span class=\"ctl\">Date picker</span>"
            default: control = "<span class=\"ctl\">\(n.maxLength.map { "Up to \($0) characters" } ?? "Short answer")</span>"
            }
            return "<div class=\"in \(esc(n.input))\" \(attrs)><span class=\"lb\" dir=\"auto\">\(esc(n.label))\(n.required ? "<span class=\"rq\" aria-hidden=\"true\"> *</span>" : "")</span>\(control)</div>"
        case .actionBar(let n):
            return "<div class=\"ab\(n.protected ? " pr" : "")\" \(attrs)>" + n.actions.map {
                "<span class=\"act \($0.role.rawValue)\(n.protected ? " pr" : "")\" data-action=\"\(esc($0.id))\" dir=\"auto\">\(esc($0.label))</span>"
            }.joined() + "</div>"
        case .confirmationPanel(let n):
            return "<div class=\"cp pr\" \(attrs) role=\"group\" aria-label=\"Confirmation\"><p class=\"ct\" dir=\"auto\">\(esc(n.title))</p>"
                + "<p dir=\"auto\">\(esc(n.statement))</p><p class=\"ef\" dir=\"auto\">\(esc(n.effect))</p></div>"
        case .outcomeStatus(let n):
            return "<p class=\"oc pr \(n.outcome.rawValue)\" \(attrs) role=\"status\" dir=\"auto\">\(esc(n.text))</p>"
        case .moduleSlot(let n):
            return "<div class=\"mod \(n.size.rawValue)\" \(attrs)>Viadere module: \(esc(n.module))</div>"
        case .notice(let n):
            return "<div class=\"nt pr \(n.kind.rawValue)\" \(attrs) role=\"note\">" + (n.title.map { "<p class=\"ntt\" dir=\"auto\">\(esc($0))</p>" } ?? "")
                + "<p dir=\"auto\">\(esc(n.text))</p></div>"
        }
    }

    // MARK: Document

    /// One preview document for all screens of a Loop. `notice` replaces the screens (for example while the automated checks fail).
    static func document(screens: [LoopPreview.Screen], notice: String? = nil, entryPoints: [LoopEntryPoint] = []) -> (html: String, css: String) {
        var css = baseCSS
        for (index, screen) in screens.enumerated() { css += "\n.t\(index){\(vars(screen.tree.style))}" }
        let esc = DashboardUI.esc
        var body = "<p class=\"label\">\(esc(previewLabel)). Banners, Face ID and system screens are drawn by iOS and appear here as placeholders.</p>"
        if let notice {
            body += "<div class=\"empty\" role=\"status\">\(esc(notice))</div>"
        } else if screens.isEmpty {
            body += "<div class=\"empty\" role=\"status\">Nothing to preview yet.</div>"
        } else {
            if let origin = screens.first?.tree.compactOrigin, entryPoints.contains(where: { $0 == .message || $0 == .alert }) {
                body += "<div class=\"ph banner\" role=\"note\"><span class=\"pht\">Placeholder: notification banner shown by iOS</span><span>\(esc(origin))</span></div>"
            }
            body += "<div class=\"row\">"
            for (index, screen) in screens.enumerated() {
                body += "<figure class=\"phone t\(index)\" aria-label=\"\(esc(screen.label))\"><figcaption>\(esc(screen.label))</figcaption>"
                    + "<div class=\"ph sys\" role=\"note\">Placeholder: status bar shown by iOS</div><div class=\"dev\(screen.tree.style.frameId == nil ? "" : " frame")\">"
                    + fragment(screen.tree) + "</div>"
                    + (screen.confirmation ? "<div class=\"ph faceid\" role=\"note\">Placeholder: Face ID or passcode prompt shown by iOS when the customer confirms</div>" : "")
                    + "</figure>"
            }
            body += "</div>"
        }
        let html = """
        <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Preview</title><style>\(css)</style></head>\
        <body><main aria-label="\(esc(previewLabel))">\(body)</main></body></html>
        """
        return (html, css)
    }

    /// The preview's CSP: no script source at all, the stylesheet pinned by hash, nothing else loadable, sandboxed, framable by the console only.
    static func csp(css: String) -> String {
        "default-src 'none'; style-src 'sha256-\(DashboardUI.sha256Base64(css))'; img-src 'none'; font-src 'none'; connect-src 'none'; "
            + "form-action 'none'; base-uri 'none'; frame-ancestors 'self'; sandbox"
    }

    static func response(screens: [LoopPreview.Screen], notice: String? = nil, entryPoints: [LoopEntryPoint] = []) -> Response {
        let (html, css) = document(screens: screens, notice: notice, entryPoints: entryPoints)
        let response = Response(status: .ok, body: .init(string: html))
        response.headers.contentType = .html
        response.headers.replaceOrAdd(name: "Content-Security-Policy", value: csp(css: css))
        response.headers.replaceOrAdd(name: "X-Frame-Options", value: "SAMEORIGIN")
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        response.headers.replaceOrAdd(name: "X-Robots-Tag", value: "noindex")
        return response
    }

    // MARK: Styles

    static func vars(_ style: PresentationStyle) -> String {
        let p = style.palette.light
        let q = ProtectedPalette.palette(.light)
        let radius: String
        switch style.radius {
        case .none: radius = "0"
        case .small: radius = "6px"
        case .medium: radius = "12px"
        case .large: radius = "20px"
        }
        let border: String
        switch style.border {
        case .none: border = "0"
        case .hairline: border = "1px solid rgba(0,0,0,.12)"
        case .regular: border = "2px solid rgba(0,0,0,.18)"
        }
        let size: String
        switch style.typeScale {
        case .compact: size = "14px"
        case .standard: size = "15px"
        case .large: size = "17px"
        }
        return "--p:\(p.primary.hex);--op:\(p.onPrimary.hex);--s:\(p.secondary.hex);--a:\(p.accent.hex);--sf:\(p.surface.hex);--os:\(p.onSurface.hex);"
            + "--qp:\(q.primary.hex);--qop:\(q.onPrimary.hex);--qs:\(q.secondary.hex);--qsf:\(q.surface.hex);--qos:\(q.onSurface.hex);"
            + "--r:\(radius);--b:\(border);--fs:\(size)"
    }

    static let baseCSS = """
    *{box-sizing:border-box}body{margin:0;padding:16px;font:15px/1.45 -apple-system,system-ui,sans-serif;background:#ECE8E1;color:#1F1E1C}
    .label{font-size:12px;color:#625D55;margin:0 0 12px}.empty{padding:16px;border:1px dashed #8C7550;border-radius:12px;background:#FCFBF8}
    .row{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start}
    .phone{width:320px;margin:0;border-radius:36px;padding:12px;background:#1F1E1C;font-size:var(--fs)}
    figcaption{color:#F5F2EC;font-size:12px;margin:2px 8px 8px}
    .ph{font-size:11px;color:#625D55;border:1px dashed #8C7550;border-radius:10px;padding:6px 8px;background:#F5F2EC;margin:6px 0}
    .ph.sys{margin:0 0 6px}.banner{display:flex;flex-direction:column;gap:2px;max-width:320px;margin-bottom:12px}.pht{font-weight:600}
    .dev{border-radius:24px;min-height:420px;padding:14px;background:var(--sf);color:var(--os)}.dev.frame{outline:3px double var(--a);outline-offset:-8px}
    .nav{font-weight:600;text-align:center;margin:0 0 10px}
    .pr{background:var(--qsf);color:var(--qos)}
    .attr{display:flex;flex-wrap:wrap;align-items:center;gap:6px;border:1px solid rgba(0,0,0,.2);border-radius:12px;padding:6px 10px;margin-bottom:12px;font-size:13px}
    .attr .by{font-weight:600}.vb{font-size:11px;padding:1px 8px;border-radius:999px;border:1px solid var(--qos)}
    .hd{font-size:1.2em;margin:4px 0 8px;color:var(--os)}.tx{margin:0 0 10px}.tx.secondary{color:var(--s)}
    .fg{display:flex;flex-direction:column;gap:10px;margin-bottom:12px}
    .ch{border:var(--b);border-radius:var(--r);padding:8px 10px;margin:0;display:flex;flex-direction:column;gap:6px}.ch legend{font-weight:600;padding:0 4px}
    .op{display:block;padding:6px 10px;border-radius:var(--r);border:1px solid rgba(0,0,0,.15);overflow-wrap:anywhere}
    .op.ci::before{content:"\\25CB  "}.op.sq::before{content:"\\25A1  "}.slot .op{display:inline-block}
    .in{display:flex;flex-direction:column;gap:4px}.lb{font-weight:600;overflow-wrap:anywhere}
    .ctl{display:block;padding:8px 10px;border-radius:var(--r);border:var(--b);color:var(--s);font-size:13px}
    .yn{display:inline-block;padding:4px 14px;margin-right:6px;border-radius:999px;border:1px solid rgba(0,0,0,.2)}
    .box{display:inline-block;width:18px;height:18px;border:2px solid var(--os);border-radius:4px}.rq{color:var(--s)}
    .ab{display:flex;flex-direction:column;gap:8px;margin-top:12px;background:transparent}
    .act{display:block;text-align:center;padding:10px 14px;border-radius:var(--r);font-weight:600;overflow-wrap:anywhere}
    .act.primary{background:var(--p);color:var(--op)}.act.secondary{border:1px solid var(--s);color:var(--os)}
    .act.pr.primary{background:var(--qp);color:var(--qop);border-radius:999px}.act.pr.secondary{background:transparent;border:1px solid var(--qos);color:var(--qos);border-radius:999px}
    .cp{border:1px solid rgba(0,0,0,.2);border-radius:12px;padding:12px;margin-bottom:10px}.ct{font-weight:600;margin:0 0 6px}.ef{color:var(--qs)}
    .oc{border-radius:12px;padding:10px 12px;font-weight:600}
    .nt{border-radius:12px;padding:10px 12px;border-left:3px solid var(--qos);margin:8px 0}.ntt{font-weight:600;margin:0 0 4px}.nt p{margin:0}
    .mod{border:1px dashed var(--s);border-radius:var(--r);padding:16px;margin-bottom:10px;color:var(--s)}
    """
}
