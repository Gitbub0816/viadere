import Foundation

/// Product illustrations drawn in HTML and CSS: device mockups, the request flow, the privacy split and the signed result.
///
/// Every business here is fictional and every mockup is labelled as an illustration. The visible text of these blocks is
/// part of the page text, so the marketing integrity lint checks it like any other copy. Used by `{{ generate: mockup NAME }}`
/// and by `hero_art: NAME` in front matter.
public enum Showcase {
    public static let names = ["signin", "payment", "conversation", "wallet", "verify", "authenticator", "lineup", "contrast", "flow",
                               "privacy", "signed-result", "stage", "pillars", "channels", "curl"]

    public static func render(_ name: String) -> String? {
        switch name {
        case "signin": return device(signinScreen, label: signinLabel, screen: "screen-lock")
        case "payment": return device(paymentScreen, label: paymentLabel, screen: "screen-app")
        case "conversation": return device(conversationScreen, label: conversationLabel, screen: "screen-app")
        case "wallet": return device(walletScreen, label: walletLabel, screen: "screen-wallet")
        case "verify": return device(verifyScreen, label: verifyLabel, screen: "screen-app", concept: true)
        case "authenticator": return device(authenticatorScreen, label: authenticatorLabel, screen: "screen-app", concept: true)
        case "lineup": return lineup
        case "contrast": return contrast
        case "flow": return flow
        case "privacy": return privacy
        case "signed-result": return signedResult
        case "stage": return stage
        case "pillars": return pillars
        case "channels": return channels
        case "curl": return Markdown.codeWindow(info: "bash POST /v1/business/interactions", code: curlSample)
        default: return nil
        }
    }

    static let caption = "Illustration with a fictional business. Not a live screen."

    // MARK: Building blocks

    static func e(_ s: String) -> String { HTML.escape(s) }

    struct Biz { let name: String; let cls: String; let icon: String }
    static let northwind = Biz(name: "Northwind Air", cls: "lg-northwind", icon: "plane")
    static let larkspur = Biz(name: "Larkspur Bank", cls: "lg-larkspur", icon: "bank")
    static let juniper = Biz(name: "Juniper Coffee", cls: "lg-juniper", icon: "cup")
    static let fernhill = Biz(name: "Fernhill Market", cls: "lg-fernhill", icon: "leaf")
    static let riverbend = Biz(name: "Riverbend Cellars", cls: "lg-riverbend", icon: "grape")

    static func logo(_ b: Biz, _ extra: String = "") -> String {
        "<span class=\"blogo \(b.cls)\(extra.isEmpty ? "" : " " + extra)\">\(Icons.svg(b.icon))</span>"
    }
    static func name(_ b: Biz) -> String { "<span class=\"bname\">\(e(b.name))\(Icons.verifiedSeal())</span>" }

    static let appMark = "<span class=\"nt-app\"><svg viewBox=\"0 0 321.71 146\" aria-hidden=\"true\" focusable=\"false\"><use href=\"#mark-dark\"/></svg></span>"

    static let statusIcons = """
    <span class="sb-icons" aria-hidden="true"><svg viewBox="0 0 18 12"><rect x="0" y="8" width="3" height="4" rx=".8"/><rect x="5" y="5.5" width="3" height="6.5" rx=".8"/><rect x="10" y="3" width="3" height="9" rx=".8"/><rect x="15" y="0" width="3" height="12" rx=".8"/></svg><svg viewBox="0 0 16 12"><path d="M8 11.5l2.6-3.1a4 4 0 0 0-5.2 0zM8 2.2c2.6 0 5 1 6.8 2.7l1.2-1.4A12 12 0 0 0 8 .4 12 12 0 0 0 0 3.5l1.2 1.4A10 10 0 0 1 8 2.2zm0 3.6c1.6 0 3 .6 4.2 1.5l1.2-1.4A8 8 0 0 0 8 4a8 8 0 0 0-5.4 1.9l1.2 1.4C5 6.4 6.4 5.8 8 5.8z"/></svg><svg viewBox="0 0 27 12"><rect x=".5" y=".5" width="23" height="11" rx="3.2" fill="none" stroke="currentColor" opacity=".45"/><rect x="2" y="2" width="17" height="8" rx="2"/><rect x="24.6" y="4" width="1.6" height="4" rx=".8" opacity=".45"/></svg></span>
    """

    static func statusBar(time: String?) -> String {
        "<div class=\"sbar\" aria-hidden=\"true\"><span class=\"sb-time\">\(time ?? "")</span>\(statusIcons)</div>"
    }

    /// An iPhone-like frame drawn in CSS. The whole device is one image to assistive technology, described by `label`.
    static func device(_ screen: String, label: String, screen screenClass: String, concept: Bool = false, extra: String = "") -> String {
        let time: String? = screenClass == "screen-lock" ? nil : "9:41"
        return """
        <figure class="device\(concept ? " is-concept" : "")\(extra.isEmpty ? "" : " " + extra)">\(concept ? "<span class=\"concept-tag\">Planned · design concept</span>" : "")<div class="phone" role="img" aria-label="\(e(label))"><div class="screen \(screenClass)"><span class="island" aria-hidden="true"></span>\(statusBar(time: time))\(screen)<span class="home-ind" aria-hidden="true"></span></div></div><figcaption class="device-cap">\(caption)</figcaption></figure>
        """
    }

    // MARK: Screens

    static let signinLabel = "Illustration: an iPhone lock screen showing a Viadere notification. Northwind Air, a verified business, asks whether you are signing in from Safari on a Mac near Seattle, Washington, at 9:41 AM. The actions are Approve, Deny and This was not me."
    static let signinScreen = """
    <div class="ls"><div class="ls-top"><span class="ls-lock">\(Icons.svg("lock"))</span><span class="ls-date">Tuesday, October 28</span><span class="ls-time">9:41</span></div>
    <div class="ls-stack">
    <div class="nt nt-ghost"><div class="nt-head">\(appMark)<span class="nt-appname">Viadere</span><span class="nt-when">12m ago</span></div><div class="nt-line"><b>Fernhill Market</b> Your order is ready for pickup at bay 3.</div></div>
    <div class="nt nt-x"><div class="nt-head">\(appMark)<span class="nt-appname">Viadere</span><span class="nt-when">now</span></div>
    <div class="nt-biz">\(logo(northwind))<span class="nt-who">\(name(northwind))<span class="nt-kind">Sign-in request</span></span><span class="nt-timer">\(Icons.svg("clock"))1:52</span></div>
    <div class="nt-q">Is this you signing in?</div>
    <div class="nt-facts"><span><span class="fl">Browser</span>Safari on Mac</span><span><span class="fl">Near</span>Seattle, WA</span><span><span class="fl">Time</span>9:41 AM</span></div>
    <div class="nt-assure">\(Icons.svg("faceid"))Approve with Face ID</div></div>
    <div class="nt-menu"><span class="nt-act is-ok">Approve\(Icons.svg("check"))</span><span class="nt-act is-no">Deny\(Icons.svg("x"))</span><span class="nt-act">This was not me</span></div>
    </div>
    <div class="ls-foot" aria-hidden="true"><span class="ls-round">\(Icons.svg("bolt"))</span><span class="ls-round">\(Icons.svg("sparkle"))</span></div></div>
    """

    static let paymentLabel = "Illustration: the Viadere approval sheet. Larkspur Bank, a verified business, asks: someone is trying to spend $285.28 at Juniper Coffee in or near Portland, Oregon. Is this you? A note says the approval signs this amount, payee and reference. Below are a Slide to approve control and a No, this was not me button."
    static let paymentScreen = """
    <div class="sheet-wrap"><div class="sheet-behind" aria-hidden="true"><span class="sb-title">Larkspur Bank</span><span class="sb-line"></span><span class="sb-line short"></span></div>
    <div class="sheet"><span class="sheet-grab" aria-hidden="true"></span>
    <div class="sheet-biz">\(logo(larkspur))<span class="nt-who">\(name(larkspur))<span class="nt-kind">Card purchase · expires in 1:58</span></span></div>
    <div class="sheet-lead">Someone is trying to spend</div>
    <div class="sheet-amount">$285.28</div>
    <div class="sheet-payee">at <b>Juniper Coffee</b></div>
    <div class="sheet-where">In or near Portland, OR · Visa ending 4417</div>
    <div class="sheet-q">Is this you?</div>
    <div class="sheet-bind">\(Icons.svg("signature"))<span>Your approval signs this amount, payee and reference. If any of them changes, the signature no longer matches.</span></div>
    <div class="slide"><span class="slide-knob">\(Icons.svg("arrow"))</span><span class="slide-label">Slide to approve</span></div>
    <div class="sheet-deny">No, this was not me</div></div></div>
    """

    static let conversationLabel = "Illustration: a Viadere conversation with Fernhill Market, a verified business. An order status card shows order 4471 ready for pickup at bay 3 until 8 PM. The business asks when you will arrive with three choices, and you reply: in 10 minutes."
    static let conversationScreen = """
    <div class="chat"><div class="chat-nav"><span class="chat-back">\(Icons.svg("arrow-back"))</span>\(logo(fernhill))<span class="nt-who">\(name(fernhill))<span class="nt-kind">Verified business · replies are from Fernhill Market</span></span></div>
    <div class="chat-body"><span class="chat-day">Today 5:12 PM</span>
    <div class="bub in">Good news: your order is packed.</div>
    <div class="ostatus"><div class="os-top"><span class="os-ref">Order 4471</span><span class="os-pill">Ready for pickup</span></div>
    <div class="os-steps"><span class="done">Placed</span><span class="done">Packed</span><span class="now">Ready</span><span>Collected</span></div>
    <div class="os-meta">\(Icons.svg("bag"))Pickup bay 3 · until 8:00 PM</div></div>
    <div class="bub in req"><span>When will you arrive?</span><span class="chips"><span class="chip-x is-on">In 10 min</span><span class="chip-x">In 30 min</span><span class="chip-x">Tomorrow</span></span></div>
    <div class="bub out">In 10 min, thank you!<span class="bub-meta">Delivered</span></div>
    <div class="bub in">See you soon. Bay 3 is by the north entrance.</div></div>
    <div class="chat-compose"><span>Message Fernhill Market</span><span class="send">\(Icons.svg("arrow"))</span></div></div>
    """

    static let walletLabel = "Illustration: an Apple Wallet style rewards pass from Juniper Coffee showing 7 of 10 stamps and a Tuesday perk of a free drip coffee, with a notification that the Tuesday coffee is ready to claim."
    static var walletScreen: String {
        let stamps = (0..<10).map { "<span class=\"stamp\($0 < 7 ? " on" : "")\"></span>" }.joined()
        return """
        <div class="wallet"><div class="w-banner"><div class="nt-head">\(appMark)<span class="nt-appname">Viadere</span><span class="nt-when">now</span></div><div class="nt-line"><b>Juniper Coffee</b> Your Tuesday coffee is ready to claim.</div></div>
        <div class="w-title">Wallet</div>
        <div class="w-peek p1"><span>Northwind Air</span><span>Boarding pass</span></div><div class="w-peek p2"><span>Fernhill Market</span><span>Member</span></div>
        <div class="pass"><div class="pass-top">\(logo(juniper, "on-pass"))<span class="pass-org">Juniper Coffee</span><span class="pass-kind">Rewards</span></div>
        <div class="pass-stamps">\(stamps)</div>
        <div class="pass-fields"><span><span class="pl">Stamps</span><span class="pv">7 of 10</span></span><span><span class="pl">Tuesday perk</span><span class="pv">Free drip coffee</span></span></div>
        <div class="pass-code">\(qr(seed: 7))<span>Scan at the counter</span></div></div></div>
        """
    }

    static let verifyLabel = "Design concept for Verify, which is planned and not available: Riverbend Cellars asks to confirm your age. The result reads Over 21, confirmed. Only the over-21 answer is shared; your date of birth, name, address and ID number are not shared."
    static let verifyScreen = """
    <div class="vfy"><div class="vfy-head">\(logo(riverbend))<span class="nt-who">\(name(riverbend))<span class="nt-kind">wants to confirm your age</span></span></div>
    <div class="vfy-result"><span class="vfy-check">\(Icons.svg("check"))</span><span class="vfy-big">Over 21</span><span class="vfy-ok">Confirmed</span></div>
    <div class="vfy-list"><span class="vfy-row is-share">\(Icons.svg("check"))Age is over 21<b>Shared</b></span><span class="vfy-row">\(Icons.svg("eye-off"))Date of birth<b>Not shared</b></span><span class="vfy-row">\(Icons.svg("eye-off"))Name and address<b>Not shared</b></span><span class="vfy-row">\(Icons.svg("eye-off"))ID number<b>Not shared</b></span></div>
    <div class="vfy-btns"><span class="ub ub-pri">Share “over 21”</span><span class="ub">Decline</span></div></div>
    """

    static let authenticatorLabel = "Design concept for Authenticator, which is planned and not available: a vault listing passkeys for Northwind Air and Fernhill Market and one-time codes for Larkspur Bank and Juniper Coffee."
    static let authenticatorScreen = """
    <div class="vault"><div class="va-title">Authenticator</div><div class="va-search">\(Icons.svg("eye"))Search accounts</div>
    <span class="va-sec">Passkeys</span>
    <div class="va-row">\(logo(northwind))<span class="va-who"><b>Northwind Air</b><span>Passkey · this iPhone</span></span>\(Icons.svg("passkey", cls: "ic va-tail"))</div>
    <div class="va-row">\(logo(fernhill))<span class="va-who"><b>Fernhill Market</b><span>Passkey · synced</span></span>\(Icons.svg("passkey", cls: "ic va-tail"))</div>
    <span class="va-sec">Codes</span>
    <div class="va-row">\(logo(larkspur))<span class="va-who"><b>Larkspur Bank</b><span class="va-code">482 913</span></span><span class="ring r1"></span></div>
    <div class="va-row">\(logo(juniper))<span class="va-who"><b>Juniper Coffee</b><span class="va-code">120 774</span></span><span class="ring r2"></span></div>
    <div class="va-foot">\(Icons.svg("lock"))Recovery is separate from identity checks</div></div>
    """

    // MARK: Compositions

    static var lineup: String {
        """
        <div class="lineup">\(device(conversationScreen, label: conversationLabel, screen: "screen-app", extra: "lu-left"))\(device(signinScreen, label: signinLabel, screen: "screen-lock", extra: "lu-center"))\(device(paymentScreen, label: paymentLabel, screen: "screen-app", extra: "lu-right"))</div>
        <p class="lineup-cap">Illustrations with fictional businesses. Not live screens.</p>
        """
    }

    static let contrast = """
    <div class="contrast">
    <div class="ct ct-sms"><span class="ct-label">An ordinary text message</span>
    <div class="ct-thread"><span class="ct-from">+1 (555) 013-2291</span><span class="ct-bubble">Your account has been locked. Reply YES to confirm it is you, or visit lnk.example/unlock</span></div>
    <ul class="ct-list is-no"><li>\(Icons.svg("x"))Who actually sent this?</li><li>\(Icons.svg("x"))What does “YES” approve?</li><li>\(Icons.svg("x"))Does it ever expire?</li></ul></div>
    <div class="ct ct-via"><span class="ct-label">The same moment, with Viadere</span>
    <div class="nt nt-x nt-flat"><div class="nt-head">\(appMark)<span class="nt-appname">Viadere</span><span class="nt-when">now</span></div><div class="nt-biz">\(logo(northwind))<span class="nt-who">\(name(northwind))<span class="nt-kind">Sign-in request</span></span><span class="nt-timer">\(Icons.svg("clock"))1:52</span></div><div class="nt-q">Is this you signing in?</div><div class="nt-facts"><span><span class="fl">Browser</span>Safari on Mac</span><span><span class="fl">Near</span>Seattle, WA</span></div></div>
    <ul class="ct-list is-yes"><li>\(Icons.svg("check"))A verified business name</li><li>\(Icons.svg("check"))The purpose, device and place</li><li>\(Icons.svg("check"))An expiry you can see</li><li>\(Icons.svg("check"))An answer signed on your phone</li></ul></div>
    </div><p class="fig-note">Illustration with fictional names. Viadere never asks you to approve a sign-in or payment by text reply.</p>
    """

    static let flow = """
    <div class="flow"><ol class="flow-row">
    <li class="fnode"><span class="fn-ic">\(Icons.svg("store"))</span><span class="fn-step">01 · Business</span><b>Ask</b><span class="fn-txt">A verified business issues one structured request: who, what, why and for how long.</span><code>POST /v1/business/interactions</code></li>
    <li class="fnode fn-via"><span class="fn-ic"><svg viewBox="0 0 321.71 146" aria-hidden="true" focusable="false"><use href="#mark-dark"/></svg></span><span class="fn-step">02 · Viadere</span><b>Check and route</b><span class="fn-txt">Confirms the business is verified and has consent for this purpose, then picks the right channel.</span><code>verify · consent · route</code></li>
    <li class="fnode"><span class="fn-ic">\(Icons.svg("phone"))</span><span class="fn-step">03 · Customer</span><b>Decide</b><span class="fn-txt">The phone shows the verified name and the exact context. The customer answers with Face ID.</span><code>approve · deny · not me</code></li>
    <li class="fnode"><span class="fn-ic">\(Icons.svg("seal"))</span><span class="fn-step">04 · Business</span><b>Verify</b><span class="fn-txt">A signed result returns by webhook. The business checks the device signature against the request it created.</span><code>ES256 · single-use challenge</code></li>
    </ol><div class="flow-return" aria-hidden="true"><span class="fr-line"></span><span class="fr-label">\(Icons.svg("arrow-back"))Signed result returns to the business</span></div></div>
    """

    static let privacy = """
    <div class="psplit">
    <div class="ps ps-biz"><span class="ps-h">\(Icons.svg("eye"))What the business receives</span>
    <div class="ps-code"><span class="pc-l"><span class="tok-p">"sub"</span>: <span class="tok-s">"sub_k3JxQ…"</span></span><span class="pc-l"><span class="tok-p">"decision"</span>: <span class="tok-s">"approve"</span></span><span class="pc-l"><span class="tok-p">"amr"</span>: <span class="tok-s">"biometric"</span></span><span class="pc-l"><span class="tok-p">"request_id"</span>: <span class="tok-s">"req_8f2c…"</span></span><span class="pc-l"><span class="tok-p">"txn_digest"</span>: <span class="tok-s">"5e1a…"</span></span></div>
    <ul class="ps-list"><li>\(Icons.svg("split"))A pseudonym made for this one business</li><li>\(Icons.svg("check"))Your decision and how you confirmed it</li><li>\(Icons.svg("signature"))Proof tied to the exact request it sent</li></ul></div>
    <div class="ps ps-you"><span class="ps-h">\(Icons.svg("eye-off"))What stays with you</span>
    <ul class="ps-list ps-keep"><li>\(Icons.svg("phone"))Your phone number</li><li>\(Icons.svg("user"))Your Viadere account identity</li><li>\(Icons.svg("store"))Which other businesses you use</li><li>\(Icons.svg("chip"))Your signing keys, held in the Secure Enclave</li><li>\(Icons.svg("id"))Your date of birth, when Verify ships (planned)</li></ul></div>
    </div>
    """

    static let signedResult = """
    <figure class="sres"><div class="sres-win"><div class="code-bar"><span class="dots" aria-hidden="true"><span></span><span></span><span></span></span><span class="code-title">approval result · decoded</span><span class="code-lang">ES256</span></div>
    <div class="sres-body">
    <div class="sr"><span class="k">aud</span><span class="v">biz_northwind</span><span class="n">One business</span></div>
    <div class="sr"><span class="k">sub</span><span class="v">sub_k3JxQ…</span><span class="n">Pairwise pseudonym</span></div>
    <div class="sr"><span class="k">challenge</span><span class="v">Zq8u…Yw</span><span class="n">Used once</span></div>
    <div class="sr"><span class="k">decision</span><span class="v is-ok">approve</span><span class="n">Or deny, or report</span></div>
    <div class="sr"><span class="k">amr</span><span class="v">biometric</span><span class="n">How you confirmed</span></div>
    <div class="sr"><span class="k">txn_digest</span><span class="v">5e1a…c09f</span><span class="n">What you saw</span></div>
    <div class="sr"><span class="k">exp</span><span class="v">iat + 300 s</span><span class="n">Short-lived</span></div>
    </div><div class="sres-foot">\(Icons.svg("seal"))Signed on the device with a key that never leaves it</div></div>
    <figcaption class="fig-note">Illustrative values. The business verifies the signature with the key it enrolled for this customer.</figcaption></figure>
    """

    static let stage = """
    <figure class="stage"><img src="/assets/media/viadere-mark-final.webp" width="1008" height="567" alt="The Viadere mark: a satin ribbon that forms the letters v, i and a, with a floating dot." loading="lazy" decoding="async"><figcaption class="stage-cap">A trusted way to connect.</figcaption></figure>
    """

    static let pillars = """
    <ul class="pillars">
    <li><span class="pl-ic">\(Icons.svg("chip"))</span><b>Device-held keys</b><span>Approval keys are created in the Secure Enclave of your iPhone, one per business relationship. They do not leave the device.</span></li>
    <li><span class="pl-ic">\(Icons.svg("signature"))</span><b>Signed decisions</b><span>Every approval is signed over the amount, payee or context you saw, a single-use challenge and a short expiry.</span></li>
    <li><span class="pl-ic">\(Icons.svg("split"))</span><b>Pairwise identifiers</b><span>Each business sees its own pseudonym for you, so two businesses cannot match you by comparing notes.</span></li>
    <li><span class="pl-ic">\(Icons.svg("seal"))</span><b>Verified business identity</b><span>A business is reviewed before it can reach anyone, and its verified name travels with every request.</span></li>
    </ul>
    """

    static let channels = """
    <div class="chan">
    <div class="chan-c is-app"><span class="chan-ic">\(Icons.svg("phone"))</span><b>Viadere app</b><span class="chan-tag">Push and in-app</span><span class="chan-txt">Everything, including device-signed approvals, structured choices and Live Activities for ongoing orders and trips.</span></div>
    <div class="chan-c"><span class="chan-ic">\(Icons.svg("message"))</span><b>RCS</b><span class="chan-tag">Text with suggested replies</span><span class="chan-txt">Good for confirmations and support. A tap is an unauthenticated reply, so it never approves anything sensitive.</span></div>
    <div class="chan-c"><span class="chan-ic">\(Icons.svg("sms"))</span><b>SMS</b><span class="chan-tag">Plain text and secure links</span><span class="chan-txt">Reaches every phone. Ordinary SMS is not end-to-end encrypted, so sensitive requests become a secure link to the app.</span></div>
    </div>
    """

    static let curlSample = """
    curl -X POST https://viadere.com/v1/business/interactions \\
      -H "Authorization: Bearer $VIADERE_TEST_KEY" \\
      -H "Idempotency-Key: order-1042-confirm" \\
      -H "Content-Type: application/json" \\
      -d '{
        "relationshipId": "1111…5555",
        "kind": "confirm",
        "purpose": "transactional",
        "payload": { "title": "Confirm pickup" },
        "sensitivity": "standard",
        "allowedChannels": ["nativePush", "inApp"],
        "ttlSeconds": 3600,
        "idempotencyKey": "order-1042-confirm"
      }'
    """

    /// A decorative QR-like pattern (not a scannable code): three finder squares plus deterministic noise.
    static func qr(seed: UInt32) -> String {
        let n = 25
        var s = seed &* 2654435761 | 1
        var d = ""
        func finder(_ x: Int, _ y: Int) -> Bool {
            for (fx, fy) in [(0, 0), (n - 7, 0), (0, n - 7)] where x >= fx && x < fx + 7 && y >= fy && y < fy + 7 { return true }
            return false
        }
        for y in 0..<n {
            for x in 0..<n where !finder(x, y) && !(x < 8 && y < 8) && !(x > n - 9 && y < 8) && !(x < 8 && y > n - 9) {
                s ^= s << 13; s ^= s >> 17; s ^= s << 5
                if s % 100 < 47 { d += "M\(x) \(y)h1v1h-1z" }
            }
        }
        for (fx, fy) in [(0, 0), (n - 7, 0), (0, n - 7)] {
            d += "M\(fx) \(fy)h7v7h-7zM\(fx + 1) \(fy + 1)v5h5v-5zM\(fx + 2) \(fy + 2)h3v3h-3z"
        }
        return "<svg class=\"qr\" viewBox=\"-1 -1 27 27\" shape-rendering=\"crispEdges\" aria-hidden=\"true\" focusable=\"false\"><rect x=\"-1\" y=\"-1\" width=\"27\" height=\"27\" fill=\"#fff\"/><path fill=\"#1F1E1C\" fill-rule=\"evenodd\" d=\"\(d)\"/></svg>"
    }

    /// Icons for the four products, used by the product cards.
    public static func productIcon(_ url: String) -> String {
        if url.contains("messaging") { return "message" }
        if url.contains("approve") { return "faceid" }
        if url.contains("verify") { return "id" }
        if url.contains("authenticator") { return "passkey" }
        return "sparkle"
    }
}
