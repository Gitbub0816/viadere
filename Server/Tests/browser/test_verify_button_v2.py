"""Headless-browser test for version 2 of the embeddable "Verify with Viadere" web component (Python + Playwright, no Node.js in the repo).

Version 2 shows the Viadere code (a CKey optical code, read by the Viadere app) first and the same link as a QR code one control away.
This loads the real Server/Public/verify-button/v2/viadere-verify.{js,css} into Chromium from a local web root served with the same
**strict CSP** as the v1 test (no inline script or style, Trusted Types required) and checks:

* everything the v1 test checks (which link renders, variants, the modal panel, focus trap, Escape, other options, phone hand-off, and the
  QR encoder module-for-module against the `qrcode` reference library), because the QR path must keep working for people without the app;
* the CKey encoder against **every** vector of docs/protocol/vectors/ckey-profile0-v1.json (made by the CKey reference build): the same
  version and the same codeword, bit for bit;
* the CKey drawing: `new XMLSerializer().serializeToString(svg)` is the reference renderer's "concept" SVG **byte for byte** for every
  vector (compared by the SHA-256 in the vector file, with no normalisation at all), and the SVG inside the panel is the same document
  after undoing the two things the panel changes on purpose (see `test_the_panel_draws_the_reference_symbol_with_its_own_ids_and_label`);
* the switch to the QR code and back, keyboard use and focus, unique ids with several buttons on a page, and forced-colours behaviour;
* that none of it violates the CSP or makes a request.

Run: see Server/Tests/browser/README.md (needs `qrcode` as well as `playwright`).
"""
import functools
import hashlib
import http.server
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
from pathlib import Path

import qrcode
import qrcode.util
from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parents[3]
PUBLIC = REPO / "Server" / "Public" / "verify-button" / "v2"
VECTORS = json.loads((REPO / "docs" / "protocol" / "vectors" / "ckey-profile0-v1.json").read_text())["vectors"]
LINK = "https://viadere.io/v/ABCDEFGH"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; "
       "require-trusted-types-for 'script'; trusted-types 'none'")

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>verify</title>
<link rel="stylesheet" href="/v2/viadere-verify.css"></head><body><main id="host"></main>
<script src="/v2/viadere-verify.js"></script><script src="/harness.js"></script></body></html>"""

# Collects CSP violations (an external file, so the page itself needs no inline script).
HARNESS = """window.__violations = [];
document.addEventListener('securitypolicyviolation', function (e) { window.__violations.push(e.violatedDirective + ' ' + e.blockedURI); });
window.__events = [];
['viadere-verify-open', 'viadere-verify-close', 'viadere-verify-send'].forEach(function (n) {
  document.addEventListener(n, function (e) { window.__events.push(n + (e.detail && e.detail.link ? ' ' + e.detail.link : '')); });
});"""

IPHONE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1")

RENDER_JS = """(attrs) => {
  const host = document.getElementById('host');
  host.textContent = '';
  const el = document.createElement('viadere-verify');
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  host.appendChild(el);
  const a = el.querySelector('a.vdv-btn');
  if (!a) return { empty: true, children: el.childNodes.length };
  return { href: a.getAttribute('href'), cls: a.className, label: (el.querySelector('.vdv-label') || {}).textContent || null,
           aria: a.getAttribute('aria-label'), rel: a.getAttribute('rel'), styled: el.querySelectorAll('[style]').length,
           height: a.getBoundingClientRect().height, width: a.getBoundingClientRect().width,
           bg: getComputedStyle(a).backgroundColor };
}"""

# What is on screen in the open panel.
PANEL_JS = """() => {
  const d = document.querySelector('dialog.vdv-panel');
  const shown = (sel) => { const n = d.querySelector(sel); return !!n && n.getClientRects().length > 0; };
  const ckey = d.querySelector('.vdv-ckey-frame svg'), qr = d.querySelector('.vdv-qr');
  return { ckey: shown('.vdv-ckey-frame svg'), qr: shown('.vdv-qr'), lead: d.querySelector('.vdv-lead').textContent,
           swap: shown('.vdv-switch') ? d.querySelector('.vdv-switch').textContent : null, mode: d.getAttribute('data-vdv-code'),
           status: d.querySelector('.vdv-status').textContent, focus: document.activeElement.textContent,
           ckeyRole: ckey.getAttribute('role'), ckeyLabel: ckey.getAttribute('aria-label'),
           qrRole: qr.getAttribute('role'), qrLabel: qr.getAttribute('aria-label'),
           ckeyWidth: ckey.getBoundingClientRect().width, ckeyHeight: ckey.getBoundingClientRect().height,
           styled: d.querySelectorAll('[style]').length, fine: Array.from(d.querySelectorAll('.vdv-fine')).filter(n => n.getClientRects().length).map(n => n.textContent) };
}"""


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def end_headers(self):
        self.send_header("Content-Security-Policy", CSP)
        super().end_headers()


class VerifyButtonV2BrowserTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        shutil.copytree(PUBLIC, Path(cls.root) / "v2")
        (Path(cls.root) / "index.html").write_text(PAGE)
        (Path(cls.root) / "harness.js").write_text(HARNESS)
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=cls.root))
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.url = cls.origin + "/index.html"
        cls.pw = sync_playwright().start()
        exe = os.environ.get("CHROMIUM_PATH")
        if not exe:
            for candidate in Path("/opt/pw-browsers").glob("chromium-*/chrome-linux*/chrome"):
                exe = str(candidate)
                break
        cls.browser = cls.pw.chromium.launch(executable_path=exe) if exe else cls.pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.server.shutdown()
        shutil.rmtree(cls.root, ignore_errors=True)

    def open(self, **context):
        ctx = self.browser.new_context(**context)
        page = ctx.new_page()
        self.navigations = []
        self.requests = []
        page.on("request", lambda request: self.requests.append(request.url))
        page.route("https://viadere.io/**", lambda route: (self.navigations.append(route.request.url),
                                                             route.fulfill(status=200, body="landing", content_type="text/plain")))
        page.goto(self.url)
        page.wait_for_function("customElements.get('viadere-verify') !== undefined")
        return ctx, page

    def assert_no_violations(self, page):
        self.assertEqual(page.evaluate("window.__violations"), [], "the component must work under a strict CSP with Trusted Types")

    def assert_no_requests_beyond_the_page(self):
        allowed = {self.origin + path for path in ["/index.html", "/v2/viadere-verify.css", "/v2/viadere-verify.js", "/harness.js"]}
        self.assertEqual(set(self.requests) - allowed, set(), "the component makes no network requests")

    # Rendering (unchanged from v1) ------------------------------------------------------------------------------------------------

    def test_only_a_viadere_session_link_renders(self):
        ctx, page = self.open()
        ok = page.evaluate(RENDER_JS, {"link": LINK})
        self.assertEqual(ok["href"], LINK)
        self.assertEqual(ok["label"], "Verify with Viadere")
        self.assertEqual(ok["rel"], "noopener noreferrer")
        self.assertEqual(ok["styled"], 0, "no inline style attributes")
        self.assertGreaterEqual(ok["height"], 44, "44 px minimum touch target")
        self.assertIn("vdv-filled", ok["cls"])
        staging = page.evaluate(RENDER_JS, {"link": "https://viadere.cksites.dev/v/ABCDEFGH"})
        self.assertEqual(staging["href"], "https://viadere.cksites.dev/v/ABCDEFGH")
        for bad in ["http://viadere.io/v/ABCDEFGH", "https://evil.test/v/ABCDEFGH", "https://viadere.io.evil.test/v/ABCDEFGH",
                    "https://viadere.io/v/abcdefgh", "https://viadere.io/v/ABCDEFG1", "https://viadere.io/v/ABCDEFGHI",
                    "https://viadere.io/v/ABCDEFGH?x=1", "https://viadere.io/v/ABCDEFGH#x", "javascript:alert(1)//https://viadere.io/v/ABCDEFGH",
                    "https://viadere.io/k/ABCDEFGH", " https://viadere.io/v/ABCDEFGH", ""]:
            self.assertTrue(page.evaluate(RENDER_JS, {"link": bad}).get("empty"), bad)
        self.assert_no_violations(page)
        ctx.close()

    def test_variants_sizes_icon_only_and_themes(self):
        ctx, page = self.open(color_scheme="light")
        for variant in ["filled", "ivory", "outline"]:
            for size, minimum in [("sm", 36), ("md", 44), ("lg", 52)]:
                r = page.evaluate(RENDER_JS, {"link": LINK, "variant": variant, "size": size})
                self.assertIn(f"vdv-{variant}", r["cls"])
                self.assertGreaterEqual(r["height"], minimum)
        icon = page.evaluate(RENDER_JS, {"link": LINK, "display": "icon"})
        self.assertIsNone(icon["label"])
        self.assertEqual(icon["aria"], "Verify with Viadere", "an icon-only button still has an accessible name")
        self.assertAlmostEqual(icon["width"], icon["height"], delta=1)
        unknown = page.evaluate(RENDER_JS, {"link": LINK, "variant": "red", "size": "huge"})
        self.assertIn("vdv-filled", unknown["cls"])
        light = page.evaluate(RENDER_JS, {"link": LINK})["bg"]
        dark = page.evaluate(RENDER_JS, {"link": LINK, "theme": "dark"})["bg"]
        self.assertEqual(light, "rgb(31, 30, 28)", "charcoal in light mode")
        self.assertEqual(dark, "rgb(243, 240, 234)", "ivory in dark mode")
        ctx.close()
        ctx, page = self.open(color_scheme="dark")
        self.assertEqual(page.evaluate(RENDER_JS, {"link": LINK})["bg"], "rgb(243, 240, 234)", "follows the visitor's preference")
        self.assertEqual(page.evaluate(RENDER_JS, {"link": LINK, "theme": "light"})["bg"], "rgb(31, 30, 28)")
        ctx.close()

    # Desktop: the panel, Viadere code first ---------------------------------------------------------------------------------------

    def test_desktop_opens_an_accessible_panel_with_the_viadere_code_first(self):
        ctx, page = self.open()
        page.evaluate(RENDER_JS, {"link": LINK, "send-to-phone": ""})
        page.click("a.vdv-btn")
        self.assertEqual(self.navigations, [], "a computer does not navigate away")
        dialog = page.locator("dialog.vdv-panel")
        self.assertTrue(dialog.evaluate("d => d.open"))
        self.assertTrue(page.evaluate("document.querySelector('dialog.vdv-panel').matches(':modal')"), "a modal dialog: the page is inert")
        labelled = page.evaluate("document.getElementById(document.querySelector('dialog').getAttribute('aria-labelledby')).textContent")
        self.assertEqual(labelled, "Verify with Viadere")
        described = page.evaluate("document.getElementById(document.querySelector('dialog').getAttribute('aria-describedby')).textContent")
        self.assertIn("Nothing is shared until you approve", described)
        first = page.evaluate(PANEL_JS)
        self.assertTrue(first["ckey"], "the Viadere code first")
        self.assertFalse(first["qr"], "the QR code is one control away, not on screen")
        self.assertEqual(first["mode"], "ckey")
        self.assertEqual(first["lead"], "Scan with the Viadere app")
        self.assertEqual(first["swap"], "Use your phone’s camera instead")
        self.assertEqual((first["ckeyRole"], first["ckeyLabel"]), ("img", "Viadere code to scan with the Viadere app"))
        self.assertEqual((first["qrRole"], first["qrLabel"]), ("img", "QR code to continue in the Viadere app"))
        self.assertGreaterEqual(first["ckeyWidth"], 240, "large enough to scan from a screen")
        self.assertAlmostEqual(first["ckeyWidth"], first["ckeyHeight"], delta=1)
        self.assertEqual(first["styled"], 0, "no inline style attributes, in the SVG either")
        self.assertEqual(first["focus"], "Choose another option", "focus starts where it did in v1")
        # Focus trap: Tab and Shift+Tab never leave the panel, and reach the close button, the switch and the options button.
        seen = set()
        for key in ["Tab", "Tab", "Tab", "Tab", "Shift+Tab", "Shift+Tab", "Shift+Tab", "Shift+Tab", "Shift+Tab"]:
            page.keyboard.press(key)
            self.assertTrue(page.evaluate("document.querySelector('dialog').contains(document.activeElement)"), key)
            seen.add(page.evaluate("document.activeElement.getAttribute('aria-label') || document.activeElement.textContent"))
        self.assertEqual(seen, {"Close", "Use your phone’s camera instead", "Choose another option"})
        # Other options: exactly as in v1.
        page.click("text=Choose another option")
        self.assertFalse(page.locator(".vdv-ckey-frame svg").is_visible())
        self.assertFalse(page.locator(".vdv-qr").is_visible())
        self.assertEqual(page.locator(".vdv-secondary[aria-controls$='-options']").get_attribute("aria-expanded"), "true")
        titles = page.locator(".vdv-option-title").all_text_contents()
        self.assertEqual(titles, ["Open Viadere on this device", "Enter a code in the app", "Send to my phone", "Get the Viadere app"])
        self.assertEqual(page.evaluate("document.activeElement.querySelector('.vdv-option-title').textContent"), "Open Viadere on this device")
        page.click("text=Enter a code in the app")
        self.assertIn("ABCD‑EFGH", page.locator(".vdv-code-value").text_content())
        self.assertIn("A B C D E F G H", page.locator(".vdv-status").text_content(), "the code is announced to screen readers")
        page.click("text=Send to my phone")
        self.assertIn("viadere-verify-send " + LINK, page.evaluate("window.__events"))
        page.click("text=Back to the code")
        back = page.evaluate(PANEL_JS)
        self.assertTrue(back["ckey"], "back to the code that was showing")
        self.assertEqual(back["focus"], "Choose another option")
        # Escape closes and focus returns to the button.
        page.keyboard.press("Escape")
        self.assertEqual(page.locator("dialog.vdv-panel").count(), 0)
        self.assertTrue(page.evaluate("document.activeElement.classList.contains('vdv-btn')"))
        self.assertEqual(page.evaluate("window.__events.filter(e => !e.startsWith('viadere-verify-send'))"), ["viadere-verify-open", "viadere-verify-close"])
        self.assert_no_violations(page)
        self.assert_no_requests_beyond_the_page()
        ctx.close()

    def test_one_control_switches_to_the_qr_code_and_back_by_keyboard(self):
        ctx, page = self.open()
        page.evaluate(RENDER_JS, {"link": LINK, "expires-at": "2026-11-02T10:05:00Z"})
        page.focus("a.vdv-btn")
        page.keyboard.press("Enter")
        self.assertEqual(page.evaluate(PANEL_JS)["focus"], "Choose another option")
        page.keyboard.press("Shift+Tab")
        self.assertEqual(page.evaluate(PANEL_JS)["focus"], "Use your phone’s camera instead", "the switch is the control before the options button")
        page.keyboard.press("Enter")
        qr = page.evaluate(PANEL_JS)
        self.assertTrue(qr["qr"])
        self.assertFalse(qr["ckey"])
        self.assertEqual(qr["mode"], "qr")
        self.assertEqual(qr["lead"], "Scan with your phone’s camera")
        self.assertEqual(qr["swap"], "Back to the Viadere code")
        self.assertEqual(qr["focus"], "Back to the Viadere code", "focus stays on the control that was used")
        self.assertEqual(qr["status"], "Showing a QR code for your phone’s camera.", "the change is announced")
        self.assertTrue(any(text.startswith("This code works until ") for text in qr["fine"]), "the expiry applies to both codes")
        # The QR code on screen is the encoder's symbol for exactly the link (dark modules and quiet zone).
        drawn = page.evaluate("document.querySelector('.vdv-qr path').getAttribute('d')")
        matrix = page.evaluate("t => customElements.get('viadere-verify').qr(t)", LINK)
        expected = "".join(f"M{x + 4} {y + 4}h1v1h-1z" for y, row in enumerate(matrix) for x, dark in enumerate(row) if dark)
        self.assertEqual(drawn, expected)
        # Other options and back keep the QR code the person chose.
        page.click("text=Choose another option")
        page.click("text=Back to the code")
        self.assertTrue(page.evaluate(PANEL_JS)["qr"])
        page.click("text=Back to the Viadere code")
        again = page.evaluate(PANEL_JS)
        self.assertTrue(again["ckey"])
        self.assertFalse(again["qr"])
        self.assertEqual(again["lead"], "Scan with the Viadere app")
        self.assertEqual(again["swap"], "Use your phone’s camera instead")
        self.assertEqual(again["status"], "Showing the Viadere code for the Viadere app.")
        page.keyboard.press("Escape")
        # A panel opened again starts with the Viadere code.
        page.click("a.vdv-btn")
        self.assertTrue(page.evaluate(PANEL_JS)["ckey"])
        page.click(".vdv-close")
        self.assertEqual(page.locator("dialog").count(), 0)
        self.assert_no_violations(page)
        self.assert_no_requests_beyond_the_page()
        ctx.close()

    def test_send_to_phone_is_offered_only_when_the_integrator_enables_it(self):
        ctx, page = self.open()
        page.evaluate(RENDER_JS, {"link": LINK})
        page.click("a.vdv-btn")
        page.click("text=Choose another option")
        self.assertNotIn("Send to my phone", page.locator(".vdv-option-title").all_text_contents())
        page.click(".vdv-close")
        self.assertEqual(page.locator("dialog").count(), 0)
        ctx.close()

    def test_a_modified_click_keeps_the_browsers_behaviour(self):
        ctx, page = self.open()
        page.evaluate(RENDER_JS, {"link": LINK})
        with ctx.expect_page() as popup:
            page.click("a.vdv-btn", modifiers=["Shift"])
        popup.value.close()
        self.assertEqual(page.locator("dialog").count(), 0)
        ctx.close()

    def test_forced_colours_show_the_qr_code_with_an_explanation(self):
        # The concept style is cream ink on a dark vignette: forced colours would repaint it. That mode gets the high-contrast QR code.
        ctx, page = self.open(forced_colors="active")
        page.evaluate(RENDER_JS, {"link": LINK})
        page.click("a.vdv-btn")
        forced = page.evaluate(PANEL_JS)
        self.assertTrue(forced["qr"])
        self.assertFalse(forced["ckey"])
        self.assertEqual(forced["lead"], "Scan with your phone’s camera")
        self.assertIsNone(forced["swap"], "no switch to a code that cannot be drawn in this mode")
        self.assertTrue(any("High-contrast colours are on" in text for text in forced["fine"]), "…and the panel says why")
        self.assertEqual(forced["focus"], "Choose another option")
        colours = page.evaluate("""() => { const q = document.querySelector('.vdv-qr');
            return [getComputedStyle(q.querySelector('rect')).fill, getComputedStyle(q.querySelector('path')).fill]; }""")
        self.assertEqual(colours, ["rgb(255, 255, 255)", "rgb(31, 30, 28)"], "the QR code keeps its own black on white")
        for key in ["Tab", "Tab", "Tab", "Shift+Tab"]:
            page.keyboard.press(key)
            self.assertTrue(page.evaluate("document.querySelector('dialog').contains(document.activeElement)"), key)
        # Forced colours ending while the panel is open brings the Viadere code and the switch back; starting again hides them, and
        # focus never stays on the control that disappeared.
        page.emulate_media(forced_colors="none")
        page.wait_for_function("() => document.querySelector('dialog.vdv-panel').getAttribute('data-vdv-code') === 'ckey'")
        normal = page.evaluate(PANEL_JS)
        self.assertTrue(normal["ckey"])
        self.assertEqual(normal["swap"], "Use your phone’s camera instead")
        self.assertFalse(any("High-contrast" in text for text in normal["fine"]))
        page.focus(".vdv-switch")
        page.emulate_media(forced_colors="active")
        page.wait_for_function("() => document.querySelector('dialog.vdv-panel').getAttribute('data-vdv-code') === 'qr'")
        self.assertEqual(page.evaluate(PANEL_JS)["focus"], "Choose another option")
        page.keyboard.press("Escape")
        self.assertEqual(page.locator("dialog").count(), 0)
        self.assert_no_violations(page)
        ctx.close()

    # Phone: hand-off ----------------------------------------------------------------------------------------------------------------

    def test_a_phone_follows_the_universal_link(self):
        ctx, page = self.open(user_agent=IPHONE, viewport={"width": 390, "height": 844}, has_touch=True, is_mobile=True)
        page.evaluate(RENDER_JS, {"link": LINK})
        with page.expect_navigation():
            page.click("a.vdv-btn")
        self.assertEqual(self.navigations, [LINK], "the OS hands the link to the installed app, or shows the landing page")
        ctx.close()

    # QR correctness (unchanged from v1) ---------------------------------------------------------------------------------------------

    def test_the_qr_code_is_a_correct_symbol(self):
        ctx, page = self.open()
        def reference(text, mask=None):
            ref = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=0, mask_pattern=mask)
            ref.add_data(qrcode.util.QRData(text.encode(), mode=qrcode.util.MODE_8BIT_BYTE))  # byte mode, as the component encodes
            ref.make(fit=True)
            return [[bool(v) for v in row] for row in ref.get_matrix()]
        for text in [LINK, "https://viadere.cksites.dev/v/ZZZZ9999", "https://viadere.io/v/23456789", "A", "x" * 120]:
            ours = page.evaluate("t => customElements.get('viadere-verify').qr(t)", text)
            matches = [mask for mask in range(8) if reference(text, mask) == ours]
            self.assertEqual(len(matches), 1, f"{text!r}: exactly one reference mask must reproduce the symbol")
            # Which of the eight masks wins depends on the penalty evaluation, where libraries differ in details; any mask is a valid
            # symbol, so the test pins the encoding (data, error correction, interleaving, placement, format and version bits) only.
        self.assertEqual(len(page.evaluate("t => customElements.get('viadere-verify').qr(t)", LINK)), 29, "a session link is a version 3 symbol")
        ctx.close()

    # CKey correctness ---------------------------------------------------------------------------------------------------------------

    def test_the_ckey_encoder_reproduces_every_reference_vector(self):
        self.assertEqual(len(VECTORS), 37)
        self.assertEqual({v["version"] for v in VECTORS}, set(range(1, 32)), "the vectors cover all 31 versions")
        self.assertEqual({v["level"] for v in VECTORS}, {0, 1, 2, 3}, "…and all four levels")
        ctx, page = self.open()
        for v in VECTORS:
            ours = page.evaluate("([bytes, level, version]) => customElements.get('viadere-verify').ckey(bytes, level, version)",
                                 [list(bytes.fromhex(v["payload"])), v["level"], v["requested_version"]])
            self.assertEqual(ours["version"], v["version"], v["name"])
            self.assertEqual(ours["level"], v["level"], v["name"])
            self.assertEqual(ours["codeword"], v["codeword"], f"{v['name']}: the codeword must be the reference's, bit for bit")
        # Text is encoded as UTF-8 at level M with the smallest version, which is what the panel does with the link.
        named = {v["name"]: v for v in VECTORS}
        link = bytes.fromhex(named["verify-link"]["payload"]).decode()
        self.assertEqual(link, "https://viadere.io/v/K7QFM2XA")
        self.assertEqual(page.evaluate("t => customElements.get('viadere-verify').ckey(t)", link),
                         {"version": 2, "level": 1, "codeword": named["verify-link"]["codeword"]})
        self.assertEqual(page.evaluate("t => customElements.get('viadere-verify').ckey(t).version", "https://viadere.cksites.dev/v/ZZZZ9999"), 3,
                         "the longest session link (38 bytes) is a version 3 symbol")
        # Out of range: null, never a wrong symbol.
        for arguments in [["x" * 5000, 3, 0], ["x" * 40, 1, 1], ["x", 4, 0], ["x", 1, 32], [[256], 1, 0]]:
            self.assertIsNone(page.evaluate("a => customElements.get('viadere-verify').ckey(a[0], a[1], a[2])", arguments), arguments)
        self.assert_no_violations(page)
        ctx.close()

    def test_the_ckey_drawing_is_the_reference_svg_byte_for_byte(self):
        # `ckeySVG` builds DOM nodes (createElementNS, attributes only). Its XML serialization is compared with the SVG document the
        # reference renderer wrote for the same input ("concept" preset, scale 16) through the SHA-256 recorded in the vector file.
        # No normalisation is needed: XMLSerializer writes the namespace declaration first and then the attributes in the order they
        # were set, keeps attribute case for SVG elements, and writes childless elements as `<tag/>`, which is how the reference prints.
        ctx, page = self.open()
        for v in VECTORS:
            text = page.evaluate("""([bytes, level, version]) =>
                new XMLSerializer().serializeToString(customElements.get('viadere-verify').ckeySVG(bytes, level, version))""",
                                 [list(bytes.fromhex(v["payload"])), v["level"], v["requested_version"]])
            self.assertTrue(text.startswith('<svg xmlns="http://www.w3.org/2000/svg" width="496" height="496" viewBox="-1 -1 31 31" role="img" '), v["name"])
            self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), v["concept_svg_sha256"],
                             f"{v['name']}: the serialized SVG must be the reference renderer's output, byte for byte")
        self.assert_no_violations(page)
        ctx.close()

    def test_the_panel_draws_the_reference_symbol_with_its_own_ids_and_label(self):
        # The SVG in the panel differs from the reference document in exactly two deliberate ways, which this test undoes before hashing:
        #   1. ids: the reference's fixed ids (ckey-ink, ckey-bg, ckey-grain, ckey-depth) get the panel's unique suffix ("-vdv-N"), in the
        #      `id` attributes and in the `url(#…)` references, so two symbols in one document never share an id;
        #   2. the accessible name: "Viadere code to scan with the Viadere app" instead of the reference's "CKey scalable symbol …".
        # Everything else (every element, attribute, coordinate, their order) must be the reference's bytes.
        vector = next(v for v in VECTORS if v["name"] == "verify-link")
        link = bytes.fromhex(vector["payload"]).decode()
        ctx, page = self.open()
        page.evaluate("""(link) => {
          const host = document.getElementById('host');
          host.textContent = '';
          const stranger = document.createElement('span');   // an integrator's own element that happens to use a reference id
          stranger.id = 'ckey-ink';
          host.appendChild(stranger);
          for (let i = 0; i < 2; i++) { const el = document.createElement('viadere-verify'); el.setAttribute('link', link); host.appendChild(el); }
        }""", link)
        suffixes = []
        for index in [0, 1, 0]:
            page.evaluate("i => document.querySelectorAll('viadere-verify')[i].open()", index)
            self.assertEqual(page.locator("dialog.vdv-panel").count(), 1, "one panel at a time")
            info = page.evaluate("""() => {
              const svg = document.querySelector('dialog.vdv-panel .vdv-ckey-frame svg');
              const ids = Array.from(document.querySelectorAll('[id]')).map(n => n.id);
              const refs = [];
              svg.querySelectorAll('*').forEach(n => { for (const a of n.attributes) { const m = /^url\\(#(.+)\\)$/.exec(a.value); if (m) refs.push(m[1]); } });
              return { text: new XMLSerializer().serializeToString(svg), ids, own: Array.from(svg.querySelectorAll('[id]')).map(n => n.id),
                       resolved: refs.every(id => svg.contains(document.getElementById(id))), refs: refs.length,
                       dialogId: document.querySelector('dialog.vdv-panel').getAttribute('aria-labelledby').replace(/-title$/, ''),
                       scripts: svg.querySelectorAll('script, a, image, use, foreignObject, style').length,
                       text_nodes: svg.textContent };
            }""")
            self.assertEqual(len(info["ids"]), len(set(info["ids"])), "every id in the document is unique")
            suffix = "-" + info["dialogId"]
            suffixes.append(suffix)
            self.assertRegex(suffix, r"^-vdv-\d+$")
            self.assertEqual(info["own"], [name + suffix for name in ["ckey-ink", "ckey-bg", "ckey-grain", "ckey-depth"]])
            self.assertTrue(info["resolved"], "every url(#…) points at this symbol's own definitions")
            self.assertEqual(info["refs"], 5, "background, grain, ink fill, ink stroke, depth")
            self.assertEqual(info["scripts"], 0, "shapes, gradients and filters only")
            self.assertEqual(info["text_nodes"], "", "the link is never printed as text in the symbol")
            self.assertNotIn(link, info["text"])
            normalised = info["text"]
            for name in ["ckey-ink", "ckey-bg", "ckey-grain", "ckey-depth"]:
                self.assertEqual(normalised.count(name + suffix), {"ckey-ink": 3}.get(name, 2), name)
                normalised = normalised.replace(name + suffix, name)
            label = 'aria-label="Viadere code to scan with the Viadere app"'
            self.assertEqual(normalised.count(label), 1)
            normalised = normalised.replace(label, f'aria-label="CKey scalable symbol profile 0 version {vector["version"]}"')
            self.assertEqual(hashlib.sha256(normalised.encode()).hexdigest(), vector["concept_svg_sha256"])
            page.evaluate("i => document.querySelectorAll('viadere-verify')[i].close()", index)
        self.assertEqual(len(set(suffixes)), 3, "a new suffix for every panel")
        self.assertIsNone(re.search(r"\sstyle=", info["text"]), "attributes only, no inline style")
        self.assert_no_violations(page)
        self.assert_no_requests_beyond_the_page()
        ctx.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
