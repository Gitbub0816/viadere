"""Headless-browser test for the embeddable "Verify with Viadere" web component (Python + Playwright, no Node.js in the repo).

Loads the real Server/Public/verify-button/v1/viadere-verify.{js,css} into Chromium from a local web root served with a **strict CSP**
(no inline script or style, Trusted Types required) and checks: which link (if any) renders, that nothing violates the CSP, the desktop
QR-first panel (focus trap, Escape, focus return, other options), the phone hand-off (a plain navigation to the universal link), and that
the QR code is a correct ISO/IEC 18004 symbol (module-for-module equal to the `qrcode` reference library's encoding of the same text, version and mask).

Run: see Server/Tests/browser/README.md (needs `qrcode` as well as `playwright`).
"""
import functools
import http.server
import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path

import qrcode
import qrcode.util
from playwright.sync_api import sync_playwright

PUBLIC = Path(__file__).resolve().parents[2] / "Public" / "verify-button" / "v1"
LINK = "https://viadere.com/v/ABCDEFGH"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; "
       "require-trusted-types-for 'script'; trusted-types 'none'")

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>verify</title>
<link rel="stylesheet" href="/v1/viadere-verify.css"></head><body><main id="host"></main>
<script src="/v1/viadere-verify.js"></script><script src="/harness.js"></script></body></html>"""

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


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def end_headers(self):
        self.send_header("Content-Security-Policy", CSP)
        super().end_headers()


class VerifyButtonBrowserTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        shutil.copytree(PUBLIC, Path(cls.root) / "v1")
        (Path(cls.root) / "index.html").write_text(PAGE)
        (Path(cls.root) / "harness.js").write_text(HARNESS)
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=cls.root))
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}/index.html"
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
        page.route("https://viadere.com/**", lambda route: (self.navigations.append(route.request.url),
                                                             route.fulfill(status=200, body="landing", content_type="text/plain")))
        page.goto(self.url)
        page.wait_for_function("customElements.get('viadere-verify') !== undefined")
        return ctx, page

    def assert_no_violations(self, page):
        self.assertEqual(page.evaluate("window.__violations"), [], "the component must work under a strict CSP with Trusted Types")

    # Rendering -------------------------------------------------------------------------------------------------------------------

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
        for bad in ["http://viadere.com/v/ABCDEFGH", "https://evil.test/v/ABCDEFGH", "https://viadere.com.evil.test/v/ABCDEFGH",
                    "https://viadere.com/v/abcdefgh", "https://viadere.com/v/ABCDEFG1", "https://viadere.com/v/ABCDEFGHI",
                    "https://viadere.com/v/ABCDEFGH?x=1", "https://viadere.com/v/ABCDEFGH#x", "javascript:alert(1)//https://viadere.com/v/ABCDEFGH",
                    "https://viadere.com/k/ABCDEFGH", " https://viadere.com/v/ABCDEFGH", ""]:
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

    # Desktop: QR-first panel ---------------------------------------------------------------------------------------------------

    def test_desktop_opens_an_accessible_qr_first_panel(self):
        ctx, page = self.open()
        page.evaluate(RENDER_JS, {"link": LINK, "send-to-phone": ""})
        page.click("a.vdv-btn")
        self.assertEqual(self.navigations, [], "a computer does not navigate away")
        dialog = page.locator("dialog.vdv-panel")
        self.assertTrue(dialog.evaluate("d => d.open"))
        self.assertTrue(page.evaluate("document.querySelector('dialog.vdv-panel').matches(':modal')"), "a modal dialog: the page is inert")
        labelled = page.evaluate("document.getElementById(document.querySelector('dialog').getAttribute('aria-labelledby')).textContent")
        self.assertEqual(labelled, "Verify with Viadere")
        self.assertEqual(page.locator(".vdv-qr").get_attribute("role"), "img")
        self.assertTrue(page.locator(".vdv-qr").is_visible(), "QR first")
        self.assertEqual(page.evaluate("document.activeElement.textContent"), "Choose another option")
        # Focus trap: Tab and Shift+Tab never leave the panel.
        for key in ["Tab", "Tab", "Tab", "Shift+Tab", "Shift+Tab", "Shift+Tab", "Shift+Tab"]:
            page.keyboard.press(key)
            self.assertTrue(page.evaluate("document.querySelector('dialog').contains(document.activeElement)"), key)
        # Other options.
        page.click("text=Choose another option")
        self.assertFalse(page.locator(".vdv-qr").is_visible())
        self.assertEqual(page.locator(".vdv-secondary[aria-controls$='-options']").get_attribute("aria-expanded"), "true")
        titles = page.locator(".vdv-option-title").all_text_contents()
        self.assertEqual(titles, ["Open Viadere on this device", "Enter a code in the app", "Send to my phone", "Get the Viadere app"])
        page.click("text=Enter a code in the app")
        self.assertIn("ABCD‑EFGH", page.locator(".vdv-code-value").text_content())
        self.assertIn("A B C D E F G H", page.locator(".vdv-status").text_content(), "the code is announced to screen readers")
        page.click("text=Send to my phone")
        self.assertIn("viadere-verify-send " + LINK, page.evaluate("window.__events"))
        page.click("text=Back to the QR code")
        self.assertTrue(page.locator(".vdv-qr").is_visible())
        # Escape closes and focus returns to the button.
        page.keyboard.press("Escape")
        self.assertEqual(page.locator("dialog.vdv-panel").count(), 0)
        self.assertTrue(page.evaluate("document.activeElement.classList.contains('vdv-btn')"))
        self.assertEqual(page.evaluate("window.__events.filter(e => !e.startsWith('viadere-verify-send'))"), ["viadere-verify-open", "viadere-verify-close"])
        self.assert_no_violations(page)
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

    # Phone: hand-off ----------------------------------------------------------------------------------------------------------------

    def test_a_phone_follows_the_universal_link(self):
        ctx, page = self.open(user_agent=IPHONE, viewport={"width": 390, "height": 844}, has_touch=True, is_mobile=True)
        page.evaluate(RENDER_JS, {"link": LINK})
        with page.expect_navigation():
            page.click("a.vdv-btn")
        self.assertEqual(self.navigations, [LINK], "the OS hands the link to the installed app, or shows the landing page")
        ctx.close()

    # QR correctness -----------------------------------------------------------------------------------------------------------------

    def test_the_qr_code_is_a_correct_symbol(self):
        ctx, page = self.open()
        def reference(text, mask=None):
            ref = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=0, mask_pattern=mask)
            ref.add_data(qrcode.util.QRData(text.encode(), mode=qrcode.util.MODE_8BIT_BYTE))  # byte mode, as the component encodes
            ref.make(fit=True)
            return [[bool(v) for v in row] for row in ref.get_matrix()]
        for text in [LINK, "https://viadere.cksites.dev/v/ZZZZ9999", "https://viadere.com/v/23456789", "A", "x" * 120]:
            ours = page.evaluate("t => customElements.get('viadere-verify').qr(t)", text)
            matches = [mask for mask in range(8) if reference(text, mask) == ours]
            self.assertEqual(len(matches), 1, f"{text!r}: exactly one reference mask must reproduce the symbol")
            # Which of the eight masks wins depends on the penalty evaluation, where libraries differ in details; any mask is a valid
            # symbol, so the test pins the encoding (data, error correction, interleaving, placement, format and version bits) only.
        self.assertEqual(len(page.evaluate("t => customElements.get('viadere-verify').qr(t)", LINK)), 29, "a session link is a version 3 symbol")
        ctx.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
