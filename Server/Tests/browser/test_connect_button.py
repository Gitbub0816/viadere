"""Headless-browser test for the embeddable "Connect with Viadere" web component (Python + Playwright, no Node.js).

Loads the real Server/Public/connect-button/v1/viadere-connect.{js,css} into Chromium from a local temporary web root and
checks which link (if any) <viadere-connect> renders for each attribute case.

Run: see Server/Tests/browser/README.md
"""
import functools
import http.server
import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path

from playwright.sync_api import sync_playwright

PUBLIC = Path(__file__).resolve().parents[2] / "Public" / "connect-button" / "v1"
SIG = "A" * 43
CTX = "eyJhIjoxfQ"

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>connect</title>
<link rel="stylesheet" href="/v1/viadere-connect.css"></head><body>
<script src="/v1/viadere-connect.js"></script></body></html>"""

# name -> attributes
CASES = {
    "plain": {"code": "AF2345"},
    "dashed": {"code": "af-2345"},
    "ambiguous": {"code": "AF 23I5"},
    "zero": {"code": "ZO2345"},
    "short": {"code": "AF234"},
    "long": {"code": "AF23456"},
    "hostile": {"code": "javascript:alert(1)"},
    "empty": {},
    "signed": {"code": "AF2345", "ctx": CTX, "sig": SIG},
    "ctxOnly": {"code": "AF2345", "ctx": CTX},
    "badSig": {"code": "AF2345", "ctx": CTX, "sig": "short"},
    "badCtx": {"code": "AF2345", "ctx": "a b<c", "sig": SIG},
    "bigCtx": {"code": "AF2345", "ctx": "A" * 513, "sig": SIG},
    "injected": {"code": "AF2345&x=1", "ctx": 'x"onmouseover="alert(1)', "sig": SIG},
    "label": {"code": "AF2345", "label": "<img src=x onerror=alert(1)>" + "y" * 60},
}

RENDER_JS = """(attrs) => {
  const el = document.createElement('viadere-connect');
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  document.body.appendChild(el);
  const root = el.shadowRoot;
  const a = root && root.querySelector('a');
  if (!a) return { empty: true, shadowText: root ? root.textContent : null };
  return { href: a.getAttribute('href'), label: a.querySelector('span').textContent, html: root.innerHTML,
           rel: a.getAttribute('rel'), injectedElements: root.querySelectorAll('img, script').length,
           height: a.getBoundingClientRect().height };
}"""


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class ConnectButtonBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp(prefix="viadere-btn-"))
        shutil.copytree(PUBLIC, cls.root / "v1")
        (cls.root / "index.html").write_text(PAGE, encoding="utf-8")
        handler = functools.partial(Quiet, directory=str(cls.root))
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}/"

        cls.pw = sync_playwright().start()
        exe = os.environ.get("CHROMIUM_PATH") or ("/opt/pw-browsers/chromium" if os.path.exists("/opt/pw-browsers/chromium") else None)
        cls.browser = cls.pw.chromium.launch(headless=True, **({"executable_path": exe} if exe else {}))
        cls.page = cls.browser.new_page()
        cls.requests = []
        cls.page.on("request", lambda r: cls.requests.append(r.url))
        cls.errors = []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.goto(cls.base)
        cls.page.wait_for_function("customElements.get('viadere-connect') !== undefined")
        cls.results = {name: cls.page.evaluate(RENDER_JS, attrs) for name, attrs in CASES.items()}

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.root, ignore_errors=True)

    def href(self, key):
        return self.results[key].get("href")

    def test_the_component_loads_without_errors_or_extra_requests(self):
        self.assertEqual(self.errors, [])
        for url in self.requests:
            self.assertTrue(url.startswith(self.base), f"unexpected request {url}")

    def test_valid_codes_link_to_the_connect_page(self):
        self.assertEqual(self.href("plain"), "https://viadere.com/c/AF2345")
        self.assertEqual(self.href("dashed"), "https://viadere.com/c/AF2345")
        self.assertEqual(self.href("ambiguous"), "https://viadere.com/c/AF2315", "I -> 1 like the server")
        self.assertEqual(self.href("zero"), "https://viadere.com/c/Z02345", "O -> 0 like the server")

    def test_invalid_codes_render_nothing(self):
        for key in ["short", "long", "hostile", "empty", "injected"]:
            self.assertTrue(self.results[key].get("empty"), f"{key} renders nothing")

    def test_signed_context(self):
        self.assertEqual(self.href("signed"), f"https://viadere.com/c/AF2345?ctx={CTX}&sig={SIG}")
        for key in ["ctxOnly", "badSig", "badCtx", "bigCtx"]:
            self.assertEqual(self.href(key), "https://viadere.com/c/AF2345", f"{key} falls back to the plain link")

    def test_label_is_text_and_bounded(self):
        r = self.results["label"]
        self.assertEqual(len(r["label"]), 40)
        self.assertTrue(r["label"].startswith("<img"), "kept as literal text")
        self.assertNotIn("<img", r["html"], "never interpolated into markup (it is serialised escaped)")
        self.assertEqual(r["injectedElements"], 0)

    def test_every_link_points_at_viadere_com_only(self):
        for key, r in self.results.items():
            if "href" in r:
                self.assertTrue(r["href"].startswith("https://viadere.com/c/"), key)
                self.assertEqual(r["rel"], "noopener noreferrer")

    def test_stylesheet_loaded_and_touch_target(self):
        self.assertTrue(any(u.endswith("viadere-connect.css") for u in self.requests))
        self.assertGreaterEqual(self.results["plain"]["height"], 44)


if __name__ == "__main__":
    unittest.main()
