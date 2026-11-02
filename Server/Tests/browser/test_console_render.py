"""Renders the business dashboard and the operator console in headless Chromium and checks the layout (Python + Playwright, no Node.js).

1. `CONSOLE_DUMP_DIR=<dir> swift test --filter ConsoleRenderDump` (in Server/) boots the app with a busy fixture business and an operator, crawls
   every console page reachable by link and writes bodies, headers and a manifest.json to <dir>.
2. This script serves <dir> with the **real response headers** (the CSP pins the stylesheet by hash, so a CSS change that is not reflected in the
   pin shows up as a violation here), then opens each HTML page at 1440 / 1024 / 820 / 560 / 390 px, light and dark, and reports:
   CSP violations, horizontal page overflow, elements that stick out of the viewport or their card, text below WCAG AA contrast, and targets
   smaller than 24 CSS px. Screenshots go to --out.

Run (see README.md for the venv):
    CONSOLE_DUMP_DIR=/tmp/console-dump swift test --package-path Server --filter ConsoleRenderDump
    python Server/Tests/browser/test_console_render.py /tmp/console-dump --out /tmp/console-shots [--only brand,loops] [--widths 1440,390]
Exit status 1 when any check fails. `python -m unittest` runs the same checks when CONSOLE_DUMP_DIR is set (screenshots skipped).
"""
import argparse
import http.server
import json
import os
import re
import sys
import threading
import unittest
from pathlib import Path

from playwright.sync_api import sync_playwright

WIDTHS = [1440, 1024, 820, 560, 390]
SCHEMES = ["light", "dark"]

MEASURE_JS = r"""() => {
  const out = {overflow: [], contrast: [], small: []};
  const vw = document.documentElement.clientWidth;
  out.scrollWidth = document.documentElement.scrollWidth; out.clientWidth = vw;
  const scrollers = (el) => { for (let p = el; p && p !== document.body; p = p.parentElement) {
    const o = getComputedStyle(p).overflowX; if ((o === 'auto' || o === 'scroll') && p !== document.documentElement) return p; } return null; };
  const label = (el) => el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (typeof el.className === 'string' && el.className ? '.' + el.className.trim().split(/\s+/).join('.') : '');
  const parse = (c) => { const m = c.match(/rgba?\(([^)]+)\)/); if (!m) return null; const p = m[1].split(/[ ,\/]+/).filter(Boolean).map(Number); return {r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1}; };
  const over = (top, bot) => ({r: top.r * top.a + bot.r * (1 - top.a), g: top.g * top.a + bot.g * (1 - top.a), b: top.b * top.a + bot.b * (1 - top.a), a: 1});
  const lum = (c) => { const f = (v) => { v /= 255; return v <= .03928 ? v / 12.92 : Math.pow((v + .055) / 1.055, 2.4); }; return .2126 * f(c.r) + .7152 * f(c.g) + .0722 * f(c.b); };
  const bgOf = (el) => { const stack = []; for (let p = el; p; p = p.parentElement) { const cs = getComputedStyle(p); const c = parse(cs.backgroundColor); if (c && c.a > 0) { stack.push(c); if (c.a >= 1) break; } }
    let base = {r: 255, g: 255, b: 255, a: 1}; if (!stack.length || stack[stack.length - 1].a < 1) { const b = parse(getComputedStyle(document.body).backgroundColor); if (b && b.a > 0) base = b; else base = parse(getComputedStyle(document.documentElement).backgroundColor) || base; if (base.a < 1) base = {r: 255, g: 255, b: 255, a: 1}; }
    for (let i = stack.length - 1; i >= 0; i--) base = over(stack[i], base); return base; };
  const seen = new Set();
  for (const el of document.querySelectorAll('body *')) {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) continue;
    if (el.closest('iframe, svg, .vh, .skip')) continue;
    // Overflow: sticks out of the viewport and is not inside a deliberate scroller.
    if ((r.right > vw + 1 || r.left < -1) && !scrollers(el)) { const k = label(el); if (!seen.has('o' + k)) { seen.add('o' + k); out.overflow.push(k + ' ' + Math.round(r.left) + '..' + Math.round(r.right)); } }
    // Text contrast for elements with their own text.
    const own = Array.from(el.childNodes).some(n => n.nodeType === 3 && n.textContent.trim().length > 0);
    if (own && !el.matches('option') && !(el.closest('[disabled]') || el.closest('[aria-disabled=true]'))) {
      const fg = parse(cs.color); if (fg) {
        const bg = bgOf(el); const op = parseFloat(cs.opacity) || 1; let eff = fg; let o = 1; for (let p = el; p; p = p.parentElement) o *= parseFloat(getComputedStyle(p).opacity) || 1;
        eff = over({r: fg.r, g: fg.g, b: fg.b, a: fg.a * o}, bg);
        const l1 = lum(eff), l2 = lum(bg), ratio = (Math.max(l1, l2) + .05) / (Math.min(l1, l2) + .05);
        const size = parseFloat(cs.fontSize), bold = parseInt(cs.fontWeight) >= 700; const large = size >= 24 || (size >= 18.66 && bold);
        if (ratio < (large ? 3 : 4.5)) { const k = label(el) + ' "' + el.textContent.trim().slice(0, 24) + '"'; if (!seen.has('c' + k)) { seen.add('c' + k); out.contrast.push(ratio.toFixed(2) + ' ' + k); } }
      }
    }
    // Targets below WCAG 2.2 AA minimum (24px), unless inline in text.
    if (el.matches('a[href], button, input:not([type=hidden]), select, summary') && cs.display !== 'inline') {
      if ((r.width < 24 || r.height < 24) && !(el.matches('input[type=checkbox], input[type=radio]') && el.closest('label'))) { const k = label(el) + ' ' + Math.round(r.width) + 'x' + Math.round(r.height); if (!seen.has('s' + k)) { seen.add('s' + k); out.small.push(k); } }
    }
  }
  return out;
}"""


def make_handler(root: Path, entries: dict):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            entry = entries.get(self.path) or entries.get(self.path.split("?")[0])
            if entry is None:
                self.send_response(404)
                self.end_headers()
                return
            body = (root / entry["file"]).read_bytes()
            self.send_response(entry["status"])
            self.send_header("Content-Type", entry["contentType"])
            for k, v in entry["headers"].items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return Handler


def slug(path: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-")[:70] or "root"


def chromium_path():
    for candidate in (os.environ.get("CHROMIUM_PATH"), "/opt/pw-browsers/chromium"):
        if candidate and Path(candidate).exists():
            return candidate
    return None


def run(dump: Path, out: Path | None, widths, schemes, only):
    manifest = json.loads((dump / "manifest.json").read_text())
    entries = {e["path"]: e for e in manifest}
    pages = [e for e in manifest if e["status"] == 200 and "html" in e["contentType"] and (not only or any(o in e["path"] for o in only))
             and "/preview" not in e["path"]]
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(dump, entries))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    problems = []
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=chromium_path())
        for scheme in schemes:
            for width in widths:
                context = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=scheme)
                for e in pages:
                    page = context.new_page()
                    violations = []
                    page.on("console", lambda m, v=violations: v.append(m.text) if "Content Security Policy" in m.text else None)
                    page.goto(base + e["path"], wait_until="load")
                    m = page.evaluate(MEASURE_JS)
                    tag = f"{e['path']} @{width} {scheme}"
                    if violations:
                        problems.append((tag, "csp", violations[:2]))
                    if m["scrollWidth"] > m["clientWidth"] + 1:
                        problems.append((tag, "page-overflow", [f"{m['scrollWidth']} > {m['clientWidth']}"]))
                    if m["overflow"]:
                        problems.append((tag, "sticks-out", m["overflow"][:5]))
                    if m["contrast"]:
                        problems.append((tag, "contrast", m["contrast"][:6]))
                    if m["small"]:
                        problems.append((tag, "small-target", m["small"][:4]))
                    if out is not None:
                        out.mkdir(parents=True, exist_ok=True)
                        page.screenshot(path=str(out / f"{e['realm']}-{slug(e['path'])}-{width}-{scheme}.png"), full_page=True)
                    page.close()
                context.close()
        browser.close()
    server.shutdown()
    return len(pages), problems


class ConsoleRenderTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("CONSOLE_DUMP_DIR"), "CONSOLE_DUMP_DIR not set")
    def test_no_csp_violation_overflow_or_contrast_failure(self):
        count, problems = run(Path(os.environ["CONSOLE_DUMP_DIR"]), None, WIDTHS, SCHEMES, [])
        hard = [x for x in problems if x[1] in ("csp", "page-overflow", "contrast")]
        self.assertGreater(count, 20)
        self.assertEqual(hard, [], "\n".join(map(str, hard[:20])))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("dump", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--widths", default=",".join(map(str, WIDTHS)))
    ap.add_argument("--schemes", default=",".join(SCHEMES))
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    n, problems = run(a.dump, a.out, [int(w) for w in a.widths.split(",")], a.schemes.split(","), [o for o in a.only.split(",") if o])
    print(f"{n} pages")
    for tag, kind, detail in problems:
        print(f"{kind:14} {tag}: {'; '.join(detail)}")
    hard = [x for x in problems if x[1] in ("csp", "page-overflow", "contrast")]
    print(f"{len(problems)} findings, {len(hard)} blocking")
    sys.exit(1 if hard else 0)
