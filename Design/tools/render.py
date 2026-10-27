"""Rasterise / print HTML with headless Chromium via Python Playwright (port of render.js)."""
import glob
import os
from playwright.sync_api import sync_playwright

_CANDIDATES = [
    '/opt/pw-browsers/chromium',
    *sorted(glob.glob('/opt/pw-browsers/chromium-*/chrome-linux*/chrome')),
]


def _launch_kwargs():
    """Use $VIADERE_CHROMIUM or a preinstalled Chromium if there is one; otherwise Playwright's own browser."""
    path = os.environ.get('VIADERE_CHROMIUM')
    if not path:
        path = next((c for c in _CANDIDATES if os.path.isfile(c) and os.access(c, os.X_OK)), None)
    return {'executable_path': path} if path else {}


def render_many(jobs):
    """jobs: dicts with html, out (path or None to return bytes), w, h and optional
    scale, wait (ms), pdf (+ pw/ph CSS px), transparent, full."""
    results = []
    with sync_playwright() as pw:
        b = pw.chromium.launch(**_launch_kwargs())
        for j in jobs:
            pg = b.new_page(viewport={'width': j['w'], 'height': j['h']}, device_scale_factor=j.get('scale', 1))
            pg.set_content(j['html'], wait_until='load')
            if j.get('wait'):
                pg.wait_for_timeout(j['wait'])
            if j.get('pdf'):
                data = pg.pdf(path=j.get('out'), width=j['pw'], height=j['ph'], print_background=False, page_ranges='1',
                              margin={'top': '0', 'right': '0', 'bottom': '0', 'left': '0'})
            else:
                data = pg.screenshot(path=j.get('out'), omit_background=bool(j.get('transparent')), full_page=bool(j.get('full')))
            results.append(data)
            pg.close()
        b.close()
    return results
