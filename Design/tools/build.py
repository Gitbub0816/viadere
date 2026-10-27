#!/usr/bin/env python3
"""Regenerate every Viadere brand asset from the single Bézier source (geom.py + final.json).

    python3 Design/tools/build.py

Writes, relative to the repo root:
  Design/svg/*.svg, Design/png/*.png, Design/pdf/*.pdf     artwork (PNG/PDF rendered by headless Chromium)
  App/Shared/DesignSystem/ViadereMark.swift                SwiftUI path data
  App/Resources/Assets.xcassets/**                         app icon, image sets and colour sets
  Design/brand-guide.html                                  the self-contained brand guide

Setup: see Design/README.md (a venv at Design/tools/.venv with requirements.txt; build.py re-runs
itself inside it automatically).
"""
import os
import re
import sys

TOOLS = os.path.dirname(os.path.abspath(__file__))
VENV_PY = os.path.join(TOOLS, '.venv', 'bin', 'python')


def _ensure_deps():
    try:
        import fontTools, PIL, playwright  # noqa: F401
    except ImportError:
        if os.path.isfile(VENV_PY) and os.path.realpath(sys.prefix) != os.path.realpath(os.path.join(TOOLS, '.venv')):
            os.execv(VENV_PY, [VENV_PY, os.path.abspath(__file__), *sys.argv[1:]])
        sys.exit('Missing dependencies. Run:\n'
                 f'  python3 -m venv {TOOLS}/.venv && {TOOLS}/.venv/bin/pip install -r {TOOLS}/requirements.txt\n'
                 'then re-run this script (see Design/README.md).')


_ensure_deps()
sys.path.insert(0, TOOLS)

import assets      # noqa: E402
import brand as B  # noqa: E402
import guide       # noqa: E402
import render      # noqa: E402
import swift       # noqa: E402


def pdf_signature(data):
    """What a PDF draws: its content streams and page size. Chromium stamps a creation date and a
    user-agent string into every PDF, so byte equality is meaningless between runs."""
    streams = re.findall(rb'stream\r?\n(.*?)\r?\nendstream', data, re.S)
    return streams, re.findall(rb'/MediaBox\s*\[[^\]]*\]', data)


def main():
    print('svg    ', len(B.write_svgs()), 'files')

    jobs = B.jobs()
    for j in jobs:
        os.makedirs(os.path.dirname(j['out']), exist_ok=True)
    pdf_jobs = [dict(j, out=None) if j.get('pdf') else j for j in jobs]
    results = render.render_many(pdf_jobs)
    kept = 0
    for j, data in zip(jobs, results):
        if not j.get('pdf'):
            continue
        if os.path.isfile(j['out']):
            with open(j['out'], 'rb') as fh:
                if pdf_signature(fh.read()) == pdf_signature(data):
                    kept += 1
                    continue
        with open(j['out'], 'wb') as fh:
            fh.write(data)
    print('render ', len(jobs), 'files (png written;', len([j for j in jobs if j.get('pdf')]), 'pdf,', kept, 'unchanged and kept)')

    swift.write()
    print('swift  ', os.path.relpath(B.OUT_SWIFT, B.REPO))
    assets.write()
    print('assets ', os.path.relpath(assets.X, B.REPO))
    html = guide.write()
    print('guide  ', f'{len(html) / 1024:.0f}KB')


if __name__ == '__main__':
    main()
