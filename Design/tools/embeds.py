#!/usr/bin/env python3
"""Generate the "Verify with Viadere" embed kit: Design/embeds/ (Python only; fontTools + Playwright, no Node.js).

    python3 Design/tools/embeds.py        (re-runs itself inside Design/tools/.venv when needed, like build.py)

Writes:
  Design/embeds/svg/viadere-mark*.svg, viadere-wordmark*.svg      copies of the brand artwork (Design/svg, the single Bézier source)
  Design/embeds/svg/verify-{variant}-{theme}-{size}.svg           button artwork, label outlined in Outfit SemiBold (no font needed)
  Design/embeds/svg/verify-icon-{variant}-{theme}-{size}.svg      icon-only buttons
  Design/embeds/png/*@2x.png, *@3x.png                            renders of the buttons (transparent outside the capsule)

Geometry and colours are the ones the live buttons use (Server/Public/verify-button/v1/viadere-verify.css, the iOS SDK's
VerifyButtonColors and the Android VerifyColors): height 36/44/52, font 13/15/17, mark 2 em, gap 0.55 em, side padding 0.45 × height.
"""
import os
import re
import shutil
import sys

TOOLS = os.path.dirname(os.path.abspath(__file__))
VENV_PY = os.path.join(TOOLS, '.venv', 'bin', 'python')

try:
    from fontTools.ttLib import TTFont  # noqa: F401
    import playwright  # noqa: F401
except ImportError:
    if os.path.isfile(VENV_PY) and os.path.realpath(sys.prefix) != os.path.realpath(os.path.join(TOOLS, '.venv')):
        os.execv(VENV_PY, [VENV_PY, os.path.abspath(__file__), *sys.argv[1:]])
    sys.exit('Missing dependencies: see Design/README.md (Design/tools/.venv).')

from fontTools.pens.svgPathPen import SVGPathPen  # noqa: E402
from fontTools.pens.transformPen import TransformPen  # noqa: E402
from fontTools.ttLib import TTFont  # noqa: E402

sys.path.insert(0, TOOLS)
import render  # noqa: E402

REPO = os.path.abspath(os.path.join(TOOLS, '..', '..'))
OUT = os.path.join(REPO, 'Design', 'embeds')
LABEL = 'Verify with Viadere'

SIZES = {'sm': (36, 13), 'md': (44, 15), 'lg': (52, 17)}
CHARCOAL, IVORY, IVORY_DARK, SILVER = '#1F1E1C', '#F5F2EC', '#F3F0EA', '#C9C4BB'
# variant/theme -> (background or None, foreground, border)
VARIANTS = {
    ('filled', 'light'): (CHARCOAL, IVORY, CHARCOAL),
    ('filled', 'dark'): (IVORY_DARK, CHARCOAL, IVORY_DARK),
    ('ivory', 'light'): (IVORY, CHARCOAL, SILVER),
    ('ivory', 'dark'): (IVORY, CHARCOAL, SILVER),
    ('outline', 'light'): (None, CHARCOAL, CHARCOAL),
    ('outline', 'dark'): (None, IVORY_DARK, IVORY_DARK),
}
MARK_W, MARK_H = 321.71, 146.0


def mark_paths():
    svg = open(os.path.join(REPO, 'Design', 'svg', 'viadere-mark-mono-dark.svg')).read()
    paths = re.findall(r'd="([^"]+)"', svg)
    assert len(paths) == 4, paths
    return paths[0], paths[1:]


def label_glyphs():
    font = TTFont(os.path.join(REPO, 'App', 'Resources', 'Fonts', 'Outfit-SemiBold.ttf'))
    gs, cmap = font.getGlyphSet(), font.getBestCmap()
    upm = font['head'].unitsPerEm
    kern = {}
    if 'kern' in font:
        for table in font['kern'].kernTables:
            kern.update(table.kernTable)
    out = []
    for ch in LABEL:
        name = cmap[ord(ch)]
        pen = SVGPathPen(gs)
        gs[name].draw(TransformPen(pen, (1, 0, 0, -1, 0, 0)))
        out.append((name, pen.getCommands(), gs[name].width))
    return out, upm, kern, font['OS/2'].sCapHeight


def fmt(v):
    return ('%.2f' % v).rstrip('0').rstrip('.')


def button_svg(variant, theme, size, icon_only):
    height, font_px = SIZES[size]
    bg, fg, border = VARIANTS[(variant, theme)]
    back, fronts = mark_paths()
    mark_w = font_px * (1.75 if icon_only else 2.0)
    mark_scale = mark_w / MARK_W
    mark_h = MARK_H * mark_scale
    gap = font_px * 0.55
    pad = 0 if icon_only else height * 0.45
    glyphs, upm, kern, cap = label_glyphs()
    s = font_px / upm
    tracking = -0.005 * font_px
    text_w = 0.0
    if not icon_only:
        for i, (name, _, adv) in enumerate(glyphs):
            text_w += adv * s + (tracking if i < len(glyphs) - 1 else 0)
            if i + 1 < len(glyphs):
                text_w += kern.get((name, glyphs[i + 1][0]), 0) * s
    width = height if icon_only else pad * 2 + mark_w + gap + text_w
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {fmt(width)} {fmt(height)}" width="{fmt(width)}" height="{fmt(height)}" '
             f'role="img" aria-label="{LABEL}"><title>{LABEL}</title>']
    r = height / 2
    parts.append(f'<rect x="0.5" y="0.5" width="{fmt(width - 1)}" height="{fmt(height - 1)}" rx="{fmt(r - 0.5)}" '
                 f'fill="{bg or "none"}" stroke="{border}" stroke-width="1"/>')
    mx = (width - mark_w) / 2 if icon_only else pad
    my = (height - mark_h) / 2
    parts.append(f'<g transform="translate({fmt(mx)} {fmt(my)}) scale({mark_scale:.5f})" fill="{fg}">'
                 f'<path d="{back}" opacity="0.62"/>' + ''.join(f'<path d="{d}"/>' for d in fronts) +
                 '<circle cx="155.21" cy="20.5" r="20.5"/></g>')
    if not icon_only:
        x = pad + mark_w + gap
        baseline = height / 2 + cap * s / 2
        glyph_parts = []
        for i, (name, d, adv) in enumerate(glyphs):
            if d:
                glyph_parts.append(f'<path transform="translate({fmt(x)} {fmt(baseline)}) scale({s:.6f})" d="{d}"/>')
            x += adv * s + tracking
            if i + 1 < len(glyphs):
                x += kern.get((name, glyphs[i + 1][0]), 0) * s
        parts.append(f'<g fill="{fg}">' + ''.join(glyph_parts) + '</g>')
    parts.append('</svg>')
    return '\n'.join(parts) + '\n', width, height


def main():
    svg_dir, png_dir = os.path.join(OUT, 'svg'), os.path.join(OUT, 'png')
    os.makedirs(svg_dir, exist_ok=True)
    os.makedirs(png_dir, exist_ok=True)
    for name in ['viadere-mark.svg', 'viadere-mark-on-dark.svg', 'viadere-mark-mono-dark.svg', 'viadere-mark-mono-light.svg',
                 'viadere-wordmark.svg', 'viadere-wordmark-on-dark.svg', 'viadere-lockup-horizontal.svg', 'viadere-lockup-horizontal-on-dark.svg']:
        shutil.copyfile(os.path.join(REPO, 'Design', 'svg', name), os.path.join(svg_dir, name))
    jobs = []
    written = 0
    for (variant, theme) in VARIANTS:
        if variant == 'ivory' and theme == 'dark':
            continue  # the ivory button is the same on both; one file
        for size in SIZES:
            for icon_only in (False, True):
                name = f'verify-{"icon-" if icon_only else ""}{variant}{"" if variant == "ivory" else "-" + theme}-{size}'
                svg, w, h = button_svg(variant, theme, size, icon_only)
                with open(os.path.join(svg_dir, name + '.svg'), 'w') as fh:
                    fh.write(svg)
                written += 1
                for scale in (2, 3):
                    html = ('<!doctype html><html><head><style>html,body{margin:0;background:transparent}svg{display:block}</style></head><body>'
                            + svg + '</body></html>')
                    jobs.append({'html': html, 'out': os.path.join(png_dir, f'{name}@{scale}x.png'), 'w': int(w + 0.999), 'h': int(h),
                                 'scale': scale, 'transparent': True})
    render.render_many(jobs)
    print('embeds', written, 'button svgs,', len(jobs), 'pngs ->', os.path.relpath(OUT, REPO))


if __name__ == '__main__':
    main()
