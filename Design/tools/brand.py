"""Every Viadere brand deliverable (SVGs + raster/PDF jobs) from the single geometry source
(geom.py + final.json). Port of the library half of build.js."""
import json
import math
import os
import re

import geom as G
import glyphs as _glyphs
from mark import markGroup, THEMES  # noqa: F401  (THEMES re-exported for swift.py / guide.py)

TOOLS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(TOOLS, '..', '..'))
DESIGN = os.path.join(REPO, 'Design')
APP_RESOURCES = os.path.join(REPO, 'App', 'Resources')

f2 = G.f
js_str = G.js_str


def D(*p): return os.path.join(DESIGN, *p)
def A(*p): return os.path.join(APP_RESOURCES, *p)


def write(path, s):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='') as fh:
        fh.write(s)


def read(path):
    with open(path, encoding='utf-8', newline='') as fh:
        return fh.read()


with open(os.path.join(TOOLS, 'final.json'), encoding='utf-8') as _fh:
    params = json.load(_fh)

# ---------- palette ----------
PAL = {
    'charcoal': '#1F1E1C', 'graphite': '#4A4844', 'silver': '#C9C4BB', 'ivory': '#F5F2EC', 'champagne': '#C2AE8E',
    'champagneDeep': '#8C7550', 'black': '#121211',
}
WORD = {
    'light': {'via': '#1F1E1C', 'dere': '#3E3C39'},
    'dark': {'via': '#F3EFE8', 'dere': '#B9B2A7'},
}

# ---------- outlined Outfit glyphs ----------
glyphs = _glyphs.load()
glyphs['ascD'] = max(glyphs[300]['glyphs']['d']['bounds'][3], glyphs[600]['glyphs']['i']['bounds'][3])   # 'd' ascender / 'i' dot
glyphs['overshoot'] = -min(glyphs[300]['glyphs'][c]['bounds'][1] for c in ('a', 'e', 'r', 'v'))


# ---------- mark ----------
def mark(theme, id, mono=None):
    return markGroup(mono=mono, id=id, params=params) if mono else markGroup(theme=theme, id=id, params=params)


M0 = mark('primary', 'x')
MW, MH, RT = M0['W'], M0['H'], M0['g']['ribbonTop']      # mark viewBox, ribbon top (dot space)


def svgWrap(w, h, inner, defs='', title='Viadere'):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {f2(w)} {f2(h)}" width="{f2(w)}" height="{f2(h)}" '
            f'role="img" aria-label="{title}">\n<title>{title}</title>\n<defs>{defs}</defs>\n{inner}\n</svg>\n')


def markFile(m):
    return svgWrap(m['W'], m['H'], m['body'].replace('><', '>\n<'), m['defs'].replace('><', '>\n<'))


# ---------- wordmark (Outfit, outlined) ----------
def wordmark(size, colors, wVia=None, wDere=None, track=None):
    """Returns {body, width, xHeight, ascent} at a font size where 1 unit = size/1000."""
    parts = [('via', wVia or 600, colors['via']), ('dere', wDere or 300, colors['dere'])]
    s = size / 1000
    track = -8 if track is None else track
    x = 0
    body = ''
    for txt, w, col in parts:
        gl = glyphs[w]['glyphs']
        g = ''
        for ch in txt:
            g += f'<path transform="translate({f2(x)} 0) scale({js_str(s)})" d="{gl[ch]["d"]}"/>'
            x += (gl[ch]['adv'] + track) * s
        body += f'<g fill="{col}">{g}</g>'
    x -= track * s
    return {'body': body, 'width': x, 'xHeight': glyphs[600]['xHeight'] * s, 'ascent': 0.74 * size}


def wordmarkSVG(theme):
    size = 100
    wm = wordmark(size, WORD[theme])
    asc = glyphs['ascD'] * size / 1000
    os_ = glyphs['overshoot'] * size / 1000
    return svgWrap(wm['width'], asc + os_, f'<g transform="translate(0 {f2(asc)})">{wm["body"]}</g>', '', 'viadere')


# Lockups carry built-in clear space: P = one dot diameter on every side.
CLEAR = 2 * params['dotR']
# Horizontal lockup: x-height = 0.66 x ribbon height (ribbon reads heavier than the type, as in the reference);
# baseline 0.1h above ribbon bottom; gap 0.26h.
LOCKUP = {'xh': 0.66, 'gap': 0.26, 'base': 0.10, 'stackedWidth': 1.24, 'stackedGap': 0.58}


def lockupH(theme, markTheme, id):
    m = mark(markTheme, id)
    rh = 100
    size = LOCKUP['xh'] * rh / (glyphs[600]['xHeight'] / 1000)
    wm = wordmark(size, WORD[theme])
    gap = LOCKUP['gap'] * rh
    baseline = RT + rh - LOCKUP['base'] * rh
    asc = glyphs['ascD'] * size / 1000
    top = min(0, baseline - asc)
    bottom = max(m['H'], baseline + glyphs['overshoot'] * size / 1000)
    P = CLEAR
    W = m['W'] + gap + wm['width'] + 2 * P
    H = bottom - top + 2 * P
    inner = (f'<g transform="translate({f2(P)} {f2(P - top)})">{m["body"]}'
             f'<g transform="translate({f2(m["W"] + gap)} {f2(baseline)})">{wm["body"]}</g></g>')
    return {'svg': svgWrap(W, H, inner, m['defs']), 'W': W, 'H': H}


def lockupS(theme, markTheme, id):
    """Stacked lockup: wordmark width = 1.24 x ribbon width; gap ribbon-bottom -> ascender = 0.58h."""
    m = mark(markTheme, id)
    target = m['W'] * LOCKUP['stackedWidth']
    w1 = wordmark(100, WORD[theme])
    size = 100 * target / w1['width']
    wm = wordmark(size, WORD[theme])
    asc = glyphs['ascD'] * size / 1000
    P = CLEAR
    IW = max(m['W'], wm['width'])
    mx = (IW - m['W']) / 2
    wx = (IW - wm['width']) / 2
    baseline = m['H'] + LOCKUP['stackedGap'] * 100 + asc
    H = baseline + glyphs['overshoot'] * size / 1000 + 2 * P
    W = IW + 2 * P
    inner = (f'<g transform="translate({f2(P)} {f2(P)})"><g transform="translate({f2(mx)} 0)">{m["body"]}</g>'
             f'<g transform="translate({f2(wx)} {f2(baseline)})">{wm["body"]}</g></g>')
    return {'svg': svgWrap(W, H, inner, m['defs']), 'W': W, 'H': H}


# ---------- app icons (1024, full-bleed; iOS applies the mask) ----------
def icon(kind):
    S = 1024
    ribbonW = 0.76 * S                       # mark ribbon width ~ 76% of the canvas
    sc = ribbonW / MW
    mh = MH * sc
    x0 = (S - ribbonW) / 2
    y0 = (S - mh) / 2 - 6                    # optical centre: bbox centred, nudged up 6px
    defs = ''
    if kind == 'light':
        m = mark('primary', 'il')
        defs += '<linearGradient id="bgl" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#FAF8F4"/><stop offset="1" stop-color="#ECE8E0"/></linearGradient>'
        defs += '<filter id="sh" x="-10%" y="-10%" width="120%" height="140%"><feDropShadow dx="0" dy="6" stdDeviation="9" flood-color="#3A3226" flood-opacity="0.16"/></filter>'
        bg = f'<rect width="{S}" height="{S}" fill="url(#bgl)"/>'
    elif kind == 'dark':
        m = mark('dark', 'id')
        defs += '<linearGradient id="bgd" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2C2B29"/><stop offset="1" stop-color="#121211"/></linearGradient>'
        defs += '<radialGradient id="bgg" cx="0.5" cy="0.18" r="0.75"><stop offset="0" stop-color="#FFFFFF" stop-opacity="0.07"/><stop offset="1" stop-color="#FFFFFF" stop-opacity="0"/></radialGradient>'
        defs += '<filter id="sh" x="-10%" y="-10%" width="120%" height="140%"><feDropShadow dx="0" dy="8" stdDeviation="10" flood-color="#000" flood-opacity="0.45"/></filter>'
        bg = f'<rect width="{S}" height="{S}" fill="url(#bgd)"/><rect width="{S}" height="{S}" fill="url(#bgg)"/>'
    else:  # tinted: grayscale on black; iOS applies the user's tint
        m = markGroup(mono='#FFFFFF', id='it', params=params, monoBack=0.55)
        bg = f'<rect width="{S}" height="{S}" fill="#000"/>'
    filt = '' if kind == 'tinted' else ' filter="url(#sh)"'
    inner = f'{bg}<g{filt} transform="translate({f2(x0)} {f2(y0)}) scale({sc:.5f})">{m["body"]}</g>'
    return svgWrap(S, S, inner, defs + m['defs'], 'Viadere app icon')


# ---------- SVG files ----------
def svg_files():
    files = {}
    files['viadere-mark.svg'] = markFile(mark('primary', 'vm'))
    files['viadere-mark-on-dark.svg'] = markFile(mark('dark', 'vd'))
    files['viadere-mark-mono-dark.svg'] = markFile(markGroup(mono=PAL['charcoal'], id='mmd', params=params))
    files['viadere-mark-mono-light.svg'] = markFile(markGroup(mono=PAL['ivory'], id='mml', params=params))
    files['viadere-wordmark.svg'] = wordmarkSVG('light')
    files['viadere-wordmark-on-dark.svg'] = wordmarkSVG('dark')
    LH, LHD = lockupH('light', 'primary', 'lh'), lockupH('dark', 'dark', 'lhd')
    LS, LSD = lockupS('light', 'primary', 'ls'), lockupS('dark', 'dark', 'lsd')
    files['viadere-lockup-horizontal.svg'] = LH['svg']
    files['viadere-lockup-horizontal-on-dark.svg'] = LHD['svg']
    files['viadere-lockup-stacked.svg'] = LS['svg']
    files['viadere-lockup-stacked-on-dark.svg'] = LSD['svg']
    files['app-icon-light.svg'] = icon('light')
    files['app-icon-dark.svg'] = icon('dark')
    files['app-icon-tinted.svg'] = icon('tinted')
    return files


def write_svgs():
    files = svg_files()
    for n, s in files.items():
        write(D('svg', n), s)
    return files


# ---------- raster / PDF jobs ----------
def page(svg, bg, w, h):
    return (f'<!doctype html><html><head><style>@page{{margin:0;size:{js_str(w)}px {js_str(h)}px}}'
            f'html,body{{margin:0;padding:0;background:{bg};}}svg{{display:block;width:{js_str(w)}px;height:{js_str(h)}px}}'
            f'</style></head><body>{svg}</body></html>')


def svgOf(n): return read(D('svg', n))


def ratio(n):
    m = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svgOf(n))
    return float(m.group(1)), float(m.group(2))


def jobs():
    out = []
    for n in ('app-icon-light', 'app-icon-dark', 'app-icon-tinted'):
        out.append({'html': page(svgOf(n + '.svg'), '#000', 1024, 1024), 'out': D('png', n + '-1024.png'), 'w': 1024, 'h': 1024})
    for n in ('viadere-mark', 'viadere-mark-on-dark', 'viadere-mark-mono-dark', 'viadere-mark-mono-light',
              'viadere-lockup-horizontal', 'viadere-lockup-horizontal-on-dark', 'viadere-lockup-stacked', 'viadere-lockup-stacked-on-dark'):
        w, h = ratio(n + '.svg')
        W = 1024
        H = int(G.js_round(W * h / w))
        out.append({'html': page(svgOf(n + '.svg'), 'transparent', W, H), 'out': D('png', n + '@1024w.png'), 'w': W, 'h': H, 'transparent': True})
    # vector PDFs for the asset catalog (Chromium keeps paths + gradients as vectors)
    for n, wpt in (('viadere-mark', 120), ('viadere-mark-on-dark', 120), ('viadere-mark-mono-dark', 120), ('viadere-mark-mono-light', 120),
                   ('viadere-wordmark', 160), ('viadere-wordmark-on-dark', 160), ('viadere-lockup-horizontal', 240), ('viadere-lockup-horizontal-on-dark', 240)):
        w, h = ratio(n + '.svg')
        W = wpt / 0.75
        H = W * h / w                       # CSS px; PDF pt = px x 0.75
        Wr, Hr = float(f'{W:.2f}'), float(f'{H:.2f}')
        out.append({'html': page(svgOf(n + '.svg'), 'transparent', Wr, Hr), 'out': D('pdf', n + '.pdf'),
                    'w': math.ceil(W), 'h': math.ceil(H), 'pdf': True, 'pw': f'{W:.2f}px', 'ph': f'{H:.2f}px'})
    return out

# generated Swift path data lives in the app target (source of truth for the SwiftUI mark)
OUT_SWIFT = os.path.join(REPO, 'App', 'Shared', 'DesignSystem', 'ViadereMark.swift')
