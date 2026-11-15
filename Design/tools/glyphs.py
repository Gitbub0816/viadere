"""Outline the Outfit glyphs used by the wordmark (fontTools).

Reads the bundled Outfit TTFs (App/Resources/Fonts, SIL OFL 1.1) and returns, per weight,
{'upm', 'xHeight', 'capHeight', 'ascender', 'descender', 'glyphs': {char: {'d', 'adv', 'bounds'}}}
with y flipped for SVG. Only weights 300 (Light) and 600 (SemiBold) are used by the artwork.
"""
import os
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.pens.boundsPen import BoundsPen

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
FONT_FILES = {300: 'Outfit-Light.ttf', 400: 'Outfit-Regular.ttf', 600: 'Outfit-SemiBold.ttf'}
CHARS = 'viadereVIADERatrustedwyocn .'


def load(weights=(300, 600)):
    out = {}
    for w in weights:
        f = TTFont(os.path.join(REPO, 'App', 'Resources', 'Fonts', FONT_FILES[w]))
        gs = f.getGlyphSet()
        cmap = f.getBestCmap()
        upm = f['head'].unitsPerEm
        hhea, os2 = f['hhea'], f['OS/2']
        d = {'upm': upm, 'xHeight': os2.sxHeight, 'capHeight': os2.sCapHeight,
             'ascender': hhea.ascent, 'descender': hhea.descent, 'glyphs': {}}
        for ch in CHARS:
            g = cmap.get(ord(ch))
            if not g:
                continue
            pen = SVGPathPen(gs)
            tp = TransformPen(pen, (1, 0, 0, -1, 0, 0))   # flip y for SVG
            gs[g].draw(tp)
            bp = BoundsPen(gs)
            gs[g].draw(bp)
            d['glyphs'][ch] = {'d': pen.getCommands(), 'adv': gs[g].width, 'bounds': bp.bounds}
        out[w] = d
    return out
