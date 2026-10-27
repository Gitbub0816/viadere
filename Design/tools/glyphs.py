import json, sys
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.pens.boundsPen import BoundsPen
base = sys.argv[1]
out = {}
for w in [200, 300, 400, 500, 600, 700]:
    f = TTFont(f"{base}/outfit-latin-{w}-normal.woff")
    gs = f.getGlyphSet(); cmap = f.getBestCmap(); upm = f['head'].unitsPerEm
    hhea = f['hhea']; os2 = f['OS/2']
    d = {'upm': upm, 'xHeight': os2.sxHeight, 'capHeight': os2.sCapHeight, 'ascender': hhea.ascent, 'descender': hhea.descent, 'glyphs': {}}
    for ch in 'viadereVIADERatrustedwyocn .':
        g = cmap.get(ord(ch))
        if not g: continue
        pen = SVGPathPen(gs)
        tp = TransformPen(pen, (1, 0, 0, -1, 0, 0))   # flip y for SVG
        gs[g].draw(tp)
        bp = BoundsPen(gs); gs[g].draw(bp)
        d['glyphs'][ch] = {'d': pen.getCommands(), 'adv': gs[g].width, 'bounds': bp.bounds}
    out[w] = d
json.dump(out, open(sys.argv[2], 'w'))
print({w: (out[w]['upm'], out[w]['xHeight']) for w in out})
