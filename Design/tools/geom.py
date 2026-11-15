"""Viadere mark geometry (v2).

The ribbon silhouette is a constant-width band following a zig-zag centreline
V0..V5 (start-crest, trough, crest(i), trough, crest(a), end-trough):
 - outer corners (crest tops, trough bottoms) are rounded with a cubic,
 - inner corners are sharp notches (intersection of the offset edges),
 - both ends come to a point (left tip top-left, right tip bottom-right).
Front faces are the "\\" strokes (each wraps its crest and trough). The "/" strokes
show the back face; they are separated from the fronts by "twist edges": cubic
curves running across the band from each notch to the opposite outer edge.
Every outline is made of cubic Béziers (straight edges are degree-raised lines).
Output is normalised: ribbon spans y = dotSpace .. dotSpace+100, x from 0.

Ported 1:1 from the former geom.js; all arithmetic uses Python floats (IEEE
doubles, same as JavaScript numbers) and the same operation order.
"""
import math

P = {
    'V': [[14, 22], [80, 78], [140, 22], [186, 78], [244, 22], [306, 78]],
    'h': 17.5,           # half width of the band (perpendicular)
    'cornerTop': 1.0,    # tangent length factor for rounded crests (x h)
    'cornerBot': 1.0,    # ... for rounded troughs
    'cornerEnd': 1.0,    # ... for the end caps
    'kappa': 0.62,       # corner roundness (0.552 ~ circle)
    'twistA': 0.45, 'twistB': 0.45, 'twistAngle': 10, 'twistArrive': 60, 'tauA': 0.35, 'tauB': 0.65,
    'dotR': 19, 'dotGap': 6, 'dotDX': 0,
    'H': 100,
}


# ---------- JavaScript number semantics ----------
def js_round(x):
    """Math.round: round half toward +infinity."""
    r = math.floor(x)
    return float(r + 1 if x - r >= 0.5 else r)


def js_str(v):
    """Number.prototype.toString for the magnitudes used here."""
    if isinstance(v, int):
        return str(v)
    if v != v or v in (math.inf, -math.inf):
        return str(v)
    if v == int(v) and abs(v) < 1e21:
        return str(int(v))
    return repr(v)


def f(n):
    """Round to 2 decimals and print like JS (no trailing zeros, no -0)."""
    v = js_round(n * 100) / 100
    if v == 0:
        v = 0.0
    return js_str(v)


def pt(q):
    return f'{f(q[0])} {f(q[1])}'


# ---------- vector helpers ----------
def add(a, b): return [a[0] + b[0], a[1] + b[1]]
def sub(a, b): return [a[0] - b[0], a[1] - b[1]]
def mul(a, s): return [a[0] * s, a[1] * s]
def js_hypot(*xs):
    """Math.hypot as implemented by V8 (scale by max, Kahan-summed squares); math.hypot can differ by 1 ulp."""
    mx = max(abs(x) for x in xs)
    if mx == 0:
        return 0.0
    total = 0.0
    comp = 0.0
    for x in xs:
        n = abs(x) / mx
        summand = n * n - comp
        prelim = total + summand
        comp = (prelim - total) - summand
        total = prelim
    return math.sqrt(total) * mx


def length(a): return js_hypot(a[0], a[1])
def nrm(a): return mul(a, 1 / length(a))


def rot(a, deg):
    r = deg * math.pi / 180
    c, s = math.cos(r), math.sin(r)
    return [a[0] * c - a[1] * s, a[0] * s + a[1] * c]


def isect(p, u, q, v):
    d = u[0] * v[1] - u[1] * v[0]
    s = ((q[0] - p[0]) * v[1] - (q[1] - p[1]) * v[0]) / d
    return add(p, mul(u, s))


def line(a, b): return [a, add(a, mul(sub(b, a), 1 / 3)), add(a, mul(sub(b, a), 2 / 3)), b]
def rev(c): return [c[3], c[2], c[1], c[0]]
def corner(a, C, b, k): return [a, add(a, mul(sub(C, a), k)), add(b, mul(sub(C, b), k)), b]


def _or(v, default):
    """JS `v || default` for numbers (0 and undefined fall through)."""
    return v if v else default


def raw(p):
    # band half-width is given horizontally (hw): every stroke is the centreline shifted ±hw in x,
    # so the perpendicular half-width per stroke is hw * |sin(angle)|.
    V = p['V']
    U, N, HS = [], [], []
    for i in range(5):
        u = nrm(sub(V[i + 1], V[i]))
        U.append(u)
        N.append([u[1], -u[0]])
        HS.append(p['hw'] * abs(u[1]))
    h = p['hw'] * 0.8

    def topL(i): return [add(V[i], mul(N[i], HS[i])), U[i]]
    def botL(i): return [add(V[i], mul(N[i], -HS[i])), U[i]]
    def X(l1, l2): return isect(l1[0], l1[1], l2[0], l2[1])

    R, Nt, Nb = {}, {}, {}
    for i in (1, 2, 3, 4):
        top = i % 2 == 0                # crest: outer corner on top
        L = [topL(i - 1), topL(i)] if top else [botL(i - 1), botL(i)]
        C = X(L[0], L[1])
        t = h * (p['cornerTop'] if top else p['cornerBot'])
        a = sub(C, mul(U[i - 1], t))
        b = add(C, mul(U[i], t))
        R[i] = {'a': a, 'b': b, 'C': C, 'c': corner(a, C, b, p['kappa'])}
        if top:
            Nb[i] = X(botL(i - 1), botL(i))
        else:
            Nt[i] = X(topL(i - 1), topL(i))

    # Ends: left tip on bottom line of seg0 at the crest height; top runs flat then rounds down.
    def ext(c, k, fn):
        v = 1e9 if fn == 'min' else -1e9
        for i in range(51):
            t = i / 50
            u = 1 - t
            y = u * u * u * c[0][k] + 3 * u * u * t * c[1][k] + 3 * u * t * t * c[2][k] + t * t * t * c[3][k]
            v = min(v, y) if fn == 'min' else max(v, y)
        return v

    yTop = min(ext(R[2]['c'], 1, 'min'), ext(R[4]['c'], 1, 'min')) + _or(p.get('startDrop'), 0)
    S = isect([0, yTop], [1, 0], botL(0)[0], U[0])
    CS = isect([0, yTop], [1, 0], topL(0)[0], U[0])
    sB = add(CS, mul(U[0], h * p['cornerEnd']))
    startCap = corner(S, CS, sB, p['kappa'])
    startCap[1] = add(S, mul(sub(CS, S), _or(p.get('capFlat'), 0.6)))
    yBot = max(ext(R[1]['c'], 1, 'max'), ext(R[3]['c'], 1, 'max')) - _or(p.get('endLift'), 0)
    E = isect([0, yBot], [1, 0], topL(4)[0], U[4])
    CE = isect([0, yBot], [1, 0], botL(4)[0], U[4])
    cerR = p.get('cornerEndR')
    eA = sub(CE, mul(U[4], h * (cerR if cerR is not None else p['cornerEnd'])))
    endCap = corner(E, CE, eA, p['kappa'])       # E -> eA along the bottom
    endCap[1] = add(E, mul(sub(CE, E), _or(p.get('capFlat'), 0.6)))

    # Twist edges. Each twist endpoint lies on a rounded corner at parameter tau; the corner
    # is split there so the front and back pieces share exact edges.
    def splitC(c, t):
        def l(a, b): return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t]
        a = l(c[0], c[1]); b = l(c[1], c[2]); cc = l(c[2], c[3])
        d = l(a, b); e = l(b, cc); ff = l(d, e)
        return [[c[0], a, d, ff], [ff, e, cc, c[3]]]

    def tang(c): return nrm(sub(c[3], c[2]))     # end tangent of a cubic

    def tw(frm, dFrom, to, dTo, a, b):
        d = length(sub(to, frm))
        return [frm, add(frm, mul(dFrom, d * a)), sub(to, mul(dTo, d * b)), to]

    T = {}
    # Trough k: B on the trough's rounded bottom (tauB in 0..1) or further up the "/" bottom edge (tauB > 1).
    # Crest k:  A on the crest's rounded top (tauA in 0..1) or further down the "/" top edge (tauA < 0).
    for k in (1, 3):
        ex = None
        if p['tauB'] <= 1:
            c0, c1 = splitC(R[k]['c'], p['tauB'])
            B = c0[3]
            tB = tang(c0)
        else:
            B = add(R[k]['b'], mul(U[k], (p['tauB'] - 1) * p['hw']))
            c0 = R[k]['c']
            c1 = None
            tB = U[k]
            ex = line(R[k]['b'], B)
        dFrom = nrm(rot(U[k - 1], p['twistAngle']))
        dTo = nrm(rot(tB, p['twistArrive']))
        tail = [c0, ex] if ex else [c0]                  # outline from R.a to B (front side)
        rest = [line(B, Nb[k + 1])] if ex else [c1, line(R[k]['b'], Nb[k + 1])]   # B to the next notch (lens side)
        T[k] = {'P': B, 'tail': tail, 'rest': rest, 'c': tw(Nt[k], dFrom, B, dTo, p['twistA'], p['twistB'])}
    for k in (2, 4):
        ex = None
        if p['tauA'] >= 0:
            c0, c1 = splitC(R[k]['c'], p['tauA'])
            A = c0[3]
            tA = tang(c0)
        else:
            A = sub(R[k]['a'], mul(U[k - 1], -p['tauA'] * p['hw']))
            c1 = R[k]['c']
            c0 = None
            tA = U[k - 1]
            ex = line(A, R[k]['a'])
        dFrom = nrm(rot(tA, p['twistArrive']))
        dTo = nrm(rot(U[k], p['twistAngle']))
        head = [ex, c1] if ex else [c1]                  # outline from A over the crest to R.b (front side)
        lensTop = [line(Nt[k - 1], A)] if ex else [line(Nt[k - 1], R[k]['a']), c0]   # notch to A (lens side)
        T[k] = {'P': A, 'head': head, 'lensTop': lensTop, 'c': tw(A, dFrom, Nb[k], dTo, p['twistB'], p['twistA'])}

    sil = [
        startCap, line(sB, Nt[1]), line(Nt[1], R[2]['a']), R[2]['c'], line(R[2]['b'], Nt[3]), line(Nt[3], R[4]['a']), R[4]['c'], line(R[4]['b'], E),
        endCap, line(eA, Nb[4]), line(Nb[4], R[3]['b']), rev(R[3]['c']), line(R[3]['a'], Nb[2]), line(Nb[2], R[1]['b']), rev(R[1]['c']), line(R[1]['a'], S),
    ]

    def revAll(segs): return [rev(s) for s in reversed(segs)]

    front = [
        [startCap, line(sB, Nt[1]), T[1]['c'], *revAll(T[1]['tail']), line(R[1]['a'], S)],
        [*T[2]['head'], line(R[2]['b'], Nt[3]), T[3]['c'], *revAll(T[3]['tail']), line(R[3]['a'], Nb[2]), rev(T[2]['c'])],
        [*T[4]['head'], line(R[4]['b'], E), endCap, line(eA, Nb[4]), rev(T[4]['c'])],
    ]
    back = [
        [T[1]['c'], *T[1]['rest'], rev(T[2]['c']), *revAll(T[2]['lensTop'])],
        [T[3]['c'], *T[3]['rest'], rev(T[4]['c']), *revAll(T[4]['lensTop'])],
    ]
    lensAxis = [[Nt[1], T[2]['P']], [Nt[3], T[4]['P']]]
    yMin = min(yTop, ext(R[2]['c'], 1, 'min'), ext(R[4]['c'], 1, 'min'))
    yMax = max(yBot, ext(R[1]['c'], 1, 'max'), ext(R[3]['c'], 1, 'max'))
    return {'sil': sil, 'front': front, 'back': back, 'lensAxis': lensAxis, 'crest1': R[2], 'yTop': yMin, 'yBot': yMax, 'S': S, 'E': E}


def build(p0=None):
    p = dict(P)
    p.update(p0 or {})
    r = raw(p)
    # normalise: ribbon height -> H; place below dot space
    minX = r['S'][0]
    maxX = r['E'][0]
    minY = r['yTop']
    maxY = r['yBot']                        # caps sit exactly on these lines
    s = p['H'] / (maxY - minY)
    dotSpace = p['dotR'] * 2 + p['dotGap']

    def tf(q): return [(q[0] - minX) * s, (q[1] - minY) * s + dotSpace]
    def T(path): return [[tf(q) for q in c] for c in path]

    W = (maxX - minX) * s
    c1 = tf(r['crest1']['C'])
    dot = {'cx': c1[0] + p['dotDX'], 'cy': p['dotR'], 'r': p['dotR']}
    return {'p': p, 'W': W, 'H': p['H'] + dotSpace, 'ribbonTop': dotSpace, 'sil': T(r['sil']),
            'front': [T(x) for x in r['front']], 'back': [T(x) for x in r['back']],
            'lensAxis': [[tf(q) for q in a] for a in r['lensAxis']], 'dot': dot}


def pathD(segs):
    d = f'M{pt(segs[0][0])}'
    for c in segs:
        is_line = (abs((c[1][0] - c[0][0]) * 3 - (c[3][0] - c[0][0])) < 1e-6
                   and abs((c[2][1] - c[0][1]) * 3 - 2 * (c[3][1] - c[0][1])) < 1e-6)
        d += f'L{pt(c[3])}' if is_line else f'C{pt(c[1])} {pt(c[2])} {pt(c[3])}'
    return d + 'Z'
