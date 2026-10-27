// Viadere mark geometry (v2).
// The ribbon silhouette is a constant-width band following a zig-zag centreline
// V0..V5 (start-crest, trough, crest(i), trough, crest(a), end-trough):
//  - outer corners (crest tops, trough bottoms) are rounded with a cubic,
//  - inner corners are sharp notches (intersection of the offset edges),
//  - both ends come to a point (left tip top-left, right tip bottom-right).
// Front faces are the "\" strokes (each wraps its crest and trough). The "/" strokes
// show the back face; they are separated from the fronts by "twist edges": cubic
// curves running across the band from each notch to the opposite outer edge.
// Every outline is made of cubic Béziers (straight edges are degree-raised lines).
// Output is normalised: ribbon spans y = dotSpace .. dotSpace+100, x from 0.

const P = {
  V: [[14, 22], [80, 78], [140, 22], [186, 78], [244, 22], [306, 78]],
  h: 17.5,                 // half width of the band (perpendicular)
  cornerTop: 1.0,          // tangent length factor for rounded crests (x h)
  cornerBot: 1.0,          // ... for rounded troughs
  cornerEnd: 1.0,          // ... for the end caps
  kappa: 0.62,             // corner roundness (0.552 ~ circle)
  twistA: 0.45, twistB: 0.45, twistAngle: 10, twistArrive: 60, tauA: 0.35, tauB: 0.65,
  dotR: 19, dotGap: 6, dotDX: 0,
  H: 100,
};

const add = (a, b) => [a[0] + b[0], a[1] + b[1]];
const sub = (a, b) => [a[0] - b[0], a[1] - b[1]];
const mul = (a, s) => [a[0] * s, a[1] * s];
const len = (a) => Math.hypot(a[0], a[1]);
const nrm = (a) => mul(a, 1 / len(a));
const rot = (a, deg) => { const r = deg * Math.PI / 180, c = Math.cos(r), s = Math.sin(r); return [a[0] * c - a[1] * s, a[0] * s + a[1] * c]; };
function isect(p, u, q, v) { const d = u[0] * v[1] - u[1] * v[0]; const s = ((q[0] - p[0]) * v[1] - (q[1] - p[1]) * v[0]) / d; return add(p, mul(u, s)); }
const line = (a, b) => [a, add(a, mul(sub(b, a), 1 / 3)), add(a, mul(sub(b, a), 2 / 3)), b];
const rev = (c) => [c[3], c[2], c[1], c[0]];
const corner = (a, C, b, k) => [a, add(a, mul(sub(C, a), k)), add(b, mul(sub(C, b), k)), b];

function raw(p) {
  // band half-width is given horizontally (hw): every stroke is the centreline shifted ±hw in x,
  // so the perpendicular half-width per stroke is hw * |sin(angle)|.
  const V = p.V, U = [], N = [], HS = [];
  for (let i = 0; i < 5; i++) { const u = nrm(sub(V[i + 1], V[i])); U.push(u); N.push([u[1], -u[0]]); HS.push(p.hw * Math.abs(u[1])); }
  const h = p.hw * 0.8;
  const topL = (i) => [add(V[i], mul(N[i], HS[i])), U[i]];
  const botL = (i) => [add(V[i], mul(N[i], -HS[i])), U[i]];
  const X = (l1, l2) => isect(l1[0], l1[1], l2[0], l2[1]);
  const R = {}, Nt = {}, Nb = {};
  for (const i of [1, 2, 3, 4]) {
    const top = i % 2 === 0;           // crest: outer corner on top
    const L = top ? [topL(i - 1), topL(i)] : [botL(i - 1), botL(i)];
    const C = X(L[0], L[1]);
    const t = h * (top ? p.cornerTop : p.cornerBot);
    const a = sub(C, mul(U[i - 1], t)), b = add(C, mul(U[i], t));
    R[i] = { a, b, C, c: corner(a, C, b, p.kappa) };
    if (top) Nb[i] = X(botL(i - 1), botL(i)); else Nt[i] = X(topL(i - 1), topL(i));
  }
  // Ends: left tip on bottom line of seg0 at the crest height; top runs flat then rounds down.
  const ext = (c, k, fn) => { let v = fn === 'min' ? 1e9 : -1e9; for (let i = 0; i <= 50; i++) { const t = i / 50, u = 1 - t; const y = u*u*u*c[0][k] + 3*u*u*t*c[1][k] + 3*u*t*t*c[2][k] + t*t*t*c[3][k]; v = fn === 'min' ? Math.min(v, y) : Math.max(v, y); } return v; };
  const yTop = Math.min(ext(R[2].c, 1, 'min'), ext(R[4].c, 1, 'min')) + (p.startDrop || 0);
  const S = isect([0, yTop], [1, 0], botL(0)[0], U[0]);
  const CS = isect([0, yTop], [1, 0], topL(0)[0], U[0]);
  const sB = add(CS, mul(U[0], h * p.cornerEnd));
  const startCap = corner(S, CS, sB, p.kappa);
  startCap[1] = add(S, mul(sub(CS, S), p.capFlat || 0.6));
  const yBot = Math.max(ext(R[1].c, 1, 'max'), ext(R[3].c, 1, 'max')) - (p.endLift || 0);
  const E = isect([0, yBot], [1, 0], topL(4)[0], U[4]);
  const CE = isect([0, yBot], [1, 0], botL(4)[0], U[4]);
  const eA = sub(CE, mul(U[4], h * (p.cornerEndR != null ? p.cornerEndR : p.cornerEnd)));
  const endCap = corner(E, CE, eA, p.kappa);       // E -> eA along the bottom
  endCap[1] = add(E, mul(sub(CE, E), p.capFlat || 0.6));
  // Twist edges. Each twist endpoint lies on a rounded corner at parameter tau; the corner
  // is split there so the front and back pieces share exact edges.
  const splitC = (c, t) => {
    const l = (a, b) => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t];
    const a = l(c[0], c[1]), b = l(c[1], c[2]), cc = l(c[2], c[3]), d = l(a, b), e = l(b, cc), f = l(d, e);
    return [[c[0], a, d, f], [f, e, cc, c[3]]];
  };
  const tang = (c) => nrm(sub(c[3], c[2]));   // end tangent of a cubic
  const tw = (from, dFrom, to, dTo, a, b) => { const d = len(sub(to, from)); return [from, add(from, mul(dFrom, d * a)), sub(to, mul(dTo, d * b)), to]; };
  const T = {};
  // Trough k: B on the trough's rounded bottom (tauB in 0..1) or further up the "/" bottom edge (tauB > 1).
  // Crest k:  A on the crest's rounded top (tauA in 0..1) or further down the "/" top edge (tauA < 0).
  for (const k of [1, 3]) {
    let c0, c1, B, tB, ext = null;
    if (p.tauB <= 1) { [c0, c1] = splitC(R[k].c, p.tauB); B = c0[3]; tB = tang(c0); }
    else { B = add(R[k].b, mul(U[k], (p.tauB - 1) * p.hw)); c0 = R[k].c; c1 = null; tB = U[k]; ext = line(R[k].b, B); }
    const dFrom = nrm(rot(U[k - 1], p.twistAngle));
    const dTo = nrm(rot(tB, p.twistArrive));
    const tail = ext ? [c0, ext] : [c0];                       // outline from R.a to B (front side)
    const rest = ext ? [line(B, Nb[k + 1])] : [c1, line(R[k].b, Nb[k + 1])];   // outline from B to the next notch (lens side)
    T[k] = { P: B, tail, rest, c: tw(Nt[k], dFrom, B, dTo, p.twistA, p.twistB) };
  }
  for (const k of [2, 4]) {
    let c0, c1, A, tA, ext = null;
    if (p.tauA >= 0) { [c0, c1] = splitC(R[k].c, p.tauA); A = c0[3]; tA = tang(c0); }
    else { A = sub(R[k].a, mul(U[k - 1], -p.tauA * p.hw)); c1 = R[k].c; c0 = null; tA = U[k - 1]; ext = line(A, R[k].a); }
    const dFrom = nrm(rot(tA, p.twistArrive));
    const dTo = nrm(rot(U[k], p.twistAngle));
    const head = ext ? [ext, c1] : [c1];                       // outline from A over the crest to R.b (front side)
    const lensTop = ext ? [line(Nt[k - 1], A)] : [line(Nt[k - 1], R[k].a), c0];   // outline from notch to A (lens side)
    T[k] = { P: A, head, lensTop, c: tw(A, dFrom, Nb[k], dTo, p.twistB, p.twistA) };
  }
  const sil = [
    startCap, line(sB, Nt[1]), line(Nt[1], R[2].a), R[2].c, line(R[2].b, Nt[3]), line(Nt[3], R[4].a), R[4].c, line(R[4].b, E),
    endCap, line(eA, Nb[4]), line(Nb[4], R[3].b), rev(R[3].c), line(R[3].a, Nb[2]), line(Nb[2], R[1].b), rev(R[1].c), line(R[1].a, S),
  ];
  const revAll = (segs) => segs.slice().reverse().map(rev);
  const front = [
    [startCap, line(sB, Nt[1]), T[1].c, ...revAll(T[1].tail), line(R[1].a, S)],
    [...T[2].head, line(R[2].b, Nt[3]), T[3].c, ...revAll(T[3].tail), line(R[3].a, Nb[2]), rev(T[2].c)],
    [...T[4].head, line(R[4].b, E), endCap, line(eA, Nb[4]), rev(T[4].c)],
  ];
  const back = [
    [T[1].c, ...T[1].rest, rev(T[2].c), ...revAll(T[2].lensTop)],
    [T[3].c, ...T[3].rest, rev(T[4].c), ...revAll(T[4].lensTop)],
  ];
  const lensAxis = [[Nt[1], T[2].P], [Nt[3], T[4].P]];
  const yMin = Math.min(yTop, ext(R[2].c, 1, 'min'), ext(R[4].c, 1, 'min')), yMax = Math.max(yBot, ext(R[1].c, 1, 'max'), ext(R[3].c, 1, 'max'));
  return { sil, front, back, lensAxis, crest1: R[2], yTop: yMin, yBot: yMax, S, E };
}

function build(p0 = {}) {
  const p = Object.assign({}, P, p0);
  const r = raw(p);
  // normalise: ribbon height -> H; place below dot space
  const minX = r.S[0], maxX = r.E[0];
  const minY = r.yTop, maxY = r.yBot;          // caps sit exactly on these lines
  const s = p.H / (maxY - minY);
  const dotSpace = p.dotR * 2 + p.dotGap;
  const tf = (q) => [(q[0] - minX) * s, (q[1] - minY) * s + dotSpace];
  const T = (path) => path.map(c => c.map(tf));
  const W = (maxX - minX) * s;
  const c1 = tf(r.crest1.C);
  const dot = { cx: c1[0] + p.dotDX, cy: p.dotR, r: p.dotR };
  return { p, W, H: p.H + dotSpace, ribbonTop: dotSpace, sil: T(r.sil), front: r.front.map(T), back: r.back.map(T), lensAxis: r.lensAxis.map(a => a.map(tf)), dot };
}

const f = (n) => { const v = Math.round(n * 100) / 100; return (Object.is(v, -0) ? 0 : v).toString(); };
const pt = (q) => `${f(q[0])} ${f(q[1])}`;
function pathD(segs) {
  let d = `M${pt(segs[0][0])}`;
  for (const c of segs) {
    const isLine = Math.abs((c[1][0] - c[0][0]) * 3 - (c[3][0] - c[0][0])) < 1e-6 && Math.abs((c[2][1] - c[0][1]) * 3 - 2 * (c[3][1] - c[0][1])) < 1e-6;
    d += isLine ? `L${pt(c[3])}` : `C${pt(c[1])} ${pt(c[2])} ${pt(c[3])}`;
  }
  return d + 'Z';
}
module.exports = { P, build, pathD, f, pt };
