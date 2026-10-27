// Builds every Viadere brand deliverable from the single geometry source (geom.js + final.json).
const fs = require('fs'), path = require('path');
const G = require('./geom'); const { markGroup, THEMES } = require('./mark'); const { renderMany } = require('./render');
const REPO = '/home/user/viadere';
const SCR = path.resolve(__dirname, '..');
const params = JSON.parse(fs.readFileSync(path.join(SCR, 'gen/final.json')));
const glyphs = JSON.parse(fs.readFileSync(path.join(SCR, 'glyphs.json')));
const D = (...p) => path.join(REPO, 'Design', ...p);
const A = (...p) => path.join(REPO, 'App/Resources', ...p);
for (const d of [D('svg'), D('png'), D('pdf'), D('swift'), A('Assets.xcassets'), A('Fonts')]) fs.mkdirSync(d, { recursive: true });
const write = (f, s) => { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, s); };
const f2 = G.f;

// ---------- palette ----------
const PAL = {
  charcoal: '#1F1E1C', graphite: '#4A4844', silver: '#C9C4BB', ivory: '#F5F2EC', champagne: '#C2AE8E',
  champagneDeep: '#8C7550', black: '#121211',
};
const WORD = {
  light: { via: '#1F1E1C', dere: '#3E3C39' },
  dark: { via: '#F3EFE8', dere: '#B9B2A7' },
};

// ---------- mark ----------
function mark(theme, id, mono) { return markGroup(mono ? { mono, id, params } : { theme, id, params }); }
const M0 = mark('primary', 'x');
const MW = M0.W, MH = M0.H, RT = M0.g.ribbonTop;      // mark viewBox, ribbon top (dot space)
const svgWrap = (w, h, inner, defs = '', title = 'Viadere') =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${f2(w)} ${f2(h)}" width="${f2(w)}" height="${f2(h)}" role="img" aria-label="${title}">\n<title>${title}</title>\n<defs>${defs}</defs>\n${inner}\n</svg>\n`;
const markFile = (m) => svgWrap(m.W, m.H, m.body.replace(/></g, '>\n<'), m.defs.replace(/></g, '>\n<'));

// ---------- wordmark (Outfit, outlined) ----------
// Returns {body, width, xHeight, ascent} at a font size where 1 unit = size/1000.
function wordmark(size, colors, opt = {}) {
  const parts = [['via', opt.wVia || 600, colors.via], ['dere', opt.wDere || 300, colors.dere]];
  const s = size / 1000, track = (opt.track != null ? opt.track : -8);
  let x = 0, body = '';
  for (const [txt, w, col] of parts) {
    const gl = glyphs[w].glyphs;
    let g = '';
    for (const ch of txt) {
      g += `<path transform="translate(${f2(x)} 0) scale(${s})" d="${gl[ch].d}"/>`;
      x += (gl[ch].adv + track) * s;
    }
    body += `<g fill="${col}">${g}</g>`;
  }
  x -= track * s;
  return { body, width: x, xHeight: glyphs[600].xHeight * s, ascent: 0.74 * size /* d ascender ≈ 740u */ };
}
// measure real ascender of 'd' at 300 weight
glyphs.ascD = Math.max(glyphs[300].glyphs.d.bounds[3], glyphs[600].glyphs.i.bounds[3]);   // tallest point: 'd' ascender / 'i' dot
glyphs.overshoot = -Math.min(...['a', 'e', 'r', 'v'].map(c => glyphs[300].glyphs[c].bounds[1]));

function wordmarkSVG(theme) {
  const size = 100, wm = wordmark(size, WORD[theme]);
  const asc = glyphs.ascD * size / 1000, pad = 0;
  const os = glyphs.overshoot * size / 1000;
  return svgWrap(wm.width, asc + os, `<g transform="translate(0 ${f2(asc)})">${wm.body}</g>`, '', 'viadere');
}

// Lockups carry built-in clear space: P = one dot diameter on every side.
const CLEAR = 2 * params.dotR;
// Horizontal lockup: x-height = 0.66 × ribbon height (ribbon reads heavier than the type, as in the reference);
// baseline 0.1h above ribbon bottom; gap 0.26h.
const LOCKUP = { xh: 0.66, gap: 0.26, base: 0.10, stackedWidth: 1.24, stackedGap: 0.58 };
function lockupH(theme, markTheme, id) {
  const m = mark(markTheme, id);
  const rh = 100, size = LOCKUP.xh * rh / (glyphs[600].xHeight / 1000);
  const wm = wordmark(size, WORD[theme]);
  const gap = LOCKUP.gap * rh;
  const baseline = RT + rh - LOCKUP.base * rh;
  const asc = glyphs.ascD * size / 1000;
  const top = Math.min(0, baseline - asc);
  const bottom = Math.max(m.H, baseline + glyphs.overshoot * size / 1000);
  const P = CLEAR;
  const W = m.W + gap + wm.width + 2 * P, H = bottom - top + 2 * P;
  const inner = `<g transform="translate(${f2(P)} ${f2(P - top)})">${m.body}<g transform="translate(${f2(m.W + gap)} ${f2(baseline)})">${wm.body}</g></g>`;
  return { svg: svgWrap(W, H, inner, m.defs), W, H };
}
// Stacked lockup: wordmark width = 1.24 × ribbon width; gap ribbon-bottom → ascender = 0.58h.
function lockupS(theme, markTheme, id) {
  const m = mark(markTheme, id);
  const target = m.W * LOCKUP.stackedWidth;
  const w1 = wordmark(100, WORD[theme]); const size = 100 * target / w1.width;
  const wm = wordmark(size, WORD[theme]);
  const asc = glyphs.ascD * size / 1000;
  const P = CLEAR;
  const IW = Math.max(m.W, wm.width), mx = (IW - m.W) / 2, wx = (IW - wm.width) / 2;
  const baseline = m.H + LOCKUP.stackedGap * 100 + asc;
  const H = baseline + glyphs.overshoot * size / 1000 + 2 * P, W = IW + 2 * P;
  const inner = `<g transform="translate(${f2(P)} ${f2(P)})"><g transform="translate(${f2(mx)} 0)">${m.body}</g><g transform="translate(${f2(wx)} ${f2(baseline)})">${wm.body}</g></g>`;
  return { svg: svgWrap(W, H, inner, m.defs), W, H };
}

// ---------- app icons (1024, full-bleed; iOS applies the mask) ----------
function icon(kind) {
  const S = 1024, ribbonW = 0.76 * S;              // mark ribbon width ≈ 76% of the canvas
  const sc = ribbonW / MW, mh = MH * sc;
  const x0 = (S - ribbonW) / 2, y0 = (S - mh) / 2 - 6;   // optical centre: bbox centred, nudged up 6px
  let bg, defs = '', m, shadow;
  if (kind === 'light') {
    m = mark('primary', 'il');
    defs += `<linearGradient id="bgl" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#FAF8F4"/><stop offset="1" stop-color="#ECE8E0"/></linearGradient>`;
    defs += `<filter id="sh" x="-10%" y="-10%" width="120%" height="140%"><feDropShadow dx="0" dy="6" stdDeviation="9" flood-color="#3A3226" flood-opacity="0.16"/></filter>`;
    bg = `<rect width="${S}" height="${S}" fill="url(#bgl)"/>`;
  } else if (kind === 'dark') {
    m = mark('dark', 'id');
    defs += `<linearGradient id="bgd" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2C2B29"/><stop offset="1" stop-color="#121211"/></linearGradient>`;
    defs += `<radialGradient id="bgg" cx="0.5" cy="0.18" r="0.75"><stop offset="0" stop-color="#FFFFFF" stop-opacity="0.07"/><stop offset="1" stop-color="#FFFFFF" stop-opacity="0"/></radialGradient>`;
    defs += `<filter id="sh" x="-10%" y="-10%" width="120%" height="140%"><feDropShadow dx="0" dy="8" stdDeviation="10" flood-color="#000" flood-opacity="0.45"/></filter>`;
    bg = `<rect width="${S}" height="${S}" fill="url(#bgd)"/><rect width="${S}" height="${S}" fill="url(#bgg)"/>`;
  } else { // tinted: grayscale on black; iOS applies the user's tint
    m = markGroup({ mono: '#FFFFFF', id: 'it', params, monoBack: 0.55 });
    bg = `<rect width="${S}" height="${S}" fill="#000"/>`;
  }
  const filt = kind === 'tinted' ? '' : ' filter="url(#sh)"';
  const inner = `${bg}<g${filt} transform="translate(${f2(x0)} ${f2(y0)}) scale(${sc.toFixed(5)})">${m.body}</g>`;
  return svgWrap(S, S, inner, defs + m.defs, 'Viadere app icon');
}

// ---------- write SVGs ----------
const files = {};
files['viadere-mark.svg'] = markFile(mark('primary', 'vm'));
files['viadere-mark-on-dark.svg'] = markFile(mark('dark', 'vd'));
files['viadere-mark-mono-dark.svg'] = markFile(markGroup({ mono: PAL.charcoal, id: 'mmd', params }));
files['viadere-mark-mono-light.svg'] = markFile(markGroup({ mono: PAL.ivory, id: 'mml', params }));
files['viadere-wordmark.svg'] = wordmarkSVG('light');
files['viadere-wordmark-on-dark.svg'] = wordmarkSVG('dark');
const LH = lockupH('light', 'primary', 'lh'), LHD = lockupH('dark', 'dark', 'lhd');
const LS = lockupS('light', 'primary', 'ls'), LSD = lockupS('dark', 'dark', 'lsd');
files['viadere-lockup-horizontal.svg'] = LH.svg;
files['viadere-lockup-horizontal-on-dark.svg'] = LHD.svg;
files['viadere-lockup-stacked.svg'] = LS.svg;
files['viadere-lockup-stacked-on-dark.svg'] = LSD.svg;
files['app-icon-light.svg'] = icon('light');
files['app-icon-dark.svg'] = icon('dark');
files['app-icon-tinted.svg'] = icon('tinted');
for (const [n, s] of Object.entries(files)) write(D('svg', n), s);

// ---------- rasterize ----------
const page = (svg, bg, w, h) => `<!doctype html><html><head><style>@page{margin:0;size:${w}px ${h}px}html,body{margin:0;padding:0;background:${bg};}svg{display:block;width:${w}px;height:${h}px}</style></head><body>${svg}</body></html>`;
const svgOf = (n) => fs.readFileSync(D('svg', n), 'utf8');
const jobs = [];
const ratio = (n) => { const m = svgOf(n).match(/viewBox="0 0 ([\d.]+) ([\d.]+)"/); return [+m[1], +m[2]]; };
for (const n of ['app-icon-light', 'app-icon-dark', 'app-icon-tinted']) jobs.push({ html: page(svgOf(n + '.svg'), '#000', 1024, 1024), out: D('png', n + '-1024.png'), w: 1024, h: 1024 });
for (const [n, bg] of [['viadere-mark', 'transparent'], ['viadere-mark-on-dark', 'transparent'], ['viadere-mark-mono-dark', 'transparent'], ['viadere-mark-mono-light', 'transparent'],
  ['viadere-lockup-horizontal', 'transparent'], ['viadere-lockup-horizontal-on-dark', 'transparent'], ['viadere-lockup-stacked', 'transparent'], ['viadere-lockup-stacked-on-dark', 'transparent']]) {
  const [w, h] = ratio(n + '.svg'); const W = 1024, H = Math.round(W * h / w);
  jobs.push({ html: page(svgOf(n + '.svg'), bg, W, H), out: D('png', n + '@1024w.png'), w: W, h: H, transparent: true });
}
// vector PDFs for the asset catalog (Chromium keeps paths + gradients as vectors)
const pdfs = [['viadere-mark', 120], ['viadere-mark-on-dark', 120], ['viadere-mark-mono-dark', 120], ['viadere-mark-mono-light', 120], ['viadere-wordmark', 160], ['viadere-wordmark-on-dark', 160], ['viadere-lockup-horizontal', 240], ['viadere-lockup-horizontal-on-dark', 240]];
for (const [n, wpt] of pdfs) {
  const [w, h] = ratio(n + '.svg'); const W = wpt / 0.75, H = W * h / w;  // CSS px; PDF pt = px × 0.75
  jobs.push({ html: page(svgOf(n + '.svg'), 'transparent', +W.toFixed(2), +H.toFixed(2)), out: D('pdf', n + '.pdf'), w: Math.ceil(W), h: Math.ceil(H), pdf: true, pw: W, ph: H });
}
module.exports = { LOCKUP, CLEAR, PAL, WORD, MW, MH, RT, params, mark, wordmark, glyphs, lockupH, lockupS };

if (require.main === module) {
  (async () => {
    const { chromium } = require('playwright');
    const b = await chromium.launch();
    for (const j of jobs) {
      const pg = await b.newPage({ viewport: { width: j.w, height: j.h } });
      await pg.setContent(j.html, { waitUntil: 'load' });
      if (j.pdf) await pg.pdf({ path: j.out, width: j.pw.toFixed(2) + 'px', height: j.ph.toFixed(2) + 'px', printBackground: false, pageRanges: '1', margin: { top: 0, right: 0, bottom: 0, left: 0 } });
      else await pg.screenshot({ path: j.out, omitBackground: !!j.transparent });
      await pg.close();
    }
    await b.close();
    console.log('rendered', jobs.length, 'files');
  })();
}
