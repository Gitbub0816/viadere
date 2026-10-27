// Builds mark SVG markup from geometry.
const G = require('./geom');

// Per-face gradients. front[i] = vertical stops for front band i (top -> bottom of ribbon);
// lens[i] = stops along the lens axis (trough end -> crest end); base fills the silhouette under the seams.
const THEMES = {
  primary: { // charcoal -> ivory -> champagne, for ivory / white backgrounds
    base: '#5E5A54',
    front: [
      [[0, '#41403D'], [0.45, '#2A2927'], [1, '#1C1B19']],
      [[0, '#D8D1C5'], [0.3, '#BDB5A8'], [0.62, '#5C5954'], [1, '#22211F']],
      [[0, '#D5C9B4'], [0.5, '#BEAE93'], [1, '#958268']],
    ],
    lens: [
      [[0, '#2B2A27'], [0.45, '#7A756D'], [1, '#CEC6B9']],
      [[0, '#8F897F'], [0.5, '#CFC8BC'], [1, '#E9E2D6']],
    ],
    dot: ['#4A4845', '#1C1B19'],
  },
  dark: { // ivory -> champagne, for black / charcoal backgrounds
    base: '#8D877D',
    front: [
      [[0, '#D9D4CB'], [1, '#9A948A']],
      [[0, '#F5F1EA'], [0.55, '#DCD6CC'], [1, '#A49D92']],
      [[0, '#ECE3D3'], [0.5, '#D7C9B0'], [1, '#AD9978']],
    ],
    lens: [
      [[0, '#4B4843'], [0.5, '#8C867C'], [1, '#C9C2B6']],
      [[0, '#5E584F'], [0.5, '#A39A8B'], [1, '#D3C8B4']],
    ],
    dot: ['#FFFDF8', '#D3CCC0'],
  },
};

function markGroup(opts = {}) {
  const { theme = 'primary', mono = null, id = 'vm', params } = opts;
  const g = G.build(params || {});
  const { W, H, ribbonTop } = g;
  const dot = g.dot;
  let defs = '', body = '';
  const circle = (fill) => `<circle cx="${G.f(dot.cx)}" cy="${G.f(dot.cy)}" r="${G.f(dot.r)}" fill="${fill}"/>`;
  if (mono) {
    const backOp = opts.monoBack != null ? opts.monoBack : 0.62;
    body += `<path d="${G.pathD(g.sil)}" fill="${mono}" opacity="${backOp}"/>`;
    for (const fr of g.front) body += `<path d="${G.pathD(fr)}" fill="${mono}"/>`;
    body += circle(mono);
    return { defs, body, W, H, g };
  }
  const T = THEMES[theme];
  const st = (arr) => arr.map(([o, c]) => `<stop offset="${o}" stop-color="${c}"/>`).join('');
  const y0 = ribbonTop, y1 = ribbonTop + 100;
  defs += `<radialGradient id="${id}-d" cx="0.36" cy="0.32" r="0.72"><stop offset="0" stop-color="${T.dot[0]}"/><stop offset="1" stop-color="${T.dot[1]}"/></radialGradient>`;
  body += `<path d="${G.pathD(g.sil)}" fill="${T.base}"/>`;
  g.back.forEach((bk, i) => {
    const [a, b] = g.lensAxis[i];
    defs += `<linearGradient id="${id}-l${i}" x1="${G.f(a[0])}" y1="${G.f(a[1])}" x2="${G.f(b[0])}" y2="${G.f(b[1])}" gradientUnits="userSpaceOnUse">${st(T.lens[i])}</linearGradient>`;
    body += `<path d="${G.pathD(bk)}" fill="url(#${id}-l${i})"/>`;
  });
  g.front.forEach((fr, i) => {
    defs += `<linearGradient id="${id}-f${i}" x1="0" y1="${G.f(y0)}" x2="0" y2="${G.f(y1)}" gradientUnits="userSpaceOnUse">${st(T.front[i])}</linearGradient>`;
    body += `<path d="${G.pathD(fr)}" fill="url(#${id}-f${i})"/>`;
  });
  body += circle(`url(#${id}-d)`);
  return { defs, body, W, H, g };
}

function markSVG(opts = {}) {
  const m = markGroup(opts);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${G.f(m.W)} ${G.f(m.H)}" width="${G.f(m.W)}" height="${G.f(m.H)}"><title>Viadere</title><defs>${m.defs}</defs>${m.body}</svg>`;
}
module.exports = { markGroup, markSVG, THEMES };
