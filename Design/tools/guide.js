// Generates Design/brand-guide.html (self-contained: inline SVG, base64 icons + Outfit woff2).
const fs = require('fs'), path = require('path');
const B = require('./build.js');
const G = require('./geom');
const { markGroup } = require('./mark');
const SCR = path.resolve(__dirname, '..');
const b64 = (p) => fs.readFileSync(p).toString('base64');
const font = (w) => `@font-face{font-family:"Outfit";font-weight:${w};font-display:swap;src:url(data:font/woff2;base64,${b64(path.join(SCR, `fontdl/package/files/outfit-latin-${w}-normal.woff2`))}) format("woff2")}`;
const icon = (k) => `data:image/png;base64,${b64(path.join(SCR, `icon-${k}-360.png`))}`;
const svgStr = (m, cls = '', label = 'Viadere mark') => `<svg class="${cls}" viewBox="0 0 ${G.f(m.W)} ${G.f(m.H)}" role="img" aria-label="${label}"><defs>${m.defs}</defs>${m.body}</svg>`;
const mark = (theme, id, cls) => svgStr(markGroup({ theme, id, params: B.params }), cls);
const mono = (color, id, cls) => svgStr(markGroup({ mono: color, id, params: B.params }), cls);
const fileSvg = (n, cls, idPrefix) => fs.readFileSync(`/home/user/viadere/Design/svg/${n}`, 'utf8')
  .replace(/<title>[^<]*<\/title>/, '').replace(/ width="[\d.]+" height="[\d.]+"/, ` class="${cls}"`)
  .replace(/id="([^"]+)"/g, `id="${idPrefix}$1"`).replace(/url\(#([^)]+)\)/g, `url(#${idPrefix}$1)`);

// Deconstruction: one front face highlighted, the rest faint.
const g0 = markGroup({ theme: 'primary', id: 'dc', params: B.params }).g;
const part = (idx, withDot, label) => {
  const faint = `<path d="${G.pathD(g0.sil)}" fill="currentColor" opacity=".10"/><circle cx="${G.f(g0.dot.cx)}" cy="${G.f(g0.dot.cy)}" r="${G.f(g0.dot.r)}" fill="currentColor" opacity="${withDot ? 1 : 0.1}"/>`;
  const hi = idx == null ? '' : `<path d="${G.pathD(g0.front[idx])}" fill="currentColor"/>`;
  return `<figure class="part"><svg viewBox="0 0 ${G.f(g0.W)} ${G.f(g0.H)}" aria-label="${label}">${faint}${hi}</svg><figcaption>${label}</figcaption></figure>`;
};

// Clear-space diagram: unit d = dot diameter.
const dUnit = g0.dot.r * 2;
const cs = (() => {
  const pad = dUnit, W = g0.W + pad * 2, H = g0.H + pad * 2;
  const m = markGroup({ theme: 'primary', id: 'cs', params: B.params });
  return `<svg class="clear" viewBox="0 0 ${G.f(W)} ${G.f(H)}" aria-label="Clear space diagram">
  <defs>${m.defs}<pattern id="hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><line x1="0" y1="0" x2="0" y2="6" stroke="#C2AE8E" stroke-width="1.2" opacity=".55"/></pattern></defs>
  <rect x="0" y="0" width="${G.f(W)}" height="${G.f(H)}" fill="url(#hatch)"/>
  <rect x="${G.f(pad)}" y="${G.f(pad)}" width="${G.f(g0.W)}" height="${G.f(g0.H)}" fill="#F5F2EC"/>
  <g transform="translate(${G.f(pad)} ${G.f(pad)})">${m.body}</g>
  <rect x="${G.f(pad)}" y="${G.f(pad)}" width="${G.f(g0.W)}" height="${G.f(g0.H)}" fill="none" stroke="#8C7550" stroke-width=".8" stroke-dasharray="3 3"/>
  ${[[pad / 2, H / 2], [W - pad / 2, H / 2], [W / 2, pad / 2], [W / 2, H - pad / 2]].map(([x, y]) => `<text x="${G.f(x)}" y="${G.f(y + 4)}" text-anchor="middle" font-size="12" font-family="Outfit" fill="#8C7550">d</text>`).join('')}
  </svg>`;
})();

const PAL = [
  ['Charcoal', '#1F1E1C', 'Primary dark. Text, primary buttons, mark on light.', '#F5F2EC'],
  ['Graphite', '#4A4844', 'Secondary dark. Ribbon shading, icons.', '#F5F2EC'],
  ['Silver', '#C9C4BB', 'Neutral mid-tone. Ribbon highlight, dividers.', '#1F1E1C'],
  ['Ivory', '#F5F2EC', 'Primary light. Backgrounds, mark on dark.', '#1F1E1C'],
  ['Champagne', '#C2AE8E', 'Accent. Ribbon end, verification, focus.', '#1F1E1C'],
];
const SEM = [
  ['Background', '#F5F2EC', '#121211'], ['Surface', '#FCFBF8', '#1C1B1A'], ['SurfaceRaised', '#FFFFFF', '#262523'],
  ['TextPrimary', '#1F1E1C', '#F3F0EA'], ['TextSecondary', '#6B675F', '#A29D94'], ['TextTertiary', '#9A958C', '#6F6B64'],
  ['Accent', '#8C7550', '#CDB993'], ['Danger', '#A3412E', '#E08068'], ['Success', '#4C7458', '#8DBB98'],
  ['Hairline', 'rgba(31,30,28,.10)', 'rgba(243,240,234,.12)'],
];

const comp = (theme) => `
<div class="ds ${theme}">
  <div class="ds-head"><span class="sec">Connections</span><span class="link">See all</span></div>
  <div class="card">
    <div class="row"><span class="tile">◫</span><div><b>Harbor Bank</b><small>Connected · verified</small></div><span class="chev">›</span></div>
    <div class="hair"></div>
    <div class="row"><span class="tile">◷</span><div><b>Northside Clinic</b><small>Appointments</small></div><span class="chev">›</span></div>
  </div>
  <div class="seg"><span class="on">All</span><span>Businesses</span><span>Requests</span></div>
  <div class="card approval">
    <div class="req">Harbor Bank <span class="badge verified">✓ Verified</span></div>
    <div class="ttl">Approve sign-in on a new Mac?</div>
    <div class="kv"><span>Location</span><span>Lisbon, PT</span></div><div class="hair"></div>
    <div class="kv"><span>Device</span><span>MacBook Air</span></div>
    <div class="slide"><span class="knob">→</span><span class="lbl">Slide to approve</span></div>
    <div class="pair"><span class="btn danger">Deny</span><span class="btn primary">Approve</span></div>
  </div>
  <label class="field"><span>Email</span><div class="input">name@example.com</div><small>We'll send a one-time code.</small></label>
  <div class="card"><div class="toggle"><span>Face ID for approvals</span><span class="sw on"><i></i></span></div><div class="hair"></div><div class="toggle"><span>Marketing messages</span><span class="sw"><i></i></span></div></div>
  <div class="badges"><span class="badge verified">✓ Verified</span><span class="badge">Pending</span><span class="badge success">Active</span><span class="badge danger">Revoked</span></div>
  <span class="btn primary">Continue</span><span class="btn secondary">Not now</span>
</div>`;

const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Viadere Brand Guide</title>
<meta name="description" content="Viadere identity: mark, lockups, app icons, palette, clear space, usage and component principles.">
<style>
${font(300)}${font(400)}${font(600)}
:root{--charcoal:#1F1E1C;--graphite:#4A4844;--silver:#C9C4BB;--ivory:#F5F2EC;--champagne:#C2AE8E;--champ-deep:#8C7550;--black:#121211;
 --bg:var(--ivory);--fg:var(--charcoal);--muted:#6B675F;--hair:rgba(31,30,28,.10);--surface:#FCFBF8}
*{box-sizing:border-box}
html,body{margin:0;background:var(--ivory);color:var(--charcoal);font:15px/1.6 -apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased}
section{padding:96px 24px}
.wrap{max-width:1080px;margin:0 auto}
.dark{background:var(--black);color:#F3F0EA;--fg:#F3F0EA;--muted:#A29D94;--hair:rgba(243,240,234,.12);--surface:#1C1B1A}
.light{background:var(--ivory);--surface:#FCFBF8}
.paper{background:#ECE8E1}
h1,h2,h3{font-family:"Outfit",-apple-system,sans-serif;font-weight:400;letter-spacing:-.01em;margin:0}
h2{font-size:34px;line-height:1.15;margin-bottom:12px}
h3{font-size:18px;font-weight:600;margin:0 0 6px}
.eyebrow{font:500 12px/1 -apple-system,sans-serif;letter-spacing:.18em;text-transform:uppercase;color:var(--muted);margin-bottom:18px}
p{color:var(--muted);max-width:620px;margin:0 0 16px}
.lede{font-size:17px}
.grid{display:grid;gap:20px}
.g2{grid-template-columns:repeat(2,1fr)}.g3{grid-template-columns:repeat(3,1fr)}.g4{grid-template-columns:repeat(4,1fr)}.g5{grid-template-columns:repeat(5,1fr)}
@media (max-width:820px){.g2,.g3,.g4,.g5{grid-template-columns:1fr 1fr}section{padding:64px 16px}h2{font-size:28px}}
@media (max-width:520px){.g2,.g3,.g4,.g5{grid-template-columns:1fr}}
.tile-box{border-radius:20px;padding:40px 28px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;min-height:220px;border:1px solid var(--hair)}
.tile-box.on-light{background:#F5F2EC;color:#1F1E1C}.tile-box.on-white{background:#fff}.tile-box.on-dark{background:#121211;color:#F3F0EA;border-color:rgba(243,240,234,.08)}.tile-box.on-char{background:#2A2927}
.tile-box svg{width:100%;max-width:300px;height:auto}
.cap{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#8E8A83}
.hero{padding:120px 24px 110px;text-align:center}
.hero svg.lock{width:min(640px,100%);height:auto}
.tag{font:400 14px/1 "Outfit",sans-serif;letter-spacing:.5em;text-transform:uppercase;color:#BDB6AA;margin-top:44px}
.parts{display:flex;align-items:center;justify-content:center;gap:28px;flex-wrap:wrap;color:var(--charcoal)}
.part{margin:0;text-align:center;width:180px}.part svg{width:100%;height:auto}.part figcaption{font-size:12px;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin-top:10px}
.plus{font:300 28px "Outfit";color:#A29D94}
.icons{display:flex;gap:40px;align-items:flex-end;flex-wrap:wrap}
.icons figure{margin:0;text-align:center}.icons img{display:block;border-radius:22.37%;box-shadow:0 10px 30px rgba(0,0,0,.14)}
.icons figcaption{font-size:12px;color:var(--muted);margin-top:12px}
.swatch{border-radius:18px;overflow:hidden;border:1px solid var(--hair);background:var(--surface)}
.swatch .chip{height:130px;display:flex;align-items:flex-end;padding:14px;font:600 13px "Outfit";letter-spacing:.04em}
.swatch .meta{padding:14px 16px 18px}.swatch .meta b{display:block;font-weight:600;color:var(--fg)}.swatch code{font:500 13px ui-monospace,Menlo,monospace;color:var(--fg)}.swatch small{display:block;color:var(--muted);font-size:12px;line-height:1.45;margin-top:6px}
table{width:100%;border-collapse:collapse;font-size:14px}
.tablewrap{overflow-x:auto}
@media (max-width:520px){th,td{padding:10px 6px}td code{font-size:11px}.dotc{margin-right:5px}}
th,td{padding:12px 10px;border-bottom:1px solid var(--hair);text-align:left}th{font-weight:500;color:var(--muted);font-size:12px;letter-spacing:.1em;text-transform:uppercase}
td code{font:500 12.5px ui-monospace,Menlo,monospace}
.dotc{display:inline-block;width:14px;height:14px;border-radius:50%;vertical-align:-2px;margin-right:8px;border:1px solid rgba(0,0,0,.12)}
.clear{width:100%;max-width:520px;height:auto;display:block}
.rule{border-left:2px solid var(--champagne);padding:4px 0 4px 16px;margin-bottom:18px}
.rule b{display:block;color:var(--fg);font-weight:600}
.minis{display:flex;gap:28px;align-items:flex-end;flex-wrap:wrap}.minis div{text-align:center;font-size:11px;color:var(--muted)}
.dd{border-radius:16px;padding:22px;background:var(--surface);border:1px solid var(--hair);display:flex;flex-direction:column;gap:14px}
.dd .stage{height:120px;border-radius:12px;display:flex;align-items:center;justify-content:center;background:#F5F2EC;overflow:hidden}
.dd .stage svg{width:62%;height:auto}
.dd .v{font:600 12px/1 -apple-system,sans-serif;letter-spacing:.1em;text-transform:uppercase}
.dd.do .v{color:#4C7458}.dd.dont .v{color:#A3412E}
.dd p{font-size:13px;margin:0}
.type-row{display:flex;align-items:baseline;gap:24px;padding:14px 0;border-bottom:1px solid var(--hair)}
.type-row span:first-child{width:120px;flex:none;font-size:12px;color:var(--muted)}
.principles{counter-reset:p}.principles li{list-style:none;margin:0 0 18px;padding-left:44px;position:relative;color:var(--muted)}
.principles li b{color:var(--fg);display:block;font-weight:600}
.principles li::before{counter-increment:p;content:counter(p,decimal-leading-zero);position:absolute;left:0;top:1px;font:400 14px "Outfit";color:var(--champagne)}
.principles{padding:0;margin:0}
/* component mock: mirrors ViadereDesignSystem.swift */
.ds{--bg:#F5F2EC;--sf:#FCFBF8;--sr:#FFFFFF;--tr:#EAE6DF;--t1:#1F1E1C;--t2:#6B675F;--t3:#9A958C;--ac:#8C7550;--acs:rgba(194,174,142,.16);--pf:#1F1E1C;--op:#F5F2EC;--dg:#A3412E;--ok:#4C7458;--hl:rgba(31,30,28,.10);--sw:#1F1E1C;
 background:var(--bg);color:var(--t1);border-radius:28px;padding:26px 20px;display:flex;flex-direction:column;gap:14px;border:1px solid var(--hl);max-width:390px;width:100%;font-size:15px}
.ds.dk{--bg:#121211;--sf:#1C1B1A;--sr:#262523;--tr:#2A2927;--t1:#F3F0EA;--t2:#A29D94;--t3:#6F6B64;--ac:#CDB993;--acs:rgba(205,185,147,.14);--pf:#F3F0EA;--op:#1F1E1C;--dg:#E08068;--ok:#8DBB98;--hl:rgba(243,240,234,.12);--sw:#CDB993}
.ds .ds-head{display:flex;justify-content:space-between;align-items:baseline;padding:6px 4px 0}
.ds .sec{font-size:12px;font-weight:500;letter-spacing:.1em;text-transform:uppercase;color:var(--t2)}.ds .link{font-size:13px;font-weight:500;color:var(--ac)}
.ds .card{background:var(--sf);border:1px solid var(--hl);border-radius:20px;padding:6px 16px;box-shadow:0 6px 14px rgba(0,0,0,.035)}
.ds.dk .card{box-shadow:none}
.ds .row{display:flex;align-items:center;gap:14px;min-height:58px}.ds .row div{flex:1;display:flex;flex-direction:column}.ds .row b{font-weight:400;color:var(--t1)}.ds .row small{color:var(--t2);font-size:14px}
.ds .tile{width:36px;height:36px;border-radius:10px;background:var(--sr);border:1px solid var(--hl);display:grid;place-items:center;color:var(--t1);font-size:15px}
.ds .chev{color:var(--t3);font-size:20px}
.ds .hair{height:1px;background:var(--hl)}
.ds .row+.hair{margin-left:50px}
.ds .seg{display:flex;background:var(--tr);border-radius:12px;padding:3px;gap:2px}.ds .seg span{flex:1;text-align:center;font-size:14px;color:var(--t2);padding:8px 0;border-radius:9px}
.ds .seg .on{background:var(--sr);color:var(--t1);font-weight:600;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.ds .approval{padding:20px 18px;display:flex;flex-direction:column;gap:8px}
.ds .req{font-size:14px;color:var(--t2);font-weight:500;display:flex;gap:8px;align-items:center}.ds .ttl{font:600 21px/1.25 -apple-system,sans-serif;margin-bottom:8px}
.ds .kv{display:flex;justify-content:space-between;font-size:14px;padding:8px 0}.ds .kv span:first-child{color:var(--t2)}
.ds .slide{margin-top:10px;height:60px;border-radius:30px;background:var(--tr);border:1px solid var(--hl);position:relative;display:flex;align-items:center}
.ds .knob{position:absolute;left:4px;width:52px;height:52px;border-radius:50%;background:var(--pf);color:var(--op);display:grid;place-items:center;font-weight:600}
.ds .slide .lbl{flex:1;text-align:center;padding-left:30px;font-size:14px;font-weight:500;color:var(--t2)}
.ds .pair{display:flex;gap:12px;margin-top:6px}.ds .pair .btn{flex:1}
.ds .btn{display:flex;align-items:center;justify-content:center;min-height:52px;border-radius:14px;font-weight:600;font-size:16px}
.ds .btn.primary{background:var(--pf);color:var(--op)}.ds .btn.secondary{background:var(--sf);border:1px solid var(--hl);color:var(--t1)}
.ds .btn.danger{background:color-mix(in srgb,var(--dg) 8%,transparent);border:1px solid color-mix(in srgb,var(--dg) 22%,transparent);color:var(--dg)}
.ds .field{display:flex;flex-direction:column;gap:8px}.ds .field>span{font-size:13px;font-weight:500;color:var(--t2)}
.ds .input{min-height:52px;border-radius:12px;background:var(--sf);border:1.5px solid var(--ac);display:flex;align-items:center;padding:0 16px;color:var(--t3)}
.ds .field small{font-size:13px;color:var(--t2)}
.ds .toggle{display:flex;justify-content:space-between;align-items:center;min-height:52px}
.ds .sw{width:50px;height:30px;border-radius:15px;background:var(--tr);border:1px solid var(--hl);position:relative}.ds .sw i{position:absolute;top:2px;left:2px;width:24px;height:24px;border-radius:50%;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.18)}
.ds .sw.on{background:var(--sw);border-color:transparent}.ds .sw.on i{left:22px;background:#F5F2EC}
.ds .badges{display:flex;gap:8px;flex-wrap:wrap}
.ds .badge{font-size:12px;font-weight:500;padding:4px 9px;border-radius:999px;background:var(--tr);color:var(--t2);border:1px solid var(--hl)}
.ds .badge.verified{background:var(--acs);color:var(--ac)}.ds .badge.success{color:var(--ok)}.ds .badge.danger{color:var(--dg)}
.mocks{display:flex;gap:28px;flex-wrap:wrap;justify-content:center}
footer{padding:48px 24px;text-align:center;font-size:12px;color:#8E8A83}
</style></head>
<body>

<section class="dark hero">
  <div class="wrap">
    ${fileSvg('viadere-lockup-horizontal-on-dark.svg', 'lock', 'h-')}
    <div class="tag">A trusted way to connect.</div>
  </div>
</section>

<section class="light">
  <div class="wrap">
    <div class="eyebrow">01 · The mark</div>
    <h2>One continuous ribbon that reads “via”.</h2>
    <p class="lede">A single band falls into a <b>v</b>, rises through the <b>i</b> beneath a floating dot, and arches into an <b>a</b> before it settles to the right. Where it twists, the back of the ribbon shows. That twist is the moment of connection. The gradient travels from charcoal through ivory to champagne.</p>
    <div class="grid g2" style="margin-top:36px">
      <div class="tile-box on-light">${mark('primary', 'm1')}<span class="cap">Primary · on ivory / white</span></div>
      <div class="tile-box on-dark">${mark('dark', 'm2')}<span class="cap">On dark · black / charcoal</span></div>
      <div class="tile-box on-white">${mono('#1F1E1C', 'm3')}<span class="cap">Monochrome dark</span></div>
      <div class="tile-box on-char">${mono('#F5F2EC', 'm4')}<span class="cap">Monochrome light</span></div>
    </div>
  </div>
</section>

<section class="paper">
  <div class="wrap">
    <div class="eyebrow">02 · Meaning</div>
    <h2>People, identity, access: connection.</h2>
    <p>The mark is built from three gestures joined by one path, linking people to businesses securely and simply.</p>
    <div class="parts" style="margin-top:40px">
      ${part(0, false, 'v · People')}<span class="plus">+</span>${part(1, true, 'i · Identity')}<span class="plus">+</span>${part(2, false, 'a · Access')}<span class="plus">=</span>
      <figure class="part">${mark('primary', 'm5')}<figcaption>Connection</figcaption></figure>
    </div>
  </div>
</section>

<section class="light">
  <div class="wrap">
    <div class="eyebrow">03 · Lockups</div>
    <h2>Mark and wordmark.</h2>
    <p>Lowercase <b>viadere</b> set in Outfit: <b>via</b> in SemiBold, <b>dere</b> in Light. The wordmark is outlined in every artwork file, so no font is needed. Horizontal: wordmark x-height = 0.66 × ribbon height, so the ribbon reads heavier than the type; gap = 0.26 × ribbon height. Stacked: wordmark width = 1.24 × ribbon width. Every lockup file includes one dot diameter of clear space.</p>
    <div class="grid g2" style="margin-top:36px">
      <div class="tile-box on-light">${fileSvg('viadere-lockup-horizontal.svg', '', 'lh-')}<span class="cap">Horizontal</span></div>
      <div class="tile-box on-dark">${fileSvg('viadere-lockup-horizontal-on-dark.svg', '', 'lhd-')}<span class="cap">Horizontal · on dark</span></div>
      <div class="tile-box on-light">${fileSvg('viadere-lockup-stacked.svg', '', 'ls-').replace('class=""', 'style="max-width:220px"')}<span class="cap">Stacked</span></div>
      <div class="tile-box on-dark">${fileSvg('viadere-lockup-stacked-on-dark.svg', '', 'lsd-').replace('class=""', 'style="max-width:220px"')}<span class="cap">Stacked · on dark</span></div>
    </div>
  </div>
</section>

<section class="paper">
  <div class="wrap">
    <div class="eyebrow">04 · App icon</div>
    <h2>Quiet on the home screen.</h2>
    <p>Full-bleed 1024 px artwork. iOS applies the mask. The ribbon spans about 76% of the width, and the mark’s bounding box (dot included) is optically centred. There is a single soft shadow and no other effects. The dark and tinted variants ship in the same asset catalog.</p>
    <div class="icons" style="margin-top:36px">
      <figure><img src="${icon('light')}" width="180" height="180" alt="Light app icon"><figcaption>Light</figcaption></figure>
      <figure><img src="${icon('dark')}" width="180" height="180" alt="Dark app icon"><figcaption>Dark</figcaption></figure>
      <figure><img src="${icon('tinted')}" width="120" height="120" alt="Tinted app icon"><figcaption>Tinted (iOS 18)</figcaption></figure>
      <figure><img src="${icon('light')}" width="60" height="60" alt=""><figcaption>60 pt</figcaption></figure>
      <figure><img src="${icon('dark')}" width="40" height="40" alt=""><figcaption>40 pt</figcaption></figure>
      <figure><img src="${icon('light')}" width="29" height="29" alt=""><figcaption>29 pt</figcaption></figure>
    </div>
  </div>
</section>

<section class="light">
  <div class="wrap">
    <div class="eyebrow">05 · Colour</div>
    <h2>Charcoal, ivory, champagne.</h2>
    <p>A neutral, warm palette. Champagne is the only accent and appears rarely: on verification, focus and the ribbon’s end. Never substitute blue, and never pair the mark with a shield.</p>
    <div class="grid g5" style="margin-top:32px">
      ${PAL.map(([n, h, r, ink]) => `<div class="swatch"><div class="chip" style="background:${h};color:${ink}">${n}</div><div class="meta"><code>${h}</code><small>${r}</small></div></div>`).join('')}
    </div>
    <h3 style="margin-top:48px">Semantic tokens</h3>
    <p>These are the colour sets in <code>Assets.xcassets/Colors</code> and <code>ViadereColor</code> in Swift.</p>
    <div class="tablewrap"><table><thead><tr><th>Token</th><th>Light</th><th>Dark</th></tr></thead><tbody>
      ${SEM.map(([n, l, d]) => `<tr><td>${n}</td><td><span class="dotc" style="background:${l}"></span><code>${l}</code></td><td><span class="dotc" style="background:${d}"></span><code>${d}</code></td></tr>`).join('')}
    </tbody></table></div>
  </div>
</section>

<section class="paper">
  <div class="wrap grid g2" style="align-items:center;gap:48px">
    <div>
      <div class="eyebrow">06 · Clear space &amp; size</div>
      <h2>Give it room.</h2>
      <div class="rule"><b>Clear space = d</b>Keep at least one dot diameter (d) clear on every side of the mark or lockup. Use 2d where you can.</div>
      <div class="rule"><b>Minimum size</b>Gradient mark: 32 px / 24 pt wide (8 mm in print). Below that, use the monochrome mark down to 20 px wide. Horizontal lockup: 96 px wide. App icon: any system size.</div>
      <div class="rule"><b>Proportions</b>The ribbon is 3.2 : 1 (width : height). The dot is 0.41 × the ribbon height and floats 0.05 × the ribbon height above it, over the “i” rise.</div>
    </div>
    <div>${cs}
      <div class="minis" style="margin-top:22px">
        ${[96, 60, 40, 32].map(w => `<div>${mark('primary', 'mn' + w).replace('<svg class=""', `<svg style="width:${w}px;height:auto;display:block"`)}${w}px</div>`).join('')}
        ${[24, 20].map(w => `<div>${mono('#1F1E1C', 'mm' + w).replace('<svg class=""', `<svg style="width:${w}px;height:auto;display:block"`)}${w}px mono</div>`).join('')}
      </div>
    </div>
  </div>
</section>

<section class="light">
  <div class="wrap">
    <div class="eyebrow">07 · Usage</div>
    <h2>Do and don’t.</h2>
    <div class="grid g4" style="margin-top:32px">
      <div class="dd do"><div class="stage">${mark('primary', 'd1')}</div><span class="v">Do</span><p>Use the primary gradient on ivory or white.</p></div>
      <div class="dd do"><div class="stage" style="background:#121211">${mark('dark', 'd2')}</div><span class="v">Do</span><p>Use the on-dark version on black or charcoal.</p></div>
      <div class="dd do"><div class="stage" style="background:linear-gradient(135deg,#8B7B66,#3E3933)">${mono('#F5F2EC', 'd3')}</div><span class="v">Do</span><p>Use monochrome on photography and mid-tones.</p></div>
      <div class="dd do"><div class="stage">${mono('#1F1E1C', 'd4')}</div><span class="v">Do</span><p>Use monochrome for small sizes, print and engraving.</p></div>
      <div class="dd dont"><div class="stage">${mark('primary', 'x1').replace('<svg class=""', '<svg style="transform:scaleX(1.45) scaleY(.8)"')}</div><span class="v">Don’t</span><p>Stretch, squash or redraw the ribbon.</p></div>
      <div class="dd dont"><div class="stage">${mono('#2F6FDB', 'x2')}</div><span class="v">Don’t</span><p>Recolour it in blue or any off-palette hue.</p></div>
      <div class="dd dont"><div class="stage">${mark('primary', 'x3').replace('<svg class=""', '<svg style="transform:rotate(-14deg)"')}</div><span class="v">Don’t</span><p>Rotate, tilt or animate it off its baseline.</p></div>
      <div class="dd dont"><div class="stage" style="background:#9C9384">${mark('primary', 'x4')}</div><span class="v">Don’t</span><p>Place the gradient on mid-tones, or add outlines or glows.</p></div>
    </div>
  </div>
</section>

<section class="paper">
  <div class="wrap">
    <div class="eyebrow">08 · Typography</div>
    <h2>Two faces, clear roles.</h2>
    <p><b>Outfit</b> (SIL OFL 1.1) is used only for the wordmark and display moments. <b>SF Pro</b> sets all interface text, with Dynamic Type. The scale is tight: seven sizes, two weights in most places.</p>
    <div style="margin-top:28px">
      <div class="type-row"><span>Display · 34 Semibold</span><span style="font:600 34px/1.15 -apple-system,sans-serif">A trusted way to connect.</span></div>
      <div class="type-row"><span>Title · 22 Semibold</span><span style="font:600 22px -apple-system,sans-serif">Approve sign-in on a new Mac?</span></div>
      <div class="type-row"><span>Headline · 17 Semibold</span><span style="font:600 17px -apple-system,sans-serif">Harbor Bank</span></div>
      <div class="type-row"><span>Body · 17 Regular</span><span style="font:400 17px -apple-system,sans-serif">Your details are shared only when you say so.</span></div>
      <div class="type-row"><span>Subhead · 15</span><span style="font:400 15px -apple-system,sans-serif;color:var(--muted)">Connected · verified</span></div>
      <div class="type-row"><span>Footnote · 13</span><span style="font:400 13px -apple-system,sans-serif;color:var(--muted)">We’ll send a one-time code.</span></div>
      <div class="type-row"><span>Caption · 12 Medium</span><span style="font:500 12px -apple-system,sans-serif;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)">Connections</span></div>
    </div>
  </div>
</section>

<section class="dark">
  <div class="wrap grid g2" style="gap:56px;align-items:start">
    <div>
      <div class="eyebrow">09 · Components</div>
      <h2>Custom, calm and deliberate.</h2>
      <p>Viadere uses its own components (<code>ViadereDesignSystem.swift</code>) rather than stock controls. They share these principles:</p>
      <ol class="principles" style="margin-top:28px">
        <li><b>Custom over stock</b>Buttons, fields, toggles, selectors and approvals are drawn by Viadere. Use system UI only where the platform requires it, such as sheets, keyboards and share.</li>
        <li><b>Hairlines, not borders</b>Edges are 1 px at 10–12% opacity. Light mode gets one barely-there shadow; dark mode gets none.</li>
        <li><b>One primary action</b>The charcoal (or ivory, in dark mode) button appears once per screen. Secondary actions sit on surface with a hairline.</li>
        <li><b>Champagne is earned</b>The accent marks verification, focus and links. It never fills large areas.</li>
        <li><b>Deliberate approvals</b>Sensitive actions use slide-to-approve or a Deny/Approve pair of equal size, with the facts listed above the decision.</li>
        <li><b>Generous space, tight type</b>Use a 24 pt screen margin, a 4-pt rhythm and seven type sizes. If it feels crowded, remove something.</li>
        <li><b>Restrained motion</b>Use ease-outs of 0.16 s and critically damped springs, with subtle haptics. Respect Reduce Motion.</li>
      </ol>
    </div>
    <div class="mocks">${comp('lt')}</div>
  </div>
  <div class="wrap grid g2" style="gap:56px;margin-top:48px;align-items:start">
    <div><h3 style="margin-top:8px">Dark appearance</h3><p>Every token has a dark value. The primary action becomes ivory, the accent brightens to champagne and shadows are dropped. Surfaces separate with hairlines alone.</p></div>
    <div class="mocks">${comp('dk')}</div>
  </div>
</section>

<footer class="light">Viadere brand guide · artwork generated from one Bézier source (Design/README.md) · Outfit © The Outfit Project Authors, SIL OFL 1.1</footer>
</body></html>
`;
fs.writeFileSync('/home/user/viadere/Design/brand-guide.html', html);
console.log('guide', (html.length / 1024).toFixed(0) + 'KB');
