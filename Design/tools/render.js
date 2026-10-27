// usage: node render.js out.png width height  (reads HTML from stdin) or render(html, out, w, h)
const { chromium } = require('playwright');
async function renderMany(jobs) {
  const b = await chromium.launch();
  for (const j of jobs) {
    const pg = await b.newPage({ viewport: { width: j.w, height: j.h }, deviceScaleFactor: j.scale || 1 });
    await pg.setContent(j.html, { waitUntil: 'load' });
    if (j.wait) await pg.waitForTimeout(j.wait);
    if (j.pdf) await pg.pdf({ path: j.out, width: j.w + 'px', height: j.h + 'px', printBackground: false, pageRanges: '1' });
    else await pg.screenshot({ path: j.out, omitBackground: !!j.transparent, fullPage: !!j.full });
    await pg.close();
  }
  await b.close();
}
module.exports = { renderMany };
