/*! Verify with Viadere v2 — https://viadere.io — dependency-free web component, docs/VERIFY-BUTTON.md.
 *  No network requests, no cookies, no storage, no analytics, no iframes, no inline styles, no innerHTML (works under a strict CSP and
 *  Trusted Types). It renders a link to a verification session your SERVER created (https://viadere.io/v/{CODE}) and, where the phone
 *  cannot be handed the link directly (a computer), a panel with the Viadere code (a CKey, read by the Viadere app) first, the same
 *  link as a QR code for the phone's camera one control away, and other options. It never sees a result: your server reads the
 *  session with its API key and verifies Viadere's signed result.
 *  Usage: <link rel="stylesheet" href=".../viadere-verify.css"> <script src=".../viadere-verify.js" defer></script>
 *         <viadere-verify link="https://viadere.io/v/ABCDEFGH"></viadere-verify>
 *  Attributes: link (required), variant="filled|ivory|outline", size="sm|md|lg", display="label|icon", theme="auto|light|dark",
 *  expires-at (ISO 8601, optional), send-to-phone (boolean, only when your server can reach this visitor's phone; see the docs). */
/*! The CKey encoder and renderer in this file are a port of the CKey reference core (github.com/clearkeysolutions/ckey, v0.1.0-build.85).
 *  Portions Copyright (c) 2026 ClearKey Solutions, LLC. MIT License:
 *  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the
 *  "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish,
 *  distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to
 *  the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions
 *  of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 *  WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 *  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. */
(function () {
  'use strict';

  var SVG_NS = 'http://www.w3.org/2000/svg';
  // A session link: https, a Viadere link domain, /v/ and eight characters of the code alphabet (no I, O, 0, 1). Nothing else is rendered.
  var LINK = /^https:\/\/(viadere\.io|viadere\.cksites\.dev)\/v\/([A-HJ-NP-Z2-9]{8})$/;
  // Labels per flow. Only "verify" exists today; a sign-in flow adds its own entry and copy here.
  var FLOWS = {
    verify: {
      label: 'Verify with Viadere',
      title: 'Verify with Viadere',
      scan: 'Scan with the Viadere app',
      scanQR: 'Scan with your phone’s camera',
      explain: 'Viadere opens and shows you which verified business is asking and exactly what it would learn. Nothing is shared until you approve.'
    }
  };
  var MARK_PATHS = [
    ['M0 46C31.34 46 52.61 53.08 58.62 61.38L88.74 102.99L115.22 66.49C130.87 44.9 156.4 45.68 170.7 68.18L189.31 97.44L215.59 61.52C231.34 40 256.71 40.99 270.74 63.66L321.71 146C290.37 146 271.7 141.91 268.73 137.12L240.79 91.98L213.57 129.17C198.67 149.53 174.45 148.74 160.91 127.45L141.09 96.28L116.14 130.69C101.32 151.11 76.1 151.1 61.31 130.67L0 46Z', '0.62'],
    ['M0 46C31.34 46 52.61 53.08 58.62 61.38L88.74 102.99C101.18 120.16 102.65 139.14 118.23 127.81L116.14 130.69C101.32 151.11 76.1 151.1 61.31 130.67L0 46Z', null],
    ['M113.12 69.37L115.22 66.49C130.87 44.9 156.4 45.68 170.7 68.18L189.31 97.44C200.84 115.58 199.82 137.73 215.67 126.3L213.57 129.17C198.67 149.53 174.45 148.74 160.91 127.45L141.09 96.28C129.64 78.27 128.81 57.95 113.12 69.37Z', null],
    ['M213.49 64.4L215.59 61.52C231.34 40 256.71 40.99 270.74 63.66L321.71 146C290.37 146 271.7 141.91 268.73 137.12L240.79 91.98C229.56 73.83 229.23 53.05 213.49 64.4Z', null]
  ];

  // ---------------------------------------------------------------------------------------------------------------------------------
  // QR code (ISO/IEC 18004): byte mode, error correction level M, versions 1 to 10, best of the eight masks. A session link is 29 to 38
  // bytes, so it always fits in version 3 or 4.
  var ECC_PER_BLOCK = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26];
  var ECC_BLOCKS = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5];

  function rawModules(ver) {
    var result = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
      var n = Math.floor(ver / 7) + 2;
      result -= (25 * n - 10) * n - 55;
      if (ver >= 7) result -= 36;
    }
    return result;
  }
  function dataCodewords(ver) { return Math.floor(rawModules(ver) / 8) - ECC_PER_BLOCK[ver] * ECC_BLOCKS[ver]; }

  function gfMul(x, y) {
    var z = 0;
    for (var i = 7; i >= 0; i--) {
      z = (z << 1) ^ ((z >>> 7) * 0x11D);
      z ^= ((y >>> i) & 1) * x;
    }
    return z & 0xFF;
  }
  function rsDivisor(degree) {
    var result = [];
    for (var i = 0; i < degree - 1; i++) result.push(0);
    result.push(1);
    var root = 1;
    for (i = 0; i < degree; i++) {
      for (var j = 0; j < result.length; j++) {
        result[j] = gfMul(result[j], root);
        if (j + 1 < result.length) result[j] ^= result[j + 1];
      }
      root = gfMul(root, 0x02);
    }
    return result;
  }
  function rsRemainder(data, divisor) {
    var result = divisor.map(function () { return 0; });
    data.forEach(function (b) {
      var factor = b ^ result.shift();
      result.push(0);
      divisor.forEach(function (coef, i) { result[i] ^= gfMul(coef, factor); });
    });
    return result;
  }

  function qrMatrix(text) {
    var bytes = Array.from(new TextEncoder().encode(String(text)));
    var ver = 0;
    for (var v = 1; v <= 10; v++) {
      if (4 + (v < 10 ? 8 : 16) + 8 * bytes.length <= dataCodewords(v) * 8) { ver = v; break; }
    }
    if (!ver) return null;
    // Data bits: mode, length, bytes, terminator, padding.
    var bits = [];
    function put(value, length) { for (var i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1); }
    put(4, 4);
    put(bytes.length, ver < 10 ? 8 : 16);
    bytes.forEach(function (b) { put(b, 8); });
    var capacity = dataCodewords(ver) * 8;
    put(0, Math.min(4, capacity - bits.length));
    put(0, (8 - bits.length % 8) % 8);
    for (var pad = 0xEC; bits.length < capacity; pad ^= 0xEC ^ 0x11) put(pad, 8);
    var data = [];
    for (var k = 0; k < bits.length; k += 8) {
      var byte = 0;
      for (var b2 = 0; b2 < 8; b2++) byte = (byte << 1) | bits[k + b2];
      data.push(byte);
    }
    // Error correction and interleaving.
    var numBlocks = ECC_BLOCKS[ver], eccLen = ECC_PER_BLOCK[ver], rawCodewords = Math.floor(rawModules(ver) / 8);
    var numShort = numBlocks - rawCodewords % numBlocks, shortLen = Math.floor(rawCodewords / numBlocks);
    var divisor = rsDivisor(eccLen), blocks = [], offset = 0;
    for (var bi = 0; bi < numBlocks; bi++) {
      var dat = data.slice(offset, offset + shortLen - eccLen + (bi < numShort ? 0 : 1));
      offset += dat.length;
      var ecc = rsRemainder(dat, divisor);
      if (bi < numShort) dat.push(0);
      blocks.push(dat.concat(ecc));
    }
    var codewords = [];
    for (var ci = 0; ci < blocks[0].length; ci++) {
      blocks.forEach(function (block, j) { if (ci !== shortLen - eccLen || j >= numShort) codewords.push(block[ci]); });
    }

    var size = ver * 4 + 17, modules = [], fn = [];
    for (var y = 0; y < size; y++) { modules.push(new Array(size).fill(false)); fn.push(new Array(size).fill(false)); }
    function setFn(x, yy, dark) { modules[yy][x] = dark; fn[yy][x] = true; }
    function finder(cx, cy) {
      for (var dy = -4; dy <= 4; dy++) for (var dx = -4; dx <= 4; dx++) {
        var dist = Math.max(Math.abs(dx), Math.abs(dy)), xx = cx + dx, yy = cy + dy;
        if (xx >= 0 && xx < size && yy >= 0 && yy < size) setFn(xx, yy, dist !== 2 && dist !== 4);
      }
    }
    function alignment(cx, cy) {
      for (var dy = -2; dy <= 2; dy++) for (var dx = -2; dx <= 2; dx++) setFn(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
    function formatBits(mask) {
      var d = (0 << 3) | mask, rem = d; // level M = 0b00
      for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
      var f = ((d << 10) | rem) ^ 0x5412;
      function bit(i2) { return ((f >>> i2) & 1) !== 0; }
      for (i = 0; i <= 5; i++) setFn(8, i, bit(i));
      setFn(8, 7, bit(6)); setFn(8, 8, bit(7)); setFn(7, 8, bit(8));
      for (i = 9; i < 15; i++) setFn(14 - i, 8, bit(i));
      for (i = 0; i < 8; i++) setFn(size - 1 - i, 8, bit(i));
      for (i = 8; i < 15; i++) setFn(8, size - 15 + i, bit(i));
      setFn(8, size - 8, true);
    }
    for (var t = 0; t < size; t++) { setFn(6, t, t % 2 === 0); setFn(t, 6, t % 2 === 0); }
    finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
    if (ver > 1) {
      var n = Math.floor(ver / 7) + 2, step = Math.ceil((ver * 4 + 4) / (n * 2 - 2)) * 2, pos = [6];
      for (var p = size - 7; pos.length < n; p -= step) pos.splice(1, 0, p);
      for (var ai = 0; ai < n; ai++) for (var aj = 0; aj < n; aj++) {
        if (!((ai === 0 && aj === 0) || (ai === 0 && aj === n - 1) || (ai === n - 1 && aj === 0))) alignment(pos[ai], pos[aj]);
      }
    }
    formatBits(0);
    if (ver >= 7) {
      var r = ver;
      for (var vi = 0; vi < 12; vi++) r = (r << 1) ^ ((r >>> 11) * 0x1F25);
      var vb = (ver << 12) | r;
      for (vi = 0; vi < 18; vi++) {
        var vbit = ((vb >>> vi) & 1) !== 0, va = size - 11 + vi % 3, vbb = Math.floor(vi / 3);
        setFn(va, vbb, vbit); setFn(vbb, va, vbit);
      }
    }
    // Codewords in the zig-zag order.
    var idx = 0;
    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (var vert = 0; vert < size; vert++) for (var jj = 0; jj < 2; jj++) {
        var x = right - jj, upward = ((right + 1) & 2) === 0, yy2 = upward ? size - 1 - vert : vert;
        if (!fn[yy2][x] && idx < codewords.length * 8) {
          modules[yy2][x] = ((codewords[idx >>> 3] >>> (7 - (idx & 7))) & 1) !== 0;
          idx++;
        }
      }
    }
    function applyMask(mask) {
      for (var my = 0; my < size; my++) for (var mx = 0; mx < size; mx++) {
        var inv;
        switch (mask) {
          case 0: inv = (mx + my) % 2 === 0; break;
          case 1: inv = my % 2 === 0; break;
          case 2: inv = mx % 3 === 0; break;
          case 3: inv = (mx + my) % 3 === 0; break;
          case 4: inv = (Math.floor(mx / 3) + Math.floor(my / 2)) % 2 === 0; break;
          case 5: inv = mx * my % 2 + mx * my % 3 === 0; break;
          case 6: inv = (mx * my % 2 + mx * my % 3) % 2 === 0; break;
          default: inv = ((mx + my) % 2 + mx * my % 3) % 2 === 0;
        }
        if (inv && !fn[my][mx]) modules[my][mx] = !modules[my][mx];
      }
    }
    function addHistory(len, h) { if (h[0] === 0) len += size; h.pop(); h.unshift(len); }
    function countPatterns(h) {
      var c = h[1], core = c > 0 && h[2] === c && h[3] === c * 3 && h[4] === c && h[5] === c;
      return (core && h[0] >= c * 4 && h[6] >= c ? 1 : 0) + (core && h[6] >= c * 4 && h[0] >= c ? 1 : 0);
    }
    function terminate(color, len, h) {
      if (color) { addHistory(len, h); len = 0; }
      len += size;
      addHistory(len, h);
      return countPatterns(h);
    }
    function penalty() {
      var score = 0, dark = 0;
      for (var pass = 0; pass < 2; pass++) {
        for (var a = 0; a < size; a++) {
          var color = false, run = 0, h = [0, 0, 0, 0, 0, 0, 0];
          for (var b = 0; b < size; b++) {
            var m = pass === 0 ? modules[a][b] : modules[b][a];
            if (m === color) {
              run++;
              if (run === 5) score += 3; else if (run > 5) score++;
            } else {
              addHistory(run, h);
              if (!color) score += countPatterns(h) * 40;
              color = m;
              run = 1;
            }
          }
          score += terminate(color, run, h) * 40;
        }
      }
      for (var y3 = 0; y3 < size - 1; y3++) for (var x3 = 0; x3 < size - 1; x3++) {
        var c3 = modules[y3][x3];
        if (c3 === modules[y3][x3 + 1] && c3 === modules[y3 + 1][x3] && c3 === modules[y3 + 1][x3 + 1]) score += 3;
      }
      modules.forEach(function (row) { row.forEach(function (m2) { if (m2) dark++; }); });
      var total = size * size;
      score += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10;
      return score;
    }
    var best = 0, bestScore = Infinity;
    for (var mask = 0; mask < 8; mask++) {
      applyMask(mask);
      formatBits(mask);
      var s = penalty();
      if (s < bestScore) { best = mask; bestScore = s; }
      applyMask(mask);
    }
    applyMask(best);
    formatBits(best);
    return modules;
  }

  // ---------------------------------------------------------------------------------------------------------------------------------
  // The Viadere code: a CKey optical code (openckey.org, Profile 0, Format 0.27, standard layout), read by the Viadere app's scanner.
  // A line-for-line port of ViadereCore/OpticalCode/CKeySymbol.swift and CKeySVG.swift, themselves a verified port of the CKey reference
  // core (clearkeysolutions/ckey v0.1.0-build.85: src/core_internal.inc, src/api_codec.inc, src/api_render.inc). The browser test
  // reproduces every vector of docs/protocol/vectors/ckey-profile0-v1.json: the codeword bit for bit and the SVG byte for byte.
  // A session link is 29 to 38 bytes: a version 2 or 3 symbol at level M.
  var CK_GRID = [29, 31, 33, 36, 38, 41, 44, 47, 50, 54, 58, 62, 67, 71, 77, 82, 88, 94, 101, 108, 116, 124, 133, 143, 153, 164, 176, 188, 202, 216, 232];
  var CK_SLOTS = [72, 80, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 168, 176, 192, 200, 216, 232, 248, 272, 288, 304, 328, 352, 376, 408, 440, 464, 504, 536, 576];
  var CK_RINGS = [3, 3, 3, 4, 4, 5, 5, 6, 6, 7, 8, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 20, 22, 23, 25, 27, 29, 32, 34, 37];
  var CK_COL = [2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 7, 7, 8, 9, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21, 23];
  var CK_ROW = [10, 12, 13, 14, 15, 16, 17, 18, 20, 21, 23, 25, 27, 28, 31, 33, 35, 38, 41, 44, 47, 50, 54, 58, 62, 67, 72, 77, 83, 88, 95];
  var CK_PARITY = [14, 28, 44, 60]; // percent of each block, levels L, M, Q, H
  var CK_C = 14.5, CK_TAU = 6.283185307179586476925286766559, CK_RING0 = 3.4, CK_DIAL0 = 7.6;
  var ckExp = [], ckLog = [], ckLayouts = {};
  (function () {
    for (var i = 0, x = 1; i < 255; i++) {
      ckExp[i] = x; ckLog[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11D;
    }
    for (i = 255; i < 512; i++) ckExp[i] = ckExp[i - 255];
  })();
  function ckMul(a, b) { return a && b ? ckExp[ckLog[a] + ckLog[b]] : 0; }
  function ckCrc32c(bytes) {
    var crc = 0xFFFFFFFF;
    bytes.forEach(function (b) {
      crc ^= b;
      for (var k = 0; k < 8; k++) crc = (crc >>> 1) ^ (0x82F63B78 & -(crc & 1));
    });
    return ~crc >>> 0;
  }
  // SplitMix32 (the fill for unused frame bytes and the whitening sequence); `state` is a one-element array.
  function ckPad(state) {
    var v = state[0] = (state[0] + 0x9E3779B9) >>> 0;
    v = Math.imul(v ^ (v >>> 16), 0x85EBCA6B);
    v = Math.imul(v ^ (v >>> 13), 0xC2B2AE35);
    return (v ^ (v >>> 16)) & 0xFF;
  }
  // lowbias32: a bijection on 32-bit words, so distinct sites never tie.
  function ckHash(x) {
    x ^= x >>> 16; x = Math.imul(x, 0x7FEB352D); x ^= x >>> 15; x = Math.imul(x, 0x846CA68B); x ^= x >>> 16;
    return x >>> 0;
  }
  // The codeword is split into ceil(C/255) near-equal blocks (longer ones first); each keeps 2*round(pct*n/200) parity bytes.
  function ckBlocks(codewordBytes, level) {
    var count = Math.floor((codewordBytes + 254) / 255), blocks = [];
    for (var b = 0; b < count; b++) {
      var n = Math.floor(codewordBytes / count) + (b < codewordBytes % count ? 1 : 0);
      var parity = Math.max(2, 2 * Math.floor((CK_PARITY[level] * n + 100) / 200));
      blocks.push({ n: n, k: n - Math.min(parity, n - 1) });
    }
    return blocks;
  }
  function ckDataBytes(blocks) { return blocks.reduce(function (sum, b) { return sum + b.k; }, 0); }
  function ckCapacity(version, level) {
    var data = ckDataBytes(ckBlocks(ckLayout(version).bytes, level));
    return data > 12 ? Math.min(data - 12, 65535) : 0; // header (8) + CRC-32C (4)
  }

  // Where every mark of a version sits. Sites are {kind (0 Cartesian module, 1 dial ray, 2 ring dot), x, y, ring, slot, id}, in placement order.
  function ckLayout(v) {
    if (ckLayouts[v]) return ckLayouts[v];
    var i = v - 1, grid = CK_GRID[i], slots = CK_SLOTS[i], rings = CK_RINGS[i], col0 = CK_COL[i], row0 = CK_ROW[i], p = 29.0 / grid;
    // The clearances a Cartesian module keeps: frame, corner finders, Grid Key, the polar field and the Ray Keys.
    var e = 0.34 * p * 1.4142135623730951, clear = Math.max(0.375, p), finderNeed = 0.4 + e + clear;
    var gx0 = col0 * p + 0.16 * p, gy0 = row0 * p + 0.16 * p, gx1 = (col0 + 2) * p - 0.16 * p, gy1 = (row0 + 2) * p - 0.16 * p;
    var rayOuter = CK_DIAL0 + 2.2 * p + 0.2 * p / 2, keyA = CK_TAU * (3.0 * slots / 4.0 - 2.0) / slots;
    var keyRays = [[0.0, -1.0, 1.0], [-1.0, 0.0, 0.5], [Math.sin(keyA), -Math.cos(keyA), 0.75]];
    function finder(x, y, cx, cy, right, bottom) {
      var dx = x - cx, dy = y - cy, r = 2.3;
      if (right) dx = -dx;
      if (bottom) dy = -dy;
      if (dx <= 0 && dy <= 0) return Math.abs(Math.sqrt(dx * dx + dy * dy) - r);
      var ex = dx + r, ey = dy + r;
      return Math.min(Math.sqrt(ex * ex + dy * dy), Math.sqrt(dx * dx + ey * ey));
    }
    function segment(x, y, x0, y0, x1, y1) {
      var vx = x1 - x0, vy = y1 - y0, wx = x - x0, wy = y - y0;
      var t = Math.min(Math.max((wx * vx + wy * vy) / (vx * vx + vy * vy), 0.0), 1.0);
      var px = x0 + t * vx - x, py = y0 + t * vy - y;
      return Math.sqrt(px * px + py * py);
    }
    function margin(x, y) {
      var qx = Math.abs(x - 14.5) - (14.0 - 3.5), qy = Math.abs(y - 14.5) - (14.0 - 3.5), ox = Math.max(qx, 0.0), oy = Math.max(qy, 0.0);
      var m = -(Math.sqrt(ox * ox + oy * oy) + Math.min(Math.max(qx, qy), 0.0) - 3.5) - 0.325 - e - clear;
      m = Math.min(m, finder(x, y, 4.0, 4.0, false, false) - finderNeed);
      m = Math.min(m, finder(x, y, 25.0, 4.0, true, false) - finderNeed);
      m = Math.min(m, finder(x, y, 4.0, 25.0, false, true) - finderNeed);
      m = Math.min(m, finder(x, y, 25.0, 25.0, true, true) - finderNeed);
      var gx = Math.max(gx0 - x, 0.0, x - gx1), gy = Math.max(gy0 - y, 0.0, y - gy1);
      m = Math.min(m, Math.sqrt(gx * gx + gy * gy) - e - p);
      var dx = x - CK_C, dy = y - CK_C;
      m = Math.min(m, Math.sqrt(dx * dx + dy * dy) - rayOuter - e - p);
      keyRays.forEach(function (ray) {
        var r1 = CK_DIAL0 + 3.4 * p * ray[2], ux = ray[0], uy = ray[1];
        m = Math.min(m, segment(x, y, CK_C + CK_DIAL0 * ux, CK_C + CK_DIAL0 * uy, CK_C + r1 * ux, CK_C + r1 * uy) - 0.22 * p - e - p);
      });
      return m;
    }
    var placement = ckHash((0x434B5030 ^ v) >>> 0), nodes = []; // "CKP0"
    function add(kind, x, y, ring, slot, a, b) {
      var id = ((kind << 24) | (a << 12) | b) >>> 0;
      nodes.push({ kind: kind, x: x, y: y, ring: ring, slot: slot, id: id, order: ckHash((id ^ placement) >>> 0) });
    }
    for (var row = 0; row < grid; row++) for (var col = 0; col < grid; col++) {
      var x = (col + 0.5) * p, y = (row + 0.5) * p;
      if (margin(x, y) > 0.0) add(0, x, y, -1, -1, row, col);
    }
    var keyHalf = Math.floor(3 * slots / 4), keyThree = keyHalf - 2, ringKey = Math.floor(slots / 4);
    function reserved(slot) { return slot === 0 || slot === keyHalf || slot === keyThree; }
    for (var slot = 0; slot < slots; slot++) if (!reserved(slot)) add(1, 0, 0, -1, slot, 0, slot);
    for (var ring = 0; ring < rings; ring++) for (slot = 0; slot < slots; slot++) {
      // Ring slots are also cleared on the Ray Key bearings, and the Ring Key owns sixteen slots of the outermost ring.
      if (reserved(slot) || (ring === rings - 1 && slot >= ringKey && slot < ringKey + 16)) continue;
      var r = CK_RING0 + 0.86 * p * ring, a = CK_TAU * slot / slots;
      add(2, CK_C + r * Math.sin(a), CK_C - r * Math.cos(a), ring, slot, ring, slot);
    }
    nodes.sort(function (n1, n2) { return n1.order - n2.order; });
    var state = [(0x434B5730 + v) >>> 0], white = [], byte = 0; // "CKW0"
    for (var n = 0; n < nodes.length; n++) {
      if (n % 8 === 0) byte = ckPad(state);
      white.push(((byte >>> (7 - n % 8)) & 1) !== 0);
    }
    return (ckLayouts[v] = { slots: slots, rings: rings, col0: col0, row0: row0, pitch: p, nodes: nodes, white: white,
      bytes: Math.floor(nodes.length / 8), keyHalf: keyHalf, keyThree: keyThree, ringKey: ringKey });
  }

  // Encodes text (as UTF-8) or an array of bytes. `level` 0 to 3 (L, M, Q, H; default M); `version` 1 to 31, or 0 / absent for the
  // smallest that fits. Returns null when the arguments are out of range or the payload does not fit.
  function ckEncode(data, level, version) {
    var payload = typeof data === 'string' ? Array.from(new TextEncoder().encode(data)) : Array.prototype.slice.call(data);
    level = level === undefined ? 1 : level;
    var v = version || 0, i, j, b;
    if ([0, 1, 2, 3].indexOf(level) < 0 || v > 31 || [v].concat(payload).some(function (x) { return x !== (x & 0xFF); })) return null;
    if (!v) for (v = 1; v <= 31 && ckCapacity(v, level) < payload.length;) v++;
    if (v > 31 || ckCapacity(v, level) < payload.length) return null;
    var blocks = ckBlocks(ckLayout(v).bytes, level);
    // Frame: magic, format, profile, version, level, length, payload, CRC-32C, then the normative SplitMix32 fill.
    var framed = [0xC7, 0x4B, 0x1B, 0, v, level, payload.length >>> 8, payload.length & 0xFF].concat(payload);
    var crc = ckCrc32c(framed);
    for (b = 0; b < 4; b++) framed.push((crc >>> (24 - 8 * b)) & 0xFF);
    for (var state = [ckCrc32c(framed)], total = ckDataBytes(blocks); framed.length < total;) framed.push(ckPad(state));
    // Reed-Solomon per block (systematic), then byte-interleave so local damage spreads over every block.
    var coded = [], offset = 0;
    blocks.forEach(function (block) {
      var parity = block.n - block.k, generator = [1], dataPart = framed.slice(offset, offset + block.k), work = dataPart.slice();
      offset += block.k;
      for (var root = 0; root < parity; root++) {
        var next = generator.concat([0]).map(function () { return 0; });
        for (i = 0; i < generator.length; i++) {
          next[i] ^= generator[i];
          next[i + 1] ^= ckMul(generator[i], ckExp[root]);
        }
        generator = next;
      }
      for (i = 0; i < parity; i++) work.push(0);
      for (i = 0; i < block.k; i++) {
        var feedback = work[i];
        if (feedback) for (j = 1; j <= parity; j++) work[i + j] ^= ckMul(generator[j], feedback);
      }
      coded.push(dataPart.concat(work.slice(block.k)));
    });
    var codeword = [];
    for (j = 0; j < blocks[0].n; j++) for (b = 0; b < blocks.length; b++) if (j < blocks[b].n) codeword.push(coded[b][j]);
    return { version: v, level: level, codeword: codeword };
  }

  // ---------------------------------------------------------------------------------------------------------------------------------
  // DOM helpers: elements, attributes and text only. Never markup strings, never `style` or event-handler attributes.

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    (children || []).forEach(function (c) { node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return node;
  }
  function svg(tag, attrs) {
    var node = document.createElementNS(SVG_NS, tag);
    Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    return node;
  }
  function mark(cls) {
    var root = svg('svg', { 'class': cls, viewBox: '0 0 321.71 146', 'aria-hidden': 'true', focusable: 'false' });
    MARK_PATHS.forEach(function (p) {
      var path = svg('path', { d: p[0], fill: 'currentColor' });
      if (p[1]) path.setAttribute('opacity', p[1]);
      root.appendChild(path);
    });
    root.appendChild(svg('circle', { cx: '155.21', cy: '20.5', r: '20.5', fill: 'currentColor' }));
    return root;
  }
  function qrSVG(text) {
    var m = qrMatrix(text);
    if (!m) return null;
    var size = m.length, quiet = 4, d = '';
    for (var y = 0; y < size; y++) for (var x = 0; x < size; x++) if (m[y][x]) d += 'M' + (x + quiet) + ' ' + (y + quiet) + 'h1v1h-1z';
    var full = size + quiet * 2;
    var root = svg('svg', { 'class': 'vdv-qr', viewBox: '0 0 ' + full + ' ' + full, role: 'img', 'aria-label': 'QR code to continue in the Viadere app',
      'shape-rendering': 'crispEdges' });
    root.appendChild(svg('rect', { width: String(full), height: String(full), fill: '#FFFFFF' }));
    root.appendChild(svg('path', { d: d, fill: '#1F1E1C' }));
    return root;
  }

  // The CKey as an SVG element: the reference's "concept" preset (cream metallic ink on a dark vignette, a few muted accent marks),
  // element for element and attribute for attribute what `ckey_render_scalable_styled_svg` prints, so that its XML serialization is
  // the reference's output byte for byte (the browser test compares SHA-256 for every vector). Only this certified preset is
  // offered: another style would need the reference's scan-safety checks, which are not ported. Attributes only, never `style`.
  //
  // Ids: the reference uses the fixed ids ckey-ink, ckey-bg, ckey-grain and ckey-depth. An id must be unique in a document, and a
  // page can hold several buttons (and other CKeys of its own), so the panel passes `idSuffix` = "-" + its own unique panel id
  // ("-vdv-3"), which no other element shares. Without a suffix (the static test hook) the ids are the reference's.
  function ckeySVG(symbol, idSuffix, label) {
    var L = ckLayout(symbol.version), p = L.pitch, dot = 0.2 * p, slots = L.slots, sfx = idSuffix || '';
    var ink = 'url(#ckey-ink' + sfx + ')', accents = ['#a9b896', '#9ea1a6'];
    function f(x) { return x.toFixed(4); } // "%.4f", as the reference prints every coordinate
    function node(tag, attrs, children) {
      var n = svg(tag, attrs);
      (children || []).forEach(function (c) { n.appendChild(c); });
      return n;
    }
    function stop(offset, colour) { return svg('stop', { offset: offset, 'stop-color': colour }); }
    function px(r, a) { return f(CK_C + r * Math.sin(a)); }
    function py(r, a) { return f(CK_C - r * Math.cos(a)); }
    // A rounded square module centred at (cx, cy).
    function module(cx, cy, fill) {
      var h = 0.34 * p, m = svg('rect', { x: f(cx - h), y: f(cy - h), width: f(2 * h), height: f(2 * h), rx: f(0.16 * p), stroke: 'none' });
      if (fill) m.setAttribute('fill', fill);
      return m;
    }
    function ray(slot, length, width) {
      var a = CK_TAU * slot / slots, r1 = CK_DIAL0 + length;
      return svg('path', { d: 'M ' + px(CK_DIAL0, a) + ' ' + py(CK_DIAL0, a) + ' L ' + px(r1, a) + ' ' + py(r1, a), fill: 'none',
        'stroke-width': f(width), 'stroke-linecap': 'round' });
    }
    // A run of adjacent ring sites as one round-capped arc. Caps add a dot diameter, so the centreline is shortened by a dot radius
    // at each end; a run over half a turn sets the large-arc flag.
    function ringRun(radius, from, to) {
      var cap = dot / radius, a0 = CK_TAU * from / slots + cap, a1 = CK_TAU * to / slots - cap;
      return svg('path', { d: 'M ' + px(radius, a0) + ' ' + py(radius, a0) + ' A ' + f(radius) + ' ' + f(radius) + ' 0 ' + (a1 - a0 > CK_TAU / 2 ? 1 : 0) +
        ' 1 ' + px(radius, a1) + ' ' + py(radius, a1), fill: 'none', 'stroke-width': f(2 * dot), 'stroke-linecap': 'round' });
    }
    function ringDot(radius, slot, fill) {
      var a = CK_TAU * slot / slots, c = svg('circle', { cx: px(radius, a), cy: py(radius, a), r: f(dot), stroke: 'none' });
      if (fill) c.setAttribute('fill', fill);
      return c;
    }
    function group(cls, children) { return node('g', { 'class': cls }, children); }

    // Materials: ink sheen, background vignette, paper grain, and depth (drop shadow and bevel).
    var defs = node('defs', {}, [
      node('linearGradient', { id: 'ckey-ink' + sfx, gradientUnits: 'userSpaceOnUse', x1: '0', y1: '0', x2: '29', y2: '29' },
        [stop('0', '#f6eee0'), stop('0.55', '#c8b69a'), stop('1', '#f6eee0')]),
      node('radialGradient', { id: 'ckey-bg' + sfx, gradientUnits: 'userSpaceOnUse', cx: '14.5', cy: '14.5', r: '21' }, [stop('0', '#14161e'), stop('1', '#07080c')]),
      node('filter', { id: 'ckey-grain' + sfx, x: '0', y: '0', width: '100%', height: '100%' }, [
        svg('feTurbulence', { type: 'fractalNoise', baseFrequency: '1.7', numOctaves: '2', seed: '7' }),
        svg('feColorMatrix', { type: 'saturate', values: '0' })]),
      node('filter', { id: 'ckey-depth' + sfx, x: '-2%', y: '-2%', width: '104%', height: '104%', 'color-interpolation-filters': 'sRGB' }, [
        svg('feDropShadow', { dx: '0.05', dy: '0.09', stdDeviation: '0.07', 'flood-color': '#000000', 'flood-opacity': f(0.75 * 0.5), result: 'shadowed' }),
        svg('feGaussianBlur', { 'in': 'SourceAlpha', stdDeviation: '0.045', result: 'bump' }),
        node('feSpecularLighting', { 'in': 'bump', surfaceScale: '3', specularConstant: f(1.1 * 0.6), specularExponent: '16', 'lighting-color': '#ffffff', result: 'spec' },
          [svg('feDistantLight', { azimuth: '225', elevation: '40' })]),
        svg('feComposite', { 'in': 'spec', in2: 'SourceAlpha', operator: 'in', result: 'shine' }),
        svg('feComposite', { 'in': 'shine', in2: 'shadowed', operator: 'arithmetic', k1: '0', k2: '1', k3: '1', k4: '0' })])]);

    // Corner finders: one inset arc per corner; only the top-left arc is interrupted (the orientation signature).
    var inset = 4.0, radius = 2.3, thickness = 0.8, halfGap = (0.95 + thickness) / (2.0 * radius), middle = 5.0 * CK_TAU / 8.0;
    var a1 = middle - halfGap, a2 = middle + halfGap;
    var arcFrom = 'M ' + f(inset - radius) + ' ' + f(inset) + ' A ' + f(radius) + ' ' + f(radius) + ' 0 0 1 ';
    var arcTo = f(inset) + ' ' + f(inset - radius);
    var finders = ['', 'translate(29.000000 0) scale(-1 1)', 'translate(29.000000 29.000000) scale(-1 -1)', 'translate(0 29.000000) scale(1 -1)'].map(function (transform, corner) {
      var d = corner ? arcFrom + arcTo : arcFrom + f(inset + radius * Math.cos(a1)) + ' ' + f(inset + radius * Math.sin(a1)) +
        ' M ' + f(inset + radius * Math.cos(a2)) + ' ' + f(inset + radius * Math.sin(a2)) + ' A ' + f(radius) + ' ' + f(radius) + ' 0 0 1 ' + arcTo;
      return node('g', { transform: transform, fill: 'none', 'stroke-linecap': 'round' }, [svg('path', { d: d, 'stroke-width': f(thickness) })]);
    });

    // Calibration keys: the Grid Key (2 x 2 modules), three Ray Keys (full, half and three-quarter length) and the Ring Key.
    var gridKey = [];
    for (var r = 0; r < 2; r++) for (var cc = 0; cc < 2; cc++) gridKey.push(module((L.col0 + cc + 0.5) * p, (L.row0 + r + 0.5) * p, null));
    var keyRay = 3.4 * p, rk = CK_RING0 + 0.86 * p * (L.rings - 1), k = L.ringKey;
    var polarKeys = [ray(0, keyRay * 1.0, 0.44 * p), ray(L.keyHalf, keyRay * 0.5, 0.44 * p), ray(L.keyThree, keyRay * 0.75, 0.44 * p),
      ringDot(rk, k, null), ringDot(rk, k + 2, null), ringDot(rk, k + 6, null), ringRun(rk, k + 7.5, k + 15.5)];

    // Data: dial rays in placement order, then ring runs, then the Cartesian modules. A site is printed when its codeword bit,
    // whitened, is one; a few sites take an accent colour (decorative: styling never changes where a reader samples).
    var polar = [], cartesian = [], ringBits = [], ringAccent = [];
    L.nodes.forEach(function (n, i) {
      var data = i < L.bytes * 8 && ((symbol.codeword[i >>> 3] >>> (7 - i % 8)) & 1) !== 0, bit = data !== L.white[i];
      var h = ckHash((n.id ^ 0x41434345) >>> 0), accent = h % 100 < 18 ? accents[Math.floor(h / 100) % 2] : null; // "ACCE"
      if (n.kind === 0) { if (bit) cartesian.push(module(n.x, n.y, accent)); }
      else if (n.kind === 1) polar.push(ray(n.slot, (bit ? 2.2 : 1.0) * p, 0.2 * p));
      else { ringBits[n.ring * slots + n.slot] = bit; ringAccent[n.ring * slots + n.slot] = accent; }
    });
    for (var ring = 0; ring < L.rings; ring++) {
      var rr = CK_RING0 + 0.86 * p * ring;
      for (var slot = 0; slot < slots;) {
        var at = ring * slots + slot, end = slot + 1;
        if (!ringBits[at]) { slot++; continue; }
        while (end < slots && ringBits[ring * slots + end]) end++;
        if (end - slot === 1) polar.push(ringDot(rr, slot, ringAccent[at]));
        else {
          var run = ringRun(rr, slot - 0.5, end - 0.5);
          polar.push(ringAccent[at] ? node('g', { stroke: ringAccent[at] }, [run]) : run);
        }
        slot = end;
      }
    }

    return node('svg', { width: '496', height: '496', viewBox: '-1 -1 31 31', role: 'img', 'aria-label': label || 'CKey scalable symbol profile 0 version ' + symbol.version }, [
      defs,
      svg('rect', { x: '-1', y: '-1', width: '31', height: '31', fill: 'url(#ckey-bg' + sfx + ')' }),
      svg('rect', { x: '-1', y: '-1', width: '31', height: '31', filter: 'url(#ckey-grain' + sfx + ')', opacity: f(0.18 * 0.4) }),
      node('g', { fill: ink, stroke: ink, filter: 'url(#ckey-depth' + sfx + ')' }, [
        group('ckey-frame', [svg('rect', { x: '0.5', y: '0.5', width: '28', height: '28', rx: '3.5', fill: 'none', 'stroke-width': '0.65' })]),
        group('ckey-finders', finders), group('ckey-grid-key', gridKey), group('ckey-polar-keys', polarKeys),
        group('ckey-data-polar', polar), group('ckey-data-cartesian', cartesian)])]);
  }

  // A phone or tablet, where the operating system can hand a universal link / App Link to the installed Viadere app (or show the landing
  // page with the App Store link when it is not installed). Everything else gets the panel with the Viadere code first.
  function isHandheld() {
    var nav = window.navigator || {};
    if (nav.userAgentData && typeof nav.userAgentData.mobile === 'boolean' && nav.userAgentData.mobile) return true;
    var ua = String(nav.userAgent || '');
    if (/iPhone|iPad|iPod|Android/i.test(ua)) return true;
    // iPadOS presents itself as a Mac.
    return /Macintosh/.test(ua) && (nav.maxTouchPoints || 0) > 1;
  }

  function formatCode(code) { return code.slice(0, 4) + '‑' + code.slice(4); }

  var counter = 0;

  class ViadereVerify extends HTMLElement {
    static get observedAttributes() { return ['link', 'variant', 'size', 'display', 'theme', 'expires-at', 'send-to-phone', 'flow']; }

    /** The QR module matrix of `text` (rows of booleans), exposed for tests and for integrators who draw their own QR. */
    static qr(text) { return qrMatrix(text); }

    /** The CKey (Profile 0) of `data` (text, or an array of bytes): `{version, level, codeword}` with the codeword as lower-case hex, or
     *  null when it does not fit. `level` 0 to 3 (default 1, M, which the panel uses); `version` 1 to 31 (default: the smallest that
     *  fits). Exposed for tests. */
    static ckey(data, level, version) {
      var symbol = ckEncode(data, level, version);
      return symbol && { version: symbol.version, level: symbol.level,
        codeword: symbol.codeword.map(function (b) { return (b < 16 ? '0' : '') + b.toString(16); }).join('') };
    }

    /** The same CKey as a detached SVG element in the "concept" style, with the reference renderer's ids and label. Exposed for tests. */
    static ckeySVG(data, level, version) {
      var symbol = ckEncode(data, level, version);
      return symbol && ckeySVG(symbol);
    }

    connectedCallback() { this.render(); }
    disconnectedCallback() { this.close(); }
    attributeChangedCallback() { if (this.isConnected) this.render(); }

    get session() {
      var match = LINK.exec(String(this.getAttribute('link') || ''));
      return match ? { link: match[0], code: match[2] } : null;
    }

    render() {
      this.close();
      while (this.firstChild) this.removeChild(this.firstChild);
      var session = this.session;
      if (!session) return;
      var flow = FLOWS[this.getAttribute('flow') || 'verify'] || FLOWS.verify;
      var variant = ['filled', 'ivory', 'outline'].indexOf(this.getAttribute('variant')) >= 0 ? this.getAttribute('variant') : 'filled';
      var size = ['sm', 'md', 'lg'].indexOf(this.getAttribute('size')) >= 0 ? this.getAttribute('size') : 'md';
      var iconOnly = this.getAttribute('display') === 'icon';
      var theme = ['light', 'dark'].indexOf(this.getAttribute('theme')) >= 0 ? this.getAttribute('theme') : 'auto';
      this.setAttribute('data-vdv-theme', theme);
      var button = el('a', { 'class': 'vdv-btn vdv-' + variant + ' vdv-' + size + (iconOnly ? ' vdv-icon' : ''), href: session.link,
        rel: 'noopener noreferrer', referrerpolicy: 'no-referrer', 'aria-haspopup': 'dialog' });
      button.appendChild(mark('vdv-mark'));
      if (iconOnly) button.setAttribute('aria-label', flow.label);
      else button.appendChild(el('span', { 'class': 'vdv-label' }, [flow.label]));
      var self = this;
      button.addEventListener('click', function (event) {
        // Phones hand the link to the app by universal link / App Link; a modified click keeps the browser's own behaviour.
        if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || isHandheld()) return;
        if (typeof HTMLDialogElement !== 'function' || !HTMLDialogElement.prototype.showModal) return;
        event.preventDefault();
        self.open();
      });
      this._button = button;
      this._flow = flow;
      this._session = session;
      this.appendChild(button);
    }

    /** Opens the panel: the Viadere code first, the QR code one control away (computers; or call it yourself). */
    open() {
      var session = this._session, flow = this._flow;
      if (!session || this._dialog) return;
      var id = 'vdv-' + (++counter);
      var dialog = el('dialog', { 'class': 'vdv-panel', 'aria-labelledby': id + '-title', 'aria-describedby': id + '-explain', 'data-vdv-theme': this.getAttribute('data-vdv-theme') || 'auto' });
      var close = el('button', { type: 'button', 'class': 'vdv-close', 'aria-label': 'Close' }, ['×']);
      var header = el('div', { 'class': 'vdv-head' }, [mark('vdv-mark'), el('h2', { id: id + '-title', 'class': 'vdv-title' }, [flow.title]), close]);
      var status = el('p', { 'class': 'vdv-status', role: 'status', 'aria-live': 'polite' });

      // View 1: the code. The Viadere code (a CKey, read by the Viadere app's scanner) first; one control swaps it for the same link
      // as a QR code, which a phone's own camera reads (also without the app), and back. Both encode exactly the validated link.
      var lead = el('p', { 'class': 'vdv-lead' });
      var qrView = el('div', { 'class': 'vdv-view', id: id + '-qr' }, [lead]);
      var symbol = ckEncode(session.link), qr = qrSVG(session.link);
      var ckeyFrame = symbol && el('div', { 'class': 'vdv-ckey-frame' }, [ckeySVG(symbol, '-' + id, 'Viadere code to scan with the Viadere app')]);
      var qrFrame = qr && el('div', { 'class': 'vdv-qr-frame' }, [qr]);
      if (ckeyFrame) qrView.appendChild(ckeyFrame);
      if (qrFrame) qrView.appendChild(qrFrame);
      // Shown instead of the switch in forced-colours (high contrast) mode, where only the QR code is offered.
      var contrast = el('p', { 'class': 'vdv-fine', hidden: '' }, ['High-contrast colours are on, so this is a QR code: the Viadere code needs its own colours. The Viadere app reads this one too.']);
      qrView.appendChild(contrast);
      qrView.appendChild(el('p', { 'class': 'vdv-explain', id: id + '-explain' }, [flow.explain]));
      var expires = Date.parse(this.getAttribute('expires-at') || '');
      if (!isNaN(expires)) {
        var time = new Date(expires);
        qrView.appendChild(el('p', { 'class': 'vdv-fine' }, ['This code works until ' + time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + '.']));
      }
      var swap = el('button', { type: 'button', 'class': 'vdv-switch' });
      if (ckeyFrame && qrFrame) qrView.appendChild(swap);
      var more = el('button', { type: 'button', 'class': 'vdv-secondary', 'aria-controls': id + '-options', 'aria-expanded': 'false' }, ['Choose another option']);
      qrView.appendChild(more);

      // View 2: the other options.
      var options = el('div', { 'class': 'vdv-view', id: id + '-options', hidden: '' });
      var list = el('ul', { 'class': 'vdv-options' });
      list.appendChild(el('li', {}, [el('a', { 'class': 'vdv-option', href: session.link, rel: 'noopener noreferrer', referrerpolicy: 'no-referrer' },
        [el('span', { 'class': 'vdv-option-title' }, ['Open Viadere on this device']), el('span', { 'class': 'vdv-option-detail' }, ['If the Viadere app is installed here.'])])]));
      var typed = el('button', { type: 'button', 'class': 'vdv-option' },
        [el('span', { 'class': 'vdv-option-title' }, ['Enter a code in the app']), el('span', { 'class': 'vdv-option-detail' }, ['Type a short code into Viadere on your phone.'])]);
      list.appendChild(el('li', {}, [typed]));
      var send = null;
      if (this.hasAttribute('send-to-phone')) {
        send = el('button', { type: 'button', 'class': 'vdv-option' },
          [el('span', { 'class': 'vdv-option-title' }, ['Send to my phone']), el('span', { 'class': 'vdv-option-detail' }, ['Get a Viadere notification on the phone linked to your account.'])]);
        list.appendChild(el('li', {}, [send]));
      }
      list.appendChild(el('li', {}, [el('a', { 'class': 'vdv-option', href: session.link, target: '_blank', rel: 'noopener noreferrer', referrerpolicy: 'no-referrer' },
        [el('span', { 'class': 'vdv-option-title' }, ['Get the Viadere app']), el('span', { 'class': 'vdv-option-detail' }, ['Free on the App Store. Then scan the code again.'])])]));
      options.appendChild(list);
      var codeBox = el('p', { 'class': 'vdv-code', hidden: '' }, ['Open Viadere, choose Enter code and type ', el('strong', { 'class': 'vdv-code-value' }, [formatCode(session.code)])]);
      options.appendChild(codeBox);
      var back = el('button', { type: 'button', 'class': 'vdv-secondary', 'aria-controls': id + '-qr' }, ['Back to the code']);
      options.appendChild(back);

      dialog.appendChild(header);
      dialog.appendChild(qrView);
      dialog.appendChild(options);
      dialog.appendChild(status);

      var self = this;
      // Which code is on screen. Forced colours replace the concept style's colours, so that mode always gets the QR code (drawn
      // black on white, exempt from colour forcing) and no switch; the choice is restored when forced colours end.
      var forced = typeof window.matchMedia === 'function' ? window.matchMedia('(forced-colors: active)') : null;
      var wantQR = !ckeyFrame;
      function showCode(announce) {
        var high = !!(forced && forced.matches), asQR = !ckeyFrame || (!!qrFrame && (wantQR || high));
        if (ckeyFrame) ckeyFrame.hidden = asQR;
        if (qrFrame) qrFrame.hidden = !asQR;
        lead.textContent = asQR ? flow.scanQR : flow.scan;
        swap.textContent = asQR ? 'Back to the Viadere code' : 'Use your phone’s camera instead';
        swap.hidden = high;
        contrast.hidden = !(high && ckeyFrame && qrFrame);
        dialog.setAttribute('data-vdv-code', asQR ? 'qr' : 'ckey');
        if (announce) status.textContent = asQR ? 'Showing a QR code for your phone’s camera.' : 'Showing the Viadere code for the Viadere app.';
      }
      function forcedChanged() {
        var focused = document.activeElement === swap;
        showCode(false);
        if (focused && swap.hidden) more.focus(); // never leave focus on a control that just disappeared
      }
      swap.addEventListener('click', function () { wantQR = !wantQR; showCode(true); });
      if (forced && forced.addEventListener) forced.addEventListener('change', forcedChanged);
      this._release = function () { if (forced && forced.removeEventListener) forced.removeEventListener('change', forcedChanged); };
      function show(view) {
        var toOptions = view === options;
        qrView.hidden = toOptions;
        options.hidden = !toOptions;
        more.setAttribute('aria-expanded', toOptions ? 'true' : 'false');
        (toOptions ? list.querySelector('.vdv-option') : more).focus();
      }
      more.addEventListener('click', function () { show(options); });
      back.addEventListener('click', function () { codeBox.hidden = true; status.textContent = ''; show(qrView); });
      typed.addEventListener('click', function () {
        codeBox.hidden = false;
        status.textContent = 'Your code is ' + session.code.split('').join(' ') + '.';
      });
      if (send) {
        send.addEventListener('click', function () {
          // Your page asks your server to send the request to this customer's phone (see the docs). The component never makes a request.
          self.dispatchEvent(new CustomEvent('viadere-verify-send', { bubbles: true, composed: true, detail: { link: session.link } }));
          status.textContent = 'Check your phone for a notification from Viadere.';
        });
      }
      close.addEventListener('click', function () { self.close(); });
      dialog.addEventListener('cancel', function (event) { event.preventDefault(); self.close(); });
      dialog.addEventListener('click', function (event) { if (event.target === dialog) self.close(); });
      // Focus stays inside the panel (showModal makes the page inert; this also wraps Tab at both ends).
      dialog.addEventListener('keydown', function (event) {
        if (event.key !== 'Tab') return;
        var focusable = Array.prototype.filter.call(dialog.querySelectorAll('a[href], button:not([disabled])'), function (node) {
          return node.offsetParent !== null || node === document.activeElement;
        });
        if (!focusable.length) return;
        var first = focusable[0], last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      });
      this._dialog = dialog;
      showCode(false);
      this.appendChild(dialog);
      dialog.showModal();
      more.focus();
      this.dispatchEvent(new CustomEvent('viadere-verify-open', { bubbles: true, composed: true }));
    }

    /** Closes the panel (call it when your server sees the session completed) and returns focus to the button. */
    close() {
      var dialog = this._dialog;
      if (!dialog) return;
      this._dialog = null;
      if (this._release) this._release();
      this._release = null;
      if (dialog.open) dialog.close();
      if (dialog.parentNode) dialog.parentNode.removeChild(dialog);
      if (this._button && this._button.isConnected) this._button.focus();
      this.dispatchEvent(new CustomEvent('viadere-verify-close', { bubbles: true, composed: true }));
    }
  }

  if (!customElements.get('viadere-verify')) customElements.define('viadere-verify', ViadereVerify);
})();
