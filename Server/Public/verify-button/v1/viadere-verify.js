/*! Verify with Viadere v1 — https://viadere.com — dependency-free web component, docs/VERIFY-BUTTON.md.
 *  No network requests, no cookies, no storage, no analytics, no iframes, no inline styles, no innerHTML (works under a strict CSP and
 *  Trusted Types). It renders a link to a verification session your SERVER created (https://viadere.com/v/{CODE}) and, where the phone
 *  cannot be handed the link directly (a computer), a QR-first panel with other options. It never sees a result: your server reads the
 *  session with its API key and verifies Viadere's signed result.
 *  Usage: <link rel="stylesheet" href=".../viadere-verify.css"> <script src=".../viadere-verify.js" defer></script>
 *         <viadere-verify link="https://viadere.com/v/ABCDEFGH"></viadere-verify>
 *  Attributes: link (required), variant="filled|ivory|outline", size="sm|md|lg", display="label|icon", theme="auto|light|dark",
 *  expires-at (ISO 8601, optional), send-to-phone (boolean, only when your server can reach this visitor's phone; see the docs). */
(function () {
  'use strict';

  var SVG_NS = 'http://www.w3.org/2000/svg';
  // A session link: https, a Viadere link domain, /v/ and eight characters of the code alphabet (no I, O, 0, 1). Nothing else is rendered.
  var LINK = /^https:\/\/(viadere\.com|viadere\.cksites\.dev)\/v\/([A-HJ-NP-Z2-9]{8})$/;
  // Labels per flow. Only "verify" exists today; a sign-in flow adds its own entry and copy here.
  var FLOWS = {
    verify: {
      label: 'Verify with Viadere',
      title: 'Verify with Viadere',
      scan: 'Scan with your phone’s camera',
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
  // QR code (ISO/IEC 18004): byte mode, error correction level M, versions 1 to 10, best of the eight masks. A session link is 30 to 38
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

  // A phone or tablet, where the operating system can hand a universal link / App Link to the installed Viadere app (or show the landing
  // page with the App Store link when it is not installed). Everything else gets the QR-first panel.
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

    /** Opens the QR-first panel (computers; or call it yourself). */
    open() {
      var session = this._session, flow = this._flow;
      if (!session || this._dialog) return;
      var id = 'vdv-' + (++counter);
      var dialog = el('dialog', { 'class': 'vdv-panel', 'aria-labelledby': id + '-title', 'aria-describedby': id + '-explain', 'data-vdv-theme': this.getAttribute('data-vdv-theme') || 'auto' });
      var close = el('button', { type: 'button', 'class': 'vdv-close', 'aria-label': 'Close' }, ['×']);
      var header = el('div', { 'class': 'vdv-head' }, [mark('vdv-mark'), el('h2', { id: id + '-title', 'class': 'vdv-title' }, [flow.title]), close]);
      var status = el('p', { 'class': 'vdv-status', role: 'status', 'aria-live': 'polite' });

      // View 1: the QR code.
      var qrView = el('div', { 'class': 'vdv-view', id: id + '-qr' }, [el('p', { 'class': 'vdv-lead' }, [flow.scan])]);
      var code = qrSVG(session.link);
      if (code) qrView.appendChild(el('div', { 'class': 'vdv-qr-frame' }, [code]));
      qrView.appendChild(el('p', { 'class': 'vdv-explain', id: id + '-explain' }, [flow.explain]));
      var expires = Date.parse(this.getAttribute('expires-at') || '');
      if (!isNaN(expires)) {
        var time = new Date(expires);
        qrView.appendChild(el('p', { 'class': 'vdv-fine' }, ['This code works until ' + time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + '.']));
      }
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
      var back = el('button', { type: 'button', 'class': 'vdv-secondary', 'aria-controls': id + '-qr' }, ['Back to the QR code']);
      options.appendChild(back);

      dialog.appendChild(header);
      dialog.appendChild(qrView);
      dialog.appendChild(options);
      dialog.appendChild(status);

      var self = this;
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
      if (dialog.open) dialog.close();
      if (dialog.parentNode) dialog.parentNode.removeChild(dialog);
      if (this._button && this._button.isConnected) this._button.focus();
      this.dispatchEvent(new CustomEvent('viadere-verify-close', { bubbles: true, composed: true }));
    }
  }

  if (!customElements.get('viadere-verify')) customElements.define('viadere-verify', ViadereVerify);
})();
