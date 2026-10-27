/*! Connect with Viadere v1 — https://viadere.com — dependency-free web component.
 *  No network requests, no cookies, no storage, no analytics, no iframes. It renders a link to
 *  https://viadere.com/c/{CODE} (optionally with a signed ctx/sig from your dashboard) and nothing else.
 *  Usage: <viadere-connect code="AF2345"></viadere-connect>
 *  Attributes: code (required), ctx + sig (optional, both or neither), theme="auto|light|dark", label. */
(function () {
  'use strict';
  var ORIGIN = 'https://viadere.com/c/';
  var MARK = '<svg class="m" viewBox="0 0 321.71 146" aria-hidden="true" focusable="false" xmlns="http://www.w3.org/2000/svg">' +
    '<path d="M0 46C31.34 46 52.61 53.08 58.62 61.38L88.74 102.99L115.22 66.49C130.87 44.9 156.4 45.68 170.7 68.18L189.31 97.44L215.59 61.52C231.34 40 256.71 40.99 270.74 63.66L321.71 146C290.37 146 271.7 141.91 268.73 137.12L240.79 91.98L213.57 129.17C198.67 149.53 174.45 148.74 160.91 127.45L141.09 96.28L116.14 130.69C101.32 151.11 76.1 151.1 61.31 130.67L0 46Z" fill="currentColor" opacity="0.62"/>' +
    '<path d="M0 46C31.34 46 52.61 53.08 58.62 61.38L88.74 102.99C101.18 120.16 102.65 139.14 118.23 127.81L116.14 130.69C101.32 151.11 76.1 151.1 61.31 130.67L0 46Z" fill="currentColor"/>' +
    '<path d="M113.12 69.37L115.22 66.49C130.87 44.9 156.4 45.68 170.7 68.18L189.31 97.44C200.84 115.58 199.82 137.73 215.67 126.3L213.57 129.17C198.67 149.53 174.45 148.74 160.91 127.45L141.09 96.28C129.64 78.27 128.81 57.95 113.12 69.37Z" fill="currentColor"/>' +
    '<path d="M213.49 64.4L215.59 61.52C231.34 40 256.71 40.99 270.74 63.66L321.71 146C290.37 146 271.7 141.91 268.73 137.12L240.79 91.98C229.56 73.83 229.23 53.05 213.49 64.4Z" fill="currentColor"/>' +
    '<circle cx="155.21" cy="20.5" r="20.5" fill="currentColor"/></svg>';
  var CSS = ':host{display:inline-block}a{display:inline-flex;align-items:center;gap:.6em;box-sizing:border-box;min-height:44px;padding:.6em 1.25em;border-radius:999px;' +
    'font:600 15px/1.2 -apple-system,"SF Pro Text","Segoe UI",system-ui,sans-serif;letter-spacing:-.005em;text-decoration:none;background:#1F1E1C;color:#F5F2EC;border:1px solid #1F1E1C}' +
    'a:hover{background:#4A4844;border-color:#4A4844}a:focus-visible{outline:2px solid #8C7550;outline-offset:2px}.m{width:2.1em;height:auto;flex:none}' +
    ':host([theme=dark]) a{background:#F3F0EA;color:#1F1E1C;border-color:#F3F0EA}:host([theme=dark]) a:hover{background:#C9C4BB;border-color:#C9C4BB}' +
    '@media(prefers-color-scheme:dark){:host(:not([theme=light])) a{background:#F3F0EA;color:#1F1E1C;border-color:#F3F0EA}:host(:not([theme=light])) a:hover{background:#C9C4BB;border-color:#C9C4BB}}' +
    '@media(forced-colors:active){a{border:1px solid LinkText}}';
  // Same normalisation as the Viadere server: strip separators, upper-case, I→1 and O→0, then exactly six [0-9A-Z].
  function normalize(raw) {
    var c = String(raw || '').replace(/[\s\-._\/]/g, '').toUpperCase().replace(/I/g, '1').replace(/O/g, '0');
    return /^[0-9A-Z]{6}$/.test(c) ? c : null;
  }
  var B64 = /^[A-Za-z0-9_-]+$/;
  function href(code, ctx, sig) {
    var c = normalize(code);
    if (!c) return null;
    var url = ORIGIN + c;
    if (ctx && sig && ctx.length <= 512 && B64.test(ctx) && sig.length === 43 && B64.test(sig)) url += '?ctx=' + ctx + '&sig=' + sig;
    return url;
  }
  class ViadereConnect extends HTMLElement {
    static get observedAttributes() { return ['code', 'ctx', 'sig', 'label']; }
    connectedCallback() { this.render(); }
    attributeChangedCallback() { if (this.isConnected) this.render(); }
    render() {
      var root = this.shadowRoot || this.attachShadow({ mode: 'open' });
      var url = href(this.getAttribute('code'), this.getAttribute('ctx'), this.getAttribute('sig'));
      if (!url) { root.textContent = ''; return; }
      var label = (this.getAttribute('label') || 'Connect with Viadere').slice(0, 40);
      root.innerHTML = '<style>' + CSS + '</style><a part="button" rel="noopener noreferrer" referrerpolicy="no-referrer"></a>';
      var a = root.querySelector('a');
      a.setAttribute('href', url);
      a.innerHTML = MARK + '<span></span>';
      a.querySelector('span').textContent = label;
    }
  }
  if (!customElements.get('viadere-connect')) customElements.define('viadere-connect', ViadereConnect);
})();
