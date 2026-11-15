# Third-party notices

Code in this repository that is derived from, or links, other projects' work. Dependencies resolved by a package manager carry their own
licence files; this file covers what is written into or pinned by the repository itself.

## CKey (clearkeysolutions/ckey)

- **Ported:** `Packages/ViadereCore/Sources/ViadereCore/OpticalCode/CKeySymbol.swift` and `CKeySVG.swift` are a Swift port of the CKey Profile 0
  encoder and styled SVG renderer (`src/core_internal.inc`, `src/api_codec.inc`, `src/api_render.inc`) at tag `v0.1.0-build.85`
  (commit `ede38f57aa1a20c456b1858f4fccd919e98ef269`). `docs/protocol/vectors/ckey-profile0-v1.json` was produced by that build.
  The renderer port also covers the reference's custom styles (module shapes, ring style, ray caps, colours and materials), and
  `CKeyStyleCheck.swift` ports its style check (`structural_problem` and the strict `safety_problem` in `src/core_internal.inc`);
  `docs/protocol/vectors/ckey-style-v1.json` (verdicts and styled SVGs) was produced by the same build.
  `Server/Public/verify-button/v2/viadere-verify.js` (the "Verify with Viadere" web button) contains a JavaScript port of the same encoder and
  of the "concept" preset of the renderer, made from the Swift port and checked against the same vectors
  (`Server/Tests/browser/test_verify_button_v2.py`); the file carries the copyright and permission notice, because it is served to integrators' pages on its own.
- **Linked (iOS app only):** the `CKeyScanner` product of the same commit (`App/project.yml`).
- **Name and mark:** "CKey" is governed by the trademark policy at openckey.org/trademark. Viadere says that it reads and draws CKey codes;
  it does not claim CKey Safe Actions support or openckey.org certification.

```
MIT License

Copyright (c) 2026 ClearKey Solutions, LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
