# Browser tests

`test_connect_button.py` loads the real `Server/Public/connect-button/v1/*` files into headless Chromium (served from a temporary
local directory) and checks which link `<viadere-connect>` renders for each attribute case. Python + Playwright only; no Node.js.

`test_verify_button.py` does the same for `Server/Public/verify-button/v1/*` under a strict CSP with Trusted Types: rendering and link
validation, variants, the desktop QR-first panel (modal, focus trap, Escape, focus return, other options), the phone hand-off, and the QR
encoder module-for-module against the `qrcode` reference library (byte mode, level M; pinned `qrcode==8.2`, Python only).

`test_verify_button_v2.py` covers `Server/Public/verify-button/v2/*` (the Viadere code, a CKey, first; the QR code one control away) under
the same CSP: everything the v1 test checks, plus the CKey encoder against every vector in `docs/protocol/vectors/ckey-profile0-v1.json`
(same version and codeword), the drawing (`XMLSerializer` output equal to the CKey reference renderer's SVG byte for byte, by the SHA-256
in the vector file; the panel's copy after undoing its unique id suffix and its own accessible name), the switch to the QR code and back,
keyboard and focus, unique ids with several buttons on one page, forced colours (QR code only, with an explanation) and no requests.
It needs no CKey software: the vectors are data. Reading a drawn code back with the CKey reference decoder is a manual check
(`docs/SECURITY.md` §2.104), not part of CI.

```sh
python3 -m venv .venv && .venv/bin/pip install playwright==1.64.1 qrcode==8.2
.venv/bin/playwright install chromium        # once, unless a Chromium is already present
.venv/bin/python Server/Tests/browser/test_connect_button.py
.venv/bin/python Server/Tests/browser/test_verify_button.py
.venv/bin/python Server/Tests/browser/test_verify_button_v2.py
```

If Chromium is already installed, set `CHROMIUM_PATH=/path/to/chrome` (the script also uses `/opt/pw-browsers/chromium`
when it exists). In this repo's dev container: `Design/tools/.venv/bin/python Server/Tests/browser/test_connect_button.py`.
CI runs it in the `browser` job of `.github/workflows/ci.yml`.
