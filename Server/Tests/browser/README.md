# Browser tests

`test_connect_button.py` loads the real `Server/Public/connect-button/v1/*` files into headless Chromium (served from a temporary
local directory) and checks which link `<viadere-connect>` renders for each attribute case. Python + Playwright only; no Node.js.

`test_verify_button.py` does the same for `Server/Public/verify-button/v1/*` under a strict CSP with Trusted Types: rendering and link
validation, variants, the desktop QR-first panel (modal, focus trap, Escape, focus return, other options), the phone hand-off, and the QR
encoder module-for-module against the `qrcode` reference library (byte mode, level M; pinned `qrcode==8.2`, Python only).

```sh
python3 -m venv .venv && .venv/bin/pip install playwright==1.64.1 qrcode==8.2
.venv/bin/playwright install chromium        # once, unless a Chromium is already present
.venv/bin/python Server/Tests/browser/test_connect_button.py
.venv/bin/python Server/Tests/browser/test_verify_button.py
```

If Chromium is already installed, set `CHROMIUM_PATH=/path/to/chrome` (the script also uses `/opt/pw-browsers/chromium`
when it exists). In this repo's dev container: `Design/tools/.venv/bin/python Server/Tests/browser/test_connect_button.py`.
CI runs it in the `browser` job of `.github/workflows/ci.yml`.
