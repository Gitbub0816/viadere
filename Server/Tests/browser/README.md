# Browser tests

`test_connect_button.py` loads the real `Server/Public/connect-button/v1/*` files into headless Chromium (served from a temporary
local directory) and checks which link `<viadere-connect>` renders for each attribute case. Python + Playwright only; no Node.js.

```sh
python3 -m venv .venv && .venv/bin/pip install playwright==1.64.1
.venv/bin/playwright install chromium        # once, unless a Chromium is already present
.venv/bin/python Server/Tests/browser/test_connect_button.py
```

If Chromium is already installed, set `CHROMIUM_PATH=/path/to/chrome` (the script also uses `/opt/pw-browsers/chromium`
when it exists). In this repo's dev container: `Design/tools/.venv/bin/python Server/Tests/browser/test_connect_button.py`.
CI runs it in the `browser` job of `.github/workflows/ci.yml`.
