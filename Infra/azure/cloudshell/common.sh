# shellcheck shell=bash
# Sourced by the Cloud Shell helpers. No `set -e`: an interactive Cloud Shell exits (and drops the session) on the first error, so each
# step checks its own result with fail().
step() { echo; echo "=== $* ==="; }
fail() { echo "FAILED: $*"; exit 1; }
need() { for v in "$@"; do [ -n "${!v:-}" ] || fail "set $v first (see docs/ops/AZURE-SETUP.md, Cloud Shell)"; done; }
