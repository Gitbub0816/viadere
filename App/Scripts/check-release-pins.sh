#!/bin/sh
# Fails a Release or Staging build (archive) while the certificate pins are still placeholders.
#
# A build with placeholder pins fails closed at runtime (it can never connect); this turns that into a build error so a broken
# binary is never archived or shipped. Debug builds are never checked.
#
#   Release  the production pins live in ViadereConfiguration.productionPinning (marker: PinningConfiguration.placeholderPrefix,
#            "REPLACE_ME").
#   Staging  the pins for viadere-api.cksites.dev come from Configs/Staging.xcconfig (VIADERE_PIN_PRIMARY / VIADERE_PIN_BACKUP, exported
#            to this script as build settings): each must be base64 of exactly 32 bytes, and the two must differ. The staging API URL
#            must be https.
set -eu

case "${CONFIGURATION:-}" in
  Release)
    CONFIG_FILE="${SRCROOT}/../Packages/ViadereKit/Sources/ViadereKit/Config/ViadereConfiguration.swift"
    MARKER="REPLACE_ME"
    if [ ! -f "$CONFIG_FILE" ]; then
      echo "error: cannot find $CONFIG_FILE to verify the certificate pins" >&2
      exit 1
    fi
    if grep -n "$MARKER" "$CONFIG_FILE" >&2; then
      echo "error: ViadereConfiguration.productionPinning still contains $MARKER placeholder pins. Replace them with the real SPKI SHA-256 pins (current key + backup) before archiving a Release build. See PinningConfiguration for the command." >&2
      exit 1
    fi
    exit 0
    ;;
  Staging)
    fail=0
    check_pin() { # name value
      name="$1"; value="$2"
      case "$value" in
        ""|REPLACE_ME*)
          echo "error: $name is not set in App/Configs/Staging.xcconfig (still a placeholder). Compute it with App/Scripts/compute-spki-pins.py; see docs/ops/STAGING-SETUP.md." >&2
          fail=1; return ;;
      esac
      bytes=$(printf '%s' "$value" | /usr/bin/openssl base64 -d -A 2>/dev/null | wc -c | tr -d ' ')
      if [ "$bytes" != "32" ]; then
        echo "error: $name is not a base64 SHA-256 hash (32 bytes); got $bytes bytes." >&2
        fail=1
      fi
    }
    check_pin VIADERE_PIN_PRIMARY "${VIADERE_PIN_PRIMARY:-}"
    check_pin VIADERE_PIN_BACKUP "${VIADERE_PIN_BACKUP:-}"
    if [ -n "${VIADERE_PIN_PRIMARY:-}" ] && [ "${VIADERE_PIN_PRIMARY:-}" = "${VIADERE_PIN_BACKUP:-}" ]; then
      echo "error: VIADERE_PIN_PRIMARY and VIADERE_PIN_BACKUP are the same value; the backup must be a different key." >&2
      fail=1
    fi
    case "${VIADERE_API_BASE_URL:-}" in
      https://*) ;;
      *) echo "error: VIADERE_API_BASE_URL must be an https URL in a Staging build (got '${VIADERE_API_BASE_URL:-}')." >&2; fail=1 ;;
    esac
    case "${VIADERE_PLIST_DEFS:-}" in
      *VIADERE_LOCAL_DEV*) echo "error: VIADERE_LOCAL_DEV (the plain-HTTP ATS exception) must not be defined in a Staging build." >&2; fail=1 ;;
    esac
    exit "$fail"
    ;;
  *)
    exit 0
    ;;
esac
