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
#
# Both configurations also check the build-pinned manifest keys of the app target (Brand Kits and hosted Loops, SECURITY.md §2.92,
# §2.93): VIADERE_BRAND_MANIFEST_KEYS and VIADERE_LOOP_PUBLICATION_KEYS must each hold one or more `kid:publicKey` entries (or bare
# publicKeys), comma separated, where publicKey is base64url of a 65-byte uncompressed P-256 point and kid, when given, is the base64url
# SHA-256 of its SPKI. An empty or malformed value would silently make every Brand Kit neutral and every Loop unshowable. The App Clip
# renders neither and is not checked for them.
#
# VIADERE_CKEY_SAFE_ACTION_KEYS (app target only, SECURITY.md §2.104): `keyId:alg:publicKey` entries, comma separated, keyId 1 to 32 of
# A-Z a-z 0-9 . _ - and either ES256 with SEC 1 hex (02/03 + 64 hex digits, or 04 + 128) or Ed25519 with 64 hex digits. The app also
# refuses a point off the curve, which this script cannot check. Empty is a warning in both configurations: the app then refuses every scanned
# Safe Action and the sign-in code works only as a plain link or QR, and "Sign in with Viadere" is staging-only (ADR-0024), so a Release
# archive must not need a key no production server can use. A malformed value is an error in both (the app would drop the whole list).
set -eu

# DER SubjectPublicKeyInfo header of an uncompressed P-256 key (id-ecPublicKey, prime256v1, BIT STRING), base64.
SPKI_P256_PREFIX_B64="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgA="

b64url_decode() { # value -> raw bytes on stdout
  s=$(printf '%s' "$1" | tr '_-' '/+')
  case $(( ${#s} % 4 )) in
    2) s="${s}==" ;;
    3) s="${s}=" ;;
  esac
  printf '%s' "$s" | /usr/bin/openssl base64 -d -A 2>/dev/null
}

check_manifest_keys() { # name value
  name="$1"; value="$2"
  case "$value" in
    ""|*REPLACE_ME*|*'$('*)
      echo "error: $name is not set (Configs/*.xcconfig). Without it every manifest fails verification. See the comment in Configs/Shared.xcconfig." >&2
      return 1 ;;
  esac
  status=0
  old_ifs=$IFS; IFS=','
  for entry in $value; do
    entry=$(printf '%s' "$entry" | tr -d ' ')
    case "$entry" in
      *:*) kid="${entry%%:*}"; key="${entry#*:}" ;;
      *) kid=""; key="$entry" ;;
    esac
    bytes=$(b64url_decode "$key" | wc -c | tr -d ' ')
    first=$(b64url_decode "$key" | od -An -tx1 -N1 | tr -d ' \n')
    if [ "$bytes" != "65" ] || [ "$first" != "04" ]; then
      echo "error: $name has an entry that is not a base64url X9.63 P-256 public key (65 bytes starting 0x04)." >&2
      status=1; continue
    fi
    if [ -n "$kid" ]; then
      derived=$( { printf '%s' "$SPKI_P256_PREFIX_B64" | /usr/bin/openssl base64 -d -A; b64url_decode "$key"; } | /usr/bin/openssl dgst -sha256 -binary \
        | /usr/bin/openssl base64 -A | tr '+/' '-_' | tr -d '=')
      if [ "$kid" != "$derived" ]; then
        echo "error: $name has a kid that does not match its key (expected $derived)." >&2
        status=1
      fi
    fi
  done
  IFS=$old_ifs
  return $status
}

check_safe_action_keys() { # value
  case "${TARGET_NAME:-}" in
    ViadereClip) return 0 ;;
  esac
  value="$1"
  if [ -z "$value" ]; then
    echo "warning: VIADERE_CKEY_SAFE_ACTION_KEYS is not set: this build refuses every scanned Safe Action (the sign-in link and QR still work)."
    return 0
  fi
  case "$value" in
    *REPLACE_ME*|*'$('*)
      echo "error: VIADERE_CKEY_SAFE_ACTION_KEYS is a placeholder. Set it to keyId:alg:publicKey (from /.well-known/ckey-safe-actions.json) or leave it empty." >&2
      return 1 ;;
  esac
  status=0
  seen=","
  old_ifs=$IFS; IFS=','
  for entry in $value; do
    entry=$(printf '%s' "$entry" | tr -d ' ')
    if ! printf '%s' "$entry" | grep -Eq '^[A-Za-z0-9._-]{1,32}:(ES256:(0[23][0-9A-Fa-f]{64}|04[0-9A-Fa-f]{128})|Ed25519:[0-9A-Fa-f]{64})$'; then
      echo "error: VIADERE_CKEY_SAFE_ACTION_KEYS has an entry that is not keyId:alg:publicKey (key id of 1 to 32 letters, digits, '.', '_' or '-'; ES256 with 66 or 130 SEC 1 hex digits, or Ed25519 with 64)." >&2
      status=1; continue
    fi
    id="${entry%%:*}"
    case "$seen" in
      *",$id,"*) echo "error: VIADERE_CKEY_SAFE_ACTION_KEYS lists the key id $id twice." >&2; status=1 ;;
    esac
    seen="$seen$id,"
  done
  IFS=$old_ifs
  case "$value" in
    *,) echo "error: VIADERE_CKEY_SAFE_ACTION_KEYS ends with an empty entry." >&2; status=1 ;;
  esac
  return $status
}

check_all_manifest_keys() {
  case "${TARGET_NAME:-}" in
    ViadereClip) return 0 ;;
  esac
  keys_ok=0
  check_manifest_keys VIADERE_BRAND_MANIFEST_KEYS "${VIADERE_BRAND_MANIFEST_KEYS:-}" || keys_ok=1
  check_manifest_keys VIADERE_LOOP_PUBLICATION_KEYS "${VIADERE_LOOP_PUBLICATION_KEYS:-}" || keys_ok=1
  return $keys_ok
}

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
    check_all_manifest_keys || exit 1
    check_safe_action_keys "${VIADERE_CKEY_SAFE_ACTION_KEYS:-}" || exit 1
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
    # Staging: an EMPTY manifest-key set is a warning, not an error, so the app keeps building before the staging keys exist (the app
    # fails closed at runtime: neutral Brand Kits, no Loops). A malformed set is still an error; Release stays strict.
    # Each set is checked on its own: empty warns, anything else must be valid.
    if [ -z "${VIADERE_BRAND_MANIFEST_KEYS:-}" ]; then
      echo "warning: VIADERE_BRAND_MANIFEST_KEYS is not set: this Staging build shows no Brand Kits."
    else
      check_manifest_keys VIADERE_BRAND_MANIFEST_KEYS "${VIADERE_BRAND_MANIFEST_KEYS}" || fail=1
    fi
    if [ -z "${VIADERE_LOOP_PUBLICATION_KEYS:-}" ]; then
      echo "warning: VIADERE_LOOP_PUBLICATION_KEYS is not set: this Staging build shows no Loops."
    else
      check_manifest_keys VIADERE_LOOP_PUBLICATION_KEYS "${VIADERE_LOOP_PUBLICATION_KEYS}" || fail=1
    fi
    check_safe_action_keys "${VIADERE_CKEY_SAFE_ACTION_KEYS:-}" || fail=1
    exit "$fail"
    ;;
  *)
    exit 0
    ;;
esac
