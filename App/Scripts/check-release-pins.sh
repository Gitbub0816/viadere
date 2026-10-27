#!/bin/sh
# Fails a Release build (archive) while the production certificate pins are still the REPLACE_ME placeholders.
#
# A Release build with placeholder pins fails closed at runtime (it can never connect); this turns that into a build
# error so a broken binary is never archived or shipped. Debug builds are never checked.
#
# The marker is PinningConfiguration.placeholderPrefix ("REPLACE_ME", see `isPlaceholder`). The pins live in
# ViadereConfiguration.productionPinning.
set -eu

if [ "${CONFIGURATION:-}" != "Release" ]; then
  exit 0
fi

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
