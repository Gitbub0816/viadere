#!/usr/bin/env bash
# Install checksum-pinned, Go/Rust/native release binaries used by CI (no Node, no `curl | sh`, no unpinned downloads).
# Usage: .github/scripts/install-tools.sh gitleaks syft grype trivy cosign flyctl osv-scanner actionlint
# Every download is verified against the SHA-256 below (linux/amd64, computed 2026-10-27 from the official release assets) before it
# is unpacked. To update a tool: bump VERSION, download the asset once, record `sha256sum`, run CI. Monthly, with the dependency
# refresh (docs/ops/SECURE-SDLC.md).
set -euo pipefail

BIN_DIR="${INSTALL_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# name | version | url | sha256 | kind (tgz:<member> | bin)
declare -A VERSION URL SHA KIND
VERSION[gitleaks]=8.30.1
URL[gitleaks]="https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz"
SHA[gitleaks]=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
KIND[gitleaks]="tgz:gitleaks"

VERSION[syft]=1.55.0
URL[syft]="https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_linux_amd64.tar.gz"
SHA[syft]=bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d
KIND[syft]="tgz:syft"

VERSION[grype]=0.121.0
URL[grype]="https://github.com/anchore/grype/releases/download/v0.121.0/grype_0.121.0_linux_amd64.tar.gz"
SHA[grype]=64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519
KIND[grype]="tgz:grype"

VERSION[trivy]=0.76.1
URL[trivy]="https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz"
SHA[trivy]=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0
KIND[trivy]="tgz:trivy"

VERSION[cosign]=3.1.4
URL[cosign]="https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64"
SHA[cosign]=424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa
KIND[cosign]="bin"

VERSION[flyctl]=0.4.123
URL[flyctl]="https://github.com/superfly/flyctl/releases/download/v0.4.123/flyctl_0.4.123_Linux_x86_64.tar.gz"
SHA[flyctl]=08d8b45e04ed99223cd938622407664dbed70abeda8f1d15ccc7f4b3e91094bc
KIND[flyctl]="tgz:flyctl"

VERSION[osv-scanner]=2.7.0
URL[osv-scanner]="https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64"
SHA[osv-scanner]=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
KIND[osv-scanner]="bin"

VERSION[actionlint]=1.7.12
URL[actionlint]="https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz"
SHA[actionlint]=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
KIND[actionlint]="tgz:actionlint"

[ "$(uname -s)-$(uname -m)" = "Linux-x86_64" ] || { echo "install-tools.sh: only linux/amd64 runners are supported" >&2; exit 1; }

for tool in "$@"; do
  [ -n "${URL[$tool]:-}" ] || { echo "unknown tool: $tool" >&2; exit 2; }
  file="$TMP/$tool.download"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$file" "${URL[$tool]}"
  echo "${SHA[$tool]}  $file" | sha256sum --check --status \
    || { echo "CHECKSUM MISMATCH for $tool ${VERSION[$tool]}: refusing to install" >&2; exit 3; }
  case "${KIND[$tool]}" in
    bin) install -m 0755 "$file" "$BIN_DIR/$tool" ;;
    tgz:*)
      member="${KIND[$tool]#tgz:}"
      mkdir -p "$TMP/$tool.x"
      tar -xzf "$file" -C "$TMP/$tool.x" "$member"
      install -m 0755 "$TMP/$tool.x/$member" "$BIN_DIR/$tool"
      ;;
  esac
  echo "installed $tool ${VERSION[$tool]}"
done

if [ -n "${GITHUB_PATH:-}" ]; then echo "$BIN_DIR" >> "$GITHUB_PATH"; fi
