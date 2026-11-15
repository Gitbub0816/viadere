#!/bin/bash
# Build, scan, push and sign the server image (and the authority image) from the owner's Mac, for when GitHub-hosted Actions are not
# available. It mirrors .github/workflows/release.yml step for step; then deploy with Infra/azure/deploy-staging.sh. Staging only.
#
#   bash Infra/release-local.sh v0.1.0-staging.1            # tags the current commit, builds and publishes both images
#   bash Infra/azure/deploy-staging.sh v0.1.0-staging.1      # migrates and rolls the api to that image
#
# Needs (macOS, bash 3.2 compatible): Docker Desktop (buildx), git, gh (logged in, scope write:packages), and
#   brew install cosign syft trivy
# Differences from the CI release, by construction:
#   * The cosign signature is keyless with YOUR identity (browser sign-in to Sigstore), not the release workflow's identity, so
#     azure.yml's `cosign verify --certificate-identity-regexp .../release.yml@...` refuses these images: deploy them with
#     Infra/azure/deploy-staging.sh. Production deploys stay CI-only (they also need the SLSA provenance, which only CI produces).
#   * Images are built for linux/amd64 (Container Apps). On Apple silicon that runs under emulation: expect a long first build.
set -euo pipefail
TAG="${1:-}"
OWNER_REPO="gitbub0816/viadere"
REGISTRY="ghcr.io"
fail() { echo "FAILED: $*" >&2; exit 1; }
case "$TAG" in v*-staging.*) ;; *) fail "usage: bash Infra/release-local.sh v0.1.0-staging.N" ;; esac
for tool in docker git gh cosign syft trivy; do command -v "$tool" >/dev/null || fail "$tool is not installed"; done
cd "$(git rev-parse --show-toplevel)" || fail "run inside the repository"
[ -z "$(git status --porcelain)" ] || fail "the working tree has changes: commit or stash them first (the image must match a commit)"
SHA="$(git rev-parse HEAD)"

echo "== tag $TAG at $SHA"
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  [ "$(git rev-parse "$TAG^{commit}")" = "$SHA" ] || fail "$TAG already exists on another commit"
else
  git tag -a "$TAG" -m "Viadere $TAG (local release)"
fi
git push origin "refs/tags/$TAG" || fail "push the tag"

echo "== GHCR login"
gh auth token | docker login "$REGISTRY" -u "$(gh api user --jq .login)" --password-stdin >/dev/null || fail "GHCR login (gh auth refresh -s write:packages)"

publish() { # $1 = image name, $2 = Dockerfile
  local image="$REGISTRY/$OWNER_REPO/$1" shatag ref digest
  shatag="$image:sha-${SHA:0:12}"
  echo "== $1: build (linux/amd64)"
  # --provenance/--sbom false: one plain image manifest like CI's `docker build` (no index), which deploy-staging.sh requires.
  docker buildx build --platform linux/amd64 --provenance=false --sbom=false --load -f "$2" \
    --label org.opencontainers.image.source="https://github.com/Gitbub0816/viadere" \
    --label org.opencontainers.image.revision="$SHA" \
    -t "$shatag" . || fail "$1 build"
  echo "== $1: scan (fail on fixable HIGH or CRITICAL)"
  trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$shatag" || fail "$1 has fixable HIGH/CRITICAL findings: not published"
  echo "== $1: push"
  docker push "$shatag" >/dev/null || fail "$1 push"
  docker tag "$shatag" "$image:$TAG" && docker push "$image:$TAG" >/dev/null || fail "$1 push tag"
  digest="$(docker inspect --format '{{index .RepoDigests 0}}' "$shatag" | cut -d@ -f2)"
  case "$digest" in sha256:*) ;; *) fail "$1 digest" ;; esac
  ref="$image@$digest"
  case "$(docker buildx imagetools inspect --raw "$ref" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("mediaType",""))')" in
    application/vnd.oci.image.manifest.v1+json|application/vnd.docker.distribution.manifest.v2+json) ;;
    *) fail "$1 was pushed as an index, not a single image (Docker Desktop: Settings > General, turn off the containerd image store, then retry)" ;;
  esac
  echo "== $1: SBOM and keyless signature (a browser window opens for the Sigstore sign-in)"
  syft "registry:$ref" --platform linux/amd64 -o "spdx-json=sbom-$1.spdx.json" || fail "$1 SBOM"
  cosign sign --yes "$ref" || fail "$1 sign"
  cosign attest --yes --type spdxjson --predicate "sbom-$1.spdx.json" "$ref" || fail "$1 SBOM attestation"
  rm -f "sbom-$1.spdx.json"
  echo "$1 $ref"
}

publish viadere-server Server/Dockerfile
publish viadere-authority Server/Dockerfile.authority
echo "DONE: images for $TAG are on GHCR. Deploy the server with: bash Infra/azure/deploy-staging.sh $TAG"
