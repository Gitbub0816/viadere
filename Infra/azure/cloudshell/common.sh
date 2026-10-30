# shellcheck shell=bash
# Sourced by the Cloud Shell helpers. No `set -e`: an interactive Cloud Shell exits (and drops the session) on the first error, so each
# step checks its own result with fail().
step() { echo; echo "=== $* ==="; }
fail() { echo "FAILED: $*"; exit 1; }
need() { for v in "$@"; do [ -n "${!v:-}" ] || fail "set $v first (see docs/ops/AZURE-SETUP.md, Cloud Shell)"; done; }

TOFU_VERSION=1.13.2
RG_APP=rg-viadere-stg-app
STATE_RG="${STATE_RG:-rg-viadere-stg-tfstate}"

# Installs OpenTofu (checksum-verified; ephemeral sessions keep nothing) and initialises Infra/azure against the remote state.
tofu_ready() {
  if ! ~/bin/tofu version 2>/dev/null | grep -q "v$TOFU_VERSION"; then
    local dl base want
    dl="$(mktemp -d)" || fail "mktemp"
    mkdir -p ~/bin || fail "mkdir ~/bin"
    base="https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}"
    curl --proto '=https' --tlsv1.2 -fsSL -o "$dl/tofu.zip" "$base/tofu_${TOFU_VERSION}_linux_amd64.zip" || fail "download tofu"
    curl --proto '=https' --tlsv1.2 -fsSL -o "$dl/sums" "$base/tofu_${TOFU_VERSION}_SHA256SUMS" || fail "download sums"
    want="$(grep " tofu_${TOFU_VERSION}_linux_amd64.zip\$" "$dl/sums" | cut -d' ' -f1)"
    [ -n "$want" ] || fail "checksum missing"
    echo "$want  $dl/tofu.zip" | sha256sum --check --quiet || fail "checksum"
    unzip -o -q "$dl/tofu.zip" tofu -d "$dl" || fail "unzip tofu"
    install "$dl/tofu" ~/bin/ || fail "install tofu"
  fi
  export PATH=~/bin:$PATH
  tofu version | head -1
  cat > backend.staging.hcl <<HCL
use_azuread_auth     = true
subscription_id      = "$SUB_ID"
resource_group_name  = "$STATE_RG"
storage_account_name = "$STATE_SA"
container_name       = "tfstate"
key                  = "viadere/azure/staging.tfstate"
HCL
  tofu init -input=false -backend-config=backend.staging.hcl >/dev/null || fail "tofu init"
}

# True once job-viadere-migrate has succeeded: from then on the database may hold data encrypted under the service keys.
migrate_has_run() {
  [ -n "$(az containerapp job execution list -n job-viadere-migrate -g "$RG_APP" \
          --query "[?properties.status=='Succeeded'] | [0].name" -o tsv 2>/dev/null)" ]
}

# Starts a Container Apps job and waits for its execution to finish (status Succeeded, else fail).
run_job() {
  local job="$1" exec status
  exec="$(az containerapp job start -n "$job" -g "$RG_APP" --query name -o tsv)" || fail "start $job"
  [ -n "$exec" ] || fail "start $job: no execution name"
  echo "started $job ($exec)"
  for _ in $(seq 1 60); do
    status="$(az containerapp job execution show -n "$job" -g "$RG_APP" --job-execution-name "$exec" --query properties.status -o tsv 2>/dev/null)"
    case "$status" in
      Succeeded) echo "$job: Succeeded"; return 0 ;;
      Failed|Stopped|Degraded) fail "$job: $status (logs: Log Analytics, ContainerAppConsoleLogs_CL, job $job)" ;;
    esac
    sleep 15
  done
  fail "$job: still ${status:-unknown} after 15 minutes"
}
