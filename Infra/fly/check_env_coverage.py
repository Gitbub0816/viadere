#!/usr/bin/env python3
"""Verify that every variable in Server/.env.example is accounted for in the Fly deployment.

A variable is accounted for when it is (a) a [env] key in BOTH fly.production.toml and fly.staging.toml, (b) listed in secrets.txt, or
(c) in EXEMPT with a reason. Also fails if a fly.toml [env] key is unknown to the server (typo) or duplicates a secret.
Run:  python3 -I Infra/fly/check_env_coverage.py     (standard library only; exit 1 on any gap)
"""
import re
import sys
import tomllib
from pathlib import Path

root = Path(__file__).resolve().parents[2]
here = Path(__file__).resolve().parent

EXEMPT = {
    "POSTGRES_PASSWORD": "docker-compose only; production uses Neon credentials inside DATABASE_URL",
    "APNS_KEY_PATH": "alternative to APNS_KEY_P8; Fly has no mounted secret files, use the inline secret",
    "PASS_CERTIFICATE_PATH": "alternative to PASS_CERTIFICATE_PEM; use the inline PEM secrets on Fly",
    "PASS_PRIVATE_KEY_PATH": "alternative to PASS_PRIVATE_KEY_PEM; use the inline PEM secrets on Fly",
    "PASS_WWDR_CERTIFICATE_PATH": "alternative to PASS_WWDR_CERTIFICATE_PEM; use the inline PEM secrets on Fly",
    "WALLET_ENCRYPTION_KEY_PATHS": "development only; refused in staging/production (use WALLET_ENCRYPTION_KEY_WRAPPED)",
    "ASSET_DOMAIN": "Brand Kits are not offered on Fly (no asset store): unset, so no brand image is served",
    "BRAND_MANIFEST_SIGNING_KEY": "Brand Kits are not offered on Fly: unset, so every business is served neutral",
    "BRAND_SELECTION_KEY": "Brand Kits are not offered on Fly",
    "BRAND_ASSET_DIRECTORY": "development only; refused in staging/production",
}
# Azure-only settings (WP-B2/B3): Infra/azure sets them on Container Apps (checked by Infra/azure/check_env_coverage.py); on Fly they stay unset
# and the server uses its defaults (one combined process, database queue transport, DATABASE_URL password auth, no Key Vault).
AZURE_ONLY = {
    "ROLE", "QUEUE_TRANSPORT", "AZURE_SERVICEBUS_FQDN", "AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_KEY_VAULT_URL", "AZURE_KEY_VAULT_KEK_KEY",
    "AZURE_KEY_VAULT_KD_LOG_KEY", "AZURE_KEY_VAULT_LINK_DESCRIPTOR_KEY", "AZURE_KEY_VAULT_AUDIT_HEAD_KEY", "AZURE_AUDIT_BLOB_ENDPOINT",
    "AZURE_AUDIT_BLOB_CONTAINER", "AZURE_KEY_VAULT_LOOP_PUBLICATION_KEY", "DATABASE_AUTH", "DATABASE_HOST", "DATABASE_PORT", "DATABASE_NAME", "DATABASE_USER", "DATABASE_CA_FILE",
    "DATABASE_WORKER_ROLE", "AZURE_KEY_VAULT_BRAND_MANIFEST_KEY", "AZURE_BRAND_BLOB_ENDPOINT", "AZURE_BRAND_BLOB_CONTAINER",
}
EXEMPT.update({name: "Azure only (Infra/azure); unset on Fly" for name in AZURE_ONLY})
# Names the server reads that are not in .env.example (documented in Server/README.md).
EXTRA_KNOWN = {"AUDIT_CHAIN_LEGACY_THROUGH_SEQ", "PASS_CERTIFICATE_PEM", "PASS_PRIVATE_KEY_PEM", "PASS_WWDR_CERTIFICATE_PEM",
               "BIND_HOST", "EMAIL_API_AUTH_HEADER", "EMAIL_API_AUTH_SCHEME"}

example = set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]{2,})=", (root / "Server/.env.example").read_text(), re.M))
secrets = {l.strip() for l in (here / "secrets.txt").read_text().splitlines() if l.strip() and not l.startswith("#")}
envs = {}
for name in ("fly.production.toml", "fly.staging.toml"):
    envs[name] = set(tomllib.loads((here / name).read_text()).get("env", {}))

problems = []
for var in sorted(example):
    if var in secrets or var in EXEMPT:
        continue
    for name, keys in envs.items():
        if var not in keys:
            problems.append(f"{var}: not in [env] of {name}, secrets.txt or EXEMPT")
for name, keys in envs.items():
    for var in sorted(keys & secrets):
        problems.append(f"{var}: is both a secret and a plain [env] value in {name}")
    for var in sorted(keys - example - EXTRA_KNOWN):
        problems.append(f"{var}: [env] key of {name} unknown to Server/.env.example (typo?)")
if envs["fly.production.toml"] != envs["fly.staging.toml"]:
    diff = envs["fly.production.toml"] ^ envs["fly.staging.toml"]
    problems.append(f"production and staging [env] key sets differ: {sorted(diff)}")
for var in sorted(secrets - example - EXTRA_KNOWN):
    problems.append(f"{var}: in secrets.txt but unknown to Server/.env.example")

if problems:
    print("\n".join(problems))
    sys.exit(1)
print(f"ok: {len(example)} variables in .env.example; {len(secrets)} secrets; {len(EXEMPT)} exempt; env keys production={len(envs['fly.production.toml'])}")
