#!/usr/bin/env python3
"""Verify that every variable in Server/.env.example is accounted for in the Azure deployment (Infra/azure), the counterpart of
Infra/fly/check_env_coverage.py.

A variable is accounted for when it is (a) set by the module on the server processes (containerapps.tf / locals.tf), (b) a Key Vault secret reference
(the app_secret_env default in variables.tf, or the database credentials in locals.tf), (c) a key of app_env in terraform.tfvars.example, or (d) in
EXEMPT with a reason. Also fails when the module or the example sets a name the server does not know (a typo), when app_env sets a secret, when a
retired name reappears, or when the Azure contract names of docs/ops/AZURE-SETUP.md section 11 are missing from the module.
Run:  python3 -I Infra/azure/check_env_coverage.py     (standard library only; exit 1 on any gap)
"""
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
here = Path(__file__).resolve().parent

EXEMPT = {
    "POSTGRES_PASSWORD": "docker-compose only",
    "APNS_KEY_PATH": "alternative to APNS_KEY_P8 (Key Vault reference)",
    "PASS_CERTIFICATE_PATH": "alternative to PASS_CERTIFICATE_PEM",
    "PASS_PRIVATE_KEY_PATH": "alternative to PASS_PRIVATE_KEY_PEM",
    "PASS_WWDR_CERTIFICATE_PATH": "alternative to PASS_WWDR_CERTIFICATE_PEM",
    "WALLET_ENCRYPTION_KEY_PATHS": "development only; refused in staging/production (use WALLET_ENCRYPTION_KEY_WRAPPED)",
    "KEY_DIRECTORY_LOG_KEY": "replaced on Azure by the Key Vault key AZURE_KEY_VAULT_KD_LOG_KEY (the server refuses both at once)",
    "DATABASE_URL": "Key Vault secret database-url, referenced only while postgres_password_auth_enabled (locals.tf db_password_secret)",
    "DATABASE_MIGRATION_URL": "Key Vault secret database-migration-url, migrate job only, only while postgres_password_auth_enabled",
    "DATABASE_PORT": "default 5432 (Azure Database for PostgreSQL listens there)",
    "DATABASE_CA_FILE": "empty: verify-full against the image's system trust store (Azure's DigiCert/Microsoft roots)",
    "METRICS_BIND_HOST": "set in app_env when METRICS_PORT is used (terraform.tfvars.example)",
    "TWILIO_ACCOUNT_SID": "Twilio is optional (SMS_PROVIDER=mailersend on Azure); add to app_secret_env if used",
    "TWILIO_AUTH_TOKEN": "Twilio is optional; add to app_secret_env if used",
    "TWILIO_FROM_NUMBER": "Twilio is optional; plain config if used",
    "TWILIO_MESSAGING_SERVICE_SID": "Twilio is optional; plain config if used",
    "DIDIT_API_KEY": "only when Verify is enabled (plan 5.6): add to app_secret_env then",
    "DIDIT_WEBHOOK_SECRET": "only when Verify is enabled",
    "DIDIT_WEBHOOK_SECRET_PREVIOUS": "only during a Didit secret rotation",
    "RCS_PROVIDER_TOKEN": "optional RCS group (plan 5.6)",
    "RCS_WEBHOOK_SECRET": "optional RCS group (plan 5.6)",
    "WALLET_ENCRYPTION_KEY_WRAPPED": "only when Verify's Wallet method is enabled (kms1: form, unwrapped with kek-data)",
    "PASS_CERTIFICATE_PEM": "Wallet passes are optional (Key Vault certificate wallet-pass-type when enabled, plan 5.6)",
    "PASS_PRIVATE_KEY_PEM": "Wallet passes are optional",
    "PASS_WWDR_CERTIFICATE_PEM": "Wallet passes are optional",
    "METRICS_TOKEN": "removed with OTLP push (plan 5.6); a Key Vault secret only if a scrape endpoint is kept",
    "EDGE_TOKEN_PREVIOUS": "only during an edge-token rotation (Key Vault secret versions, plan 5.6)",
    "DATA_ENCRYPTION_KEYS_PREVIOUS": "only during a rotation (docs/ops/KEY-ROTATION.md)",
    "SERVER_PEPPERS_PREVIOUS": "only during a rotation",
    "AUDIT_CHAIN_KEYS_PREVIOUS": "only during a rotation",
    "CONNECT_LINK_SIGNING_KEYS_PREVIOUS": "only during a rotation",
    "AUDIT_CHAIN_LEGACY_THROUGH_SEQ": "removed: fresh database (plan 5.6)",
    "EMAIL_API_AUTH_HEADER": "plain configuration when the provider needs it (app_env)",
    "EMAIL_API_AUTH_SCHEME": "plain configuration when the provider needs it (app_env)",
    "AZURE_KEY_VAULT_AUDIT_HEAD_KEY": "set on the worker (containerapps.tf process_env.worker)",
}
# Names the server reads that are not in .env.example.
EXTRA_KNOWN = {"AUDIT_CHAIN_LEGACY_THROUGH_SEQ", "PASS_CERTIFICATE_PEM", "PASS_PRIVATE_KEY_PEM", "PASS_WWDR_CERTIFICATE_PEM",
               "BIND_HOST", "EMAIL_API_AUTH_HEADER", "EMAIL_API_AUTH_SCHEME"}
# Retired by WP-B2: must not be set anywhere in the Azure module.
RETIRED = {"GCP_WORKLOAD_IDENTITY_AUDIENCE", "GCP_SERVICE_ACCOUNT_EMAIL", "GCP_SUBJECT_TOKEN_FILE", "AUDIT_HEAD_KMS_KEY", "AUDIT_HEAD_EXPORT_ENDPOINT",
           "AUDIT_HEAD_EXPORT_ACCESS_KEY_ID", "AUDIT_HEAD_EXPORT_SECRET_ACCESS_KEY", "FLY_PRIVATE_IP"}
# The contract of docs/ops/AZURE-SETUP.md section 11: the module must set every one of them.
CONTRACT = {"ENVIRONMENT", "PORT", "BIND_HOST", "AUTO_MIGRATE", "RATE_LIMIT_STORE", "RUN_BACKGROUND_JOBS", "DATABASE_APP_ROLE", "ROLE", "AZURE_CLIENT_ID",
            "AZURE_TENANT_ID", "AZURE_KEY_VAULT_URL", "AZURE_KEY_VAULT_KEK_KEY", "AZURE_KEY_VAULT_KD_LOG_KEY", "AZURE_KEY_VAULT_LINK_DESCRIPTOR_KEY",
            "AZURE_KEY_VAULT_AUDIT_HEAD_KEY", "AZURE_AUDIT_BLOB_ENDPOINT", "AZURE_AUDIT_BLOB_CONTAINER", "AZURE_SERVICEBUS_FQDN", "QUEUE_TRANSPORT",
            "DATABASE_HOST", "DATABASE_NAME", "DATABASE_USER", "DATABASE_AUTH", "HEALTH_PEER_NETWORKS", "DATABASE_WORKER_ROLE"}


def env_keys(text: str) -> set[str]:
    """Upper-case keys assigned in HCL maps (`NAME = ...`)."""
    return set(re.findall(r"^\s*([A-Z][A-Z0-9_]{2,})\s*=", text, re.M))


def block(text: str, start: str) -> str:
    """The text of the `{ ... }` block that follows `start` (balanced braces)."""
    index = text.index(start)
    open_at = text.index("{", index)
    depth = 0
    for position in range(open_at, len(text)):
        depth += {"{": 1, "}": -1}.get(text[position], 0)
        if depth == 0:
            return text[open_at:position + 1]
    raise ValueError(start)


example = set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]{2,})=", (root / "Server/.env.example").read_text(), re.M))
containerapps = (here / "containerapps.tf").read_text()
locals_tf = (here / "locals.tf").read_text()
variables = (here / "variables.tf").read_text()
tfvars = (here / "terraform.tfvars.example").read_text()

module_env = env_keys(block(containerapps, "base_env = {")) | env_keys(block(containerapps, "process_env = {"))
# A service key may be referenced in its envelope-wrapped form (`<NAME>_WRAPPED`, SECURITY.md §2.92); it accounts for `<NAME>`.
WRAPPABLE = {"DATA_ENCRYPTION_KEY", "SERVER_PEPPER", "AUDIT_CHAIN_KEY", "SUBJECT_REF_KEY", "CONNECT_LINK_SIGNING_KEY", "DATA_ENCRYPTION_KEYS_PREVIOUS",
             "SERVER_PEPPERS_PREVIOUS", "AUDIT_CHAIN_KEYS_PREVIOUS", "CONNECT_LINK_SIGNING_KEYS_PREVIOUS"}
raw_secrets = env_keys(block(variables, 'variable "app_secret_env"')) | env_keys(block(locals_tf, "db_password_secret")) | {"DATABASE_MIGRATION_URL"}
secrets = {name[: -len("_WRAPPED")] if name.endswith("_WRAPPED") and name[: -len("_WRAPPED")] in WRAPPABLE else name for name in raw_secrets}
app_env = env_keys(block(tfvars, "app_env = {"))
accounted = module_env | secrets | app_env

problems = []
for var in sorted(example):
    if var not in accounted and var not in EXEMPT:
        problems.append(f"{var}: not set by Infra/azure, not a Key Vault reference, not in terraform.tfvars.example app_env, not EXEMPT")
for var in sorted((module_env | app_env | secrets) - example - EXTRA_KNOWN):
    problems.append(f"{var}: set by Infra/azure but unknown to Server/.env.example (typo?)")
for var in sorted((module_env | app_env | secrets) & RETIRED):
    problems.append(f"{var}: retired by WP-B2 but still set by Infra/azure")
for var in sorted(app_env & secrets):
    problems.append(f"{var}: a secret must be a Key Vault reference, never a plain app_env value")
for var in sorted(CONTRACT - module_env):
    problems.append(f"{var}: part of the AZURE-SETUP.md section 11 contract but not set by containerapps.tf")
for var in sorted(RETIRED & example):
    problems.append(f"{var}: retired by WP-B2 but still in Server/.env.example")

if problems:
    print("\n".join(problems))
    sys.exit(1)
print(f"ok: {len(example)} variables in .env.example; module sets {len(module_env)}, {len(secrets)} Key Vault references, {len(app_env)} app_env keys, "
      f"{len(EXEMPT)} exempt")
