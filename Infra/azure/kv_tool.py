#!/usr/bin/env python3
"""Owner helper for the Azure environment (docs/ops/AZURE-SETUP.md sections 7 and 8). Python standard library + the Azure CLI (`az`).

Secret values are written through the ARM control plane (PUT Microsoft.KeyVault/vaults/secrets), which works whether or not the vault's
public endpoint is reachable from this machine (standard profile: private endpoint only). Values are never printed, never put on a command
line (they travel in a mode-600 temporary file inside a mode-700 directory that is deleted afterwards) and never written to the repository.

    # every server secret from an env file made by `python3 -I Infra/fly/generate_secrets.py --env-file s.env` (plus the third-party values
    # you add to it); NAME -> secret name comes from `tofu output -json key_vault_secret_map`:
    python3 -I Infra/azure/kv_tool.py put-env --vault-id "$KV_ID" --map map.json --env-file s.env

    # one secret, value read from stdin (or typed without echo):
    python3 -I Infra/azure/kv_tool.py put --vault-id "$KV_ID" --name cloudflared-tunnel-token < token.txt

    # database passwords (until WP-B2 ships Entra token auth): generates the viadere_app and viadere_migrator passwords, stores
    # database-url and database-migration-url in Key Vault, and writes the role SQL with SCRAM-SHA-256 verifiers (no plaintext password)
    # to a new mode-600 file for the one-off psql job:
    python3 -I Infra/azure/kv_tool.py db-passwords --vault-id "$KV_ID" --host "$PG_FQDN" --sql-out db-roles.sql

    # one-off psql job spec (for `az containerapp job create --yaml`): fetches your Entra token for PostgreSQL with `az`, mounts the SQL
    # as a secret file; the spec file (mode 600) holds the token and must be deleted after use:
    python3 -I Infra/azure/kv_tool.py psql-job --environment-id "$CAE_ID" --host "$PG_FQDN" --sql db-roles.sql --out dbadmin-job.json
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile

API_VERSION = "2026-02-01"  # Microsoft.KeyVault, newest GA in the azapi 2.13.0 schema set (2026-10-29)
VAULT_ID_RE = re.compile(r"^/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/[A-Za-z0-9-]{3,24}$", re.I)
SECRET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,126}$")
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
SCRAM_ITERATIONS = 4096  # PostgreSQL's default scram_iterations
PSQL_IMAGE = "docker.io/library/postgres:18.6@sha256:979bccfde35445db618c65107d27d08c6c21339d8dc3ad4c830c6633947be0e4"  # 2026-10-28
ENV_ID_RE = re.compile(r"^/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/]+/providers/Microsoft\.App/managedEnvironments/[A-Za-z0-9-]+$", re.I)


def parse_env_file(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    with open(path, encoding="utf-8") as handle:
        for number, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            name, sep, value = line.partition("=")
            name = name.strip()
            if not sep or not ENV_NAME_RE.match(name):
                raise SystemExit(f"{path}:{number}: not NAME=value")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            values[name] = value
    return values


def plan_env_upload(values: dict[str, str], mapping: dict[str, str]) -> tuple[list[tuple[str, str]], list[str]]:
    """(secret name, env name) pairs to write, and env names that have no Key Vault secret (skipped)."""
    pairs, skipped = [], []
    for name in sorted(values):
        secret = mapping.get(name)
        if secret is None:
            skipped.append(name)
            continue
        if not SECRET_NAME_RE.match(secret):
            raise SystemExit(f"invalid secret name in map for {name}: {secret!r}")
        if not values[name]:
            raise SystemExit(f"{name} is empty; refusing to store an empty secret")
        pairs.append((secret, name))
    return pairs, skipped


def scram_sha256_verifier(password: str, salt: bytes | None = None, iterations: int = SCRAM_ITERATIONS) -> str:
    """PostgreSQL's stored SCRAM-SHA-256 verifier: SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey> (RFC 5802/7677)."""
    salt = salt if salt is not None else secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731
    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


def database_url(role: str, password: str, host: str, database: str = "viadere") -> str:
    # token_urlsafe passwords need no percent-encoding.
    return f"postgres://{role}:{password}@{host}:5432/{database}?sslmode=verify-full"


def role_sql(app_verifier: str, migrator_verifier: str, database: str = "viadere") -> str:
    """SQL run once by the PostgreSQL Entra admin group (docs/ops/AZURE-SETUP.md section 8); mirrors docs/ops/STAGING-SETUP.md 4.2."""
    for v in (app_verifier, migrator_verifier):
        if not v.startswith("SCRAM-SHA-256$") or "'" in v:
            raise ValueError("not a SCRAM verifier")
    return f"""\\set ON_ERROR_STOP on
-- Viadere database roles (password roles until WP-B2 ships Entra token auth). Run as a member of the PostgreSQL Entra admin group.
CREATE ROLE viadere_migrator LOGIN PASSWORD '{migrator_verifier}';
CREATE ROLE viadere_app LOGIN PASSWORD '{app_verifier}';
-- PostgreSQL 16+: the creator must be able to SET ROLE to the new owner.
GRANT viadere_migrator TO CURRENT_USER;
ALTER DATABASE {database} OWNER TO viadere_migrator;
REVOKE viadere_migrator FROM CURRENT_USER;
GRANT CONNECT ON DATABASE {database} TO viadere_app;
-- `ViadereServer migrate` (job-viadere-migrate) creates the schema as viadere_migrator and grants viadere_app DML only.
"""


def psql_job_spec(environment_id: str, host: str, sql: str, token: str, admin_group: str = "grp-viadere-db-admins") -> dict:
    """Container Apps job (az containerapp job create --yaml) that runs `sql` once as the PostgreSQL Entra admin group."""
    if not ENV_ID_RE.match(environment_id):
        raise SystemExit("--environment-id must be the Container Apps environment's ARM id")
    if not token or not sql.strip():
        raise SystemExit("empty token or SQL")
    return {
        "location": "eastus",
        "properties": {
            "environmentId": environment_id,
            "workloadProfileName": "Consumption",
            "configuration": {
                "triggerType": "Manual",
                "replicaTimeout": 600,
                "replicaRetryLimit": 0,
                "manualTriggerConfig": {"parallelism": 1, "replicaCompletionCount": 1},
                "secrets": [{"name": "pgtoken", "value": token}, {"name": "rolesql", "value": sql}],
            },
            "template": {
                "containers": [{
                    "name": "psql",
                    "image": PSQL_IMAGE,
                    "resources": {"cpu": 0.25, "memory": "0.5Gi"},
                    "command": ["psql", "-X", "-v", "ON_ERROR_STOP=1", "-f", "/mnt/sql/rolesql"],
                    "env": [
                        {"name": "PGHOST", "value": host},
                        {"name": "PGDATABASE", "value": "postgres"},
                        {"name": "PGUSER", "value": admin_group},
                        {"name": "PGSSLMODE", "value": "verify-full"},
                        {"name": "PGSSLROOTCERT", "value": "system"},
                        {"name": "PGPASSWORD", "secretRef": "pgtoken"},
                    ],
                    "volumeMounts": [{"volumeName": "sql", "mountPath": "/mnt/sql"}],
                }],
                "volumes": [{"name": "sql", "storageType": "Secret", "secrets": [{"secretRef": "rolesql", "path": "rolesql"}]}],
            },
        },
    }


def entra_postgres_token(*, az: str = "az", runner=subprocess.run) -> str:
    result = runner([az, "account", "get-access-token", "--resource-type", "oss-rdbms", "--query", "accessToken", "-o", "tsv"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0 or not result.stdout.strip():
        raise SystemExit("could not get an Entra token for PostgreSQL (az login as a member of grp-viadere-db-admins)")
    return result.stdout.strip()


def write_private_file(path: str, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)


def az_put_secret(vault_id: str, name: str, value: str, *, az: str = "az", runner=subprocess.run) -> None:
    if not VAULT_ID_RE.match(vault_id):
        raise SystemExit("--vault-id must be the vault's ARM id (tofu output -json key_vault | .id)")
    if not SECRET_NAME_RE.match(name):
        raise SystemExit(f"invalid secret name {name!r}")
    if not value:
        raise SystemExit(f"refusing to store an empty value for {name}")
    directory = tempfile.mkdtemp(prefix="kvtool-")
    try:
        os.chmod(directory, 0o700)
        body = os.path.join(directory, "body.json")
        write_private_file(body, json.dumps({"properties": {"value": value, "contentType": "text/plain"}}))
        url = f"https://management.azure.com{vault_id}/secrets/{name}?api-version={API_VERSION}"
        result = runner([az, "rest", "--method", "put", "--url", url, "--body", f"@{body}", "--output", "none"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            # az echoes the request URL, never the body; still, print only the first line of the error.
            first = (result.stderr or "").strip().splitlines()[:1]
            raise SystemExit(f"az rest failed for {name}: {first[0] if first else 'no message'}")
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    print(f"set {name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write Viadere secrets to Key Vault through the ARM control plane.")
    sub = parser.add_subparsers(dest="command", required=True)
    p_env = sub.add_parser("put-env", help="store every mapped NAME=value of an env file")
    p_env.add_argument("--vault-id", required=True)
    p_env.add_argument("--map", required=True, help="JSON object ENV_NAME -> secret name (tofu output -json key_vault_secret_map)")
    p_env.add_argument("--env-file", required=True)
    p_env.add_argument("--dry-run", action="store_true", help="list what would be stored (names only)")
    p_one = sub.add_parser("put", help="store one secret read from stdin")
    p_one.add_argument("--vault-id", required=True)
    p_one.add_argument("--name", required=True)
    p_db = sub.add_parser("db-passwords", help="generate DB passwords, store the URLs, write the role SQL with SCRAM verifiers")
    p_db.add_argument("--vault-id", required=True)
    p_db.add_argument("--host", required=True, help="PostgreSQL FQDN (tofu output -json postgres | .fqdn)")
    p_db.add_argument("--sql-out", required=True, help="new file for the role SQL (mode 600; delete it after use)")
    p_job = sub.add_parser("psql-job", help="write a one-off psql job spec that runs a SQL file as the Entra admin group")
    p_job.add_argument("--environment-id", required=True, help="tofu output -json container_apps_environment | .id")
    p_job.add_argument("--host", required=True)
    p_job.add_argument("--sql", required=True)
    p_job.add_argument("--out", required=True, help="new file (mode 600); holds your token: delete it after `job create`")
    p_job.add_argument("--admin-group", default="grp-viadere-db-admins")
    args = parser.parse_args(argv)

    if args.command == "psql-job":
        with open(args.sql, encoding="utf-8") as handle:
            sql = handle.read()
        spec = psql_job_spec(args.environment_id, args.host, sql, entra_postgres_token(), args.admin_group)
        write_private_file(args.out, json.dumps(spec, indent=1))
        print(f"wrote {args.out}; run: az containerapp job create -n job-viadere-dbadmin -g <app rg> --yaml {args.out}")
        return 0

    if args.command == "put-env":
        with open(args.map, encoding="utf-8") as handle:
            mapping = json.load(handle)
        if not isinstance(mapping, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in mapping.items()):
            raise SystemExit("--map must be a JSON object of strings")
        pairs, skipped = plan_env_upload(parse_env_file(args.env_file), mapping)
        values = parse_env_file(args.env_file)
        for secret, env_name in pairs:
            if args.dry_run:
                print(f"would set {secret} from {env_name}")
            else:
                az_put_secret(args.vault_id, secret, values[env_name])
        for name in skipped:
            print(f"skipped {name}: no Key Vault secret is mapped to it (not used on Azure, or plain configuration)")
        missing = sorted(set(mapping) - {env for _, env in pairs})
        for name in missing:
            print(f"NOT SET {name} -> {mapping[name]}: not in the env file (set it separately)")
        return 0
    if args.command == "put":
        value = getpass.getpass(f"{args.name}: ") if sys.stdin.isatty() else sys.stdin.read().rstrip("\n")
        az_put_secret(args.vault_id, args.name, value)
        return 0
    # db-passwords
    if not re.match(r"^[a-z0-9-]+\.postgres\.database\.azure\.com$", args.host):
        raise SystemExit("--host must be the server FQDN (<name>.postgres.database.azure.com)")
    app_pw, migrator_pw = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    sql = role_sql(scram_sha256_verifier(app_pw), scram_sha256_verifier(migrator_pw))
    write_private_file(args.sql_out, sql)  # first, so an existing file aborts before anything is stored
    az_put_secret(args.vault_id, "database-url", database_url("viadere_app", app_pw, args.host))
    az_put_secret(args.vault_id, "database-migration-url", database_url("viadere_migrator", migrator_pw, args.host))
    print(f"wrote {args.sql_out} (SCRAM verifiers only); run it with the one-off psql job, then delete it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
