"""Unit tests for Infra/azure/kv_tool.py (no network, no az: the subprocess runner is replaced).

Run:  python3 -I -m unittest discover -s Infra/azure/tests -t Infra/azure/tests
"""
from __future__ import annotations

import base64
import hashlib
import io
import hmac
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import kv_tool  # noqa: E402

VAULT = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-sec/providers/Microsoft.KeyVault/vaults/kv-vdr-stgabc1l"


class EnvFiles(unittest.TestCase):
    def write(self, text: str) -> str:
        handle = tempfile.NamedTemporaryFile("w", delete=False, suffix=".env")
        handle.write(text)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_parses_quotes_and_comments(self):
        path = self.write("# comment\nSERVER_PEPPER=abc\nEDGE_TOKEN='x y'\n\nAPNS_KEY_P8=\"k\"\n")
        self.assertEqual(kv_tool.parse_env_file(path), {"SERVER_PEPPER": "abc", "EDGE_TOKEN": "x y", "APNS_KEY_P8": "k"})

    def test_rejects_malformed_lines(self):
        with self.assertRaises(SystemExit):
            kv_tool.parse_env_file(self.write("lowercase=1\n"))

    def test_upload_plan_maps_and_skips(self):
        pairs, skipped = kv_tool.plan_env_upload({"SERVER_PEPPER": "a", "METRICS_TOKEN": "b"}, {"SERVER_PEPPER": "server-pepper"})
        self.assertEqual(pairs, [("server-pepper", "SERVER_PEPPER")])
        self.assertEqual(skipped, ["METRICS_TOKEN"])

    def test_upload_plan_refuses_empty_values(self):
        with self.assertRaises(SystemExit):
            kv_tool.plan_env_upload({"SERVER_PEPPER": ""}, {"SERVER_PEPPER": "server-pepper"})


class Scram(unittest.TestCase):
    def test_verifier_matches_rfc_5802_derivation(self):
        salt = bytes(range(16))
        verifier = kv_tool.scram_sha256_verifier("pencil", salt=salt, iterations=4096)
        head, keys = verifier.split("$", 1)[1].split("$")
        iterations, salt_b64 = head.split(":")
        stored_b64, server_b64 = keys.split(":")
        self.assertEqual(int(iterations), 4096)
        self.assertEqual(base64.b64decode(salt_b64), salt)
        salted = hashlib.pbkdf2_hmac("sha256", b"pencil", salt, 4096)
        client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
        self.assertEqual(base64.b64decode(stored_b64), hashlib.sha256(client_key).digest())
        self.assertEqual(base64.b64decode(server_b64), hmac.new(salted, b"Server Key", hashlib.sha256).digest())

    def test_role_sql_contains_no_plaintext(self):
        password = "correct-horse-battery-staple"
        sql = kv_tool.role_sql(kv_tool.scram_sha256_verifier(password), kv_tool.scram_sha256_verifier("other"))
        self.assertNotIn(password, sql)
        self.assertIn("CREATE ROLE viadere_app LOGIN PASSWORD 'SCRAM-SHA-256$4096:", sql)
        self.assertIn("ALTER DATABASE viadere OWNER TO viadere_migrator;", sql)

    def test_role_sql_rejects_non_verifiers(self):
        with self.assertRaises(ValueError):
            kv_tool.role_sql("plaintext", kv_tool.scram_sha256_verifier("x"))


class Put(unittest.TestCase):
    def test_value_travels_in_a_private_file_not_on_the_command_line(self):
        seen = {}

        def runner(cmd, **kwargs):
            body = cmd[cmd.index("--body") + 1][1:]
            seen["cmd"] = cmd
            seen["mode"] = stat.S_IMODE(os.stat(body).st_mode)
            seen["body"] = json.loads(Path(body).read_text())
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with redirect_stdout(io.StringIO()):
            kv_tool.az_put_secret(VAULT, "server-pepper", "s3cr3t-value", runner=runner)
        self.assertNotIn("s3cr3t-value", " ".join(seen["cmd"]))
        self.assertEqual(seen["mode"], 0o600)
        self.assertEqual(seen["body"]["properties"]["value"], "s3cr3t-value")
        self.assertIn(f"https://management.azure.com{VAULT}/secrets/server-pepper?api-version=", " ".join(seen["cmd"]))

    def test_temporary_file_is_removed_even_on_failure(self):
        seen = {}

        def runner(cmd, **kwargs):
            seen["body"] = cmd[cmd.index("--body") + 1][1:]
            return subprocess.CompletedProcess(cmd, 1, "", "ERROR: forbidden\nmore")

        with self.assertRaises(SystemExit) as ctx:
            kv_tool.az_put_secret(VAULT, "server-pepper", "v", runner=runner)
        self.assertIn("forbidden", str(ctx.exception))
        self.assertFalse(os.path.exists(seen["body"]))

    def test_rejects_bad_vault_ids_and_names(self):
        never = lambda *a, **k: self.fail("az must not run")  # noqa: E731
        with self.assertRaises(SystemExit):
            kv_tool.az_put_secret("kv-vdr-stg", "x", "v", runner=never)
        with self.assertRaises(SystemExit):
            kv_tool.az_put_secret(VAULT, "Bad_Name", "v", runner=never)
        with self.assertRaises(SystemExit):
            kv_tool.az_put_secret(VAULT, "ok", "", runner=never)

    def test_database_url_uses_verify_full(self):
        self.assertEqual(kv_tool.database_url("viadere_app", "pw", "psql-x.postgres.database.azure.com"),
                         "postgres://viadere_app:pw@psql-x.postgres.database.azure.com:5432/viadere?sslmode=verify-full")


class PsqlJob(unittest.TestCase):
    ENV = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-app/providers/Microsoft.App/managedEnvironments/cae-viadere-stg"

    def test_sql_is_mounted_and_token_is_a_secret_reference(self):
        spec = kv_tool.psql_job_spec(self.ENV, "psql-x.postgres.database.azure.com", "SELECT 1;", "eyJ0eXAi-entra-token")
        container = spec["properties"]["template"]["containers"][0]
        env = {e["name"]: e for e in container["env"]}
        self.assertEqual(env["PGPASSWORD"], {"name": "PGPASSWORD", "secretRef": "pgtoken"})
        self.assertNotIn("eyJ0eXAi-entra-token", json.dumps(container))
        self.assertEqual(container["command"][-1], "/mnt/sql/rolesql")
        self.assertIn("@sha256:", container["image"])
        self.assertEqual(spec["properties"]["configuration"]["replicaRetryLimit"], 0)

    def test_rejects_bad_environment_id(self):
        with self.assertRaises(SystemExit):
            kv_tool.psql_job_spec("cae-viadere-stg", "h", "SELECT 1;", "tok")

    def test_token_errors_are_reported(self):
        failing = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "no login")  # noqa: E731
        with self.assertRaises(SystemExit):
            kv_tool.entra_postgres_token(runner=failing)


if __name__ == "__main__":
    unittest.main()
