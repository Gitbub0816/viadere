"""Tests for .github/scripts/key_inventory.py (reviewed key inventory and JWKS publication gate, ADR-0024 section 7.3, ledger S6-06)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / ".github" / "scripts"))
import key_inventory  # noqa: E402

# RFC 7638 section 3.1 example key and its documented thumbprint.
RFC_JWK = {"kty": "RSA", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                       "e": "AQAB", "alg": "RS256", "kid": "2011-04-29"}
EC_JWK = {"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
VERSION = "0123456789abcdef0123456789abcdef"
TEMPLATE = (ROOT / "Infra" / "azure-authority" / "publish" / "openid-configuration.template.json").read_text()


def change(**extra):
    return {"keys": [{"name": "oidc-signing-rs256", "version": VERSION, "jwk": RFC_JWK},
                     {"name": "grant-signing", "version": VERSION, "jwk": EC_JWK}], **extra}


class Inventory(unittest.TestCase):
    def test_rfc7638_vector(self):
        self.assertEqual(key_inventory.thumbprint(RFC_JWK), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")

    def test_inventory_comes_from_the_reviewed_change_file_with_public_members_only(self):
        inventory = key_inventory.from_change_file(change())
        self.assertEqual([e["thumbprint"] for e in inventory], [key_inventory.thumbprint(RFC_JWK), key_inventory.thumbprint(EC_JWK)])
        # Non-key members (kid, alg) are dropped; only kty/n/e or kty/crv/x/y remain.
        self.assertEqual(set(inventory[0]["jwk"]), {"kty", "n", "e"})

    def test_no_log_reading_mode_exists(self):
        # S6-06: the old log parser is gone; nothing in the tool looks for printed inventory lines.
        self.assertFalse(hasattr(key_inventory, "build"))
        self.assertNotIn("VIADERE-KEY-INVENTORY", (ROOT / ".github" / "scripts" / "key_inventory.py").read_text())
        workflow = (ROOT / ".github" / "workflows" / "authority-admin.yml").read_text()
        self.assertNotIn("log-analytics", workflow)
        self.assertIn("key-inventory-check", workflow)

    def test_private_members_and_bad_entries_are_refused(self):
        for bad in [change(keys=[{"name": "grant-signing", "version": VERSION, "jwk": dict(EC_JWK, d="secret")}]),
                    {"keys": [{"name": "Grant Signing", "version": VERSION, "jwk": EC_JWK}]},
                    {"keys": [{"name": "grant-signing", "version": "latest", "jwk": EC_JWK}]},
                    {"keys": [{"name": "grant-signing", "version": VERSION, "jwk": EC_JWK, "pinned": True}]},
                    {"keys": [{"name": "a", "version": VERSION, "jwk": EC_JWK}, {"name": "b", "version": VERSION, "jwk": EC_JWK}]},
                    {"seal_keys": [{"kid": "not-the-thumbprint", "jwk": EC_JWK}]},
                    {"other": []}]:
            with self.assertRaises(SystemExit, msg=json.dumps(bad)[:80]):
                key_inventory.from_change_file(bad)

    def test_unknown_kid_is_reported(self):
        listed = {"kty": "RSA", "n": RFC_JWK["n"], "e": "AQAB", "alg": "RS256", "use": "sig", "kid": key_inventory.thumbprint(RFC_JWK)}
        stranger = dict(listed, n="AAAA", kid="not-in-inventory")
        inventory = [{"thumbprint": key_inventory.thumbprint(RFC_JWK)}]
        self.assertEqual(key_inventory.check({"keys": [listed]}, inventory), [])
        self.assertTrue(key_inventory.check({"keys": [listed, stranger]}, inventory))

    def test_hand_pasted_value_with_wrong_kid_fails(self):
        jwk = dict(RFC_JWK, use="sig", kid="other")
        self.assertTrue(key_inventory.check({"keys": [jwk]}, [{"thumbprint": key_inventory.thumbprint(RFC_JWK)}]))


class Documents(unittest.TestCase):
    def test_documents_are_built_from_the_inventory_and_pass_the_publication_gate(self):
        inventory = key_inventory.from_change_file(change())
        docs = key_inventory.documents(inventory, "https://id.staging.example", TEMPLATE)
        discovery = json.loads(docs[".well-known/openid-configuration"])
        self.assertEqual(discovery["issuer"], "https://id.staging.example")
        self.assertEqual(discovery["jwks_uri"], "https://id.staging.example/oidc/jwks.json")
        oidc, grant = json.loads(docs["oidc/jwks.json"]), json.loads(docs["grant/jwks.json"])
        self.assertEqual([k["alg"] for k in oidc["keys"]], ["RS256"])
        self.assertEqual([k["alg"] for k in grant["keys"]], ["ES256"])
        # The grant JWKS and the OIDC JWKS never share a key, and both pass the gate the publish workflow runs.
        self.assertFalse({k["kid"] for k in oidc["keys"]} & {k["kid"] for k in grant["keys"]})
        self.assertEqual(key_inventory.check(oidc, inventory), [])
        self.assertEqual(key_inventory.check(grant, inventory), [])
        with tempfile.TemporaryDirectory() as out:
            inv = Path(out) / "inv.json"
            inv.write_text(json.dumps(inventory))
            tpl = Path(out) / "t.json"
            tpl.write_text(TEMPLATE)
            self.assertEqual(key_inventory.main(["x", "--documents", str(inv), "https://id.staging.example", str(tpl), str(Path(out) / "id")]), 0)
            self.assertTrue((Path(out) / "id" / ".well-known" / "openid-configuration").exists())

    def test_bad_issuers_are_refused(self):
        inventory = key_inventory.from_change_file(change())
        for issuer in ["http://id.example.com", "https://id.example.com/", "https://id.example.com/path", "https://ID.example.com", "https://localhost"]:
            with self.assertRaises(SystemExit, msg=issuer):
                key_inventory.documents(inventory, issuer, TEMPLATE)


if __name__ == "__main__":
    unittest.main()
