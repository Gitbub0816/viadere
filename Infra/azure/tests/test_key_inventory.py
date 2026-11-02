"""Tests for .github/scripts/key_inventory.py (JWKS publication gate, ADR-0024 section 7.3)."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / ".github" / "scripts"))
import key_inventory  # noqa: E402

# RFC 7638 section 3.1 example key and its documented thumbprint.
RFC_JWK = {"kty": "RSA", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                       "e": "AQAB", "alg": "RS256", "kid": "2011-04-29"}


class Inventory(unittest.TestCase):
    def test_rfc7638_vector(self):
        self.assertEqual(key_inventory.thumbprint(RFC_JWK), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")

    def test_inventory_from_log_lines_ignores_everything_else(self):
        public = {"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
        rows = [{"Log_s": "starting"}, {"Log_s": "VIADERE-KEY-INVENTORY " + json.dumps({"name": "grant-signing", "version": "v1", "jwk": public})}]
        inventory = key_inventory.build(rows)
        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0]["thumbprint"], key_inventory.thumbprint(public))

    def test_private_member_is_refused(self):
        rows = [{"Log_s": "VIADERE-KEY-INVENTORY " + json.dumps({"name": "x", "jwk": {"kty": "EC", "crv": "P-256", "x": "a", "y": "b", "d": "secret"}})}]
        with self.assertRaises(SystemExit):
            key_inventory.build(rows)

    def test_no_lines_is_an_error(self):
        with self.assertRaises(SystemExit):
            key_inventory.build([{"Log_s": "nothing"}])

    def test_unknown_kid_is_reported(self):
        listed = {"kty": "RSA", "n": RFC_JWK["n"], "e": "AQAB", "alg": "RS256", "use": "sig", "kid": key_inventory.thumbprint(RFC_JWK)}
        stranger = dict(listed, n="AAAA", kid="not-in-inventory")
        inventory = [{"thumbprint": key_inventory.thumbprint(RFC_JWK)}]
        self.assertEqual(key_inventory.check({"keys": [listed]}, inventory), [])
        self.assertTrue(key_inventory.check({"keys": [listed, stranger]}, inventory))

    def test_hand_pasted_value_with_wrong_kid_fails(self):
        jwk = dict(RFC_JWK, use="sig", kid="other")
        self.assertTrue(key_inventory.check({"keys": [jwk]}, [{"thumbprint": key_inventory.thumbprint(RFC_JWK)}]))


if __name__ == "__main__":
    unittest.main()
