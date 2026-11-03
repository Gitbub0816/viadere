#!/usr/bin/env python3
"""Authority key inventory tooling (ADR-0024 section 7.3, ledger S6-06). Standard library only; run with `python3 -I`.

  key_inventory.py --change-file CHANGE.json OUT.json
        build the inventory from a REVIEWED change file (Infra/azure-authority/changes/*.json, CODEOWNERS on protected main):
        {"keys": [{"name", "version", "jwk"}], "seal_keys": [{"kid", "jwk"}]}. Public members only; every RFC 7638 thumbprint is re-derived.
        authority-admin.yml attests OUT.json only after `ViadereAuthority admin key-inventory-check` succeeded, i.e. after the serving
        authority verified every entry against its own source of truth (Key Vault at exactly name/version, or its unwrapped seal key).
        Nothing is read from any log.
  key_inventory.py --check JWKS.json INVENTORY.json
        every JWK of a published set must be in the attested inventory (kid = thumbprint)
  key_inventory.py --documents INVENTORY.json ISSUER TEMPLATE OUTDIR
        write the static id. documents from the attested inventory: OUTDIR/.well-known/openid-configuration (TEMPLATE with the issuer;
        the template is pinned to Core's OIDCProfile.discoveryDocument by a Swift test), OUTDIR/oidc/jwks.json (oidc-signing-rs256,
        oidc-signing-es256) and OUTDIR/grant/jwks.json (grant-signing)
"""
import base64
import hashlib
import json
import os
import re
import sys

PRIVATE = {"d", "p", "q", "dp", "dq", "qi", "k", "oth"}
NAME = re.compile(r"^[a-z0-9-]{1,127}$")
VERSION = re.compile(r"^[0-9a-fA-F]{32}$")
ISSUER = re.compile(r"^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
SETS = {"oidc": {"oidc-signing-rs256": "RS256", "oidc-signing-es256": "ES256"}, "grant": {"grant-signing": "ES256"}}


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def thumbprint(jwk: dict) -> str:
    kty = jwk.get("kty")
    if kty == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:
        raise ValueError(f"unsupported kty {kty!r}")
    canonical = json.dumps(members, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()


def public_jwk(jwk: object) -> dict:
    """The key members only (EC P-256: kty, crv, x, y; RSA: kty, n, e). A private member anywhere is an error."""
    if not isinstance(jwk, dict):
        raise SystemExit("jwk must be an object")
    if PRIVATE & set(jwk):
        raise SystemExit("private key member in an inventory JWK: refused")
    if jwk.get("kty") == "EC":
        if jwk.get("crv") != "P-256" or len(b64url_decode(jwk.get("x", ""))) != 32 or len(b64url_decode(jwk.get("y", ""))) != 32:
            raise SystemExit("EC JWK must be P-256 with 32-byte x and y")
        return {"kty": "EC", "crv": "P-256", "x": jwk["x"], "y": jwk["y"]}
    if jwk.get("kty") == "RSA":
        if len(b64url_decode(jwk.get("n", ""))) < 256 or not jwk.get("e"):
            raise SystemExit("RSA JWK must have n (2048 bits or more) and e")
        return {"kty": "RSA", "n": jwk["n"], "e": jwk["e"]}
    raise SystemExit("jwk kty must be EC or RSA")


def from_change_file(change: dict) -> list:
    """The strict change-file schema of `ViadereAuthority admin key-inventory-record` (AuthorityAdminKeys.swift parseInventory)."""
    if not isinstance(change, dict) or not change or not set(change) <= {"keys", "seal_keys"}:
        raise SystemExit("change file members: keys and/or seal_keys")
    entries = []
    for item in change.get("keys", []):
        if not isinstance(item, dict) or set(item) != {"name", "version", "jwk"}:
            raise SystemExit("keys entry members: name, version, jwk")
        if not NAME.match(str(item["name"])) or not VERSION.match(str(item["version"])):
            raise SystemExit(f"invalid name or version in {item.get('name')!r}")
        jwk = public_jwk(item["jwk"])
        entries.append({"name": item["name"], "version": item["version"].lower(), "source": "key_vault", "seal_row": None, "jwk": jwk,
                        "thumbprint": thumbprint(jwk)})
    for item in change.get("seal_keys", []):
        if not isinstance(item, dict) or set(item) != {"kid", "jwk"}:
            raise SystemExit("seal_keys entry members: kid, jwk")
        jwk = public_jwk(item["jwk"])
        if jwk["kty"] != "EC" or thumbprint(jwk) != item["kid"]:
            raise SystemExit("seal key kid must be the RFC 7638 thumbprint of its EC JWK")
        entries.append({"name": "recovery-seal", "version": item["kid"], "source": "seal_key", "seal_row": item["kid"], "jwk": jwk,
                        "thumbprint": item["kid"]})
    if not entries or len(entries) > 20 or len({e["thumbprint"] for e in entries}) != len(entries):
        raise SystemExit("1-20 entries with distinct keys")
    return entries


def check(jwks: dict, inventory: list) -> list:
    known = {e["thumbprint"] for e in inventory}
    problems = []
    for jwk in jwks.get("keys", []):
        if PRIVATE & set(jwk):
            problems.append("private member in a published JWK")
            continue
        tp = thumbprint(jwk)
        if tp not in known:
            problems.append(f"kid {jwk.get('kid')!r} (thumbprint {tp}) is not in the attested inventory")
        elif jwk.get("kid") not in {tp, None}:
            problems.append(f"kid {jwk.get('kid')!r} differs from its thumbprint {tp}")
        if jwk.get("use") != "sig" or jwk.get("alg") not in {"RS256", "ES256"}:
            problems.append(f"kid {jwk.get('kid')!r}: use must be sig and alg RS256 or ES256")
    return problems


def documents(inventory: list, issuer: str, template: str) -> dict:
    """{relative path: JSON text} of the static id. documents. Only Key Vault entries of the listed names are published; an issuer that is not
    an https host (no path, no trailing slash) is refused."""
    if not ISSUER.match(issuer):
        raise SystemExit("issuer must be https://<host> with no path and no trailing slash")
    if "{{ISSUER}}" not in template:
        raise SystemExit("template has no {{ISSUER}} placeholder")
    out = {".well-known/openid-configuration": template.replace("{{ISSUER}}", issuer)}
    json.loads(out[".well-known/openid-configuration"])
    for set_name, names in SETS.items():
        keys = []
        for entry in inventory:
            if entry.get("source") == "key_vault" and entry.get("name") in names:
                jwk = public_jwk(entry["jwk"])
                if thumbprint(jwk) != entry["thumbprint"]:
                    raise SystemExit("inventory entry thumbprint does not match its JWK")
                keys.append({**jwk, "kid": entry["thumbprint"], "use": "sig", "alg": names[entry["name"]]})
        keys.sort(key=lambda k: k["kid"])
        out[f"{set_name}/jwks.json"] = json.dumps({"keys": keys}, sort_keys=True, separators=(",", ":"))
    return out


def main(argv: list) -> int:
    if len(argv) == 4 and argv[1] == "--check":
        with open(argv[2]) as jwks_file, open(argv[3]) as inventory_file:
            problems = check(json.load(jwks_file), json.load(inventory_file))
        for p in problems:
            print("INVALID: " + p, file=sys.stderr)
        return 1 if problems else 0
    if len(argv) == 4 and argv[1] == "--change-file":
        with open(argv[2]) as change_file:
            entries = from_change_file(json.load(change_file))
        with open(argv[3], "w") as out:
            json.dump(entries, out, indent=2, sort_keys=True)
        return 0
    if len(argv) == 6 and argv[1] == "--documents":
        with open(argv[2]) as inventory_file, open(argv[4]) as template_file:
            docs = documents(json.load(inventory_file), argv[3], template_file.read())
        for relative, text in docs.items():
            path = os.path.join(argv[5], relative)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as out:
                out.write(text)
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
