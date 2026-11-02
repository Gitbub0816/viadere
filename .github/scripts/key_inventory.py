#!/usr/bin/env python3
"""Authority key inventory tooling (ADR-0024 section 7.3). Standard library only; run with `python3 -I`.

  key_inventory.py LOG.json OUT.json    parse the admin job's execution log (Log Analytics JSON rows), keep ONLY the allow-listed lines
                                        `VIADERE-KEY-INVENTORY {json}`, re-derive each RFC 7638 thumbprint and write the inventory
  key_inventory.py --check JWKS.json INVENTORY.json   every JWK of a published set must be in the attested inventory (kid = thumbprint)

An entry: {"name": "grant-signing", "version": "<kv version>", "seal_row": null, "jwk": {...public key only...}}. A private member (d, p, q, dp,
dq, qi, k) anywhere is an error: the job's log allow-list contains public material only.
"""
import base64
import hashlib
import json
import sys

PRIVATE = {"d", "p", "q", "dp", "dq", "qi", "k"}
MARK = "VIADERE-KEY-INVENTORY "


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


def build(log_rows: list) -> list:
    entries = []
    for row in log_rows:
        text = row.get("Log_s") if isinstance(row, dict) else None
        if not isinstance(text, str) or MARK not in text:
            continue
        entry = json.loads(text.split(MARK, 1)[1])
        jwk = entry.get("jwk") or {}
        if PRIVATE & set(jwk):
            raise SystemExit("private key member in the inventory line: refused")
        entry["thumbprint"] = thumbprint(jwk)
        entries.append(entry)
    if not entries:
        raise SystemExit("no inventory lines in the execution log")
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


def main(argv: list) -> int:
    if len(argv) == 4 and argv[1] == "--check":
        problems = check(json.load(open(argv[2])), json.load(open(argv[3])))
        for p in problems:
            print("INVALID: " + p, file=sys.stderr)
        return 1 if problems else 0
    if len(argv) == 3:
        rows = json.load(open(argv[1]))
        if isinstance(rows, dict):
            rows = rows.get("rows") or rows.get("tables", [{}])[0].get("rows", [])
        json.dump(build(rows), open(argv[2], "w"), indent=2)
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
