#!/usr/bin/env python3
"""Domain-control evidence for a tenant destination key (ADR-0031 section 1.2, revision 3.1). Standard library only; run with `python3 -I`.

  destination_key_evidence.py --change-file CHANGE.json OUT.json
        CHANGE.json is a reviewed `tenant-key-register` change file (Infra/azure-authority/changes/*.json on protected main). For every host it
        re-fetches the evidence itself, outside the api and the dashboard:
          dns_txt    : TXT `_viadere-destkey.<host>` from two independent DNS-over-HTTPS resolvers (Cloudflare and Google). Both must return
                       `v=1; kid=<thumbprint>`. A resolver that reports the answer as DNSSEC-validated (AD) is recorded as `validated`; a SERVFAIL
                       with the resolver's DNSSEC failure is `bogus` and refused; otherwise `unsigned` (the evidence then rests on the two resolvers
                       agreeing, which the summary states for the reviewer).
          well_known : https://<host>/.well-known/viadere-verification.json fetched with certificate validation; its `destination_kids` must list
                       the thumbprint.
        The live result must agree with the evidence committed in the change file (same method, same DNSSEC state), and the thumbprint is
        re-derived from the change file's public JWK (RFC 7638), never taken from the file. OUT.json holds the raw answers for the attestation.
        Exit status 0 only when every host passes.
  destination_key_evidence.py --self-test
        offline checks of the parsing and comparison rules.
"""
import base64
import hashlib
import json
import re
import sys
import urllib.parse
import urllib.request

HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]*[a-z]$")
RESOLVERS = {"cloudflare-dns.com": "https://cloudflare-dns.com/dns-query", "dns.google": "https://dns.google/resolve"}


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def thumbprint(jwk: dict) -> str:
    if set(jwk) - {"kty", "crv", "x", "y"} or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("public_key must be a public EC P-256 JWK")
    canonical = '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (jwk["x"], jwk["y"])
    return b64u(hashlib.sha256(canonical.encode()).digest())


def txt_values(answer: dict) -> list:
    out = []
    for record in answer.get("Answer", []):
        if record.get("type") == 16:
            data = record.get("data", "")
            # DoH JSON quotes each character-string; concatenate them.
            out.append("".join(re.findall(r'"((?:[^"\\]|\\.)*)"', data)) or data)
    return out


def dnssec_state(answer: dict) -> str:
    if answer.get("Status") == 2 and answer.get("Comment", "").lower().find("dnssec") >= 0:
        return "bogus"
    return "validated" if answer.get("AD") else "unsigned"


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "viadere-authority-admin"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read(1 << 20))


def check_host(host: str, kid: str, committed: dict, fetch=fetch_json) -> dict:
    if not HOST.match(host):
        raise ValueError(f"{host}: not a lowercase A-label host")
    expected = f"v=1; kid={kid}"
    method = committed.get("method")
    if method == "dns_txt":
        name = "_viadere-destkey." + host
        answers, states = [], set()
        for resolver, base in RESOLVERS.items():
            answer = fetch(base + "?" + urllib.parse.urlencode({"name": name, "type": "TXT", "do": "1"}))
            state = dnssec_state(answer)
            if state == "bogus":
                raise ValueError(f"{host}: DNSSEC-bogus answer from {resolver}")
            values = txt_values(answer)
            if expected not in values:
                raise ValueError(f"{host}: {resolver} does not return {expected!r}")
            answers.append({"resolver": resolver, "records": values})
            states.add(state)
        state = "validated" if states == {"validated"} else "unsigned"
        if committed.get("dnssec") != state:
            raise ValueError(f"{host}: committed dnssec {committed.get('dnssec')!r} but live answers are {state!r}")
        return {"host": host, "method": method, "dnssec": state, "answers": answers}
    if method == "well_known":
        url = f"https://{host}/.well-known/viadere-verification.json"
        if committed.get("url") != url:
            raise ValueError(f"{host}: evidence url must be {url}")
        doc = fetch(url)
        kids = doc.get("destination_kids", []) if isinstance(doc, dict) else []
        if kid not in kids:
            raise ValueError(f"{host}: {url} does not list the thumbprint")
        return {"host": host, "method": method, "url": url, "kids": kids}
    raise ValueError(f"{host}: unknown evidence method {method!r}")


def run(change: dict, fetch=fetch_json) -> list:
    if set(change) != {"tenant_id", "display_name", "public_key", "hosts", "not_after", "pop", "evidence"}:
        raise ValueError("not a tenant-key-register change file")
    kid = thumbprint(change["public_key"])
    hosts = change["hosts"]
    evidence = {e.get("host"): e for e in change["evidence"]}
    if sorted(evidence) != sorted(hosts) or len(hosts) != len(set(hosts)):
        raise ValueError("evidence must have exactly one entry per host")
    return [check_host(h, kid, evidence[h], fetch) for h in hosts]


def self_test():
    jwk = {"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tAf6RjsmsL7HfSwLgm8OxhdWp2kE"}
    kid = thumbprint(jwk)
    good = {"Status": 0, "AD": True, "Answer": [{"type": 16, "data": f'"v=1; kid={kid}"'}]}
    change = {"tenant_id": "ten_x", "display_name": "X", "public_key": jwk, "hosts": ["login.example.com"], "not_after": 1, "pop": "a.b.c",
              "evidence": [{"host": "login.example.com", "method": "dns_txt", "dnssec": "validated", "answers": []}]}
    assert run(change, lambda url: good)[0]["dnssec"] == "validated"
    for bad in [{"Status": 2, "Comment": "DNSSEC validation failure"}, {"Status": 0, "Answer": [{"type": 16, "data": '"v=1; kid=other"'}]}]:
        try:
            run(change, lambda url, b=bad: b)
            raise AssertionError("accepted")
        except ValueError:
            pass
    unsigned = dict(good, AD=False)
    try:
        run(change, lambda url: unsigned)
        raise AssertionError("a committed 'validated' state must match the live answers")
    except ValueError:
        pass
    print("self-test ok")


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    if len(argv) != 3 or argv[0] != "--change-file":
        sys.exit(__doc__)
    with open(argv[1], encoding="utf-8") as f:
        change = json.load(f)
    try:
        result = run(change)
    except (ValueError, OSError) as error:
        sys.exit(f"destination key evidence refused: {error}")
    with open(argv[2], "w", encoding="utf-8") as f:
        json.dump({"kid": thumbprint(change["public_key"]), "tenant_id": change["tenant_id"], "evidence": result}, f, indent=2, sort_keys=True)
    for e in result:
        print(f"{e['host']}: {e['method']}" + (f" ({e['dnssec']}: two resolvers agree)" if e["method"] == "dns_txt" else ""))


if __name__ == "__main__":
    main(sys.argv[1:])
