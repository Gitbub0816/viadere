#!/usr/bin/env python3
"""Generates webhook-v2-negative.json (review STAGE2_3_CODE_REVIEW R23-10).

Independent of every SDK: the string to sign, the HMAC and the Content-Digest are computed here from ADR-0025 section 1 with the standard library only.
Run `python3 generate_webhook_v2_negative.py > webhook-v2-negative.json`. The TypeScript, Kotlin and harness verifiers consume the output.

Each case is a complete receiver situation: the endpoint the receiver registered, its tenant id and keys, its clock, the request as received and the
expected outcome: "ok" or the failure code of the first check that fails (malformed_signature, timestamp_outside_tolerance, tenant_mismatch,
digest_mismatch, no_matching_signature). Check order: malformed, timestamp, tenant, digest, MAC.
"""
import base64
import hashlib
import hmac
import json

T = 1793620800
EVENT = "evt_0f6c1d2e3a4b4c5d8e9f0a1b2c3d4e5f"
TENANT = "ten_7a1b2c3d4e5f60718293a4b5c6d7e8f9"
OTHER_TENANT = "ten_other00000000000000000000000000"
KID1, SECRET1 = "whk_1a2b3c4d_v1", "whsec_testsecret_one"
KID0, SECRET0 = "whk_1a2b3c4d_v0", "whsec_testsecret_zero"
BODY = (
    '{"id":"evt_0f6c1d2e3a4b4c5d8e9f0a1b2c3d4e5f","occurred_at":"2026-11-02T12:00:00.000Z",'
    '"request_id":"adl_AAAAAAAAAAAAAAAAAAAAAA","tenant_id":"ten_7a1b2c3d4e5f60718293a4b5c6d7e8f9",'
    '"type":"auth.delivery.opened","version":"2026-10-27"}'
)
ENDPOINT = "https://hooks.example.com/viadere/events"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def digest(body: str) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body.encode()).digest()).decode() + ":"


def mac(secret, kid, host, path, t, event, tenant, body):
    sts = "\n".join(["VIADERE-WEBHOOK-V2", "POST", host, path, str(t), event, tenant, kid, hashlib.sha256(body.encode()).hexdigest()])
    return b64url(hmac.new(secret.encode(), sts.encode(), hashlib.sha256).digest())


def entry(secret=SECRET1, kid=KID1, host="hooks.example.com", path="/viadere/events", t=T, event=EVENT, tenant=TENANT, body=BODY):
    return f"v2={kid}:{mac(secret, kid, host, path, t, event, tenant, body)}"


def case(name, expect, signature=None, *, body=BODY, content_digest="auto", event=EVENT, tenant=TENANT, expected_tenant=TENANT, endpoint=ENDPOINT,
         keys=None, now=T, note=""):
    headers = {"Viadere-Signature": signature if signature is not None else f"t={T},{entry()}", "Viadere-Event-Id": event, "Viadere-Tenant": tenant}
    if content_digest == "auto":
        headers["Content-Digest"] = digest(body)
    elif content_digest is not None:
        headers["Content-Digest"] = content_digest
    return {
        "name": name,
        "note": note,
        "endpoint": endpoint,
        "tenant_id": expected_tenant,
        "keys": keys if keys is not None else {KID1: SECRET1},
        "now": now,
        "headers": headers,
        "body": body,
        "expect": expect,
    }


good = entry()
tampered = BODY.replace("opened", "completed")

cases = [
    case("valid", "ok"),
    case("valid at the +300 s boundary", "ok", now=T + 300),
    case("valid at the -300 s boundary", "ok", now=T - 300),
    case("rotation: two entries, receiver holds only the previous secret", "ok", f"t={T},{entry(SECRET1, KID1)},{entry(SECRET0, KID0)}", keys={KID0: SECRET0}),
    case("rotation: one entry has a bad MAC, the other verifies", "ok", f"t={T},v2={KID0}:{'A' * 43},{good}", keys={KID0: SECRET0, KID1: SECRET1}),
    case("an unknown scheme next to a valid v2 entry is ignored", "ok", f"t={T},v3=whatever,{good}"),
    case("v1-only header", "malformed_signature", f"t={T},v1={'0' * 64}", note="a v2 verifier never accepts v1= alone"),
    case("duplicate kid", "malformed_signature", f"t={T},{good},{good}"),
    case("two t= entries", "malformed_signature", f"t={T},t={T},{good}"),
    case("no t=", "malformed_signature", good),
    case("MAC of the wrong length", "malformed_signature", f"t={T},v2={KID1}:{'A' * 42}"),
    case("t= with 13 digits", "malformed_signature", f"t=1793620800000,{good}"),
    case("t= with a sign", "malformed_signature", f"t=+{T},{good}"),
    case("LF in the event id", "malformed_signature", event=EVENT + "\nX", note="no signed field can contain LF"),
    case("event id outside its charset", "malformed_signature", event="evt_bad id"),
    case("LF in the signature header", "malformed_signature", f"t={T},{good}\nv1=00"),
    case("stale timestamp (+301 s)", "timestamp_outside_tolerance", now=T + 301),
    case("timestamp in the future (-301 s)", "timestamp_outside_tolerance", now=T - 301),
    case("tenant header is not the receiver's tenant", "tenant_mismatch", f"t={T},{entry(tenant=OTHER_TENANT)}", tenant=OTHER_TENANT,
         note="signed for another tenant: refused before the MAC is even compared"),
    case("Content-Digest of another body", "digest_mismatch", content_digest=digest(tampered)),
    case("body tampered after signing (digest header unchanged)", "digest_mismatch", body=tampered, content_digest=digest(BODY)),
    case("Content-Digest header missing", "digest_mismatch", content_digest=None),
    case("body tampered and digest recomputed, MAC unchanged", "no_matching_signature", body=tampered, content_digest="auto"),
    case("wrong secret", "no_matching_signature", f"t={T},{entry('whsec_not_the_secret')}"),
    case("only an unknown kid", "no_matching_signature", f"t={T},{entry(SECRET0, KID0)}", keys={KID1: SECRET1}),
    case("kid swapped into another entry (per-MAC key binding)", "no_matching_signature", f"t={T},v2={KID1}:{entry(SECRET0, KID0).split(':', 1)[1]}"),
    case("path differs only in percent-encoding case", "no_matching_signature", f"t={T},{entry(path='/a/b%2fc')}",
         endpoint="https://hooks.example.com/a/b%2Fc"),
    case("signed for another host (cross-endpoint replay)", "no_matching_signature", endpoint="https://other.example.com/viadere/events"),
    case("signed for another path (cross-endpoint replay)", "no_matching_signature", endpoint="https://hooks.example.com/other"),
    case("signed with a different event id header", "no_matching_signature", event="evt_ffffffffffffffffffffffffffffffff",
         note="the MAC covers the event id; the header was swapped after signing"),
    case("non-default port is part of the signed host", "ok", f"t={T},{entry(host='hooks.example.com:8443', path='/a/b%20c?tenant=x&k=1')}",
         endpoint="https://hooks.example.com:8443/a/b%20c?tenant=x&k=1"),
    case("non-default port signed but receiver registered the default", "no_matching_signature", f"t={T},{entry(host='hooks.example.com:8443')}"),
]

print(json.dumps({
    "description": "Negative and boundary vectors for webhook signature v2 (ADR-0025, review R23-10). Generated by generate_webhook_v2_negative.py with the Python standard library only; every verifier must reach exactly the expected outcome. Check order: malformed, timestamp, tenant, digest, MAC.",
    "cases": cases,
}, indent=2))
