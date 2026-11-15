#!/usr/bin/env python3
"""Generates the authority and destination format vectors (ledger L-11, L-15):

    python3 -I generate_authority_v1.py keylog            > keylog-v1.json
    python3 -I generate_authority_v1.py device-statements > device-statements-v1.json
    python3 -I generate_authority_v1.py auth-destination  > auth-destination-v1.json
    python3 -I generate_authority_v1.py recovery-seal     > recovery-seal-v1.json

Independent of the Swift code. Everything is computed here from the normative text: SECURITY §2.1 (base64url, raw low-S r||s ES256) and §2.2
(canonical JSON), ADR-0023 §2 (JOSE profile), ADR-0031 §3-§4 (`viadere-destination+jws`), ADR-0033 §1, §2, §4.1, §5 and SECURITY §2.103 (statements,
key-log PoP, entry hash, comparison code), ADR-0034 §1-§2 (HPKE recovery envelopes; RFC 9180 is implemented here on top of the `cryptography` ECDH,
HMAC and AES-GCM primitives, and checked against RFC 9180 A.3.1 before anything is written). Needs only the standard library and `cryptography`
(install it into a virtual environment outside the repository). ECDSA uses RFC 6979 deterministic nonces and HPKE fixed ephemeral keys, so the
output is byte-for-byte reproducible.

Each case names its expected outcome: "accept", or the refusal code of the first check that fails in the order the normative text gives.
"""
import base64
import hashlib
import hmac
import json
import sys
import unicodedata

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
NOW = 1_800_000_000
ENV = "stg"
ISS = "urn:viadere:authority:stg"
AUD = "urn:viadere:device"


# ---------------------------------------------------------------------------------------------------------------------------------------------
# Encodings (SECURITY §2.1, §2.2)

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def canonical(o) -> bytes:
    # Keys sorted (ASCII keys only here, so code-point order = UTF-16 order), no whitespace, `/` and non-ASCII literal, no floats.
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def key(scalar: int):
    return ec.derive_private_key(scalar, ec.SECP256R1())


def x963(priv) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def xy(priv):
    raw = x963(priv)
    return b64u(raw[1:33]), b64u(raw[33:])


def thumbprint(priv) -> str:
    """RFC 7638: members crv, kty, x, y in lexicographic order, SHA-256, base64url."""
    x, y = xy(priv)
    return b64u(hashlib.sha256(('{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (x, y)).encode()).digest())


def device_kid(priv) -> str:
    """The device `KeyIdentifier`: base64url SHA-256 of the DER SubjectPublicKeyInfo (never mixed with RFC 7638)."""
    spki = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return b64u(hashlib.sha256(spki).digest())


def raw_sig(priv, data: bytes, high_s=False) -> bytes:
    der = priv.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    s = min(s, N - s)
    if high_s:
        s = N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def der_sig(priv, data: bytes) -> bytes:
    r, s = decode_dss_signature(priv.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
    return encode_dss_signature(r, min(s, N - s))


def jws_bytes(header: bytes, payload: bytes, priv, high_s=False, signature=None) -> str:
    h, p = b64u(header), b64u(payload)
    sig = signature if signature is not None else raw_sig(priv, (h + "." + p).encode(), high_s)
    return h + "." + p + "." + b64u(sig)


def jws(header: dict, payload: dict, priv, **kw) -> str:
    return jws_bytes(canonical(header), canonical(payload), priv, **kw)


def tamper_payload(compact: str, payload: dict) -> str:
    """Replaces the payload segment and keeps the old signature."""
    h, _, s = compact.split(".")
    return h + "." + b64u(canonical(payload)) + "." + s


def pubkey(priv) -> dict:
    x, y = xy(priv)
    return {"x": x, "y": y, "x963": b64u(x963(priv))}


# Fixed keys. The authority statement keys stand in for the owner-pinned `device-statement-signing` [active, standby].
ACTIVE = key(0x5D2A4C3E1F0B9A8776655443322110FFEEDDCCBBAA99887766554433221100AB)
STANDBY = key(0x2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F80913)
UNKNOWN = key(0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF)
DEVICE_A = key(0x6F1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8)
DEVICE_B = key(0x0A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F9)
DEVICE_C = key(0x3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B)
DEVICE_X = key(0x7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D)
TENANT_KEY = key(0x4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D)
TENANT_OTHER = key(0x58293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F607)
SEAL = key(0x1F2E3D4C5B6A79880716253443526170F1E2D3C4B5A69788A7B6C5D4E3F20110)
SEAL_OTHER = key(0x6A79880716253443526170F1E2D3C4B5A69788A7B6C5D4E3F201101F2E3D4C5B)

ACCOUNT = "acct_" + hashlib.sha256(b"vector-account-1").hexdigest()[:32]
OTHER_ACCOUNT = "acct_" + hashlib.sha256(b"vector-account-2").hexdigest()[:32]


def nonce(label: str) -> str:
    return b64u(hashlib.sha256(label.encode()).digest())


def ach(label: str) -> str:
    return "ach_" + b64u(hashlib.sha256(label.encode()).digest()[:16])


# ---------------------------------------------------------------------------------------------------------------------------------------------
# Key log (ADR-0033 §4.1, §5; SECURITY §2.103)

def pop_message(env, typ, kid, n, extra=()):
    return "\n".join(["VIADERE-KEYLOG-V1", env, typ, kid, n] + list(extra))


def entry_hash(entry: dict, domain="VIADERE-KEYLOG-ENTRY-V1\n") -> str:
    assert "entry_hash" not in entry
    return hashlib.sha256(domain.encode() + canonical(entry)).hexdigest()


def device_add_code(env, n, kids) -> str:
    joined = "\n".join(sorted(kids, key=lambda k: k.encode()))
    h = hashlib.sha256(("VIADERE-DEVICE-ADD-V1\n" + env + "\n" + n + "\n" + joined).encode()).digest()
    return "%06d" % (int.from_bytes(h[:8], "big") % 1_000_000)


def keylog():
    kid_a, kid_b, kid_c = device_kid(DEVICE_A), device_kid(DEVICE_B), device_kid(DEVICE_C)
    pops = []

    def pop_case(name, signer, env, typ, kid, n, extra=(), verify=None, expect="accept", sig=None, high_s=False):
        signed = pop_message(env, typ, kid, n, extra)
        v = verify or {"env": env, "type": typ, "kid": kid, "nonce": n, "extra": list(extra)}
        message = pop_message(v["env"], v["type"], v["kid"], v["nonce"], v["extra"])
        pops.append({"name": name, "public_key": b64u(x963(DEVICE_A)), "env": v["env"], "type": v["type"], "kid": v["kid"], "nonce": v["nonce"],
                     "extra": v["extra"], "message": message,
                     "pop": sig if sig is not None else b64u(raw_sig(signer, signed.encode(), high_s)), "expect": expect})

    n1 = nonce("pop-nonce-1")
    head_hash = hashlib.sha256(b"head").hexdigest()
    env_digest = b64u(hashlib.sha256(b"enc||ct").digest())
    pop_case("genesis", DEVICE_A, "stg", "genesis", kid_a, n1)
    pop_case("device_added", DEVICE_A, "stg", "device_added", kid_a, n1)
    pop_case("device_added production", DEVICE_A, "prod", "device_added", kid_a, n1)
    pop_case("enrollment_confirmed over the head hash", DEVICE_A, "stg", "enrollment_confirmed", kid_a, head_hash)
    pop_case("recovery_started with envelope_digest", DEVICE_A, "stg", "recovery_started", kid_a, n1, [env_digest])
    pop_case("high-S twin accepted", DEVICE_A, "stg", "genesis", kid_a, n1, high_s=True)
    base = {"env": "stg", "type": "device_added", "kid": kid_a, "nonce": n1, "extra": []}
    pop_case("wrong key", DEVICE_X, "stg", "device_added", kid_a, n1, expect="reject")
    pop_case("signed for prod, checked for stg", DEVICE_A, "prod", "device_added", kid_a, n1, verify=base, expect="reject")
    pop_case("signed for genesis, checked as device_added", DEVICE_A, "stg", "genesis", kid_a, n1, verify=base, expect="reject")
    pop_case("signed for another kid", DEVICE_A, "stg", "device_added", kid_b, n1, verify=base, expect="reject")
    pop_case("signed over another nonce", DEVICE_A, "stg", "device_added", kid_a, nonce("pop-nonce-2"), verify=base, expect="reject")
    pop_case("start without the envelope_digest", DEVICE_A, "stg", "recovery_started", kid_a, n1,
             verify={"env": "stg", "type": "recovery_started", "kid": kid_a, "nonce": n1, "extra": [env_digest]}, expect="reject")
    wrong_domain = "\n".join(["VIADERE-KEYLOG-V2", "stg", "device_added", kid_a, n1]).encode()
    pop_case("wrong domain separator", DEVICE_A, "stg", "device_added", kid_a, n1, expect="reject", sig=b64u(raw_sig(DEVICE_A, wrong_domain)))
    msg = pop_message("stg", "device_added", kid_a, n1).encode()
    pop_case("DER signature refused", DEVICE_A, "stg", "device_added", kid_a, n1, expect="reject", sig=b64u(der_sig(DEVICE_A, msg)))
    pop_case("padded base64url refused", DEVICE_A, "stg", "device_added", kid_a, n1, expect="reject",
             sig=base64.urlsafe_b64encode(raw_sig(DEVICE_A, msg)).decode())
    standard = base64.b64encode(raw_sig(DEVICE_A, msg)).decode().rstrip("=")
    assert "+" in standard or "/" in standard, "pick a message whose signature uses the characters that differ"
    pop_case("standard base64 alphabet refused", DEVICE_A, "stg", "device_added", kid_a, n1, expect="reject", sig=standard)

    # Entry chain (the authority's entry body; `prev_hash` of the first entry is 32 zero bytes).
    entries = []
    prev = "0" * 64
    rows = [("genesis", kid_a, DEVICE_A, "approvalBiometric", {"attestation": "swk", "origin": "minted"}),
            ("genesis", kid_b, DEVICE_B, "requestSigning", {"attestation": "swk", "origin": "minted"}),
            ("enrollment_confirmed", kid_a, DEVICE_A, "approvalBiometric", {"head_hash": head_hash, "seq": 1}),
            ("device_added", kid_c, DEVICE_C, "approvalBiometric", {"reported_name": "Ada's iPad", "usable_from": NOW + 72 * 3600})]
    for seq, (typ, kid, priv, purpose, detail) in enumerate(rows):
        body = {"account_ref": ACCOUNT, "seq": seq, "type": typ, "kid": kid, "public_key": b64u(x963(priv)), "key_purpose": purpose,
                "detail": detail, "created_at": NOW + seq, "prev_hash": prev}
        h = entry_hash(body)
        entries.append({"entry": body, "canonical": canonical(body).decode(), "entry_hash": h,
                        "wrong_domain_hash": entry_hash(body, "VIADERE-KEYLOG-ENTRY-V2\n"), "undomained_hash": hashlib.sha256(canonical(body)).hexdigest()})
        prev = h
    tampered = dict(entries[2]["entry"], detail={"head_hash": head_hash, "seq": 2})

    # Comparison codes (ADR-0033 §4.1 item 4).
    codes = []
    for label, env, kids in [("one key", "stg", [kid_c]), ("two keys given unsorted", "stg", [kid_c, kid_a]), ("two keys sorted", "stg", sorted([kid_c, kid_a])),
                             ("production", "prod", [kid_c, kid_a]), ("three keys", "stg", [kid_b, kid_c, kid_a])]:
        n = nonce("device-add-" + label)
        codes.append({"name": label, "env": env, "nonce": n, "kids": kids, "code": device_add_code(env, n, kids),
                      "unsorted_join_code": "%06d" % (int.from_bytes(hashlib.sha256(("VIADERE-DEVICE-ADD-V1\n" + env + "\n" + n + "\n" + "\n".join(kids)).encode()).digest()[:8], "big") % 1_000_000)})
    # A nonce whose code has leading zeros (search is deterministic).
    i = 0
    while True:
        n = nonce("leading-zero-%d" % i)
        c = device_add_code("stg", n, [kid_c])
        if c.startswith("00"):
            codes.append({"name": "leading zeros kept", "env": "stg", "nonce": n, "kids": [kid_c], "code": c, "unsorted_join_code": c})
            break
        i += 1

    names = []
    for raw, ok in [("Ada's iPad", True), ("école", True), ("x" * 40, True), ("x" * 41, False), ("", False), ("iPad‮evil", False),
                    ("iPad​x", False), ("line\nbreak", False), ("tab\tname", False), ("para sep", False)]:
        nfc = unicodedata.normalize("NFC", raw)
        bad = any(unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp", "Cn", "Co", "Cs") for ch in nfc)
        assert ok == (1 <= len(nfc) <= 40 and not bad), raw
        names.append({"raw": raw, "accepted": ok, "nfc": nfc if ok else None})

    refs = [{"value": ACCOUNT, "valid": True}, {"value": ACCOUNT.upper().replace("ACCT_", "acct_"), "valid": False},
            {"value": ACCOUNT[:-1], "valid": False}, {"value": "acct-" + ACCOUNT[5:], "valid": False}, {"value": ACCOUNT + "0", "valid": False}]
    return {
        "description": "Key-log formats (ADR-0033 §4.1, §5; SECURITY §2.103): PoP strings and signatures, the entry hash chain, the device-add "
                       "comparison code, reported names and account references. Generated by generate_authority_v1.py keylog.",
        "now": NOW,
        "pop": pops,
        "zero_hash": "0" * 64,
        "entries": entries,
        "tampered_entry": {"entry": tampered, "original_hash": entries[2]["entry_hash"]},
        "comparison_codes": codes,
        "reported_names": names,
        "account_refs": refs,
    }


# ---------------------------------------------------------------------------------------------------------------------------------------------
# Device statements (ADR-0033 §2, §3)

def head_jws(payload: dict, signer=ACTIVE, kid=None, typ="viadere-keylog-head+jws", **kw) -> str:
    return jws({"alg": "ES256", "kid": kid or thumbprint(signer), "typ": typ}, payload, signer, **kw)


def challenge_payload(purpose, display, **extra):
    p = {"v": 1, "iss": ISS, "aud": AUD, "env": ENV, "ach": ach(purpose), "nonce": nonce("challenge-" + purpose), "purpose": purpose, "display": display,
         "match_required": "match_digits" in display, "iat": NOW, "exp": NOW + 120}
    p.update(extra)
    return p


def display_digest(display) -> str:
    return hashlib.sha256(b"VIADERE-DISPLAY-V1\n" + canonical(display)).hexdigest()


def device_statements():
    kid_a, kid_b, kid_c = device_kid(DEVICE_A), device_kid(DEVICE_B), device_kid(DEVICE_C)
    oidc_display = {"v": 1, "purpose": "oidc_login", "client_name": "Example Bank", "redirect_uri": "https://rp.example-bank.com/oidc/cb",
                    "redirect_host": "rp.example-bank.com", "match_digits": 2}
    link_display = {"v": 1, "purpose": "link_open", "tenant_name": "Example Bank", "client_name": "Example Bank web",
                    "return_url": "https://www.example-bank.com/return?x=1", "return_host": "www.example-bank.com"}
    added_display = {"v": 1, "purpose": "keylog_device_added", "reported_name": "Ada's iPad", "reported_name_source": "new_device",
                     "kids": [kid_c], "match_digits": 6}
    set_display = {"v": 1, "purpose": "recovery_codes_set", "set_id": "rcs_" + b64u(hashlib.sha256(b"set").digest()[:16]), "count": 10}
    displays = [{"name": n, "display": d, "canonical": canonical(d).decode(), "digest": display_digest(d),
                 "wrong_domain_digest": hashlib.sha256(b"VIADERE-DISPLAY-V2\n" + canonical(d)).hexdigest()}
                for n, d in [("oidc_login", oidc_display), ("link_open", link_display), ("keylog_device_added", added_display),
                             ("recovery_codes_set", set_display)]]

    oidc = challenge_payload("oidc_login", oidc_display, redirect_uri=oidc_display["redirect_uri"])
    link = challenge_payload("link_open", link_display, return_url=link_display["return_url"])
    added = challenge_payload("keylog_device_added", added_display, account_ref=ACCOUNT, kids=[kid_c])
    codes_set = challenge_payload("recovery_codes_set", set_display, account_ref=ACCOUNT)
    hdr = {"alg": "ES256", "kid": thumbprint(ACTIVE), "typ": "viadere-challenge+jws"}
    challenges = []

    def ch(name, compact, expect="accept", payload=None, revoked=(), now=NOW):
        challenges.append({"name": name, "jws": compact, "expect": expect, "revoked_kids": list(revoked), "now": now,
                           **({"payload_canonical": canonical(payload).decode()} if payload is not None and expect == "accept" else {})})

    for name, p in [("oidc_login", oidc), ("link_open", link), ("keylog_device_added with account_ref and kids", added),
                    ("recovery_codes_set", codes_set)]:
        ch(name, jws(hdr, p, ACTIVE), payload=p)
    ch("signed by the standby key", jws(dict(hdr, kid=thumbprint(STANDBY)), oidc, STANDBY), payload=oidc)
    ch("high-S twin accepted", jws(hdr, oidc, ACTIVE, high_s=True), payload=oidc)
    ch("standby accepted after the active key is revoked", jws(dict(hdr, kid=thumbprint(STANDBY)), oidc, STANDBY), payload=oidc, revoked=[thumbprint(ACTIVE)])
    ch("exp + 60 s is still valid", jws(hdr, oidc, ACTIVE), payload=oidc, now=NOW + 180)
    ch("iat - 60 s is still valid", jws(hdr, oidc, ACTIVE), payload=oidc, now=NOW - 60)
    ch("revoked active key", jws(hdr, oidc, ACTIVE), "unknown_key", revoked=[thumbprint(ACTIVE)])
    ch("unknown key", jws(dict(hdr, kid=thumbprint(UNKNOWN)), oidc, UNKNOWN), "unknown_key")
    ch("wrong key under a pinned kid", jws(hdr, oidc, UNKNOWN), "bad_signature")
    ch("tampered payload", tamper_payload(jws(hdr, oidc, ACTIVE), dict(oidc, nonce=nonce("other"))), "bad_signature")
    h, p, _ = jws(hdr, oidc, ACTIVE).split(".")
    ch("DER signature", h + "." + p + "." + b64u(der_sig(ACTIVE, (h + "." + p).encode())), "bad_signature")
    ch("padded signature segment", h + "." + p + "." + base64.urlsafe_b64encode(raw_sig(ACTIVE, (h + "." + p).encode())).decode(), "malformed")
    ch("two segments", h + "." + p, "malformed")
    ch("wrong typ", jws(dict(hdr, typ="viadere-keylog-head+jws"), oidc, ACTIVE), "wrong_type")
    ch("typ JWT", jws(dict(hdr, typ="JWT"), oidc, ACTIVE), "wrong_type")
    ch("alg none", jws(dict(hdr, alg="none"), oidc, ACTIVE), "unsupported_algorithm")
    ch("alg ES384", jws(dict(hdr, alg="ES384"), oidc, ACTIVE), "unsupported_algorithm")
    ch("alg HS256", jws(dict(hdr, alg="HS256"), oidc, ACTIVE), "unsupported_algorithm")
    ch("crit header member", jws(dict(hdr, crit=["exp"]), oidc, ACTIVE), "malformed")
    ch("jwk header member", jws(dict(hdr, jwk={"kty": "EC"}), oidc, ACTIVE), "malformed")
    ch("missing kid", jws({"alg": "ES256", "typ": "viadere-challenge+jws"}, oidc, ACTIVE), "malformed")
    ch("non-canonical header (spaces)", jws_bytes(json.dumps(hdr, sort_keys=True).encode(), canonical(oidc), ACTIVE), "malformed")
    ch("non-canonical payload (member order)", jws_bytes(canonical(hdr), json.dumps(oidc, separators=(",", ":")).encode(), ACTIVE), "malformed")
    dup = canonical(oidc).decode().replace('"v":1}', '"v":1,"v":1}')
    assert dup != canonical(oidc).decode()
    ch("duplicate payload member", jws_bytes(canonical(hdr), dup.encode(), ACTIVE), "malformed")
    ch("float iat", jws_bytes(canonical(hdr), canonical(oidc).decode().replace('"iat":%d' % NOW, '"iat":%d.0' % NOW).encode(), ACTIVE), "malformed")
    ch("escaped slash in payload", jws_bytes(canonical(hdr), canonical(oidc).decode().replace("https://", "https:\\/\\/").encode(), ACTIVE), "malformed")
    big = dict(oidc, display=dict(oidc_display, client_name="x" * 3000))
    ch("over 4096 bytes", jws(hdr, big, ACTIVE), "malformed")
    ch("production issuer in staging", jws(hdr, dict(oidc, iss="urn:viadere:authority:prod"), ACTIVE), "claims")
    ch("production env in staging", jws(hdr, dict(oidc, env="prod"), ACTIVE), "claims")
    ch("wrong audience", jws(hdr, dict(oidc, aud="urn:viadere:api"), ACTIVE), "claims")
    ch("v 2", jws(hdr, dict(oidc, v=2), ACTIVE), "claims")
    ch("extra member", jws(hdr, dict(oidc, grant="yes"), ACTIVE), "claims")
    ch("missing match_required", jws(hdr, {k: v for k, v in oidc.items() if k != "match_required"}, ACTIVE), "claims")
    ch("display purpose differs", jws(hdr, dict(oidc, display=dict(oidc_display, purpose="link_open")), ACTIVE), "claims")
    ch("return_url on oidc_login", jws(hdr, dict(oidc, return_url="https://evil.example/"), ACTIVE), "claims")
    ch("link_open without return_url", jws(hdr, {k: v for k, v in link.items() if k != "return_url"}, ACTIVE), "claims")
    ch("account_ref on oidc_login", jws(hdr, dict(oidc, account_ref=ACCOUNT), ACTIVE), "claims")
    ch("kids on link_open", jws(hdr, dict(link, kids=[kid_c]), ACTIVE), "claims")
    ch("duplicate kids", jws(hdr, dict(added, kids=[kid_c, kid_c]), ACTIVE), "claims")
    ch("malformed account_ref", jws(hdr, dict(added, account_ref="acct_XYZ"), ACTIVE), "claims")
    ch("short nonce", jws(hdr, dict(oidc, nonce=b64u(b"\x01" * 16)), ACTIVE), "claims")
    ch("exp not after iat", jws(hdr, dict(oidc, exp=NOW), ACTIVE), "claims")
    ch("expired (exp + 61 s)", jws(hdr, oidc, ACTIVE), "expired", now=NOW + 181)
    ch("not yet valid (iat - 61 s)", jws(hdr, oidc, ACTIVE), "not_yet_valid", now=NOW - 61)

    # Heads.
    def head_payload(**over):
        p = {"v": 1, "iss": ISS, "aud": AUD, "env": ENV, "account_ref": ACCOUNT, "seq": 3, "head_hash": hashlib.sha256(b"head-3").hexdigest(),
             "keys": [{"kid": kid_a, "purpose": "approvalBiometric", "usable_from": NOW - 86400, "entry_type": "genesis", "imported": False, "grant_capable": True},
                      {"kid": kid_b, "purpose": "requestSigning", "usable_from": NOW - 86400, "entry_type": "genesis", "imported": False, "grant_capable": True},
                      {"kid": kid_c, "purpose": "approvalBiometric", "usable_from": NOW + 259200, "entry_type": "device_added", "imported": False,
                       "grant_capable": False}],
             "pending_recoveries": [{"recovery_id": "7K3M9Q2W4X6Z", "started_at": NOW - 3600, "activates_at": NOW + 255600, "legacy": False,
                                     "kids": [device_kid(DEVICE_X)]}],
             "recovery_set": "active", "issued_at": NOW - 60}
        p.update(over)
        return p

    hp = head_payload()
    heads = []

    def hd(name, compact, expect="accept", own=None, minimum_seq=3, now=NOW, revoked=(), payload=None, exact_entry=None, exact_pending=None):
        heads.append({"name": name, "jws": compact, "expect": expect, "own_kids": own if own is not None else [kid_a, kid_b], "minimum_seq": minimum_seq,
                      "now": now, "revoked_kids": list(revoked),
                      **({"payload_canonical": canonical(payload).decode()} if payload is not None and expect == "accept" else {}),
                      **({"exact_entry": exact_entry} if exact_entry else {}), **({"exact_pending": exact_pending} if exact_pending else {})})

    hd("head", head_jws(hp), payload=hp,
       exact_entry=[{"own_kids": [kid_c], "expect": "accept"}, {"own_kids": [kid_a], "expect": "entry_mismatch"},
                    {"own_kids": [kid_c, device_kid(DEVICE_X)], "expect": "not_my_account"}],
       exact_pending=[{"new_kids": [device_kid(DEVICE_X)], "expect": "accept"}, {"new_kids": [device_kid(DEVICE_X), kid_c], "expect": "recovery_mismatch"},
                      {"new_kids": [kid_c], "expect": "recovery_mismatch"}])
    attacker = head_payload(keys=hp["keys"] + [{"kid": device_kid(DEVICE_X), "purpose": "approvalBiometric", "usable_from": NOW, "entry_type": "device_added",
                                                 "imported": False, "grant_capable": False}])
    hd("an attacker key beside the new device's own", head_jws(attacker), payload=attacker, own=[kid_c],
       exact_entry=[{"own_kids": [kid_c], "expect": "entry_mismatch"}])
    for state in ["none", "refresh_suggested", "invalidated"]:
        p = head_payload(recovery_set=state, pending_recoveries=[])
        hd("recovery_set " + state, head_jws(p), payload=p)
    hd("a higher seq than stored", head_jws(hp), payload=hp, minimum_seq=2)
    hd("exactly 15 minutes old", head_jws(hp), payload=hp, now=NOW - 60 + 900)
    hd("high-S twin accepted", head_jws(hp, high_s=True), payload=hp)
    hd("stale (15 min + 1 s)", head_jws(hp), "stale", now=NOW - 60 + 901)
    hd("issued more than 60 s in the future", head_jws(head_payload(issued_at=NOW + 61)), "not_yet_valid")
    hd("rollback (seq below the stored)", head_jws(hp), "rollback", minimum_seq=4)
    hd("not my account", head_jws(hp), "not_my_account", own=[kid_a, device_kid(DEVICE_X)])
    hd("revoked signer", head_jws(hp), "unknown_key", revoked=[thumbprint(ACTIVE)])
    hd("unknown signer", head_jws(hp, signer=UNKNOWN), "unknown_key")
    hd("tampered seq", tamper_payload(head_jws(hp), head_payload(seq=4)), "bad_signature")
    hd("unknown recovery_set", head_jws(head_payload(recovery_set="paused")), "claims")
    hd("kid_header member of revision 2", head_jws(head_payload(kid_header=thumbprint(ACTIVE))), "claims")
    hd("extra key member", head_jws(head_payload(keys=[dict(hp["keys"][0], revoked=False)] + hp["keys"][1:])), "claims")
    hd("RFC 7638 kid in keys", head_jws(head_payload(keys=[dict(hp["keys"][0], kid=thumbprint(DEVICE_A) + "x")] + hp["keys"][1:])), "claims")
    hd("pending recovery kid malformed", head_jws(head_payload(pending_recoveries=[dict(hp["pending_recoveries"][0], kids=["nope"])])), "claims")
    hd("wrong env", head_jws(head_payload(env="prod")), "claims")
    hd("missing issued_at", head_jws({k: v for k, v in hp.items() if k != "issued_at"}), "claims")

    # Cross-`typ`: each of the four device statement types presented to each Core verifier (ADR-0033 §2).
    tenant_record = {"v": 1, "iss": ISS, "aud": AUD, "env": ENV, "tenant_id": "tnt_example", "seq": 7, "display_name": "Example Bank",
                     "allowed_hosts": ["login.example-bank.com"], "keys": [{"kid": thumbprint(TENANT_KEY), "public_key": {"crv": "P-256", "kty": "EC",
                     "x": xy(TENANT_KEY)[0], "y": xy(TENANT_KEY)[1]}, "not_after": NOW + 86400 * 365}], "issued_at": NOW - 60}
    revocation = {"v": 1, "iss": ISS, "aud": AUD, "env": ENV, "revoked": [{"key_family": "device-statement", "kid": thumbprint(ACTIVE)}], "issued_at": NOW - 60}
    statements = {"viadere-challenge+jws": (oidc, ACTIVE), "viadere-keylog-head+jws": (hp, ACTIVE), "viadere-tenant-keys+jws": (tenant_record, ACTIVE),
                  "viadere-device-keys-revocation+jws": (revocation, STANDBY)}
    cross = []
    for typ, (payload, signer) in statements.items():
        compact = jws({"alg": "ES256", "kid": thumbprint(signer), "typ": typ}, payload, signer)
        for verifier in ["viadere-challenge+jws", "viadere-keylog-head+jws"]:
            cross.append({"typ": typ, "verifier": verifier, "jws": compact, "expect": "accept" if typ == verifier else "wrong_type"})
        # Same payload re-labelled with the verifier's typ: still refused, by member set (no type confusion through the payload).
        for verifier in ["viadere-challenge+jws", "viadere-keylog-head+jws"]:
            if verifier != typ:
                relabelled = jws({"alg": "ES256", "kid": thumbprint(signer), "typ": verifier}, payload, signer)
                cross.append({"typ": typ + " relabelled", "verifier": verifier, "jws": relabelled, "expect": "claims"})

    rfc7638 = [dict(pubkey(k), kid=thumbprint(k), device_kid=device_kid(k)) for k in [ACTIVE, STANDBY, TENANT_KEY, DEVICE_A]]
    return {
        "description": "Authority device statements (ADR-0033 §2, §3; SECURITY §2.103): viadere-challenge+jws and viadere-keylog-head+jws under the "
                       "JOSE profile of ADR-0023 §2, display digests, revocation by pinned kid, cross-typ refusals of all four statement types, and "
                       "RFC 7638 kid agreement. Generated by generate_authority_v1.py device-statements.",
        "env": ENV,
        "pinned_keys": [dict(pubkey(ACTIVE), kid=thumbprint(ACTIVE)), dict(pubkey(STANDBY), kid=thumbprint(STANDBY))],
        "unknown_key": dict(pubkey(UNKNOWN), kid=thumbprint(UNKNOWN)),
        "rfc7638": rfc7638,
        "displays": displays,
        "challenges": challenges,
        "heads": heads,
        "cross_typ": cross,
    }


# ---------------------------------------------------------------------------------------------------------------------------------------------
# Destination statements (ADR-0031 §3, §4)

def auth_destination():
    url = "https://login.example-bank.com/magic?token=Zm9vYmFyYmF6&session=s-1"
    tenant = "tnt_example-bank"
    sub = "sub_" + b64u(hashlib.sha256(b"subject").digest())
    brq = "req_dest_0001"
    jti = b64u(hashlib.sha256(b"jti-1").digest()[:16])
    digest = b64u(hashlib.sha256(url.encode()).digest())
    kid = thumbprint(TENANT_KEY)
    hdr = {"alg": "ES256", "kid": kid, "typ": "viadere-destination+jws"}

    def payload(**over):
        p = {"v": 1, "iss": tenant, "aud": AUD, "sub": sub, "brq": brq, "purpose": "sign_in", "url_sha256": digest, "host": "login.example-bank.com",
             "iat": NOW, "exp": NOW + 300, "jti": jti}
        p.update(over)
        return p

    p0 = payload()
    expectation = {"tenant_id": tenant, "request_id": brq, "purpose": "sign_in", "allowed_hosts": ["login.example-bank.com", "www.example-bank.com"],
                   "now": NOW + 10, "keys": [dict(pubkey(TENANT_KEY), kid=kid, not_after=NOW + 86400 * 365)]}
    cases = []

    def case(name, compact, expect="accept", opened=None, opened_expect=None, seen=False, **over):
        c = {"name": name, "jws": compact, "expect": expect, "jti_seen_before": seen}
        if over:
            c["expectation"] = over
        if opened is not None:
            c["opened_url"], c["opened_expect"] = opened, opened_expect
        cases.append(c)

    case("valid sign_in", jws(hdr, p0, TENANT_KEY), opened=url, opened_expect="accept")
    for purpose in ["step_up", "verify_contact"]:
        case("valid " + purpose, jws(hdr, payload(purpose=purpose), TENANT_KEY), purpose=purpose)
    case("high-S twin accepted (business SDKs do not normalise S)", jws(hdr, p0, TENANT_KEY, high_s=True))
    case("lifetime exactly 600 s", jws(hdr, payload(exp=NOW + 600), TENANT_KEY))
    case("exp + 60 s is still valid", jws(hdr, p0, TENANT_KEY), now=NOW + 360)
    case("iat - 60 s is still valid", jws(hdr, p0, TENANT_KEY), now=NOW - 60)
    case("URL byte changed after create", jws(hdr, p0, TENANT_KEY), opened=url.replace("s-1", "s-2"), opened_expect="url_mismatch")
    case("URL with a trailing slash added", jws(hdr, p0, TENANT_KEY), opened=url.replace(".com/", ".com//"), opened_expect="url_mismatch")
    other = "https://www.example-bank.com/magic"
    case("URL of another allowed host under the signed digest", jws(hdr, payload(url_sha256=b64u(hashlib.sha256(other.encode()).digest())), TENANT_KEY),
         opened=other, opened_expect="host_not_allowed")
    case("wrong key under the tenant kid", jws(hdr, p0, TENANT_OTHER), "bad_signature")
    case("tampered payload", tamper_payload(jws(hdr, p0, TENANT_KEY), payload(brq="req_dest_0002")), "bad_signature")
    case("unknown kid", jws(dict(hdr, kid=thumbprint(TENANT_OTHER)), p0, TENANT_OTHER), "unknown_key")
    case("no tenant record (fail closed)", jws(hdr, p0, TENANT_KEY), "unknown_key", keys=[])
    case("key past not_after", jws(hdr, p0, TENANT_KEY), "key_expired", keys=[dict(pubkey(TENANT_KEY), kid=kid, not_after=NOW + 10)])
    case("replayed jti", jws(hdr, p0, TENANT_KEY), "replayed", seen=True)
    case("wrong brq", jws(hdr, payload(brq="req_dest_0002"), TENANT_KEY), "wrong_request")
    case("wrong purpose", jws(hdr, payload(purpose="step_up"), TENANT_KEY), "wrong_purpose")
    case("wrong issuer (another tenant)", jws(hdr, payload(iss="tnt_other"), TENANT_KEY), "wrong_issuer")
    case("host outside allowed_hosts", jws(hdr, payload(host="evil.example-bank.net"), TENANT_KEY), "host_not_allowed")
    case("expired (exp + 61 s)", jws(hdr, p0, TENANT_KEY), "expired", now=NOW + 361)
    case("not yet valid (iat - 61 s)", jws(hdr, p0, TENANT_KEY), "not_yet_valid", now=NOW - 61)
    case("lifetime 601 s", jws(hdr, payload(exp=NOW + 601), TENANT_KEY), "lifetime_too_long")
    case("exp before iat", jws(hdr, payload(exp=NOW - 1), TENANT_KEY), "lifetime_too_long")
    case("wrong audience", jws(hdr, payload(aud="urn:viadere:api"), TENANT_KEY), "wrong_audience")
    case("wrong typ", jws(dict(hdr, typ="viadere-challenge+jws"), p0, TENANT_KEY), "wrong_type")
    case("alg ES384", jws(dict(hdr, alg="ES384"), p0, TENANT_KEY), "unsupported_algorithm")
    case("alg none", jws(dict(hdr, alg="none"), p0, TENANT_KEY), "unsupported_algorithm")
    case("crit header", jws(dict(hdr, crit=["exp"]), p0, TENANT_KEY), "unknown_critical_header")
    case("extra header member", jws(dict(hdr, x5u="https://evil.example/k"), p0, TENANT_KEY), "malformed")
    case("non-canonical payload (member order)", jws_bytes(canonical(hdr), json.dumps(p0, separators=(",", ":")).encode(), TENANT_KEY), "malformed")
    case("non-canonical payload (spaces)", jws_bytes(canonical(hdr), json.dumps(p0, sort_keys=True).encode(), TENANT_KEY), "malformed")
    case("duplicate member", jws_bytes(canonical(hdr), canonical(p0).decode().replace('"v":1}', '"v":1,"v":1}').encode(), TENANT_KEY), "malformed")
    case("float iat", jws_bytes(canonical(hdr), canonical(p0).decode().replace('"iat":%d' % NOW, '"iat":%d.0' % NOW).encode(), TENANT_KEY), "malformed")
    case("extra payload member (the URL itself)", jws(hdr, payload(url=url), TENANT_KEY), "malformed")
    case("missing jti", jws(hdr, {k: v for k, v in p0.items() if k != "jti"}, TENANT_KEY), "malformed")
    case("url_sha256 in hex", jws(hdr, payload(url_sha256=hashlib.sha256(url.encode()).hexdigest()), TENANT_KEY), "malformed")
    case("url_sha256 padded", jws(hdr, payload(url_sha256=digest + "="), TENANT_KEY), "malformed")
    case("upper-case host", jws(hdr, payload(host="Login.Example-Bank.com"), TENANT_KEY), "malformed")
    case("IP literal host", jws(hdr, payload(host="192.168.1.10"), TENANT_KEY), "malformed")
    case("jti of 64 bits", jws(hdr, payload(jti=b64u(b"\x01" * 8)), TENANT_KEY), "malformed")
    case("string iat", jws(hdr, payload(iat=str(NOW)), TENANT_KEY), "malformed")
    case("unknown purpose", jws(hdr, payload(purpose="login"), TENANT_KEY), "malformed")
    case("empty", "", "missing")
    case("two segments", ".".join(jws(hdr, p0, TENANT_KEY).split(".")[:2]), "malformed")
    case("over 4096 bytes (ADR-0031 §3; Core caps at 2048)", jws(hdr, payload(brq="r" * 128, host="a" * 60 + "." + "b" * 60 + "." + "c" * 60 + "." + "example.com"), TENANT_KEY)
         + "A" * 3200, "malformed")

    # ADR-0031 §3 fixes `purpose` to sign_in | step_up | verify_contact. See the `spec_disagreements` member.
    disagreements = [{"name": "purpose account_notice (ADR-0031 §3 allows sign_in, step_up, verify_contact only)",
                      "jws": jws(hdr, payload(purpose="account_notice"), TENANT_KEY), "expect": "malformed", "expectation": {"purpose": "account_notice"}}]

    return {
        "description": "Business-signed destination statements viadere-destination+jws (ADR-0031 §3, §4; SECURITY §2.101): the device check "
                       "before Continue (verifyForDevice) and after open (verifyOpened). Registration PoPs and tenant records are not in Core yet "
                       "and have no cases here. Generated by generate_authority_v1.py auth-destination.",
        "url": url,
        "url_sha256": digest,
        "tenant_id": tenant,
        "subject_ref": sub,
        "request_id": brq,
        "jti": jti,
        "iat": NOW,
        "lifetime": 300,
        "kid": kid,
        "expectation": expectation,
        "cases": cases,
        "spec_disagreements": disagreements,
    }


# ---------------------------------------------------------------------------------------------------------------------------------------------
# HPKE (RFC 9180, mode_base, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256) and recovery envelopes (ADR-0034 §1, §2)

def i2osp(n, length):
    return n.to_bytes(length, "big")


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def labeled_extract(suite_id, salt, label, ikm):
    return hkdf_extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def labeled_expand(suite_id, prk, label, info, length):
    return hkdf_expand(prk, i2osp(length, 2) + b"HPKE-v1" + suite_id + label + info, length)


def hpke_seal(pk_r_bytes, sk_e, info, aad, pt, aead_id=0x0002):
    nk = {0x0001: 16, 0x0002: 32}[aead_id]
    kem_suite = b"KEM" + i2osp(0x0010, 2)
    pk_r = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk_r_bytes)
    dh = sk_e.exchange(ec.ECDH(), pk_r)
    enc = x963(sk_e)
    eae_prk = labeled_extract(kem_suite, b"", b"eae_prk", dh)
    shared = labeled_expand(kem_suite, eae_prk, b"shared_secret", enc + pk_r_bytes, 32)
    suite = b"HPKE" + i2osp(0x0010, 2) + i2osp(0x0001, 2) + i2osp(aead_id, 2)
    psk_id_hash = labeled_extract(suite, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(suite, b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = labeled_extract(suite, shared, b"secret", b"")
    k = labeled_expand(suite, secret, b"key", context, nk)
    base_nonce = labeled_expand(suite, secret, b"base_nonce", context, 12)
    return enc, AESGCM(k).encrypt(base_nonce, pt, aad)


RFC9180_A31 = {
    "info": "4f6465206f6e2061204772656369616e2055726e",
    "skEm": "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb",
    "pkRm": "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
    "skRm": "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
    "enc": "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
    "pt": "4265617574792069732074727574682c20747275746820626561757479",
    "aad": "436f756e742d30",
    "ct": "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434",
}


def check_rfc9180():
    v = {k: bytes.fromhex(x) for k, x in RFC9180_A31.items()}
    enc, ct = hpke_seal(v["pkRm"], key(int.from_bytes(v["skEm"], "big")), v["info"], v["aad"], v["pt"], aead_id=0x0001)
    assert enc == v["enc"] and ct == v["ct"], "the HPKE implementation does not reproduce RFC 9180 A.3.1"


CODES = ["0123456789", "ABCDEFGHJK", "MNPQRSTVWX", "YZ01234567", "89ABCDEFGH", "JKMNPQRSTV", "WXYZ012345", "6789ABCDEF", "GHJKMNPQRS", "TVWXYZ0123"]


def recovery_seal():
    check_rfc9180()
    seal_pub = x963(SEAL)
    seal_kid = thumbprint(SEAL)
    set_id = "rcs_" + b64u(hashlib.sha256(b"set-id").digest()[:16])
    ach_set, nonce_set = ach("seal-set"), nonce("seal-set")
    ach_start, nonce_start = ach("seal-start"), nonce("seal-start")
    kids = sorted([device_kid(DEVICE_X), device_kid(DEVICE_B)])

    def set_plain(**over):
        p = {"v": 1, "purpose": "recovery_codes_set", "account_ref": ACCOUNT, "set_id": set_id, "nonce": nonce_set, "codes": CODES}
        p.update(over)
        return p

    def start_plain(**over):
        p = {"v": 1, "purpose": "recovery_started", "recovery_id": "7K3M9Q2W4X6Z", "nonce": nonce_start, "code": CODES[3], "new_kids": kids}
        p.update(over)
        return p

    infos = {"recovery_codes_set": "VIADERE-RECOVERY-SET-V1\n", "recovery_started": "VIADERE-RECOVERY-START-V1\n"}
    cases = []
    counter = [0]

    def seal(name, purpose, plaintext, expect="accept", env="stg", challenge=None, open_with=None, plaintext_bytes=None, to=SEAL, kid=None,
             mutate=None, envelope_override=None, claimed_digest=None, authority=None):
        counter[0] += 1
        c_ach, c_nonce = challenge or ((ach_set, nonce_set) if purpose == "recovery_codes_set" else (ach_start, nonce_start))
        info = (infos[purpose] + env).encode()
        aad = (c_ach + "\n" + c_nonce).encode()
        pt = plaintext_bytes if plaintext_bytes is not None else canonical(plaintext)
        sk_e = key(int.from_bytes(hashlib.sha256(b"ephemeral-%d" % counter[0]).digest(), "big") % (N - 1) + 1)
        enc, ct = hpke_seal(x963(to), sk_e, info, aad, pt)
        if mutate == "ct":
            ct = ct[:-1] + bytes([ct[-1] ^ 1])
        if mutate == "enc":
            enc = x963(key(0x42))
        envelope = {"v": 1, "kid": kid or thumbprint(to), "enc": b64u(enc), "ct": b64u(ct)}
        if envelope_override:
            envelope = envelope_override(envelope)
        ow = {"purpose": purpose, "env": env, "challenge_id": c_ach, "nonce": c_nonce}
        if open_with:
            ow.update(open_with)
        c = {"name": name, "envelope": envelope, "envelope_digest": b64u(hashlib.sha256(enc + ct).digest()), "open_with": ow, "expect": expect,
             "info": info.decode(), "aad": aad.decode(), "ephemeral_public": b64u(x963(sk_e))}
        if expect == "accept":
            c["plaintext"] = pt.decode()
        if claimed_digest:
            c["claimed_digest"] = claimed_digest
        if authority:
            c["authority"] = authority
        cases.append(c)
        return c

    seal("set", "recovery_codes_set", set_plain())
    seal("set for production", "recovery_codes_set", set_plain(), env="prod")
    seal("start with two new keys", "recovery_started", start_plain())
    seal("start with four new keys", "recovery_started", start_plain(new_kids=sorted([device_kid(k) for k in [DEVICE_A, DEVICE_B, DEVICE_C, DEVICE_X]])))
    seal("start with one new key", "recovery_started", start_plain(new_kids=[device_kid(DEVICE_X)]))
    seal("sealed for prod, opened in stg (info env)", "recovery_codes_set", set_plain(), "open_failed", env="prod", open_with={"env": "stg"})
    seal("sealed as a set, opened as a start (info purpose)", "recovery_codes_set", set_plain(), "open_failed", open_with={"purpose": "recovery_started"})
    seal("another challenge id (aad)", "recovery_codes_set", set_plain(), "open_failed", open_with={"challenge_id": ach("other")})
    seal("another challenge nonce (aad)", "recovery_codes_set", set_plain(), "open_failed", open_with={"nonce": nonce("other")})
    seal("tampered ct", "recovery_codes_set", set_plain(), "open_failed", mutate="ct")
    seal("substituted enc", "recovery_codes_set", set_plain(), "open_failed", mutate="enc")
    seal("sealed to another key", "recovery_codes_set", set_plain(), "wrong_key", to=SEAL_OTHER)
    seal("another key's ciphertext under our kid", "recovery_codes_set", set_plain(), "open_failed", to=SEAL_OTHER, kid=seal_kid)
    seal("envelope with an extra member", "recovery_codes_set", set_plain(), "malformed", envelope_override=lambda e: dict(e, alg="HPKE"))
    seal("envelope v 2", "recovery_codes_set", set_plain(), "malformed", envelope_override=lambda e: dict(e, v=2))
    seal("envelope without kid", "recovery_codes_set", set_plain(), "malformed", envelope_override=lambda e: {k: v for k, v in e.items() if k != "kid"})
    seal("compressed enc (33 bytes)", "recovery_codes_set", set_plain(), "malformed",
         envelope_override=lambda e: dict(e, enc=b64u(SEAL_OTHER.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint))))
    seal("ct shorter than a tag", "recovery_codes_set", set_plain(), "malformed", envelope_override=lambda e: dict(e, ct=b64u(b"\x00" * 16)))
    # SECURITY §2.1: base64url has no padding. Core's envelope parser decodes `enc` and `ct` without the strict check (see `spec_disagreements`).
    seal("padded enc", "recovery_codes_set", set_plain(), "malformed", envelope_override=lambda e: dict(e, enc=e["enc"] + "="))
    seal("padded ct", "recovery_codes_set", set_plain(), "malformed", envelope_override=lambda e: dict(e, ct=e["ct"] + ("=" * (-len(e["ct"]) % 4) or "==")))
    disagreements = [c for c in cases if c["name"] in ("padded enc", "padded ct")]
    cases[:] = [c for c in cases if c not in disagreements]
    seal("set plaintext with an extra member", "recovery_codes_set", set_plain(device="iPhone"), "plaintext_members")
    seal("set plaintext without nonce", "recovery_codes_set", {k: v for k, v in set_plain().items() if k != "nonce"}, "plaintext_members")
    seal("set plaintext with the start purpose", "recovery_codes_set", set_plain(purpose="recovery_started"), "plaintext_members")
    seal("set_id not rcs_ + 22", "recovery_codes_set", set_plain(set_id="rcs_short"), "plaintext_members")
    seal("non-normalized code (lower case)", "recovery_codes_set", set_plain(codes=CODES[:9] + ["tvwxyz0123"]), "plaintext_codes")
    seal("non-normalized code (grouped)", "recovery_codes_set", set_plain(codes=CODES[:9] + ["TVWXY-Z0123"]), "plaintext_codes")
    seal("code with I (maps to 1)", "recovery_codes_set", set_plain(codes=CODES[:9] + ["TVWXYZI123"]), "plaintext_codes")
    seal("nine codes", "recovery_codes_set", set_plain(codes=CODES[:9]), "plaintext_codes")
    seal("duplicate code", "recovery_codes_set", set_plain(codes=CODES[:9] + [CODES[0]]), "plaintext_codes")
    seal("non-canonical plaintext (spaces)", "recovery_codes_set", None, "plaintext_encoding", plaintext_bytes=json.dumps(set_plain(), sort_keys=True).encode())
    seal("non-canonical plaintext (member order)", "recovery_codes_set", None, "plaintext_encoding",
         plaintext_bytes=json.dumps(set_plain(), separators=(",", ":")).encode())
    seal("start without new_kids", "recovery_started", {k: v for k, v in start_plain().items() if k != "new_kids"}, "plaintext_members")
    seal("start with a non-normalized code", "recovery_started", start_plain(code="yz01234567"), "plaintext_members")
    seal("unsorted new_kids", "recovery_started", start_plain(new_kids=list(reversed(kids))), "plaintext_new_kids")
    seal("duplicate new_kids", "recovery_started", start_plain(new_kids=[kids[0], kids[0]]), "plaintext_new_kids")
    seal("five new_kids", "recovery_started", start_plain(new_kids=sorted([device_kid(k) for k in [DEVICE_A, DEVICE_B, DEVICE_C, DEVICE_X, UNKNOWN]])),
         "plaintext_new_kids")
    seal("empty new_kids", "recovery_started", start_plain(new_kids=[]), "plaintext_new_kids")
    seal("RFC 7638 thumbprint in new_kids", "recovery_started", start_plain(new_kids=[thumbprint(DEVICE_X) + "="]), "plaintext_new_kids")
    good = cases[0]
    seal("envelope_digest in the device signature does not match", "recovery_codes_set", set_plain(), "accept",
         claimed_digest=b64u(hashlib.sha256(b"another envelope").digest()))
    # ADR-0034 §7 revision 3.1 additions: Core opens and parses these; the authority's comparisons refuse them.
    seal("set sealed for another account than the authorizing key's", "recovery_codes_set", set_plain(account_ref=OTHER_ACCOUNT), "accept",
         authority={"authorizing_account_ref": ACCOUNT, "challenge_set_id": set_id, "expect": "account_mismatch"})
    seal("set_id differs from the challenge's", "recovery_codes_set", set_plain(set_id="rcs_" + b64u(hashlib.sha256(b"other-set").digest()[:16])), "accept",
         authority={"authorizing_account_ref": ACCOUNT, "challenge_set_id": set_id, "expect": "set_id_mismatch"})
    seal("PoP keys a strict superset of new_kids", "recovery_started", start_plain(new_kids=[kids[0]]), "accept",
         authority={"pop_kids": kids, "expect": "new_kids_mismatch"})
    seal("PoP keys a strict subset of new_kids", "recovery_started", start_plain(), "accept",
         authority={"pop_kids": [kids[0]], "expect": "new_kids_mismatch"})
    seal("PoP keys equal to new_kids", "recovery_started", start_plain(), "accept", authority={"pop_kids": list(reversed(kids)), "expect": "accept"})
    assert good["expect"] == "accept"

    a = {k: v for k, v in RFC9180_A31.items()}
    return {
        "description": "Sealed recovery envelopes (ADR-0034 §1, §2, §7; SECURITY §2.103), lean construction HPKE mode_base DHKEM(P-256, HKDF-SHA256) / "
                       "HKDF-SHA256 / AES-256-GCM with fixed ephemeral keys, plus RFC 9180 A.3.1 (AES-128-GCM) to check the KEM and key schedule. "
                       "The ADR-0034 §9 JWE construction is not implemented yet and has no cases. Generated by generate_authority_v1.py recovery-seal.",
        "rfc9180_a31": dict(a, suite="DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM", mode=0),
        "seal_key": {"d": b64u(SEAL.private_numbers().private_value.to_bytes(32, "big")), **pubkey(SEAL), "kid": seal_kid},
        "other_seal_key": {**pubkey(SEAL_OTHER), "kid": thumbprint(SEAL_OTHER)},
        "cases": cases,
        "spec_disagreements": disagreements,
    }


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else ""
    builders = {"keylog": keylog, "device-statements": device_statements, "auth-destination": auth_destination, "recovery-seal": recovery_seal}
    if which not in builders:
        sys.exit("usage: generate_authority_v1.py {keylog|device-statements|auth-destination|recovery-seal}")
    print(json.dumps(builders[which](), indent=2, ensure_ascii=False))
