#!/usr/bin/env python3
"""Generates docs/protocol/vectors/http-signatures-v1.json (SECURITY.md 2.112, ADR-0020 section 3).

The Viadere profile of RFC 9421 (HTTP Message Signatures) with RFC 9530 Content-Digest for business API requests, written from the RFCs and
independently of the Swift and TypeScript code. Needs only the standard library and `cryptography` (deterministic ECDSA, RFC 6979, needs
OpenSSL 3.2 or later); run it from a virtual environment outside the repository:

    python3 -I generate_http_signatures_v1.py > http-signatures-v1.json

Signatures are deterministic (RFC 6979) and then folded to low S, so re-running reproduces the file byte for byte.

Before it writes anything it checks its own signature-base serializer against the non-normative example of RFC 9421 section 2.5 (Figure 1).
"""
import base64, hashlib, json, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
TAG = "viadere-api-v1"
BODY_COMPONENTS = ["@method", "@authority", "@path", "@query", "content-digest", "content-type"]
BODILESS_COMPONENTS = ["@method", "@authority", "@path", "@query"]
NOW = 1_800_000_000
AUTHORITY = "viadere.com"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64(b: bytes) -> str:  # RFC 8941 byte sequence: standard alphabet, padded
    return base64.b64encode(b).decode()


def key(scalar: int):
    return ec.derive_private_key(scalar, ec.SECP256R1())


def x963(priv) -> str:
    return b64u(priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))


def raw_sign(priv, message: bytes) -> bytes:
    """Deterministic ECDSA P-256/SHA-256 (RFC 6979), raw r||s with s folded to s <= n/2."""
    r, s = decode_dss_signature(priv.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
    if s > N // 2:
        s = N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def high_s(raw: bytes) -> bytes:
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    return raw[:32] + (N - s).to_bytes(32, "big")


def der(raw: bytes) -> bytes:
    return encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))


def sf_string(s: str) -> str:
    assert all(0x20 <= ord(c) <= 0x7E and c not in '"\\' for c in s)
    return '"' + s + '"'


def params_value(components, params) -> str:
    """RFC 9421 section 2.3: the inner list of component identifiers, then the parameters in the order given."""
    out = "(" + " ".join(sf_string(c) for c in components) + ")"
    for name, value in params:
        out += ";" + name + "=" + (str(value) if isinstance(value, int) else sf_string(value))
    return out


def signature_base(lines, params_val: str) -> str:
    """RFC 9421 section 2.5: one `"name": value` line per covered component, then the @signature-params line, LF-joined, no trailing LF."""
    out = "".join(f'{sf_string(name)}: {value}\n' for name, value in lines)
    out += '"@signature-params": ' + params_val
    out.encode("ascii")
    return out


def content_digest(body: bytes) -> str:  # RFC 9530: Dictionary, sha-256 member, byte sequence value
    return "sha-256=:" + b64(hashlib.sha256(body).digest()) + ":"


def self_check():
    """RFC 9421 section 2.5, Figure 1 (non-normative example signature base)."""
    digest = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
    comps = ["@method", "@authority", "@path", "content-digest", "content-length", "content-type"]
    got = signature_base([("@method", "POST"), ("@authority", "example.com"), ("@path", "/foo"), ("content-digest", digest),
                          ("content-length", "18"), ("content-type", "application/json")],
                         params_value(comps, [("created", 1618884473), ("keyid", "test-key-rsa-pss")]))
    expected = ('"@method": POST\n"@authority": example.com\n"@path": /foo\n"content-digest": ' + digest + '\n"content-length": 18\n'
                '"content-type": application/json\n"@signature-params": ("@method" "@authority" "@path" "content-digest" "content-length" '
                '"content-type");created=1618884473;keyid="test-key-rsa-pss"')
    assert got == expected, got
    # RFC 9530 Appendix B.1-style check: sha-256 of {"hello": "world"} as the RFC lists it.
    assert content_digest(b'{"hello": "world"}') == "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"


# ---------------------------------------------------------------------------------------------------------------------------------------------
# Fixed identities

BIZ_A = "0f7c2b1a-3d4e-4f50-8a6b-7c8d9e0f1a2b"
BIZ_B = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
KEY_A1 = "2b3c4d5e-6f70-4a8b-9cad-1e2f3a4b5c6d"
KEY_A2 = "3c4d5e6f-7081-4b9c-8dbe-2f3a4b5c6d7e"
KEY_B1 = "4d5e6f70-8192-4cad-9ecf-3a4b5c6d7e8f"

SK_A = key(0x1F2E3D4C5B6A79880123456789ABCDEF0011223344556677)
SK_REVOKED = key(0x2A2B2C2D2E2F30313233343536373839)
SK_OTHER_BIZ = key(0x3A3B3C3D3E3F40414243444546474849)
SK_OTHER_KEY = key(0x4A4B4C4D4E4F50515253545556575859)

KEYS = [
    {"keyid": "vsk_0123456789abcdef", "priv": SK_A, "business_id": BIZ_A, "api_key_id": KEY_A1, "revoked": False},
    {"keyid": "vsk_1111222233334444", "priv": SK_REVOKED, "business_id": BIZ_A, "api_key_id": KEY_A1, "revoked": True},
    {"keyid": "vsk_aaaabbbbccccdddd", "priv": SK_OTHER_BIZ, "business_id": BIZ_B, "api_key_id": KEY_B1, "revoked": False},
    {"keyid": "vsk_5555666677778888", "priv": SK_OTHER_KEY, "business_id": BIZ_A, "api_key_id": KEY_A2, "revoked": False},
]
KEY_BY_ID = {k["keyid"]: k for k in KEYS}
PRESENTER = {"business_id": BIZ_A, "api_key_id": KEY_A1}

BODY = b'{"method":"otp","request_id":"login-7f3a","subject_ref":"sr_9QeZrVYk0aU4mF1x","purpose":"sign_in","template":"auth.sign_in_code.v1","otp":{"code":"482913","code_kind":"otp"}}'
NONCE = "8hKq3vW1xZ0aB4cD5eF6gA"


def split_target(path_and_query: str):
    path, sep, query = path_and_query.partition("?")
    return path, "?" + query


def build(method="POST", target="/v1/business/auth-deliveries", body=BODY, content_type="application/json", keyid="vsk_0123456789abcdef",
          created=NOW - 10, expires=None, nonce=NONCE, tag=TAG, components=None, params=None, sign_authority=AUTHORITY, sign_method=None,
          sign_target=None, sign_digest=None, label="sig1", priv=None):
    """A signed request. `sign_*` sign something other than what is sent (the signature then covers a different message)."""
    expires = created + 300 if expires is None else expires
    with_body = len(body) > 0
    components = components if components is not None else (BODY_COMPONENTS if with_body else BODILESS_COMPONENTS)
    params = params if params is not None else [("created", created), ("expires", expires), ("keyid", keyid), ("nonce", nonce), ("tag", tag)]
    digest = content_digest(body) if with_body else None
    s_path, s_query = split_target(sign_target or target)
    values = {"@method": sign_method or method, "@authority": sign_authority, "@path": s_path, "@query": s_query,
              "content-digest": sign_digest or digest, "content-type": content_type,
              "@target-uri": "https://" + sign_authority + (sign_target or target), "idempotency-key": "k-1"}
    pv = params_value(components, params)
    base = signature_base([(c, values[c]) for c in components], pv)
    signer = priv or (KEY_BY_ID[keyid]["priv"] if keyid in KEY_BY_ID else SK_A)
    raw = raw_sign(signer, base.encode("ascii"))
    headers = []
    if with_body:
        headers.append(["Content-Type", content_type])
        headers.append(["Content-Digest", digest])
    headers.append(["Signature-Input", f"{label}={pv}"])
    headers.append(["Signature", f"{label}=:{b64(raw)}:"])
    return {"method": method, "path_and_query": target, "headers": headers, "body": body.decode()}, base, raw


def header(req, name):
    return next(v for n, v in req["headers"] if n.lower() == name.lower())


def set_header(req, name, value):
    req["headers"] = [[n, value if n.lower() == name.lower() else v] for n, v in req["headers"]]


def drop_header(req, name):
    req["headers"] = [[n, v] for n, v in req["headers"] if n.lower() != name.lower()]


def positive(name, description, **kw):
    req, base, raw = build(**kw)
    return {"name": name, "description": description, "request": req, "presenter": PRESENTER, "signature_base": base,
            "signature_input": header(req, "Signature-Input"), "signature": header(req, "Signature"),
            "content_digest": next((v for n, v in req["headers"] if n == "Content-Digest"), None),
            "signature_raw_b64url": b64u(raw), "keyid": kw.get("keyid", "vsk_0123456789abcdef"), "nonce": kw.get("nonce", NONCE),
            "created": kw.get("created", NOW - 10)}


def negative(name, description, expected, req, presenter=PRESENTER, used_nonces=None):
    case = {"name": name, "description": description, "expected_error": expected, "request": req, "presenter": presenter}
    if used_nonces:
        case["used_nonces"] = used_nonces
    return case


def main():
    self_check()
    pos = [
        positive("post_json_body", "POST with a JSON body: all six components, Content-Digest sha-256."),
        positive("get_no_query", "GET without a query string: bodiless components; @query is the lone '?'.", method="GET",
                 target="/v1/business/auth-deliveries/adl_AAAAAAAAAAAAAAAAAAAAAA", body=b"", nonce="Zm9vYmFyYmF6cXV4cXV1eA"),
        positive("get_with_query", "GET with a percent-encoded query: @path and @query are taken undecoded.", method="GET",
                 target="/v1/business/interactions?limit=20&cursor=a%2Fb", body=b"", nonce="cXdlcnR5dWlvcGFzZGZnaA"),
        positive("post_empty_body", "POST without a body (cancel): bodiless components, no Content-Digest.",
                 target="/v1/business/auth-deliveries/adl_AAAAAAAAAAAAAAAAAAAAAA/cancel", body=b"", nonce="MTIzNDU2Nzg5MDEyMzQ1Ng"),
        positive("parameters_reordered_with_alg", "Parameters in another order, with the optional alg naming the one allowed algorithm; created at the 300 s edge.",
                 created=NOW - 300, nonce="b3JkZXJlZC1wYXJhbXMtMDE",
                 params=[("keyid", "vsk_0123456789abcdef"), ("alg", "ecdsa-p256-sha256"), ("nonce", "b3JkZXJlZC1wYXJhbXMtMDE"), ("tag", TAG),
                         ("created", NOW - 300), ("expires", NOW)]),
    ]

    neg = []
    base_req = lambda **kw: build(**kw)[0]

    # Fields
    r = base_req(); drop_header(r, "Signature"); drop_header(r, "Signature-Input")
    neg.append(negative("no_signature", "Neither Signature nor Signature-Input.", "missing_signature", r))
    r = base_req(); drop_header(r, "Signature")
    neg.append(negative("signature_input_without_signature", "Signature-Input alone.", "signature_incomplete", r))
    r = base_req(); r["headers"].append(["Signature-Input", header(r, "Signature-Input")])
    neg.append(negative("duplicate_signature_input_field", "Two Signature-Input field lines.", "duplicate_field", r))
    r = base_req(); r["headers"].append(["Signature", header(r, "Signature")])
    neg.append(negative("duplicate_signature_field", "Two Signature field lines.", "duplicate_field", r))
    r = base_req(); r["headers"].append(["Content-Digest", header(r, "Content-Digest")])
    neg.append(negative("duplicate_content_digest_field", "Two Content-Digest field lines (RFC 9421 section 2.1 would join them; the profile refuses).", "duplicate_field", r))
    r = base_req(); r["headers"].append(["Content-Type", "text/plain"])
    neg.append(negative("duplicate_content_type_field", "Two Content-Type field lines.", "duplicate_field", r))
    r = base_req(); si = header(r, "Signature-Input"); set_header(r, "Signature-Input", si + ", " + si.replace("sig1=", "sig2=", 1))
    sg = header(r, "Signature"); set_header(r, "Signature", sg + ", " + sg.replace("sig1=", "sig2=", 1))
    neg.append(negative("two_signatures_in_one_field", "Two members in one Signature-Input and Signature field.", "multiple_signatures", r))
    r = base_req(); set_header(r, "Signature", header(r, "Signature").replace("sig1=", "sig2=", 1))
    neg.append(negative("label_mismatch", "Signature and Signature-Input carry different labels.", "label_mismatch", r))
    r = base_req(); set_header(r, "Signature-Input", header(r, "Signature-Input").replace('("@method"', '( "@method"'))
    neg.append(negative("non_strict_serialization", "Signature-Input that is not in strict structured-field serialization.", "malformed_signature_input", r))
    r = base_req(); set_header(r, "Signature", "sig1=" + header(r, "Signature")[6:-1])
    neg.append(negative("signature_not_byte_sequence", "Signature value that is not a byte sequence.", "malformed_signature", r))

    # Components
    neg.append(negative("extra_component", "An extra covered component (idempotency-key).", "wrong_components",
                        base_req(components=BODY_COMPONENTS + ["idempotency-key"]) | {}))
    neg[-1]["request"]["headers"].insert(0, ["Idempotency-Key", "k-1"])
    neg.append(negative("missing_query_component", "@query not covered.", "wrong_components",
                        base_req(components=["@method", "@authority", "@path", "content-digest", "content-type"])))
    neg.append(negative("target_uri_instead", "@target-uri instead of @authority/@path/@query.", "wrong_components",
                        base_req(components=["@method", "@target-uri", "content-digest", "content-type"])))
    neg.append(negative("components_reordered", "The right components in another order.", "wrong_components",
                        base_req(components=["@authority", "@method", "@path", "@query", "content-digest", "content-type"])))
    neg.append(negative("bodiless_list_on_body", "A body request signed with the bodiless list (content-digest and content-type not covered).", "wrong_components",
                        base_req(components=BODILESS_COMPONENTS)))
    r = base_req(); set_header(r, "Signature-Input", header(r, "Signature-Input").replace('"content-type")', '"content-type";sf)'))
    neg.append(negative("component_parameter", "A parameter on a component identifier (;sf).", "component_parameters", r))

    # Parameters
    def without(name):
        return [p for p in [("created", NOW - 10), ("expires", NOW + 290), ("keyid", "vsk_0123456789abcdef"), ("nonce", NONCE), ("tag", TAG)] if p[0] != name]
    for missing in ["created", "expires", "keyid", "nonce", "tag"]:
        neg.append(negative(f"missing_{missing}", f"No {missing} parameter.", "missing_parameter", base_req(params=without(missing))))
    neg.append(negative("unknown_parameter", "An unregistered parameter.", "unknown_parameter", base_req(params=without("zzz") + [("foo", 1)])))
    neg.append(negative("duplicate_parameter", "created given twice.", "duplicate_parameter", base_req(params=without("zzz") + [("created", NOW - 10)])))
    neg.append(negative("wrong_algorithm", "alg names another algorithm.", "wrong_algorithm", base_req(params=without("zzz") + [("alg", "ed25519")])))
    neg.append(negative("wrong_tag", "tag of another application.", "wrong_tag", base_req(tag="viadere-biz-v1")))
    neg.append(negative("keyid_as_integer", "keyid as an integer instead of a string.", "malformed_parameter",
                        base_req(params=[("created", NOW - 10), ("expires", NOW + 290), ("keyid", 12345), ("nonce", NONCE), ("tag", TAG)])))
    neg.append(negative("malformed_keyid", "keyid outside vsk_ + 16 lowercase hex.", "malformed_keyid", base_req(keyid="vsk_0123456789ABCDEF")))
    neg.append(negative("short_nonce", "nonce shorter than 22 base64url characters.", "malformed_nonce", base_req(nonce="c2hvcnQ")))

    # Time
    neg.append(negative("created_in_future", "created more than 300 s ahead of the verifier.", "created_in_future", base_req(created=NOW + 301)))
    neg.append(negative("stale_created", "created more than 300 s ago.", "stale", base_req(created=NOW - 301)))
    neg.append(negative("expires_passed", "expires already passed.", "expired", base_req(created=NOW - 100, expires=NOW - 1)))
    neg.append(negative("expires_too_far", "expires more than 300 s after created.", "invalid_expires", base_req(expires=NOW - 10 + 301)))
    neg.append(negative("expires_not_after_created", "expires equal to created.", "invalid_expires", base_req(expires=NOW - 10)))

    # Content
    r = base_req(); r["body"] = r["body"].replace("482913", "000000")
    neg.append(negative("digest_mismatch", "The body differs from the signed Content-Digest.", "digest_mismatch", r))
    r = base_req(components=BODILESS_COMPONENTS); drop_header(r, "Content-Digest")
    neg.append(negative("body_without_digest", "A body and no Content-Digest field.", "digest_required", r))
    r = base_req(sign_digest="sha-512=:" + b64(hashlib.sha512(BODY).digest()) + ":"); set_header(r, "Content-Digest", "sha-512=:" + b64(hashlib.sha512(BODY).digest()) + ":")
    neg.append(negative("digest_sha512", "Content-Digest with sha-512 only (the profile requires sha-256 alone).", "malformed_digest", r))
    r = base_req(); set_header(r, "Content-Digest", header(r, "Content-Digest") + ", sha-512=:" + b64(hashlib.sha512(BODY).digest()) + ":")
    neg.append(negative("digest_two_members", "Content-Digest with a second member.", "malformed_digest", r))
    r = base_req(method="GET", target="/v1/business/auth-deliveries/adl_AAAAAAAAAAAAAAAAAAAAAA", body=b"")
    r["headers"].insert(0, ["Content-Digest", content_digest(b"")])
    neg.append(negative("digest_on_bodiless", "Content-Digest on a request without a body.", "digest_not_allowed", r))
    r = base_req(); drop_header(r, "Content-Type")
    neg.append(negative("body_without_content_type", "A body and no Content-Type field.", "content_type_required", r))

    # Signature bytes
    r, _, raw = build(); set_header(r, "Signature", "sig1=:" + b64(high_s(raw)) + ":")
    neg.append(negative("high_s", "The same signature with s replaced by n - s (valid ECDSA, not canonical).", "high_s", r))
    r, _, raw = build(); set_header(r, "Signature", "sig1=:" + b64(der(raw)) + ":")
    neg.append(negative("der_signature", "The same signature DER-encoded.", "not_raw_signature", r))
    r, _, raw = build(); set_header(r, "Signature", "sig1=:" + b64(raw[:63]) + ":")
    neg.append(negative("short_signature", "63 signature bytes.", "not_raw_signature", r))

    # Keys
    neg.append(negative("unknown_key", "keyid nobody registered.", "unknown_key", base_req(keyid="vsk_ffffffffffffffff", priv=SK_A)))
    neg.append(negative("revoked_key", "A revoked signing key.", "revoked_key", base_req(keyid="vsk_1111222233334444")))
    neg.append(negative("key_of_another_business", "A signing key registered by another business.", "wrong_business", base_req(keyid="vsk_aaaabbbbccccdddd")))
    neg.append(negative("key_of_another_api_key", "A signing key bound to another API key of the same business.", "wrong_api_key", base_req(keyid="vsk_5555666677778888")))
    neg.append(negative("signed_with_other_private_key", "Registered keyid, signature made with a different private key.", "bad_signature",
                        base_req(priv=SK_OTHER_KEY)))

    # Message binding
    neg.append(negative("other_authority", "Signed for another authority (Host).", "bad_signature", base_req(sign_authority="evil.example")))
    neg.append(negative("authority_with_port", "Signed for the authority with an explicit port.", "bad_signature", base_req(sign_authority="viadere.com:443")))
    neg.append(negative("other_path", "Signed for another path.", "bad_signature", base_req(sign_target="/v1/business/auth-approvals")))
    neg.append(negative("other_query", "Signed for another query.", "bad_signature",
                        base_req(method="GET", target="/v1/business/interactions?limit=20", sign_target="/v1/business/interactions?limit=21", body=b"")))
    neg.append(negative("query_added", "Signed without a query, sent with one.", "bad_signature",
                        base_req(method="GET", target="/v1/business/interactions?limit=20", sign_target="/v1/business/interactions", body=b"")))
    neg.append(negative("other_method", "Signed for PUT, sent as POST.", "bad_signature", base_req(sign_method="PUT")))
    r = base_req(); set_header(r, "Content-Type", "text/plain")
    neg.append(negative("other_content_type", "Content-Type changed after signing.", "bad_signature", r))

    # Replay
    neg.append(negative("replayed_nonce", "The nonce was already used with this key.", "replayed", base_req(),
                        used_nonces=[{"scope": f"bizsig:{BIZ_A}:vsk_0123456789abcdef", "nonce": NONCE}]))

    doc = {
        "description": "Viadere RFC 9421 profile for business API requests (SECURITY.md 2.112). Generated by generate_http_signatures_v1.py "
                       "(Python standard library + cryptography, deterministic ECDSA RFC 6979, low S). Verification order and error codes are normative.",
        "profile": {
            "tag": TAG, "algorithm": "ecdsa-p256-sha256", "body_components": BODY_COMPONENTS, "bodiless_components": BODILESS_COMPONENTS,
            "required_parameters": ["created", "expires", "keyid", "nonce", "tag"], "optional_parameters": ["alg"],
            "max_age_seconds": 300, "max_future_skew_seconds": 300, "max_lifetime_seconds": 300, "nonce_ttl_seconds": 600,
            "keyid_pattern": "^vsk_[0-9a-f]{16}$", "nonce_pattern": "^[A-Za-z0-9_-]{22,64}$", "replay_scope": "bizsig:{business_id}:{keyid}",
        },
        "now": NOW,
        "accepted_authorities": [AUTHORITY],
        "keys": [{"keyid": k["keyid"], "public_key": x963(k["priv"]), "business_id": k["business_id"], "api_key_id": k["api_key_id"],
                  "revoked": k["revoked"]} for k in KEYS],
        "signer_private_key_hex": format(SK_A.private_numbers().private_value, "064x"),
        "positive": pos,
        "negative": neg,
    }
    json.dump(doc, sys.stdout, indent=2, ensure_ascii=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
