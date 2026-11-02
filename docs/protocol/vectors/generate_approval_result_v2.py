#!/usr/bin/env python3
"""Generates docs/protocol/vectors/approval-result-v2.json (ADR-0022 §2-§3, ADR-0023 §2; Stage 5).

Independent of the Swift code: canonical JSON (SECURITY §2.2, ASCII-only members here), ES256 with raw r||s and low S, the v2 member set, the
number-match tags (ADR-0020 §2a), the SDK key derivation and the code sampler. Run: python3 -I generate_approval_result_v2.py > approval-result-v2.json
The ECDSA signatures are randomized; re-running changes the `jws` strings but every case keeps its expected outcome.
"""
import base64, hashlib, hmac, json, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def canonical(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


SCALAR = bytes.fromhex("6f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8")
priv = ec.derive_private_key(int.from_bytes(SCALAR, "big"), ec.SECP256R1())
pub = priv.public_key()
x963 = pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
spki = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
KID = b64u(hashlib.sha256(spki).digest())

OTHER = ec.derive_private_key(0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF, ec.SECP256R1())


def sign(header: dict, payload: dict, key=priv) -> str:
    h, p = b64u(canonical(header)), b64u(canonical(payload))
    der = key.sign((h + "." + p).encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    if s > N // 2:
        s = N - s
    return h + "." + p + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


NOW = 1_793_000_000
AUD = "6c0f6a0e-6f4b-4f3b-9f55-6f3a1d2c3b4a"
SUB = "sub_" + b64u(bytes([7]) * 32)
REQUEST_ID = "req_stage5_vector_0001"
CHALLENGE = b64u(bytes(range(32)))
CODE = "47"
AUTH = {"action_display": "Sign in to Example Bank", "capability": "auth.challenge", "match_digits": 2, "v": 1}
TXN_DIGEST = hashlib.sha256(b"VIADERE-TXN-V1\n" + canonical(AUTH)).hexdigest()
JTI = b64u(bytes(range(100, 116)))
HEADER = {"alg": "ES256", "kid": KID, "typ": "viadere-approval+jws"}


def claims(**over):
    base = {"v": 2, "alg": "ES256", "kid": KID, "aud": AUD, "sub": SUB, "request_id": REQUEST_ID, "challenge": CHALLENGE, "cap": "auth.challenge",
            "decision": "approve", "amr": "biometric", "iat": NOW, "exp": NOW + 300, "txn_digest": TXN_DIGEST, "jti": JTI, "match": CODE,
            "invalid_match_attempts": 0}
    for k, v in over.items():
        if v is None:
            base.pop(k, None)
        else:
            base[k] = v
    return base


cases = [
    {"name": "approve_v2_with_the_right_number", "expectation": "required", "jws": sign(HEADER, claims()), "outcome": "approve"},
    {"name": "deny_number_mismatch_after_three_wrong_entries", "expectation": "required",
     "jws": sign(HEADER, claims(decision="deny", match=None, deny_reason="number_mismatch", invalid_match_attempts=3)), "outcome": "deny"},
    {"name": "report_not_me", "expectation": "required", "jws": sign(HEADER, claims(decision="report", match=None, deny_reason="not_me")), "outcome": "report"},
    {"name": "v1_result_for_a_number_matched_request", "expectation": "required",
     "jws": sign(HEADER, claims(v=1, jti=None, match=None, invalid_match_attempts=None)), "error": "numberMatchRequired"},
    {"name": "v2_approve_without_match", "expectation": "required", "jws": sign(HEADER, claims(match=None)), "error": "numberMismatch"},
    {"name": "v2_approve_with_the_wrong_number", "expectation": "required", "jws": sign(HEADER, claims(match="74")), "error": "numberMismatch"},
    {"name": "match_on_a_request_that_asked_for_none", "expectation": "not_requested", "jws": sign(HEADER, claims()), "error": "unexpectedMatch"},
    {"name": "unknown_payload_member", "expectation": "required", "jws": sign(HEADER, claims(extra="x")), "error": "malformed"},
    {"name": "deny_reason_on_an_approve", "expectation": "required", "jws": sign(HEADER, claims(deny_reason="not_me")), "error": "malformed"},
    {"name": "not_me_on_a_deny", "expectation": "required", "jws": sign(HEADER, claims(decision="deny", match=None, deny_reason="not_me")), "error": "malformed"},
    {"name": "missing_jti", "expectation": "required", "jws": sign(HEADER, claims(jti=None)), "error": "malformed"},
    {"name": "short_jti", "expectation": "required", "jws": sign(HEADER, claims(jti=b64u(bytes(8)))), "error": "malformed"},
    {"name": "invalid_match_attempts_out_of_range", "expectation": "required", "jws": sign(HEADER, claims(invalid_match_attempts=4)), "error": "malformed"},
    {"name": "match_with_a_leading_zero", "expectation": "required", "jws": sign(HEADER, claims(match="07")), "error": "malformed"},
    {"name": "wrong_typ", "expectation": "required", "jws": sign(dict(HEADER, typ="JWT"), claims()), "error": "unsupportedType"},
    {"name": "extra_header_member_jwk", "expectation": "required", "jws": sign(dict(HEADER, jwk="x"), claims()), "error": "malformed"},
    {"name": "wrong_audience", "expectation": "required", "jws": sign(HEADER, claims(aud="00000000-0000-4000-8000-000000000001")), "error": "wrongAudience"},
    {"name": "signed_by_another_key", "expectation": "required", "jws": sign(HEADER, claims(), key=OTHER), "error": "badSignature"},
    {"name": "expired", "expectation": "required", "jws": sign(HEADER, claims(iat=NOW - 900, exp=NOW - 600)), "error": "expired"},
    {"name": "v3", "expectation": "required", "jws": sign(HEADER, claims(v=3)), "error": "unsupportedVersion"},
]

# Number-match tags (ADR-0020 §2a) with the SDK key derivation: K = HKDF-SHA256(ikm = SDK secret, salt = none, info = label, 32 bytes).
SDK_SECRET = bytes(range(32))


def hkdf(label: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label.encode()).derive(SDK_SECRET)


K_MATCH = hkdf("viadere-match-tag-key-v1")
K_SH = hkdf("viadere-session-handle-key-v1")


def tag(code: str) -> str:
    return b64u(hmac.new(K_MATCH, ("viadere-match-tag-v1\n" + SUB + "\n" + code).encode(), hashlib.sha256).digest())


tags = [{"code": c, "match_tag": tag(c), "match_prefix_tag": tag(c[:2]) if len(c) == 3 else None} for c in ["47", "470", "999", "10"]]
handles = [{"initiating_session_id": s, "session_handle": b64u(hmac.new(K_SH, ("viadere-session-handle-v1\n" + s).encode(), hashlib.sha256).digest())}
           for s in ["sess-1f2e3d", "browser-session-0001"]]


# The code sampler: 16-bit big-endian samples, accepted below the largest multiple of the span (65520 for 90, 64800 for 900), then low + sample % span.
def draw(digits: int, stream: bytes) -> str:
    low, span = (10, 90) if digits == 2 else (100, 900)
    limit = (65536 // span) * span
    for i in range(0, len(stream), 2):
        sample = int.from_bytes(stream[i:i + 2], "big")
        if sample < limit:
            return str(low + sample % span)
    raise ValueError("stream exhausted")


draws = [{"digits": d, "random_hex": h, "code": draw(d, bytes.fromhex(h))}
         for d, h in [(2, "0000"), (2, "ffef"), (2, "fff1ffff0059"), (3, "0384"), (3, "fd20fd1f"), (3, "ffff00ff")]]

out = {
    "description": "ApprovalResult v2 (ADR-0022 §3, ADR-0023 §2 JOSE profile): business-side verification with number matching, jti, deny_reason; match tags, SDK key derivation, code sampler.",
    "now": NOW,
    "device_key": {"private_scalar_hex": SCALAR.hex(), "public_x963_b64url": b64u(x963), "kid": KID},
    "context": {"aud": AUD, "sub": SUB, "request_id": REQUEST_ID, "challenge": CHALLENGE, "capability": "auth.challenge",
                "authentication": {"action_display": AUTH["action_display"], "match_digits": 2}, "txn_digest": TXN_DIGEST, "code": CODE,
                "request_expires_at": NOW + 120, "minimum_amr": "biometric"},
    "cases": cases,
    "match_tags": {"sdk_secret_hex": SDK_SECRET.hex(), "k_match_hex": K_MATCH.hex(), "subject_ref": SUB, "tags": tags},
    "session_handles": {"k_sh_hex": K_SH.hex(), "handles": handles},
    "code_draws": draws,
}
json.dump(out, sys.stdout, indent=2)
sys.stdout.write("\n")
