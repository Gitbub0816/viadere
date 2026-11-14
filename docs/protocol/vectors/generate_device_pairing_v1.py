#!/usr/bin/env python3
"""Generates docs/protocol/vectors/device-pairing-v1.json (SECURITY.md 2.105, implementation plan v3 WP-D1).

Independent of the Swift code: the key proofs over the pairing id (VIADERE-ENROLL-V1), the key-list digest, the comparison digest
(VIADERE-PAIR-CODE-V1) and its 6-digit code, the pairing code normalization, and the trusted device's approval statement (VIADERE-PAIR-V1)
signed with ES256 (raw r||s, low S, base64url). Needs only the standard library and `cryptography`; run it from a virtual environment outside
the repository:

    python3 -I generate_device_pairing_v1.py > device-pairing-v1.json

ECDSA signatures are randomized: re-running changes the signature strings, never the expected outcomes.
"""
import base64, datetime, hashlib, json, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import serialization

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def key(scalar: int):
    return ec.derive_private_key(scalar, ec.SECP256R1())


def x963(priv) -> str:
    return b64u(priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))


def sign(priv, message: bytes, high_s: bool = False) -> str:
    r, s = decode_dss_signature(priv.sign(message, ec.ECDSA(hashes.SHA256())))
    if s > N // 2:
        s = N - s
    if high_s:
        s = N - s
    return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def iso_ms(seconds: int, millis: int = 0) -> str:
    t = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S") + ".%03dZ" % millis


def key_list_digest(keys) -> str:
    lines = sorted(f"{purpose}:{public}" for purpose, public in keys)
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def comparison_digest(pairing_id: str, nonce: str, kld: str) -> str:
    return hashlib.sha256("\n".join(["VIADERE-PAIR-CODE-V1", pairing_id, nonce, kld]).encode()).hexdigest()


def decimal6(digest_hex: str) -> str:
    return "%06d" % (int.from_bytes(bytes.fromhex(digest_hex)[:8], "big") % 1_000_000)


def normalize_code(raw: str):
    if len(raw) > 64:
        return None
    cleaned = "".join(c for c in raw.upper() if not c.isspace() and c != "-")
    if len(cleaned) != 12:
        return None
    mapped = "".join({"I": "1", "L": "1", "O": "0"}.get(c, c) for c in cleaned)
    return mapped if all(c in ALPHABET for c in mapped) else None


def statement(f) -> bytes:
    return "\n".join(["VIADERE-PAIR-V1", f["accountId"], f["pairingId"], f["nonce"], f["newDeviceKeys"], f["approverDeviceId"],
                      f["approverPublicKey"], f["comparisonDigest"], f["match"], f["expiresAt"], f["signedAt"], f["assurance"]]).encode()


PAIRING_ID = "0b9a4c3e-2d1f-4e5a-8b7c-6d5e4f3a2b1c"
ACCOUNT_ID = "6f1c2a4e-9b3d-4c5e-8f70-112233445566"
OTHER_ACCOUNT_ID = "7a2d3b5f-0c4e-4d6f-9081-223344556677"
APPROVER_DEVICE_ID = "1c2d3e4f-5a6b-4c7d-8e9f-a0b1c2d3e4f5"
CHALLENGE = b64u(bytes(range(32, 64)))
NONCE = b64u(bytes(range(64, 96)))
OTHER_NONCE = b64u(bytes(range(96, 128)))
NOW = 1_793_000_000
EXPIRES = iso_ms(NOW + 240)
SIGNED = iso_ms(NOW, 125)

new_keys = {"request": key(0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f800),
            "approvalUserPresence": key(0x2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80911),
            "approvalBiometric": key(0x3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a22)}
attacker_keys = {"request": key(0x4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b33),
                 "approvalBiometric": key(0x5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c44)}
approver = key(0x6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d55)
other = key(0x708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e66)

proofs = []
for purpose, priv in new_keys.items():
    public = x963(priv)
    message = f"VIADERE-ENROLL-V1\n{PAIRING_ID}\n{CHALLENGE}\n{purpose}\n{public}"
    proofs.append({"purpose": purpose, "publicKey": public, "proofMessage": message, "proof": sign(priv, message.encode())})

kld = key_list_digest((p["purpose"], p["publicKey"]) for p in proofs)
cmp_input = "\n".join(["VIADERE-PAIR-CODE-V1", PAIRING_ID, NONCE, kld])
cmp = comparison_digest(PAIRING_ID, NONCE, kld)
CODE = decimal6(cmp)

attacker_kld = key_list_digest((purpose, x963(priv)) for purpose, priv in attacker_keys.items())
attacker_cmp = comparison_digest(PAIRING_ID, NONCE, attacker_kld)

base = {"accountId": ACCOUNT_ID, "pairingId": PAIRING_ID, "nonce": NONCE, "newDeviceKeys": kld, "approverDeviceId": APPROVER_DEVICE_ID,
        "approverPublicKey": x963(approver), "comparisonDigest": cmp, "match": CODE, "expiresAt": EXPIRES, "signedAt": SIGNED,
        "assurance": "biometric"}


def case(name, expect, signer=approver, high_s=False, **over):
    fields = dict(base)
    fields.update(over)
    out = dict(fields)
    out["signature"] = sign(signer, statement(fields), high_s=high_s)
    return {"name": name, "expect": expect, "approval": out, "signingInput": statement(fields).decode()}


cases = [
    # Valid statements: the signature verifies with the approver's registered key and every field has its canonical shape.
    case("valid", "valid"),
    case("valid_high_s_encoding", "valid", high_s=True),
    # Refused by the statement check itself.
    case("signed_by_another_key", "bad_signature", signer=other),
    case("passcode_assurance", "assurance_too_low", assurance="devicePasscode"),
    case("match_not_six_digits", "malformed", match="12345"),
    case("digest_not_lowercase_hex", "malformed", comparisonDigest=cmp.upper()),
    case("nonce_not_256_bits", "malformed", nonce=b64u(bytes(16))),
    # Valid signatures over the wrong binding: the server refuses them against the stored pairing (`pairing_mismatch`).
    case("other_account", "binding_mismatch", accountId=OTHER_ACCOUNT_ID),
    case("other_nonce", "binding_mismatch", nonce=OTHER_NONCE, comparisonDigest=comparison_digest(PAIRING_ID, OTHER_NONCE, kld)),
    case("substituted_new_device_keys", "binding_mismatch", newDeviceKeys=attacker_kld, comparisonDigest=attacker_cmp),
    # A valid, well-bound statement whose typed number is not the code: `comparison_mismatch`.
    case("wrong_number", "comparison_mismatch", match="%06d" % ((int(CODE) + 1) % 1_000_000)),
]

decimal6_cases = [{"digest": d, "code": decimal6(d)} for d in [
    "00000000000f4240" + "00" * 24,          # exactly 1 000 000 -> 000000
    "00000000000000ff" + "11" * 24,          # 255 -> 000255
    "ffffffffffffffff" + "22" * 24,          # 2^64 - 1
    cmp,
]]

normalization = [
    {"input": "ABCD-EFGH-JKMN", "normalized": "ABCDEFGHJKMN"},
    {"input": " abcd efgh jkmn ", "normalized": "ABCDEFGHJKMN"},
    {"input": "o0Il-1LOo-ZZZZ", "normalized": "00111100ZZZZ"},
    {"input": "ABCD-EFGH-JKMU", "normalized": None},
    {"input": "ABCD-EFGH-JKM", "normalized": None},
]
for item in normalization:
    assert normalize_code(item["input"]) == item["normalized"], item

doc = {
    "description": "Device pairing (SECURITY.md 2.105): key proofs of the new device over the pairing id (VIADERE-ENROLL-V1), the key-list "
                   "digest, the comparison digest VIADERE-PAIR-CODE-V1 and its 6-digit code (decimal6 of the first 8 bytes), the pairing "
                   "code normalization, and the trusted device's VIADERE-PAIR-V1 approval statement. Signatures are ECDSA P-256 / SHA-256, "
                   "raw r||s, base64url; verify them, do not compare them (ECDSA is randomized). Generated by generate_device_pairing_v1.py.",
    "version": 1,
    "now": NOW,
    "pairingId": PAIRING_ID,
    "challenge": CHALLENGE,
    "nonce": NONCE,
    "newDeviceKeys": proofs,
    "keyListDigest": kld,
    "comparisonInput": cmp_input,
    "comparisonDigest": cmp,
    "code": CODE,
    "substitution": {
        "description": "A relay that registers its own keys under the same pairing id and nonce gets another digest and, here, another code.",
        "keys": [{"purpose": p, "publicKey": x963(k)} for p, k in attacker_keys.items()],
        "keyListDigest": attacker_kld,
        "comparisonDigest": attacker_cmp,
        "code": decimal6(attacker_cmp),
    },
    "approver": {"deviceId": APPROVER_DEVICE_ID, "accountId": ACCOUNT_ID, "approvalBiometricPublicKey": x963(approver)},
    "approvals": cases,
    "decimal6": decimal6_cases,
    "pairingCodeNormalization": normalization,
}
assert decimal6(attacker_cmp) != CODE, "regenerate with other attacker scalars: the substituted code collides"
json.dump(doc, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
