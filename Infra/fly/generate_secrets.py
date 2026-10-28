#!/usr/bin/env python3
"""Generate the server-owned secrets for a Viadere Fly app (staging by default). Python standard library only.

    python3 -I Infra/fly/generate_secrets.py                      # print a ready-to-paste `fly secrets set` command
    python3 -I Infra/fly/generate_secrets.py --env-file s.env     # write NAME=value lines to a new chmod-600 file instead
    python3 -I Infra/fly/generate_secrets.py --check              # self-check: generate a set and validate it against the server's rules
    python3 -I Infra/fly/generate_secrets.py --check s.env        # validate an existing env file (e.g. before `fly secrets import`)

What is generated (formats and minimum lengths come from Server/Sources/ViadereServerKit/Config/*.swift and Approve/ApproveSettings.swift):

  CONNECT_LINK_SIGNING_KEY, SERVER_PEPPER, DATA_ENCRYPTION_KEY, AUDIT_CHAIN_KEY, SUBJECT_REF_KEY
      base64url (no padding) of 32 random bytes; the server needs at least 32 bytes and, in staging/production, five different values
  KEY_DIRECTORY_LOG_KEY
      base64url of a 32-byte P-256 private scalar: 1 <= d < n (the curve order); candidates outside that range are rejected and redrawn
  EDGE_TOKEN
      the shared value of the Cloudflare header X-Viadere-Edge-Token: 32..256 printable ASCII characters, no spaces
  METRICS_TOKEN
      same rule; the bearer token of GET /metrics

All values are distinct. Never reuse a staging value in production, and keep production secrets in the escrow described in
docs/ops/RESILIENCE.md. Third-party credentials (database URLs, APNs key, Twilio, email API key) are NOT generated: the printed command lists
them as placeholders. Nothing here touches the network; values go to stdout or to the file you name, nowhere else.
"""
import argparse
import base64
import os
import secrets
import stat
import sys

# Order of the NIST P-256 group: a valid private scalar d satisfies 0 < d < N.
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# name -> kind. `bytes32`: base64url secret, >= 32 bytes. `scalar`: P-256 scalar. `token`: opaque header token.
GENERATED = {
    "CONNECT_LINK_SIGNING_KEY": "bytes32",
    "SERVER_PEPPER": "bytes32",
    "DATA_ENCRYPTION_KEY": "bytes32",
    "AUDIT_CHAIN_KEY": "bytes32",
    "SUBJECT_REF_KEY": "bytes32",
    "KEY_DIRECTORY_LOG_KEY": "scalar",
    "EDGE_TOKEN": "token",
    "METRICS_TOKEN": "token",
}
# The five that the server compares pairwise on their first 32 bytes (ServerConfig.fromEnvironment).
INDEPENDENT_KEYS = ["CONNECT_LINK_SIGNING_KEY", "SERVER_PEPPER", "DATA_ENCRYPTION_KEY", "AUDIT_CHAIN_KEY", "SUBJECT_REF_KEY"]

# Third-party values the product owner supplies (placeholders in the printed command).
THIRD_PARTY = [
    ("DATABASE_URL", "'postgres://viadere_app:<password>@<endpoint>.neon.tech/viadere?sslmode=verify-full'"),
    ("DATABASE_MIGRATION_URL", "'postgres://viadere_migrator:<password>@<endpoint>.neon.tech/viadere?sslmode=verify-full'"),
    ("EMAIL_API_KEY", "'<MailerSend API token (email)>'"),
    ("APNS_KEY_P8", '"$(cat AuthKey_<KEYID>.p8)"'),
    ("MAILERSEND_SMS_API_TOKEN", "'<MailerSend API token (SMS)>'"),
    ("MAILERSEND_SMS_INBOUND_SECRET", "'<inbound route secret>'"),
    ("MAILERSEND_SMS_WEBHOOK_SECRET", "'<SMS webhook signing secret>'"),
]


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    """Server rule (Base64URL.decode, then standard base64): accepts unpadded base64url or standard base64."""
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded) if not ("+" in text or "/" in text) else base64.b64decode(padded, validate=True)
    except ValueError:
        return None


def p256_scalar():
    while True:
        raw = secrets.token_bytes(32)
        if 0 < int.from_bytes(raw, "big") < P256_ORDER:
            return raw


def generate(include_log_key=True):
    values = {}
    for name, kind in GENERATED.items():
        if name == "KEY_DIRECTORY_LOG_KEY" and not include_log_key:
            continue
        while True:
            if kind == "bytes32":
                value = b64url(secrets.token_bytes(32))
            elif kind == "scalar":
                value = b64url(p256_scalar())
            else:
                value = secrets.token_urlsafe(48)  # 64 URL-safe characters
            if value not in values.values():
                break
        values[name] = value
    return values


def validate(values):
    """Returns a list of problems (empty = valid) using the server's rules."""
    problems = []
    for name, kind in GENERATED.items():
        value = values.get(name)
        if value is None:
            if name != "KEY_DIRECTORY_LOG_KEY":
                problems.append("%s is missing" % name)
            continue
        if kind == "bytes32":
            data = b64url_decode(value)
            if data is None or len(data) < 32:
                problems.append("%s must be base64url of at least 32 bytes" % name)
        elif kind == "scalar":
            data = b64url_decode(value)
            if data is None or len(data) != 32 or not (0 < int.from_bytes(data, "big") < P256_ORDER):
                problems.append("%s must be base64url of a 32-byte P-256 scalar (0 < d < n)" % name)
        else:
            if not (32 <= len(value) <= 256 and all(0x20 < ord(c) < 0x7F for c in value)):
                problems.append("%s must be 32..256 printable ASCII characters without spaces" % name)
    decoded = [(n, b64url_decode(values[n])) for n in INDEPENDENT_KEYS if n in values and b64url_decode(values[n])]
    for i, (first, a) in enumerate(decoded):
        for second, b in decoded[i + 1:]:
            if a[:32] == b[:32]:
                problems.append("%s and %s must be different values" % (first, second))
    seen = {}
    for name in GENERATED:
        if name in values:
            if values[name] in seen:
                problems.append("%s repeats the value of %s" % (name, seen[values[name]]))
            seen[values[name]] = name
    return problems


def parse_env_file(path):
    values = {}
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise SystemExit("%s:%d is not NAME=value" % (path, number))
            name, _, value = line.partition("=")
            values[name.strip()] = value.strip().strip("'\"")
    return values


def write_env_file(path, values):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL  # never overwrite an existing secrets file
    try:
        descriptor = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
    except FileExistsError:
        raise SystemExit("%s already exists; refusing to overwrite a secrets file (delete it or choose another path)" % path)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        for name, value in values.items():
            handle.write("%s=%s\n" % (name, value))
    os.chmod(path, 0o600)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate Viadere server secrets.")
    parser.add_argument("--app", default="viadere-server-staging", help="Fly app name (default: %(default)s)")
    parser.add_argument("--env-file", metavar="PATH", help="write NAME=value lines to this new file (mode 600) instead of printing them")
    parser.add_argument("--no-log-key", action="store_true", help="skip KEY_DIRECTORY_LOG_KEY (only needed once APPROVE_V2_ENABLED=true)")
    parser.add_argument("--check", nargs="?", const="", metavar="ENV_FILE",
                        help="validate ENV_FILE, or with no file generate a fresh set and validate it (self-check); prints nothing secret")
    args = parser.parse_args(argv)

    if args.check is not None:
        if args.check:
            values, label = parse_env_file(args.check), args.check
        else:
            values, label = generate(not args.no_log_key), "a freshly generated set"
            # The validator must also reject bad input, otherwise the check proves nothing.
            broken = dict(values, SERVER_PEPPER=values["CONNECT_LINK_SIGNING_KEY"], EDGE_TOKEN="short",
                          AUDIT_CHAIN_KEY=b64url(b"\x01" * 8))
            if "KEY_DIRECTORY_LOG_KEY" in values:
                broken["KEY_DIRECTORY_LOG_KEY"] = b64url(P256_ORDER.to_bytes(32, "big"))
            if len(validate(broken)) < 4:
                print("self-check failed: the validator accepted invalid values", file=sys.stderr)
                return 2
            if validate(dict(values, KEY_DIRECTORY_LOG_KEY=b64url(bytes(32)))) == validate(values):
                print("self-check failed: a zero P-256 scalar was accepted", file=sys.stderr)
                return 2
        problems = validate(values)
        for problem in problems:
            print("INVALID: " + problem, file=sys.stderr)
        print("%s: %s" % (label, "OK" if not problems else "%d problem(s)" % len(problems)))
        return 1 if problems else 0

    values = generate(not args.no_log_key)
    assert not validate(values), "generated values failed validation"
    if args.env_file:
        write_env_file(args.env_file, values)
        print("Wrote %d secrets to %s (mode 600). Load them, then delete the file:" % (len(values), args.env_file))
        print("  fly secrets import --app %s --stage < %s && rm -P %s" % (args.app, args.env_file, args.env_file))
    else:
        print("# 1) Server-owned secrets (generated now; shown once; keep DATA_ENCRYPTION_KEY, SERVER_PEPPER, AUDIT_CHAIN_KEY safe):")
        print("fly secrets set --app %s --stage \\" % args.app)
        print(" \\\n".join("  %s='%s'" % (name, value) for name, value in values.items()))
    print()
    print("# 2) Third-party values (YOU fill these in; see docs/ops/STAGING-SETUP.md):")
    print("fly secrets set --app %s --stage \\" % args.app)
    print(" \\\n".join("  %s=%s" % (name, placeholder) for name, placeholder in THIRD_PARTY))
    print()
    print("# EDGE_TOKEN is also the value of the Cloudflare 'X-Viadere-Edge-Token' request header rule (docs/ops/STAGING-SETUP.md, Cloudflare).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
