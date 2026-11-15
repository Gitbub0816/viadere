#!/usr/bin/env python3
"""Print the SPKI SHA-256 pin (base64) of every certificate a TLS server presents, for App/Configs/Staging.xcconfig.

    python3 -I App/Scripts/compute-spki-pins.py api-staging.viadere.com
    python3 -I App/Scripts/compute-spki-pins.py --pem chain.pem          # a PEM bundle instead of a live connection

Standard library only; shells out to `openssl` (LibreSSL on macOS works). Nothing is sent anywhere except the TLS handshake to the host.

Which pin to use: the app accepts a connection when ANY certificate in the validated chain matches ANY pin
(ViadereKit PinEvaluator). Cloudflare renews its edge leaf certificates often and may change CA, so pin the issuing CA
(intermediate) key rather than the leaf, and keep a second pin for a different key: the other CA Cloudflare uses, or a
key you control. Pins are public values, not secrets.
"""
import argparse
import base64
import hashlib
import re
import subprocess
import sys

PEM = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


def openssl(args, data=None):
    result = subprocess.run(["openssl", *args], input=data, capture_output=True, timeout=30)
    if result.returncode != 0:
        raise SystemExit("openssl %s failed: %s" % (" ".join(args[:2]), result.stderr.decode(errors="replace").strip()))
    return result.stdout


def fetch_chain(host, port):
    out = subprocess.run(["openssl", "s_client", "-connect", "%s:%d" % (host, port), "-servername", host, "-showcerts"],
                         input=b"", capture_output=True, timeout=30)
    chain = PEM.findall(out.stdout.decode(errors="replace"))
    if not chain:
        raise SystemExit("no certificates received from %s:%d: %s" % (host, port, out.stderr.decode(errors="replace").strip()[-300:]))
    return chain


def describe(pem):
    pem_bytes = pem.encode()
    pubkey = openssl(["x509", "-pubkey", "-noout"], pem_bytes)
    der = openssl(["pkey", "-pubin", "-outform", "der"], pubkey)
    pin = base64.b64encode(hashlib.sha256(der).digest()).decode()
    text = openssl(["x509", "-noout", "-subject", "-issuer", "-enddate"], pem_bytes).decode().strip().splitlines()
    return pin, text


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host", nargs="?", help="server name, e.g. api-staging.viadere.com")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--pem", help="read the certificates from this PEM file instead of connecting")
    args = parser.parse_args()
    if bool(args.host) == bool(args.pem):
        parser.error("give a host or --pem FILE")
    if args.pem:
        with open(args.pem, encoding="utf-8") as handle:
            chain = PEM.findall(handle.read())
        if not chain:
            raise SystemExit("no certificates in %s" % args.pem)
    else:
        chain = fetch_chain(args.host, args.port)
    for index, pem in enumerate(chain):
        pin, text = describe(pem)
        role = "leaf" if index == 0 else "CA (intermediate/root as presented)"
        print("[%d] %s" % (index, role))
        for line in text:
            print("    " + line)
        print("    pin: " + pin)
    print("\nPut one CA pin and a backup pin (a different key) in App/Configs/Staging.xcconfig:")
    print("  VIADERE_PIN_PRIMARY = <pin>\n  VIADERE_PIN_BACKUP  = <pin>")


if __name__ == "__main__":
    main()
