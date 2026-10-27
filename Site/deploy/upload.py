#!/usr/bin/env python3
"""Deploy Site/dist to Cloudflare Workers Static Assets with the REST direct-upload API (Python stdlib only).

Flow (Cloudflare "Workers Static Assets: direct upload"):
  1. POST /accounts/{account_id}/workers/scripts/{name}/assets-upload-session
       JSON {"manifest": {"/path": {"hash": "<32 hex>", "size": <bytes>}}}
       -> result {"jwt": <upload token>, "buckets": [[hash, ...], ...]}   (buckets omit files Cloudflare already has;
          if buckets is empty the returned jwt is already the completion token)
  2. POST /accounts/{account_id}/workers/assets/upload?base64=true   (one request per bucket)
       multipart/form-data, Authorization: Bearer <upload jwt>; one part per file, field name = the file's hash,
       body = the file's base64 text, part Content-Type = the type to serve the file with.
       The response to the last bucket is 201 with result.jwt = completion token (valid one hour).
  3. PUT /accounts/{account_id}/workers/scripts/{name}
       multipart/form-data with a "metadata" JSON part: {"assets": {"jwt": <completion jwt>, "config": {...}},
       "compatibility_date": "..."}: an assets-only Worker, no script part.

Sources:
  https://developers.cloudflare.com/workers/static-assets/direct-upload/
  https://developers.cloudflare.com/api/resources/workers/subresources/scripts/methods/update/
  Hash: first 32 hex chars of SHA-256 over (base64 of file content + file extension without the dot), as in the
  documented sample code (`createManifest`).

UNVERIFIED against a live account (no credentials were available when this was written): the multipart part names in
step 3 ("metadata"), the omission of a script part for an assets-only Worker, and routing of `_headers` through
`assets.config._headers` (the API reference lists `_headers` and `_redirects` under assets.config; Wrangler does the
same instead of uploading them as assets). Run with --dry-run first; use a throwaway Worker name for the first real run.

Environment (never printed):
  CLOUDFLARE_API_TOKEN   token with "Workers Scripts: Edit"
  CLOUDFLARE_ACCOUNT_ID  account id
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import mimetypes
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

API = "https://api.cloudflare.com/client/v4"
MAX_FILE_BYTES = 25 * 1024 * 1024        # per-file limit for Workers static assets
MAX_BUCKET_BYTES = 40 * 1024 * 1024      # keep each upload request comfortably small
CONFIG_FILES = {"_headers", "_redirects"}  # sent in assets.config, not as assets
IGNORED = {".DS_Store"}

mimetypes.add_type("image/svg+xml", ".svg")
mimetypes.add_type("font/woff2", ".woff2")
mimetypes.add_type("application/xml", ".xml")
mimetypes.add_type("text/plain", ".txt")


class DeployError(Exception):
    pass


def file_hash(data: bytes, extension: str) -> str:
    """32 hex chars: sha256(base64(content) + extension-without-dot)."""
    return hashlib.sha256(base64.b64encode(data) + extension.encode()).hexdigest()[:32]


def collect(directory: Path) -> tuple[dict[str, dict], dict[str, Path], dict[str, str]]:
    """Returns (manifest, hash -> path, config file contents)."""
    manifest: dict[str, dict] = {}
    by_hash: dict[str, Path] = {}
    config: dict[str, str] = {}
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        rel = path.relative_to(directory).as_posix()
        if path.name in IGNORED:
            continue
        if rel in CONFIG_FILES:
            config[rel] = path.read_text(encoding="utf-8")
            continue
        data = path.read_bytes()
        if len(data) > MAX_FILE_BYTES:
            raise DeployError(f"{rel} is {len(data)} bytes; the per-file limit is {MAX_FILE_BYTES}")
        h = file_hash(data, path.suffix.lstrip("."))
        manifest["/" + rel] = {"hash": h, "size": len(data)}
        by_hash[h] = path
    return manifest, by_hash, config


def redact(text: str, secrets: list[str]) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, "[redacted]")
    return text


class Client:
    def __init__(self, token: str, account_id: str):
        self.token, self.account = token, account_id
        self.secrets = [token]

    def request(self, method: str, url: str, body: bytes | None, headers: dict[str, str], bearer: str | None = None,
                retries: int = 4) -> dict:
        h = {"Authorization": f"Bearer {bearer or self.token}", "User-Agent": "viadere-site-deploy/1", **headers}
        for attempt in range(retries + 1):
            req = urllib.request.Request(url, data=body, method=method, headers=h)
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    payload = json.loads(resp.read() or b"{}")
                    payload["_status"] = resp.status
                    return payload
            except urllib.error.HTTPError as e:
                text = e.read().decode("utf-8", "replace")
                if e.code in (429, 500, 502, 503, 504) and attempt < retries:
                    wait = int(e.headers.get("Retry-After", 0) or 0) or 2 ** attempt
                    print(f"  HTTP {e.code}, retrying in {wait}s", file=sys.stderr)
                    time.sleep(wait)
                    continue
                raise DeployError(f"{method} {redact(url, self.secrets)} failed with HTTP {e.code}: {redact(text, self.secrets)[:800]}")
            except urllib.error.URLError as e:
                if attempt < retries:
                    time.sleep(2 ** attempt)
                    continue
                raise DeployError(f"{method} {redact(url, self.secrets)} failed: {e.reason}")
        raise DeployError("unreachable")

    def start_session(self, name: str, manifest: dict) -> dict:
        url = f"{API}/accounts/{self.account}/workers/scripts/{name}/assets-upload-session"
        res = self.request("POST", url, json.dumps({"manifest": manifest}).encode(), {"Content-Type": "application/json"})
        return res["result"]

    def upload_bucket(self, upload_jwt: str, files: list[tuple[str, Path]]) -> dict:
        boundary = "----viadere" + uuid.uuid4().hex
        parts: list[bytes] = []
        for h, path in files:
            ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            parts.append(
                (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{h}\"; filename=\"{h}\"\r\n"
                 f"Content-Type: {ctype}\r\n\r\n").encode()
                + base64.b64encode(path.read_bytes()) + b"\r\n")
        body = b"".join(parts) + f"--{boundary}--\r\n".encode()
        self.secrets.append(upload_jwt)
        return self.request("POST", f"{API}/accounts/{self.account}/workers/assets/upload?base64=true", body,
                            {"Content-Type": f"multipart/form-data; boundary={boundary}"}, bearer=upload_jwt)

    def publish(self, name: str, completion_jwt: str, config: dict, compat_date: str) -> dict:
        assets_config = {"html_handling": "auto-trailing-slash", "not_found_handling": "404-page"}
        assets_config.update(config)
        metadata = {"assets": {"jwt": completion_jwt, "config": assets_config}, "compatibility_date": compat_date}
        boundary = "----viadere" + uuid.uuid4().hex
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n"
                f"{json.dumps(metadata)}\r\n--{boundary}--\r\n").encode()
        self.secrets.append(completion_jwt)
        return self.request("PUT", f"{API}/accounts/{self.account}/workers/scripts/{name}", body,
                            {"Content-Type": f"multipart/form-data; boundary={boundary}"})


def buckets_of(names: list[list[str]], by_hash: dict[str, Path]) -> list[list[tuple[str, Path]]]:
    """Respect the server's grouping, splitting any bucket that would exceed MAX_BUCKET_BYTES."""
    out: list[list[tuple[str, Path]]] = []
    for group in names:
        cur: list[tuple[str, Path]] = []
        size = 0
        for h in group:
            p = by_hash[h]
            n = p.stat().st_size * 4 // 3 + 4
            if cur and size + n > MAX_BUCKET_BYTES:
                out.append(cur)
                cur, size = [], 0
            cur.append((h, p))
            size += n
        if cur:
            out.append(cur)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dir", default=str(Path(__file__).resolve().parent.parent / "dist"), help="directory to upload (default Site/dist)")
    ap.add_argument("--name", default=os.environ.get("CLOUDFLARE_WORKER_NAME", "viadere-site"), help="Worker name (default viadere-site)")
    ap.add_argument("--dry-run", action="store_true", help="hash and list files, make no network requests")
    ap.add_argument("--compatibility-date", default=datetime.date.today().isoformat())
    args = ap.parse_args(argv)

    directory = Path(args.dir)
    if not directory.is_dir():
        print(f"error: {directory} does not exist; run `swift run viadere-site` first", file=sys.stderr)
        return 2
    manifest, by_hash, config = collect(directory)
    if not manifest:
        print("error: nothing to upload", file=sys.stderr)
        return 2
    total = sum(m["size"] for m in manifest.values())
    print(f"{len(manifest)} files, {total} bytes; config files: {', '.join(sorted(config)) or 'none'}; worker: {args.name}")

    if args.dry_run:
        for path, meta in manifest.items():
            print(f"  {meta['hash']}  {meta['size']:>9}  {path}")
        print("dry run: no requests were made")
        return 0

    token, account = os.environ.get("CLOUDFLARE_API_TOKEN"), os.environ.get("CLOUDFLARE_ACCOUNT_ID")
    if not token or not account:
        print("error: set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID", file=sys.stderr)
        return 2
    client = Client(token, account)
    try:
        session = client.start_session(args.name, manifest)
        completion = session["jwt"] if not session.get("buckets") else None
        needed = session.get("buckets", [])
        print(f"{sum(len(b) for b in needed)} of {len(by_hash)} files need uploading in {len(needed)} bucket(s)")
        if needed:
            groups = buckets_of(needed, by_hash)
            for i, group in enumerate(groups, 1):
                res = client.upload_bucket(session["jwt"], group)
                print(f"  uploaded bucket {i}/{len(groups)} ({len(group)} files)")
                if res.get("result", {}).get("jwt"):
                    completion = res["result"]["jwt"]
        if not completion:
            raise DeployError("the upload finished without a completion token")
        client.publish(args.name, completion, config, args.compatibility_date)
        print(f"deployed {args.name}")
        return 0
    except DeployError as e:
        print(f"error: {redact(str(e), client.secrets)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
