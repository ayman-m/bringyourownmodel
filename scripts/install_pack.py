#!/usr/bin/env python3
"""Install a Guardian pack zip on Cortex XSOAR 6 or Cortex platform from the command line (standard library only).

This sends the pack to the same endpoint the console's pack upload uses. Run it instead of uploading by hand.
Guardian packs are custom (unsigned) packs, so the request carries skipVerify=true and skipValidation=true; without them the
platform refuses the zip ("Pack does not have a valid signature").

Environment: DEMISTO_BASE_URL, DEMISTO_API_KEY (a Standard API key); on Cortex platform also XSIAM_AUTH_ID (the key's numeric id).
DEMISTO_VERIFY_SSL=false only for a self-signed certificate; behind a TLS-inspecting proxy set SSL_CERT_FILE to your CA bundle.

Usage: python3 install_pack.py Guardian-<version>.zip                (XSOAR 6)
       python3 install_pack.py GuardianCortexPlatform-<version>.zip  (Cortex platform)
"""
from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path


def _context():
    base = os.environ.get("DEMISTO_BASE_URL")
    key = os.environ.get("DEMISTO_API_KEY")
    if not (base and key):
        sys.exit("install_pack: set DEMISTO_BASE_URL and DEMISTO_API_KEY (and XSIAM_AUTH_ID on Cortex platform)")
    verify = os.environ.get("DEMISTO_VERIFY_SSL", "true").lower() in ("true", "1", "yes")
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if not base.startswith("http"):
        base = "https://" + base
    headers = {"Authorization": key, "Accept": "application/json"}
    base = base.rstrip("/")
    auth_id = os.environ.get("XSIAM_AUTH_ID")
    if auth_id:
        headers["x-xdr-auth-id"] = auth_id
        base += "/xsoar"
    return base, headers, ctx


def _request(base, headers, ctx, method, path, body=None, content_type=None, timeout=600):
    hdrs = dict(headers)
    if content_type:
        hdrs["Content-Type"] = content_type
    req = urllib.request.Request(base + path, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            status, raw = resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode(errors="replace")
    time.sleep(1.5)
    return status, raw


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    zip_path = Path(sys.argv[1])
    if not zip_path.is_file():
        sys.exit(f"install_pack: {zip_path} not found")
    with zipfile.ZipFile(zip_path) as zf:
        meta = json.loads(zf.read("metadata.json"))
    pack_name, version = meta.get("name"), meta.get("currentVersion")
    base, headers, ctx = _context()
    on_xsiam = "x-xdr-auth-id" in headers
    boundary = uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{zip_path.name}\"\r\n"
            "Content-Type: application/zip\r\n\r\n").encode() + zip_path.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    print(f"Installing {pack_name} {version} ({zip_path.name}) on {'Cortex platform' if on_xsiam else 'Cortex XSOAR 6'} ...")
    status, raw = _request(base, headers, ctx, "POST", "/contentpacks/installed/upload?skipVerify=true&skipValidation=true",
                           body, f"multipart/form-data; boundary={boundary}")
    if status != 200:
        print(f"  ✗ upload failed: HTTP {status} {raw[:300]}")
        return 1
    # the install finishes shortly after the upload call returns
    for _ in range(12):
        time.sleep(5)
        status, raw = _request(base, headers, ctx, "GET", "/contentpacks/metadata/installed")
        try:
            installed = {p.get("name"): p.get("currentVersion") for p in json.loads(raw)}
        except ValueError:
            installed = {}
        if installed.get(pack_name) == version:
            print(f"  ✓ {pack_name} {version} is installed")
            print("  next: create the Jobs (create_jobs.py)" + (" and adopt the playbooks (adopt_playbooks.py)" if on_xsiam else ""))
            return 0
    print(f"  ✗ upload was accepted but {pack_name} {version} is not listed as installed yet; check the console's pack list")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
