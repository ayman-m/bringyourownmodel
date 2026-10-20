#!/usr/bin/env python3
"""Adopt the Guardian playbooks on a Cortex platform tenant after a pack install (standard library only).

Why: a pack install on Cortex platform leaves the pack's playbooks "not adopted", and a playbook that is not adopted cannot be
attached to an issue or run by a Job ("playbook is not adopted"). Detaching a playbook and saving its YAML again
adopts it, provided the YAML carries `adopted: true` (Guardian's does). This does that for every playbook, one call at
a time with a pause between calls. Not needed on Cortex XSOAR 6.

Environment (the same as create_jobs.py): DEMISTO_BASE_URL, DEMISTO_API_KEY, XSIAM_AUTH_ID, and DEMISTO_VERIFY_SSL=false only
for a self-signed certificate. Use a Standard API key and its numeric id.

Usage: python3 adopt_playbooks.py [--playbooks-dir DIR] [PlaybookId ...]
The default folder is `playbooks/` next to this script (the release tools) or Packs/GuardianXSIAM/Playbooks in a checkout.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

PAUSE_SECONDS = 1.5


def _context():
    base = os.environ.get("DEMISTO_BASE_URL")
    key = os.environ.get("DEMISTO_API_KEY")
    auth_id = os.environ.get("XSIAM_AUTH_ID")
    if not (base and key and auth_id):
        sys.exit("adopt_playbooks: set DEMISTO_BASE_URL, DEMISTO_API_KEY and XSIAM_AUTH_ID")
    verify = os.environ.get("DEMISTO_VERIFY_SSL", "true").lower() in ("true", "1", "yes")
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if not base.startswith("http"):
        base = "https://" + base
    headers = {"Authorization": key, "x-xdr-auth-id": auth_id, "Accept": "application/json"}
    return base.rstrip("/") + "/xsoar", headers, ctx


def _request(base, headers, ctx, method, path, body=None, content_type=None):
    hdrs = dict(headers)
    if content_type:
        hdrs["Content-Type"] = content_type
    req = urllib.request.Request(base + path, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
            status, raw = resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode(errors="replace")
    time.sleep(PAUSE_SECONDS)
    return status, raw


def _multipart(filename: str, content: bytes):
    boundary = uuid.uuid4().hex
    head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
            "Content-Type: application/x-yaml\r\n\r\n").encode()
    return head + content + f"\r\n--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"


def _default_dir() -> Path:
    here = Path(__file__).resolve().parent
    for candidate in (here / "playbooks", here.parent / "Packs" / "GuardianXSIAM" / "Playbooks"):
        if candidate.is_dir():
            return candidate
    return here / "playbooks"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--playbooks-dir", type=Path, default=_default_dir())
    parser.add_argument("names", nargs="*", help="playbook ids to adopt (default: all in the folder)")
    args = parser.parse_args()
    files = sorted(args.playbooks_dir.glob("playbook-*.yml"))
    if not files:
        sys.exit(f"adopt_playbooks: no playbook-*.yml in {args.playbooks_dir}")
    base, headers, ctx = _context()
    failures = 0
    for path in files:
        pid = path.stem.replace("playbook-", "", 1)
        if args.names and pid not in args.names:
            continue
        _request(base, headers, ctx, "POST", f"/playbook/detach/{pid}")  # a pack-owned playbook refuses a save until detached
        body, ctype = _multipart(path.name, path.read_bytes())
        status, raw = _request(base, headers, ctx, "POST", "/playbook/save/yaml", body, ctype)
        gstatus, graw = _request(base, headers, ctx, "GET", f"/playbook/{pid}")
        adopted = None
        try:
            adopted = json.loads(graw).get("adopted")
        except ValueError:
            pass
        ok = status == 200 and adopted is True
        failures += 0 if ok else 1
        print(f"  {'✓' if ok else '✗'} {pid}: save HTTP {status}, adopted={adopted}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
