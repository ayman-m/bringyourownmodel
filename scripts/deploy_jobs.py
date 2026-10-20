#!/usr/bin/env python3
"""Create/update Guardian scheduled Jobs on XSOAR 6 via the REST API.

Why this exists (skill gotcha #23): on XSOAR 6.14.0 neither a content-pack zip
install nor `demisto-sdk upload` actually creates a Job on the server — the Job
JSON ships in the pack for `validate`/git, but the live object is only created
by a raw `POST /jobs`, which additionally requires a `startDate` the pack JSON
omits. `demisto-sdk upload -z` (scripts/deploy.sh) therefore delivers every
OTHER content type; this script closes the Jobs gap.

`POST /jobs` is upsert-by-object, not by-name, so posting a Job without the
existing id/version creates a DUPLICATE. We search by name first and merge the
server's id/version onto our payload (the JobCreator pattern) so re-running is
idempotent.

Reads DEMISTO_BASE_URL / DEMISTO_API_KEY / DEMISTO_VERIFY_SSL from the
environment (deploy.sh sources .env before calling this).
"""

from __future__ import annotations

import glob
import json
import os
import ssl
import sys
import urllib.request

# GUARDIAN_PACK selects the pack whose Jobs are deployed ("Guardian" for XSOAR 6, "GuardianXSIAM" for Cortex platform).
PACK = os.environ.get("GUARDIAN_PACK", "Guardian")
# GUARDIAN_JOBS_DIR points at a folder of job-*.json files instead (the release install tools ship one per pack).
JOBS_DIR = os.environ.get("GUARDIAN_JOBS_DIR")
JOBS_GLOB = os.path.join(JOBS_DIR, "job-*.json") if JOBS_DIR else f"Packs/{PACK}/Jobs/job-*.json"
# GUARDIAN_SKIP_JOBS is a comma-separated list of job names to leave out (for example GuardianIntakeSweep on an
# Cortex platform tenant whose real issue queue should not be triaged by a model).
SKIP_JOBS = {n.strip() for n in os.environ.get("GUARDIAN_SKIP_JOBS", "").split(",") if n.strip()}
# A fixed, deterministic startDate — the recurrence is driven by humanCron, not
# this value; it only needs to be a valid past timestamp so the scheduler arms.
DEFAULT_START_DATE = "2024-01-01T00:00:00Z"


def _client():
    base = os.environ.get("DEMISTO_BASE_URL")
    key = os.environ.get("DEMISTO_API_KEY")
    if not base or not key:
        sys.exit("deploy_jobs: DEMISTO_BASE_URL and DEMISTO_API_KEY must be set")
    # Secure-by-default: TLS verification is ON unless DEMISTO_VERIFY_SSL is
    # explicitly set to a false-y value. The lab tenant dev box (self-signed cert
    # reached over an authenticated GCP lab access tunnel) sets DEMISTO_VERIFY_SSL=false
    # in .env to opt out; a properly-provisioned server needs no override.
    verify = os.environ.get("DEMISTO_VERIFY_SSL", "true").lower() in ("true", "1", "yes")
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    headers = {"Authorization": key, "Content-Type": "application/json", "Accept": "application/json"}
    base = base.rstrip("/")
    xsiam_id = os.environ.get("XSIAM_AUTH_ID")
    if xsiam_id:
        # Cortex platform: the standard key needs its numeric id, and the content API lives under /xsoar
        headers["x-xdr-auth-id"] = xsiam_id
        base += "/xsoar"
    return base, headers, ctx


def _post(base, headers, ctx, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
        raw = resp.read().decode()
    return json.loads(raw) if raw.strip() else {}


def _find_existing(base, headers, ctx, name):
    """Return the existing job object (with id/version) or None."""
    try:
        res = _post(base, headers, ctx, "/jobs/search", {"query": f'name:"{name}"', "page": 0, "size": 1})
    except Exception as exc:  # search failure shouldn't block a create attempt
        print(f"  (jobs/search failed for {name!r}: {exc}; will attempt create)")
        return None
    data = res.get("data") or res.get("jobs") or []
    return data[0] if data else None


def main() -> int:
    files = sorted(glob.glob(JOBS_GLOB))
    if not files:
        print("deploy_jobs: no Jobs/job-*.json to deploy")
        return 0
    base, headers, ctx = _client()
    failures = 0
    for path in files:
        job = json.load(open(path))
        name = job.get("name") or job.get("id")
        if name in SKIP_JOBS:
            print(f"  - {name}: skipped (GUARDIAN_SKIP_JOBS)")
            continue
        job.setdefault("startDate", DEFAULT_START_DATE)
        existing = _find_existing(base, headers, ctx, name)
        if existing:
            # Merge server id/version so this is an UPDATE, not a duplicate create.
            job["id"] = existing.get("id", job.get("id"))
            job["version"] = existing.get("version", -1)
        else:
            job.setdefault("version", -1)
        try:
            saved = _post(base, headers, ctx, "/jobs", job)
        except Exception as exc:
            print(f"  ✗ {name}: POST /jobs failed: {exc}")
            failures += 1
            continue
        # POST /jobs returns HTTP 200 even on a bad spec; the failure is an
        # envelope with id == 'editJobErr' (skill gotcha).
        if isinstance(saved, dict) and saved.get("id") == "editJobErr":
            print(f"  ✗ {name}: server rejected the job spec ({saved.get('error') or saved})")
            failures += 1
            continue
        verb = "updated" if existing else "created"
        print(f"  ✓ {name}: {verb} (id={saved.get('id') if isinstance(saved, dict) else '?'})")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
