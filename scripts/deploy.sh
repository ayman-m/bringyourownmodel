#!/usr/bin/env bash
# Uploads Packs/Guardian to a Cortex XSOAR 6 server as a pack zip.
#
# Reads DEMISTO_BASE_URL / DEMISTO_API_KEY / DEMISTO_VERIFY_SSL from .env (if
# present) or the caller's environment. See .env.example for the expected
# shape. Requires demisto-sdk >= 1.39.0 and a reachable XSOAR 6 server —
# this script does nothing useful in an offline/no-server environment.
#
# Before uploading, re-syncs GuardianCommon.py's shared helper block into
# every consuming Guardian script (see scripts/inject_common.py and the
# comment header in Packs/Guardian/Scripts/GuardianCommon/GuardianCommon.py
# for why: XSOAR 6 scripts can't `import` each other) so the uploaded pack
# always reflects the latest GuardianCommon.py source.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

export DEMISTO_SDK_IGNORE_CONTENT_WARNING=true

# Prefer the repo-local venv's demisto-sdk. demisto-sdk pins pydantic <2, while
# a system Python that also serves other tooling typically has pydantic 2.x —
# importing the system demisto-sdk under pydantic 2 dies with
# "cannot import name 'ModelMetaclass' from 'pydantic.main'". The venv exists to
# isolate that; without this, deploy.sh silently picks the wrong interpreter.
SDK="demisto-sdk"
if [ -x .venv/bin/demisto-sdk ]; then
  SDK=".venv/bin/demisto-sdk"
fi

python3 scripts/inject_common.py

# TLS verification follows DEMISTO_VERIFY_SSL rather than being hardcoded off.
# deploy_jobs.py already defaults it to true; passing --insecure unconditionally
# here made the two halves of one deploy disagree about whether the server's
# certificate matters.
UPLOAD_TLS=""
case "$(printf '%s' "${DEMISTO_VERIFY_SSL:-true}" | tr '[:upper:]' '[:lower:]')" in
  false|0|no) UPLOAD_TLS="--insecure" ;;
esac

# shellcheck disable=SC2086
"$SDK" upload -i Packs/Guardian -z --override-existing $UPLOAD_TLS

# Jobs are NOT created by the pack-zip upload above on XSOAR 6.14.0 (skill
# gotcha #23) — deliver them via the REST API (idempotent upsert-by-name).
python3 scripts/deploy_jobs.py
