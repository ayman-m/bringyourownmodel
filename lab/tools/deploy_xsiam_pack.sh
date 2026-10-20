#!/usr/bin/env bash
# Install Packs/GuardianXSIAM on the XSIAM lab tenant with `demisto-sdk upload -x -z`, from a throwaway scratch repo.
# Why a scratch repo: the SDK reads the repo-root .env, which holds the XSOAR lab's URL and key and would win over the
# XSIAM variables. The scratch copy has no .env, so the only credentials in play are the ones exported here.
# Needs XSIAM_ENV (a file with SDK_URL, SDK_KEY, SDK_ID; default: the lab's Internal .env). Never prints the key.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENV_FILE="${XSIAM_ENV:-$HOME/Documents/Projects/Internal/.env}"
SCRATCH="${XSIAM_SCRATCH:-${TMPDIR:-/tmp}/guardian-xsiam-sdk}"
rm -rf "$SCRATCH" && mkdir -p "$SCRATCH/Packs" "$SCRATCH/Tests"
rsync -a --exclude __pycache__ --exclude .pytest_cache "$ROOT/Packs/GuardianXSIAM" "$ROOT/Packs/Base" "$SCRATCH/Packs/"
cp "$ROOT/.private-repo-settings" "$SCRATCH/" && cp "$ROOT/Tests/secrets_white_list.json" "$SCRATCH/Tests/"
( cd "$SCRATCH" && git init -q && git remote add origin https://example.invalid/scratch.git && git add -A && git -c user.email=lab@example.invalid -c user.name=lab commit -q -m scratch )
set -a; eval "$(grep -E '^(SDK_URL|SDK_KEY|SDK_ID)=' "$ENV_FILE")"; set +a
export DEMISTO_BASE_URL="$SDK_URL" DEMISTO_API_KEY="$SDK_KEY" XSIAM_AUTH_ID="$SDK_ID"
unset SDK_URL SDK_KEY SDK_ID
cd "$SCRATCH"
"$ROOT/.venv/bin/demisto-sdk" upload -i Packs/GuardianXSIAM -x -z --skip_validation --override-existing "$@"
# A pack install leaves the playbooks "not adopted" (cannot be attached or run by a Job); adopt them again.
if [ -z "${SKIP_ADOPT:-}" ]; then
  ( cd "$ROOT/lab/tools" && XSIAM_ENV="$ENV_FILE" python3 xsiam_adopt_playbooks.py )
fi
