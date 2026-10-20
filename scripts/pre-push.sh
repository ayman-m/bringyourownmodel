#!/bin/sh
# Pre-push check: secrets and forbidden terms. Install: ln -sf ../../scripts/pre-push.sh .git/hooks/pre-push
cd "$(git rev-parse --show-toplevel)" || exit 1
status=0
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source . --no-banner --redact --log-level error || { echo "pre-push: gitleaks reported possible secrets"; status=1; }
else
  echo "pre-push: gitleaks is not installed"; status=1
fi
terms=.local/forbidden-terms.txt
if [ -f "$terms" ]; then
  python3 - "$terms" <<'PY' || status=1
import re, subprocess, sys
rx = [re.compile(l.strip(), re.I) for l in open(sys.argv[1]) if l.strip() and not l.startswith('#')]
found = 0
for f in subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0'):
    if not f or f.startswith('.local/'):
        continue
    try:
        raw = open(f, 'rb').read()
    except OSError:
        continue
    if any(r.search(f) for r in rx):
        print('pre-push: forbidden term in file name %s' % f); found += 1
        continue
    if b'\0' in raw[:4096]:
        continue
    for i, line in enumerate(raw.decode('utf8', 'ignore').splitlines(), 1):
        if any(r.search(line) for r in rx):
            print('pre-push: forbidden term in %s:%d' % (f, i)); found += 1
            break
sys.exit(1 if found else 0)
PY
else
  echo "pre-push: $terms is missing; create it before pushing"; status=1
fi
exit $status
