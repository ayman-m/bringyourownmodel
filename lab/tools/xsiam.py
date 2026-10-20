"""Paced Cortex XSIAM content-API helper for lab scripts (standard key, /xsoar/*). Same rules as tenant.py: one call at a time,
1.5s gap after every call, never prints keys. Reads the lab tenant's SDK_URL / SDK_KEY / SDK_ID from XSIAM_ENV
(default ~/Documents/Projects/Internal/.env)."""
import os, ssl, sys, time, urllib3, requests
from pathlib import Path
urllib3.disable_warnings()
ENV_FILE = Path(os.environ.get('XSIAM_ENV', str(Path.home() / 'Documents/Projects/Internal/.env')))
ENV = {}
for line in ENV_FILE.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1); ENV[k.strip()] = v.strip().strip('"').strip("'")
BASE = ENV['SDK_URL'].rstrip('/')
if not BASE.startswith('http'): BASE = 'https://' + BASE
S = requests.Session()
S.headers.update({'Authorization': ENV['SDK_KEY'], 'x-xdr-auth-id': ENV['SDK_ID'], 'Accept': 'application/json'})
CA = Path.home() / '.cache' / 'xsiam_ca_bundle.pem'
S.verify = str(CA) if CA.exists() and CA.stat().st_size else True
CALLS = 0
def call(method, path, **kw):
    """path is relative to <tenant>/xsoar, e.g. '/contentpacks/metadata/installed'."""
    global CALLS
    CALLS += 1
    r = S.request(method, BASE + '/xsoar' + path, timeout=kw.pop('timeout', 120), allow_redirects=False, **kw)
    time.sleep(1.5)
    return r
