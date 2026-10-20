"""After a pack install on XSIAM the pack's playbooks are not 'adopted' and cannot be attached to an issue or run by a
Job ("playbook is not adopted"). Detaching it and saving the playbook file again over REST (POST /playbook/save/yaml) adopts it, provided the
YAML carries `adopted: true`. Paced, one call per playbook. Usage: xsiam_adopt_playbooks.py [PlaybookId ...] (default: all)"""
import sys
from pathlib import Path
from xsiam import call
d = Path(__file__).resolve().parents[2] / 'Packs' / 'GuardianXSIAM' / 'Playbooks'
want = set(sys.argv[1:])
for f in sorted(d.glob('playbook-*.yml')):
    pid = f.stem.replace('playbook-', '')
    if want and pid not in want: continue
    call('POST', '/playbook/detach/' + pid)  # a pack-owned (system) playbook refuses a save until detached
    r = call('POST', '/playbook/save/yaml', files={'file': (f.name, f.read_bytes(), 'application/x-yaml')})
    a = call('GET', '/playbook/' + pid).json()
    print(pid, 'save', r.status_code, '| adopted', a.get('adopted'))
