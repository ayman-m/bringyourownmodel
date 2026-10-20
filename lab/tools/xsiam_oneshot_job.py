"""Run a playbook ONCE through a Job on the XSIAM lab tenant (a job run is the only supported way to start a playbook with no
pre-existing issue) and delete the Job afterwards. The job body is cloned from an existing working job on the tenant so its
field shapes are valid. Usage: xsiam_oneshot_job.py <PlaybookId> [wait_seconds] [template job name]"""
import sys, time, copy, datetime
from xsiam import call
pb = sys.argv[1]; wait = int(sys.argv[2]) if len(sys.argv) > 2 else 120
template = sys.argv[3] if len(sys.argv) > 3 else 'Koi Ext Script Runner - Refresh'
koi = (call('POST', '/jobs/search', json={'page': 0, 'size': 3, 'query': 'name:"%s"' % template}).json().get('data') or [{}])[0]
j = copy.deepcopy(koi)
for k in ('id', 'version', 'sequenceNumber', 'primaryTerm', 'cacheVersn', 'modified', 'created', 'lastRunTime', 'lastJobRunTime', 'currentIncidentId', 'investigationId',
          'nextRunTime', 'displayNextRunTime', 'runStatus', 'previousRunStatus', 'schedulingStatus', 'sortValues', 'jobSchedulingKey', 'incidentSchedulingKey', 'scheduledEntryGuid', 'autime'):
    j.pop(k, None)
name = 'GuardianOneShot-' + pb
start = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=60)).strftime('%Y-%m-%dT%H:%M:%SZ')
j.update({'id': '', 'version': -1, 'name': name, 'playbookId': pb, 'scheduled': True, 'recurrent': False, 'startDate': start, 'details': 'one-shot lab run', 'tags': ['guardian-lab']})
r = call('POST', '/jobs', json=j); jid = r.json().get('id'); print('created', r.status_code, jid)
try:
    time.sleep(wait)
    x = (call('POST', '/jobs/search', json={'page': 0, 'size': 3, 'query': 'name:"%s"' % name}).json().get('data') or [{}])[0]
    inv = x.get('currentIncidentId'); print('job run:', x.get('runStatus'), inv)
    if inv:
        p = call('GET', '/inv-playbook/' + inv).json()
        print('playbook:', p.get('state'), {t: (v.get('task') or {}).get('name', '')[:24] + ':' + str(v.get('state')) for t, v in (p.get('tasks') or {}).items() if v.get('state')})
finally:
    d = call('DELETE', '/jobs/' + jid); print('job deleted', d.status_code)
