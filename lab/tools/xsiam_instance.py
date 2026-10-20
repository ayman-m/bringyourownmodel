"""Create/enable the Guardian Cohere lab instance on the XSIAM lab tenant, run on a lab engine, pointing at the lab model
middleware. The model URL and bearer token come from the repo .env (NORTH_MOCK_URL, NORTH_MOCK_BEARER_TOKEN); the tenant
credentials from xsiam.py. Prints no secrets. Usage: xsiam_instance.py [engine-name]"""
import json, sys
from pathlib import Path
from xsiam import call
env = {}
for line in (Path(__file__).resolve().parents[2] / '.env').read_text().splitlines():
    if '=' in line and not line.strip().startswith('#'):
        k, v = line.split('=', 1); env[k.strip()] = v.strip().strip('"')
ENGINE_NAME = sys.argv[1] if len(sys.argv) > 1 else 'AutomationEngine'
NAME = 'GuardianCohereXsiamLab'
VALUES = {'endpoint_url': env['NORTH_MOCK_URL'], 'agent_id': 'lab-agent-0001', 'session_id': '',
          'bearer_token': env['NORTH_MOCK_BEARER_TOKEN'], 'conversation_mode': 'stateless', 'tool_format': 'openai',
          'model': 'command-r:35b', 'model_tier': 'medium', 'request_timeout': '300', 'insecure': True, 'proxy': False}
search = call('POST', '/settings/integration/search', json={'size': 400}).json()
cohere = next(c for c in search['configurations'] if c.get('id') == 'GuardianCohere')
engine = next(e for e in search['engines']['engines'] if e['name'] == ENGINE_NAME)
data = []
for p in cohere['configuration']:
    val = VALUES.get(p['name'], p.get('defaultValue', ''))
    entry = dict(p); entry['value'] = val
    entry['hasvalue'] = val not in (None, '', False) or isinstance(val, bool)
    data.append(entry)
existing = next((i for i in search['instances'] if i['name'] == NAME), None)
payload = {'brand': 'GuardianCohere', 'name': NAME, 'enabled': 'true', 'engine': engine['id'], 'engineGroup': '', 'propagationLabels': ['all'],
           'isIntegrationScript': True, 'configuration': cohere, 'data': data, 'version': existing.get('version', -1) if existing else -1}
if existing: payload['id'] = existing['id']
r = call('PUT', '/settings/integration', json=payload)
print(r.status_code, (r.json().get('name') if r.ok else r.text[:400]), '| engine', ENGINE_NAME)
