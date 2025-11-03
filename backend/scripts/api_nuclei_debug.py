import time, json, sys
import requests

BASE = 'http://127.0.0.1:8000'

payload = {
    'target_url': 'http://testphp.vulnweb.com',
    'scan_types': ['nuclei'],
    'options': {
        'enable_ai_analysis': False,
        'enable_mitre_mapping': True,
        'include_low_risk': True,
        'deep_scan': False,
        'timeout_minutes': 5,
    }
}

try:
    r = requests.post(f"{BASE}/api/v1/scans/comprehensive/start", json=payload, timeout=30)
    print('start:', r.status_code, r.text[:200])
    r.raise_for_status()
    scan_id = r.json()['scan_id']
except Exception as e:
    print('start_err:', e)
    sys.exit(1)

deadline = time.time() + 300
while time.time() < deadline:
    s = requests.get(f"{BASE}/api/v1/scans/comprehensive/{scan_id}/status", timeout=15)
    if s.status_code == 200:
        data = s.json()
        print('status:', data)
        if data.get('status') in ('completed','failed'):
            break
    else:
        print('poll_err:', s.status_code)
    time.sleep(3)

res = requests.get(f"{BASE}/api/v1/scans/comprehensive/{scan_id}/result", params={'debug': 1}, timeout=60)
print('result:', res.status_code)
if res.status_code == 200:
    j = res.json()
    print('vuln_count:', len(j.get('vulnerabilities', [])))
    dbg = j.get('debug') or {}
    print('debug_keys:', list(dbg.keys()))
    nd = (dbg.get('nuclei') or {})
    print('nuclei_debug:', json.dumps({
        'output_file': nd.get('output_file'),
        'output_file_exists': nd.get('output_file_exists'),
        'stdout_lines_parsed': nd.get('stdout_lines_parsed'),
    }, indent=2))
    st = nd.get('stderr_tail')
    if isinstance(st, str) and st:
        print('stderr_tail_last_200:\n', st[-200:])
else:
    print('result_body:', res.text[:500])
