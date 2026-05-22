
import urllib.request
import json

# Test 1: local scan
data = json.dumps({'scan_types': ['system_info', 'firewall']}).encode()
req = urllib.request.Request(
    'http://127.0.0.1:5000/api/start_local_scan',
    data=data,
    headers={'Content-Type': 'application/json'}
)
try:
    resp = urllib.request.urlopen(req)
    print(f"Test 1 - Local scan: {resp.status} {resp.read().decode()}")
except Exception as e:
    print(f"Test 1 - ERROR: {e}")
    if hasattr(e, 'read'):
        print(e.read().decode())
