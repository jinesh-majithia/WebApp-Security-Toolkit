
#!/usr/bin/env python3
"""Scan orchestrator – runs scanners in threads, emits progress via Socket.IO."""
import json
import time
import threading
from datetime import datetime

from utils.database import db, ScanHistory
from scanners.remote import (
    SQLInjectionScanner, XSSScanner, PortScanner, DirectoryScanner,
    SubdomainScanner, DNSEnumerator, HTTPHeadersScanner,
)
from scanners.local_scanners import (
    LocalSystemInfoScanner, FirewallScanner, LocalPortScanner,
    WiFiSecurityScanner, WindowsSecurityScanner, NetworkShareScanner,
)

# ---------------------------------------------------------------------------
# Map scanner names to their classes
# ---------------------------------------------------------------------------
REMOTE_SCANNERS = {
    'sql_injection': SQLInjectionScanner,
    'xss': XSSScanner,
    'port_scan': PortScanner,
    'directory_scan': DirectoryScanner,
    'subdomain_scan': SubdomainScanner,
    'dns_enum': DNSEnumerator,
    'http_headers': HTTPHeadersScanner,
}

LOCAL_SCANNERS = {
    'system_info': LocalSystemInfoScanner,
    'firewall': FirewallScanner,
    'local_ports': LocalPortScanner,
    'wifi_security': WiFiSecurityScanner,
    'windows_security': WindowsSecurityScanner,
    'network_share': NetworkShareScanner,
}


def run_remote_scan(app, target_url, scan_types, scan_id, socketio):
    """Run remote-target scanners in a background thread."""
    def _run():
        with app.app_context():
            all_results = {}
            for name, Klass in REMOTE_SCANNERS.items():
                if scan_types != ['all'] and name not in scan_types:
                    continue
                scanner = Klass(target_url, scan_id)
                results = scanner.safe_scan()
                all_results[name] = results
                socketio.emit('scan_progress', {
                    'scan_id': scan_id, 'scan_type': name,
                    'results': results, 'status': 'completed',
                })
                time.sleep(0.5)

            record = db.session.get(ScanHistory, scan_id)
            if record:
                record.status = 'completed'
                record.completed_at = datetime.utcnow()
                record.results = json.dumps(all_results, indent=2, default=str)
                db.session.add(record)
                db.session.commit()
            socketio.emit('scan_complete', {'scan_id': scan_id, 'status': 'completed'})

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread


def run_local_scan(app, scan_types, scan_id, socketio):
    """Run local-machine scanners in a background thread."""
    def _run():
        with app.app_context():
            all_results = {}
            for name, Klass in LOCAL_SCANNERS.items():
                if scan_types != ['all'] and name not in scan_types:
                    continue
                scanner = Klass()
                results = scanner.safe_scan()
                all_results[name] = results
                socketio.emit('local_scan_progress', {
                    'scan_id': scan_id, 'scan_type': name,
                    'results': results, 'status': 'completed',
                })
                time.sleep(0.3)

            record = db.session.get(ScanHistory, scan_id)
            if record:
                record.status = 'completed'
                record.completed_at = datetime.utcnow()
                record.results = json.dumps(all_results, indent=2, default=str)
                db.session.add(record)
                db.session.commit()
            socketio.emit('local_scan_complete', {'scan_id': scan_id, 'status': 'completed'})

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread
