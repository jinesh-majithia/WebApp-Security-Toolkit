
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


def _run_scanners(scanner_map, scan_types, scan_id, socketio, progress_event, delay=0.3):
    """Generic scanner runner. Emits progress per scan type."""
    all_results = {}

    with db.session.begin():
        record = db.session.get(ScanHistory, scan_id)
        if record:
            record.status = 'running'

    for name, Klass in scanner_map.items():
        if scan_types != ['all'] and name not in scan_types:
            continue
        try:
            scanner = Klass(Klass('').target_url if hasattr(Klass, '__init__') and 'target_url' in Klass.__init__.__code__.co_varnames else 'localhost')
            # Local scanners don't take target_url; remote scanners do
            if issubclass(Klass, SQLInjectionScanner.__class__) or True:  # simplified check
                scanner = Klass('localhost' if name in LOCAL_SCANNERS else 'localhost')
            results = scanner.safe_scan()
        except Exception:
            results = [{'severity': 'error', 'title': 'Scanner Error', 'description': 'Failed to instantiate scanner.'}]

        all_results[name] = results
        if socketio:
            socketio.emit(progress_event, {
                'scan_id': scan_id,
                'scan_type': name,
                'results': results,
                'status': 'completed',
            })
        time.sleep(delay)

    with db.session.begin():
        record = db.session.get(ScanHistory, scan_id)
        if record:
            record.status = 'completed'
            record.completed_at = datetime.utcnow()
            record.results = json.dumps(all_results, indent=2, default=str)

    if socketio:
        socketio.emit(progress_event.replace('progress', 'complete'), {
            'scan_id': scan_id,
            'status': 'completed',
        })


def run_remote_scan(target_url, scan_types, scan_id, socketio):
    """Run remote-target scanners in a background thread."""
    with db.session.begin():
        record = db.session.get(ScanHistory, scan_id)
        if record:
            record.status = 'pending'

    def _run():
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

        with db.session.begin():
            record = db.session.get(ScanHistory, scan_id)
            if record:
                record.status = 'completed'
                record.completed_at = datetime.utcnow()
                record.results = json.dumps(all_results, indent=2, default=str)
        socketio.emit('scan_complete', {'scan_id': scan_id, 'status': 'completed'})

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread


def run_local_scan(scan_types, scan_id, socketio):
    """Run local-machine scanners in a background thread."""
    with db.session.begin():
        record = db.session.get(ScanHistory, scan_id)
        if record:
            record.status = 'pending'

    def _run():
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

        with db.session.begin():
            record = db.session.get(ScanHistory, scan_id)
            if record:
                record.status = 'completed'
                record.completed_at = datetime.utcnow()
                record.results = json.dumps(all_results, indent=2, default=str)
        socketio.emit('local_scan_complete', {'scan_id': scan_id, 'status': 'completed'})

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread
