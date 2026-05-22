
#!/usr/bin/env python3
"""
Network Security Toolkit - Web Application
A comprehensive web-based network security scanning dashboard.
"""
import os
import sys
import json
import time
import threading
import socket
import subprocess
from datetime import datetime
from pathlib import Path

import requests
from flask import Flask, render_template, request, jsonify, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from bs4 import BeautifulSoup
import dns.resolver

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ---------- Database Models ----------
class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), default='running')
    results = db.Column(db.Text, default='{}')
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'target_url': self.target_url,
            'scan_type': self.scan_type,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }

with app.app_context():
    db.create_all()

# ---------- Scanner Classes ----------
class ScannerBase:
    def __init__(self, target_url, scan_id=None):
        self.target_url = target_url.rstrip('/')
        self.scan_id = scan_id
        self.results = []
        self.vulnerable = False
        self.timeout = 10

    def add_result(self, severity, title, description, detail=''):
        self.results.append({
            'severity': severity,
            'title': title,
            'description': description,
            'detail': detail
        })

class SQLInjectionScanner(ScannerBase):
    def scan(self):
        sql_payloads = [
            "' OR '1'='1",
            "' OR 'a'='a",
            "' UNION SELECT NULL, NULL --",
            "'; DROP TABLE users --",
            "' OR 1=1 --",
        ]
        for payload in sql_payloads:
            try:
                target = f"{self.target_url}?id={payload}"
                response = requests.get(target, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
                if any(err in response.text.lower() for err in ['error', 'syntax', 'mysql', 'sql', 'odbc', 'driver']):
                    self.add_result('high', 'SQL Injection Detected', f'Payload: {payload}', target)
                    self.vulnerable = True
                if 'sql' in response.text.lower() or 'mysql' in response.text.lower():
                    self.add_result('medium', 'Possible SQL Info Leak', f'Payload: {payload}', target)
            except Exception as e:
                continue
        if not self.vulnerable:
            self.add_result('safe', 'No SQL Injection Found', 'Target appears resistant to SQL injection')
        return self.results

class XSSScanner(ScannerBase):
    def scan(self):
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "\"<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
        ]
        for payload in xss_payloads:
            try:
                target = f"{self.target_url}?search={payload}"
                response = requests.get(target, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
                if payload in response.text:
                    self.add_result('high', 'Reflected XSS Detected', f'Payload: {payload}', target)
                    self.vulnerable = True
            except Exception as e:
                continue
        # Check for DOM-based XSS
        try:
            response = requests.get(self.target_url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                if action:
                    self.add_result('info', f'Form Found at {action}', 'Potential XSS attack surface', form.prettify()[:200])
        except:
            pass
        if not self.vulnerable:
            self.add_result('safe', 'No XSS Found', 'Target appears resistant to XSS attacks')
        return self.results

class PortScanner(ScannerBase):
    def scan(self):
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
        try:
            # Extract domain from URL
            domain = self.target_url.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
            ip = socket.gethostbyname(domain)
            self.add_result('info', f'Resolved IP', f'{domain} → {ip}', '')
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        service = self._get_service_name(port)
                        self.add_result('medium' if port in [22, 3306, 3389, 5432, 6379, 27017] else 'low', 
                                       f'Port {port} Open', f'{service} service detected', f'http://{domain}:{port}')
                        self.vulnerable = True
                    sock.close()
                except:
                    continue
        except Exception as e:
            self.add_result('error', 'Port Scan Failed', str(e), '')
        if not self.vulnerable:
            self.add_result('safe', 'No Open Ports Found', 'Common ports are closed or filtered')
        return self.results

    def _get_service_name(self, port):
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
            110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
            995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 2049: 'NFS', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
        return services.get(port, 'Unknown')

class DirectoryScanner(ScannerBase):
    def scan(self):
        directories = [
            'admin', 'login', 'backup', 'wp-admin', 'dashboard', 'config', '.git',
            'robots.txt', 'sitemap.xml', 'phpinfo.php', 'uploads', 'images',
            'css', 'js', 'api', 'v1', 'v2', 'graphql', 'swagger', 'docs',
            'test', 'dev', 'staging', 'beta', 'old', 'private', 'secret',
        ]
        for directory in directories:
            try:
                target = f"{self.target_url}/{directory}"
                response = requests.get(target, timeout=3, headers={'User-Agent': 'Mozilla/5.0'})
                if response.status_code in [200, 301, 302, 403]:
                    severity = 'high' if directory in ['.git', 'admin', 'backup', 'config'] else 'medium'
                    self.add_result(severity, f'Discovered: /{directory}', f'HTTP {response.status_code}', target)
                    self.vulnerable = True
            except:
                continue
        if not self.vulnerable:
            self.add_result('safe', 'No Directories Found', 'Common directories are not exposed')
        return self.results

class SubdomainScanner(ScannerBase):
    def scan(self):
        domain = self.target_url.replace('http://', '').replace('https://', '').split('/')[0]
        subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'blog',
            'shop', 'cdn', 'm', 'app', 'beta', 'staging', 'webmail', 'portal',
            'cpanel', 'whm', 'support', 'help', 'status', 'docs', 'wiki',
            'remote', 'vpn', 'secure', 'login', 'sso', 'cloud', 'demo',
        ]
        for sub in subdomains:
            try:
                target = f"http://{sub}.{domain}"
                response = requests.get(target, timeout=3, headers={'User-Agent': 'Mozilla/5.0'})
                if response.status_code < 400 or response.status_code == 403:
                    self.add_result('medium' if sub in ['admin', 'api', 'dev', 'test'] else 'low',
                                   f'Subdomain: {sub}.{domain}', f'HTTP {response.status_code}', target)
                    self.vulnerable = True
            except:
                continue
        if not self.vulnerable:
            self.add_result('safe', 'No Subdomains Found', 'No common subdomains were discovered')
        return self.results

class DNSEnumerator(ScannerBase):
    def scan(self):
        domain = self.target_url.replace('http://', '').replace('https://', '').split('/')[0]
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                for rdata in answers:
                    self.add_result('info', f'{rtype} Record', str(rdata), domain)
                    self.vulnerable = True
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                self.add_result('error', 'NXDOMAIN', f'Domain {domain} does not exist', '')
                break
            except Exception as e:
                continue
        if not self.vulnerable:
            self.add_result('safe', 'No DNS Records Found', 'Unable to resolve any DNS records')
        return self.results

class HTTPHeadersScanner(ScannerBase):
    def scan(self):
        try:
            response = requests.get(self.target_url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': {'desc': 'HSTS', 'critical': True},
                'Content-Security-Policy': {'desc': 'CSP', 'critical': True},
                'X-Content-Type-Options': {'desc': 'Prevents MIME sniffing', 'critical': True},
                'X-Frame-Options': {'desc': 'Clickjacking protection', 'critical': True},
                'X-XSS-Protection': {'desc': 'XSS filter', 'critical': False},
                'Referrer-Policy': {'desc': 'Referrer information control', 'critical': False},
                'Permissions-Policy': {'desc': 'Browser features control', 'critical': False},
            }
            
            for header, info in security_headers.items():
                if header in headers:
                    self.add_result('safe', f'{info["desc"]} Present', f'{header}: {headers[header]}', '')
                else:
                    severity = 'high' if info['critical'] else 'medium'
                    self.add_result(severity, f'Missing: {info["desc"]}', f'{header} header is not set', '')
                    self.vulnerable = True

            # Server info disclosure
            if 'Server' in headers:
                self.add_result('low', 'Server Info Disclosure', f'Server: {headers["Server"]}', '')
            if 'X-Powered-By' in headers:
                self.add_result('low', 'Technology Disclosure', f'X-Powered-By: {headers["X-Powered-By"]}', '')
            
            self.add_result('info', 'HTTP Response Code', str(response.status_code), self.target_url)
            
        except Exception as e:
            self.add_result('error', 'HTTP Scan Failed', str(e), '')
        if not self.vulnerable:
            self.add_result('safe', 'Security Headers OK', 'All critical security headers are present')
        return self.results

# ---------- Scan Orchestrator ----------
def run_scan(target_url, scan_types, scan_id):
    with app.app_context():
        record = db.session.get(ScanHistory, scan_id)
        if not record:
            return
        record.status = 'running'
        db.session.commit()

    all_results = {}
    scanners = {
        'sql_injection': SQLInjectionScanner(target_url),
        'xss': XSSScanner(target_url),
        'port_scan': PortScanner(target_url),
        'directory_scan': DirectoryScanner(target_url),
        'subdomain_scan': SubdomainScanner(target_url),
        'dns_enum': DNSEnumerator(target_url),
        'http_headers': HTTPHeadersScanner(target_url),
    }

    for scan_type, scanner in scanners.items():
        if scan_type in scan_types or 'all' in scan_types:
            try:
                results = scanner.scan()
                all_results[scan_type] = results
                socketio.emit('scan_progress', {
                    'scan_id': scan_id,
                    'scan_type': scan_type,
                    'results': results,
                    'status': 'completed'
                })
            except Exception as e:
                all_results[scan_type] = [{'severity': 'error', 'title': 'Scan Failed', 'description': str(e)}]
                socketio.emit('scan_progress', {
                    'scan_id': scan_id,
                    'scan_type': scan_type,
                    'results': all_results[scan_type],
                    'status': 'error'
                })
            time.sleep(0.5)

    with app.app_context():
        record = db.session.get(ScanHistory, scan_id)
        if record:
            record.status = 'completed'
            record.completed_at = datetime.utcnow()
            record.results = json.dumps(all_results, indent=2)
            db.session.commit()
    
    socketio.emit('scan_complete', {'scan_id': scan_id, 'status': 'completed'})

# ---------- Web Routes ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scans')
def scans():
    history = ScanHistory.query.order_by(ScanHistory.started_at.desc()).all()
    return render_template('scans.html', scans=[s.to_dict() for s in history])

@app.route('/scan/<int:scan_id>')
def scan_detail(scan_id):
    record = ScanHistory.query.get_or_404(scan_id)
    results = json.loads(record.results) if record.results else {}
    return render_template('scan_detail.html', scan=record.to_dict(), results=results)

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    data = request.json
    target_url = data.get('target_url', '').strip()
    scan_types = data.get('scan_types', ['all'])
    
    if not target_url:
        return jsonify({'error': 'Target URL is required'}), 400
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = f'https://{target_url}'

    record = ScanHistory(target_url=target_url, scan_type=','.join(scan_types), status='pending')
    db.session.add(record)
    db.session.commit()

    thread = threading.Thread(target=run_scan, args=(target_url, scan_types, record.id))
    thread.daemon = True
    thread.start()

    return jsonify({'scan_id': record.id, 'status': 'started'})

@app.route('/api/bulk_scan', methods=['POST'])
def bulk_scan():
    """Scan multiple targets"""
    data = request.json
    targets = data.get('targets', [])
    if not targets:
        return jsonify({'error': 'At least one target is required'}), 400
    
    scan_ids = []
    for target in targets:
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
        record = ScanHistory(target_url=target, scan_type='all', status='pending')
        db.session.add(record)
        db.session.commit()
        thread = threading.Thread(target=run_scan, args=(target, ['all'], record.id))
        thread.daemon = True
        thread.start()
        scan_ids.append(record.id)
    
    return jsonify({'scan_ids': scan_ids, 'status': 'started'})

@app.route('/api/export/<int:scan_id>/<fmt>')
def export_scan(scan_id, fmt):
    record = ScanHistory.query.get_or_404(scan_id)
    results = json.loads(record.results) if record.results else {}
    
    if fmt == 'json':
        return jsonify({
            'target': record.target_url,
            'scan_type': record.scan_type,
            'started_at': record.started_at.isoformat(),
            'completed_at': record.completed_at.isoformat() if record.completed_at else None,
            'results': results
        })
    
    elif fmt == 'csv':
        csv_lines = ['severity,scan_type,title,description,detail']
        for scan_type, findings in results.items():
            for finding in findings:
                csv_lines.append(f'"{finding.get("severity","")}","{scan_type}","{finding.get("title","")}","{finding.get("description","")}","{finding.get("detail","")}"')
        return Response('\n'.join(csv_lines), mimetype='text/csv',
                       headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}.csv'})
    
    elif fmt == 'txt':
        lines = [f"Network Security Toolkit Scan Report", f"=" * 40,
                 f"Target: {record.target_url}", f"Date: {record.started_at}",
                 f"Status: {record.status}", ""]
        for scan_type, findings in results.items():
            lines.append(f"\n--- {scan_type.upper()} ---")
            for finding in findings:
                sev = finding.get('severity', '')
                title = finding.get('title', '')
                desc = finding.get('description', '')
                icon = {'high': '🔴', 'medium': '🟠', 'low': '🟡', 'info': 'ℹ️', 'safe': '✅', 'error': '❌'}.get(sev, '•')
                lines.append(f"  {icon} [{sev.upper()}] {title}: {desc}")
        return Response('\n'.join(lines), mimetype='text/plain',
                       headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}.txt'})
    
    return jsonify({'error': 'Unsupported format'}), 400

@app.route('/api/delete_scan/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    record = ScanHistory.query.get_or_404(scan_id)
    db.session.delete(record)
    db.session.commit()
    return jsonify({'status': 'deleted'})

# ---------- Socket.IO Events ----------
@socketio.on('connect')
def handle_connect():
    emit('connected', {'data': 'Connected to scan server'})

# ---------- Main ----------
if __name__ == '__main__':
    print("=" * 50)
    print("  Network Security Toolkit - Web Dashboard v1.0.0")
    print("  Starting server on http://0.0.0.0:5000")
    print("=" * 50)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True, use_reloader=False)
