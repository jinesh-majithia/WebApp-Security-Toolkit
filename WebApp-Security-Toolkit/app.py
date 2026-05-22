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
import re
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

# ---------- Scanner Base ----------
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

# ---------- REMOTE SCANNERS ----------
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
            '"<script>alert(\'XSS\')</script>',
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

# ---------- LOCAL SECURITY SCANNERS ----------
class LocalSystemInfoScanner(ScannerBase):
    """Checks local system security configuration - no target URL needed"""
    def __init__(self):
        super().__init__('localhost')
    
    def scan(self):
        import platform
        import getpass
        
        os_name = platform.system()
        os_version = platform.version()
        os_release = platform.release()
        self.add_result('info', 'Operating System', f'{os_name} {os_release} (Build {os_version})', '')
        
        hostname = socket.gethostname()
        self.add_result('info', 'Hostname', hostname, '')
        
        current_user = getpass.getuser()
        self.add_result('info', 'Current User', current_user, '')
        
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin:
                self.add_result('high', 'Running as Administrator', 
                    'Running with admin privileges increases attack surface. Malware can gain elevated access.', '')
                self.vulnerable = True
            else:
                self.add_result('safe', 'Running as Standard User', 
                    'Standard user privileges limit potential damage from exploits.', '')
        except:
            pass
        
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
            uac_val, _ = winreg.QueryValueEx(key, "EnableLUA")
            if uac_val == 0:
                self.add_result('high', 'UAC Disabled', 
                    'User Account Control is disabled. Malware can make system changes without notification.', '')
                self.vulnerable = True
            elif uac_val == 1:
                self.add_result('safe', 'UAC Enabled', 
                    'User Account Control is active, adding a layer of protection.', '')
        except:
            pass
        
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop")
            timeout, _ = winreg.QueryValueEx(key, "ScreenSaveTimeOut")
            timeout_sec = int(timeout)
            if timeout_sec > 900:
                self.add_result('medium', 'Screen Lock Timeout Too Long', 
                    f'Current: {timeout_sec//60} minutes. Recommended: 5-15 minutes.', '')
                self.vulnerable = True
            else:
                self.add_result('safe', 'Screen Lock Timeout OK', f'Current: {timeout_sec//60} minutes', '')
        except:
            pass
        
        try:
            import psutil
            process_count = len(psutil.pids())
            self.add_result('info', 'Running Processes', f'{process_count} processes active', '')
            suspicious = ['remmina', 'vnc', 'anydesk', 'teamviewer', 'logmein']
            running_suspicious = []
            for proc in psutil.process_iter(['name']):
                try:
                    pname = proc.info['name'].lower() if proc.info['name'] else ''
                    if any(s in pname for s in suspicious):
                        running_suspicious.append(proc.info['name'])
                except:
                    pass
            if running_suspicious:
                self.add_result('medium', 'Remote Access Tools Running', 
                    f'Suspicious: {", ".join(set(running_suspicious))}', '')
                self.vulnerable = True
        except ImportError:
            self.add_result('info', 'Process Info', 'Install psutil for detailed process analysis (pip install psutil)', '')
        
        if not self.vulnerable:
            self.add_result('info', 'System Security OK', 'Basic system security checks passed', '')
        return self.results

class FirewallScanner(ScannerBase):
    """Checks Windows Firewall status"""
    def __init__(self):
        super().__init__('localhost')
    
    def scan(self):
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.lower()
            if 'on' in output:
                self.add_result('safe', 'Windows Firewall', 'Firewall is enabled for all profiles', '')
            else:
                self.add_result('high', 'Windows Firewall Disabled', 
                    'The Windows Firewall is disabled. System is exposed to network attacks.', '')
                self.vulnerable = True
        except Exception as e:
            self.add_result('error', 'Firewall Check Failed', str(e), '')
        
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all', 'dir=in'],
                capture_output=True, text=True, timeout=10
            )
            rules_count = result.stdout.count('Rule Name:')
            open_ports_in = result.stdout.count('LocalPort:')
            self.add_result('info', 'Firewall Rules', f'{rules_count} inbound rules, {open_ports_in} port openings', '')
            
            if 'RemotePort: any' in result.stdout and 'Action: Allow' in result.stdout:
                self.add_result('medium', 'Permissive Firewall Rules', 
                    'Some firewall rules allow all remote ports.', '')
        except:
            pass
        
        if not self.vulnerable:
            self.add_result('info', 'Firewall Security OK', 'Firewall configuration appears secure', '')
        return self.results

class LocalPortScanner(ScannerBase):
    """Scans localhost for listening ports"""
    def __init__(self):
        super().__init__('localhost')
    
    def scan(self):
        try:
            result = subprocess.run(
                ['netstat', '-ano', '-p', 'TCP'],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.split('\n')
            listening_ports = []
            for line in lines:
                if 'LISTENING' in line:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        addr_port = parts[1]
                        pid = parts[-1]
                        if ':' in addr_port:
                            port = addr_port.rsplit(':', 1)[-1]
                            listening_ports.append({'port': port, 'pid': pid})
            
            if listening_ports:
                well_known = [p for p in listening_ports if int(p['port']) < 1024]
                dynamic = [p for p in listening_ports if int(p['port']) >= 49152]
                registered = [p for p in listening_ports if 1024 <= int(p['port']) < 49152]
                
                self.add_result('info', 'Listening Ports', 
                    f'{len(listening_ports)} total: {len(well_known)} privileged, {len(registered)} registered, {len(dynamic)} dynamic', '')
                
                dangerous_ports = {'22': 'SSH', '23': 'Telnet', '445': 'SMB', 
                                   '3389': 'RDP', '5900': 'VNC', '21': 'FTP'}
                for p in listening_ports:
                    if p['port'] in dangerous_ports:
                        self.add_result('medium', f'{dangerous_ports[p["port"]]} Listening',
                            f'Port {p["port"]} is open (PID: {p["pid"]}). Consider disabling if not needed.', '')
                        self.vulnerable = True
                
                port_list = ', '.join([f"{p['port']} (PID:{p['pid']})" for p in listening_ports[:20]])
                if len(listening_ports) > 20:
                    port_list += f' ... and {len(listening_ports)-20} more'
                self.add_result('info', 'Open Ports Detail', port_list, '')
            else:
                self.add_result('safe', 'No Listening Ports', 'No TCP ports found in LISTENING state', '')
        except Exception as e:
            self.add_result('error', 'Port Check Failed', str(e), '')
        
        if not self.vulnerable:
            self.add_result('safe', 'Local Ports OK', 'No dangerous services running', '')
        return self.results

class WiFiSecurityScanner(ScannerBase):
    """Checks Wi-Fi security configuration"""
    def __init__(self):
        super().__init__('localhost')
    
    def scan(self):
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout
            
            if 'There is no wireless interface' in output or 'not found' in output.lower():
                self.add_result('info', 'Wi-Fi Status', 'No wireless interface detected (wired connection)', '')
                return self.results
            
            ssid_match = re.search(r'SSID\s+:\s(.+)', output)
            ssid = ssid_match.group(1).strip() if ssid_match else 'Unknown'
            
            signal_match = re.search(r'Signal\s+:\s(\d+)%', output)
            signal = signal_match.group(1) if signal_match else 'Unknown'
            
            auth_match = re.search(r'Authentication\s+:\s(.+)', output)
            auth = auth_match.group(1).strip() if auth_match else 'Unknown'
            
            cipher_match = re.search(r'Cipher\s+:\s(.+)', output)
            cipher = cipher_match.group(1).strip() if cipher_match else 'Unknown'
            
            self.add_result('info', f'Connected to: {ssid}', 
                f'Signal: {signal}% | Auth: {auth} | Cipher: {cipher}', '')
            
            if 'WEP' in auth or 'WEP' in cipher:
                self.add_result('high', 'WEP Encryption Detected', 
                    f'Wi-Fi network uses WEP, which is trivially cracked.', '')
                self.vulnerable = True
            elif 'WPA2' in auth:
                if 'CCMP' in cipher or 'AES' in cipher:
                    self.add_result('safe', 'Strong Wi-Fi Encryption', f'WPA2 with {cipher} encryption', '')
                else:
                    self.add_result('medium', 'Weak Wi-Fi Cipher', 
                        f'WPA2 with {cipher} (TKIP is weaker)', '')
                    self.vulnerable = True
            elif 'WPA3' in auth:
                self.add_result('safe', 'WPA3 Encryption', 'Latest wireless security standard', '')
            elif 'Open' in auth or 'None' in auth:
                self.add_result('high', 'Open Wi-Fi Network', 
                    f'Network has no encryption! All traffic is visible.', '')
                self.vulnerable = True
            else:
                self.add_result('medium', f'Unknown Security: {auth}', 'Could not verify encryption strength', '')
            
            profiles_result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profiles'],
                capture_output=True, text=True, timeout=10
            )
            profile_count = profiles_result.stdout.count('All User Profile')
            self.add_result('info', 'Saved Wi-Fi Networks', f'{profile_count} saved network profiles', '')
            
        except Exception as e:
            self.add_result('error', 'Wi-Fi Check Failed', str(e), '')
        
        if not self.vulnerable:
            self.add_result('safe', 'Wi-Fi Security OK', 'Wireless configuration appears secure', '')
        return self.results

class WindowsSecurityScanner(ScannerBase):
    """Checks Windows security features"""
    def __init__(self):
        super().__init__('localhost')
    
    def scan(self):
        # Windows Defender
        try:
            result = subprocess.run(
                ['powershell', '-Command', 
                 'Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled'],
                capture_output=True, text=True, timeout=15
            )
            if 'True' in result.stdout:
                self.add_result('safe', 'Windows Defender', 'Real-time protection is active', '')
            else:
                self.add_result('high', 'Windows Defender Disabled', 
                    'Real-time antivirus protection is not active!', '')
                self.vulnerable = True
        except:
            self.add_result('info', 'Windows Defender', 'Could not query Defender status', '')
        
        # BitLocker
        try:
            result = subprocess.run(
                ['powershell', '-Command', 
                 'Get-BitLockerVolume -MountPoint C: | Select-Object ProtectionStatus'],
                capture_output=True, text=True, timeout=15
            )
            if 'On' in result.stdout or 'True' in result.stdout:
                self.add_result('safe', 'BitLocker', 'Drive encryption is active on C:', '')
            else:
                self.add_result('medium', 'BitLocker Disabled', 
                    'Drive encryption is not enabled. Data at risk if device is stolen.', '')
                self.vulnerable = True
        except:
            self.add_result('info', 'BitLocker', 'BitLocker check requires admin privileges', '')
        
        # Guest account
        try:
            result = subprocess.run(
                ['powershell', '-Command', 'Get-LocalUser -Name "Guest" | Select-Object Enabled'],
                capture_output=True, text=True, timeout=15
            )
            if 'True' in result.stdout:
                self.add_result('high', 'Guest Account Enabled', 
                    'The Guest account is active. Disable it to prevent unauthorized access.', '')
                self.vulnerable = True
            else:
                self.add_result('safe', 'Guest Account', 'Guest account is disabled', '')
        except:
            pass
        
        # Password policy
        try:
            result = subprocess.run(
                ['powershell', '-Command', 'net accounts'],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout
            match = re.search(r'Maximum password age\s*:\s*(\d+)', output)
            if match:
                max_age = int(match.group(1))
                if max_age > 90:
                    self.add_result('medium', 'Password Expiration', 
                        f'Passwords expire every {max_age} days. Recommended: 60-90 days.', '')
                    self.vulnerable = True
                else:
                    self.add_result('safe', 'Password Expiration', f'Passwords expire every {max_age} days', '')
        except:
            pass
        
        if not self.vulnerable:
            self.add_result('safe', 'Windows Security OK', 'All Windows security checks passed', '')
        return self.results

class NetworkShareScanner(ScannerBase):
    """Checks for exposed network shares"""
    def __init__(self):
        super().__init__('localhost')
    
    def scan(self):
        try:
            result = subprocess.run(['net', 'share'], capture_output=True, text=True, timeout=10)
            output = result.stdout
            
            shares = []
            for line in output.split('\n'):
                if '\\' in line and not line.startswith('The command'):
                    parts = line.strip().split()
                    if parts:
                        shares.append(parts[0])
            
            admin_shares = [s for s in shares if s.endswith('$')]
            user_shares = [s for s in shares if not s.endswith('$')]
            
            if user_shares:
                self.add_result('medium', 'User-Created Shares Found', 
                    f'Shared folders: {", ".join(user_shares)}', 
                    'Audit share permissions to ensure they are not exposed')
                self.vulnerable = True
            else:
                self.add_result('safe', 'No User Shares', 'No user-created network shares found', '')
            
            if admin_shares:
                self.add_result('info', 'Admin Shares', 
                    f'{len(admin_shares)} administrative shares exist (hidden, normal)', 
                    ', '.join(admin_shares))
            
            self.add_result('info', 'Total Shares', 
                f'{len(shares)} total shares ({len(admin_shares)} admin, {len(user_shares)} user)', '')
                
        except Exception as e:
            self.add_result('error', 'Share Check Failed', str(e), '')
        
        if not self.vulnerable:
            self.add_result('safe', 'Network Shares OK', 'No unauthorized sharing detected', '')
        return self.results


# ---------- LOCAL SCAN ORCHESTRATOR ----------
def run_local_scan(scan_types, scan_id):
    with app.app_context():
        record = db.session.get(ScanHistory, scan_id)
        if not record:
            return
        record.status = 'running'
        db.session.commit()

    all_results = {}
    scanners = {
        'system_info': LocalSystemInfoScanner(),
        'firewall': FirewallScanner(),
        'local_ports': LocalPortScanner(),
        'wifi_security': WiFiSecurityScanner(),
        'windows_security': WindowsSecurityScanner(),
        'network_share': NetworkShareScanner(),
    }

    for scan_type, scanner in scanners.items():
        if scan_type in scan_types or 'all' in scan_types:
            try:
                results = scanner.scan()
                all_results[scan_type] = results
                socketio.emit('local_scan_progress', {
                    'scan_id': scan_id,
                    'scan_type': scan_type,
                    'results': results,
                    'status': 'completed'
                })
            except Exception as e:
                all_results[scan_type] = [{'severity': 'error', 'title': 'Scan Failed', 'description': str(e)}]
                socketio.emit('local_scan_progress', {
                    'scan_id': scan_id,
                    'scan_type': scan_type,
                    'results': all_results[scan_type],
                    'status': 'error'
                })
            time.sleep(0.3)

    with app.app_context():
        record = db.session.get(ScanHistory, scan_id)
        if record:
            record.status = 'completed'
            record.completed_at = datetime.utcnow()
            record.results = json.dumps(all_results, indent=2)
            db.session.commit()
    
    socketio.emit('local_scan_complete', {'scan_id': scan_id, 'status': 'completed'})


# ---------- REMOTE SCAN ORCHESTRATOR ----------
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


# ---------- WEB ROUTES ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/local')
def local_scan_page():
    return render_template('local_scan.html')

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

@app.route('/api/start_local_scan', methods=['POST'])
def start_local_scan():
    """Run local security audit - no target URL required"""
    data = request.json
    scan_types = data.get('scan_types', ['all'])
    
    record = ScanHistory(target_url='LOCAL_MACHINE', scan_type=','.join(scan_types), status='pending')
    db.session.add(record)
    db.session.commit()

    thread = threading.Thread(target=run_local_scan, args=(scan_types, record.id))
    thread.daemon = True
    thread.start()

    return jsonify({'scan_id': record.id, 'status': 'started'})

@app.route('/api/bulk_scan', methods=['POST'])
def bulk_scan():
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
