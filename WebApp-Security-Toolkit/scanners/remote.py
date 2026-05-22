
#!/usr/bin/env python3
"""Remote target scanners – SQLi, XSS, Port, Directory, Subdomain, DNS, HTTP Headers."""
import socket
import requests
from bs4 import BeautifulSoup
import dns.resolver
from .base import ScannerBase

UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
TIMEOUT = 5


class SQLInjectionScanner(ScannerBase):
    def scan(self):
        payloads = ["' OR '1'='1", "' OR 'a'='a", "' UNION SELECT NULL --", "'; DROP TABLE --", "' OR 1=1 --"]
        for p in payloads:
            try:
                r = requests.get(f"{self.target_url}?id={p}", timeout=TIMEOUT, headers=UA)
                body = r.text.lower()
                if any(kw in body for kw in ['error', 'syntax', 'mysql', 'sql', 'odbc', 'driver']):
                    self.add_result('high', 'SQL Injection Detected', f'Payload: {p}', r.url)
                elif 'sql' in body or 'mysql' in body:
                    self.add_result('medium', 'Possible SQL Info Leak', f'Payload: {p}', r.url)
            except requests.RequestException:
                continue
        if not self.vulnerable:
            self.add_result('safe', 'No SQL Injection Found', 'Target appears resistant to SQL injection')
        return self.results


class XSSScanner(ScannerBase):
    def scan(self):
        payloads = [
            "<script>alert('XSS')</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
        ]
        for p in payloads:
            try:
                r = requests.get(f"{self.target_url}?search={p}", timeout=TIMEOUT, headers=UA)
                if p in r.text:
                    self.add_result('high', 'Reflected XSS Detected', f'Payload: {p}', r.url)
            except requests.RequestException:
                continue
        # Surface attack surface: forms
        try:
            soup = BeautifulSoup(requests.get(self.target_url, timeout=TIMEOUT, headers=UA).text, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action:
                    self.add_result('info', f'Form → {action}', 'Potential XSS surface', form.prettify()[:200])
        except Exception:
            pass
        if not self.vulnerable:
            self.add_result('safe', 'No XSS Found', 'Target appears resistant to XSS attacks')
        return self.results


SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
    110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 1521: 'Oracle', 2049: 'NFS', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
}
HIGH_RISK_PORTS = {22, 3306, 3389, 5432, 6379, 27017}
COMMON_PORTS = list(SERVICES.keys())


class PortScanner(ScannerBase):
    def scan(self):
        domain = self.target_url.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
        try:
            ip = socket.gethostbyname(domain)
            self.add_result('info', 'Resolved IP', f'{domain} → {ip}', '')
        except socket.gaierror as e:
            self.add_result('error', 'DNS Resolution Failed', str(e), '')
            return self.results

        for port in COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((ip, port)) == 0:
                    sev = 'high' if port in HIGH_RISK_PORTS else 'low'
                    self.add_result(sev, f'Port {port} Open', f'{SERVICES[port]} service', f'{domain}:{port}')
                sock.close()
            except Exception:
                continue
        if not self.vulnerable:
            self.add_result('safe', 'No Open Ports Found', 'Common ports are closed or filtered')
        return self.results


DIRECTORIES = [
    'admin', 'login', 'backup', 'wp-admin', 'dashboard', 'config', '.git',
    'robots.txt', 'sitemap.xml', 'phpinfo.php', 'uploads', 'api', 'graphql',
    'swagger', 'docs', 'test', 'dev', 'staging', 'private', 'secret',
]


class DirectoryScanner(ScannerBase):
    def scan(self):
        for d in DIRECTORIES:
            try:
                r = requests.get(f"{self.target_url}/{d}", timeout=3, headers=UA)
                if r.status_code in (200, 301, 302, 403):
                    sev = 'high' if d in ('.git', 'admin', 'backup', 'config') else 'medium'
                    self.add_result(sev, f'Discovered: /{d}', f'HTTP {r.status_code}', r.url)
            except requests.RequestException:
                continue
        if not self.vulnerable:
            self.add_result('safe', 'No Directories Found', 'Common directories are not exposed')
        return self.results


SUBDOMAINS = [
    'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'blog', 'shop',
    'cdn', 'm', 'app', 'beta', 'staging', 'webmail', 'portal', 'cpanel',
    'whm', 'support', 'help', 'status', 'docs', 'wiki', 'remote', 'vpn',
    'secure', 'login', 'sso', 'cloud', 'demo',
]


class SubdomainScanner(ScannerBase):
    def scan(self):
        domain = self.target_url.replace('http://', '').replace('https://', '').split('/')[0]
        for sub in SUBDOMAINS:
            try:
                r = requests.get(f"http://{sub}.{domain}", timeout=3, headers=UA)
                if r.status_code < 400 or r.status_code == 403:
                    sev = 'high' if sub in ('admin', 'api', 'dev', 'test') else 'low'
                    self.add_result(sev, f'Subdomain: {sub}.{domain}', f'HTTP {r.status_code}', r.url)
            except requests.RequestException:
                continue
        if not self.vulnerable:
            self.add_result('safe', 'No Subdomains Found', 'No common subdomains discovered')
        return self.results


RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']


class DNSEnumerator(ScannerBase):
    def scan(self):
        domain = self.target_url.replace('http://', '').replace('https://', '').split('/')[0]
        for rtype in RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                for rdata in answers:
                    self.add_result('info', f'{rtype} Record', str(rdata), domain)
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                self.add_result('error', 'NXDOMAIN', f'Domain {domain} does not exist', '')
                break
            except Exception:
                continue
        if not self.vulnerable:
            self.add_result('safe', 'No DNS Records Found', 'Unable to resolve any DNS records')
        return self.results


SECURITY_HEADERS = {
    'Strict-Transport-Security': ('HSTS', True),
    'Content-Security-Policy': ('CSP', True),
    'X-Content-Type-Options': ('MIME-sniffing prevention', True),
    'X-Frame-Options': ('Clickjacking protection', True),
    'X-XSS-Protection': ('XSS filter', False),
    'Referrer-Policy': ('Referrer control', False),
    'Permissions-Policy': ('Feature control', False),
}


class HTTPHeadersScanner(ScannerBase):
    def scan(self):
        try:
            r = requests.get(self.target_url, timeout=TIMEOUT, headers=UA)
            headers = r.headers

            for hdr, (desc, critical) in SECURITY_HEADERS.items():
                if hdr in headers:
                    self.add_result('safe', f'{desc} Present', f'{hdr}: {headers[hdr]}', '')
                else:
                    sev = 'high' if critical else 'medium'
                    self.add_result(sev, f'Missing: {desc}', f'{hdr} header is not set', '')

            if 'Server' in headers:
                self.add_result('low', 'Server Info Disclosure', f'Server: {headers["Server"]}', '')
            if 'X-Powered-By' in headers:
                self.add_result('low', 'Technology Disclosure', f'X-Powered-By: {headers["X-Powered-By"]}', '')

            self.add_result('info', 'HTTP Response Code', str(r.status_code), self.target_url)
        except requests.RequestException as e:
            self.add_result('error', 'HTTP Scan Failed', str(e), '')

        if not self.vulnerable:
            self.add_result('safe', 'Security Headers OK', 'All critical security headers are present')
        return self.results
