
#!/usr/bin/env python3
"""Local machine security scanners – system, firewall, ports, Wi-Fi, Windows, shares."""
import socket
import subprocess
import re
import platform
import getpass
from .base import ScannerBase


class LocalSystemInfoScanner(ScannerBase):
    def __init__(self):
        super().__init__('localhost')

    def scan(self):
        os_name = platform.system()
        self.add_result('info', 'Operating System', f'{os_name} {platform.release()} (Build {platform.version()})', '')
        self.add_result('info', 'Hostname', socket.gethostname(), '')
        self.add_result('info', 'Current User', getpass.getuser(), '')

        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                self.add_result('high', 'Running as Administrator',
                                'Admin privileges increase attack surface.', '')
            else:
                self.add_result('safe', 'Standard User', 'Limited privileges – good for security.', '')
        except Exception:
            pass

        # UAC check
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as k:
                uac, _ = winreg.QueryValueEx(k, "EnableLUA")
            if uac == 0:
                self.add_result('high', 'UAC Disabled', 'Malware can make system changes silently.', '')
            else:
                self.add_result('safe', 'UAC Enabled', 'User Account Control is active.', '')
        except Exception:
            pass

        # Screensaver lock timeout
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop") as k:
                timeout_sec = int(winreg.QueryValueEx(k, "ScreenSaveTimeOut")[0])
            if timeout_sec > 900:
                self.add_result('medium', 'Screen Lock Timeout Long',
                                f'{timeout_sec//60} min (recommended ≤15)', '')
            else:
                self.add_result('safe', 'Screen Lock Timeout OK', f'{timeout_sec//60} min', '')
        except Exception:
            pass

        # Process check for remote-access tools
        try:
            import psutil
            suspicious = ['remmina', 'vnc', 'anydesk', 'teamviewer', 'logmein']
            found = set()
            for proc in psutil.process_iter(['name']):
                try:
                    name = (proc.info['name'] or '').lower()
                    if any(s in name for s in suspicious):
                        found.add(proc.info['name'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            if found:
                self.add_result('medium', 'Remote Access Tools Running', ', '.join(found), '')
        except ImportError:
            self.add_result('info', 'Process Info', 'Install psutil for process analysis (pip install psutil)', '')

        if not self.vulnerable:
            self.add_result('info', 'System OK', 'Basic system security checks passed', '')
        return self.results


class FirewallScanner(ScannerBase):
    def __init__(self):
        super().__init__('localhost')

    def scan(self):
        try:
            r = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                               capture_output=True, text=True, timeout=10)
            if 'on' in r.stdout.lower():
                self.add_result('safe', 'Windows Firewall', 'Enabled for all profiles.', '')
            else:
                self.add_result('high', 'Windows Firewall Disabled', 'System exposed to network attacks.', '')
        except Exception as e:
            self.add_result('error', 'Firewall Check Failed', str(e), '')

        try:
            r = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all', 'dir=in'],
                               capture_output=True, text=True, timeout=10)
            rules = r.stdout.count('Rule Name:')
            self.add_result('info', 'Firewall Rules', f'{rules} inbound rules', '')
        except Exception:
            pass

        if not self.vulnerable:
            self.add_result('safe', 'Firewall OK', 'Configuration appears secure.', '')
        return self.results


class LocalPortScanner(ScannerBase):
    def __init__(self):
        super().__init__('localhost')

    def scan(self):
        try:
            r = subprocess.run(['netstat', '-ano', '-p', 'TCP'], capture_output=True, text=True, timeout=10)
            listening, pid_map = [], {}
            for line in r.stdout.split('\n'):
                if 'LISTENING' in line:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        port = parts[1].rsplit(':', 1)[-1]
                        pid = parts[-1]
                        listening.append({'port': port, 'pid': pid})
                        pid_map[pid] = pid_map.get(pid, 0) + 1

            if listening:
                low_ports = [p for p in listening if int(p['port']) < 1024]
                high_ports = [p for p in listening if int(p['port']) >= 49152]
                if low_ports:
                    self.add_result('medium', f'{len(low_ports)} Privileged Ports Open',
                                    'Ports <1024 require admin – potential attack surface.',
                                    ', '.join(p['port'] for p in low_ports[:10]))
                self.add_result('info', f'{len(listening)} Listening Ports',
                                f'{len(low_ports)} privileged, {len(high_ports)} ephemeral', '')
                if len(pid_map) > 100:
                    self.add_result('info', 'Many Active Processes', f'{len(pid_map)} unique PIDs listening', '')
            else:
                self.add_result('info', 'No Listening Ports', 'No TCP ports in LISTENING state.', '')
        except Exception as e:
            self.add_result('error', 'Port Scan Failed', str(e), '')

        if not self.vulnerable:
            self.add_result('safe', 'Local Ports OK', 'No unusual port activity.', '')
        return self.results


class WiFiSecurityScanner(ScannerBase):
    def __init__(self):
        super().__init__('localhost')

    def scan(self):
        try:
            r = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True, timeout=10)
            out = r.stdout
            if 'There is no wireless interface' in out:
                self.add_result('info', 'Wi-Fi Status', 'No wireless interface (wired connection).', '')
                return self.results

            ssid = self._extract(r'SSID\s+:\s(.+)', out) or 'Unknown'
            signal = self._extract(r'Signal\s+:\s(\d+)%', out) or '?'
            auth = self._extract(r'Authentication\s+:\s(.+)', out) or 'Unknown'
            cipher = self._extract(r'Cipher\s+:\s(.+)', out) or 'Unknown'

            self.add_result('info', f'Wi-Fi: {ssid}', f'Signal: {signal}% | Auth: {auth} | Cipher: {cipher}', '')

            if 'WEP' in auth:
                self.add_result('high', 'WEP Encryption', 'WEP is trivially cracked.', '')
            elif 'WPA2' in auth and ('TKIP' in cipher):
                self.add_result('medium', 'Weak Cipher (TKIP)', 'WPA2 with TKIP is less secure.', '')
            elif 'WPA3' in auth:
                self.add_result('safe', 'WPA3 Encryption', 'Latest wireless security standard.', '')
            elif 'Open' in auth or 'None' in auth:
                self.add_result('high', 'Open Wi-Fi', 'No encryption! All traffic visible.', '')
            else:
                self.add_result('safe' if 'AES' in cipher or 'CCMP' in cipher else 'medium',
                                f'Encryption: {auth}', f'Cipher: {cipher}', '')

            profiles = subprocess.run(['netsh', 'wlan', 'show', 'profiles'],
                                      capture_output=True, text=True, timeout=10)
            count = profiles.stdout.count('All User Profile')
            self.add_result('info', 'Saved Wi-Fi Networks', f'{count} profiles stored.', '')
        except Exception as e:
            self.add_result('error', 'Wi-Fi Check Failed', str(e), '')

        if not self.vulnerable:
            self.add_result('safe', 'Wi-Fi Security OK', 'Wireless configuration appears secure.', '')
        return self.results

    @staticmethod
    def _extract(pattern, text, default=None):
        m = re.search(pattern, text)
        return m.group(1).strip() if m else default


class WindowsSecurityScanner(ScannerBase):
    def __init__(self):
        super().__init__('localhost')

    def _ps(self, cmd):
        try:
            return subprocess.run(['powershell', '-Command', cmd],
                                  capture_output=True, text=True, timeout=15).stdout
        except Exception:
            return ''

    def scan(self):
        # Defender
        out = self._ps('Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled')
        if 'True' in out:
            self.add_result('safe', 'Windows Defender', 'Real-time protection active.', '')
        else:
            self.add_result('high', 'Defender Disabled', 'Antivirus real-time protection is off!', '')

        # BitLocker
        out = self._ps('Get-BitLockerVolume -MountPoint C: | Select-Object ProtectionStatus')
        if 'On' in out:
            self.add_result('safe', 'BitLocker', 'Drive encryption active on C:.', '')
        else:
            self.add_result('medium', 'BitLocker Disabled', 'Data at risk if device is stolen.', '')

        # Guest account
        out = self._ps('Get-LocalUser -Name "Guest" | Select-Object Enabled')
        if 'True' in out:
            self.add_result('high', 'Guest Account Enabled', 'Disable to prevent unauthorized access.', '')
        else:
            self.add_result('safe', 'Guest Account', 'Guest account is disabled.', '')

        # Password expiry
        out = self._ps('net accounts')
        m = re.search(r'Maximum password age\s*:\s*(\d+)', out)
        if m:
            days = int(m.group(1))
            if days > 90:
                self.add_result('medium', 'Password Expires Every {days} Days',
                                'Recommended: 60–90 days max.', '')
            else:
                self.add_result('safe', f'Password Expires Every {days} Days', '', '')

        if not self.vulnerable:
            self.add_result('safe', 'Windows Security OK', 'All Windows security checks passed.', '')
        return self.results


class NetworkShareScanner(ScannerBase):
    def __init__(self):
        super().__init__('localhost')

    def scan(self):
        try:
            r = subprocess.run(['net', 'share'], capture_output=True, text=True, timeout=10)
            shares = [line.strip().split()[0] for line in r.stdout.split('\n')
                      if '\\' in line and not line.startswith('The command') and line.strip()]
            admin = [s for s in shares if s.endswith('$')]
            user = [s for s in shares if not s.endswith('$')]

            if user:
                self.add_result('medium', 'User Shares Found',
                                f'Shared: {", ".join(user)}', 'Audit permissions.')
            else:
                self.add_result('safe', 'No User Shares', 'No user-created network shares.', '')

            self.add_result('info', f'{len(shares)} Total Shares',
                            f'{len(admin)} admin, {len(user)} user', '')
        except Exception as e:
            self.add_result('error', 'Share Check Failed', str(e), '')

        if not self.vulnerable:
            self.add_result('safe', 'Network Shares OK', 'No unauthorized sharing detected.', '')
        return self.results
