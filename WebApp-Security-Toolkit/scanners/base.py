
#!/usr/bin/env python3
"""Base scanner class with safe defaults and error handling."""


class ScanError(Exception):
    """Custom exception for scanner failures."""
    pass


class ScannerBase:
    """Thread-safe base scanner with fallback behavior."""

    def __init__(self, target_url, scan_id=None):
        self.target_url = (target_url or '').rstrip('/')
        self.scan_id = scan_id
        self.results = []
        self._vulnerable = False
        self.timeout = 10

    @property
    def vulnerable(self):
        return self._vulnerable

    def add_result(self, severity, title, description, detail=''):
        """Add a finding with severity validation."""
        valid = {'high', 'medium', 'low', 'info', 'safe', 'error'}
        sev = severity.lower() if severity in valid else 'info'
        if sev in ('high', 'medium', 'low'):
            self._vulnerable = True
        self.results.append({
            'severity': sev,
            'title': str(title)[:200],
            'description': str(description)[:500],
            'detail': str(detail)[:1000],
        })

    def scan(self):
        """Override in subclass. Must return list of findings."""
        raise NotImplementedError

    def safe_scan(self):
        """Wrapper that never raises – returns results or error finding."""
        try:
            return self.scan()
        except Exception as e:
            self.results = [{
                'severity': 'error',
                'title': 'Scan Failed',
                'description': f'{type(e).__name__}: {e}',
                'detail': '',
            }]
            return self.results
