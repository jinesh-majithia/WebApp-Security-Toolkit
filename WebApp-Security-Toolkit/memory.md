
# Project Memory

## Network Security Toolkit Web App
- **Type**: Flask web application with Socket.IO real-time features
- **Port**: 5000
- **Database**: SQLite (scans.db)

## Architecture
- `app.py` - Main Flask application with all scanner logic embedded
- `templates/index.html` - Dashboard with scan UI
- `templates/index.html` - Dashboard with remote scan UI
- `templates/local_scan.html` - Local security audit page
- `templates/scans.html` - Scan history listing
- `templates/scan_detail.html` - Individual scan report view

## Built-in Scanners (8 modules):
## Routes
- `/` - Dashboard (remote scans)
- `/local` - Local security audit page
- `/scans` - Scan history
- `/scan/<id>` - Scan detail view
- `/api/start_scan` - Start remote scan (POST)
- `/api/start_local_scan` - Start local audit (POST)
- `/api/bulk_scan` - Start bulk scan (POST)
- `/api/export/<id>/<fmt>` - Export results (json/csv/txt)
- `/api/delete_scan/<id>` - Delete scan (DELETE)

## Built-in Scanners (Remote - 7 modules):
1. SQL Injection Scanner
2. XSS Scanner  
3. Port Scanner (23 common ports)
4. Directory Scanner (20+ common dirs)
5. Subdomain Scanner (25+ common subdomains)
6. DNS Enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
7. HTTP Headers Security Analyzer (HSTS, CSP, X-Frame-Options, etc.)
8. All-in-one mode

## Built-in Scanners (Local - 6 modules):
1. System Info Scanner - OS, user, admin status, UAC, process info
2. Firewall Scanner - Firewall state, rules analysis
3. Local Port Scanner - netstat-based listening port detection
4. Wi-Fi Security Scanner - SSID, encryption type, signal strength
5. Windows Security Scanner - Defender, BitLocker, Guest account, password policy
6. Network Share Scanner - Shared folders and admin shares

## Features:
- Asynchronous scanning via threading
- Real-time results via Socket.IO
- CSV/JSON/TXT export
- Bulk scan support
- Scan history with SQLite persistence
- Dark theme UI with animated background
- Local machine security auditing (no target URL needed)

## To run: `python app.py`

## Known Issues / Fixes:
- **Stale server processes**: Multiple Flask instances on port 5000 cause routing issues. Kill all PIDs on :5000 with `taskkill /F /PID <pid>` before restarting.
