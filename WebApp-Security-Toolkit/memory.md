
# Project Memory

## Network Security Toolkit Web App
- **Type**: Flask web application with Socket.IO real-time features
- **Port**: 5000
- **Database**: SQLite (scans.db)

## Architecture
- `app.py` - Main Flask application with all scanner logic embedded
- `templates/index.html` - Dashboard with scan UI
- `templates/scans.html` - Scan history listing
- `templates/scan_detail.html` - Individual scan report view

## Built-in Scanners (8 modules):
1. SQL Injection Scanner
2. XSS Scanner  
3. Port Scanner (23 common ports)
4. Directory Scanner (20+ common dirs)
5. Subdomain Scanner (25+ common subdomains)
6. DNS Enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
7. HTTP Headers Security Analyzer (HSTS, CSP, X-Frame-Options, etc.)
8. All-in-one mode

## Features:
- Asynchronous scanning via threading
- Real-time results via Socket.IO
- CSV/JSON/TXT export
- Bulk scan support
- Scan history with SQLite persistence
- Dark theme UI with animated background

## To run: `python app.py`
