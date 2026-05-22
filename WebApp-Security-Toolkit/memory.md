
# Project Memory

## Network Security Toolkit Web App
- **Type**: Flask web application with Socket.IO real-time features
- **Port**: 5000
- **Database**: SQLite (scans.db)

## Architecture


## Key Design Decisions
- **Fail-safe**: Every scanner has `safe_scan()` that catches all exceptions → returns error finding
- **No CSS/JS duplication**: All shared styles in `main.css`, shared logic in `main.js`
- **Thread safety**: `db.session.begin()` context manager, `daemon=True` threads
- **Stateless templates**: Templates use only `{{ url_for }}` for static assets; no embedded styles/blocks
- **App context for background threads**: Both `run_remote_scan()` and `run_local_scan()` accept `app` as first arg and wrap thread logic in `with app.app_context():`

## Routes
| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Remote scan dashboard |
| `/local` | GET | Local security audit page |
| `/scans` | GET | Scan history |
| `/scan/<id>` | GET | Scan detail view |
| `/api/start_scan` | POST | Start remote scan |
| `/api/start_local_scan` | POST | Start local audit |
| `/api/bulk_scan` | POST | Start bulk scan |
| `/api/export/<id>/<fmt>` | GET | Export JSON/CSV/TXT |
| `/api/delete_scan/<id>` | DELETE | Delete scan |

## To run: `python app.py`

## Known Issues
- **Stale server processes**: Kill all PIDs on :5000 with `taskkill /F /PID <pid>` before restarting
- **psutil**: Not installed by default; process scanner degrades gracefully with `ImportError`
- **Pending scans from before fix**: Scans started before app_context fix (IDs 9-12) show "pending" forever; they can be deleted via UI

## Fixed Issues
- **RuntimeError: Working outside of application context**: Fixed in `utils/orchestrator.py` by wrapping background thread logic inside `with app.app_context():`. Also updated `app.py` to pass `app` as first arg to both `run_remote_scan()` and `run_local_scan()`.

scans.db should be ignored when pushing commit
