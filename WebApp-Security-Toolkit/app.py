
#!/usr/bin/env python3
"""
Network Security Toolkit – Web Application
Minimal entry-point. All logic lives in scanners/ and utils/.
"""
import os
import json

from flask import Flask, render_template, request, jsonify, Response
from flask_socketio import SocketIO, emit

from utils.database import db, ScanHistory
from utils.orchestrator import run_remote_scan, run_local_scan

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.urandom(24).hex(),
    SQLALCHEMY_DATABASE_URI='sqlite:///scans.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)
db.init_app(app)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

with app.app_context():
    db.create_all()

# ---------------------------------------------------------------------------
# Web routes
# ---------------------------------------------------------------------------
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
    return render_template('scan_detail.html', scan=record.to_dict(), results=record.get_results())

# ---------------------------------------------------------------------------
# API – start scans
# ---------------------------------------------------------------------------
@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get('target_url') or '').strip()
    scan_types = data.get('scan_types', ['all'])
    if not target:
        return jsonify({'error': 'Target URL is required'}), 400
    if not target.startswith(('http://', 'https://')):
        target = f'https://{target}'

    record = ScanHistory(target_url=target, scan_type=','.join(scan_types), status='pending')
    db.session.add(record)
    db.session.commit()

    run_remote_scan(target, scan_types, record.id, socketio)
    return jsonify({'scan_id': record.id, 'status': 'started'})


@app.route('/api/start_local_scan', methods=['POST'])
def start_local_scan():
    data = request.get_json(silent=True) or {}
    scan_types = data.get('scan_types', ['all'])

    record = ScanHistory(target_url='LOCAL_MACHINE', scan_type=','.join(scan_types), status='pending')
    db.session.add(record)
    db.session.commit()

    run_local_scan(scan_types, record.id, socketio)
    return jsonify({'scan_id': record.id, 'status': 'started'})


@app.route('/api/bulk_scan', methods=['POST'])
def bulk_scan():
    data = request.get_json(silent=True) or {}
    targets = data.get('targets', [])
    if not targets:
        return jsonify({'error': 'At least one target is required'}), 400

    scan_ids = []
    for t in targets:
        if not t.startswith(('http://', 'https://')):
            t = f'https://{t}'
        record = ScanHistory(target_url=t, scan_type='all', status='pending')
        db.session.add(record)
        db.session.commit()
        run_remote_scan(t, ['all'], record.id, socketio)
        scan_ids.append(record.id)

    return jsonify({'scan_ids': scan_ids, 'status': 'started'})

# ---------------------------------------------------------------------------
# API – export / delete
# ---------------------------------------------------------------------------
@app.route('/api/export/<int:scan_id>/<fmt>')
def export_scan(scan_id, fmt):
    record = ScanHistory.query.get_or_404(scan_id)
    results = record.get_results()
    started = record.started_at.isoformat() if record.started_at else ''
    completed = record.completed_at.isoformat() if record.completed_at else ''

    if fmt == 'json':
        return jsonify({
            'target': record.target_url,
            'scan_type': record.scan_type,
            'started_at': started,
            'completed_at': completed,
            'results': results,
        })

    lines = []
    if fmt == 'csv':
        lines.append('severity,scan_type,title,description,detail')
        for stype, findings in results.items():
            for f in findings:
                lines.append(
                    f'"{f.get("severity","")}","{stype}","{f.get("title","")}",'
                    f'"{f.get("description","")}","{f.get("detail","")}"'
                )
        return Response('\n'.join(lines), mimetype='text/csv',
                        headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}.csv'})

    if fmt == 'txt':
        lines = [
            "Network Security Toolkit Scan Report",
            "=" * 40,
            f"Target: {record.target_url}",
            f"Date: {started}",
            f"Status: {record.status}",
            "",
        ]
        icons = {'high': '🔴', 'medium': '🟠', 'low': '🟡', 'info': 'ℹ️', 'safe': '✅', 'error': '❌'}
        for stype, findings in results.items():
            lines.append(f"\n--- {stype.upper()} ---")
            for f in findings:
                sev = f.get('severity', '')
                lines.append(f"  {icons.get(sev, '•')} [{sev.upper()}] {f.get('title','')}: {f.get('description','')}")
        return Response('\n'.join(lines), mimetype='text/plain',
                        headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}.txt'})

    return jsonify({'error': f'Unsupported format: {fmt}'}), 400


@app.route('/api/delete_scan/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    record = ScanHistory.query.get_or_404(scan_id)
    db.session.delete(record)
    db.session.commit()
    return jsonify({'status': 'deleted'})

# ---------------------------------------------------------------------------
# Socket.IO
# ---------------------------------------------------------------------------
@socketio.on('connect')
def handle_connect():
    emit('connected', {'data': 'Connected to scan server'})

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    print("=" * 50)
    print("  Network Security Toolkit – Web Dashboard")
    print("  http://0.0.0.0:5000")
    print("=" * 50)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True, use_reloader=False)
