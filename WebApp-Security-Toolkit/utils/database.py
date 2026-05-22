
#!/usr/bin/env python3
"""Database models and initialization for Network Security Toolkit."""
import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class ScanHistory(db.Model):
    __tablename__ = 'scan_history'
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
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        }

    def get_results(self):
        try:
            return json.loads(self.results) if self.results else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_results(self, data):
        self.results = json.dumps(data, indent=2, default=str)
