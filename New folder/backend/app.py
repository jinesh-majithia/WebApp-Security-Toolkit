
from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({
        "service": "DevSecOps Backend API",
        "status": "healthy",
        "version": "1.0.0"
    })

@app.route('/health')
def health():
    return jsonify({"status": "ok"}), 200

@app.route('/api/pipeline')
def pipeline_status():
    return jsonify({
        "pipeline": "DevSecOps Secure Deployment Pipeline",
        "security_gates": [
            {"name": "Secret Scanning", "tool": "TruffleHog", "status": "pass"},
            {"name": "Dependency Scanning", "tool": "Trivy", "status": "pass"},
            {"name": "Static Analysis", "tool": "Semgrep", "status": "pass"},
            {"name": "Container Security", "tool": "Trivy", "status": "pass"}
        ]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
