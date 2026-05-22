
import React from 'react';
import './App.css';

function App() {
  return (
    <div className="app">
      <header className="app-header">
        <h1>DevSecOps Pipeline Demo</h1>
        <p className="subtitle">Automated Security-First Deployment</p>
      </header>
      <main className="app-main">
        <section className="pipeline-status">
          <h2>Pipeline Security Gates</h2>
          <div className="gate-list">
            <div className="gate">
              <span className="gate-icon">🔍</span>
              <div className="gate-info">
                <h3>Secret Scanning</h3>
                <p>TruffleHog scans for leaked credentials</p>
              </div>
            </div>
            <div className="gate">
              <span className="gate-icon">📦</span>
              <div className="gate-info">
                <h3>Dependency Scanning</h3>
                <p>Trivy checks for vulnerable packages</p>
              </div>
            </div>
            <div className="gate">
              <span className="gate-icon">⚡</span>
              <div className="gate-info">
                <h3>Static Analysis</h3>
                <p>Semgrep finds code logic flaws</p>
              </div>
            </div>
            <div className="gate">
              <span className="gate-icon">🐳</span>
              <div className="gate-info">
                <h3>Container Security</h3>
                <p>Trivy scans Docker images</p>
              </div>
            </div>
          </div>
        </section>
        <section className="pipeline-flow">
          <h2>Pipeline Flow</h2>
          <div className="flow-steps">
            <div className="step completed">Push Code</div>
            <div className="step arrow">→</div>
            <div className="step active">Secret Scan</div>
            <div className="step arrow">→</div>
            <div className="step">Dependency Scan</div>
            <div className="step arrow">→</div>
            <div className="step">Static Analysis</div>
            <div className="step arrow">→</div>
            <div className="step">Container Scan</div>
            <div className="step arrow">→</div>
            <div className="step">Deploy</div>
          </div>
        </section>
      </main>
      <footer className="app-footer">
        <p>Secured with ❤️ using Open Source Tools</p>
      </footer>
    </div>
  );
}

export default App;
