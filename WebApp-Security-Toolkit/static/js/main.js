
/* ============================================================
   Network Security Toolkit – Shared JavaScript
   ============================================================ */

// ----- Socket.IO connection -----
const socket = io();

socket.on('connect', () => console.log('🔗 Connected to scan server'));

// ----- Toast helper -----
function showToast(message, type = 'info') {
    const container = document.querySelector('.toast-container');
    if (!container) return;
    const el = document.createElement('div');
    el.className = `toast align-items-center text-bg-${type} border-0`;
    el.role = 'alert';
    el.innerHTML = `<div class="d-flex">
        <div class="toast-body">${message}</div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>`;
    container.appendChild(el);
    const bsToast = new bootstrap.Toast(el);
    bsToast.show();
    el.addEventListener('hidden.bs.toast', () => el.remove());
}

// ----- Stats update -----
function updateStats(stats) {
    const map = { high: 'statsHigh', safe: 'statsSafe', info: 'statsInfo', total: 'statsTotal' };
    for (const [key, id] of Object.entries(map)) {
        const el = document.getElementById(id);
        if (el) el.textContent = stats[key] ?? 0;
    }
}

// ----- Result rendering -----
function renderResults(containerId, allResults) {
    const container = document.getElementById(containerId);
    if (!container) return;

    let html = '';
    for (const [scanType, findings] of Object.entries(allResults)) {
        html += `<div class="terminal-header mb-2">
            <span class="text-uppercase fw-bold">🔍 ${scanType.replace(/_/g, ' ')}</span>
            <span class="badge bg-${findings.some(f => f.severity === 'high' || f.severity === 'medium') ? 'danger' : 'secondary'} ms-2">${findings.length} checks</span>
        </div>`;
        for (const f of findings) {
            const icons = { high: '🔴', medium: '🟠', low: '🟡', info: 'ℹ️', safe: '✅', error: '❌' };
            const sev = f.severity || 'info';
            const badgeClass = sev === 'high' ? 'danger' : sev === 'medium' ? 'warning text-dark' : sev === 'low' ? 'info' : sev === 'safe' ? 'success' : 'secondary';
            html += `<div class="result-item severity-${sev}">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <strong>${f.title || ''}</strong>
                        <p class="mb-0 text-secondary small">${f.description || ''}</p>
                        ${f.detail ? `<code class="small text-info">${f.detail}</code>` : ''}
                    </div>
                    <span class="badge bg-${badgeClass}">${sev}</span>
                </div>
            </div>`;
        }
    }
    container.innerHTML = html;
}

// ----- Scan type selector (local & remote) -----
function toggleScanType(el) {
    const isAll = el.dataset.scan === 'all';
    if (isAll) {
        document.querySelectorAll('.scan-type-card').forEach(c => c.classList.remove('selected'));
        el.classList.add('selected');
    } else {
        document.querySelector('[data-scan="all"]')?.classList.remove('selected');
        el.classList.toggle('selected');
        // If nothing selected, re-select "All"
        if (!document.querySelectorAll('.scan-type-card.selected').length) {
            document.querySelector('[data-scan="all"]')?.classList.add('selected');
        }
    }
}

function getSelectedScanTypes() {
    const selected = document.querySelectorAll('.scan-type-card.selected');
    const scans = Array.from(selected).map(el => el.dataset.scan);
    return scans.includes('all') ? ['all'] : (scans.length ? scans : ['all']);
}

// ----- Progress bar helper -----
function startProgressBar(intervalMs = 800) {
    const bar = document.getElementById('progressFill');
    if (!bar) return null;
    let progress = 0;
    const id = setInterval(() => {
        progress += 5;
        bar.style.width = Math.min(progress, 90) + '%';
        if (progress >= 90) clearInterval(id);
    }, intervalMs);
    return id;
}
</code_snippet_output>
