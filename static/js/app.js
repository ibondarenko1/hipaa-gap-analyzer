function setStatus(controlId, status, btn) {
    const row = document.getElementById('row-' + controlId);
    row.querySelectorAll('.sbtn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    row.className = row.className.replace(/\b(compliant|partial|non_compliant|not_assessed)\b/g, '').trim() + ' ' + status;
    row.dataset.status = status;

    // Show/hide remediation
    const rem = row.querySelector('.remediation');
    if (rem) rem.style.display = (status === 'non_compliant' || status === 'not_assessed') ? 'block' : 'none';

    const notes = row.querySelector('.notes').value;
    fetch('/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ control_id: controlId, status, notes })
    }).then(r => r.json()).then(d => {
        if (d.success) { updateStats(d.stats); showToast('Saved: ' + controlId); }
    });
}

function saveNotes(controlId, notes) {
    const row = document.getElementById('row-' + controlId);
    const status = row.dataset.status || 'not_assessed';
    fetch('/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ control_id: controlId, status, notes })
    }).then(r => r.json()).then(d => {
        if (d.success && notes.trim()) showToast('Notes saved');
    });
}

function updateStats(s) {
    document.getElementById('s-compliant').textContent = s.compliant;
    document.getElementById('s-partial').textContent = s.partial;
    document.getElementById('s-gap').textContent = s.non_compliant;
    document.getElementById('s-critical').textContent = s.critical_gaps;
    document.getElementById('s-score').textContent = s.risk_score + '%';

    const rl = document.getElementById('risk-level');
    rl.textContent = s.risk_level;
    rl.className = 'risk-level ' + s.risk_level.toLowerCase();

    const circle = document.getElementById('score-circle');
    const offset = 251.3 - (251.3 * s.risk_score / 100);
    circle.style.strokeDashoffset = offset;
    circle.style.stroke = s.risk_score >= 80 ? '#22c55e' : s.risk_score >= 60 ? '#f59e0b' : '#ef4444';

    const total = s.total;
    document.getElementById('bar-compliant').style.width = (s.compliant / total * 100) + '%';
    document.getElementById('bar-partial').style.width = (s.partial / total * 100) + '%';
    document.getElementById('bar-gap').style.width = (s.non_compliant / total * 100) + '%';
}

function filterControls(filter, btn) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    document.querySelectorAll('.control-row').forEach(row => {
        const status = row.dataset.status || 'not_assessed';
        const risk = row.dataset.risk;
        if (filter === 'all') row.classList.remove('hidden');
        else if (filter === 'critical') row.classList.toggle('hidden', risk !== 'critical');
        else if (filter === 'not_assessed') row.classList.toggle('hidden', status !== 'not_assessed');
        else row.classList.toggle('hidden', status !== filter);
    });
}

function toggleSection(header) {
    const body = header.nextElementSibling;
    const chevron = header.querySelector('.chevron');
    body.classList.toggle('open');
    chevron.style.transform = body.classList.contains('open') ? 'rotate(90deg)' : 'rotate(0)';
}

function showToast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2000);
}
