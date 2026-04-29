/* SENTINEL — Alert Triage Module */

let alerts = [];
let mitreData = {};
let currentIdx = 0;
let score = 0;
let correct = 0;
let answered = 0;
let startTime = null;

async function initTriage() {
  [alerts, mitreData] = await Promise.all([
    fetch('data/alerts.json').then(r => r.json()),
    fetch('data/mitre.json').then(r => r.json())
  ]);

  startTime = Date.now();
  renderQueue();
  updateScoreDisplay();
}

function renderQueue() {
  const container = document.getElementById('alert-queue');
  if (!container) return;
  container.innerHTML = '';

  alerts.forEach((alert, idx) => {
    const card = buildAlertCard(alert, idx);
    container.appendChild(card);
  });

  updateProgress();
}

function buildAlertCard(alert, idx) {
  const div = document.createElement('div');
  div.className = 'alert-row animate-fade-in';
  div.id = `alert-${alert.id}`;
  div.style.animationDelay = `${idx * 0.04}s`;

  const severityIcons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };

  div.innerHTML = `
    <div class="alert-row-header">
      <div class="alert-icon alert-icon-${alert.severity}">
        ${severityIcons[alert.severity] || '⚪'}
      </div>
      <div style="flex:1;min-width:0;">
        <div class="flex items-center gap-2 mb-1">
          <span class="badge badge-${alert.severity}">${alert.severity.toUpperCase()}</span>
          <span class="badge badge-muted">${alert.source}</span>
          ${alert.mitreTactic ? `<span class="tag tag-teal" style="font-size:0.6rem;">${alert.mitreTactic}</span>` : ''}
          <span class="badge badge-${alert.difficulty === 'easy' ? 'low' : alert.difficulty === 'medium' ? 'medium' : 'high'}" style="margin-left:auto;">
            ${alert.difficulty}
          </span>
        </div>
        <div class="alert-title">${alert.title}</div>
        <div class="alert-meta">
          <span class="font-mono">${SENTINEL.formatTime(alert.timestamp)}</span>
          ${alert.mitreId ? ` · <span class="text-teal">${alert.mitreId}</span>` : ''}
        </div>
      </div>
    </div>

    <div class="alert-log">${alert.logSnippet}</div>

    <div class="triage-actions">
      <button class="btn btn-sm btn-tp" onclick="submitAnswer(${alert.id}, 'true_positive')">
        🚨 True Positive — Real Threat
      </button>
      <button class="btn btn-sm btn-fp" onclick="submitAnswer(${alert.id}, 'false_positive')">
        ✅ False Positive — Benign
      </button>
      <button class="btn btn-sm btn-esc" onclick="submitAnswer(${alert.id}, 'escalate')">
        ↑ Escalate to Analyst
      </button>
    </div>

    <div class="ai-reveal" id="reveal-${alert.id}"></div>
  `;

  return div;
}

function submitAnswer(alertId, answer) {
  const alert = alerts.find(a => a.id === alertId);
  if (!alert) return;

  const row = document.getElementById(`alert-${alertId}`);
  if (!row || row.classList.contains('answered')) return;

  row.classList.add('answered');

  /* Disable buttons */
  row.querySelectorAll('.triage-actions .btn').forEach(btn => {
    btn.disabled = true;
    btn.style.opacity = '0.5';
  });

  const isCorrect = answer === alert.correctAnswer;
  const pts = isCorrect ? (alert.difficulty === 'easy' ? 10 : alert.difficulty === 'medium' ? 15 : 20) : 0;

  if (isCorrect) {
    correct++;
    score += pts;
    SENTINEL.updateScore(pts);
    SENTINEL.toast(`+${pts} pts — Correct!`, 'success');
  } else {
    SENTINEL.toast(`Incorrect — AI would have caught this`, 'error');
  }

  answered++;

  /* Build AI reveal card */
  const reveal = document.getElementById(`reveal-${alertId}`);
  const answerLabels = { true_positive: '🚨 True Positive', false_positive: '✅ False Positive', escalate: '↑ Escalate' };
  const correctLabel = answerLabels[alert.correctAnswer];
  const yourLabel = answerLabels[answer];

  const tacticColor = alert.mitreTactic ? SENTINEL.mitreColor(alert.mitreTactic, mitreData) : '#6b7280';

  reveal.innerHTML = `
    <div class="ai-reveal-header">
      <span>🤖</span> AI Analysis — Confidence ${alert.aiConfidence}%
    </div>
    <div class="${isCorrect ? 'result-correct' : 'result-wrong'}">
      ${isCorrect ? '✓ Correct!' : '✗ Incorrect'} — You answered: <strong>${yourLabel}</strong>
      ${!isCorrect ? ` · Correct answer: <strong>${correctLabel}</strong>` : ''}
      ${isCorrect ? ` <span class="font-mono text-teal">+${pts} pts</span>` : ''}
    </div>
    <p style="font-size:0.8125rem;color:var(--text-muted);line-height:1.6;margin-bottom:0.625rem;">
      ${alert.aiExplanation}
    </p>
    <div class="ai-confidence-bar">
      <span class="ai-confidence-label">AI Confidence</span>
      <div class="progress-bar" style="flex:1;">
        <div class="progress-fill" style="width:${alert.aiConfidence}%;background:${alert.aiConfidence > 85 ? 'var(--teal)' : alert.aiConfidence > 60 ? 'var(--medium)' : 'var(--critical)'}"></div>
      </div>
      <span class="ai-confidence-val">${alert.aiConfidence}%</span>
    </div>
    ${alert.mitreTactic ? `
    <div class="flex items-center gap-2 mt-2">
      <span class="text-xs text-muted">MITRE ATT&CK:</span>
      <span class="tag" style="background:${tacticColor}20;border-color:${tacticColor}50;color:${tacticColor}">
        ${alert.mitreId} · ${alert.mitreTactic}
      </span>
    </div>` : ''}
  `;

  reveal.classList.add('show');
  updateScoreDisplay();
  updateProgress();

  /* Auto-scroll to next unanswered */
  setTimeout(() => {
    const next = document.querySelector('.alert-row:not(.answered)');
    if (next) next.scrollIntoView({ behavior: 'smooth', block: 'start' });
    else showDebrief();
  }, 300);
}

function updateScoreDisplay() {
  const el = document.getElementById('triage-score');
  if (el) el.textContent = score;

  const accEl = document.getElementById('triage-accuracy');
  if (accEl && answered > 0) {
    accEl.textContent = Math.round((correct / answered) * 100) + '%';
  }

  const answeredEl = document.getElementById('triage-answered');
  if (answeredEl) answeredEl.textContent = `${answered} / ${alerts.length}`;
}

function updateProgress() {
  const bar = document.getElementById('triage-progress');
  if (bar && alerts.length > 0) {
    bar.style.width = ((answered / alerts.length) * 100) + '%';
  }
}

function showDebrief() {
  const debrief = document.getElementById('triage-debrief');
  if (!debrief) return;

  const elapsed = Math.round((Date.now() - startTime) / 1000);
  const minutes = Math.floor(elapsed / 60);
  const seconds = elapsed % 60;
  const pct = Math.round((correct / alerts.length) * 100);
  const scoreClass = SENTINEL.scoreClass(pct);
  const scoreLabel = SENTINEL.scoreLabel(pct);

  const aiTime = Math.round(alerts.length * 0.8);

  debrief.innerHTML = `
    <div class="score-debrief">
      <div class="text-xs text-muted mb-2" style="text-transform:uppercase;letter-spacing:0.1em;">Triage Complete</div>
      <div class="stat-big ${scoreClass} mb-2">${pct}%</div>
      <div style="font-size:1rem;font-weight:600;color:var(--text-primary);margin-bottom:0.5rem;">${scoreLabel}</div>
      <div class="text-sm text-muted mb-4">You completed triage in ${minutes}m ${seconds}s · AI would complete in ~${aiTime}s</div>

      <div class="score-breakdown">
        <div class="score-row">
          <span class="score-row-label">Correct classifications</span>
          <span class="score-row-val text-low">${correct} / ${alerts.length}</span>
        </div>
        <div class="score-row">
          <span class="score-row-label">Triage score</span>
          <span class="score-row-val text-teal">${score} pts</span>
        </div>
        <div class="score-row">
          <span class="score-row-label">Your time</span>
          <span class="score-row-val">${minutes}m ${seconds}s</span>
        </div>
        <div class="score-row">
          <span class="score-row-label">AI triage time (same alerts)</span>
          <span class="score-row-val text-teal">~${aiTime}s</span>
        </div>
        <div class="score-row">
          <span class="score-row-label">Speed advantage (AI vs Human)</span>
          <span class="score-row-val text-teal">${Math.round(elapsed / aiTime)}× faster</span>
        </div>
      </div>

      <div class="flex gap-3 mt-4" style="justify-content:center;">
        <a href="investigate.html" class="btn btn-primary">Next: Investigate Scenarios →</a>
        <button onclick="resetTriage()" class="btn btn-secondary">Retry Triage</button>
      </div>
    </div>
  `;

  debrief.classList.remove('hidden');
  debrief.scrollIntoView({ behavior: 'smooth' });

  /* Save progress */
  const p = SENTINEL.getProgress();
  p.triageScore = score;
  p.triageTotal = alerts.length;
  p.triageCompleted = true;
  SENTINEL.saveProgress(p);
}

function resetTriage() {
  score = 0; correct = 0; answered = 0;
  startTime = Date.now();
  document.getElementById('triage-debrief').classList.add('hidden');
  renderQueue();
  updateScoreDisplay();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

document.addEventListener('DOMContentLoaded', initTriage);
