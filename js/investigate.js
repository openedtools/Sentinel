/* SENTINEL — Incident Investigation Module */

let scenarios = [];
let mitreData = {};
let activeScenario = null;
let currentDecisionIdx = 0;
let scenarioScore = 0;
let decisionsAnswered = 0;
let decisionsCorrect = 0;

async function initInvestigation() {
  [scenarios, mitreData] = await Promise.all([
    fetch('data/scenarios.json').then(r => r.json()),
    fetch('data/mitre.json').then(r => r.json())
  ]);

  /* Check if a scenario was requested via URL param */
  const params = new URLSearchParams(window.location.search);
  const reqId = params.get('scenario');
  if (reqId) {
    const s = scenarios.find(x => x.id === reqId);
    if (s) { loadScenario(s); return; }
  }

  renderScenarioPicker();
}

/* ── Scenario picker (shown when no scenario active) ── */
function renderScenarioPicker() {
  const container = document.getElementById('investigation-root');
  if (!container) return;

  const progress = SENTINEL.getProgress();

  container.innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">🔍 Incident Investigation</div>
        <div class="page-subtitle">Choose a scenario to investigate. Each is drawn directly from your Day 3 course content.</div>
      </div>
    </div>
    <div class="grid-2" style="gap:1rem;">
      ${scenarios.map(s => buildScenarioPickCard(s, progress)).join('')}
    </div>`;
}

function buildScenarioPickCard(s, progress) {
  const completed = (progress.scenariosCompleted || []).includes(s.id);
  const scored = progress.scenarioScores?.[s.id];

  return `
    <div class="scenario-card ${completed ? 'completed' : ''}">
      ${completed ? `<div class="scenario-complete-badge">✓ Completed ${scored ? '· ' + scored + ' pts' : ''}</div>` : ''}
      <div class="scenario-icon">${s.icon}</div>
      <div class="scenario-name">${s.name}</div>
      <div class="scenario-sub">${s.subtitle}</div>
      <div class="scenario-desc">${s.description}</div>
      <div class="scenario-tags">
        <span class="badge badge-${s.difficulty}">${s.difficulty}</span>
        <span class="tag">${s.topic}</span>
      </div>
      <div style="margin-bottom:0.75rem;">
        <div class="text-xs text-muted mb-1">Objectives:</div>
        ${s.objectives.map(o => `<div class="text-xs" style="color:var(--text-muted);line-height:1.6;padding-left:8px;">· ${o}</div>`).join('')}
      </div>
      <button class="btn btn-primary btn-full" onclick="loadScenarioById('${s.id}')">
        ${completed ? '↩ Replay Scenario' : '▶ Start Investigation'}
      </button>
    </div>`;
}

function loadScenarioById(id) {
  const s = scenarios.find(x => x.id === id);
  if (s) loadScenario(s);
}

/* ── Load and render a scenario ── */
function loadScenario(scenario) {
  activeScenario = scenario;
  currentDecisionIdx = 0;
  scenarioScore = 0;
  decisionsAnswered = 0;
  decisionsCorrect = 0;

  const container = document.getElementById('investigation-root');
  if (!container) return;

  container.innerHTML = buildScenarioLayout(scenario);
  renderTimeline(scenario);
  renderCurrentDecision(scenario);
}

function buildScenarioLayout(s) {
  return `
    <div class="page-header">
      <div class="flex items-center gap-3">
        <button onclick="renderScenarioPicker()" class="btn btn-ghost btn-sm">← All Scenarios</button>
        <div>
          <div class="flex items-center gap-2">
            <span style="font-size:1.25rem">${s.icon}</span>
            <span class="page-title">${s.name}</span>
            <span class="badge badge-${s.difficulty}">${s.difficulty}</span>
          </div>
          <div class="page-subtitle">${s.subtitle} · ${s.topic}</div>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <span class="text-xs text-muted">Score:</span>
        <span class="font-mono text-teal" id="scenario-score-display">0 pts</span>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 360px;gap:1rem;">

      <!-- Left: Timeline -->
      <div>
        <div class="card mb-3" style="background:rgba(0,212,216,0.04);border-color:rgba(0,212,216,0.2);">
          <div style="font-weight:600;color:var(--text-primary);margin-bottom:4px;">Mission Briefing</div>
          <p class="text-sm" style="line-height:1.7;">${s.description}</p>
        </div>

        <div class="card">
          <div class="card-header">
            <div class="card-title">Attack Timeline</div>
            <div class="flex gap-3 text-xs text-muted">
              <span style="color:var(--critical)">■</span> Attack
              <span style="color:var(--low)">■</span> Defense
              <span style="color:var(--medium)">■</span> Decision
            </div>
          </div>
          <div class="timeline" id="scenario-timeline"></div>
        </div>
      </div>

      <!-- Right: Decision panel + objectives -->
      <div style="display:flex;flex-direction:column;gap:1rem;">

        <!-- Decision panel -->
        <div class="card" id="decision-panel" style="border-color:rgba(245,158,11,0.3);background:rgba(245,158,11,0.03);">
          <div id="decision-content">
            <div class="text-xs text-muted">Read through the timeline, then answer the decision questions below.</div>
          </div>
        </div>

        <!-- Progress -->
        <div class="card">
          <div class="card-title mb-2">Your Progress</div>
          <div class="flex justify-between text-xs mb-2">
            <span class="text-muted">Decisions answered</span>
            <span class="font-mono" id="decisions-answered">0 / ${s.decisions.length}</span>
          </div>
          <div class="progress-bar mb-3">
            <div class="progress-fill" id="decision-progress" style="width:0%"></div>
          </div>
          <div class="flex justify-between text-xs">
            <span class="text-muted">Scenario score</span>
            <span class="font-mono text-teal" id="scenario-score-sidebar">0 pts</span>
          </div>
        </div>

        <!-- Objectives -->
        <div class="card">
          <div class="card-title mb-2">Learning Objectives</div>
          ${s.objectives.map((o, i) => `
            <div class="flex items-start gap-2 mb-2" id="obj-${i}">
              <span style="color:var(--text-dim);font-size:1rem;flex-shrink:0;">○</span>
              <span class="text-xs" style="color:var(--text-muted);line-height:1.5;">${o}</span>
            </div>`).join('')}
        </div>

        <!-- MITRE reference for this scenario -->
        <div class="card">
          <div class="card-title mb-2">MITRE ATT&CK® in This Scenario</div>
          <div id="scenario-mitre"></div>
        </div>

      </div>
    </div>

    <!-- Debrief (hidden until complete) -->
    <div id="scenario-debrief" class="hidden mt-4"></div>`;
}

/* ── Render timeline events ── */
function renderTimeline(scenario) {
  const container = document.getElementById('scenario-timeline');
  if (!container) return;

  const mitreEl = document.getElementById('scenario-mitre');
  const tactics = new Set();

  container.innerHTML = scenario.events.map((event, idx) => {
    if (event.mitreTactic) tactics.add(event.mitreTactic);

    const typeClass = event.type === 'attack' ? 'attack' :
                      event.type === 'defense' ? 'defense' : 'decision';
    const delay = idx * 0.07;

    return `
      <div class="timeline-event animate-fade-in" style="animation-delay:${delay}s;">
        <div class="timeline-dot timeline-dot-${typeClass}"></div>
        <div class="timeline-time">${event.time}</div>
        <div class="timeline-card ${typeClass}" onclick="toggleEventDetail(this)">
          <div class="timeline-card-title">
            ${event.type === 'attack' ? '🔴' : event.type === 'defense' ? '🟢' : '🟡'}
            ${event.title}
            ${event.mitreTactic ? `<span class="tag tag-${typeClass === 'attack' ? 'attack' : 'teal'}" style="margin-left:6px;font-size:0.6rem;">${event.mitreId} · ${event.mitreTactic}</span>` : ''}
          </div>
          <div class="timeline-card-detail" style="display:none;margin-top:6px;">${event.detail}
            ${event.aiNote ? `<div class="timeline-ai-note mt-2">🤖 <strong>AI Note:</strong> ${event.aiNote}</div>` : ''}
          </div>
        </div>
      </div>`;
  }).join('');

  /* MITRE tactics used in this scenario */
  if (mitreEl) {
    const tacticList = [...tactics];
    if (tacticList.length === 0) {
      mitreEl.innerHTML = '<div class="text-xs text-muted">No MITRE tactics in this scenario.</div>';
    } else {
      mitreEl.innerHTML = tacticList.map(t => {
        const info = mitreData.tactics.find(x => x.name === t);
        const color = info ? info.color : '#6b7280';
        return `<div class="tag mb-1" style="background:${color}15;border-color:${color}40;color:${color};display:inline-flex;margin-right:4px;">
          ${t}
        </div>`;
      }).join('');
    }
  }
}

function toggleEventDetail(card) {
  const detail = card.querySelector('.timeline-card-detail');
  if (detail) {
    detail.style.display = detail.style.display === 'none' ? 'block' : 'none';
  }
}

/* ── Decision rendering ── */
function renderCurrentDecision(scenario) {
  const panel = document.getElementById('decision-content');
  if (!panel) return;

  if (currentDecisionIdx >= scenario.decisions.length) {
    showScenarioDebrief(scenario);
    return;
  }

  const decision = scenario.decisions[currentDecisionIdx];

  panel.innerHTML = `
    <div class="flex items-center gap-2 mb-3">
      <span style="background:var(--medium);color:#000;border-radius:50%;width:22px;height:22px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0;">
        ${currentDecisionIdx + 1}
      </span>
      <span style="font-size:0.6875rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--medium);">
        Decision Point ${currentDecisionIdx + 1} of ${scenario.decisions.length}
      </span>
    </div>
    <div style="font-size:0.875rem;font-weight:600;color:var(--text-primary);line-height:1.5;margin-bottom:1rem;">
      ${decision.question}
    </div>
    <div id="decision-options">
      ${decision.options.map(opt => `
        <button class="decision-card" id="opt-${opt.id}" onclick="answerDecision('${decision.id}', '${opt.id}')">
          <div class="decision-text"><strong>${opt.id.toUpperCase()}.</strong> ${opt.text}</div>
          <div class="decision-consequence">${opt.consequence}</div>
        </button>`).join('')}
    </div>`;
}

function answerDecision(decisionId, optionId) {
  const decision = activeScenario.decisions.find(d => d.id === decisionId);
  if (!decision) return;

  const selectedOpt = decision.options.find(o => o.id === optionId);
  const isCorrect = selectedOpt.correct;

  decisionsAnswered++;
  if (isCorrect) {
    decisionsCorrect++;
    scenarioScore += 30;
    SENTINEL.updateScore(30);
    SENTINEL.toast('+30 pts — Correct response!', 'success');
  } else {
    SENTINEL.toast('Incorrect — see consequence below', 'error');
  }

  /* Reveal all options */
  decision.options.forEach(opt => {
    const btn = document.getElementById(`opt-${opt.id}`);
    if (!btn) return;
    btn.disabled = true;
    btn.classList.add('revealed');
    if (opt.correct) btn.classList.add('correct-answer');
    if (opt.id === optionId && !opt.correct) btn.classList.add('wrong-answer');
  });

  /* Update score displays */
  const scoreDisplay = document.getElementById('scenario-score-display');
  const scoreSidebar = document.getElementById('scenario-score-sidebar');
  if (scoreDisplay) scoreDisplay.textContent = scenarioScore + ' pts';
  if (scoreSidebar) scoreSidebar.textContent = scenarioScore + ' pts';

  const answeredEl = document.getElementById('decisions-answered');
  if (answeredEl) answeredEl.textContent = `${decisionsAnswered} / ${activeScenario.decisions.length}`;

  const progressBar = document.getElementById('decision-progress');
  if (progressBar) progressBar.style.width = ((decisionsAnswered / activeScenario.decisions.length) * 100) + '%';

  /* Show Next button */
  const panel = document.getElementById('decision-content');
  const nextBtn = document.createElement('div');
  nextBtn.style.marginTop = '1rem';
  nextBtn.innerHTML = currentDecisionIdx + 1 < activeScenario.decisions.length
    ? `<button class="btn btn-primary btn-full" onclick="nextDecision()">Next Decision →</button>`
    : `<button class="btn btn-primary btn-full" onclick="nextDecision()">See Debrief →</button>`;
  panel.appendChild(nextBtn);
}

function nextDecision() {
  currentDecisionIdx++;
  renderCurrentDecision(activeScenario);
}

/* ── Scenario debrief ── */
function showScenarioDebrief(scenario) {
  const panel = document.getElementById('decision-content');
  if (panel) {
    panel.innerHTML = `
      <div class="text-center">
        <div style="font-size:2rem;margin-bottom:8px;">🎯</div>
        <div style="font-weight:700;color:var(--teal);margin-bottom:4px;">Scenario Complete</div>
        <div class="text-xs text-muted">Scroll down to see your debrief</div>
      </div>`;
  }

  /* Mark objectives complete */
  scenario.objectives.forEach((_, i) => {
    const el = document.getElementById(`obj-${i}`);
    if (el) {
      el.querySelector('span:first-child').textContent = '✓';
      el.querySelector('span:first-child').style.color = 'var(--low)';
    }
  });

  const debrief = document.getElementById('scenario-debrief');
  if (!debrief) return;

  const pct = Math.round((decisionsCorrect / scenario.decisions.length) * 100);
  const scoreClass = SENTINEL.scoreClass(pct);
  const scoreLabel = SENTINEL.scoreLabel(pct);

  debrief.innerHTML = `
    <div class="card" style="background:rgba(0,212,216,0.04);border-color:rgba(0,212,216,0.3);">
      <div class="flex items-center gap-3 mb-4">
        <span style="font-size:2rem">${scenario.icon}</span>
        <div>
          <div style="font-size:1.125rem;font-weight:700;color:var(--text-primary)">${scenario.name} — Debrief</div>
          <div class="text-xs text-muted">${scenario.topic}</div>
        </div>
        <div class="text-right" style="margin-left:auto;">
          <div class="stat-big ${scoreClass}" style="font-size:2rem">${decisionsCorrect}/${scenario.decisions.length}</div>
          <div class="stat-label">decisions correct</div>
        </div>
      </div>

      <div class="card mb-3" style="background:var(--bg-primary);">
        <div class="card-title mb-2" style="color:var(--teal)">Key Takeaway</div>
        <p style="font-size:0.875rem;color:var(--text-muted);line-height:1.7;">${scenario.debrief}</p>
      </div>

      <div class="score-breakdown mb-4">
        <div class="score-row">
          <span class="score-row-label">Decisions correct</span>
          <span class="score-row-val text-teal">${decisionsCorrect} / ${scenario.decisions.length}</span>
        </div>
        <div class="score-row">
          <span class="score-row-label">Points earned</span>
          <span class="score-row-val text-teal">${scenarioScore} pts</span>
        </div>
        <div class="score-row">
          <span class="score-row-label">Performance level</span>
          <span class="score-row-val">${scoreLabel}</span>
        </div>
      </div>

      <div class="flex gap-3" style="flex-wrap:wrap;">
        <button onclick="renderScenarioPicker()" class="btn btn-primary">← Choose Another Scenario</button>
        <a href="remediate.html" class="btn btn-secondary">Try Remediation Lab →</a>
        <button onclick="loadScenarioById('${scenario.id}')" class="btn btn-ghost">↩ Replay This Scenario</button>
      </div>
    </div>`;

  debrief.classList.remove('hidden');
  debrief.scrollIntoView({ behavior: 'smooth' });

  /* Save progress */
  const p = SENTINEL.getProgress();
  p.scenariosCompleted = p.scenariosCompleted || [];
  if (!p.scenariosCompleted.includes(scenario.id)) p.scenariosCompleted.push(scenario.id);
  p.scenarioScores = p.scenarioScores || {};
  p.scenarioScores[scenario.id] = scenarioScore;
  SENTINEL.saveProgress(p);
}

document.addEventListener('DOMContentLoaded', initInvestigation);
