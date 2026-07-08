/* SENTINEL — Live Fire Exercise
   A staged, timed, AI-driven promptware attack. The student authorizes
   scoped/reversible containment at each gate using the Standing Authority
   Matrix, then certifies with a final knowledge check.

   Flow per stage:  BRIEF telemetry  →  DECISION GATE (timed)  →  RESULT
                    →  CONCEPT QUIZ  →  advance.  Then FINAL EXAM → CERT.
*/
'use strict';

const LF = {
  data: null,
  stageIdx: 0,
  score: 0,
  maxScore: 0,
  gateCorrect: 0,
  quizCorrect: 0,
  examCorrect: 0,
  timerId: null,
  timedOut: false,
  killChain: [],        // phases reached
  startTime: null,
};

async function initLiveFire() {
  try {
    LF.data = await fetch('data/livefire.json').then(r => {
      if (!r.ok) throw new Error(r.status);
      return r.json();
    });
  } catch (e) {
    const root = document.getElementById('livefire-root');
    if (root) root.innerHTML =
      `<div class="lf-shell"><div class="card" style="text-align:center;padding:2rem;">
        <div style="font-size:2rem;margin-bottom:8px;">⚠</div>
        <div style="font-weight:700;color:var(--text-primary);margin-bottom:6px;">Could not load the exercise data.</div>
        <div class="text-sm text-muted">Live Fire loads <code>data/livefire.json</code> via fetch, which needs a local web server (not <code>file://</code>).<br>Run <code>python -m http.server</code> in the project folder, then reload.</div>
      </div></div>`;
    return;
  }
  // per-stage max (gate 30 + quiz 10) plus final exam (10 each)
  LF.maxScore = LF.data.stages.length * 40 + LF.data.finalExam.questions.length * 10;
  renderBriefing();
}

/* ══════════════ MISSION BRIEFING ══════════════ */
function renderBriefing() {
  const m = LF.data.meta;
  const root = document.getElementById('livefire-root');
  root.innerHTML = `
    <div class="lf-shell">
      <div class="lf-hero">
        <div class="lf-hero-glow"></div>
        <div class="lf-hero-inner">
          <div class="lf-tag">LIVE FIRE EXERCISE · ADVANCES ON A CLOCK</div>
          <h1 class="lf-hero-title">${m.name}</h1>
          <div class="lf-hero-sub">${m.subtitle}</div>
          <div class="lf-hero-org">▤ ${m.org}</div>
        </div>
      </div>

      <div class="lf-grid-brief">
        <div class="card lf-brief-card">
          <div class="lf-section-label">Situation</div>
          <p class="lf-body">${m.context}</p>
          <p class="lf-body" style="margin-top:10px;color:var(--text-muted);">${m.premise}</p>
        </div>

        <div class="card lf-matrix-card">
          <div class="lf-section-label">Standing Authority Matrix</div>
          <div class="text-xs text-muted" style="margin-bottom:12px;line-height:1.6;">Your decision rulebook. Prefer the <strong style="color:var(--ok);">lowest tier that fully contains</strong> the threat — scoped and reversible, no business outage.</div>
          ${LF.data.authorityMatrix.map(t => {
            const tier = t.tier.split('—')[0].trim().toLowerCase();
            const cls = tier.includes('green') ? 'green' : tier.includes('amber') ? 'amber' : 'red';
            return `<div class="lf-matrix-row lf-matrix-${cls}">
              <div class="lf-matrix-tier">${t.tier}</div>
              <div class="lf-matrix-meaning">${t.meaning}</div>
              <div class="lf-matrix-eg"><span class="text-muted">e.g.</span> ${t.examples}</div>
            </div>`;
          }).join('')}
        </div>
      </div>

      <div class="card lf-objectives-card">
        <div class="lf-section-label">What this exercise tests</div>
        <div class="lf-obj-grid">
          <div class="lf-obj"><span class="lf-obj-ico">◧</span><div><strong>Shift detection left</strong><span>Catch AI threats at Identity/Network, not just EDR.</span></div></div>
          <div class="lf-obj"><span class="lf-obj-ico">⛓</span><div><strong>Promptware kill chain</strong><span>ClickFix → injection → MCP recon → poisoning → ransomware.</span></div></div>
          <div class="lf-obj"><span class="lf-obj-ico">⚷</span><div><strong>NHI governance</strong><span>Treat agents & service accounts as privileged users (ZSP).</span></div></div>
          <div class="lf-obj"><span class="lf-obj-ico">⟲</span><div><strong>Safe AI containment</strong><span>Scoped, reversible levers — no business outage.</span></div></div>
        </div>
      </div>

      <div class="lf-start-row">
        <button class="btn btn-primary btn-lg lf-start-btn" onclick="LF_start()">▶ Begin Live Fire — 5 Stages</button>
        <span class="text-xs text-muted">Each gate is timed. Hesitation has a cost, just like the real thing.</span>
      </div>
    </div>`;
}

function LF_start() {
  LF.stageIdx = 0;
  LF.score = 0;
  LF.gateCorrect = 0;
  LF.quizCorrect = 0;
  LF.examCorrect = 0;
  LF.killChain = [];
  LF.startTime = Date.now();
  renderStage();
}

/* ══════════════ STAGE VIEW ══════════════ */
function renderStage() {
  const s = LF.data.stages[LF.stageIdx];
  const root = document.getElementById('livefire-root');
  const total = LF.data.stages.length;

  root.innerHTML = `
    <div class="lf-shell">
      ${renderProgressRail()}

      <div class="lf-stage-head">
        <div>
          <div class="lf-stage-phase">STAGE ${LF.stageIdx + 1} / ${total} · ${s.phase}</div>
          <h2 class="lf-stage-title">${s.title}</h2>
          <div class="lf-stage-meta">
            <span class="lf-chip lf-chip-vector">⚡ ${s.vector}</span>
            <span class="lf-chip">${s.mitreId} · ${s.mitreTactic}</span>
            <span class="lf-chip lf-chip-layer">Detect at: ${s.layer}</span>
          </div>
        </div>
        <div class="lf-timer" id="lf-timer">
          <svg viewBox="0 0 44 44" class="lf-timer-svg"><circle cx="22" cy="22" r="19" class="lf-timer-track"/><circle cx="22" cy="22" r="19" class="lf-timer-arc" id="lf-timer-arc"/></svg>
          <span class="lf-timer-num" id="lf-timer-num">${s.clock}</span>
        </div>
      </div>

      <div class="lf-grid-stage">
        <div class="card lf-narrative-card">
          <div class="lf-section-label">Live telemetry</div>
          <p class="lf-body" style="margin-bottom:14px;">${s.narrative}</p>
          <div class="lf-telemetry" id="lf-telemetry"></div>
        </div>

        <div class="card lf-gate-card" id="lf-gate">
          <div class="lf-section-label lf-gate-label">◉ Decision Gate</div>
          <div class="lf-gate-pressure">⏱ ${s.gate.timePressure}</div>
          <div class="lf-gate-prompt">${s.gate.prompt}</div>
          <div class="lf-gate-options" id="lf-gate-options">
            ${s.gate.options.map(o => `
              <button class="lf-opt" id="lf-opt-${o.id}" onclick="LF_answerGate('${o.id}')">
                <span class="lf-opt-key">${o.id.toUpperCase()}</span>
                <span class="lf-opt-text">${o.text}</span>
                ${o.authority && o.authority !== 'None' ? `<span class="lf-opt-auth lf-auth-${o.authority.toLowerCase()}">${o.authority}</span>` : ''}
              </button>`).join('')}
          </div>
        </div>
      </div>
    </div>`;

  // stream telemetry lines in
  const tel = document.getElementById('lf-telemetry');
  s.telemetry.forEach((t, i) => {
    setTimeout(() => {
      if (!document.getElementById('lf-telemetry')) return;
      const div = document.createElement('div');
      div.className = `lf-tel-row lf-tel-${t.signal}`;
      div.innerHTML = `<span class="lf-tel-src">${t.source}</span><span class="lf-tel-line">${t.line}</span>`;
      tel.appendChild(div);
    }, 250 + i * 400);
  });

  startGateTimer(s.clock);
}

function renderProgressRail() {
  return `<div class="lf-rail">
    ${LF.data.stages.map((st, i) => {
      const state = i < LF.stageIdx ? 'done' : i === LF.stageIdx ? 'active' : 'todo';
      return `<div class="lf-rail-node lf-rail-${state}">
        <div class="lf-rail-dot">${i < LF.stageIdx ? '✓' : i + 1}</div>
        <div class="lf-rail-label">${st.phase}</div>
      </div>${i < LF.data.stages.length - 1 ? '<div class="lf-rail-link lf-rail-link-' + (i < LF.stageIdx ? 'done' : 'todo') + '"></div>' : ''}`;
    }).join('')}
  </div>`;
}

/* ══════════════ TIMER ══════════════ */
function startGateTimer(seconds) {
  LF.timedOut = false;
  clearInterval(LF.timerId);
  const arc = document.getElementById('lf-timer-arc');
  const num = document.getElementById('lf-timer-num');
  const circ = 2 * Math.PI * 19;
  if (arc) { arc.style.strokeDasharray = circ; arc.style.strokeDashoffset = '0'; }
  let remaining = seconds;
  const total = seconds;

  LF.timerId = setInterval(() => {
    remaining -= 0.1;
    const frac = Math.max(0, remaining / total);
    if (arc) arc.style.strokeDashoffset = (circ * (1 - frac)).toFixed(1);
    if (num) num.textContent = Math.max(0, Math.ceil(remaining));
    const timerEl = document.getElementById('lf-timer');
    if (timerEl) timerEl.classList.toggle('lf-timer-crit', remaining <= total * 0.33);
    if (remaining <= 0) {
      clearInterval(LF.timerId);
      LF_gateTimeout();
    }
  }, 100);
}

function LF_gateTimeout() {
  if (LF.timedOut) return;
  LF.timedOut = true;
  const s = LF.data.stages[LF.stageIdx];
  // timeout = the attack advanced. Treat as a wrong outcome with a distinct penalty.
  document.querySelectorAll('.lf-opt').forEach(b => b.disabled = true);
  LF.score -= 15;
  SENTINEL.updateScore(-15);
  SENTINEL.toast('⏱ Time expired — the agent moved first (−15)', 'error', 3500);
  revealGate(null, true);
}

/* ══════════════ GATE ANSWER ══════════════ */
function LF_answerGate(optId) {
  if (LF.timedOut) return;
  clearInterval(LF.timerId);
  const s = LF.data.stages[LF.stageIdx];
  const opt = s.gate.options.find(o => o.id === optId);
  document.querySelectorAll('.lf-opt').forEach(b => b.disabled = true);

  LF.score += opt.score;
  SENTINEL.updateScore(opt.score);
  if (opt.correct) {
    LF.gateCorrect++;
    SENTINEL.toast(`✓ Scoped & reversible — ${opt.score > 0 ? '+' + opt.score : opt.score}`, 'success');
  } else {
    SENTINEL.toast(`${opt.score >= 0 ? '+' : ''}${opt.score} — see the consequence`, 'error');
  }
  revealGate(optId, false);
}

function revealGate(optId, wasTimeout) {
  const s = LF.data.stages[LF.stageIdx];
  const correctOpt = s.gate.options.find(o => o.correct);

  s.gate.options.forEach(o => {
    const btn = document.getElementById(`lf-opt-${o.id}`);
    if (!btn) return;
    btn.classList.add('lf-opt-revealed');
    if (o.correct) btn.classList.add('lf-opt-correct');
    else if (o.id === optId) btn.classList.add('lf-opt-wrong');
    // append consequence
    const con = document.createElement('div');
    con.className = 'lf-opt-consequence';
    con.textContent = o.consequence;
    btn.appendChild(con);
  });

  const chosen = optId ? s.gate.options.find(o => o.id === optId) : null;
  const gate = document.getElementById('lf-gate');
  const result = document.createElement('div');
  result.className = 'lf-gate-result ' + (chosen && chosen.correct ? 'lf-result-good' : 'lf-result-bad');
  result.innerHTML = `
    <div class="lf-result-head">
      ${wasTimeout ? '⏱ You ran out of time' : chosen && chosen.correct ? '✓ Correct authorization' : '✗ Suboptimal authorization'}
      ${chosen ? `<span class="lf-result-auth lf-auth-${(chosen.authority||'none').toLowerCase()}">${chosen.authority} tier</span>` : ''}
    </div>
    <div class="lf-teaching"><span class="lf-teaching-ico">🎓</span><div>${s.teaching}</div></div>
    <button class="btn btn-primary lf-next-btn" onclick="LF_showQuiz()">Concept check →</button>`;
  gate.appendChild(result);
  result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  LF.killChain.push(s.phase);
}

/* ══════════════ CONCEPT QUIZ ══════════════ */
function LF_showQuiz() {
  const s = LF.data.stages[LF.stageIdx];
  const root = document.getElementById('livefire-root');
  const modal = document.createElement('div');
  modal.className = 'lf-quiz-overlay';
  modal.id = 'lf-quiz-overlay';
  modal.innerHTML = `
    <div class="lf-quiz-box">
      <div class="lf-section-label">Concept check — Stage ${LF.stageIdx + 1}</div>
      <div class="lf-quiz-prompt">${s.quiz.prompt}</div>
      <div class="lf-quiz-options" id="lf-quiz-options">
        ${s.quiz.options.map(o => `
          <button class="lf-quiz-opt" id="lf-quiz-${o.id}" onclick="LF_answerQuiz('${o.id}')">
            <span class="lf-opt-key">${o.id.toUpperCase()}</span><span>${o.text}</span>
          </button>`).join('')}
      </div>
      <div class="lf-quiz-explain" id="lf-quiz-explain" style="display:none;"></div>
      <button class="btn btn-primary lf-next-btn" id="lf-quiz-continue" style="display:none;" onclick="LF_advance()">Continue →</button>
    </div>`;
  root.appendChild(modal);
}

function LF_answerQuiz(optId) {
  const s = LF.data.stages[LF.stageIdx];
  const opt = s.quiz.options.find(o => o.id === optId);
  s.quiz.options.forEach(o => {
    const btn = document.getElementById(`lf-quiz-${o.id}`);
    if (!btn) return;
    btn.disabled = true;
    if (o.correct) btn.classList.add('lf-quiz-correct');
    else if (o.id === optId) btn.classList.add('lf-quiz-wrong');
  });
  if (opt.correct) {
    LF.quizCorrect++;
    LF.score += 10;
    SENTINEL.updateScore(10);
    SENTINEL.toast('+10 — concept locked in', 'success');
  } else {
    SENTINEL.toast('Not quite — read the explanation', 'error');
  }
  const ex = document.getElementById('lf-quiz-explain');
  ex.style.display = 'block';
  ex.innerHTML = `<strong style="color:var(--teal);">Why:</strong> ${s.quiz.explain}`;
  document.getElementById('lf-quiz-continue').style.display = '';
}

function LF_advance() {
  const ov = document.getElementById('lf-quiz-overlay');
  if (ov) ov.remove();
  LF.stageIdx++;
  if (LF.stageIdx < LF.data.stages.length) {
    renderStage();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  } else {
    renderFinalExam();
  }
}

/* ══════════════ FINAL EXAM ══════════════ */
function renderFinalExam() {
  LF.examIdx = 0;
  const root = document.getElementById('livefire-root');
  root.innerHTML = `
    <div class="lf-shell">
      <div class="lf-exam-head">
        <div class="lf-tag">CERTIFICATION CHECK</div>
        <h2 class="lf-stage-title">${LF.data.finalExam.title}</h2>
        <div class="text-sm text-muted" style="margin-top:4px;">${LF.data.finalExam.intro}</div>
      </div>
      <div class="card lf-exam-card" id="lf-exam-card"></div>
    </div>`;
  renderExamQuestion();
}

function renderExamQuestion() {
  const q = LF.data.finalExam.questions[LF.examIdx];
  const card = document.getElementById('lf-exam-card');
  const total = LF.data.finalExam.questions.length;
  card.innerHTML = `
    <div class="lf-exam-progress">Question ${LF.examIdx + 1} of ${total}</div>
    <div class="lf-quiz-prompt">${q.prompt}</div>
    <div class="lf-quiz-options" id="lf-exam-options">
      ${q.options.map(o => `
        <button class="lf-quiz-opt" id="lf-exam-${o.id}" onclick="LF_answerExam('${o.id}')">
          <span class="lf-opt-key">${o.id.toUpperCase()}</span><span>${o.text}</span>
        </button>`).join('')}
    </div>
    <div class="lf-quiz-explain" id="lf-exam-explain" style="display:none;"></div>
    <button class="btn btn-primary lf-next-btn" id="lf-exam-next" style="display:none;" onclick="LF_nextExam()">
      ${LF.examIdx + 1 < total ? 'Next question →' : 'See results →'}
    </button>`;
}

function LF_answerExam(optId) {
  const q = LF.data.finalExam.questions[LF.examIdx];
  const opt = q.options.find(o => o.id === optId);
  q.options.forEach(o => {
    const btn = document.getElementById(`lf-exam-${o.id}`);
    if (!btn) return;
    btn.disabled = true;
    if (o.correct) btn.classList.add('lf-quiz-correct');
    else if (o.id === optId) btn.classList.add('lf-quiz-wrong');
  });
  if (opt.correct) {
    LF.examCorrect++;
    LF.score += 10;
    SENTINEL.updateScore(10);
    SENTINEL.toast('+10 — correct', 'success');
  } else {
    SENTINEL.toast('Incorrect', 'error');
  }
  document.getElementById('lf-exam-next').style.display = '';
}

function LF_nextExam() {
  LF.examIdx++;
  if (LF.examIdx < LF.data.finalExam.questions.length) renderExamQuestion();
  else renderResults();
}

/* ══════════════ RESULTS / CERTIFICATE ══════════════ */
function renderResults() {
  const stages = LF.data.stages.length;
  const examTotal = LF.data.finalExam.questions.length;
  const gatePct = Math.round((LF.gateCorrect / stages) * 100);
  const quizPct = Math.round((LF.quizCorrect / stages) * 100);
  const examPct = Math.round((LF.examCorrect / examTotal) * 100);
  const pts = Math.max(0, LF.score);
  const overall = Math.round((pts / LF.maxScore) * 100);
  const passed = LF.gateCorrect >= 4 && LF.examCorrect >= 4;

  const elapsed = Math.round((Date.now() - LF.startTime) / 1000);
  const mins = Math.floor(elapsed / 60), secs = elapsed % 60;

  const rank = overall >= 90 ? 'Incident Commander' :
               overall >= 75 ? 'Senior SOC Analyst' :
               overall >= 55 ? 'SOC Analyst' : 'SOC Analyst (Trainee)';

  // persist
  const p = SENTINEL.getProgress();
  p.livefireScore = pts;
  p.livefireCompleted = true;
  p.livefireBest = Math.max(p.livefireBest || 0, overall);
  SENTINEL.saveProgress(p);

  const root = document.getElementById('livefire-root');
  root.innerHTML = `
    <div class="lf-shell">
      <div class="lf-cert ${passed ? 'lf-cert-pass' : 'lf-cert-fail'}">
        <div class="lf-cert-glow"></div>
        <div class="lf-cert-inner">
          <div class="lf-cert-seal">${passed ? '✓' : '↻'}</div>
          <div class="lf-tag" style="color:${passed ? 'var(--ok)' : 'var(--medium)'};">${passed ? 'CERTIFIED — PROMPTWARE DEFENSE' : 'NOT YET CERTIFIED'}</div>
          <h1 class="lf-hero-title" style="font-size:2rem;">${overall}%</h1>
          <div class="lf-cert-rank">${rank}</div>
          <div class="lf-cert-name">${SENTINEL._escHtml(SENTINEL.getStudentName() || 'Analyst')} · ${LF.data.meta.name}</div>
        </div>
      </div>

      <div class="lf-result-stats">
        <div class="lf-rstat"><div class="lf-rstat-num" style="color:var(--teal);">${pts}</div><div class="lf-rstat-lbl">points earned</div></div>
        <div class="lf-rstat"><div class="lf-rstat-num" style="color:${gatePct>=80?'var(--ok)':'var(--medium)'};">${LF.gateCorrect}/${stages}</div><div class="lf-rstat-lbl">gates — scoped & reversible</div></div>
        <div class="lf-rstat"><div class="lf-rstat-num" style="color:${quizPct>=80?'var(--ok)':'var(--medium)'};">${LF.quizCorrect}/${stages}</div><div class="lf-rstat-lbl">concept checks</div></div>
        <div class="lf-rstat"><div class="lf-rstat-num" style="color:${examPct>=80?'var(--ok)':'var(--medium)'};">${LF.examCorrect}/${examTotal}</div><div class="lf-rstat-lbl">certification exam</div></div>
        <div class="lf-rstat"><div class="lf-rstat-num" style="color:var(--text);">${mins}m ${secs}s</div><div class="lf-rstat-lbl">response time</div></div>
      </div>

      <div class="card lf-debrief-card">
        <div class="lf-section-label">After-action debrief</div>
        <p class="lf-body">You worked the full <strong>promptware kill chain</strong> — ClickFix initial access, indirect prompt injection, MCP-driven tool recon, RAG/NHI abuse, and agentic ransomware (JadePuffer). ${passed
          ? 'Because you reached for <strong>scoped, reversible levers</strong> early — isolating one endpoint, dropping the agent to proposal-only mode, rotating the over-scoped NHI token, and freezing the RAG index — the final ransomware detonation was containable to three hosts by an automated playbook. That is the doctrine: shift detection left, deny footholds with reversible containment, and meet machine speed with pre-authorized automation.'
          : 'Review the gates you missed. The pattern that certifies is consistent: choose the <strong>lowest authority tier that fully contains</strong> the threat, act at machine speed, and never trade a scoped reversible lever for a business-outage Red action or a human-speed delay.'}</p>
        <div class="lf-takeaways">
          <div class="lf-takeaway"><span>◧</span> EDR detection is already late — hunt Identity & Network anomalies first.</div>
          <div class="lf-takeaway"><span>⚷</span> Govern NHIs as privileged users: Zero Standing Privilege, least scope, rotate.</div>
          <div class="lf-takeaway"><span>⟲</span> Freeze / proposal-only / rotate / isolate = contain without an outage.</div>
          <div class="lf-takeaway"><span>⛓</span> Human on the loop: set scoped rules, let automation execute at machine speed.</div>
        </div>
      </div>

      <div class="lf-start-row">
        <button class="btn btn-primary btn-lg" onclick="LF_start()">↻ Run Again</button>
        <a href="scenarios.html" class="btn btn-secondary btn-lg">Scenario Library →</a>
        <a href="index.html" class="btn btn-ghost btn-lg">Command Center</a>
      </div>
    </div>`;
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

document.addEventListener('DOMContentLoaded', initLiveFire);
