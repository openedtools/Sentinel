/* SENTINEL — Shared utilities, nav, localStorage */

const SENTINEL = {
  version: '1.0',
  storageKey: 'sentinel_progress',

  /* ── Score/progress storage ── */
  getProgress() {
    try {
      return JSON.parse(localStorage.getItem(this.storageKey)) || {
        triageScore: 0,
        triageTotal: 0,
        triageCompleted: false,
        scenariosCompleted: [],
        scenarioScores: {},
        remediationCompleted: false,
        logsScore: 0,
        logsCompleted: false,
        vulnsScore: 0,
        vulnsCompleted: false,
        riskScore: 0,
        riskCompleted: false,
        totalScore: 0
      };
    } catch { return {}; }
  },

  saveProgress(data) {
    try { localStorage.setItem(this.storageKey, JSON.stringify(data)); } catch {}
  },

  updateScore(delta) {
    const p = this.getProgress();
    p.totalScore = (p.totalScore || 0) + delta;
    this.saveProgress(p);
    this.updateNavScore();
  },

  resetProgress() {
    localStorage.removeItem(this.storageKey);
    this.updateNavScore();
  },

  /* ── Nav score badge ── */
  updateNavScore() {
    const el = document.getElementById('nav-score');
    if (!el) return;
    const p = this.getProgress();
    el.textContent = (p.totalScore || 0) + ' pts';
  },

  /* ── Active nav link ── */
  markActiveNav() {
    const pageId = this._getPageId ? this._getPageId() : 'dashboard';
    document.querySelectorAll('.nav-item[data-page]').forEach(item => {
      item.classList.toggle('active', item.dataset.page === pageId);
    });
    // legacy horizontal nav fallback
    const page = window.location.pathname.split('/').pop() || 'index.html';
    document.querySelectorAll('.nav-link').forEach(link => {
      const href = link.getAttribute('href');
      link.classList.toggle('active', href === page || (page === '' && href === 'index.html'));
    });
  },

  /* ── Toast notifications ── */
  _toastContainer: null,

  getToastContainer() {
    if (!this._toastContainer) {
      this._toastContainer = document.createElement('div');
      this._toastContainer.className = 'toast-container';
      document.body.appendChild(this._toastContainer);
    }
    return this._toastContainer;
  },

  toast(message, type = 'info', duration = 3000) {
    const icons = { success: '✓', error: '✗', info: 'ℹ', warning: '⚠' };
    const container = this.getToastContainer();
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.innerHTML = `<span>${icons[type] || 'ℹ'}</span><span>${message}</span>`;
    container.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity 0.3s'; setTimeout(() => el.remove(), 300); }, duration);
  },

  /* ── Animated counter ── */
  animateCount(el, target, duration = 1500, suffix = '') {
    if (!el) return;
    const start = 0;
    const startTime = performance.now();
    const easeOut = t => 1 - Math.pow(1 - t, 3);

    const tick = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const value = Math.round(easeOut(progress) * target);
      el.textContent = value.toLocaleString() + suffix;
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  },

  /* ── Severity helpers ── */
  severityBadge(sev) {
    return `<span class="badge badge-${sev}">${sev.toUpperCase()}</span>`;
  },

  severityIcon(sev) {
    const icons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
    return icons[sev] || '⚪';
  },

  /* ── Time formatter ── */
  formatTime(isoStr) {
    try {
      const d = new Date(isoStr);
      return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    } catch { return isoStr; }
  },

  /* ── MITRE tactic color ── */
  mitreColor(tactic, mitreData) {
    if (!mitreData) return '#6b7280';
    const found = mitreData.tactics.find(t => t.name === tactic);
    return found ? found.color : '#6b7280';
  },

  /* ── Score class helper ── */
  scoreClass(pct) {
    if (pct >= 85) return 'score-excellent';
    if (pct >= 65) return 'score-good';
    if (pct >= 40) return 'score-fair';
    return 'score-poor';
  },

  scoreLabel(pct) {
    if (pct >= 85) return 'Excellent — Senior Analyst';
    if (pct >= 65) return 'Good — Mid-Level Analyst';
    if (pct >= 40) return 'Fair — Junior Analyst';
    return 'Needs Practice — Apprentice';
  }
};

/* ── Live log feed (used on dashboard and remediation) ── */
const LIVE_LOG = {
  entries: [
    { cls: 'log-crit', msg: '[CRITICAL] Polymorphic executable detected on WS-004 — hash mutation confirmed' },
    { cls: 'log-high', msg: '[HIGH] Port scan from WS-011 → 10.14.1.0/24 — 1842 packets in 4.2s' },
    { cls: 'log-info', msg: '[INFO] AI reduced 2,742 raw alerts to 130 prioritized incidents (-95.3%)' },
    { cls: 'log-crit', msg: '[CRITICAL] WMI remote exec: WS-011 → FILE-SERVER-01 via encoded PowerShell' },
    { cls: 'log-ok',   msg: '[RESOLVED] Nightly backup job — 2GB to Azure Backup — authorized (CHG-0417)' },
    { cls: 'log-high', msg: '[HIGH] Email summarizer prompt injection — exfil attempt blocked by DLP' },
    { cls: 'log-crit', msg: '[CRITICAL] LSASS memory access on DC-01 by wdcu.exe — credential dump' },
    { cls: 'log-high', msg: '[HIGH] New Domain Admin created outside change window: svc_backup_new' },
    { cls: 'log-crit', msg: '[CRITICAL] GPO pushed: AV disabled on 47 endpoints by svc_backup_new' },
    { cls: 'log-info', msg: '[INFO] Deepfake score 0.94 — CEO_Video_Message_Q2.mp4 flagged by DLP' },
    { cls: 'log-high', msg: '[HIGH] Software update hash mismatch: IntelAnalyticsSuite v4.2.1' },
    { cls: 'log-crit', msg: '[CRITICAL] DNS tunneling: FILE-SERVER-01 → *.exfilbase64.co — 847 queries' },
    { cls: 'log-ok',   msg: '[RESOLVED] Vulnerability scan from SCAN-HOST — authorized (CHG-0417-001)' },
    { cls: 'log-high', msg: '[HIGH] WormGPT spear-phish detected — ai_generated_score=0.97' },
    { cls: 'log-info', msg: '[INFO] Anomalous API calls: 312 Azure RM queries in 31s from legacy-monitor-app' }
  ],
  idx: 0,

  init(feedEl) {
    if (!feedEl) return;
    this.feedEl = feedEl;
    this.entries.forEach(e => this._append(e));
    feedEl.scrollTop = feedEl.scrollHeight;
    setInterval(() => this._tick(), 2800);
  },

  _append(entry) {
    if (!this.feedEl) return;
    const now = new Date();
    const ts = now.toTimeString().slice(0, 8);
    const div = document.createElement('div');
    div.className = `log-entry ${entry.cls}`;
    div.textContent = `${ts} ${entry.msg}`;
    this.feedEl.appendChild(div);
  },

  _tick() {
    const fakeEntries = [
      { cls: 'log-info', msg: '[INFO] AI engine processed 847 alerts — 19 escalated to human review' },
      { cls: 'log-high', msg: '[HIGH] Lateral movement attempt blocked: WS-004 → DC-01 (quarantine active)' },
      { cls: 'log-ok',   msg: '[RESOLVED] Incident #IR-2026-004 closed — polymorphic payload contained' },
      { cls: 'log-crit', msg: '[CRITICAL] Outbound connection to newly registered domain — blocked by NGFW' },
      { cls: 'log-info', msg: '[INFO] Post-quantum TLS negotiation successful — client: SEC-VAULT-01' }
    ];
    const e = fakeEntries[Math.floor(Math.random() * fakeEntries.length)];
    this._append(e);
    if (this.feedEl.children.length > 40) this.feedEl.removeChild(this.feedEl.firstChild);
    this.feedEl.scrollTop = this.feedEl.scrollHeight;
  }
};

/* ── Student identity ── */
SENTINEL.getStudentName = function() {
  return localStorage.getItem('sentinel_student_name') || null;
};

SENTINEL.setStudentName = function(name) {
  localStorage.setItem('sentinel_student_name', name.trim());
  this.updateNavScore();
};

SENTINEL.updateNavScore = function() {
  const p = this.getProgress();
  const score = (p.totalScore || 0) + ' pts';
  const name = this.getStudentName() || 'Analyst';

  // legacy horizontal nav
  const scoreEl = document.getElementById('nav-score');
  if (scoreEl) scoreEl.textContent = score;
  const nameEl = document.getElementById('nav-student-name');
  if (nameEl) nameEl.textContent = name;

  // new sidebar user card
  const sbScore = document.getElementById('sb-score');
  if (sbScore) sbScore.textContent = score;
  const sbName = document.getElementById('sb-name');
  if (sbName) sbName.textContent = name;
  const sbAvatar = document.getElementById('sb-avatar');
  if (sbAvatar) {
    sbAvatar.textContent = name.trim().split(/\s+/).map(w => w[0]).join('').toUpperCase().slice(0, 2) || 'A';
  }
  // topbar score pill
  const tbScore = document.getElementById('topbar-score');
  if (tbScore) tbScore.textContent = score;
};

/* ── Name entry modal ── */
SENTINEL.showNameModal = function() {
  return new Promise(resolve => {
    const overlay = document.createElement('div');
    overlay.id = 'name-modal';
    overlay.style.cssText = [
      'position:fixed;inset:0;z-index:900',
      'display:flex;align-items:center;justify-content:center',
      'background:radial-gradient(circle at 50% 40%,rgba(94,234,212,.09),transparent 55%),var(--bg-0)',
      'padding:24px',
    ].join(';');

    overlay.innerHTML = `
      <div style="width:100%;max-width:460px;background:var(--bg-1);border:1px solid var(--line-strong);border-radius:14px;padding:36px;box-shadow:0 24px 60px rgba(0,0,0,.55);text-align:center;">

        <!-- Logo block -->
        <div style="width:56px;height:56px;margin:0 auto 20px;border-radius:14px;background:linear-gradient(135deg,var(--teal),var(--teal-deep,#0d9488));display:flex;align-items:center;justify-content:center;position:relative;box-shadow:0 0 0 1px rgba(94,234,212,.4) inset,0 8px 24px rgba(94,234,212,.25);">
          <div style="position:absolute;inset:12px;border:2px solid rgba(0,0,0,.4);border-radius:5px;border-top-color:transparent;transform:rotate(-12deg);"></div>
        </div>

        <div style="font-size:22px;font-weight:700;letter-spacing:.06em;color:var(--text-primary);margin-bottom:4px;">SENTINEL</div>
        <div style="font-size:11px;color:var(--teal);letter-spacing:.18em;text-transform:uppercase;margin-bottom:22px;">SOC Simulator · DCOI Day 3</div>

        <!-- Live alert counter -->
        <div style="margin-bottom:20px;padding:10px 16px;background:var(--bg-2);border:1px solid var(--border);border-radius:8px;display:flex;align-items:center;justify-content:space-between;">
          <span style="font-size:10px;color:var(--text-muted);letter-spacing:.08em;text-transform:uppercase;">Alerts · Live</span>
          <div style="display:flex;align-items:center;gap:8px;">
            <div style="width:6px;height:6px;border-radius:50%;background:var(--teal);box-shadow:0 0 6px var(--teal);animation:pulse 1.4s ease-in-out infinite;"></div>
            <span id="login-alert-count" style="font-family:var(--font-mono);font-size:15px;font-weight:700;color:var(--teal);">2,742</span>
          </div>
        </div>

        <div style="font-size:18px;font-weight:600;color:var(--text-primary);margin-bottom:6px;">Welcome, Analyst.</div>
        <div style="font-size:13px;color:var(--text-muted);line-height:1.6;margin-bottom:26px;">
          Enter your name or callsign to begin.<br>Your score saves automatically to this device.
        </div>

        <input id="name-input" type="text"
          placeholder="e.g. Capt Best · Team Alpha · SGT Williams"
          maxlength="40" autocomplete="off" autocorrect="off" spellcheck="false"
          style="width:100%;box-sizing:border-box;padding:12px 14px;background:var(--bg-2);border:1px solid var(--line-strong);border-radius:8px;color:var(--text-primary);font-family:var(--font-ui);font-size:14px;margin-bottom:16px;text-align:center;letter-spacing:.02em;outline:none;">

        <button id="name-submit-btn" class="btn btn-primary" style="width:100%;justify-content:center;padding:11px 14px;font-size:13px;">
          Begin Training →
        </button>

        <div style="font-size:10px;color:var(--text-dim);margin-top:18px;line-height:1.5;">
          All data simulated for training purposes. Score stored locally only.
        </div>
      </div>`;

    document.body.appendChild(overlay);

    /* Live alert counter — setInterval so it works in background tabs */
    const startVal = 2742, startT = Date.now();
    const ratePerMin = 9;
    const counterEl = overlay.querySelector('#login-alert-count');
    const counterInt = setInterval(() => {
      if (!counterEl || !document.body.contains(counterEl)) { clearInterval(counterInt); return; }
      const elapsedMin = (Date.now() - startT) / 60000;
      const val = Math.floor(startVal + elapsedMin * ratePerMin + Math.sin(Date.now() / 3000) * 1.2);
      counterEl.textContent = val.toLocaleString();
    }, 200);

    const input = overlay.querySelector('#name-input');
    const btn   = overlay.querySelector('#name-submit-btn');
    input.focus();

    input.addEventListener('focus', () => { input.style.borderColor = 'var(--teal)'; });
    input.addEventListener('blur',  () => { input.style.borderColor = 'var(--line-strong)'; });

    const submit = () => {
      const val = input.value.trim();
      if (!val) { input.style.borderColor = 'var(--critical)'; input.focus(); return; }
      clearInterval(counterInt);
      SENTINEL.setStudentName(val);
      overlay.style.opacity = '0';
      overlay.style.transition = 'opacity 0.2s';
      setTimeout(() => { overlay.remove(); resolve(val); }, 200);
    };

    btn.addEventListener('click', submit);
    input.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
  });
};

/* ── Intro / orientation modal ── */
SENTINEL.showIntroModal = function(studentName) {
  return new Promise(resolve => {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.id = 'intro-modal';
    overlay.innerHTML = `
      <div class="modal-box modal-wide">
        <div style="margin-bottom:1.25rem;">
          <div style="font-size:0.75rem;font-weight:700;text-transform:uppercase;letter-spacing:0.12em;color:var(--teal);margin-bottom:6px;">
            MISSION BRIEFING
          </div>
          <div class="modal-title">Welcome, <span style="color:var(--teal);">${studentName}</span>.</div>
          <div class="modal-subtitle" style="margin-top:4px;line-height:1.6;">
            SENTINEL simulates a real AI-enabled Security Operations Center (SOC). You'll triage live alerts,
            investigate five attack scenarios from today's lesson, and take hands-on remediation action
            against a network under attack.
          </div>
        </div>

        <div style="background:var(--bg-primary);border-radius:var(--radius-md);padding:1rem;margin-bottom:1.25rem;">
          <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:0.08em;">
            Recommended Order
          </div>
          <div class="intro-modules">
            <div class="intro-module-card">
              <div class="intro-module-num">1</div>
              <div>
                <div class="intro-module-name">⚡ Alert Triage</div>
                <div class="intro-module-desc">Classify 20 real alerts. See what AI catches vs. what humans miss. ~45 min</div>
              </div>
            </div>
            <div class="intro-module-card">
              <div class="intro-module-num">2</div>
              <div>
                <div class="intro-module-name">🦠 Polymorphic Payload</div>
                <div class="intro-module-desc">AI malware that defeats signature AV. ~20 min</div>
              </div>
            </div>
            <div class="intro-module-card">
              <div class="intro-module-num">3</div>
              <div>
                <div class="intro-module-name">📧 The Email Summarizer</div>
                <div class="intro-module-desc">Zero-click prompt injection attack. ~20 min</div>
              </div>
            </div>
            <div class="intro-module-card">
              <div class="intro-module-num">4</div>
              <div>
                <div class="intro-module-name">🛠 Remediation Lab</div>
                <div class="intro-module-desc">Quarantine nodes, block ports, stop the breach. ~25 min</div>
              </div>
            </div>
            <div class="intro-module-card">
              <div class="intro-module-num">5</div>
              <div>
                <div class="intro-module-name">🎭 🤖 📦 More Scenarios</div>
                <div class="intro-module-desc">Deepfake fraud, agentic AI, supply chain. ~60 min</div>
              </div>
            </div>
            <div class="intro-module-card">
              <div class="intro-module-num">6</div>
              <div>
                <div class="intro-module-name">📜 Log Analysis</div>
                <div class="intro-module-desc">Click suspicious lines in raw Windows, Linux, and firewall logs. ~30 min</div>
              </div>
            </div>
            <div class="intro-module-card">
              <div class="intro-module-num">7</div>
              <div>
                <div class="intro-module-name">🎯 Vuln Prioritization</div>
                <div class="intro-module-desc">Build a patch queue from real CVEs across 3 organizations. ~25 min</div>
              </div>
            </div>
            <div class="intro-module-card" style="background:rgba(0,212,216,0.06);border-color:rgba(0,212,216,0.2);">
              <div class="intro-module-num" style="background:var(--medium);color:#000;">💡</div>
              <div>
                <div class="intro-module-name" style="color:var(--teal);">Cross-links</div>
                <div class="intro-module-desc">Alerts in Triage connect to Investigation scenarios. Watch for the 🔗 callouts.</div>
              </div>
            </div>
          </div>
        </div>

        <div style="background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.2);border-radius:var(--radius-md);padding:10px 14px;margin-bottom:1.25rem;font-size:0.8125rem;color:var(--medium);">
          ⏱ Full completion: ~3 hours across all modules. Your progress saves automatically to this browser.
        </div>

        <div class="flex gap-3">
          <a href="triage.html" class="btn btn-primary btn-lg" style="flex:1;justify-content:center;" onclick="closeIntroModal()">
            ⚡ Start with Alert Triage
          </a>
          <button onclick="closeIntroModal()" class="btn btn-secondary btn-lg">
            Explore Dashboard
          </button>
        </div>
      </div>`;

    document.body.appendChild(overlay);
    window._closeIntroModal = () => {
      overlay.style.opacity = '0';
      overlay.style.transition = 'opacity 0.2s';
      setTimeout(() => { overlay.remove(); resolve(); }, 200);
    };
    window.closeIntroModal = window._closeIntroModal;
  });
};

/* ── Score export ── */
SENTINEL.logout = function() {
  localStorage.removeItem('sentinel_student_name');
  localStorage.removeItem(this.storageKey);
  localStorage.removeItem('sentinel_intro_seen');
  localStorage.removeItem('sentinel_incident_answers');
  window.location.href = 'index.html';
};

SENTINEL.generateScoreCode = function() {
  const name = (this.getStudentName() || 'ANON').toUpperCase().replace(/\s+/g, '-').slice(0, 12);
  const p = this.getProgress();
  const date = new Date();
  const dateStr = date.getDate().toString().padStart(2,'0') +
                  ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'][date.getMonth()] +
                  date.getFullYear().toString().slice(2);
  const triage  = p.triageCompleted ? `T${p.triageScore || 0}` : 'T--';
  const scns    = `SCN${(p.scenariosCompleted || []).length}/5`;
  const logs    = p.logsCompleted  ? `L${p.logsScore  || 0}` : 'L--';
  const vulns   = p.vulnsCompleted ? `V${p.vulnsScore  || 0}` : 'V--';
  const risk    = p.riskCompleted  ? `R${p.riskScore  || 0}` : 'R--';
  const pts     = (p.totalScore || 0);
  return `SENTINEL·${name}·${dateStr}·${triage}·${scns}·${logs}·${vulns}·${risk}·${pts}PTS`;
};

SENTINEL.copyScoreCode = function() {
  const code = this.generateScoreCode();
  const box  = document.getElementById('score-code-display');
  navigator.clipboard.writeText(code).then(() => {
    if (box) { box.classList.add('score-code-copied'); setTimeout(() => box.classList.remove('score-code-copied'), 2000); }
    this.toast('Score code copied to clipboard!', 'success');
  }).catch(() => {
    this.toast('Copy the code manually from the box above', 'info');
  });
};

/* ── Cross-reference map: alert IDs ↔ scenario IDs ── */
const CROSS_REFS = {
  alertToScenario: {
    1:  { id: 'scenario-1', name: 'Polymorphic Payload' },
    6:  { id: 'scenario-1', name: 'Polymorphic Payload' },
    7:  { id: 'scenario-1', name: 'Polymorphic Payload' },
    16: { id: 'scenario-1', name: 'Polymorphic Payload' },
    3:  { id: 'scenario-2', name: 'The Email Summarizer' },
    11: { id: 'scenario-2', name: 'The Email Summarizer' },
    5:  { id: 'scenario-3', name: 'Ghost Wire Transfer' },
    12: { id: 'scenario-4', name: 'Autonomous Recon' },
    8:  { id: 'scenario-5', name: 'Tainted Update' },
    19: { id: 'scenario-5', name: 'Tainted Update' },
    9:  { id: 'scenario-1', name: 'Polymorphic Payload' }
  },
  scenarioToAlertIds: {
    'scenario-1': [1, 6, 7, 9, 16],
    'scenario-2': [3, 11],
    'scenario-3': [5],
    'scenario-4': [12],
    'scenario-5': [8, 19]
  }
};

/* ── Page ID detection ── */
SENTINEL._getPageId = function() {
  const raw = window.location.pathname.split('/').pop() || 'index.html';
  const page = raw.includes('.') ? raw : (raw || 'index.html') + '.html';
  return { 'index.html': 'dashboard', 'incident-response.html': 'incidents',
           'triage.html': 'triage', 'investigate.html': 'investigate',
           'remediate.html': 'remediate', 'scenarios.html': 'scenarios',
           'logs.html': 'logs', 'vulns.html': 'vulns', 'risk.html': 'risk' }[page] || 'dashboard';
};

SENTINEL._escHtml = function(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
};

/* ── App shell injection (sidebar + topbar) ── */
SENTINEL.renderShell = function() {
  const PAGE_META = {
    dashboard:   { name: 'Command Center',       href: 'index.html',             icon: '⊞' },
    incidents:   { name: 'Incident Response',    href: 'incident-response.html', icon: '⚑' },
    triage:      { name: 'Alert Triage',         href: 'triage.html',            icon: '⚡' },
    investigate: { name: 'Investigation',        href: 'investigate.html',       icon: '🔍' },
    remediate:   { name: 'Remediation Lab',      href: 'remediate.html',         icon: '🛠' },
    scenarios:   { name: 'Scenario Library',     href: 'scenarios.html',         icon: '📋' },
    logs:        { name: 'Log Analysis',         href: 'logs.html',              icon: '📜' },
    vulns:       { name: 'Vuln Prioritization',  href: 'vulns.html',             icon: '🎯' },
    risk:        { name: 'Risk Register',        href: 'risk.html',              icon: '⚖' },
  };
  const pageId  = this._getPageId();
  const current = PAGE_META[pageId];
  const name    = this.getStudentName() || 'Analyst';
  const p       = this.getProgress();
  const score   = (p.totalScore || 0) + ' pts';
  const initials = name.trim().split(/\s+/).map(w => w[0]).join('').toUpperCase().slice(0, 2) || 'A';
  const firstName = this._escHtml(name.split(' ')[0]);
  const hour = new Date().getHours();
  const tod  = hour < 12 ? 'morning' : hour < 17 ? 'afternoon' : 'evening';

  const navItem = ([id, m]) =>
    `<a href="${m.href}" class="nav-item${id === pageId ? ' active' : ''}" data-page="${id}">` +
    `<span class="nav-icon">${m.icon}</span>${m.name}</a>`;

  const sb = document.getElementById('sb');
  if (sb) {
    sb.innerHTML = `<aside class="sidebar">
      <div class="brand">
        <div class="brand-mark"></div>
        <div><div class="brand-text">SENTINEL</div><div class="brand-sub">SOC Simulator</div></div>
      </div>
      <nav style="flex:1;overflow-y:auto;padding:0.25rem 0;">
        <div class="nav-section-label">OPERATIONS</div>
        ${navItem(['dashboard', PAGE_META.dashboard])}
        ${navItem(['incidents', PAGE_META.incidents])}
        <a class="nav-item nav-item-dim" style="opacity:.38;pointer-events:none;cursor:default;" title="Coming soon"><span class="nav-icon">◎</span>Detection &amp; Threat Intel</a>
        <div class="nav-section-label" style="margin-top:0.5rem;">ASSETS</div>
        <a class="nav-item nav-item-dim" style="opacity:.38;pointer-events:none;cursor:default;"><span class="nav-icon">▤</span>Assets</a>
        <a class="nav-item nav-item-dim" style="opacity:.38;pointer-events:none;cursor:default;"><span class="nav-icon">▢</span>Endpoints</a>
        <a class="nav-item nav-item-dim" style="opacity:.38;pointer-events:none;cursor:default;"><span class="nav-icon">⚷</span>Identity</a>
        <div class="nav-section-label" style="margin-top:0.5rem;">TRAINING</div>
        ${navItem(['triage',      PAGE_META.triage])}
        ${navItem(['investigate', PAGE_META.investigate])}
        ${navItem(['remediate',   PAGE_META.remediate])}
        ${navItem(['scenarios',   PAGE_META.scenarios])}
        ${navItem(['logs',        PAGE_META.logs])}
        ${navItem(['vulns',       PAGE_META.vulns])}
        ${navItem(['risk',        PAGE_META.risk])}
      </nav>
      <div class="sidebar-foot">
        <div class="user-card">
          <div class="user-avatar" id="sb-avatar">${this._escHtml(initials)}</div>
          <div>
            <div class="user-name" id="sb-name">${this._escHtml(name)}</div>
            <div class="user-role" id="sb-score">${this._escHtml(score)}</div>
          </div>
        </div>
      </div>
    </aside>`;
  }

  const tb = document.getElementById('topbar-mount');
  if (tb) {
    let navBtn = '';
    if (pageId === 'dashboard') {
      navBtn = `<button id="toggle-incidents-btn" class="btn btn-primary" style="font-size:11px;" onclick="SENTINEL.toggleIncidentsView()">Incidents flow ›</button>`;
    } else if (pageId === 'incidents') {
      navBtn = `<a href="index.html" class="btn" style="font-size:11px;">← Command Center</a>`;
    }
    const sidebarCollapsed = localStorage.getItem('sentinel_sidebar_collapsed') === '1';
    const app = document.querySelector('.app');
    if (app && sidebarCollapsed) app.classList.add('sidebar-collapsed');

    tb.innerHTML = `<header class="topbar">
      <button id="sb-toggle-btn" title="Toggle sidebar" onclick="SENTINEL.toggleSidebar()"
        style="flex-shrink:0;width:30px;height:30px;background:none;border:1px solid var(--line);border-radius:6px;color:var(--text-muted);font-size:15px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:color .15s,border-color .15s;margin-right:8px;"
        onmouseenter="this.style.borderColor='var(--teal)';this.style.color='var(--teal)'"
        onmouseleave="this.style.borderColor='var(--line)';this.style.color='var(--text-muted)'"
        >${sidebarCollapsed ? '☰' : '✕'}</button>
      <div>
        <div class="crumb">SENTINEL <span style="color:var(--text-muted);margin:0 4px;">/</span> <span style="color:var(--text);font-weight:600;">${current.name}</span></div>
        <div class="greeting">Good ${tod}, <strong style="color:var(--teal);">${firstName}</strong></div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">17 APR 2026 · DCOI Thailand · Day 3 — AI-Enabled SIEM/SOC</div>
      </div>
      <div style="flex:1;"></div>
      <div style="display:flex;gap:8px;align-items:center;">
        <span class="pill"><span style="color:var(--teal);">★</span> <span id="topbar-score" style="color:var(--teal);font-weight:700;">${this._escHtml(score)}</span></span>
        <span class="pill">⏱ Last 24H</span>
        <span class="pill live"><span class="dot"></span>STREAMING</span>
        ${navBtn}
        <button class="pill" title="End session" style="cursor:pointer;background:none;color:var(--text-muted);font-family:var(--font-ui);font-size:13px;border-color:var(--line);" onclick="SENTINEL.logout()">⏻</button>
      </div>
    </header>`;
  }
};

/* ── Sidebar collapse toggle ── */
SENTINEL.toggleSidebar = function() {
  const app = document.querySelector('.app');
  if (!app) return;
  const collapsed = app.classList.toggle('sidebar-collapsed');
  localStorage.setItem('sentinel_sidebar_collapsed', collapsed ? '1' : '');
  const btn = document.getElementById('sb-toggle-btn');
  if (btn) btn.textContent = collapsed ? '☰' : '✕';
};

/* ── Incidents view toggle (dashboard only) ── */
SENTINEL.toggleIncidentsView = function() {
  const cmd = document.getElementById('view-command');
  const inc = document.getElementById('view-incidents');
  const btn = document.getElementById('toggle-incidents-btn');
  if (!cmd || !inc) return;
  const showingInc = inc.style.display !== 'none';
  cmd.style.display = showingInc ? '' : 'none';
  inc.style.display = showingInc ? 'none' : '';
  if (btn) btn.textContent = showingInc ? 'Incidents flow ›' : '‹ Command Center';
  if (!showingInc && !inc.dataset.built) {
    inc.dataset.built = '1';
    if (typeof buildIncidentsFlow === 'function') buildIncidentsFlow(inc);
  }
};

/* ── First-visit flow ── */
SENTINEL.initFirstVisit = async function(isDashboard = false) {
  let name = this.getStudentName();
  if (!name) {
    name = await this.showNameModal();
  }
  if (isDashboard && !localStorage.getItem('sentinel_intro_seen')) {
    localStorage.setItem('sentinel_intro_seen', '1');
    await this.showIntroModal(name);
  }
  this.updateNavScore();
};

/* ── Init on DOM ready ── */
document.addEventListener('DOMContentLoaded', () => {
  SENTINEL.renderShell();
  SENTINEL.markActiveNav();
  SENTINEL.updateNavScore();
});
