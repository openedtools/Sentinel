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
    const page = window.location.pathname.split('/').pop() || 'index.html';
    document.querySelectorAll('.nav-link').forEach(link => {
      const href = link.getAttribute('href');
      if (href === page || (page === 'index.html' && href === 'index.html') || (page === '' && href === 'index.html')) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
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

/* ── Init on DOM ready ── */
document.addEventListener('DOMContentLoaded', () => {
  SENTINEL.markActiveNav();
  SENTINEL.updateNavScore();
});
