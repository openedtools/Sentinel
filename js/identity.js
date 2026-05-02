/* SENTINEL — Identity & Access Module */

const USERS = [
  { id:'u01',  name:'A. Johnson',      role:'SOC Analyst',            dept:'SecOps',   priv:'Standard',       mfa:true,  lastLogin:'17 APR 05:42', accountAge:'1.2 yrs', risk:'Low',      groups:['SOC-Analysts'],                          notes:'' },
  { id:'u02',  name:'L. Culhane',      role:'SOC Analyst',            dept:'SecOps',   priv:'Standard',       mfa:true,  lastLogin:'17 APR 06:01', accountAge:'2.1 yrs', risk:'Low',      groups:['SOC-Analysts'],                          notes:'' },
  { id:'u03',  name:'Admin-Primary',   role:'Domain Administrator',   dept:'IT-OPS',   priv:'Domain Admin',   mfa:false, lastLogin:'14 APR 22:10', accountAge:'5.4 yrs', risk:'Critical', groups:['Domain Admins','Enterprise Admins'],    notes:'No MFA on DA account' },
  { id:'u04',  name:'svc_backup',      role:'Backup Service Account', dept:'IT-OPS',   priv:'Local Admin',    mfa:false, lastLogin:'17 APR 04:33', accountAge:'3.8 yrs', risk:'High',     groups:['Backup-Operators','Domain Admins'],      notes:'Service acct in Domain Admins — least privilege violation' },
  { id:'u05',  name:'svc_backup_new',  role:'Service Account (NEW)',  dept:'IT-OPS',   priv:'Domain Admin',   mfa:false, lastLogin:'17 APR 04:47', accountAge:'0 days',  risk:'Critical', groups:['Domain Admins','Administrators'],        notes:'Created outside change window — active incident' },
  { id:'u06',  name:'CEO-Office',      role:'Chief Executive Officer',dept:'Executive',priv:'Privileged User', mfa:true,  lastLogin:'17 APR 07:12', accountAge:'6.1 yrs', risk:'Medium',   groups:['Executives','Finance-Read'],             notes:'Deepfake delivery target' },
  { id:'u07',  name:'CFO-Office',      role:'Chief Financial Officer',dept:'Finance',  priv:'Privileged User', mfa:true,  lastLogin:'17 APR 06:44', accountAge:'4.2 yrs', risk:'High',     groups:['Executives','Finance-Full','Wire-Auth'], notes:'Spear-phish target (WormGPT)' },
  { id:'u08',  name:'J. Retired',      role:'Former IT Director',     dept:'IT-OPS',   priv:'Local Admin',    mfa:false, lastLogin:'89 days ago',  accountAge:'8.9 yrs', risk:'High',     groups:['IT-Staff','Local-Admins','VPN-Users'],   notes:'Stale account — should be disabled' },
  { id:'u09',  name:'T. Park',         role:'IT Support Specialist',  dept:'IT-OPS',   priv:'Local Admin',    mfa:true,  lastLogin:'17 APR 02:14', accountAge:'1.8 yrs', risk:'High',     groups:['IT-Support','Local-Admins'],             notes:'Workstation WS-004 compromised' },
  { id:'u10',  name:'Guest-Acct-01',   role:'Guest / Temp',           dept:'Visitors', priv:'Standard',       mfa:false, lastLogin:'Never',        accountAge:'2.3 yrs', risk:'Medium',   groups:['Guest'],                                 notes:'Never-logged-in account — should be reviewed/disabled' },
  { id:'u11',  name:'dev-alice',       role:'Software Engineer',      dept:'Dev-Ops',  priv:'Standard',       mfa:true,  lastLogin:'17 APR 08:00', accountAge:'0.9 yrs', risk:'Low',      groups:['Developers','Git-Contributors'],          notes:'' },
  { id:'u12',  name:'hr-manager',      role:'HR Manager',             dept:'HR',       priv:'Privileged User', mfa:false, lastLogin:'16 APR 14:23', accountAge:'3.5 yrs', risk:'High',     groups:['HR-Staff','HR-PII-Full','Finance-Read'],  notes:'HR data access without MFA' },
  { id:'u13',  name:'Admin-DR',        role:'DR Domain Admin',        dept:'IT-OPS',   priv:'Domain Admin',   mfa:true,  lastLogin:'Never',        accountAge:'4.1 yrs', risk:'High',     groups:['Domain Admins'],                         notes:'Disaster-recovery admin — never used, never rotated password' },
  { id:'u14',  name:'svc_legacy_app',  role:'Legacy App Service Acct',dept:'Finance',  priv:'Privileged User', mfa:false, lastLogin:'17 APR 00:02', accountAge:'7.2 yrs', risk:'Medium',   groups:['Legacy-App-Users','DB-Readers'],          notes:'Service account with interactive logon enabled' },
  { id:'u15',  name:'finance-user',    role:'Finance Analyst',        dept:'Finance',  priv:'Standard',       mfa:true,  lastLogin:'17 APR 07:55', accountAge:'1.1 yrs', risk:'Low',      groups:['Finance-Read'],                           notes:'' },
];

/* ── Identity Risk Audit challenge ── */
const AUDIT_FLAGS = [
  'Least-privilege violation',
  'MFA not enforced',
  'Account should be disabled',
  'No action needed',
];

const AUDIT_ACCOUNTS = [
  {
    id:'aa01', name:'Admin-Primary', role:'Domain Administrator', dept:'IT-OPS',
    mfa:false, lastLogin:'3 days ago', priv:'Domain Admin', groups:['Domain Admins','Enterprise Admins'],
    detail:'No MFA enrolled. Last login 3 days ago (off-hours). Full DA + EA membership.',
    correct:['MFA not enforced'],
    explanation:'Domain Admin without MFA is the highest-risk identity configuration. A single credential breach = total domain compromise. MFA is non-negotiable for any privileged account. Least-privilege isn\'t violated here if DA access is legitimate — but MFA must be enforced.'
  },
  {
    id:'aa02', name:'svc_backup', role:'Backup Service Account', dept:'IT-OPS',
    mfa:false, lastLogin:'Today (automated)', priv:'Local Admin + Domain Admin', groups:['Backup-Operators','Domain Admins'],
    detail:'Backup service account in both Backup-Operators AND Domain Admins. Interactive logon enabled. No MFA (service account).',
    correct:['Least-privilege violation'],
    explanation:'A backup service account only needs Backup-Operators rights — not Domain Admin. This is a textbook least-privilege violation. Service accounts should use managed service accounts (gMSA) with no interactive logon capability. MFA can\'t be applied to automated service accounts, so that flag doesn\'t apply.'
  },
  {
    id:'aa03', name:'svc_backup_new', role:'Service Account (created today)', dept:'IT-OPS',
    mfa:false, lastLogin:'Today 04:47 (active incident)', priv:'Domain Admin', groups:['Domain Admins','Administrators'],
    detail:'Created OUTSIDE change window at 04:33. Immediately added to Domain Admins. Active incident — lateral movement origin.',
    correct:['Least-privilege violation','Account should be disabled'],
    explanation:'This account was created by the attacker to establish persistence. It should be disabled immediately. It\'s also a massive least-privilege violation — a new service account with DA rights is never appropriate. Both flags apply.'
  },
  {
    id:'aa04', name:'J. Retired', role:'Former IT Director (departed)', dept:'IT-OPS',
    mfa:false, lastLogin:'89 days ago', priv:'Local Admin + VPN access', groups:['IT-Staff','Local-Admins','VPN-Users'],
    detail:'Employee departed. Account not offboarded. Last login 89 days ago. Still has local admin and VPN rights.',
    correct:['Account should be disabled'],
    explanation:'Offboarding failure — this is an orphaned account. Former employees\' accounts must be disabled on their last day. 89 days of potential unauthorized access is a serious gap. Local admin + VPN makes this a high-value target for an attacker with the credentials.'
  },
  {
    id:'aa05', name:'dev-alice', role:'Software Engineer', dept:'Dev-Ops',
    mfa:true, lastLogin:'Today (normal hours)', priv:'Standard', groups:['Developers','Git-Contributors'],
    detail:'MFA enrolled. Standard user. Active today. Access limited to dev systems and Git.',
    correct:['No action needed'],
    explanation:'dev-alice has the right access level for their role (standard user, dev systems only), MFA is enrolled, and the account is actively used. This is what a correctly configured developer account looks like.'
  },
  {
    id:'aa06', name:'hr-manager', role:'HR Manager (PII access)', dept:'HR',
    mfa:false, lastLogin:'Yesterday', priv:'Privileged User', groups:['HR-Staff','HR-PII-Full','Finance-Read'],
    detail:'HR-PII-Full gives access to all 2,100 employee records. MFA not enrolled. Finance-Read on top of HR role.',
    correct:['MFA not enforced','Least-privilege violation'],
    explanation:'Anyone with access to PII for 2,100 employees must have MFA — full stop. The Finance-Read group also violates least-privilege; HR managers don\'t need read access to financial systems for their job function. Both violations apply.'
  },
  {
    id:'aa07', name:'Admin-DR', role:'Disaster Recovery Admin', dept:'IT-OPS',
    mfa:true, lastLogin:'Never', priv:'Domain Admin', groups:['Domain Admins'],
    detail:'Created 4 years ago for DR testing. MFA enrolled but never activated. Password never rotated. Never logged in.',
    correct:['Account should be disabled'],
    explanation:'A never-used Domain Admin account with a 4-year-old password is a ticking time bomb. It should be disabled until needed, with just-in-time access granted only during DR exercises. Active but never-used privileged accounts violate PAM best practice. MFA is enrolled (not a violation), but the account should still be disabled.'
  },
  {
    id:'aa08', name:'Guest-Acct-01', role:'Guest / Temporary', dept:'Visitors',
    mfa:false, lastLogin:'Never', priv:'Standard', groups:['Guest'],
    detail:'Guest account created 2.3 years ago. Never logged in. No MFA (guest account).',
    correct:['Account should be disabled'],
    explanation:'Guest and temporary accounts that have never been used and are over 2 years old should be removed. They represent orphaned credentials that an attacker could leverage. MFA is typically not required for guest accounts, so that flag doesn\'t apply — but the account should be disabled or deleted.'
  },
  {
    id:'aa09', name:'svc_legacy_app', role:'Legacy Application Service Account', dept:'Finance',
    mfa:false, lastLogin:'Today (automated)', priv:'Privileged User + interactive logon', groups:['Legacy-App-Users','DB-Readers'],
    detail:'7-year-old service account. Interactive logon enabled — an actual human can log in with these credentials. No MFA.',
    correct:['Least-privilege violation'],
    explanation:'Service accounts should never have interactive logon enabled. This allows a human to use the credentials to log into any workstation — violating the principle that service accounts are for machines only (T1078.003). The lack of MFA is expected for automated service accounts, so that flag doesn\'t apply. Fix: convert to a gMSA (Group Managed Service Account) and disable interactive logon.'
  },
  {
    id:'aa10', name:'L. Culhane', role:'SOC Analyst', dept:'SecOps',
    mfa:true, lastLogin:'Today 06:01 (active work)', priv:'Standard', groups:['SOC-Analysts'],
    detail:'MFA enrolled. Active during work hours. Standard user with SOC tool access only.',
    correct:['No action needed'],
    explanation:'L. Culhane has appropriate access (standard user, SOC tools only), MFA enrolled, and active normal-hours usage. This is correctly configured and no action is needed.'
  },
  {
    id:'aa11', name:'CFO-Office', role:'Chief Financial Officer', dept:'Finance',
    mfa:true, lastLogin:'Today (spear-phish target)', priv:'Privileged User', groups:['Executives','Finance-Full','Wire-Auth'],
    detail:'MFA enrolled. Wire-Auth group allows initiating wire transfers. Active spear-phish target (WormGPT campaign).',
    correct:['Least-privilege violation'],
    explanation:'Wire-Auth in addition to Finance-Full gives excessive privilege. The CFO may have a business need for Wire-Auth, but Finance-Full access on top of it creates an overly broad attack surface. Given the active spear-phish targeting this account, a privilege review is warranted. MFA is correctly enrolled. Flag: least-privilege review needed.'
  },
  {
    id:'aa12', name:'T. Park', role:'IT Support Specialist', dept:'IT-OPS',
    mfa:true, lastLogin:'Today 02:14 (off-hours — incident)', priv:'Local Admin', groups:['IT-Support','Local-Admins'],
    detail:'MFA enrolled. Workstation WS-004 is compromised. Login at 02:14 outside normal hours during active incident.',
    correct:['Account should be disabled'],
    explanation:'When an analyst\'s workstation is confirmed compromised, their account credentials must be treated as stolen. The account should be disabled, credentials reset, and MFA re-enrolled from a clean device before restoring access. Off-hours login during an incident confirms the attacker may already have the credentials.'
  },
];

let auditAnswers = {};
let auditDone    = false;

/* ── Render functions ── */
function renderIdStats() {
  const container = document.getElementById('id-stats');
  if (!container) return;

  const critRisk = USERS.filter(u=>u.risk==='Critical').length;
  const noMFA    = USERS.filter(u=>!u.mfa).length;
  const domainAdmins = USERS.filter(u=>u.priv==='Domain Admin').length;
  const stale    = USERS.filter(u=>u.lastLogin.includes('days ago')||u.lastLogin==='Never').length;

  document.getElementById('id-badge-critical').textContent = `${critRisk} Critical`;
  document.getElementById('id-badge-nomfa').textContent    = `${noMFA} No MFA`;

  container.innerHTML = [
    { label:'Total Accounts',  value:USERS.length,   color:'var(--teal)',     icon:'⚷' },
    { label:'Domain Admins',   value:domainAdmins,   color:'var(--critical)', icon:'👑' },
    { label:'No MFA Enrolled', value:noMFA,          color:'var(--high)',     icon:'⚠' },
    { label:'Stale Accounts',  value:stale,          color:'var(--medium)',   icon:'⏱' },
  ].map(s=>`
    <div class="card" style="padding:1rem;">
      <div class="card-title mb-2">${s.icon} ${s.label}</div>
      <div style="font-size:1.875rem;font-weight:700;font-family:var(--font-mono);color:${s.color};line-height:1;">${s.value}</div>
    </div>`).join('');

  /* Risk banner for active incidents */
  const banner = document.getElementById('id-risk-banner');
  if (banner) {
    banner.style.display = 'block';
    banner.innerHTML = `
      <div style="padding:12px 16px;background:rgba(244,63,94,0.08);border:1px solid rgba(244,63,94,0.3);border-radius:8px;display:flex;align-items:center;gap:12px;">
        <div style="font-size:1.25rem;">🚨</div>
        <div>
          <div style="font-size:0.875rem;font-weight:700;color:var(--critical);margin-bottom:2px;">ACTIVE IDENTITY THREAT — svc_backup_new</div>
          <div class="text-xs text-muted">New Domain Admin account created outside change window at 04:33. This is the lateral movement account from the active WS-011 incident.
            Investigate in Incident Investigation → Polymorphic Payload scenario.</div>
        </div>
      </div>`;
  }
}

const RISK_COLOR = { Critical:'var(--critical)', High:'var(--high)', Medium:'var(--medium)', Low:'var(--ok)' };

function getFilteredUsers() {
  const q    = (document.getElementById('id-search')?.value      || '').toLowerCase();
  const priv = document.getElementById('id-filter-priv')?.value   || '';
  const risk = document.getElementById('id-filter-risk')?.value   || '';
  return USERS.filter(u =>
    (!q    || u.name.toLowerCase().includes(q) || u.role.toLowerCase().includes(q) || u.dept.toLowerCase().includes(q)) &&
    (!priv || u.priv === priv) &&
    (!risk || u.risk === risk)
  );
}

function filterUsers() {
  const list = getFilteredUsers();
  renderUserTable(list);
  const el = document.getElementById('id-filter-count');
  if (el) el.textContent = `${list.length} of ${USERS.length} accounts`;
}

function clearIdFilters() {
  ['id-search','id-filter-priv','id-filter-risk'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  filterUsers();
}

function renderUserTable(list) {
  const wrap = document.getElementById('id-table-wrap');
  if (!wrap) return;
  wrap.innerHTML = `
    <table style="width:100%;border-collapse:collapse;">
      <thead>
        <tr style="border-bottom:1px solid var(--line-strong);background:var(--bg-1);">
          ${['Name / Account','Role','Dept','Privilege','MFA','Last Login','Risk'].map(h=>
            `<th class="text-xs text-muted" style="text-align:left;padding:8px 10px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;white-space:nowrap;">${h}</th>`
          ).join('')}
        </tr>
      </thead>
      <tbody>
        ${list.length === 0 ? `<tr><td colspan="7" style="padding:2rem;text-align:center;" class="text-xs text-muted">No accounts match.</td></tr>` :
          list.map(u => `
          <tr style="border-bottom:1px solid var(--line-soft);transition:background .12s;"
            onmouseenter="this.style.background='var(--bg-2)'" onmouseleave="this.style.background=''">
            <td style="padding:7px 10px;">
              <div style="font-size:0.8125rem;font-weight:600;color:var(--text-primary);">${u.name}</div>
              ${u.notes?`<div class="text-xs" style="color:var(--high);margin-top:1px;">⚠ ${u.notes}</div>`:''}
            </td>
            <td style="padding:7px 10px;font-size:0.75rem;color:var(--text-muted);">${u.role}</td>
            <td style="padding:7px 10px;font-size:0.75rem;color:var(--text-muted);">${u.dept}</td>
            <td style="padding:7px 10px;">
              <span style="font-size:0.6875rem;font-weight:700;color:${u.priv==='Domain Admin'?'var(--critical)':u.priv==='Local Admin'?'var(--high)':u.priv==='Privileged User'?'var(--medium)':'var(--text-muted)'};">
                ${u.priv}
              </span>
            </td>
            <td style="padding:7px 10px;">
              <span style="font-size:0.75rem;font-weight:700;color:${u.mfa?'var(--ok)':'var(--critical)'};">${u.mfa?'✓ MFA':'✗ None'}</span>
            </td>
            <td style="padding:7px 10px;font-size:0.75rem;color:${u.lastLogin==='Never'||u.lastLogin.includes('days')?'var(--high)':'var(--text-muted)'};">${u.lastLogin}</td>
            <td style="padding:7px 10px;">
              <span style="font-size:0.6875rem;font-weight:700;color:${RISK_COLOR[u.risk]||'var(--text-muted)'};">${u.risk}</span>
            </td>
          </tr>`).join('')}
      </tbody>
    </table>`;
}

function renderPrivSpotlight() {
  const container = document.getElementById('priv-spotlight');
  if (!container) return;
  const privAccounts = USERS.filter(u => u.priv === 'Domain Admin' || u.priv === 'Local Admin');

  container.innerHTML = privAccounts.map(u => `
    <div style="padding:10px;border-radius:6px;background:var(--bg-2);border:1px solid ${u.risk==='Critical'?'rgba(244,63,94,0.3)':u.risk==='High'?'rgba(251,146,60,0.2)':'var(--line-soft)'};margin-bottom:8px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
        <span style="font-size:0.75rem;font-weight:700;color:var(--text-primary);">${u.name}</span>
        <span style="font-size:0.625rem;font-weight:700;color:${RISK_COLOR[u.risk]||'var(--text-muted)'};">${u.risk}</span>
      </div>
      <div class="text-xs text-muted mb-2">${u.role}</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;">
        <span style="font-size:0.5625rem;font-weight:700;color:${u.mfa?'var(--ok)':'var(--critical)'};background:${u.mfa?'rgba(74,222,128,0.1)':'rgba(244,63,94,0.1)'};padding:1px 6px;border-radius:10px;">MFA: ${u.mfa?'YES':'NO'}</span>
        <span style="font-size:0.5625rem;padding:1px 6px;border-radius:10px;background:var(--bg-elev);color:var(--text-muted);">${u.priv}</span>
      </div>
    </div>`).join('');
}

/* ── Identity Risk Audit ── */
function renderAudit() {
  const grid = document.getElementById('audit-grid');
  if (!grid) return;

  grid.innerHTML = AUDIT_ACCOUNTS.map(a => {
    const answers = auditAnswers[a.id] || [];
    return `
      <div style="padding:12px;border:1px solid var(--line-soft);border-radius:8px;background:var(--bg-2);">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:6px;">
          <div>
            <div style="font-size:0.8125rem;font-weight:700;color:var(--text-primary);">${a.name}</div>
            <div class="text-xs text-muted">${a.role} · ${a.dept}</div>
          </div>
          <span style="font-size:0.6875rem;color:${a.mfa?'var(--ok)':'var(--critical)'};font-weight:700;">${a.mfa?'✓ MFA':'✗ No MFA'}</span>
        </div>
        <div class="text-xs text-muted mb-2" style="line-height:1.5;background:var(--bg-0);padding:6px 8px;border-radius:4px;">${a.detail}</div>
        <div style="display:flex;flex-direction:column;gap:4px;">
          ${AUDIT_FLAGS.map(flag => {
            const sel = answers.includes(flag);
            const selColor = flag === 'No action needed' ? 'var(--ok)' : flag === 'MFA not enforced' ? 'var(--critical)' : 'var(--high)';
            return `
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding:4px 6px;border-radius:4px;transition:background .1s;"
                onmouseenter="this.style.background='var(--bg-0)'" onmouseleave="this.style.background=''">
                <input type="checkbox" ${sel?'checked':''} ${auditDone?'disabled':''}
                  onchange="toggleAuditFlag('${a.id}','${flag}',this.checked)"
                  style="accent-color:var(--teal);width:14px;height:14px;">
                <span style="font-size:0.75rem;color:${sel?selColor:'var(--text-muted)'};">${flag}</span>
              </label>`;
          }).join('')}
        </div>
      </div>`;
  }).join('');

  const reviewed = Object.keys(auditAnswers).length;
  const prog = document.getElementById('audit-progress');
  if (prog) prog.textContent = `${reviewed} / 12 reviewed`;
  const submitRow = document.getElementById('audit-submit-row');
  if (submitRow) submitRow.style.display = !auditDone && reviewed === 12 ? 'block' : 'none';
}

function toggleAuditFlag(accountId, flag, checked) {
  if (auditDone) return;
  if (!auditAnswers[accountId]) auditAnswers[accountId] = [];
  if (checked) {
    if (!auditAnswers[accountId].includes(flag)) auditAnswers[accountId].push(flag);
  } else {
    auditAnswers[accountId] = auditAnswers[accountId].filter(f => f !== flag);
  }
  /* Auto-mark reviewed once user touches any checkbox for an account */
  const prog = document.getElementById('audit-progress');
  const reviewed = Object.keys(auditAnswers).length;
  if (prog) prog.textContent = `${reviewed} / 12 reviewed`;
  const submitRow = document.getElementById('audit-submit-row');
  if (submitRow) submitRow.style.display = !auditDone && reviewed === 12 ? 'block' : 'none';
}

function scoreAuditAccount(a) {
  const given   = new Set(auditAnswers[a.id] || []);
  const correct = new Set(a.correct);
  /* Check exact match — all correct flags selected, no incorrect ones */
  const allCorrectSelected  = a.correct.every(f => given.has(f));
  const noWrongSelected     = [...given].every(f => correct.has(f));
  return allCorrectSelected && noWrongSelected;
}

function submitAudit() {
  if (auditDone) return;
  auditDone = true;

  let correct = 0;
  AUDIT_ACCOUNTS.forEach(a => { if (scoreAuditAccount(a)) correct++; });
  const score = correct * 5;
  const pct   = Math.round((correct / 12) * 100);

  const resultsEl = document.getElementById('audit-results');
  const submitRow = document.getElementById('audit-submit-row');
  if (submitRow) submitRow.style.display = 'none';

  const scoreBadge = document.getElementById('audit-score-badge');
  if (scoreBadge) scoreBadge.textContent = `${score} pts`;

  if (resultsEl) {
    resultsEl.style.display = 'block';
    resultsEl.innerHTML = `
      <div style="background:rgba(94,234,212,0.06);border:1px solid rgba(94,234,212,0.25);border-radius:10px;padding:1rem;margin-bottom:1rem;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.5rem;">
          <div style="font-size:1rem;font-weight:700;color:var(--text-primary);">${correct}/12 correct · ${SENTINEL.scoreLabel(pct)}</div>
          <div style="font-size:1.5rem;font-weight:700;font-family:var(--font-mono);color:var(--teal);">${score} pts</div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:0.75rem;">
          ${AUDIT_ACCOUNTS.map(a => {
            const isCorrect = scoreAuditAccount(a);
            const given = auditAnswers[a.id] || [];
            return `
              <div style="padding:10px;border-radius:8px;border:1px solid ${isCorrect?'rgba(74,222,128,0.3)':'rgba(244,63,94,0.3)'};background:${isCorrect?'rgba(74,222,128,0.06)':'rgba(244,63,94,0.06)'};">
                <div style="font-size:0.6875rem;font-weight:700;color:${isCorrect?'var(--ok)':'var(--critical)'};">${isCorrect?'✓':'✗'} ${a.name}</div>
                ${!isCorrect?`
                  <div class="text-xs text-muted">You flagged: <span style="color:var(--medium);">${given.join(', ')||'nothing'}</span></div>
                  <div class="text-xs text-muted">Correct: <span style="color:var(--ok);">${a.correct.join(', ')}</span></div>
                `:''}
                <div class="text-xs text-muted" style="line-height:1.5;border-top:1px solid var(--line-soft);padding-top:4px;margin-top:4px;">${a.explanation}</div>
              </div>`;
          }).join('')}
        </div>
      </div>`;
  }

  renderAudit();
  saveIdentityScore(score);
  SENTINEL.toast(`Identity Audit complete — ${score}/60 pts (${correct}/12 correct)`, score >= 48 ? 'success' : score >= 30 ? 'info' : 'warning');
}

function saveIdentityScore(score) {
  const p = SENTINEL.getProgress();
  const prev = p.identityCompleted ? (p.identityScore || 0) : 0;
  if (!p.identityCompleted || score > prev) {
    const delta = score - prev;
    p.identityScore     = score;
    p.identityCompleted = true;
    p.totalScore = (p.totalScore || 0) + delta;
    SENTINEL.saveProgress(p);
    SENTINEL.updateNavScore();
  }
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', () => {
  SENTINEL.initFirstVisit();
  renderIdStats();
  filterUsers();
  renderPrivSpotlight();
  renderAudit();
});
