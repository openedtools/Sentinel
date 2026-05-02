/* SENTINEL — Asset Inventory Module */

const ASSETS = [
  { id:'DC-01',           type:'Server',      os:'Windows Server 2022', owner:'IT-OPS',    criticality:'Critical', zone:'Internal-Core',  lastSeen:'2 min ago',  patch:'Behind',  patchPct:62,  alerts:3, incidents:2, desc:'Primary Domain Controller — controls auth, GPO, DNS for all 41,700 endpoints' },
  { id:'DC-02',           type:'Server',      os:'Windows Server 2022', owner:'IT-OPS',    criticality:'Critical', zone:'Internal-Core',  lastSeen:'4 min ago',  patch:'Behind',  patchPct:62,  alerts:1, incidents:1, desc:'Backup Domain Controller — FSMO roles holder, AD replication' },
  { id:'ERP-SERVER-01',   type:'Server',      os:'Windows Server 2019', owner:'Finance',   criticality:'Critical', zone:'Internal-DMZ',   lastSeen:'1 min ago',  patch:'Current', patchPct:98,  alerts:0, incidents:0, desc:'SAP ERP — financials, procurement, HR payroll for 2,100 staff' },
  { id:'HR-SERVER-01',    type:'Server',      os:'Windows Server 2019', owner:'HR',        criticality:'Critical', zone:'Internal-DMZ',   lastSeen:'3 min ago',  patch:'Current', patchPct:95,  alerts:0, incidents:0, desc:'HR database — PII for 2,100 employees inc. SSN, medical, salary' },
  { id:'MAIL-01',         type:'Server',      os:'Exchange 2019',       owner:'IT-OPS',    criticality:'High',     zone:'DMZ',            lastSeen:'1 min ago',  patch:'Behind',  patchPct:78,  alerts:2, incidents:1, desc:'Corporate mail — CVE-2024-21413 (Outlook RCE, CVSS 9.8) unpatched' },
  { id:'FILE-SERVER-01',  type:'Server',      os:'Windows Server 2022', owner:'IT-OPS',    criticality:'High',     zone:'Internal-Core',  lastSeen:'8 min ago',  patch:'Critical',patchPct:41,  alerts:4, incidents:2, desc:'Primary file share — 2.3 TB corp data · DNS tunnel target (active incident)' },
  { id:'PROXY-01',        type:'Network',     os:'Palo Alto PAN-OS',    owner:'Net-Ops',   criticality:'High',     zone:'Perimeter',      lastSeen:'0 min ago',  patch:'Current', patchPct:100, alerts:1, incidents:0, desc:'Next-gen firewall / web proxy — all outbound traffic flows through this' },
  { id:'VPN-GW-01',       type:'Network',     os:'Cisco IOS-XE',        owner:'Net-Ops',   criticality:'High',     zone:'Perimeter',      lastSeen:'0 min ago',  patch:'Current', patchPct:100, alerts:0, incidents:0, desc:'Remote access VPN gateway — 1,400 concurrent remote workers' },
  { id:'BACKUP-SERVER-01',type:'Server',      os:'Windows Server 2022', owner:'IT-OPS',    criticality:'High',     zone:'Internal-Core',  lastSeen:'12 min ago', patch:'Behind',  patchPct:71,  alerts:1, incidents:1, desc:'Immutable backup target — last resort against ransomware · svc_backup_new anomaly' },
  { id:'WEB-01',          type:'Server',      os:'Ubuntu 22.04 LTS',    owner:'Dev-Ops',   criticality:'Medium',   zone:'DMZ',            lastSeen:'0 min ago',  patch:'Current', patchPct:97,  alerts:0, incidents:0, desc:'Public-facing corporate website — static content, no PII processed' },
  { id:'DEV-SERVER-01',   type:'Server',      os:'Ubuntu 22.04 LTS',    owner:'Dev-Ops',   criticality:'Medium',   zone:'Dev',            lastSeen:'5 min ago',  patch:'Behind',  patchPct:68,  alerts:0, incidents:0, desc:'Developer build server — CI/CD pipelines, no production data' },
  { id:'SCAN-HOST-01',    type:'Server',      os:'Kali Linux',          owner:'SecOps',    criticality:'Medium',   zone:'SecOps',         lastSeen:'15 min ago', patch:'Current', patchPct:100, alerts:0, incidents:0, desc:'Authorized vulnerability scanner — change-controlled scan windows only' },
  { id:'PRINT-01',        type:'Server',      os:'Windows Server 2016', owner:'Facilities',criticality:'Low',      zone:'Internal-User',  lastSeen:'24 min ago', patch:'Critical',patchPct:31,  alerts:0, incidents:0, desc:'Print server — 47 printers, no sensitive data stored' },
  { id:'LEGACY-APP-01',   type:'Server',      os:'Windows Server 2012 R2', owner:'Finance',criticality:'Medium',   zone:'Internal-DMZ',   lastSeen:'18 min ago', patch:'Critical',patchPct:0,   alerts:1, incidents:0, desc:'End-of-life legacy app server — vendor contract expires 30 JUN 2026, no patches available' },
  { id:'WS-001',          type:'Workstation', os:'Windows 11 Pro',      owner:'A.Johnson', criticality:'Medium',   zone:'Internal-User',  lastSeen:'3 min ago',  patch:'Current', patchPct:100, alerts:0, incidents:0, desc:'SOC Analyst workstation' },
  { id:'WS-002',          type:'Workstation', os:'Windows 11 Pro',      owner:'L.Culhane', criticality:'Medium',   zone:'Internal-User',  lastSeen:'6 min ago',  patch:'Current', patchPct:100, alerts:0, incidents:0, desc:'SOC Analyst workstation' },
  { id:'WS-003',          type:'Workstation', os:'Windows 11 Pro',      owner:'M.Stanton', criticality:'Medium',   zone:'Internal-User',  lastSeen:'9 min ago',  patch:'Current', patchPct:100, alerts:0, incidents:0, desc:'SOC Analyst workstation' },
  { id:'WS-004',          type:'Workstation', os:'Windows 11 Pro',      owner:'T.Park',    criticality:'High',     zone:'Internal-User',  lastSeen:'2 min ago',  patch:'Behind',  patchPct:54,  alerts:3, incidents:1, desc:'QUARANTINED — polymorphic payload active · lateral movement source' },
  { id:'WS-005',          type:'Workstation', os:'macOS Sequoia',       owner:'CFO-Office', criticality:'High',    zone:'Internal-User',  lastSeen:'4 min ago',  patch:'Current', patchPct:100, alerts:1, incidents:0, desc:'CFO workstation — spear-phish target (WormGPT campaign)' },
  { id:'WS-006',          type:'Workstation', os:'Windows 11 Pro',      owner:'CEO-Office', criticality:'High',    zone:'Internal-User',  lastSeen:'7 min ago',  patch:'Current', patchPct:100, alerts:1, incidents:0, desc:'CEO workstation — deepfake video delivered via corporate email' },
  { id:'WS-007',          type:'Workstation', os:'Windows 11 Pro',      owner:'Legal',     criticality:'Medium',   zone:'Internal-User',  lastSeen:'11 min ago', patch:'Current', patchPct:100, alerts:0, incidents:0, desc:'Legal department workstation — privileged document access' },
  { id:'WS-008',          type:'Workstation', os:'Windows 11 Pro',      owner:'Finance',   criticality:'Medium',   zone:'Internal-User',  lastSeen:'14 min ago', patch:'Current', patchPct:100, alerts:0, incidents:0, desc:'Finance analyst workstation' },
  { id:'WS-009',          type:'Workstation', os:'Ubuntu 22.04',        owner:'Dev-Ops',   criticality:'Low',      zone:'Dev',            lastSeen:'22 min ago', patch:'Current', patchPct:100, alerts:0, incidents:0, desc:'DevOps engineer workstation — development environment only' },
  { id:'WS-010',          type:'Workstation', os:'Windows 11 Pro',      owner:'HR',        criticality:'Medium',   zone:'Internal-User',  lastSeen:'31 min ago', patch:'Behind',  patchPct:72,  alerts:0, incidents:0, desc:'HR manager workstation — access to all PII in HR-SERVER-01' },
  { id:'WS-011',          type:'Workstation', os:'Windows 11 Pro',      owner:'Compromised', criticality:'Critical', zone:'Internal-User', lastSeen:'2 min ago', patch:'Behind', patchPct:48, alerts:5, incidents:2, desc:'COMPROMISED — lateral movement source, WMI exec to FILE-SERVER-01, port scan origin' },
  { id:'AZURE-VAULT-01',  type:'Cloud',       os:'Azure Key Vault',     owner:'IT-OPS',    criticality:'Critical', zone:'Cloud-Azure',    lastSeen:'0 min ago',  patch:'Current', patchPct:100, alerts:1, incidents:0, desc:'Azure Key Vault — stores 312 secrets inc. API keys, DB creds, TLS private keys' },
  { id:'AWS-S3-LOGS',     type:'Cloud',       os:'AWS S3',              owner:'SecOps',    criticality:'Medium',   zone:'Cloud-AWS',      lastSeen:'0 min ago',  patch:'Current', patchPct:100, alerts:0, incidents:0, desc:'Centralized SIEM log archive — 90-day retention, tamper-evident' },
  { id:'GCP-ML-01',       type:'Cloud',       os:'GCP Vertex AI',       owner:'AI-Team',   criticality:'Medium',   zone:'Cloud-GCP',      lastSeen:'0 min ago',  patch:'Current', patchPct:100, alerts:0, incidents:0, desc:'ML model training environment — no production PII, synthetic data only' },
  { id:'IOT-HVAC-01',     type:'Server',      os:'Embedded Linux 4.9',  owner:'Facilities',criticality:'Low',      zone:'OT-IoT',         lastSeen:'44 min ago', patch:'Critical',patchPct:5,   alerts:0, incidents:0, desc:'Building HVAC controller — isolated from IT network, air-gapped' },
  { id:'KIOSK-LOBBY-01',  type:'Workstation', os:'Windows 10 LTSC',     owner:'Facilities',criticality:'Low',      zone:'Guest',          lastSeen:'2 hrs ago',  patch:'Behind',  patchPct:45,  alerts:0, incidents:0, desc:'Lobby visitor kiosk — guest WiFi registration, isolated guest VLAN' },
];

/* ── Asset Classification Exercise ── */
const CLASS_ASSETS = [
  { id:'ca-dc',    label:'DC-01 — Primary Domain Controller',   role:'Controls authentication for all 41,700 endpoints. Compromise = total org takeover.', sensitivity:'Identity/Auth', zone:'Internal-Core',  correct:'Critical',  hint:'Active Directory is the keys to the kingdom.' },
  { id:'ca-erp',   label:'ERP-SERVER-01 — SAP Financial System', role:'Processes all financial transactions, payroll, and procurement for 2,100 staff.', sensitivity:'Financial/PII',  zone:'Internal-DMZ',   correct:'Critical',  hint:'Disruption stops all business operations.' },
  { id:'ca-hr',    label:'HR-SERVER-01 — Employee PII Database', role:'Stores SSN, salary, medical data for 2,100 employees.', sensitivity:'PII/PHI',       zone:'Internal-DMZ',   correct:'Critical',  hint:'PII breach triggers GDPR/HIPAA notification requirements.' },
  { id:'ca-mail',  label:'MAIL-01 — Corporate Exchange Server',  role:'Handles all internal and external email. Unpatched CVE-2024-21413 (CVSS 9.8).', sensitivity:'Confidential', zone:'DMZ',            correct:'High',      hint:'Mail server breach enables phishing, lateral movement, and data theft.' },
  { id:'ca-web',   label:'WEB-01 — Public Corporate Website',    role:'Static public-facing site. No user PII processed. CDN-fronted.', sensitivity:'Public',       zone:'DMZ',            correct:'Medium',    hint:'Defacement is a reputation issue, not a data breach risk.' },
  { id:'ca-ws004', label:'WS-004 — Quarantined Workstation',     role:'Currently compromised and quarantined. Polymorphic malware active. Standard user.', sensitivity:'Internal',     zone:'Internal-User',  correct:'High',      hint:'Active compromise elevates criticality beyond normal workstation rating.' },
  { id:'ca-dev',   label:'DEV-SERVER-01 — Build Server',         role:'CI/CD pipelines. No production data. Segmented dev network.', sensitivity:'Internal-Dev',  zone:'Dev',            correct:'Medium',    hint:'Supply-chain risk if pipelines are poisoned, but no direct PII/auth risk.' },
  { id:'ca-iot',   label:'IOT-HVAC-01 — Building HVAC Controller',role:'Embedded building controller. Air-gapped from IT network. No data stored.', sensitivity:'Operational', zone:'OT-IoT',         correct:'Low',       hint:'Physical isolation limits blast radius. Availability impact only.' },
  { id:'ca-vault', label:'AZURE-VAULT-01 — Azure Key Vault',     role:'Stores 312 secrets including DB credentials, API keys, and TLS private keys.', sensitivity:'Secrets/Keys', zone:'Cloud-Azure',    correct:'Critical',  hint:'A Key Vault breach exposes every downstream service that uses those secrets.' },
  { id:'ca-kiosk', label:'KIOSK-LOBBY-01 — Visitor Lobby Kiosk', role:'Guest WiFi registration kiosk. Isolated guest VLAN. No corp data access.', sensitivity:'Public',       zone:'Guest',          correct:'Low',       hint:'Complete network isolation makes breach impact very limited.' },
];

let classRatings = {};
let classDone    = false;
let selectedAsset = null;

/* ── Render functions ── */
function renderAssetStats() {
  const container = document.getElementById('asset-stats');
  if (!container) return;
  const critical = ASSETS.filter(a => a.criticality === 'Critical').length;
  const atRisk   = ASSETS.filter(a => a.alerts > 0 || a.patch === 'Critical').length;
  const patchBehind = ASSETS.filter(a => a.patch !== 'Current').length;
  const avgPatch = Math.round(ASSETS.reduce((s,a)=>s+a.patchPct,0)/ASSETS.length);

  document.getElementById('badge-critical-count').textContent = `${critical} Critical`;
  document.getElementById('badge-atrisk-count').textContent   = `${atRisk} At-Risk`;

  container.innerHTML = [
    { label:'Total Assets',     value: ASSETS.length, color:'var(--teal)',     icon:'▤' },
    { label:'Critical Assets',  value: critical,       color:'var(--critical)', icon:'🔴' },
    { label:'Patch Behind',     value: patchBehind,    color:'var(--high)',     icon:'⚠' },
    { label:'Avg Patch Compliance', value: avgPatch+'%', color: avgPatch>=85?'var(--ok)':'var(--medium)', icon:'🛡' },
  ].map(s => `
    <div class="card" style="padding:1rem;">
      <div class="card-title mb-2">${s.icon} ${s.label}</div>
      <div style="font-size:1.875rem;font-weight:700;font-family:var(--font-mono);color:${s.color};line-height:1;">${s.value}</div>
    </div>`).join('');
}

function getFilteredAssets() {
  const q    = (document.getElementById('asset-search')?.value  || '').toLowerCase();
  const type = document.getElementById('filter-type')?.value        || '';
  const crit = document.getElementById('filter-criticality')?.value || '';
  const patch= document.getElementById('filter-patch')?.value       || '';
  return ASSETS.filter(a =>
    (!q    || a.id.toLowerCase().includes(q) || a.owner.toLowerCase().includes(q) || a.os.toLowerCase().includes(q)) &&
    (!type || a.type === type) &&
    (!crit || a.criticality === crit) &&
    (!patch|| a.patch === patch)
  );
}

function filterAssets() {
  const filtered = getFilteredAssets();
  renderAssetTable(filtered);
  const el = document.getElementById('filter-count');
  if (el) el.textContent = `${filtered.length} of ${ASSETS.length} assets`;
}

function clearFilters() {
  ['asset-search','filter-type','filter-criticality','filter-patch'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  filterAssets();
}

const CRIT_COLOR = { Critical:'var(--critical)', High:'var(--high)', Medium:'var(--medium)', Low:'var(--low)' };
const PATCH_COLOR = { Current:'var(--ok)', Behind:'var(--medium)', Critical:'var(--critical)' };

function renderAssetTable(list) {
  const wrap = document.getElementById('asset-table-wrap');
  if (!wrap) return;
  wrap.innerHTML = `
    <table style="width:100%;border-collapse:collapse;">
      <thead>
        <tr style="border-bottom:1px solid var(--line-strong);position:sticky;top:0;background:var(--bg-1);z-index:1;">
          ${['Asset / Host','Type','OS','Owner','Criticality','Patch','Alerts'].map(h =>
            `<th class="text-xs text-muted" style="text-align:left;padding:8px 12px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;white-space:nowrap;">${h}</th>`
          ).join('')}
        </tr>
      </thead>
      <tbody>
        ${list.length === 0 ? `<tr><td colspan="7" style="padding:2rem;text-align:center;" class="text-xs text-muted">No assets match your filters.</td></tr>` :
          list.map(a => `
          <tr id="row-${a.id}" onclick="showAssetDetail('${a.id}')"
            style="border-bottom:1px solid var(--line-soft);cursor:pointer;transition:background .12s;"
            onmouseenter="this.style.background='var(--bg-2)'" onmouseleave="this.style.background=''">
            <td style="padding:8px 12px;font-family:var(--font-mono);font-size:0.75rem;font-weight:600;color:var(--text-primary);">${a.id}</td>
            <td style="padding:8px 12px;"><span class="badge badge-muted" style="font-size:0.5625rem;">${a.type}</span></td>
            <td style="padding:8px 12px;font-size:0.75rem;color:var(--text-muted);white-space:nowrap;">${a.os}</td>
            <td style="padding:8px 12px;font-size:0.75rem;color:var(--text-muted);">${a.owner}</td>
            <td style="padding:8px 12px;">
              <span style="font-size:0.6875rem;font-weight:700;color:${CRIT_COLOR[a.criticality]};">${a.criticality}</span>
            </td>
            <td style="padding:8px 12px;">
              <div style="display:flex;align-items:center;gap:6px;">
                <div style="width:36px;height:4px;background:var(--bg-elevated);border-radius:2px;overflow:hidden;">
                  <div style="height:100%;width:${a.patchPct}%;background:${PATCH_COLOR[a.patch]};border-radius:2px;"></div>
                </div>
                <span style="font-size:0.6875rem;font-family:var(--font-mono);color:${PATCH_COLOR[a.patch]};">${a.patchPct}%</span>
              </div>
            </td>
            <td style="padding:8px 12px;">
              ${a.alerts > 0
                ? `<span style="font-size:0.75rem;font-weight:700;color:var(--critical);">🔴 ${a.alerts}</span>`
                : `<span class="text-xs text-muted">—</span>`}
            </td>
          </tr>`).join('')}
      </tbody>
    </table>`;
}

function showAssetDetail(assetId) {
  const a = ASSETS.find(x => x.id === assetId);
  if (!a) return;
  selectedAsset = assetId;

  const openVulns = a.patch === 'Critical' ? 3 : a.patch === 'Behind' ? 1 : 0;
  const panel = document.getElementById('asset-detail-panel');
  if (!panel) return;

  panel.innerHTML = `
    <div class="card" style="border-color:${CRIT_COLOR[a.criticality]}40;">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:0.75rem;">
        <div>
          <div style="font-size:1rem;font-weight:700;font-family:var(--font-mono);color:var(--text-primary);">${a.id}</div>
          <div class="text-xs text-muted mt-1">${a.type} · ${a.zone}</div>
        </div>
        <span style="font-size:0.75rem;font-weight:700;color:${CRIT_COLOR[a.criticality]};background:${CRIT_COLOR[a.criticality]}18;padding:3px 8px;border-radius:4px;">${a.criticality}</span>
      </div>

      <div class="text-xs text-muted mb-3" style="line-height:1.6;">${a.desc}</div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:0.75rem;">
        <div style="background:var(--bg-2);border-radius:6px;padding:8px;">
          <div class="text-xs text-muted mb-1">OS</div>
          <div style="font-size:0.75rem;color:var(--text-primary);">${a.os}</div>
        </div>
        <div style="background:var(--bg-2);border-radius:6px;padding:8px;">
          <div class="text-xs text-muted mb-1">Owner</div>
          <div style="font-size:0.75rem;color:var(--text-primary);">${a.owner}</div>
        </div>
        <div style="background:var(--bg-2);border-radius:6px;padding:8px;">
          <div class="text-xs text-muted mb-1">Last Seen</div>
          <div style="font-size:0.75rem;color:var(--text-primary);">${a.lastSeen}</div>
        </div>
        <div style="background:var(--bg-2);border-radius:6px;padding:8px;">
          <div class="text-xs text-muted mb-1">Patch Compliance</div>
          <div style="font-size:0.75rem;font-weight:700;color:${PATCH_COLOR[a.patch]};">${a.patchPct}% · ${a.patch}</div>
        </div>
      </div>

      <hr class="divider">
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:6px;text-align:center;">
        <div>
          <div style="font-size:1.375rem;font-weight:700;font-family:var(--font-mono);color:${a.alerts>0?'var(--critical)':'var(--ok)'};">${a.alerts}</div>
          <div class="text-xs text-muted">Open Alerts</div>
        </div>
        <div>
          <div style="font-size:1.375rem;font-weight:700;font-family:var(--font-mono);color:${a.incidents>0?'var(--high)':'var(--ok)'};">${a.incidents}</div>
          <div class="text-xs text-muted">Incidents</div>
        </div>
        <div>
          <div style="font-size:1.375rem;font-weight:700;font-family:var(--font-mono);color:${openVulns>0?'var(--medium)':'var(--ok)'};">${openVulns}</div>
          <div class="text-xs text-muted">Open Vulns</div>
        </div>
      </div>
      ${a.alerts > 0 || a.incidents > 0 ? `
        <div style="margin-top:0.75rem;padding:8px 10px;background:rgba(244,63,94,0.06);border:1px solid rgba(244,63,94,0.2);border-radius:6px;">
          <div class="text-xs" style="color:var(--critical);font-weight:600;">⚠ Active Security Events</div>
          <div class="text-xs text-muted mt-1">Investigate in the Incident Investigation module.</div>
        </div>` : ''}
    </div>`;
}

/* ── Classification Exercise ── */
function renderClassification() {
  const grid = document.getElementById('classification-grid');
  if (!grid) return;

  grid.innerHTML = CLASS_ASSETS.map(a => {
    const rating = classRatings[a.id] || '';
    return `
      <div style="padding:12px;border:1px solid var(--line-soft);border-radius:8px;background:var(--bg-2);">
        <div style="font-size:0.8125rem;font-weight:600;color:var(--text-primary);margin-bottom:4px;">${a.label}</div>
        <div class="text-xs text-muted mb-1">Role: ${a.role}</div>
        <div class="flex gap-2 mb-2">
          <span class="tag" style="font-size:0.5625rem;">Data: ${a.sensitivity}</span>
          <span class="tag" style="font-size:0.5625rem;">Zone: ${a.zone}</span>
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;">
          ${['Critical','High','Medium','Low'].map(lvl => `
            <button onclick="rateAsset('${a.id}','${lvl}')" ${classDone?'disabled':''} class="btn btn-sm"
              style="font-size:0.6875rem;padding:3px 8px;border-color:${rating===lvl?CRIT_COLOR[lvl]:'var(--line-strong)'};
                     color:${rating===lvl?CRIT_COLOR[lvl]:'var(--text-muted)'};
                     background:${rating===lvl?CRIT_COLOR[lvl]+'18':'transparent'};">
              ${lvl}
            </button>`).join('')}
        </div>
      </div>`;
  }).join('');

  const rated = Object.keys(classRatings).length;
  const prog  = document.getElementById('class-progress');
  if (prog) prog.textContent = `${rated} / 10 rated`;
  const submitRow = document.getElementById('class-submit-row');
  if (submitRow) submitRow.style.display = !classDone && rated === 10 ? 'block' : 'none';
}

function rateAsset(assetId, rating) {
  if (classDone) return;
  classRatings[assetId] = rating;
  renderClassification();
}

function submitClassification() {
  if (classDone) return;
  classDone = true;

  let correct = 0;
  CLASS_ASSETS.forEach(a => { if (classRatings[a.id] === a.correct) correct++; });
  const score = correct * 5;
  const pct   = Math.round((correct / 10) * 100);

  const resultsEl = document.getElementById('class-results');
  const submitRow = document.getElementById('class-submit-row');
  if (submitRow) submitRow.style.display = 'none';

  const scoreBadge = document.getElementById('class-score-badge');
  if (scoreBadge) { scoreBadge.textContent = `${score} pts`; }

  if (resultsEl) {
    resultsEl.style.display = 'block';
    resultsEl.innerHTML = `
      <div style="background:rgba(94,234,212,0.06);border:1px solid rgba(94,234,212,0.25);border-radius:10px;padding:1rem;margin-bottom:1rem;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.5rem;">
          <div style="font-size:1rem;font-weight:700;color:var(--text-primary);">${correct}/10 correct · ${SENTINEL.scoreLabel(pct)}</div>
          <div style="font-size:1.5rem;font-weight:700;font-family:var(--font-mono);color:var(--teal);">${score} pts</div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:0.75rem;">
          ${CLASS_ASSETS.map(a => {
            const isCorrect = classRatings[a.id] === a.correct;
            return `
              <div style="padding:8px 10px;border-radius:6px;border:1px solid ${isCorrect?'rgba(74,222,128,0.3)':'rgba(244,63,94,0.3)'};background:${isCorrect?'rgba(74,222,128,0.06)':'rgba(244,63,94,0.06)'};">
                <div style="font-size:0.6875rem;font-weight:700;color:${isCorrect?'var(--ok)':'var(--critical)'};">${isCorrect?'✓':'✗'} ${a.label.split('—')[0].trim()}</div>
                ${!isCorrect?`<div class="text-xs text-muted">You: <span style="color:var(--medium);">${classRatings[a.id]||'—'}</span> · Correct: <span style="color:var(--ok);">${a.correct}</span></div>`:''}
                <div class="text-xs text-muted" style="line-height:1.5;margin-top:2px;">${a.hint}</div>
              </div>`;
          }).join('')}
        </div>
      </div>`;
  }

  renderClassification();
  saveAssetsScore(score);
  SENTINEL.toast(`Asset Classification complete — ${score}/50 pts (${correct}/10 correct)`, score >= 40 ? 'success' : score >= 25 ? 'info' : 'warning');
}

function saveAssetsScore(score) {
  const p = SENTINEL.getProgress();
  const prev = p.assetsCompleted ? (p.assetsScore || 0) : 0;
  if (!p.assetsCompleted || score > prev) {
    const delta = score - prev;
    p.assetsScore     = score;
    p.assetsCompleted = true;
    p.totalScore = (p.totalScore || 0) + delta;
    SENTINEL.saveProgress(p);
    SENTINEL.updateNavScore();
  }
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', () => {
  SENTINEL.initFirstVisit();
  renderAssetStats();
  filterAssets();
  renderClassification();
});
