/* SENTINEL — Detection & Threat Intel Module */

const IOCS = [
  { id:1, type:'IPv4',     value:'185.220.101.47',                      actor:'APT-NOCTURNE',   source:'GreyNoise',      firstSeen:'17 APR 03:14', status:'active',       tags:['C2','Tor-exit'],       confidence:95 },
  { id:2, type:'SHA-256',  value:'4a9f7c3d18b2e05a...c8d1',             actor:'APT-NOCTURNE',   source:'VirusTotal',     firstSeen:'17 APR 02:58', status:'active',       tags:['ransomware','polymorphic'], confidence:99 },
  { id:3, type:'Domain',   value:'*.exfilbase64[.]co',                  actor:'APT-NOCTURNE',   source:'Threat Feed',    firstSeen:'17 APR 04:22', status:'active',       tags:['DNS-tunnel','exfil'],   confidence:97 },
  { id:4, type:'Filename', value:'wdcu.exe (SHA-256: 3b7e...f9a2)',      actor:'LAZARUS-CLONE',  source:'CISA Advisory',  firstSeen:'17 APR 05:01', status:'active',       tags:['cred-dump','LSASS'],    confidence:98 },
  { id:5, type:'SHA-256',  value:'9f4b2a1c77e36d08...bb3c',             actor:'SUPPLY-CHAIN-X', source:'Internal',       firstSeen:'17 APR 00:35', status:'active',       tags:['tampered','supply-chain'], confidence:91 },
  { id:6, type:'Email',    value:'ai_generated ≥0.97 + display-name spoof', actor:'LAZARUS-CLONE', source:'Proofpoint', firstSeen:'17 APR 06:18', status:'active',       tags:['spear-phish','BEC'],    confidence:94 },
  { id:7, type:'IPv4',     value:'10.14.1.143 (WS-011)',                actor:'Internal',       source:'SIEM',           firstSeen:'17 APR 04:47', status:'investigating', tags:['lateral-movement'],    confidence:88 },
  { id:8, type:'CVE',      value:'CVE-2024-21413 (Outlook RCE, CVSS 9.8)', actor:'LAZARUS-CLONE', source:'NVD',         firstSeen:'16 APR 00:00', status:'patching',     tags:['initial-access','RCE'], confidence:100 },
];

const ACTORS = [
  {
    id: 'APT-NOCTURNE',
    flag: '🌙',
    nation: 'Unknown / Criminal',
    motivation: 'Financial — Ransomware',
    tlp: 'RED',
    tlpColor: 'var(--critical)',
    techniques: ['DNS Tunneling (T1071.004)', 'Polymorphic Payloads (T1027)', 'C2 over HTTPS (T1071.001)', 'Data Exfiltration (T1048)'],
    iocIds: [1, 2, 3],
  },
  {
    id: 'LAZARUS-CLONE',
    flag: '🔒',
    nation: 'DPRK-linked TTPs',
    motivation: 'Credential Theft + Espionage',
    tlp: 'AMBER',
    tlpColor: 'var(--high)',
    techniques: ['Credential Dumping (T1003.001)', 'Spear Phishing (T1566.001)', 'WMI Exec (T1047)', 'Phishing Link (T1566.002)'],
    iocIds: [4, 6, 8],
  },
  {
    id: 'SUPPLY-CHAIN-X',
    flag: '📦',
    nation: 'Unknown — Nation-state suspected',
    motivation: 'Supply Chain Compromise',
    tlp: 'AMBER',
    tlpColor: 'var(--high)',
    techniques: ['Trojanized Software (T1195.002)', 'Trusted Relationship (T1199)', 'Signed Binary Proxy (T1218)'],
    iocIds: [5],
  },
];

const RULES = [
  { id:'RULE-001', name:'Polymorphic Binary Detection', type:'Behavioral', status:'active',  matches:3,
    logic:'hash_change_rate > 2/hr AND process_injection = true → CRITICAL',
    secplus:'T1027 — Obfuscated Files or Information' },
  { id:'RULE-002', name:'DNS Tunnel Exfil Pattern',     type:'Signature',  status:'active',  matches:847,
    logic:'dns_query_rate > 200/min AND query_entropy > 4.2 → HIGH',
    secplus:'T1071.004 — DNS Application Layer Protocol' },
  { id:'RULE-003', name:'LSASS Memory Access',          type:'Behavioral', status:'active',  matches:1,
    logic:'target_process = lsass.exe AND access_type = VM_READ AND signer = untrusted → CRITICAL',
    secplus:'T1003.001 — OS Credential Dumping: LSASS Memory' },
  { id:'RULE-004', name:'WMI Lateral Movement',         type:'Behavioral', status:'active',  matches:2,
    logic:'wmi_exec = true AND encoded_command = true AND src_host != dst_host → HIGH',
    secplus:'T1047 — Windows Management Instrumentation' },
  { id:'RULE-005', name:'AI-Generated Phish Classifier', type:'ML Model',  status:'active',  matches:14,
    logic:'llm_score > 0.90 AND display_name_mismatch = true → HIGH',
    secplus:'T1566.001 — Phishing: Spearphishing Attachment' },
  { id:'RULE-006', name:'Software Hash Integrity Check', type:'Signature', status:'active',  matches:1,
    logic:'install_hash != vendor_manifest_hash → HIGH',
    secplus:'T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain' },
];

/* ── IOC Matching Challenge data ── */
const CHALLENGE_IOCS = [
  { id:'ci1', label:'*.exfilbase64[.]co',            type:'Domain',   color:'var(--high)' },
  { id:'ci2', label:'wdcu.exe (cred-dump tool)',     type:'Filename', color:'var(--critical)' },
  { id:'ci3', label:'10.14.1.143 (WS-011)',          type:'IPv4',     color:'var(--medium)' },
  { id:'ci4', label:'SHA-256: 4a9f7c3d...c8d1',     type:'SHA-256',  color:'var(--critical)' },
  { id:'ci5', label:'SHA-256: 9f4b2a1c...bb3c',     type:'SHA-256',  color:'var(--high)' },
  { id:'ci6', label:'ai_generated_score ≥ 0.97',    type:'Email',    color:'var(--medium)' },
];

const CHALLENGE_ALERTS = [
  { id:'ca1', title:'DNS tunneling from FILE-SERVER-01',
    desc:'FILE-SERVER-01 → *.exfilbase64[.]co · 847 queries in 4 min · encoded subdomains',
    correctIoc:'ci1',
    explanation:'The domain *.exfilbase64[.]co is the C2 tunnel destination. High-volume DNS queries with random subdomains are the exfiltration channel. (T1071.004)' },
  { id:'ca2', title:'LSASS memory access on DC-01',
    desc:'wdcu.exe read LSASS at 05:01 · unsigned binary · 22 credential hashes extracted',
    correctIoc:'ci2',
    explanation:'wdcu.exe is a custom credential-dumping tool. Its presence and LSASS memory access indicates credential theft (T1003.001). The filename hash links back to LAZARUS-CLONE tooling.' },
  { id:'ca3', title:'WMI lateral movement WS-011 → FILE-SERVER-01',
    desc:'Encoded PowerShell via WMI · src: 10.14.1.143 · dst: FILE-SERVER-01 · 04:47',
    correctIoc:'ci3',
    explanation:'The source IP 10.14.1.143 is WS-011, the already-compromised host used for lateral movement. The internal IP is an IOC because it shows the pivot path (T1047).' },
  { id:'ca4', title:'Polymorphic executable on WS-004',
    desc:'Binary mutation every 8 min · AV bypassed × 3 · process injection into svchost.exe',
    correctIoc:'ci4',
    explanation:'The SHA-256 hash 4a9f7c3d...c8d1 is the initial dropper before mutation. Even though it mutates, the parent hash remains constant and is the actionable IOC (T1027).' },
  { id:'ca5', title:'Software update hash mismatch — IntelAnalyticsSuite v4.2.1',
    desc:'Downloaded hash: 9f4b2a1c...bb3c · Vendor manifest: 7e3c1a9d...0f44 · MISMATCH',
    correctIoc:'ci5',
    explanation:'The mismatched SHA-256 hash 9f4b2a1c...bb3c identifies the trojanized installer. Hash mismatch = supply chain compromise. Block and quarantine immediately (T1195.002).' },
  { id:'ca6', title:'WormGPT spear-phish targeting CFO',
    desc:'From: ceo@exec-corp[.]co (spoofed) · ai_generated_score=0.97 · Proofpoint blocked',
    correctIoc:'ci6',
    explanation:'The AI-generated score ≥ 0.97 pattern is the behavioral IOC — it marks messages crafted by LLMs to evade human detection. Combined with display-name spoofing it\'s a strong BEC indicator (T1566.001).' },
];

let selectedChipId  = null;
let assignments     = {};
let challengeDone   = false;

/* ── Render functions ── */
function renderStats() {
  const container = document.getElementById('intel-stats');
  if (!container) return;
  const stats = [
    { label:'IOCs Tracked',    value: IOCS.length,                            color:'var(--teal)',     icon:'◎' },
    { label:'Active Actors',   value: ACTORS.length,                          color:'var(--critical)', icon:'⚑' },
    { label:'Rules Firing',    value: RULES.filter(r=>r.status==='active').length, color:'var(--ok)', icon:'⚡' },
    { label:'Avg Confidence',  value: Math.round(IOCS.reduce((s,i)=>s+i.confidence,0)/IOCS.length)+'%', color:'var(--medium)', icon:'▲' },
  ];
  container.innerHTML = stats.map(s => `
    <div class="card" style="padding:1rem;">
      <div class="card-title mb-2">${s.icon} ${s.label}</div>
      <div style="font-size:1.875rem;font-weight:700;font-family:var(--font-mono);color:${s.color};line-height:1;">${s.value}</div>
    </div>`).join('');
}

function renderIOCTable(list) {
  const container = document.getElementById('ioc-table');
  if (!container) return;
  if (!list || list.length === 0) {
    container.innerHTML = '<div class="text-xs text-muted" style="padding:1rem;text-align:center;">No IOCs match filter.</div>';
    return;
  }
  const statusColor = { active:'var(--critical)', investigating:'var(--medium)', patching:'var(--low)' };
  container.innerHTML = `
    <table style="width:100%;border-collapse:collapse;">
      <thead>
        <tr style="border-bottom:1px solid var(--line-strong);">
          <th class="text-xs text-muted" style="text-align:left;padding:4px 8px 8px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;">Type</th>
          <th class="text-xs text-muted" style="text-align:left;padding:4px 8px 8px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;">Value</th>
          <th class="text-xs text-muted" style="text-align:left;padding:4px 8px 8px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;">Actor</th>
          <th class="text-xs text-muted" style="text-align:left;padding:4px 8px 8px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;">Tags</th>
          <th class="text-xs text-muted" style="text-align:left;padding:4px 8px 8px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;">Confidence</th>
          <th class="text-xs text-muted" style="text-align:left;padding:4px 8px 8px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;">Status</th>
        </tr>
      </thead>
      <tbody>
        ${list.map(ioc => `
          <tr style="border-bottom:1px solid var(--line-soft);transition:background .15s;" onmouseenter="this.style.background='var(--bg-2)'" onmouseleave="this.style.background=''">
            <td style="padding:7px 8px;"><span class="badge badge-muted" style="font-size:0.625rem;">${ioc.type}</span></td>
            <td style="padding:7px 8px;font-family:var(--font-mono);font-size:0.75rem;color:var(--text-primary);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${ioc.value}">${ioc.value}</td>
            <td style="padding:7px 8px;font-size:0.75rem;color:var(--text-muted);">${ioc.actor}</td>
            <td style="padding:7px 8px;">${ioc.tags.map(t=>`<span class="tag" style="font-size:0.5625rem;margin-right:2px;">${t}</span>`).join('')}</td>
            <td style="padding:7px 8px;">
              <div style="display:flex;align-items:center;gap:6px;">
                <div style="flex:1;height:4px;background:var(--bg-elevated);border-radius:2px;overflow:hidden;min-width:40px;">
                  <div style="height:100%;width:${ioc.confidence}%;background:var(--teal);border-radius:2px;"></div>
                </div>
                <span class="font-mono" style="font-size:0.6875rem;color:var(--teal);">${ioc.confidence}%</span>
              </div>
            </td>
            <td style="padding:7px 8px;"><span style="font-size:0.6875rem;font-weight:600;color:${statusColor[ioc.status]||'var(--text-muted)'};">${ioc.status.toUpperCase()}</span></td>
          </tr>`).join('')}
      </tbody>
    </table>`;
}

function filterIOCs() {
  const q    = (document.getElementById('ioc-search')?.value || '').toLowerCase();
  const type = document.getElementById('ioc-type-filter')?.value || '';
  const filtered = IOCS.filter(i =>
    (!type || i.type === type) &&
    (!q    || i.value.toLowerCase().includes(q) || i.actor.toLowerCase().includes(q) || i.tags.join(' ').toLowerCase().includes(q))
  );
  renderIOCTable(filtered);
}

function renderActors() {
  const container = document.getElementById('actor-profiles');
  if (!container) return;
  const tlpBg = { RED:'rgba(244,63,94,0.12)', AMBER:'rgba(251,146,60,0.12)', GREEN:'rgba(74,222,128,0.12)' };
  container.innerHTML = ACTORS.map((a, i) => `
    <div style="padding:12px;background:var(--bg-2);border-radius:8px;margin-bottom:8px;border:1px solid var(--line-soft);">
      <div class="flex items-center justify-between mb-2">
        <div style="font-size:0.875rem;font-weight:700;color:var(--text-primary);">${a.flag} ${a.id}</div>
        <span style="font-size:0.625rem;font-weight:700;padding:2px 6px;border-radius:3px;background:${tlpBg[a.tlp]};color:${a.tlpColor};">TLP:${a.tlp}</span>
      </div>
      <div class="text-xs text-muted mb-1">🌐 ${a.nation}</div>
      <div class="text-xs mb-2" style="color:var(--medium);">💰 ${a.motivation}</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px;">
        ${a.techniques.map(t=>`<span class="tag" style="font-size:0.5625rem;">${t}</span>`).join('')}
      </div>
    </div>`).join('');
}

function renderRules() {
  const container = document.getElementById('rules-list');
  if (!container) return;
  const typeColor = { Behavioral:'var(--teal)', Signature:'var(--low)', 'ML Model':'var(--medium)' };
  container.innerHTML = RULES.map(r => `
    <div style="padding:10px 12px;border:1px solid var(--line-soft);border-radius:8px;margin-bottom:8px;background:var(--bg-2);">
      <div class="flex items-center justify-between mb-1">
        <div style="font-size:0.8125rem;font-weight:600;color:var(--text-primary);">${r.name}</div>
        <div style="display:flex;gap:6px;align-items:center;">
          <span class="badge badge-ok" style="font-size:0.5625rem;">${r.matches} hit${r.matches!==1?'s':''}</span>
          <span style="font-size:0.625rem;font-weight:700;color:${typeColor[r.type]||'var(--text-muted)'};">${r.type.toUpperCase()}</span>
        </div>
      </div>
      <div style="font-family:var(--font-mono);font-size:0.6875rem;color:#a3e635;background:var(--bg-0);padding:6px 8px;border-radius:4px;margin-bottom:6px;">${r.logic}</div>
      <div class="text-xs text-muted">${r.secplus}</div>
    </div>`).join('');
}

/* ── Challenge ── */
function renderChallenge() {
  renderChips();
  renderAlertTargets();
}

function renderChips() {
  const container = document.getElementById('ioc-chips');
  if (!container) return;
  container.innerHTML = CHALLENGE_IOCS.map(c => {
    const assigned  = Object.values(assignments).includes(c.id);
    const isSelected = selectedChipId === c.id;
    return `
      <div id="chip-${c.id}" onclick="selectChip('${c.id}')"
        style="padding:6px 12px;border-radius:20px;border:2px solid ${isSelected?c.color:(assigned?'var(--ok)':'var(--line-strong)')};
               background:${isSelected?`rgba(94,234,212,0.15)`:(assigned?'rgba(74,222,128,0.08)':'var(--bg-2)')};
               color:${isSelected?'var(--text-primary)':(assigned?'var(--ok)':'var(--text-muted)')};
               font-size:0.75rem;font-family:var(--font-mono);cursor:${assigned&&!challengeDone?'default':'pointer'};
               user-select:none;transition:all .15s;display:flex;align-items:center;gap:6px;">
        <span style="font-size:0.5625rem;font-weight:700;color:${c.color};text-transform:uppercase;">${c.type}</span>
        ${c.label}
        ${assigned ? '<span style="color:var(--ok);">✓</span>' : ''}
      </div>`;
  }).join('');
}

function renderAlertTargets() {
  const container = document.getElementById('alert-targets');
  if (!container) return;
  container.innerHTML = CHALLENGE_ALERTS.map(a => {
    const assignedIocId = assignments[a.id];
    const assignedIoc   = CHALLENGE_IOCS.find(c => c.id === assignedIocId);
    return `
      <div id="target-${a.id}" onclick="assignToAlert('${a.id}')"
        style="padding:10px 12px;border:2px solid ${assignedIocId?'var(--teal)':'var(--line-strong)'};
               border-radius:8px;background:${selectedChipId&&!assignedIocId?'rgba(94,234,212,0.06)':'var(--bg-2)'};
               cursor:${selectedChipId&&!assignedIocId?'pointer':'default'};transition:all .15s;"
        onmouseenter="hoverTarget(this,'${a.id}','enter')" onmouseleave="hoverTarget(this,'${a.id}','leave')">
        <div style="font-size:0.8125rem;font-weight:600;color:var(--text-primary);margin-bottom:4px;">${a.title}</div>
        <div class="text-xs text-muted" style="line-height:1.5;margin-bottom:6px;">${a.desc}</div>
        <div style="min-height:22px;">
          ${assignedIoc
            ? `<span style="font-size:0.6875rem;font-family:var(--font-mono);color:var(--teal);background:rgba(94,234,212,0.1);padding:2px 8px;border-radius:12px;">${assignedIoc.label}</span>`
            : `<span style="font-size:0.6875rem;color:var(--text-dim);font-style:italic;">— drop IOC here —</span>`}
        </div>
      </div>`;
  }).join('');
}

function hoverTarget(el, alertId, dir) {
  if (!selectedChipId) return;
  if (assignments[alertId]) return;
  el.style.borderColor = dir === 'enter' ? 'var(--teal)' : 'var(--line-strong)';
  el.style.background  = dir === 'enter' ? 'rgba(94,234,212,0.1)' : 'rgba(94,234,212,0.06)';
}

function selectChip(iocId) {
  if (challengeDone) return;
  const alreadyAssigned = Object.values(assignments).includes(iocId);
  if (alreadyAssigned) return;
  selectedChipId = (selectedChipId === iocId) ? null : iocId;
  renderChips();
  renderAlertTargets();
}

function assignToAlert(alertId) {
  if (!selectedChipId || challengeDone) return;
  if (assignments[alertId]) return;
  assignments[alertId] = selectedChipId;
  selectedChipId = null;
  updateChallengeProgress();
  renderChips();
  renderAlertTargets();
}

function updateChallengeProgress() {
  const matched = Object.keys(assignments).length;
  const badge = document.getElementById('challenge-progress');
  if (badge) badge.textContent = `${matched} / 6 matched`;
  const submitRow = document.getElementById('challenge-submit-row');
  if (submitRow) submitRow.style.display = matched === 6 ? 'block' : 'none';
}

function submitChallenge() {
  if (challengeDone) return;
  challengeDone = true;

  let correct = 0;
  CHALLENGE_ALERTS.forEach(a => {
    if (assignments[a.id] === a.correctIoc) correct++;
  });
  const score = correct * 10;

  const resultsEl = document.getElementById('challenge-results');
  const submitRow = document.getElementById('challenge-submit-row');
  if (submitRow) submitRow.style.display = 'none';

  const scoreBadge = document.getElementById('challenge-score-badge');
  if (scoreBadge) { scoreBadge.textContent = `${score} pts`; scoreBadge.style.borderColor='var(--ok)'; scoreBadge.style.color='var(--ok)'; }

  const pct = Math.round((correct / 6) * 100);
  const grade = SENTINEL.scoreLabel(pct);

  if (resultsEl) {
    resultsEl.style.display = 'block';
    resultsEl.innerHTML = `
      <div style="background:rgba(94,234,212,0.06);border:1px solid rgba(94,234,212,0.25);border-radius:10px;padding:1rem;margin-bottom:1rem;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.75rem;">
          <div style="font-size:1rem;font-weight:700;color:var(--text-primary);">Results: ${correct}/6 correct</div>
          <div style="font-size:1.5rem;font-weight:700;font-family:var(--font-mono);color:var(--teal);">${score} pts</div>
        </div>
        <div class="text-xs text-muted mb-3">${grade}</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
          ${CHALLENGE_ALERTS.map(a => {
            const isCorrect = assignments[a.id] === a.correctIoc;
            const assignedIoc = CHALLENGE_IOCS.find(c => c.id === assignments[a.id]);
            const correctIoc  = CHALLENGE_IOCS.find(c => c.id === a.correctIoc);
            return `
              <div style="padding:10px;border-radius:8px;border:1px solid ${isCorrect?'rgba(74,222,128,0.3)':'rgba(244,63,94,0.3)'};background:${isCorrect?'rgba(74,222,128,0.06)':'rgba(244,63,94,0.06)'};">
                <div style="font-size:0.6875rem;font-weight:700;color:${isCorrect?'var(--ok)':'var(--critical)'};margin-bottom:4px;">${isCorrect?'✓ CORRECT':'✗ INCORRECT'}</div>
                <div style="font-size:0.75rem;font-weight:600;color:var(--text-primary);margin-bottom:4px;">${a.title}</div>
                ${!isCorrect?`<div class="text-xs text-muted mb-1">You matched: <span style="color:var(--medium);">${assignedIoc?.label||'—'}</span></div>
                <div class="text-xs text-muted mb-1">Correct IOC: <span style="color:var(--ok);">${correctIoc?.label}</span></div>`:''}
                <div class="text-xs text-muted" style="line-height:1.5;border-top:1px solid var(--line-soft);padding-top:4px;margin-top:4px;">${a.explanation}</div>
              </div>`;
          }).join('')}
        </div>
      </div>`;
  }

  saveDetectionScore(score);
  SENTINEL.toast(`IOC Challenge complete — ${score}/60 pts (${correct}/6 correct)`, score >= 50 ? 'success' : score >= 30 ? 'info' : 'warning');
}

function saveDetectionScore(score) {
  const p = SENTINEL.getProgress();
  const prev = p.detectionCompleted ? (p.detectionScore || 0) : 0;
  if (!p.detectionCompleted || score > prev) {
    const delta = score - prev;
    p.detectionScore     = score;
    p.detectionCompleted = true;
    p.totalScore = (p.totalScore || 0) + delta;
    SENTINEL.saveProgress(p);
    SENTINEL.updateNavScore();
  }
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', () => {
  SENTINEL.initFirstVisit();
  renderStats();
  renderIOCTable(IOCS);
  renderActors();
  renderRules();
  renderChallenge();
});
