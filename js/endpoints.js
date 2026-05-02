/* SENTINEL — Endpoint Management Module */

const ENDPOINTS = [
  {
    id:'WS-001', user:'A.Johnson', os:'Windows 11 Pro 23H2', health:'Healthy', av:'Running', compliance:100, checkin:'2 min',
    processes:['explorer.exe','chrome.exe (3 tabs)','sentinel-edr.exe','outlook.exe'],
    network:['443 → sentinel.cloud (EDR beacon)','443 → google.com'],
    files:['C:\\Users\\ajohnson\\Documents\\IR-Report.docx (read)'],
    alerts:0,
  },
  {
    id:'WS-002', user:'L.Culhane', os:'Windows 11 Pro 23H2', health:'Healthy', av:'Running', compliance:100, checkin:'5 min',
    processes:['explorer.exe','teams.exe','sentinel-edr.exe','notepad.exe'],
    network:['443 → teams.microsoft.com','443 → sentinel.cloud'],
    files:['C:\\Users\\lculhane\\Desktop\\analysis.xlsx (read)'],
    alerts:0,
  },
  {
    id:'WS-004', user:'T.Park (COMPROMISED)', os:'Windows 11 Pro 23H2', health:'Compromised', av:'Disabled', compliance:54, checkin:'2 min',
    processes:['explorer.exe','svchost.exe (injected — parent: malware.tmp)','cmd.exe (parent: svchost.exe)','net.exe /domain','powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQ=='],
    network:['443 → 185.220.101.47 (TOR exit — C2)','53 → beacon01.exfilbase64[.]co (DNS tunnel)','445 → DC-01 (SMB)'],
    files:['C:\\Windows\\Temp\\malware.tmp (write — unsigned)','C:\\Windows\\System32\\wdcu.exe (write — hash mismatch)'],
    alerts:3,
  },
  {
    id:'WS-005', user:'CFO-Office', os:'macOS Sequoia 15.3', health:'At-Risk', av:'Running', compliance:92, checkin:'4 min',
    processes:['Finder','Safari','Microsoft Outlook (suspicious attachment opened 06:18)','curl http://185.220.101.47/beacon'],
    network:['443 → microsoft.com','80 → 185.220.101.47 (flagged — C2 candidate)'],
    files:['~/Downloads/Q2_Board_Update.xlsm (macro enabled)'],
    alerts:1,
  },
  {
    id:'WS-006', user:'CEO-Office', os:'Windows 11 Pro 23H2', health:'At-Risk', av:'Running', compliance:100, checkin:'7 min',
    processes:['explorer.exe','outlook.exe','vlc.exe (CEO_Video_Message_Q2.mp4 — deepfake score 0.94)'],
    network:['443 → outlook.office365.com','443 → amazon-dlp.cdn.co (DLP alert — blocked)'],
    files:['C:\\Users\\ceo\\Downloads\\CEO_Video_Message_Q2.mp4 (DLP flagged)'],
    alerts:1,
  },
  {
    id:'WS-011', user:'Compromised (svc_backup_new)', os:'Windows 11 Pro 23H2', health:'Quarantined', av:'Error', compliance:48, checkin:'2 min',
    processes:['explorer.exe','wmic.exe /node:FILE-SERVER-01 process call create "cmd /c ..."','powershell.exe -enc JABjAG0AZAAgAD0A...','net.exe localgroup administrators svc_backup_new /add'],
    network:['10.14.1.0/24 (port scan — 1842 pkts/4.2s)','WMI to FILE-SERVER-01 (lateral movement)','443 → DC-01 (LDAP queries — 312 in 31s)'],
    files:['C:\\Windows\\System32\\wdcu.exe (created)','C:\\ProgramData\\svc_b.ps1 (persistence — RunKey)'],
    alerts:5,
  },
  {
    id:'FILE-SERVER-01', user:'SYSTEM', os:'Windows Server 2022', health:'At-Risk', av:'Running', compliance:41, checkin:'8 min',
    processes:['services.exe','svchost.exe','dns.exe (anomalous — 847 external queries/min)','wmic.exe (remote execution received from WS-011)'],
    network:['53 → *.exfilbase64[.]co (DNS tunnel — 847 queries)','445 ← WS-011 (SMB lateral movement)'],
    files:['C:\\Shares\\Finance\\Q1_Report.xlsx (bulk read — 2.3 GB in 4 min)','C:\\Windows\\Temp\\exfil_stage.tmp (write — suspicious)'],
    alerts:4,
  },
  {
    id:'DC-01', user:'SYSTEM', os:'Windows Server 2022', health:'At-Risk', av:'Running', compliance:62, checkin:'4 min',
    processes:['lsass.exe (MEMORY READ by wdcu.exe at 05:01 — 22 credential hashes extracted)','ntds.dit (active)','svchost.exe','dns.exe'],
    network:['88 ← all domain members (Kerberos normal)','389 ← WS-011 (LDAP — 312 queries in 31s — anomalous)'],
    files:['C:\\Windows\\NTDS\\ntds.dit (read by wdcu.exe — CREDENTIAL DUMP)'],
    alerts:1,
  },
  {
    id:'SCAN-HOST-01', user:'secops-scanner', os:'Kali Linux 2026.1', health:'Healthy', av:'Running', compliance:100, checkin:'15 min',
    processes:['nmap (authorized scan — CHG-0417-001)','openvas-scanner','bash'],
    network:['10.14.1.0/24 port scan (authorized — change controlled)'],
    files:['/var/log/nmap/scan_20260417.xml (write)'],
    alerts:0,
  },
  {
    id:'BACKUP-SERVER-01', user:'svc_backup', os:'Windows Server 2022', health:'At-Risk', av:'Running', compliance:71, checkin:'12 min',
    processes:['BackupExec.exe','svchost.exe','net.exe (svc_backup_new — new service account — anomalous)'],
    network:['445 → Azure Backup (authorized)','443 → DC-01 (LDAP query by svc_backup_new — new account)'],
    files:['C:\\Backup\\Config\\scheduled_tasks.xml (modified — svc_backup_new added as admin)'],
    alerts:1,
  },
  {
    id:'MAIL-01', user:'SYSTEM', os:'Exchange 2019 CU14', health:'At-Risk', av:'Running', compliance:78, checkin:'1 min',
    processes:['MSExchangeTransport.exe','MSExchangeFrontendTransport.exe (CVE-2024-21413 — unpatched)','W3SVC.exe'],
    network:['25 ← inbound (WormGPT phish received 06:18)','443 → Proofpoint (DLP scan)'],
    files:['C:\\inetpub\\wwwroot\\aspnet_client\\shell.aspx (WEBSHELL DETECTED — CVE exploit attempt)'],
    alerts:2,
  },
  {
    id:'KIOSK-LOBBY-01', user:'kiosk-guest', os:'Windows 10 LTSC 2021', health:'Healthy', av:'Running', compliance:45, checkin:'2 hrs',
    processes:['explorer.exe (kiosk mode)','iexplore.exe (restricted)'],
    network:['443 → guest-wifi-portal.corp.local (isolated VLAN)'],
    files:['C:\\Kiosk\\log_20260417.txt (write)'],
    alerts:0,
  },
];

/* ── Endpoint Triage Drill ── */
const DRILL_ENDPOINTS = [
  {
    id:'de1', hostname:'ACCT-WS-14', user:'finance-user',
    telemetry:'excel.exe spawned cmd.exe → cmd.exe spawned powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==\nnet use Z: \\\\fileserver\\finance /user:admin (pass spray attempt)\n453 failed auth attempts to CORP\\fileserver in 2 min',
    correct:'Compromised',
    explanation:'excel.exe → cmd.exe → powershell.exe is a classic macro execution chain. The base64-encoded PowerShell command decodes to a reverse shell. 453 failed auth attempts confirm credential spraying. Macro-enabled documents are a primary delivery vector (T1566.001, T1059.001).'
  },
  {
    id:'de2', hostname:'DEV-WS-07', user:'dev-alice',
    telemetry:'code.exe (VS Code — normal dev activity)\ngit.exe clone https://github.com/org/repo\npython3.exe main.py (no network connection)\nnpm install (package install — 47 packages)',
    correct:'Clean',
    explanation:'All processes are consistent with normal developer activity. VS Code, git, Python, and npm are expected tools. No anomalous parent-child relationships, no suspicious network connections, no unknown executables. This is normal developer baseline.'
  },
  {
    id:'de3', hostname:'HR-WS-03', user:'hr-manager',
    telemetry:'outlook.exe opened: Q1_Bonus_List.xlsm (macro enabled)\nwinword.exe spawned wscript.exe (uncommon parent)\nwscript.exe connected to 203.0.113.44:443 (unknown IP — no PTR)\ncertutil.exe -decode payload.b64 C:\\Users\\Public\\svc.exe',
    correct:'Compromised',
    explanation:'winword.exe spawning wscript.exe is a strong indicator of a malicious macro. certutil.exe decoding a base64 file is a classic Living-off-the-Land technique (T1140). The unknown external IP connection completes the initial access + C2 pattern. Quarantine immediately.'
  },
  {
    id:'de4', hostname:'EXEC-WS-01', user:'vp-engineering',
    telemetry:'chrome.exe (normal browsing)\nzoom.exe (video call — 45 min duration)\nslack.exe\noutlook.exe\nOneDrive.exe (sync 12 files — corp OneDrive tenant)',
    correct:'Clean',
    explanation:'All processes (Chrome, Zoom, Slack, Outlook, OneDrive) are standard enterprise applications. OneDrive syncing to corporate tenant is authorized. No unusual parent-child process relationships, no scripting engine abuse, no external unknown connections.'
  },
  {
    id:'de5', hostname:'OPS-WS-09', user:'ops-svc-account',
    telemetry:'svchost.exe (normal)\ntaskeng.exe (scheduled task — runs 03:00 daily)\ntaskeng.exe spawned cmd.exe → cmd.exe spawned whoami, ipconfig /all, net group "Domain Admins"\nResults written to C:\\Windows\\Temp\\r3c0n.txt',
    correct:'Suspicious',
    explanation:'A scheduled task performing host and domain reconnaissance (whoami, ipconfig, net group) is unusual. Writing results to Temp is consistent with data staging. This could be an attacker with persistence (T1053.005) or an unauthorized admin script. Escalate — do not dismiss without investigation.'
  },
  {
    id:'de6', hostname:'SEC-WS-02', user:'soc-analyst',
    telemetry:'wireshark.exe (packet capture on eth0 — authorized SOC tool)\nnmap.exe (scan 10.14.1.0/24 — CHG-0417-002 approved)\nProcessHacker.exe (process inspection — SOC standard tool)\npython3.exe parse_logs.py (log analysis script)',
    correct:'Clean',
    explanation:'All activity is consistent with an authorized SOC analyst performing their job. Wireshark, nmap (with a change ticket), ProcessHacker, and Python scripts are all expected security analyst tools. Context and authorization make this normal.'
  },
  {
    id:'de7', hostname:'SALES-WS-22', user:'sales-rep',
    telemetry:'chrome.exe\noutlook.exe opened: Invoice_URGENT_PayNow.pdf.exe (note: double extension)\nrundll32.exe C:\\Users\\Public\\update.dll,DllMain\nupdate.dll wrote to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run (persistence)',
    correct:'Compromised',
    explanation:'A file named Invoice_URGENT.pdf.exe using a double extension is a classic social engineering trick. rundll32.exe loading an untrusted DLL from %Public% is a LOLBin technique (T1218.011). Registry persistence in HKCU\\Run confirms the attacker is establishing a foothold (T1547.001).'
  },
  {
    id:'de8', hostname:'INFRA-WS-05', user:'infra-engineer',
    telemetry:'putty.exe (SSH to prod-server-03 — authorized maintenance)\nwinscp.exe (SFTP transfer — config backup to NAS)\nregedit.exe (opened C:\\Windows\\System32\\drivers\\etc\\hosts — read only)\nnotepad.exe',
    correct:'Suspicious',
    explanation:'PuTTY and WinSCP are legitimate tools, but regedit accessing the hosts file warrants investigation — this could be an attacker poisoning DNS resolution. Mark suspicious and verify with the user: was this authorized? The combination of remote access tools + hosts file modification is a common lateral movement setup technique (T1565.001).'
  },
];

let drillAnswers  = {};
let drillDone     = false;
let selectedEp    = null;

/* ── Render endpoint grid ── */
const HEALTH_COLOR = {
  Healthy:     { fg:'var(--ok)',       bg:'rgba(74,222,128,0.08)',  border:'rgba(74,222,128,0.25)' },
  'At-Risk':   { fg:'var(--medium)',   bg:'rgba(250,204,21,0.08)',  border:'rgba(250,204,21,0.25)' },
  Compromised: { fg:'var(--critical)', bg:'rgba(244,63,94,0.08)',   border:'rgba(244,63,94,0.25)'  },
  Quarantined: { fg:'var(--high)',     bg:'rgba(251,146,60,0.08)',  border:'rgba(251,146,60,0.25)' },
};
const AV_COLOR  = { Running:'var(--ok)', Disabled:'var(--critical)', Error:'var(--high)' };
const HEALTH_ICON = { Healthy:'🟢', 'At-Risk':'🟡', Compromised:'🔴', Quarantined:'🟠' };

function renderEpStats() {
  const container = document.getElementById('ep-stats');
  if (!container) return;
  const healthy     = ENDPOINTS.filter(e=>e.health==='Healthy').length;
  const atRisk      = ENDPOINTS.filter(e=>e.health==='At-Risk').length;
  const compromised = ENDPOINTS.filter(e=>e.health==='Compromised'||e.health==='Quarantined').length;
  const avDisabled  = ENDPOINTS.filter(e=>e.av!=='Running').length;

  document.getElementById('ep-badge-healthy').textContent = `${healthy} Healthy`;
  document.getElementById('ep-badge-atrisk').textContent  = `${atRisk} At-Risk`;
  document.getElementById('ep-badge-comp').textContent    = `${compromised} Compromised/Quarantined`;

  container.innerHTML = [
    { label:'Total Endpoints', value:ENDPOINTS.length,  color:'var(--teal)',     icon:'▢' },
    { label:'Healthy',         value:healthy,            color:'var(--ok)',       icon:'🟢' },
    { label:'At-Risk',         value:atRisk,             color:'var(--medium)',   icon:'🟡' },
    { label:'AV Disabled',     value:avDisabled,         color:'var(--critical)', icon:'🛡' },
  ].map(s=>`
    <div class="card" style="padding:1rem;">
      <div class="card-title mb-2">${s.icon} ${s.label}</div>
      <div style="font-size:1.875rem;font-weight:700;font-family:var(--font-mono);color:${s.color};line-height:1;">${s.value}</div>
    </div>`).join('');
}

function getFilteredEndpoints() {
  const q      = (document.getElementById('ep-search')?.value      || '').toLowerCase();
  const health = document.getElementById('ep-filter-health')?.value || '';
  const av     = document.getElementById('ep-filter-av')?.value     || '';
  return ENDPOINTS.filter(e =>
    (!q      || e.id.toLowerCase().includes(q) || e.user.toLowerCase().includes(q) || e.os.toLowerCase().includes(q)) &&
    (!health || e.health === health) &&
    (!av     || e.av === av)
  );
}

function filterEndpoints() {
  const list = getFilteredEndpoints();
  renderEpGrid(list);
  const el = document.getElementById('ep-filter-count');
  if (el) el.textContent = `${list.length} of ${ENDPOINTS.length} endpoints`;
}

function clearEpFilters() {
  ['ep-search','ep-filter-health','ep-filter-av'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  filterEndpoints();
}

function renderEpGrid(list) {
  const grid = document.getElementById('ep-grid');
  if (!grid) return;
  if (list.length === 0) {
    grid.innerHTML = '<div class="text-xs text-muted" style="padding:2rem;text-align:center;grid-column:1/-1;">No endpoints match filter.</div>';
    return;
  }
  grid.innerHTML = list.map(e => {
    const hc = HEALTH_COLOR[e.health] || HEALTH_COLOR.Healthy;
    const isSelected = selectedEp === e.id;
    return `
      <div onclick="showEpDetail('${e.id}')"
        style="padding:12px;border-radius:8px;border:2px solid ${isSelected?'var(--teal)':(hc.border)};
               background:${isSelected?'rgba(94,234,212,0.06)':hc.bg};cursor:pointer;transition:all .15s;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
          <div style="font-size:0.8125rem;font-weight:700;font-family:var(--font-mono);color:var(--text-primary);">${e.id}</div>
          <span style="font-size:0.625rem;font-weight:700;color:${hc.fg};">${HEALTH_ICON[e.health]} ${e.health.toUpperCase()}</span>
        </div>
        <div class="text-xs text-muted mb-1" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${e.user}</div>
        <div class="text-xs text-muted mb-2">${e.os.split(' ').slice(0,3).join(' ')}</div>
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <span class="text-xs" style="color:${AV_COLOR[e.av]};font-weight:600;">AV: ${e.av}</span>
          <span class="text-xs font-mono" style="color:${e.compliance>=85?'var(--ok)':e.compliance>=60?'var(--medium)':'var(--critical)'};">${e.compliance}%</span>
        </div>
        <div style="height:3px;background:var(--bg-elevated);border-radius:2px;overflow:hidden;margin-top:4px;">
          <div style="height:100%;width:${e.compliance}%;background:${e.compliance>=85?'var(--ok)':e.compliance>=60?'var(--medium)':'var(--critical)'};border-radius:2px;"></div>
        </div>
        ${e.alerts>0?`<div style="margin-top:6px;font-size:0.625rem;font-weight:700;color:var(--critical);">🔴 ${e.alerts} ALERT${e.alerts>1?'S':''}</div>`:''}
      </div>`;
  }).join('');
}

function showEpDetail(epId) {
  const e = ENDPOINTS.find(x => x.id === epId);
  if (!e) return;
  selectedEp = epId;
  filterEndpoints();

  const panel = document.getElementById('ep-detail-panel');
  if (!panel) return;
  const hc = HEALTH_COLOR[e.health] || HEALTH_COLOR.Healthy;

  panel.innerHTML = `
    <div class="card" style="border-color:${hc.border};">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:0.75rem;">
        <div>
          <div style="font-size:0.9375rem;font-weight:700;font-family:var(--font-mono);color:var(--text-primary);">${e.id}</div>
          <div class="text-xs text-muted mt-1">${e.user} · ${e.os}</div>
        </div>
        <span style="font-size:0.75rem;font-weight:700;color:${hc.fg};background:${hc.bg};padding:3px 8px;border-radius:4px;">${HEALTH_ICON[e.health]} ${e.health}</span>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:0.75rem;">
        <div style="background:var(--bg-2);border-radius:6px;padding:8px;">
          <div class="text-xs text-muted mb-1">AV Status</div>
          <div style="font-size:0.75rem;font-weight:700;color:${AV_COLOR[e.av]};">${e.av}</div>
        </div>
        <div style="background:var(--bg-2);border-radius:6px;padding:8px;">
          <div class="text-xs text-muted mb-1">Patch Compliance</div>
          <div style="font-size:0.75rem;font-weight:700;color:${e.compliance>=85?'var(--ok)':e.compliance>=60?'var(--medium)':'var(--critical)'};">${e.compliance}%</div>
        </div>
        <div style="background:var(--bg-2);border-radius:6px;padding:8px;">
          <div class="text-xs text-muted mb-1">Last Check-In</div>
          <div style="font-size:0.75rem;color:var(--text-primary);">${e.checkin} ago</div>
        </div>
        <div style="background:var(--bg-2);border-radius:6px;padding:8px;">
          <div class="text-xs text-muted mb-1">Open Alerts</div>
          <div style="font-size:0.75rem;font-weight:700;color:${e.alerts>0?'var(--critical)':'var(--ok)'};">${e.alerts>0?`🔴 ${e.alerts}`:'Clear'}</div>
        </div>
      </div>

      <div style="margin-bottom:0.75rem;">
        <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.06em;">Process Tree</div>
        <div style="background:var(--bg-0);border:1px solid var(--line-soft);border-radius:6px;padding:8px;font-family:var(--font-mono);font-size:0.6875rem;color:#a3e635;line-height:1.8;">
          ${e.processes.map(p=>`<div>→ ${SENTINEL._escHtml(p)}</div>`).join('')}
        </div>
      </div>

      <div style="margin-bottom:0.75rem;">
        <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.06em;">Network Connections</div>
        <div style="background:var(--bg-0);border:1px solid var(--line-soft);border-radius:6px;padding:8px;font-family:var(--font-mono);font-size:0.6875rem;color:var(--low);line-height:1.8;">
          ${e.network.map(n=>`<div>${SENTINEL._escHtml(n)}</div>`).join('')}
        </div>
      </div>

      <div>
        <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.06em;">Recent File Events</div>
        <div style="background:var(--bg-0);border:1px solid var(--line-soft);border-radius:6px;padding:8px;font-family:var(--font-mono);font-size:0.6875rem;color:var(--medium);line-height:1.8;">
          ${e.files.map(f=>`<div>${SENTINEL._escHtml(f)}</div>`).join('')}
        </div>
      </div>
    </div>`;
}

/* ── Triage Drill ── */
function renderDrill() {
  const grid = document.getElementById('drill-grid');
  if (!grid) return;
  grid.innerHTML = DRILL_ENDPOINTS.map(de => {
    const answer = drillAnswers[de.id] || '';
    return `
      <div style="padding:12px;border:1px solid var(--line-soft);border-radius:8px;background:var(--bg-2);">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
          <span class="badge badge-muted" style="font-family:var(--font-mono);font-size:0.625rem;">${de.hostname}</span>
          <span class="text-xs text-muted">${de.user}</span>
        </div>
        <div style="background:var(--bg-0);border:1px solid var(--line-soft);border-radius:6px;padding:8px;font-family:var(--font-mono);font-size:0.6875rem;color:#a3e635;line-height:1.7;margin-bottom:8px;white-space:pre-wrap;max-height:130px;overflow-y:auto;">${SENTINEL._escHtml(de.telemetry)}</div>
        <div style="display:flex;gap:6px;">
          ${['Clean','Suspicious','Compromised'].map(lvl => {
            const lvlColor = lvl==='Clean'?'var(--ok)':lvl==='Suspicious'?'var(--medium)':'var(--critical)';
            const sel = answer === lvl;
            return `
              <button onclick="answerDrill('${de.id}','${lvl}')" ${drillDone?'disabled':''} class="btn btn-sm"
                style="flex:1;justify-content:center;font-size:0.6875rem;
                       border-color:${sel?lvlColor:'var(--line-strong)'};
                       color:${sel?lvlColor:'var(--text-muted)'};
                       background:${sel?lvlColor+'18':'transparent'};">
                ${lvl}
              </button>`;
          }).join('')}
        </div>
      </div>`;
  }).join('');

  const answered = Object.keys(drillAnswers).length;
  const prog = document.getElementById('drill-progress');
  if (prog) prog.textContent = `${answered} / 8 triaged`;
  const submitRow = document.getElementById('drill-submit-row');
  if (submitRow) submitRow.style.display = !drillDone && answered === 8 ? 'block' : 'none';
}

function answerDrill(endpointId, verdict) {
  if (drillDone) return;
  drillAnswers[endpointId] = verdict;
  renderDrill();
}

function submitDrill() {
  if (drillDone) return;
  drillDone = true;

  let correct = 0;
  DRILL_ENDPOINTS.forEach(de => { if (drillAnswers[de.id] === de.correct) correct++; });
  const score = correct * 10;
  const pct   = Math.round((correct / 8) * 100);

  const resultsEl = document.getElementById('drill-results');
  const submitRow = document.getElementById('drill-submit-row');
  if (submitRow) submitRow.style.display = 'none';

  const scoreBadge = document.getElementById('drill-score-badge');
  if (scoreBadge) scoreBadge.textContent = `${score} pts`;

  if (resultsEl) {
    resultsEl.style.display = 'block';
    resultsEl.innerHTML = `
      <div style="background:rgba(94,234,212,0.06);border:1px solid rgba(94,234,212,0.25);border-radius:10px;padding:1rem;margin-bottom:1rem;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.5rem;">
          <div style="font-size:1rem;font-weight:700;color:var(--text-primary);">${correct}/8 correct · ${SENTINEL.scoreLabel(pct)}</div>
          <div style="font-size:1.5rem;font-weight:700;font-family:var(--font-mono);color:var(--teal);">${score} pts</div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:0.75rem;">
          ${DRILL_ENDPOINTS.map(de => {
            const isCorrect = drillAnswers[de.id] === de.correct;
            const yourColor = de.correct==='Clean'?'var(--ok)':de.correct==='Suspicious'?'var(--medium)':'var(--critical)';
            return `
              <div style="padding:10px;border-radius:8px;border:1px solid ${isCorrect?'rgba(74,222,128,0.3)':'rgba(244,63,94,0.3)'};background:${isCorrect?'rgba(74,222,128,0.06)':'rgba(244,63,94,0.06)'};">
                <div style="font-size:0.6875rem;font-weight:700;color:${isCorrect?'var(--ok)':'var(--critical)'};">${isCorrect?'✓ CORRECT':'✗ INCORRECT'} — ${de.hostname}</div>
                ${!isCorrect?`<div class="text-xs text-muted mb-1">You: <span style="color:var(--medium);">${drillAnswers[de.id]||'—'}</span> · Correct: <span style="color:${yourColor};">${de.correct}</span></div>`:''}
                <div class="text-xs text-muted" style="line-height:1.5;border-top:1px solid var(--line-soft);padding-top:4px;margin-top:4px;">${de.explanation}</div>
              </div>`;
          }).join('')}
        </div>
      </div>`;
  }

  renderDrill();
  saveEndpointsScore(score);
  SENTINEL.toast(`Endpoint Triage complete — ${score}/80 pts (${correct}/8 correct)`, score >= 64 ? 'success' : score >= 40 ? 'info' : 'warning');
}

function saveEndpointsScore(score) {
  const p = SENTINEL.getProgress();
  const prev = p.endpointsCompleted ? (p.endpointsScore || 0) : 0;
  if (!p.endpointsCompleted || score > prev) {
    const delta = score - prev;
    p.endpointsScore     = score;
    p.endpointsCompleted = true;
    p.totalScore = (p.totalScore || 0) + delta;
    SENTINEL.saveProgress(p);
    SENTINEL.updateNavScore();
  }
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', () => {
  SENTINEL.initFirstVisit();
  renderEpStats();
  filterEndpoints();
  renderDrill();
});
