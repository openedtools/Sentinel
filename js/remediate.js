/* SENTINEL — Remediation Lab */

const NETWORK = {
  nodes: [
    { id: 'internet',   label: 'INTERNET',       x: 80,  y: 200, type: 'cloud',    status: 'external', icon: '🌐' },
    { id: 'firewall',   label: 'FIREWALL',        x: 210, y: 200, type: 'device',   status: 'clean',    icon: '🔥' },
    { id: 'switch',     label: 'CORE SWITCH',     x: 370, y: 200, type: 'device',   status: 'clean',    icon: '🔀' },
    { id: 'dmz',        label: 'DMZ SERVER',      x: 520, y: 80,  type: 'server',   status: 'clean',    icon: '🖥' },
    { id: 'ws004',      label: 'WS-004',          x: 520, y: 160, type: 'endpoint', status: 'compromised', icon: '💻' },
    { id: 'ws011',      label: 'WS-011',          x: 520, y: 240, type: 'endpoint', status: 'suspicious',  icon: '💻' },
    { id: 'fileserver', label: 'FILE-SERVER-01',  x: 520, y: 320, type: 'server',   status: 'compromised', icon: '🗄' },
    { id: 'dc01',       label: 'DC-01',           x: 670, y: 140, type: 'server',   status: 'compromised', icon: '🔐' },
    { id: 'ws002',      label: 'WS-002',          x: 670, y: 240, type: 'endpoint', status: 'clean',    icon: '💻' },
    { id: 'ws003',      label: 'WS-003',          x: 670, y: 320, type: 'endpoint', status: 'clean',    icon: '💻' }
  ],
  edges: [
    { from: 'internet',   to: 'firewall' },
    { from: 'firewall',   to: 'switch' },
    { from: 'switch',     to: 'dmz' },
    { from: 'switch',     to: 'ws004' },
    { from: 'switch',     to: 'ws011' },
    { from: 'switch',     to: 'fileserver' },
    { from: 'fileserver', to: 'dc01' },
    { from: 'fileserver', to: 'ws002' },
    { from: 'fileserver', to: 'ws003' },
    { from: 'ws004',      to: 'fileserver', active: true, threat: true },
    { from: 'ws011',      to: 'fileserver', active: true, threat: true }
  ],
  ports: [
    { port: 22,   service: 'SSH',   status: 'open',   node: 'dmz' },
    { port: 80,   service: 'HTTP',  status: 'open',   node: 'dmz' },
    { port: 443,  service: 'HTTPS', status: 'open',   node: 'dmz' },
    { port: 445,  service: 'SMB',   status: 'open',   node: 'fileserver', threat: true },
    { port: 3389, service: 'RDP',   status: 'open',   node: 'dc01', threat: true },
    { port: 135,  service: 'RPC',   status: 'open',   node: 'dc01' },
    { port: 53,   service: 'DNS',   status: 'open',   node: 'firewall', threat: true },
    { port: 4444, service: 'C2',    status: 'open',   node: 'ws004', threat: true },
    { port: 8080, service: 'HTTP-Alt', status: 'open', node: 'ws004' }
  ],
  blocklist: [],
  actionLog: []
};

let selectedNode = null;
let labScore = 0;
let actionsAvailable = {
  quarantine: true, blockip: true, closeport: true,
  openport: true, killprocess: true, resetcreds: true
};

const STATUS_COLORS = {
  clean:       '#22c55e',
  suspicious:  '#f59e0b',
  compromised: '#ef4444',
  quarantined: '#374151',
  external:    '#6b7280'
};

function initRemediation() {
  renderTopology();
  renderNodeList();
  renderPortTable();
  renderActionLog();
}

/* ── SVG Topology ── */
function renderTopology() {
  const svg = document.getElementById('topology-svg');
  if (!svg) return;

  let svgContent = '';

  /* Edges */
  NETWORK.edges.forEach(edge => {
    const from = NETWORK.nodes.find(n => n.id === edge.from);
    const to   = NETWORK.nodes.find(n => n.id === edge.to);
    if (!from || !to) return;

    const isActive = edge.threat;
    const color = isActive ? '#ef4444' : '#1f2937';
    const strokeWidth = isActive ? 2 : 1.5;
    const dash = isActive ? '6,3' : 'none';

    svgContent += `<line x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}"
      stroke="${color}" stroke-width="${strokeWidth}" stroke-dasharray="${dash}" opacity="0.7"
      class="topo-edge" data-from="${edge.from}" data-to="${edge.to}"/>`;
  });

  /* Nodes */
  NETWORK.nodes.forEach(node => {
    const color = STATUS_COLORS[node.status] || '#6b7280';
    const isSelected = selectedNode === node.id;
    const isQuarantined = node.status === 'quarantined';

    svgContent += `
      <g class="topo-node" data-id="${node.id}" onclick="selectNode('${node.id}')" style="cursor:pointer;">
        <circle cx="${node.x}" cy="${node.y}" r="22"
          fill="${color}18" stroke="${color}"
          stroke-width="${isSelected ? 3 : 1.5}"
          stroke-dasharray="${isQuarantined ? '5,3' : 'none'}"
          opacity="${isQuarantined ? 0.5 : 1}"/>
        ${isSelected ? `<circle cx="${node.x}" cy="${node.y}" r="28" fill="none" stroke="${color}" stroke-width="1" opacity="0.3"/>` : ''}
        <text x="${node.x}" y="${node.y + 5}" text-anchor="middle" font-size="14"
          opacity="${isQuarantined ? 0.4 : 1}">${node.icon}</text>
        <text x="${node.x}" y="${node.y + 38}" text-anchor="middle"
          font-size="8" font-weight="600" font-family="Inter,sans-serif"
          fill="${color}" opacity="${isQuarantined ? 0.5 : 1}">${node.label}</text>
        ${node.status === 'compromised' ? `
          <circle cx="${node.x + 16}" cy="${node.y - 16}" r="7" fill="#ef4444" opacity="0.9"/>
          <text x="${node.x + 16}" y="${node.y - 13}" text-anchor="middle" font-size="9">!</text>
        ` : ''}
        ${node.status === 'suspicious' ? `
          <circle cx="${node.x + 16}" cy="${node.y - 16}" r="7" fill="#f59e0b" opacity="0.9"/>
          <text x="${node.x + 16}" y="${node.y - 13}" text-anchor="middle" font-size="9">?</text>
        ` : ''}
      </g>`;
  });

  svg.innerHTML = svgContent;
}

function selectNode(nodeId) {
  selectedNode = selectedNode === nodeId ? null : nodeId;
  renderTopology();
  renderNodeList();
  updateActionPanel();
}

/* ── Node list (sidebar) ── */
function renderNodeList() {
  const container = document.getElementById('node-list');
  if (!container) return;

  container.innerHTML = NETWORK.nodes
    .filter(n => n.id !== 'internet')
    .map(n => {
      const color = STATUS_COLORS[n.status];
      return `
        <div class="node-item ${selectedNode === n.id ? 'selected' : ''}" onclick="selectNode('${n.id}')">
          <div class="node-dot" style="background:${color}"></div>
          <div style="flex:1;min-width:0;">
            <div class="node-name">${n.label}</div>
            <div class="node-sub">${n.status.toUpperCase()} · ${n.type}</div>
          </div>
          <span style="font-size:14px;opacity:${n.status === 'quarantined' ? 0.4 : 1}">${n.icon}</span>
        </div>`;
    }).join('');
}

/* ── Port table ── */
function renderPortTable() {
  const tbody = document.getElementById('port-tbody');
  if (!tbody) return;

  tbody.innerHTML = NETWORK.ports.map(p => `
    <tr>
      <td class="font-mono">${p.port}</td>
      <td>${p.service}</td>
      <td>${p.node.toUpperCase()}</td>
      <td>
        <span class="${p.status === 'open' ? (p.threat ? 'text-critical' : 'port-open') : 'port-closed'}">
          ${p.status === 'open' ? '● OPEN' : '○ CLOSED'}
          ${p.threat && p.status === 'open' ? ' ⚠' : ''}
        </span>
      </td>
      <td>
        ${p.status === 'open'
          ? `<button class="btn btn-sm btn-danger" onclick="closePort(${p.port})">Close</button>`
          : `<button class="btn btn-sm btn-secondary" onclick="openPort(${p.port})">Open</button>`}
      </td>
    </tr>`).join('');
}

/* ── Action log ── */
function renderActionLog() {
  const container = document.getElementById('action-log');
  if (!container) return;

  if (NETWORK.actionLog.length === 0) {
    container.innerHTML = '<div class="text-xs text-muted" style="padding:8px;">No actions taken yet. Select a node and use the actions above.</div>';
    return;
  }

  container.innerHTML = NETWORK.actionLog.slice().reverse().map(entry => `
    <div class="log-entry ${entry.type === 'success' ? 'log-ok' : entry.type === 'error' ? 'log-crit' : 'log-info'}">
      ${new Date(entry.ts).toTimeString().slice(0,8)} ${entry.msg}
    </div>`).join('');
}

function logAction(msg, type = 'info') {
  NETWORK.actionLog.push({ msg, type, ts: Date.now() });
  renderActionLog();
}

/* ── Update action panel based on selection ── */
function updateActionPanel() {
  const node = NETWORK.nodes.find(n => n.id === selectedNode);
  const info = document.getElementById('selected-node-info');
  if (!info) return;

  if (!node) {
    info.innerHTML = '<div class="text-xs text-muted">Select a node on the network diagram to take actions against it.</div>';
    return;
  }

  const color = STATUS_COLORS[node.status];
  info.innerHTML = `
    <div class="flex items-center gap-2 mb-2">
      <span style="font-size:1.25rem">${node.icon}</span>
      <div>
        <div style="font-size:0.875rem;font-weight:700;color:var(--text-primary)">${node.label}</div>
        <div class="flex items-center gap-1 mt-1">
          <div class="node-dot" style="background:${color};width:8px;height:8px;border-radius:50%;"></div>
          <span style="font-size:0.6875rem;color:${color};font-weight:600;text-transform:uppercase;">${node.status}</span>
        </div>
      </div>
    </div>
    <div class="text-xs text-muted">${getNodeDescription(node)}</div>`;
}

function getNodeDescription(node) {
  const desc = {
    ws004: 'Initial infection vector. Running polymorphic malware. Communicating with C2 server on port 4444.',
    ws011: 'Performed internal port scan. Lateral movement attempt to FILE-SERVER-01 detected.',
    fileserver: 'Compromised via WMI remote execution. Malicious scheduled task installed. DNS tunneling in progress.',
    dc01: 'LSASS memory dump executed. Domain Admin credentials likely stolen. New backdoor account created.',
    dmz: 'DMZ perimeter server. Currently clean. Exposed ports: 22, 80, 443.',
    firewall: 'Network firewall. DNS tunneling traffic on port 53 flagged.',
    switch: 'Core network switch. All traffic flowing through. No compromise detected.',
    ws002: 'Clean endpoint. No compromise detected.',
    ws003: 'Clean endpoint. No compromise detected.'
  };
  return desc[node.id] || 'No additional information available.';
}

/* ── Remediation Actions ── */
function quarantineNode() {
  if (!selectedNode) { SENTINEL.toast('Select a node first', 'warning'); return; }
  const node = NETWORK.nodes.find(n => n.id === selectedNode);
  if (!node || node.status === 'quarantined') { SENTINEL.toast('Node is already quarantined', 'info'); return; }
  if (node.id === 'firewall' || node.id === 'switch') {
    SENTINEL.toast('Cannot quarantine core infrastructure — this would disconnect the entire network!', 'error');
    logAction(`⚠ BLOCKED: Quarantine of ${node.label} would sever all network connections`, 'error');
    return;
  }

  const wasCompromised = node.status === 'compromised';
  node.status = 'quarantined';

  /* Remove threat edges from this node */
  NETWORK.edges.forEach(e => {
    if (e.from === node.id || e.to === node.id) e.threat = false;
  });

  if (wasCompromised) {
    labScore += 25;
    SENTINEL.updateScore(25);
    SENTINEL.toast(`+25 pts — ${node.label} quarantined. Lateral movement blocked.`, 'success');
    logAction(`✓ QUARANTINE: ${node.label} isolated from network. Active threat connections severed.`, 'success');
  } else {
    logAction(`✓ QUARANTINE: ${node.label} isolated (status was: ${node.status}).`, 'info');
    SENTINEL.toast(`${node.label} quarantined`, 'success');
  }

  renderTopology();
  renderNodeList();
  updateActionPanel();
  checkVictoryCondition();
}

function blockIP() {
  const input = document.getElementById('block-ip-input');
  const ip = input ? input.value.trim() : '';
  const knownThreatIPs = ['10.14.1.11', '10.14.2.5', 'api.unknown-cdn.io', 'exfilbase64.co'];
  const entry = ip || 'api.unknown-cdn.io';

  if (NETWORK.blocklist.includes(entry)) {
    SENTINEL.toast(`${entry} is already blocked`, 'info');
    return;
  }

  NETWORK.blocklist.push(entry);
  const isThreat = knownThreatIPs.some(t => entry.includes(t.split('.')[0]) || entry === t);
  const pts = isThreat ? 15 : 5;
  labScore += pts;
  SENTINEL.updateScore(pts);
  SENTINEL.toast(`+${pts} pts — ${entry} added to blocklist`, 'success');
  logAction(`✓ BLOCK: ${entry} added to firewall blocklist. ${NETWORK.blocklist.length} total blocked.`, 'success');

  if (input) input.value = '';
  renderBlocklist();
}

function renderBlocklist() {
  const el = document.getElementById('blocklist');
  if (!el) return;
  if (NETWORK.blocklist.length === 0) {
    el.innerHTML = '<div class="text-xs text-muted">No IPs/domains blocked yet.</div>';
    return;
  }
  el.innerHTML = NETWORK.blocklist.map(ip => `
    <div class="flex justify-between items-center text-xs mb-1">
      <span class="font-mono text-critical">✗ ${ip}</span>
      <button class="btn btn-sm btn-ghost" style="padding:2px 6px;" onclick="unblockIP('${ip}')">remove</button>
    </div>`).join('');
}

function unblockIP(ip) {
  NETWORK.blocklist = NETWORK.blocklist.filter(x => x !== ip);
  SENTINEL.toast(`${ip} removed from blocklist`, 'info');
  logAction(`↩ UNBLOCK: ${ip} removed from firewall blocklist.`, 'info');
  renderBlocklist();
}

function closePort(port) {
  const p = NETWORK.ports.find(x => x.port === port);
  if (!p || p.status === 'closed') return;
  p.status = 'closed';
  const pts = p.threat ? 20 : 5;
  labScore += pts;
  SENTINEL.updateScore(pts);
  SENTINEL.toast(`+${pts} pts — Port ${port} (${p.service}) closed`, 'success');
  logAction(`✓ PORT CLOSED: ${p.port}/${p.service} on ${p.node.toUpperCase()} — traffic blocked.`, 'success');
  renderPortTable();
  checkVictoryCondition();
}

function openPort(port) {
  const p = NETWORK.ports.find(x => x.port === port);
  if (!p || p.status === 'open') return;
  p.status = 'open';
  SENTINEL.toast(`Port ${port} re-opened`, 'info');
  logAction(`↩ PORT OPENED: ${p.port}/${p.service} on ${p.node.toUpperCase()} — re-enabled.`, 'info');
  renderPortTable();
}

function killProcess() {
  if (!selectedNode) { SENTINEL.toast('Select a node first', 'warning'); return; }
  const node = NETWORK.nodes.find(n => n.id === selectedNode);
  if (!node) return;

  const processes = {
    ws004: 'svchost_x86.exe (malware) + C2 beacon',
    fileserver: 'wdcu.exe (malware) + DNS tunnel client',
    dc01: 'wdcu.exe (credential dumper)',
    ws011: 'portscan.exe'
  };

  const proc = processes[node.id];
  if (!proc) {
    SENTINEL.toast(`No known malicious processes on ${node.label}`, 'info');
    logAction(`ℹ KILL PROCESS: No malicious processes identified on ${node.label}.`, 'info');
    return;
  }

  labScore += 15;
  SENTINEL.updateScore(15);
  SENTINEL.toast(`+15 pts — Malicious process terminated on ${node.label}`, 'success');
  logAction(`✓ KILL PROCESS: ${proc} terminated on ${node.label}. Threat activity reduced.`, 'success');

  if (node.status === 'compromised') node.status = 'suspicious';
  renderTopology();
  renderNodeList();
  updateActionPanel();
}

function resetCredentials() {
  if (!selectedNode) { SENTINEL.toast('Select a node first', 'warning'); return; }
  const node = NETWORK.nodes.find(n => n.id === selectedNode);

  labScore += 20;
  SENTINEL.updateScore(20);
  SENTINEL.toast(`+20 pts — Credentials reset on ${node ? node.label : 'selected node'}`, 'success');
  logAction(`✓ CREDS RESET: All user credentials on ${node ? node.label : selectedNode} invalidated. Active sessions terminated.`, 'success');

  if (node && node.id === 'dc01') {
    logAction(`⚠ NOTE: svc_backup_new backdoor account detected and disabled during credential reset.`, 'success');
    labScore += 10;
    SENTINEL.updateScore(10);
  }
}

function aiRecommend() {
  const btn = document.getElementById('ai-recommend-btn');
  if (btn) {
    btn.innerHTML = `<span class="spinner"></span> AI Analyzing...`;
    btn.disabled = true;
  }

  setTimeout(() => {
    const steps = [
      '1. Quarantine WS-004 (source of initial infection)',
      '2. Quarantine FILE-SERVER-01 (active lateral movement + DNS exfil)',
      '3. Kill process wdcu.exe on DC-01 to stop credential dumping',
      '4. Close port 4444 on WS-004 (C2 beacon)',
      '5. Close port 53 at firewall (DNS tunneling exfiltration)',
      '6. Block domain: exfilbase64.co (DNS tunnel target)',
      '7. Reset all domain credentials (DC-01 credentials compromised)',
      '8. Disable backdoor account svc_backup_new',
      '9. Quarantine WS-011 (lateral movement source)',
      '10. Re-enable AV via GPO (47 endpoints affected)'
    ];

    const modal = document.getElementById('ai-modal');
    const modalContent = document.getElementById('ai-modal-content');
    if (modal && modalContent) {
      modalContent.innerHTML = `
        <div class="flex items-center gap-2 mb-3">
          <span style="font-size:1.25rem">🤖</span>
          <div>
            <div style="font-size:0.9375rem;font-weight:700;color:var(--teal)">AI Recommended Response</div>
            <div class="text-xs text-muted">Optimal action sequence to contain this incident</div>
          </div>
        </div>
        <div style="background:var(--bg-primary);border-radius:8px;padding:1rem;margin-bottom:1rem;">
          ${steps.map((s, i) => `
            <div class="flex items-start gap-2 mb-2" style="animation:fade-in 0.2s ease ${i*0.08}s both;">
              <span style="background:var(--teal);color:#000;border-radius:50%;width:18px;height:18px;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;flex-shrink:0;margin-top:1px">${i+1}</span>
              <span class="text-xs" style="color:var(--text-primary);line-height:1.5;">${s.slice(3)}</span>
            </div>`).join('')}
        </div>
        <div style="background:rgba(0,212,216,0.05);border:1px solid rgba(0,212,216,0.2);border-radius:8px;padding:0.75rem;margin-bottom:1rem;">
          <div class="text-xs text-teal font-mono mb-1">ESTIMATED IMPACT</div>
          <div class="text-xs text-muted">Following all 10 steps will: stop active exfiltration, remove C2 persistence,
          close all known attack paths, and prevent further lateral movement.
          Estimated containment time: 4 minutes (automated) vs 45+ minutes (manual).</div>
        </div>
        <button class="btn btn-primary btn-full" onclick="closeAIModal()">Got it — I'll follow this plan</button>`;
      modal.classList.remove('hidden');
    }

    if (btn) {
      btn.innerHTML = `🤖 AI Recommend`;
      btn.disabled = false;
    }
  }, 1800);
}

function closeAIModal() {
  const modal = document.getElementById('ai-modal');
  if (modal) modal.classList.add('hidden');
}

/* ── Victory condition ── */
function checkVictoryCondition() {
  const compromised = NETWORK.nodes.filter(n => n.status === 'compromised');
  const openThreats = NETWORK.ports.filter(p => p.threat && p.status === 'open');

  if (compromised.length === 0 && openThreats.length === 0) {
    setTimeout(() => {
      SENTINEL.toast('🎉 Incident contained! All compromised nodes isolated.', 'success', 5000);
      logAction('★ INCIDENT CONTAINED: All threat vectors neutralized. Network secured.', 'success');
    }, 500);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  initRemediation();
  renderBlocklist();
  updateActionPanel();
});
