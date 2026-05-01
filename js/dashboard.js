/* SENTINEL — Command Center Dashboard */

async function initDashboard() {
  const mitreData = SENTINEL_MITRE;

  /* ── Animated stat counters ── */
  SENTINEL.animateCount(document.getElementById('stat-alerts'),       2742, 1800);
  SENTINEL.animateCount(document.getElementById('stat-incidents'),     130, 1400);
  SENTINEL.animateCount(document.getElementById('stat-resolved'),      103, 1200);
  SENTINEL.animateCount(document.getElementById('stat-open'),           27, 1000);
  SENTINEL.animateCount(document.getElementById('stat-automated'),      97, 1300);
  SENTINEL.animateCount(document.getElementById('stat-manual'),         33, 1100);
  SENTINEL.animateCount(document.getElementById('stat-automated-pct'), 75, 1500, '%');
  SENTINEL.animateCount(document.getElementById('stat-prevented'),  286000, 2000);

  /* Animate automation bar */
  setTimeout(() => {
    const bar = document.getElementById('automation-bar');
    if (bar) bar.style.width = '75%';
  }, 400);

  buildMitreChart(mitreData);
  buildAIFlowViz();
  LIVE_LOG.init(document.getElementById('log-feed'));
  buildSparklines();
  buildLowerGrid();
  startLiveAlertCounter();
  initTweaksPanel();

  /* Animate vol bars */
  setTimeout(() => {
    document.querySelectorAll('.vol-bar-fill').forEach(bar => {
      bar.style.transition = 'width 1.4s ease';
      bar.style.width = bar.dataset.width;
    });
  }, 500);
}

/* ══════════════════════════════════════════
   MITRE ATT&CK Chart (v2 — tactic IDs)
   ══════════════════════════════════════════ */
function buildMitreChart(mitreData) {
  const container = document.getElementById('mitre-chart');
  if (!container) return;

  const counts = mitreData.dayThreeCounts;
  const max = Math.max(...Object.values(counts));

  const tacticIds = {
    'Reconnaissance':       'TA0043',
    'Initial Access':       'TA0001',
    'Execution':            'TA0002',
    'Persistence':          'TA0003',
    'Privilege Escalation': 'TA0004',
    'Defense Evasion':      'TA0005',
    'Credential Access':    'TA0006',
    'Discovery':            'TA0007',
    'Lateral Movement':     'TA0008',
    'Collection':           'TA0009',
    'Command and Control':  'TA0011',
    'Exfiltration':         'TA0010',
    'Impact':               'TA0040',
  };

  let html = '';
  for (const [tactic, count] of Object.entries(counts)) {
    if (count === 0) continue;
    const pct = (count / max) * 100;
    const tacticInfo = mitreData.tactics.find(t => t.name === tactic);
    const color = tacticInfo ? tacticInfo.color : '#6b7280';
    const tacticId = tacticIds[tactic] || '';
    const countColor = count >= 8 ? 'var(--critical)' : count >= 4 ? 'var(--medium)' : 'var(--text-muted)';

    html += `
      <div style="display:flex;align-items:center;gap:0;margin-bottom:9px;">
        <div style="width:3px;height:32px;background:${color};border-radius:2px;flex-shrink:0;margin-right:10px;opacity:0.85;"></div>
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
            <div style="display:flex;align-items:center;gap:5px;min-width:0;overflow:hidden;">
              <span style="font-size:0.75rem;font-weight:600;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${tactic}</span>
              ${tacticId ? `<span style="font-family:var(--font-mono);font-size:0.5rem;color:${color};background:${color}18;border:1px solid ${color}35;padding:1px 5px;border-radius:3px;flex-shrink:0;">${tacticId}</span>` : ''}
            </div>
            <span style="font-family:var(--font-mono);font-size:0.8125rem;font-weight:700;color:${countColor};margin-left:8px;flex-shrink:0;">${count}</span>
          </div>
          <div style="height:3px;background:var(--bg-elevated);border-radius:2px;overflow:hidden;">
            <div class="mitre-bar-fill" style="height:100%;width:0%;background:${color};border-radius:2px;opacity:0.75;" data-target="${pct}"></div>
          </div>
        </div>
      </div>`;
  }
  container.innerHTML = html;

  setTimeout(() => {
    container.querySelectorAll('.mitre-bar-fill').forEach(bar => {
      bar.style.transition = 'width 1.2s ease';
      bar.style.width = bar.dataset.target + '%';
    });
  }, 200);
}

/* ══════════════════════════════════════════
   AI CORE VISUALIZER — Design v2
   RAF-based: CoreParticles, StreamingComets,
   OutboundPulses. No animation libraries.
   ══════════════════════════════════════════ */
function buildAIFlowViz() {
  const wrap = document.getElementById('aicore-wrap') || document.getElementById('sankey-svg')?.parentElement;
  if (!wrap) return;

  const INTENSITY = 5;
  const VOL_MULT  = 1;
  const SVG_NS    = 'http://www.w3.org/2000/svg';

  const SOURCES = [
    { id:'ep',   label:'Endpoints',    sub:'41,700',    icon:'▣', color:'#5eead4', count:'56.3 TB' },
    { id:'ngfw', label:'NGFW',         sub:'Firewall',  icon:'◈', color:'#fb923c', count:'3.1 TB' },
    { id:'aws',  label:'AWS',          sub:'Cloud',     icon:'☁', color:'#facc15', count:'2.6 TB' },
    { id:'azure',label:'Azure',        sub:'Cloud',     icon:'◆', color:'#38bdf8', count:'238 GB' },
    { id:'gcp',  label:'Google Cloud', sub:'Cloud',     icon:'◉', color:'#4ade80', count:'2.6 TB' },
    { id:'o365', label:'Office 365',   sub:'Email',     icon:'✉', color:'#f43f5e', count:'201 GB', alert:true },
    { id:'okta', label:'Okta',         sub:'Identity',  icon:'⚷', color:'#a78bfa', count:'2.5 GB' },
    { id:'pp',   label:'Proofpoint',   sub:'Email Sec', icon:'◐', color:'#22d3ee', count:'5.5 GB' },
  ];

  wrap.style.cssText = 'position:relative;overflow:hidden;' + (wrap.style.cssText || '');
  wrap.innerHTML = '';

  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.style.cssText = 'position:absolute;inset:0;';
  wrap.appendChild(svg);

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:absolute;inset:0;pointer-events:none;overflow:hidden;';
  wrap.appendChild(overlay);

  let W, H, coreCx, coreCy, coreR, sourceX, incidentX, sourceYs, incidentLanes;
  let activeRAFs = [];
  let coreParticles = [];
  let gParticles, gComets, gPulses;

  const mk   = tag => document.createElementNS(SVG_NS, tag);
  const mkC  = (cx, cy, r, a) => { const c = mk('circle'); c.setAttribute('cx',cx); c.setAttribute('cy',cy); c.setAttribute('r',r); for (const [k,v] of Object.entries(a||{})) c.setAttribute(k,v); return c; };

  function computeGeom(w, h) {
    W = w; H = h;
    coreCx = W * 0.46;
    coreCy = H * 0.5;
    coreR  = Math.min(H * 0.32, 130);
    sourceX    = Math.max(W * 0.12, 110);
    incidentX  = Math.min(W * 0.78, W - 200);
    sourceYs   = SOURCES.map((_, i) => 50 + (i / (SOURCES.length - 1)) * (H - 100));
    incidentLanes = [
      { y: H * 0.32, label: 'AUTOMATED', color: '#5eead4', count: 78 },
      { y: H * 0.68, label: 'MANUAL',    color: '#fb923c', count: 16 },
    ];
  }

  function buildDefs() {
    const defs = mk('defs');
    defs.innerHTML = `
      <radialGradient id="v2coreGrad" cx="50%" cy="50%" r="50%">
        <stop offset="0%"   stop-color="#5eead4" stop-opacity="0.5"/>
        <stop offset="40%"  stop-color="#0d9488" stop-opacity="0.18"/>
        <stop offset="100%" stop-color="#0d9488" stop-opacity="0"/>
      </radialGradient>
      <radialGradient id="v2coreGlow" cx="50%" cy="50%" r="50%">
        <stop offset="0%"   stop-color="#5eead4" stop-opacity="0.4"/>
        <stop offset="100%" stop-color="#5eead4" stop-opacity="0"/>
      </radialGradient>
      <linearGradient id="v2streamGrad" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%"   stop-color="#5eead4" stop-opacity="0"/>
        <stop offset="100%" stop-color="#5eead4" stop-opacity="0.45"/>
      </linearGradient>
      <linearGradient id="v2outAuto" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%"   stop-color="#5eead4" stop-opacity="0.5"/>
        <stop offset="100%" stop-color="#5eead4" stop-opacity="0.05"/>
      </linearGradient>
      <linearGradient id="v2outMan" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%"   stop-color="#fb923c" stop-opacity="0.45"/>
        <stop offset="100%" stop-color="#fb923c" stop-opacity="0.05"/>
      </linearGradient>`;
    svg.appendChild(defs);
  }

  function buildStaticElements() {
    // Source → Core bezier paths
    SOURCES.forEach((s, i) => {
      const y = sourceYs[i];
      const path = mk('path');
      path.setAttribute('d', `M ${sourceX+14} ${y} C ${sourceX+60} ${y}, ${coreCx-coreR-40} ${coreCy}, ${coreCx-coreR} ${coreCy}`);
      path.setAttribute('stroke', s.alert ? 'rgba(244,63,94,0.5)' : 'url(#v2streamGrad)');
      path.setAttribute('stroke-width', s.alert ? '1.4' : '1');
      path.setAttribute('fill', 'none');
      path.setAttribute('opacity', '0.65');
      svg.appendChild(path);
    });

    // Halo glow
    svg.appendChild(mkC(coreCx, coreCy, coreR+60, { fill:'url(#v2coreGlow)' }));

    // Outer dotted ring (spin)
    const outerRing = mkC(coreCx, coreCy, coreR, { fill:'none', stroke:'rgba(94,234,212,0.4)', 'stroke-width':'1', 'stroke-dasharray':'2 5' });
    outerRing.style.cssText = `transform-origin:${coreCx}px ${coreCy}px;animation:spin ${28/(INTENSITY/5)}s linear infinite`;
    svg.appendChild(outerRing);

    // Mid ring (spinReverse)
    const midRing = mkC(coreCx, coreCy, coreR-22, { fill:'none', stroke:'rgba(94,234,212,0.18)', 'stroke-width':'1', 'stroke-dasharray':'1 3' });
    midRing.style.cssText = `transform-origin:${coreCx}px ${coreCy}px;animation:spinReverse ${20/(INTENSITY/5)}s linear infinite`;
    svg.appendChild(midRing);

    // Inner filled ring
    svg.appendChild(mkC(coreCx, coreCy, coreR-44, { fill:'url(#v2coreGrad)', stroke:'rgba(94,234,212,0.5)', 'stroke-width':'0.8' }));

    // 36 tick marks
    for (let i = 0; i < 36; i++) {
      const a = (i / 36) * Math.PI * 2;
      const r1 = coreR + 6, r2 = coreR + (i % 3 === 0 ? 14 : 10);
      const line = mk('line');
      line.setAttribute('x1', coreCx + Math.cos(a)*r1); line.setAttribute('y1', coreCy + Math.sin(a)*r1);
      line.setAttribute('x2', coreCx + Math.cos(a)*r2); line.setAttribute('y2', coreCy + Math.sin(a)*r2);
      line.setAttribute('stroke', 'rgba(94,234,212,0.4)'); line.setAttribute('stroke-width', '1');
      svg.appendChild(line);
    }

    // Core → incident output streams
    incidentLanes.forEach((lane, i) => {
      const path = mk('path');
      path.setAttribute('d', `M ${coreCx+coreR} ${coreCy} C ${coreCx+coreR+80} ${coreCy}, ${incidentX-80} ${lane.y}, ${incidentX-14} ${lane.y}`);
      path.setAttribute('stroke', i===0 ? 'url(#v2outAuto)' : 'url(#v2outMan)');
      path.setAttribute('stroke-width', i===0 ? '6' : '3');
      path.setAttribute('fill', 'none'); path.setAttribute('opacity', '0.85');
      svg.appendChild(path);
    });

    // Animated groups (on top)
    gParticles = mk('g'); svg.appendChild(gParticles);
    gComets    = mk('g'); svg.appendChild(gComets);
    gPulses    = mk('g'); svg.appendChild(gPulses);
  }

  function buildOverlayElements() {
    overlay.innerHTML = '';

    // Source labels
    SOURCES.forEach((s, i) => {
      const y = sourceYs[i];
      const div = document.createElement('div');
      div.style.cssText = `position:absolute;left:${sourceX-108}px;top:${y-14}px;width:122px;display:flex;align-items:center;gap:7px;justify-content:flex-end;`;
      div.innerHTML = `<div style="text-align:right;"><div style="font-size:11px;font-weight:600;color:${s.alert?'var(--crit)':'var(--text)'};line-height:1.2;">${s.label}${s.alert?'<span style="margin-left:3px;font-size:9px;padding:1px 3px;background:rgba(244,63,94,0.18);color:var(--crit);border-radius:3px;font-family:var(--font-mono);">!</span>':''}</div><div style="font-size:9px;color:var(--text-muted);font-family:var(--font-mono);">${s.count}</div></div><div style="width:22px;height:22px;border-radius:5px;background:${s.color}1f;border:1px solid ${s.color}66;display:flex;align-items:center;justify-content:center;color:${s.color};font-size:11px;flex-shrink:0;">${s.icon}</div>`;
      overlay.appendChild(div);
    });

    const makeLabel = (cssText, html) => { const d = document.createElement('div'); d.style.cssText = cssText; d.innerHTML = html; overlay.appendChild(d); };

    // Alerts counter (left of core)
    makeLabel(`position:absolute;left:${coreCx-coreR-96}px;top:${coreCy-20}px;text-align:right;width:78px;`,
      `<div style="font-size:22px;font-weight:600;color:var(--text);line-height:1;font-family:var(--font-mono);">2,742</div><div style="font-size:9px;letter-spacing:0.14em;color:var(--text-muted);margin-top:3px;font-weight:700;">ALERTS / 24H</div>`);

    // AI label inside core
    makeLabel(`position:absolute;left:${coreCx-40}px;top:${coreCy-14}px;width:80px;text-align:center;`,
      `<div style="font-size:9px;letter-spacing:0.18em;color:var(--teal);font-weight:700;">SENTINEL · AI</div><div style="font-size:8px;color:var(--text-muted);font-family:var(--font-mono);margin-top:2px;">v4.2 · streaming</div>`);

    // Incidents counter (right of core)
    makeLabel(`position:absolute;left:${coreCx+coreR+24}px;top:${coreCy-20}px;text-align:left;width:80px;`,
      `<div style="font-size:22px;font-weight:600;color:var(--teal);line-height:1;font-family:var(--font-mono);">94</div><div style="font-size:9px;letter-spacing:0.14em;color:var(--text-muted);margin-top:3px;font-weight:700;">INCIDENTS</div>`);

    // Incident lane counters
    incidentLanes.forEach((lane, i) => {
      makeLabel(`position:absolute;left:${incidentX+16}px;top:${lane.y-18}px;width:130px;`,
        `<div style="font-size:22px;font-weight:600;color:${i===0?'var(--teal)':'var(--high)'};line-height:1;font-family:var(--font-mono);">${lane.count}</div><div style="font-size:9px;letter-spacing:0.14em;color:var(--text-muted);margin-top:3px;font-weight:700;">${lane.label}</div>`);
    });

    // "Can be automated" callout
    makeLabel(`position:absolute;left:${coreCx+coreR+80}px;top:${coreCy+90}px;background:var(--bg-2);border:1px solid var(--line-strong);border-radius:999px;padding:6px 14px;font-size:11px;color:var(--text);white-space:nowrap;pointer-events:auto;`,
      `<span style="color:var(--teal);font-family:var(--font-mono);font-weight:700;">20</span> can be automated <span style="color:var(--text-muted);font-size:10px;margin-left:6px;">· 10 playbooks ready</span>`);
  }

  /* ── CoreParticles — DO NOT MODIFY orbital math ── */
  function startCoreParticles() {
    const count = Math.round(INTENSITY * 5);
    const r = coreR - 50;
    coreParticles = Array.from({ length: count }).map(() => ({
      a0:    Math.random() * Math.PI * 2,
      rad:   r * (0.3 + Math.random() * 0.7),
      speed: 0.4 + Math.random() * 1.4,
      size:  1 + Math.random() * 2,
      color: ['#5eead4','#2dd4bf','#f43f5e','#facc15','#38bdf8'][Math.floor(Math.random() * 5)],
      phase: Math.random() * 5,
    }));
    coreParticles.forEach(p => gParticles.appendChild(mkC(coreCx, coreCy, p.size, { fill: p.color })));

    const start = performance.now();
    let raf;
    const loop = () => {
      const t = (performance.now() - start) / 1000;
      for (let i = 0; i < coreParticles.length; i++) {
        const p = coreParticles[i];
        const a = p.a0 + t * p.speed;
        const x = coreCx + Math.cos(a) * p.rad;
        const y = coreCy + Math.sin(a) * p.rad * 0.65;
        const node = gParticles.children[i];
        if (node) {
          node.setAttribute('cx', x);
          node.setAttribute('cy', y);
          node.setAttribute('opacity', 0.4 + 0.6 * Math.abs(Math.sin(t + p.phase)));
        }
      }
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    activeRAFs.push(() => cancelAnimationFrame(raf));
  }

  /* ── StreamingComets — cubic bezier from sources to core ── */
  function startStreamingComets() {
    const spawnInterval = Math.max(180, 1300 / (INTENSITY * VOL_MULT));
    const comets = [];
    let lastSpawn = 0, raf;
    const tick = t => {
      if (t - lastSpawn > spawnInterval) {
        lastSpawn = t;
        const idx = Math.floor(Math.random() * SOURCES.length);
        comets.push({ src: SOURCES[idx], y0: sourceYs[idx], start: t, dur: 1400 + Math.random() * 800 });
      }
      const alive = comets.filter(c => t - c.start < c.dur);
      comets.length = 0; comets.push(...alive);
      while (gComets.firstChild) gComets.removeChild(gComets.firstChild);
      for (const c of comets) {
        const p = (t - c.start) / c.dur, mt = 1 - p;
        const p0x=sourceX+14,p0y=c.y0, p1x=sourceX+60,p1y=c.y0, p2x=coreCx-coreR-40,p2y=coreCy, p3x=coreCx-coreR,p3y=coreCy;
        const x=mt*mt*mt*p0x+3*mt*mt*p*p1x+3*mt*p*p*p2x+p*p*p*p3x;
        const y=mt*mt*mt*p0y+3*mt*mt*p*p1y+3*mt*p*p*p2y+p*p*p*p3y;
        const op=p<0.1?p/0.1:(p>0.85?(1-p)/0.15:1);
        gComets.appendChild(mkC(x,y,c.src.alert?2.4:1.6,{fill:c.src.color,opacity:String(op*0.95)}));
        gComets.appendChild(mkC(x,y,5,{fill:c.src.color,opacity:String(op*0.18)}));
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    activeRAFs.push(() => cancelAnimationFrame(raf));
  }

  /* ── OutboundPulses — cubic bezier from core to incident lanes ── */
  function startOutboundPulses() {
    const spawnInterval = Math.max(900, 4000 / INTENSITY);
    const pulses = [];
    let lastSpawn = 0, raf;
    const tick = t => {
      if (t - lastSpawn > spawnInterval) {
        lastSpawn = t;
        pulses.push({ laneIdx: Math.random() < 0.78 ? 0 : 1, start: t, dur: 1600 + Math.random() * 600 });
      }
      const alive = pulses.filter(p => t - p.start < p.dur);
      pulses.length = 0; pulses.push(...alive);
      while (gPulses.firstChild) gPulses.removeChild(gPulses.firstChild);
      for (const p of pulses) {
        const lane = incidentLanes[p.laneIdx];
        const pr=(t-p.start)/p.dur, mt=1-pr;
        const p0x=coreCx+coreR,p0y=coreCy, p1x=coreCx+coreR+80,p1y=coreCy, p2x=incidentX-80,p2y=lane.y, p3x=incidentX-14,p3y=lane.y;
        const x=mt*mt*mt*p0x+3*mt*mt*pr*p1x+3*mt*pr*pr*p2x+pr*pr*pr*p3x;
        const y=mt*mt*mt*p0y+3*mt*mt*pr*p1y+3*mt*pr*pr*p2y+pr*pr*pr*p3y;
        const fade=pr<0.1?pr/0.1:(pr>0.85?(1-pr)/0.15:1);
        gPulses.appendChild(mkC(x,y,3,{fill:lane.color,opacity:String(fade)}));
        gPulses.appendChild(mkC(x,y,8,{fill:lane.color,opacity:String(fade*0.2)}));
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    activeRAFs.push(() => cancelAnimationFrame(raf));
  }

  function rebuild() {
    activeRAFs.forEach(fn => fn()); activeRAFs = [];
    svg.innerHTML = ''; overlay.innerHTML = '';
    const w = wrap.offsetWidth, h = wrap.offsetHeight;
    if (!w || !h) return;
    svg.setAttribute('width', w); svg.setAttribute('height', h);
    computeGeom(w, h);
    buildDefs();
    buildStaticElements();
    buildOverlayElements();
    startCoreParticles();
    startStreamingComets();
    startOutboundPulses();
  }

  let resizeTimer;
  const ro = new ResizeObserver(() => { clearTimeout(resizeTimer); resizeTimer = setTimeout(rebuild, 80); });
  ro.observe(wrap);
  // Initial build after layout (setTimeout so it works in background tabs too)
  setTimeout(rebuild, 0);

  /* legacy: remove any orphaned #sankey-svg element */
  const svgPlaceholder = document.getElementById('sankey-svg');
  if (svgPlaceholder && svgPlaceholder !== svg) svgPlaceholder.remove();
}


/* ══════════════════════════════════════════
   Incident Modal — Slice 6
   Two-column detail view with AI analysis,
   raw telemetry, quiz, and playbook.
   Quiz: +25 correct, −5 wrong.
   Persisted in localStorage.
   ══════════════════════════════════════════ */
function showIncidentModal(alertId) {
  const alert = (typeof ALERTS !== 'undefined' ? ALERTS : []).find(a => a.id === alertId);
  if (!alert) return;

  const ANSWERS_KEY = 'sentinel_incident_answers';
  function getAnswers() { try { return JSON.parse(localStorage.getItem(ANSWERS_KEY) || '{}'); } catch { return {}; } }
  function saveAnswer(id, optionId, correct) {
    const ans = getAnswers(); ans[id] = { optionId, correct };
    localStorage.setItem(ANSWERS_KEY, JSON.stringify(ans));
  }

  const existing = getAnswers()[alertId];
  const SEV_COLOR = { critical:'var(--critical)', high:'var(--high)', medium:'var(--medium)', low:'var(--low)' };
  const col = SEV_COLOR[alert.severity] || 'var(--text-muted)';
  const esc = s => SENTINEL._escHtml(String(s || ''));

  /* Remove any existing modal */
  document.getElementById('incident-modal-overlay')?.remove();

  const overlay = document.createElement('div');
  overlay.id = 'incident-modal-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.72);z-index:1000;display:flex;align-items:flex-start;justify-content:center;overflow-y:auto;padding:40px 20px;';
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };

  const modal = document.createElement('div');
  modal.style.cssText = 'width:100%;max-width:980px;background:var(--bg-1);border:1px solid var(--border);border-radius:14px;overflow:hidden;position:relative;margin:auto;';

  /* Modal header */
  const head = document.createElement('div');
  head.style.cssText = 'padding:1.25rem 1.5rem;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:flex-start;background:var(--bg-2);';
  head.innerHTML = `
    <div>
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
        <span style="display:inline-flex;align-items:center;justify-content:center;padding:2px 8px;border-radius:4px;background:${col}22;color:${col};font-size:9px;font-weight:700;letter-spacing:.08em;">${esc(alert.severity).toUpperCase()}</span>
        <span style="font-size:11px;font-family:var(--font-mono);color:var(--text-muted);">INC-${String(alert.id).padStart(4,'0')}</span>
        <span style="font-size:11px;font-family:var(--font-mono);color:var(--text-muted);">${esc(alert.ts)}</span>
      </div>
      <div style="font-size:18px;font-weight:600;color:var(--text-primary);">${esc(alert.title)}</div>
      <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">${esc(alert.source)} · MITRE ${esc(alert.mitre)} (${esc(alert.tactic)})</div>
    </div>
    <button id="modal-close-btn" style="background:none;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;padding:4px;line-height:1;">✕</button>`;
  modal.appendChild(head);

  /* Modal body — two-column grid */
  const body = document.createElement('div');
  body.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:0;';

  /* Left column */
  const left = document.createElement('div');
  left.style.cssText = 'padding:1.5rem;border-right:1px solid var(--border);display:flex;flex-direction:column;gap:1.25rem;';

  /* AI Analysis box */
  left.innerHTML += `
    <div style="background:rgba(0,212,216,.04);border:1px solid rgba(0,212,216,.2);border-radius:10px;padding:1rem;">
      <div style="font-size:11px;font-weight:700;color:var(--teal);letter-spacing:.08em;margin-bottom:8px;">◈ AI ANALYSIS</div>
      <div style="font-size:13px;line-height:1.6;color:var(--text-primary);">${esc(alert.summary)}</div>
      <div style="display:flex;justify-content:space-between;font-size:11px;margin-top:12px;">
        <span style="color:var(--text-muted);">Confidence</span>
        <span style="font-family:var(--font-mono);color:var(--teal);font-weight:700;">${alert.conf}%</span>
      </div>
      <div style="height:4px;background:var(--bg-elevated);border-radius:2px;overflow:hidden;margin-top:4px;">
        <div style="height:100%;width:${alert.conf}%;background:var(--teal);border-radius:2px;"></div>
      </div>
      ${alert.actor ? `<div style="margin-top:10px;"><span style="font-size:11px;color:var(--text-muted);">Suspect actor: </span><span style="font-family:var(--font-mono);font-size:11px;color:var(--critical);font-weight:700;">${esc(alert.actor)}</span></div>` : ''}
    </div>`;

  /* Raw telemetry */
  left.innerHTML += `
    <div>
      <div style="font-size:11px;font-weight:700;color:var(--text-muted);letter-spacing:.06em;margin-bottom:8px;">RAW TELEMETRY</div>
      <div style="background:var(--bg-0);border:1px solid var(--border);border-radius:8px;padding:12px;font-family:var(--font-mono);font-size:11px;line-height:1.7;">
        ${(alert.logs || []).map((l,i) => `<div style="color:${i===alert.logs.length-1?'var(--teal)':'var(--text-muted)'};">&gt; ${esc(l)}</div>`).join('')}
      </div>
    </div>`;

  /* Decision quiz */
  if (alert.decision) {
    const dec = alert.decision;
    const quizId = `quiz-${alertId}`;
    left.innerHTML += `
      <div id="${quizId}">
        <div style="font-size:11px;font-weight:700;color:var(--text-muted);letter-spacing:.06em;margin-bottom:8px;">DECISION POINT · QUIZ</div>
        <div style="font-size:13px;line-height:1.6;color:var(--text-primary);margin-bottom:12px;">${esc(dec.q)}</div>
        <div id="${quizId}-options" style="display:flex;flex-direction:column;gap:8px;">
          ${dec.options.map(o => {
            let btnStyle = 'display:flex;align-items:flex-start;gap:8px;padding:10px 12px;border-radius:8px;border:1px solid var(--border);background:var(--bg-2);cursor:pointer;text-align:left;width:100%;font-family:var(--font-ui);font-size:12px;color:var(--text-primary);';
            if (existing) {
              if (o.id === existing.optionId && o.correct)    btnStyle += 'border-color:var(--low);background:rgba(34,197,94,.08);';
              else if (o.id === existing.optionId && !o.correct) btnStyle += 'border-color:var(--critical);background:rgba(239,68,68,.08);';
              else if (o.correct)                              btnStyle += 'border-color:var(--low);background:rgba(34,197,94,.06);opacity:.7;';
            }
            return `<button ${existing ? 'disabled' : ''} data-option="${esc(o.id)}" data-correct="${o.correct}" data-fb="${esc(o.fb)}" style="${btnStyle}" class="quiz-opt-btn">
              <span style="flex-shrink:0;font-family:var(--font-mono);font-size:10px;color:var(--text-muted);margin-top:1px;">${esc(o.id).toUpperCase()}.</span>
              <span>${esc(o.text)}</span>
            </button>`;
          }).join('')}
        </div>
        ${existing ? renderFeedback(dec.options.find(o => o.id === existing.optionId)) : '<div id="' + quizId + '-feedback"></div>'}
      </div>`;
  }

  body.appendChild(left);

  /* Right column */
  const right = document.createElement('div');
  right.style.cssText = 'padding:1.5rem;display:flex;flex-direction:column;gap:1.25rem;';
  right.innerHTML = `
    <div>
      <div style="font-size:11px;font-weight:700;color:var(--text-muted);letter-spacing:.06em;margin-bottom:10px;">RECOMMENDED PLAYBOOK</div>
      <div style="display:flex;flex-direction:column;gap:8px;">
        ${[{step:1,name:'Isolate affected endpoint',auto:true},{step:2,name:'Snapshot memory + disk',auto:true},{step:3,name:'Disable user credentials',auto:false},{step:4,name:'Hunt for related IOCs',auto:true},{step:5,name:'Notify IR lead',auto:false}].map(p=>`
        <div style="display:flex;align-items:center;gap:10px;padding:8px 10px;border:1px solid var(--border);border-radius:6px;background:var(--bg-2);">
          <div style="flex-shrink:0;width:22px;height:22px;border-radius:5px;background:var(--bg-elevated);display:flex;align-items:center;justify-content:center;font-size:11px;font-family:var(--font-mono);color:var(--teal);">${p.step}</div>
          <div style="flex:1;font-size:12px;color:var(--text-primary);">${p.name}</div>
          <span style="flex-shrink:0;font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;${p.auto?'background:rgba(94,234,212,.12);color:var(--teal);border:1px solid rgba(94,234,212,.25);':'background:rgba(251,146,60,.1);color:var(--high);border:1px solid rgba(251,146,60,.25);'}">${p.auto?'AUTO':'MANUAL'}</span>
        </div>`).join('')}
      </div>
    </div>
    <div>
      <div style="font-size:11px;font-weight:700;color:var(--text-muted);letter-spacing:.06em;margin-bottom:10px;">TRIAGE ACTIONS</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <button class="btn btn-primary" style="font-size:12px;">▶ Run Playbook</button>
        <button class="btn" style="font-size:12px;">Assign…</button>
        <button class="btn" style="font-size:12px;background:rgba(239,68,68,.12);border-color:rgba(239,68,68,.3);color:var(--critical);">Quarantine</button>
        <button class="btn btn-ghost" style="font-size:12px;">Mark FP</button>
        <button class="btn btn-ghost" style="font-size:12px;">Escalate</button>
      </div>
    </div>
    <div>
      <div style="font-size:11px;font-weight:700;color:var(--text-muted);letter-spacing:.06em;margin-bottom:10px;">CHAIN OF EVENTS</div>
      <div style="display:flex;flex-direction:column;gap:0;">
        ${[
          {time:'02:14:33 · INITIAL ACCESS',title:'Macro-enabled doc opened',detail:'Word spawned a child process; binary written to disk.',type:'attack'},
          {time:'02:16:01 · DEFENSE EVASION',title:'Payload mutates self',detail:'Hash changes; behavior fingerprint stays identical.',type:'attack'},
          {time:'02:19:55 · AI DETECTION',title:'Behavioral correlation alert',detail:'SIEM AI links file write + parent-child + network beacon across two hosts.',type:'defense'},
          {time:'02:21:00 · DECISION',title:'Awaiting analyst response',detail:'',type:'pending'},
        ].map(e=>`
        <div style="display:flex;gap:12px;padding-bottom:14px;position:relative;">
          <div style="flex-shrink:0;width:10px;height:10px;border-radius:50%;margin-top:3px;${e.type==='attack'?'background:var(--critical);':e.type==='defense'?'background:var(--teal);':'background:var(--text-dim);'};flex-shrink:0;"></div>
          <div style="flex:1;">
            <div style="font-size:9px;font-family:var(--font-mono);color:var(--text-muted);letter-spacing:.06em;">${e.time}</div>
            <div style="font-size:12px;font-weight:600;color:var(--text-primary);margin-top:2px;">${e.title}</div>
            ${e.detail?`<div style="font-size:11px;color:var(--text-muted);margin-top:2px;line-height:1.5;">${e.detail}</div>`:''}
          </div>
        </div>`).join('')}
      </div>
    </div>`;

  body.appendChild(right);
  modal.appendChild(body);
  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  /* Close button */
  modal.querySelector('#modal-close-btn').onclick = () => overlay.remove();

  /* Quiz interaction */
  if (alert.decision && !existing) {
    modal.querySelectorAll('.quiz-opt-btn').forEach(btn => {
      btn.addEventListener('mouseenter', () => { if (!btn.disabled) btn.style.borderColor = 'var(--teal)'; });
      btn.addEventListener('mouseleave', () => { if (!btn.disabled) btn.style.borderColor = 'var(--border)'; });
      btn.addEventListener('click', () => {
        const optId = btn.dataset.option;
        const correct = btn.dataset.correct === 'true';
        const fb = btn.dataset.fb;
        /* Score */
        SENTINEL.updateScore(correct ? 25 : -5);
        /* Save */
        saveAnswer(alertId, optId, correct);
        /* Visual feedback */
        modal.querySelectorAll('.quiz-opt-btn').forEach(b => {
          const bCorrect = b.dataset.correct === 'true';
          b.disabled = true;
          if (b === btn && correct)  { b.style.borderColor='var(--low)'; b.style.background='rgba(34,197,94,.08)'; }
          else if (b === btn)        { b.style.borderColor='var(--critical)'; b.style.background='rgba(239,68,68,.08)'; }
          else if (bCorrect)         { b.style.borderColor='var(--low)'; b.style.opacity='0.7'; }
        });
        const fbEl = modal.querySelector(`#quiz-${alertId}-feedback`);
        if (fbEl) fbEl.outerHTML = renderFeedback(alert.decision.options.find(o => o.id === optId));
      });
    });
  }

  function renderFeedback(option) {
    if (!option) return '';
    const ok = option.correct;
    return `<div style="margin-top:10px;padding:10px 12px;border-radius:8px;border:1px solid ${ok?'var(--low)':'var(--critical)'};background:${ok?'rgba(34,197,94,.08)':'rgba(239,68,68,.06)'};font-size:12px;line-height:1.5;">
      <strong style="color:${ok?'var(--low)':'var(--critical)'};">${ok?'✓ Correct · +25 pts':'✗ Incorrect · −5 pts'}</strong><br>${esc(option.fb)}
    </div>`;
  }
}

/* ══════════════════════════════════════════
   INCIDENTS FLOW — Design v2
   Branching SVG: AI core → 127 incidents →
   AUTOMATED (teal) → RESOLVED
   MANUAL    (amber) → severity fan
   HITL dashed bridge + animated comets.
   ══════════════════════════════════════════ */
function buildIncidentsFlow(container) {
  if (!container) return;
  const INTENSITY = 5;
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const mk = tag => document.createElementNS(SVG_NS, tag);

  const SEVERITIES = [
    { code:'C', label:'Critical', count:3,  color:'#f43f5e', dy:-54 },
    { code:'H', label:'High',     count:12, color:'#fb923c', dy:-18 },
    { code:'M', label:'Medium',   count:8,  color:'#facc15', dy: 18 },
    { code:'L', label:'Low',      count:4,  color:'#38bdf8', dy: 54 },
  ];

  /* Header */
  const header = document.createElement('div');
  header.style.cssText = 'padding:1rem 1.5rem 0.75rem;display:flex;align-items:center;justify-content:space-between;';
  header.innerHTML = `
    <div>
      <div class="card-title-large">Incidents Flow — AI Processing Pipeline</div>
      <div class="text-xs text-muted mt-1">How SENTINEL AI routes 127 incidents from raw alerts to resolution</div>
    </div>
    <span class="badge badge-teal" style="font-size:0.6875rem;">LIVE · ${new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'})}</span>`;
  container.appendChild(header);

  /* Canvas wrapper */
  const wrap = document.createElement('div');
  wrap.style.cssText = 'position:relative;overflow:hidden;height:540px;';
  container.appendChild(wrap);

  const svg = mk('svg');
  svg.style.cssText = 'position:absolute;inset:0;';
  wrap.appendChild(svg);

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:absolute;inset:0;pointer-events:none;overflow:hidden;';
  wrap.appendChild(overlay);

  /* Animated comet groups */
  const gInflow  = mk('g'); svg.appendChild(gInflow);
  const gFlow    = mk('g'); svg.appendChild(gFlow);

  let W, H, aiX, aiY, aiR, incidentsX, splitX, autoX, autoY, manualX, manualY,
      resolvedX, resolvedY, sevHubX, sevHubY, hitlMidX, hitlMidY, hitlBackX, hitlBackY;
  let activeRAFs = [];

  function computeLayout(w, h) {
    W = w; H = h;
    aiX = 260; aiY = H * 0.5;
    aiR = Math.min(H * 0.26, 110);
    incidentsX = aiX + aiR + 130;
    splitX     = incidentsX + 130;
    autoX      = W * 0.6;  autoY  = H * 0.22;
    manualX    = W * 0.6;  manualY = H * 0.78;
    resolvedX  = W * 0.86; resolvedY = H * 0.18;
    sevHubX    = W * 0.86; sevHubY   = H * 0.78;
    hitlMidX   = autoX + 170;
    hitlMidY   = (autoY + manualY) * 0.5;
    hitlBackX  = (autoX + resolvedX) * 0.5;
    hitlBackY  = autoY;
  }

  function buildSVG(w, h) {
    svg.setAttribute('width', w); svg.setAttribute('height', h);
    svg.innerHTML = '';
    gInflow.innerHTML = ''; svg.appendChild(gInflow);
    gFlow.innerHTML   = ''; svg.appendChild(gFlow);

    /* defs */
    const defs = mk('defs');
    defs.innerHTML = `
      <radialGradient id="ifCoreGrad" cx="50%" cy="50%" r="50%">
        <stop offset="0%"   stop-color="#5eead4" stop-opacity="0.55"/>
        <stop offset="40%"  stop-color="#0d9488" stop-opacity="0.18"/>
        <stop offset="100%" stop-color="#0d9488" stop-opacity="0"/>
      </radialGradient>
      <radialGradient id="ifHalo" cx="50%" cy="50%" r="50%">
        <stop offset="0%"   stop-color="#5eead4" stop-opacity="0.4"/>
        <stop offset="100%" stop-color="#5eead4" stop-opacity="0"/>
      </radialGradient>
      <linearGradient id="ifTrunk" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%"   stop-color="#5eead4" stop-opacity="0.7"/>
        <stop offset="100%" stop-color="#5eead4" stop-opacity="0.25"/>
      </linearGradient>
      <linearGradient id="ifAuto" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%"   stop-color="#5eead4" stop-opacity="0.55"/>
        <stop offset="100%" stop-color="#5eead4" stop-opacity="0.1"/>
      </linearGradient>
      <linearGradient id="ifMan" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%"   stop-color="#fb923c" stop-opacity="0.55"/>
        <stop offset="100%" stop-color="#fb923c" stop-opacity="0.1"/>
      </linearGradient>`;
    svg.insertBefore(defs, svg.firstChild);

    const c = (cx,cy,r,attrs) => { const el=mk('circle'); el.setAttribute('cx',cx); el.setAttribute('cy',cy); el.setAttribute('r',r); for(const[k,v] of Object.entries(attrs||{})) el.setAttribute(k,v); return el; };
    const p = (d,attrs) => { const el=mk('path'); el.setAttribute('d',d); for(const[k,v] of Object.entries(attrs||{})) el.setAttribute(k,v); return el; };
    const t = (x,y,txt,attrs) => { const el=mk('text'); el.setAttribute('x',x); el.setAttribute('y',y); el.textContent=txt; for(const[k,v] of Object.entries(attrs||{})) el.setAttribute(k,v); return el; };

    /* AI core halo + rings */
    svg.appendChild(c(aiX,aiY,aiR+50,{fill:'url(#ifHalo)'}));
    const outerRing = c(aiX,aiY,aiR,{fill:'none',stroke:'rgba(94,234,212,0.4)','stroke-width':'1','stroke-dasharray':'2 5'});
    outerRing.style.cssText = `transform-origin:${aiX}px ${aiY}px;animation:spin ${28/(INTENSITY/5)}s linear infinite`;
    svg.appendChild(outerRing);
    const midRing = c(aiX,aiY,aiR-20,{fill:'none',stroke:'rgba(94,234,212,0.18)','stroke-width':'1','stroke-dasharray':'1 3'});
    midRing.style.cssText = `transform-origin:${aiX}px ${aiY}px;animation:spinReverse ${20/(INTENSITY/5)}s linear infinite`;
    svg.appendChild(midRing);
    svg.appendChild(c(aiX,aiY,aiR-40,{fill:'url(#ifCoreGrad)',stroke:'rgba(94,234,212,0.5)','stroke-width':'0.8'}));

    /* 36 tick marks */
    for (let i=0;i<36;i++) {
      const a=(i/36)*Math.PI*2, r1=aiR+4, r2=aiR+(i%3===0?12:8);
      const ln=mk('line');
      ln.setAttribute('x1',aiX+Math.cos(a)*r1); ln.setAttribute('y1',aiY+Math.sin(a)*r1);
      ln.setAttribute('x2',aiX+Math.cos(a)*r2); ln.setAttribute('y2',aiY+Math.sin(a)*r2);
      ln.setAttribute('stroke','rgba(94,234,212,0.4)'); ln.setAttribute('stroke-width','1');
      svg.appendChild(ln);
    }

    /* Core particles (reuse from AICore — minimal orbital version) */
    const gCP = mk('g'); svg.appendChild(gCP);
    const cpCount = Math.round(INTENSITY * 5);
    const cpList = Array.from({length:cpCount},(_,i)=>({
      a0: (i/cpCount)*Math.PI*2, speed: 0.004+Math.random()*0.012,
      rad: (aiR-46)*(0.4+Math.random()*0.6), phase: Math.random()*Math.PI*2,
      color: ['#5eead4','#a5f3fc','#38bdf8','#22d3ee'][Math.floor(Math.random()*4)],
    }));
    const cpDots = cpList.map(()=>{ const el=mk('circle'); el.setAttribute('r','1.5'); gCP.appendChild(el); return el; });

    /* Trunk: AI → incidents junction */
    svg.appendChild(p(`M ${aiX+aiR} ${aiY} L ${incidentsX-12} ${aiY}`,{stroke:'url(#ifTrunk)','stroke-width':'6',fill:'none'}));

    /* Incidents junction node */
    svg.appendChild(c(incidentsX,aiY,9,{fill:'var(--bg-1)',stroke:'var(--teal)','stroke-width':'1.5'}));
    svg.appendChild(c(incidentsX,aiY,3,{fill:'var(--teal)'}));

    /* Split paths */
    svg.appendChild(p(`M ${incidentsX+9} ${aiY} C ${splitX+30} ${aiY}, ${autoX-80} ${autoY}, ${autoX-14} ${autoY}`,{stroke:'url(#ifAuto)','stroke-width':'6',fill:'none'}));
    svg.appendChild(p(`M ${incidentsX+9} ${aiY} C ${splitX+30} ${aiY}, ${manualX-80} ${manualY}, ${manualX-14} ${manualY}`,{stroke:'url(#ifMan)','stroke-width':'4',fill:'none'}));

    /* AUTOMATED node */
    svg.appendChild(c(autoX,autoY,14,{fill:'var(--bg-1)',stroke:'var(--teal)','stroke-width':'2'}));
    const tAuto = t(autoX,autoY+4,'⚙',{'text-anchor':'middle','font-size':'13','font-family':'JetBrains Mono',fill:'var(--teal)','font-weight':'600'});
    svg.appendChild(tAuto);

    /* MANUAL node */
    svg.appendChild(c(manualX,manualY,14,{fill:'var(--bg-1)',stroke:'#fb923c','stroke-width':'2'}));
    const tMan = t(manualX,manualY+4,'⌘',{'text-anchor':'middle','font-size':'13','font-family':'JetBrains Mono',fill:'#fb923c','font-weight':'600'});
    svg.appendChild(tMan);

    /* AUTO → RESOLVED */
    svg.appendChild(p(`M ${autoX+14} ${autoY} C ${autoX+100} ${autoY}, ${resolvedX-100} ${resolvedY}, ${resolvedX-14} ${resolvedY}`,{stroke:'rgba(94,234,212,0.55)','stroke-width':'6',fill:'none'}));

    /* MANUAL → SEVERITY HUB */
    svg.appendChild(p(`M ${manualX+14} ${manualY} C ${manualX+80} ${manualY}, ${sevHubX-80} ${sevHubY}, ${sevHubX-14} ${sevHubY}`,{stroke:'rgba(251,146,60,0.5)','stroke-width':'4',fill:'none'}));

    /* Pill is rendered as a fixed 212px block at left=(hitlMidX-106), top=(hitlMidY-21)
       height = 6px padding + 14px line1 + 2px gap + 11px line2 + 6px padding = 39px
       vertical center = (hitlMidY-21) + 19.5 ≈ hitlMidY - 1 → use hitlMidY */
    const PILL_W     = 212;
    const PILL_H     = 46;
    const pillLeftX  = hitlMidX - PILL_W / 2;
    const pillRightX = hitlMidX + PILL_W / 2;
    const pillConnY  = hitlMidY;

    /* Small anchor dots on pill edges */
    svg.appendChild(c(pillLeftX,  pillConnY, 3, {fill:'rgba(251,146,60,0.85)'}));
    svg.appendChild(c(pillRightX, pillConnY, 3, {fill:'rgba(94,234,212,0.85)'}));

    /* Dashed line: MANUAL node → left edge of pill (incoming, amber) */
    const manToHitl = p(
      `M ${manualX+14} ${manualY} C ${manualX+90} ${manualY-30}, ${pillLeftX-90} ${pillConnY+30}, ${pillLeftX} ${pillConnY}`,
      {stroke:'rgba(251,146,60,0.6)', 'stroke-width':'1.5', fill:'none', 'stroke-dasharray':'4 4'});
    manToHitl.style.animation = 'dashDrift 2s linear infinite';
    svg.appendChild(manToHitl);

    /* Dashed line: right edge of pill → RESOLVED node (teal, up-right) */
    const hitlToResolved = p(
      `M ${pillRightX} ${pillConnY} C ${pillRightX+70} ${pillConnY-50}, ${resolvedX-70} ${resolvedY+40}, ${resolvedX-10} ${resolvedY}`,
      {stroke:'rgba(94,234,212,0.6)', 'stroke-width':'1.5', fill:'none', 'stroke-dasharray':'4 4'});
    hitlToResolved.style.animation = 'dashDrift 2s linear infinite';
    svg.appendChild(hitlToResolved);

    /* Dashed line: right edge of pill → SEVERITY HUB (amber, down-right) */
    const hitlToSevHub = p(
      `M ${pillRightX} ${pillConnY} C ${pillRightX+70} ${pillConnY+50}, ${sevHubX-70} ${sevHubY-40}, ${sevHubX-10} ${sevHubY}`,
      {stroke:'rgba(251,146,60,0.6)', 'stroke-width':'1.5', fill:'none', 'stroke-dasharray':'4 4'});
    hitlToSevHub.style.animation = 'dashDrift 2s linear infinite';
    svg.appendChild(hitlToSevHub);

    /* Severity fan-out paths */
    SEVERITIES.forEach(s => {
      const sx = sevHubX+70, sy = sevHubY+s.dy;
      svg.appendChild(p(`M ${sevHubX+14} ${sevHubY} C ${sevHubX+30} ${sevHubY}, ${sx-30} ${sy}, ${sx-8} ${sy}`,
        {stroke:s.color,'stroke-opacity':'0.55','stroke-width':'1.6',fill:'none'}));
    });

    /* RESOLVED node */
    svg.appendChild(c(resolvedX,resolvedY,10,{fill:'var(--teal)',stroke:'rgba(94,234,212,0.4)','stroke-width':'6'}));

    /* Severity hub anchor */
    svg.appendChild(c(sevHubX,sevHubY,5,{fill:'#fb923c'}));

    /* Severity dots */
    SEVERITIES.forEach(s => {
      svg.appendChild(c(sevHubX+70,sevHubY+s.dy,5,{fill:s.color,stroke:`${s.color}55`,'stroke-width':'4'}));
    });

    /* Comet groups must be last (top layer) */
    svg.appendChild(gInflow); svg.appendChild(gFlow);

    /* ── Overlay labels ── */
    overlay.innerHTML = '';
    const lbl = (lft,tp,html) => { const d=document.createElement('div'); d.style.cssText=`position:absolute;left:${lft}px;top:${tp}px;`; d.innerHTML=html; overlay.appendChild(d); };

    /* Live alert count (left of orb) */
    const alertLX = aiX - aiR - 130, alertLY = aiY - 24;
    lbl(alertLX, alertLY, `<div style="width:100px;text-align:right;">
      <div style="font-size:26px;font-weight:700;color:var(--text-primary);line-height:1;font-family:var(--font-mono);" id="if-alert-count">2,742</div>
      <div style="font-size:9px;letter-spacing:.16em;color:var(--text-muted);margin-top:4px;font-weight:700;">ALERTS · LIVE</div>
      <div style="font-size:10px;color:var(--teal);margin-top:4px;opacity:.8;font-family:var(--font-mono);">↑ ingesting</div>
    </div>`);

    /* AI label inside core */
    lbl(aiX-50, aiY-14, `<div style="width:100px;text-align:center;">
      <div style="font-size:9px;letter-spacing:.18em;color:var(--teal);font-weight:700;">SENTINEL · AI</div>
      <div style="font-size:8px;color:var(--text-muted);font-family:var(--font-mono);margin-top:2px;">v4.2 · streaming</div>
    </div>`);

    /* INCIDENTS label */
    lbl(incidentsX-50, aiY-50, `<div style="width:100px;text-align:center;">
      <div style="font-size:18px;font-weight:600;color:var(--teal);line-height:1;font-family:var(--font-mono);">127</div>
      <div style="font-size:9px;letter-spacing:.14em;color:var(--text-muted);margin-top:3px;font-weight:700;">INCIDENTS</div>
    </div>`);

    /* AUTOMATED label */
    lbl(autoX-60, autoY-50, `<div style="width:120px;text-align:center;">
      <div style="font-size:18px;font-weight:600;color:var(--teal);line-height:1;font-family:var(--font-mono);">97</div>
      <div style="font-size:9px;letter-spacing:.14em;color:var(--text-muted);margin-top:3px;font-weight:700;">AUTOMATED</div>
    </div>`);

    /* MANUAL label */
    lbl(manualX-60, manualY+20, `<div style="width:120px;text-align:center;">
      <div style="font-size:18px;font-weight:600;color:#fb923c;line-height:1;font-family:var(--font-mono);">30</div>
      <div style="font-size:9px;letter-spacing:.14em;color:var(--text-muted);margin-top:3px;font-weight:700;">MANUAL</div>
    </div>`);

    /* RESOLVED label */
    lbl(resolvedX+18, resolvedY-20, `<div style="width:130px;">
      <div style="font-size:22px;font-weight:700;color:var(--text-primary);line-height:1;font-family:var(--font-mono);">103</div>
      <div style="font-size:9px;letter-spacing:.14em;color:var(--text-muted);margin-top:3px;font-weight:700;">RESOLVED<br>INCIDENTS</div>
    </div>`);

    /* HITL pill — fixed 212px block, left edge = pillLeftX, top = hitlMidY - PILL_H/2 */
    lbl(pillLeftX, hitlMidY - Math.round(PILL_H / 2),
      `<div style="display:block;width:${PILL_W}px;box-sizing:border-box;background:var(--bg-2);border:1px dashed rgba(94,234,212,.7);border-radius:999px;padding:6px 18px;font-size:11px;white-space:nowrap;color:var(--text-primary);box-shadow:0 0 14px rgba(94,234,212,.12);text-align:center;">
        <span style="color:var(--teal);font-weight:700;font-family:var(--font-mono);">20</span> can be automated
        <div style="font-size:9px;color:var(--text-muted);margin-top:2px;">HITL · 10 playbooks ready</div>
      </div>`);

    /* OPEN INCIDENTS by severity */
    lbl(sevHubX+78, sevHubY-78, `<div style="width:180px;">
      <div style="font-size:22px;font-weight:700;color:#fb923c;line-height:1;font-family:var(--font-mono);">27</div>
      <div style="font-size:9px;letter-spacing:.14em;color:var(--text-muted);margin-top:3px;margin-bottom:12px;font-weight:700;">OPEN<br>INCIDENTS</div>
      <div style="display:flex;flex-direction:column;gap:4px;">
        ${SEVERITIES.map(s=>`<div style="display:flex;align-items:center;gap:8px;">
          <span style="display:inline-flex;align-items:center;justify-content:center;width:22px;height:18px;border-radius:4px;background:${s.color}22;color:${s.color};font-size:10px;font-weight:700;">${s.code}</span>
          <span style="font-size:11px;color:var(--text-muted);">${s.label}</span>
          <span style="margin-left:auto;font-size:12px;color:${s.color};font-weight:700;font-family:var(--font-mono);">${s.count}</span>
        </div>`).join('')}
      </div>
    </div>`);

    /* ── Animation: core particles ── */
    let cpRAF;
    function cpTick(t2) {
      cpList.forEach((p2,i) => {
        const a = p2.a0 + t2*0.001 * p2.speed * 300;
        const x = aiX + Math.cos(a)*p2.rad;
        const y = aiY + Math.sin(a)*p2.rad*0.65;
        cpDots[i].setAttribute('cx',x); cpDots[i].setAttribute('cy',y);
        cpDots[i].setAttribute('fill',p2.color);
        cpDots[i].setAttribute('opacity', String(0.4+0.6*Math.abs(Math.sin(t2*0.001+p2.phase))));
      });
      cpRAF = requestAnimationFrame(cpTick);
    }
    cpRAF = requestAnimationFrame(cpTick);
    activeRAFs.push(()=>cancelAnimationFrame(cpRAF));

    /* ── Animation: inflow comets (AI → incidents junction) ── */
    const inflowComets = [];
    let inflowLast = 0;
    const inflowInterval = Math.max(280, 1600/INTENSITY);
    let inflowRAF;
    function inflowTick(t2) {
      if (t2 - inflowLast > inflowInterval) {
        inflowLast = t2;
        inflowComets.push({ start:t2, dur:900+Math.random()*300,
          color:['#5eead4','#facc15','#fb923c','#f43f5e'][Math.floor(Math.random()*4)] });
      }
      const aliveI = inflowComets.filter(c2=>t2-c2.start<c2.dur);
      inflowComets.length=0; inflowComets.push(...aliveI);
      while(gInflow.firstChild) gInflow.removeChild(gInflow.firstChild);
      for(const c2 of inflowComets) {
        const pr=(t2-c2.start)/c2.dur;
        const x=aiX+aiR+(incidentsX-aiX-aiR)*pr, y=aiY;
        const fade=pr<0.1?pr/0.1:(pr>0.85?(1-pr)/0.15:1);
        const dot=mk('circle'); dot.setAttribute('cx',x); dot.setAttribute('cy',y);
        dot.setAttribute('r','2'); dot.setAttribute('fill',c2.color); dot.setAttribute('opacity',String(fade));
        gInflow.appendChild(dot);
      }
      inflowRAF = requestAnimationFrame(inflowTick);
    }
    inflowRAF = requestAnimationFrame(inflowTick);
    activeRAFs.push(()=>cancelAnimationFrame(inflowRAF));

    /* ── Animation: flow comets (branching paths) ── */
    const flowComets = [];
    let flowLast = 0;
    const flowInterval = Math.max(400, 1800/INTENSITY);
    let flowRAF;
    function flowTick(t2) {
      if (t2 - flowLast > flowInterval) {
        flowLast = t2;
        flowComets.push({ start:t2, dur:1900+Math.random()*400,
          path: Math.random()<0.78?'auto':'manual' });
      }
      const aliveF = flowComets.filter(c2=>t2-c2.start<c2.dur);
      flowComets.length=0; flowComets.push(...aliveF);
      while(gFlow.firstChild) gFlow.removeChild(gFlow.firstChild);
      for(const c2 of flowComets) {
        const pr=(t2-c2.start)/c2.dur;
        let x,y,color;
        if(c2.path==='auto') {
          if(pr<0.5) {
            const t3=pr*2,mt=1-t3;
            const[p0x,p0y]=[incidentsX,aiY],[p1x,p1y]=[splitX+30,aiY],[p2x,p2y]=[autoX-80,autoY],[p3x,p3y]=[autoX,autoY];
            x=mt*mt*mt*p0x+3*mt*mt*t3*p1x+3*mt*t3*t3*p2x+t3*t3*t3*p3x;
            y=mt*mt*mt*p0y+3*mt*mt*t3*p1y+3*mt*t3*t3*p2y+t3*t3*t3*p3y;
          } else {
            const t3=(pr-0.5)*2,mt=1-t3;
            const[p0x,p0y]=[autoX,autoY],[p1x,p1y]=[autoX+100,autoY],[p2x,p2y]=[resolvedX-100,resolvedY],[p3x,p3y]=[resolvedX,resolvedY];
            x=mt*mt*mt*p0x+3*mt*mt*t3*p1x+3*mt*t3*t3*p2x+t3*t3*t3*p3x;
            y=mt*mt*mt*p0y+3*mt*mt*t3*p1y+3*mt*t3*t3*p2y+t3*t3*t3*p3y;
          }
          color='#5eead4';
        } else {
          if(pr<0.45) {
            const t3=pr/0.45,mt=1-t3;
            const[p0x,p0y]=[incidentsX,aiY],[p1x,p1y]=[splitX+30,aiY],[p2x,p2y]=[manualX-80,manualY],[p3x,p3y]=[manualX,manualY];
            x=mt*mt*mt*p0x+3*mt*mt*t3*p1x+3*mt*t3*t3*p2x+t3*t3*t3*p3x;
            y=mt*mt*mt*p0y+3*mt*mt*t3*p1y+3*mt*t3*t3*p2y+t3*t3*t3*p3y;
            color='#fb923c';
          } else if(pr<0.85) {
            const t3=(pr-0.45)/0.4,mt=1-t3;
            const[p0x,p0y]=[manualX,manualY],[p1x,p1y]=[manualX+80,manualY],[p2x,p2y]=[sevHubX-80,sevHubY],[p3x,p3y]=[sevHubX,sevHubY];
            x=mt*mt*mt*p0x+3*mt*mt*t3*p1x+3*mt*t3*t3*p2x+t3*t3*t3*p3x;
            y=mt*mt*mt*p0y+3*mt*mt*t3*p1y+3*mt*t3*t3*p2y+t3*t3*t3*p3y;
            color='#fb923c';
          } else {
            if(!c2.sev) c2.sev=SEVERITIES[Math.floor(Math.random()*SEVERITIES.length)];
            const t3=(pr-0.85)/0.15,mt=1-t3;
            const sx=sevHubX+70,sy=sevHubY+c2.sev.dy;
            const[p0x,p0y]=[sevHubX,sevHubY],[p1x,p1y]=[sevHubX+30,sevHubY],[p2x,p2y]=[sx-30,sy],[p3x,p3y]=[sx,sy];
            x=mt*mt*mt*p0x+3*mt*mt*t3*p1x+3*mt*t3*t3*p2x+t3*t3*t3*p3x;
            y=mt*mt*mt*p0y+3*mt*mt*t3*p1y+3*mt*t3*t3*p2y+t3*t3*t3*p3y;
            color=c2.sev.color;
          }
        }
        const fade=pr<0.05?pr/0.05:(pr>0.92?(1-pr)/0.08:1);
        const dot=mk('circle'); dot.setAttribute('cx',x); dot.setAttribute('cy',y);
        dot.setAttribute('r','2.4'); dot.setAttribute('fill',color); dot.setAttribute('opacity',String(fade));
        gFlow.appendChild(dot);
      }
      flowRAF = requestAnimationFrame(flowTick);
    }
    flowRAF = requestAnimationFrame(flowTick);
    activeRAFs.push(()=>cancelAnimationFrame(flowRAF));
  }

  function rebuild() {
    activeRAFs.forEach(fn=>fn()); activeRAFs=[];
    const w=wrap.offsetWidth, h=wrap.offsetHeight;
    if(!w||!h) return;
    computeLayout(w,h);
    buildSVG(w,h);
  }

  let resizeTimer2;
  const ro2 = new ResizeObserver(()=>{ clearTimeout(resizeTimer2); resizeTimer2=setTimeout(rebuild,80); });
  ro2.observe(wrap);
  setTimeout(rebuild, 0);

  /* footer */
  const footer = document.createElement('div');
  footer.style.cssText = 'padding:0.75rem 1.5rem;border-top:1px solid var(--border);background:rgba(0,0,0,.1);display:flex;gap:1.5rem;flex-wrap:wrap;justify-content:center;';
  footer.innerHTML = `
    <div class="flex gap-2 items-center text-xs text-muted"><div style="width:8px;height:8px;border-radius:50%;background:var(--teal);"></div>127 Incidents (2,742 alerts → 95.3% reduced)</div>
    <div class="flex gap-2 items-center text-xs text-muted"><div style="width:8px;height:8px;border-radius:50%;background:var(--teal);opacity:.5;"></div>97 Auto-resolved</div>
    <div class="flex gap-2 items-center text-xs text-muted"><div style="width:8px;height:8px;border-radius:50%;background:#fb923c;opacity:.7;"></div>30 Manual review</div>
    <div class="flex gap-2 items-center text-xs text-muted" style="border:1px dashed rgba(94,234,212,.4);border-radius:4px;padding:2px 8px;">20 HITL-eligible (AI playbooks)</div>`;
  container.appendChild(footer);
}

/* ══════════════════════════════════════════
   Live Alert Counter — updates #stat-alerts
   after initial animateCount settles.
   ~9/min growth + sine jitter (setInterval
   so it works in background tabs).
   ══════════════════════════════════════════ */
function startLiveAlertCounter() {
  const el = document.getElementById('stat-alerts');
  if (!el) return;
  const startVal = 2742, startT = Date.now();
  const ratePerMin = 9;
  setTimeout(() => {
    setInterval(() => {
      const elapsedMin = (Date.now() - startT) / 60000;
      const val = Math.floor(startVal + elapsedMin * ratePerMin + Math.sin(Date.now() / 3000) * 1.2);
      el.textContent = val.toLocaleString();
    }, 800);
  }, 2000);
}

/* ══════════════════════════════════════════
   Lower Grid — Incident Queue, Rules Feed,
   Threat Actor Panel
   ══════════════════════════════════════════ */
function buildLowerGrid() {
  const SEV_COLOR = { critical:'var(--critical)', high:'var(--high)', medium:'var(--medium)', low:'var(--low)' };
  const SEV_LABEL = { critical:'CRIT', high:'HIGH', medium:'MED',  low:'LOW'  };

  /* ── Incident Queue ── */
  const qList = document.getElementById('incident-queue-list');
  if (qList && typeof ALERTS !== 'undefined') {
    qList.innerHTML = ALERTS.slice(0,8).map(a => {
      const col = SEV_COLOR[a.severity] || 'var(--text-muted)';
      const lbl = SEV_LABEL[a.severity] || '?';
      return `<div class="incident-row" onclick="showIncidentModal(${a.id})" style="display:flex;align-items:center;gap:10px;padding:8px 4px;border-bottom:1px solid var(--border);cursor:pointer;" onmouseenter="this.style.background='var(--bg-elevated)'" onmouseleave="this.style.background=''">
        <span style="flex-shrink:0;width:36px;height:20px;display:inline-flex;align-items:center;justify-content:center;border-radius:4px;background:${col}22;color:${col};font-size:9px;font-weight:700;letter-spacing:.06em;">${lbl}</span>
        <div style="flex:1;min-width:0;">
          <div style="font-size:12px;font-weight:600;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${SENTINEL._escHtml(a.title)}</div>
          <div style="font-size:10px;color:var(--text-muted);margin-top:1px;">${SENTINEL._escHtml(a.source)} · ${a.tactic}</div>
        </div>
        <div style="flex-shrink:0;text-align:right;">
          <div style="font-size:10px;font-family:var(--font-mono);color:${col};">${a.conf}%</div>
          <div style="font-size:9px;color:var(--text-muted);">${a.ts}</div>
        </div>
        <span style="flex-shrink:0;color:var(--text-dim);font-size:12px;">›</span>
      </div>`;
    }).join('');
  }

  /* ── Rules Feed ── */
  const rList = document.getElementById('rules-feed-list');
  if (rList && typeof RULES !== 'undefined') {
    rList.innerHTML = RULES.map(r => `
      <div style="display:flex;align-items:flex-start;gap:8px;padding:8px 4px;border-bottom:1px solid var(--border);">
        <div style="flex-shrink:0;width:8px;height:8px;border-radius:50%;margin-top:4px;background:${r.fired ? 'var(--critical)' : 'var(--text-dim)'};${r.fired ? 'box-shadow:0 0 6px var(--critical)' : ''}"></div>
        <div style="flex:1;min-width:0;">
          <div style="font-size:11px;color:var(--text-primary);font-weight:600;line-height:1.4;">${SENTINEL._escHtml(r.name)}</div>
          <div style="font-size:10px;color:${r.fired ? 'var(--critical)' : 'var(--text-muted)'};margin-top:2px;">${SENTINEL._escHtml(r.meta)}</div>
        </div>
      </div>`).join('');
  }

  /* ── Threat Actor Panel ── */
  const aList = document.getElementById('actor-panel-list');
  if (aList && typeof ACTORS !== 'undefined') {
    const actorColors = ['var(--critical)','var(--high)','var(--medium)'];
    aList.innerHTML = ACTORS.map((a,i) => `
      <div style="padding:10px 4px;border-bottom:1px solid var(--border);">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px;">
          <span style="flex-shrink:0;width:32px;height:32px;border-radius:8px;background:${actorColors[i]}22;color:${actorColors[i]};font-size:11px;font-weight:700;display:inline-flex;align-items:center;justify-content:center;font-family:var(--font-mono);">${SENTINEL._escHtml(a.code)}</span>
          <div>
            <div style="font-size:11px;font-weight:700;color:${actorColors[i]};font-family:var(--font-mono);">${SENTINEL._escHtml(a.name)}</div>
            <div style="font-size:9px;color:var(--text-muted);margin-top:2px;">${SENTINEL._escHtml(a.tags)}</div>
          </div>
        </div>
      </div>`).join('');
  }
}

/* ══════════════════════════════════════════
   Sparklines (data inventory)
   ══════════════════════════════════════════ */
function buildSparklines() {
  document.querySelectorAll('.sparkline').forEach(el => {
    const pts = Array.from({ length: 14 }, () => 15 + Math.random() * 55);
    const W = 44; const H = 18;
    const max = Math.max(...pts); const min = Math.min(...pts);
    const rng = max - min || 1;
    const coords = pts.map((v, i) => {
      const x = (i / (pts.length - 1)) * W;
      const y = H - ((v - min) / rng) * H;
      return `${x},${y}`;
    }).join(' ');
    el.innerHTML = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"
                        style="vertical-align:middle;margin-left:6px;">
      <polyline points="${coords}" fill="none" stroke="#00d4d8" stroke-width="1.5"
                stroke-linecap="round" stroke-linejoin="round" opacity="0.55"/>
    </svg>`;
  });
}

/* ══════════════════════════════════════════
   TweaksPanel — Instructor Controls
   Floating panel toggled by ⚙ button.
   Controls: name, intensity, volume,
   log rate, AI sensitivity, MITRE toggle,
   inject attack, replay.
   ══════════════════════════════════════════ */
const SENTINEL_TWEAKS = (function() {
  let open = false;
  const state = {
    intensity:    5,
    volume:      'med',
    logRate:      1.0,
    aiSens:       75,
    showMitre:    true,
  };

  function row(label, controlHtml) {
    return `<div style="display:flex;flex-direction:column;gap:5px;margin-bottom:10px;">
      <div style="display:flex;justify-content:space-between;font-size:11px;color:rgba(255,255,255,.55);">
        <span>${label}</span>
      </div>
      ${controlHtml}
    </div>`;
  }

  function rowH(label, controlHtml) {
    return `<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
      <span style="font-size:11px;color:rgba(255,255,255,.55);">${label}</span>
      ${controlHtml}
    </div>`;
  }

  function section(label) {
    return `<div style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:rgba(94,234,212,.6);padding:8px 0 2px;border-top:1px solid rgba(255,255,255,.06);margin-top:4px;">${label}</div>`;
  }

  function render() {
    const panel = document.getElementById('tweaks-panel');
    if (!panel) return;
    if (!open) { panel.style.display = 'none'; return; }
    panel.style.cssText = 'display:block;position:fixed;bottom:72px;right:20px;z-index:499;width:280px;max-height:calc(100vh - 100px);overflow-y:auto;background:rgba(7,10,15,.92);border:1px solid rgba(94,234,212,.25);border-radius:12px;padding:14px 16px;box-shadow:0 16px 48px rgba(0,0,0,.6);backdrop-filter:blur(20px);';
    panel.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">
        <div style="font-size:13px;font-weight:700;color:var(--text-primary);">⚙ Instructor Controls</div>
        <button onclick="SENTINEL_TWEAKS.toggle()" style="background:none;border:none;color:rgba(255,255,255,.4);cursor:pointer;font-size:14px;padding:0 2px;">✕</button>
      </div>

      ${section('Identity')}
      ${row('Student name', `<input id="twk-name" type="text" value="${SENTINEL._escHtml(SENTINEL.getStudentName()||'')}"
        style="width:100%;box-sizing:border-box;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);border-radius:6px;color:var(--text-primary);font-family:var(--font-ui);font-size:12px;padding:6px 8px;outline:none;"
        placeholder="Capt Best · Team Alpha">`)}

      ${section('Simulation')}
      ${row(`Animation intensity <span id="twk-intensity-val" style="color:var(--teal);">${state.intensity}</span>`, `<input id="twk-intensity" type="range" min="1" max="10" step="1" value="${state.intensity}"
        style="width:100%;accent-color:var(--teal);">`)}
      ${row('Alert volume', `<div style="display:flex;gap:6px;">
        ${['Low','Med','Storm'].map(v=>`<button class="twk-vol-btn" data-vol="${v.toLowerCase()}" style="flex:1;padding:5px 0;border-radius:6px;font-size:11px;cursor:pointer;border:1px solid ${state.volume===v.toLowerCase()?'var(--teal)':'rgba(255,255,255,.1)'};background:${state.volume===v.toLowerCase()?'rgba(94,234,212,.12)':'rgba(255,255,255,.04)'};color:${state.volume===v.toLowerCase()?'var(--teal)':'rgba(255,255,255,.5)'};">${v}</button>`).join('')}
      </div>`)}
      ${row(`Live log rate <span id="twk-lograte-val" style="color:var(--teal);">${state.logRate.toFixed(1)}×</span>`, `<input id="twk-lograte" type="range" min="3" max="30" step="1" value="${Math.round(state.logRate*10)}"
        style="width:100%;accent-color:var(--teal);">`)}
      ${row(`AI sensitivity <span id="twk-aisens-val" style="color:var(--teal);">${state.aiSens}%</span>`, `<input id="twk-aisens" type="range" min="20" max="99" step="1" value="${state.aiSens}"
        style="width:100%;accent-color:var(--teal);">`)}

      ${section('Display')}
      ${rowH('Show MITRE panel', `<button id="twk-mitre-toggle" style="width:40px;height:22px;border-radius:999px;border:none;cursor:pointer;position:relative;background:${state.showMitre?'var(--teal)':'rgba(255,255,255,.15)'};">
        <span style="position:absolute;top:3px;${state.showMitre?'right:3px':'left:3px'};width:16px;height:16px;border-radius:50%;background:#fff;transition:all .15s;"></span>
      </button>`)}

      ${section('Actions')}
      <button onclick="SENTINEL_TWEAKS.injectAttack()" style="width:100%;margin-bottom:8px;padding:8px;border-radius:7px;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);color:var(--critical);font-size:12px;font-weight:600;cursor:pointer;">⚡ Inject Random Attack</button>
      <button onclick="location.reload()" style="width:100%;padding:8px;border-radius:7px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);color:rgba(255,255,255,.6);font-size:12px;cursor:pointer;">↺ Replay Simulation</button>
    `;

    /* Wire up controls */
    const nameInput = panel.querySelector('#twk-name');
    if (nameInput) {
      nameInput.addEventListener('change', () => {
        const v = nameInput.value.trim();
        if (!v) return;
        SENTINEL.setStudentName(v);
        SENTINEL.renderShell();
      });
    }

    const intensitySlider = panel.querySelector('#twk-intensity');
    if (intensitySlider) {
      intensitySlider.addEventListener('input', () => {
        state.intensity = Number(intensitySlider.value);
        const lbl = panel.querySelector('#twk-intensity-val');
        if (lbl) lbl.textContent = state.intensity;
      });
    }

    const logRateSlider = panel.querySelector('#twk-lograte');
    if (logRateSlider) {
      logRateSlider.addEventListener('input', () => {
        state.logRate = Number(logRateSlider.value) / 10;
        const lbl = panel.querySelector('#twk-lograte-val');
        if (lbl) lbl.textContent = state.logRate.toFixed(1) + '×';
        if (typeof LIVE_LOG !== 'undefined') LIVE_LOG.setRate(state.logRate);
      });
    }

    const aiSensSlider = panel.querySelector('#twk-aisens');
    if (aiSensSlider) {
      aiSensSlider.addEventListener('input', () => {
        state.aiSens = Number(aiSensSlider.value);
        const lbl = panel.querySelector('#twk-aisens-val');
        if (lbl) lbl.textContent = state.aiSens + '%';
      });
    }

    panel.querySelectorAll('.twk-vol-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        state.volume = btn.dataset.vol;
        render();
      });
    });

    const mitreToggle = panel.querySelector('#twk-mitre-toggle');
    if (mitreToggle) {
      mitreToggle.addEventListener('click', () => {
        state.showMitre = !state.showMitre;
        const mitreCard = document.getElementById('mitre-chart')?.closest('.card');
        if (mitreCard) mitreCard.style.display = state.showMitre ? '' : 'none';
        render();
      });
    }
  }

  return {
    toggle() { open = !open; render(); },
    injectAttack() {
      if (typeof ALERTS === 'undefined' || !ALERTS.length) return;
      const a = ALERTS[Math.floor(Math.random() * ALERTS.length)];
      if (typeof showIncidentModal === 'function') showIncidentModal(a.id);
    },
    getState() { return { ...state }; },
  };
})();

document.addEventListener('DOMContentLoaded', initDashboard);
