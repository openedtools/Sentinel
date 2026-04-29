/* SENTINEL — Command Center Dashboard */

async function initDashboard() {
  const mitreData = await fetch('data/mitre.json').then(r => r.json());

  /* ── Animated stat counters ── */
  SENTINEL.animateCount(document.getElementById('stat-alerts'),    2742, 1800);
  SENTINEL.animateCount(document.getElementById('stat-incidents'),  130, 1400);
  SENTINEL.animateCount(document.getElementById('stat-resolved'),   103, 1200);
  SENTINEL.animateCount(document.getElementById('stat-open'),        27, 1000);
  SENTINEL.animateCount(document.getElementById('stat-automated'),   97, 1300);
  SENTINEL.animateCount(document.getElementById('stat-manual'),      33, 1100);
  SENTINEL.animateCount(document.getElementById('stat-automated-pct'), 75, 1500, '%');
  SENTINEL.animateCount(document.getElementById('stat-prevented'), 286000, 2000);

  /* ── MITRE ATT&CK bar chart ── */
  buildMitreChart(mitreData);

  /* ── Sankey flow diagram ── */
  buildSankey();

  /* ── Live log feed ── */
  LIVE_LOG.init(document.getElementById('log-feed'));

  /* ── Ingestion sparklines (simple SVG lines) ── */
  buildSparklines();
}

function buildMitreChart(mitreData) {
  const container = document.getElementById('mitre-chart');
  if (!container) return;

  const counts = mitreData.dayThreeCounts;
  const max = Math.max(...Object.values(counts));

  let html = '';
  for (const [tactic, count] of Object.entries(counts)) {
    if (count === 0) continue;
    const pct = (count / max) * 100;
    const tacticInfo = mitreData.tactics.find(t => t.name === tactic);
    const color = tacticInfo ? tacticInfo.color : '#6b7280';
    html += `
      <div class="mitre-row mt-1">
        <span class="mitre-tactic-name truncate">${tactic}</span>
        <div class="mitre-bar-wrap">
          <div class="mitre-bar-fill" style="width:0%;background:${color}" data-target="${pct}"></div>
        </div>
        <span class="mitre-count">${count}</span>
      </div>`;
  }
  container.innerHTML = html;

  /* Animate bars after render */
  setTimeout(() => {
    container.querySelectorAll('.mitre-bar-fill').forEach(bar => {
      bar.style.transition = 'width 1.2s ease';
      bar.style.width = bar.dataset.target + '%';
    });
  }, 200);
}

function buildSankey() {
  const svg = document.getElementById('sankey-svg');
  if (!svg) return;

  const W = svg.clientWidth || 600;
  const H = svg.clientHeight || 300;

  /* Define nodes */
  const nodes = [
    { id: 'sources',   label: '78 Data Sources',   x: W*0.05, y: H*0.45, w: 14 },
    { id: 'alerts',    label: '2,742 Alerts',       x: W*0.28, y: H*0.45, w: 14 },
    { id: 'ai',        label: 'AI Filter',           x: W*0.50, y: H*0.45, w: 14 },
    { id: 'incidents', label: '130 Incidents',       x: W*0.70, y: H*0.45, w: 14 },
    { id: 'auto',      label: '97 Automated',        x: W*0.88, y: H*0.25, w: 10 },
    { id: 'manual',    label: '33 Manual',           x: W*0.88, y: H*0.65, w: 10 },
    { id: 'resolved',  label: '103 Resolved',        x: W*0.95, y: H*0.20, w: 8  },
    { id: 'open',      label: '27 Open',             x: W*0.95, y: H*0.70, w: 8  }
  ];

  /* Draw curved flow paths */
  const paths = [
    { from: 'sources',   to: 'alerts',    color: '#00d4d8', opacity: 0.6, width: 12 },
    { from: 'alerts',    to: 'ai',        color: '#00d4d8', opacity: 0.5, width: 10 },
    { from: 'ai',        to: 'incidents', color: '#00d4d8', opacity: 0.6, width: 6  },
    { from: 'incidents', to: 'auto',      color: '#22c55e', opacity: 0.5, width: 5  },
    { from: 'incidents', to: 'manual',    color: '#f59e0b', opacity: 0.5, width: 3  },
    { from: 'auto',      to: 'resolved',  color: '#22c55e', opacity: 0.4, width: 4  },
    { from: 'manual',    to: 'resolved',  color: '#22c55e', opacity: 0.4, width: 2  },
    { from: 'manual',    to: 'open',      color: '#ef4444', opacity: 0.4, width: 2  }
  ];

  let svgContent = '';

  /* Paths */
  paths.forEach(p => {
    const fromNode = nodes.find(n => n.id === p.from);
    const toNode   = nodes.find(n => n.id === p.to);
    if (!fromNode || !toNode) return;

    const x1 = fromNode.x + fromNode.w/2;
    const y1 = fromNode.y;
    const x2 = toNode.x - toNode.w/2;
    const y2 = toNode.y;
    const cx = (x1 + x2) / 2;

    svgContent += `<path d="M${x1},${y1} C${cx},${y1} ${cx},${y2} ${x2},${y2}"
      fill="none" stroke="${p.color}" stroke-width="${p.width}"
      stroke-opacity="${p.opacity}" stroke-linecap="round"/>`;
  });

  /* Nodes */
  nodes.forEach(n => {
    const labelBelow = n.id === 'sources' || n.id === 'alerts' || n.id === 'incidents';
    const labelY = labelBelow ? n.y + 18 : n.y - 10;
    const color = ['resolved','auto'].includes(n.id) ? '#22c55e' : ['open','manual'].includes(n.id) ? '#f97316' : '#00d4d8';

    svgContent += `
      <circle cx="${n.x}" cy="${n.y}" r="${n.w/2 + 4}" fill="${color}" fill-opacity="0.15" stroke="${color}" stroke-width="1.5"/>
      <text x="${n.x}" y="${labelY}" text-anchor="middle" fill="${color}" font-size="10" font-weight="600">${n.label}</text>`;
  });

  /* Filter annotation */
  svgContent += `
    <rect x="${W*0.45}" y="${H*0.05}" width="${W*0.12}" height="24" rx="4"
      fill="rgba(0,212,216,0.1)" stroke="rgba(0,212,216,0.4)" stroke-width="1"/>
    <text x="${W*0.51}" y="${H*0.05+16}" text-anchor="middle" fill="#00d4d8" font-size="9" font-weight="700">
      95% noise reduced
    </text>`;

  svg.innerHTML = svgContent;
}

function buildSparklines() {
  document.querySelectorAll('.sparkline').forEach(canvas => {
    const points = Array.from({length: 12}, () => 20 + Math.random() * 60);
    const w = 60; const h = 24;
    const max = Math.max(...points);
    const min = Math.min(...points);
    const range = max - min || 1;
    const pts = points.map((v, i) => {
      const x = (i / (points.length - 1)) * w;
      const y = h - ((v - min) / range) * h;
      return `${x},${y}`;
    }).join(' ');
    canvas.innerHTML = `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">
      <polyline points="${pts}" fill="none" stroke="#00d4d8" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
  });
}

document.addEventListener('DOMContentLoaded', initDashboard);
