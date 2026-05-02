/* SENTINEL — Compliance Control Mapper
   3 regulatory scenarios (HIPAA, PCI-DSS, NIST 800-53); students click to map
   security controls to framework requirements, then answer a concept quiz. */
'use strict';

/* ── State ── */
let currentScenario = 0;
let scenarioScores  = [null, null, null]; // null = not yet completed
let totalScore      = 0;
let startTime       = null;
let selectedControl = null;              // id of currently selected control card
let mappingState    = [{}, {}, {}];      // { reqId: controlId } per scenario

/* ── Scenario metadata (right panel list) ── */
const COMP_SCENARIOS = [
  { id: 1, title: 'HIPAA Healthcare',      icon: '🏥', pts: 33 },
  { id: 2, title: 'PCI-DSS Payments',      icon: '💳', pts: 33 },
  { id: 3, title: 'NIST 800-53 Federal',   icon: '🏛', pts: 33 },
];

/* ── Full scenario data ── */
const SCENARIOS = [

  /* ── Scenario 1: HIPAA ── */
  {
    id: 'hipaa',
    title: 'HIPAA Healthcare',
    icon: '🏥',
    points: 33,
    analogy: {
      title: 'Your Role',
      body: `You manage IT security for <strong style="color:var(--text-primary);">City General Hospital</strong>.
      HIPAA (Health Insurance Portability and Accountability Act) is the federal law requiring hospitals to
      protect patient health information — called <em>PHI</em>. Think of HIPAA like the hospital's rulebook
      for patient privacy. Every control you assign today protects a real patient's medical record.`,
    },
    requirements: [
      { id: 'access',       label: 'Access Controls',       desc: 'Limit who can view patient data' },
      { id: 'audit',        label: 'Audit Controls',        desc: 'Record who accessed what, and when' },
      { id: 'integrity',    label: 'Integrity Controls',    desc: 'Prevent unauthorized modification of records' },
      { id: 'transmission', label: 'Transmission Security', desc: 'Protect data moving across networks' },
    ],
    controls: [
      {
        id: 'rbac', label: 'Role-Based Access Control (RBAC)', mapsTo: 'access',
        explanation: 'RBAC enforces that only staff with the right job role can open a patient record — a nurse sees only their assigned patients, not those in another ward. This directly satisfies the Access Controls requirement.',
      },
      {
        id: 'audit_log', label: 'Audit Logging System', mapsTo: 'audit',
        explanation: 'Audit logs create a timestamped record of every access event — who opened which record, when, and from which workstation. This is the technical foundation of the Audit Controls requirement.',
      },
      {
        id: 'digsig', label: 'Digital Signatures on Records', mapsTo: 'integrity',
        explanation: 'A digital signature creates a cryptographic fingerprint of a record. If anyone modifies it later, the signature breaks — proving tampering occurred. This directly satisfies Integrity Controls.',
      },
      {
        id: 'tls', label: 'TLS Encryption', mapsTo: 'transmission',
        explanation: 'TLS encrypts data in transit between a browser and a server, or between hospital systems. Anyone who intercepts the traffic sees only ciphertext. This is the definition of Transmission Security.',
      },
      {
        id: 'ids', label: 'Intrusion Detection System (IDS)', mapsTo: null,
        explanation: null,
      },
      {
        id: 'awareness', label: 'Security Awareness Training', mapsTo: null,
        explanation: null,
      },
    ],
    quiz: {
      q: 'Under HIPAA, a nurse tries to open a patient\'s record but the system denies access. Which HIPAA control type enforced that decision?',
      opts: [
        { val: 'A', text: 'Transmission Security' },
        { val: 'B', text: 'Access Controls' },
        { val: 'C', text: 'Audit Controls' },
        { val: 'D', text: 'Integrity Controls' },
      ],
      correct: 'B',
      explain: 'The system blocked the nurse <em>before</em> any data was touched — the decision about who is allowed to see what is <strong>Access Controls</strong>. Transmission Security protects data in transit; Audit Controls record what happened; Integrity Controls detect if a record was modified.',
    },
  },

  /* ── Scenario 2: PCI-DSS ── */
  {
    id: 'pcidss',
    title: 'PCI-DSS Payments',
    icon: '💳',
    points: 33,
    analogy: {
      title: 'Your Role',
      body: `You secure the payment systems for a retail chain with 200 stores.
      <strong style="color:var(--text-primary);">PCI-DSS</strong> (Payment Card Industry Data Security Standard)
      is the set of rules that Visa, Mastercard, and other card brands require any business that processes
      payments to follow. Think of it like the card networks' contract: if you want to accept cards,
      you protect cardholder data their way.`,
    },
    requirements: [
      { id: 'stored',   label: 'Protect Stored Cardholder Data',     desc: 'Secure card numbers and sensitive data at rest' },
      { id: 'vuln',     label: 'Maintain Vulnerability Management',  desc: 'Keep systems patched and malware-free' },
      { id: 'access',   label: 'Implement Strong Access Controls',   desc: 'Restrict who can access cardholder data systems' },
      { id: 'monitor',  label: 'Regularly Monitor & Test Networks',  desc: 'Log activity and run security tests continuously' },
    ],
    controls: [
      {
        id: 'db_enc', label: 'Database Encryption', mapsTo: 'stored',
        explanation: 'Encrypting the payment database means that even if an attacker steals the file, the card numbers are unreadable without the encryption key. This is the core of the Protect Stored Cardholder Data requirement.',
      },
      {
        id: 'av_patch', label: 'Antivirus + Patch Management', mapsTo: 'vuln',
        explanation: 'Keeping antivirus signatures current and applying OS/application patches closes known vulnerabilities before attackers can exploit them. This satisfies Maintain Vulnerability Management.',
      },
      {
        id: 'mfa', label: 'Multi-Factor Authentication (MFA)', mapsTo: 'access',
        explanation: 'MFA requires a second proof of identity beyond a password before allowing access to payment systems. A stolen password alone is not enough to get in. This implements Strong Access Controls.',
      },
      {
        id: 'nids', label: 'Network IDS + Log Review', mapsTo: 'monitor',
        explanation: 'A network intrusion detection system flags anomalous traffic in real time, while log review catches patterns over time. Together they satisfy the Regularly Monitor and Test Networks requirement.',
      },
      {
        id: 'training2', label: 'Security Awareness Training', mapsTo: null,
        explanation: null,
      },
      {
        id: 'badge', label: 'Physical Access Badges', mapsTo: null,
        explanation: null,
      },
    ],
    quiz: {
      q: 'A retail store uses point-to-point encryption (P2PE) so that card data is encrypted from the moment a card is swiped until it reaches the payment processor. Which PCI-DSS requirement does this primarily satisfy?',
      opts: [
        { val: 'A', text: 'Maintain Vulnerability Management' },
        { val: 'B', text: 'Implement Strong Access Controls' },
        { val: 'C', text: 'Protect Stored Cardholder Data' },
        { val: 'D', text: 'Regularly Monitor & Test Networks' },
      ],
      correct: 'C',
      explain: 'P2PE ensures cardholder data is encrypted before it is ever stored or transmitted, protecting it at rest and in motion. This directly satisfies <strong>Protect Stored Cardholder Data</strong>. Vulnerability Management is about patching; Access Controls govern who can reach the system; Monitoring is about detection.',
    },
  },

  /* ── Scenario 3: NIST 800-53 ── */
  {
    id: 'nist',
    title: 'NIST 800-53 Federal',
    icon: '🏛',
    points: 33,
    analogy: {
      title: 'Your Role',
      body: `Your company just won a federal government contract to build a cloud platform for a U.S. agency.
      <strong style="color:var(--text-primary);">NIST 800-53</strong> is the catalog of security controls
      every federal information system — and their contractors — must implement. Think of it as the government's
      master checklist. Your security team must map your controls to NIST's control families before the
      authorization to operate (ATO) is granted.`,
    },
    requirements: [
      { id: 'ac', label: 'Access Control (AC)',                       desc: 'Govern who can access systems and data' },
      { id: 'ir', label: 'Incident Response (IR)',                    desc: 'Plan and practice how to handle security events' },
      { id: 'sc', label: 'System & Communications Protection (SC)',   desc: 'Secure network boundaries and data flows' },
      { id: 'au', label: 'Audit & Accountability (AU)',               desc: 'Log and track all system activity' },
    ],
    controls: [
      {
        id: 'least_priv', label: 'Least Privilege Policy', mapsTo: 'ac',
        explanation: 'Least privilege means users and processes get only the permissions they need — nothing more. This limits blast radius when an account is compromised. It is a foundational NIST AC (Access Control) family control.',
      },
      {
        id: 'ir_plan', label: 'Incident Response Plan + Drills', mapsTo: 'ir',
        explanation: 'An IR plan documents who does what when a breach occurs. Quarterly drills test that the team can execute it. NIST IR controls require both a documented plan and evidence of regular practice.',
      },
      {
        id: 'netseg', label: 'Network Segmentation & Firewalls', mapsTo: 'sc',
        explanation: 'Segmenting the network with firewalls restricts which systems can talk to each other, limiting lateral movement by attackers. This directly implements NIST SC (System & Communications Protection) controls.',
      },
      {
        id: 'siem', label: 'Centralized SIEM / Log Aggregation', mapsTo: 'au',
        explanation: 'A SIEM collects, correlates, and stores logs from all systems in one place. NIST AU (Audit & Accountability) controls require that audit records be generated, protected, and reviewed — exactly what a SIEM provides.',
      },
      {
        id: 'pwpol', label: 'Password Complexity Policy', mapsTo: null,
        explanation: null,
      },
      {
        id: 'dlp', label: 'Data Loss Prevention (DLP)', mapsTo: null,
        explanation: null,
      },
    ],
    quiz: {
      q: 'A federal agency requires all contractors to document their breach notification procedure and run a tabletop exercise quarterly. This falls under which NIST 800-53 control family?',
      opts: [
        { val: 'A', text: 'Access Control (AC)' },
        { val: 'B', text: 'Audit & Accountability (AU)' },
        { val: 'C', text: 'System & Communications Protection (SC)' },
        { val: 'D', text: 'Incident Response (IR)' },
      ],
      correct: 'D',
      explain: 'Breach notification procedures and tabletop exercises are Incident Response (IR) activities. The IR control family requires agencies and contractors to have a plan, test it, and update it. AC governs access; AU governs logging; SC governs network protection.',
    },
  },
];

/* ── Key concepts for right panel (one per scenario) ── */
const KEY_CONCEPTS = [
  {
    heading: 'HIPAA Safeguards',
    body: 'HIPAA requires three types of safeguards: <strong>Administrative</strong> (policies, training), <strong>Physical</strong> (door locks, workstation controls), and <strong>Technical</strong> (the four controls in this scenario). All three must be addressed.',
  },
  {
    heading: 'PCI-DSS Merchant Levels',
    body: 'PCI-DSS compliance level (1–4) depends on annual card transaction volume. Level 1 merchants (>6M transactions/year) require an on-site QSA audit. Lower levels allow self-assessment questionnaires (SAQ).',
  },
  {
    heading: 'NIST 800-53 Control Families',
    body: 'NIST 800-53 organizes hundreds of controls into 20 families. The four in this scenario — AC, IR, SC, AU — are among the most frequently tested on Security+. Federal systems choose a baseline (Low, Moderate, High) that determines which controls apply.',
  },
];

/* ── Entry point ── */
function initCompliance() {
  startTime = Date.now();
  SENTINEL.renderShell();
  updateProgressBar();
  renderScenario(0);
  updateRightPanel();
}

/* ── Scenario router ── */
function renderScenario(idx) {
  currentScenario = idx;
  selectedControl = null;

  const main = document.getElementById('compliance-main');
  if (!main) return;
  main.innerHTML = '';
  window.scrollTo({ top: 0, behavior: 'smooth' });

  if (idx === 3) {
    renderDebrief();
    return;
  }

  const sc = SCENARIOS[idx];

  /* Shuffle controls so replay order varies */
  const shuffled = [...sc.controls].sort(() => Math.random() - 0.5);

  const controlCards = shuffled.map(c => {
    const isAssigned = !!mappingState[idx][
      sc.requirements.find(r => r.id === c.mapsTo)?.id
    ];
    const assigned = isAssigned ? ' assigned' : '';
    return `<button class="comp-control-card${assigned}" id="ctrl-${c.id}"
      onclick="selectControl('${c.id}', ${idx})">${c.label}</button>`;
  }).join('');

  const reqSlots = sc.requirements.map(r => {
    const assignedCtrlId = mappingState[idx][r.id];
    if (assignedCtrlId) {
      const ctrl = sc.controls.find(c => c.id === assignedCtrlId);
      return `<div class="comp-req-slot filled" id="slot-${r.id}">
        <div class="comp-req-slot-label">${r.label}</div>
        <div class="comp-req-slot-desc">${r.desc}</div>
        <div class="comp-req-slot-assigned">✓ ${ctrl.label}</div>
        <div class="comp-mapping-explanation">${ctrl.explanation}</div>
      </div>`;
    }
    return `<div class="comp-req-slot" id="slot-${r.id}"
      onclick="assignControl('${r.id}', ${idx})">
      <div class="comp-req-slot-label">${r.label}</div>
      <div class="comp-req-slot-desc">${r.desc}</div>
    </div>`;
  }).join('');

  /* Quiz */
  const { q, opts, correct } = sc.quiz;
  const optBtns = opts.map(o =>
    `<button class="quiz-option btn" data-val="${o.val}"
       onclick="submitScenarioQuiz(${idx}, '${o.val}', '${correct}')">
       <strong style="font-family:var(--font-mono);margin-right:8px;">${o.val}.</strong>${o.val === correct ? o.text : o.text}
     </button>`
  ).join('');

  const allMapped = sc.requirements.every(r => !!mappingState[idx][r.id]);
  const quizDisplay = allMapped ? 'block' : 'none';
  const nextLabel = idx < 2 ? 'Next Scenario →' : 'View Results →';
  const quizAnswered = scenarioScores[idx] !== null;

  main.innerHTML = `
    <div class="card mb-4 animate-fade-in">
      <div class="card-header" style="align-items:flex-start;gap:10px;">
        <div style="display:flex;align-items:center;gap:10px;flex:1;">
          <span style="font-size:1.4rem;">${sc.icon}</span>
          <div>
            <div style="font-size:0.9375rem;font-weight:700;color:var(--text-primary);">
              Scenario ${idx + 1} of 3 — ${sc.title}
            </div>
            <div style="font-size:0.75rem;color:var(--text-muted);">Compliance Control Mapper · ${sc.points} pts</div>
          </div>
        </div>
        <span class="badge badge-medium" style="flex-shrink:0;">Domain 5</span>
      </div>

      <!-- Analogy hook -->
      <div class="comp-analogy">
        <div class="text-xs" style="color:#818cf8;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px;">
          ${sc.analogy.title}
        </div>
        <div class="text-sm" style="line-height:1.7;">${sc.analogy.body}</div>
      </div>

      <!-- Instructions -->
      <div class="text-xs text-muted mb-2" style="line-height:1.6;">
        <strong style="color:var(--text-primary);">How to play:</strong>
        Click a <strong style="color:var(--text-primary);">control</strong> on the left to select it (it will glow teal),
        then click the <strong style="color:var(--text-primary);">requirement</strong> on the right it satisfies to assign it.
        Two controls are distractors — they won't fit any requirement.
      </div>

      <!-- Selection hint -->
      <div id="comp-hint-${idx}" class="comp-selection-hint" style="opacity:0;">
        ← Select a control first
      </div>

      <!-- Mapping area -->
      <div class="comp-mapping-area">
        <div>
          <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">
            🔧 Controls Pool
          </div>
          <div class="comp-controls-pool">${controlCards}</div>
        </div>
        <div>
          <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">
            📑 Framework Requirements
          </div>
          <div class="comp-req-grid">${reqSlots}</div>
        </div>
      </div>

      <!-- Quiz (hidden until all slots filled) -->
      <div id="comp-quiz-${idx}" style="display:${quizDisplay};border-top:1px solid var(--line);padding-top:1.25rem;margin-top:0.5rem;">
        <div class="text-xs text-muted mb-3" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">
          Concept Check — 8 pts
        </div>
        <div class="text-sm" style="font-weight:600;color:var(--text-primary);margin-bottom:12px;">${q}</div>
        <div style="display:grid;gap:8px;">${optBtns}</div>
        <div id="comp-quiz-feedback-${idx}" style="display:none;margin-top:12px;"></div>
      </div>

      <div style="margin-top:1rem;">
        <button id="comp-next-btn-${idx}" class="btn btn-primary" style="display:${quizAnswered ? 'inline-flex' : 'none'};"
          onclick="renderScenario(${idx + 1})">
          ${nextLabel}
        </button>
      </div>
    </div>`;

  updateRightPanel();
}

/* ── Select a control card ── */
function selectControl(controlId, scenarioIdx) {
  const sc = SCENARIOS[scenarioIdx];

  /* Don't allow selecting an already-assigned control */
  const ctrl = sc.controls.find(c => c.id === controlId);
  if (!ctrl) return;
  const alreadyAssigned = sc.requirements.some(r => mappingState[scenarioIdx][r.id] === controlId);
  if (alreadyAssigned) return;

  /* Deselect previous */
  if (selectedControl) {
    const prevCard = document.getElementById('ctrl-' + selectedControl);
    if (prevCard) prevCard.classList.remove('selected');
  }

  /* Toggle: clicking the same card again deselects it */
  if (selectedControl === controlId) {
    selectedControl = null;
    const hint = document.getElementById('comp-hint-' + scenarioIdx);
    if (hint) { hint.style.opacity = '0'; hint.textContent = '← Select a control first'; }
    return;
  }

  selectedControl = controlId;
  const card = document.getElementById('ctrl-' + controlId);
  if (card) card.classList.add('selected');

  const hint = document.getElementById('comp-hint-' + scenarioIdx);
  if (hint) {
    hint.style.opacity = '1';
    hint.textContent = `"${ctrl.label}" selected — now click a requirement box to assign it`;
  }
}

/* ── Attempt to assign selected control to a requirement slot ── */
function assignControl(reqId, scenarioIdx) {
  if (!selectedControl) {
    SENTINEL.toast('Select a control card first', 'info', 2000);
    return;
  }

  const sc = SCENARIOS[scenarioIdx];
  const ctrl = sc.controls.find(c => c.id === selectedControl);
  const req  = sc.requirements.find(r => r.id === reqId);
  if (!ctrl || !req) return;

  if (ctrl.mapsTo === reqId) {
    /* ── Correct match ── */
    mappingState[scenarioIdx][reqId] = selectedControl;

    /* Update the slot to filled state */
    const slot = document.getElementById('slot-' + reqId);
    if (slot) {
      slot.className = 'comp-req-slot filled';
      slot.removeAttribute('onclick');
      slot.innerHTML = `
        <div class="comp-req-slot-label">${req.label}</div>
        <div class="comp-req-slot-desc">${req.desc}</div>
        <div class="comp-req-slot-assigned">✓ ${ctrl.label}</div>
        <div class="comp-mapping-explanation">${ctrl.explanation}</div>`;
    }

    /* Gray out the control card */
    const card = document.getElementById('ctrl-' + selectedControl);
    if (card) { card.classList.remove('selected'); card.classList.add('assigned'); }

    /* Clear selection state */
    selectedControl = null;
    const hint = document.getElementById('comp-hint-' + scenarioIdx);
    if (hint) { hint.style.opacity = '0'; }

    checkAllMapped(scenarioIdx);

  } else {
    /* ── Wrong match ── */
    const slot = document.getElementById('slot-' + reqId);
    if (slot) {
      slot.classList.add('comp-shake');
      slot.addEventListener('animationend', () => slot.classList.remove('comp-shake'), { once: true });
    }

    const card = document.getElementById('ctrl-' + selectedControl);
    if (card) card.classList.remove('selected');

    selectedControl = null;
    const hint = document.getElementById('comp-hint-' + scenarioIdx);
    if (hint) { hint.style.opacity = '0'; hint.textContent = '← Select a control first'; }

    const msg = ctrl.mapsTo === null
      ? `"${ctrl.label}" is a distractor — it doesn't map to any HIPAA/PCI-DSS/NIST requirement here. Try another control.`
      : `"${ctrl.label}" doesn't satisfy "${req.label}" — try a different pairing.`;
    SENTINEL.toast(msg, 'info', 3000);
  }
}

/* ── Check if all requirements are filled → unlock quiz ── */
function checkAllMapped(scenarioIdx) {
  const sc = SCENARIOS[scenarioIdx];
  const allFilled = sc.requirements.every(r => !!mappingState[scenarioIdx][r.id]);
  if (!allFilled) return;

  /* Award mapping base points (once only) */
  if (scenarioScores[scenarioIdx] === null) {
    const basePts = sc.points - 8; // 25 pts (or 25 for all scenarios)
    totalScore += basePts;
    SENTINEL.updateScore(basePts);
    /* Don't finalize scenarioScores yet — wait for quiz */
  }

  const quiz = document.getElementById('comp-quiz-' + scenarioIdx);
  if (quiz) {
    quiz.style.display = 'block';
    quiz.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  updateRightPanel();
}

/* ── Quiz submission ── */
function submitScenarioQuiz(scenarioIdx, selected, correct) {
  const isCorrect = selected === correct;
  const quizPts   = isCorrect ? 8 : 0;

  if (scenarioScores[scenarioIdx] === null) {
    const basePts = SCENARIOS[scenarioIdx].points - 8;
    scenarioScores[scenarioIdx] = basePts + quizPts;
    totalScore += quizPts;
    if (quizPts > 0) SENTINEL.updateScore(quizPts);
  }

  updateProgressBar();
  updateRightPanel();

  /* Highlight options */
  document.querySelectorAll(`#comp-quiz-${scenarioIdx} .quiz-option`).forEach(btn => {
    btn.disabled = true;
    const v = btn.dataset.val;
    if (v === correct)               { btn.style.borderColor = 'var(--ok)';       btn.style.background = 'rgba(74,222,128,.08)'; }
    if (v === selected && !isCorrect){ btn.style.borderColor = 'var(--critical)'; btn.style.background = 'rgba(244,63,94,.08)'; }
  });

  const sc = SCENARIOS[scenarioIdx];
  const fb = document.getElementById('comp-quiz-feedback-' + scenarioIdx);
  if (fb) {
    fb.style.display = 'block';
    fb.innerHTML = (isCorrect
      ? `<div class="badge badge-ok" style="font-size:12px;padding:6px 12px;margin-bottom:8px;">✓ Correct! +8 pts</div>`
      : `<div class="badge badge-critical" style="font-size:12px;padding:6px 12px;margin-bottom:8px;">✗ Incorrect — correct answer highlighted above.</div>`) +
      `<div style="background:var(--bg-primary);border-radius:6px;padding:10px 12px;font-size:12px;color:var(--text-muted);line-height:1.6;border-left:3px solid var(--teal);">
        <strong style="color:var(--teal);">Explanation:</strong> ${sc.quiz.explain}
      </div>`;
  }

  const nextBtn = document.getElementById('comp-next-btn-' + scenarioIdx);
  if (nextBtn) nextBtn.style.display = 'inline-flex';
}

/* ── Progress bar ── */
function updateProgressBar() {
  const done  = scenarioScores.filter(s => s !== null).length;
  const fill  = document.getElementById('comp-progress-fill');
  const label = document.getElementById('comp-progress-label');
  if (fill)  fill.style.width  = `${(done / 3) * 100}%`;
  if (label) label.textContent = `${done} / 3 scenarios`;
}

/* ── Right panel ── */
function updateRightPanel() {
  const panel = document.getElementById('compliance-right-panel');
  if (!panel) return;

  const concept = KEY_CONCEPTS[currentScenario] || KEY_CONCEPTS[0];

  const scenarioRows = COMP_SCENARIOS.map((s, i) => {
    const score = scenarioScores[i];
    const isCurrent = i === currentScenario && score === null;
    let scoreDisplay, dotColor;
    if (score !== null) {
      scoreDisplay = `<span style="color:var(--ok);font-family:var(--font-mono);font-weight:700;">✓ ${score} pts</span>`;
      dotColor = 'var(--ok)';
    } else if (isCurrent) {
      scoreDisplay = `<span style="color:var(--teal);font-size:11px;">In progress…</span>`;
      dotColor = 'var(--teal)';
    } else {
      scoreDisplay = `<span style="color:var(--text-dim);font-family:var(--font-mono);">—</span>`;
      dotColor = 'var(--text-dim)';
    }
    return `<div style="display:flex;align-items:center;justify-content:space-between;padding:7px 0;${i < 2 ? 'border-bottom:1px solid var(--line);' : ''}">
      <div style="display:flex;align-items:center;gap:8px;">
        <span style="font-size:11px;width:8px;height:8px;border-radius:50%;background:${dotColor};display:inline-block;flex-shrink:0;"></span>
        <span style="font-size:12px;color:var(--text-muted);">${s.icon} ${s.title}</span>
      </div>
      <div style="font-size:12px;">${scoreDisplay}</div>
    </div>`;
  }).join('');

  panel.innerHTML = `
    <div class="card mb-3" style="padding:1rem 1.25rem;">
      <div class="text-xs text-muted mb-1" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Your Score</div>
      <div style="font-size:2.5rem;font-weight:800;color:var(--teal);font-family:var(--font-mono);line-height:1;">${totalScore}</div>
      <div class="text-xs text-muted" style="margin-top:2px;">out of 99 pts</div>
    </div>

    <div class="card mb-3" style="padding:1rem 1.25rem;">
      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Scenarios</div>
      ${scenarioRows}
    </div>

    <div class="card" style="padding:1rem 1.25rem;border-color:rgba(99,102,241,0.3);background:rgba(99,102,241,0.04);">
      <div class="text-xs mb-1" style="color:#818cf8;font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Key Concept</div>
      <div style="font-size:12px;font-weight:700;color:var(--text-primary);margin-bottom:4px;">${concept.heading}</div>
      <div style="font-size:11px;color:var(--text-muted);line-height:1.65;">${concept.body}</div>
    </div>`;
}

/* ── Final debrief ── */
function renderDebrief() {
  const main = document.getElementById('compliance-main');
  if (!main) return;

  const p = SENTINEL.getProgress();
  p.complianceScore     = totalScore;
  p.complianceCompleted = true;
  SENTINEL.saveProgress(p);

  const elapsed = startTime ? Math.round((Date.now() - startTime) / 1000) : 0;
  const mins    = Math.floor(elapsed / 60);
  const secs    = elapsed % 60;
  const pct     = Math.round((totalScore / 99) * 100);
  const label   = SENTINEL.scoreLabel ? SENTINEL.scoreLabel(pct) : '';
  const cls     = SENTINEL.scoreClass ? SENTINEL.scoreClass(pct) : '';

  const rows = COMP_SCENARIOS.map((s, i) => {
    const sc   = SCENARIOS[i];
    const pts  = scenarioScores[i] ?? 0;
    const base = sc.points - 8;
    const quiz = pts - base;
    return `<tr>
      <td class="text-xs" style="padding:6px 8px;">${s.icon} ${s.title}</td>
      <td class="text-xs font-mono" style="padding:6px 8px;text-align:center;color:${pts >= base ? 'var(--ok)' : 'var(--text-muted)'};">
        ${pts >= base ? '✓' : '○'} ${base} mapping
      </td>
      <td class="text-xs font-mono" style="padding:6px 8px;text-align:center;color:${quiz > 0 ? 'var(--ok)' : 'var(--critical)'};">
        ${quiz > 0 ? '✓' : '✗'} ${quiz > 0 ? quiz : 0} quiz
      </td>
    </tr>`;
  }).join('');

  main.innerHTML = `
    <div class="card mb-4 animate-fade-in">
      <div class="card-header">
        <span class="card-icon">🏁</span>
        <div>
          <div class="card-title">Compliance Control Mapper — Complete</div>
          <div class="card-sub">Security+ Domain 5 · Security Program Management</div>
        </div>
      </div>

      <div style="text-align:center;padding:1.5rem 0;border-bottom:1px solid var(--line);margin-bottom:1.25rem;">
        <div class="stat-big ${cls}" style="font-size:3rem;">${totalScore}</div>
        <div class="text-sm text-muted">out of 99 pts</div>
        <div style="margin-top:8px;font-size:1rem;font-weight:600;color:var(--teal);">${label}</div>
        <div class="text-xs text-muted mt-1">Completed in ${mins}m ${secs}s</div>
      </div>

      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Score Breakdown</div>
      <table style="width:100%;border-collapse:collapse;margin-bottom:1.25rem;">
        <thead>
          <tr style="border-bottom:1px solid var(--line);">
            <th class="text-xs text-muted" style="text-align:left;padding:4px 8px;font-weight:700;">Framework</th>
            <th class="text-xs text-muted" style="padding:4px 8px;font-weight:700;text-align:center;">Mapping</th>
            <th class="text-xs text-muted" style="padding:4px 8px;font-weight:700;text-align:center;">Quiz</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
        <tfoot>
          <tr style="border-top:1px solid var(--line);">
            <td class="text-xs" style="padding:6px 8px;font-weight:700;">Total</td>
            <td colspan="2" class="text-xs font-mono" style="padding:6px 8px;text-align:center;color:var(--teal);font-weight:700;">${totalScore} / 99</td>
          </tr>
        </tfoot>
      </table>

      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">What you practiced (Sec+ Domain 5)</div>
      <div style="background:var(--bg-primary);border-radius:8px;padding:1rem;margin-bottom:1.25rem;">
        <div style="display:grid;gap:6px;">
          ${[
            'HIPAA requires Access, Audit, Integrity, and Transmission Security controls for patient health information (PHI)',
            'PCI-DSS is enforced by card brands — any business accepting card payments must comply regardless of size',
            'NIST 800-53 organizes federal security controls into families: AC, IR, SC, AU, and 16 others',
            'Compliance frameworks don\'t prescribe specific products — they define requirements that controls must satisfy',
            'A single control can satisfy multiple framework requirements across different frameworks',
            'Distractors are real security controls — they just don\'t fit these specific framework requirements',
          ].map(s => `<div class="text-xs" style="display:flex;gap:8px;"><span style="color:var(--ok);">✓</span><span>${s}</span></div>`).join('')}
        </div>
      </div>

      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <a href="index.html" class="btn btn-primary" style="font-size:13px;">Command Center</a>
        <button class="btn" style="font-size:13px;" onclick="resetCompliance()">Retry Lab</button>
        <a href="phishing.html" class="btn" style="font-size:13px;">← Phishing Forensics</a>
      </div>
    </div>`;

  updateRightPanel();
  updateProgressBar();
}

/* ── Reset ── */
function resetCompliance() {
  scenarioScores  = [null, null, null];
  mappingState    = [{}, {}, {}];
  totalScore      = 0;
  selectedControl = null;
  currentScenario = 0;
  startTime       = Date.now();
  updateProgressBar();
  renderScenario(0);
  updateRightPanel();
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', initCompliance);
