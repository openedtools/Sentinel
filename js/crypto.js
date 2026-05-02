/* ── SENTINEL — Cryptography Playground ── */
'use strict';

/* ── State ── */
let currentLab  = 0;
let labScores   = [null, null, null, null, null]; // index 0-4, null = not attempted
let totalScore  = 0;
let startTime   = null;
let aesKey      = null;   // CryptoKey (AES-GCM-256)
let rsaKeyPair  = null;   // { publicKey, privateKey }
let sha256Timer = null;   // debounce handle
let aesLastCipherBuf = null; // last encrypted ArrayBuffer (for decrypt)
let aesLastIV        = null; // last IV used

const CRYPTO_LABS = [
  { id: 1, title: 'Symmetric Encryption (AES)', icon: '🔒', pts: 20 },
  { id: 2, title: 'Asymmetric Encryption (RSA)', icon: '🔑', pts: 20 },
  { id: 3, title: 'Hashing (SHA-256 & MD5)',     icon: '#',  pts: 20 },
  { id: 4, title: 'PKI & Trust Chains',          icon: '📜', pts: 20 },
  { id: 5, title: 'Post-Quantum Cryptography',   icon: '⚛',  pts: 20 },
];

const MD5_RAINBOW = {
  '482c811da5d5b4bc6d497ffa98491e38': 'password123',
  '21232f297a57a5a743894a0e4a801fc3': 'admin',
  '5f4dcc3b5aa765d61d8327deb882cf99': 'password',
  'e10adc3949ba59abbe56e057f20f883e': '123456',
  '96e79218965eb72c92a549dd5a330112': '111111'
};

/* ── Helpers ── */
function buf2hex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function hex2buf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes.buffer;
}
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/* ── Entry point ── */
function initCrypto() {
  startTime = Date.now();

  // Feature-detect WebCrypto
  if (!window.crypto?.subtle) {
    document.getElementById('crypto-main').innerHTML = `
      <div class="card" style="border-color:var(--high);padding:1.5rem;">
        <div style="color:var(--high);font-weight:700;font-size:1rem;margin-bottom:.5rem;">⚠ WebCrypto API Not Available</div>
        <p class="text-sm text-muted">Your browser does not support the Web Cryptography API
        (window.crypto.subtle). This is required for the live encryption demos.<br><br>
        Try opening this page over HTTPS or in a modern browser (Chrome 37+, Firefox 34+, Safari 11+).
        The conceptual content is still available below.</p>
      </div>`;
    return;
  }

  renderLab(0);
  updateRightPanel();
}

/* ── Lab router ── */
function renderLab(idx) {
  currentLab = idx;
  const main = document.getElementById('crypto-main');
  if (!main) return;
  main.innerHTML = '';
  window.scrollTo({ top: 0, behavior: 'smooth' });

  if (idx === 5) { showFinalDebrief(); return; }

  switch (idx) {
    case 0: renderLab1(main); break;
    case 1: renderLab2(main); break;
    case 2: renderLab3(main); break;
    case 3: renderLab4(main); break;
    case 4: renderLab5(main); break;
  }
  updateRightPanel();
}

/* ── Progress bar ── */
function updateProgressBar() {
  const done = labScores.filter(s => s !== null).length;
  const fill  = document.getElementById('crypto-progress-fill');
  const label = document.getElementById('crypto-progress-label');
  if (fill)  fill.style.width = `${(done / 5) * 100}%`;
  if (label) label.textContent = `${done} / 5 labs`;
}

/* ── Right panel ── */
function updateRightPanel() {
  const panel = document.getElementById('crypto-right-panel');
  if (!panel) return;

  const keyConceptsByLab = [
    { heading: 'Symmetric Encryption', body: 'Same key encrypts and decrypts. Fast. Good for bulk data. Key must stay secret.' },
    { heading: 'Asymmetric Encryption', body: 'Public key encrypts; private key decrypts. Solves the key-distribution problem. Slower than AES.' },
    { heading: 'Cryptographic Hashing', body: 'One-way transformation. Same input = same hash. Changing one bit completely changes the output (avalanche effect).' },
    { heading: 'PKI & Trust Chains', body: 'Certificates bind an identity to a public key. Browser trusts Root CAs installed by the OS; everything else is derived.' },
    { heading: 'Post-Quantum Cryptography', body: 'NIST has standardized ML-KEM (Kyber), ML-DSA (Dilithium), and SLH-DSA (SPHINCS+) to replace quantum-vulnerable algorithms.' },
  ];

  const concept = keyConceptsByLab[currentLab] || keyConceptsByLab[0];

  const labRows = CRYPTO_LABS.map((lab, i) => {
    const score = labScores[i];
    let icon, color;
    if (score === null)      { icon = '○'; color = 'var(--text-muted)'; }
    else if (score > 0)      { icon = '✓'; color = 'var(--ok)'; }
    else                     { icon = '✗'; color = 'var(--critical)'; }
    const pts = score !== null ? `${score} pts` : '—';
    return `<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--line);">
      <span style="color:${color};font-size:13px;width:14px;flex-shrink:0;">${icon}</span>
      <span class="text-xs" style="flex:1;color:${currentLab === i ? 'var(--text-primary)' : 'var(--text-muted)'};">${lab.icon} ${lab.title}</span>
      <span class="text-xs font-mono" style="color:${color};">${pts}</span>
    </div>`;
  }).join('');

  panel.innerHTML = `
    <div class="card mb-4" style="padding:1rem 1.25rem;">
      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Your Score</div>
      <div style="font-size:2.5rem;font-weight:800;color:var(--teal);font-family:var(--font-mono);line-height:1;">${totalScore}</div>
      <div class="text-xs text-muted" style="margin-top:2px;">out of 100 pts</div>
      <div style="margin-top:12px;padding:8px;background:var(--bg-primary);border-radius:6px;">
        <div class="text-xs" style="color:var(--ok);">+20 pts — correct answer</div>
        <div class="text-xs" style="color:var(--critical);margin-top:2px;">+0 pts — incorrect</div>
      </div>
    </div>

    <div class="card mb-4" style="padding:1rem 1.25rem;">
      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Lab Progress</div>
      ${labRows}
    </div>

    <div class="card" style="padding:1rem 1.25rem;border-color:rgba(94,234,212,0.3);">
      <div class="text-xs" style="color:var(--teal);font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px;">Key Concept</div>
      <div class="text-xs" style="color:var(--text-primary);font-weight:600;margin-bottom:4px;">${concept.heading}</div>
      <div class="text-xs text-muted" style="line-height:1.6;">${concept.body}</div>
    </div>`;
}

/* ── Shared quiz handler ── */
function submitLabQuiz(labIndex, selected, correct, nextBtnId) {
  const isCorrect = selected === correct;
  const pts = isCorrect ? 20 : 0;

  if (labScores[labIndex] === null) {
    labScores[labIndex] = pts;
    totalScore += pts;
    if (SENTINEL?.updateScore) SENTINEL.updateScore(pts);
  }

  updateProgressBar();
  updateRightPanel();

  // Highlight answers
  const opts = document.querySelectorAll('.quiz-option');
  opts.forEach(btn => {
    btn.disabled = true;
    const val = btn.dataset.val;
    if (val === correct)  { btn.style.borderColor = 'var(--ok)';       btn.style.background = 'rgba(74,222,128,.08)'; }
    if (val === selected && selected !== correct) { btn.style.borderColor = 'var(--critical)'; btn.style.background = 'rgba(244,63,94,.08)'; }
  });

  // Feedback
  const fb = document.getElementById('quiz-feedback');
  if (fb) {
    fb.innerHTML = isCorrect
      ? `<div class="badge badge-ok" style="font-size:12px;padding:6px 12px;">✓ Correct! +20 pts</div>`
      : `<div class="badge badge-critical" style="font-size:12px;padding:6px 12px;">✗ Incorrect — the correct answer is highlighted above.</div>`;
    fb.style.display = 'block';
  }

  // Show next button
  const nextBtn = document.getElementById(nextBtnId || 'next-lab-btn');
  if (nextBtn) nextBtn.style.display = 'inline-flex';
}

/* ═══════════════════════════════════════
   LAB 1 — Symmetric Encryption (AES-GCM)
═══════════════════════════════════════ */
function renderLab1(main) {
  main.innerHTML = `
    <div class="card mb-4 animate-fade-in">
      <div class="card-header">
        <span class="card-icon">🔒</span>
        <div>
          <div class="card-title">Lab 1 of 5 — Symmetric Encryption (AES-GCM-256)</div>
          <div class="card-sub">Same key locks and unlocks · 20 pts</div>
        </div>
      </div>

      <!-- Analogy -->
      <div style="background:rgba(94,234,212,.07);border:1px solid rgba(94,234,212,.25);border-radius:8px;padding:1rem;margin-bottom:1.25rem;">
        <div class="text-xs" style="color:var(--teal);font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Analogy first</div>
        <div class="text-sm" style="line-height:1.6;">
          Think of a <strong style="color:var(--text-primary);">combination padlock</strong>. The same combination opens it and locks it.
          Anyone who knows the combination can do both. AES works the same way — one secret key encrypts
          <em>and</em> decrypts. The trick is keeping that key safe.
        </div>
      </div>

      <!-- Demo -->
      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Live Demo — AES-GCM-256</div>
      <div style="background:var(--bg-primary);border-radius:8px;padding:1rem;margin-bottom:1rem;">
        <div id="aes-key-status" class="text-xs font-mono mb-3" style="color:var(--text-muted);">Generating 256-bit AES key…</div>

        <textarea id="aes-plaintext" placeholder="Type a message to encrypt…"
          style="width:100%;box-sizing:border-box;background:var(--bg-2);border:1px solid var(--line);border-radius:6px;padding:10px 12px;color:var(--text-primary);font-family:var(--font-mono);font-size:12px;resize:vertical;min-height:72px;outline:none;"
          oninput="this.style.borderColor='var(--teal)'" onblur="this.style.borderColor='var(--line)'"></textarea>

        <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;">
          <button id="aes-encrypt-btn" class="btn btn-primary" style="font-size:12px;" onclick="aesEncrypt()" disabled>Encrypt</button>
          <button id="aes-decrypt-btn" class="btn" style="font-size:12px;" onclick="aesDecrypt()" disabled>Decrypt</button>
          <button id="aes-encrypt-again-btn" class="btn" style="font-size:12px;" onclick="aesEncryptAgain()" disabled>Encrypt Again (new IV)</button>
        </div>

        <div id="aes-output" class="alert-log mt-3" style="display:none;min-height:60px;"></div>
      </div>

      <div style="background:rgba(251,146,60,.07);border:1px solid rgba(251,146,60,.25);border-radius:8px;padding:.85rem 1rem;margin-bottom:1.25rem;">
        <div class="text-xs" style="color:var(--high);font-weight:700;margin-bottom:4px;">⚛ Quantum Threat — Grover's Algorithm</div>
        <div class="text-xs text-muted" style="line-height:1.6;">
          Grover's algorithm gives a quantum computer a quadratic speedup on brute-force search.
          For symmetric keys, it effectively <strong>halves the key length</strong>:
          AES-128 → 64-bit effective security (breakable). <strong>AES-256 → 128-bit effective security (safe).</strong><br>
          <span style="color:var(--ok);">✅ Verdict: AES-256 is quantum-resistant.</span>
        </div>
      </div>

      <!-- Quiz -->
      <div id="lab1-quiz">
        <div class="text-xs text-muted mb-3" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Quiz — 20 pts</div>
        <div class="text-sm" style="font-weight:600;color:var(--text-primary);margin-bottom:12px;">
          Why does encrypting the same message twice produce <em>different</em> ciphertext?
        </div>
        <div style="display:grid;gap:8px;">
          <button class="quiz-option btn" data-val="A" onclick="pickQuizOpt(this,'A','C','next-lab-btn')">A) It's a bug in the implementation</button>
          <button class="quiz-option btn" data-val="B" onclick="pickQuizOpt(this,'B','C','next-lab-btn')">B) Different encryption keys are used each time</button>
          <button class="quiz-option btn" data-val="C" onclick="pickQuizOpt(this,'C','C','next-lab-btn')">C) A random Initialization Vector (IV) ensures non-deterministic output</button>
          <button class="quiz-option btn" data-val="D" onclick="pickQuizOpt(this,'D','C','next-lab-btn')">D) AES is inherently unreliable — results vary by chance</button>
        </div>
        <div id="quiz-feedback" style="display:none;margin-top:12px;"></div>
      </div>
      <div style="margin-top:1rem;">
        <button id="next-lab-btn" class="btn btn-primary" style="display:none;" onclick="renderLab(1)">Next: Asymmetric Encryption →</button>
      </div>
    </div>`;

  // Generate AES key on load
  crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
    .then(key => {
      aesKey = key;
      const status = document.getElementById('aes-key-status');
      if (status) status.innerHTML = '<span style="color:var(--ok);">✓ AES-256 key generated (lives only in browser memory)</span>';
      const encBtn = document.getElementById('aes-encrypt-btn');
      if (encBtn) encBtn.disabled = false;
    })
    .catch(() => {
      const status = document.getElementById('aes-key-status');
      if (status) status.textContent = '⚠ Key generation failed.';
    });
}

async function aesEncrypt() {
  if (!aesKey) return;
  const ptEl = document.getElementById('aes-plaintext');
  const plaintext = ptEl?.value?.trim();
  if (!plaintext) { if (ptEl) { ptEl.style.borderColor = 'var(--critical)'; ptEl.focus(); } return; }

  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  try {
    const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc.encode(plaintext));
    aesLastCipherBuf = cipherBuf;
    aesLastIV        = iv;

    const out = document.getElementById('aes-output');
    if (out) {
      out.style.display = 'block';
      out.innerHTML = `<div class="text-xs" style="color:var(--text-muted);margin-bottom:4px;">IV (hex): <span style="color:var(--teal);">${buf2hex(iv)}</span></div>
<div class="text-xs" style="color:var(--text-muted);margin-bottom:4px;">Ciphertext (hex, first 48 chars): <span style="color:var(--high);">${buf2hex(cipherBuf).slice(0, 96)}…</span></div>
<div class="text-xs" style="color:var(--text-muted);">Same message, but this ciphertext is unique to this IV. Click Encrypt Again to see a new one.</div>`;
    }
    const decBtn = document.getElementById('aes-decrypt-btn');
    const againBtn = document.getElementById('aes-encrypt-again-btn');
    if (decBtn) decBtn.disabled = false;
    if (againBtn) againBtn.disabled = false;
  } catch (e) {
    const out = document.getElementById('aes-output');
    if (out) { out.style.display = 'block'; out.textContent = 'Encryption error: ' + e.message; }
  }
}

async function aesEncryptAgain() {
  const ptEl = document.getElementById('aes-plaintext');
  const plaintext = ptEl?.value?.trim();
  if (!plaintext || !aesKey) return;

  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc.encode(plaintext));

  const out = document.getElementById('aes-output');
  if (out) {
    out.innerHTML = `<div class="text-xs" style="color:var(--text-muted);margin-bottom:4px;">NEW IV (hex): <span style="color:var(--teal);">${buf2hex(iv)}</span></div>
<div class="text-xs" style="color:var(--text-muted);margin-bottom:4px;">NEW Ciphertext (hex, first 48 chars): <span style="color:var(--high);">${buf2hex(cipherBuf).slice(0, 96)}…</span></div>
<div class="text-xs" style="color:var(--ok);">↑ Completely different ciphertext — same message, different IV. This is why AES-GCM is safe to use for repeated encryptions.</div>`;
  }
}

async function aesDecrypt() {
  if (!aesKey || !aesLastCipherBuf || !aesLastIV) return;
  try {
    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: aesLastIV }, aesKey, aesLastCipherBuf);
    const plaintext = new TextDecoder().decode(plainBuf);
    const out = document.getElementById('aes-output');
    if (out) {
      out.innerHTML += `<div class="text-xs" style="color:var(--ok);margin-top:8px;border-top:1px solid var(--line);padding-top:8px;">
        Decrypted: <strong>${esc(plaintext)}</strong> — original message recovered perfectly.</div>`;
    }
  } catch (e) {
    const out = document.getElementById('aes-output');
    if (out) out.innerHTML += `<div class="text-xs" style="color:var(--critical);margin-top:8px;">Decryption failed: ${e.message}</div>`;
  }
}

function pickQuizOpt(btn, selected, correct, nextId) {
  if (btn.disabled) return;
  const idx = CRYPTO_LABS.findIndex(l => l.title.includes('Symmetric') && currentLab === 0)
    !== -1 ? currentLab : currentLab;
  submitLabQuiz(currentLab, selected, correct, nextId);
}

/* ═══════════════════════════════════════
   LAB 2 — Asymmetric Encryption (RSA-OAEP)
═══════════════════════════════════════ */
function renderLab2(main) {
  main.innerHTML = `
    <div class="card mb-4 animate-fade-in">
      <div class="card-header">
        <span class="card-icon">🔑</span>
        <div>
          <div class="card-title">Lab 2 of 5 — Asymmetric Encryption (RSA-OAEP-2048)</div>
          <div class="card-sub">Public key encrypts · Private key decrypts · 20 pts</div>
        </div>
      </div>

      <!-- Analogy -->
      <div style="background:rgba(94,234,212,.07);border:1px solid rgba(94,234,212,.25);border-radius:8px;padding:1rem;margin-bottom:1.25rem;">
        <div class="text-xs" style="color:var(--teal);font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Analogy first</div>
        <div class="text-sm" style="line-height:1.6;">
          Think of a <strong style="color:var(--text-primary);">mailbox slot</strong>. Anyone can drop a letter through the slot (public key encrypts).
          But only you have the key to open the box door and read it (private key decrypts).
          You can publish your mailbox address to the world — that's safe. Guard the door key.
        </div>
      </div>

      <!-- Demo -->
      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Live Demo — RSA-OAEP-2048</div>
      <div style="background:var(--bg-primary);border-radius:8px;padding:1rem;margin-bottom:1rem;">
        <button id="rsa-keygen-btn" class="btn btn-primary" style="font-size:12px;" onclick="rsaGenerate()">Generate RSA Key Pair</button>
        <div id="rsa-spinner" style="display:none;margin-top:8px;" class="text-xs text-muted">⏳ Generating 2048-bit RSA key pair… (may take a moment)</div>
        <div id="rsa-keys-display" style="display:none;margin-top:12px;">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px;">
            <div style="background:var(--bg-2);border:1px solid var(--ok);border-radius:6px;padding:10px;">
              <div class="text-xs" style="color:var(--ok);font-weight:700;margin-bottom:4px;">PUBLIC KEY — share freely</div>
              <div class="text-xs font-mono text-muted" style="word-break:break-all;line-height:1.5;" id="rsa-pub-display">…</div>
            </div>
            <div style="background:var(--bg-2);border:1px solid var(--critical);border-radius:6px;padding:10px;">
              <div class="text-xs" style="color:var(--critical);font-weight:700;margin-bottom:4px;">PRIVATE KEY — never share</div>
              <div class="text-xs font-mono text-muted">Lives in browser memory only. Not shown.</div>
            </div>
          </div>
          <textarea id="rsa-plaintext" maxlength="100" placeholder="Type a short message (≤ 100 chars)…"
            style="width:100%;box-sizing:border-box;background:var(--bg-2);border:1px solid var(--line);border-radius:6px;padding:10px 12px;color:var(--text-primary);font-family:var(--font-mono);font-size:12px;resize:none;height:60px;outline:none;"
            oninput="document.getElementById('rsa-charcount').textContent=this.value.length+'/100'"></textarea>
          <div class="text-xs text-muted" style="text-align:right;margin-bottom:8px;" id="rsa-charcount">0/100</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button class="btn btn-primary" style="font-size:12px;" onclick="rsaEncrypt()">Encrypt with Public Key</button>
          </div>
          <div id="rsa-cipher-output" class="alert-log mt-3" style="display:none;"></div>
          <div id="rsa-decrypt-btns" style="display:none;margin-top:8px;gap:8px;display:none;flex-wrap:wrap;">
            <button class="btn" style="font-size:12px;border-color:var(--ok);color:var(--ok);" onclick="rsaDecrypt(true)">Decrypt with Private Key ✓</button>
            <button class="btn" style="font-size:12px;border-color:var(--critical);color:var(--critical);" onclick="rsaDecrypt(false)">Try Without Private Key ✗</button>
          </div>
        </div>
      </div>

      <!-- Quantum callout — RSA vulnerable -->
      <div style="background:rgba(244,63,94,.07);border:1px solid rgba(244,63,94,.3);border-radius:8px;padding:.85rem 1rem;margin-bottom:.85rem;">
        <div class="text-xs" style="color:var(--critical);font-weight:700;margin-bottom:4px;">⚛ Quantum Threat — Shor's Algorithm</div>
        <div class="text-xs text-muted" style="line-height:1.6;">
          Shor's algorithm factors large integers exponentially faster than any classical method.
          RSA-2048 classically: longer than the age of the universe to break.
          With a ~4,000-qubit fault-tolerant quantum computer: <strong>approximately 8 hours.</strong><br>
          <span style="color:var(--critical);">❌ Verdict: RSA is quantum-VULNERABLE.</span>
        </div>
      </div>

      <!-- HNDL callout -->
      <div style="background:rgba(94,163,234,.07);border:1px solid rgba(94,163,234,.3);border-radius:8px;padding:.85rem 1rem;margin-bottom:.85rem;">
        <div class="text-xs" style="color:var(--low);font-weight:700;margin-bottom:4px;">🔗 HNDL — Harvest Now, Decrypt Later</div>
        <div class="text-xs text-muted" style="line-height:1.6;">
          An adversary doesn't need a quantum computer <em>today</em>. They record and store your
          RSA-encrypted traffic now, then decrypt it once quantum computers are available.
          In the exercise, the <strong>SEC-VAULT-01</strong> post-quantum TLS upgrade is a direct response to this threat.
          <br><br>
          If your RSA-encrypted data has a 20-year secrecy requirement and quantum computers
          arrive in 10 years — <strong>you've already lost.</strong>
        </div>
      </div>

      <!-- PQC replacement -->
      <div style="background:rgba(94,234,212,.05);border:1px solid rgba(94,234,212,.2);border-radius:8px;padding:.85rem 1rem;margin-bottom:1.25rem;">
        <div class="text-xs" style="color:var(--teal);font-weight:700;margin-bottom:4px;">✅ PQC Replacement: ML-KEM (CRYSTALS-Kyber)</div>
        <div class="text-xs text-muted" style="line-height:1.6;">
          NIST FIPS 203 standardizes <strong>ML-KEM (Module-Lattice Key Encapsulation Mechanism)</strong> — formerly known as Kyber.
          It replaces RSA and ECDH for key exchange. Based on the hardness of solving lattice problems,
          which is believed to resist both classical and quantum attacks.
        </div>
      </div>

      <!-- Quiz -->
      <div id="lab2-quiz">
        <div class="text-xs text-muted mb-3" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Quiz — 20 pts</div>
        <div class="text-sm" style="font-weight:600;color:var(--text-primary);margin-bottom:12px;">
          An adversary records RSA-encrypted HTTPS traffic today. Under an HNDL strategy, what is their plan?
        </div>
        <div style="display:grid;gap:8px;">
          <button class="quiz-option btn" data-val="A" onclick="submitLabQuiz(1,'A','C','next-lab2-btn')">A) Sell the encrypted data on the dark web immediately</button>
          <button class="quiz-option btn" data-val="B" onclick="submitLabQuiz(1,'B','C','next-lab2-btn')">B) Force TLS renegotiation to a weaker cipher suite</button>
          <button class="quiz-option btn" data-val="C" onclick="submitLabQuiz(1,'C','C','next-lab2-btn')">C) Store the ciphertext and wait until a quantum computer can run Shor's algorithm</button>
          <button class="quiz-option btn" data-val="D" onclick="submitLabQuiz(1,'D','C','next-lab2-btn')">D) Use rainbow tables to reverse RSA key derivation</button>
        </div>
        <div id="quiz-feedback" style="display:none;margin-top:12px;"></div>
      </div>
      <div style="margin-top:1rem;">
        <button id="next-lab2-btn" class="btn btn-primary" style="display:none;" onclick="renderLab(2)">Next: Hashing →</button>
      </div>
    </div>`;
}

async function rsaGenerate() {
  const btn = document.getElementById('rsa-keygen-btn');
  const spinner = document.getElementById('rsa-spinner');
  const display = document.getElementById('rsa-keys-display');
  if (btn) btn.disabled = true;
  if (spinner) spinner.style.display = 'block';

  try {
    rsaKeyPair = await crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['encrypt', 'decrypt']
    );
    const pubSpki = await crypto.subtle.exportKey('spki', rsaKeyPair.publicKey);
    const pubB64  = btoa(String.fromCharCode(...new Uint8Array(pubSpki)));
    const pubPem  = pubB64.match(/.{1,32}/g).join('\n');

    const pubEl = document.getElementById('rsa-pub-display');
    if (pubEl) pubEl.textContent = `-----BEGIN PUBLIC KEY-----\n${pubPem}\n-----END PUBLIC KEY-----`;
    if (spinner) spinner.style.display = 'none';
    if (display) display.style.display = 'block';
  } catch (e) {
    if (spinner) spinner.style.display = 'none';
    if (btn) { btn.disabled = false; btn.textContent = 'Retry Key Generation'; }
  }
}

async function rsaEncrypt() {
  if (!rsaKeyPair) return;
  const ptEl = document.getElementById('rsa-plaintext');
  const plaintext = ptEl?.value?.trim();
  if (!plaintext) { if (ptEl) { ptEl.style.borderColor = 'var(--critical)'; ptEl.focus(); } return; }

  try {
    const enc = new TextEncoder();
    const cipherBuf = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaKeyPair.publicKey, enc.encode(plaintext));
    const out = document.getElementById('rsa-cipher-output');
    if (out) {
      out.style.display = 'block';
      out.innerHTML = `<div class="text-xs text-muted mb-1">Ciphertext (hex, first 64 chars of ${cipherBuf.byteLength * 2} total):</div>
<div class="text-xs font-mono" style="color:var(--high);word-break:break-all;">${buf2hex(cipherBuf).slice(0, 128)}…</div>`;
    }
    const decBtns = document.getElementById('rsa-decrypt-btns');
    if (decBtns) decBtns.style.display = 'flex';
    // Store for decrypt
    window._rsaLastCipher = cipherBuf;
  } catch (e) {
    const out = document.getElementById('rsa-cipher-output');
    if (out) { out.style.display = 'block'; out.textContent = 'Encryption error: ' + e.message; }
  }
}

async function rsaDecrypt(useKey) {
  const out = document.getElementById('rsa-cipher-output');
  if (!window._rsaLastCipher) return;

  if (!useKey) {
    if (out) out.innerHTML += `<div class="text-xs" style="color:var(--critical);margin-top:8px;border-top:1px solid var(--line);padding-top:8px;">
      <strong>DECRYPTION FAILED</strong> — without the private key the ciphertext is indistinguishable from random noise.
      This is by design: RSA-OAEP guarantees only the private key holder can read the message.</div>`;
    return;
  }

  try {
    const plainBuf = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, rsaKeyPair.privateKey, window._rsaLastCipher);
    const plaintext = new TextDecoder().decode(plainBuf);
    if (out) out.innerHTML += `<div class="text-xs" style="color:var(--ok);margin-top:8px;border-top:1px solid var(--line);padding-top:8px;">
      Decrypted: <strong>${esc(plaintext)}</strong> — private key holder can read the message.</div>`;
  } catch (e) {
    if (out) out.innerHTML += `<div class="text-xs" style="color:var(--critical);margin-top:8px;">Error: ${e.message}</div>`;
  }
}

/* ═══════════════════════════════════════
   LAB 3 — Hashing (SHA-256 & MD5)
═══════════════════════════════════════ */
function renderLab3(main) {
  const rainbowRows = Object.entries(MD5_RAINBOW).map(([hash, plain]) =>
    `<tr id="md5-row-${hash.slice(0,8)}">
      <td class="text-xs font-mono" style="color:var(--high);word-break:break-all;padding:6px 8px;">${hash}</td>
      <td style="padding:6px 8px;">
        <button class="btn" style="font-size:11px;" onclick="lookupMD5('${hash}')">Look Up</button>
      </td>
      <td id="md5-found-${hash.slice(0,8)}" class="text-xs font-mono" style="padding:6px 8px;color:var(--text-muted);">—</td>
    </tr>`
  ).join('');

  main.innerHTML = `
    <div class="card mb-4 animate-fade-in">
      <div class="card-header">
        <span class="card-icon">#</span>
        <div>
          <div class="card-title">Lab 3 of 5 — Hashing (SHA-256 & MD5)</div>
          <div class="card-sub">One-way fingerprints · 20 pts</div>
        </div>
      </div>

      <!-- Analogy -->
      <div style="background:rgba(94,234,212,.07);border:1px solid rgba(94,234,212,.25);border-radius:8px;padding:1rem;margin-bottom:1.25rem;">
        <div class="text-xs" style="color:var(--teal);font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Analogy first</div>
        <div class="text-sm" style="line-height:1.6;">
          A hash function is like a <strong style="color:var(--text-primary);">fingerprint machine</strong>. Feed in any document and get a fixed-size
          fingerprint out. The same document always gives the same fingerprint, but you cannot
          reconstruct the document from the fingerprint alone. Change one comma in the document and
          the fingerprint changes completely.
        </div>
      </div>

      <!-- Demo 1: SHA-256 live -->
      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Demo 1 — Live SHA-256 (Avalanche Effect)</div>
      <div style="background:var(--bg-primary);border-radius:8px;padding:1rem;margin-bottom:1rem;">
        <textarea id="sha256-input" placeholder="Type anything — watch the hash update in real time…"
          style="width:100%;box-sizing:border-box;background:var(--bg-2);border:1px solid var(--line);border-radius:6px;padding:10px 12px;color:var(--text-primary);font-family:var(--font-mono);font-size:12px;resize:none;height:60px;outline:none;"
          oninput="liveHash(this.value)"></textarea>
        <div style="margin-top:8px;">
          <div class="text-xs text-muted mb-1">SHA-256 output:</div>
          <div id="sha256-output" class="alert-log font-mono text-xs" style="min-height:32px;word-break:break-all;color:var(--teal);">—</div>
        </div>
        <div class="text-xs text-muted mt-2" style="line-height:1.6;">
          Try adding or removing just one character. The entire 64-character hash changes completely — that's the <strong>avalanche effect</strong>.
        </div>
      </div>

      <!-- Demo 2: MD5 rainbow table -->
      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Demo 2 — MD5 Rainbow Table Attack</div>
      <div style="background:var(--bg-primary);border-radius:8px;padding:1rem;margin-bottom:1rem;">
        <div class="text-xs text-muted mb-3" style="line-height:1.5;">
          A leaked database stores these five MD5 hashes. A rainbow table contains pre-computed
          MD5 hashes for millions of common passwords. Click "Look Up" to see how instantly they crack.
        </div>
        <div style="overflow-x:auto;">
          <table style="width:100%;border-collapse:collapse;">
            <thead>
              <tr style="border-bottom:1px solid var(--line);">
                <th class="text-xs text-muted" style="text-align:left;padding:4px 8px;font-weight:700;">MD5 Hash (from database)</th>
                <th class="text-xs text-muted" style="padding:4px 8px;font-weight:700;"></th>
                <th class="text-xs text-muted" style="text-align:left;padding:4px 8px;font-weight:700;">Plaintext</th>
              </tr>
            </thead>
            <tbody>${rainbowRows}</tbody>
          </table>
        </div>
      </div>

      <!-- Quantum callout -->
      <div style="background:rgba(251,146,60,.07);border:1px solid rgba(251,146,60,.25);border-radius:8px;padding:.85rem 1rem;margin-bottom:.85rem;">
        <div class="text-xs" style="color:var(--high);font-weight:700;margin-bottom:4px;">⚛ Quantum + Hash Algorithms</div>
        <div class="text-xs text-muted" style="line-height:1.6;">
          Grover's algorithm weakens hashing, but doubling the output length restores the security margin.
        </div>
        <table class="threat-matrix mt-2" style="width:100%;">
          <thead><tr><th>Algorithm</th><th>Classical</th><th>Quantum</th><th>Verdict</th></tr></thead>
          <tbody>
            <tr><td class="font-mono">MD5</td><td><span class="quantum-vuln">❌ Broken</span></td><td><span class="quantum-vuln">❌ Broken</span></td><td>DO NOT USE</td></tr>
            <tr><td class="font-mono">SHA-256</td><td><span class="quantum-safe">✅ 256-bit</span></td><td><span class="quantum-warn">⚠ 128-bit</span></td><td>Adequate</td></tr>
            <tr><td class="font-mono">SHA-384</td><td><span class="quantum-safe">✅ 384-bit</span></td><td><span class="quantum-safe">✅ 192-bit</span></td><td>Safe</td></tr>
            <tr><td class="font-mono">SHA-512</td><td><span class="quantum-safe">✅ 512-bit</span></td><td><span class="quantum-safe">✅ 256-bit</span></td><td>Recommended</td></tr>
          </tbody>
        </table>
      </div>

      <!-- Quiz -->
      <div id="lab3-quiz">
        <div class="text-xs text-muted mb-3" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Quiz — 20 pts</div>
        <div class="text-sm" style="font-weight:600;color:var(--text-primary);margin-bottom:12px;">
          A database stores unsalted MD5 hashes. An attacker steals the file. How quickly can they recover common passwords?
        </div>
        <div style="display:grid;gap:8px;">
          <button class="quiz-option btn" data-val="A" onclick="submitLabQuiz(2,'A','B','next-lab3-btn')">A) Weeks — requires a supercomputer to brute-force</button>
          <button class="quiz-option btn" data-val="B" onclick="submitLabQuiz(2,'B','B','next-lab3-btn')">B) Instantly — via pre-computed rainbow tables</button>
          <button class="quiz-option btn" data-val="C" onclick="submitLabQuiz(2,'C','B','next-lab3-btn')">C) Never — they need the salt to reverse a hash</button>
          <button class="quiz-option btn" data-val="D" onclick="submitLabQuiz(2,'D','B','next-lab3-btn')">D) They cannot — hash functions are mathematically irreversible</button>
        </div>
        <div id="quiz-feedback" style="display:none;margin-top:12px;"></div>
      </div>
      <div style="margin-top:1rem;">
        <button id="next-lab3-btn" class="btn btn-primary" style="display:none;" onclick="renderLab(3)">Next: PKI & Trust Chains →</button>
      </div>
    </div>`;
}

function liveHash(val) {
  if (sha256Timer) clearTimeout(sha256Timer);
  sha256Timer = setTimeout(async () => {
    const outEl = document.getElementById('sha256-output');
    if (!outEl) return;
    if (!val) { outEl.textContent = '—'; return; }
    try {
      const buf  = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(val));
      outEl.textContent = buf2hex(buf);
    } catch { outEl.textContent = '(error)'; }
  }, 50);
}

let md5LookupCount = 0;
function lookupMD5(hash) {
  const short = hash.slice(0, 8);
  const cell = document.getElementById(`md5-found-${short}`);
  const plain = MD5_RAINBOW[hash];
  if (cell && plain) {
    cell.innerHTML = `<span style="color:var(--critical);font-weight:700;">${esc(plain)}</span>
      <span style="color:var(--text-muted);margin-left:6px;">(found in 0.003ms)</span>`;
  }
  md5LookupCount++;
  // Allow quiz after first lookup
  const quizSection = document.getElementById('lab3-quiz');
  if (quizSection && md5LookupCount === 1) {
    quizSection.style.opacity = '1';
  }
}

/* ═══════════════════════════════════════
   LAB 4 — PKI & Trust Chains
═══════════════════════════════════════ */
const CERT_DATA = {
  root: {
    label: 'Root CA',
    color: 'var(--teal)',
    pem: `Subject:  CN=SENTINEL Root CA, O=Training Corp, C=US
Issuer:   CN=SENTINEL Root CA, O=Training Corp, C=US
Self-signed: YES (this is the trust anchor)
Valid:    2020-01-01 → 2040-12-31
Key:      RSA 4096-bit
Sig Alg:  sha256WithRSAEncryption
Type:     Root Certificate Authority
Usage:    Certificate Sign, CRL Sign`
  },
  intermediate: {
    label: 'Intermediate CA',
    color: 'var(--medium)',
    pem: `Subject:  CN=SENTINEL Issuing CA 1, O=Training Corp, C=US
Issuer:   CN=SENTINEL Root CA, O=Training Corp, C=US
Signed by: Root CA ✓
Valid:    2022-01-01 → 2032-12-31
Key:      RSA 2048-bit
Sig Alg:  sha256WithRSAEncryption
Type:     Intermediate Certificate Authority
Constraints: pathLenConstraint=0 (cannot issue sub-CAs)
Usage:    Certificate Sign, CRL Sign, OCSP Signing`
  },
  leaf: {
    label: 'Leaf Certificate',
    color: 'var(--ok)',
    pem: `Subject:  CN=openedtools.github.io, O=Training Corp, C=US
Issuer:   CN=SENTINEL Issuing CA 1, O=Training Corp, C=US
Signed by: Intermediate CA ✓
Valid:    2025-03-01 → 2026-03-01
SANs:     DNS:openedtools.github.io, DNS:*.openedtools.github.io
Key:      RSA 2048-bit
Sig Alg:  sha256WithRSAEncryption
Type:     End-Entity (TLS server)
Usage:    Digital Signature, Key Encipherment
Extended: TLS Web Server Authentication (1.3.6.1.5.5.7.3.1)`
  }
};

const CERT_ERRORS = {
  expired: {
    title: 'Certificate Expired',
    color: 'var(--critical)',
    body: `Your connection is not private. Attackers might be trying to steal your information.
<strong>NET::ERR_CERT_DATE_INVALID</strong>

The certificate for this site expired on 2024-03-01.
The server's clock may be off, or someone is intercepting your connection.

Why it matters: browsers won't accept expired certs even from trusted CAs.
Lesson: certificate lifecycle management is a real-world ops pain point.`
  },
  selfsigned: {
    title: 'Self-Signed Certificate',
    color: 'var(--high)',
    body: `Your connection is not private.
<strong>NET::ERR_CERT_AUTHORITY_INVALID</strong>

This certificate is not trusted because it is signed by an unknown issuer.
A self-signed cert is the digital equivalent of writing your own reference letter.

Why it matters: no Root CA has vouched for this cert, so the trust chain breaks.
Lesson: internal systems (dev servers, VPNs) often need a private internal CA.`
  },
  mismatch: {
    title: 'Domain Mismatch',
    color: 'var(--medium)',
    body: `Your connection is not private.
<strong>NET::ERR_CERT_COMMON_NAME_INVALID</strong>

The certificate is for "other-domain.com" but you tried to reach "our-site.com".
Someone may be intercepting traffic (e.g., a misconfigured load balancer,
or an active man-in-the-middle attack).

Why it matters: SANs (Subject Alternative Names) must exactly match the hostname.
Lesson: check cert SANs during incident response — mismatches can indicate MITM.`
  }
};

function renderLab4(main) {
  main.innerHTML = `
    <div class="card mb-4 animate-fade-in">
      <div class="card-header">
        <span class="card-icon">📜</span>
        <div>
          <div class="card-title">Lab 4 of 5 — PKI & Trust Chains</div>
          <div class="card-sub">How browsers decide who to trust · 20 pts</div>
        </div>
      </div>

      <!-- Analogy -->
      <div style="background:rgba(94,234,212,.07);border:1px solid rgba(94,234,212,.25);border-radius:8px;padding:1rem;margin-bottom:1.25rem;">
        <div class="text-xs" style="color:var(--teal);font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;">Analogy first</div>
        <div class="text-sm" style="line-height:1.6;">
          Think of a <strong style="color:var(--text-primary);">chain of notary stamps</strong>. Your browser arrives pre-loaded
          with ~150 Root CAs it trusts unconditionally (installed by your OS). Each Root CA can
          vouch for Intermediate CAs with its stamp, which in turn vouch for website certificates.
          If any link in the chain is missing or untrusted — the browser refuses to connect.
        </div>
      </div>

      <!-- Interactive cert chain -->
      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Interactive Certificate Chain — click a node to inspect it</div>
      <div style="background:var(--bg-primary);border-radius:8px;padding:1.25rem;margin-bottom:1rem;">
        <div class="cert-chain-wrap">
          <div class="cert-node" id="cert-node-root" onclick="showCert('root')">
            <div class="cert-node-icon">🏛</div>
            <div class="cert-node-name">Root CA</div>
            <div class="cert-node-type">Self-signed</div>
          </div>
          <div class="cert-connector"></div>
          <div class="cert-node" id="cert-node-intermediate" onclick="showCert('intermediate')">
            <div class="cert-node-icon">🏢</div>
            <div class="cert-node-name">Intermediate CA</div>
            <div class="cert-node-type">Issued by Root</div>
          </div>
          <div class="cert-connector"></div>
          <div class="cert-node" id="cert-node-leaf" onclick="showCert('leaf')">
            <div class="cert-node-icon">🌐</div>
            <div class="cert-node-name">Leaf Certificate</div>
            <div class="cert-node-type">TLS server cert</div>
          </div>
        </div>
        <div id="cert-detail-panel" class="alert-log mt-3" style="display:none;white-space:pre-wrap;font-size:11px;line-height:1.7;"></div>
      </div>

      <!-- Certificate errors -->
      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Common Certificate Errors</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;">
        <button class="btn" style="font-size:12px;" onclick="showCertError('expired')">Expired ⚠</button>
        <button class="btn" style="font-size:12px;" onclick="showCertError('selfsigned')">Self-Signed ⚠</button>
        <button class="btn" style="font-size:12px;" onclick="showCertError('mismatch')">Domain Mismatch ⚠</button>
      </div>
      <div id="cert-error-panel" style="display:none;margin-bottom:1.25rem;"></div>

      <!-- Quantum callout -->
      <div style="background:rgba(244,63,94,.07);border:1px solid rgba(244,63,94,.3);border-radius:8px;padding:.85rem 1rem;margin-bottom:.85rem;">
        <div class="text-xs" style="color:var(--critical);font-weight:700;margin-bottom:4px;">⚛ Quantum Threat to PKI</div>
        <div class="text-xs text-muted" style="line-height:1.6;">
          Most certificates today use <code>sha256WithRSAEncryption</code> or <code>sha256WithECDSA</code>
          for signatures. Both RSA and ECC (Elliptic Curve) are broken by Shor's algorithm.
          A quantum computer could <strong>forge certificate signatures</strong> — creating valid-looking certs
          for any domain, enabling undetectable MITM attacks against HTTPS.<br>
          <span style="color:var(--critical);">❌ Current PKI infrastructure is quantum-vulnerable.</span>
        </div>
      </div>

      <!-- PQC for certs -->
      <div style="background:rgba(94,234,212,.05);border:1px solid rgba(94,234,212,.2);border-radius:8px;padding:.85rem 1rem;margin-bottom:1.25rem;">
        <div class="text-xs" style="color:var(--teal);font-weight:700;margin-bottom:6px;">✅ PQC Replacements for Certificate Signatures</div>
        <div class="text-xs text-muted" style="line-height:1.6;">
          <strong>ML-DSA (FIPS 204)</strong> — Module-Lattice Digital Signature Algorithm (Dilithium).
          Replaces RSA and ECDSA for certificate signatures.<br>
          <strong>SLH-DSA (FIPS 205)</strong> — Stateless Hash-Based Digital Signatures (SPHINCS+).
          Conservative hash-based backup with minimal assumptions.<br><br>
          🔗 The <strong>SEC-VAULT-01</strong> entry in your Command Center exercise uses post-quantum TLS —
          ML-KEM for key exchange and ML-DSA for certificate validation.
        </div>
      </div>

      <!-- Quiz -->
      <div id="lab4-quiz">
        <div class="text-xs text-muted mb-3" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Quiz — 20 pts</div>
        <div class="text-sm" style="font-weight:600;color:var(--text-primary);margin-bottom:12px;">
          A certificate shows <code>sha256WithRSAEncryption</code>. A fault-tolerant quantum computer comes online. What is the most critical consequence?
        </div>
        <div style="display:grid;gap:8px;">
          <button class="quiz-option btn" data-val="A" onclick="submitLabQuiz(3,'A','B','next-lab4-btn')">A) Only data-in-transit is at risk — stored data is safe</button>
          <button class="quiz-option btn" data-val="B" onclick="submitLabQuiz(3,'B','B','next-lab4-btn')">B) The RSA signature can be forged — attacker creates valid-looking certs for any domain</button>
          <button class="quiz-option btn" data-val="C" onclick="submitLabQuiz(3,'C','B','next-lab4-btn')">C) The certificate expires immediately upon key compromise</button>
          <button class="quiz-option btn" data-val="D" onclick="submitLabQuiz(3,'D','B','next-lab4-btn')">D) AES session keys are broken directly</button>
        </div>
        <div id="quiz-feedback" style="display:none;margin-top:12px;"></div>
      </div>
      <div style="margin-top:1rem;">
        <button id="next-lab4-btn" class="btn btn-primary" style="display:none;" onclick="renderLab(4)">Next: Post-Quantum Cryptography →</button>
      </div>
    </div>`;
}

function showCert(type) {
  const data = CERT_DATA[type];
  if (!data) return;

  // Update active node styling
  ['root', 'intermediate', 'leaf'].forEach(t => {
    const node = document.getElementById(`cert-node-${t}`);
    if (node) node.classList.toggle('cert-active', t === type);
  });

  const panel = document.getElementById('cert-detail-panel');
  if (panel) {
    panel.style.display = 'block';
    panel.style.borderColor = data.color;
    panel.innerHTML = `<span style="color:${data.color};font-weight:700;">=== ${data.label} ===</span>\n${esc(data.pem)}`;
  }
}

function showCertError(type) {
  const err = CERT_ERRORS[type];
  if (!err) return;
  const panel = document.getElementById('cert-error-panel');
  if (panel) {
    panel.style.display = 'block';
    panel.innerHTML = `<div style="background:rgba(244,63,94,.07);border:1px solid ${err.color};border-radius:8px;padding:1rem;">
      <div class="text-xs" style="color:${err.color};font-weight:700;margin-bottom:8px;">⚠ ${err.title}</div>
      <pre style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);white-space:pre-wrap;line-height:1.6;margin:0;">${err.body}</pre>
    </div>`;
  }
}

/* ═══════════════════════════════════════
   LAB 5 — Post-Quantum Cryptography
═══════════════════════════════════════ */
function renderLab5(main) {
  main.innerHTML = `
    <div class="card mb-4 animate-fade-in">
      <div class="card-header">
        <span class="card-icon">⚛</span>
        <div>
          <div class="card-title">Lab 5 of 5 — Post-Quantum Cryptography</div>
          <div class="card-sub">Synthesis · Which algorithms survive · 20 pts</div>
        </div>
      </div>

      <div class="text-sm text-muted mb-4" style="line-height:1.6;background:var(--bg-primary);border-radius:8px;padding:1rem;">
        You've now seen every major cryptographic primitive — symmetric encryption, asymmetric encryption,
        hashing, and certificates. This lab brings it all together: which algorithms are safe against
        a quantum computer, which are broken, and what to use instead.
      </div>

      <!-- Algorithm Threat Matrix -->
      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Algorithm Threat Matrix</div>
      <div style="overflow-x:auto;margin-bottom:1.25rem;">
        <table class="threat-matrix" style="width:100%;">
          <thead>
            <tr>
              <th>Algorithm</th>
              <th>Classical Security</th>
              <th>Quantum Security</th>
              <th>Status</th>
              <th>PQC Replacement</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td class="font-mono text-xs">MD5</td>
              <td><span class="quantum-vuln">❌ Broken</span></td>
              <td><span class="quantum-vuln">❌ Broken</span></td>
              <td class="text-xs" style="color:var(--critical);font-weight:600;">DO NOT USE</td>
              <td class="text-xs">—</td>
            </tr>
            <tr>
              <td class="font-mono text-xs">AES-128</td>
              <td><span class="quantum-safe">✅ 128-bit</span></td>
              <td><span class="quantum-vuln">⚠ 64-bit</span></td>
              <td class="text-xs" style="color:var(--high);font-weight:600;">CAUTION</td>
              <td class="text-xs">AES-256</td>
            </tr>
            <tr>
              <td class="font-mono text-xs">AES-256</td>
              <td><span class="quantum-safe">✅ 256-bit</span></td>
              <td><span class="quantum-safe">✅ 128-bit</span></td>
              <td class="text-xs" style="color:var(--ok);font-weight:600;">SAFE</td>
              <td class="text-xs">Not needed</td>
            </tr>
            <tr>
              <td class="font-mono text-xs">RSA-2048</td>
              <td><span class="quantum-safe">✅ 112-bit</span></td>
              <td><span class="quantum-vuln">❌ ~8 hours</span></td>
              <td class="text-xs" style="color:var(--critical);font-weight:600;">VULNERABLE</td>
              <td class="text-xs">ML-KEM (FIPS 203)</td>
            </tr>
            <tr>
              <td class="font-mono text-xs">ECC P-256</td>
              <td><span class="quantum-safe">✅ 128-bit</span></td>
              <td><span class="quantum-vuln">❌ Broken</span></td>
              <td class="text-xs" style="color:var(--critical);font-weight:600;">VULNERABLE</td>
              <td class="text-xs">ML-KEM (FIPS 203)</td>
            </tr>
            <tr>
              <td class="font-mono text-xs">SHA-256</td>
              <td><span class="quantum-safe">✅ 256-bit</span></td>
              <td><span class="quantum-warn">⚠ 128-bit</span></td>
              <td class="text-xs" style="color:var(--medium);font-weight:600;">ADEQUATE</td>
              <td class="text-xs">SHA-384 / SHA-512</td>
            </tr>
            <tr>
              <td class="font-mono text-xs">SHA-512</td>
              <td><span class="quantum-safe">✅ 512-bit</span></td>
              <td><span class="quantum-safe">✅ 256-bit</span></td>
              <td class="text-xs" style="color:var(--ok);font-weight:600;">SAFE</td>
              <td class="text-xs">Not needed</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- HNDL Timeline -->
      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">HNDL Threat Timeline</div>
      <div style="background:var(--bg-primary);border-radius:8px;padding:1.25rem;margin-bottom:1.25rem;">
        <div class="hndl-timeline">
          <div class="hndl-marker" style="left:0%;">
            <div class="hndl-dot" style="background:var(--ok);"></div>
            <div class="hndl-year">TODAY 2026</div>
            <div class="hndl-label">Adversaries recording<br>RSA-encrypted traffic</div>
          </div>
          <div class="hndl-marker" style="left:33%;">
            <div class="hndl-dot" style="background:var(--medium);"></div>
            <div class="hndl-year">~2031</div>
            <div class="hndl-label">Data classified today<br>still needs protection</div>
          </div>
          <div class="hndl-marker" style="left:60%;">
            <div class="hndl-dot" style="background:var(--high);"></div>
            <div class="hndl-year">Q-DAY ~2033–36?</div>
            <div class="hndl-label">Fault-tolerant quantum<br>computer viable</div>
          </div>
          <div class="hndl-marker" style="left:100%;">
            <div class="hndl-dot" style="background:var(--critical);"></div>
            <div class="hndl-year">~2036+</div>
            <div class="hndl-label">All stored RSA traffic<br>decryptable retroactively</div>
          </div>
        </div>
        <div class="text-xs text-muted mt-2" style="line-height:1.6;">
          If your data must stay secret past Q-Day, it must be encrypted with PQC algorithms <strong>today</strong>.
          There is no retroactive fix for already-recorded ciphertext.
        </div>
      </div>

      <!-- NIST PQC Standards -->
      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">NIST PQC Standards (2024)</div>
      <div class="grid-3 mb-4">
        <div class="pqc-card">
          <div class="pqc-card-name">ML-KEM</div>
          <div class="pqc-card-fips">FIPS 203</div>
          <div class="pqc-card-body">Formerly CRYSTALS-Kyber. Replaces RSA and ECDH for <strong>key exchange</strong>. Lattice-based. Fast, compact key sizes.</div>
        </div>
        <div class="pqc-card">
          <div class="pqc-card-name">ML-DSA</div>
          <div class="pqc-card-fips">FIPS 204</div>
          <div class="pqc-card-body">Formerly CRYSTALS-Dilithium. Replaces RSA and ECDSA for <strong>digital signatures</strong> (e.g., in certificates).</div>
        </div>
        <div class="pqc-card">
          <div class="pqc-card-name">SLH-DSA</div>
          <div class="pqc-card-fips">FIPS 205</div>
          <div class="pqc-card-body">Formerly SPHINCS+. Hash-based signature scheme. More conservative assumptions — backup if lattice math is broken.</div>
        </div>
      </div>

      <!-- Cross-link -->
      <div style="background:rgba(94,234,212,.05);border:1px solid rgba(94,234,212,.2);border-radius:8px;padding:.85rem 1rem;margin-bottom:1.25rem;">
        <div class="text-xs" style="color:var(--teal);font-weight:700;margin-bottom:4px;">🔗 Live in the Exercise</div>
        <div class="text-xs text-muted" style="line-height:1.6;">
          The live log in your <a href="index.html" style="color:var(--teal);">Command Center</a> shows:
          <code class="font-mono" style="color:var(--ok);">[INFO] Post-quantum TLS negotiation successful — client: SEC-VAULT-01</code><br>
          That's ML-KEM handling key exchange for a connection that previously used RSA.
          Your organization is already transitioning — but legacy systems remain vulnerable until fully migrated.
        </div>
      </div>

      <!-- Quiz -->
      <div id="lab5-quiz">
        <div class="text-xs text-muted mb-3" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Final Quiz — 20 pts</div>
        <div class="text-sm" style="font-weight:600;color:var(--text-primary);margin-bottom:12px;">
          Your organization uses RSA-2048 to encrypt 20-year classified contracts. HNDL is a known threat.
          Which NIST PQC algorithm should replace your key exchange?
        </div>
        <div style="display:grid;gap:8px;">
          <button class="quiz-option btn" data-val="A" onclick="submitLab5Quiz('A')">A) SLH-DSA (FIPS 205) — hash-based signatures</button>
          <button class="quiz-option btn" data-val="B" onclick="submitLab5Quiz('B')">B) ML-DSA (FIPS 204) — lattice-based signatures</button>
          <button class="quiz-option btn" data-val="C" onclick="submitLab5Quiz('C')">C) ML-KEM (FIPS 203) — lattice-based key encapsulation</button>
          <button class="quiz-option btn" data-val="D" onclick="submitLab5Quiz('D')">D) AES-256 — it's already quantum-resistant, no change needed</button>
        </div>
        <div id="quiz-feedback" style="display:none;margin-top:12px;"></div>
      </div>
      <div style="margin-top:1rem;">
        <button id="next-lab5-btn" class="btn btn-primary" style="display:none;" onclick="completeCrypto()">View Final Results →</button>
      </div>
    </div>`;
}

function submitLab5Quiz(selected) {
  submitLabQuiz(4, selected, 'C', 'next-lab5-btn');
}

/* ═══════════════════════════════════════
   Complete & Debrief
═══════════════════════════════════════ */
function completeCrypto() {
  const p = SENTINEL.getProgress();
  p.cryptoScore     = totalScore;
  p.cryptoCompleted = true;
  SENTINEL.saveProgress(p);
  renderLab(5); // shows debrief
}

function showFinalDebrief() {
  const main = document.getElementById('crypto-main');
  if (!main) return;

  const elapsed = startTime ? Math.round((Date.now() - startTime) / 1000) : 0;
  const mins = Math.floor(elapsed / 60);
  const secs = elapsed % 60;
  const timeStr = `${mins}m ${secs}s`;
  const pct = Math.round((totalScore / 100) * 100);
  const label = SENTINEL.scoreLabel ? SENTINEL.scoreLabel(pct) : '';

  const labRows = CRYPTO_LABS.map((lab, i) => {
    const s = labScores[i] ?? 0;
    const icon = s > 0 ? '✓' : '✗';
    const color = s > 0 ? 'var(--ok)' : 'var(--critical)';
    return `<tr>
      <td class="text-xs" style="padding:6px 8px;">${lab.icon} ${lab.title}</td>
      <td class="text-xs font-mono" style="color:${color};padding:6px 8px;text-align:center;">${icon} ${s} pts</td>
    </tr>`;
  }).join('');

  const scoreClass = SENTINEL.scoreClass ? SENTINEL.scoreClass(pct) : '';

  main.innerHTML = `
    <div class="card mb-4 animate-fade-in">
      <div class="card-header">
        <span class="card-icon">🏁</span>
        <div>
          <div class="card-title">Cryptography Playground — Complete</div>
          <div class="card-sub">Security+ Domain 1 · General Security Concepts</div>
        </div>
      </div>

      <div style="text-align:center;padding:1.5rem 0;border-bottom:1px solid var(--line);margin-bottom:1.25rem;">
        <div class="stat-big ${scoreClass}" style="font-size:3rem;">${totalScore}</div>
        <div class="text-sm text-muted">out of 100 pts</div>
        <div style="margin-top:8px;font-size:1rem;font-weight:600;color:var(--teal);">${label}</div>
        <div class="text-xs text-muted mt-1">Completed in ${timeStr}</div>
      </div>

      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Lab Breakdown</div>
      <table style="width:100%;border-collapse:collapse;margin-bottom:1.25rem;">
        <thead>
          <tr style="border-bottom:1px solid var(--line);">
            <th class="text-xs text-muted" style="text-align:left;padding:4px 8px;font-weight:700;">Lab</th>
            <th class="text-xs text-muted" style="padding:4px 8px;font-weight:700;text-align:center;">Score</th>
          </tr>
        </thead>
        <tbody>${labRows}</tbody>
        <tfoot>
          <tr style="border-top:1px solid var(--line);">
            <td class="text-xs" style="padding:6px 8px;font-weight:700;">Total</td>
            <td class="text-xs font-mono" style="padding:6px 8px;text-align:center;color:var(--teal);font-weight:700;">${totalScore} / 100</td>
          </tr>
        </tfoot>
      </table>

      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">What you practiced (Sec+ Domain 1)</div>
      <div style="background:var(--bg-primary);border-radius:8px;padding:1rem;margin-bottom:1.25rem;">
        <div style="display:grid;gap:6px;">
          ${['Symmetric vs asymmetric encryption — when to use each',
             'Why AES-256 is quantum-resistant (Grover\'s algorithm)',
             'How RSA key exchange works — and why it fails against Shor\'s algorithm',
             'HNDL (Harvest Now, Decrypt Later) — the retroactive quantum threat',
             'Cryptographic hashing and the avalanche effect',
             'Why MD5 is broken — rainbow tables and unsalted hashes',
             'PKI trust chains — Root CA → Intermediate CA → Leaf certificate',
             'NIST PQC standards: ML-KEM, ML-DSA, SLH-DSA (FIPS 203/204/205)']
            .map(s => `<div class="text-xs" style="display:flex;gap:8px;"><span style="color:var(--ok);">✓</span><span>${s}</span></div>`)
            .join('')}
        </div>
      </div>

      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <a href="risk.html" class="btn btn-primary" style="font-size:13px;">← Risk Register</a>
        <button class="btn" style="font-size:13px;" onclick="resetCrypto()">Retry Cryptography</button>
        <a href="index.html" class="btn" style="font-size:13px;">Command Center</a>
      </div>
    </div>`;

  updateRightPanel();
  updateProgressBar();
}

function resetCrypto() {
  labScores   = [null, null, null, null, null];
  totalScore  = 0;
  currentLab  = 0;
  startTime   = Date.now();
  aesKey      = null;
  rsaKeyPair  = null;
  aesLastCipherBuf = null;
  aesLastIV        = null;
  md5LookupCount   = 0;
  updateProgressBar();
  renderLab(0);
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', initCrypto);
