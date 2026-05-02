# SENTINEL — Development Roadmap

Live site: https://openedtools.github.io/Sentinel  
Repo: openedtools/Sentinel  
Stack: Vanilla HTML/CSS/JS · No backend · localStorage for progress · Static site (GitHub Pages)

---

## Completed Modules (15 total)

| # | Module | File | Domain / Topic | Pts |
|---|--------|------|----------------|-----|
| 1 | Command Center (dashboard) | index.html | — | — |
| 2 | Alert Triage | triage.html | Sec+ Domain 4 (Ops) | 100 |
| 3 | Incident Investigation (5 scenarios) | investigate.html | Sec+ Domain 2 & 4 | 100 |
| 4 | Remediation Lab | remediate.html | Sec+ Domain 3 & 4 | 100 |
| 5 | Scenario Library | scenarios.html | — | — |
| 6 | Log Decoding Challenge | logs.html | Sec+ Domain 2 & 4 | 100 |
| 7 | Vulnerability Prioritization Lab | vulns.html | Sec+ Domain 2 | 100 |
| 8 | Risk Register Simulator | risk.html | Sec+ Domain 5 | 100 |
| 9 | Detection & Threat Intel | detection.html | Sec+ Domain 4 | 60 |
| 10 | Assets | assets.html | Sec+ Domain 2 & 5 | 50 |
| 11 | Endpoints | endpoints.html | Sec+ Domain 4 | 80 |
| 12 | Identity | identity.html | Sec+ Domain 1 & 2 | 60 |
| 13 | Cryptography Playground | crypto.html | Sec+ Domain 1 | 100 |
| 14 | Glossary / Term Tooltips ✅ | js/glossary.js (site-wide) | ESL support | — |
| 15 | Phishing Header Forensics Lab ✅ | phishing.html | Sec+ Domain 2 | 100 |

**Current max score: ~1150 pts across 12 scored modules.**

### Score Code Format (updated)
`SENTINEL·Name·DateStr·TR{n}·SCN{n}/5·LG{n}·VL{n}·RK{n}·DT{n}·AS{n}·EP{n}·ID{n}·CR{n}·PH{n}·{total}PTS`

---

## Teaching Context (informs all future work)

SENTINEL is used live in class by international students — many English is a second language,
many have no prior IT background. Every module should follow this three-layer pattern:

1. **Analogy card first** — plain-English metaphor before any jargon
2. **Visual/interactive demo** — the concept becomes visceral before the quiz
3. **Jargon locked** — technical terms only appear *after* the student has experienced the concept

Cross-cutting theme running through all content: **AI-enabled attack + defense**, and how
**quantum computing threatens current cryptography** (HNDL, Shor's, Grover's, PQC transition).

---

## Priority 1 — Security+ Coverage Gaps (New Training Modules)

### ✅ DONE — Phishing Header Forensics Lab
File: `phishing.html` / `js/phishing.js` · **100 pts · Sec+ Domain 2**

5 progressively harder email samples covering: display name spoofing, Reply-To redirect (BEC),
SPF/DKIM/DMARC authentication deep-dive, lookalike/subdomain domain tricks, and AI-generated
phishing (WormGPT) that defeats content filtering. Students click Examine buttons to surface
forensic findings; quiz unlocks after all fields examined. Scoring: 5 × 20 pts = 100 pts.

---

### NEXT — Compliance Control Mapper
File: `compliance.html` / `js/compliance.js`  
Sec+ Domain: 5 — Security Program Management  
**Teaching hook for international students:** connect abstract framework names to real business
scenarios. HIPAA = hospital, PCI-DSS = credit card swipe, NIST = government contract.

- 3 scenarios: healthcare (HIPAA), payment (PCI-DSS), federal contractor (NIST 800-53)
- Click-to-assign: given a pool of 10 controls, student maps each to the right framework requirement
- Progressive reveal: each correct match shows why that control satisfies that requirement
- Teaches: HIPAA safeguards, PCI-DSS requirements, NIST controls — by recognition, not by rote
- **Scoring:** 3 scenarios × ~33 pts = 100 pts

**Architecture notes for next thread:**
- Follow the phishing.js pattern: data object → sequential scenarios → quiz per scenario → debrief
- Score code segment: `CO{n}` (e.g., CO100)
- Register in main.js: `complianceScore`, `complianceCompleted`, page id `compliance`
- Sidebar section: add under TRAINING after phishing

### Threat Hunt Mode (Dashboard Enhancement)
Enhancement to: index.html / js/dashboard.js  
Sec+ Domain: 4 — Security Operations  
**Teaching hook:** positions students as active hunters, not passive alarm-watchers — shifts mindset.

- "Hunt Mode" toggle button on Command Center
- Student receives a hypothesis (e.g., "Suspected beaconing on port 443 at regular intervals")
- Interactive log filter panel: filter live event log by source IP, time range, keyword
- Student must confirm or deny the hypothesis from the evidence
- Teaches: proactive threat hunting vs reactive alerting — growing Sec+ and real-world topic

---

## Priority 2 — Teaching Depth for International / Non-Technical Students

These aren't new pages — they're improvements to make existing content more accessible
to learners with no prior IT background or ESL learners reading under time pressure.

### ✅ DONE — Glossary / Term Tooltips
File: `js/glossary.js` (site-wide, loaded on all 14 HTML pages)

~65 security terms with plain-English definitions. Acronyms always show their full expansion
first in the tooltip (SIEM → "Security Information and Event Management" then the definition).
Auto-scans text nodes via TreeWalker on DOMContentLoaded; skips nav, buttons, code blocks.
Single delegated hover listener; tooltip positioned above the hovered term.

### Concept Map / Learning Path Overlay
- A "What does this teach me?" button on every module card (visible on scenarios.html and dashboard)
- Opens a modal showing: which Sec+ domain, which real-world job task, which other modules connect
- Simple SVG or CSS diagram showing module dependencies (Triage → Investigate → Remediate, etc.)
- **Benefit:** helps students understand *why* they're doing each exercise, not just *what*

### Translated Analogy Cards
- The analogy cards already exist in each module (e.g., "combination padlock" for AES)
- Add a language toggle (🌐) that swaps the analogy card text into Thai, Spanish, or French
- Store translations as a static JSON object — no backend needed
- Target languages chosen for DCOI audience (Thailand primary; others secondary)
- **Benefit:** when a concept is genuinely hard, reading it in your first language first unlocks it

---

## Priority 3 — Quality of Life

### Instructor Dashboard
File: `instructor.html`  
- Read-only view showing all students' progress and scores in a leaderboard
- Students paste their score code (`SENTINEL·Name·Date·TR90·…·CR80·510PTS`)
- Instructor page decodes all pasted codes and renders a comparison table
- No backend needed — score codes contain all the data
- Bonus: export to CSV for attendance/grade records

### Scenarios Page Update
- Update `scenarios.html` to list all 15 completed modules (currently only shows the original 5 SIEM scenarios)
- Add Detection, Assets, Endpoints, Identity, Cryptography, and Phishing Forensics
  to the module listing with correct Sec+ domain tags and time estimates

### Mobile / Tablet Layout Pass
- Grid layouts break below ~900px — a single CSS media query pass would fix tablets
- Especially important for international classroom settings where students may only have tablets

### Print / Export Score Card
- "Print Score Card" button that generates a clean summary of all completed modules
- Useful in-person where instructors collect paper evidence of completion

---

## Priority 4 — Advanced / Stretch Goals

### AI-Assisted Debrief Mode
- After completing any module, student can click "Ask the AI" to get a plain-English explanation
  of what they got wrong and why — powered by a call to the Claude API
- Requires a tiny serverless function (Cloudflare Worker or Netlify Function) as a proxy
- Would be transformative for self-paced learners outside of class

### Network Topology Visualizer
- Interactive node map of the simulated DCOI network (DC-01, FILE-SERVER-01, WS-004, etc.)
- Clicking a node shows its incidents, endpoints data, and recent logs
- Ties together the scattered references to hostnames across all modules
- Teaching value: students see the *network* not just isolated events

### Red Team vs Blue Team Mode
- Two-player version: one student plays attacker (chooses attack TTPs from a menu),
  the other plays defender (must detect and respond)
- Turn-based, text-driven, no graphics needed
- Teaching value: understanding attacker perspective is Sec+ Domain 2 core content
- Stretch: instructor runs one "attacker" screen projected to the class, teams compete

---

## Architecture Notes (for new thread context)

**Shell pattern** (all pages follow this):
```html
<div class="app">
  <div id="sb"></div>       <!-- sidebar injected by SENTINEL.renderShell() -->
  <div class="main">
    <div id="topbar-mount"></div>
    <!-- page content -->
  </div>
</div>
<script src="js/data.js"></script>
<script src="js/main.js"></script>
<script src="js/[page].js"></script>
```

**Registering a new page in `js/main.js`:**
1. `_getPageId()` — add `'page.html': 'pageid'` to the map
2. `getProgress()` — add `pageScore: 0, pageCompleted: false` to default object
3. `generateScoreCode()` — add `const seg = p.pageCompleted ? \`XX${score}\` : 'XX--';` and interpolate
4. `PAGE_META` inside `renderShell()` — add `pageid: { name, href, icon }`
5. Sidebar nav HTML inside `renderShell()` — add `${navItem(['pageid', PAGE_META.pageid])}`

**CSS design tokens:**
- `--teal` (#5eead4) — primary accent
- `--critical` (#f43f5e), `--high` (#fb923c), `--medium` (#facc15), `--low` (#38bdf8), `--ok` (#4ade80)
- `--bg-primary`, `--bg-2`, `--line`, `--line-strong`, `--text-primary`, `--text-muted`, `--text-dim`
- Fonts: Inter (UI) + JetBrains Mono (logs/code) — loaded from Google Fonts in style.css

**Key cross-references already in the codebase:**
- `js/data.js` line 248 — HNDL scenario with RSA-2048/DH-1024 downgrade explanation
- `js/main.js` line 201 — SEC-VAULT-01 post-quantum TLS log entry
- `js/main.js` line 167 — svc_backup_new Domain Admin creation (identity module)

**Score code format:**
`SENTINEL·Name·DateStr·TR{n}·SC{n}·LG{n}·VL{n}·RK{n}·DT{n}·AS{n}·EP{n}·ID{n}·CR{n}·{total}PTS`

**Progress stored in:** `localStorage` key `sentinel_progress` as JSON.
Save via `SENTINEL.saveProgress(p)`. Update score delta via `SENTINEL.updateScore(delta)`.

**Lab unlock pattern** (logs.js, risk.js, crypto.js):
- Sequential sections; completing the quiz reveals the next section / unlocks a Next button
- `submitLabQuiz(labIndex, selected, correct, nextBtnId)` pattern in crypto.js is cleanest — reuse it
