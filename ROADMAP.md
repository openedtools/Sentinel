# SENTINEL — Development Roadmap

Live site: https://openedtools.github.io/Sentinel  
Repo: openedtools/Sentinel  
Stack: Vanilla HTML/CSS/JS · No backend · localStorage for progress · Static site (GitHub Pages)

---

## Completed Modules (8 total)

| # | Module | File | Sec+ Domain | Time |
|---|--------|------|-------------|------|
| 1 | Command Center (dashboard) | index.html | — | — |
| 2 | Alert Triage | triage.html | Domain 4 (Ops) | ~15 min |
| 3 | Incident Investigation (5 scenarios) | investigate.html | Domain 2 & 4 | ~25 min |
| 4 | Remediation Lab | remediate.html | Domain 3 & 4 | ~20 min |
| 5 | Scenario Library | scenarios.html | — | — |
| 6 | Log Decoding Challenge | logs.html | Domain 2 & 4 | ~30 min |
| 7 | Vulnerability Prioritization Lab | vulns.html | Domain 2 | ~25 min |
| 8 | Risk Register Simulator | risk.html | Domain 5 | ~30 min |

---

## Priority 1 — Activate Grayed-Out Nav Sections

These four sections exist in the sidebar as disabled placeholders (opacity 0.38, pointer-events none).
They are under the OPERATIONS and ASSETS nav groups in js/main.js → renderShell().
Each should be a simulated XSIAM-style read page + at least one interactive training element.

### Detection & Threat Intel (icon: ◎)
File to create: `detection.html` / `js/detection.js`
- IOC (Indicator of Compromise) browser — searchable table of IPs, hashes, domains, CVEs
- Threat actor profiles (3–4 actors active in the exercise scenario)
- Detection rule library — show existing YARA/Sigma-style rules with match logic explained
- **Training element**: IOC Matching Challenge — given a set of alerts, drag IOCs to the alert they
  explain. Teaches: what IOCs are, how threat intel enriches alert context.

### Assets (icon: ▤)
File to create: `assets.html` / `js/assets.js`
- Simulated asset inventory: ~30 assets with type, owner, criticality, OS, last-seen, patch status
- Filterable/sortable table (no backend — filter in JS)
- Asset detail card: shows open vulnerabilities, recent alerts, assigned incidents
- **Training element**: Asset Classification Exercise — given 10 assets, students assign
  criticality (Critical/High/Medium/Low) based on data sensitivity and business function.
  Connects to risk register concepts (asset value drives impact score).

### Endpoints (icon: ▢)
File to create: `endpoints.html` / `js/endpoints.js`
- EDR-style endpoint list: hostname, user, OS, last check-in, AV status, patch compliance %
- Color-coded health: green (healthy), yellow (stale/at-risk), red (compromised/quarantined)
- Endpoint detail: process tree, recent alerts, network connections
- **Training element**: Endpoint Triage Drill — 8 endpoints shown with EDR telemetry snippets
  (running processes, network connections, file events). Student marks each as Clean / Suspicious /
  Compromised. Teaches: what EDR data looks like, indicators of living-off-the-land attacks.

### Identity (icon: ⚷)
File to create: `identity.html` / `js/identity.js`
- User account list: name, role, MFA status, last login, privilege level, account age
- Highlight risky patterns: never-logged-in admins, MFA not enrolled, stale accounts
- Privileged account spotlight: Domain Admins, Service Accounts
- **Training element**: Identity Risk Audit — given 12 accounts with attributes, students flag
  which ones violate least-privilege, need MFA enforcement, or should be disabled.
  Teaches: identity hygiene, PAM concepts, insider threat indicators (Sec+ Domain 1 & 2).

---

## Priority 2 — New Training Modules (Security+ Coverage Gaps)

### Cryptography Playground
File: `crypto.html` / `js/crypto.js`  
Sec+ Domain: 1 — General Security Concepts (12% of exam)  
Uses: Web Crypto API (window.crypto.subtle) — no backend needed  
- **Symmetric vs Asymmetric**: student encrypts a message with a public key, sees they can't
  decrypt without the private key. Then encrypt/decrypt with a shared AES key.
- **Hashing demo**: type any text, see SHA-256 output update live. Change one character,
  see the hash completely change (avalanche effect). Compare MD5 vs SHA-256 length/speed.
- **Hash cracking sim**: given 5 common passwords hashed with MD5, student matches them to
  a rainbow table — teaches why MD5 is broken for passwords.
- **PKI chain**: interactive cert chain diagram — Root CA → Intermediate CA → Leaf cert.
  Student inspects a PEM cert (decoded in-browser) and identifies expiry, CN, SANs.
- **Scoring**: quiz questions after each section — 4 sections × ~25 pts = 100 pts max

### Phishing Header Forensics Lab
File: `phishing.html` / `js/phishing.js`  
Sec+ Domain: 2 — Threats, Vulnerabilities & Mitigations  
- 5 raw email samples (headers + body) — student must identify malicious indicators
- Interactive header parser: student clicks on header fields to annotate them
- Checks: SPF pass/fail, DKIM signature, DMARC policy, display-name vs actual From mismatch,
  reply-to redirect, suspicious link hover (URL shown vs displayed text), urgency language
- Each sample has 3–5 hidden indicators to find
- Teaches: what a real phishing email looks like at the protocol level

### Compliance Control Mapper
File: `compliance.html` / `js/compliance.js`  
Sec+ Domain: 5 — Security Program Management (exam heavily tests compliance frameworks)  
- 3 scenarios: healthcare (HIPAA), payment (PCI-DSS), federal contractor (NIST 800-53)
- Given a business scenario + a set of 10 security controls, student drags each control to
  the correct compliance requirement it satisfies
- Speed-matching format with a timer (adults respond well to competitive pressure)
- Teaches: HIPAA safeguards, PCI-DSS requirements, NIST controls — by name, not by rote

### Threat Hunt Mode (Dashboard Enhancement)
Enhancement to: index.html / js/dashboard.js  
Sec+ Domain: 4 — Security Operations  
- Add a "Hunt Mode" toggle button to the dashboard Command Center
- Flips the dashboard from passive observation to active investigation mode
- Student is given a hypothesis ("Suspected beaconing on port 443 at regular intervals")
- Interactive log filter panel: filter live event log by source, time range, keyword
- Student must confirm or deny the hypothesis by finding/not-finding supporting evidence
- Teaches: proactive threat hunting vs reactive alerting — a growing Security+ topic

---

## Priority 3 — Quality of Life

- **Instructor Dashboard**: read-only view showing all students' progress and scores.
  Could be a separate `instructor.html` that reads from a shared URL parameter
  (e.g., students paste score codes, instructor page decodes and renders a leaderboard).
  No backend needed — score codes contain all the data.

- **Scenarios page**: update scenarios.html to list the 3 new Security+ modules
  (Log Analysis, Vuln Prioritization, Risk Register) alongside the 5 SIEM scenarios.

- **Mobile layout pass**: the grid layouts use fixed columns that break below ~900px.
  A single CSS media query pass would make the site usable on tablets for students
  without laptops.

- **Print/export**: a "Print Score Card" button that generates a clean summary of
  all completed modules — useful for in-person training where instructors collect paper.

---

## Architecture Notes (for new thread context)

- All pages follow the same shell pattern:
  `<div id="sb"></div>` (sidebar) + `<div class="main"><div id="topbar-mount"></div>...`
- `js/main.js` injects sidebar + topbar via `SENTINEL.renderShell()` on DOMContentLoaded
- New pages need: their filename registered in `SENTINEL._getPageId()`,
  a nav entry in `PAGE_META` inside `renderShell()`, and a nav item in the sidebar HTML
- Progress stored in localStorage key `sentinel_progress` as JSON
- To add a new module's score: add `xyzScore` and `xyzCompleted` to the default progress
  object in `getProgress()`, save via `SENTINEL.saveProgress(p)`, and add to `generateScoreCode()`
- CSS variables: `--teal` (#5eead4), `--critical` (#f43f5e), `--high` (#fb923c),
  `--medium` (#facc15), `--low` (#38bdf8), `--ok` (#4ade80)
- Fonts: Inter (UI) + JetBrains Mono (logs/code) — loaded from Google Fonts in style.css
