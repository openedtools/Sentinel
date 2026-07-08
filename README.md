# SENTINEL — AI-Enabled SOC Simulator

**Simulated Environment for Network Training, Intelligence, and Logging**

A browser-based SOC simulator for international cybersecurity students learning AI-enabled SIEM and SOC workflows. Modeled after Cortex XSIAM. No install, no login, runs entirely in-browser.

---

## Modules

| Module | File | Description |
|--------|------|-------------|
| Command Center | `index.html` | XSIAM-style dashboard — alert flows, MITRE breakdown, data ingestion, and a progress-aware **Mission Path** that guides students to their next step |
| **Live Fire Exercise** ◎ | `livefire.html` | **Capstone.** A five-stage AI-driven promptware attack that advances on a clock. Authorize scoped, reversible containment at each timed decision gate using the Standing Authority Matrix, then certify. |
| Alert Triage | `triage.html` | Classify 20 real alerts; AI reveals ground truth after each |
| Incident Investigation | `investigate.html` | 5 full scenarios with attack timelines and decision points |
| Remediation Lab | `remediate.html` | Live network topology — quarantine, block IPs, manage ports |
| Scenario Library | `scenarios.html` | Progress tracker and quick-launch for all scenarios |

### Live Fire Exercise — "Operation JadePuffer"

The flagship assessment. The student is the on-shift SOC analyst at a hospital
running an AI clinical assistant wired to email, a patient-records RAG index,
and internal tools over MCP. A single malicious instruction kicks off the full
**promptware kill chain**, and the attack does not wait for human-speed analysis:

1. **ClickFix** — initial access via paste-and-run PowerShell (no file to scan)
2. **Indirect prompt injection** — a poisoned "note" plants promptware in the AI's memory
3. **MCP tool recon** — the agent enumerates its reachable tools and finds an over-scoped NHI token
4. **RAG poisoning / NHI abuse** — the knowledge base is turned into an exfiltration channel
5. **Agentic ransomware (JadePuffer)** — autonomous, self-pacing, multi-host encryption

At each stage a **timed decision gate** asks the student to authorize a response
using the **Standing Authority Matrix** (Green = scoped & reversible, Amber =
analyst approval, Red = incident-commander only). The doctrine rewarded
throughout: shift detection left (Identity/Network, not just EDR), govern
Non-Human Identities with Zero Standing Privilege, prefer reversible containment
(freeze a RAG index, drop an agent to proposal-only mode, rotate an OAuth token,
isolate one endpoint), and meet machine-speed threats with pre-authorized
automation. A concept check follows each gate, and a five-question
**certification exam** issues a final rank (SOC Analyst → Incident Commander).

## Scenarios

1. 🦠 **Polymorphic Payload** — AI malware evades signature-based AV
2. 📧 **The Email Summarizer** — Prompt injection / zero-click attack
3. 🎭 **Ghost Wire Transfer** — Deepfake CEO fraud ($25M)
4. 🤖 **Autonomous Recon** — Agentic AI full kill chain
5. 📦 **Tainted Update** — SolarWinds-style supply chain attack

---

## Deploy to GitHub Pages (3 steps)

```bash
# 1. Create a new repo on github.com, then:
git init
git add .
git commit -m "Initial SENTINEL deployment"
git remote add origin https://github.com/YOUR_USERNAME/sentinel-soc-sim.git
git push -u origin main

# 2. On GitHub: Settings → Pages → Source: Deploy from branch → main → / (root) → Save

# 3. Your URL will be:
#    https://YOUR_USERNAME.github.io/sentinel-soc-sim
```

Share that URL with students — works on any browser, no install required.

## Run Locally

Just open `index.html` in any browser. All data files are loaded via `fetch()` so you need a local server for the JSON files:

```bash
# Python (simplest)
python -m http.server 8080
# then open http://localhost:8080

# Node (if installed)
npx serve .
```

---

*SENTINEL · International Student Edition · AI-Enabled SIEM/SOC · All data simulated for training purposes*

