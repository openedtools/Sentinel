# SENTINEL — AI-Enabled SOC Simulator

**Simulated Environment for Network Training, Intelligence, and Logging**

A browser-based SOC simulator for the DCOI Thailand Day 3 course — *Introduction to AI-Enabled SIEMs and SOCs*. Modeled after Cortex XSIAM. No install, no login, runs entirely in-browser.

---

## Modules

| Module | File | Description |
|--------|------|-------------|
| Command Center | `index.html` | XSIAM-style dashboard — alert flows, MITRE breakdown, data ingestion |
| Alert Triage | `triage.html` | Classify 20 real alerts; AI reveals ground truth after each |
| Incident Investigation | `investigate.html` | 5 full scenarios with attack timelines and decision points |
| Remediation Lab | `remediate.html` | Live network topology — quarantine, block IPs, manage ports |
| Scenario Library | `scenarios.html` | Progress tracker and quick-launch for all scenarios |

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

*SENTINEL · DCOI Thailand · Day 3 — AI-Enabled SIEM/SOC · All data simulated for training purposes*
