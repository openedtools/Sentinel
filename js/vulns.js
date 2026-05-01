/* SENTINEL — Vulnerability Prioritization Lab */

/* ── Round data ── */
const VULN_ROUNDS = [
  {
    id: 1,
    org: 'State Government Agency',
    icon: '🏛',
    scenario: 'You are the CISO for a state government agency. A 2-hour maintenance window opens tonight. Your patching team can safely update 5 systems before the window closes. 8 vulnerabilities are pending. Prioritize wisely — unpatched critical systems will be exploited.',
    patchSlots: 5,
    cvssGuide: 'CVSS 9.0–10.0 = Critical · 7.0–8.9 = High · 4.0–6.9 = Medium',
    contextNote: 'This agency runs citizen-facing web services and stores voter registration data. Internet-facing systems are the highest-risk targets.',
    vulns: [
      {
        id: 'v1-1', cve: 'CVE-2024-48502', cvss: 10.0, severity: 'critical',
        title: 'Perimeter Firewall: Unauthenticated RCE',
        description: 'Unauthenticated remote code execution in the firewall management interface. An attacker on the internet can gain full OS-level control with no credentials required.',
        asset: 'Perimeter Firewall (NGFW-01)', internetFacing: true, exploitInWild: true, patchAvailable: true,
        priorityRank: 1,
        consequence: 'Attackers gained admin access to NGFW-01, modified routing rules, and created a persistent backdoor. All internal traffic was visible to the attacker.',
        tip: 'Internet-facing + CVSS 10.0 + active exploit = patch first, every time.'
      },
      {
        id: 'v1-2', cve: 'CVE-2024-31978', cvss: 9.8, severity: 'critical',
        title: 'VPN Gateway: Authentication Bypass',
        description: 'Complete authentication bypass in the SSL VPN gateway. Remote attackers can establish VPN sessions as any user without valid credentials, gaining full internal network access.',
        asset: 'SSL VPN Gateway (VPN-GW)', internetFacing: true, exploitInWild: true, patchAvailable: true,
        priorityRank: 2,
        consequence: 'Remote attackers created unauthorized VPN sessions and performed reconnaissance of the internal network for 6 days before detection.',
        tip: 'VPN gateways are the front door to your network. Authentication bypass = every insider threat from outside.'
      },
      {
        id: 'v1-3', cve: 'CVE-2024-22741', cvss: 9.4, severity: 'critical',
        title: 'Web Application Firewall: Session Token Leak',
        description: 'A timing side-channel allows remote attackers to derive valid session tokens for authenticated web application users, enabling session hijacking without any credentials.',
        asset: 'WAF Cluster (WAF-01/02)', internetFacing: true, exploitInWild: true, patchAvailable: true,
        priorityRank: 3,
        consequence: 'Three citizen portal accounts were hijacked. Attacker accessed voter registration records for 11,200 constituents.',
        tip: 'Session hijacking on an internet-facing service = immediate data breach risk.'
      },
      {
        id: 'v1-4', cve: 'CVE-2024-0519', cvss: 8.8, severity: 'high',
        title: 'Browser Engine: Zero-Day Memory Corruption',
        description: 'Out-of-bounds memory read in the Chromium V8 JavaScript engine. Actively exploited in the wild via malicious web pages. No user interaction required beyond visiting a page.',
        asset: 'All Workstations (847 endpoints)', internetFacing: false, exploitInWild: true, patchAvailable: true,
        priorityRank: 4,
        consequence: 'A spear-phishing email drove 3 employees to a malicious page. Attackers achieved code execution on their workstations and began lateral movement.',
        tip: 'Not internet-facing, but exploit-in-wild on 847 endpoints is a massive exposure surface.'
      },
      {
        id: 'v1-5', cve: 'CVE-2024-21412', cvss: 8.1, severity: 'high',
        title: 'Windows SmartScreen: Security Bypass',
        description: 'Maliciously crafted internet shortcut files (.url) bypass SmartScreen security warnings. Used in targeted attacks to execute malware delivered via phishing emails.',
        asset: 'All Workstations (847 endpoints)', internetFacing: false, exploitInWild: true, patchAvailable: true,
        priorityRank: 5,
        consequence: 'A phishing campaign using .url attachments bypassed AV on 12 workstations. Ransomware was deployed 48 hours later.',
        tip: 'Exploit-in-wild targeting your endpoint fleet via a known phishing vector — high priority despite lower CVSS.'
      },
      {
        id: 'v1-6', cve: 'CVE-2024-20353', cvss: 8.6, severity: 'high',
        title: 'Core Network Switch: Denial of Service',
        description: 'Malformed packet causes the core switch to crash and reload. An attacker on the network can cause repeated outages. No remote code execution possible.',
        asset: 'Core Network Switch (CORE-SW)', internetFacing: true, exploitInWild: false, patchAvailable: true,
        priorityRank: 6,
        consequence: 'Network availability was unaffected during the maintenance window. Patched in the next scheduled cycle with no incident.',
        tip: 'Internet-facing but no exploit in the wild and DoS-only (no RCE). Disruption risk, not a breach risk.'
      },
      {
        id: 'v1-7', cve: 'CVE-2023-38545', cvss: 9.8, severity: 'critical',
        title: 'HTTP Library: Heap Overflow (SOCKS5)',
        description: 'Heap-based buffer overflow in curl\'s SOCKS5 proxy handling. Could allow RCE if an attacker controls a SOCKS5 proxy server that the vulnerable application connects to.',
        asset: 'Application Servers (APP-01 through APP-04)', internetFacing: false, exploitInWild: false, patchAvailable: true,
        priorityRank: 7,
        consequence: 'No exploitation occurred. Patched during the next window. High CVSS but no in-wild exploit and requires attacker to control a proxy server the app connects to.',
        tip: 'CVSS 9.8 looks scary, but exploitation requires controlling an upstream server — no exploit in the wild yet.'
      },
      {
        id: 'v1-8', cve: 'CVE-2023-35628', cvss: 8.1, severity: 'high',
        title: 'Windows MSHTML: RCE via Calendar Invite',
        description: 'Remote code execution triggered by opening a malicious calendar invite. Requires Outlook to be open and the invite to be previewed — no click required.',
        asset: 'Internal Mail Servers + Workstations', internetFacing: false, exploitInWild: false, patchAvailable: true,
        priorityRank: 8,
        consequence: 'No exploitation occurred during the window. Zero-click RCE via email is a serious threat, but no active in-wild exploitation allowed later scheduling.',
        tip: 'Zero-click RCE via email is severe, but no in-wild exploit yet. Patch soon — just not tonight.'
      }
    ]
  },
  {
    id: 2,
    org: 'Regional Hospital System',
    icon: '🏥',
    scenario: 'You are the Security Director for a 400-bed regional hospital. The 3-hour maintenance window runs from 02:00–05:00, when elective procedures are paused. However, 2 systems (ICU monitoring and the PACS imaging server) cannot be patched during active patient care hours and must wait for a full maintenance weekend. Choose your top 5 from the remaining 8 patchable systems.',
    patchSlots: 5,
    cvssGuide: 'HIPAA requires breach notification within 60 days. Patient safety systems have zero tolerance for outages.',
    contextNote: 'ICU-MONITOR and PACS-SERVER are marked as unpatchable tonight — factor this into your plan. HIPAA fines for exposed PHI start at $100/record.',
    vulns: [
      {
        id: 'v2-1', cve: 'CVE-2024-50234', cvss: 10.0, severity: 'critical',
        title: 'EHR System: SQL Injection → Admin Takeover',
        description: 'Unauthenticated SQL injection in the Electronic Health Records login portal allows an attacker to bypass auth and retrieve all patient records. Affects 287,000 patient PHI records.',
        asset: 'EHR Portal (EHR-WEB)', internetFacing: true, exploitInWild: true, patchAvailable: true,
        priorityRank: 1,
        consequence: 'Ransomware group accessed the EHR portal and encrypted 287,000 patient records. Hospital paid $2.3M ransom and faced $4.1M HIPAA penalty.',
        tip: 'Internet-facing, PHI exposure, active exploit — this is the ransomware entry point. No question on priority.'
      },
      {
        id: 'v2-2', cve: 'CVE-2024-44719', cvss: 9.6, severity: 'critical',
        title: 'VPN: Credential Stuffing Amplifier',
        description: 'VPN gateway accepts unlimited auth attempts without lockout and leaks whether a username exists (valid/invalid distinction in error messages). Enables credential stuffing at scale.',
        asset: 'Remote Access VPN (VPN-HOSP)', internetFacing: true, exploitInWild: true, patchAvailable: true,
        priorityRank: 2,
        consequence: 'Attackers used leaked credentials from a prior healthcare data breach to authenticate 4 valid VPN accounts. Internal network was compromised.',
        tip: 'Healthcare credentials from prior breaches are actively traded. VPN without lockout is an open invitation.'
      },
      {
        id: 'v2-3', cve: 'CVE-2024-31102', cvss: 9.1, severity: 'critical',
        title: 'Pharmacy System: Privilege Escalation',
        description: 'Local privilege escalation in the pharmacy dispensing software. A low-privileged attacker (e.g., via a phishing foothold) can gain SYSTEM-level access to the pharmacy server, potentially modifying medication records.',
        asset: 'Pharmacy Server (PHARM-SRV)', internetFacing: false, exploitInWild: true, patchAvailable: true,
        priorityRank: 3,
        consequence: 'An attacker with workstation access escalated to the pharmacy server. Tampered medication records were caught by a pharmacist before dispensing.',
        tip: 'Patient safety risk — medication tampering has life-threatening consequences. Exploit-in-wild despite not being internet-facing.'
      },
      {
        id: 'v2-4', cve: 'CVE-2024-18847', cvss: 8.9, severity: 'high',
        title: 'Lab Results System: Authentication Bypass',
        description: 'Forged JWT tokens allow unauthenticated access to the laboratory information system. An attacker can read or modify lab results for any patient.',
        asset: 'Lab Information System (LIS-01)', internetFacing: true, exploitInWild: true, patchAvailable: true,
        priorityRank: 4,
        consequence: 'Modified lab results triggered two unnecessary procedures before the tampered records were detected. HIPAA violation issued.',
        tip: 'Falsified lab results are a patient safety issue AND a HIPAA violation. Internet-facing + exploit = patch tonight.'
      },
      {
        id: 'v2-5', cve: 'CVE-2024-52211', cvss: 8.5, severity: 'high',
        title: 'Workstations: Remote Code Execution via USB',
        description: 'Malicious USB drives auto-execute payloads via a Windows AutoRun vulnerability. Visitor kiosks and nurse stations with USB ports are particularly exposed.',
        asset: 'Clinical Workstations (320 endpoints)', internetFacing: false, exploitInWild: true, patchAvailable: true,
        priorityRank: 5,
        consequence: 'A "lost" USB drive left in the ER waiting room was plugged into a nurse station by a curious staff member. Ransomware spread to 40 workstations before containment.',
        tip: 'Physical access threat vector — hospitals have many visitors. Exploit-in-wild via a common attack makes this urgent.'
      },
      {
        id: 'v2-6', cve: 'CVE-2024-29145', cvss: 8.2, severity: 'high',
        title: 'ICU Patient Monitoring: Firmware RCE',
        description: 'Remote code execution in ICU vital-sign monitoring firmware. Could allow an attacker to alter displayed readings or disable alarms. CANNOT be patched during active patient monitoring — requires scheduled downtime.',
        asset: 'ICU Monitoring System (ICU-MONITOR)', internetFacing: false, exploitInWild: false, patchAvailable: false,
        unpatchableTonight: true,
        priorityRank: 99,
        consequence: 'Deferred to maintenance weekend. No exploitation occurred. Physical network segmentation was applied as a compensating control.',
        tip: 'CANNOT be patched tonight — patient safety constraint. Note as compensating control needed.'
      },
      {
        id: 'v2-7', cve: 'CVE-2024-11038', cvss: 7.8, severity: 'high',
        title: 'PACS Imaging Server: Path Traversal',
        description: 'Directory traversal vulnerability allowing unauthenticated access to DICOM image files. Patient X-rays, MRIs, and CT scans exposed without authentication.',
        asset: 'PACS Imaging Server (PACS-SRV)', internetFacing: false, exploitInWild: false, patchAvailable: false,
        unpatchableTonight: true,
        priorityRank: 99,
        consequence: 'Deferred to maintenance weekend — PACS downtime requires radiologist scheduling. Compensating control: blocked all external routing to PACS.',
        tip: 'CANNOT be patched tonight — requires coordinated radiology downtime. No in-wild exploit yet; compensating controls sufficient.'
      },
      {
        id: 'v2-8', cve: 'CVE-2023-40547', cvss: 8.3, severity: 'high',
        title: 'UEFI Bootloader: Secure Boot Bypass',
        description: 'Secure Boot bypass allowing unsigned bootloader code to execute at system startup. Enables persistent firmware implants that survive OS reinstalls.',
        asset: 'Administrative Servers (ADM-01/02)', internetFacing: false, exploitInWild: false, patchAvailable: true,
        priorityRank: 6,
        consequence: 'No exploitation occurred. Patched in a subsequent window. No in-wild exploit made this lower priority than patient-safety systems.',
        tip: 'Serious but no in-wild exploit and requires local access. Patient-safety vulnerabilities take priority tonight.'
      }
    ]
  },
  {
    id: 3,
    org: 'Defense Contractor (Classified Programs)',
    icon: '🛡',
    scenario: 'You are the ISSO (Information Systems Security Officer) for a defense contractor supporting classified programs. You have a 4-hour authorized maintenance window and can patch 5 systems. Two networks exist: NIPR (unclassified, internet-connected) and SIPR (classified, air-gapped). A supply chain alert has flagged one third-party software package. Prioritize carefully — DISA STIG compliance is mandatory.',
    patchSlots: 5,
    cvssGuide: 'DISA STIGs categorize: CAT I = Critical (patch immediately) · CAT II = High · CAT III = Medium',
    contextNote: 'NIPR systems face internet threats. SIPR systems are air-gapped but still need patches for insider threat scenarios. Supply chain integrity is a top concern under Executive Order 14028.',
    vulns: [
      {
        id: 'v3-1', cve: 'CVE-2024-60011', cvss: 10.0, severity: 'critical',
        title: 'NIPR Boundary Firewall: RCE (CAT I STIG)',
        description: 'Unauthenticated remote code execution in the NIPR perimeter firewall. Exploitation gives an attacker full control of the boundary device, enabling traffic inspection, modification, and NIPR network access.',
        asset: 'NIPR Perimeter Firewall (NIPR-FW)', internetFacing: true, exploitInWild: true, patchAvailable: true,
        priorityRank: 1,
        consequence: 'State-sponsored actors exploited the firewall to gain NIPR network access. Lateral movement toward SIPR boundary attempted but blocked by network segmentation.',
        tip: 'Boundary device RCE with active exploit = DISA CAT I. The gateway between internet and your classified network must be first.'
      },
      {
        id: 'v3-2', cve: 'CVE-2024-55318', cvss: 9.8, severity: 'critical',
        title: 'Supply Chain: Backdoored Build Tool',
        description: 'A widely-used internal build pipeline tool was found to contain a backdoor in versions 3.1.0–3.4.2. The backdoor exfiltrates source code and build artifacts to an attacker-controlled server. Identified via CISA supply chain alert.',
        asset: 'CI/CD Pipeline Servers (BUILD-01/02/03)', internetFacing: false, exploitInWild: true, patchAvailable: true,
        priorityRank: 2,
        consequence: 'Source code for three classified programs was exfiltrated to an external server before the supply chain compromise was detected. SolarWinds-class incident.',
        tip: 'Supply chain compromise actively exfiltrating classified source code. EO 14028 mandates immediate response. No CVSS score fully captures the strategic damage.'
      },
      {
        id: 'v3-3', cve: 'CVE-2024-47209', cvss: 9.3, severity: 'critical',
        title: 'Identity Provider: Token Forgery (CAT I STIG)',
        description: 'Cryptographic flaw allows forging authentication tokens for any user in the Active Directory environment. An attacker with any valid account can impersonate any user including domain administrators.',
        asset: 'Identity Provider / AD (IDP-01)', internetFacing: false, exploitInWild: true, patchAvailable: true,
        priorityRank: 3,
        consequence: 'A compromised contractor account was used to forge domain administrator tokens. Attacker moved laterally across the NIPR environment for 11 days.',
        tip: 'Token forgery means any valid user becomes any user. With insider threat risk in a contractor environment, this is a top-3 priority.'
      },
      {
        id: 'v3-4', cve: 'CVE-2024-38112', cvss: 8.8, severity: 'high',
        title: 'NIPR Workstations: MSHTML Zero-Day (CAT I STIG)',
        description: 'Zero-day in Windows MSHTML component exploited via malicious URL files delivered by phishing. No patch from vendor yet — mitigation requires registry key disable. Exploit kit available.',
        asset: 'NIPR Workstations (214 endpoints)', internetFacing: false, exploitInWild: true, patchAvailable: false,
        mitigationOnly: true,
        mitigation: 'Disable MSHTML via registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer',
        priorityRank: 4,
        consequence: 'A spear-phishing campaign targeting cleared personnel exploited the zero-day. Three workstations compromised; classified document access attempted.',
        tip: 'No patch available, but a registry mitigation exists. Applying mitigations counts — document it for STIG compliance.'
      },
      {
        id: 'v3-5', cve: 'CVE-2024-21767', cvss: 8.5, severity: 'high',
        title: 'Classified Document Server: Path Traversal (CAT II STIG)',
        description: 'Path traversal in the classified document management system allows any authenticated SIPR user to access documents outside their clearance level. Insider threat vector.',
        asset: 'SIPR Document Server (SIPR-DOC)', internetFacing: false, exploitInWild: false, patchAvailable: true,
        priorityRank: 5,
        consequence: 'An insider accessed TS/SCI documents outside their need-to-know. Discovered during quarterly audit. Damage assessment classified.',
        tip: 'Air-gapped SIPR system — no internet exploit possible. But insider threat access to documents above clearance level is a serious DISA finding.'
      },
      {
        id: 'v3-6', cve: 'CVE-2024-29944', cvss: 8.1, severity: 'high',
        title: 'Endpoint Detection Tool: Privilege Escalation (CAT II STIG)',
        description: 'Privilege escalation in the deployed endpoint detection agent. An attacker with local access can escalate to SYSTEM, effectively blinding the security tool and installing persistent malware.',
        asset: 'All NIPR Endpoints (214 systems)', internetFacing: false, exploitInWild: false, patchAvailable: true,
        priorityRank: 6,
        consequence: 'No exploitation. Patched in subsequent window. Low priority vs. active exploits targeting boundary and identity infrastructure.',
        tip: 'Escalating on the security tool is serious, but no active exploit and it requires existing foothold. Boundary and identity systems are higher priority.'
      },
      {
        id: 'v3-7', cve: 'CVE-2023-44487', cvss: 7.5, severity: 'high',
        title: 'Internal Web Services: HTTP/2 Rapid Reset DoS',
        description: 'HTTP/2 Rapid Reset attack causes denial of service on internal web services. An attacker on the network can crash internal web applications. No code execution possible.',
        asset: 'Internal Web Servers (WEB-INT-01/02)', internetFacing: false, exploitInWild: false, patchAvailable: true,
        priorityRank: 7,
        consequence: 'No exploitation. Internal availability risk only — no classified data exposure. Patched in next routine cycle.',
        tip: 'DoS-only, internal-only, no active exploit. Availability risk but lower than breach-enabling vulnerabilities.'
      },
      {
        id: 'v3-8', cve: 'CVE-2024-30080', cvss: 9.8, severity: 'critical',
        title: 'MSMQ: Unauthenticated RCE (Internal Only)',
        description: 'Remote code execution in Microsoft Message Queue service. Only reachable from inside the network — not internet-exposed. No exploit in the wild yet, but CISA issued an advisory.',
        asset: 'Legacy Application Servers (LEGACY-01/02)', internetFacing: false, exploitInWild: false, patchAvailable: true,
        priorityRank: 8,
        consequence: 'No exploitation. High CVSS but zero internet exposure and no active exploit. Patched in next cycle without incident.',
        tip: 'CVSS 9.8 looks alarming, but no internet exposure + no exploit-in-wild means other systems with active exploits take priority tonight.'
      }
    ]
  }
];

/* ── Module state ── */
let currentRound = 0;
let patchQueue = [];          // array of vuln IDs in order
let totalScore = 0;
let roundScores = [];
let roundPhase = 'selecting'; // 'selecting' | 'results'
let startTime = null;

/* ── Scoring ── */
const PTS_CORRECT_INCLUDE = 15;   // correct CVE in top-5 selection
const PTS_TOP1_BONUS      = 10;   // #1 priority CVE correctly at top of queue
const PTS_ORDER_BONUS     = 5;    // perfect ordering bonus

/* ── Init ── */
function initVulns() {
  startTime = Date.now();
  SENTINEL.initFirstVisit().then(() => {
    renderRound();
    updateProgressBar();
  });
}

/* ── Render round ── */
function renderRound() {
  const round = VULN_ROUNDS[currentRound];
  patchQueue = [];
  roundPhase = 'selecting';

  const main = document.getElementById('vuln-main');
  if (!main) return;

  const patchableVulns = round.vulns.filter(v => !v.unpatchableTonight);
  const unpatchableVulns = round.vulns.filter(v => v.unpatchableTonight);

  main.innerHTML = `
    <!-- Round header -->
    <div class="page-header" style="margin-bottom:1rem;">
      <div>
        <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.12em;color:var(--teal);margin-bottom:4px;">
          Round ${round.id} of ${VULN_ROUNDS.length}
        </div>
        <div class="page-title">${round.icon} ${SENTINEL._escHtml(round.org)}</div>
      </div>
    </div>

    <!-- Scenario briefing -->
    <div class="card mb-4" style="background:rgba(0,212,216,0.04);border-color:rgba(0,212,216,0.2);">
      <div class="flex items-start gap-3">
        <div style="font-size:1.5rem;flex-shrink:0;">${round.icon}</div>
        <div>
          <div class="card-title mb-2" style="color:var(--teal);">Mission Briefing</div>
          <p class="text-sm" style="line-height:1.7;color:var(--text-muted);">${SENTINEL._escHtml(round.scenario)}</p>
          ${round.contextNote ? `<div class="flex items-start gap-2 mt-3 text-xs" style="color:var(--medium);"><span>⚠</span><span>${SENTINEL._escHtml(round.contextNote)}</span></div>` : ''}
        </div>
      </div>
    </div>

    <!-- Two-column: CVE cards + patch queue -->
    <div style="display:grid;grid-template-columns:1fr 320px;gap:1rem;align-items:start;">

      <!-- Left: Available CVEs -->
      <div>
        <div class="flex items-center justify-between mb-3">
          <div>
            <div class="card-title-large">Available Vulnerabilities</div>
            <div class="text-xs text-muted mt-1">${patchableVulns.length} patchable tonight · Click to add to your patch queue</div>
          </div>
          <span class="badge badge-critical">${patchableVulns.length} PENDING</span>
        </div>
        <div id="vuln-cards-list">
          ${patchableVulns.map(v => buildVulnCard(v, round.patchSlots)).join('')}
        </div>

        ${unpatchableVulns.length > 0 ? `
          <div class="mt-4 mb-2">
            <div class="card-title-large" style="color:var(--text-muted);">Cannot Patch Tonight</div>
            <div class="text-xs text-muted mt-1 mb-3">Operational constraints prevent patching — plan compensating controls</div>
            ${unpatchableVulns.map(v => buildVulnCard(v, 0, true)).join('')}
          </div>
        ` : ''}
      </div>

      <!-- Right: Patch Queue -->
      <div style="position:sticky;top:72px;">
        <div class="card" style="border-color:rgba(94,234,212,0.25);">
          <div class="flex items-center justify-between mb-3">
            <div>
              <div class="card-title-large">Patch Queue</div>
              <div class="text-xs text-muted mt-1">Tonight's maintenance window</div>
            </div>
            <span class="badge badge-teal" id="queue-count">0 / ${round.patchSlots}</span>
          </div>

          <!-- Queue slots -->
          <div id="patch-queue-slots" class="patch-queue-slots">
            ${Array.from({length: round.patchSlots}, (_, i) => `
              <div class="patch-slot empty" id="slot-${i}" data-slot="${i}">
                <div class="patch-slot-num">${i + 1}</div>
                <div class="patch-slot-empty-label">— empty —</div>
              </div>
            `).join('')}
          </div>

          <div class="mt-3">
            <button class="btn btn-primary" style="width:100%;justify-content:center;" id="submit-queue-btn" onclick="submitQueue()" disabled>
              Submit Patch Plan →
            </button>
            <div class="text-xs text-muted mt-2 text-center">Select ${round.patchSlots} vulnerabilities to patch tonight</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Results area (hidden until submitted) -->
    <div id="results-area" class="hidden mt-4"></div>

    <!-- Round actions (hidden until results shown) -->
    <div id="round-actions" class="hidden mt-4"></div>
  `;

  updateRightPanel(round);
}

function buildVulnCard(v, patchSlots, disabled = false) {
  const cvssColor = v.cvss >= 9.0 ? 'var(--critical)' : v.cvss >= 7.0 ? 'var(--high)' : 'var(--medium)';
  const cvssWidth = (v.cvss / 10 * 100).toFixed(0);

  return `
    <div class="vuln-card ${disabled ? 'vuln-card-disabled' : ''}" id="vcard-${v.id}" data-id="${v.id}">
      <div class="vuln-card-header">
        <div style="flex:1;min-width:0;">
          <div class="flex items-center gap-2 mb-1 flex-wrap">
            <span class="badge badge-${v.severity}">${v.severity.toUpperCase()}</span>
            <span class="font-mono text-xs" style="color:var(--text-muted);">${SENTINEL._escHtml(v.cve)}</span>
            ${v.internetFacing ? '<span class="badge badge-critical" style="font-size:0.6rem;">INTERNET-FACING</span>' : '<span class="badge badge-muted" style="font-size:0.6rem;">INTERNAL</span>'}
            ${v.exploitInWild ? '<span class="badge badge-high" style="font-size:0.6rem;">EXPLOIT IN WILD</span>' : ''}
            ${v.unpatchableTonight ? '<span class="badge badge-muted" style="font-size:0.6rem;">⛔ CANNOT PATCH TONIGHT</span>' : ''}
            ${v.mitigationOnly ? '<span class="badge badge-medium" style="font-size:0.6rem;">MITIGATION ONLY</span>' : ''}
          </div>
          <div style="font-size:0.875rem;font-weight:600;color:var(--text-primary);">${SENTINEL._escHtml(v.title)}</div>
          <div class="text-xs text-muted mt-1" style="line-height:1.5;">${SENTINEL._escHtml(v.description)}</div>
          <div class="text-xs mt-2" style="color:var(--text-dim);">
            Asset: <span style="color:var(--text-muted);">${SENTINEL._escHtml(v.asset)}</span>
          </div>
          ${v.mitigation ? `<div class="text-xs mt-1" style="color:var(--medium);">Mitigation: ${SENTINEL._escHtml(v.mitigation)}</div>` : ''}
        </div>
        <div style="flex-shrink:0;text-align:right;min-width:80px;">
          <div style="font-size:1.5rem;font-weight:700;font-family:var(--font-mono);color:${cvssColor};">${v.cvss.toFixed(1)}</div>
          <div class="text-xs text-muted">CVSS v3</div>
          <div class="cvss-bar mt-1">
            <div class="cvss-fill" style="width:${cvssWidth}%;background:${cvssColor};"></div>
          </div>
        </div>
      </div>
      ${!disabled ? `
        <div class="vuln-card-footer">
          <div class="flex items-center gap-3">
            <div class="flex items-center gap-1 text-xs" style="color:${v.patchAvailable !== false ? 'var(--ok)' : 'var(--high)'};">
              ${v.patchAvailable !== false ? '✓ Patch available' : '⚠ Mitigation only'}
            </div>
          </div>
          <button class="btn btn-sm btn-secondary vuln-add-btn" id="add-btn-${v.id}" onclick="toggleQueue('${v.id}')">
            + Add to Queue
          </button>
        </div>
      ` : `
        <div class="vuln-card-footer">
          <div class="text-xs" style="color:var(--text-dim);">Scheduled for next maintenance window · Apply compensating controls now</div>
        </div>
      `}
    </div>
  `;
}

/* ── Queue management ── */
function toggleQueue(vulnId) {
  const round = VULN_ROUNDS[currentRound];
  const idx = patchQueue.indexOf(vulnId);

  if (idx >= 0) {
    // Remove from queue
    patchQueue.splice(idx, 1);
    const card = document.getElementById(`vcard-${vulnId}`);
    if (card) card.classList.remove('vuln-card-queued');
    const addBtn = document.getElementById(`add-btn-${vulnId}`);
    if (addBtn) { addBtn.textContent = '+ Add to Queue'; addBtn.classList.remove('btn-danger'); addBtn.classList.add('btn-secondary'); }
  } else {
    if (patchQueue.length >= round.patchSlots) {
      SENTINEL.toast(`Queue full — remove a vulnerability first`, 'warning');
      return;
    }
    patchQueue.push(vulnId);
    const card = document.getElementById(`vcard-${vulnId}`);
    if (card) card.classList.add('vuln-card-queued');
    const addBtn = document.getElementById(`add-btn-${vulnId}`);
    if (addBtn) { addBtn.textContent = '✕ Remove'; addBtn.classList.remove('btn-secondary'); addBtn.classList.add('btn-danger'); }
  }

  refreshQueueSlots();
}

function refreshQueueSlots() {
  const round = VULN_ROUNDS[currentRound];
  const slotsEl = document.getElementById('patch-queue-slots');
  const countEl = document.getElementById('queue-count');
  const submitBtn = document.getElementById('submit-queue-btn');

  if (!slotsEl) return;

  for (let i = 0; i < round.patchSlots; i++) {
    const slot = document.getElementById(`slot-${i}`);
    if (!slot) continue;

    if (i < patchQueue.length) {
      const vulnId = patchQueue[i];
      const v = round.vulns.find(x => x.id === vulnId);
      if (!v) continue;
      const cvssColor = v.cvss >= 9.0 ? 'var(--critical)' : v.cvss >= 7.0 ? 'var(--high)' : 'var(--medium)';
      slot.className = 'patch-slot filled';
      slot.innerHTML = `
        <div class="patch-slot-num">${i + 1}</div>
        <div style="flex:1;min-width:0;">
          <div style="font-size:0.75rem;font-weight:600;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${SENTINEL._escHtml(v.title)}</div>
          <div class="text-xs text-muted">${SENTINEL._escHtml(v.cve)}</div>
        </div>
        <div style="display:flex;align-items:center;gap:6px;flex-shrink:0;">
          ${i > 0 ? `<button class="queue-order-btn" title="Move up" onclick="moveInQueue('${vulnId}', -1)">▲</button>` : '<span style="width:20px;"></span>'}
          ${i < patchQueue.length - 1 ? `<button class="queue-order-btn" title="Move down" onclick="moveInQueue('${vulnId}', 1)">▼</button>` : '<span style="width:20px;"></span>'}
          <span style="font-family:var(--font-mono);font-size:0.875rem;font-weight:700;color:${cvssColor};">${v.cvss.toFixed(1)}</span>
        </div>
      `;
    } else {
      slot.className = 'patch-slot empty';
      slot.innerHTML = `
        <div class="patch-slot-num">${i + 1}</div>
        <div class="patch-slot-empty-label">— empty —</div>
      `;
    }
  }

  if (countEl) countEl.textContent = `${patchQueue.length} / ${round.patchSlots}`;
  if (submitBtn) submitBtn.disabled = patchQueue.length < round.patchSlots;
}

function moveInQueue(vulnId, direction) {
  const idx = patchQueue.indexOf(vulnId);
  if (idx < 0) return;
  const newIdx = idx + direction;
  if (newIdx < 0 || newIdx >= patchQueue.length) return;
  [patchQueue[idx], patchQueue[newIdx]] = [patchQueue[newIdx], patchQueue[idx]];
  refreshQueueSlots();
}

/* ── Submit queue ── */
function submitQueue() {
  const round = VULN_ROUNDS[currentRound];
  roundPhase = 'results';

  const submitBtn = document.getElementById('submit-queue-btn');
  if (submitBtn) submitBtn.disabled = true;

  /* Disable all add buttons */
  round.vulns.forEach(v => {
    const btn = document.getElementById(`add-btn-${v.id}`);
    if (btn) { btn.disabled = true; btn.style.opacity = '0.4'; }
  });

  /* Score calculation */
  const optimalOrder = round.vulns
    .filter(v => !v.unpatchableTonight)
    .sort((a, b) => a.priorityRank - b.priorityRank)
    .slice(0, round.patchSlots)
    .map(v => v.id);

  const optimalSet = new Set(optimalOrder);
  let roundScore = 0;

  /* Points for correctly including high-priority CVEs */
  patchQueue.forEach((id, userRank) => {
    if (optimalSet.has(id)) {
      roundScore += PTS_CORRECT_INCLUDE;
      if (userRank === 0 && id === optimalOrder[0]) {
        roundScore += PTS_TOP1_BONUS;
      }
    }
  });

  /* Bonus for good ordering */
  let orderMatches = 0;
  patchQueue.forEach((id, idx) => {
    if (id === optimalOrder[idx]) orderMatches++;
  });
  if (orderMatches >= round.patchSlots - 1) roundScore += PTS_ORDER_BONUS;

  /* Show results */
  renderResults(round, optimalOrder, optimalSet, roundScore);
  totalScore += roundScore;
  roundScores.push(roundScore);
  SENTINEL.updateScore(roundScore);
  SENTINEL.toast(`Round complete! +${roundScore} pts`, 'success');
  updateProgressBar();
}

function renderResults(round, optimalOrder, optimalSet, roundScore) {
  const el = document.getElementById('results-area');
  if (!el) return;

  const allPatchable = round.vulns.filter(v => !v.unpatchableTonight);
  const correctlyIncluded = patchQueue.filter(id => optimalSet.has(id));
  const incorrectlyIncluded = patchQueue.filter(id => !optimalSet.has(id));
  const pct = Math.round((correctlyIncluded.length / round.patchSlots) * 100);

  el.innerHTML = `
    <div class="card" style="border-color:rgba(94,234,212,0.25);">
      <div class="flex items-center justify-between mb-4">
        <div>
          <div class="card-title mb-1">Maintenance Window Results</div>
          <div style="font-size:0.8125rem;color:var(--text-muted);">${correctlyIncluded.length}/${round.patchSlots} optimal selections · ${incorrectlyIncluded.length} suboptimal</div>
        </div>
        <div class="stat-big stat-teal" style="font-size:1.5rem;">+${roundScore} pts</div>
      </div>

      <!-- Consequence cards: unpatched high-priority CVEs -->
      ${optimalOrder.filter(id => !patchQueue.includes(id)).length > 0 ? `
        <div class="mb-4">
          <div class="card-title mb-2" style="color:var(--critical);">⚠ Unpatched Systems — Consequences</div>
          ${optimalOrder.filter(id => !patchQueue.includes(id)).map(id => {
            const v = round.vulns.find(x => x.id === id);
            if (!v) return '';
            return `
              <div class="consequence-card">
                <div class="flex items-center gap-2 mb-2">
                  <span class="badge badge-critical">${v.cve}</span>
                  <span style="font-size:0.8125rem;font-weight:600;color:var(--text-primary);">${SENTINEL._escHtml(v.title)}</span>
                </div>
                <div class="text-xs" style="color:var(--critical);line-height:1.5;">💥 ${SENTINEL._escHtml(v.consequence)}</div>
              </div>
            `;
          }).join('')}
        </div>
      ` : `
        <div class="mb-4 card" style="background:rgba(74,222,128,0.06);border-color:rgba(74,222,128,0.25);">
          <div style="color:var(--ok);font-weight:600;margin-bottom:4px;">✓ Perfect Selection!</div>
          <div class="text-xs text-muted">You patched all optimal systems. No critical unpatched vulnerabilities remain.</div>
        </div>
      `}

      <!-- Why these were optimal -->
      <div class="mb-4">
        <div class="card-title mb-2" style="color:var(--teal);">Optimal Patch Order — Rationale</div>
        ${optimalOrder.map((id, rank) => {
          const v = round.vulns.find(x => x.id === id);
          if (!v) return '';
          const userIncluded = patchQueue.includes(id);
          return `
            <div class="optimal-row ${userIncluded ? 'optimal-included' : 'optimal-missed'}">
              <div class="optimal-rank">${rank + 1}</div>
              <div style="flex:1;min-width:0;">
                <div class="flex items-center gap-2">
                  <span class="text-xs font-mono" style="color:var(--text-muted);">${v.cve}</span>
                  <span style="font-size:0.8125rem;font-weight:600;color:var(--text-primary);">${SENTINEL._escHtml(v.title)}</span>
                  ${userIncluded ? '<span class="badge badge-ok" style="font-size:0.55rem;">YOU INCLUDED</span>' : '<span class="badge badge-critical" style="font-size:0.55rem;">MISSED</span>'}
                </div>
                <div class="text-xs text-muted mt-1">${SENTINEL._escHtml(v.tip)}</div>
              </div>
              <div style="flex-shrink:0;font-family:var(--font-mono);font-size:0.875rem;font-weight:700;color:${v.cvss >= 9 ? 'var(--critical)' : 'var(--high)'};">${v.cvss.toFixed(1)}</div>
            </div>
          `;
        }).join('')}
      </div>

      <!-- Learning callout -->
      <div class="card" style="background:rgba(0,212,216,0.04);border-color:rgba(0,212,216,0.15);">
        <div class="card-title mb-2" style="color:var(--teal);">💡 Prioritization Framework</div>
        <div class="text-xs" style="line-height:1.8;color:var(--text-muted);">
          <div>1. <strong style="color:var(--text-primary);">CVSS score</strong> — baseline severity (but not the whole story)</div>
          <div>2. <strong style="color:var(--critical);">Exploit in wild?</strong> — active exploitation multiplies urgency</div>
          <div>3. <strong style="color:var(--high);">Internet-facing?</strong> — external attack surface vs. internal</div>
          <div>4. <strong style="color:var(--text-primary);">Asset criticality</strong> — what does this system protect?</div>
          <div>5. <strong style="color:var(--medium);">Operational constraints</strong> — can it be patched now safely?</div>
        </div>
      </div>
    </div>
  `;
  el.classList.remove('hidden');

  /* Show next button */
  const actEl = document.getElementById('round-actions');
  if (actEl) {
    const isLast = currentRound >= VULN_ROUNDS.length - 1;
    actEl.innerHTML = `
      <div class="flex gap-3" style="justify-content:flex-end;">
        ${isLast
          ? `<button class="btn btn-primary btn-lg" onclick="showFinalDebrief()">View Final Results →</button>`
          : `<button class="btn btn-primary" onclick="nextRound()">Next Round →</button>`
        }
      </div>
    `;
    actEl.classList.remove('hidden');
    actEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

function nextRound() {
  currentRound++;
  window.scrollTo({ top: 0, behavior: 'smooth' });
  setTimeout(renderRound, 100);
}

/* ── Right panel ── */
function updateRightPanel(round) {
  const el = document.getElementById('vuln-right-panel');
  if (!el) return;
  el.innerHTML = `
    <!-- Score -->
    <div class="card">
      <div class="card-title mb-2">Session Score</div>
      <div class="stat-big stat-teal">${totalScore}</div>
      <div class="stat-label">pts earned</div>
      <hr class="divider">
      <div class="flex justify-between text-xs">
        <span class="text-muted">Round</span>
        <span class="font-mono text-teal">${currentRound + 1} / ${VULN_ROUNDS.length}</span>
      </div>
    </div>

    <!-- CVSS guide -->
    <div class="card">
      <div class="card-title mb-3">CVSS v3 Scale</div>
      <div class="flex justify-between text-xs mb-2">
        <span style="color:var(--critical);">● Critical</span><span class="font-mono text-muted">9.0 – 10.0</span>
      </div>
      <div class="flex justify-between text-xs mb-2">
        <span style="color:var(--high);">● High</span><span class="font-mono text-muted">7.0 – 8.9</span>
      </div>
      <div class="flex justify-between text-xs mb-2">
        <span style="color:var(--medium);">● Medium</span><span class="font-mono text-muted">4.0 – 6.9</span>
      </div>
      <div class="flex justify-between text-xs">
        <span style="color:var(--low);">● Low</span><span class="font-mono text-muted">0.1 – 3.9</span>
      </div>
      <hr class="divider">
      <div class="text-xs text-muted" style="line-height:1.6;">${SENTINEL._escHtml(round.cvssGuide)}</div>
    </div>

    <!-- Priority factors -->
    <div class="card">
      <div class="card-title mb-3">Prioritization Factors</div>
      <div class="text-xs" style="line-height:1.8;color:var(--text-muted);">
        <div><span style="color:var(--critical);">🔴</span> Internet-facing asset?</div>
        <div><span style="color:var(--high);">🟠</span> Active exploit in the wild?</div>
        <div><span style="color:var(--medium);">🟡</span> CVSS severity score?</div>
        <div><span style="color:var(--low);">🔵</span> Asset criticality / data sensitivity?</div>
        <div><span style="color:var(--ok);">🟢</span> Patch actually available?</div>
      </div>
    </div>

    <!-- Key concept -->
    <div class="card" style="background:rgba(0,212,216,0.04);border-color:rgba(0,212,216,0.2);">
      <div class="card-title mb-2" style="color:var(--teal);">💡 Key Concept</div>
      <p class="text-xs" style="line-height:1.6;">
        A CVSS 9.8 with no public exploit and no internet exposure can be <strong style="color:var(--text-primary);">lower priority</strong>
        than a CVSS 7.5 that's actively exploited on an internet-facing system.
      </p>
      <hr class="divider">
      <p class="text-xs" style="line-height:1.6;">
        Security+ expects you to understand <strong style="color:var(--teal);">risk-based prioritization</strong>,
        not just severity scores. Context determines urgency.
      </p>
    </div>
  `;
}

/* ── Progress bar ── */
function updateProgressBar() {
  const bar = document.getElementById('vuln-progress-fill');
  const label = document.getElementById('vuln-progress-label');
  const completed = roundScores.length;
  if (bar) bar.style.width = ((completed / VULN_ROUNDS.length) * 100) + '%';
  if (label) label.textContent = `${completed} / ${VULN_ROUNDS.length} rounds`;
}

/* ── Final debrief ── */
function showFinalDebrief() {
  const main = document.getElementById('vuln-main');
  if (!main) return;

  const maxScore = VULN_ROUNDS.length * (5 * PTS_CORRECT_INCLUDE + PTS_TOP1_BONUS + PTS_ORDER_BONUS);
  const pct = Math.round((totalScore / maxScore) * 100);
  const scoreClass = SENTINEL.scoreClass(pct);
  const scoreLabel = SENTINEL.scoreLabel(pct);
  const elapsed = Math.round((Date.now() - startTime) / 1000);
  const mins = Math.floor(elapsed / 60);
  const secs = elapsed % 60;

  main.innerHTML = `
    <div class="score-debrief">
      <div class="text-xs text-muted mb-2" style="text-transform:uppercase;letter-spacing:0.1em;">Vulnerability Prioritization Complete</div>
      <div class="stat-big ${scoreClass} mb-2">${pct}%</div>
      <div style="font-size:1rem;font-weight:600;color:var(--text-primary);margin-bottom:0.5rem;">${scoreLabel}</div>
      <div class="text-sm text-muted mb-4">Completed in ${mins}m ${secs}s across ${VULN_ROUNDS.length} organizations</div>

      <div class="score-breakdown">
        ${roundScores.map((s, i) => `
          <div class="score-row">
            <span class="score-row-label">${VULN_ROUNDS[i].icon} ${VULN_ROUNDS[i].org}</span>
            <span class="score-row-val text-teal">+${s} pts</span>
          </div>
        `).join('')}
        <div class="score-row" style="border-top:1px solid var(--border);padding-top:8px;margin-top:4px;">
          <span class="score-row-label" style="font-weight:700;color:var(--text-primary);">Total</span>
          <span class="score-row-val text-teal" style="font-size:1rem;">${totalScore} pts</span>
        </div>
      </div>

      <div class="card mt-4" style="background:rgba(0,212,216,0.04);border-color:rgba(0,212,216,0.2);text-align:left;">
        <div class="card-title mb-2" style="color:var(--teal);">What you practiced (Security+ mapped)</div>
        <div class="text-xs" style="line-height:1.9;color:var(--text-muted);">
          <div>📘 <strong style="color:var(--text-primary);">Domain 2:</strong> Vulnerability scanning, CVSS scoring, patch management</div>
          <div>📘 <strong style="color:var(--text-primary);">Domain 2:</strong> Risk-based prioritization vs. raw severity scoring</div>
          <div>📘 <strong style="color:var(--text-primary);">Domain 3:</strong> Network segmentation, compensating controls</div>
          <div>📘 <strong style="color:var(--text-primary);">Domain 2:</strong> Supply chain risk (EO 14028 / SolarWinds class threats)</div>
          <div>📘 <strong style="color:var(--text-primary);">Domain 5:</strong> Compliance requirements (HIPAA, DISA STIG) affecting patch priority</div>
        </div>
      </div>

      <div class="flex gap-3 mt-4" style="justify-content:center;">
        <a href="scenarios.html" class="btn btn-primary btn-lg">Scenario Library →</a>
        <button onclick="resetModule()" class="btn btn-secondary">Retry Vuln Lab</button>
      </div>
    </div>
  `;

  /* Save progress */
  const p = SENTINEL.getProgress();
  p.vulnsScore = totalScore;
  p.vulnsCompleted = true;
  SENTINEL.saveProgress(p);
  updateProgressBar();
}

/* ── Reset ── */
function resetModule() {
  currentRound = 0;
  totalScore = 0;
  roundScores = [];
  patchQueue = [];
  startTime = Date.now();
  window.scrollTo({ top: 0, behavior: 'smooth' });
  renderRound();
  updateProgressBar();
}

document.addEventListener('DOMContentLoaded', initVulns);
