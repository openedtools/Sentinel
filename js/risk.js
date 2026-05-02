/* SENTINEL — Risk Register Simulator */

const RISK_ROUNDS = [
  {
    id: 1, org: 'SaaS Startup', icon: '🚀',
    scenario: 'You are the first security hire at a 60-person SaaS company. You have a $40K budget and a board presentation in 90 days. For each risk: plot it on the matrix, then choose your response.',
    riskTolerance: 'Medium — investors accept some risk for growth velocity',
    risks: [
      {
        id: 'r1-1',
        asset: 'Customer PII Database (85,000 users)',
        threat: 'SQL injection via public product-search API endpoint',
        vulnerability: 'API parameters passed directly to database queries — no input validation',
        ale: '$72,000/yr', sle: '$180,000', aro: '0.4×/yr',
        optL: 4, optI: 5, optResponse: 'mitigate',
        optControls: ['parameterized', 'waf'],
        controls: [
          { id: 'parameterized', name: 'Parameterized queries + input validation', type: 'Preventive', reduces: 'likelihood' },
          { id: 'waf',           name: 'Web Application Firewall',                 type: 'Preventive', reduces: 'likelihood' },
          { id: 'encrypt',       name: 'Encrypt database at rest',                 type: 'Preventive', reduces: 'impact'     },
          { id: 'monitor',       name: 'Database activity monitoring',             type: 'Detective',  reduces: 'likelihood' }
        ],
        explanation: 'CVSS 9.8-class vulnerability on an internet-facing endpoint holding PII. Likelihood 4 (actively exploited class of bug) × Impact 5 (full breach, GDPR fines) = score 20. Parameterized queries eliminate the root cause; WAF adds a detection layer. Accept is wrong — score 20 exceeds any reasonable risk appetite.',
        consequenceGood: 'SQL injection attempts blocked. Zero breach. Customers never knew.',
        consequenceBad: '85,000 records exfiltrated. $180K GDPR fine, 3 months of incident response, 22% customer churn.',
        consequenceTransfer: 'Cyber insurance paid legal costs but not the GDPR fine. Premium tripled. Root cause still unresolved.',
        secplus: 'Domain 2: Vulnerability management · Domain 5: Risk response strategies'
      },
      {
        id: 'r1-2',
        asset: 'Production Web Server (order processing)',
        threat: 'Ransomware via unpatched Apache RCE (CVE, CVSS 9.8)',
        vulnerability: 'Apache version 18 months behind patch level — known critical vulnerability',
        ale: '$96,000/yr', sle: '$240,000', aro: '0.4×/yr',
        optL: 4, optI: 5, optResponse: 'mitigate',
        optControls: ['patch', 'vuln_scan'],
        controls: [
          { id: 'patch',     name: 'Emergency patch + patch management program', type: 'Preventive', reduces: 'likelihood' },
          { id: 'vuln_scan', name: 'Automated vulnerability scanning (weekly)',   type: 'Detective',  reduces: 'likelihood' },
          { id: 'backup',    name: 'Immutable daily backups (offsite)',           type: 'Corrective', reduces: 'impact'     },
          { id: 'edr',       name: 'Endpoint Detection & Response agent',        type: 'Detective',  reduces: 'impact'     }
        ],
        explanation: 'An internet-facing server running a CVSS 9.8 CVE with a public exploit is near-certain to be compromised. Patch immediately. Backups reduce impact but do not reduce likelihood — both controls together address the full risk. Likelihood 4 × Impact 5 = 20.',
        consequenceGood: 'Patched before exploitation. Vulnerability scanner catches 14 more issues in the same cycle.',
        consequenceBad: 'Server encrypted by ransomware. 6 days of downtime. $240K in recovery + lost revenue.',
        consequenceTransfer: 'Insurance covered $180K but not the full loss. Deductible was $25K. Unpatched server remains a liability.',
        secplus: 'Domain 2: Patch management, vulnerability scanning · Domain 5: Mitigation controls'
      },
      {
        id: 'r1-3',
        asset: 'CEO Laptop (strategic plans, cached SSO credentials)',
        threat: 'Physical theft at industry conference',
        vulnerability: 'Full-disk encryption disabled; no MDM/remote-wipe capability enrolled',
        ale: '$18,000/yr', sle: '$60,000', aro: '0.3×/yr',
        optL: 3, optI: 3, optResponse: 'mitigate',
        optControls: ['fde', 'mdm'],
        controls: [
          { id: 'fde',      name: 'Full-disk encryption (BitLocker/FileVault)', type: 'Preventive', reduces: 'impact'     },
          { id: 'mdm',      name: 'MDM with remote wipe capability',           type: 'Corrective', reduces: 'impact'     },
          { id: 'vpn',      name: 'Mandatory VPN for all remote work',         type: 'Preventive', reduces: 'likelihood' },
          { id: 'awareness',name: 'Security awareness training (travel risks)', type: 'Deterrent',  reduces: 'likelihood' }
        ],
        explanation: 'Conference laptop theft is common (Likelihood 3) but with FDE the impact drops from 3 to 1 — stolen hardware becomes worthless without the key. MDM remote wipe adds a corrective control. Together they reduce residual risk to score ~3. Cost of controls ($0 for FDE if using native OS tools) << cost of a breach.',
        consequenceGood: 'Laptop stolen at DEF CON. Remote-wiped within 20 minutes. Encrypted drive unreadable. $1,200 replacement cost only.',
        consequenceBad: 'Unencrypted drive read overnight. M&A strategy document and SSO session tokens exfiltrated. Competitor filed a blocking patent 3 weeks later.',
        consequenceTransfer: 'Insurance replaced hardware but did not cover IP theft. FDE still needed.',
        secplus: 'Domain 1: Data protection · Domain 3: Physical security · Domain 5: Control types (preventive/corrective)'
      },
      {
        id: 'r1-4',
        asset: 'Payment Processing (outsourced to PCI-DSS Level 1 processor)',
        threat: 'Third-party payment processor breach exposes card data',
        vulnerability: 'No direct card data stored — all payment handled by certified processor (Stripe-equivalent)',
        ale: '$3,000/yr', sle: '$30,000', aro: '0.1×/yr',
        optL: 1, optI: 3, optResponse: 'transfer',
        optControls: [],
        controls: [
          { id: 'contract',  name: 'SLA + liability clause in processor contract',   type: 'Administrative', reduces: 'impact'     },
          { id: 'audit',     name: 'Annual PCI-DSS attestation review of processor', type: 'Detective',      reduces: 'likelihood' },
          { id: 'tokenize',  name: 'Tokenization — never handle raw PANs',           type: 'Preventive',     reduces: 'impact'     }
        ],
        explanation: 'By outsourcing to a PCI-DSS Level 1 processor and never touching raw card data, you have already transferred and minimized this risk. Likelihood 1 (major processors rarely breached) × Impact 3 (limited since liability is contractually shifted) = score 3. This is a textbook Transfer: the processor bears PCI scope; you bear only reputational risk.',
        consequenceGood: 'Processor suffers a minor breach. Your contractual protections apply. You notify affected customers. No fines.',
        consequenceBad: 'N/A — at score 3 with a reputable PCI-DSS processor, this risk is already well-managed.',
        consequenceTransfer: 'This IS the correct answer. Outsourcing to a certified processor is risk transfer by design.',
        secplus: 'Domain 5: Risk transfer · Third-party risk management · PCI-DSS compliance'
      },
      {
        id: 'r1-5',
        asset: 'Company Social Media Accounts',
        threat: 'Account takeover via credential stuffing → brand damage post',
        vulnerability: 'Shared password in a team password manager; MFA enabled on all accounts',
        ale: '$4,000/yr', sle: '$20,000', aro: '0.2×/yr',
        optL: 2, optI: 2, optResponse: 'accept',
        optControls: [],
        controls: [
          { id: 'mfa',     name: 'Enforce MFA (already in place)',         type: 'Preventive', reduces: 'likelihood' },
          { id: 'monitor', name: 'Social media monitoring alerts',         type: 'Detective',  reduces: 'impact'     },
          { id: 'policy',  name: 'Social media response runbook',          type: 'Corrective', reduces: 'impact'     }
        ],
        explanation: 'MFA is already enabled, which makes credential stuffing very difficult (Likelihood 2). Brand damage from a temporary hijack is real but recoverable (Impact 2). Score 4 is within the startup\'s risk tolerance. Accept does NOT mean ignore — it means acknowledge the residual risk and document it. Additional controls (monitoring, runbook) exist but the ROI doesn\'t justify the budget at this risk level.',
        consequenceGood: 'One account compromise attempt blocked by MFA. Monitoring alert fires. Passwords rotated.',
        consequenceBad: 'At score 4, rare events happen. A temporary hijacked post caused 2 days of PR management. Recovered fully.',
        consequenceTransfer: 'Insurance doesn\'t cover reputational risk at this scale. Accept with monitoring is the right call.',
        secplus: 'Domain 5: Risk acceptance · Risk appetite · Residual risk documentation'
      }
    ]
  },
  {
    id: 2, org: 'Community Bank', icon: '🏦',
    scenario: 'You are the CISO of a $2B regional bank. Regulators (OCC) expect demonstrable risk management. Six risks require assessment this quarter. Budget is constrained — prioritize carefully.',
    riskTolerance: 'Low — regulatory environment, fiduciary duty, and reputational exposure demand conservative posture',
    risks: [
      {
        id: 'r2-1',
        asset: 'Wire Transfer System ($2M processed daily)',
        threat: 'Business Email Compromise — fake CFO email authorizes fraudulent wire',
        vulnerability: 'Wire approval process relies on email confirmation only; no out-of-band verification',
        ale: '$175,000/yr', sle: '$350,000', aro: '0.5×/yr',
        optL: 4, optI: 5, optResponse: 'mitigate',
        optControls: ['oob_verify', 'mfa_wire'],
        controls: [
          { id: 'oob_verify', name: 'Out-of-band phone verification for all wires >$10K', type: 'Preventive', reduces: 'likelihood' },
          { id: 'mfa_wire',   name: 'MFA required for wire transfer portal login',         type: 'Preventive', reduces: 'likelihood' },
          { id: 'training',   name: 'BEC awareness training (quarterly)',                  type: 'Deterrent',  reduces: 'likelihood' },
          { id: 'limit',      name: 'Lower single-approval wire limit to $25K',            type: 'Preventive', reduces: 'impact'     }
        ],
        explanation: 'BEC is the #1 financial cybercrime by dollar loss (FBI IC3). Banks are primary targets. Likelihood 4 × Impact 5 = 20. Out-of-band verification (call the CFO on a known number) breaks the attack chain entirely — attacker controls email but not the phone. MFA prevents portal hijacking. Both controls are low-cost relative to the ALE.',
        consequenceGood: 'Three BEC attempts this quarter. All caught by out-of-band callback procedure. $0 loss.',
        consequenceBad: '$350K wire sent to overseas account. Recovery: $12K recovered. Regulator notified. $85K in investigation costs.',
        consequenceTransfer: 'Cyber insurance covered $200K after a 45-day claims process. $150K uncovered. Out-of-band verification costs $0.',
        secplus: 'Domain 2: Social engineering (BEC) · Domain 5: Risk mitigation · Preventive controls'
      },
      {
        id: 'r2-2',
        asset: 'ATM Network (18 ATMs across branch locations)',
        threat: 'Physical card skimmer installation on ATM fascia',
        vulnerability: 'ATM inspection currently monthly; skimmers can operate undetected for weeks',
        ale: '$27,000/yr', sle: '$45,000', aro: '0.6×/yr',
        optL: 3, optI: 2, optResponse: 'transfer',
        optControls: [],
        controls: [
          { id: 'insurance', name: 'Card fraud insurance policy',              type: 'Administrative', reduces: 'impact'     },
          { id: 'inspect',   name: 'Weekly ATM physical inspections',          type: 'Detective',      reduces: 'likelihood' },
          { id: 'jitter',    name: 'Anti-skimming card jitter technology',     type: 'Preventive',     reduces: 'likelihood' },
          { id: 'emv',       name: 'EMV chip enforcement (no mag-stripe)',     type: 'Preventive',     reduces: 'impact'     }
        ],
        explanation: 'Score 6 (medium-low). Card networks already shift skimming liability under EMV rules. A fraud insurance policy transfers the residual financial risk efficiently. The bank cannot fully prevent physical skimming on public ATMs — transfer is more cost-effective than trying to fully mitigate. Note: Transfer does NOT eliminate risk; it shifts the financial consequence.',
        consequenceGood: 'Two skimmer incidents this year. Insurance paid $42K in fraud losses. Net cost to bank: $8K deductible.',
        consequenceBad: 'Uninsured skimmer incident. $45K loss absorbed directly. Plus customer notification costs.',
        consequenceTransfer: 'Correct. Card fraud insurance with ATM rider is standard practice — the cost of mitigation beyond basic controls exceeds the residual loss.',
        secplus: 'Domain 3: Physical security · Domain 5: Risk transfer, insurance as a risk control'
      },
      {
        id: 'r2-3',
        asset: 'Core Banking Platform (all accounts, transactions)',
        threat: 'Ransomware via unpatched vendor software (critical CVE, CVSS 9.1)',
        vulnerability: 'Core banking vendor patch requires 6-week testing cycle — currently 4 months behind',
        ale: '$480,000/yr', sle: '$1,200,000', aro: '0.4×/yr',
        optL: 3, optI: 5, optResponse: 'mitigate',
        optControls: ['compensating', 'backup'],
        controls: [
          { id: 'compensating', name: 'Compensating controls (network isolation, enhanced monitoring)', type: 'Preventive', reduces: 'likelihood' },
          { id: 'backup',       name: 'Immutable offline backups tested monthly',                       type: 'Corrective', reduces: 'impact'     },
          { id: 'ir_plan',      name: 'Tested ransomware incident response playbook',                   type: 'Corrective', reduces: 'impact'     },
          { id: 'accelerate',   name: 'Accelerate patch testing cycle (vendor negotiation)',            type: 'Preventive', reduces: 'likelihood' }
        ],
        explanation: 'Likelihood 3 (internal network required, but active exploit exists) × Impact 5 (core banking offline = business stopped, OCC regulators involved) = 15. Can\'t patch immediately due to testing requirements — compensating controls (network segmentation, enhanced IDS) reduce likelihood while patch testing completes. Immutable backups reduce recovery time/impact. Document everything for regulators.',
        consequenceGood: 'Ransomware attempt blocked by network segmentation. Patch applied 3 weeks later after accelerated testing.',
        consequenceBad: 'Core banking encrypted. 4-day outage. $1.2M recovery cost. OCC issued a Matter Requiring Attention. CEO testified before board.',
        consequenceTransfer: 'Insurance covered $600K. Remaining $600K was uninsured. Regulators don\'t accept "insurance covered it" as a control.',
        secplus: 'Domain 2: Compensating controls · Domain 5: Risk when patch is not immediately possible'
      },
      {
        id: 'r2-4',
        asset: 'Employee Email (O365, 280 accounts)',
        threat: 'Password spray attack → account takeover → internal phishing pivot',
        vulnerability: 'MFA not enforced for legacy IMAP/POP3 connectors used by 40 employees',
        ale: '$28,000/yr', sle: '$70,000', aro: '0.4×/yr',
        optL: 5, optI: 2, optResponse: 'mitigate',
        optControls: ['mfa', 'disable_legacy'],
        controls: [
          { id: 'mfa',            name: 'Enforce MFA on all authentication paths',            type: 'Preventive', reduces: 'likelihood' },
          { id: 'disable_legacy', name: 'Disable legacy IMAP/POP3 authentication protocols', type: 'Preventive', reduces: 'likelihood' },
          { id: 'siem',           name: 'Alert on impossible-travel login events',            type: 'Detective',  reduces: 'impact'     },
          { id: 'awareness',      name: 'Phishing simulation + awareness training',           type: 'Deterrent',  reduces: 'likelihood' }
        ],
        explanation: 'O365 password spray is nearly constant (Likelihood 5). MFA on modern auth is already protecting most accounts — the gap is legacy protocols that bypass MFA entirely. Disabling legacy protocols + enforcing MFA brings likelihood from 5 to 1. Impact is 2 because a single compromised account has limited blast radius with proper segmentation. Score 10 → residual score ~2 after controls.',
        consequenceGood: 'Legacy protocols disabled. Password spray attempts continue but all fail. Zero account takeovers.',
        consequenceBad: 'IMAP account takeover used to pivot internal phishing campaign. 3 wire transfer approvals tricked. $210K loss.',
        consequenceTransfer: 'Insurance requires MFA to be in place for coverage. Claim denied.',
        secplus: 'Domain 1: MFA · Domain 2: Password attacks · Domain 5: Reducing likelihood via technical controls'
      },
      {
        id: 'r2-5',
        asset: 'Shadow IT: Unapproved Cloud App storing customer loan documents',
        threat: 'Uncontrolled cloud app exposes customer financial data — regulatory violation',
        vulnerability: 'Loan officers using personal Dropbox to share documents with customers. IT has no visibility.',
        ale: '$95,000/yr', sle: '$190,000', aro: '0.5×/yr',
        optL: 4, optI: 4, optResponse: 'avoid',
        optControls: [],
        controls: [
          { id: 'dlp',     name: 'DLP to detect/block uploads to unapproved cloud', type: 'Preventive', reduces: 'likelihood' },
          { id: 'casb',    name: 'CASB for cloud app visibility and control',        type: 'Detective',  reduces: 'likelihood' },
          { id: 'policy',  name: 'Acceptable use policy + annual attestation',       type: 'Deterrent',  reduces: 'likelihood' }
        ],
        explanation: 'Likelihood 4 (confirmed active use, likely ongoing) × Impact 4 (GLBA violation, OCC finding, customer PII on consumer cloud) = 16. The correct response is Avoid: prohibit the activity and migrate documents to an approved, bank-controlled system. Mitigation controls (DLP, CASB) are additive but the root cause is an unauthorized business process — stop it.',
        consequenceGood: 'Loan officers migrated to approved SharePoint with DLP. OCC auditor finds no exceptions.',
        consequenceBad: 'OCC examination discovers Dropbox usage. GLBA violation. $85K fine. 90-day remediation order.',
        consequenceTransfer: 'No insurance product covers regulatory fines. Avoid is the only correct answer here.',
        secplus: 'Domain 3: Shadow IT, CASB · Domain 5: Risk avoidance · Regulatory risk'
      }
    ]
  },
  {
    id: 3, org: 'Municipal Water Utility', icon: '💧',
    scenario: 'You are the new IT/OT Security Manager for a city water utility serving 280,000 residents. A recent DHS advisory flagged water utilities as active targets. Risk appetite is near-zero for anything affecting public health.',
    riskTolerance: 'Very Low — public health and life-safety consequences mean most risks must be mitigated or avoided',
    risks: [
      {
        id: 'r3-1',
        asset: 'Water Treatment SCADA — Chemical Dosing System',
        threat: 'Remote access via internet-exposed HMI interface (found in Shodan scan)',
        vulnerability: 'HMI management interface directly accessible from internet on port 4840; default vendor credentials unchanged',
        ale: 'Incalculable — public health emergency', sle: 'Life-safety event', aro: 'Actively targeted',
        optL: 5, optI: 5, optResponse: 'avoid',
        optControls: [],
        controls: [
          { id: 'airgap',    name: 'Remove HMI from internet — air-gap immediately',      type: 'Preventive', reduces: 'likelihood' },
          { id: 'creds',     name: 'Change all default vendor credentials',                type: 'Preventive', reduces: 'likelihood' },
          { id: 'jumpserver',name: 'Restrict to jump server with MFA (if remote needed)',  type: 'Preventive', reduces: 'likelihood' },
          { id: 'monitor',   name: 'OT network monitoring (Dragos/Claroty)',               type: 'Detective',  reduces: 'impact'     }
        ],
        explanation: 'This is the Oldsmar, Florida water treatment attack (2021) scenario — attacker increased sodium hydroxide to 111× safe levels. Likelihood 5 (actively Internet-exposed with default creds, already on Shodan) × Impact 5 (mass poisoning event) = 25. Avoid = remove from internet immediately. Then mitigate remaining OT access risk with jump servers. No financial calculus applies to public health.',
        consequenceGood: 'HMI removed from internet in 4 hours. Credentials rotated. CISA notified. No incident.',
        consequenceBad: 'Attacker modified chlorine dosing. Water unsafe for 72 hours. 47 hospitalizations. Federal investigation. Utility board dissolved.',
        consequenceTransfer: 'No insurance product covers a mass-casualty water event. You cannot transfer life-safety risk.',
        secplus: 'Domain 2: ICS/SCADA vulnerabilities · Domain 5: Risk avoidance · Critical infrastructure security'
      },
      {
        id: 'r3-2',
        asset: 'Programmable Logic Controllers (PLCs) — Pump Control',
        threat: 'Authentication bypass via unchanged default vendor credentials on OT network',
        vulnerability: 'All 14 PLCs use factory-default username/password from vendor documentation (publicly available)',
        ale: '$2,400,000/yr', sle: '$6,000,000', aro: '0.4×/yr',
        optL: 3, optI: 5, optResponse: 'mitigate',
        optControls: ['creds', 'segment'],
        controls: [
          { id: 'creds',   name: 'Change all default credentials on every PLC',           type: 'Preventive', reduces: 'likelihood' },
          { id: 'segment', name: 'Network segmentation — PLCs on isolated VLAN',          type: 'Preventive', reduces: 'likelihood' },
          { id: 'monitor', name: 'OT anomaly detection (monitor PLC command sequences)',  type: 'Detective',  reduces: 'impact'     },
          { id: 'patch',   name: 'Vendor firmware update to patch known CVEs',            type: 'Preventive', reduces: 'likelihood' }
        ],
        explanation: 'Requires OT network access (Likelihood 3, not internet-facing) but default credentials are published in vendor manuals online. Any insider or attacker who laterally moves to OT has instant PLC access. Impact 5 because PLC control loss = pump station shutdown or runaway operation. Mitigate: change creds (free, immediate) and segment (reduces blast radius).',
        consequenceGood: 'Default credentials rotated in 2-week sprint. OT VLAN isolated. Insider threat attempt detected and failed.',
        consequenceBad: 'Disgruntled contractor used default creds to disable 4 pump stations. 18-hour water pressure outage for 80,000 residents.',
        consequenceTransfer: 'Liability insurance will not cover infrastructure failures caused by failure to apply basic security hygiene.',
        secplus: 'Domain 2: Default credentials (T1078.001) · Domain 3: Network segmentation for OT/ICS · Domain 5: Cost of control vs. cost of risk'
      },
      {
        id: 'r3-3',
        asset: 'OT Network — SCADA Historian and Engineering Workstations',
        threat: 'Ransomware propagation from IT network to OT network (IT/OT convergence gap)',
        vulnerability: 'IT and OT networks share a flat network segment — no DMZ or data diode between them',
        ale: '$800,000/yr', sle: '$2,000,000', aro: '0.4×/yr',
        optL: 3, optI: 5, optResponse: 'mitigate',
        optControls: ['dmz', 'backup'],
        controls: [
          { id: 'dmz',     name: 'IT/OT DMZ with data diode (unidirectional gateway)', type: 'Preventive', reduces: 'likelihood' },
          { id: 'backup',  name: 'OT-specific immutable backups + tested recovery',    type: 'Corrective', reduces: 'impact'     },
          { id: 'ir_plan', name: 'OT incident response plan + tabletop exercise',      type: 'Corrective', reduces: 'impact'     },
          { id: 'edr',     name: 'OT-compatible EDR on engineering workstations',      type: 'Detective',  reduces: 'impact'     }
        ],
        explanation: 'Colonial Pipeline was IT ransomware that led to OT shutdown due to exactly this architecture gap. Likelihood 3 (requires IT compromise first, then lateral movement) × Impact 5 (treatment operations halt) = 15. A data diode between IT and OT prevents any eastbound traffic — IT ransomware cannot reach OT. Backups enable recovery without paying ransom.',
        consequenceGood: 'Ransomware hit IT network. Data diode prevented OT spread. Water treatment unaffected. IT recovered from backup in 11 hours.',
        consequenceBad: 'Ransomware reached OT historian. SCADA engineers locked out. Manual operations for 9 days. $2M recovery + federal cybersecurity assessment.',
        consequenceTransfer: 'Critical infrastructure cyber insurance requires demonstrated IT/OT segmentation for coverage. Claim rejected.',
        secplus: 'Domain 3: Network segmentation, air gaps, data diodes · Domain 2: Ransomware, lateral movement'
      },
      {
        id: 'r3-4',
        asset: 'Remote Monitoring System (SCADA access for on-call operators)',
        threat: 'Former operator uses credentials not revoked after termination',
        vulnerability: 'Offboarding process is manual — average 11 days to revoke SCADA access after employee departure',
        ale: '$120,000/yr', sle: '$400,000', aro: '0.3×/yr',
        optL: 3, optI: 4, optResponse: 'mitigate',
        optControls: ['autorevoke', 'mfa'],
        controls: [
          { id: 'autorevoke', name: 'Automated credential revocation tied to HR system (same-day)', type: 'Preventive', reduces: 'likelihood' },
          { id: 'mfa',        name: 'MFA on all remote SCADA access',                               type: 'Preventive', reduces: 'likelihood' },
          { id: 'pam',        name: 'Privileged Access Management (PAM) with session recording',    type: 'Detective',  reduces: 'impact'     },
          { id: 'review',     name: 'Quarterly access review — remove stale accounts',              type: 'Detective',  reduces: 'likelihood' }
        ],
        explanation: 'Insider/former-insider threat is one of the highest-probability risks at utilities (disgruntled employees with operational knowledge). Likelihood 3 × Impact 4 = 12. Automated revocation closes the 11-day window. MFA prevents credential replay. PAM records sessions — critical for forensics and deterrence. This maps directly to the principle of least privilege and identity lifecycle management.',
        consequenceGood: 'Terminated operator attempted remote login 3 days after firing. Account already revoked. Alert fired. Law enforcement notified.',
        consequenceBad: 'Former operator (fired for cause) logged in remotely 6 days later, modified pump schedules. 14-hour service disruption.',
        consequenceTransfer: 'No transfer option — operational consequences are the utility\'s responsibility regardless of who caused them.',
        secplus: 'Domain 1: Identity lifecycle management · Domain 2: Insider threat · Domain 5: Least privilege, PAM'
      },
      {
        id: 'r3-5',
        asset: 'Remote Pump Stations (8 unmanned locations)',
        threat: 'Physical intrusion and manual sabotage of pumps or chemical storage',
        vulnerability: 'Pump stations use standard padlocks; no alarm systems, CCTV, or tamper detection installed',
        ale: '$48,000/yr', sle: '$120,000', aro: '0.4×/yr',
        optL: 2, optI: 4, optResponse: 'mitigate',
        optControls: ['alarm', 'cctv'],
        controls: [
          { id: 'alarm',  name: 'Intrusion alarm with 24/7 monitoring + police response', type: 'Detective',  reduces: 'impact'     },
          { id: 'cctv',   name: 'IP CCTV with motion detection at all stations',          type: 'Detective',  reduces: 'impact'     },
          { id: 'locks',  name: 'High-security locks + tamper-evident seals',             type: 'Preventive', reduces: 'likelihood' },
          { id: 'fence',  name: 'Perimeter fencing upgrade',                              type: 'Deterrent',  reduces: 'likelihood' }
        ],
        explanation: 'Security+ explicitly includes physical security as part of information and operational security. Likelihood 2 (remote locations, not a common target) × Impact 4 (localized service disruption, chemical spill risk) = 8. Alarms + CCTV are detective/deterrent controls that reduce response time and deter casual attackers. Physical security is non-negotiable for unmanned critical infrastructure.',
        consequenceGood: 'Trespasser detected at Station 4 by motion alarm. Police on-scene in 8 minutes. No damage.',
        consequenceBad: 'Vandal disabled pump controls at Station 7. 22,000 residents lost water pressure for 31 hours. $120K in repairs.',
        consequenceTransfer: 'Property insurance covers physical damage but not the service liability or regulatory scrutiny.',
        secplus: 'Domain 3: Physical security controls · Domain 5: Detective and deterrent controls · Control categories'
      }
    ]
  }
];

/* ── State ── */
let currentRound  = 0;
let currentRisk   = 0;
let selectedCell  = null; // {l, i}
let selectedResp  = null;
let selectedCtrl  = new Set();
let totalScore    = 0;
let roundScores   = [];
let riskScores    = [];
let startTime     = null;

const PTS_MATRIX_EXACT    = 10;
const PTS_MATRIX_CLOSE    = 6;
const PTS_MATRIX_FAR      = 2;
const PTS_RESPONSE        = 12;
const PTS_CONTROL         = 8;

/* ── Init ── */
function initRisk() {
  startTime = Date.now();
  SENTINEL.initFirstVisit().then(() => {
    renderRound();
    updateProgressBar();
  });
}

/* ── Render round intro ── */
function renderRound() {
  currentRisk = 0;
  riskScores  = [];
  selectedCell = null;
  selectedResp = null;
  selectedCtrl.clear();

  const r = RISK_ROUNDS[currentRound];
  const main = document.getElementById('risk-main');
  if (!main) return;

  main.innerHTML = `
    <div class="card mb-4" style="background:rgba(0,212,216,0.04);border-color:rgba(0,212,216,0.2);">
      <div class="flex items-start gap-3">
        <div style="font-size:2rem;flex-shrink:0;">${r.icon}</div>
        <div>
          <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.12em;color:var(--teal);margin-bottom:4px;">Round ${r.id} of ${RISK_ROUNDS.length}</div>
          <div class="page-title" style="font-size:1.25rem;margin-bottom:6px;">${SENTINEL._escHtml(r.org)}</div>
          <p class="text-sm" style="line-height:1.7;color:var(--text-muted);margin-bottom:10px;">${SENTINEL._escHtml(r.scenario)}</p>
          <div class="flex items-center gap-2">
            <span class="text-xs text-muted">Risk Tolerance:</span>
            <span class="badge badge-medium">${SENTINEL._escHtml(r.riskTolerance)}</span>
          </div>
        </div>
      </div>
    </div>
    <div id="risk-card-area"></div>
  `;

  renderRiskCard();
  updateRightPanel();
}

/* ── Render one risk card ── */
function renderRiskCard() {
  const r  = RISK_ROUNDS[currentRound];
  const ri = r.risks[currentRisk];
  selectedCell = null; selectedResp = null; selectedCtrl.clear();

  const area = document.getElementById('risk-card-area');
  if (!area) return;

  area.innerHTML = `
    <!-- Risk details -->
    <div class="card mb-3">
      <div class="flex items-center justify-between mb-3">
        <div class="flex items-center gap-2">
          <span class="badge badge-muted">Risk ${currentRisk + 1} of ${r.risks.length}</span>
          <span class="card-title-large">${SENTINEL._escHtml(ri.asset)}</span>
        </div>
      </div>
      <div class="risk-detail-grid">
        <div class="risk-detail-item">
          <div class="risk-detail-label">Threat</div>
          <div class="risk-detail-val">${SENTINEL._escHtml(ri.threat)}</div>
        </div>
        <div class="risk-detail-item">
          <div class="risk-detail-label">Vulnerability</div>
          <div class="risk-detail-val">${SENTINEL._escHtml(ri.vulnerability)}</div>
        </div>
        <div class="risk-detail-item">
          <div class="risk-detail-label">ALE (Annual Loss Expectancy)</div>
          <div class="risk-detail-val" style="font-family:var(--font-mono);color:var(--high);">${SENTINEL._escHtml(ri.ale)}</div>
        </div>
        <div class="risk-detail-item">
          <div class="risk-detail-label">Sec+ Reference</div>
          <div class="risk-detail-val text-xs" style="color:var(--teal);">${SENTINEL._escHtml(ri.secplus)}</div>
        </div>
      </div>
    </div>

    <!-- Assessment panel -->
    <div class="card mb-3">
      <div class="card-title mb-4" style="color:var(--teal);">Step 1 — Plot this risk on the matrix</div>
      <div class="risk-assess-layout">

        <!-- Matrix -->
        <div>
          <div class="matrix-labels-wrap">
            <div class="matrix-y-axis-label">LIKELIHOOD →</div>
            <div>
              <div class="matrix-header-row">
                <div class="matrix-corner"></div>
                ${[1,2,3,4,5].map(i => `<div class="matrix-axis-label">${i}</div>`).join('')}
                <div class="matrix-axis-end-label">IMPACT</div>
              </div>
              <div id="risk-matrix">${buildMatrix()}</div>
            </div>
          </div>
          <div class="flex items-center gap-3 mt-3" style="font-size:0.7rem;flex-wrap:wrap;">
            <span class="flex items-center gap-1"><span style="width:10px;height:10px;border-radius:2px;background:rgba(74,222,128,0.4);display:inline-block;"></span> Low (1–4)</span>
            <span class="flex items-center gap-1"><span style="width:10px;height:10px;border-radius:2px;background:rgba(250,204,21,0.4);display:inline-block;"></span> Medium (5–9)</span>
            <span class="flex items-center gap-1"><span style="width:10px;height:10px;border-radius:2px;background:rgba(251,146,60,0.4);display:inline-block;"></span> High (10–15)</span>
            <span class="flex items-center gap-1"><span style="width:10px;height:10px;border-radius:2px;background:rgba(244,63,94,0.4);display:inline-block;"></span> Critical (16–25)</span>
          </div>
        </div>

        <!-- Score display -->
        <div>
          <div class="risk-score-display" id="risk-score-display">
            <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted);margin-bottom:4px;">Risk Score</div>
            <div id="score-num" style="font-size:3rem;font-weight:700;font-family:var(--font-mono);color:var(--text-dim);line-height:1;">—</div>
            <div id="score-label" style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text-dim);margin-top:4px;">Select a cell</div>
            <hr class="divider" style="margin:12px 0;">
            <div style="font-size:0.7rem;color:var(--text-dim);">L: <span id="sel-l">—</span> × I: <span id="sel-i">—</span></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Response strategy -->
    <div class="card mb-3" id="response-card" style="opacity:.4;pointer-events:none;">
      <div class="card-title mb-3" style="color:var(--teal);">Step 2 — Choose a response strategy</div>
      <div class="response-grid">
        ${['accept','mitigate','transfer','avoid'].map(resp => `
          <button class="response-btn" id="resp-${resp}" onclick="selectResponse('${resp}')">
            <div class="response-btn-icon">${{accept:'✓',mitigate:'🛡',transfer:'↔',avoid:'✗'}[resp]}</div>
            <div class="response-btn-label">${resp.charAt(0).toUpperCase()+resp.slice(1)}</div>
            <div class="response-btn-desc">${{
              accept:   'Risk is within tolerance — document and monitor',
              mitigate: 'Reduce likelihood or impact with controls',
              transfer: 'Shift financial risk to third party (insurance, contract)',
              avoid:    'Stop the activity that creates the risk entirely'
            }[resp]}</div>
          </button>
        `).join('')}
      </div>
    </div>

    <!-- Controls (shown when mitigate selected) -->
    <div class="card mb-3 hidden" id="controls-card">
      <div class="card-title mb-3" style="color:var(--teal);">Step 3 — Select controls to implement</div>
      <div class="text-xs text-muted mb-3">Choose the most effective controls. Consider cost and control type.</div>
      <div id="controls-list" class="controls-list"></div>
    </div>

    <!-- Submit -->
    <div class="flex gap-3 mb-4">
      <button class="btn btn-primary" id="submit-risk-btn" onclick="submitRisk()" disabled>
        Submit Assessment →
      </button>
    </div>

    <!-- Reveal area -->
    <div id="risk-reveal" class="hidden"></div>
    <div id="risk-nav" class="hidden mt-3"></div>
  `;

  updateRightPanel();
}

/* ── Build 5×5 matrix ── */
function buildMatrix() {
  let html = '';
  for (let l = 5; l >= 1; l--) {
    html += `<div class="matrix-row">`;
    html += `<div class="matrix-row-label">${l}</div>`;
    for (let i = 1; i <= 5; i++) {
      const score = l * i;
      const zone  = score >= 16 ? 'critical' : score >= 10 ? 'high' : score >= 5 ? 'medium' : 'low';
      html += `<div class="matrix-cell matrix-${zone}" data-l="${l}" data-i="${i}" onclick="selectCell(${l},${i})">${score}</div>`;
    }
    html += `</div>`;
  }
  return html;
}

/* ── Matrix cell selection ── */
function selectCell(l, i) {
  selectedCell = {l, i};
  const score  = l * i;

  document.querySelectorAll('.matrix-cell').forEach(c => c.classList.remove('matrix-selected'));
  const cell = document.querySelector(`.matrix-cell[data-l="${l}"][data-i="${i}"]`);
  if (cell) cell.classList.add('matrix-selected');

  const zone  = score >= 16 ? 'Critical' : score >= 10 ? 'High' : score >= 5 ? 'Medium' : 'Low';
  const color = score >= 16 ? 'var(--critical)' : score >= 10 ? 'var(--high)' : score >= 5 ? 'var(--medium)' : 'var(--ok)';
  const numEl = document.getElementById('score-num');
  const lblEl = document.getElementById('score-label');
  const selL  = document.getElementById('sel-l');
  const selI  = document.getElementById('sel-i');
  if (numEl) { numEl.textContent = score; numEl.style.color = color; }
  if (lblEl) { lblEl.textContent = zone + ' Risk'; lblEl.style.color = color; }
  if (selL)  selL.textContent = l;
  if (selI)  selI.textContent = i;

  const respCard = document.getElementById('response-card');
  if (respCard) { respCard.style.opacity = '1'; respCard.style.pointerEvents = 'auto'; }
}

/* ── Response selection ── */
function selectResponse(resp) {
  selectedResp = resp;
  selectedCtrl.clear();

  document.querySelectorAll('.response-btn').forEach(b => b.classList.remove('response-selected'));
  const btn = document.getElementById(`resp-${resp}`);
  if (btn) btn.classList.add('response-selected');

  const ctrlCard = document.getElementById('controls-card');
  const ri = RISK_ROUNDS[currentRound].risks[currentRisk];

  if (resp === 'mitigate' && ri.controls && ri.controls.length) {
    ctrlCard.classList.remove('hidden');
    const list = document.getElementById('controls-list');
    if (list) {
      list.innerHTML = ri.controls.map(c => `
        <label class="control-item" id="ctrl-${c.id}">
          <input type="checkbox" value="${c.id}" onchange="toggleControl('${c.id}')">
          <div class="control-item-body">
            <div class="flex items-center gap-2">
              <span class="badge badge-${c.type === 'Preventive' ? 'teal' : c.type === 'Detective' ? 'low' : c.type === 'Corrective' ? 'medium' : 'muted'}">${c.type}</span>
              <span style="font-size:0.8125rem;font-weight:600;color:var(--text-primary);">${SENTINEL._escHtml(c.name)}</span>
            </div>
            <div class="text-xs text-muted mt-1">Reduces: <strong style="color:var(--text-primary);">${c.reduces}</strong></div>
          </div>
        </label>
      `).join('');
    }
  } else {
    ctrlCard.classList.add('hidden');
  }

  checkSubmitReady();
}

function toggleControl(id) {
  if (selectedCtrl.has(id)) selectedCtrl.delete(id);
  else selectedCtrl.add(id);
  checkSubmitReady();
}

function checkSubmitReady() {
  const btn = document.getElementById('submit-risk-btn');
  if (!btn) return;
  const ri = RISK_ROUNDS[currentRound].risks[currentRisk];
  const needsControls = selectedResp === 'mitigate' && ri.controls && ri.controls.length > 0;
  btn.disabled = !selectedCell || !selectedResp || (needsControls && selectedCtrl.size === 0);
}

/* ── Submit risk assessment ── */
function submitRisk() {
  const ri = RISK_ROUNDS[currentRound].risks[currentRisk];
  let pts  = 0;

  /* Matrix accuracy */
  const dl = Math.abs(selectedCell.l - ri.optL);
  const di = Math.abs(selectedCell.i - ri.optI);
  const dist = dl + di;
  const matrixPts = dist === 0 ? PTS_MATRIX_EXACT : dist <= 2 ? PTS_MATRIX_CLOSE : dist <= 4 ? PTS_MATRIX_FAR : 0;
  pts += matrixPts;

  /* Response */
  const respCorrect = selectedResp === ri.optResponse;
  const respPts = respCorrect ? PTS_RESPONSE : 0;
  pts += respPts;

  /* Controls */
  let ctrlPts = 0;
  if (selectedResp === 'mitigate' && ri.optControls && ri.optControls.length) {
    const correctPicks = ri.optControls.filter(id => selectedCtrl.has(id)).length;
    ctrlPts = Math.round((correctPicks / ri.optControls.length) * PTS_CONTROL);
    pts += ctrlPts;
  }

  totalScore += pts;
  riskScores.push(pts);
  SENTINEL.updateScore(pts);

  /* Disable inputs */
  document.querySelectorAll('.matrix-cell').forEach(c => { c.style.pointerEvents = 'none'; });
  document.querySelectorAll('.response-btn').forEach(b => { b.disabled = true; });
  document.querySelectorAll('.control-item input').forEach(c => { c.disabled = true; });
  const submitBtn = document.getElementById('submit-risk-btn');
  if (submitBtn) submitBtn.disabled = true;

  /* Show correct cell */
  const correctCell = document.querySelector(`.matrix-cell[data-l="${ri.optL}"][data-i="${ri.optI}"]`);
  if (correctCell) correctCell.classList.add('matrix-optimal');

  renderReveal(ri, matrixPts, respCorrect, respPts, ctrlPts, pts);
  updateRightPanel();
}

/* ── Reveal answer ── */
function renderReveal(ri, matrixPts, respCorrect, respPts, ctrlPts, pts) {
  const reveal = document.getElementById('risk-reveal');
  if (!reveal) return;

  const score = selectedCell.l * selectedCell.i;
  const optScore = ri.optL * ri.optI;
  const goodResp = ri.optResponse;

  const consequenceKey = respCorrect ? 'consequenceGood' : (selectedResp === 'transfer' ? 'consequenceTransfer' : 'consequenceBad');
  const consequence = ri[consequenceKey] || ri.consequenceBad;
  const consequenceColor = respCorrect ? 'var(--ok)' : 'var(--critical)';

  reveal.innerHTML = `
    <div class="card" style="border-color:rgba(94,234,212,.25);">
      <div class="flex items-center justify-between mb-3">
        <div class="card-title" style="color:var(--teal);">Assessment Review</div>
        <div class="stat-big stat-teal" style="font-size:1.5rem;">+${pts} pts</div>
      </div>

      <div class="reveal-grid">
        <!-- Matrix accuracy -->
        <div class="reveal-item ${matrixPts === PTS_MATRIX_EXACT ? 'reveal-correct' : matrixPts > 0 ? 'reveal-partial' : 'reveal-wrong'}">
          <div class="reveal-item-head">Risk Score</div>
          <div class="reveal-item-body">
            Your score: <strong>${score}</strong> (L${selectedCell.l} × I${selectedCell.i}) &nbsp;·&nbsp;
            Optimal: <strong>${optScore}</strong> (L${ri.optL} × I${ri.optI})
            <span class="font-mono" style="margin-left:8px;color:var(--teal);">+${matrixPts} pts</span>
          </div>
        </div>

        <!-- Response -->
        <div class="reveal-item ${respCorrect ? 'reveal-correct' : 'reveal-wrong'}">
          <div class="reveal-item-head">Response Strategy</div>
          <div class="reveal-item-body">
            Your choice: <strong>${selectedResp}</strong> &nbsp;·&nbsp;
            Recommended: <strong>${goodResp}</strong>
            <span class="font-mono" style="margin-left:8px;color:var(--teal);">+${respPts} pts</span>
          </div>
        </div>

        ${selectedResp === 'mitigate' && ri.optControls && ri.optControls.length ? `
        <div class="reveal-item ${ctrlPts === PTS_CONTROL ? 'reveal-correct' : ctrlPts > 0 ? 'reveal-partial' : 'reveal-wrong'}">
          <div class="reveal-item-head">Control Selection</div>
          <div class="reveal-item-body">
            Optimal controls: <strong>${ri.optControls.map(id => ri.controls.find(c => c.id === id)?.name || id).join(', ')}</strong>
            <span class="font-mono" style="margin-left:8px;color:var(--teal);">+${ctrlPts} pts</span>
          </div>
        </div>` : ''}
      </div>

      <!-- Explanation -->
      <div class="mt-3 p-3" style="background:var(--bg-2);border-radius:var(--radius-md);">
        <div class="text-xs font-mono" style="color:var(--teal);margin-bottom:6px;">WHY</div>
        <p class="text-xs" style="line-height:1.7;color:var(--text-muted);">${SENTINEL._escHtml(ri.explanation)}</p>
      </div>

      <!-- Consequence -->
      <div class="mt-3 p-3" style="background:${respCorrect ? 'rgba(74,222,128,0.06)' : 'rgba(244,63,94,0.06)'};border:1px solid ${respCorrect ? 'rgba(74,222,128,0.25)' : 'rgba(244,63,94,0.2)'};border-radius:var(--radius-md);">
        <div class="text-xs font-mono mb-1" style="color:${consequenceColor};">${respCorrect ? 'OUTCOME — WHAT HAPPENED' : 'CONSEQUENCE — WHAT WENT WRONG'}</div>
        <p class="text-xs" style="line-height:1.6;color:${consequenceColor};">${SENTINEL._escHtml(consequence)}</p>
      </div>

      <div class="text-xs mt-2" style="color:rgba(94,234,212,.6);">📘 ${SENTINEL._escHtml(ri.secplus)}</div>
    </div>
  `;
  reveal.classList.remove('hidden');

  /* Nav button */
  const nav = document.getElementById('risk-nav');
  const r   = RISK_ROUNDS[currentRound];
  const isLastRisk  = currentRisk >= r.risks.length - 1;
  const isLastRound = currentRound >= RISK_ROUNDS.length - 1;

  if (nav) {
    nav.innerHTML = `
      <div class="flex gap-3" style="justify-content:flex-end;">
        ${isLastRisk
          ? isLastRound
            ? `<button class="btn btn-primary btn-lg" onclick="showFinalDebrief()">View Final Results →</button>`
            : `<button class="btn btn-primary" onclick="nextRound()">Next Round: ${RISK_ROUNDS[currentRound+1].org} →</button>`
          : `<button class="btn btn-primary" onclick="nextRisk()">Next Risk →</button>`
        }
      </div>`;
    nav.classList.remove('hidden');
    nav.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  SENTINEL.toast(`+${pts} pts`, pts >= 20 ? 'success' : 'info');
  updateProgressBar();
}

/* ── Navigation ── */
function nextRisk() {
  currentRisk++;
  window.scrollTo({ top: 0, behavior: 'smooth' });
  setTimeout(renderRiskCard, 80);
}

function nextRound() {
  const r = RISK_ROUNDS[currentRound];
  roundScores.push(riskScores.reduce((a, b) => a + b, 0));
  currentRound++;
  window.scrollTo({ top: 0, behavior: 'smooth' });
  setTimeout(renderRound, 80);
}

/* ── Right panel ── */
function updateRightPanel() {
  const el = document.getElementById('risk-right-panel');
  if (!el) return;
  const r  = RISK_ROUNDS[currentRound];
  el.innerHTML = `
    <div class="card">
      <div class="card-title mb-2">Session Score</div>
      <div class="stat-big stat-teal">${totalScore}</div>
      <div class="stat-label">pts earned</div>
      <hr class="divider">
      <div class="flex justify-between text-xs mb-1">
        <span class="text-muted">Round</span><span class="font-mono text-teal">${currentRound+1} / ${RISK_ROUNDS.length}</span>
      </div>
      <div class="flex justify-between text-xs">
        <span class="text-muted">Risk</span><span class="font-mono text-teal">${currentRisk+1} / ${r.risks.length}</span>
      </div>
    </div>

    <div class="card">
      <div class="card-title mb-3">Scoring</div>
      <div class="flex justify-between text-xs mb-2"><span class="text-muted">Matrix — exact</span><span class="font-mono text-teal">+${PTS_MATRIX_EXACT} pts</span></div>
      <div class="flex justify-between text-xs mb-2"><span class="text-muted">Matrix — close (±2)</span><span class="font-mono text-low">+${PTS_MATRIX_CLOSE} pts</span></div>
      <div class="flex justify-between text-xs mb-2"><span class="text-muted">Correct response</span><span class="font-mono text-teal">+${PTS_RESPONSE} pts</span></div>
      <div class="flex justify-between text-xs"><span class="text-muted">Best controls</span><span class="font-mono text-teal">+${PTS_CONTROL} pts</span></div>
    </div>

    <div class="card">
      <div class="card-title mb-3">Risk = L × I</div>
      <div class="text-xs" style="line-height:1.9;color:var(--text-muted);">
        <div><span style="color:var(--ok);">●</span> 1–4 &nbsp; Low — consider Accept</div>
        <div><span style="color:var(--medium);">●</span> 5–9 &nbsp; Medium — Accept or Mitigate</div>
        <div><span style="color:var(--high);">●</span> 10–15 High — Mitigate or Transfer</div>
        <div><span style="color:var(--critical);">●</span> 16–25 Critical — Mitigate or Avoid</div>
      </div>
    </div>

    <div class="card">
      <div class="card-title mb-3">Response Strategies</div>
      <div class="text-xs" style="line-height:1.9;color:var(--text-muted);">
        <div><strong style="color:var(--ok);">Accept</strong> — within tolerance; document</div>
        <div><strong style="color:var(--teal);">Mitigate</strong> — controls reduce L or I</div>
        <div><strong style="color:var(--low);">Transfer</strong> — insurance / contract shifts $</div>
        <div><strong style="color:var(--critical);">Avoid</strong> — stop the risky activity</div>
      </div>
      <hr class="divider">
      <p class="text-xs" style="line-height:1.6;color:var(--text-muted);">
        <strong style="color:var(--text-primary);">Residual risk</strong> = risk remaining after controls. Transfer does not remove risk — it shifts the financial consequence.
      </p>
    </div>

    <div class="card" style="background:rgba(0,212,216,0.04);border-color:rgba(0,212,216,0.2);">
      <div class="card-title mb-2" style="color:var(--teal);">💡 Key Concept</div>
      <p class="text-xs" style="line-height:1.6;">
        <strong style="color:var(--text-primary);">ALE = SLE × ARO</strong><br>
        Single Loss Expectancy × Annual Rate of Occurrence.<br>
        A CVSS 10 bug patched in 24 hours has a lower ALE than a CVSS 6 bug on an ignored system.
      </p>
    </div>
  `;
}

/* ── Progress bar ── */
function updateProgressBar() {
  const total = RISK_ROUNDS.reduce((s, r) => s + r.risks.length, 0);
  const done  = RISK_ROUNDS.slice(0, currentRound).reduce((s, r) => s + r.risks.length, 0) + riskScores.length;
  const bar   = document.getElementById('risk-progress-fill');
  const lbl   = document.getElementById('risk-progress-label');
  if (bar) bar.style.width = ((done / total) * 100) + '%';
  if (lbl) lbl.textContent = `${done} / ${total} risks assessed`;
}

/* ── Final debrief ── */
function showFinalDebrief() {
  roundScores.push(riskScores.reduce((a, b) => a + b, 0));
  const total    = RISK_ROUNDS.reduce((s, r) => s + r.risks.length, 0);
  const maxScore = total * (PTS_MATRIX_EXACT + PTS_RESPONSE + PTS_CONTROL);
  const pct      = Math.round((totalScore / maxScore) * 100);
  const elapsed  = Math.round((Date.now() - startTime) / 1000);
  const mins = Math.floor(elapsed / 60), secs = elapsed % 60;

  const main = document.getElementById('risk-main');
  if (!main) return;

  main.innerHTML = `
    <div class="score-debrief">
      <div class="text-xs text-muted mb-2" style="text-transform:uppercase;letter-spacing:.1em;">Risk Register Complete</div>
      <div class="stat-big ${SENTINEL.scoreClass(pct)} mb-2">${pct}%</div>
      <div style="font-size:1rem;font-weight:600;color:var(--text-primary);margin-bottom:.5rem;">${SENTINEL.scoreLabel(pct)}</div>
      <div class="text-sm text-muted mb-4">Completed in ${mins}m ${secs}s · ${total} risks across ${RISK_ROUNDS.length} organizations</div>

      <div class="score-breakdown">
        ${RISK_ROUNDS.map((r, i) => `
          <div class="score-row">
            <span class="score-row-label">${r.icon} ${r.org}</span>
            <span class="score-row-val text-teal">+${roundScores[i] || 0} pts</span>
          </div>`).join('')}
        <div class="score-row" style="border-top:1px solid var(--border);padding-top:8px;margin-top:4px;">
          <span class="score-row-label" style="font-weight:700;color:var(--text-primary);">Total</span>
          <span class="score-row-val text-teal" style="font-size:1rem;">${totalScore} pts</span>
        </div>
      </div>

      <div class="card mt-4" style="background:rgba(0,212,216,0.04);border-color:rgba(0,212,216,0.2);text-align:left;">
        <div class="card-title mb-2" style="color:var(--teal);">What you practiced (Security+ Domain 5)</div>
        <div class="text-xs" style="line-height:1.9;color:var(--text-muted);">
          <div>📘 <strong style="color:var(--text-primary);">Qualitative risk analysis</strong> — Likelihood × Impact matrix scoring</div>
          <div>📘 <strong style="color:var(--text-primary);">Risk response strategies</strong> — Accept, Mitigate, Transfer, Avoid with real tradeoffs</div>
          <div>📘 <strong style="color:var(--text-primary);">Control types</strong> — Preventive, Detective, Corrective, Deterrent, Administrative</div>
          <div>📘 <strong style="color:var(--text-primary);">Quantitative concepts</strong> — ALE, SLE, ARO applied to real scenarios</div>
          <div>📘 <strong style="color:var(--text-primary);">Compliance context</strong> — GDPR, PCI-DSS, GLBA, OCC, DISA framing risk decisions</div>
          <div>📘 <strong style="color:var(--text-primary);">Residual risk</strong> — Transfer shifts $, not the underlying risk</div>
        </div>
      </div>

      <div class="flex gap-3 mt-4" style="justify-content:center;">
        <a href="logs.html" class="btn btn-primary btn-lg">Log Analysis →</a>
        <button onclick="resetModule()" class="btn btn-secondary">Retry Risk Register</button>
      </div>
    </div>
  `;

  const p = SENTINEL.getProgress();
  p.riskScore = totalScore; p.riskCompleted = true;
  SENTINEL.saveProgress(p);
  updateProgressBar();
}

function resetModule() {
  currentRound = 0; currentRisk = 0;
  totalScore = 0; roundScores = []; riskScores = [];
  selectedCell = null; selectedResp = null; selectedCtrl.clear();
  startTime = Date.now();
  window.scrollTo({ top: 0, behavior: 'smooth' });
  renderRound(); updateProgressBar();
}

document.addEventListener('DOMContentLoaded', initRisk);
