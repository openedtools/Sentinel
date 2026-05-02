/* SENTINEL — Glossary & Term Tooltips
   Scans all text nodes on load and wraps known security terms with hover tooltips.
   Acronyms always show their full expansion first, reinforcing the term for ESL learners. */
'use strict';

const GLOSSARY = {

  /* ── Security Operations ── */
  'SIEM': {
    expand: 'Security Information and Event Management',
    def: 'Software that collects logs from every system in real time, spots suspicious patterns, and fires alerts. SENTINEL simulates one.'
  },
  'SOAR': {
    expand: 'Security Orchestration, Automation and Response',
    def: 'A platform that automates repetitive analyst tasks — like isolating a host or resetting a password — in response to an alert. Reduces mean-time-to-respond.'
  },
  'SOC': {
    expand: 'Security Operations Center',
    def: 'The team (and room) responsible for monitoring an organization\'s systems 24/7, triaging alerts, and responding to incidents.'
  },
  'EDR': {
    expand: 'Endpoint Detection and Response',
    def: 'Software installed on every laptop and server that records what processes run, watches for malicious behavior, and can isolate the device remotely.'
  },
  'IOC': {
    expand: 'Indicator of Compromise',
    def: 'Evidence that an attack has already happened — a malicious IP address, file hash, domain name, or registry key left behind by the attacker.'
  },
  'IOA': {
    expand: 'Indicator of Attack',
    def: 'Signs that an attack is in progress right now — unusual process behavior, lateral movement attempts — before damage is done. Earlier warning than an IOC.'
  },
  'APT': {
    expand: 'Advanced Persistent Threat',
    def: 'A highly skilled, well-funded attacker (often a nation-state) who breaks in quietly and stays for months or years to steal data without being detected.'
  },
  'TTPs': {
    expand: 'Tactics, Techniques, and Procedures',
    def: 'The attacker\'s playbook: the overall goal (tactic), how they achieve it (technique), and the specific tools or steps (procedure). Documented in MITRE ATT&CK.'
  },
  'TTP': {
    expand: 'Tactic, Technique, or Procedure',
    def: 'One entry from an attacker\'s playbook: a goal, method, or specific step. See also: TTPs.'
  },
  'MITRE ATT&CK': {
    expand: 'MITRE Adversarial Tactics, Techniques & Common Knowledge',
    def: 'A free, publicly maintained knowledge base of real-world attacker behaviors organized by tactic (why) and technique (how). The industry-standard reference for threat modeling.'
  },

  /* ── Attack Techniques ── */
  'lateral movement': {
    def: 'After breaking into one machine, the attacker jumps to other systems inside the network — looking for more valuable targets like a domain controller or file server.'
  },
  'exfiltration': {
    def: 'Secretly copying stolen data out of the network and sending it to the attacker. Often disguised as normal web traffic or DNS queries to avoid detection.'
  },
  'privilege escalation': {
    def: 'Gaining higher-level access than you started with. A regular user account becomes an admin; an admin becomes a domain administrator with full network control.'
  },
  'persistence': {
    def: 'Techniques attackers use to stay on a system even after reboots — creating new admin accounts, installing backdoors, or modifying startup tasks.'
  },
  'reconnaissance': {
    def: 'The attacker\'s information-gathering phase: scanning ports, probing services, mapping the network, and researching targets before launching the real attack.'
  },
  'beaconing': {
    def: 'Malware that regularly "phones home" to an attacker\'s server — like a heartbeat — to receive new instructions or confirm the compromised machine is still online.'
  },
  'command and control': {
    def: 'The communication channel between malware on a victim\'s machine and the attacker. Abbreviated C2 or C&C. Cutting this channel isolates the attacker from their malware.'
  },

  /* ── Malware ── */
  'malware': {
    def: 'Any software intentionally designed to damage a system, steal data, or gain unauthorized access. Includes viruses, ransomware, spyware, and trojans.'
  },
  'ransomware': {
    def: 'Malware that encrypts all your files and demands a ransom payment in cryptocurrency to unlock them. Modern ransomware also exfiltrates a copy of your data first.'
  },
  'polymorphic': {
    def: 'Malware that constantly rewrites its own code — changing its appearance on every infection. Defeats signature-based antivirus because there is no fixed pattern to match.'
  },
  'botnet': {
    def: 'A network of hundreds or thousands of compromised computers controlled remotely by an attacker. Used for spam, DDoS attacks, or stealing credentials at scale.'
  },

  /* ── Vulnerabilities ── */
  'CVE': {
    expand: 'Common Vulnerabilities and Exposures',
    def: 'A unique public ID number for a specific security flaw — like a bug report number the whole industry shares. Example: CVE-2021-44228 is the Log4Shell vulnerability.'
  },
  'CVSS': {
    expand: 'Common Vulnerability Scoring System',
    def: 'A 0–10 number that rates how severe a vulnerability is. Score of 9.8 means patch immediately. Score of 2.0 can wait. Used to prioritize which flaws to fix first.'
  },
  'zero-day': {
    def: 'A vulnerability the software vendor doesn\'t know about yet — so there\'s no patch. Attackers who find these can exploit them freely until the vendor discovers and fixes the flaw.'
  },
  'exploit': {
    def: 'A piece of code or a technique that takes advantage of a specific vulnerability to gain unauthorized access or cause harm.'
  },

  /* ── Identity ── */
  'MFA': {
    expand: 'Multi-Factor Authentication',
    def: 'Requiring two or more proofs of identity to log in: something you know (password) + something you have (phone app) + something you are (fingerprint). One stolen factor is not enough.'
  },
  'PAM': {
    expand: 'Privileged Access Management',
    def: 'Tools that control, monitor, and record what administrators and high-privilege accounts do. Limits the "blast radius" if an admin account is compromised.'
  },
  'SSO': {
    expand: 'Single Sign-On',
    def: 'Log in once and access all your authorized applications without re-entering credentials. Convenient, but a high-value target — one stolen token unlocks everything.'
  },
  'LDAP': {
    expand: 'Lightweight Directory Access Protocol',
    def: 'A protocol for looking up and authenticating users against a directory like Active Directory. Attackers often query LDAP to enumerate user accounts and groups.'
  },
  'Active Directory': {
    def: 'Microsoft\'s service that manages users, computers, and permissions in a Windows network. Compromising it (especially the Domain Controller) means full control of the entire organization.'
  },

  /* ── Network ── */
  'firewall': {
    def: 'A system that sits between networks and decides which traffic to allow or block based on rules. Like a security guard checking IDs at a door.'
  },
  'IDS': {
    expand: 'Intrusion Detection System',
    def: 'A sensor that watches network traffic and raises an alarm when it sees suspicious patterns. Detects but does not block — compare with IPS.'
  },
  'IPS': {
    expand: 'Intrusion Prevention System',
    def: 'Like an IDS, but it automatically blocks malicious traffic in real time rather than just alerting on it.'
  },
  'NGFW': {
    expand: 'Next-Generation Firewall',
    def: 'A firewall that inspects the actual content of packets (not just ports and IPs), understands applications, and integrates threat intelligence feeds.'
  },
  'DLP': {
    expand: 'Data Loss Prevention',
    def: 'Tools that monitor and block sensitive data from leaving the organization — catching credit card numbers in emails or patient records being uploaded to cloud storage.'
  },
  'VPN': {
    expand: 'Virtual Private Network',
    def: 'An encrypted tunnel between your device and a remote network. Makes your traffic private and lets remote employees access internal systems securely.'
  },
  'DNS': {
    expand: 'Domain Name System',
    def: 'The internet\'s phone book — translates human-readable names (google.com) into IP addresses. Attackers abuse DNS for command-and-control traffic and data exfiltration.'
  },
  'TLS': {
    expand: 'Transport Layer Security',
    def: 'The encryption protocol that secures HTTPS connections. When you see a padlock in your browser, TLS is protecting the data in transit. Successor to the broken SSL protocol.'
  },
  'HTTPS': {
    expand: 'HyperText Transfer Protocol Secure',
    def: 'HTTP with TLS encryption added. All data between your browser and the server is encrypted in transit. The padlock icon in the address bar confirms it is active.'
  },

  /* ── Cryptography ── */
  'AES': {
    expand: 'Advanced Encryption Standard',
    def: 'The world\'s most widely used symmetric encryption algorithm. AES-256 uses a 256-bit key and is considered quantum-resistant. Used to encrypt files, disks, and VPN tunnels.'
  },
  'RSA': {
    expand: 'Rivest–Shamir–Adleman',
    def: 'The most common asymmetric encryption algorithm. A public key encrypts; only the matching private key decrypts. Vulnerable to quantum computers running Shor\'s algorithm.'
  },
  'PKI': {
    expand: 'Public Key Infrastructure',
    def: 'The system of certificates, certificate authorities, and trust rules that lets browsers verify a website is really who it claims to be.'
  },
  'CA': {
    expand: 'Certificate Authority',
    def: 'A trusted organization that issues digital certificates and vouches for the identity of websites. Your browser ships with ~150 trusted Root CAs pre-installed by your operating system.'
  },
  'HNDL': {
    expand: 'Harvest Now, Decrypt Later',
    def: 'A quantum attack strategy: adversaries record encrypted traffic today and store it, planning to decrypt it once a quantum computer arrives. Data with long secrecy requirements is already at risk.'
  },
  'PQC': {
    expand: 'Post-Quantum Cryptography',
    def: 'Encryption algorithms designed to resist attacks from quantum computers. NIST finalized three standards in 2024: ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205).'
  },
  'ML-KEM': {
    expand: 'Module-Lattice Key Encapsulation Mechanism',
    def: 'NIST FIPS 203. The post-quantum replacement for RSA and ECDH key exchange. Formerly CRYSTALS-Kyber. Based on the hardness of solving lattice math problems.'
  },
  'ML-DSA': {
    expand: 'Module-Lattice Digital Signature Algorithm',
    def: 'NIST FIPS 204. The post-quantum replacement for RSA and ECDSA digital signatures (used in TLS certificates). Formerly CRYSTALS-Dilithium.'
  },
  'SLH-DSA': {
    expand: 'Stateless Hash-Based Digital Signature Algorithm',
    def: 'NIST FIPS 205. A conservative backup to ML-DSA using only hash functions — no lattice math. Formerly SPHINCS+. Larger signatures but minimal security assumptions.'
  },
  'SHA-256': {
    expand: 'Secure Hash Algorithm — 256-bit output',
    def: 'A cryptographic hash function producing a fixed 64-character fingerprint. Used for file integrity and password storage. Adequate but SHA-512 is preferred for new designs.'
  },
  'SHA-512': {
    expand: 'Secure Hash Algorithm — 512-bit output',
    def: 'The stronger sibling of SHA-256, producing a 128-character fingerprint. Retains 256-bit security even against a quantum computer running Grover\'s algorithm.'
  },
  'MD5': {
    expand: 'Message Digest Algorithm 5',
    def: 'A fast hash function that is cryptographically broken — never use it for security. Rainbow table attacks crack MD5 passwords in milliseconds. Still seen in legacy systems.'
  },
  'IV': {
    expand: 'Initialization Vector',
    def: 'A random value mixed into encryption to ensure the same message encrypted twice produces different ciphertext each time. Without it, patterns leak through encrypted data.'
  },
  'ciphertext': {
    def: 'Encrypted data. Without the correct key, ciphertext is indistinguishable from random noise — its contents are completely hidden.'
  },
  'plaintext': {
    def: 'Unencrypted, human-readable data — either before encryption happens, or after successful decryption.'
  },

  /* ── Threats / Social Engineering ── */
  'phishing': {
    def: 'A fraudulent email (or message) designed to trick the recipient into revealing credentials, clicking a malicious link, or opening an infected attachment. The most common attack entry point.'
  },
  'spear-phishing': {
    def: 'Targeted phishing aimed at a specific person, using personal details — job title, colleague names, recent events — to make the message appear legitimate.'
  },
  'social engineering': {
    def: 'Manipulating people — not systems — to gain access or information. Phishing, pretexting (fake personas), and vishing (voice calls) are all forms of social engineering.'
  },
  'prompt injection': {
    def: 'Embedding hidden instructions in content that an AI system will process — tricking it into ignoring its original instructions and doing something harmful instead.'
  },
  'supply chain attack': {
    def: 'Compromising a vendor\'s software or hardware before it reaches the victim. The attacker poisons the source so every customer who installs the product is infected.'
  },
  'MITM': {
    expand: 'Man-in-the-Middle Attack',
    def: 'An attacker secretly intercepts and possibly alters communication between two parties, each of whom believes they are talking directly to the other.'
  },
  'WormGPT': {
    def: 'An AI tool sold on criminal forums, fine-tuned specifically to write convincing phishing emails and malware with no ethical guardrails. Counterpart to legitimate AI assistants.'
  },

  /* ── Detection ── */
  'YARA': {
    expand: 'Yet Another Recursive Acronym',
    def: 'A pattern-matching rule language for identifying malware samples. Analysts write YARA rules that describe suspicious file characteristics — strings, byte patterns, file structure.'
  },
  'Sigma': {
    def: 'A generic, tool-agnostic format for writing SIEM detection rules. A single Sigma rule can be converted to query language for Splunk, Elastic, Microsoft Sentinel, and others.'
  },
  'false positive': {
    def: 'An alert triggered by legitimate, benign activity rather than a real threat. Too many false positives cause alert fatigue — analysts begin ignoring alerts, including real ones.'
  },
  'false negative': {
    def: 'A real threat that the security system failed to detect. The most dangerous outcome — you have no idea an attack occurred or is in progress.'
  },
  'threat intelligence': {
    def: 'Curated information about known attacker TTPs, infrastructure, and targets — shared between organizations and vendors so defenders can proactively block known threats.'
  },
  'threat hunting': {
    def: 'Proactively searching for attackers already inside the network, rather than waiting for an automated alert. Assumes the network may already be compromised.'
  },

  /* ── Risk / Compliance ── */
  'risk register': {
    def: 'A document that lists all known organizational risks with their likelihood, potential impact, and current controls. Used to decide what to accept, mitigate, transfer, or avoid.'
  },
  'HIPAA': {
    expand: 'Health Insurance Portability and Accountability Act',
    def: 'US law requiring healthcare organizations to protect patient health data with administrative, physical, and technical safeguards. Violations carry significant fines.'
  },
  'PCI-DSS': {
    expand: 'Payment Card Industry Data Security Standard',
    def: 'A security standard that any organization processing credit card payments must follow. Covers encryption, access control, network segmentation, and regular penetration testing.'
  },
  'NIST': {
    expand: 'National Institute of Standards and Technology',
    def: 'A US federal agency that publishes widely adopted cybersecurity standards and frameworks — including NIST SP 800-53 (security controls) and the Cybersecurity Framework (CSF).'
  },
  'GRC': {
    expand: 'Governance, Risk, and Compliance',
    def: 'The combined practice of setting security policies (governance), managing organizational risk, and meeting regulatory requirements (compliance).'
  },

  /* ── Incident Response ── */
  'triage': {
    def: 'Rapidly sorting and prioritizing alerts or incidents by urgency — focusing limited analyst time on the most critical threats first. Borrowed from emergency medicine.'
  },
  'containment': {
    def: 'Isolating compromised systems from the rest of the network to stop an attack from spreading further. Typically the first active response step after confirming a breach.'
  },
  'quarantine': {
    def: 'Removing a device from the network while preserving its state and logs for forensic investigation. Like containment but with emphasis on evidence preservation.'
  },
  'remediation': {
    def: 'Fixing the root cause after an attack: removing malware, patching the exploited vulnerability, resetting compromised credentials, and restoring from clean backups.'
  }
};

/* ── Tooltip engine ── */
(function () {

  let _tip = null;

  function getTip() {
    if (!_tip) {
      _tip = document.createElement('div');
      _tip.id = 'gl-tip';
      document.body.appendChild(_tip);
    }
    return _tip;
  }

  function showTip(termEl, key) {
    const entry = GLOSSARY[key];
    if (!entry) return;

    const tip = getTip();
    tip.innerHTML =
      `<div class="gl-term">${key}</div>` +
      (entry.expand ? `<div class="gl-expand">${entry.expand}</div>` : '') +
      `<div class="gl-def">${entry.def}</div>`;

    /* Position above the term; flip below if near top of viewport */
    tip.style.visibility = 'hidden';
    tip.style.opacity = '0';
    tip.classList.add('gl-visible');

    requestAnimationFrame(() => {
      const rect = termEl.getBoundingClientRect();
      const tipH = tip.offsetHeight;
      const tipW = tip.offsetWidth;

      let top = rect.top - tipH - 10;
      if (top < 8) top = rect.bottom + 8;

      let left = rect.left;
      if (left + tipW > window.innerWidth - 8) left = window.innerWidth - tipW - 8;
      if (left < 8) left = 8;

      tip.style.top  = top + 'px';
      tip.style.left = left + 'px';
      tip.style.visibility = '';
      tip.style.opacity = '1';
    });
  }

  function hideTip() {
    if (_tip) {
      _tip.style.opacity = '0';
      _tip.classList.remove('gl-visible');
    }
  }

  /* Elements whose entire subtree should be skipped when scanning */
  const SKIP_TAGS = new Set([
    'SCRIPT', 'STYLE', 'CODE', 'PRE', 'BUTTON',
    'INPUT', 'TEXTAREA', 'SELECT', 'OPTION', 'A',
    'LABEL', 'HEADER', 'NAV'
  ]);
  const SKIP_CLASSES = [
    'sidebar', 'topbar', 'nav-item', 'nav-section-label',
    'btn', 'badge', 'pill', 'quiz-option', 'glossary-term',
    'brand', 'user-card', 'toast', 'modal-overlay'
  ];

  function shouldSkip(el) {
    if (SKIP_TAGS.has(el.tagName)) return true;
    return SKIP_CLASSES.some(c => el.classList.contains(c));
  }

  SENTINEL.initGlossary = function () {

    /* Build a lowercase lookup map: "lateral movement" → canonical key */
    const termMap = new Map();
    for (const key of Object.keys(GLOSSARY)) {
      termMap.set(key.toLowerCase(), key);
    }

    /* Sort terms longest-first so multi-word phrases match before shorter substrings */
    const sortedTerms = Array.from(termMap.keys()).sort((a, b) => b.length - a.length);

    /* Build combined regex */
    const escaped = sortedTerms.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    const re = new RegExp('\\b(' + escaped.join('|') + ')\\b', 'gi');

    /* Walk all text nodes */
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          let el = node.parentElement;
          while (el && el !== document.body) {
            if (shouldSkip(el)) return NodeFilter.FILTER_REJECT;
            el = el.parentElement;
          }
          return node.textContent.trim() ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
        }
      }
    );

    /* Collect first — never modify the DOM while walking */
    const textNodes = [];
    let n;
    while ((n = walker.nextNode())) textNodes.push(n);

    textNodes.forEach(textNode => {
      const text = textNode.textContent;
      if (!re.test(text)) { re.lastIndex = 0; return; }
      re.lastIndex = 0;

      const frag = document.createDocumentFragment();
      let last = 0, m;
      re.lastIndex = 0;

      while ((m = re.exec(text)) !== null) {
        /* Text before this match */
        if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));

        /* Wrap the matched term */
        const canonicalKey = termMap.get(m[0].toLowerCase());
        const span = document.createElement('span');
        span.className = 'glossary-term';
        span.dataset.glKey = canonicalKey;
        span.textContent = m[0];
        frag.appendChild(span);

        last = m.index + m[0].length;
      }

      if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
      textNode.parentNode.replaceChild(frag, textNode);
    });

    /* Delegated hover events — one listener for the entire page */
    document.addEventListener('mouseover', e => {
      const term = e.target.closest('.glossary-term');
      if (term) showTip(term, term.dataset.glKey);
    });

    document.addEventListener('mouseout', e => {
      if (e.target.closest('.glossary-term')) hideTip();
    });
  };

  /* Auto-init after renderShell() has run (main.js DOMContentLoaded fires first) */
  document.addEventListener('DOMContentLoaded', () => {
    if (typeof SENTINEL !== 'undefined') SENTINEL.initGlossary();
  });

}());
