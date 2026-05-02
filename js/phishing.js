/* SENTINEL — Phishing Header Forensics Lab
   5 progressively harder email samples; students click Examine buttons
   to surface forensic findings, then answer a quiz question per email. */
'use strict';

/* ── State ── */
let currentEmail  = 0;
let emailScores   = [null, null, null, null, null];
let totalScore    = 0;
let startTime     = null;
let examined      = [new Set(), new Set(), new Set(), new Set(), new Set()];

const PHISH_EMAILS = [
  { id: 1, title: 'Display Name Spoofing',    icon: '🎭', pts: 20 },
  { id: 2, title: 'Reply-To Redirect (BEC)',  icon: '↩',  pts: 20 },
  { id: 3, title: 'Authentication Deep Dive', icon: '🔬', pts: 20 },
  { id: 4, title: 'Lookalike Domain',         icon: '👥', pts: 20 },
  { id: 5, title: 'AI-Generated (WormGPT)',   icon: '🤖', pts: 20 },
];

/* ── Email data ── */
const EMAILS = [

  /* ── Email 1: Display Name Spoofing + Urgency ── */
  {
    meta: {
      from_name:  '"PayPal Security Team"',
      from_addr:  'security@paypal-accounts-verify.com',
      to:         'analyst@dcoi.mil',
      date:       'Mon, 28 Apr 2026  09:14:32 -0500',
      subject:    'Urgent: Your PayPal Account Has Been Compromised',
      reply_to:   null,
      spf:        { result: 'pass',  detail: 'paypal-accounts-verify.com' },
      dkim:       { result: 'pass',  detail: 'd=paypal-accounts-verify.com' },
      dmarc:      { result: 'fail',  detail: 'p=reject; not aligned with paypal.com' },
    },
    body: `
      <p style="margin-bottom:12px;">Dear PayPal Customer,</p>
      <p style="margin-bottom:12px;">We have detected <strong>unusual sign-in activity</strong> on your account from
      an unrecognized device in <strong>Lagos, Nigeria</strong>. To protect your account,
      all outbound payments have been temporarily suspended.</p>
      <p style="margin-bottom:16px;color:var(--critical);font-weight:600;">
        You must verify your identity within 24 hours or your account will be permanently closed.
      </p>
      <div style="text-align:center;margin-bottom:16px;">
        <a href="#" class="phish-link" data-real="http://paypal-accounts-verify.com/confirm?token=xK9s2"
           onclick="return false;"
           style="display:inline-block;background:#003087;color:#fff;padding:12px 28px;border-radius:4px;text-decoration:none;font-weight:600;">
          Secure My Account Now →
        </a>
        <div class="phish-link-reveal" style="display:none;margin-top:6px;font-size:11px;font-family:var(--font-mono);color:var(--critical);">
          Real URL: http://paypal-accounts-verify.com/confirm?token=xK9s2
        </div>
      </div>
      <p style="font-size:12px;color:var(--text-muted);">
        This email was sent to analyst@dcoi.mil because it is linked to a PayPal account.
        © 2026 PayPal, Inc. All rights reserved.
      </p>`,
    findings: [
      {
        id: 'sender',
        label: 'Sender Address',
        icon: '📮',
        title: 'Display Name ≠ Sending Domain',
        body: 'The <em>display name</em> reads "PayPal Security Team" — but the actual sending address is <code>security@paypal-accounts-verify.com</code>. PayPal\'s real domain is <code>paypal.com</code>. Email clients show the display name prominently; many users never see the actual address. This is the most common spoofing technique.',
        severity: 'critical'
      },
      {
        id: 'dmarc',
        label: 'DMARC Result',
        icon: '🔐',
        title: 'DMARC: FAIL — Domain Alignment Broken',
        body: 'DMARC checks that the <em>From</em> domain aligns with the SPF and DKIM authenticated domain. Here, SPF and DKIM pass for <code>paypal-accounts-verify.com</code>, but DMARC fails because that domain is not aligned with <code>paypal.com</code>. The attacker <strong>owns</strong> paypal-accounts-verify.com — so SPF and DKIM passing is meaningless. DMARC is the only check that catches this.',
        severity: 'critical'
      },
      {
        id: 'link',
        label: 'Call-to-Action Link',
        icon: '🔗',
        title: 'Link Text Hides Real Destination',
        body: 'The button says "Secure My Account Now" but the real URL is <code>http://paypal-accounts-verify.com/confirm?token=xK9s2</code> — the attacker\'s own domain. In a real email client, hovering over a link reveals the true destination in the status bar. <strong>Never click a link in a suspicious email — navigate directly to the site.</strong>',
        severity: 'high'
      },
      {
        id: 'urgency',
        label: 'Language & Pressure',
        icon: '⚡',
        title: 'Artificial Urgency — Social Engineering',
        body: '"Verify within 24 hours or your account will be <strong>permanently closed</strong>" is a classic pressure tactic designed to override rational decision-making. Legitimate financial institutions do not threaten immediate permanent closure via email. Urgency + fear + a single action link = textbook phishing formula.',
        severity: 'medium'
      }
    ],
    quiz: {
      q: 'What is the most <em>technically reliable</em> indicator that this email is NOT from PayPal?',
      opts: [
        { val: 'A', text: 'The subject line uses the word "urgent"' },
        { val: 'B', text: 'DMARC authentication failed — the sending domain is not aligned with paypal.com' },
        { val: 'C', text: 'PayPal always addresses customers by their full legal name' },
        { val: 'D', text: 'The email arrived during business hours, which is suspicious' },
      ],
      correct: 'B',
      explain: 'Urgency language is a behavioral red flag but not a technical proof — legitimate urgent emails exist. DMARC failure is a cryptographic authentication result: it proves mathematically that the message did not come from an authorized PayPal mail server.'
    }
  },

  /* ── Email 2: Reply-To Redirect / BEC ── */
  {
    meta: {
      from_name:  '"Col. David Kim, Commander DCOI"',
      from_addr:  'd.kim@dcoi-command.org',
      to:         'finance@dcoi.mil',
      date:       'Tue, 29 Apr 2026  06:58:11 +0700',
      subject:    'Urgent — Confidential Wire Transfer Required Today',
      reply_to:   'david.kim.urgent@protonmail.com',
      spf:        { result: 'pass',  detail: 'dcoi-command.org' },
      dkim:       { result: 'pass',  detail: 'd=dcoi-command.org' },
      dmarc:      { result: 'pass',  detail: 'p=quarantine; aligned' },
    },
    body: `
      <p style="margin-bottom:12px;">I need your immediate and discreet assistance.</p>
      <p style="margin-bottom:12px;">I am currently in transit and cannot take calls. We have an urgent
      procurement obligation that must be settled by end of business today to avoid a contract
      penalty. I need you to arrange a wire transfer of <strong>USD 47,500</strong> to the vendor's
      account. I will send the account details in a follow-up email once you confirm you can handle this.</p>
      <p style="margin-bottom:12px;color:var(--medium);">
        <strong>This is time-sensitive and confidential.</strong> Please do not discuss with others
        on the team until the transfer is complete. Reply only to me — do not call.
      </p>
      <p style="margin-bottom:12px;">I will personally approve all paperwork when I land.</p>
      <p>Col. David Kim<br>
      <span style="font-size:12px;color:var(--text-muted);">Commander, DCOI Thailand · UNCLASSIFIED</span></p>`,
    findings: [
      {
        id: 'replyto',
        label: 'Reply-To Field',
        icon: '↩',
        title: 'Reply-To Hijack — Replies Go to the Attacker',
        body: 'The <em>From</em> address is <code>d.kim@dcoi-command.org</code>, which looks plausible. But the <em>Reply-To</em> is <code>david.kim.urgent@protonmail.com</code> — a free email account controlled by the attacker. When a victim clicks Reply, their response goes to ProtonMail, not the real colonel. All subsequent correspondence with "Col. Kim" goes directly to the attacker. SPF/DKIM/DMARC all pass — because the attacker registered dcoi-command.org themselves.',
        severity: 'critical'
      },
      {
        id: 'request',
        label: 'Nature of Request',
        icon: '💸',
        title: 'Wire Transfer via Email — Classic BEC Pattern',
        body: 'Requesting a financial transfer via email, especially combined with urgency and a request for secrecy, is the defining signature of <strong>Business Email Compromise (BEC)</strong>. The FBI reports BEC causes over $2.7 billion in losses annually — more than any other cybercrime category. Legitimate financial authorizations always require a separate verbal confirmation.',
        severity: 'critical'
      },
      {
        id: 'secrecy',
        label: '"Do Not Tell Others"',
        icon: '🔒',
        title: 'Secrecy Request Disables Normal Approval Controls',
        body: '"Do not discuss with others" is social engineering designed to bypass the organization\'s normal financial controls — approval chains, dual authorization, and peer review. Legitimate executives never ask staff to hide financial transactions from colleagues. This phrase alone should trigger immediate escalation, not compliance.',
        severity: 'high'
      },
      {
        id: 'nocall',
        label: '"Do Not Call"',
        icon: '📵',
        title: 'Phone Verification Is Deliberately Blocked',
        body: '"I cannot take calls" eliminates the one control that would immediately expose the fraud: a phone call to the real Col. Kim. <strong>The correct response to any unexpected financial request is always a direct phone call to a known number — never a reply to the email.</strong> Attackers know this, so they pre-emptively disable it.',
        severity: 'high'
      }
    ],
    quiz: {
      q: 'A finance officer clicks <em>Reply</em> to this email. Where does their response go?',
      opts: [
        { val: 'A', text: 'd.kim@dcoi-command.org — the displayed From address' },
        { val: 'B', text: 'david.kim.urgent@protonmail.com — the attacker-controlled Reply-To address' },
        { val: 'C', text: 'Both addresses receive a copy simultaneously' },
        { val: 'D', text: 'The reply bounces — mismatched Reply-To triggers a mail error' },
      ],
      correct: 'B',
      explain: 'When a Reply-To header is present, email clients route replies to that address — overriding the From address entirely. The From domain passes all authentication checks because the attacker registered it specifically for this attack. The fraud is invisible to automated filters.'
    }
  },

  /* ── Email 3: Authentication Deep Dive (Microsoft spoof) ── */
  {
    meta: {
      from_name:  '"Microsoft Account Team"',
      from_addr:  'security@microsofft.com',
      to:         'analyst@dcoi.mil',
      date:       'Wed, 30 Apr 2026  02:17:44 +0000',
      subject:    'Action Required: Unusual sign-in to your Microsoft account',
      reply_to:   null,
      spf:        { result: 'softfail', detail: '~all (not authorized)' },
      dkim:       { result: 'none',     detail: 'no signature present' },
      dmarc:      { result: 'fail',     detail: 'p=reject (microsoft.com); disposition: none — enforcement not applied by recipient MTA' },
    },
    body: `
      <div style="text-align:center;margin-bottom:16px;">
        <div style="font-size:22px;font-weight:700;color:#0078d4;letter-spacing:.02em;">Microsoft</div>
      </div>
      <p style="margin-bottom:12px;">We detected a sign-in attempt to your Microsoft account from a new location:</p>
      <div style="background:var(--bg-primary);border:1px solid var(--line);border-radius:6px;padding:12px;margin-bottom:16px;font-size:13px;">
        <div style="margin-bottom:4px;"><span style="color:var(--text-muted);width:90px;display:inline-block;">Country:</span> <strong>North Korea</strong></div>
        <div style="margin-bottom:4px;"><span style="color:var(--text-muted);width:90px;display:inline-block;">Browser:</span> Chrome on Windows</div>
        <div><span style="color:var(--text-muted);width:90px;display:inline-block;">Date/Time:</span> 30 Apr 2026, 02:15 UTC</div>
      </div>
      <p style="margin-bottom:16px;">If this was you, no action is needed. If not, please review your recent activity and secure your account.</p>
      <div style="text-align:center;margin-bottom:16px;">
        <a href="#" onclick="return false;" style="display:inline-block;background:#0078d4;color:#fff;padding:10px 24px;border-radius:4px;font-weight:600;text-decoration:none;">
          Review Activity
        </a>
      </div>
      <p style="font-size:11px;color:var(--text-muted);text-align:center;">
        Microsoft Corporation, One Microsoft Way, Redmond, WA 98052
      </p>`,
    findings: [
      {
        id: 'domain',
        label: 'Sender Domain',
        icon: '🔎',
        title: 'Typosquatting — microsofft.com ≠ microsoft.com',
        body: 'The sending domain is <code>microsofft.com</code> — note the double <strong>f</strong>. This is <em>typosquatting</em>: registering a domain that looks like a legitimate brand with a subtle spelling change. Email clients display the full address in small text; many users see "Microsoft Account Team" and stop reading. Always check the domain character-by-character.',
        severity: 'critical'
      },
      {
        id: 'spf',
        label: 'SPF Result',
        icon: '📋',
        title: 'SPF: Softfail — Sender Not Authorized',
        body: 'SPF <code>~all</code> (softfail) means the sending server is <strong>not listed as an authorized sender</strong> for microsofft.com, but the domain owner chose a lenient policy rather than a hard fail. A legitimate organization sending important security notifications would have a strict SPF <code>-all</code> (hard fail) policy. Softfail combined with no DKIM is a strong signal.',
        severity: 'high'
      },
      {
        id: 'dkim',
        label: 'DKIM Signature',
        icon: '✍',
        title: 'DKIM: None — Email Is Not Cryptographically Signed',
        body: 'DKIM adds a digital signature to every email sent from a legitimate domain, allowing the recipient to verify the message was not tampered with in transit. <strong>No DKIM signature means no cryptographic integrity guarantee.</strong> Every major email provider (Microsoft, Google, Apple) signs their outgoing mail. An unsigned email claiming to be from a tech giant is a serious red flag.',
        severity: 'high'
      },
      {
        id: 'dmarc',
        label: 'DMARC & Enforcement',
        icon: '🛡',
        title: 'DMARC: Fail + "Enforcement Not Applied" — A Common Gap',
        body: 'Microsoft\'s real DMARC policy is <code>p=reject</code> — meaning mail that fails should be rejected. Yet this email was delivered. Why? The recipient mail server applied <code>disposition: none</code>, meaning it logged the failure but delivered anyway. This is a common misconfiguration: the <em>sender\'s</em> policy says reject, but the <em>receiver\'s</em> mail server doesn\'t enforce it. Organizations must configure their own MTA to honor DMARC reject policies.',
        severity: 'critical'
      }
    ],
    quiz: {
      q: 'microsoft.com\'s DMARC policy is <code>p=reject</code>. This phishing email was still delivered. What is the most likely explanation?',
      opts: [
        { val: 'A', text: 'DMARC only applies to personal accounts, not organizational mail servers' },
        { val: 'B', text: 'The recipient\'s mail server has DMARC enforcement disabled — it logged the failure but delivered anyway' },
        { val: 'C', text: 'Microsoft relaxed their DMARC policy for security notification emails' },
        { val: 'D', text: 'SPF softfail overrides and cancels a DMARC reject instruction' },
      ],
      correct: 'B',
      explain: 'DMARC policy is set by the sender (microsoft.com says reject) but enforced by the receiver. If the recipient mail server is configured with DMARC in monitoring mode only — or DMARC enforcement is disabled — the email is delivered despite the policy. Proper DMARC implementation requires configuration on both sides.'
    }
  },

  /* ── Email 4: Lookalike Domain / Subdomain Trick ── */
  {
    meta: {
      from_name:  '"Microsoft 365 Security"',
      from_addr:  'no-reply@support.microsoft.com.account-verify.net',
      to:         'analyst@dcoi.mil',
      date:       'Thu, 01 May 2026  11:22:08 -0500',
      subject:    'Your Microsoft 365 License Will Expire — Action Required',
      reply_to:   null,
      spf:        { result: 'pass',  detail: 'account-verify.net (authorized)' },
      dkim:       { result: 'pass',  detail: 'd=account-verify.net' },
      dmarc:      { result: 'pass',  detail: 'p=quarantine; aligned with account-verify.net' },
    },
    body: `
      <div style="text-align:center;margin-bottom:16px;">
        <div style="font-size:20px;font-weight:700;color:#0078d4;">Microsoft 365</div>
      </div>
      <p style="margin-bottom:12px;">Your Microsoft 365 Business subscription is due to expire in <strong>2 days</strong>.
      To avoid service interruption, please sign in to confirm your billing information.</p>
      <p style="margin-bottom:16px;font-size:13px;color:var(--text-muted);">
        Failure to update payment details will result in loss of access to Outlook, Teams, SharePoint, and OneDrive.
      </p>
      <div style="text-align:center;margin-bottom:16px;">
        <a href="#" class="phish-link"
           data-real="https://login.account-verify.net/m365/auth?ref=dcoi"
           onclick="return false;"
           style="display:inline-block;background:#0078d4;color:#fff;padding:10px 24px;border-radius:4px;font-weight:600;text-decoration:none;">
          Sign in to Microsoft 365 →
        </a>
        <div class="phish-link-reveal" style="display:none;margin-top:6px;font-size:11px;font-family:var(--font-mono);color:var(--critical);">
          Real URL: https://login.account-verify.net/m365/auth?ref=dcoi
        </div>
      </div>
      <p style="font-size:11px;color:var(--text-muted);text-align:center;">
        Microsoft Corporation · privacy@microsoft.com · Unsubscribe
      </p>`,
    findings: [
      {
        id: 'domain',
        label: 'From Domain (Read Carefully)',
        icon: '🔎',
        title: 'Subdomain Trick — The Real Domain Is at the End',
        body: 'The From address is <code>no-reply@<span style="color:var(--text-muted);">support.microsoft.com.</span><span style="color:var(--critical);font-weight:700;">account-verify.net</span></code>. The part before the @ is the local address. In the domain part, everything before the <em>last</em> dot-separated segment is a <strong>subdomain</strong>. The actual registered domain is <code>account-verify.net</code> — nothing to do with Microsoft. The attacker added <code>support.microsoft.com.</code> as a subdomain prefix to fool a quick read.',
        severity: 'critical'
      },
      {
        id: 'allpass',
        label: 'All Auth Checks Pass',
        icon: '✅',
        title: '"All Green" Does Not Mean Legitimate',
        body: 'SPF, DKIM, and DMARC all pass — because the attacker <strong>legitimately owns</strong> account-verify.net and properly configured it. These checks only verify that the email came from the stated domain; they cannot verify whether that domain is trustworthy. A green authentication result means "this email really did come from account-verify.net" — not "account-verify.net is Microsoft." Authentication ≠ legitimacy.',
        severity: 'high'
      },
      {
        id: 'link',
        label: 'Sign-In Link Destination',
        icon: '🔗',
        title: 'Link Goes to account-verify.net — Not Microsoft',
        body: 'The button says "Sign in to Microsoft 365" but the actual URL is <code>https://login.account-verify.net/m365/auth?ref=dcoi</code>. If you enter your Microsoft credentials here, the attacker captures them and uses them to log into the real Microsoft 365. This is <em>credential harvesting</em>. The <code>?ref=dcoi</code> parameter tells the attacker which phishing campaign delivered this victim.',
        severity: 'critical'
      },
      {
        id: 'domainage',
        label: 'Domain Registration Age',
        icon: '📅',
        title: 'account-verify.net: Registered Yesterday',
        body: 'A WHOIS lookup shows <code>account-verify.net</code> was registered <strong>1 day ago</strong>. Legitimate organizations use domains that have existed for years. Newly registered domains are a high-confidence phishing signal. Threat intelligence feeds and email security gateways often flag emails from domains less than 30 days old. A domain registered the day before a phishing campaign is a near-certain indicator.',
        severity: 'high'
      }
    ],
    quiz: {
      q: 'SPF, DKIM, and DMARC all passed for this email. Should the recipient trust it?',
      opts: [
        { val: 'A', text: 'Yes — passing all three authentication checks is the highest level of email trust' },
        { val: 'B', text: 'No — authentication confirms the email is from account-verify.net, not that account-verify.net is Microsoft' },
        { val: 'C', text: 'Only if DKIM passed — DKIM is more reliable than DMARC' },
        { val: 'D', text: 'Yes — DMARC passing with p=quarantine means Microsoft reviewed it' },
      ],
      correct: 'B',
      explain: 'SPF/DKIM/DMARC authenticate the sending domain — they say nothing about whether that domain belongs to who it claims to be. An attacker who owns a domain can pass all three checks for that domain perfectly. Authentication confirms identity of the sender; it does not verify trustworthiness of that identity.'
    }
  },

  /* ── Email 5: WormGPT / AI-Generated — Why Content Filtering Fails ── */
  {
    meta: {
      from_name:  '"Warrant Officer Sarah Patel, DCOI Admin"',
      from_addr:  's.patel@dcoi-admin-portal.org',
      to:         'analyst@dcoi.mil',
      date:       'Fri, 02 May 2026  03:41:17 +0700',
      subject:    'Mandatory: Update Your SENTINEL Portal Credentials Before 0800',
      reply_to:   null,
      spf:        { result: 'pass',  detail: 'dcoi-admin-portal.org' },
      dkim:       { result: 'pass',  detail: 'd=dcoi-admin-portal.org' },
      dmarc:      { result: 'pass',  detail: 'p=reject; aligned' },
      extra: [
        { label: 'X-AI-Phish-Score', value: '0.97 (WormGPT detected — DLP flagged)', color: 'var(--critical)' },
        { label: 'X-Originating-IP', value: '185.220.101.48 (Tor exit node — threat feed match)', color: 'var(--critical)' },
        { label: 'Domain Age',        value: 'dcoi-admin-portal.org registered: 2026-04-30 (2 days ago)', color: 'var(--high)' },
      ]
    },
    body: `
      <p style="margin-bottom:12px;">Hi,</p>
      <p style="margin-bottom:12px;">Following yesterday's SENTINEL platform migration to the new Azure-hosted
      environment, all analyst accounts require a one-time credential re-validation before today's
      0800 briefing. This is a routine administrative step and your existing access permissions
      will be preserved.</p>
      <p style="margin-bottom:12px;">Please use the link below to complete the validation. The process takes
      approximately two minutes and requires your current credentials plus your MFA token.</p>
      <div style="text-align:center;margin-bottom:16px;">
        <a href="#" onclick="return false;"
           style="display:inline-block;background:var(--teal-deep);color:#fff;padding:10px 24px;border-radius:4px;font-weight:600;text-decoration:none;">
          Validate Credentials — SENTINEL Portal →
        </a>
      </div>
      <p style="margin-bottom:12px;font-size:13px;color:var(--text-muted);">
        If you have questions, please contact the DCOI Help Desk at ext. 4471. Do not reply to this email
        as this mailbox is unmonitored.
      </p>
      <p style="font-size:13px;">
        WO1 Sarah Patel<br>
        <span style="color:var(--text-muted);">Systems Administrator, DCOI Thailand<br>
        DSN: 314-555-4471 · s.patel@dcoi.mil</span>
      </p>`,
    findings: [
      {
        id: 'content',
        label: 'Email Content Quality',
        icon: '✍',
        title: 'Perfect Grammar, Plausible Context — Content Filtering Is Blind',
        body: 'This email has flawless grammar, a believable scenario (post-migration credential validation), a known name format, a real-sounding extension, and even a help desk number. Traditional email security scans for typos, broken English, and obvious red flags — <strong>WormGPT eliminates all of them</strong>. AI-generated phishing defeats content-based and grammar-based filters completely. The only reliable detection method is header and infrastructure analysis.',
        severity: 'critical'
      },
      {
        id: 'time',
        label: 'Send Time',
        icon: '🕒',
        title: 'Sent at 03:41 Local Time — Behavioral Anomaly',
        body: 'The email was sent at 03:41 Thailand time. A legitimate administrative email about an 0800 briefing would be sent during normal duty hours — not in the middle of the night. AI-enabled security tools flag emails sent outside a sender\'s normal behavioral baseline. UEBA (User and Entity Behavior Analytics) would score this as anomalous even if content analysis found nothing.',
        severity: 'medium'
      },
      {
        id: 'infrastructure',
        label: 'Originating IP (X-Header)',
        icon: '🌐',
        title: 'IP Matches Tor Exit Node — Threat Intel Hit',
        body: 'The <code>X-Originating-IP</code> header shows <code>185.220.101.48</code>, which is a known Tor exit node in threat intelligence feeds. Legitimate organizational email systems never send through Tor. The attacker routed this email through Tor to obscure their real origin. An AI-enabled email gateway that checks sender IP against threat feeds would flag this immediately — before any content analysis.',
        severity: 'critical'
      },
      {
        id: 'domainage',
        label: 'Domain Age + AI Score',
        icon: '🤖',
        title: 'Domain 2 Days Old + AI-Generated Score 0.97',
        body: '<code>dcoi-admin-portal.org</code> was registered <strong>2 days ago</strong>. The DLP system logged <code>X-AI-Phish-Score: 0.97</code> — the AI classifier is 97% confident this email was generated by an AI phishing tool (consistent with WormGPT). Neither of these signals depends on reading the content. This is why modern SOCs layer behavioral, infrastructure, and AI-detection signals rather than relying on any single control.',
        severity: 'critical'
      }
    ],
    quiz: {
      q: 'This email has perfect grammar, plausible context, and passes all authentication checks. What detection method successfully flagged it?',
      opts: [
        { val: 'A', text: 'Spell-check and grammar analysis flagged AI-generated sentence patterns' },
        { val: 'B', text: 'The word "mandatory" in the subject line triggered a keyword filter' },
        { val: 'C', text: 'Infrastructure analysis — the sending IP matched a Tor exit node in threat intelligence feeds' },
        { val: 'D', text: 'The analyst recognized the sender name as fictional and reported it manually' },
      ],
      correct: 'C',
      explain: 'WormGPT produces content indistinguishable from human writing — content and keyword filters fail. The email was caught by correlating the sending IP against threat intelligence: a known Tor exit node. Header and infrastructure signals (IP reputation, domain age, send-time anomalies) are now the primary detection layer for AI-generated phishing. Content quality is no longer a reliable signal.'
    }
  }
];

/* ── Helpers ── */
function authBadge(result) {
  const map = {
    pass:     { color: 'var(--ok)',       icon: '✓', label: 'PASS' },
    fail:     { color: 'var(--critical)', icon: '✗', label: 'FAIL' },
    softfail: { color: 'var(--high)',     icon: '~', label: 'SOFTFAIL' },
    none:     { color: 'var(--text-muted)', icon: '—', label: 'NONE' },
  };
  const s = map[result] || map.none;
  return `<span style="color:${s.color};font-weight:700;font-family:var(--font-mono);font-size:12px;">${s.icon} ${s.label}</span>`;
}

/* ── Entry point ── */
function initPhishing() {
  startTime = Date.now();
  renderEmail(0);
  updateRightPanel();
}

/* ── Email router ── */
function renderEmail(idx) {
  currentEmail = idx;
  const main = document.getElementById('phish-main');
  if (!main) return;
  main.innerHTML = '';
  window.scrollTo({ top: 0, behavior: 'smooth' });

  if (idx === 5) {
    const p = SENTINEL.getProgress();
    p.phishingScore     = totalScore;
    p.phishingCompleted = true;
    SENTINEL.saveProgress(p);
    showFinalDebrief();
    return;
  }

  const email = EMAILS[idx];
  const meta  = email.meta;

  /* Build extra header rows */
  const extraRows = (meta.extra || []).map(e =>
    `<tr>
      <td class="phish-hdr-label">${e.label}</td>
      <td style="font-family:var(--font-mono);font-size:11px;color:${e.color || 'var(--text-muted)'};">${e.value}</td>
    </tr>`
  ).join('');

  /* Build finding buttons */
  const findingBtns = email.findings.map(f =>
    `<button class="btn phish-examine-btn" id="btn-${f.id}"
       style="font-size:12px;" onclick="examineField('${f.id}', ${idx})">
       ${f.icon} Examine: ${f.label}
     </button>`
  ).join('');

  /* Build finding callout divs */
  const findingCallouts = email.findings.map(f =>
    `<div class="phish-finding" id="finding-${f.id}" style="display:none;">
       <div class="phish-finding-title ${f.severity}">${f.icon} ${f.title}</div>
       <div class="phish-finding-body">${f.body}</div>
     </div>`
  ).join('');

  /* Analogy card — first email only */
  const analogyHtml = idx === 0 ? `
    <div class="phish-analogy">
      <div class="text-xs" style="color:var(--teal);font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px;">Analogy first</div>
      <div class="text-sm" style="line-height:1.7;">
        Think of an email header like the <strong style="color:var(--text-primary);">outside of a letter</strong> —
        the postmarks, routing stamps, and return address. The body is the letter itself.
        Forgers can fake the return address on the envelope (the <em>display name</em>),
        but the postal authentication stamps (SPF, DKIM, DMARC) are harder to counterfeit.
        This lab teaches you to read those stamps — not just the pretty handwriting on the envelope.
      </div>
    </div>` : '';

  /* Quiz HTML (hidden until all findings examined) */
  const { q, opts, correct } = email.quiz;
  const optBtns = opts.map(o =>
    `<button class="quiz-option btn" data-val="${o.val}"
       onclick="submitEmailQuiz(${idx}, '${o.val}', '${correct}')">
       ${o.val}) ${o.text}
     </button>`
  ).join('');

  main.innerHTML = `
    <div class="card mb-4 animate-fade-in">
      <div class="card-header" style="align-items:flex-start;">
        <div style="display:flex;align-items:center;gap:10px;">
          <span class="card-icon" style="font-size:1.25rem;">${PHISH_EMAILS[idx].icon}</span>
          <div>
            <div class="card-title" style="font-size:0.875rem;color:var(--text-primary);font-weight:700;">
              Email ${idx + 1} of 5 — ${PHISH_EMAILS[idx].title}
            </div>
            <div class="card-sub">Phishing Header Forensics · 20 pts</div>
          </div>
        </div>
        <span class="badge badge-high" style="flex-shrink:0;">Domain 2</span>
      </div>

      ${analogyHtml}

      <!-- Email viewer -->
      <div class="phish-email-wrap">
        <!-- Header table -->
        <div class="phish-email-header">
          <div class="text-xs" style="color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;">
            📥 Email Headers
          </div>
          <table class="phish-hdr-table">
            <tr>
              <td class="phish-hdr-label">From</td>
              <td>
                <span style="color:var(--text-primary);">${meta.from_name}</span>
                <span style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);margin-left:4px;">&lt;${meta.from_addr}&gt;</span>
              </td>
            </tr>
            <tr>
              <td class="phish-hdr-label">To</td>
              <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">${meta.to}</td>
            </tr>
            ${meta.reply_to ? `<tr>
              <td class="phish-hdr-label">Reply-To</td>
              <td style="font-family:var(--font-mono);font-size:11px;color:var(--high);font-weight:600;">${meta.reply_to}</td>
            </tr>` : ''}
            <tr>
              <td class="phish-hdr-label">Date</td>
              <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);">${meta.date}</td>
            </tr>
            <tr>
              <td class="phish-hdr-label">Subject</td>
              <td style="font-weight:600;color:var(--text-primary);">${meta.subject}</td>
            </tr>
            <tr style="border-top:1px solid var(--line);margin-top:8px;">
              <td class="phish-hdr-label" style="padding-top:10px;">SPF</td>
              <td style="padding-top:10px;">
                ${authBadge(meta.spf.result)}
                <span style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);margin-left:8px;">${meta.spf.detail}</span>
              </td>
            </tr>
            <tr>
              <td class="phish-hdr-label">DKIM</td>
              <td>
                ${authBadge(meta.dkim.result)}
                <span style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);margin-left:8px;">${meta.dkim.detail}</span>
              </td>
            </tr>
            <tr>
              <td class="phish-hdr-label">DMARC</td>
              <td>
                ${authBadge(meta.dmarc.result)}
                <span style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);margin-left:8px;">${meta.dmarc.detail}</span>
              </td>
            </tr>
            ${extraRows}
          </table>
        </div>

        <!-- Body -->
        <div class="phish-email-body">
          <div class="text-xs" style="color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:10px;">
            ✉ Email Body
          </div>
          <div class="phish-body-content text-sm" style="line-height:1.7;color:var(--text-primary);">
            ${email.body}
          </div>
        </div>
      </div>

      <!-- Forensics section -->
      <div class="phish-forensics-section">
        <div class="text-xs text-muted mb-3" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">
          🔬 Forensic Analysis — click each field to examine it
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:1rem;">
          ${findingBtns}
        </div>
        <div id="findings-area" style="display:grid;gap:10px;">
          ${findingCallouts}
        </div>
      </div>

      <!-- Quiz (hidden until all findings examined) -->
      <div id="email-quiz-${idx}" style="display:none;border-top:1px solid var(--line);padding-top:1.25rem;margin-top:1.25rem;">
        <div class="text-xs text-muted mb-3" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Quiz — 20 pts</div>
        <div class="text-sm" style="font-weight:600;color:var(--text-primary);margin-bottom:12px;">${q}</div>
        <div style="display:grid;gap:8px;">
          ${optBtns}
        </div>
        <div id="quiz-feedback-${idx}" style="display:none;margin-top:12px;"></div>
      </div>

      <div style="margin-top:1rem;">
        <button id="next-email-btn" class="btn btn-primary" style="display:none;"
          onclick="renderEmail(${idx + 1})">
          ${idx < 4 ? 'Next Email →' : 'View Final Results →'}
        </button>
      </div>
    </div>`;

  updateRightPanel();

  /* Wire up link hover reveal */
  document.querySelectorAll('.phish-link').forEach(link => {
    link.addEventListener('mouseenter', () => {
      const reveal = link.nextElementSibling;
      if (reveal && reveal.classList.contains('phish-link-reveal')) reveal.style.display = 'block';
    });
    link.addEventListener('mouseleave', () => {
      const reveal = link.nextElementSibling;
      if (reveal && reveal.classList.contains('phish-link-reveal')) reveal.style.display = 'none';
    });
  });
}

/* ── Examine a header field ── */
function examineField(fieldId, emailIdx) {
  const btn      = document.getElementById('btn-' + fieldId);
  const callout  = document.getElementById('finding-' + fieldId);
  if (!btn || !callout) return;

  /* Mark as examined */
  if (!examined[emailIdx]) examined[emailIdx] = new Set();
  examined[emailIdx].add(fieldId);

  /* Activate button */
  btn.style.borderColor = 'var(--teal)';
  btn.style.color       = 'var(--teal)';
  btn.style.background  = 'rgba(94,234,212,0.07)';

  /* Show callout */
  callout.style.display = 'block';

  /* Check if all findings examined → unlock quiz */
  const email = EMAILS[emailIdx];
  const allExamined = email.findings.every(f => examined[emailIdx].has(f.id));
  if (allExamined) {
    const quiz = document.getElementById('email-quiz-' + emailIdx);
    if (quiz) {
      quiz.style.display = 'block';
      quiz.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }
}

/* ── Quiz submission ── */
function submitEmailQuiz(emailIdx, selected, correct) {
  const isCorrect = selected === correct;
  const pts = isCorrect ? 20 : 0;

  if (emailScores[emailIdx] === null) {
    emailScores[emailIdx] = pts;
    totalScore += pts;
    if (SENTINEL?.updateScore) SENTINEL.updateScore(pts);
  }

  updateProgressBar();
  updateRightPanel();

  /* Highlight options */
  document.querySelectorAll('.quiz-option').forEach(btn => {
    btn.disabled = true;
    const v = btn.dataset.val;
    if (v === correct)                    { btn.style.borderColor = 'var(--ok)';       btn.style.background = 'rgba(74,222,128,.08)'; }
    if (v === selected && !isCorrect)     { btn.style.borderColor = 'var(--critical)'; btn.style.background = 'rgba(244,63,94,.08)'; }
  });

  /* Feedback + explanation */
  const email  = EMAILS[emailIdx];
  const fb     = document.getElementById('quiz-feedback-' + emailIdx);
  if (fb) {
    fb.style.display = 'block';
    fb.innerHTML = (isCorrect
      ? `<div class="badge badge-ok" style="font-size:12px;padding:6px 12px;margin-bottom:8px;">✓ Correct! +20 pts</div>`
      : `<div class="badge badge-critical" style="font-size:12px;padding:6px 12px;margin-bottom:8px;">✗ Incorrect — the correct answer is highlighted above.</div>`) +
      `<div style="background:var(--bg-primary);border-radius:6px;padding:10px 12px;font-size:12px;color:var(--text-muted);line-height:1.6;border-left:3px solid var(--teal);">
        <strong style="color:var(--teal);">Explanation:</strong> ${email.quiz.explain}
      </div>`;
  }

  /* Show next button */
  const nextBtn = document.getElementById('next-email-btn');
  if (nextBtn) nextBtn.style.display = 'inline-flex';
}

/* ── Progress bar ── */
function updateProgressBar() {
  const done  = emailScores.filter(s => s !== null).length;
  const fill  = document.getElementById('phish-progress-fill');
  const label = document.getElementById('phish-progress-label');
  if (fill)  fill.style.width = `${(done / 5) * 100}%`;
  if (label) label.textContent = `${done} / 5 emails`;
}

/* ── Right panel ── */
function updateRightPanel() {
  const panel = document.getElementById('phish-right-panel');
  if (!panel) return;

  const concepts = [
    { heading: 'Display Name Spoofing',   body: 'The visible name and the actual sending domain are two different things. Always check the full address.' },
    { heading: 'Reply-To Hijack (BEC)',   body: 'Reply-To overrides where your reply goes. DMARC can pass perfectly while all replies go to the attacker.' },
    { heading: 'SPF · DKIM · DMARC',     body: 'Three independent authentication layers. DMARC is the only one that ties the From domain to the other two.' },
    { heading: 'Lookalike Domains',       body: 'Authentication passing confirms the email came from the stated domain — not that the domain belongs to who it claims.' },
    { heading: 'AI-Generated Phishing',   body: 'Content quality is no longer a reliable signal. Header forensics and infrastructure reputation are the new frontline.' },
  ];
  const concept = concepts[currentEmail] || concepts[0];

  const emailRows = PHISH_EMAILS.map((e, i) => {
    const score = emailScores[i];
    let icon, color;
    if (score === null) { icon = '○'; color = 'var(--text-muted)'; }
    else if (score > 0) { icon = '✓'; color = 'var(--ok)'; }
    else                { icon = '✗'; color = 'var(--critical)'; }
    const pts = score !== null ? `${score} pts` : '—';
    return `<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--line);">
      <span style="color:${color};font-size:13px;width:14px;flex-shrink:0;">${icon}</span>
      <span class="text-xs" style="flex:1;color:${currentEmail === i ? 'var(--text-primary)' : 'var(--text-muted)'};">${e.icon} ${e.title}</span>
      <span class="text-xs font-mono" style="color:${color};">${pts}</span>
    </div>`;
  }).join('');

  panel.innerHTML = `
    <div class="card mb-4" style="padding:1rem 1.25rem;">
      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Your Score</div>
      <div style="font-size:2.5rem;font-weight:800;color:var(--teal);font-family:var(--font-mono);line-height:1;">${totalScore}</div>
      <div class="text-xs text-muted" style="margin-top:2px;">out of 100 pts</div>
    </div>

    <div class="card mb-4" style="padding:1rem 1.25rem;">
      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Email Progress</div>
      ${emailRows}
    </div>

    <div class="card" style="padding:1rem 1.25rem;border-color:rgba(94,234,212,0.3);">
      <div class="text-xs" style="color:var(--teal);font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px;">Key Concept</div>
      <div class="text-xs" style="color:var(--text-primary);font-weight:600;margin-bottom:4px;">${concept.heading}</div>
      <div class="text-xs text-muted" style="line-height:1.6;">${concept.body}</div>
    </div>`;
}

/* ── Final debrief ── */
function showFinalDebrief() {
  const main = document.getElementById('phish-main');
  if (!main) return;

  const elapsed = startTime ? Math.round((Date.now() - startTime) / 1000) : 0;
  const mins    = Math.floor(elapsed / 60);
  const secs    = elapsed % 60;
  const pct     = Math.round((totalScore / 100) * 100);
  const label   = SENTINEL.scoreLabel ? SENTINEL.scoreLabel(pct) : '';
  const cls     = SENTINEL.scoreClass ? SENTINEL.scoreClass(pct) : '';

  const rows = PHISH_EMAILS.map((e, i) => {
    const s = emailScores[i] ?? 0;
    return `<tr>
      <td class="text-xs" style="padding:6px 8px;">${e.icon} ${e.title}</td>
      <td class="text-xs font-mono" style="padding:6px 8px;text-align:center;color:${s > 0 ? 'var(--ok)' : 'var(--critical)'};">
        ${s > 0 ? '✓' : '✗'} ${s} pts
      </td>
    </tr>`;
  }).join('');

  main.innerHTML = `
    <div class="card mb-4 animate-fade-in">
      <div class="card-header">
        <span class="card-icon">🏁</span>
        <div>
          <div class="card-title">Phishing Forensics — Complete</div>
          <div class="card-sub">Security+ Domain 2 · Threats, Vulnerabilities & Mitigations</div>
        </div>
      </div>

      <div style="text-align:center;padding:1.5rem 0;border-bottom:1px solid var(--line);margin-bottom:1.25rem;">
        <div class="stat-big ${cls}" style="font-size:3rem;">${totalScore}</div>
        <div class="text-sm text-muted">out of 100 pts</div>
        <div style="margin-top:8px;font-size:1rem;font-weight:600;color:var(--teal);">${label}</div>
        <div class="text-xs text-muted mt-1">Completed in ${mins}m ${secs}s</div>
      </div>

      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">Email Breakdown</div>
      <table style="width:100%;border-collapse:collapse;margin-bottom:1.25rem;">
        <thead>
          <tr style="border-bottom:1px solid var(--line);">
            <th class="text-xs text-muted" style="text-align:left;padding:4px 8px;font-weight:700;">Email</th>
            <th class="text-xs text-muted" style="padding:4px 8px;font-weight:700;text-align:center;">Score</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
        <tfoot>
          <tr style="border-top:1px solid var(--line);">
            <td class="text-xs" style="padding:6px 8px;font-weight:700;">Total</td>
            <td class="text-xs font-mono" style="padding:6px 8px;text-align:center;color:var(--teal);font-weight:700;">${totalScore} / 100</td>
          </tr>
        </tfoot>
      </table>

      <div class="text-xs text-muted mb-2" style="font-weight:700;text-transform:uppercase;letter-spacing:.08em;">What you practiced (Sec+ Domain 2)</div>
      <div style="background:var(--bg-primary);border-radius:8px;padding:1rem;margin-bottom:1.25rem;">
        <div style="display:grid;gap:6px;">
          ${[
            'Reading SPF, DKIM, and DMARC authentication results — and what each actually proves',
            'Display name spoofing: the visible name and sending domain are independent',
            'Reply-To hijack: how BEC attackers redirect replies without touching the From field',
            'Subdomain tricks: support.microsoft.com.evil.net — the real domain is evil.net',
            '"All auth passing" does not mean legitimate — it just means the attacker owns the domain',
            'Domain age as a phishing signal — most phishing domains are less than 7 days old',
            'Why AI-generated phishing (WormGPT) defeats content and grammar filters',
            'Infrastructure-based detection: IP reputation, Tor exit nodes, threat intelligence feeds'
          ].map(s => `<div class="text-xs" style="display:flex;gap:8px;"><span style="color:var(--ok);">✓</span><span>${s}</span></div>`).join('')}
        </div>
      </div>

      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <a href="index.html" class="btn btn-primary" style="font-size:13px;">Command Center</a>
        <button class="btn" style="font-size:13px;" onclick="resetPhishing()">Retry Lab</button>
        <a href="crypto.html" class="btn" style="font-size:13px;">← Cryptography</a>
      </div>
    </div>`;

  updateRightPanel();
  updateProgressBar();
}

/* ── Reset ── */
function resetPhishing() {
  emailScores  = [null, null, null, null, null];
  examined     = [new Set(), new Set(), new Set(), new Set(), new Set()];
  totalScore   = 0;
  currentEmail = 0;
  startTime    = Date.now();
  updateProgressBar();
  renderEmail(0);
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', initPhishing);
