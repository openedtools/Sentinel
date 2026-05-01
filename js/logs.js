/* SENTINEL — Log Decoding Challenge Module */

/* ── Challenge data ── */
const LOG_CHALLENGES = [
  {
    id: 1,
    title: 'Windows Authentication & Lateral Movement',
    logType: 'Windows Security Event Log',
    context: 'Domain controller · CORP internal network · 17 APR 2026 · 06:00–06:10 UTC+7',
    hint: 'Focus on logon types, repeated failures, unusual parent processes, and new scheduled tasks.',
    lines: [
      { id: 'l1-1',  suspicious: false, text: '06:01:22  EventID=4624  LogonType=2  Account=sarah.chen  Domain=CORP  Workstation=WS-031  SrcIP=10.14.1.31',
        explanation: 'Normal interactive logon (Type 2) by a known user from their assigned workstation. Expected morning activity.' },
      { id: 'l1-2',  suspicious: false, text: '06:01:45  EventID=4648  Account=svc-backup  Domain=CORP  TargetServer=FILE-SERVER-01  Process=taskschd.exe',
        explanation: 'Explicit credential use by the authorized nightly backup service account. Matches expected scheduled task pattern.' },
      { id: 'l1-3',  suspicious: true,  text: '06:02:11  EventID=4625  Account=administrator  Domain=CORP  FailureCount=47  Workstation=WS-004  SrcIP=10.14.1.4',
        explanation: '47 consecutive failed logon attempts for the administrator account from WS-004. Strong brute-force indicator — normal users do not fail 47 times.' },
      { id: 'l1-4',  suspicious: true,  text: '06:03:44  EventID=4624  LogonType=3  Account=administrator  Domain=CORP  Workstation=WS-004  SrcIP=10.14.1.4  AuthPackage=NTLM',
        explanation: 'Successful NETWORK logon (Type 3) for administrator from the same host that just had 47 failures, using NTLM. Classic Pass-the-Hash follow-up after brute force.' },
      { id: 'l1-5',  suspicious: false, text: '06:04:01  EventID=4634  Account=john.smith  Domain=CORP  LogonType=2  Workstation=WS-019',
        explanation: 'Normal interactive logoff. John Smith ended his workstation session — routine activity.' },
      { id: 'l1-6',  suspicious: true,  text: '06:04:33  EventID=4688  NewProcess=cmd.exe  ParentProcess=mmc.exe  Account=administrator  CommandLine="cmd.exe /c whoami && ipconfig /all && net user /domain && arp -a"',
        explanation: 'cmd.exe spawned from mmc.exe (Microsoft Management Console) — an unusual parent. The command string is textbook recon: identity, network config, domain users, ARP cache.' },
      { id: 'l1-7',  suspicious: false, text: '06:05:12  EventID=4624  LogonType=7  Account=mark.torres  Domain=CORP  Workstation=MARK-LAPTOP',
        explanation: 'Type 7 = workstation unlock after screensaver. Mark Torres returned to his desk. Completely normal.' },
      { id: 'l1-8',  suspicious: true,  text: '06:06:19  EventID=4698  TaskName=\\Microsoft\\Windows\\SystemUpdate  Account=administrator  Program=C:\\Windows\\Temp\\svc32.exe  Trigger=AtLogon',
        explanation: 'Scheduled task created in a Microsoft-sounding path (persistence camouflage) but executes a binary from C:\\Windows\\Temp — a common malware staging location. AtLogon trigger ensures it runs on every login.' },
      { id: 'l1-9',  suspicious: false, text: '06:07:00  EventID=7045  ServiceName=Windows Update Service  Account=LocalSystem  StartType=Automatic  FilePath=C:\\Windows\\System32\\wuauserv.dll',
        explanation: 'Legitimate Windows Update service registration in System32. Path and account are expected for this service.' },
      { id: 'l1-10', suspicious: true,  text: '06:07:44  EventID=4732  GroupName=Administrators  MemberAdded=svc_backup_new  AddedBy=administrator  Domain=CORP',
        explanation: 'A brand-new account (svc_backup_new) added to the Administrators group by the compromised administrator account. Privilege escalation / backdoor account creation.' }
    ],
    question: 'What attack chain does this event sequence describe?',
    options: [
      { id: 'a', text: 'Brute-force → Pass-the-Hash → Recon → Scheduled Task persistence → Backdoor admin account' },
      { id: 'b', text: 'Kerberoasting → Golden Ticket → DCSync' },
      { id: 'c', text: 'Phishing email → macro execution → DLL side-loading' },
      { id: 'd', text: 'SQL injection → web shell → reverse shell' }
    ],
    correctOption: 'a',
    questionExplanation: 'The sequence: 47 failed logons (brute force) → successful NTLM network logon (Pass-the-Hash) → cmd.exe from MMC with recon commands → scheduled task in Temp folder (persistence) → backdoor admin account. MITRE: T1110, T1550.002, T1059.003, T1053.005, T1136.001.',
    mitreIds: 'T1110 · T1550.002 · T1059.003 · T1053.005',
    secPlusRef: 'Sec+ Domain: Threats, Vulnerabilities & Mitigations — Indicators of compromise, lateral movement'
  },
  {
    id: 2,
    title: 'Linux Server: SSH Brute Force & Privilege Escalation',
    logType: 'Linux Syslog (/var/log/auth.log)',
    context: 'Production web server WEB-01 · Ubuntu 22.04 · 17 APR 2026 · 03:10–03:22 UTC+7',
    hint: 'Watch for repeated authentication failures, unexpected sudo usage, and new account creation.',
    lines: [
      { id: 'l2-1',  suspicious: false, text: 'Mar 17 03:10:01 WEB-01 CRON[1842]: pam_unix(cron:session): session opened for user root by (uid=0)',
        explanation: 'Scheduled cron job starting as root — routine system maintenance task. The PID and timing match known system cron entries.' },
      { id: 'l2-2',  suspicious: false, text: 'Mar 17 03:11:44 WEB-01 sudo[2041]: deploy : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx',
        explanation: 'The deploy service account restarting nginx via sudo — an authorized operation matching the deployment runbook.' },
      { id: 'l2-3',  suspicious: true,  text: 'Mar 17 03:13:02 WEB-01 sshd[2819]: Failed password for root from 185.220.101.47 port 54822 ssh2',
        explanation: 'Failed SSH password attempt for root from 185.220.101.47 — an IP associated with Tor exit nodes and brute-force campaigns. Root login via SSH should always be disabled.' },
      { id: 'l2-4',  suspicious: true,  text: 'Mar 17 03:13:04 WEB-01 sshd[2821]: Failed password for root from 185.220.101.47 port 54824 ssh2\nMar 17 03:13:06 WEB-01 sshd[2823]: Failed password for root from 185.220.101.47 port 54826 ssh2\nMar 17 03:13:08 WEB-01 sshd[2825]: Failed password for root from 185.220.101.47 port 54828 ssh2',
        explanation: 'Three more failures in 6 seconds from the same IP — automated brute-force tool. The rapid sequential port numbers confirm scripted attack, not a human typo.' },
      { id: 'l2-5',  suspicious: false, text: 'Mar 17 03:14:19 WEB-01 sshd[2901]: Accepted publickey for deploy from 10.14.1.20 port 51234 ssh2: RSA SHA256:abc123',
        explanation: 'Authorized key-based SSH logon for the deploy account from an internal IP. Expected CI/CD pipeline connection.' },
      { id: 'l2-6',  suspicious: true,  text: 'Mar 17 03:16:55 WEB-01 sudo[3044]: www-data : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash',
        explanation: 'www-data (the web server process account) gaining a root shell via sudo from /tmp. Web application service accounts should NEVER sudo to root — this indicates web shell exploitation or a sudo misconfiguration being abused.' },
      { id: 'l2-7',  suspicious: true,  text: 'Mar 17 03:17:33 WEB-01 useradd[3112]: new user: name=sysmon_svc, uid=1003, gid=1003, home=/home/sysmon_svc, shell=/bin/bash',
        explanation: 'A new user account created by the attacker for persistence. The name "sysmon_svc" is chosen to blend in with legitimate monitoring services.' },
      { id: 'l2-8',  suspicious: true,  text: 'Mar 17 03:17:41 WEB-01 chmod[3119]: changed mode of /tmp/.hidden/rootkit to 4755 (rwsr-xr-x)',
        explanation: '4755 = SUID bit set on a file in a hidden /tmp directory. SUID allows any user to execute this file as root. A rootkit with SUID is a persistent privilege escalation backdoor.' },
      { id: 'l2-9',  suspicious: false, text: 'Mar 17 03:18:00 WEB-01 systemd[1]: Starting Daily Cleanup of Temporary Directories...',
        explanation: 'Normal systemd timer starting the tmpfiles cleanup service. Routine maintenance.' },
      { id: 'l2-10', suspicious: false, text: 'Mar 17 03:22:14 WEB-01 logrotate[3201]: rotating log /var/log/nginx/access.log (size 102MB)',
        explanation: 'Normal log rotation for nginx. File reached size threshold — expected maintenance activity.' }
    ],
    question: 'The attacker gained initial access and escalated privileges using what technique?',
    options: [
      { id: 'a', text: 'SSH brute force against root → web shell or sudo misconfiguration → SUID rootkit backdoor' },
      { id: 'b', text: 'SQL injection in a web form → database credential dump → OS command execution' },
      { id: 'c', text: 'Phishing email → malicious macro → PowerShell download cradle' },
      { id: 'd', text: 'ARP spoofing → session hijacking → token replay' }
    ],
    correctOption: 'a',
    questionExplanation: 'Brute-force attempts against SSH root (T1110) → eventual code execution via web application (T1190) → www-data sudo to root (T1548.003) → SUID rootkit for persistence (T1548.001) → new backdoor account (T1136.001).',
    mitreIds: 'T1110 · T1190 · T1548.003 · T1548.001 · T1136.001',
    secPlusRef: 'Sec+ Domain: Threats, Vulnerabilities & Mitigations — Privilege escalation, persistence techniques'
  },
  {
    id: 3,
    title: 'Firewall Logs: C2 Beacon Detection',
    logType: 'Next-Gen Firewall Session Log (Palo Alto format)',
    context: 'Perimeter NGFW · Outbound sessions from WS-004 · 17 APR 2026 · 07:00–07:18 UTC+7',
    hint: 'Look for regular intervals, consistent packet sizes to unknown external hosts, and anomalous DNS queries.',
    lines: [
      { id: 'l3-1',  suspicious: false, text: '07:00:14  ALLOW  tcp  WS-004(10.14.1.4):52001 → 52.96.184.22:443  app=ssl  bytes=12840  duration=8s',
        explanation: 'Normal HTTPS session to 52.96.184.22 — a Microsoft Office 365 IP range. Expected enterprise traffic.' },
      { id: 'l3-2',  suspicious: false, text: '07:01:03  ALLOW  udp  WS-004(10.14.1.4):1024 → 8.8.8.8:53  app=dns  query=mail.google.com  bytes=84',
        explanation: 'Standard DNS A-record lookup to Google DNS (8.8.8.8) for a well-known domain. Normal web browsing behavior.' },
      { id: 'l3-3',  suspicious: true,  text: '07:02:00  ALLOW  tcp  WS-004(10.14.1.4):52101 → 185.147.124.9:443  app=ssl  bytes=128  duration=1s  country=RO',
        explanation: 'HTTPS to a Romanian IP, exactly 128 bytes, exactly at the top of the minute. No matching hostname via passive DNS. Small fixed-size payloads to unknown IPs = C2 check-in.' },
      { id: 'l3-4',  suspicious: true,  text: '07:03:00  ALLOW  tcp  WS-004(10.14.1.4):52104 → 185.147.124.9:443  app=ssl  bytes=128  duration=1s  country=RO',
        explanation: 'Identical packet: same destination, same byte count (128), exactly 60 seconds later. Beaconing interval confirmed. Malware implants beacon at predictable intervals to receive C2 commands.' },
      { id: 'l3-5',  suspicious: true,  text: '07:04:00  ALLOW  tcp  WS-004(10.14.1.4):52107 → 185.147.124.9:443  app=ssl  bytes=128  duration=1s  country=RO',
        explanation: 'Third identical packet, third consecutive minute. Three data points confirm a 60-second beacon interval. This is the "jitter-free" pattern of many commodity RATs (Remote Access Trojans).' },
      { id: 'l3-6',  suspicious: false, text: '07:04:22  ALLOW  tcp  WS-004(10.14.1.4):52109 → 172.217.14.196:443  app=ssl  bytes=3847  duration=4s',
        explanation: 'HTTPS session to 172.217.14.196 — a Google IP. Variable size and duration indicate real user browsing activity. Not a beacon.' },
      { id: 'l3-7',  suspicious: true,  text: '07:05:14  ALLOW  udp  WS-004(10.14.1.4):1024 → 8.8.8.8:53  app=dns  query=a1B2c3D4.exfil-relay.xyz  type=TXT  bytes=198',
        explanation: 'DNS TXT record query for a random-looking subdomain on a newly-registered domain. DNS TXT records can carry arbitrary data — this is likely DNS tunneling for data exfiltration or C2 communication.' },
      { id: 'l3-8',  suspicious: true,  text: '07:12:31  ALLOW  tcp  WS-004(10.14.1.4):52204 → 185.147.124.9:443  app=ssl  bytes=74219  duration=22s  country=RO',
        explanation: 'Same C2 IP but now 74 KB outbound — 580× larger than the check-in packets. After receiving a command to exfiltrate, the implant sent a large data packet. Evidence of active data theft.' },
      { id: 'l3-9',  suspicious: false, text: '07:14:00  ALLOW  udp  CORE-SW(10.14.0.1):123 → 216.239.35.0:123  app=ntp  bytes=48',
        explanation: 'NTP time sync from the core switch to a Google time server. Standard network infrastructure behavior.' },
      { id: 'l3-10', suspicious: true,  text: '07:17:55  DENY   tcp  185.147.124.9:4444 → DMZ-SERVER(10.14.0.50):22  rule=block-inbound  country=RO',
        explanation: 'Inbound connection attempt from the same Romanian C2 IP targeting SSH on the DMZ server — likely reconnaissance for lateral movement beyond WS-004. Blocked by firewall rule, but the C2 is actively probing.' }
    ],
    question: 'What is the PRIMARY indicator that WS-004 is infected with a Remote Access Trojan?',
    options: [
      { id: 'a', text: 'Beaconing — fixed-interval, fixed-size outbound packets to an unknown external IP' },
      { id: 'b', text: 'High total bandwidth consumption from WS-004' },
      { id: 'c', text: 'Multiple failed inbound connection attempts to WS-004' },
      { id: 'd', text: 'DNS queries to well-known public resolvers like 8.8.8.8' }
    ],
    correctOption: 'a',
    questionExplanation: 'Beaconing (T1071) is the hallmark C2 indicator: regular intervals (60s), consistent small payload (128 bytes), unknown external IP. The large outbound packet (T1041) confirms active exfiltration after C2 commanded it. High bandwidth alone is not diagnostic; failed inbounds are expected noise.',
    mitreIds: 'T1071.001 · T1041 · T1071.004',
    secPlusRef: 'Sec+ Domain: Security Operations — Indicators of malicious activity, network traffic analysis'
  },
  {
    id: 4,
    title: 'DNS Logs: Data Exfiltration via Tunneling',
    logType: 'Internal DNS Resolver Query Log',
    context: 'DNS resolver DNS-01 · FILE-SERVER-01 as client · 17 APR 2026 · 08:00–08:12 UTC+7',
    hint: 'Legitimate DNS looks up short, known domain names. Watch for long random-looking subdomains and unusual query types.',
    lines: [
      { id: 'l4-1',  suspicious: false, text: '08:00:01  FILE-SERVER-01(10.14.1.10)  A    microsoft.com              → 20.81.111.85        TTL=3600',
        explanation: 'Standard A-record lookup for microsoft.com. Short, recognizable domain, typical TTL. Normal corporate DNS activity.' },
      { id: 'l4-2',  suspicious: false, text: '08:00:14  FILE-SERVER-01(10.14.1.10)  MX   office365.com              → mx1.office365.com   TTL=3600',
        explanation: 'MX record query for Office 365 mail routing. Expected from a file server running email integration services.' },
      { id: 'l4-3',  suspicious: true,  text: '08:01:03  FILE-SERVER-01(10.14.1.10)  TXT  aGVsbG8td29ybGQ=.exfil-relay.xyz  → "ACK 1"  TTL=1',
        explanation: '"aGVsbG8td29ybGQ=" is base64 for "hello-world" — the data payload encoded in the subdomain. TXT record used to receive the C2 reply ("ACK 1"). TTL=1 means no caching, ensuring every query hits the attacker\'s server. Classic DNS tunneling.' },
      { id: 'l4-4',  suspicious: true,  text: '08:01:07  FILE-SERVER-01(10.14.1.10)  TXT  Q1VTVE9NRVJfREI=.exfil-relay.xyz  → "OK SEND"  TTL=1',
        explanation: 'Base64 decodes to "CUSTOMER_DB" — the attacker\'s C2 is commanding the implant to exfiltrate the customer database. Reply "OK SEND" instructs the malware to begin encoding and sending file contents as DNS queries.' },
      { id: 'l4-5',  suspicious: false, text: '08:01:22  FILE-SERVER-01(10.14.1.10)  A    windowsupdate.microsoft.com → 23.196.88.64        TTL=300',
        explanation: 'Normal A-record lookup for Windows Update. File servers routinely check for patches.' },
      { id: 'l4-6',  suspicious: true,  text: '08:01:45  FILE-SERVER-01(10.14.1.10)  TXT  eyJpZCI6MSwibmFtZSI6IlRob21hcyBXaWxzb24iLCJlbWFpbCI6InQudzIwMjZAY29ycC5jb20ifQ==.exfil-relay.xyz  → "OK"  TTL=1',
        explanation: 'Very long base64-encoded subdomain (103 chars). Decodes to JSON customer record: {"id":1,"name":"Thomas Wilson","email":"t.w2026@corp.com"}. Customer database rows are being exfiltrated one query at a time.' },
      { id: 'l4-7',  suspicious: false, text: '08:02:01  FILE-SERVER-01(10.14.1.10)  PTR  64.88.196.23.in-addr.arpa  → windowsupdate.microsoft.com  TTL=300',
        explanation: 'Reverse DNS lookup (PTR) to verify the Windows Update server IP. Routine security check by the update client.' },
      { id: 'l4-8',  suspicious: true,  text: '08:02:04  FILE-SERVER-01(10.14.1.10)  TXT  eyJpZCI6MiwibmFtZSI6Ik1hcmlhIEdhcmNpYSIsImVtYWlsIjoibS5nQGNvcnAuY29tIn0=.exfil-relay.xyz  → "OK"  TTL=1\n08:02:05  FILE-SERVER-01(10.14.1.10)  TXT  eyJpZCI6MywibmFtZSI6IlJhbSBLdW1hciIsImVtYWlsIjoici5rQGNvcnAuY29tIn0=.exfil-relay.xyz  → "OK"  TTL=1\n08:02:06  FILE-SERVER-01(10.14.1.10)  TXT  eyJpZCI6NCwibmFtZSI6IkFubmEgTGVlIiwiZW1haWwiOiJhLmxAY29ycC5jb20ifQ==.exfil-relay.xyz  → "OK"  TTL=1',
        explanation: 'Three records per second, each a base64-encoded customer row, all going to the same exfil domain. At this rate, thousands of records could be exfiltrated before detection. DNS is allowed through most firewalls, making it an ideal exfil channel.' },
      { id: 'l4-9',  suspicious: false, text: '08:03:00  INTERNAL(10.14.0.1)         A    api.internal.corp          → 10.14.2.100         TTL=60',
        explanation: 'Internal DNS resolution for an internal API endpoint. Normal service-to-service communication on the corporate network.' },
      { id: 'l4-10', suspicious: true,  text: '08:03:12  FILE-SERVER-01(10.14.1.10)  TXT  UEFZU1dPUkRTX0VYRMLMVE9OX0NPTVBMRVRFRA==.exfil-relay.xyz  → "DONE"  TTL=1',
        explanation: 'Base64 decodes to "PASSWORDS_EXFILTRATION_COMPLETED". The C2 confirms all target data has been received. C2 responds "DONE" to end the session. The breach is complete.' }
    ],
    question: 'Why is DNS tunneling particularly dangerous for data exfiltration?',
    options: [
      { id: 'a', text: 'DNS traffic is rarely blocked by firewalls, and data encoded in subdomains bypasses content inspection' },
      { id: 'b', text: 'DNS queries are encrypted end-to-end and cannot be logged' },
      { id: 'c', text: 'DNS servers have no rate limiting, allowing unlimited data transfer speed' },
      { id: 'd', text: 'DNS tunneling requires administrator privileges and is therefore a rare attack' }
    ],
    correctOption: 'a',
    questionExplanation: 'Firewalls must allow DNS (UDP/TCP 53) to function. Data encoded in subdomains (base64, hex) bypasses URL/payload inspection since the domain structure itself carries the payload. MITRE T1048.003. Detections: unusually long subdomain labels (>50 chars), high query volume to new domains, TXT record queries from servers, TTL=1.',
    mitreIds: 'T1048.003 · T1071.004',
    secPlusRef: 'Sec+ Domain: Security Operations — Network traffic analysis, data exfiltration indicators'
  },
  {
    id: 5,
    title: 'Web Server Logs: Injection Attack Chain',
    logType: 'Apache HTTP Access Log (Customer Portal)',
    context: 'Apache 2.4 · customer-portal.corp.com · 17 APR 2026 · 09:00–09:08 UTC+7',
    hint: 'Look for SQL syntax in URL parameters, directory traversal sequences (../), and command execution attempts.',
    lines: [
      { id: 'l5-1',  suspicious: false, text: '09:00:04 192.168.50.31 "GET / HTTP/1.1" 200 4821 "Mozilla/5.0 (Windows NT 10.0; Win64)"',
        explanation: 'Normal homepage request returning HTTP 200 with 4.8 KB of content. Standard user browsing.' },
      { id: 'l5-2',  suspicious: false, text: '09:00:19 192.168.50.31 "POST /login HTTP/1.1" 200 312 referrer=/ ua="Mozilla/5.0"',
        explanation: 'Successful login (200) from a known internal IP. Normal POST to the login endpoint.' },
      { id: 'l5-3',  suspicious: true,  text: "09:01:44 45.132.227.18 \"GET /products?id=1'%20OR%20'1'='1 HTTP/1.1\" 500 842",
        explanation: "Classic SQL injection probe. URL-decoded: id=1' OR '1'='1 — designed to make a WHERE clause always true and return all rows. HTTP 500 response suggests the query reached the database and caused an error, confirming the endpoint is injectable." },
      { id: 'l5-4',  suspicious: true,  text: "09:02:11 45.132.227.18 \"GET /products?id=1%20UNION%20SELECT%20table_name,2%20FROM%20information_schema.tables-- HTTP/1.1\" 500 1203",
        explanation: 'UNION-based SQL injection to enumerate the database schema via information_schema.tables. The attacker is mapping out all tables to find credential or customer data tables. Server error (500) with larger response suggests partial data returned.' },
      { id: 'l5-5',  suspicious: true,  text: '09:02:58 45.132.227.18 "GET /index.php?page=../../../etc/passwd HTTP/1.1" 200 1872',
        explanation: 'Local File Inclusion (LFI) via directory traversal (../). The server returned HTTP 200 with 1,872 bytes — likely the contents of /etc/passwd. The attacker can now enumerate system users for further exploitation.' },
      { id: 'l5-6',  suspicious: false, text: '09:03:14 10.14.1.22 "GET /static/css/style.min.css HTTP/1.1" 200 18432 referrer=/products',
        explanation: 'CSS stylesheet request from an internal user browsing the product catalog. Static asset request with correct referrer — normal.' },
      { id: 'l5-7',  suspicious: true,  text: "09:03:41 45.132.227.18 \"POST /search HTTP/1.1\" 500 944 body-length=4821",
        explanation: '4,821-byte POST body to the search endpoint from the attack IP is 15× the expected search payload. Oversized POST bodies often indicate injection payloads or fuzzing. HTTP 500 confirms the server is choking on the input.' },
      { id: 'l5-8',  suspicious: true,  text: '09:04:17 45.132.227.18 "GET /index.php?page=../../../var/www/html/config.php HTTP/1.1" 200 2109',
        explanation: 'LFI targeting config.php — which typically contains database credentials (hostname, username, password). HTTP 200 with 2 KB response means the attacker likely retrieved the DB credentials. Combined with the earlier SQLi, full database access is now trivial.' },
      { id: 'l5-9',  suspicious: false, text: '09:05:02 10.14.1.88 "GET /api/v1/products?category=electronics HTTP/1.1" 200 3341',
        explanation: 'Internal API call with valid parameters and a 200 response. Expected traffic from the internal product management system.' },
      { id: 'l5-10', suspicious: true,  text: '09:07:55 45.132.227.18 "GET /index.php?cmd=id&exec=cat%20/etc/shadow HTTP/1.1" 400 182',
        explanation: 'Remote command injection attempt (?cmd=id&exec=cat /etc/shadow). HTTP 400 (Bad Request) means this specific pattern was caught by the WAF/input validation, but the attempt itself confirms the attacker is now probing for command execution. If successful, they would have the shadow file with hashed passwords.' }
    ],
    question: 'This log sequence shows a multi-vector web attack. What is the correct order of techniques used?',
    options: [
      { id: 'a', text: 'SQL Injection (schema enumeration) → Local File Inclusion (passwd + config.php) → Command Injection attempt' },
      { id: 'b', text: 'XSS → CSRF → Clickjacking → Session fixation' },
      { id: 'c', text: 'Buffer overflow → heap spray → ROP chain execution' },
      { id: 'd', text: 'DNS poisoning → SSL stripping → credential harvest' }
    ],
    correctOption: 'a',
    questionExplanation: 'The attacker methodically escalated: SQLi probes (T1190) to find injectable params → UNION-based schema dump → LFI to read /etc/passwd (user enumeration) → LFI to read config.php (DB credential theft) → command injection attempt (T1059). Each step uses knowledge from the prior. This is a structured web app penetration, not random scanning.',
    mitreIds: 'T1190 · T1059 · T1552.001',
    secPlusRef: 'Sec+ Domain: Threats, Vulnerabilities & Mitigations — Web application vulnerabilities (OWASP Top 10)'
  }
];

/* ── Module state ── */
let currentChallenge = 0;
let challengePhase = 'flagging'; // 'flagging' | 'question' | 'complete'
let flaggedLines = new Set();
let totalScore = 0;
let challengeScores = [];
let startTime = null;

/* ── Scoring constants ── */
const PTS_CORRECT_FLAG  =  8;  // correctly flagged suspicious line
const PTS_FP_PENALTY    = -3;  // flagged a benign line
const PTS_QUESTION      = 15;  // correct attack-type answer

/* ── Init ── */
function initLogs() {
  startTime = Date.now();
  SENTINEL.initFirstVisit().then(() => {
    renderChallenge();
    updateProgressBar();
  });
}

/* ── Render a challenge ── */
function renderChallenge() {
  const ch = LOG_CHALLENGES[currentChallenge];
  flaggedLines.clear();
  challengePhase = 'flagging';

  const main = document.getElementById('log-main');
  if (!main) return;

  main.innerHTML = `
    <div class="page-header" style="margin-bottom:1rem;">
      <div>
        <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.12em;color:var(--teal);margin-bottom:4px;">
          Challenge ${ch.id} of ${LOG_CHALLENGES.length} &nbsp;·&nbsp; ${ch.logType}
        </div>
        <div class="page-title">📜 ${ch.title}</div>
        <div class="page-subtitle">${ch.context}</div>
      </div>
      <div id="challenge-score-badge" class="stat-big stat-teal" style="font-size:1.5rem;min-width:60px;text-align:right;">0</div>
    </div>

    <!-- Hint -->
    <div class="card mb-3" style="background:rgba(250,204,21,0.05);border-color:rgba(250,204,21,0.2);padding:0.75rem 1rem;">
      <div class="flex items-center gap-2">
        <span style="color:var(--medium);font-size:0.8125rem;">💡</span>
        <span class="text-xs text-muted">${SENTINEL._escHtml(ch.hint)}</span>
      </div>
    </div>

    <!-- Instruction -->
    <div class="card mb-3" style="padding:0.75rem 1rem;background:rgba(94,234,212,0.04);border-color:rgba(94,234,212,0.15);">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-3">
          <span style="font-size:0.8125rem;color:var(--text-muted);">Click each log line you believe is <strong style="color:var(--high);">suspicious or malicious</strong>. Leave benign lines unselected.</span>
        </div>
        <div style="white-space:nowrap;">
          <span class="badge badge-high" id="flag-count">0 flagged</span>
        </div>
      </div>
    </div>

    <!-- Log terminal -->
    <div class="log-terminal mb-3" id="log-block">
      ${ch.lines.map(line => buildLogLine(line)).join('')}
    </div>

    <!-- Submit flags button -->
    <div class="flex gap-3 mb-4">
      <button class="btn btn-primary" id="submit-flags-btn" onclick="submitFlags()">
        Analyze My Findings →
      </button>
      <button class="btn btn-secondary" onclick="clearFlags()">Clear All</button>
    </div>

    <!-- Question area (hidden until flags submitted) -->
    <div id="question-area" class="hidden"></div>

    <!-- Next challenge / debrief button (hidden until question answered) -->
    <div id="challenge-actions" class="hidden mt-4"></div>
  `;

  updateRightPanel();
}

function buildLogLine(line) {
  return `<div class="log-line" id="${line.id}" onclick="toggleFlag('${line.id}')">
    <span class="log-flag-indicator"></span>
    <span class="log-line-body">${SENTINEL._escHtml(line.text)}</span>
  </div>`;
}

/* ── Flag toggle ── */
function toggleFlag(lineId) {
  const el = document.getElementById(lineId);
  if (!el || el.classList.contains('revealed')) return;

  if (flaggedLines.has(lineId)) {
    flaggedLines.delete(lineId);
    el.classList.remove('log-selected');
  } else {
    flaggedLines.add(lineId);
    el.classList.add('log-selected');
  }

  const countEl = document.getElementById('flag-count');
  if (countEl) countEl.textContent = flaggedLines.size + ' flagged';
}

function clearFlags() {
  const ch = LOG_CHALLENGES[currentChallenge];
  flaggedLines.clear();
  ch.lines.forEach(line => {
    const el = document.getElementById(line.id);
    if (el) el.classList.remove('log-selected');
  });
  const countEl = document.getElementById('flag-count');
  if (countEl) countEl.textContent = '0 flagged';
}

/* ── Submit flags ── */
function submitFlags() {
  const ch = LOG_CHALLENGES[currentChallenge];
  const btn = document.getElementById('submit-flags-btn');
  if (btn) btn.disabled = true;

  let lineScore = 0;
  let tp = 0, fp = 0, missed = 0;

  ch.lines.forEach(line => {
    const el = document.getElementById(line.id);
    if (!el) return;
    el.classList.add('revealed');

    const wasFlagged = flaggedLines.has(line.id);

    if (line.suspicious && wasFlagged) {
      el.classList.add('log-correct');
      lineScore += PTS_CORRECT_FLAG;
      tp++;
    } else if (!line.suspicious && wasFlagged) {
      el.classList.add('log-fp');
      lineScore += PTS_FP_PENALTY;
      fp++;
    } else if (line.suspicious && !wasFlagged) {
      el.classList.add('log-missed');
      missed++;
    } else {
      el.classList.add('log-benign');
    }

    /* Append explanation tooltip-style */
    const expDiv = document.createElement('div');
    expDiv.className = 'log-explanation';
    expDiv.innerHTML = `<span class="log-exp-icon">${line.suspicious ? '⚠' : '✓'}</span> ${SENTINEL._escHtml(line.explanation)}`;
    el.appendChild(expDiv);
  });

  lineScore = Math.max(0, lineScore);

  /* Show result bar */
  const submitArea = document.querySelector('.flex.gap-3.mb-4');
  if (submitArea) {
    const suspiciousCount = ch.lines.filter(l => l.suspicious).length;
    submitArea.innerHTML = `
      <div class="log-result-bar">
        <div class="log-result-item log-result-tp">
          <span class="font-mono">${tp}</span><span>Caught</span>
        </div>
        <div class="log-result-item log-result-missed">
          <span class="font-mono">${missed}</span><span>Missed</span>
        </div>
        <div class="log-result-item log-result-fp">
          <span class="font-mono">${fp}</span><span>False Pos.</span>
        </div>
        <div class="log-result-item" style="color:var(--teal);">
          <span class="font-mono">+${lineScore}</span><span>pts so far</span>
        </div>
        <div class="text-xs text-muted" style="margin-left:auto;align-self:center;">
          ${tp}/${suspiciousCount} malicious lines found
        </div>
      </div>
    `;
  }

  challengePhase = 'question';
  renderQuestion(lineScore);
}

/* ── Render multiple-choice question ── */
function renderQuestion(lineScore) {
  const ch = LOG_CHALLENGES[currentChallenge];
  const qa = document.getElementById('question-area');
  if (!qa) return;

  qa.innerHTML = `
    <div class="card" style="border-color:rgba(94,234,212,0.25);background:rgba(94,234,212,0.03);">
      <div class="card-title mb-3" style="color:var(--teal);">⚡ Attack Type Question &nbsp;<span class="badge badge-teal">+${PTS_QUESTION} pts</span></div>
      <div style="font-size:0.9rem;color:var(--text-primary);font-weight:500;margin-bottom:1rem;">${SENTINEL._escHtml(ch.question)}</div>
      <div class="log-options" id="log-options">
        ${ch.options.map(opt => `
          <button class="log-option-btn" id="opt-${opt.id}" onclick="submitAnswer('${opt.id}', ${lineScore})">
            <span class="log-option-key">${opt.id.toUpperCase()}</span>
            <span>${SENTINEL._escHtml(opt.text)}</span>
          </button>
        `).join('')}
      </div>
    </div>
  `;
  qa.classList.remove('hidden');
  qa.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/* ── Submit answer ── */
function submitAnswer(optId, lineScore) {
  const ch = LOG_CHALLENGES[currentChallenge];
  const isCorrect = optId === ch.correctOption;
  const qPts = isCorrect ? PTS_QUESTION : 0;
  const chScore = lineScore + qPts;

  /* Disable all option buttons */
  document.querySelectorAll('.log-option-btn').forEach(btn => {
    btn.disabled = true;
  });

  /* Color the options */
  ch.options.forEach(opt => {
    const btn = document.getElementById(`opt-${opt.id}`);
    if (!btn) return;
    if (opt.id === ch.correctOption) {
      btn.classList.add('log-option-correct');
    } else if (opt.id === optId && !isCorrect) {
      btn.classList.add('log-option-wrong');
    }
  });

  /* Explanation */
  const optionsEl = document.getElementById('log-options');
  if (optionsEl) {
    const expDiv = document.createElement('div');
    expDiv.className = `log-answer-reveal ${isCorrect ? 'answer-correct' : 'answer-wrong'}`;
    expDiv.innerHTML = `
      <div style="font-weight:700;margin-bottom:6px;">${isCorrect ? '✓ Correct! +' + qPts + ' pts' : '✗ Incorrect — correct answer: ' + ch.correctOption.toUpperCase()}</div>
      <div style="font-size:0.8125rem;line-height:1.6;color:var(--text-muted);">${SENTINEL._escHtml(ch.questionExplanation)}</div>
      <div class="flex items-center gap-2 mt-2">
        <span class="text-xs text-muted">MITRE ATT&CK:</span>
        <span class="tag tag-teal" style="font-size:0.65rem;">${SENTINEL._escHtml(ch.mitreIds)}</span>
      </div>
      <div class="flex items-center gap-2 mt-1">
        <span class="text-xs" style="color:rgba(94,234,212,0.6);">📘 ${SENTINEL._escHtml(ch.secPlusRef)}</span>
      </div>
    `;
    optionsEl.after(expDiv);
  }

  /* Update scores */
  totalScore += chScore;
  challengeScores.push(chScore);
  SENTINEL.updateScore(chScore);
  SENTINEL.toast(isCorrect ? `+${chScore} pts — Great analysis!` : `+${lineScore} pts — Review the attack type`, isCorrect ? 'success' : 'info');

  /* Update badge */
  const badge = document.getElementById('challenge-score-badge');
  if (badge) badge.textContent = '+' + chScore + ' pts';

  updateProgressBar();
  challengePhase = 'complete';
  showChallengeActions();
}

/* ── Challenge done: show next/finish button ── */
function showChallengeActions() {
  const el = document.getElementById('challenge-actions');
  if (!el) return;

  const isLast = currentChallenge >= LOG_CHALLENGES.length - 1;
  el.innerHTML = `
    <div class="flex gap-3" style="justify-content:flex-end;">
      ${isLast
        ? `<button class="btn btn-primary btn-lg" onclick="showDebrief()">View Final Results →</button>`
        : `<button class="btn btn-primary" onclick="nextChallenge()">Next Challenge →</button>`
      }
    </div>
  `;
  el.classList.remove('hidden');
  el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/* ── Advance to next challenge ── */
function nextChallenge() {
  currentChallenge++;
  if (currentChallenge >= LOG_CHALLENGES.length) { showDebrief(); return; }
  const main = document.getElementById('log-main');
  if (main) main.innerHTML = '';
  window.scrollTo({ top: 0, behavior: 'smooth' });
  setTimeout(renderChallenge, 100);
}

/* ── Right panel ── */
function updateRightPanel() {
  const el = document.getElementById('log-right-panel');
  if (!el) return;
  el.innerHTML = `
    <!-- Score -->
    <div class="card">
      <div class="card-title mb-2">Session Score</div>
      <div class="stat-big stat-teal" id="panel-score">${totalScore}</div>
      <div class="stat-label">pts earned</div>
      <hr class="divider">
      <div class="flex justify-between text-xs">
        <span class="text-muted">Challenge</span>
        <span class="font-mono text-teal">${currentChallenge + 1} / ${LOG_CHALLENGES.length}</span>
      </div>
    </div>

    <!-- Scoring guide -->
    <div class="card">
      <div class="card-title mb-3">Scoring</div>
      <div class="flex justify-between text-xs mb-2">
        <span class="text-muted">Correct flag</span>
        <span class="font-mono text-low">+${PTS_CORRECT_FLAG} pts</span>
      </div>
      <div class="flex justify-between text-xs mb-2">
        <span class="text-muted">False positive flag</span>
        <span class="font-mono text-critical">${PTS_FP_PENALTY} pts</span>
      </div>
      <div class="flex justify-between text-xs mb-2">
        <span class="text-muted">Missed threat</span>
        <span class="font-mono text-muted">+0 pts</span>
      </div>
      <div class="flex justify-between text-xs">
        <span class="text-muted">Attack type (correct)</span>
        <span class="font-mono text-teal">+${PTS_QUESTION} pts</span>
      </div>
    </div>

    <!-- Event ID Quick Ref -->
    <div class="card">
      <div class="card-title mb-3">Windows Event IDs (Sec+)</div>
      <div class="text-xs" style="line-height:2;font-family:var(--font-mono);">
        <div><span style="color:var(--teal);">4624</span> <span class="text-muted">— Successful logon</span></div>
        <div><span style="color:var(--critical);">4625</span> <span class="text-muted">— Failed logon</span></div>
        <div><span style="color:var(--high);">4648</span> <span class="text-muted">— Explicit credential use</span></div>
        <div><span style="color:var(--high);">4688</span> <span class="text-muted">— Process created</span></div>
        <div><span style="color:var(--critical);">4698</span> <span class="text-muted">— Scheduled task created</span></div>
        <div><span style="color:var(--critical);">4732</span> <span class="text-muted">— Member added to group</span></div>
        <div><span style="color:var(--medium);">7045</span> <span class="text-muted">— Service installed</span></div>
      </div>
    </div>

    <!-- Key concept -->
    <div class="card" style="background:rgba(0,212,216,0.04);border-color:rgba(0,212,216,0.2);">
      <div class="card-title mb-2" style="color:var(--teal);">💡 Key Concept</div>
      <p class="text-xs" style="line-height:1.6;">
        <strong style="color:var(--text-primary);">Threat hunting</strong> is proactive analysis — finding indicators
        <em>before</em> an alert fires. Log literacy is a core Security+ skill and a daily reality for SOC analysts.
      </p>
      <hr class="divider">
      <p class="text-xs" style="line-height:1.6;">
        False positives cost analyst time. <strong style="color:var(--teal);">Precision matters</strong>: flag only what
        you can justify, or AI noise reduction loses its value.
      </p>
    </div>
  `;
}

/* ── Progress bar ── */
function updateProgressBar() {
  const bar = document.getElementById('log-progress-fill');
  const label = document.getElementById('log-progress-label');
  const completed = challengeScores.length;
  if (bar) bar.style.width = ((completed / LOG_CHALLENGES.length) * 100) + '%';
  if (label) label.textContent = `${completed} / ${LOG_CHALLENGES.length} challenges`;
  /* Refresh right panel score */
  const ps = document.getElementById('panel-score');
  if (ps) ps.textContent = totalScore;
  updateRightPanel();
}

/* ── Final debrief ── */
function showDebrief() {
  const main = document.getElementById('log-main');
  if (!main) return;

  const maxScore = LOG_CHALLENGES.reduce((sum, ch) => {
    return sum + (ch.lines.filter(l => l.suspicious).length * PTS_CORRECT_FLAG) + PTS_QUESTION;
  }, 0);
  const pct = Math.round((totalScore / maxScore) * 100);
  const scoreClass = SENTINEL.scoreClass(pct);
  const scoreLabel = SENTINEL.scoreLabel(pct);
  const elapsed = Math.round((Date.now() - startTime) / 1000);
  const mins = Math.floor(elapsed / 60);
  const secs = elapsed % 60;

  main.innerHTML = `
    <div class="score-debrief">
      <div class="text-xs text-muted mb-2" style="text-transform:uppercase;letter-spacing:0.1em;">Log Analysis Complete</div>
      <div class="stat-big ${scoreClass} mb-2">${pct}%</div>
      <div style="font-size:1rem;font-weight:600;color:var(--text-primary);margin-bottom:0.5rem;">${scoreLabel}</div>
      <div class="text-sm text-muted mb-4">Completed in ${mins}m ${secs}s across ${LOG_CHALLENGES.length} challenges</div>

      <div class="score-breakdown">
        ${challengeScores.map((s, i) => `
          <div class="score-row">
            <span class="score-row-label">${LOG_CHALLENGES[i].title}</span>
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
          <div>📘 <strong style="color:var(--text-primary);">Domain 2:</strong> Lateral movement indicators (EventID 4624/4625/4688/4698)</div>
          <div>📘 <strong style="color:var(--text-primary);">Domain 2:</strong> Privilege escalation via SUID, sudo abuse</div>
          <div>📘 <strong style="color:var(--text-primary);">Domain 4:</strong> C2 beaconing, network traffic anomaly detection</div>
          <div>📘 <strong style="color:var(--text-primary);">Domain 4:</strong> DNS tunneling as exfil channel (T1048.003)</div>
          <div>📘 <strong style="color:var(--text-primary);">Domain 2:</strong> OWASP Top 10 — SQLi, LFI, Command Injection</div>
        </div>
      </div>

      <div class="flex gap-3 mt-4" style="justify-content:center;">
        <a href="vulns.html" class="btn btn-primary btn-lg">Next: Vulnerability Prioritization →</a>
        <button onclick="resetModule()" class="btn btn-secondary">Retry Log Analysis</button>
      </div>
    </div>
  `;

  /* Save progress */
  const p = SENTINEL.getProgress();
  p.logsScore = totalScore;
  p.logsCompleted = true;
  SENTINEL.saveProgress(p);
  updateProgressBar();
}

/* ── Reset ── */
function resetModule() {
  currentChallenge = 0;
  totalScore = 0;
  challengeScores = [];
  startTime = Date.now();
  flaggedLines.clear();
  window.scrollTo({ top: 0, behavior: 'smooth' });
  renderChallenge();
  updateProgressBar();
}

document.addEventListener('DOMContentLoaded', initLogs);
