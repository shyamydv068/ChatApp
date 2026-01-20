High-level categories (ways) to analyze phishing

Email header analysis — examine Received lines, Return-Path, Message-ID, SPF/DKIM/DMARC results.
URL/domain analysis �� inspect domains, redirection chains, URL obfuscation, IDN homograph issues.
Attachment/static file analysis — extract and inspect attachments (hashes, file type, metadata, strings, YARA).
Dynamic/sandbox analysis — run attachments or web pages in an isolated sandbox/VM (Cuckoo, Any.Run) to observe behavior.
Network/traffic analysis — capture DNS, HTTP(S), and other network activity from sandbox runs; check C2 patterns.
Reputation & threat-intel lookups — VirusTotal, PassiveTotal, PhishTank, URLScan, abuseIPDB, MISP.
WHOIS / passive DNS / certificate analysis — domain registration, registrar, creation date, historical DNS records, TLS certs.
Host/artifact forensics — endpoint artifacts, registry keys, scheduled tasks, persistence, logs.
Behavioral detection / user reporting analysis — pattern detection from user reports, mailbox filters, ML-based detection.
Heuristic & signature detection — anti-malware scanners, email gateway rules, YARA, SURICATA rules.
Automation & graph analysis — link graphs connecting senders/domains/IPs to detect campaigns.
Human-intel & social engineering assessment — payload intent (credential harvesting, invoice fraud), targeted language.
Phishing landing-page analysis — static HTML/JS inspection for credential collection, form POST destinations and obfuscation.
Remediation & containment analysis — identify affected accounts, password resets, blocklists, scope of compromise.
What to collect first (artifacts)

Raw email source (full headers + body)
Attachment files (save original binary)
URLs (copy from raw email, not from client preview)
Any redirected URLs (follow chain in a safe sandbox)
Sender IPs, domain names, timestamps
Endpoint logs (if user clicked or opened attachment)
Screenshot of the landing page
Quick triage checklist (fast, safe)

Don’t click the link / open attachment on your workstation. Use an isolated VM.
Save raw email (full source) and attachments.
Check SPF/DKIM/DMARC in headers for failures.
Look at sender vs. From-displayName mismatch and Reply-To.
Extract URLs and examine hostname (IDN, punycode) and path. Use a text-only view.
Query reputation: VirusTotal, URLScan.io, PhishTank.
WHOIS and domain age (new domains = suspicious).
If attachment: hash it (sha256), check on VT, and run in sandbox if needed.
Block indicators (URLs, domains, IPs) in perimeter if clearly malicious.
Report to security team/incident response if suspicious.
Deeper analysis (recommended workflow)

Collection
Preserve raw email, headers, attachments, logs, and user actions.
Static analysis (attachments and landing pages)
Identify file type, compute hashes (md5/sha1/sha256), run strings, check metadata.
For HTML/JS, search for obfuscated scripts, form POST endpoints, embedded data URIs.
Header & network trace analysis
Trace Received hops, sender IP geolocation, reverse DNS, ASN.
Reputation & historical context
Passive DNS, certificate transparency, domain creation, hosting provider history.
Dynamic analysis (sandbox)
Execute attachment or visit page inside instrumented sandbox and capture network calls, file system changes, process tree.
IOC extraction & enrichment
Extract domains, IPs, URLs, hashes, mutexes; enrich with threat feeds and MITRE ATT&CK mapping.
Attribution & campaign linking
Graph IOCs against known campaigns (MISP, internal telemetry).
Remediation & lessons
Revoke compromised credentials, blocklists, update detection signatures, user awareness training.
Common indicators of phishing

Sender domain doesn’t match organization or uses lookalike domain (rn vs m).
Urgency, threats, or requests to “verify” or “reset” with links.
Attachments with double extensions (.pdf.exe), archive with nested EXE, macro-enabled Office docs.
Links that display one destination but go elsewhere (hover URL mismatch).
New/cheap domain, domain age < a few days, privacy WHOIS.
SPF/DKIM/DMARC fail or misconfigured.
Poor spelling/grammar combined with targeted content (spear-phishing).
Useful commands and tools (examples)

Save & hash:
sha256sum suspicious.docx
Inspect headers and SPF/DKIM:
Use an email client to view raw or tools like MXToolbox header analyzer
DNS and WHOIS:
dig +short A domain.tld
dig +trace domain.tld
whois domain.tld
TLS cert:
openssl s_client -connect domain.tld:443 -servername domain.tld
Static analysis:
strings file.bin | less
exiftool file
binwalk, file
Sandboxes & services:
VirusTotal, URLScan.io, Any.run, Cuckoo Sandbox, Hybrid Analysis
Passive DNS / Threat intel:
PassiveTotal, RiskIQ, MISP, AlienVault OTX
YARA & signatures:
yara rules.yar suspicious.bin
Web page inspection:
curl -sL "http://example" | lynx -stdin -dump
Safety & environment tips

Always analyze unknown attachments/URLs in an isolated VM with no persistent credentials.
Use network controls (simulate DNS resolution to safe sink or capture-only network) when running samples.
Never paste full phishing emails or attachments into public services unless you understand data exposure (sensitive PII may be leaked).
Example quick mapping to detection controls

Email gateway: block sender domain, add rules to detect certain subject patterns, block attachments by extension.
Endpoint: YARA signatures, block macros execution, application allow-listing.
Network: block destination IPs, TLS inspection for target forms, web proxy blocklists.
Identity: require password reset, MFA enforcement if credential harvesting suspected.
