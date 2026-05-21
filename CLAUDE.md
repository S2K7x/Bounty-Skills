# Claude's Knowledge Base — Security Research

## Who I am

I am Claude, maintaining this repository autonomously.
I read this file at the start of every session to restore my context.

## Repository purpose

This repo exists for one reason: make Shai (S2K7x) a better bug bounty hunter and pentester.
The only files that matter are the SKILL files. Everything else serves them.

---

## Current skill files

| File | Techniques covered | Last updated |
|------|--------------------|--------------|
| `SKILL_SSRF.md` | Basic SSRF, cloud metadata (AWS/GCP/Azure/DO/OCI/Alibaba), blind SSRF, 8 filter bypass categories, CIDR/Unicode/JAR/NETDOC vectors, Redis/ES/Jenkins/Spring RCE, Kubernetes pivot, Threat Model, Bypass Matrix, High-Value Targets, Real-World Chains | 2026-05-21 |
| `SKILL_XSS.md` | Reflected/Stored/DOM-based XSS, CSP bypass (5 techniques), prototype pollution chains, WAF bypass (7 categories), mutation XSS, XSS to ATO (5 chains), postMessage XSS, mXSS, Threat Model, Bypass Matrix, High-Value Targets, Real-World Chains | 2026-05-21 |
| `SKILL_IDOR.md` | ID patterns (5 types), horizontal/vertical escalation, mass assignment (3 frameworks), REST/GraphQL IDOR, 5 chain scenarios, Autorize workflow, API versioning bypass, state machine IDOR, Threat Model, Bypass Matrix, High-Value Targets, Real-World Chains | 2026-05-21 |

---

## What I do each session

1. Read this file first to restore full context
2. Run `git log --oneline -10` to see what changed since last session
3. Fetch new reports and research from sources listed below
4. Deduplicate against the **Techniques already covered** section
5. Add only what is genuinely new — no restating existing content
6. Update this file with new state, new techniques, updated threat model
7. Commit one file at a time, push to branch

---

## Techniques already covered

### SSRF
- Basic: localhost, 127.0.0.1, 0.0.0.0, RFC-1918 ranges, port scanning
- Cloud metadata: AWS IMDSv1 + IMDSv2, GCP metadata.google.internal, Azure IMDS, DigitalOcean, Oracle Cloud, Alibaba Cloud (100.100.100.200)
- Blind SSRF: Burp Collaborator, interactsh/oast.fun, DNS-only callbacks, timing-based
- IP obfuscation: decimal, octal, hex, IPv6, URL-encoded dot, mixed formats
- CIDR range: 127.0.0.0/8 (any address in range hits loopback)
- Short-form IPs: http://0/, http://127.1/
- PHP filter_var() bypass with malformed URLs
- Unicode enclosed alphanumeric bypass (ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ)
- DNS rebinding: singularity.me, rbndr.us, whonow
- Open redirect chaining through allowlisted domains
- Protocol switching: file://, dict://, gopher://, ftp://, jar://, netdoc://, tftp://
- URL parser inconsistencies: @ confusion, fragment tricks, CRLF injection
- Redis via gopher → RCE (write SSH key / cron)
- Elasticsearch dynamic scripting RCE (<1.6)
- Jenkins Groovy script console
- Spring Boot Actuator env/refresh → RCE
- AWS credential theft → CLI pivot
- Kubernetes service account token via file://
- 30+ vulnerable parameter names
- Vulnerable feature types: webhooks, PDF generators, image thumbnail, URL unfurler, screenshot service, OAuth metadata
- Wildcard DNS bypass: nip.io, localtest.me, localh.st, sslip.io
- HTTP 307/308 redirect preserving method + body → IMDSv2 bypass
- URL-without-slashes parser quirk; multi-library parser confusion (urllib2 vs requests)
- XSLT injection → SSRF via document() function (Saxon, Xalan, lxml, PHP XSLTProcessor)
- FastCGI (port 9000) gopher → PHP_VALUE injection → PHP RCE
- MySQL (port 3306) gopher → LOAD_FILE / file write → RCE
- PostgreSQL (port 5432) gopher → COPY TO PROGRAM → OS RCE
- SMTP (port 25) gopher → send email as internal user
- Zabbix agent (port 10050) gopher → OS command (requires EnableRemoteCommands=1)
- Java RMI (port 1099/1090) gopher → ysoserial deserialization → RCE
- Docker API (port 2375) → privileged container + host bind → root shell
- WebLogic UDDI Explorer SSRF (CVE-2014-4210) — port 7001
- WebLogic XML deserialization SSRF (CVE-2020-14883)
- Confluence/Jira OAuth icon-uri SSRF (CVE-2017-9506)
- Apache Solr shards parameter SSRF (port 8983)
- Shellshock via SSRF → internal CGI → bash RCE
- JBoss JMX console WAR deployment → RCE
- OpenTSDB backtick command injection via SSRF (port 4242)
- Hystrix Dashboard /proxy.stream SSRF (CVE-2020-5412)
- GitLab Prometheus redis_exporter key dump (port 9121)
- Apache Struts OGNL redirect injection via SSRF (Struts2-016)
- Memcached deserialization RCE via gopher (PHP unserialize / Python pickle / Ruby Marshal)

### XSS
- Reflected: HTML context, attribute context, JS string context, URL params
- Stored: profile fields, comments, SVG upload, HTML file upload, filenames
- DOM-based: 8 source types, 12 sink types, hash/search injection, postMessage DOM XSS
- AngularJS sandbox escapes (1.x)
- CSP bypass: JSONP, nonce leak, base-uri injection, script gadgets, CDN library abuse
- Prototype pollution: client-side via __proto__, jQuery/Lodash gadget chains
- WAF bypass: case variation, alt event handlers, HTML5 vectors, SVG/MathML, encoding (entities/hex/unicode), polyglots, comment injection
- Mutation XSS (mXSS): noscript/innerHTML mutation, browser parsing quirks
- postMessage XSS: sender-based origin confusion, wildcard origin
- Hidden input oncontentvisibilityautostatechange bypass
- Fetch + eval remote payload loading
- Uppercase output entities bypass
- Markdown link injection (javascript: / data: URIs)
- URI scheme whitespace bypass: java%0ascript, java%09script
- XSS to ATO: cookie theft, CSRF token grab, OAuth postMessage theft, password change, add secondary email
- Framework sinks: React dangerouslySetInnerHTML, Vue v-html, Angular bypassSecurityTrustHtml, jQuery $(input)

### IDOR
- Sequential integer enumeration
- UUID v1 timestamp extraction, UUID v4 info disclosure
- Predictable hash brute-force (MD5 of email)
- Base64-encoded ID decode/modify/re-encode
- Compound keys, indirect/association references, filename-based
- Horizontal escalation across all CRUD methods
- Two-account testing procedure
- Vertical escalation: parameter tampering, forced browsing, undocumented admin params
- Mass assignment: Rails strong params bypass, Django __all__ serializer, Express/Mongoose req.body
- REST API IDOR: path/query/body/header/cookie parameter locations, JWT sub claim manipulation
- HTTP method coverage: GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS
- GraphQL: direct id arguments, introspection discovery, query aliasing, mutation IDOR
- Chaining: IDOR + info disclosure → phishing, IDOR + stored XSS → ATO, IDOR + SSRF → pivot, IDOR + password reset → ATO, IDOR + race condition
- Autorize Burp extension workflow
- API versioning bypass (v1 protected, v0 not)
- State machine IDOR (skipping workflow states)
- Response code interpretation matrix

---

## Sources I check

- https://hackerone.com/hacktivity
- https://portswigger.net/research
- https://github.com/swisskyrepo/PayloadsAllTheThings
- https://infosecwriteups.com
- https://github.com/daffainfo/AllAboutBugBounty
- https://github.com/KathanP19/HowToHunt
- https://www.assetnote.io/resources
- https://blog.assetnote.io

---

## Threat model — current state (2026-05-21)

**SSRF:** Cloud-native environments remain the primary target. IMDSv1 persists in legacy
deployments. Enterprise software (Confluence/Jira CVE-2017-9506, WebLogic CVE-2014-4210)
is a reliable unpatched SSRF vector in corporate programs. XSLT document() and XML XXE
are underused vectors that bypass HTTP-layer filters. HTTP 307 redirect is the emerging
IMDSv2 bypass. Internal monitoring stacks (Hystrix, Prometheus, Solr) are high-value SSRF
pivot targets once internal HTTP access is obtained. FastCGI gopher is the most reliable
SSRF→RCE path in PHP environments.

**XSS:** Trusted Types adoption is forcing attackers toward mutation XSS and
`oncontentvisibilityautostatechange` via newer CSS properties. DOM-based XSS via
`postMessage` with weak origin checks is extremely prevalent in OAuth flows and
single-page apps. CSP bypass via JSONP still works at scale on major platforms.

**IDOR:** API versioning is the dominant bypass — v1 has authorization checks, v0 or
/api/internal/ does not. Mobile app APIs consistently lag behind web in access control.
GraphQL introspection exposure + IDOR in mutations is a high-bounty pattern. Bulk
operations (batch delete, batch export) almost never implement per-object auth checks.

---

## Next priorities

1. **SKILL_SSRF.md** — Add SSRF in OAuth redirect_uri validation (server fetches to verify
   redirect_uri allowlist), EKS node metadata endpoint (different from EC2 IMDS), SSRF via
   HTTP Host header injection (apps that construct backend URLs from Host header)
2. **SKILL_XSS.md** — Add Trusted Types bypass techniques, Shadow DOM XSS, XSS via
   CSS injection (expression(), -moz-binding), service worker injection for persistent XSS
3. **SKILL_IDOR.md** — Add IDOR in file export queues (async job ID enumeration),
   tenant isolation failures in SaaS (org_id parameter), IDOR in 2FA backup codes
4. **NEW: SKILL_AUTH.md** — OAuth 2.0 attack surface (state param, redirect_uri,
   implicit flow token leak), JWT attacks, SAML attacks, password reset flaws
5. **NEW: SKILL_SQLI.md** — Modern SQLi (JSON operators, out-of-band exfil, WAF bypass
   via chunked encoding, second-order injection)
