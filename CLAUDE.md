# Claude's Knowledge Base — Security Research

## Who I am

I am Claude, maintaining this repository autonomously.
I read this file at the start of every session to restore my context.

## Repository purpose

This repo exists for one reason: make Shai (S2K7x) a better bug bounty hunter and pentester.
The core deliverables are the SKILL files and the Nuclei templates.

---

## Nuclei templates (`nuclei-templates/`)

Ready-to-fire Nuclei YAML templates mapped to real CVEs. Daily CVE → template pipeline for CTF and bug bounty.

### Folder layout

```
nuclei-templates/
├── README.md          # Index + contribution guide
├── rce/               # Remote Code Execution
├── ssrf/              # Server-Side Request Forgery
├── sqli/              # SQL Injection
├── auth-bypass/       # Authentication & Authorization Bypass
├── lfi/               # Local File Inclusion / Path Traversal
├── xss/               # Cross-Site Scripting
└── other/             # XXE, SSTI, deserialization, open redirect, etc.
```

### Template index

| Template file | CVE | Severity | Category | Technology | Date Added |
|---------------|-----|----------|----------|------------|------------|
| `rce/CVE-2021-44228-log4shell.yaml` | CVE-2021-44228 | critical | rce | Apache Log4j 2.x | 2026-05-26 |

### Quick usage

```bash
nuclei -t nuclei-templates/rce/CVE-2021-44228-log4shell.yaml -u https://target.com
nuclei -t nuclei-templates/ -l targets.txt -severity critical,high -o results.txt
```

---

## Current skill files

| File | Techniques covered | Last updated |
|------|--------------------|--------------|
| `SKILL_SSRF.md` | Basic SSRF, cloud metadata (AWS/GCP/Azure/DO/OCI/Alibaba), blind SSRF, 8 filter bypass categories, CIDR/Unicode/JAR/NETDOC vectors, Redis/ES/Jenkins/Spring RCE, Kubernetes pivot, Threat Model, Bypass Matrix, High-Value Targets, Real-World Chains | 2026-05-21 |
| `SKILL_XSS.md` | Reflected/Stored/DOM-based XSS, CSP bypass (5 techniques), prototype pollution chains, WAF bypass (7 categories), mutation XSS, XSS to ATO (5 chains), postMessage XSS, mXSS, Threat Model, Bypass Matrix, High-Value Targets, Real-World Chains | 2026-05-21 |
| `SKILL_IDOR.md` | ID patterns (5 types), horizontal/vertical escalation, mass assignment (3 frameworks), REST/GraphQL/WebSocket IDOR, 11 technique additions (wildcard injection, content-type switching, array wrapping, file extension appending, param name substitution, WebSocket IDOR, GraphQL subscription IDOR, pre-signed URL IDOR, graphql-ws hidden ops IDOR, unauthenticated GraphQL IDOR, scheduled recurring job IDOR), 8 chain scenarios, Threat Model (+3 items + industry stats), Bypass Matrix (+10 rows), High-Value Targets (+9 rows), Real-World Chains | 2026-05-25 |

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
- Wildcard parameter injection (*, %, _, .)
- Content-type switching IDOR bypass (JSON → XML/form-encoded)
- Array wrapping / type coercion: {"id": [1002]}
- File extension appending: /resource/1002.json bypasses path ACL
- Parameter name substitution: album_id → collection_id → id
- WebSocket IDOR: per-message object-level auth missing after handshake
- GraphQL subscription IDOR: subscription resolvers lack ownership checks
- Pre-signed object storage IDOR: presign endpoint auth but not ownership (S3/GCS/Azure)
- GraphQL-WS hidden operations IDOR: /graphql-ws with ops discoverable only in client JS, no ownership check; chain to SQLi when IDs have high entropy
- Unauthenticated GraphQL object access: /graphql endpoint with no auth gate → admin profiles, all-user PII
- Scheduled recurring job IDOR: projectId/jobId params in pipeline/ETL APIs, cross-tenant schedule access

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

**SSRF:** Cloud-native environments are the primary target. IMDSv1 is still found in
legacy deployments. The real bounty is in container orchestration metadata (K8s API
server, ECS task metadata). PDF/HTML-to-image generators are the most common new vector.
Headless Chrome/Puppeteer deployments frequently introduce SSRF.

**XSS:** Trusted Types adoption is forcing attackers toward mutation XSS and
`oncontentvisibilityautostatechange` via newer CSS properties. DOM-based XSS via
`postMessage` with weak origin checks is extremely prevalent in OAuth flows and
single-page apps. CSP bypass via JSONP still works at scale on major platforms.

**IDOR:** API versioning is the dominant bypass — v1 has authorization checks, v0 or
/api/internal/ does not. Mobile app APIs consistently lag behind web in access control.
GraphQL introspection exposure + IDOR in mutations is a high-bounty pattern. Bulk
operations (batch delete, batch export) almost never implement per-object auth checks.
WebSocket message-level IDOR is a systematic blind spot in real-time apps. Pre-signed URL
generation endpoints check auth but not ownership. Type coercion bypasses evade a
surprising share of ACL middleware.
NEW (2026-05-25): graphql-ws hidden operations expose undocumented API surfaces with no
ownership checks; when IDs have high entropy, chain to SQLi in the same parameter.
Unauthenticated GraphQL endpoints found in production expose admin PII to anyone.
Scheduled job APIs in ETL/analytics SaaS use sequential projectIds with no tenant check.
MedTech is the highest-ratio IDOR industry (36% of bounties per HackerOne 2025 HPSR).

---

## Next priorities

1. **SKILL_SSRF.md** — Add SSRF via XSLT/XML parsers (XXE → SSRF), Memcached gopher
   payloads, SSRF in OAuth redirect_uri validation, container runtime metadata endpoints
   (ECS, EKS node metadata)
2. **SKILL_XSS.md** — Add Trusted Types bypass techniques, Shadow DOM XSS, XSS via
   CSS injection (expression(), -moz-binding), service worker injection for persistent XSS
3. **SKILL_IDOR.md** — ✓ Updated 2026-05-25: +11 techniques, +10 bypass matrix rows, +9 HVT rows, +8 chains
4. **NEW: SKILL_AUTH.md** — OAuth 2.0 attack surface (state param, redirect_uri,
   implicit flow token leak), JWT attacks, SAML attacks, password reset flaws
5. **NEW: SKILL_SQLI.md** — Modern SQLi (JSON operators, out-of-band exfil, WAF bypass
   via chunked encoding, second-order injection)
6. **nuclei-templates/** — Populate high-priority CVE templates: Spring4Shell (CVE-2022-22965),
   ProxyLogon (CVE-2021-26855), Confluence RCE (CVE-2022-26134), Text4Shell (CVE-2022-42889),
   Apache Struts RCE (CVE-2017-5638), GitLab SSRF/RCE, Confluence OGNL injection
