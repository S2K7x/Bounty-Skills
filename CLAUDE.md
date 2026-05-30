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
| `auth-bypass/CVE-2025-29927-nextjs-middleware-auth-bypass.yaml` | CVE-2025-29927 | critical | auth-bypass | Next.js 12.x-15.x | 2026-05-26 |

### Quick usage

```bash
nuclei -t nuclei-templates/rce/CVE-2021-44228-log4shell.yaml -u https://target.com
nuclei -t nuclei-templates/ -l targets.txt -severity critical,high -o results.txt
```

---

## Current skill files

| File | Techniques covered | Last updated |
|------|--------------------|--------------|
| `SKILL_SSRF.md` | Basic SSRF, cloud metadata (AWS/GCP/Azure/DO/OCI/Alibaba), blind SSRF, 8 filter bypass categories, CIDR/Unicode/JAR/NETDOC vectors, Redis/ES/Jenkins/Spring RCE, Kubernetes pivot, Routing-based SSRF (Host header), HTTP/2 pseudo-header SSRF, CVE-2025-61882 (Oracle EBS SSRF→CRLF→XSLT RCE), AI agent SSRF via prompt injection, HasPrefix allowlist bypass, SNI proxy SSRF, Threat Model (+6 new patterns), Bypass Matrix (+6 rows), High-Value Targets (+6 rows) | 2026-05-26 |
| `SKILL_XSS.md` | Reflected/Stored/DOM-based XSS, CSP bypass (5 techniques), prototype pollution chains, WAF bypass (7 categories), mutation XSS, XSS to ATO (5 chains), postMessage XSS, mXSS, Threat Model, Bypass Matrix, High-Value Targets, Real-World Chains | 2026-05-21 |
| `SKILL_IDOR.md` | ID patterns (5 types), horizontal/vertical escalation, mass assignment (3 frameworks), REST/GraphQL/WebSocket IDOR, 24 technique additions (wildcard injection, content-type switching, array wrapping, file extension appending, param name substitution, WebSocket IDOR, GraphQL subscription IDOR, pre-signed URL IDOR, graphql-ws hidden ops IDOR, unauthenticated GraphQL IDOR, scheduled recurring job IDOR, hex ID bypass, timestamp enumeration, MongoDB ObjectID, blind IDOR, soft-delete IDOR, share link IDOR, Next.js CVE-2025-29927, AI chatbot API IDOR, cursor token IDOR, HTTP verb tunneling IDOR, SSE stream IDOR, path normalization IDOR, referrer-based bypass, bulk/batch IDOR, X-Original-URL header IDOR, CSV import file IDOR), 10 chain scenarios, Threat Model (+25 items + industry stats), Bypass Matrix (+25 rows), High-Value Targets (+23 rows), Real-World Chains | 2026-05-30 |
| `SKILL_SSRF.md` | Basic SSRF, cloud metadata (AWS/GCP/Azure/DO/OCI/Alibaba), blind SSRF, 8 filter bypass categories, CIDR/Unicode/JAR/NETDOC vectors, Redis/ES/Jenkins/Spring RCE, Kubernetes pivot, Threat Model, Bypass Matrix, High-Value Targets, Real-World Chains | 2026-05-21 |
| `SKILL_XSS.md` | Reflected/Stored/DOM-based XSS, CSP bypass (8 techniques), prototype pollution chains, WAF bypass (12 categories), mutation XSS, XSS to ATO (5 chains), postMessage XSS, mXSS, DOM clobbering, dangling markup, cookie sandwich (HttpOnly bypass), DOMPurify PP bypass (CVE-2024-45801), CSS nonce oracle + bfcache, PHP max_input_vars CSP bypass, full-width unicode, array method invocation, regex source reconstruction, null byte attribute injection, JSFuck obfuscation, Angular CSTI version matrix, DOM clobbering→CSP, Threat Model, Bypass Matrix, High-Value Targets, Real-World Chains | 2026-05-27 |
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
- Routing-based SSRF: Host header injection, X-Forwarded-Host, load balancer misrouting, internal subnet fuzzing
- HTTP/2 pseudo-header SSRF: :authority set to internal IP, :scheme arbitrary bytes, reverse proxy translation gap
- CVE-2025-61882 Oracle EBS: pre-auth SSRF in UiServlet → CRLF injection → BI Publisher XSLT → Runtime.exec() RCE (CVSS 9.8)
- AI agent SSRF via prompt injection: LLM tool-calling agents coerced via hidden instructions in fetched content
- URL allowlist HasPrefix bypass: `https://ALLOWED@INTERNAL_HOST/` bypasses strings.HasPrefix / startsWith checks (CVE-2025-8341 Grafana pattern)
- SNI proxy SSRF: TLS SNI field in ClientHello used for routing → internal HTTPS service access

### XSS
- Reflected: HTML context, attribute context, JS string context, URL params
- Stored: profile fields, comments, SVG upload, HTML file upload, filenames
- DOM-based: 8 source types, 12 sink types, hash/search injection, postMessage DOM XSS
- AngularJS sandbox escapes (1.x) — version-specific payloads 1.0–1.6+, WAF bypass via string split/join
- CSP bypass: JSONP, nonce leak, base-uri injection, script gadgets, CDN library abuse, PHP max_input_vars header drop, CSS attr selector nonce oracle + bfcache, DOM clobbering → script.src + strict-dynamic
- Prototype pollution: client-side via __proto__, jQuery/Lodash gadget chains, DOMPurify depth bypass (CVE-2024-45801)
- WAF bypass: case variation, alt event handlers, HTML5 vectors, SVG/MathML, encoding (entities/hex/unicode), polyglots, comment injection, full-width unicode (U+FF1C/FF1E), null byte in attribute names, array method invocation, regex .source reconstruction, JSFuck ([]!() only)
- Mutation XSS (mXSS): noscript/innerHTML mutation, browser parsing quirks
- postMessage XSS: sender-based origin confusion, wildcard origin
- Hidden input oncontentvisibilityautostatechange bypass
- Fetch + eval remote payload loading
- Uppercase output entities bypass
- Markdown link injection (javascript: / data: URIs)
- URI scheme whitespace bypass: java%0ascript, java%09script
- XSS to ATO: cookie theft, CSRF token grab, OAuth postMessage theft, password change, add secondary email
- Cookie sandwich technique: HttpOnly cookie bypass via RFC2109 legacy parsing
- Dangling markup injection: CSRF token/data theft without JS under strict CSP
- DOM clobbering → CSP bypass: clobber script.src config property → strict-dynamic trust inheritance
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
- Hex-encoded numeric ID bypass: submit ID as 0x4642d — ACL integer-format check skips non-decimal input
- Unix timestamp ID enumeration: determine creation-time window, sweep ±N seconds
- MongoDB ObjectID prediction: extract timestamp from known OID; enumerate counter bytes of same second
- Blind IDOR (write-only / side-effect): silent sabotage — unsubscribe, delete, revoke with no visible data in response
- Soft-delete IDOR: ACL stripped when object is soft-deleted; direct API call bypasses UI restriction
- Share link generation IDOR: share endpoint checks auth not ownership; create link for any resource
- Next.js middleware bypass: CVE-2025-29927 — x-middleware-subrequest header skips all middleware, CVSS 9.1
- AI/chatbot backend API IDOR: sequential lead_id/session_id in chatbot REST endpoints, no object-level auth (McHire/McDonald's: 64M records, Jun 2025)
- Cursor/pagination token IDOR: decode base64/JWT cursor, modify userId/scope, re-encode → victim's paginated data
- HTTP verb tunneling IDOR: POST + X-HTTP-Method-Override: DELETE / _method=DELETE param bypasses method-specific WAF/ACL
- Server-Sent Events (SSE) IDOR: userId/channel param in SSE URL not ownership-checked after initial connection auth
- Path normalization IDOR: /api/users/1001%2F..%2F1002 passes gateway (matches "1001"), backend normalizes to "1002"
- Referrer-based access control bypass: Referer: https://target.com/admin spoofs trusted page → ACL grants access
- Bulk/batch operation IDOR: {"ids": [own_id, victim_id]} — per-object auth skipped on batch requests
- X-Original-URL / X-Rewrite-URL header IDOR: Nginx/Varnish/Symfony proxy trusts header → backend routes to header value
- CSV/JSON import file IDOR: import file references victim's object IDs; ownership not checked on each row during processing

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

## Threat model — current state (2026-05-26)

**SSRF:** Cloud-native environments are the primary target. IMDSv1 is still found in
legacy deployments. The real bounty is in container orchestration metadata (K8s API
server, ECS task metadata). PDF/HTML-to-image generators are the most common new vector.
Headless Chrome/Puppeteer deployments frequently introduce SSRF.
NEW (2026-05-26): Routing-based SSRF via Host header injection is under-tested in microservice stacks.
HTTP/2 pseudo-header (:authority) SSRF bypasses HTTP/1.1-based WAF rules. CVE-2025-61882 (Oracle EBS)
is a pre-auth SSRF→CRLF→XSLT RCE chain (CVSS 9.8) actively exploited by Cl0p ransomware.
AI agent SSRF via prompt injection is a new class — bypasses URL filters by coercing the LLM's tool calls.
The `strings.HasPrefix`/`startsWith` URL allowlist anti-pattern (CVE-2025-8341) is widespread.
SSRF attack volume increased 452% from 2023 to 2024 per SonicWall 2025 Cyber Threat Report.

**XSS:** Trusted Types adoption is forcing attackers toward mutation XSS and
`oncontentvisibilityautostatechange` via newer CSS properties. DOM-based XSS via
`postMessage` with weak origin checks is extremely prevalent in OAuth flows and
single-page apps. CSP bypass via JSONP still works at scale on major platforms.
NEW (2026-05-27): Cookie sandwich technique (PortSwigger Dec 2024) bypasses HttpOnly on
Tomcat/Flask stacks — critical for XSS monetization where cookies are HttpOnly. CSS
attribute selector nonce oracle + bfcache is a novel technique for leaking CSP nonces
without script execution. DOMPurify CVE-2024-45801 (prototype pollution depth bypass)
affects all DOMPurify <2.5.4/<3.1.3 — widespread in production. JSFuck + array method
invocation are the most reliable WAF bypass when keywords and parens are both filtered.

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
NEW (2026-05-28): Blind IDOR is the emerging survivorship pattern — as read IDORs get
patched, write-only/side-effect IDORs persist undetected in scanners. Soft-delete ACL
stripping is a systematic developer blind spot; always test deleted objects directly via
API. Share link endpoints universally check auth but not ownership. CVE-2025-29927
(Next.js middleware bypass, CVSS 9.1) turns any self-hosted Next.js into an IDOR-free-
for-all via one header. AI chatbot backends (Paradox, Intercom, Drift) expose sequential
numeric IDs with no ownership check — McHire exposed 64M McDonald's records this way.
Cursor-based pagination tokens encode user scope and are trusted without re-validation.
NEW (2026-05-30): HTTP verb tunneling via X-HTTP-Method-Override is newly under-tested —
WAFs that block DELETE/PATCH at the method level pass POST+header variants through; Rails,
Django, and .NET all support verb overriding by default. SSE stream IDOR is the next
WebSocket-class blind spot — SSE adoption for AI agent status feeds and live dashboards is
accelerating with zero per-message auth standards. Path normalization discrepancy between
API gateways and backends (encoded slash traversal, dot-segment injection) is exploitable
whenever the gateway is the sole auth boundary. Bulk/batch endpoint per-object auth gaps
remain the single largest category of unpatched production IDOR. Import/export file IDOR
is the most underreported class — a malicious upload references thousands of victim objects
in a single request that security scanners never generate.

**Auth Bypass (new):** Next.js middleware-based authentication is trivially bypassed via
the x-middleware-subrequest internal header (CVE-2025-29927, CVSS 9.1, EPSS 92%). Any
self-hosted Next.js app using middleware as the sole auth gate is vulnerable on versions
< 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3. Framework-level auth flaws continue to be
high-payout bug bounty findings since they affect every route uniformly.

---

## Next priorities

1. **SKILL_SSRF.md** — ✓ Updated 2026-05-26: +6 techniques (routing-based, HTTP/2 pseudo-header, Oracle EBS CVE-2025-61882, AI agent, HasPrefix bypass, SNI proxy), +6 bypass matrix rows, +6 HVT rows, +20 threat model patterns. Remaining: SSRF via XSLT/XML parsers (XXE → SSRF), Memcached gopher payloads, SSRF in OAuth redirect_uri validation, container runtime metadata endpoints (ECS, EKS node metadata)
2. **SKILL_XSS.md** — ✓ Updated 2026-05-27: +11 techniques, +13 bypass matrix rows, +4 new CSP config rows, +4 new sinks. Remaining: Trusted Types bypass (policy injection), Shadow DOM XSS (open shadow root injection), XSS via CSS expression()/-moz-binding (legacy IE/Firefox), service worker injection for persistent XSS
3. **SKILL_IDOR.md** — ✓ Updated 2026-05-30: +7 techniques (HTTP verb tunneling, SSE IDOR, path normalization IDOR, referrer bypass, bulk/batch IDOR, X-Original-URL IDOR, CSV import IDOR), +8 bypass matrix rows, +8 HVT rows, +7 threat model items, +1 chain. Total: 24 techniques, 25 bypass rows, 23 HVT rows, 10 chains
4. **NEW: SKILL_AUTH.md** — OAuth 2.0 attack surface (state param, redirect_uri,
   implicit flow token leak), JWT attacks, SAML attacks, password reset flaws
5. **NEW: SKILL_SQLI.md** — Modern SQLi (JSON operators, out-of-band exfil, WAF bypass
   via chunked encoding, second-order injection)
6. **nuclei-templates/** — ✓ CVE-2025-29927 (Next.js auth bypass) added 2026-05-26.
   Remaining: Spring4Shell (CVE-2022-22965), ProxyLogon (CVE-2021-26855),
   Confluence RCE (CVE-2022-26134), Text4Shell (CVE-2022-42889),
   Apache Struts RCE (CVE-2017-5638), GitLab SSRF/RCE, Confluence OGNL injection
