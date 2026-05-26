# nuclei-templates

## Purpose

Daily CVE → Nuclei template pipeline for CTF and bug bounty hunting.

Each template is mapped to a real CVE, covers a specific attack category, and is tuned for OOB (out-of-band) or in-band detection. Templates are production-ready: copy, point at a target, fire.

---

## Folder Structure

```
nuclei-templates/
├── README.md          # This file — index + contribution guide
├── rce/               # Remote Code Execution
├── ssrf/              # Server-Side Request Forgery
├── sqli/              # SQL Injection
├── auth-bypass/       # Authentication & Authorization Bypass
├── lfi/               # Local File Inclusion / Path Traversal
├── xss/               # Cross-Site Scripting
└── other/             # Misc: XXE, SSTI, deserialization, open redirect, etc.
```

---

## Usage

Run a single template against a target:
```bash
nuclei -t nuclei-templates/rce/CVE-2021-44228-log4shell.yaml -u https://target.com
```

Run an entire category:
```bash
nuclei -t nuclei-templates/rce/ -u https://target.com
```

Run all templates with OOB detection (requires interactsh):
```bash
nuclei -t nuclei-templates/ -u https://target.com -interactsh-server oast.fun
```

Bulk scan from a list of targets:
```bash
nuclei -t nuclei-templates/ -l targets.txt -severity critical,high -o results.txt
```

> **Tip:** Always use `-rate-limit` and `-timeout` flags on real engagements to avoid triggering WAF bans.

---

## Template Index

| ID | CVE | Severity | Category | Technology | Date Added |
|----|-----|----------|----------|------------|------------|
| CVE-2021-44228-log4shell | CVE-2021-44228 | critical | rce | Apache Log4j 2.x | 2026-05-26 |
| CVE-2025-29927-nextjs-middleware-auth-bypass | CVE-2025-29927 | critical | auth-bypass | Next.js 12.x-15.x | 2026-05-26 |

---

## Contribution Format

### Naming Convention

```
CVE-YYYY-NNNNN-slug.yaml
```

Examples:
- `CVE-2021-44228-log4shell.yaml`
- `CVE-2022-22965-spring4shell.yaml`
- `CVE-2023-44487-rapid-reset.yaml`

For non-CVE templates use a descriptive slug prefixed with the category:
- `generic-ssrf-aws-metadata.yaml`
- `generic-lfi-dotdot-slash.yaml`

### Required YAML Fields

Every template must include:

```yaml
id: CVE-YYYY-NNNNN-slug

info:
  name: <Human-readable name>
  author: s2k7x
  severity: <info|low|medium|high|critical>
  description: <One-line description of the vulnerability>
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN
    - <primary disclosure URL>
  classification:
    cvss-score: <score>
    cve-id: CVE-YYYY-NNNNN
    cwe-id: CWE-<N>
  tags: cve,cveYYYY,<category>,<technology>
```

OOB templates must use `{{interactsh-url}}` — never hardcode a BURP collaborator domain.

### Severity Guidelines

| CVSS | severity field |
|------|---------------|
| 9.0–10.0 | critical |
| 7.0–8.9 | high |
| 4.0–6.9 | medium |
| 0.1–3.9 | low |
| N/A | info |
