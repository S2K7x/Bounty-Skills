# Bounty-Skills

> Autonomous security knowledge base maintained by Claude.
> Updated with techniques sourced from real disclosed reports, OWASP, and PortSwigger research.

---

## Skill files

| File | Coverage | Last updated |
|------|----------|--------------|
| [SKILL_SSRF.md](./SKILL_SSRF.md) | Basic SSRF · Cloud metadata (AWS/GCP/Azure/OCI/DO) · Blind detection · 8+ filter bypass categories · CIDR/Unicode/JAR/NETDOC vectors · RCE escalation (Redis, ES, Jenkins, Spring) · K8s pivot · Threat model · Bypass matrix | 2026-05-21 |
| [SKILL_XSS.md](./SKILL_XSS.md) | Reflected/Stored/DOM-based · CSP bypass (5 techniques) · Prototype pollution chains · WAF bypass (7 categories) · Mutation XSS · mXSS · postMessage XSS · XSS→ATO chains · Threat model · Bypass matrix | 2026-05-21 |
| [SKILL_IDOR.md](./SKILL_IDOR.md) | 5 ID pattern types · Horizontal/vertical escalation · Mass assignment (Rails/Django/Express) · REST + GraphQL IDOR · 5 chain scenarios · API versioning bypass · State machine IDOR · Threat model · Bypass matrix | 2026-05-21 |

---

## How this works

A Claude Code routine reads this repo at session start, checks `git log` for changes,
fetches new disclosed reports from HackerOne Hacktivity, PortSwigger research, and
PayloadsAllTheThings, deduplicates against existing content, and commits only net-new
techniques — one file per commit.

**CLAUDE.md** is the persistent memory: it tracks every technique already documented
and what to prioritize next session.

---

## Sources

- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [PortSwigger Research](https://portswigger.net/research)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [InfoSec Writeups](https://infosecwriteups.com)
- [Assetnote Blog](https://blog.assetnote.io)

---

## Scope

Currently covering: **SSRF · XSS · IDOR**

Planned: Auth (OAuth/JWT/SAML) · SQLi · Business Logic · Race Conditions · SSTI
