---
title: "Home"
nav_order: 1
layout: default
---

# THE FIELD MANUAL
### A Bug Bounty Hunter's Operational Reference
*Version 0.1 — Skeleton / Architecture Pass*
*Status: IN PROGRESS — Content iterations pending*

---

> **What this is:** A field-ready reference for hunters who already know the theory.
> Not a tutorial. Not a course. A scrub-in checklist for someone standing in front of a live target.
>
> **What this is not:** A replacement for PortSwigger, OWASP, or tool documentation.
> Where deep theory exists elsewhere, this document points you there and tells you
> exactly what to do with it.

---

## HOW TO USE THIS MANUAL

**Scenario A — You just joined a new program:**
→ Start at [Part 1: Recon & Asset Discovery](part-1)
→ Then [Part 12: Platform Strategy & Meta-game](part-12)

**Scenario B — You found something interesting, need to know how to exploit it:**
→ Go to the [Master Hunt Index](#master-hunt-index) → find your surface type → find your class

**Scenario C — You have a confirmed bug, writing the report:**
→ Go to [Part 11: Reporting Mastery](part-11)

**Scenario D — Setting up your hunting infrastructure:**
→ [Part 13: Tooling Reference](part-13) and [Part 14: Continuous Recon Infrastructure](part-14)

**Entry format legend:**
```
🔍 = Where/how to find it
🛠️ = Tools + commands
✅ = How to confirm / PoC structure
📝 = Report notes
📚 = External reference
🔗 = Related entries in this manual
⚠️  = Common mistakes / gotchas
```

---

## MASTER HUNT INDEX

Navigation by attack surface. Find what you're looking at, go to the right entry.

### By Surface Type

| Surface | Primary Classes to Test | Go To |
|--------|------------------------|-------|
| Web application (authenticated) | IDOR, auth flaws, business logic, XSS | Parts 2, 3, 6 |
| Web application (unauthenticated) | SQLi, XSS, SSRF, open redirect, XXE | Parts 4, 5 |
| API (REST) | BOLA, mass assignment, broken function auth, rate limits | Part 7 |
| API (GraphQL) | Introspection, DoS via nesting, IDOR, batching abuse | Part 7 |
| File upload endpoints | RCE via extension bypass, stored XSS, path traversal | Parts 4, 5 |
| Authentication flows | Auth bypass, JWT attacks, OAuth flaws, MFA bypass | Part 2 |
| Password reset flows | Token predictability, host header injection, race conditions | Part 2 |
| Subdomains / asset discovery | Subdomain takeover, exposed staging, leaked keys | Part 1 |
| JavaScript files | Hardcoded secrets, hidden endpoints, DOM XSS | Parts 1, 4 |
| Cloud storage (S3, GCS, Azure Blob) | Public buckets, misconfigured ACLs | Part 9 |
| Cloud metadata endpoints | SSRF → metadata → credential theft | Parts 5, 9 |
| Mobile apps (Android) | Insecure storage, exported components, SSL bypass | Part 10 |
| Mobile apps (iOS) | IPA analysis, insecure storage, deep link abuse | Part 10 |
| AI / LLM features | Prompt injection, data leakage, agent chaining | Part 8 |
| Email/notification features | Account takeover via IDOR, host header injection | Parts 2, 3 |
| Admin panels | Broken access control, exposed via recon | Parts 1, 3 |
| WebSockets | Auth bypass, injection, privilege escalation | Part 7 |
| OAuth integrations | Token leakage, open redirects, state bypass | Part 2 |

### By Vulnerability Class (Alphabetical)

| Class | Part | Notes |
|-------|------|-------|
| Auth bypass | 2 | See also: JWT, OAuth, MFA |
| Business logic flaws | 6 | Price manipulation, workflow bypass |
| CORS misconfiguration | 5 | Often chains with XSS or IDOR |
| CRLF injection | 4 | Often leads to header injection or XSS |
| CSRF | 4 | Check SameSite, tokens |
| DOM XSS | 4 | JS source/sink analysis |
| GraphQL abuse | 7 | Introspection, batching, DoS |
| Host header injection | 2, 5 | Password reset poisoning, SSRF |
| HTTP Request Smuggling | 5 | Advanced; see PortSwigger |
| IDOR / BOLA | 3 | Highest frequency high-severity class |
| Insecure deserialization | 4 | Java, PHP, Python targets |
| JWT attacks | 2 | alg:none, weak secrets, kid injection |
| LFI / Path traversal | 5 | File read → RCE chain |
| Mass assignment | 7 | API-specific |
| OAuth flaws | 2 | Redirect URI bypass, token leakage |
| Open redirect | 5 | Often chains; report impact carefully |
| Privilege escalation | 3 | Horizontal and vertical |
| Prompt injection | 8 | AI/LLM-specific |
| Race conditions | 6 | Payments, limits, coupons |
| Reflected XSS | 4 | Classic; check all inputs |
| SQLi | 4 | Error, blind, time-based |
| SSRF | 5 | Cloud metadata, internal port scan |
| SSTI | 4 | Jinja2, Twig, FreeMarker, etc. |
| Stored XSS | 4 | Profile fields, file names, comments |
| Subdomain takeover | 1 | Dangling DNS, unclaimed services |
| XXE | 5 | File upload, SOAP, XML parsers |
| XSS (DOM) | 4 | Source/sink pairs in JS |

---

