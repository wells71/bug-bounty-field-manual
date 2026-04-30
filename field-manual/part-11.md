---
title: "Part 11: Reporting Mastery"
nav_order: 12
layout: default
---

## PART 11: REPORTING MASTERY
*Status: COMPLETE — Iteration 11*

> **The mindset:** A valid bug with a bad report pays less or gets rejected entirely.
> A mediocre bug with an exceptional report gets triaged faster, escalated higher,
> and remembered when private invites go out. Reporting is not paperwork —
> it is the product you are selling. The triager is the customer.
> Write for them, not for yourself.

---

### 11.1 The Report Template

**The non-negotiable structure. Every report, every time:**
```
1. Title
2. Severity (your assessment)
3. Summary (3 sentences)
4. Steps to Reproduce
5. Evidence (request/response, screenshot, video)
6. Impact Statement
7. Suggested Remediation
```

---

#### 11.1.1 Title Formula

🔍 **The title is the first thing a triager reads. It must answer three questions
in one sentence: What is the vulnerability? Where is it? What can an attacker do?**

```
Formula:
[Vulnerability Class] in [Affected Component/Endpoint] allows [Actor] to [Impact]

Examples:

Good:
"IDOR in /api/invoices/{id} allows authenticated users to read any user's invoices"
"Stored XSS in profile display name leads to admin account takeover"
"SSRF in webhook URL parameter allows access to AWS EC2 metadata credentials"
"JWT algorithm confusion enables privilege escalation to admin role"
"Race condition in coupon redemption allows unlimited discount stacking"

Bad:
"XSS vulnerability found"           → where? what impact?
"Security issue in API"             → which class? which endpoint?
"Broken access control"             → too vague for triage queue
"Critical vulnerability"            → self-assigned severity in title
"I found a bug"                     → rejected on sight
```

**Title calibration checklist:**
```
□ Does the title name the vulnerability class specifically?
□ Does it identify the exact endpoint or component?
□ Does it state the impact in concrete terms?
□ Is it under 120 characters?
□ Does it avoid vague words: "issue", "problem", "bug", "vulnerability" alone?
```

---

#### 11.1.2 Severity Rating

→ Full coverage in [11.2 Severity Calibration](#112-severity-calibration).

**Quick reference:**
```
Critical: Direct account takeover, RCE, SQLi with data dump, mass PII exposure,
          cloud credential theft, admin access without authentication

High:     Single account takeover chain, significant PII of one user,
          authentication bypass, stored XSS → admin, SSRF to metadata

Medium:   IDOR (read-only, non-sensitive data), reflected XSS (no sensitive context),
          CSRF on sensitive action, missing rate limit on auth endpoint

Low:      Self-XSS, open redirect (standalone), missing security headers,
          username enumeration, verbose error messages

Informational: Missing HttpOnly flag alone, SPF record missing,
               theoretical attack with no realistic path
```

---

#### 11.1.3 Summary — Three Sentences

🔍 **The summary tells a triager whether to keep reading.**
**Three sentences only:**
```
Sentence 1: What the vulnerability is and where it exists
Sentence 2: What an attacker can do with it
Sentence 3: What conditions are required (authenticated? specific role?)

Example (IDOR):
"The /api/invoices/{id} endpoint does not verify that the requesting user
owns the invoice being requested. An authenticated attacker can enumerate
invoice IDs to read billing details, payment amounts, and personal information
belonging to any other user. This is exploitable by any registered user
with a standard free account."

Example (SSRF):
"The webhook delivery URL parameter is fetched server-side without
validating that the destination is external. An attacker can use this
to reach the AWS EC2 metadata endpoint at 169.254.169.254 and steal
the instance's IAM role credentials. Exploitation requires an authenticated
account with webhook creation access."
```

**What not to write in the summary:**
```
✗ "I was testing the application and noticed that..."  → triager doesn't care
✗ "This is a critical vulnerability that..."           → let the severity field handle this
✗ Reproduction steps                                   → that's the next section
✗ Remediation suggestions                              → that's the last section
```

---

#### 11.1.4 Steps to Reproduce

🔍 **Written for a developer with no security knowledge.**
**The standard: if a developer follows these steps exactly, they reproduce the bug.**

```
Format:
1. [Action] — [exact input/request/value used]
2. [Action] — [what to observe]
3. [Action] — [the confirmation]

Example (IDOR):
1. Register two accounts: Account A (attacker) and Account B (victim).
2. Log in as Account B. Create an invoice. Note the invoice ID in the URL:
   /dashboard/invoices/5523
3. Log in as Account A.
4. Send the following HTTP request using Burp Suite or curl:

   GET /api/invoices/5523 HTTP/1.1
   Host: target.com
   Authorization: Bearer <Account_A_token>
   Cookie: session=<Account_A_session>

5. Observe: the response returns Account B's full invoice including
   billing address, amount, and payment method details.

Example (SQLi):
1. Navigate to: https://target.com/search
2. In the search field, enter: test' AND SLEEP(5)-- -
3. Click Search.
4. Observe: the response is delayed by approximately 5 seconds,
   confirming time-based blind SQL injection.
5. Verify database version extraction:
   GET /search?q=test' AND IF(SUBSTRING(version(),1,1)='8',SLEEP(3),0)-- -
   [3-second delay confirms MySQL version 8.x]
```

**Quality checklist:**
```
□ Are the steps numbered and sequential?
□ Are all inputs shown exactly (no paraphrasing)?
□ Is the HTTP request included where relevant?
□ Is the expected observation stated at each critical step?
□ Could a developer follow this without asking you any questions?
□ Does the last step confirm the vulnerability, not just approach it?
```

---

#### 11.1.5 Evidence

🔍 **Evidence requirements by vulnerability type:**

| Type | Minimum Evidence | Ideal Evidence |
|------|-----------------|----------------|
| IDOR | Request + response showing another user's data | Video showing full exploit from two accounts |
| XSS | Screenshot of alert(document.domain) firing | Video showing cookie exfiltration |
| SQLi | curl command + time delay measurement | sqlmap output showing DB version + one row |
| SSRF | interactsh callback screenshot | Response showing metadata content |
| Auth bypass | Request + response showing unauthorized access | Video walkthrough |
| RCE | DNS/HTTP OOB callback screenshot | Video showing command output |
| Race condition | Turbo Intruder screenshot showing multiple successes | Video showing financial impact |

**HTTP request/response format:**
```
Always include the raw HTTP — not just a screenshot. Copy from Burp:
Right-click request → Copy as → Copy request (or use "Request" tab raw view)

Request:
POST /api/invoices/5523/delete HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGci...
Content-Type: application/json

{}

Response:
HTTP/1.1 200 OK
Content-Type: application/json

{"status": "deleted", "invoice_id": 5523}
```

**Video PoC — when to use and how:**
```
Use video when:
- Multiple steps are hard to follow in screenshots
- Race condition (timing is the evidence)
- DOM XSS (execution context matters)
- Complex chain (IDOR → password reset → ATO)

Video guidelines:
- Screen record at 1080p minimum
- Show the full flow from start to finish
- Highlight the key moment (browser console, network tab, final outcome)
- Keep under 3 minutes — edit out the boring parts
- Host on: Loom (free), YouTube unlisted, or attach as file
- Always include the timestamp of recording in the description
```

---

#### 11.1.6 Impact Statement

🔍 **The impact statement is the most underwritten section in most reports.
This is what determines severity and bounty amount. Write it as if you are
explaining to a CEO why this matters.**

**The impact formula:**
```
Impact = What the attacker gains + Who is affected + How many + Real-world consequence

Template:
"An attacker exploiting this vulnerability can [specific action] affecting
[scope of affected users — one user / all users / admin accounts].
In a realistic attack scenario, this would allow [worst case outcome].
[Optional: financial/reputational/regulatory consequence]."
```

**Examples from weak to strong:**

```
Weak (gets Low/Medium, low bounty):
"This vulnerability allows users to access other users' data."

Medium (gets expected severity):
"An authenticated attacker can read any other user's invoice data by
incrementing the invoice ID. This exposes billing details including
name, address, and payment amount."

Strong (gets elevated severity + higher bounty):
"An authenticated attacker with a free account can enumerate all user
invoices by incrementing the numeric invoice ID. Each response contains:
full name, email address, physical address, and billing amount. With
approximately 50,000 users and sequential IDs, a complete data dump of
all user billing records is achievable in under 10 minutes using a simple
script. This constitutes a mass PII breach potentially subject to GDPR
notification requirements, with direct financial and reputational risk
to the organization."
```

**Impact escalation questions to ask yourself:**
```
□ Is this exploitable by one attacker against one victim, or against all users?
□ Does this expose PII? (name, email, address, DOB, SSN, payment info)
□ Does this enable account takeover?
□ Does this allow financial manipulation?
□ Does this give access to admin functionality?
□ Is this a regulatory concern? (GDPR, HIPAA, PCI-DSS)
□ What is the worst thing an attacker can realistically do?
□ How hard is it to exploit at scale? (automated vs. manual)
```

---

#### 11.1.7 Suggested Remediation

🔍 **Always include remediation. It signals professionalism and often
increases the bounty amount. Keep it concise and technical.**

```
Format:
"To remediate this vulnerability, [specific action].
Additionally, [secondary control if applicable]."

Examples:

IDOR:
"Implement server-side ownership verification before returning any resource.
Verify that the authenticated user's ID matches the owner_id field of the
requested resource before processing the request. Do not rely on client-supplied
IDs as authorization controls."

SQLi:
"Use parameterized queries or prepared statements for all database interactions.
Avoid constructing SQL queries via string concatenation with user input.
Consider implementing a Web Application Firewall as a secondary defense-in-depth
measure, though this should not replace parameterized queries."

JWT:
"Explicitly specify the expected algorithm when verifying JWT signatures.
Never accept the algorithm from the token header — hardcode the expected
algorithm server-side. Consider using a well-tested JWT library rather than
a custom implementation."

SSRF:
"Implement a server-side allowlist of permitted webhook/URL destinations.
Resolve the destination hostname server-side and verify it does not resolve
to RFC 1918 private address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
the loopback address (127.0.0.1), or the link-local address (169.254.0.0/16)."
```

---

### 11.2 Severity Calibration

---

#### 11.2.1 CVSS vs. Real-World Impact

🔍 **CVSS (Common Vulnerability Scoring System) gives base scores but
misses business context. Most programs use CVSS as a starting point,
then adjust for actual impact.**

```
CVSS says: Reflected XSS = 6.1 (Medium)
Reality: Reflected XSS stealing admin OAuth token on internal tool = High

CVSS says: IDOR (read-only) = 5.3 (Medium)
Reality: IDOR exposing SSNs of 100,000 users = Critical

CVSS says: Missing security header = 5.0 (Medium)
Reality: Missing security header = Informational in most programs

Rule: Always argue severity from REAL ATTACKER CAPABILITY,
not from CVSS base score alone.
```

---

#### 11.2.2 Severity Framework — Bug Bounty Reality

🔍 **What actually gets each severity on most programs:**

**Critical (P1):**
```
- Remote code execution (RCE) without authentication
- SQL injection with demonstrable data extraction
- Authentication bypass — admin access without credentials
- Account takeover without user interaction
- Mass PII/credential data dump (all users)
- AWS/GCP/Azure credential theft via SSRF
- Payment system manipulation (arbitrary charges/credits)
- Subdomain takeover with ATO potential via cookies
```

**High (P2):**
```
- Account takeover requiring minimal user interaction (click a link)
- Significant PII exposure (one user's full profile with sensitive data)
- Stored XSS in admin panel or high-privilege context
- Authentication bypass for regular user access
- SSRF with internal network access (not metadata)
- SQLi (blind, limited data retrieval)
- JWT forgery enabling admin access
- Broken OAuth leading to ATO
- Race condition with financial impact
```

**Medium (P3):**
```
- IDOR reading non-sensitive data of other users
- Reflected XSS (non-admin context)
- CSRF on sensitive action (password change, email change)
- Missing rate limit on authentication endpoint
- Path traversal reading non-sensitive files
- Subdomain takeover (no cookie scope)
- Open redirect chained with OAuth
- Information disclosure (stack traces, internal IPs)
```

**Low (P4):**
```
- Self-XSS (only affects attacker's own session)
- Open redirect (standalone, no chain)
- Missing security headers (CSP, HSTS, X-Frame-Options)
- Username/email enumeration without exploitation path
- Cookie without HttpOnly/Secure flags (standalone)
- Verbose error messages revealing framework/version
- SPF/DMARC misconfiguration (if email is in scope)
```

**Informational / Out of Scope for most programs:**
```
- Clickjacking on non-sensitive pages
- Missing rate limiting on non-auth endpoints
- SSL/TLS configuration issues (weak cipher suites)
- HTTP used instead of HTTPS for non-sensitive content
- Tab nabbing via target="_blank"
- Software version disclosure (without known CVEs)
- Theoretical vulnerabilities without PoC
```

---

#### 11.2.3 Arguing Up — When to Contest Severity

🔍 **When the triager downgrades your report — how to respond:**

```
Triager: "Downgrading to P3 — IDOR reads non-sensitive data"
Your response: "Thank you for the review. I'd like to note that this IDOR
exposes the user's registered email address. Combined with the password reset
functionality at /api/reset-password, which accepts an email parameter, this
creates a viable account takeover chain: IDOR reveals email → attacker triggers
password reset to that email. I've attached steps demonstrating the full chain.
Would you consider re-evaluating as P2 given this escalation path?"

Structure: acknowledge → add context → show the chain → propose specific severity
```

**Evidence that supports severity escalation:**
```
- Chain to ATO (read IDOR + password reset = full ATO)
- Mass exploitability (affects all users, not just one)
- Regulatory impact (GDPR, HIPAA data class)
- Sensitive data class (PII, payment, medical vs. generic data)
- Ease of exploitation (no special conditions, automated scale)
- Prior art (link to similar bugs paid at higher severity on same platform)
```

---

#### 11.2.4 The MetaMask Precedent

🔍 **Context:** A clickjacking vulnerability on MetaMask's transaction
confirmation UI was awarded $120,000. Standard CVSS would have rated this
as Medium/Low. The severity was driven by:
- Target application (cryptocurrency wallet — transaction finality)
- Specific user action (one click = irreversible fund transfer)
- Financial impact (up to the user's full wallet balance)

**The lesson:** Severity is always context-dependent.
A "Low" vulnerability on a banking app moving real money is not the same
as the same vulnerability on a blog. Always write your impact statement
in the context of what the target company actually does and what
real damage your bug enables in that specific context.

---

### 11.3 Getting Paid Faster

---

#### 11.3.1 What Triagers Look for in the First 30 Seconds

🔍 **Triagers process dozens of reports per day. Your report competes for attention.**

```
The 30-second scan:
1. Title — is this real and specific?
2. Severity — does the claimed severity match the title?
3. Summary — is this clearly explained in 3 sentences?
4. Steps — are they numbered and unambiguous?
5. Evidence — is there a screenshot or request/response?

Reports that pass the 30-second scan get read fully.
Reports that fail it get queued, deprioritized, or closed as N/A.

What kills reports immediately:
✗ Vague title ("Security vulnerability found")
✗ No severity justification
✗ Wall of text with no structure
✗ Steps that reference unexplained prerequisites
✗ No evidence — "trust me, it worked"
✗ CVSS score without context
✗ Remediation before reproduction steps
✗ AI-generated text (triagers recognize it instantly in 2026 — see Part 5, AI risks)
```

---

#### 11.3.2 Responding to Triage Questions

🔍 **How to handle triage responses:**

```
"We cannot reproduce this":
- Re-read your steps as if you've never seen the app before
- Add: exact HTTP request (copy from Burp), not a description of it
- Add: exact account type needed (free? verified? specific permissions?)
- Add: region or environment if relevant
- Offer: "Happy to provide a screen recording if that would help"

"This is a duplicate":
- Ask: "Could you share the duplicate report ID?"
- If they won't: "Understood. May I ask approximately when the original
  was reported so I can track future disclosures?"
- Do not argue unless you have clear evidence yours is different

"This is informational / not a vulnerability":
- Ask for the specific reason
- If you disagree: provide a concrete attack scenario
  "To illustrate the impact: an attacker who exploits this can [specific action].
  Is there additional context that would help re-evaluate?"
- Keep it professional — one escalation attempt, then accept gracefully

"Out of scope":
- Re-read the scope rules carefully before responding
- If genuinely out of scope: accept it. Learn for next time.
- If you believe it's in scope: quote the specific scope language and explain
  why the vulnerability falls within it
```

---

#### 11.3.3 Disputing Severity Professionally

```
The professional dispute format:
1. Acknowledge their assessment without being defensive
2. Provide new information they may not have considered
3. Show the full attack chain, not just the isolated bug
4. Reference the impact on actual users of this specific application
5. Propose a specific alternative severity (don't just say "should be higher")
6. Accept the final decision gracefully — relationships matter long-term

What not to do:
✗ "This is clearly Critical and you're wrong"
✗ Multiple back-and-forth messages saying the same thing
✗ Threatening to disclose publicly during the dispute window
✗ Tagging the company on social media while the dispute is open
✗ Submitting the same vulnerability multiple times with different framing
```

---

### 11.4 Disclosure Etiquette

---

#### 11.4.1 Timeline Expectations by Platform

| Platform | Typical Triage SLA | Typical Payment SLA | Escalation Path |
|----------|-------------------|--------------------|----|
| HackerOne | 1–7 days | 30–90 days after triage | @platform if >30 days no response |
| Bugcrowd | 1–7 days | 30–60 days | Bugcrowd support ticket |
| Intigriti | 3–10 days | 14–30 days | Intigriti support |
| YesWeHack | 3–10 days | 30–60 days | YesWeHack support |

```
What "awaiting triage" means: your report is in queue, not reviewed yet
What "triaged" means: reviewed and confirmed as valid — payment coming
What "resolved" means: fixed (but may not be paid yet)
What "closed/informational" means: not accepted — can ask for reason

If no response in 14+ days: nudge once, politely
If no response in 30+ days: escalate to platform support (not social media)
```

---

#### 11.4.2 How to Escalate a Stalled Report

```
Day 14 (no response): One polite nudge on the report
"Hi, just following up on this report submitted 14 days ago.
Happy to provide additional information or a screen recording if helpful."

Day 30 (still no response): Open platform support ticket
"Report #XXXX submitted on [date] has received no triage response in 30 days.
Could you help escalate this to the program team?"

Day 60 (no resolution): Platform support escalation (second time)
Most platforms take this seriously — they want to maintain program quality

Never:
✗ Tweet at the company with vulnerability details
✗ Open a GitHub issue in the target's repo
✗ Post on Reddit/HackerOne Disclosure while under coordinated disclosure
✗ Sell the vulnerability elsewhere while it's under active disclosure
```

---

#### 11.4.3 Public Disclosure — When and How

```
Standard coordinated disclosure timeline:
- Report submitted
- Vendor acknowledges + triages
- Vendor fixes
- Vendor approves public disclosure (or 90 days pass)
- Public disclosure

Writing a public write-up (see also Part 12.4.3):
1. Confirm with the program whether disclosure is permitted
2. Never include: full exploit code, CVSS score that differs from their published one,
   information that could re-enable the attack before full patching
3. Do include: vulnerability class, affected feature, impact, the thought process
   that led you to find it (this is the valuable part)
4. Anonymize any real user data seen during testing
5. Credit the program for fixing it promptly (builds relationship)

Platform: Medium / InfoSecWriteups for maximum visibility
Timing: after the CVE/fix is public or program explicitly approves
```

---

### Part 11 — Report Quality Checklist

```
BEFORE SUBMITTING
□ Title: class + component + impact in one sentence (<120 chars)
□ Severity: justified by real impact, not CVSS default
□ Summary: 3 sentences — what, what attacker can do, what conditions
□ Steps: numbered, exact inputs shown, reproducible by developer
□ Evidence: raw HTTP request + response included
□ Evidence: screenshot or video for visual confirmation
□ Impact: who is affected, what data, what actions, at what scale
□ Remediation: specific technical fix, not "fix the bug"
□ Proofread: no typos, clear English, no AI-generated filler phrases

SUBMISSION CHECKS
□ Is this in scope? (re-read scope rules)
□ Is it a duplicate? (search program's disclosed reports first)
□ Is the severity honest? (don't over-inflate — hurts credibility)
□ Have you tested the reproduction steps one more time?

AFTER SUBMISSION
□ Check for triage response within 7 days
□ Respond to triage questions within 48 hours
□ Dispute severity once with full chain evidence, then accept
□ Nudge if no response at day 14
□ Escalate to platform support at day 30
```

📚 **Part 11 References:**
- [HackerOne — Writing a good report](https://docs.hackerone.com/hackers/submitting-reports.html)
- [Bugcrowd — Vulnerability rating taxonomy](https://bugcrowd.com/vulnerability-rating-taxonomy)
- [HackerOne — Disclosed reports (real examples)](https://hackerone.com/hacktivity)
- [InfoSecWriteups](https://infosecwriteups.com) — community write-up examples
- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [NVD CVSS guide](https://nvd.nist.gov/vuln-metrics/cvss)

---

