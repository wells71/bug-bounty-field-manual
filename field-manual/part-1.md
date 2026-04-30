---
title: "Part 1: Recon & Asset Discovery"
nav_order: 2
layout: default
---

## PART 1: RECON & ASSET DISCOVERY
*Status: COMPLETE — Iteration 1 (Parts A, B, C)*
*Last updated: 2026*

> **The mindset:** Recon is not a phase you complete and move past. It is a continuous process
> that runs in parallel with exploitation. The hunter who finds the most bugs is rarely the best
> at exploitation — they are the best at finding surface that others missed.
>
> **The goal of recon:** Build a complete map of everything the target owns, runs, and exposes.
> Every subdomain. Every endpoint. Every JS file. Every parameter. Then hunt that map.

---

### 1.1 Subdomain Enumeration

**The principle:** No single tool finds everything. Every tool queries different data sources.
Run them all, merge the output, deduplicate. The subdomains that only appear in one source
are often the most interesting ones.

---

#### 1.1.1 Passive Enumeration (Certificate Logs, APIs, Archives)

🔍 **What to do:**
Passive enumeration queries public data sources without sending a single packet to the target.
It's safe, fast, and often finds things active brute-force misses — especially legacy subdomains
that stopped resolving but still exist in certificate history.

Primary passive sources to hit:
- **Certificate Transparency logs** — every SSL cert ever issued for a domain is logged publicly.
  `crt.sh` is the most accessible interface. Search: `%.target.com`
  Also try: `%.%.target.com` to catch wildcard cert nested subdomains.
- **Shodan** — indexes Internet-facing hosts. Search: `ssl.cert.subject.cn:"target.com"`
- **SecurityTrails** — historical DNS data, subdomain history. Free tier is usable.
- **VirusTotal** — `https://www.virustotal.com/gui/domain/target.com/relations`
- **AlienVault OTX** — `https://otx.alienvault.com/api/v1/indicators/domain/target.com/passive_dns`
- **Wayback Machine CDX API** — surfaces subdomains from archived URLs:
  `http://web.archive.org/cdx/search/cdx?url=*.target.com&output=text&fl=original&collapse=urlkey`

🛠️ **Tools + Commands:**
```bash
# Subfinder — fastest passive enum, multiple API sources
subfinder -d target.com -all -o subfinder_out.txt

# With API keys configured (significantly increases results):
# Configure at ~/.config/subfinder/provider-config.yaml
# Sources: shodan, securitytrails, censys, virustotal, etc.

# Assetfinder — quick, good for pipeline inclusion
assetfinder --subs-only target.com >> passive_out.txt

# crt.sh via curl (no signup needed)
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | sort -u >> passive_out.txt

# Amass in passive mode only (slower but thorough)
amass enum -passive -d target.com -o amass_passive.txt
```

✅ **Merge and deduplicate all sources:**
```bash
cat subfinder_out.txt passive_out.txt amass_passive.txt | \
  sort -u | anew master_subdomains.txt
```
`anew` adds only new lines — critical for delta tracking in continuous recon.

⚠️ **Gotchas:**
- `crt.sh` often returns `*.target.com` entries — strip the wildcard prefix before resolving.
- Subfinder without API keys returns ~30% of what it returns with them. Set up free API keys
  for SecurityTrails, Shodan, VirusTotal, and Censys as a minimum.
- Certificate logs show historical subdomains. A subdomain appearing in crt.sh that doesn't
  resolve is still worth noting — it may be a takeover candidate. See [1.6](#16-subdomain-takeover).

📚 **References:**
- [Subfinder docs + API config](https://github.com/projectdiscovery/subfinder)
- [crt.sh](https://crt.sh)
- [SecurityTrails free tier](https://securitytrails.com)

---

#### 1.1.2 Active Brute-Force Enumeration

🔍 **What to do:**
Active brute-force sends DNS queries for every word in a wordlist: `api.target.com`,
`dev.target.com`, `staging.target.com` etc. It finds subdomains that have never been
linked anywhere publicly and won't appear in cert logs if they use wildcard certs.

The quality of your wordlist matters more than the tool.

🛠️ **Tools + Commands:**
```bash
# Amass — active mode, uses DNS brute + scraping
amass enum -active -d target.com \
  -brute -w /path/to/wordlist.txt \
  -o amass_active.txt

# Shuffledns — faster active brute with massdns backend
shuffledns -d target.com \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  -r /opt/resolvers/resolvers.txt \
  -o shuffledns_out.txt

# puredns — most reliable resolver, handles wildcard filtering
puredns bruteforce \
  /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  target.com \
  -r /opt/resolvers/resolvers.txt \
  -o puredns_out.txt
```

**Wordlist priority (use in order):**
1. `jhaddix/all.txt` — ~2M entries, best coverage for bug bounty
   `https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056`
2. `SecLists/Discovery/DNS/subdomains-top1million-110000.txt` — faster, good hit rate
3. Target-specific wordlist — generate from known subdomain naming patterns (see 1.1.3)

**Public resolver lists:**
- Use `https://github.com/trickest/resolvers` — updated regularly, removes dead resolvers.
- Never use your ISP's resolver for brute-force — it will rate-limit and return false results.

⚠️ **Gotchas:**
- Wildcard DNS (`*.target.com → 1.2.3.4`) will make every query appear to resolve.
  puredns handles this automatically. Shuffledns also detects wildcards.
  If unsure: resolve `randomstring123456789.target.com` — if it resolves, wildcard is set.
- Rate limiting from the target's DNS server is rare but happens on very aggressive scans.
  Add `-rate-limit 1000` to puredns if you see inconsistent results.

📚 **References:**
- [puredns](https://github.com/d3mondev/puredns)
- [shuffledns](https://github.com/projectdiscovery/shuffledns)
- [jhaddix all.txt](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)

---

#### 1.1.3 Permutation Scanning

🔍 **What to do:**
If you know `api.target.com` exists, there's a good chance `api2.target.com`,
`api-staging.target.com`, `api-dev.target.com` also exist.
Permutation scanning generates these variants algorithmically and resolves them.
This finds subdomains that wordlists miss and that passive sources never indexed.

🛠️ **Tools + Commands:**
```bash
# AlterX — generate permutations from known subdomains
cat master_subdomains.txt | alterx | \
  dnsx -silent -o alterx_resolved.txt

# With custom patterns:
cat master_subdomains.txt | alterx -enrich \
  -p '{{word}}-{{suffix}}' \
  -p '{{prefix}}-{{word}}' | \
  dnsx -silent >> alterx_resolved.txt

# gotator — alternative permutation generator
gotator -sub master_subdomains.txt \
  -perm /opt/gotator/permutations.txt \
  -depth 1 -numbers 3 | \
  dnsx -silent >> permutation_resolved.txt
```

**What AlterX does:** Takes `api.target.com` and generates:
`api-dev`, `api-staging`, `api-v2`, `api-internal`, `api-admin`, `api2`, `api-prod`, etc.
The `-enrich` flag adds context from the existing subdomain list to improve pattern quality.

⚠️ **Gotchas:**
- Permutation scanning generates a lot of candidates. Pipe directly into `dnsx` and only
  keep what resolves — don't store the full permutation list.
- AlterX output quality improves significantly the more subdomains you feed into it.
  Run passive + active first, then permutate on the merged list.

📚 **References:**
- [AlterX](https://github.com/projectdiscovery/alterx)
- [gotator](https://github.com/Josue87/gotator)

---

#### 1.1.4 Cross-Source Merging and Deduplication

🔍 **What to do:**
You will have output from 4–6 tools. Before doing anything else, merge and deduplicate.
This is the canonical master list every subsequent step runs against.

🛠️ **Commands:**
```bash
# Merge all outputs, deduplicate, sort
cat subfinder_out.txt \
    assetfinder_out.txt \
    amass_passive.txt \
    amass_active.txt \
    shuffledns_out.txt \
    alterx_resolved.txt \
    permutation_resolved.txt | \
  sort -u > master_subdomains_raw.txt

# anew — only add lines not already in the master file
# (use this in continuous recon to track new discoveries)
cat new_scan_output.txt | anew master_subdomains.txt
# anew prints only the NEW lines — pipe to notification or further processing
```

📚 **References:**
- [anew](https://github.com/tomnomnom/anew)

---

#### 1.1.5 Resolving Live Hosts (DNS Validation)

🔍 **What to do:**
Your master list contains subdomains that may or may not resolve. Before probing HTTP,
validate DNS resolution. This filters dead entries and confirms what's alive at the DNS layer.
Note: DNS resolution ≠ HTTP response. A subdomain resolving to an IP doesn't mean
something is listening on port 80/443. That's what 1.2 handles.

🛠️ **Tools + Commands:**
```bash
# dnsx — fast DNS resolver with A, CNAME, MX, NS record support
dnsx -l master_subdomains_raw.txt \
  -silent \
  -a -resp \
  -o dns_resolved.txt

# To also extract CNAME chains (important for takeover detection):
dnsx -l master_subdomains_raw.txt \
  -silent \
  -cname \
  -o dns_cnames.txt
# Review dns_cnames.txt for dangling CNAMEs → see 1.6 Subdomain Takeover

# massdns — bulk resolver, faster for very large lists (100k+)
massdns -r /opt/resolvers/resolvers.txt \
  -t A \
  master_subdomains_raw.txt \
  -o S \
  -w massdns_out.txt
```

**What to look for in DNS output:**
- Subdomains resolving to **private IP ranges** (10.x, 192.168.x, 172.16-31.x) —
  may indicate internal infrastructure exposed via split-horizon DNS
- **CNAME pointing to third-party services** — takeover candidates (see [1.6](#16-subdomain-takeover))
- **Wildcard resolution** — all queries resolve → strip via puredns before continuing

📚 **References:**
- [dnsx](https://github.com/projectdiscovery/dnsx)
- [massdns](https://github.com/blechschmidt/massdns)

---

### 1.2 HTTP Surface Mapping

**The principle:** DNS resolution tells you what exists. HTTP probing tells you what's
running and what it looks like. This step transforms a list of subdomains into a
prioritized attack surface with technology context, status codes, and visual thumbnails.

---

#### 1.2.1 Live Host Probing with httpx

🔍 **What to do:**
`httpx` sends HTTP/HTTPS requests to every resolved subdomain and returns rich metadata:
status code, page title, web server, tech stack, content length, favicon hash, redirect chain.
This single output is what you use to manually triage what to hunt first.

🛠️ **Tools + Commands:**
```bash
# Standard httpx run — everything useful in one pass
httpx -l dns_resolved.txt \
  -silent \
  -status-code \
  -title \
  -tech-detect \
  -content-length \
  -web-server \
  -favicon \
  -follow-redirects \
  -o httpx_out.txt

# JSON output for programmatic processing:
httpx -l dns_resolved.txt \
  -silent \
  -json \
  -o httpx_out.json

# Quick filter — only show 200s and 403s (the interesting ones):
httpx -l dns_resolved.txt -silent -mc 200,403 -o interesting_hosts.txt
```

**Reading httpx output — what to prioritize:**

| Signal | Why It's Interesting |
|--------|----------------------|
| Status 200 with title "Admin" / "Dashboard" | Exposed admin panel |
| Status 200, small content length, generic title | Possible default page, under-configured |
| Status 403 | Something is behind auth — worth probing |
| Status 401 | Auth challenge — check for bypass |
| Tech: "Jenkins", "Grafana", "Kibana" | Exposed internal tooling |
| Tech: "Laravel", "Django", "Rails" | Framework-specific attacks applicable |
| Favicon hash match | httpx can fingerprint services by favicon hash |
| Redirect to login on main domain | App is behind auth — register an account |

**Favicon hash lookup:** httpx outputs a favicon murmur hash. Cross-reference at
`https://shodan.io/search?query=http.favicon.hash:<hash>` to find other hosts running
the same service — sometimes reveals other targets or public PoCs.

⚠️ **Gotchas:**
- Default timeout is often too short for slow targets. Add `-timeout 10`.
- `httpx` follows redirects by default up to 10 hops. Watch for redirect chains that
  land on a CDN or third-party — the origin may still be directly accessible.
- Status 403 does not mean inaccessible. Test: different HTTP method, path traversal,
  add `X-Forwarded-For: 127.0.0.1` header, try `/admin./` with trailing dot.

📚 **References:**
- [httpx](https://github.com/projectdiscovery/httpx)
- [Favicon hash database](https://github.com/Lissy93/web-check)

---

#### 1.2.2 Port Scanning

🔍 **What to do:**
HTTP/HTTPS on 80/443 is not the whole picture. Internal services, dev interfaces,
and admin panels often run on non-standard ports. Port scanning finds them.

**Two-phase approach:**
1. **Naabu** — fast sweep of common ports across all live hosts (done first, broad)
2. **Nmap** — deep service fingerprint on specific interesting hosts (done second, targeted)

🛠️ **Tools + Commands:**
```bash
# Phase 1: Naabu — fast port scan across all live hosts
# Common ports first (80,443 plus 500 most common)
naabu -l dns_resolved.txt \
  -top-ports 1000 \
  -silent \
  -o naabu_out.txt

# Or scan specific high-value ports for web services:
naabu -l dns_resolved.txt \
  -p 80,81,443,8080,8443,8888,8000,8001,9000,9001,3000,3001,5000,4443,7443 \
  -silent \
  -o naabu_webports.txt

# Phase 2: Nmap — deep fingerprint on interesting hosts
# Run only on hosts that showed interesting open ports
nmap -sV -sC -p 80,443,8080,8443,8000,9000 \
  --open \
  -iL interesting_hosts.txt \
  -oA nmap_detailed

# Full port scan on a single very interesting host:
nmap -p- -sV --open -T4 specific_target.target.com -oA nmap_full
```

**Ports worth investigating beyond 80/443:**

| Port | Common Service | Why Interesting |
|------|---------------|-----------------|
| 8080, 8443 | Alt HTTP/HTTPS | Dev or proxy interfaces |
| 8888 | Jupyter, dev servers | Often unauthed |
| 9000 | PHP-FPM, Portainer | Internal service exposure |
| 3000 | Node.js, Grafana | Dev apps |
| 4848 | GlassFish admin | Exposed Java admin |
| 9200, 9300 | Elasticsearch | Unauthed data access |
| 6379 | Redis | Unauthed cache/DB |
| 27017 | MongoDB | Unauthed database |
| 5432 | PostgreSQL | Direct DB access |
| 22 | SSH | Credential attacks (OOS usually) |
| 2375, 2376 | Docker API | Container escape |

⚠️ **Gotchas:**
- Aggressive Nmap scanning (`-T5`, `-A`) can trigger WAF blocks and alert blue teams.
  Use `-T3` or `-T4` on live programs. Never `-T5` unless it's a dedicated lab.
- Port scanning entire /16 or /24 CIDR ranges is almost always out of scope.
  Stick to the resolved subdomains from your list unless CIDR ranges are explicitly in scope.
- Some programs explicitly prohibit port scanning. Read the scope rules.

📚 **References:**
- [Naabu](https://github.com/projectdiscovery/naabu)
- [Nmap reference](https://nmap.org/book/man.html)

---

#### 1.2.3 Visual Triage with Screenshots

🔍 **What to do:**
When you have 200+ live subdomains, you cannot manually visit each one in a browser.
Screenshot tools automate this — they open each URL headlessly and save a thumbnail.
You then scan the thumbnails visually in minutes, flagging interesting targets.
This is one of the highest-efficiency steps in recon.

🛠️ **Tools + Commands:**
```bash
# Aquatone — the standard
cat httpx_out.txt | aquatone \
  -out ./aquatone_report \
  -threads 5 \
  -timeout 3000

# EyeWitness — alternative, good HTML report
eyewitness --web -f httpx_out.txt \
  --timeout 10 \
  --no-prompt \
  -d eyewitness_report

# gowitness — faster, good for large lists
gowitness file -f httpx_out.txt \
  --threads 10 \
  -P ./gowitness_screenshots
gowitness report generate  # creates HTML report
```

**What to look for in the visual review:**

| Visual | What It Means |
|--------|--------------|
| Generic "Welcome to nginx" page | Default install — look for hidden paths |
| Login page (not main app) | Different auth surface — try default creds |
| Internal-looking admin panel | High priority — test all access controls |
| Error page with stack trace | Tech stack revealed, possible injection points |
| Blank page / connection refused | Filtered port or misconfigured redirect |
| Staging/dev UI (different from prod) | Often has less hardened security |
| Swagger UI / API docs | Full API map exposed publicly |
| Kibana / Grafana / Jupyter | Internal tooling, often unauthed |
| Phishing lookalike | Verify it's in scope; may be irrelevant |

⚠️ **Gotchas:**
- Screenshot tools make real HTTP requests. If a program's scope says "no automated scanning,"
  even screenshots may violate that. Most programs allow it; check scope rules.
- Aquatone works best when piped from httpx output that includes full URLs with protocol.

📚 **References:**
- [Aquatone](https://github.com/michenriksen/aquatone)
- [gowitness](https://github.com/sensepost/gowitness)

---

#### 1.2.4 Technology Fingerprinting

🔍 **What to do:**
Knowing what technology a target runs directly maps to what vulnerabilities apply.
A Laravel app gets SSTI testing. A WordPress site gets plugin enumeration.
An app behind Varnish gets cache poisoning testing. Tech fingerprinting is not optional.

🛠️ **Tools + Commands:**
```bash
# httpx already does tech detection — review the output
grep -i "tech" httpx_out.txt

# WhatWeb — deeper fingerprinting on specific targets
whatweb -a 3 https://target.com

# Wappalyzer CLI
wappalyzer https://target.com

# nuclei tech detect templates
nuclei -l httpx_out.txt \
  -t technologies/ \
  -o tech_detect.txt
```

**Manual fingerprinting signals:**
- **HTTP response headers:** `X-Powered-By`, `Server`, `X-Generator`, `X-Framework`
- **Cookie names:** `PHPSESSID` = PHP, `JSESSIONID` = Java, `_rails_session` = Rails
- **Error page content:** Stack traces reveal framework, version, file paths
- **HTML source:** `<meta name="generator">`, framework-specific HTML patterns
- **URL patterns:** `.php`, `.aspx`, `.jsp` extensions; `/wp-content/`, `/wp-admin/`

**Tech → What to test:**

| Technology | Priority Tests |
|-----------|---------------|
| WordPress | Plugin/theme vulns, xmlrpc.php, user enumeration |
| Laravel | SSTI in blade templates, debug mode, .env exposure |
| Node.js/Express | Prototype pollution, SSRF in request libs |
| Java (Spring) | Actuator endpoints, deserialization, SSTI in Thymeleaf |
| PHP (generic) | LFI, type juggling, deserialization |
| GraphQL | Introspection, DoS, IDOR |
| AWS S3 hosting | Bucket misconfiguration |
| Jenkins | Unauthenticated script console RCE |
| Elasticsearch | Unauthenticated data access |

📚 **References:**
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
- [Wappalyzer](https://github.com/wappalyzer/wappalyzer)

### 1.3 JavaScript Analysis

**The principle:** JavaScript files are the single most underexploited recon surface
in web bug bounty. Developers embed API endpoints, internal hostnames, access tokens,
feature flags, and auth logic directly in client-side JS — and it sits there publicly,
forever, indexed in the Wayback Machine.
A thorough JS pass frequently reveals more attack surface than subdomain enumeration.

---

#### 1.3.1 JS File Harvesting

🔍 **What to do:**
Collect every JS file URL associated with the target from three sources:
1. **Historical archives** — URLs the Wayback Machine has seen (including deleted files)
2. **Live crawl** — URLs present in the currently running application
3. **Direct probing** — common JS file paths that may not be linked anywhere

The union of all three gives you the most complete JS inventory.

🛠️ **Tools + Commands:**
```bash
# gau (GetAllUrls) — pulls historical URLs from Wayback, Common Crawl, OTX, URLScan
gau target.com --threads 5 --o gau_urls.txt

# waybackurls — Wayback Machine focused, fast
waybackurls target.com > wayback_urls.txt

# Katana — live crawler, handles JavaScript rendering and authenticated flows
katana -u https://target.com \
  -jc \
  -silent \
  -o katana_urls.txt

# Katana with authenticated session (cookie from logged-in browser):
katana -u https://target.com \
  -jc \
  -H "Cookie: session=<your_session_token>" \
  -silent \
  -o katana_auth_urls.txt

# Extract only .js URLs from all sources:
cat gau_urls.txt wayback_urls.txt katana_urls.txt | \
  grep -E "\.js(\?|$)" | \
  sort -u > js_urls.txt

# Download all JS files for offline analysis:
cat js_urls.txt | xargs -I{} wget -q --directory-prefix=./js_files/ {}
```

**Why authenticated crawling matters:**
Most apps load different JS bundles when logged in — admin routes, internal API paths,
feature-specific code. Always crawl both authenticated and unauthenticated.
The authenticated JS files are the ones that reveal the most.

⚠️ **Gotchas:**
- Minified/bundled JS (webpack, rollup) contains real endpoints but is unreadable as-is.
  Use `js-beautify` to format before analysis: `js-beautify ugly.js > pretty.js`
- Sourcemaps (`*.js.map`) are often left deployed in production and contain the full
  original pre-minification source. Check: `https://target.com/static/app.js.map`
- Large SPAs may have dozens of chunk files (`chunk.1a2b3c.js`). Collect all of them.

📚 **References:**
- [gau](https://github.com/lc/gau)
- [Katana](https://github.com/projectdiscovery/katana)
- [js-beautify](https://github.com/beautifier/js-beautify)

---

#### 1.3.2 Endpoint Extraction from JS

🔍 **What to do:**
Parse every collected JS file for:
- API endpoint paths (`/api/v1/users`, `/internal/admin/delete`)
- Hardcoded hostnames or internal URLs
- GraphQL query strings
- WebSocket connection strings (`wss://internal-ws.target.com`)
- Feature flags that reveal functionality
- Comments with developer notes

🛠️ **Tools + Commands:**
```bash
# LinkFinder — extracts endpoints from JS files
# On a single file:
python3 linkfinder.py -i https://target.com/static/app.js -o cli

# On a directory of downloaded JS files:
for f in ./js_files/*.js; do
  python3 linkfinder.py -i "$f" -o cli 2>/dev/null
done | sort -u > extracted_endpoints.txt

# On all JS URLs directly (no download needed):
cat js_urls.txt | while read url; do
  python3 linkfinder.py -i "$url" -o cli 2>/dev/null
done | sort -u >> extracted_endpoints.txt

# xnLinkFinder — faster alternative, handles large files better
xnLinkFinder -i https://target.com -sf target.com -o endpoints.txt

# grep patterns for manual extraction:
grep -rE '(\/api\/|\/v[0-9]+\/|\/internal\/|\/admin\/)' ./js_files/ | \
  grep -oE '"[^"]*\/[a-zA-Z][^"]*"' | \
  sort -u

# Extract anything that looks like a path:
grep -rhoE '"\/[a-zA-Z0-9_\-\/\.]{3,50}"' ./js_files/ | \
  tr -d '"' | sort -u > raw_paths.txt
```

**Manual review priorities — what to look for:**
- `fetch(`, `axios.get(`, `$.ajax(` — look at what URL it's calling
- `Authorization:`, `Bearer `, `api_key`, `apiKey` — hardcoded auth
- `localhost`, `127.0.0.1`, `10.`, `192.168.` — internal URLs hardcoded
- `TODO`, `FIXME`, `HACK`, `password`, `secret`, `debug` — developer comments
- `graphql`, `__schema`, `mutation` — GraphQL surface
- `admin`, `internal`, `private`, `legacy` — path segments worth testing

**GraphQL endpoint discovery from JS:**
```bash
grep -rE "(graphql|__schema|mutation|subscription)" ./js_files/ | \
  grep -oE '"https?://[^"]*"' | sort -u
```

📚 **References:**
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder)
- [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder)

---

#### 1.3.3 Secret and Key Detection

🔍 **What to do:**
JS files regularly contain hardcoded API keys, tokens, private keys, and credentials.
This is one of the fastest paths to a high-severity finding — a hardcoded AWS key
in a public JS file is typically a Critical with immediate payout.

Run automated tools first, then manually review anything flagged plus do your own grep passes.

🛠️ **Tools + Commands:**
```bash
# trufflehog — entropy + pattern based secret detection
trufflehog filesystem ./js_files/ \
  --only-verified \
  --json > secrets_trufflehog.json

# Without --only-verified to catch more (more false positives):
trufflehog filesystem ./js_files/ --json > secrets_all.json

# gitleaks — strong regex ruleset, good on JS files
gitleaks detect \
  --source ./js_files/ \
  --report-format json \
  --report-path secrets_gitleaks.json

# semgrep — rule-based, catches patterns tools miss
semgrep --config=p/secrets ./js_files/ --json > secrets_semgrep.json

# Manual grep patterns for common secrets:
grep -rE "(AKIA[0-9A-Z]{16})" ./js_files/        # AWS Access Key ID
grep -rE "(AIza[0-9A-Za-z_-]{35})" ./js_files/   # Google API Key
grep -rE "(sk-[a-zA-Z0-9]{48})" ./js_files/      # OpenAI API Key
grep -rE "([0-9a-f]{32})" ./js_files/             # Generic 32-char hex (MD5-length)
grep -rE "-----BEGIN (RSA|EC|PGP)" ./js_files/    # Private keys
grep -riE "(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}" ./js_files/
grep -riE "(secret|token|key|api_key)\s*[:=]\s*['\"][^'\"]{8,}" ./js_files/
```

**When you find a secret — what to do:**
1. **Do NOT use the key beyond verification.** Confirm it's real (not a placeholder like `YOUR_API_KEY_HERE`).
2. Verify it's valid: AWS keys can be tested with `aws sts get-caller-identity --profile <key>`.
   For other services, check if the key format matches known patterns.
3. Assess scope: is this JS file in scope? Is the leaked key for an in-scope service?
4. Report immediately — hardcoded secrets are P1/Critical on most programs.
5. In the report: show the file URL, the line, and what the key grants access to.

⚠️ **Gotchas:**
- Many JS files contain example/placeholder keys. Confirm before reporting.
- `--only-verified` in trufflehog makes live API calls to verify keys. Only use on keys
  you have explicit permission to test, or disable this flag.
- JS source maps sometimes contain secrets that aren't in the minified file.
  Always check for `.js.map` files separately.

📚 **References:**
- [trufflehog](https://github.com/trufflesecurity/trufflehog)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [semgrep secrets ruleset](https://semgrep.dev/p/secrets)

---

#### 1.3.4 LLM-Assisted JS Analysis

🔍 **What to do:**
Large, minified JS bundles are painful to read manually. A local LLM can scan them
and surface patterns faster than grep — particularly good at finding:
- Logic branches that reveal hidden functionality
- Auth checks that can be bypassed
- Internal endpoint patterns not caught by LinkFinder
- Comments and developer notes buried in minified code

This is a **signal amplifier**, not a replacement for manual review.
Everything the LLM flags must be manually verified.

🛠️ **Workflow:**
```bash
# Step 1: Beautify the JS first
js-beautify ./js_files/app.chunk.js > ./js_files/app.chunk.pretty.js

# Step 2: For very large files, split into chunks (LLMs have context limits)
split -l 500 app.chunk.pretty.js chunk_

# Step 3: Feed to local Ollama (Mistral-7B or DeepSeek)
# Use a structured prompt — output quality depends entirely on the prompt
```

**Prompt template for JS analysis (use with local Ollama or Claude.ai free tier):**
```
You are a security researcher analyzing JavaScript code for a bug bounty program.
Review the following JavaScript and identify:
1. All API endpoint paths (strings that look like /api/*, /v1/*, /internal/*, etc.)
2. Any hardcoded secrets, tokens, keys, or passwords
3. Any internal hostnames or IP addresses
4. Authentication or authorization logic that could be bypassed
5. Any commented-out code that reveals functionality
6. Any debug flags or feature flags that affect security behavior

For each finding, quote the relevant code and explain why it's significant.
Do not hallucinate — only report what is actually present in the code.

Code:
[paste JS chunk here]
```

**Critical rules for LLM JS analysis:**
- **Never send sensitive target data to a public LLM** — use local Ollama for JS analysis.
  Cloud LLMs (ChatGPT, Claude.ai) are fine for generic questions, not for target-specific data.
- Verify every output. LLMs confidently hallucinate endpoint paths that don't exist.
- LLMs are particularly good at explaining what obfuscated code does — use this for
  understanding, not for generating findings.

📚 **References:**
- [Ollama](https://ollama.ai) — local LLM runtime
- [Mistral-7B via Ollama](https://ollama.ai/library/mistral) — runs on 8GB RAM
- [DeepSeek-R1 via Ollama](https://ollama.ai/library/deepseek-r1) — stronger reasoning

---

### 1.4 GitHub & Source Code Recon

**The principle:** Companies accidentally commit secrets, internal endpoints,
and authentication logic to public repositories constantly. This happens not just
in dedicated security incidents but routinely — API keys in config files,
database URLs in `.env` examples, internal domain names in comments.
GitHub recon is often faster to a high-severity finding than any other technique.

---

#### 1.4.1 GitHub Dorking

🔍 **What to do:**
GitHub's search indexes code, commits, issues, and comments across all public repositories.
Searching for target-specific strings surfaces leaked secrets, internal tooling,
and configuration files that were never meant to be public.

🛠️ **Search patterns — run each in `github.com/search?type=code`:**
```
# Secrets and credentials
"target.com" password
"target.com" secret
"target.com" api_key
"target.com" apikey
"target.com" token
"target.com" "Authorization: Bearer"
"@target.com" password        # email format — finds employee credentials

# Internal infrastructure
"target.com" internal
"target.com" staging
"target.com" localhost
"target.com" "192.168."
"target.com" "10.0."
"target.com" db_password
"target.com" database_url

# Config and environment files
"target.com" filename:.env
"target.com" filename:config.yml
"target.com" filename:settings.py
"target.com" filename:database.yml
"target.com" filename:wp-config.php
"target.com" filename:*.pem
"target.com" filename:id_rsa

# AWS and cloud
"target.com" AKIA              # AWS key prefix
"target.com" aws_access_key
"target.com" aws_secret

# Specific technologies
"target.com" filename:docker-compose.yml
"target.com" filename:Dockerfile
"target.com" filename:.travis.yml   # CI/CD configs with secrets
"target.com" filename:.github

# Search by org directly:
org:targetcompany password
org:targetcompany secret
org:targetcompany filename:.env
```

**GitHub advanced search URL pattern:**
```
https://github.com/search?q="target.com"+password&type=code&s=indexed&o=desc
```
Sort by "Recently indexed" to find fresh leaks.

🛠️ **Automated tools:**
```bash
# github-dorker — automates dork list against a target
python3 github-dorker.py -q "target.com" \
  --dorks dorks.txt \
  --token <github_pat>

# trufflehog — scan GitHub org directly
trufflehog github --org=targetcompany \
  --token=<github_pat> \
  --only-verified

# Scan a specific repository:
trufflehog github --repo=https://github.com/company/repo \
  --token=<github_pat>
```

⚠️ **Gotchas:**
- GitHub rate-limits unauthenticated search heavily. Create a free GitHub account
  and generate a Personal Access Token (PAT) for all automated tooling.
- Repositories get deleted after exposure — use Google cache or the Wayback Machine
  if a link shows as 404.
- Findings in third-party repositories (not owned by the target) are still valid
  if they expose the target's secrets. Report the finding, not the repo.

📚 **References:**
- [GitHub Advanced Search](https://github.com/search/advanced)
- [github-dorker](https://github.com/obheda12/GitiLeaks)
- [trufflehog GitHub scanning](https://github.com/trufflesecurity/trufflehog)

---

#### 1.4.2 Historical Commit Scanning

🔍 **What to do:**
A secret committed and then deleted still exists in git history.
If a repository is public, its entire commit history is accessible.
Scanning history is often more fruitful than scanning the current code,
because developers frequently commit secrets, realize the mistake, and delete them —
but forget that git history is permanent.

🛠️ **Tools + Commands:**
```bash
# Clone the target repository (shallow clone is faster but misses old history)
git clone https://github.com/company/repo
cd repo

# trufflehog on the local clone — scans all commits
trufflehog git file://. --json > repo_secrets.json

# gitleaks on the local clone
gitleaks detect --source . \
  --log-opts="--all --full-history" \
  --report-format json \
  --report-path repo_secrets.json

# Manual git log search for specific strings:
git log -p --all -S "password" --source
git log -p --all -S "api_key" --source
git log -p --all -S "secret" --source
git log -p --all --grep="remove" --grep="delete" --all-match  # commits that deleted something

# View a specific commit that looks interesting:
git show <commit_hash>
```

**High-value commit message patterns to search:**
```bash
git log --all --oneline | grep -iE \
  "(remove|delete|fix|revert|secret|key|token|password|credential|oops|accident)"
```
These commit messages often correspond to exactly the moment a secret was removed from
the codebase — but the secret is still in that commit's diff.

⚠️ **Gotchas:**
- Full history clone (`--no-single-branch`) is required to scan all branches:
  `git clone --no-single-branch https://github.com/company/repo`
- Large repos can be gigabytes. For initial triage, use trufflehog's remote scan
  (no clone needed): `trufflehog github --repo=<url> --token=<pat>`

---

#### 1.4.3 Org-Wide Repository Enumeration

🔍 **What to do:**
The target company may have dozens of public repositories beyond the main product.
Internal tooling, mobile apps, infrastructure configs, SDKs, and documentation repos
all live under the same GitHub org and are all worth scanning.

🛠️ **Commands:**
```bash
# List all public repos in a GitHub org (via API):
curl -s "https://api.github.com/orgs/targetcompany/repos?per_page=100&page=1" \
  -H "Authorization: token <github_pat>" | \
  jq -r '.[].clone_url' > org_repos.txt

# Handle pagination (if org has >100 repos):
for page in 1 2 3 4 5; do
  curl -s "https://api.github.com/orgs/targetcompany/repos?per_page=100&page=$page" \
    -H "Authorization: token <github_pat>" | \
    jq -r '.[].clone_url'
done | sort -u > org_repos.txt

# Bulk scan all org repos with trufflehog:
cat org_repos.txt | while read repo; do
  trufflehog git "$repo" \
    --token=<github_pat> \
    --only-verified \
    --json 2>/dev/null
done > org_secrets.json

# Look for interesting repo names:
cat org_repos.txt | grep -iE \
  "(internal|infra|config|deploy|admin|secret|key|auth|backend|api)"
```

**What to look for beyond secrets:**
- `docker-compose.yml` or `Kubernetes` configs — internal service hostnames, ports
- `.github/workflows/` CI/CD files — secrets injected as env vars, deployment targets
- `README.md` in internal-looking repos — architecture details, internal URLs
- `CHANGELOG.md` — history of features that may have security implications
- Issues and PRs — bug reports, security discussions, feature requests that reveal logic

📚 **References:**
- [GitHub REST API — repos](https://docs.github.com/en/rest/repos/repos)
- [gitGraber](https://github.com/hisxo/gitGraber) — live GitHub monitoring

---

### 1.5 Directory & Parameter Fuzzing

**The principle:** Endpoints that aren't linked anywhere still exist and respond.
Fuzzing finds them by brute-force. This surfaces admin panels, backup files,
debug endpoints, undocumented API routes, and configuration files.
The quality of your wordlist determines the quality of your results.

---

#### 1.5.1 Directory and Path Fuzzing

🔍 **What to do:**
Send HTTP requests with every word in a wordlist appended to the target URL.
Collect non-404 responses. Manually review what's interesting.
Start broad (common paths), then go targeted (tech-specific paths based on fingerprint).

🛠️ **Tools + Commands:**
```bash
# ffuf — the standard for directory fuzzing
# Basic run:
ffuf -u https://target.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  -mc 200,201,202,204,301,302,307,401,403,405 \
  -o ffuf_dirs.json \
  -of json

# Filter noise — exclude specific response sizes or words:
ffuf -u https://target.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  -mc 200,201,301,302,401,403 \
  -fs 1234   # filter responses with this exact size (calibrate by running once first)

# Recursive fuzzing (goes into found directories):
ffuf -u https://target.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,401,403 \
  -recursion \
  -recursion-depth 2

# With custom headers (authenticated fuzzing):
ffuf -u https://target.com/api/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/api-endpoints.txt \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -mc 200,201,400,401,403,405

# File extension fuzzing:
ffuf -u https://target.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/raft-large-files.txt \
  -e .php,.html,.js,.json,.bak,.old,.txt,.xml,.conf,.config,.log \
  -mc 200,201,403 \
  -fs 0
```

**Wordlist priority by scenario:**

| Scenario | Wordlist |
|----------|---------|
| General web (first pass) | `raft-large-directories.txt` |
| API endpoints | `api-endpoints.txt` (SecLists) or Assetnote `httparchive_apiroutes_*.txt` |
| PHP apps | `PHP.fuzz.txt` (SecLists) |
| File discovery | `raft-large-files.txt` |
| Backup files | `backup-filenames.txt` (SecLists) |
| Config files | `server-configs.txt` (SecLists) |
| WordPress | `wordpress.fuzz.txt` |
| Spring Boot | `spring-boot.txt` (Assetnote) |
| .NET | `AspDotNetWordlist.txt` (SecLists) |

**Interpreting results:**

| Response | What It Means |
|----------|---------------|
| 200 | Content found — review it |
| 301/302 | Redirect — follow it |
| 401 | Authentication required — try bypass |
| 403 | Forbidden — try method change, path variation, headers |
| 405 | Method not allowed — try other HTTP methods |
| 500 | Server error — possible injection or misconfiguration |

**403 bypass attempts — always try these when you get a 403:**
```bash
# Path variations:
curl -s -o /dev/null -w "%{http_code}" https://target.com/admin
curl -s -o /dev/null -w "%{http_code}" https://target.com/admin/
curl -s -o /dev/null -w "%{http_code}" https://target.com/%2fadmin
curl -s -o /dev/null -w "%{http_code}" https://target.com/admin%20
curl -s -o /dev/null -w "%{http_code}" https://target.com/./admin
curl -s -o /dev/null -w "%{http_code}" https://target.com/admin/.

# Header-based bypass:
curl -H "X-Original-URL: /admin" https://target.com/
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/admin
curl -H "X-Custom-IP-Authorization: 127.0.0.1" https://target.com/admin
curl -H "X-Rewrite-URL: /admin" https://target.com/
```

⚠️ **Gotchas:**
- Always calibrate noise first: run a single request to a path that definitely doesn't exist
  (`/randomstring99999`) and note the response size. Use `-fs` to filter that size in your run.
- Rate limiting is real. Add `-rate 50` (50 req/sec) for conservative scanning.
  Some programs explicitly limit request rates — check scope rules.
- Never fuzz with massive wordlists (1M+ entries) against a live production app
  without considering the load. `raft-large` (~37K entries) is the right balance.

📚 **References:**
- [ffuf](https://github.com/ffuf/ffuf)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [Assetnote Wordlists](https://wordlists.assetnote.io) — tech-specific, highest quality for APIs

---

#### 1.5.2 Parameter Discovery

🔍 **What to do:**
Web applications often have undocumented parameters that change behavior, reveal data,
or enable features. Finding them is the difference between testing 5 parameters
and testing 50 — and the 45 undocumented ones are where bugs hide.

Two approaches: **passive** (mining from existing traffic) and **active** (brute-force with wordlists).

🛠️ **Tools + Commands:**
```bash
# Arjun — parameter brute-force tool, handles GET, POST, JSON, XML
# GET parameters:
arjun -u https://target.com/api/search \
  -m GET \
  --stable \
  -o arjun_params.json

# POST parameters:
arjun -u https://target.com/api/update \
  -m POST \
  --stable

# With custom headers:
arjun -u https://target.com/api/user \
  -H "Authorization: Bearer <token>" \
  -m GET

# x8 — faster parameter miner, good for APIs
x8 -u "https://target.com/api/endpoint" \
  -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  -X GET \
  --output-file x8_results.txt

# ParamMiner (Burp Suite extension) — passive, in-traffic discovery
# Install via BApp Store → right-click any request → "Guess params"
# Let it run in background while you browse the app manually
```

**Manual parameter discovery — what to look for in existing responses:**
- JSON response keys that aren't reflected in the request — try passing them back
- HTML forms with `<input type="hidden">` fields
- JavaScript files that build request objects (show you what parameters the app expects)
- API documentation endpoints: `/swagger.json`, `/api-docs`, `/openapi.yaml`

```bash
# Find parameter names from OpenAPI/Swagger specs:
curl -s https://target.com/swagger.json | \
  jq -r '.. | .parameters? // empty | .[].name' 2>/dev/null | sort -u

# Extract parameter names from JS files:
grep -rhoE '"[a-zA-Z_][a-zA-Z0-9_]{2,20}":\s*(null|true|false|[0-9]+|"[^"]*")' \
  ./js_files/ | \
  grep -oE '"[^"]*":' | tr -d '":' | sort -u > js_param_names.txt
```

**High-value undocumented parameters to try manually:**
```
debug=true, debug=1
test=true, testing=1
admin=true
internal=true
verbose=true
format=json, format=xml
callback=<function>    (JSONP)
_method=DELETE         (method override)
role=admin
user_id=<other_id>     (IDOR)
```

📚 **References:**
- [Arjun](https://github.com/s0md3v/Arjun)
- [x8](https://github.com/Sh1Yo/x8)
- [ParamMiner (BApp Store)](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943)

---

#### 1.5.3 Backup and Configuration File Discovery

🔍 **What to do:**
Developers create backup files during maintenance and forget to delete them.
Configuration files get accidentally deployed. These files are high-severity findings
because they often contain credentials, database connection strings, and full source code.

🛠️ **Commands:**
```bash
# Common backup patterns — test on every interesting URL you find:
# If you find https://target.com/admin/index.php, also try:
https://target.com/admin/index.php.bak
https://target.com/admin/index.php~
https://target.com/admin/index.php.old
https://target.com/admin/index.php.orig
https://target.com/admin/index.php.save
https://target.com/admin/index.php.swp  # vim swap file
https://target.com/admin/index.php.1
https://target.com/.admin.php.swp

# Common sensitive files to check on every target (ffuf wordlist):
ffuf -u https://target.com/FUZZ \
  -w /opt/SecLists/Discovery/Web-Content/sensitive-files-linux.txt \
  -mc 200,403

# Top targets to check manually:
/.env
/.env.local
/.env.production
/.env.backup
/config.php
/config.yml
/config.json
/settings.py
/database.yml
/wp-config.php
/web.config
/appsettings.json
/.git/HEAD          # exposed git repo
/.git/config
/phpinfo.php
/info.php
/server-status      # Apache server status
/server-info
/.htaccess
/crossdomain.xml
/sitemap.xml        # can reveal all endpoints
/robots.txt         # disallowed paths are interesting
```

**Exposed `.git` directory — critical finding:**
```bash
# Check if .git is exposed:
curl -s https://target.com/.git/HEAD
# If it returns "ref: refs/heads/main" → git directory is exposed

# Download the entire repo using git-dumper:
git-dumper https://target.com/.git ./dumped_repo
cd dumped_repo && git log --oneline  # full source code + history
```
An exposed `.git` directory is a Critical — full source code exposure.

⚠️ **Gotchas:**
- `robots.txt` disallowed paths are often the most interesting paths on the site.
  Every path in `Disallow:` is a testing target.
- Backup files may return 200 but with source code as plaintext — this means the server
  is serving the raw file rather than executing it. Always check content-type.

📚 **References:**
- [git-dumper](https://github.com/arthaud/git-dumper)
- [SecLists sensitive files](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content)

### 1.6 Subdomain Takeover

**The principle:** A subdomain takeover occurs when a subdomain's DNS record
points to an external service that is no longer claimed by the target.
An attacker can register the unclaimed service and take control of the subdomain —
serving malicious content under the target's trusted domain, stealing cookies,
bypassing CSP, or conducting phishing with a legitimate SSL certificate.
Severity is typically High or Critical because of the trust a subdomain inherits.

---

#### 1.6.1 Identifying Dangling CNAME Records

🔍 **What to do:**
A dangling CNAME points to a hostname that either doesn't resolve or resolves to
a service that isn't claimed. The workflow is:
1. Collect all subdomains (from 1.1)
2. Resolve them and extract CNAME chains
3. Check whether the CNAME target is claimed on the third-party service

🛠️ **Tools + Commands:**
```bash
# Step 1: Extract CNAME records from your subdomain list
dnsx -l master_subdomains.txt \
  -cname \
  -silent \
  -o cnames.txt

# Output format: subdomain.target.com → external-service.example.com
# Look for CNAMEs pointing to third-party platforms

# Step 2: Check which subdomains return NXDOMAIN (no resolution)
# These are immediate takeover candidates
dnsx -l master_subdomains.txt \
  -silent \
  -rc NXDOMAIN \
  -o nxdomain_subdomains.txt

# Step 3: subjack — automated takeover fingerprinting
subjack -w master_subdomains.txt \
  -t 100 \
  -timeout 30 \
  -ssl \
  -c /opt/subjack/fingerprints.json \
  -o subjack_results.txt

# Step 4: nuclei takeover templates — broad coverage
nuclei -l master_subdomains.txt \
  -t takeovers/ \
  -o nuclei_takeovers.txt
```

**What a dangling CNAME looks like:**
```
legacy-app.target.com  →  CNAME  →  legacy-app.herokudns.com
# Heroku app deleted — legacy-app.herokudns.com is unclaimed
# Anyone can create a Heroku app at that URL and take over legacy-app.target.com
```

---

#### 1.6.2 Service Fingerprinting for Takeover Candidates

🔍 **What to do:**
Not every unclaimed CNAME is takeable — some services don't allow claiming
arbitrary subdomains. Fingerprinting identifies which service the CNAME points to
and whether that service is vulnerable to takeover.

**Vulnerable services (partial list — most common in bug bounty):**

| Service | Fingerprint (response body contains) | Takeover Method |
|---------|--------------------------------------|-----------------|
| GitHub Pages | `There isn't a GitHub Pages site here` | Create repo, enable Pages |
| Heroku | `No such app` | `heroku create <appname>` |
| Netlify | `Not Found - Request ID` | Create site with matching name |
| Vercel | `The deployment could not be found` | Deploy to matching domain |
| AWS S3 | `NoSuchBucket` | Create S3 bucket with same name |
| AWS Elastic Beanstalk | `CNAME cross-account` check | Register EB environment |
| Fastly | `Fastly error: unknown domain` | Add domain in Fastly dashboard |
| Shopify | `Sorry, this shop is currently unavailable` | Create Shopify store |
| Zendesk | `Help Center Closed` | Create Zendesk account |
| Tumblr | `There's nothing here` | Register Tumblr blog |
| Ghost | `The thing you were looking for is no longer here` | Ghost(Pro) setup |
| Surge.sh | `project not found` | `surge` CLI claim |
| Cargo | `If you're moving your domain away from Cargo` | Register Cargo site |

```bash
# Check the response body of a suspicious subdomain:
curl -sk https://legacy-app.target.com | \
  grep -iE "(there isn't|no such app|not found|noSuchBucket|unknown domain)"

# Or use httpx and check the response body:
httpx -u https://legacy-app.target.com \
  -silent \
  -response-body \
  -o body_check.txt
```

📚 **References:**
- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) —
  the canonical list of vulnerable services, takeover methods, and difficulty ratings.
  **Always check this list before attempting a takeover.**

---

#### 1.6.3 Claiming and PoC Construction

🔍 **What to do:**
Once you've identified a takeover candidate and confirmed the service is vulnerable,
the PoC requires actually claiming the subdomain. This is the expected standard —
programs want proof the takeover works, not just that the CNAME is dangling.

**General takeover workflow:**
```
1. Confirm CNAME is dangling and service fingerprint matches a vulnerable service
2. Create a free account on the third-party service
3. Add the subdomain as a custom domain on your new account
4. Verify you can serve content at subdomain.target.com
5. Create a benign PoC page (plain HTML, no malicious content)
6. Screenshot the PoC page loading under the target's subdomain
7. Report immediately — then optionally release the claim
```

**GitHub Pages takeover example (most common):**
```bash
# 1. Confirm: legacy.target.com → CNAME → targetcompany.github.io
# and targetcompany.github.io returns 404

# 2. Create GitHub repo named exactly: targetcompany.github.io
#    (or the specific repo pattern matching the CNAME)

# 3. Enable GitHub Pages in repo settings

# 4. Create index.html with benign PoC content:
echo "<h1>Subdomain Takeover PoC - Bug Bounty Report</h1>
<p>This page demonstrates that legacy.target.com is vulnerable to
subdomain takeover. No malicious action has been taken.</p>" > index.html

# 5. Push to repo — site goes live at legacy.target.com
```

**S3 bucket takeover:**
```bash
# CNAME: assets.target.com → assets.target.com.s3.amazonaws.com
# Bucket doesn't exist

# Create the bucket with the exact same name:
aws s3 mb s3://assets.target.com --region us-east-1

# Upload PoC:
echo "<h1>S3 Subdomain Takeover PoC</h1>" > index.html
aws s3 cp index.html s3://assets.target.com/ --acl public-read

# Configure as static website:
aws s3 website s3://assets.target.com/ \
  --index-document index.html
```

**What to include in the report:**
- The subdomain and its full CNAME chain
- The third-party service it points to and why it's unclaimed
- Screenshot of the PoC page loading under the target's subdomain
- The real-world impact: cookie theft (if the subdomain is same-site with main app),
  phishing under trusted domain, CSP bypass, OAuth redirect URI abuse

⚠️ **Gotchas:**
- Some programs consider taking over the subdomain as out-of-scope "active exploitation."
  Check scope rules — some only want the dangling CNAME reported without a live PoC.
- Release the claim promptly after reporting. Don't hold it.
- S3 bucket names are global — if someone else already created the bucket, the finding
  may be a pre-existing takeover by a third party, which is still reportable.
- Subdomain takeover via `A` record (not CNAME) is possible but rare — requires the IP
  to be released and re-assigned (cloud IPs sometimes cycle).

📚 **References:**
- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
- [subjack](https://github.com/haccer/subjack)
- [nuclei takeover templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/takeovers)

---

### 1.7 Google & Advanced Dorking

**The principle:** Search engines have indexed things the target never intended to expose.
Dorking is free, passive, and completely legal — and it regularly surfaces admin panels,
exposed documents, login portals, and sensitive files that no scanner will find.
It takes 20 minutes and should be done on every target before any active scanning.

---

#### 1.7.1 Google Dork Patterns for Bug Hunters

🔍 **Core dorks — run these on every target:**
```
# Exposed files and sensitive content
site:target.com filetype:pdf
site:target.com filetype:xlsx OR filetype:csv
site:target.com filetype:sql
site:target.com filetype:log
site:target.com filetype:env
site:target.com filetype:bak
site:target.com filetype:conf OR filetype:config
site:target.com filetype:pem OR filetype:key

# Login and admin panels
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:dashboard
site:target.com inurl:panel
site:target.com inurl:portal
site:target.com inurl:cp
site:target.com intitle:"admin panel"
site:target.com intitle:"login" inurl:admin

# Exposed technology interfaces
site:target.com inurl:jenkins
site:target.com inurl:grafana
site:target.com inurl:kibana
site:target.com inurl:jira
site:target.com inurl:confluence
site:target.com inurl:gitlab
site:target.com inurl:phpmyadmin
site:target.com intitle:"index of /"

# API and dev exposure
site:target.com inurl:/api/v1
site:target.com inurl:swagger
site:target.com inurl:graphql
site:target.com inurl:api-docs
site:target.com inurl:debug
site:target.com inurl:test

# Sensitive data patterns
site:target.com "password" filetype:txt
site:target.com "api_key" OR "apikey"
site:target.com "Internal Server Error"
site:target.com "Stack trace"
site:target.com "SQL syntax"    # SQLi error in production

# Subdomains not found by tools
site:*.target.com -site:www.target.com
```

**Dorking workflow:**
1. Run the broad `site:target.com` first to understand scope of what's indexed
2. Work through category-specific dorks above
3. For anything interesting: `cache:target.com/found-page` to see a historical snapshot
4. Use `intext:` for finding specific strings in page body vs. `intitle:` for page titles

⚠️ **Gotchas:**
- Google limits automated queries and will serve CAPTCHAs — do this manually in browser.
- Results are not exhaustive — Google doesn't index everything. Supplement with Bing dorks
  (same syntax mostly works on `bing.com/search`).
- `site:*.target.com` finds subdomains Google has indexed — often surfaces subdomains
  passive tools missed because they never appeared in cert logs.

---

#### 1.7.2 Shodan, Censys, FOFA & GreyNoise

🔍 **What to do:**
These are search engines for Internet-connected infrastructure. They scan the entire
Internet continuously and index what they find — open ports, banners, certificates,
technologies. You query them instead of scanning the target directly.

**Shodan — `shodan.io`:**
```
# Find all hosts for a company by SSL cert org name:
ssl.cert.subject.cn:"target.com"
ssl.cert.subject.o:"Target Company Inc"

# Find specific technologies:
ssl:"target.com" product:"Apache httpd"
ssl:"target.com" product:"nginx"

# Find exposed services:
hostname:"target.com" port:8080
hostname:"target.com" port:6379        # Redis
hostname:"target.com" port:9200        # Elasticsearch
hostname:"target.com" port:27017       # MongoDB
hostname:"target.com" port:2375        # Docker API

# Favicon hash (after getting it from httpx):
http.favicon.hash:<hash_value>

# CLI queries (requires Shodan API key):
shodan search 'ssl.cert.subject.cn:"target.com"' --fields ip_str,port,org
shodan search 'hostname:"target.com"' --fields ip_str,port,product
```

**Censys — `search.censys.io`:**
```
# Certificate search:
parsed.names: target.com
parsed.subject.organization: "Target Company"

# Service search:
services.tls.certificates.leaf_data.subject.common_name: target.com
services.http.response.html_title: "Target App"

# Find hosts by ASN (if you know the company's ASN):
autonomous_system.asn: 12345
```

**FOFA — `fofa.info` (Chinese engine, excellent coverage of Asian targets):**
```
domain="target.com"
cert="target.com"
header="target.com"
title="Target App"
```

**GreyNoise — `viz.greynoise.io`:**
Not for finding assets, but for context: if an IP shows up in GreyNoise as a
mass-scanner, it's probably not worth hunting. Use it to vet suspicious hosts
found through other sources.

🛠️ **CLI setup:**
```bash
# Shodan CLI:
pip install shodan --break-system-packages
shodan init <api_key>
shodan search 'ssl:"target.com"' --fields ip_str,port,org,product > shodan_results.txt

# Censys Python SDK:
pip install censys --break-system-packages
python3 -c "
from censys.search import CensysHosts
h = CensysHosts()
for host in h.search('parsed.names: target.com'):
    print(host)
"
```

⚠️ **Gotchas:**
- Shodan free tier has limited results and no real-time data. The free tier is still useful
  for target discovery — paid tier is needed for full historical data.
- IPs found via Shodan may be CDN IPs (Cloudflare, Fastly, Akamai), not origin servers.
  An IP resolving to `target.com` but returning generic CDN content → look for origin
  IP via: historical DNS records, cert mismatch, `X-Forwarded-For` misconfiguration.
- Censys has generous free tier for security researchers — register with a research email.

📚 **References:**
- [Shodan](https://shodan.io)
- [Censys](https://search.censys.io)
- [FOFA](https://fofa.info)
- [Shodan CLI docs](https://cli.shodan.io)

---

#### 1.7.3 Wayback Machine for Deleted Endpoints

🔍 **What to do:**
The Wayback Machine archives web content continuously. Deleted pages, old API versions,
deprecated endpoints, and removed admin panels often remain in the archive.
Endpoints that no longer exist in the live app may still exist on the backend —
especially in monolithic applications where the route is just hidden, not removed.

🛠️ **Commands:**
```bash
# CDX API — get all archived URLs for a domain (no browser needed):
curl -s "http://web.archive.org/cdx/search/cdx?\
url=*.target.com/*\
&output=text\
&fl=original\
&collapse=urlkey\
&limit=100000" > wayback_all_urls.txt

# Filter for interesting patterns:
cat wayback_all_urls.txt | grep -iE \
  "(admin|internal|api|login|debug|test|backup|config|staging|legacy|upload)"

# Filter by file extension:
cat wayback_all_urls.txt | grep -E "\.(php|asp|aspx|jsp|json|xml|env|bak|sql)$"

# Extract unique paths (strip domain, deduplicate):
cat wayback_all_urls.txt | \
  grep "target.com" | \
  sed 's|https\?://[^/]*/||' | \
  sort -u > wayback_paths.txt

# Test if old paths still respond on the live site:
cat wayback_paths.txt | \
  while read path; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com/$path")
    [ "$code" != "404" ] && echo "$code https://target.com/$path"
  done
```

**What to look for in Wayback URLs:**
- Old API versions: `/api/v1/`, `/api/v0/` — may have fewer security controls than current
- Deprecated endpoints: `/old/`, `/legacy/`, `/backup/`
- Admin paths that were removed from navigation but not from routing
- Parameter patterns in old URLs that reveal how the app used to work
- Old file upload endpoints that may still function

📚 **References:**
- [Wayback CDX API docs](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server)
- [waybackurls](https://github.com/tomnomnom/waybackurls)
- [gau](https://github.com/lc/gau)

---

### 1.8 Recon Automation & Pipelines

**The principle:** Manual recon on a target once is not enough.
New subdomains get added. New features ship. New S3 buckets get created.
The hunter who finds these changes first — before anyone else runs recon —
has the lowest duplicate rate and the highest hit rate.
Continuous recon automation is what separates hunters with consistent income
from hunters who only find bugs during their manual hunting sessions.

This section covers the mental model and pipeline architecture.
For full infrastructure setup (VPS, cron, Telegram), see
[Part 14: Continuous Recon Infrastructure](#part-14-continuous-recon-infrastructure).

---

#### 1.8.1 The Delta Principle

🔍 **The core idea:**
Don't process the same data twice. On every run, compare new results against
what you already have. Only investigate the **difference** — the new subdomains,
the new endpoints, the new open ports. This is what `anew` enables.

```bash
# First run: everything is new
subfinder -d target.com -silent > master_subdomains.txt

# Every subsequent run: only new lines get through
subfinder -d target.com -silent | anew master_subdomains.txt
# anew outputs ONLY lines not already in master_subdomains.txt
# and appends them to the file

# Pipe new subdomains directly into further processing:
subfinder -d target.com -silent | \
  anew master_subdomains.txt | \
  httpx -silent -status-code -title | \
  notify  # send to Telegram/Slack
```

This means your morning routine is reviewing 0–5 new assets instead of
re-processing thousands of known ones.

---

#### 1.8.2 The Recon Pipeline Architecture

**Full pipeline — what runs nightly:**

```
[Subdomain Sources]
    Subfinder + Amass passive + crt.sh
           ↓
    [DNS Resolution] dnsx
           ↓
    [Delta Check] anew → only new subdomains continue
           ↓
    [HTTP Probing] httpx → status, title, tech
           ↓
    [Port Scan] naabu → common ports on new hosts
           ↓
    [Screenshot] gowitness → visual triage
           ↓
    [Vuln Scan] nuclei → community templates on new assets only
           ↓
    [Alert] notify → Telegram/Slack message with findings
```

**Bash pipeline (single file, runs via cron):**
```bash
#!/bin/bash
# recon_pipeline.sh
# Runs nightly, alerts on new findings

TARGET="target.com"
BASE_DIR="/opt/recon/$TARGET"
mkdir -p "$BASE_DIR"

echo "[*] Starting recon: $TARGET — $(date)"

# Step 1: Subdomain enumeration
subfinder -d "$TARGET" -all -silent 2>/dev/null | \
  anew "$BASE_DIR/subdomains.txt" > /tmp/new_subs.txt

# If nothing new, exit early
[ ! -s /tmp/new_subs.txt ] && echo "[*] No new subdomains" && exit 0

echo "[+] New subdomains: $(wc -l < /tmp/new_subs.txt)"

# Step 2: DNS resolution of new subdomains
dnsx -l /tmp/new_subs.txt -silent -a \
  -o /tmp/new_resolved.txt 2>/dev/null

# Step 3: HTTP probing
httpx -l /tmp/new_resolved.txt \
  -silent \
  -status-code \
  -title \
  -tech-detect \
  -o /tmp/new_httpx.txt 2>/dev/null

# Step 4: Nuclei on new hosts
nuclei -l /tmp/new_resolved.txt \
  -t cves/ -t exposures/ -t takeovers/ \
  -severity medium,high,critical \
  -silent \
  -o /tmp/new_nuclei.txt 2>/dev/null

# Step 5: Alert via Telegram
if [ -s /tmp/new_nuclei.txt ] || [ -s /tmp/new_httpx.txt ]; then
  MESSAGE="🔍 *Recon Alert: $TARGET*%0A"
  MESSAGE+="New subdomains: $(wc -l < /tmp/new_subs.txt)%0A"
  MESSAGE+="New HTTP hosts: $(wc -l < /tmp/new_httpx.txt)%0A"
  [ -s /tmp/new_nuclei.txt ] && \
    MESSAGE+="⚠️ Nuclei findings: $(wc -l < /tmp/new_nuclei.txt)%0A"

  curl -s -X POST \
    "https://api.telegram.org/bot<BOT_TOKEN>/sendMessage" \
    -d "chat_id=<CHAT_ID>&text=$MESSAGE&parse_mode=Markdown" \
    > /dev/null
fi

echo "[*] Done: $(date)"
```

**Cron schedule:**
```bash
# Run nightly at 2am:
0 2 * * * /opt/scripts/recon_pipeline.sh >> /var/log/recon.log 2>&1

# Or per-target with stagger to avoid running all at once:
0 2 * * * /opt/scripts/recon_pipeline.sh target1.com
0 3 * * * /opt/scripts/recon_pipeline.sh target2.com
0 4 * * * /opt/scripts/recon_pipeline.sh target3.com
```

---

#### 1.8.3 GitHub Change Monitoring

🔍 **What to do:**
When a target pushes new code to a public repository, new endpoints, features,
and sometimes secrets appear. Monitoring for commits gives you first-mover
advantage on newly introduced attack surface.

```bash
# Check latest commit hash for a repo:
curl -s "https://api.github.com/repos/company/repo/commits?per_page=1" \
  -H "Authorization: token <github_pat>" | \
  jq -r '.[0].sha' > /tmp/latest_commit.txt

# Compare to stored last-known commit:
STORED=$(cat /opt/recon/company_repo_commit.txt 2>/dev/null)
CURRENT=$(cat /tmp/latest_commit.txt)

if [ "$STORED" != "$CURRENT" ]; then
  echo "New commit detected: $CURRENT"
  # Fetch and scan the diff
  curl -s "https://api.github.com/repos/company/repo/commits/$CURRENT" \
    -H "Authorization: token <github_pat>" | \
    jq -r '.files[].filename' > /tmp/changed_files.txt
  # Run trufflehog on new commit
  trufflehog github \
    --repo=https://github.com/company/repo \
    --since-commit="$STORED" \
    --token=<github_pat>
  # Update stored commit
  echo "$CURRENT" > /opt/recon/company_repo_commit.txt
fi
```

---

#### 1.8.4 New Feature Detection via HTTP Diff

🔍 **What to do:**
Beyond new subdomains, existing subdomains can expose new endpoints when features ship.
Run periodic httpx on known live hosts and diff the results.

```bash
# Store httpx snapshot:
httpx -l known_live_hosts.txt \
  -silent -status-code -title -content-length \
  -o /opt/recon/target/httpx_snapshot_$(date +%Y%m%d).txt

# Compare today vs yesterday:
diff \
  /opt/recon/target/httpx_snapshot_$(date -d yesterday +%Y%m%d).txt \
  /opt/recon/target/httpx_snapshot_$(date +%Y%m%d).txt | \
  grep "^>" | \
  grep -E "(200|401|403)" > /tmp/new_endpoints.txt

# Alert if anything changed:
[ -s /tmp/new_endpoints.txt ] && \
  echo "New/changed endpoints detected" && \
  cat /tmp/new_endpoints.txt
```

---

#### 1.8.5 Morning Triage Routine

**What to do when you wake up to alerts:**

1. **New subdomain alert** →
   - Visit in browser manually
   - Check screenshot (gowitness)
   - Tech fingerprint (httpx output)
   - Run targeted fuzzing if it looks like a dev/staging/admin host

2. **Nuclei finding alert** →
   - Manually verify before doing anything else (nuclei has false positives)
   - If confirmed: assess severity, write report
   - If false positive: update your nuclei template exclusion list

3. **GitHub commit alert** →
   - Review changed files list
   - Look for new API endpoints in changed routes/controllers
   - Run trufflehog output through manual review
   - Test new endpoints for standard vuln classes

4. **No alerts** →
   - Not a failure. The system is working — nothing new appeared.
   - Spend the session doing deep manual testing on existing surface.

🔗 **See also:**
- [Part 14: Continuous Recon Infrastructure](#part-14-continuous-recon-infrastructure) —
  full VPS provisioning, tool installation, Telegram bot setup, and production-ready
  cron configuration.

📚 **References:**
- [notify](https://github.com/projectdiscovery/notify) — unified alert dispatcher
  (Telegram, Slack, Discord, email)
- [ProjectDiscovery blog](https://blog.projectdiscovery.io) — pipeline architecture updates
- [nahamsec recon playlist](https://www.youtube.com/c/nahamsec) — live recon methodology

---

