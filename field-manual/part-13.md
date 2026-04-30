---
title: "Part 13: Tooling Reference & Automation"
nav_order: 14
layout: default
---

> ⚙️ **This section is under construction.** Content will be added in a future iteration.

> ⚙️ **This section is under construction.** Content will be added in a future iteration.

## PART 13: TOOLING REFERENCE & AUTOMATION
*Status: PENDING — Iteration 13*

### 13.1 Recon Tools
| Tool | Purpose | Key Flags | Reference |
|------|---------|-----------|-----------|
| Subfinder | Passive subdomain enum | *pending* | *pending* |
| Amass | Active + passive enum | *pending* | *pending* |
| Assetfinder | Fast passive enum | *pending* | *pending* |
| dnsx | DNS resolution + validation | *pending* | *pending* |
| httpx | HTTP probing, tech detect | *pending* | *pending* |
| Naabu | Fast port scanning | *pending* | *pending* |
| Katana | Web crawling (authenticated) | *pending* | *pending* |
| gau / waybackurls | Historical URL discovery | *pending* | *pending* |
| Aquatone | Visual screenshot recon | *pending* | *pending* |
| AlterX | Subdomain permutation | *pending* | *pending* |
| anew | Deduplication / delta | *pending* | *pending* |

### 13.2 Exploitation Tools
| Tool | Purpose | Key Flags | Reference |
|------|---------|-----------|-----------|
| Burp Suite (Community) | Proxy, scanner, intruder | *pending* | *pending* |
| ffuf | Directory/param fuzzing | *pending* | *pending* |
| Nuclei | Template-based scanning | *pending* | *pending* |
| sqlmap | SQL injection | *pending* | *pending* |
| jwt_tool | JWT attacks | *pending* | *pending* |
| Dalfox | XSS scanner | *pending* | *pending* |
| Kiterunner | API endpoint discovery | *pending* | *pending* |
| Autorize (Burp) | IDOR / access control | *pending* | *pending* |
| ParamMiner (Burp) | Hidden parameter discovery | *pending* | *pending* |
| interactsh | OOB interaction server | *pending* | *pending* |
| Turbo Intruder | Race conditions | *pending* | *pending* |

### 13.3 Mobile Tools
| Tool | Purpose | Platform |
|------|---------|----------|
| MobSF | Static + dynamic analysis | Android/iOS |
| APKTool | APK decompilation | Android |
| JADX | Java decompilation | Android |
| Frida | Dynamic instrumentation | Android/iOS |
| Objection | Frida-based runtime exploration | Android/iOS |
| apk-mitm | Automatic SSL pin bypass | Android |

### 13.4 Wordlists & Payload Banks
- SecLists — [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
- PayloadsAllTheThings — [https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- Assetnote Wordlists — [https://wordlists.assetnote.io](https://wordlists.assetnote.io)
- jhaddix all.txt (subdomains) — [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- fuzz.txt (ffuf paths) — [https://github.com/Bo0oM/fuzz.txt](https://github.com/Bo0oM/fuzz.txt)

---

