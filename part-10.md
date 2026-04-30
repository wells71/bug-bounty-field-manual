---
title: "Part 10: Mobile Application Programs"
nav_order: 11
layout: default
---

## PART 10: MOBILE APPLICATION PROGRAMS
*Status: COMPLETE — Iteration 10*

> **The mindset:** Mobile app testing is backend testing with an extra decompilation
> step. The most valuable bugs in mobile programs are almost never in the app itself —
> they're in the API the app talks to, which is the same API surface covered in
> Parts 2–7. What the mobile-specific work gives you is: hardcoded secrets the
> web version doesn't have, API endpoints not documented anywhere, and auth
> flows implemented differently on mobile than on web. The app is the map.
> The backend is the target.

---

### 10.1 Android

---

#### 10.1.1 APK Acquisition

🔍 **Getting the APK:**
```bash
# Method 1 — APKPure or APKMirror (no device needed):
# https://apkpure.com/search?q=target-app
# https://apkmirror.com/
# Download the .apk file directly

# Method 2 — From a connected Android device:
# List installed packages:
adb shell pm list packages | grep -i target

# Get APK path:
adb shell pm path com.target.app
# → package:/data/app/com.target.app-1.apk

# Pull APK:
adb pull /data/app/com.target.app-1.apk ./target.apk

# Method 3 — Google Play via apkeep:
apkeep -a com.target.app ./
# Downloads directly from Play Store

# Method 4 — APK extraction from running emulator:
# Start emulator in Android Studio
# Install app from Play Store
# adb pull (same as Method 2)
```

---

#### 10.1.2 Static Analysis — Decompilation

🔍 **What to look for in the decompiled source:**
```bash
# APKTool — decodes resources, AndroidManifest, smali code:
apktool d target.apk -o target_decoded/
# Gives: AndroidManifest.xml, res/, smali/ (assembly-like code)

# JADX — decompiles to readable Java (best for code analysis):
jadx target.apk -d target_jadx/
# Or use jadx-gui for visual browsing:
jadx-gui target.apk

# Key files to review immediately:
cat target_decoded/AndroidManifest.xml  # permissions, activities, exported components

# In JADX — search for secrets:
grep -rE "(api_key|apikey|secret|password|token|key)" target_jadx/sources/ | \
  grep -v "//.*" | head -50

# AWS keys:
grep -rE "AKIA[0-9A-Z]{16}" target_jadx/sources/

# URLs and endpoints:
grep -rE "https?://[a-zA-Z0-9._/-]+" target_jadx/sources/ | \
  grep -v "//.*" | sort -u

# Firebase config:
grep -rE "(firebaseio\.com|firebase\.google\.com|google-services)" target_jadx/sources/

# Certificate pinning implementation:
grep -rE "(CertificatePinner|TrustManager|X509|checkServerTrusted|pin)" \
  target_jadx/sources/

# Cryptographic keys/IVs hardcoded:
grep -rE "(AES|DES|RSA|IV|key\s*=\s*\")" target_jadx/sources/

# URLs in strings.xml and other resources:
grep -rE "https?://" target_decoded/res/values/strings.xml
grep -rE "https?://" target_decoded/res/values/
```

**MobSF — automated static analysis:**
```bash
# Run MobSF (Docker):
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Upload APK at http://localhost:8000
# MobSF reports:
# - Hardcoded secrets
# - Insecure API usage
# - Exported components
# - Dangerous permissions
# - Certificate pinning presence
# - Manifest security issues
# - Firebase/API keys
```

---

#### 10.1.3 AndroidManifest.xml Analysis

🔍 **The manifest defines the app's security posture — review carefully:**
```xml
<!-- What to look for: -->

<!-- 1. Exported components (accessible to other apps / intents): -->
<activity android:name=".AdminActivity" android:exported="true" />
<!-- exported="true" without permissions → any app can launch this activity -->

<!-- 2. Dangerous permissions: -->
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.RECORD_AUDIO"/>
<!-- Are these permissions actually needed? Excessive permissions = attack surface -->

<!-- 3. Debug flag left on: -->
<application android:debuggable="true" ...>
<!-- Allows adb debugging on non-rooted device, attach debugger -->

<!-- 4. Backup flag: -->
<application android:allowBackup="true" ...>
<!-- Allows adb backup of app data without root -->
# adb backup -noapk com.target.app
# Opens: app's databases, shared preferences, files

<!-- 5. Custom URL schemes (deep links): -->
<intent-filter>
  <data android:scheme="targetapp" android:host="login"/>
</intent-filter>
<!-- Deep link: targetapp://login → test for parameter injection -->

<!-- 6. Content providers (exposed data): -->
<provider android:name=".UserProvider"
          android:exported="true"
          android:authorities="com.target.app.provider"/>
<!-- Exported provider → any app can query it -->
```

**Testing exported components:**
```bash
# List all exported activities:
adb shell dumpsys package com.target.app | grep -i "activity" | grep "exported=true"

# Launch exported activity directly (bypass auth):
adb shell am start \
  -n com.target.app/.AdminActivity \
  -e "user_id" "1" \
  --ez "bypass_auth" true

# Query exported content provider:
adb shell content query \
  --uri content://com.target.app.provider/users

# Send broadcast to exported receiver:
adb shell am broadcast \
  -a com.target.app.ACTION_LOGIN \
  -n com.target.app/.LoginReceiver
```

---

#### 10.1.4 Dynamic Analysis — Proxy Setup

🔍 **Intercepting Android app traffic with Burp:**
```bash
# Step 1: Configure Android emulator proxy
# Emulator → Settings → WiFi → Long press → Modify Network → Manual proxy
# Proxy: 127.0.0.1:8080 (or your machine's IP)

# Step 2: Install Burp CA certificate on Android
# Burp → Proxy → Options → Export CA Certificate → DER format
# adb push cacert.der /sdcard/
# Android Settings → Security → Install from storage → select cacert.der

# Step 3: For Android 7+ (user certs not trusted by default):
# Need to install cert as system cert OR use apk-mitm / patch the APK
apk-mitm target.apk
# → Outputs: target-patched.apk (disables SSL pinning + trusts user certs)
adb install target-patched.apk

# Step 4: For apps with strong SSL pinning — use Frida:
# (see 10.1.5)
```

---

#### 10.1.5 SSL Pinning Bypass with Frida and Objection

🔍 **SSL pinning prevents traffic interception. Bypass it:**
```bash
# Install Frida on device (requires rooted device or patched APK):
# Frida server on Android:
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Objection — Frida-based mobile exploration framework:
# Install:
pip install objection --break-system-packages

# Launch app with Objection:
objection -g com.target.app explore

# Inside Objection shell:
android sslpinning disable          # universal SSL pinning bypass
android root disable                 # root detection bypass
android hooking list classes         # list all classes
android hooking list class_methods com.target.security.PinningManager
android hooking watch class_method com.target.auth.TokenManager.getToken --dump-return

# Frida script — universal SSL pinning bypass:
frida -U -f com.target.app \
  --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida
# Or load script from file:
frida -U -f com.target.app -l ssl_bypass.js
```

**apk-mitm (easiest — no root required):**
```bash
# Install:
npm install -g apk-mitm

# Patch APK:
apk-mitm target.apk
# Output: target-patched.apk

# Install patched app:
adb install target-patched.apk
# Now all traffic goes through Burp without SSL pinning
```

---

#### 10.1.6 Exported Components — Deep Link Abuse

🔍 **Deep links are URLs that open the app at a specific screen:**
```bash
# Find deep link schemes from manifest:
grep -r "android:scheme" target_decoded/AndroidManifest.xml
# → targetapp://

# Find deep link hosts and paths:
grep -rA5 "intent-filter" target_decoded/AndroidManifest.xml | \
  grep -E "scheme|host|path"

# Test deep links from browser or adb:
adb shell am start \
  -a android.intent.action.VIEW \
  -d "targetapp://login?token=test&redirect=https://evil.com"

# Deep link parameter injection:
# If deep link passes URL/token to WebView without validation:
adb shell am start -d "targetapp://reset?token=../../admin"
adb shell am start -d "targetapp://open?url=javascript:alert(1)"
adb shell am start -d "targetapp://auth?redirect=https://evil.com"

# WebView JavaScript interface (if exposed):
# In JADX: search for addJavascriptInterface
grep -rn "addJavascriptInterface" target_jadx/sources/
# If found: JavaScript can call native Android methods
# Test: inject JS via deep link or URL parameter → call native methods
```

---

#### 10.1.7 Insecure Local Storage

🔍 **Android apps store sensitive data in multiple locations:**
```bash
# Requires adb access (rooted device or emulator):

# SharedPreferences (XML files):
adb shell run-as com.target.app cat \
  /data/data/com.target.app/shared_prefs/user_prefs.xml
# Look for: auth tokens, user IDs, API keys, session cookies

# SQLite databases:
adb shell run-as com.target.app ls \
  /data/data/com.target.app/databases/
adb shell run-as com.target.app \
  sqlite3 /data/data/com.target.app/databases/app.db ".tables"
adb shell run-as com.target.app \
  sqlite3 /data/data/com.target.app/databases/app.db "SELECT * FROM users LIMIT 5;"

# Files directory:
adb shell run-as com.target.app ls -la \
  /data/data/com.target.app/files/
# Download interesting files:
adb pull /data/data/com.target.app/files/tokens.json

# External storage (no root needed):
adb shell ls /sdcard/Android/data/com.target.app/
adb pull /sdcard/Android/data/com.target.app/files/

# Cache:
adb shell run-as com.target.app ls \
  /data/data/com.target.app/cache/

# In Objection:
env                        # shows all app data directories
android filesystem ls /data/data/com.target.app/
android filesystem download /data/data/com.target.app/shared_prefs/user.xml
```

---

#### 10.1.8 Hardcoded Secrets in APK

🔍 **Beyond Java source — secrets hide in resources:**
```bash
# strings.xml and other resource files:
grep -rE "(api_key|apikey|secret|token|password|key|url)" \
  target_decoded/res/values/

# Native libraries (.so files) — strings:
strings target_decoded/lib/arm64-v8a/libnative.so | \
  grep -iE "(key|secret|token|password|http)"

# Assets folder:
find target_decoded/assets/ -type f | xargs grep -lE "(key|secret|password)"
cat target_decoded/assets/config.json

# Google Services JSON (Firebase config):
cat target_decoded/assets/google-services.json
# Contains: Firebase project ID, API key, app IDs
# Test: can this API key be used for unauthorized access?

# Compiled Kotlin metadata:
# JADX handles this — search in JADX output as above

# trufflehog on decompiled source:
trufflehog filesystem target_jadx/ --json > mobile_secrets.json
```

---

### 10.2 iOS

---

#### 10.2.1 IPA Acquisition

🔍 **Getting the IPA file:**
```bash
# Method 1 — From a jailbroken device using frida-ios-dump:
python3 dump.py com.target.app
# Decrypts and dumps the IPA from a running device

# Method 2 — ipatool (Apple ID required):
ipatool download -b com.target.app \
  --purchase                          # purchase (free apps)
# Requires authentication with Apple ID

# Method 3 — From Burp history
# Some apps download their own IPA — intercept and save

# Extract IPA (it's a ZIP):
unzip target.ipa -d target_ipa/
# Main binary in: Payload/Target.app/Target
```

---

#### 10.2.2 Static Analysis

🔍 **Analyzing iOS binaries:**
```bash
# File info:
file target_ipa/Payload/Target.app/Target
# ARM64 Mach-O binary (or FAT binary with multiple archs)

# Strings extraction:
strings target_ipa/Payload/Target.app/Target | grep -iE \
  "(key|secret|token|password|api|https://)"

# class-dump — extracts Objective-C class interfaces:
class-dump -H target_ipa/Payload/Target.app/Target -o headers/
# Review headers/ for: API endpoints, auth logic, data storage methods

# Hopper Disassembler — GUI reverse engineering:
# Open binary in Hopper → decompiles to pseudo-code
# Search for strings, methods, API calls

# MobSF (same as Android — also handles iOS):
# Upload IPA to MobSF → automated static analysis report

# Info.plist — app configuration:
cat target_ipa/Payload/Target.app/Info.plist
# Contains: URL schemes (deep links), permissions, app version, ATS config

# ATS (App Transport Security) config in Info.plist:
# NSAppTransportSecurity: NSAllowsArbitraryLoads = true → HTTP allowed
# Means: app may make unencrypted HTTP requests → traffic interception easier

# Embedded secrets:
find target_ipa/ -name "*.plist" | xargs grep -l \
  -iE "(key|secret|token|password|api)"
find target_ipa/ -name "*.json" | xargs grep -l \
  -iE "(key|secret|token|password|api)"
```

---

#### 10.2.3 Dynamic Analysis — Proxy Setup

🔍 **Intercepting iOS app traffic:**
```bash
# Step 1: Install Burp CA on iOS device
# Burp → Proxy → CA Certificate → Download
# iPhone: Safari → http://burp → download cert
# Settings → General → VPN & Device Management → install cert
# Settings → General → About → Certificate Trust Settings → enable

# Step 2: Configure proxy
# iPhone → Settings → WiFi → your network → Configure Proxy → Manual
# Server: your machine IP, Port: 8080

# Step 3: SSL Pinning bypass with Objection (jailbroken device):
objection -g com.target.app explore
ios sslpinning disable

# SSL Kill Switch 2 (jailbroken device Cydia tweak):
# Installs as a Cydia package → blanket SSL pinning bypass

# Without jailbreak — re-sign IPA with modified trust:
# Use objection's patchipa command:
objection patchipa --source target.ipa
# Re-sign: codesign -f -s "iPhone Developer" target-patched.ipa
# Install: ios-deploy or Xcode
```

---

#### 10.2.4 Keychain and Insecure Storage

🔍 **iOS data storage locations:**
```bash
# Keychain — most secure, but sometimes misused:
# In Objection:
ios keychain dump
# Shows all keychain items stored by the app
# Look for: tokens, passwords, private keys stored without kSecAttrAccessible restrictions

# NSUserDefaults (like SharedPreferences):
ios nsuserdefaults get all
# Often contains: session tokens, user IDs, feature flags

# Core Data / SQLite:
ios filesystem ls
# Find .sqlite files in app Documents/Library folders
ios sqlite connect <path-to-sqlite>
ios sqlite execute query "SELECT * FROM users"

# Property Lists (.plist files):
ios filesystem download <path>/Library/Preferences/com.target.app.plist
# Decode: plutil -convert xml1 com.target.app.plist

# Sensitive data in application screenshots (iOS backgrounding):
# iOS takes a screenshot when app backgrounds
# Path: /var/mobile/Containers/Data/Application/<UUID>/Library/Caches/Snapshots/
# If screenshot contains sensitive data (passwords, tokens) → vulnerability

# Pasteboard leakage:
# In Objection:
ios pasteboard monitor
# Some apps copy sensitive data to clipboard → accessible to other apps
```

---

#### 10.2.5 Deep Link and URL Scheme Abuse (iOS)

🔍 **Same class as Android — different implementation:**
```bash
# Find URL schemes in Info.plist:
grep -A5 "CFBundleURLTypes" \
  target_ipa/Payload/Target.app/Info.plist

# Universal Links (HTTPS deep links):
# Check apple-app-site-association file:
curl -s "https://target.com/.well-known/apple-app-site-association"
# Shows which paths open in the app vs browser

# Test deep links:
# From iOS device/simulator:
xcrun simctl openurl booted "targetapp://reset?token=test"
xcrun simctl openurl booted "targetapp://payment?amount=0.01&currency=USD"

# URL scheme hijacking:
# If URL scheme is not unique (e.g., "fb://" used by multiple apps)
# Malicious app registers same scheme → receives deep link data
# Test: is the scheme generic enough to be registered by another app?
```

---

### 10.3 Common Mobile Findings

---

#### 10.3.1 OWASP Mobile Top 10 — Field Reference

| Risk | What It Means | Where to Look |
|------|--------------|---------------|
| M1: Improper Credential Usage | Hardcoded keys, secrets | Source code, resources, .plist, strings.xml |
| M2: Inadequate Supply Chain | Malicious third-party SDKs | Library dependencies (build.gradle, Podfile) |
| M3: Insecure Auth/Auth | Weak auth tokens, no expiry | Intercepted traffic, token storage |
| M4: Insufficient Input/Output Validation | Injection via deep links, WebViews | Deep link params, WebView URL handling |
| M5: Insecure Communication | No cert pinning, HTTP | Intercepted traffic, ATS config |
| M6: Inadequate Privacy Controls | PII in logs, local storage | adb logcat, storage inspection |
| M7: Insufficient Binary Protections | Debuggable, no obfuscation | Manifest, easy decompilation |
| M8: Security Misconfiguration | Debug mode, excessive permissions | Manifest analysis, exported components |
| M9: Insecure Data Storage | Tokens in SharedPrefs, plain DB | Local storage inspection |
| M10: Insufficient Cryptography | Weak algorithms, hardcoded keys | Source code analysis |

---

#### 10.3.2 API Backend Testing via Mobile Client

🔍 **The mobile app often talks to the same API as the web app — but differently:**
```bash
# After intercepting traffic:
# 1. Map all API endpoints the app calls
#    (many won't be in any public documentation)
# 2. Note: different auth headers? Different API version? Different base URL?
# 3. Test all endpoints from Part 7 — IDOR, mass assignment, auth bypass

# Mobile-specific API patterns:
# Different API version: /api/mobile/v1/ vs /api/v2/
# Mobile-specific endpoints: /api/push-token, /api/device-register
# Less security hardening: mobile API often has fewer restrictions

# Look for:
# Endpoints returning more data than web counterpart
# Endpoints accepting different parameters
# Admin functionality not exposed in web version
# Debug endpoints still active on mobile API (/api/debug, /api/test)
```

---

#### 10.3.3 Firebase and Analytics Key Leakage

🔍 **Google Services JSON contains multiple keys — not all are low-risk:**
```bash
# Find google-services.json in APK:
find target_decoded/ -name "google-services.json"
cat target_decoded/google-services.json

# Fields to test:
# api_key → test if it allows Firebase Auth user enumeration:
curl -s "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<api_key>" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"password123","returnSecureToken":true}'
# If returns idToken → user registration allowed with this key

# api_key → test Firestore access:
curl -s "https://firestore.googleapis.com/v1/projects/<project_id>/databases/(default)/documents/users?key=<api_key>"
# Returns documents → Firestore misconfiguration

# Firebase Auth enumeration:
# POST accounts:createAuthUri with email → response reveals if email is registered
curl -s "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=<api_key>" \
  -d '{"identifier":"victim@gmail.com","continueUri":"https://target.com"}'
# "signinMethods": ["password"] → email registered
# "signinMethods": [] → email not registered → user enumeration
```

---

### Part 10 — Complete Mobile Testing Checklist

```
APK / IPA ACQUISITION
□ Download from APKPure/APKMirror (Android) or ipatool (iOS)
□ Extract from connected device via adb pull / frida-ios-dump

STATIC ANALYSIS
□ APKTool decode → AndroidManifest.xml review
□ JADX decompile → Java source search for secrets and endpoints
□ MobSF automated scan → review full report
□ Manifest: exported components, debuggable flag, backup flag, URL schemes
□ Search source for: API keys, hardcoded credentials, internal URLs
□ Search strings.xml, assets/, .plist files for secrets
□ trufflehog on decompiled source
□ Firebase google-services.json → test api_key permissions

DYNAMIC ANALYSIS SETUP
□ Android: configure proxy, install Burp CA, run apk-mitm or Frida
□ iOS: configure proxy, install Burp CA, SSL Kill Switch or Objection
□ SSL pinning bypass confirmed (Burp sees decrypted traffic)

TRAFFIC ANALYSIS
□ Map all API endpoints observed in traffic
□ Compare to web app API — new endpoints? Different version?
□ Test all discovered endpoints: IDOR, mass assignment, auth bypass
□ Mobile API vs web API: different security controls?

EXPORTED COMPONENTS (Android)
□ List exported activities, services, providers, receivers
□ Launch exported activities directly without auth
□ Query exported content providers
□ Inject parameters via deep links

LOCAL STORAGE
□ Android: SharedPreferences, SQLite DBs, files directory, cache
□ iOS: Keychain dump, NSUserDefaults, Core Data, app screenshots
□ Look for: auth tokens, session IDs, PII, passwords in plain text

DEEP LINKS
□ Find all URL schemes from manifest / Info.plist
□ Test parameter injection: redirect=, url=, token=
□ Test WebView URL handling via deep link → XSS / open redirect
□ Universal Links: apple-app-site-association scope
□ URL scheme hijacking: is scheme unique?

FIREBASE
□ Firebase Realtime Database: project.firebaseio.com/.json → open?
□ google-services.json api_key: user registration open?
□ api_key: Firestore documents accessible?
□ Firebase Auth: email enumeration via createAuthUri
```

📚 **Part 10 Master References:**
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [OWASP Mobile Application Security Testing Guide (MASTG)](https://mas.owasp.org/MASTG/)
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Frida](https://frida.re)
- [Objection](https://github.com/sensepost/objection)
- [apk-mitm](https://github.com/shroudedcode/apk-mitm)
- [JADX](https://github.com/skylot/jadx)
- [APKTool](https://apktool.org)
- [Frida universal SSL bypass](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/)
- [HackTricks — Android](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting)
- [HackTricks — iOS](https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting)

---

