# REDHAVEN Phase 2B: Advanced Detection Capabilities

## New Elite-Tier Modules

### 1. **Blind XSS Hunter** (`blind_xss.py`)

**Purpose:** Detect XSS in async/hidden contexts (admin panels, emails, logs)

**Features:**

- Callback server integration (Burp Collaborator, Interact.sh, XSS Hunter, custom)
- 8+ payload variants (img onerror, script src, SVG onload, WebSocket, Fetch API)
- Context-aware injection (name, email, message, search, profile fields)
- Automatic parameter fuzzing

**Usage:**

```bash
# Setup callback server first (Interact.sh recommended)
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client  # Get your domain: xxx.interact.sh

# Test target
python3 /usr/local/bin/blind_xss -u https://target.com -c xxx.interact.sh --context message
```

**Why it matters:** Regular XSS scanners miss stored XSS that only executes in admin panels or notification emails.

---

### 2. **PostMessage Analyzer** (`postmessage_analyzer.py`)

**Purpose:** Detect insecure `window.postMessage()` handlers

**Vulnerabilities Detected:**

- Missing origin validation
- `eval()` on message data
- `innerHTML` injection
- `document.write()` abuse
- `window.location` manipulation
- Script tag creation

**Features:**

- Parses all downloaded JS files
- Generates exploit PoC HTML automatically
- Severity classification (CRITICAL/HIGH)

**Usage:**

```bash
# From URL (auto-discovers JS files)
python3 /usr/local/bin/postmessage_analyzer -u https://target.com --generate-poc

# From downloaded JS directory
python3 /usr/local/bin/postmessage_analyzer --js-dir /results/target.com/.temp/js_download --generate-poc
```

**Output:** Creates `postmessage_poc_N.html` files for confirmed vulnerabilities.

---

### 3. **2FA Bypass Tester** (`twofa_bypass.py`)

**Purpose:** Test Multi-Factor Authentication security

**Attack Vectors:**

1. **CSRF on Enrollment** - Enable/disable 2FA without CSRF token
2. **Rate Limiting** - Brute force 6-digit codes (tests 20+ attempts)
3. **Response Manipulation** - Modify JSON `"success": false` → `true`
4. **Code Reuse** - Use same OTP multiple times
5. **Direct Access** - Bypass 2FA by accessing protected pages directly
6. **Weak Backup Codes** - Test predictable backup codes

**Usage:**

```bash
# Full test suite
python3 /usr/local/bin/twofa_bypass -u https://target.com \
  --enrollment /settings/2fa/enable \
  --verify /2fa/verify \
  --protected /dashboard /admin /profile \
  --session "your_session_cookie"

# Test specific vector
python3 /usr/local/bin/twofa_bypass -u https://target.com --verify /2fa/verify
```

**Critical Findings:** Reports CSRF, missing rate limits, client-side validation flaws.

---

### 4. **Swagger Discovery** (`swagger_discovery.py`)

**Purpose:** Automatically find and analyze Swagger/OpenAPI documentation

**Discovery Paths:** Tests 25+ common paths:

- `/swagger.json`, `/api-docs`, `/v2/api-docs` (Spring Boot)
- `/openapi.yaml`, `/docs`, `/redoc`
- Framework-specific paths for Django, Flask, FastAPI, etc.

**Analysis Features:**

- Extract ALL endpoints (paths + methods)
- Identify unauthenticated endpoints
- Flag sensitive keywords (password, token, secret, admin)
- Detect deprecated endpoints
- Generate endpoint wordlist for fuzzing

**Usage:**

```bash
# Discover only
python3 /usr/local/bin/swagger_discovery -u https://api.target.com

# Full analysis + wordlist generation
python3 /usr/local/bin/swagger_discovery -u https://api.target.com \
  --analyze \
  --wordlist /results/swagger_endpoints.txt \
  --output /results/swagger_report.json
```

**Integration:** Wordlist can be fed directly to Feroxbuster, ffuf, or nuclei.

---

## Integration with REDHAVEN Scanner

These tools are available as standalone utilities but can be integrated into future modules:

### Recommended Usage Pattern

```bash
# 1. Run standard reconnaissance
./redhaven.sh -d target.com -m 2

# 2. Extract JS files for PostMessage analysis
python3 /usr/local/bin/postmessage_analyzer --js-dir /results/target.com/.temp/js_download

# 3. Discover Swagger and generate wordlist
python3 /usr/local/bin/swagger_discovery -u https://api.target.com --analyze --wordlist /tmp/api_paths.txt

# 4. Test identified 2FA endpoints
python3 /usr/local/bin/twofa_bypass -u https://target.com --all-tests

# 5. Deploy Blind XSS (monitor callback server)
python3 /usr/local/bin/blind_xss -l /results/target.com/endpoints/params_only.txt -c YOUR.interact.sh
```

---

## Dependencies

All scripts are automatically installed in the Docker image:

- **Python 3** (built-in)
- **aiohttp** - Async HTTP for race conditions
- **websockets** - WebSocket testing
- **pyyaml** - Swagger YAML parsing
- **requests** - HTTP client

---

### 5. **XXE Probe** (`fuzzing.sh` logic)

**Purpose:** Detect XML External Entity vulnerabilities in endpoints accepting XML input.

**Detection Vectors:**

- POST requests with `application/xml` Content-Type.
- Entity expansion for local file read (`/etc/hostname`).
- Blind XXE via DNS callback (Interact.sh support).

---

### 6. **Cloud IMDS Explorer** (`ssrf.sh` logic)

**Purpose:** Detect and exploit SSRF to leak Cloud Metadata.

**Supported Clouds:**

- **AWS**: Instance tags, IAM credentials.
- **GCP**: Project ID, access tokens.
- **Azure**: Subscription ID, VM details via IMDS (`v2021-02-01`).
- **DigitalOcean**: Droplet metadata.

---

## 🌩️ Out-of-Band (OOB) Support

REDHAVEN now supports global callback domains via the `OOB_DOMAIN` environment variable.

- **Blind SSRF**: Injects `http://ssrf.{OOB_DOMAIN}` into parameters.
- **Blind XSS**: Injects script loaders pointing to `${OOB_DOMAIN}`.
- **Blind XXE**: Uses DNS/HTTP callbacks for data exfiltration.

**Usage:**

```bash
docker run -e OOB_DOMAIN=xxx.interact.sh redhaven:latest ...
```

---

### 7. **CMS Detection & Vuln Scan** (`CMSeeK`)

**Purpose:** Advanced CMS identification and version-specific vulnerability scanning.

**Features:**

- Detects 180+ CMS (WordPress, Joomla, Drupal, etc.)
- Version detection and module enumeration
- Integrated into REDHAVEN's decision matrix (Mode 85)
- Standalone execution for targeted audits (Mode 7)

**Usage:**

```bash
# Standalone run
./scanner.sh -d target.com -m 7
```

---

### 8. **Cloud Bucket Enumeration** (`cloud_enum`)

**Purpose:** Enumerate public storage buckets across AWS, Azure, and GCP.

**Features:**

- Intelligent keyword generation from target domain
- Tests S3 buckets, Azure Blobs, and GCP Storage
- Identifies permissions (OPEN/PROTECTED)
- Integrated into OSINT (Mode 83) and Elite (Mode 85) pipelines

**Usage:**

```bash
# Standalone run
./scanner.sh -d target.com -m 46
```

---

### 9. **Smart Category Fuzzing** (`dirsearch` Strategy 1B)

**Purpose:** Targeted fuzzing for sensitive configuration files and backups.

**Features:**

- Complementary to broad directory brute-forcing
- Targeted categories: `conf`, `vcs`, `backups`, `db`, `logs`, `keys`
- Automatically scales threads based on WAF detection or `--stealth` flag
- Integrated into Unified Strategic Fuzzing (Mode 25)
