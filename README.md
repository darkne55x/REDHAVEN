# REDHAVEN v1.0.3 - Advanced Bug Bounty Framework

![Version](https://img.shields.io/badge/version-1.0.3-blue)
![License](https://img.shields.io/badge/license-GPLv3-green)
![Status](https://img.shields.io/badge/status-public-brightgreen)

> **The comprehensive open-source security framework for modern bug bounty hunting.**

---

## 🚀 Introduction

REDHAVEN is a modular, Docker-based security framework designed to automate the reconnaissance and vulnerability discovery process. This **Community Edition (v1.0.3)** provides the core engine and essential modules used by professional red teams.

### Key Differentiators

- ✅ **Intelligent Module Orchestration** - Modules share data and execute in optimal order
- ✅ **Low False Positive Rate** - Content-aware analysis instead of pattern matching
- ✅ **Advanced Attack Vectors** - HTTP Smuggling, BOLA/BFLA, Race Conditions, WebSockets
- ✅ **Hunter's Toolkit** - Automates manual checks (Unicode, Email, Clickjacking, Uploads)
- ✅ **Out-of-Band Detection** - Blind XSS, SSRF with callback integration
- ✅ **API-First Approach** - Automatic Swagger discovery and authorization testing
- ✅ **Client-Side Security** - PostMessage analysis, DOM XSS detection

---

## 📊 Coverage & Capabilities

### Vulnerability Classes (25+)

- OWASP Top 10 (2021)
- OWASP API Security Top 10
- HTTP Protocol Attacks (Smuggling, Cache Poisoning)
- Authentication/Authorization Bypass (2FA, BOLA/BFLA, JWT)
- Client-Side Attacks (XSS, PostMessage, CORS, Clickjacking)
- Input Sanitization Bypass (Unicode Injection, Email Header Injection)
- Infrastructure (S3, Subdomain Takeover, Cloud Misconfig)
- Supply Chain (Dependency Confusion, Backup Files)
- Mobile Security (APK/iOS Analysis)

---

## 🏗️ Architecture

### 35 Sequential Modules

#### **Phase 1: Reconnaissance (1-7)**

1. Recon Pasivo - Subfinder, Gau, Wayback, GitHub/GitLab
2. Visual Recon - Screenshot + tech detection
3. Metadata Hunter - Exiftool analysis
4. Param Mining - Arjun, x8, ParamSpider
5. Deep JS Analysis - JSLuice secrets extraction
6. WordPress Trigger - WPScan automated
7. CMS Detection - Joomla, Drupal, etc.

#### **Phase 2: Discovery (8)**

1. Secrets Hunter - Multi-tool credential scanning

#### **Phase 3: Vulnerabilities (9-18)**

1. IDOR Hunter - Authorization issues
2. XSS Engine - Reflection + DOM vectors
3. SSRF Storm - Out-of-band detection
4. CRLF Scan - Header injection
5. 403 Bypass - Access control circumvention
6. Client Fuzzing - Open Redirect, Prototype Pollution
7. JWT Suite - Token manipulation
8. Logic Flaws - Business logic testing
9. Deep Fuzzing - **Intelligent multi-tool strategy**
10. Dephunter - Supply chain attacks

#### **Phase 4: Infrastructure & Cloud (19-22)**

1. Infrastructure Scan - S3, Azure, GCP Buckets
2. Subdomain Takeover - Dangling CNAME detection
3. GraphQL Deep - Introspection + injection
4. API Rate Limit Bypass - X-Forwarded headers

#### **Phase 5: Advanced OAuth & AI (23-24)**

1. OAuth Analysis - OIDC flow compromise
2. AI Hunter - Gemini-powered analysis

#### **Phase 5: Elite Discovery (25-28)**

1. **Race Conditions v2.0** - Content-aware async testing
2. **WebSocket Hunter v2.0** - 7 attack vectors (XSS, SQLi, CMDi)
3. **Swagger Discovery** - Automatic API documentation
4. **BOLA/BFLA Testing** - API authorization bypass

#### **Phase 5B: Advanced Analysis (29-31)**

1. **PostMessage Analyzer** - DOM XSS + origin validation
2. **Blind XSS Hunter** - Out-of-band callbacks
3. **2FA Bypass Tester** - MFA security assessment

#### **Phase 5C: Elite Security (32-34)**

1. **HTTP Request Smuggling** - CL.TE, TE.CL, TE.TE
2. **CORS Misconfiguration** - 6 bypass techniques
3. **Cache Poisoning** - Web cache + CPDoS attacks

#### **Phase 5C Extension: Hunter's Toolkit (39)**

1. **Hunter's Toolkit** 
    - Unicode Injection (WAF Bypass)
    - Email Header Injection
    - Clickjacking Detection
    - File Upload Discovery

#### **Mobile Security (50-51)**

1. APK Analysis - Android security audit
2. iOS Analysis - iOS .ipa examination

#### **Automation Modes (40-42)**

1. Standard Scan - Fast recon + top vulnerabilities
2. Elite Scan - Full sequential workflow
3. **Red Team Elite** - Intelligent non-linear orchestration

#### **Reporting (99)**

1. Generate Report - Consolidated findings

---

## 🚀 Quick Start

### Build

```bash
docker build -t redhaven:latest .
```

### Run Red Team Elite Mode

```bash
docker run --rm -v $(pwd)/results:/results \
  -e BLIND_XSS_CALLBACK="xxx.interact.sh" \
  redhaven:1.0.3 -d target.com -m 42
```

---

## 🔬 Module Deep Dive: Hunter's Toolkit (v1.0.2)

**Module 39** implements manual bug hunting methodologies often missed by automated scanners:

1. **Unicode Engine:** Injects characters like `¼`, `ﬁ`, `chłodna` into parameters to detect normalization errors or WAF bypasses.
2. **Email Header Injection:** Targets `email`, `subject`, `contact` fields with SMTP payloads (`%0aBcc:`).
3. **Clickjacking:** Checks `X-Frame-Options` and CSP headers.
4. **Upload Hunter:** Crawls for hidden file upload endpoints (`/upload`, `/api/import`).

---

## 📂 Project Structure

REDHAVEN follows a modular, professional open-source structure:

```
REDHAVEN/
├── modules/             # Python security modules (Core logic)
│   ├── ai_hunter.py     # AI analysis engine
│   ├── cve_matcher.py   # CVE detection engine
│   └── ...
├── templates/           # Custom Nuclei templates
├── config/              # Configuration templates
├── docs/                # Documentation
├── scanner.sh           # Main orchestration engine (Bash)
├── start.sh             # User interface & entry point
└── Dockerfile           # Container definition
```

## 🏆 Version History

**v1.0.3 (Current - Community Edition)**
- ✅ CVE Auto-Matching Engine (automated version → CVE correlation)
- ✅ GitHub Deep Recon with TruffleHog (verified secret scanning)
- ✅ S3 Bucket Bruteforce (intelligent permutations for AWS/Azure/GCP)
- ✅ CI/CD Configuration Discovery (pipeline secret exposure)

**v1.0.2 (Previous)**
- Added **Module 39: Hunter's Toolkit**
- 100% Coverage of manual bug hunting checklist

**v1.0.1**
- Added HTTP Smuggling, CORS, Cache Poisoning
- Added Race Conditions, WebSockets, API Discovery, BOLA/BFLA

**v1.0.0 (INITIAL RELEASE PUBLIC)**
- First public release for BETA TEST.
---

## 📜 License

Educational and bug bounty use only. Follow responsible disclosure practices.

---

---

**For detailed technical documentation, see:**

- [Technical Overview](docs/TECHNICAL_OVERVIEW.txt)
- [Advanced Modules](docs/advanced_modules.md)
- [Docker Changes](docs/docker_changelog.md)

**Ready to find critical vulnerabilities? Build and deploy REDHAVEN v1.0.3 now.**
