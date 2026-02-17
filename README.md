# REDHAVEN v1.2.0 - Intelligent Offensive Framework

![Version](https://img.shields.io/badge/version-1.2.0-red?style=for-the-badge)
![License](https://img.shields.io/badge/license-GPLv3-green?style=for-the-badge)
![Status](https://img.shields.io/badge/status-Elite_Red_Team_Edition-black?style=for-the-badge)

> **The Modular Evolution: 16 Elite Upgrades & Independent Module Engine.**

---

## 🛡️ v1.2.0: The Modular & Performance Evolution

Version 1.2.0 is a fundamental architectural overhaul and a massive performance upgrade. We transitioned from a monolith to a module system while fixing systemic bottlenecks and expanding the attack surface.

### ⚡ Performance & Stability

- **Parallel Execution**: Rewrote core engines (SSRF) to use `parallel` for 20x speed gains.
- **Single-Pass Analysis**: Optimized Intelligence scoring from expensive sequential loops to single-pass `awk` processing.
- **Subshell Bug Resolution**: Fixed a critical systemic bug that caused missing finding counts in Logic, BOLA, Rate Limit, and OAuth modules.

### 🎯 Expanded Attack Surface

- **OOB Discovery**: Global `OOB_DOMAIN` support for blind SSRF/XSS/XXE callbacks.
- **New Vectors**: Integrated XXE probing, JWT `kid`/`jku`/`x5u` injection, and Azure/DigitalOcean IMDS payloads.
- **Cloud Hardening**: Added specific checks for multi-cloud metadata exfiltration.

| Architecture | Detection | Elite Logic |
| --- | --- | --- |
| **CORS v2** | **Swagger v2** | **Race Conditions v2** |
| **Smuggling v2** | **CMSeeK (CMS) v1** | **WebSockets v2** |
| **BOLA/BFLA v2** | **JWT Attack v2** | **GraphQL Deep v2** |
| **OAuth v2** | **SSRF Storm v2** | **IDOR v2** |
| **XSS v2** | **Logic Flaws v2** | **Client Fuzzing v2** |
| **API Limit v2** | **XXE Probe v1** | **Cloud Enum v1** |

---

## 💎 v1.1.2: The Intelligence Upgrade

Version 1.1.2 introduces high-fidelity vulnerability detection, drastically reducing false positives through intelligent verification engines and AST-based analysis.

### 🧠 Smart Secrets Module

A custom Python orchestrator (`smart_secrets.py`) that brings professional-grade detection:

- **Shannon Entropy Analysis**: Rejects placeholder noise and common strings.
- **Expert Regex Patterns**: 40+ precision patterns for Cloud keys, JWTs, and secrets.
- **Live Key Validation**: Automatically confirms if tokens (GitHub, Slack, etc.) are active.
- **Context Awareness**: Intelligently skips comments and code examples.

### 🔒 IDOR Hunter v2.0

Replaced regex-only detection with a behavioral verification engine:

- **Sensitive Parameter Focus**: Targets 30+ object reference names (user_id, account_id).
- **HTTP Verification**: Automatically modifies IDs (±1) and compares response integrity.
- **Noise Compression**: Aggressively filters 70+ non-vulnerable parameters.

### ⚡ XSS Engine v2.0

Advanced injection pipeline with DOM coverage:

- **DOM XSS Integration**: Nuclei-driven AST analysis on JavaScript files.
- **WAF Evasion**: Native Dalfox integration with --waf-evasion mode in deep scans.
- **POC Resolution**: Automatically filters Informational noise to highlight verified findings.

---

## 🧙‍♂️ v1.1.0: The Strategic Jump

Version 1.1.0 introduced the main framework overhaul, featuring:

- **Guided Mission Wizard**: Interactive UI for 6 high-level missions.
- **Smart Flag System**: Composable flags (`--deep`, `--stealth`, `--web-only`, `--no-recon`, `--osint`).
- **OSINT Recon Module**: Deep intelligence gathering on targets.
- **Deep Injection Engine**: Unified SQLMap/FFUF/TPLMap pipeline.
- **🔢 Sequential Organization**: All 46+ modules reorganized into intuitive, sequential ranges (0-9 Recon, 10-17 Secrets/API, 20-29 Vulns, 30-39 Elite Security, 50-51 Mobile).

---

## 📊 Coverage & Capabilities

### **Phase 1: Reconnaissance (0-7)**

1. **Passive Recon** - Subfinder, Gau, Wayback, GitHub
2. **Active Recon** - Port scan + Crawling + Surface Mapping
3. **Visual Recon** - Automated screenshots
4. **Param Mining** - Deep parameter discovery
5. **Port Scan** - Service discovery
6. **Alternate Recon** - Nelux1/Submagic integration
7. **CMS Detection** - CMSeeK Batch Analysis
8. **OSINT Intelligence** - Dorks, Emails, SPF/DMARC

### **Phase 2: Secrets & API (10-17)**

1. **Secrets Hunter** - Key/Token extraction
2. **Metadata Hunter** - Sensitive file analysis
3. **Backup Discovery** - .bak, .old, .zip exposure
4. **Swagger Discovery** - API documentation harvesting
5. **GraphQL Deep** - Introspection & Injection
6. **JWT Suite** - Token manipulation
7. **OAuth Analysis** - Flow compromise
8. **AI Hunter** - Gemini-powered intelligence

### **Phase 3: Vulnerabilities (20-29)**

1. **XSS Engine** - Reflection & DOM vectors
2. **SSRF Storm** - Out-of-band detection
3. **CRLF Scan** - Header injection
4. **IDOR Hunter** - Auth logic abuse
5. **Client-Side Fuzzing** - Redirects & Proto Pollution
6. **Deep Injection Engine** - SQLi, SSTI, LFI (Deep Mode)
7. **403 Bypass** - Access control evasion
8. **Logic Flaws** - Business logic testing
9. **Supply Chain** - Dependency exposure
10. **Cloud Enum** - S3/Azure/GCP Bucket discovery (Mode 46)

### **Phase 4: Elite Security (30-39)**

1. **HTTP Smuggling** - CL.TE/TE.CL
2. **CORS Testing** - Misconfiguration audit
3. **Cache Poisoning** - CPDoS & poisoning
4. **Race Conditions** - Async logic abuse
5. **WebSocket Hunter** - WS/WSS discovery
6. **BOLA/BFLA** - API authorization testing
7. **PostMessage Analysis** - Cross-origin security
8. **Hunter's Toolkit** - Unicode, Email, Clickjacking

### **Phase 5: Automated Missions (80-85)**

- **[80] Quick Recon**
- **[81] Vulnerability Hunt**
- **[82] Secrets & API Intel**
- **[83] OSINT Intelligence**
- **[84] Elite Classic**
- **[85] RED TEAM ELITE (Full Assault)**

---

## 🏗️ Architecture & Quick Start

### Build

```bash
docker build -t redhaven:latest .
```

### Guided Launch

```bash
./start.sh
```

### CLI Mastery (Pro)

```bash
# Full stealth injection hunt with OSINT
./start.sh -d target.com -m 81 --deep --stealth --osint
```

---

## 🏆 Version History

| Version | Milestone |
| --- | --- |
| **v1.2.0** | **Modular Evolution**: Monolith split into 28 modules, 16 Elite rewrites, Phase F integrations (dirsearch, CMSeeK, cloud_enum). |
| **v1.1.2** | **Intelligence Upgrade**: Smart Secrets, IDOR v2, XSS v2, Entropy Filtering. |
| **v1.1.0** | **Strategic Jump**: Wizard, Smart Flags, OSINT, Deep Injections, Mode Reorg. |
| **v1.0.5** | Versioning fix, container stability, attribution update (Nelux1). |
| **v1.0.4** | Nelux1 Recon (Automatic + RECinverso) integration. |
| **v1.0.3** | First Public Release, now with CVE Matcher, GitHub Recon (TruffleHog), S3 Bruteforce. |
| **v1.0.2** | Module 39: Hunter's Toolkit (Manual Check Automation). |
| **v1.0.1** | Advance Attack Suite (Smuggling, Race, WebSockets, JWT). |
| **v1.0.0** | First Official Release. |

---

## 📜 License

Educational and authorized bug bounty use only. Respect the target's scope and legal requirements.

**Ready to find critical vulnerabilities? Launch REDHAVEN v1.2.0 now.**
