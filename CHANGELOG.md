# CHANGELOG - REDHAVEN

## [v1.2.0] - 2026-02-17

### 🔄 The "Modular Evolution" Release

#### Added

- **Modular Architecture**: Ported 4000+ lines of monolithic bash into **28 independent modules** in `/modules/`.
- **Elite Upgrades (16 Rewrites)**: Complete native bash rewrites for 16 core engines.
- **Audit Resolution (v1.2.0-hotfix)**:
  - **Performance**: Parallelized SSRF engine (20x faster) and optimized Intel scoring loop (single-pass awk).
  - **New Vectors**: Added XXE probing, JWT kid/jku/x5u injection, and Azure/DigitalOcean IMDS support.
  - **OOB Integration**: Global `OOB_DOMAIN` support for blind SSRF, blind XSS, and blind XXE.
  - **Stability**: Fixed a systemic subshell bug that caused `finding_count` to be lost in 4 modules (Logic, BOLA, Rate Limit, OAuth).
  - **Safety**: Fixed `cd` context corruption bug in `bypass403.sh` and added `check_dependency` guards to missing modules.
- **Module Orchestrator**: Lightweight `scanner.sh` that sources modules dynamically.
- **Python Cleanup**: Removed 8 redundant Python scripts, keeping 9 unique engines for specialized tasks.
- **Smart Symlinking**: Dockerfile now automatically symlinks Python modules to `/usr/local/bin`.
- **Phase F — Tool Integrations**:
  - **dirsearch**: Smart category fuzzing Strategy 1B integrated into `fuzzing.sh`.
  - **CMSeeK**: Advanced CMS detection & vulnerability check added to `recon.sh` and `scanner.sh`.
  - **cloud_enum**: Cloud bucket enumeration (S3, Azure, GCP) added to `osint.sh`, Mode 83 and 85.

#### Changed

- **Version Bump**: Major jump to v1.2.0 due to fundamental architectural changes.
- **Improved Portability**: Modules can now be tested and used independently of the main orchestrator.

## [v1.1.2] - 2026-02-17

### 🧠 The "Intelligence Upgrade" Release

#### Added [v1.1.2]

- **Smart Secrets Module**: New Python-based engine (`modules/smart_secrets.py`) with Shannon entropy analysis.
- **Live Key Validation**: Support for validating GitHub, Slack, GCP, Firebase, Telegram, and S3 tokens.
- **IDOR Hunter v2**: HTTP response comparison and smart parameter detection (30+ sensitive names).
- **XSS Engine v2**: DOM XSS scanning with Nuclei and WAF-evasion mode in Dalfox.
- **Unified Secrets Hunter**: Master orchestrator combining smart_secrets, JSLuice, Nuclei, and Gitleaks.

#### Changed [v1.1.2]

- Improved IDOR noise filtering with an expanded list of 70+ excluded parameters.
- Replaced naive `grep` based secret detection with entropy-aware scanning.
- Filtered XSS Informational noise to show only verified [POC] findings.

## [v1.1.0] - 2026-02-15

### 🚀 The "Strategic Jump" Release

#### Added [v1.1.0]

- **Guided Mission Wizard**: New interactive UI in `start.sh` that replaces the complex 46-mode menu for new users.
- **Smart Flag System**: Added composable flags (`--deep`, `--stealth`, `--web-only`, `--no-recon`, `--osint`) passed natively from Bash to Docker.
- **OSINT Recon Module**: Created `modules/osint_recon.py` with 5 capabilities (Google Dorks, SPF/DMARC, Source Maps, Zone Transfer, Email Harvest).
- **Server-Side Injection Engine**: Integrated `wafw00f` for WAF detection, `sqlmap` for deep DB injection, and `ffuf` for LFI/SSTI fuzzing.
- **Automated Mode Pipelines**: Added modes 80-85 for one-click operations (Quick Recon, Vuln Hunt, Secrets Intel, OSINT Intel, Elite Classic, and Red Team Elite).
- **LFI Wordlist**: Added dedicated LFI/Traversal wordlist to Docker build.

#### Changed [v1.1.0]

- **Sequential Reorganization**: All 46+ modes reorganized into fixed ranges (0-9 Recon, 10-17 API, 20-29 Vulns, 30-39 Elite).
- **Red Team Elite**: Moved from Mode 42 to **Mode 85**.
- **Container Logic**: Enhanced environment variable passing from `start.sh` to facilitate smart flag behavior.
- **UI/UX**: Added "Operation Summary" and confirmation step before launching scans.

#### Fixed

- Fixed versioning typos across the codebase.
- Fixed case mapping bugs in `start.sh` menu (modes 30/31 vs 40/41).
- Improved Docker setup for specialized tools like `sqlmap` and `dnspython`.

---

## [v1.0.5] - 2026-02-10

### Stability & Attribution

#### Added [v1.0.5]

- Proper attribution for Mode 44 (Alternative Recon) to **Nelux1**.
- Integrated missing dependencies in Dockerfile for stability.

#### Fixed [v1.0.5]

- Versioning consistency.
- Docker mount permissions.

---

## [v1.0.4] - 2026-02-05

### Nelux1 Integration

#### Added [v1.0.4]

- **Mode 44**: Submagic integration for faster, multi-tool reconnaissance.
- Improved target cleaning logic.

---

## [v1.0.3] - FIRST PUBLIC RELEASE

### First GitHub release

#### Added [v1.0.3]

- CVE Matcher
- GitHub Recon (TruffleHog)
- S3 Bruteforce.

---

## [v1.0.0] - Initial Release

- Core framework with 35+ modules.
- Docker-based orchestration.
