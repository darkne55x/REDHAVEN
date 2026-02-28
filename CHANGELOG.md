# CHANGELOG - REDHAVEN

## [1.2.4] - 2026-02-27

### The "Elite AI Analyst" Release

### Added
- **AI Elite Analyst (redhaven-chat.py)**: 
  - New read-only analysis tools: `list_targets`, `analyze_target`, `analyze_finding`, `suggest_next_steps`.
  - The AI now reads results from the `/results/` directory instead of executing bash scripts.
  - Gemini provider now handles large file contexts using `system_instruction` for better analysis.
- **Performance Optimizations (Secrets Module)**:
  - Added strict file limits (max 30 JS files) and timeouts to LinkFinder and JSLuice.
  - Global timeouts added to prevent JS analysis from hanging on large targets.
  - Estimation: JS analysis step is now ~20x faster on bulk targets.

### Changed
- **Recon Cleanup**: Enhanced `clean_targets()` in `recon.sh` with a second-pass garbage filter. Now removes MIME types, tool errors, and invalid characters.
- **Version Unification**: Unified all core modules and scripts to v1.2.4.
- **Documentation**: Completely redesigned `README.md` to reflect the new AI-as-analyst architecture.

### Fixed
- Fixed JS analysis 24-hour hang issue.
- Fixed `redhaven-chat.py` environment issues by moving to a read-only results model.
- Fixed filename mismatches in AI target analysis (supporting dynamic filenames in OSINT/Vulns/Secrets).

## [v1.2.2] - 2026-02-17

### Added
- **Update Toolchain (Option 98)**: New menu option to force a Docker rebuild.
- **Framework Update Check**: Automatically checks GitHub for newer versions.
- **Documentation Overhaul**: Simplified README with "Getting Started" guide.

### Changed
- Refactored `start.sh` menu structure.
- Cleaned hardcoded development paths in modules.

## [1.2.1a] - 2026-02-17

### 🚨 Emergency Stability Fix
- **Fixed**: Robust `httpx` resolution inside Docker.
- **Fixed**: Path mismatches for modular Python scripts.
- **Fixed**: "Double zero" output bug in Subdomain Takeover and IDOR modules.

## [v1.2.1] - 2026-02-17

### 🛡️ The "Security & Stability" Release
- **Strict Input Validation**: Regex-based sanitization for targets in `start.sh`.
- **Stack Detection v2.0**: Enhanced logic in `recon.sh` to detect Cloud Providers, CMS, and Frameworks.

## [v1.2.0] - 2026-02-17

### 🔄 The "Modular Evolution" Release
- **Modular Architecture**: Ported 4000+ lines into **28 independent modules**.
- **Module Orchestrator**: Lightweight `scanner.sh` that sources modules dynamically.
- **OOB Integration**: Global `OOB_DOMAIN` support for blind SSRF, XSS, and XXE.

---

## [v1.1.2] - 2026-02-17
## [v1.1.0] - 2026-02-15
## [v1.0.3] - FIRST PUBLIC RELEASE
## [v1.0.0] - Initial Release
