# REDHAVEN Changelog

All notable changes to the REDHAVEN Bug Bounty Framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.3] - 2026-02-07

### Added

#### 1. CVE Auto-Matching Engine (`cve_matcher.py`)

- **Automatic version detection** from httpx tech-detect output
- **CVE database correlation** for detected technologies
- **Automated Nuclei execution** with matched CVE templates
- Supports: WordPress, Joomla, Drupal, Apache, nginx, PHP, MySQL, IIS, Tomcat, jQuery, React, Angular, Laravel, Django, Rails, Spring, ASP.NET
- Output: `vulns/cve_matched.txt`
- **Integration**: Executes automatically in Phase 6 (Infrastructure Scan) after visual recon

#### 2. GitHub Deep Recon with TruffleHog

- **Verified secret scanning** in public repositories using TruffleHog v3
- **Automatic organization detection** from target domain
- **JSON and human-readable output** formats
- Detects: API keys, tokens, credentials, database URLs, private keys
- Output: `secrets/github_deep.json`, `secrets/github_deep.txt`
- **Integration**: Executes in Phase 1 (Passive Recon) when tokens.txt is available

#### 3. S3 Bucket Bruteforce Engine (`s3_bruteforce.py`)

- **Intelligent bucket name permutations** (20+ patterns)
- **Multi-cloud support**: AWS S3, Azure Blob Storage, GCP Storage
- **Permission detection**: public read, public write, exists (private)
- Patterns include: prod/dev/staging suffixes, resource types, domain variations
- **Concurrent testing** with configurable threads
- Output: `vulns/s3_bruteforce.txt`
- **Integration**: Executes in Phase 6 (Infrastructure Scan)

#### 4. CI/CD Configuration Discovery

- **Comprehensive wordlist** for pipeline configs
- Detects: `.gitlab-ci.yml`, `.github/workflows/*`, `Jenkinsfile`, `azure-pipelines.yml`, `.circleci/config.yml`, `.drone.yml`, `.travis.yml`, and more
- **HTTP status validation** with httpx
- Critical for finding **hardcoded secrets in pipeline configurations**
- Output: `vulns/cicd_exposure.txt`
- **Integration**: Executes in Phase 4 (Metadata Hunter)

### Changed

- **scanner.sh**: Updated version to 1.0.3
- **start.sh**: Updated version to 1.0.3 in header and banner
- **README.md**: Updated version badges and feature list
- **TECHNICAL_OVERVIEW.txt**: Added v1.0.3 section documenting new modules

### Dependencies

- **New Required**: `trufflehog` (for GitHub secret scanning)
- **New Required**: `jq` (for JSON parsing)
- **New Optional**: `nuclei-templates` (auto-updates via Nuclei)

### Integration Points

All new features integrate seamlessly into existing automation modes:

- **Mode 40** (Standard): Executes all 4 features
- **Mode 41** (Elite): Full integration
- **Mode 42** (Red Team Elite): Complete coverage

**No new modes were added** - all features work within existing workflow.

### Performance Impact

- **Execution time**: +5-10 minutes on average scan (depending on target size)
- **API calls**: TruffleHog requires GitHub token (free tier sufficient)
- **Network**: S3 bruteforce generates ~50-200 HTTP requests per target

### Files Modified

```
scanner.sh           (+130 lines)  - Integrated all 4 modules
start.sh             (version bump) - Updated to 1.0.3
README.md            (feature list) - Added v1.0.3 notes
cve_matcher.py       (NEW)          - 550 lines
s3_bruteforce.py     (NEW)          - 363 lines
CHANGELOG.md         (NEW)          - This file
```

### Verification

To verify the upgrade worked correctly:

```bash
# Check version
./start.sh  # Should show "REDHAVEN 1.0.3"

# Test CVE matcher
python3 cve_matcher.py /results/test-target

# Test S3 bruteforce
python3 s3_bruteforce.py example.com

# Run full scan and verify new output files
./start.sh
# Check for:
# - results/target/vulns/cve_matched.txt
# - results/target/secrets/github_deep.txt
# - results/target/vulns/s3_bruteforce.txt
# - results/target/vulns/cicd_exposure.txt
```

---

## [1.0.2] - 2026-02-05

### Added

- **Module 39: Hunter's Toolkit**
  - Unicode injection testing
  - Email header injection
  - Clickjacking detection
  - File upload discovery
- Comprehensive manual bug hunting coverage

### Changed

- Enhanced logging for CRLF scan
- Improved module correlation
- Updated correlator.py with CRLF support

---

## [1.0.1] - 2026-02-03

### Added

- 34 sequential security testing modules
- Docker-based architecture
- AI Hunter with Gemini integration
- Correlation engine with financial impact estimation

### Features

- OWASP Top 10 (2021) coverage: 100%
- OWASP API Security Top 10 coverage: 100%
- Advanced modules: HTTP Smuggling, WebSocket testing, BOLA/BFLA
- Content-aware race condition testing
- PostMessage analyzer
- 3 automation modes (Standard, Elite, Red Team Elite)

---


## Future Roadmap

### (Planned)

- Amass integration for subdomain enumeration
- ShuffleDNS for DNS bruteforce
- Framework-specific triggers (Laravel, Django, Rails)
- Mass assignment testing for APIs

### (Planned)

- WAF detection and bypass automation
- HTML/PDF report generation
- Enhanced mobile security testing (MobSF integration)

---

**For detailed technical documentation, see:**

- [TECHNICAL_OVERVIEW.txt](TECHNICAL_OVERVIEW.txt)
- [README.md](README.md)
- [redhaven_critical_review.md](redhaven_critical_review.md) (in artifacts)
