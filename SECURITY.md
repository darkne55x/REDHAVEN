# Security Policy

## ⚠️ Intended Use

**REDHAVEN is designed for AUTHORIZED security testing only.**

This tool is intended for:

- ✅ Bug bounty programs with explicit scope
- ✅ Penetration testing with written authorization
- ✅ Red team exercises with proper contracts
- ✅ Security research on systems you own or have permission to test

**Unauthorized use of this tool is illegal** and violates laws in most jurisdictions, including:

- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act - United Kingdom
- Similar laws worldwide

## 🔒 Responsible Disclosure

If you discover a security vulnerability in **REDHAVEN itself** (not in your targets), please report it responsibly:

### Reporting Process

1. **DO NOT** open a public GitHub issue
2. Email: `frandinosocial@gmail.com` (or create a private security advisory)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Fix timeline**: Depends on severity (critical bugs get priority)
- **Credit**: Security researchers who report responsibly will be credited in release notes

## 🛡️ Security Best Practices

When using REDHAVEN:

### 1. Protect Your API Keys

```bash
# NEVER commit these files:
provider-config.yaml
tokens.txt
.env files
```

### 2. Secure Your Results

```bash
# Results may contain sensitive data
chmod 700 results/
# Encrypt before sharing
tar -czf results.tar.gz results/ && gpg -c results.tar.gz
```

### 3. Docker Security

```bash
# Don't run as root in production
docker run --user 1000:1000 ...

# Limit resources
docker run --memory="4g" --cpus="2" ...
```

### 4. Rate Limiting

- Always respect target's rate limits
- Use `--threads` wisely (default: 25)
- Add delays for sensitive targets

### 5. Scope Compliance

- **ALWAYS** verify target is in-scope before scanning
- Read program rules on HackerOne/Bugcrowd/etc.
- When in doubt, ask program owners

## 📋 Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.3   | :white_check_mark: |
| 1.0.2   | :white_check_mark: |
| < 1.0.0 | :x:                |

## 🚨 Known Security Considerations

### AI Hunter Module

- Sends vulnerability findings to Google Gemini API
- **Risk**: Data leaves your infrastructure
- **Mitigation**: Review findings before sending, use `--no-ai` flag for sensitive targets

### Blind XSS Module

- Requires external callback server (`BLIND_XSS_CALLBACK`)
- **Risk**: Callback logs may expose target info
- **Mitigation**: Use encrypted logs, self-hosted callback server

### TruffleHog GitHub Scanning

- Requires GitHub API token
- **Risk**: Token exposure in logs
- **Mitigation**: Use read-only tokens, rotate regularly

## ⚖️ Legal Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

**THE AUTHORS ARE NOT RESPONSIBLE FOR:**

- Misuse of this tool
- Unauthorized testing
- Damages caused by improper use
- Legal consequences of illegal activities

**BY USING REDHAVEN, YOU AGREE:**

- To use it only for authorized security testing
- To comply with all applicable laws
- To respect target systems and their owners
- That you are solely responsible for your actions

## 📞 Contact

- **General inquiries**: Contact via GitHub Issues
- **Security reports**: `frandinosocial@gmail.com`
- **Author**: Franco Andino ([@darkne55](https://github.com/darkne55x))

---

**Last Updated**: February 2026  
**Version**: 1.0.3
