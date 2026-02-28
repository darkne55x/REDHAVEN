#!/usr/bin/env python3
"""
REDHAVEN Smart Secrets Scanner v1.2.4
=====================================
Intelligent secret detection with entropy analysis, context awareness,
and live key validation. Replaces naive grep-based approaches.

Usage:
    python3 smart_secrets.py --dir /path/to/js_files --output /path/to/output
    python3 smart_secrets.py --file /path/to/single.js
    python3 smart_secrets.py --urls /path/to/js_urls.txt --output /path/to/output
"""

import re
import os
import sys
import json
import math
import hashlib
import argparse
import requests
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse

# ============================================================================
# PATTERN DATABASE — 40+ secret patterns with metadata
# ============================================================================
SECRET_PATTERNS = [
    # ---- AWS ----
    {
        "id": "aws-access-key",
        "name": "AWS Access Key ID",
        "regex": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "severity": "CRITICAL",
        "entropy_min": 3.5,
        "validate": True,
    },
    {
        "id": "aws-secret-key",
        "name": "AWS Secret Access Key",
        "regex": r"(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "CRITICAL",
        "entropy_min": 4.0,
        "validate": False,
        "capture_group": 1,
    },
    # ---- Google / GCP ----
    {
        "id": "gcp-api-key",
        "name": "Google API Key",
        "regex": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "HIGH",
        "entropy_min": 3.5,
        "validate": True,
    },
    {
        "id": "google-oauth-client",
        "name": "Google OAuth Client ID",
        "regex": r"[0-9]+-[a-z0-9]{32}\.apps\.googleusercontent\.com",
        "severity": "MEDIUM",
        "entropy_min": 3.0,
        "validate": False,
    },
    {
        "id": "firebase-url",
        "name": "Firebase Database URL",
        "regex": r"https?://[a-z0-9-]+\.firebaseio\.com",
        "severity": "HIGH",
        "entropy_min": 2.0,
        "validate": True,
    },
    # ---- GitHub ----
    {
        "id": "github-token-classic",
        "name": "GitHub Personal Access Token",
        "regex": r"ghp_[A-Za-z0-9]{36}",
        "severity": "CRITICAL",
        "entropy_min": 4.0,
        "validate": True,
    },
    {
        "id": "github-token-fine",
        "name": "GitHub Fine-grained Token",
        "regex": r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
        "severity": "CRITICAL",
        "entropy_min": 4.0,
        "validate": True,
    },
    {
        "id": "github-oauth",
        "name": "GitHub OAuth Access Token",
        "regex": r"gho_[A-Za-z0-9]{36}",
        "severity": "CRITICAL",
        "entropy_min": 4.0,
        "validate": True,
    },
    # ---- Stripe ----
    {
        "id": "stripe-secret",
        "name": "Stripe Secret Key",
        "regex": r"sk_live_[A-Za-z0-9]{24,}",
        "severity": "CRITICAL",
        "entropy_min": 4.0,
        "validate": False,
    },
    {
        "id": "stripe-publishable",
        "name": "Stripe Publishable Key",
        "regex": r"pk_live_[A-Za-z0-9]{24,}",
        "severity": "LOW",
        "entropy_min": 3.0,
        "validate": False,
    },
    {
        "id": "stripe-restricted",
        "name": "Stripe Restricted Key",
        "regex": r"rk_live_[A-Za-z0-9]{24,}",
        "severity": "HIGH",
        "entropy_min": 4.0,
        "validate": False,
    },
    # ---- Slack ----
    {
        "id": "slack-token",
        "name": "Slack Token",
        "regex": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        "severity": "CRITICAL",
        "entropy_min": 3.5,
        "validate": True,
    },
    {
        "id": "slack-webhook",
        "name": "Slack Webhook URL",
        "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+",
        "severity": "HIGH",
        "entropy_min": 3.0,
        "validate": False,
    },
    # ---- Twilio ----
    {
        "id": "twilio-api-key",
        "name": "Twilio API Key",
        "regex": r"SK[0-9a-fA-F]{32}",
        "severity": "HIGH",
        "entropy_min": 3.5,
        "validate": False,
    },
    # ---- SendGrid ----
    {
        "id": "sendgrid-api-key",
        "name": "SendGrid API Key",
        "regex": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "severity": "HIGH",
        "entropy_min": 4.0,
        "validate": False,
    },
    # ---- Mailgun ----
    {
        "id": "mailgun-api-key",
        "name": "Mailgun API Key",
        "regex": r"key-[0-9a-zA-Z]{32}",
        "severity": "HIGH",
        "entropy_min": 4.0,
        "validate": False,
    },
    # ---- JWT ----
    {
        "id": "jwt-token",
        "name": "JSON Web Token",
        "regex": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.+/=-]{10,}",
        "severity": "HIGH",
        "entropy_min": 4.0,
        "validate": False,
    },
    # ---- Private Keys ----
    {
        "id": "private-key-rsa",
        "name": "RSA Private Key",
        "regex": r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "entropy_min": 0,
        "validate": False,
    },
    {
        "id": "private-key-ec",
        "name": "EC Private Key",
        "regex": r"-----BEGIN EC PRIVATE KEY-----",
        "severity": "CRITICAL",
        "entropy_min": 0,
        "validate": False,
    },
    {
        "id": "private-key-openssh",
        "name": "OpenSSH Private Key",
        "regex": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "severity": "CRITICAL",
        "entropy_min": 0,
        "validate": False,
    },
    # ---- Database ----
    {
        "id": "database-url",
        "name": "Database Connection String",
        "regex": r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mssql|redis|amqp)://[^\s'\"<>]{10,}",
        "severity": "CRITICAL",
        "entropy_min": 3.0,
        "validate": False,
    },
    # ---- Heroku ----
    {
        "id": "heroku-api-key",
        "name": "Heroku API Key",
        "regex": r"(?i)heroku[_-]?api[_-]?key\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?",
        "severity": "HIGH",
        "entropy_min": 3.5,
        "validate": False,
        "capture_group": 1,
    },
    # ---- Square ----
    {
        "id": "square-access-token",
        "name": "Square Access Token",
        "regex": r"sq0atp-[0-9A-Za-z\-_]{22}",
        "severity": "HIGH",
        "entropy_min": 3.5,
        "validate": False,
    },
    {
        "id": "square-oauth-secret",
        "name": "Square OAuth Secret",
        "regex": r"sq0csp-[0-9A-Za-z\-_]{43}",
        "severity": "CRITICAL",
        "entropy_min": 4.0,
        "validate": False,
    },
    # ---- Shopify ----
    {
        "id": "shopify-token",
        "name": "Shopify Access Token",
        "regex": r"shpat_[a-fA-F0-9]{32}",
        "severity": "HIGH",
        "entropy_min": 3.5,
        "validate": False,
    },
    {
        "id": "shopify-shared-secret",
        "name": "Shopify Shared Secret",
        "regex": r"shpss_[a-fA-F0-9]{32}",
        "severity": "CRITICAL",
        "entropy_min": 4.0,
        "validate": False,
    },
    # ---- Azure ----
    {
        "id": "azure-storage-key",
        "name": "Azure Storage Account Key",
        "regex": r"(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[^\s;]{20,}",
        "severity": "CRITICAL",
        "entropy_min": 4.0,
        "validate": False,
    },
    # ---- Telegram ----
    {
        "id": "telegram-bot-token",
        "name": "Telegram Bot Token",
        "regex": r"[0-9]{8,10}:AA[0-9A-Za-z\-_]{33}",
        "severity": "HIGH",
        "entropy_min": 3.5,
        "validate": True,
    },
    # ---- Discord ----
    {
        "id": "discord-bot-token",
        "name": "Discord Bot Token",
        "regex": r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27,}",
        "severity": "HIGH",
        "entropy_min": 4.0,
        "validate": False,
    },
    {
        "id": "discord-webhook",
        "name": "Discord Webhook URL",
        "regex": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
        "severity": "HIGH",
        "entropy_min": 3.0,
        "validate": False,
    },
    # ---- Datadog ----
    {
        "id": "datadog-api-key",
        "name": "Datadog API Key",
        "regex": r"(?i)dd[-_]?api[-_]?key\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
        "severity": "HIGH",
        "entropy_min": 3.5,
        "validate": False,
        "capture_group": 1,
    },
    # ---- New Relic ----
    {
        "id": "newrelic-key",
        "name": "New Relic API Key",
        "regex": r"NRAK-[A-Z0-9]{27}",
        "severity": "HIGH",
        "entropy_min": 3.5,
        "validate": False,
    },
    # ---- Generic patterns ----
    {
        "id": "generic-api-key",
        "name": "Generic API Key Assignment",
        "regex": r"""(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?key|secret[_-]?key|auth[_-]?token|client[_-]?secret|app[_-]?secret)\s*[:=]\s*['"]([a-zA-Z0-9/+=_\-]{20,})['"]\s*[,;]?""",
        "severity": "MEDIUM",
        "entropy_min": 3.8,
        "validate": False,
        "capture_group": 1,
    },
    {
        "id": "generic-password",
        "name": "Hardcoded Password",
        "regex": r"""(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*['"]([^'"]{8,})['"]\s*[,;]?""",
        "severity": "HIGH",
        "entropy_min": 2.5,
        "validate": False,
        "capture_group": 1,
    },
    {
        "id": "bearer-token",
        "name": "Bearer Token in Code",
        "regex": r"""(?i)(?:bearer|authorization)\s*[:=]\s*['\"](?:Bearer\s+)?([A-Za-z0-9._\-/+=]{20,})['\"]""",
        "severity": "HIGH",
        "entropy_min": 4.0,
        "validate": False,
        "capture_group": 1,
    },
    # ---- S3 Buckets ----
    {
        "id": "s3-bucket-url",
        "name": "S3 Bucket URL",
        "regex": r"(?:https?://)?[a-zA-Z0-9.-]+\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com",
        "severity": "MEDIUM",
        "entropy_min": 2.0,
        "validate": True,
    },
    # ---- Algolia ----
    {
        "id": "algolia-admin-key",
        "name": "Algolia Admin API Key",
        "regex": r"(?i)algolia[_-]?(?:admin[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
        "severity": "HIGH",
        "entropy_min": 3.5,
        "validate": False,
        "capture_group": 1,
    },
    # ---- Mapbox ----
    {
        "id": "mapbox-token",
        "name": "Mapbox Access Token",
        "regex": r"pk\.[a-zA-Z0-9]{60,}",
        "severity": "MEDIUM",
        "entropy_min": 4.0,
        "validate": False,
    },
    # ---- Internal URLs / Endpoints ----
    {
        "id": "internal-url",
        "name": "Internal/Staging URL",
        "regex": r"https?://(?:[a-z0-9-]+\.)?(?:internal|staging|dev|preprod|uat|admin|localhost)\.[a-z0-9.-]+",
        "severity": "MEDIUM",
        "entropy_min": 1.0,
        "validate": False,
    },
]


# ============================================================================
# ENTROPY ENGINE
# ============================================================================
def shannon_entropy(data):
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy


# ============================================================================
# CONTEXT ANALYZER — Detect false positives from code context
# ============================================================================
PLACEHOLDER_PATTERNS = re.compile(
    r"(?i)("
    r"your[_-]?api[_-]?key|"
    r"your[_-]?secret|"
    r"your[_-]?token|"
    r"insert[_-]?here|"
    r"replace[_-]?me|"
    r"xxx+|"
    r"placeholder|"
    r"example|"
    r"sample[_-]?key|"
    r"test[_-]?key|"
    r"dummy|"
    r"fake[_-]?key|"
    r"change[_-]?me|"
    r"todo|"
    r"fixme|"
    r"<your|"
    r"\{your|"
    r"put[_-]?your|"
    r"enter[_-]?your|"
    r"fill[_-]?in"
    r")"
)

COMMENT_PATTERNS = re.compile(
    r"(?:"
    r"^\s*//|"        # JS single-line comment
    r"^\s*#|"         # Python/Ruby comment
    r"^\s*/?\*|"      # Block comment
    r"^\s*\*\s|"      # Block comment continuation
    r"<!--"           # HTML comment
    r")"
)


def is_false_positive(match_value, line_context):
    """Determine if a match is likely a false positive based on context."""
    # Check if it's a placeholder
    if PLACEHOLDER_PATTERNS.search(match_value):
        return True, "placeholder_value"
    if PLACEHOLDER_PATTERNS.search(line_context):
        return True, "placeholder_context"

    # Check if it's in a comment
    if COMMENT_PATTERNS.match(line_context.strip()):
        return True, "comment"

    # Check for repeated characters (like "AAAAAAAAAAAAA")
    if len(set(match_value)) <= 3 and len(match_value) > 8:
        return True, "low_uniqueness"

    # Check if it's all zeros or all ones
    if match_value.strip("0") == "" or match_value.strip("1") == "":
        return True, "trivial_value"

    return False, ""


# ============================================================================
# LIVE VALIDATORS
# ============================================================================
def validate_github_token(token):
    """Check if a GitHub token is valid."""
    try:
        r = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {token}"},
            timeout=5
        )
        if r.status_code == 200:
            user = r.json().get("login", "unknown")
            return True, f"ACTIVE (user: {user})"
        elif r.status_code == 401:
            return False, "expired/invalid"
        return False, f"status {r.status_code}"
    except Exception:
        return False, "validation_error"


def validate_slack_token(token):
    """Check if a Slack token is valid."""
    try:
        r = requests.post(
            "https://slack.com/api/auth.test",
            data={"token": token},
            timeout=5
        )
        data = r.json()
        if data.get("ok"):
            team = data.get("team", "unknown")
            return True, f"ACTIVE (team: {team})"
        return False, "invalid"
    except Exception:
        return False, "validation_error"


def validate_gcp_key(key):
    """Check if a Google API key is valid."""
    try:
        r = requests.get(
            f"https://maps.googleapis.com/maps/api/geocode/json?address=1&key={key}",
            timeout=5
        )
        data = r.json()
        if data.get("status") != "REQUEST_DENIED":
            return True, "ACTIVE"
        return False, "denied/invalid"
    except Exception:
        return False, "validation_error"


def validate_firebase_url(url):
    """Check if a Firebase database is publicly accessible."""
    try:
        test_url = url.rstrip("/") + "/.json"
        r = requests.get(test_url, timeout=5)
        if r.status_code == 200 and r.text != "null":
            return True, "PUBLIC_READ"
        elif r.status_code == 401:
            return False, "auth_required"
        return False, "not_accessible"
    except Exception:
        return False, "validation_error"


def validate_telegram_bot(token):
    """Check if a Telegram bot token is valid."""
    try:
        r = requests.get(
            f"https://api.telegram.org/bot{token}/getMe",
            timeout=5
        )
        data = r.json()
        if data.get("ok"):
            bot = data["result"].get("username", "unknown")
            return True, f"ACTIVE (bot: @{bot})"
        return False, "invalid"
    except Exception:
        return False, "validation_error"


def validate_s3_bucket(url):
    """Check if an S3 bucket is publicly accessible."""
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            if "<ListBucketResult" in r.text:
                return True, "PUBLIC_LIST"
            return True, "PUBLIC_ACCESS"
        elif r.status_code == 403:
            return False, "exists_but_private"
        return False, "not_found"
    except Exception:
        return False, "validation_error"


def validate_aws_key(key_id):
    """Lightweight check — AWS keys starting with AKIA are long-term credentials."""
    if key_id.startswith("AKIA"):
        return True, "LONG_TERM_CREDENTIAL (needs secret key to fully validate)"
    elif key_id.startswith("ASIA"):
        return True, "TEMPORARY_CREDENTIAL (STS)"
    return False, "unknown_prefix"


VALIDATORS = {
    "github-token-classic": validate_github_token,
    "github-token-fine": validate_github_token,
    "github-oauth": validate_github_token,
    "slack-token": validate_slack_token,
    "gcp-api-key": validate_gcp_key,
    "firebase-url": validate_firebase_url,
    "telegram-bot-token": validate_telegram_bot,
    "s3-bucket-url": validate_s3_bucket,
    "aws-access-key": validate_aws_key,
}


# ============================================================================
# CORE SCANNER
# ============================================================================
class SmartSecretScanner:
    def __init__(self, validate_live=True):
        self.validate_live = validate_live
        self.findings = []
        self.seen_hashes = set()  # Deduplication

    def scan_content(self, content, source_name="unknown"):
        """Scan text content for secrets."""
        lines = content.split("\n")

        for pattern_def in SECRET_PATTERNS:
            compiled = re.compile(pattern_def["regex"])
            capture_group = pattern_def.get("capture_group", 0)

            for line_num, line in enumerate(lines, 1):
                for match in compiled.finditer(line):
                    # Extract the matched value
                    try:
                        raw_match = match.group(capture_group)
                    except (IndexError, AttributeError):
                        raw_match = match.group(0)

                    if not raw_match or len(raw_match) < 8:
                        continue

                    # Deduplication
                    match_hash = hashlib.md5(
                        f"{pattern_def['id']}:{raw_match}".encode()
                    ).hexdigest()
                    if match_hash in self.seen_hashes:
                        continue
                    self.seen_hashes.add(match_hash)

                    # Entropy check
                    entropy = shannon_entropy(raw_match)
                    if entropy < pattern_def["entropy_min"]:
                        continue

                    # Context analysis
                    is_fp, fp_reason = is_false_positive(raw_match, line)
                    if is_fp:
                        continue

                    # Build finding
                    finding = {
                        "id": pattern_def["id"],
                        "name": pattern_def["name"],
                        "severity": pattern_def["severity"],
                        "value": raw_match,
                        "value_masked": self._mask_value(raw_match),
                        "entropy": round(entropy, 2),
                        "source": source_name,
                        "line": line_num,
                        "context": line.strip()[:200],
                        "validated": False,
                        "validation_result": "not_checked",
                    }

                    # Live validation
                    if (self.validate_live
                            and pattern_def.get("validate")
                            and pattern_def["id"] in VALIDATORS):
                        validator = VALIDATORS[pattern_def["id"]]
                        is_valid, detail = validator(raw_match)
                        finding["validated"] = True
                        finding["validation_result"] = detail
                        if is_valid:
                            # Upgrade severity if validated as active
                            finding["severity"] = "CRITICAL"

                    self.findings.append(finding)

    def scan_file(self, filepath):
        """Scan a single local file."""
        try:
            with open(filepath, "r", errors="ignore") as f:
                content = f.read()
            self.scan_content(content, source_name=filepath)
        except Exception as e:
            print(f"  [!] Error reading {filepath}: {e}", file=sys.stderr)

    def scan_url(self, url):
        """Download and scan a JS file from URL."""
        try:
            r = requests.get(url, timeout=15, headers={
                "User-Agent": "Mozilla/5.0 (compatible; REDHAVEN/1.1)"
            })
            if r.status_code == 200 and len(r.text) > 0:
                self.scan_content(r.text, source_name=url)
        except Exception:
            pass  # Silently skip failed downloads

    def scan_directory(self, dirpath):
        """Recursively scan all files in a directory."""
        for root, _, files in os.walk(dirpath):
            for fname in files:
                fpath = os.path.join(root, fname)
                self.scan_file(fpath)

    def scan_urls_parallel(self, urls, max_workers=20):
        """Download and scan multiple URLs in parallel."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_url, url): url for url in urls}
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    def _mask_value(self, value):
        """Mask a secret value for safe display."""
        if len(value) <= 12:
            return value[:4] + "*" * (len(value) - 4)
        return value[:6] + "..." + value[-4:]

    def get_summary(self):
        """Return severity counts."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def export_json(self, filepath):
        """Export findings as JSON."""
        report = {
            "scanner": "REDHAVEN Smart Secrets v1.1.0",
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "summary": self.get_summary(),
            "findings": self.findings,
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

    def export_txt(self, filepath):
        """Export findings as human-readable text."""
        summary = self.get_summary()
        with open(filepath, "w") as f:
            f.write("=" * 70 + "\n")
            f.write("REDHAVEN Smart Secrets Scanner — Results\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Total: {len(self.findings)} findings\n")
            f.write(f"  CRITICAL: {summary['CRITICAL']}\n")
            f.write(f"  HIGH:     {summary['HIGH']}\n")
            f.write(f"  MEDIUM:   {summary['MEDIUM']}\n")
            f.write(f"  LOW:      {summary['LOW']}\n\n")
            f.write("-" * 70 + "\n\n")

            # Sort by severity
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            sorted_findings = sorted(
                self.findings,
                key=lambda x: severity_order.get(x["severity"], 5)
            )

            for i, finding in enumerate(sorted_findings, 1):
                sev = finding["severity"]
                f.write(f"[{sev}] #{i}  {finding['name']}\n")
                f.write(f"  Value:    {finding['value_masked']}\n")
                f.write(f"  Entropy:  {finding['entropy']}\n")
                f.write(f"  Source:   {finding['source']}\n")
                f.write(f"  Line:     {finding['line']}\n")
                if finding["validated"]:
                    f.write(f"  Status:   {finding['validation_result']}\n")
                f.write(f"  Context:  {finding['context'][:120]}\n")
                f.write("\n")


# ============================================================================
# CLI ENTRYPOINT
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="REDHAVEN Smart Secrets Scanner v1.2.4"
    )
    parser.add_argument("--file", help="Scan a single file")
    parser.add_argument("--dir", help="Scan a directory recursively")
    parser.add_argument("--urls", help="File with URLs to download and scan")
    parser.add_argument("--output", "-o", help="Output directory", default=".")
    parser.add_argument("--no-validate", action="store_true",
                        help="Skip live key validation")
    parser.add_argument("--workers", type=int, default=20,
                        help="Parallel download workers")
    args = parser.parse_args()

    scanner = SmartSecretScanner(validate_live=not args.no_validate)

    print("[*] REDHAVEN Smart Secrets Scanner v1.2.4")
    print("[*] Patterns loaded:", len(SECRET_PATTERNS))

    # Scan based on input mode
    if args.file:
        print(f"[*] Scanning file: {args.file}")
        scanner.scan_file(args.file)
    elif args.dir:
        print(f"[*] Scanning directory: {args.dir}")
        scanner.scan_directory(args.dir)
    elif args.urls:
        with open(args.urls) as f:
            urls = [line.strip() for line in f if line.strip()]
        print(f"[*] Scanning {len(urls)} URLs with {args.workers} workers...")
        scanner.scan_urls_parallel(urls, max_workers=args.workers)
    else:
        parser.print_help()
        sys.exit(1)

    # Output
    summary = scanner.get_summary()
    total = len(scanner.findings)
    print(f"\n[*] Scan complete: {total} findings")
    print(f"    CRITICAL: {summary['CRITICAL']}  HIGH: {summary['HIGH']}  "
          f"MEDIUM: {summary['MEDIUM']}  LOW: {summary['LOW']}")

    if total > 0:
        os.makedirs(args.output, exist_ok=True)
        json_path = os.path.join(args.output, "smart_secrets.json")
        txt_path = os.path.join(args.output, "smart_secrets.txt")
        scanner.export_json(json_path)
        scanner.export_txt(txt_path)
        print(f"[*] Report: {json_path}")
        print(f"[*] Summary: {txt_path}")
    else:
        print("[*] No secrets found.")


if __name__ == "__main__":
    main()
