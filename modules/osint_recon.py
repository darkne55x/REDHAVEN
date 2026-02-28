#!/usr/bin/env python3
"""
REDHAVEN v1.2.4 — OSINT Recon Module
by darkne55

Features:
  1. Google Dorking (automated queries)
  2. SPF/DMARC Analysis (email spoofing check)
  3. Source Map Extraction (.js.map files)
  4. Email Harvesting (from web pages)
  5. DNS Zone Transfer Check
"""

import sys
import os
import re
import json
import time
import subprocess
import urllib.parse
from datetime import datetime

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    import dns.resolver
    import dns.zone
    import dns.query
except ImportError:
    pass

BANNER = """
\033[1;31m
╔══════════════════════════════════════════════════════╗
║   REDHAVEN v1.2.4 — OSINT Recon Module               ║
║   by darkne55                                        ║
╚══════════════════════════════════════════════════════╝
\033[0m"""

# Colors
RED = '\033[1;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
DIM = '\033[2m'
BOLD = '\033[1m'
RESET = '\033[0m'


def log_step(msg):
    print(f"  {BLUE}➥{RESET} {msg}")


def log_success(msg):
    print(f"  {GREEN}✓{RESET} {msg}")


def log_warn(msg):
    print(f"  {YELLOW}⚠{RESET} {DIM}{msg}{RESET}")


def log_finding(severity, msg):
    colors = {
        'CRITICAL': '\033[1;31m',
        'HIGH': '\033[0;31m',
        'MEDIUM': '\033[1;33m',
        'LOW': '\033[0;34m',
        'INFO': '\033[2m'
    }
    color = colors.get(severity, DIM)
    print(f"  {color}[{severity}]{RESET} {msg}")


# ─────────────────────────────────────────────────────────────────────
# 1. GOOGLE DORK GENERATOR
# ─────────────────────────────────────────────────────────────────────
def generate_dorks(domain):
    """Generate targeted Google dork queries for a domain, grouped logically.
    Loads from config/osint_dorks.yaml if available, otherwise uses defaults."""
    
    # Strip protocol and path just in case
    domain = re.sub(r'^https?://', '', domain).split('/')[0]
    
    # Deriving the company name (first part of the root domain)
    parts = domain.split('.')
    company_name = parts[-2] if len(parts) >= 2 else domain

    # Try to load from YAML config
    config_paths = [
        "/config/osint_dorks.yaml",  # Docker path
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "osint_dorks.yaml") # Local path
    ]
    
    dorks = None
    for path in config_paths:
        if os.path.exists(path):
            try:
                import yaml
                with open(path, 'r') as f:
                    data = yaml.safe_load(f)
                    if data and "dorks" in data:
                        # Replace placeholders
                        dorks = {}
                        for category, queries in data["dorks"].items():
                            dorks[category] = [q.replace("{domain}", domain).replace("{company_name}", company_name) for q in queries]
                        break
            except ImportError:
                log_warn(f"Python 'yaml' package not found. Using default hardcoded dorks.")
                break # Don't try other paths if yaml is missing
            except Exception as e:
                log_warn(f"Failed to load user dorks config {path}: {e}")

    # Fallback if config isn't found
    if not dorks:
        dorks = {
            "1. Archivos Sensibles Agrupados": [
                f'site:{domain} ext:env | ext:sql | ext:log | ext:conf | ext:bak | ext:inc | ext:ini | ext:sh | ext:bz2',
                f'site:{domain} ext:xml | ext:json | ext:yml | ext:yaml | ext:properties | ext:csv | ext:db',
                f'site:{domain} ext:pem | ext:key | ext:cert | ext:crt | ext:pkcs12 | ext:pfx | ext:p12',
                f'site:{domain} ext:doc | ext:docx | ext:odt | ext:pdf | ext:xls | ext:xlsx | ext:ppt | ext:pptx',
            ],
            "2. Credenciales y Secretos": [
                f'site:{domain} intext:"password" | intext:"API_KEY" | intext:"secret" ext:txt | ext:log | ext:md',
                f'site:{domain} "BEGIN RSA PRIVATE KEY" | "BEGIN OPENSSH PRIVATE KEY" | "BEGIN PGP PRIVATE KEY BLOCK"',
                f'site:{domain} intext:"Authorization: Bearer" | intext:"access_token"',
                f'site:{domain} ext:ovpn intext:"client"',
                f'site:{domain} "DB_PASSWORD" | "DB_USERNAME" | "amazonaws.com"',
                f'site:pastebin.com "{domain}" | "password" | "secret"',
            ],
            "3. Paneles de Administración (Login/Auth)": [
                f'site:{domain} inurl:admin | inurl:login | inurl:dashboard | inurl:portal',
                f'site:{domain} inurl:wp-admin | inurl:cpanel | inurl:auth',
                f'site:{domain} intitle:"Admin Login" | intitle:"Dashboard" | intitle:"Control Panel"',
                f'site:{domain} intitle:"gitlab" | intitle:"jenkins" | intitle:"grafana" | intitle:"kibana"',
            ],
            "4. Exposición de Infraestructura y Directorios": [
                f'site:{domain} intitle:"index of" | intitle:"directory listing"',
                f'site:{domain} inurl:.git/HEAD | inurl:.svn/entries',
                f'site:{domain} inurl:server-status | inurl:phpinfo',
                f'site:{domain} "Index of /wp-content/uploads/cv"',
                f'site:{domain} inurl:swagger-ui | inurl:api-docs',
            ],
            "5. Errores y Fugas de Información": [
                f'site:{domain} "Fatal error" | "Warning:" | "Stack trace:" | "Exception:"',
                f'site:{domain} "SQL syntax near" | "mysql_fetch" | "ORA-"',
                f'site:{domain} "Index of /" "parent directory"',
            ],
            "6. Terceros (3rd Party / SaaS / Cloud)": [
                f'site:postman.com "{company_name}" | "{domain}"',
                f'site:linktr.ee "{company_name}"',
                f'site:genial.ly "{company_name}"',
                f'site:trello.com "{company_name}" | "{domain}"',
                f'site:s3.amazonaws.com "{company_name}" | "{domain}"',
                f'site:github.com "{domain}" "password" | "db_password"',
                f'site:atlassian.net "{company_name}"',
                f'site:bitbucket.org "{company_name}"',
            ],
            "7. Redes Sociales y Empleados (Email/Contactos)": [
                f'site:linkedin.com/in "* @{domain}"',
                f'site:{domain} "contact" | "email" | "phone"',
            ],
            "8. Shodan & Inteligencia Externa": [
                f'site:shodan.io ssl:"{domain}" | "{company_name}"',
                f'site:shodan.io "{domain}" http.html:"admin"',
                f'site:search.censys.io "{domain}"'
            ]
        }
    return dorks

def _load_platform_dorks(domain, section_key):
    """Load a specific dorks section (shodan_dorks, censys_dorks) from YAML config."""
    domain = re.sub(r'^https?://', '', domain).split('/')[0]
    parts = domain.split('.')
    company_name = parts[-2] if len(parts) >= 2 else domain

    config_paths = [
        "/config/osint_dorks.yaml",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "osint_dorks.yaml")
    ]
    for path in config_paths:
        if os.path.exists(path):
            try:
                import yaml
                with open(path, 'r') as f:
                    data = yaml.safe_load(f)
                    if data and section_key in data:
                        result = {}
                        for category, queries in data[section_key].items():
                            result[category] = [q.replace("{domain}", domain).replace("{company_name}", company_name) for q in queries]
                        return result
            except Exception:
                pass
    return {}


def run_google_dorks(domain, output_dir):
    """Save dork queries to file for manual use in markdown format with clickable links.
    Includes Google, Shodan, and Censys dorks with platform-specific clickable URLs."""
    log_step("Phase 1: Google Advanced Dorking Arsenal...")
    dorks_dict = generate_dorks(domain)
    shodan_dict = _load_platform_dorks(domain, "shodan_dorks")
    censys_dict = _load_platform_dorks(domain, "censys_dorks")
    
    total_google = sum(len(q) for q in dorks_dict.values())
    total_shodan = sum(len(q) for q in shodan_dict.values())
    total_censys = sum(len(q) for q in censys_dict.values())
    total_all = total_google + total_shodan + total_censys
    
    txt_file = os.path.join(output_dir, "osint_google_dorks.txt")
    md_file = os.path.join(output_dir, "osint_google_dorks.md")
    
    with open(txt_file, 'w') as txt, open(md_file, 'w') as md:
        txt.write(f"# REDHAVEN OSINT — Dork Arsenal for {domain}\n")
        txt.write(f"# Generated: {datetime.now().isoformat()}\n")
        txt.write(f"# Total dorks: {total_all} (Google: {total_google} | Shodan: {total_shodan} | Censys: {total_censys})\n\n")
        
        md.write(f"# 🎯 OSINT Dork Arsenal: `{domain}`\n\n")
        md.write(f"**Total:** {total_all} dorks — Google: {total_google} | Shodan: {total_shodan} | Censys: {total_censys}\n\n")
        md.write(f"> Haz clic en los enlaces para abrir la búsqueda directo en cada plataforma.\n\n")
        
        # ── Google Dorks ──
        md.write("---\n# 🔍 Google Dorks\n\n")
        txt.write("═══ GOOGLE DORKS ═══\n\n")
        for category, queries in dorks_dict.items():
            txt.write(f"### {category} ###\n")
            md.write(f"## {category}\n")
            for dork in queries:
                url_encoded = urllib.parse.quote_plus(dork)
                url = f"https://www.google.com/search?q={url_encoded}"
                txt.write(f"{dork}\n")
                md.write(f"- [ ] [`{dork}`]({url})\n")
            txt.write("\n")
            md.write("\n")

        # ── Shodan Dorks ──
        if shodan_dict:
            md.write("---\n# 🛰️ Shodan Dorks (Nativos)\n\n")
            txt.write("═══ SHODAN DORKS ═══\n\n")
            for category, queries in shodan_dict.items():
                txt.write(f"### {category} ###\n")
                md.write(f"## {category}\n")
                for dork in queries:
                    url_encoded = urllib.parse.quote_plus(dork)
                    url = f"https://www.shodan.io/search?query={url_encoded}"
                    txt.write(f"{dork}\n")
                    md.write(f"- [ ] [`{dork}`]({url})\n")
                txt.write("\n")
                md.write("\n")

        # ── Censys Dorks ──
        if censys_dict:
            md.write("---\n# 🔬 Censys Dorks (Nativos)\n\n")
            txt.write("═══ CENSYS DORKS ═══\n\n")
            for category, queries in censys_dict.items():
                txt.write(f"### {category} ###\n")
                md.write(f"## {category}\n")
                for dork in queries:
                    url_encoded = urllib.parse.quote_plus(dork)
                    url = f"https://search.censys.io/search?resource=hosts&q={url_encoded}"
                    txt.write(f"{dork}\n")
                    md.write(f"- [ ] [`{dork}`]({url})\n")
                txt.write("\n")
                md.write("\n")
            
    log_success(f"Generated {total_all} elite Dorks → osint_google_dorks.md (CLICKABLE!)")
    if total_shodan:
        log_success(f"  ├─ {total_shodan} Shodan queries (links directos a shodan.io)")
    if total_censys:
        log_success(f"  └─ {total_censys} Censys queries (links directos a search.censys.io)")
    
    # If dorks_hunter is available, run it
    if os.path.exists("/usr/local/bin/dorks_hunter") or _cmd_exists("dorks_hunter"):
        log_step("Running dorks_hunter for automated results...")
        try:
            subprocess.run(
                ["dorks_hunter", "-d", domain, "-o", os.path.join(output_dir, "dorks_hunter_results.txt")],
                timeout=120, capture_output=True
            )
            log_success("dorks_hunter completed.")
        except Exception:
            log_warn("dorks_hunter failed or timed out.")
    
    return total_all


# ─────────────────────────────────────────────────────────────────────
# 2. SPF/DMARC ANALYSIS
# ─────────────────────────────────────────────────────────────────────
def check_spf_dmarc(domain, output_dir):
    """Check SPF and DMARC DNS records for email spoofing risk."""
    log_step("Phase 2: SPF/DMARC Email Security Analysis...")
    
    findings = []
    
    try:
        # SPF Check
        spf_record = None
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith('v=spf1'):
                    spf_record = txt
                    break
        except Exception:
            pass
        
        if spf_record is None:
            findings.append({
                'type': 'SPF',
                'severity': 'HIGH',
                'detail': f'No SPF record found for {domain}. Email spoofing is possible.',
                'record': 'MISSING'
            })
            log_finding('HIGH', f'No SPF record found for {domain}')
        else:
            findings.append({
                'type': 'SPF',
                'severity': 'INFO',
                'detail': f'SPF record found: {spf_record}',
                'record': spf_record
            })
            log_success(f"SPF record found: {spf_record[:80]}...")
            
            # Check for weak SPF
            if '+all' in spf_record:
                findings.append({
                    'type': 'SPF',
                    'severity': 'CRITICAL',
                    'detail': 'SPF uses +all (allows any IP to send mail). Complete bypass!',
                    'record': spf_record
                })
                log_finding('CRITICAL', 'SPF uses +all — allows ANY IP to send email!')
            elif '~all' in spf_record:
                findings.append({
                    'type': 'SPF',
                    'severity': 'MEDIUM',
                    'detail': 'SPF uses ~all (soft fail). Some mail servers may accept spoofed emails.',
                    'record': spf_record
                })
                log_finding('MEDIUM', 'SPF uses ~all (soft fail) — may allow spoofing')
            elif '?all' in spf_record:
                findings.append({
                    'type': 'SPF',
                    'severity': 'MEDIUM',
                    'detail': 'SPF uses ?all (neutral). No enforcement.',
                    'record': spf_record
                })
                log_finding('MEDIUM', 'SPF uses ?all (neutral) — no enforcement')
        
        # DMARC Check
        dmarc_record = None
        try:
            answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if 'v=DMARC1' in txt:
                    dmarc_record = txt
                    break
        except Exception:
            pass
        
        if dmarc_record is None:
            findings.append({
                'type': 'DMARC',
                'severity': 'HIGH',
                'detail': f'No DMARC record found for {domain}. Email spoofing protection is missing.',
                'record': 'MISSING'
            })
            log_finding('HIGH', f'No DMARC record found for {domain}')
        else:
            findings.append({
                'type': 'DMARC',
                'severity': 'INFO',
                'detail': f'DMARC record found: {dmarc_record}',
                'record': dmarc_record
            })
            log_success(f"DMARC record found: {dmarc_record[:80]}...")
            
            # Check DMARC policy
            if 'p=none' in dmarc_record:
                findings.append({
                    'type': 'DMARC',
                    'severity': 'MEDIUM',
                    'detail': 'DMARC policy is p=none (monitoring only). No emails are rejected.',
                    'record': dmarc_record
                })
                log_finding('MEDIUM', 'DMARC policy is p=none — monitoring only, no rejection')
        
    except Exception as e:
        log_warn(f"DNS lookup error: {e}")
    
    # Save results
    output_file = os.path.join(output_dir, "osint_email_security.json")
    with open(output_file, 'w') as f:
        json.dump({'domain': domain, 'findings': findings}, f, indent=2)
    
    log_success(f"Email security analysis saved → osint_email_security.json")
    return findings


# ─────────────────────────────────────────────────────────────────────
# 3. SOURCE MAP EXTRACTION
# ─────────────────────────────────────────────────────────────────────
def extract_source_maps(domain, output_dir, js_urls_file=None):
    """Check for exposed .js.map files that leak source code."""
    log_step("Phase 3: JavaScript Source Map Extraction...")
    
    js_urls = []
    
    # Try to read JS URLs from recon data
    if js_urls_file and os.path.exists(js_urls_file):
        with open(js_urls_file, 'r') as f:
            js_urls = [line.strip() for line in f if line.strip().endswith('.js')]
    
    # Also try common JS paths
    common_paths = [
        f"https://{domain}/main.js",
        f"https://{domain}/app.js",
        f"https://{domain}/bundle.js",
        f"https://{domain}/vendor.js",
        f"https://{domain}/static/js/main.js",
        f"https://{domain}/assets/js/app.js",
    ]
    js_urls.extend(common_paths)
    js_urls = list(set(js_urls))[:50]  # Dedupe, cap at 50
    
    source_maps_found = []
    
    for js_url in js_urls:
        map_url = js_url + '.map'
        try:
            resp = requests.head(map_url, timeout=5, verify=False, allow_redirects=True)
            if resp.status_code == 200:
                content_type = resp.headers.get('Content-Type', '')
                content_length = int(resp.headers.get('Content-Length', 0))
                if content_length > 100:  # Avoid empty/error responses
                    source_maps_found.append({
                        'url': map_url,
                        'size': content_length,
                        'content_type': content_type
                    })
                    log_finding('HIGH', f'Source map exposed: {map_url} ({content_length} bytes)')
        except Exception:
            continue
    
    # Save results
    output_file = os.path.join(output_dir, "osint_source_maps.json")
    with open(output_file, 'w') as f:
        json.dump({'domain': domain, 'source_maps': source_maps_found}, f, indent=2)
    
    if source_maps_found:
        log_success(f"Found {len(source_maps_found)} exposed source maps → osint_source_maps.json")
    else:
        log_warn("No exposed source maps found.")
    
    return source_maps_found


# ─────────────────────────────────────────────────────────────────────
# 4. DNS ZONE TRANSFER CHECK
# ─────────────────────────────────────────────────────────────────────
def check_zone_transfer(domain, output_dir):
    """Check if DNS zone transfer (AXFR) is allowed."""
    log_step("Phase 4: DNS Zone Transfer (AXFR) Check...")
    
    findings = []
    
    try:
        # Get nameservers
        ns_records = dns.resolver.resolve(domain, 'NS')
        nameservers = [str(ns).rstrip('.') for ns in ns_records]
        
        for ns in nameservers:
            try:
                log_step(f"  Testing zone transfer on {ns}...")
                # Resolve NS to IP
                ns_ip = str(dns.resolver.resolve(ns, 'A')[0])
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
                
                if zone:
                    records = []
                    for name, node in zone.nodes.items():
                        records.append(str(name))
                    
                    findings.append({
                        'nameserver': ns,
                        'ip': ns_ip,
                        'severity': 'CRITICAL',
                        'records_count': len(records),
                        'sample_records': records[:20]
                    })
                    log_finding('CRITICAL', f'Zone transfer ALLOWED on {ns}! ({len(records)} records leaked)')
            except Exception:
                log_success(f"Zone transfer denied on {ns} ✓")
    
    except Exception as e:
        log_warn(f"Could not resolve nameservers: {e}")
    
    # Save results
    output_file = os.path.join(output_dir, "osint_zone_transfer.json")
    with open(output_file, 'w') as f:
        json.dump({'domain': domain, 'findings': findings}, f, indent=2)
    
    return findings


# ─────────────────────────────────────────────────────────────────────
# 5. EMAIL HARVESTING
# ─────────────────────────────────────────────────────────────────────
def harvest_emails(domain, output_dir):
    """Extract emails from web pages and common sources."""
    log_step("Phase 5: Email Harvesting...")
    
    emails_found = set()
    
    # Check common pages
    pages_to_check = [
        f"https://{domain}",
        f"https://{domain}/contact",
        f"https://{domain}/about",
        f"https://{domain}/team",
        f"https://{domain}/impressum",
        f"https://{domain}/privacy",
        f"https://{domain}/humans.txt",
        f"https://{domain}/security.txt",
        f"https://{domain}/.well-known/security.txt",
    ]
    
    email_regex = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    
    for page in pages_to_check:
        try:
            resp = requests.get(page, timeout=8, verify=False, 
                              headers={'User-Agent': 'Mozilla/5.0 (compatible; REDHAVEN/1.2.0)'})
            if resp.status_code == 200:
                found = email_regex.findall(resp.text)
                for email in found:
                    if domain in email or not any(x in email for x in ['example.com', 'test.com', 'localhost']):
                        emails_found.add(email.lower())
        except Exception:
            continue
    
    # Save results
    output_file = os.path.join(output_dir, "osint_emails.txt")
    with open(output_file, 'w') as f:
        f.write(f"# REDHAVEN OSINT — Emails for {domain}\n")
        f.write(f"# Found: {len(emails_found)}\n\n")
        for email in sorted(emails_found):
            f.write(f"{email}\n")
    
    if emails_found:
        log_success(f"Found {len(emails_found)} email addresses → osint_emails.txt")
        for email in list(emails_found)[:5]:
            log_finding('INFO', f'Email: {email}')
        if len(emails_found) > 5:
            log_step(f"  ... and {len(emails_found) - 5} more")
    else:
        log_warn("No emails found.")
    
    return emails_found


# ─────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────
def _cmd_exists(cmd):
    return subprocess.run(["which", cmd], capture_output=True).returncode == 0


# ─────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <domain> <output_dir>")
        sys.exit(1)
    
    domain = sys.argv[1]
    output_dir = sys.argv[2]
    
    print(BANNER)
    print(f"  {BOLD}Target:{RESET} {domain}")
    print(f"  {BOLD}Output:{RESET} {output_dir}")
    print()
    
    os.makedirs(output_dir, exist_ok=True)
    
    total_findings = 0
    
    # 1. Google Dorks
    try:
        dork_count = run_google_dorks(domain, output_dir)
        total_findings += dork_count
    except Exception as e:
        log_warn(f"Google Dork phase failed: {e}")
    
    # 2. SPF/DMARC
    try:
        spf_findings = check_spf_dmarc(domain, output_dir)
        total_findings += len([f for f in spf_findings if f['severity'] != 'INFO'])
    except Exception as e:
        log_warn(f"SPF/DMARC phase failed: {e}")
    
    # 3. Source Maps
    try:
        js_urls_file = os.path.join(os.path.dirname(output_dir), "recon", "urls.txt")
        source_maps = extract_source_maps(domain, output_dir, js_urls_file)
        total_findings += len(source_maps)
    except Exception as e:
        log_warn(f"Source map phase failed: {e}")
    
    # 4. DNS Zone Transfer
    try:
        zone_findings = check_zone_transfer(domain, output_dir)
        total_findings += len(zone_findings)
    except Exception as e:
        log_warn(f"Zone transfer phase failed: {e}")
    
    # 5. Email Harvesting
    try:
        emails = harvest_emails(domain, output_dir)
        total_findings += len(emails)
    except Exception as e:
        log_warn(f"Email harvesting phase failed: {e}")
    
    print()
    log_success(f"OSINT Recon completed. Total intelligence items: {total_findings}")
    print()


if __name__ == '__main__':
    main()
