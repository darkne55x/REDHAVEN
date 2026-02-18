#!/usr/bin/env python3
import sys
import os
import json
import time
from pathlib import Path

# ============================================================================
# DARKNE55 CORRELATION ENGINE V1.2
# ============================================================================

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'
    RESET = '\033[0m'

# ----------------------------------------------------------------------------
# TABLAS DE VALOR Y MULTIPLICADORES
# ----------------------------------------------------------------------------

BOUNTY_TABLE = {
    "CRITICAL": 9000,
    "HIGH": 5500,
    "MEDIUM": 1200,
    "LOW": 300,
    "INFO": 50,
    "403_BYPASS": 2500,
    "CRLF": 1500,
    "REDIRECT": 800,
    "PROTO_POLLUTION": 1800
}

CHAIN_MULTIPLIERS = {
    "oauth_account_takeover": 2.2,
    "ssrf_rce": 2.0,
    "idor_pii": 1.8,
    "graphql_idor": 1.7,
    "crlf_xss": 1.5,          # <-- Ya existía, ahora funcionará
    "graphql_ratelimit": 1.9,
    "oauth_api_bypass": 2.3,
    "cdn_takeover_xss": 1.6,
    "graphql_mutation_idor": 2.1,
    "oauth_token_ssrf": 2.4,
    "bypass_idor": 2.5,
    "bypass_secrets": 2.2,
    "logic_auth_bypass": 2.0,
    "supply_chain_rce": 2.3,
    "full_takeover": 3.0
}

# ----------------------------------------------------------------------------
# UTILIDADES DE ARCHIVOS
# ----------------------------------------------------------------------------

def load_file(path):
    """Carga un archivo en una lista, manejando errores de codificación."""
    if not path.exists():
        return []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        return []

def generate_poc(chain_type, severity):
    poc = f"\n{Colors.DIM}[POC GENERATOR] Suggested steps for {chain_type}:{Colors.RESET}\n"
    
    if "bypass" in chain_type:
        poc += "  1. Intercept request to 403 endpoint.\n"
        poc += "  2. Apply bypass headers (X-Custom-IP-Authorization: 127.0.0.1).\n"
        poc += "  3. Verify 200 OK response.\n"
        poc += "  4. Pivot to sensitive endpoint discovered."
    elif "crlf" in chain_type:
        poc += "  1. Inject %0d%0aSet-Cookie: malicious=true in the parameter.\n"
        poc += "  2. Verify if the cookie is set in the response headers.\n"
        poc += "  3. Escalation: Try XSS via Location header."
    elif "idor" in chain_type:
        poc += "  1. Create two accounts (User A, User B).\n"
        poc += "  2. Observe object ID in User A's request.\n"
        poc += "  3. Replay request with User A's session but User B's ID."
    else:
        poc += "  1. Reproduce the finding manually.\n"
        poc += "  2. Chain with other vulnerabilities to increase impact."
        
    return poc

# ----------------------------------------------------------------------------
# MOTOR DE DETECCIÓN DE CADENAS (CORE LOGIC)
# ----------------------------------------------------------------------------

def detect_chains(findings):
    chains = []
    bonus = 0
    
    successful_bypasses = [l for l in findings['bypass_403'] if "200 OK" in l or "ip-custom-header" in l.lower()]

    # Chain: 403 Bypass -> IDOR
    if successful_bypasses and findings['idor']:
        mult = CHAIN_MULTIPLIERS['bypass_idor']
        impact = BOUNTY_TABLE["CRITICAL"] * (mult - 1)
        chains.append({
            "name": "ACL Bypass to IDOR",
            "desc": "Access controls bypassed allowing access to IDOR endpoints.",
            "severity": "CRITICAL",
            "multiplier": mult,
            "bonus": impact,
            "poc": generate_poc("bypass_idor", "CRITICAL")
        })
        bonus += impact

    # Chain: 403 Bypass -> Secrets
    if successful_bypasses and findings['secrets']:
        mult = CHAIN_MULTIPLIERS['bypass_secrets']
        impact = BOUNTY_TABLE["HIGH"] * (mult - 1)
        chains.append({
            "name": "ACL Bypass to Sensitive Secrets",
            "desc": "Private endpoints exposed secrets after bypass.",
            "severity": "HIGH",
            "multiplier": mult,
            "bonus": impact,
            "poc": generate_poc("bypass_secrets", "HIGH")
        })
        bonus += impact

    # Chain: CRLF -> XSS
    if findings['crlf'] and findings['xss']:
        mult = CHAIN_MULTIPLIERS['crlf_xss']
        impact = BOUNTY_TABLE["HIGH"] * (mult - 1)
        chains.append({
            "name": "CRLF Injection to XSS",
            "desc": "HTTP Response Splitting used to deliver XSS payload.",
            "severity": "HIGH",
            "multiplier": mult,
            "bonus": impact,
            "poc": generate_poc("crlf_xss", "HIGH")
        })
        bonus += impact

    # Chain: OAuth -> Account Takeover
    if findings['oauth_vulns'] and (findings['oauth_tokens'] or findings['oauth_pkce']):
        mult = CHAIN_MULTIPLIERS['oauth_account_takeover']
        impact = BOUNTY_TABLE["CRITICAL"] * (mult - 1)
        chains.append({
            "name": "OAuth Account Takeover",
            "desc": "OAuth misconfiguration combined with token leakage.",
            "severity": "CRITICAL",
            "multiplier": mult,
            "bonus": impact,
            "poc": generate_poc("oauth_ato", "CRITICAL")
        })
        bonus += impact

    # Chain: SSRF -> RCE
    if findings['ssrf'] and findings['secrets']:
        mult = CHAIN_MULTIPLIERS['ssrf_rce']
        impact = BOUNTY_TABLE["CRITICAL"] * (mult - 1)
        chains.append({
            "name": "SSRF to Cloud RCE",
            "desc": "SSRF accessing cloud metadata/secrets leading to execution.",
            "severity": "CRITICAL",
            "multiplier": mult,
            "bonus": impact,
            "poc": generate_poc("ssrf_rce", "CRITICAL")
        })
        bonus += impact

    # Chain: GraphQL -> IDOR
    if findings['graphql'] and findings['idor']:
        mult = CHAIN_MULTIPLIERS['graphql_idor']
        impact = BOUNTY_TABLE["HIGH"] * (mult - 1)
        chains.append({
            "name": "GraphQL Introspection to IDOR",
            "desc": "Schema analysis revealed unchecked mutations/queries.",
            "severity": "HIGH",
            "multiplier": mult,
            "bonus": impact,
            "poc": generate_poc("graphql_idor", "HIGH")
        })
        bonus += impact

    return chains, int(bonus)

# ----------------------------------------------------------------------------
# FUNCIÓN PRINCIPAL
# ----------------------------------------------------------------------------

def analyze_chains(target_dir):
    base_path = Path(target_dir)
    
    print(f"\n{Colors.HEADER}╔════════════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.HEADER}║      DARKNE55 SCANNER - AUTOMATED CORRELATION ENGINE V4.7      ║{Colors.RESET}")
    print(f"{Colors.HEADER}╚════════════════════════════════════════════════════════════════╝{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Target Directory: {target_dir}{Colors.RESET}\n")

    # 1. Carga de datos de vulnerabilidades (Actualizado con CRLF)
    findings = {
        "idor": load_file(base_path / "vulns" / "idor_candidates.txt"),
        "xss": load_file(base_path / "vulns" / "xss.txt"),
        "secrets": load_file(base_path / "secrets" / "js_secrets.txt"),
        "ssrf": load_file(base_path / "vulns" / "ssrf.txt"),
        "bypass_403": load_file(base_path / "vulns" / "bypass_403.txt"),
        "crlf": load_file(base_path / "vulns" / "crlf.txt"),
        "redirect": load_file(base_path / "vulns" / "open_redirect.txt"),      
        "prototype": load_file(base_path / "vulns" / "prototype_pollution.txt"),  
        "graphql": load_file(base_path / "vulns" / "graphql.txt"),
        "oauth_vulns": load_file(base_path / "vulns" / "oauth.txt"),
        "oauth_tokens": load_file(base_path / "vulns" / "oauth.txt"),
        "ratelimit": load_file(base_path / "vulns" / "ratelimit.txt"),
        "supply_chain": load_file(base_path / "vulns" / "supply_chain.txt"),
        "logic": load_file(base_path / "vulns" / "logic.txt"),
        "oauth_pkce": [],
        "cache_poisoning": []
    }

    total_bounty = 0
    report_data = {
        "findings_summary": {},
        "attack_chains": [],
        "financial_impact": {}
    }

    # 2. Análisis Individual y Reporte en CLI
    
    # --- 403 BYPASS ---
    bypasses = [l for l in findings['bypass_403'] if "200 OK" in l or "ip-custom-header" in l.lower()]
    if bypasses:
        count = len(bypasses)
        val = BOUNTY_TABLE["403_BYPASS"]
        total_bounty += val
        print(f"{Colors.GREEN}[+] 403 ACL BYPASS SUCCESS:{Colors.RESET}")
        print(f"    Count: {count} endpoints")
        print(f"    Impact: HIGH (Authentication Bypass)")
        print(f"    Est. Bounty: ${val}")
        report_data["findings_summary"]["403_Bypass"] = {"count": count, "val": val}

    # --- CRLF INJECTION ---
    if findings['crlf']:
        count = len(findings['crlf'])
        val = BOUNTY_TABLE["CRLF"]
        total_bounty += val
        print(f"\n{Colors.WARNING}[!] CRLF INJECTION DETECTED:{Colors.RESET}")
        print(f"    Count: {count} endpoints")
        print(f"    Impact: MEDIUM/HIGH (Header Injection)")
        print(f"    Est. Bounty: ${val}")
        report_data["findings_summary"]["CRLF"] = {"count": count, "val": val}

    # --- IDOR ---
    if findings['idor']:
        count = len(findings['idor'])
        val = BOUNTY_TABLE["HIGH"]
        total_bounty += val
        print(f"\n{Colors.FAIL}[!] IDOR VULNERABILITIES DETECTED:{Colors.RESET}")
        print(f"    Count: {count} potential endpoints")
        print(f"    Impact: HIGH (Unauthorized Access)")
        print(f"    Est. Bounty: ${val}")
        report_data["findings_summary"]["IDOR"] = {"count": count, "val": val}

    # --- SECRETS ---
    if findings['secrets']:
        count = len(findings['secrets'])
        val = BOUNTY_TABLE["CRITICAL"]
        total_bounty += val
        print(f"\n{Colors.FAIL}[!] HARDCODED SECRETS DISCOVERED:{Colors.RESET}")
        print(f"    Count: {count} secrets found")
        print(f"    Impact: CRITICAL (Credential Leakage)")
        print(f"    Est. Bounty: ${val}")
        report_data["findings_summary"]["SECRETS"] = {"count": count, "val": val}

    # --- XSS ---
    if findings['xss']:
        count = len(findings['xss'])
        val = count * BOUNTY_TABLE["MEDIUM"]
        total_bounty += val
        print(f"\n{Colors.WARNING}[!] REFLECTED XSS VERIFIED:{Colors.RESET}")
        print(f"    Count: {count} parameters")
        print(f"    Impact: MEDIUM (Client Side Injection)")
        print(f"    Est. Bounty: ${val}")
        report_data["findings_summary"]["XSS"] = {"count": count, "val": val}

    # --- SSRF ---
    if findings['ssrf']:
        count = len(findings['ssrf'])
        val = BOUNTY_TABLE["HIGH"]
        total_bounty += val
        print(f"\n{Colors.FAIL}[!] SSRF CANDIDATES:{Colors.RESET}")
        print(f"    Count: {count} interactions")
        report_data["findings_summary"]["SSRF"] = {"count": count, "val": val}
        
        
    # --- OPEN REDIRECT ---
    if findings['redirect']:
        count = len(findings['redirect'])
        val = count * BOUNTY_TABLE["REDIRECT"]
        total_bounty += val
        print(f"\n{Colors.WARNING}[!] OPEN REDIRECT DETECTED:{Colors.RESET}")
        print(f"    Count: {count} endpoints")
        print(f"    Impact: MEDIUM (Phishing Vector)")
        print(f"    Est. Bounty: ${val}")
        report_data["findings_summary"]["Open_Redirect"] = {"count": count, "val": val}

    # --- PROTOTYPE POLLUTION ---
    if findings['prototype']:
        count = len(findings['prototype'])
        val = BOUNTY_TABLE["PROTO_POLLUTION"]
        total_bounty += val
        print(f"\n{Colors.FAIL}[!] PROTOTYPE POLLUTION DETECTED:{Colors.RESET}")
        print(f"    Count: {count} endpoints")
        print(f"    Impact: HIGH (Client-Side / DOS)")
        print(f"    Est. Bounty: ${val}")
        report_data["findings_summary"]["Prototype_Pollution"] = {"count": count, "val": val}

    # --- GRAPHQL ---
    if findings['graphql']:
        count = len(findings['graphql'])
        val = BOUNTY_TABLE["HIGH"]
        total_bounty += val
        print(f"\n{Colors.WARNING}[!] GRAPHQL INTROSPECTION:{Colors.RESET}")
        print(f"    Count: {count} endpoints")
        report_data["findings_summary"]["GraphQL"] = {"count": count, "val": val}


    # 3. Detección de Cadenas (Correlation)
    print(f"\n{Colors.BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    print(f"{Colors.BLUE}[*] ANALYZING ATTACK CHAINS & ESCALATION PATHS...{Colors.RESET}")
    
    chains, chain_bonus = detect_chains(findings)
    final_total = total_bounty + chain_bonus

    if chains:
        print(f"{Colors.GREEN}{Colors.BOLD}>>> {len(chains)} CRITICAL CHAIN(S) IDENTIFIED <<<{Colors.RESET}")
        for i, chain in enumerate(chains, 1):
            print(f"\n  {Colors.FAIL}⚡ CHAIN #{i}: {chain['name']} (x{chain['multiplier']}){Colors.RESET}")
            print(f"     Severity: {chain['severity']}")
            print(f"     Description: {chain['desc']}")
            print(f"     Bonus Added: +${chain['bonus']}")
            print(f"{chain['poc']}")
            
        report_data["attack_chains"] = chains
    else:
        print(f"\n{Colors.DIM}[i] No multi-stage attack chains detected in this scan.{Colors.RESET}")

    # 4. Resumen Final y Guardado
    print(f"\n{Colors.BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    print(f"{Colors.BOLD}FINANCIAL IMPACT ASSESSMENT:{Colors.RESET}")
    print(f"  Base Findings Bounty:  {Colors.GREEN}${total_bounty} USD{Colors.RESET}")
    print(f"  Escalation Bonuses:    {Colors.GREEN}+${chain_bonus} USD{Colors.RESET}")
    print(f"  -------------------------------------------")
    print(f"  {Colors.BOLD}TOTAL ESTIMATED PAYOUT: {Colors.FAIL}${final_total} USD{Colors.RESET}")

    report_data["financial_impact"] = {
        "base": total_bounty,
        "bonus": chain_bonus,
        "total": final_total
    }

    # Guardar reporte JSON
    json_path = base_path / "reports" / "correlation_report.json"
    json_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=4)
        print(f"\n{Colors.CYAN}[✓] Detailed JSON report saved to: {json_path}{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Error saving report: {e}{Colors.RESET}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{Colors.FAIL}Usage: correlator.py <target_directory>{Colors.RESET}")
        sys.exit(1)
        
    target_dir = sys.argv[1]
    if os.path.isdir(target_dir):
        analyze_chains(target_dir)
    else:
        print(f"{Colors.FAIL}[!] Error: Target directory '{target_dir}' not found.{Colors.RESET}")
        sys.exit(1)
