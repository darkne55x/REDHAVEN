#!/usr/bin/env python3
"""
CORS Misconfiguration Tester - REDHAVEN Framework
Tests for dangerous CORS configurations
"""

import sys
import argparse
import requests
from typing import Dict, List

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  CORS MISCONFIGURATION TESTER                            ║
║  Part of REDHAVEN Framework v1.2                         ║
╚══════════════════════════════════════════════════════════╝
"""

class CORSTester:
    def __init__(self, url: str):
        self.url = url
        self.findings = []
    
    def test_null_origin(self) -> bool:
        """Test if null origin is reflected."""
        print(f"[*] Testing null origin reflection")
        
        headers = {'Origin': 'null'}
        
        try:
            response = requests.get(self.url, headers=headers, timeout=5)
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            
            if acao == 'null':
                self.findings.append({
                    'type': 'NULL_ORIGIN_REFLECTED',
                    'severity': 'HIGH',
                    'description': 'Null origin is reflected in ACAO header',
                    'header': acao
                })
                print(f"    [!] NULL origin reflected: {acao}")
                return True
        except Exception as e:
            print(f"    [-] Error: {e}")
        
        return False
    
    def test_arbitrary_origin(self) -> bool:
        """Test if arbitrary origins are reflected."""
        print(f"[*] Testing arbitrary origin reflection")
        
        test_origins = [
            'https://evil.com',
            'https://attacker.com',
            'http://localhost'
        ]
        
        for origin in test_origins:
            headers = {'Origin': origin}
            
            try:
                response = requests.get(self.url, headers=headers, timeout=5)
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == origin:
                    severity = 'CRITICAL' if acac == 'true' else 'HIGH'
                    
                    self.findings.append({
                        'type': 'ARBITRARY_ORIGIN_REFLECTED',
                        'severity': severity,
                        'description': f'Arbitrary origin {origin} is reflected',
                        'credentials': acac == 'true',
                        'header': acao
                    })
                    print(f"    [!] Origin {origin} reflected (credentials: {acac})")
                    return True
            except Exception as e:
                pass
        
        return False
    
    def test_subdomain_wildcard(self) -> bool:
        """Test if subdomains are automatically trusted."""
        print(f"[*] Testing subdomain wildcard")
        
        # Extract domain from URL
        from urllib.parse import urlparse
        parsed = urlparse(self.url)
        base_domain = parsed.netloc
        
        test_subdomains = [
            f"evil.{base_domain}",
            f"attacker.{base_domain}",
            f"test.{base_domain}"
        ]
        
        for subdomain in test_subdomains:
            headers = {'Origin': f'https://{subdomain}'}
            
            try:
                response = requests.get(self.url, headers=headers, timeout=5)
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                
                if subdomain in acao:
                    self.findings.append({
                        'type': 'SUBDOMAIN_WILDCARD',
                        'severity': 'MEDIUM',
                        'description': f'Subdomain {subdomain} automatically trusted',
                        'header': acao
                    })
                    print(f"    [!] Subdomain trusted: {subdomain}")
                    return True
            except Exception as e:
                pass
        
        return False
    
    def test_pre_domain_bypass(self) -> bool:
        """Test pre-domain bypass (domain.com.evil.com)."""
        print(f"[*] Testing pre-domain bypass")
        
        from urllib.parse import urlparse
        parsed = urlparse(self.url)
        base_domain = parsed.netloc
        
        malicious_origin = f"https://{base_domain}.evil.com"
        headers = {'Origin': malicious_origin}
        
        try:
            response = requests.get(self.url, headers=headers, timeout=5)
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            
            if malicious_origin in acao:
                self.findings.append({
                    'type': 'PRE_DOMAIN_BYPASS',
                    'severity': 'HIGH',
                    'description': f'Pre-domain bypass successful with {malicious_origin}',
                    'header': acao
                })
                print(f"    [!] Pre-domain bypass: {malicious_origin}")
                return True
        except Exception as e:
            print(f"    [-] Error: {e}")
        
        return False
    
    def test_post_domain_bypass(self) -> bool:
        """Test post-domain bypass (evil.comdomain.com)."""
        print(f"[*] Testing post-domain bypass")
        
        from urllib.parse import urlparse
        parsed = urlparse(self.url)
        base_domain = parsed.netloc
        
        malicious_origin = f"https://evil.com{base_domain}"
        headers = {'Origin': malicious_origin}
        
        try:
            response = requests.get(self.url, headers=headers, timeout=5)
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            
            if malicious_origin in acao:
                self.findings.append({
                    'type': 'POST_DOMAIN_BYPASS',
                    'severity': 'HIGH',
                    'description': f'Post-domain bypass successful with {malicious_origin}',
                    'header': acao
                })
                print(f"    [!] Post-domain bypass: {malicious_origin}")
                return True
        except Exception as e:
            pass
        
        return False
    
    def test_wildcard_with_credentials(self) -> bool:
        """Test if wildcard (*) is used with credentials."""
        print(f"[*] Testing wildcard with credentials")
        
        try:
            response = requests.get(self.url, timeout=5)
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*' and acac == 'true':
                self.findings.append({
                    'type': 'WILDCARD_WITH_CREDENTIALS',
                    'severity': 'CRITICAL',
                    'description': 'Wildcard ACAO with credentials enabled (invalid but dangerous)',
                    'header': acao
                })
                print(f"    [!!!] Wildcard with credentials detected")
                return True
        except Exception as e:
            print(f"    [-] Error: {e}")
        
        return False

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="CORS Misconfiguration Tester")
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-l', '--list', help='File with URLs to test')
    
    args = parser.parse_args()
    
    urls = []
    if args.list:
        with open(args.list, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        urls = [args.url]
    
    all_findings = []
    
    for url in urls:
        print(f"\n[*] Testing: {url}")
        print("="*70)
        
        tester = CORSTester(url)
        
        # Run all tests
        tester.test_null_origin()
        tester.test_arbitrary_origin()
        tester.test_subdomain_wildcard()
        tester.test_pre_domain_bypass()
        tester.test_post_domain_bypass()
        tester.test_wildcard_with_credentials()
        
        all_findings.extend(tester.findings)
    
    # Report
    print("\n" + "="*70)
    if all_findings:
        critical = [f for f in all_findings if f['severity'] == 'CRITICAL']
        high = [f for f in all_findings if f['severity'] == 'HIGH']
        medium = [f for f in all_findings if f['severity'] == 'MEDIUM']
        
        print(f"[+] FOUND {len(all_findings)} CORS MISCONFIGURATIONS")
        print("="*70)
        
        if critical:
            print(f"\n[!!!] CRITICAL ({len(critical)}):")
            for f in critical:
                print(f"  >> {f['type']}: {f['description']}")
        
        if high:
            print(f"\n[!] HIGH ({len(high)}):")
            for f in high:
                print(f"  >> {f['type']}: {f['description']}")
        
        if medium:
            print(f"\n[!] MEDIUM ({len(medium)}):")
            for f in medium:
                print(f"  >> {f['type']}: {f['description']}")
    else:
        print("[-] No CORS misconfigurations detected")
    
    print("="*70)

if __name__ == '__main__':
    main()
