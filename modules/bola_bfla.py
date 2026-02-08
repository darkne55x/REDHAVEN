#!/usr/bin/env python3
"""
BOLA/BFLA Tester - REDHAVEN Framework
Broken Object Level Authorization & Broken Function Level Authorization
Tests API endpoints for authorization bypass vulnerabilities
"""

import sys
import argparse
import requests
import json
import re
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  BOLA/BFLA TESTER - API Authorization Testing           ║
║  Part of REDHAVEN Framework v1.2                         ║
╚══════════════════════════════════════════════════════════╝
"""

class BOLABFLATester:
    def __init__(self, urls_file: str):
        self.urls_file = urls_file
        self.session = requests.Session()
        self.findings = []
    
    def extract_ids(self, url: str) -> List[str]:
        """Extract potential object IDs from URL."""
        ids = []
        
        # Numeric IDs in path
        path_ids = re.findall(r'/(\d+)(?:/|$)', urlparse(url).path)
        ids.extend(path_ids)
        
        # UUID-like patterns
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        uuids = re.findall(uuid_pattern, url, re.IGNORECASE)
        ids.extend(uuids)
        
        # IDs in query parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for key in ['id', 'user_id', 'object_id', 'item_id', 'order_id']:
            if key in params:
                ids.extend(params[key])
        
        return ids
    
    def test_bola(self, url: str) -> List[Dict]:
        """Test for Broken Object Level Authorization."""
        print(f"[*] Testing BOLA: {url}")
        
        findings = []
        ids = self.extract_ids(url)
        
        if not ids:
            return findings
        
        for original_id in ids:
            # Test ID manipulation
            test_ids = self.generate_test_ids(original_id)
            
            for test_id in test_ids:
                test_url = url.replace(str(original_id), str(test_id))
                
                try:
                    response = self.session.get(test_url, timeout=5)
                    
                    # BOLA vulnerability: accessing other user's data
                    if response.status_code == 200:
                        findings.append({
                            'type': 'BOLA',
                            'severity': 'HIGH',
                            'url': test_url,
                            'original_id': original_id,
                            'manipulated_id': test_id,
                            'description': f'Can access object {test_id} by manipulating {original_id}'
                        })
                        print(f"    [!] BOLA: Accessed {test_id} (status 200)")
                
                except Exception as e:
                    pass
        
        return findings
    
    def generate_test_ids(self, original_id: str) -> List:
        """Generate test IDs based on original ID type."""
        test_ids = []
        
        try:
            # Numeric ID
            num_id = int(original_id)
            test_ids.extend([
                num_id - 1,
                num_id + 1,
                1,
                999999,
                0,
                -1
            ])
        except ValueError:
            # String/UUID ID
            if '-' in original_id:  # UUID-like
                test_ids.append('00000000-0000-0000-0000-000000000001')
            else:
                test_ids.append('admin')
                test_ids.append('test')
        
        return test_ids
    
    def test_bfla(self, url: str) -> List[Dict]:
        """Test for Broken Function Level Authorization."""
        print(f"[*] Testing BFLA: {url}")
        
        findings = []
        
        # Detect admin/privileged endpoints
        admin_indicators = ['admin', 'delete', 'update', 'edit', 'manage', 'config']
        
        if not any(indicator in url.lower() for indicator in admin_indicators):
            return findings
        
        # Test without authentication
        try:
            response = self.session.get(url, timeout=5)
            
            if response.status_code in [200, 201, 204]:
                findings.append({
                    'type': 'BFLA',
                    'severity': 'CRITICAL',
                    'url': url,
                    'description': 'Admin/privileged endpoint accessible without proper authorization'
                })
                print(f"    [!!!] BFLA: Admin endpoint accessible (status {response.status_code})")
        
        except Exception as e:
            pass
        
        # Test HTTP method bypass
        methods = ['PUT', 'DELETE', 'PATCH']
        for method in methods:
            try:
                response = self.session.request(method, url, timeout=5)
                
                if response.status_code in [200, 201, 204]:
                    findings.append({
                        'type': 'BFLA_METHOD_BYPASS',
                        'severity': 'HIGH',
                        'url': url,
                        'method': method,
                        'description': f'Privileged {method} method accessible'
                    })
                    print(f"    [!] BFLA: {method} method accessible")
            
            except Exception as e:
                pass
        
        return findings
    
    def test_api_endpoints(self):
        """Test all endpoints from file."""
        print(f"[*] Loading endpoints from: {self.urls_file}")
        
        with open(self.urls_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        print(f"[*] Testing {len(urls)} endpoints...")
        print("="*70)
        
        for url in urls:
            # Test BOLA
            bola_findings = self.test_bola(url)
            self.findings.extend(bola_findings)
            
            # Test BFLA
            bfla_findings = self.test_bfla(url)
            self.findings.extend(bfla_findings)
        
        return self.findings

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="BOLA/BFLA API Authorization Tester")
    parser.add_argument('-l', '--list', required=True, help='File with API endpoints')
    parser.add_argument('-o', '--output', help='Output file for findings')
    
    args = parser.parse_args()
    
    tester = BOLABFLATester(args.list)
    findings = tester.test_api_endpoints()
    
    # Report
    print("\n" + "="*70)
    if findings:
        critical = [f for f in findings if f['severity'] == 'CRITICAL']
        high = [f for f in findings if f['severity'] == 'HIGH']
        
        print(f"[+] FOUND {len(findings)} AUTHORIZATION VULNERABILITIES")
        print("="*70)
        
        if critical:
            print(f"\n[!!!] CRITICAL ({len(critical)}):")
            for f in critical:
                print(f"  >> {f['type']}: {f['url']}")
                print(f"     {f['description']}")
        
        if high:
            print(f"\n[!] HIGH ({len(high)}):")
            for f in high:
                print(f"  >> {f['type']}: {f['url']}")
                print(f"     {f['description']}")
        
        # Save to file
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(findings, f, indent=2)
            print(f"\n[+] Findings saved to: {args.output}")
    else:
        print("[-] No BOLA/BFLA vulnerabilities detected")
    
    print("="*70)

if __name__ == '__main__':
    main()
