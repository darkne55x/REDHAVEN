#!/usr/bin/env python3
import sys
import asyncio
import aiohttp
import argparse
import re
import hashlib
from difflib import SequenceMatcher
from urllib.parse import urlparse

# ============================================================================
# RACE CONDITION HUNTER v2.0
# Part of REDHAVEN Framework - INTELLIGENT CONTENT ANALYSIS
# ============================================================================

BANNER = """
   (   (    (    
   )\ ))\\ ) )\\ ) 
  (()/(()/((()/( 
   /(_)/(_))/(_) 
  (_))(_)) (_))  
  | _ \\/ __| |   
  |   / (__||   
  |_|_\\___|_|   Race Condition Hunter v2.0 (Content-Aware)
"""

# Patterns that indicate REAL race condition exploitation
BUSINESS_LOGIC_PATTERNS = {
    'balance': r'(?:balance|amount|credit|funds?)[\s:]*[\$€£]?\s*(\d+(?:\.\d+)?)',
    'quantity': r'(?:quantity|qty|remaining|left|available)[\s:]*(\d+)',
    'status': r'(?:status|state)[\s:]*["\']?(\w+)["\']?',
    'success': r'(?:success|succeeded|completed)',
    'error': r'(?:error|failed|denied|insufficient)',
    'duplicate': r'(?:duplicate|already\s+(?:used|claimed|redeemed))',
    'limit': r'(?:limit\s+exceeded|too\s+many)',
}

def extract_business_values(content):
    """Extract business-critical values from response content."""
    values = {}
    
    for name, pattern in BUSINESS_LOGIC_PATTERNS.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            values[name] = matches if len(matches) > 1 else matches[0]
    
    return values

def normalize_content(content):
    """Remove dynamic elements (timestamps, session IDs, CSRFs) for comparison."""
    # Remove common dynamic patterns
    content = re.sub(r'\d{10,13}', 'TIMESTAMP', content)  # Unix timestamps
    content = re.sub(r'[0-9a-f]{32,64}', 'HASH', content, flags=re.IGNORECASE)  # MD5/SHA hashes
    content = re.sub(r'session[_-]?id["\']?\s*[:=]\s*["\']?[\w-]+', 'SESSION', content, flags=re.IGNORECASE)
    content = re.sub(r'csrf[_-]?token["\']?\s*[:=]\s*["\']?[\w-]+', 'CSRF', content, flags=re.IGNORECASE)
    content = re.sub(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}', 'DATETIME', content)  # ISO datetime
    
    return content

def calculate_content_similarity(content1, content2):
    """Calculate similarity ratio between two content strings."""
    norm1 = normalize_content(content1)
    norm2 = normalize_content(content2)
    return SequenceMatcher(None, norm1, norm2).ratio()

async def send_race_request(session, url, method="GET", data=None, headers=None, request_id=0):
    try:
        if headers:
            headers['X-Race-ID'] = str(request_id)
        
        async with session.request(method, url, data=data, headers=headers, ssl=False, timeout=10) as response:
            content = await response.text()
            content_hash = hashlib.md5(normalize_content(content).encode()).hexdigest()
            
            return {
                "id": request_id,
                "status": response.status,
                "length": len(content),
                "content": content,
                "content_hash": content_hash,
                "business_values": extract_business_values(content),
                "url": url
            }
    except Exception as e:
        return {"id": request_id, "error": str(e)}

def analyze_race_results(results):
    """Intelligent analysis to detect REAL race conditions, not just dynamic content."""
    valid_results = [r for r in results if "error" not in r]
    
    if len(valid_results) < 2:
        return False, "Insufficient valid responses"
    
    # 1. Check for different status codes (excluding normal variations)
    statuses = {r['status'] for r in valid_results}
    if len(statuses) > 1:
        # This is suspicious but not definitive
        print(f"    [!] Multiple status codes: {statuses}")
    
    # 2. Check for content hash diversity (normalized content)
    content_hashes = {r['content_hash'] for r in valid_results}
    if len(content_hashes) == 1:
        return False, "All responses are identical (after normalization)"
    
    # 3. CRITICAL: Check for business logic exploitation indicators
    business_values_sets = [r['business_values'] for r in valid_results]
    
    # Check for balance/quantity changes
    balances = [bv.get('balance') for bv in business_values_sets if 'balance' in bv]
    quantities = [bv.get('quantity') for bv in business_values_sets if 'quantity' in bv]
    
    if len(set(balances)) > 1 and balances:
        print(f"    [!!!] DIFFERENT BALANCES DETECTED: {set(balances)}")
        return True, f"Race condition: Multiple balance values {set(balances)}"
    
    if len(set(quantities)) > 1 and quantities:
        print(f"    [!!!] DIFFERENT QUANTITIES DETECTED: {set(quantities)}")
        return True, f"Race condition: Multiple quantity values {set(quantities)}"
    
    # 4. Check for success/error mixing (very suspicious)
    has_success = any('success' in r['business_values'] for r in valid_results)
    has_error = any('error' in r['business_values'] for r in valid_results)
    
    if has_success and has_error:
        print(f"    [!!!] MIXED SUCCESS/ERROR RESPONSES")
        return True, "Race condition: Some requests succeeded, others failed"
    
    # 5. Check for duplicate detection messages
    duplicate_msgs = [bv.get('duplicate') for bv in business_values_sets if 'duplicate' in bv]
    if len(duplicate_msgs) > 0 and len(duplicate_msgs) < len(valid_results):
        print(f"    [!!!] PARTIAL DUPLICATE DETECTION: {len(duplicate_msgs)}/{len(valid_results)}")
        return True, f"Race condition: {len(valid_results) - len(duplicate_msgs)} requests bypassed duplicate check"
    
    # 6. Content similarity check (low similarity = potential issue)
    if len(valid_results) >= 3:
        similarities = []
        for i in range(len(valid_results)-1):
            sim = calculate_content_similarity(valid_results[i]['content'], valid_results[i+1]['content'])
            similarities.append(sim)
        
        avg_similarity = sum(similarities) / len(similarities)
        print(f"    -> Content similarity: {avg_similarity:.2%}")
        
        if avg_similarity < 0.80:  # Less than 80% similar after normalization
            return True, f"Race condition: Low content similarity ({avg_similarity:.2%})"
    
    return False, "No definitive race condition detected"

async def race_target(url, method="GET", data=None, headers=None, concurrency=20):
    print(f"\n[*] Racing target: {url}")
    print(f"    Concurrency: {concurrency} | Method: {method}")
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        
        for i in range(concurrency):
            tasks.append(send_race_request(session, url, method, data, headers, i))
        
        # Blast all requests simultaneously
        results = await asyncio.gather(*tasks)
        
        # Analyze with intelligent detection
        is_vulnerable, reason = analyze_race_results(results)
        
        if is_vulnerable:
            print(f"    [!!!] VULNERABLE: {reason}")
        else:
            print(f"    [-] Not vulnerable: {reason}")
        
        return is_vulnerable, results

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Intelligent Race Condition Tester with Content Analysis")
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-l", "--list", help="List of URLs")
    parser.add_argument("-c", "--concurrency", type=int, default=15, help="Number of concurrent requests")
    parser.add_argument("-m", "--method", default="GET", help="HTTP Method")
    
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
        print("Usage: race_cond.py -u https://example.com/api/claim -c 20")
        sys.exit(1)
        
    print(f"[*] Loaded {len(targets)} targets.\n")
    
    # Run async loop
    loop = asyncio.get_event_loop()
    
    findings = []
    
    for target in targets:
        is_vuln, results = loop.run_until_complete(race_target(target, args.method, concurrency=args.concurrency))
        if is_vuln:
            findings.append(target)
            
    if findings:
        print("\n" + "="*60)
        print("[+] CONFIRMED RACE CONDITION VULNERABILITIES:")
        print("="*60)
        for f in findings:
            print(f" >> {f}")
    else:
        print("\n[-] No race conditions detected (intelligent analysis).")

if __name__ == "__main__":
    main()
