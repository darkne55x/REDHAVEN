#!/usr/bin/env python3
"""
REDHAVEN v1.0.3 - S3 Bucket Bruteforce Engine
Generates intelligent bucket name permutations and tests cloud storage access
"""

import sys
import os
import requests
import concurrent.futures
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from urllib.parse import urlparse

# ============================================================================
# COLORS
# ============================================================================

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class BucketInfo:
    """Cloud bucket information"""
    name: str
    provider: str  # s3, azure, gcp
    url: str
    status: str  # public_read, public_write, exists, not_found
    response_code: int
    content_preview: str = ""

# ============================================================================
# BUCKET NAME GENERATION
# ============================================================================

def generate_bucket_permutations(domain: str) -> List[str]:
    """
    Generate intelligent bucket name permutations from domain
    
    Example: example.com → 
        - example, example-prod, prod-example
        - example-dev, dev-example
        - example.com, examplecom, www-example-com
    """
    # Extract base name
    base = domain.replace('https://', '').replace('http://', '')
    base = base.split('/')[0]  # Remove path
    base = base.replace('www.', '')
    
    # Remove TLD for some variations
    base_no_tld = base.split('.')[0] if '.' in base else base
    base_no_dots = base.replace('.', '')
    base_with_dashes = base.replace('.', '-')
    
    # Environment suffixes
    env_suffixes = [
        'prod', 'production',
        'dev', 'development',
        'staging', 'stage', 'stg',
        'test', 'testing',
        'backup', 'backups', 'bak',
        'qa', 'uat',
        'demo',
        'tmp', 'temp',
    ]
    
    # Resource types
    resource_types = [
        'assets', 'static', 'media', 'images', 'img',
        'files', 'uploads', 'data',
        'logs', 'log',
        'cdn', 'content',
        'public', 'private',
        'archive', 'storage',
        'app', 'web', 'api',
    ]
    
    permutations = set()
    
    # Base variations
    permutations.add(base_no_tld)
    permutations.add(base_no_dots)
    permutations.add(base_with_dashes)
    permutations.add(base)
    permutations.add(f"www-{base_with_dashes}")
    
    # Environment combinations
    for env in env_suffixes:
        permutations.add(f"{base_no_tld}-{env}")
        permutations.add(f"{env}-{base_no_tld}")
        permutations.add(f"{base_no_tld}.{env}")
        permutations.add(f"{base_no_dots}{env}")
    
    # Resource type combinations
    for resource in resource_types:
        permutations.add(f"{base_no_tld}-{resource}")
        permutations.add(f"{resource}-{base_no_tld}")
        permutations.add(f"{base_no_tld}{resource}")
    
    # Company name variations (if domain has multiple parts)
    parts = base.split('.')
    if len(parts) > 1:
        company = parts[0]
        permutations.add(company)
        for env in ['prod', 'dev', 'staging']:
            permutations.add(f"{company}-{env}")
    
    return sorted(list(permutations))

# ============================================================================
# CLOUD PROVIDER TESTING
# ============================================================================

def test_s3_bucket(bucket_name: str, timeout: int = 5) -> Optional[BucketInfo]:
    """Test AWS S3 bucket existence and permissions"""
    urls = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
    ]
    
    for url in urls:
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=False)
            
            # Determine status
            if response.status_code == 200:
                status = "public_read"
                preview = response.text[:500] if response.text else ""
            elif response.status_code == 403:
                # Bucket exists but access denied
                if "AccessDenied" in response.text:
                    status = "exists"
                else:
                    continue
                preview = ""
            elif response.status_code == 404:
                continue
            else:
                status = f"status_{response.status_code}"
                preview = ""
            
            return BucketInfo(
                name=bucket_name,
                provider="s3",
                url=url,
                status=status,
                response_code=response.status_code,
                content_preview=preview
            )
            
        except requests.RequestException:
            continue
    
    return None

def test_azure_blob(bucket_name: str, timeout: int = 5) -> Optional[BucketInfo]:
    """Test Azure Blob Storage"""
    url = f"https://{bucket_name}.blob.core.windows.net"
    
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=False, params={'restype': 'container', 'comp': 'list'})
        
        if response.status_code == 200:
            status = "public_read"
            preview = response.text[:500]
        elif response.status_code in [403, 401]:
            status = "exists"
            preview = ""
        else:
            return None
        
        return BucketInfo(
            name=bucket_name,
            provider="azure",
            url=url,
            status=status,
            response_code=response.status_code,
            content_preview=preview
        )
        
    except requests.RequestException:
        return None

def test_gcp_bucket(bucket_name: str, timeout: int = 5) -> Optional[BucketInfo]:
    """Test Google Cloud Storage"""
    url = f"https://storage.googleapis.com/{bucket_name}"
    
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=False)
        
        if response.status_code == 200:
            status = "public_read"
            preview = response.text[:500]
        elif response.status_code == 403:
            status = "exists"
            preview = ""
        else:
            return None
        
        return BucketInfo(
            name=bucket_name,
            provider="gcp",
            url=url,
            status=status,
            response_code=response.status_code,
            content_preview=preview
        )
        
    except requests.RequestException:
        return None

def test_bucket(bucket_name: str) -> List[BucketInfo]:
    """Test bucket across all cloud providers"""
    results = []
    
    # Test S3
    s3_result = test_s3_bucket(bucket_name)
    if s3_result:
        results.append(s3_result)
    
    # Test Azure
    azure_result = test_azure_blob(bucket_name)
    if azure_result:
        results.append(azure_result)
    
    # Test GCP
    gcp_result = test_gcp_bucket(bucket_name)
    if gcp_result:
        results.append(gcp_result)
    
    return results

# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main(target: str, output_file: Optional[str] = None, threads: int = 10):
    print(f"{Colors.GREEN}{Colors.BOLD}╔═══════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}║       S3 BUCKET BRUTEFORCE ENGINE v1.0.3                  ║{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}╚═══════════════════════════════════════════════════════════╝{Colors.RESET}\n")
    
    # Generate permutations
    print(f"{Colors.CYAN}[*] Phase 1: Generating bucket name permutations...{Colors.RESET}")
    buckets = generate_bucket_permutations(target)
    print(f"  {Colors.GREEN}✓ Generated {len(buckets)} permutations{Colors.RESET}\n")
    
    # Show sample
    print(f"{Colors.DIM}  Sample permutations:{Colors.RESET}")
    for i, bucket in enumerate(buckets[:10], 1):
        print(f"    {i}. {bucket}")
    if len(buckets) > 10:
        print(f"    ... and {len(buckets) - 10} more")
    print()
    
    # Test buckets
    print(f"{Colors.CYAN}[*] Phase 2: Testing bucket existence across providers...{Colors.RESET}")
    print(f"  {Colors.DIM}(Testing S3, Azure Blob, GCP Storage with {threads} threads){Colors.RESET}\n")
    
    all_findings = []
    tested = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_bucket = {executor.submit(test_bucket, bucket): bucket for bucket in buckets}
        
        for future in concurrent.futures.as_completed(future_to_bucket):
            bucket_name = future_to_bucket[future]
            tested += 1
            
            try:
                results = future.result()
                if results:
                    for result in results:
                        all_findings.append(result)
                        
                        # Print finding immediately
                        color = Colors.RED if result.status == "public_read" else Colors.YELLOW
                        status_icon = "🔥" if result.status == "public_read" else "🔒"
                        
                        print(f"  {color}{status_icon} FOUND:{Colors.RESET} {result.provider.upper()} - {result.name}")
                        print(f"     Status: {result.status.upper()}")
                        print(f"     URL: {result.url}")
                        if result.content_preview:
                            print(f"     {Colors.DIM}Preview: {result.content_preview[:100]}...{Colors.RESET}")
                        print()
                
                # Progress indicator
                if tested % 20 == 0:
                    print(f"  {Colors.DIM}[Progress: {tested}/{len(buckets)} tested]{Colors.RESET}")
                    
            except Exception as e:
                pass
    
    # Summary
    print(f"\n{Colors.GREEN}{Colors.BOLD}╔═══════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}║               S3 BRUTEFORCE COMPLETE                       ║{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}╚═══════════════════════════════════════════════════════════╝{Colors.RESET}\n")
    
    # Count by status
    public_read = [f for f in all_findings if f.status == "public_read"]
    exists = [f for f in all_findings if f.status == "exists"]
    
    print(f"  📊 Permutations tested: {Colors.CYAN}{len(buckets)}{Colors.RESET}")
    print(f"  🎯 Buckets found: {Colors.CYAN}{len(all_findings)}{Colors.RESET}")
    print(f"  🔥 Public readable: {Colors.RED}{len(public_read)}{Colors.RESET}")
    print(f"  🔒 Private (exist): {Colors.YELLOW}{len(exists)}{Colors.RESET}")
    
    # Save results
    if output_file and all_findings:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            for finding in all_findings:
                severity = "CRITICAL" if finding.status == "public_read" else "MEDIUM"
                f.write(f"[{severity}] [{finding.provider.upper()}] {finding.name}\n")
                f.write(f"  URL: {finding.url}\n")
                f.write(f"  Status: {finding.status}\n")
                f.write(f"  Response Code: {finding.response_code}\n")
                if finding.content_preview:
                    f.write(f"  Preview: {finding.content_preview[:200]}\n")
                f.write("\n")
        
        print(f"\n  📄 Results saved to: {Colors.CYAN}{output_path}{Colors.RESET}")
    
    if public_read:
        print(f"\n  {Colors.RED}{Colors.BOLD}⚠️  CRITICAL: {len(public_read)} publicly readable bucket(s) found!{Colors.RESET}")
    elif exists:
        print(f"\n  {Colors.YELLOW}⚠️  INFO: {len(exists)} private bucket(s) confirmed to exist{Colors.RESET}")
    else:
        print(f"\n  {Colors.GREEN}✓ No buckets discovered{Colors.RESET}")
    
    print()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{Colors.RED}Usage: s3_bruteforce.py <target_domain> [output_file] [threads]{Colors.RESET}")
        print(f"{Colors.DIM}Example: s3_bruteforce.py example.com /results/example.com/vulns/s3_bruteforce.txt 15{Colors.RESET}")
        sys.exit(1)
    
    target = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    
    main(target, output_file, threads)
