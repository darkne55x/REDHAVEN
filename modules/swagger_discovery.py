#!/usr/bin/env python3
"""
Swagger/OpenAPI Discovery Tool - REDHAVEN Framework
Automatically discovers and analyzes Swagger/OpenAPI documentation
"""

import sys
import argparse
import requests
import json
import yaml
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  SWAGGER DISCOVERY - API Documentation Hunter           ║
║  Part of REDHAVEN Framework v1.2                         ║
╚══════════════════════════════════════════════════════════╝
"""

# Common Swagger/OpenAPI paths
SWAGGER_PATHS = [
    # Standard paths
    '/swagger.json',
    '/swagger.yaml',
    '/swagger-ui.html',
    '/swagger-ui/',
    '/swagger/index.html',
    '/swagger/v1/swagger.json',
    '/swagger/v2/swagger.json',
    '/swagger/v3/swagger.json',
    '/openapi.json',
    '/openapi.yaml',
    '/openapi/v3/openapi.json',
    
    # API versioned
    '/api/swagger.json',
    '/api/swagger.yaml',
    '/api/v1/swagger.json',
    '/api/v2/swagger.json',
    '/api/v3/swagger.json',
    '/api-docs',
    '/api-docs/',
    '/api-docs/swagger.json',
    
    # Framework specific
    '/v2/api-docs',  # Spring Boot
    '/v3/api-docs',  # Spring Boot 3.x
    '/docs',
    '/docs/swagger.json',
    '/redoc',
    '/api/documentation',
    
    # Alternative paths
    '/.well-known/openapi.json',
    '/swagger-resources',
    '/api/swagger-resources',
]

class SwaggerDiscovery:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.found_specs = []
    
    def discover_swagger(self) -> List[str]:
        """Discover Swagger/OpenAPI documentation."""
        print(f"[*] Discovering Swagger/OpenAPI paths at: {self.base_url}")
        
        found = []
        
        for path in SWAGGER_PATHS:
            url = urljoin(self.base_url, path)
            
            try:
                response = self.session.get(url, timeout=5, allow_redirects=True)
                
                if response.status_code == 200:
                    # Check content type and content
                    content_type = response.headers.get('Content-Type', '')
                    content = response.text[:500]
                    
                    if any(keyword in content for keyword in ['swagger', 'openapi', '"paths":', 'basePath']):
                        found.append(url)
                        print(f"    [+] Found: {url}")
                        self.found_specs.append({
                            'url': url,
                            'content_type': content_type,
                            'spec': response.text
                        })
            
            except Exception as e:
                pass  # Silent fail for common paths
        
        return found
    
    def parse_swagger_spec(self, spec_text: str) -> Dict:
        """Parse Swagger/OpenAPI specification."""
        try:
            # Try JSON first
            spec = json.loads(spec_text)
        except:
            try:
                # Try YAML
                spec = yaml.safe_load(spec_text)
            except:
                return None
        
        return spec
    
    def analyze_spec(self, spec: Dict, spec_url: str) -> Dict:
        """Analyze Swagger spec for interesting endpoints and security issues."""
        print(f"\n[*] Analyzing spec: {spec_url}")
        
        findings = {
            'endpoints': [],
            'auth_required': [],
            'no_auth': [],
            'sensitive_endpoints': [],
            'deprecated': [],
        }
        
        # Get base path
        base_path = spec.get('basePath', '')
        servers = spec.get('servers', [])
        
        # Extract paths
        paths = spec.get('paths', {})
        
        for path, methods in paths.items():
            full_path = base_path + path
            
            for method, details in methods.items():
                if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    continue
                
                endpoint_info = {
                    'path': full_path,
                    'method': method.upper(),
                    'description': details.get('summary', details.get('description', '')),
                    'parameters': details.get('parameters', []),
                }
                
                findings['endpoints'].append(endpoint_info)
                
                # Check for auth requirements
                security = details.get('security', spec.get('security', []))
                
                if not security:
                    findings['no_auth'].append(endpoint_info)
                    print(f"    [!] No auth: {method.upper()} {full_path}")
                else:
                    findings['auth_required'].append(endpoint_info)
                
                # Check for sensitive keywords
                full_text = json.dumps(details).lower()
                sensitive_keywords = ['password', 'token', 'secret', 'key', 'admin', 'internal', 'private']
                
                if any(keyword in full_text for keyword in sensitive_keywords):
                    findings['sensitive_endpoints'].append(endpoint_info)
                    print(f"    [!!!] Sensitive endpoint: {method.upper()} {full_path}")
                
                # Check for deprecated
                if details.get('deprecated'):
                    findings['deprecated'].append(endpoint_info)
        
        print(f"\n    Total endpoints: {len(findings['endpoints'])}")
        print(f"    No auth required: {len(findings['no_auth'])}")
        print(f"    Sensitive: {len(findings['sensitive_endpoints'])}")
        print(f"    Deprecated: {len(findings['deprecated'])}")
        
        return findings
    
    def generate_wordlist(self, findings: Dict, output_file: str):
        """Generate wordlist of discovered endpoints."""
        with open(output_file, 'w') as f:
            for endpoint in findings['endpoints']:
                f.write(f"{endpoint['path']}\n")
        
        print(f"\n[+] Wordlist saved to: {output_file}")
    
    def generate_report(self, all_findings: List[Dict], output_file: str):
        """Generate detailed JSON report."""
        report = {
            'discovered_specs': len(self.found_specs),
            'specs': [spec['url'] for spec in self.found_specs],
            'findings': all_findings
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Full report saved to: {output_file}")

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="Swagger/OpenAPI Discovery and Analysis")
    parser.add_argument('-u', '--url', required=True, help='Target base URL')
    parser.add_argument('-o', '--output', default='swagger_report.json', help='Output report file')
    parser.add_argument('-w', '--wordlist', help='Generate endpoint wordlist')
    parser.add_argument('--analyze', action='store_true', help='Analyze discovered specs')
    
    args = parser.parse_args()
    
    discovery = SwaggerDiscovery(args.url)
    
    # Discover Swagger paths
    found_urls = discovery.discover_swagger()
    
    if not found_urls:
        print("\n[-] No Swagger/OpenAPI documentation found")
        print("[i] Try manually checking: /api-docs, /swagger-ui.html, /v2/api-docs")
        sys.exit(0)
    
    print(f"\n[+] Found {len(found_urls)} Swagger/OpenAPI specs")
    print("="*70)
    
    all_findings = []
    
    # Analyze specs if requested
    if args.analyze:
        for spec_info in discovery.found_specs:
            spec = discovery.parse_swagger_spec(spec_info['spec'])
            
            if spec:
                findings = discovery.analyze_spec(spec, spec_info['url'])
                all_findings.append({
                    'spec_url': spec_info['url'],
                    'findings': findings
                })
        
        # Generate wordlist
        if args.wordlist and all_findings:
            combined_findings = {
                'endpoints': [],
                'no_auth': [],
                'sensitive_endpoints': []
            }
            
            for af in all_findings:
                for key in combined_findings.keys():
                    combined_findings[key].extend(af['findings'].get(key, []))
            
            discovery.generate_wordlist(combined_findings, args.wordlist)
        
        # Generate report
        discovery.generate_report(all_findings, args.output)
    
    print("\n" + "="*70)
    print("[+] Swagger discovery complete!")
    
    if not args.analyze:
        print("[i] Use --analyze to extract and analyze endpoints")
        print("[i] Use --wordlist <file> to generate endpoint list")

if __name__ == '__main__':
    main()
