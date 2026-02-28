#!/usr/bin/env python3
"""
REDHAVEN v1.2.4 - CVE Auto-Matching Engine
Detects technology versions and matches them to known CVEs
"""

import sys
import os
import re
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

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
class TechStack:
    """Detected technology with version"""
    name: str
    version: str
    url: str
    raw_line: str

@dataclass
class CVEMatch:
    """CVE matched to a technology"""
    cve_id: str
    tech_name: str
    tech_version: str
    severity: str
    description: str
    matched_urls: List[str]

# ============================================================================
# VERSION EXTRACTION
# ============================================================================

def parse_tech_versions(file_path: Path) -> List[TechStack]:
    """
    Parse httpx web_overview.txt to extract technology versions
    
    Example input:
    https://example.com [WordPress 6.4.2] [nginx/1.18.0] [200 OK]
    https://test.com [Apache/2.4.41] [PHP/7.4.3] [200 OK]
    """
    tech_stacks = []
    
    if not file_path.exists():
        print(f"{Colors.YELLOW}[!] File not found: {file_path}{Colors.RESET}")
        return tech_stacks
    
    # Regex patterns for common technologies
    patterns = {
        'WordPress': r'WordPress[/\s]+([\d.]+)',
        'Joomla': r'Joomla!?[/\s]+([\d.]+)',
        'Drupal': r'Drupal[/\s]+([\d.]+)',
        'Apache': r'Apache[/\s]+([\d.]+)',
        'nginx': r'nginx[/\s]+([\d.]+)',
        'PHP': r'PHP[/\s]+([\d.]+)',
        'MySQL': r'MySQL[/\s]+([\d.]+)',
        'IIS': r'IIS[/\s]+([\d.]+)',
        'Tomcat': r'Tomcat[/\s]+([\d.]+)',
        'jQuery': r'jQuery[/\s]+([\d.]+)',
        'React': r'React[/\s]+([\d.]+)',
        'Angular': r'Angular[/\s]+([\d.]+)',
        'Vue': r'Vue\.js[/\s]+([\d.]+)',
        'Laravel': r'Laravel[/\s]+([\d.]+)',
        'Django': r'Django[/\s]+([\d.]+)',
        'Rails': r'Rails[/\s]+([\d.]+)',
        'Spring': r'Spring[/\s]+([\d.]+)',
        'ASP.NET': r'ASP\.NET[/\s]+([\d.]+)',
        'Bootstrap': r'Bootstrap[/\s]+([\d.]+)',
    }
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Extract URL (first element)
                url_match = re.match(r'^(https?://[^\s\[]+)', line)
                url = url_match.group(1) if url_match else ''
                
                # Search for all technology patterns
                for tech_name, pattern in patterns.items():
                    for match in re.finditer(pattern, line, re.IGNORECASE):
                        version = match.group(1)
                        
                        tech_stack = TechStack(
                            name=tech_name,
                            version=version,
                            url=url,
                            raw_line=line
                        )
                        tech_stacks.append(tech_stack)
                        
    except Exception as e:
        print(f"{Colors.RED}[!] Error parsing file: {e}{Colors.RESET}")
    
    return tech_stacks

# ============================================================================
# CVE DATABASE QUERY
# ============================================================================

def query_nuclei_templates(tech_name: str, version: str) -> List[str]:
    """
    Query Nuclei templates database for CVEs matching technology/version
    Returns list of template IDs
    """
    cve_templates = []
    
    # Nuclei templates path
    nuclei_templates_base = Path("/root/nuclei-templates")
    if not nuclei_templates_base.exists():
        nuclei_templates_base = Path.home() / "nuclei-templates"
    
    if not nuclei_templates_base.exists():
        return cve_templates
    
    # Search in CVEs directory
    cves_dir = nuclei_templates_base / "cves"
    if not cves_dir.exists():
        return cve_templates
    
    # Technology-specific mappings
    tech_mapping = {
        'WordPress': 'wordpress',
        'Joomla': 'joomla',
        'Drupal': 'drupal',
        'Apache': 'apache',
        'nginx': 'nginx',
        'PHP': 'php',
        'Tomcat': 'tomcat',
        'IIS': 'iis',
        'jQuery': 'jquery',
        'Laravel': 'laravel',
        'Django': 'django',
        'Rails': 'rails',
        'Spring': 'spring',
    }
    
    tech_key = tech_mapping.get(tech_name, tech_name.lower())
    
    # Search for relevant template files
    try:
        # Search recursively for YAML files
        for yaml_file in cves_dir.rglob("*.yaml"):
            content = yaml_file.read_text(errors='ignore').lower()
            
            # Check if tech name is mentioned
            if tech_key in content:
                # Try to extract CVE ID from filename or content
                cve_id = None
                
                # From filename: CVE-2021-1234.yaml
                filename_match = re.search(r'(CVE-\d{4}-\d+)', yaml_file.name, re.IGNORECASE)
                if filename_match:
                    cve_id = filename_match.group(1).upper()
                
                # From content: id: CVE-2021-1234
                if not cve_id:
                    content_match = re.search(r'id:\s*(CVE-\d{4}-\d+)', content, re.IGNORECASE)
                    if content_match:
                        cve_id = content_match.group(1).upper()
                
                if cve_id:
                    cve_templates.append(str(yaml_file))
                    
    except Exception as e:
        print(f"{Colors.DIM}[*] Error searching templates: {e}{Colors.RESET}")
    
    return cve_templates

# ============================================================================
# NUCLEI EXECUTION
# ============================================================================

def execute_nuclei_cve(templates: List[str], target_urls: List[str], output_file: Path) -> int:
    """
    Execute Nuclei with specific CVE templates against target URLs
    Returns count of vulnerabilities found
    """
    if not templates or not target_urls:
        return 0
    
    # Create temp file with URLs
    temp_urls = Path("/tmp/cve_matcher_urls.txt")
    with open(temp_urls, 'w') as f:
        for url in set(target_urls):  # Deduplicate
            f.write(f"{url}\n")
    
    # Create temp file with template paths
    temp_templates = Path("/tmp/cve_matcher_templates.txt")
    with open(temp_templates, 'w') as f:
        for template in templates:
            f.write(f"{template}\n")
    
    print(f"{Colors.CYAN}[*] Executing Nuclei with {len(templates)} CVE templates...{Colors.RESET}")
    
    try:
        # Execute Nuclei
        cmd = [
            "nuclei",
            "-l", str(temp_urls),
            "-t", str(temp_templates),
            "-o", str(output_file),
            "-silent",
            "-duc",  # Disable update check
            "-c", "30",  # Concurrency
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # Count findings
        if output_file.exists():
            with open(output_file, 'r') as f:
                findings = len([line for line in f if line.strip()])
            return findings
        
        return 0
        
    except subprocess.TimeoutExpired:
        print(f"{Colors.YELLOW}[!] Nuclei execution timed out{Colors.RESET}")
        return 0
    except Exception as e:
        print(f"{Colors.RED}[!] Error executing Nuclei: {e}{Colors.RESET}")
        return 0
    finally:
        # Cleanup
        temp_urls.unlink(missing_ok=True)
        temp_templates.unlink(missing_ok=True)

# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main(target_dir: str):
    print(f"{Colors.GREEN}{Colors.BOLD}╔═══════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}║       CVE AUTO-MATCHING ENGINE v1.2.4                     ║{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}╚═══════════════════════════════════════════════════════════╝{Colors.RESET}\n")
    
    base_path = Path(target_dir)
    web_overview = base_path / "reports" / "web_overview.txt"
    output_dir = base_path / "vulns"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Step 1: Parse technology versions
    print(f"{Colors.CYAN}[*] Phase 1: Parsing technology versions...{Colors.RESET}")
    tech_stacks = parse_tech_versions(web_overview)
    
    if not tech_stacks:
        print(f"{Colors.YELLOW}[!] No technology versions detected.{Colors.RESET}")
        print(f"{Colors.DIM}    Make sure visual recon has been executed.{Colors.RESET}")
        return
    
    # Deduplicate and summarize
    unique_techs = {}
    for tech in tech_stacks:
        key = f"{tech.name} {tech.version}"
        if key not in unique_techs:
            unique_techs[key] = tech
    
    print(f"{Colors.GREEN}  ✓ Detected {len(unique_techs)} unique technology versions{Colors.RESET}\n")
    
    for key, tech in unique_techs.items():
        print(f"    • {Colors.BOLD}{tech.name} {tech.version}{Colors.RESET} ({tech.url})")
    
    # Step 2: Query CVE database
    print(f"\n{Colors.CYAN}[*] Phase 2: Querying CVE database (Nuclei templates)...{Colors.RESET}")
    
    all_templates = []
    all_urls = []
    tech_cve_map = {}
    
    for key, tech in unique_techs.items():
        templates = query_nuclei_templates(tech.name, tech.version)
        if templates:
            all_templates.extend(templates)
            all_urls.append(tech.url)
            tech_cve_map[key] = len(templates)
            print(f"  {Colors.GREEN}✓{Colors.RESET} {tech.name} {tech.version}: {len(templates)} CVE templates found")
        else:
            print(f"  {Colors.DIM}○{Colors.RESET} {tech.name} {tech.version}: No CVE templates found")
    
    if not all_templates:
        print(f"\n{Colors.YELLOW}[!] No CVE templates matched.{Colors.RESET}")
        print(f"{Colors.DIM}    This could mean:{Colors.RESET}")
        print(f"{Colors.DIM}    • Detected versions are up-to-date with no known CVEs{Colors.RESET}")
        print(f"{Colors.DIM}    • Nuclei templates database needs updating{Colors.RESET}")
        return
    
    # Step 3: Execute Nuclei with matched templates
    print(f"\n{Colors.CYAN}[*] Phase 3: Testing for CVE vulnerabilities...{Colors.RESET}")
    output_file = output_dir / "cve_matched.txt"
    
    findings_count = execute_nuclei_cve(all_templates, all_urls, output_file)
    
    # Summary
    print(f"\n{Colors.GREEN}{Colors.BOLD}╔═══════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}║                  CVE MATCHING COMPLETE                     ║{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}╚═══════════════════════════════════════════════════════════╝{Colors.RESET}\n")
    
    print(f"  📊 Technologies scanned: {Colors.CYAN}{len(unique_techs)}{Colors.RESET}")
    print(f"  🎯 CVE templates tested: {Colors.CYAN}{len(set(all_templates))}{Colors.RESET}")
    print(f"  🔥 Vulnerabilities found: {Colors.RED if findings_count > 0 else Colors.GREEN}{findings_count}{Colors.RESET}")
    
    if findings_count > 0:
        print(f"\n  📄 Results saved to: {Colors.CYAN}{output_file}{Colors.RESET}")
        print(f"{Colors.RED}{Colors.BOLD}  ⚠️  Action required: Review CVE findings immediately!{Colors.RESET}")
    else:
        print(f"\n  {Colors.GREEN}✓ No CVE vulnerabilities detected{Colors.RESET}")
    
    print()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{Colors.RED}Usage: cve_matcher.py <target_directory>{Colors.RESET}")
        print(f"{Colors.DIM}Example: cve_matcher.py /results/target.com{Colors.RESET}")
        sys.exit(1)
    
    target_dir = sys.argv[1]
    if not os.path.isdir(target_dir):
        print(f"{Colors.RED}[!] Error: '{target_dir}' is not a valid directory{Colors.RESET}")
        sys.exit(1)
    
    main(target_dir)
