import json
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(message)s')
logger = logging.getLogger("RedHavenTools")

# -----------------------------------------------------------------------------
# DEFAULT RESULTS PATH — Works in Docker (/results) and outside (relative)
# -----------------------------------------------------------------------------
def _get_results_dir() -> str:
    """Find the results directory. Checks /results (Docker) first, then local."""
    if os.path.isdir("/results") and os.listdir("/results"):
        return "/results"
    # Fallback: results/ relative to RedHaven root
    redhaven_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    local_results = os.path.join(redhaven_root, "results")
    if os.path.isdir(local_results):
        return local_results
    return "/results"  # Default even if empty


# -----------------------------------------------------------------------------
# LLM TOOL SCHEMAS — Read-Only Analysis Tools
# -----------------------------------------------------------------------------

REDHAVEN_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "list_targets",
            "description": "Lists all scanned targets available in the results directory. Returns the target names and a summary of what data is available for each.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_target",
            "description": "Reads ALL scan results for a specific target domain and returns a comprehensive dataset for analysis. Use this to understand the full attack surface, findings, subdomains, technologies, vulnerabilities, and more.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target domain folder name inside results/ (e.g. 'gigared.com', 'coca-cola.com')"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_finding",
            "description": "Deep-dive into a specific finding file within a target's results. Use this when you need the full contents of a particular file like vulns/xss.txt, endpoints/params_only.txt, secrets/github_deep.json, etc.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target domain (e.g. 'gigared.com')"
                    },
                    "filepath": {
                        "type": "string",
                        "description": "Relative path within the target results folder (e.g. 'vulns/xss.txt', 'recon/open_ports.txt', 'endpoints/params_only.txt')"
                    }
                },
                "required": ["target", "filepath"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "suggest_next_steps",
            "description": "Based on a target's current scan data, suggests which RedHaven scanner modes to run next and what manual tests to try for maximum bounty potential.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target domain (e.g. 'gigared.com')"
                    }
                },
                "required": ["target"]
            }
        }
    }
]


# -----------------------------------------------------------------------------
# TOOL EXECUTION — Read-Only Analysis Functions
# -----------------------------------------------------------------------------

def execute_tool(tool_name: str, arguments: dict) -> str:
    """Router: dispatches tool calls to the correct read-only handler."""
    
    results_dir = _get_results_dir()
    
    if tool_name == "list_targets":
        return _list_targets(results_dir)
    
    elif tool_name == "analyze_target":
        target = arguments.get("target", "")
        if not target:
            return json.dumps({"error": "Missing required parameter 'target'"})
        return _analyze_target(results_dir, target)
    
    elif tool_name == "analyze_finding":
        target = arguments.get("target", "")
        filepath = arguments.get("filepath", "")
        if not target or not filepath:
            return json.dumps({"error": "Missing required parameters 'target' and/or 'filepath'"})
        return _analyze_finding(results_dir, target, filepath)
    
    elif tool_name == "suggest_next_steps":
        target = arguments.get("target", "")
        if not target:
            return json.dumps({"error": "Missing required parameter 'target'"})
        return _suggest_next_steps(results_dir, target)
    
    else:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})


# -----------------------------------------------------------------------------
# 1. LIST TARGETS
# -----------------------------------------------------------------------------

def _list_targets(results_dir: str) -> str:
    """List all scanned targets and summarize available data for each."""
    if not os.path.isdir(results_dir):
        return f"Results directory not found at {results_dir}. Run scans first via start.sh."
    
    targets = []
    for entry in sorted(os.listdir(results_dir)):
        target_path = os.path.join(results_dir, entry)
        if not os.path.isdir(target_path) or entry.startswith("."):
            continue
        
        # Summarize what data exists
        data_summary = []
        for subdir in ["recon", "endpoints", "vulns", "secrets", "reports", "osint"]:
            subdir_path = os.path.join(target_path, subdir)
            if os.path.isdir(subdir_path):
                files = [f for f in os.listdir(subdir_path) if os.path.isfile(os.path.join(subdir_path, f))]
                if files:
                    data_summary.append(f"  {subdir}/: {len(files)} files ({', '.join(files[:5])}{'...' if len(files) > 5 else ''})")
        
        if data_summary:
            targets.append(f"📁 {entry}\n" + "\n".join(data_summary))
        else:
            targets.append(f"📁 {entry} (empty — scan may still be running)")
    
    if not targets:
        return f"No targets found in {results_dir}. Run a scan first using start.sh."
    
    header = f"=== AVAILABLE TARGETS ({len(targets)}) ===\nResults directory: {results_dir}\n"
    return header + "\n\n".join(targets)


# -----------------------------------------------------------------------------
# 2. ANALYZE TARGET — Full scan read
# -----------------------------------------------------------------------------

def _analyze_target(results_dir: str, target: str) -> str:
    """Read ALL result files for a target and build a rich analysis context."""
    target_dir = os.path.join(results_dir, target)
    
    if not os.path.isdir(target_dir):
        # Try fuzzy match
        available = [d for d in os.listdir(results_dir) if os.path.isdir(os.path.join(results_dir, d))]
        return f"Target '{target}' not found. Available targets: {', '.join(available)}"
    
    sections = []
    sections.append(f"=== FULL ANALYSIS FOR {target} ===")
    sections.append(f"Path: {target_dir}")
    
    # Walk through all known subdirectories in priority order
    analysis_map = {
        "recon": {
            "title": "RECONNAISSANCE",
            "files": {
                "urls.txt": ("Alive Hosts", 100),
                "alive_full.txt": ("Alive Hosts (Full Detail)", 50),
                "open_ports.txt": ("Open Ports", 100),
                "cms_detection.json": ("CMS Detection", 50),
            }
        },
        "endpoints": {
            "title": "ATTACK SURFACE",
            "files": {
                "clean_urls.txt": ("Clean URLs", 80),
                "params_only.txt": ("URLs with Parameters (Injection Candidates)", 80),
                "js_files.txt": ("JavaScript Files", 50),
                "alive_urls.txt": ("All Alive URLs", 30),
                "crawled.txt": ("Crawled URLs", 30),
            }
        },
        "vulns": {
            "title": "VULNERABILITIES FOUND",
            "files": {}  # Read ALL files dynamically
        },
        "secrets": {
            "title": "SECRETS & LEAKS",
            "files": {}  # Read ALL files dynamically
        },
        "osint": {
            "title": "OSINT INTELLIGENCE",
            "files": {}  # Read ALL files dynamically
        },
        "reports": {
            "title": "REPORTS & TECH STACK",
            "files": {
                "web_overview.txt": ("Technology Stack & Web Overview", 50),
            }
        },
    }
    
    total_findings = 0
    
    for subdir, config in analysis_map.items():
        subdir_path = os.path.join(target_dir, subdir)
        if not os.path.isdir(subdir_path):
            continue
        
        section_parts = []
        
        if config["files"]:
            # Read specific known files
            for fname, (label, max_lines) in config["files"].items():
                content = _read_file_preview(os.path.join(subdir_path, fname), max_lines)
                if content:
                    total_findings += 1
                    section_parts.append(f"  [{label}]\n{content}")
        else:
            # Read ALL files in directory (vulns, secrets)
            for fname in sorted(os.listdir(subdir_path)):
                fpath = os.path.join(subdir_path, fname)
                if os.path.isfile(fpath):
                    content = _read_file_preview(fpath, 60)
                    if content:
                        total_findings += 1
                        label = fname.replace("_", " ").replace(".txt", "").replace(".json", "").upper()
                        section_parts.append(f"  [{label}]\n{content}")
        
        if section_parts:
            sections.append(f"\n{'='*60}\n📂 {config['title']}\n{'='*60}")
            sections.extend(section_parts)
    
    # Status code breakdown
    status_dir = os.path.join(target_dir, "recon", "status_codes")
    if os.path.isdir(status_dir):
        status_lines = []
        for fname in sorted(os.listdir(status_dir)):
            fpath = os.path.join(status_dir, fname)
            if os.path.isfile(fpath):
                count = sum(1 for _ in open(fpath))
                status_lines.append(f"  {fname}: {count} URLs")
        if status_lines:
            sections.append(f"\n--- STATUS CODE BREAKDOWN ---\n" + "\n".join(status_lines))
    
    sections.insert(2, f"Total data files with content: {total_findings}")
    
    if total_findings == 0:
        sections.append("\n⚠️ No scan results found for this target. Run scanner.sh first.")
    
    return "\n".join(sections)


# -----------------------------------------------------------------------------
# 3. ANALYZE FINDING — Deep dive into specific file
# -----------------------------------------------------------------------------

def _analyze_finding(results_dir: str, target: str, filepath: str) -> str:
    """Read the FULL contents of a specific findings file."""
    full_path = os.path.join(results_dir, target, filepath)
    
    # Security: prevent path traversal
    real_path = os.path.realpath(full_path)
    real_results = os.path.realpath(os.path.join(results_dir, target))
    if not real_path.startswith(real_results):
        return json.dumps({"error": "Invalid filepath — path traversal detected"})
    
    if not os.path.exists(full_path):
        # List available files
        target_dir = os.path.join(results_dir, target)
        available = []
        for root, dirs, files in os.walk(target_dir):
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), target_dir)
                available.append(rel)
        return f"File '{filepath}' not found.\n\nAvailable files:\n" + "\n".join(sorted(available))
    
    try:
        with open(full_path, 'r', errors='replace') as f:
            content = f.read()
        
        fsize = os.path.getsize(full_path)
        lines = content.count('\n') + 1
        
        header = f"=== {filepath} ({lines} lines, {fsize} bytes) ===\n"
        
        # Cap at ~8000 chars for token safety
        if len(content) > 8000:
            content = content[:8000] + f"\n\n... [TRUNCATED — showing first 8000 of {len(content)} chars]"
        
        return header + content
    except Exception as e:
        return json.dumps({"error": f"Failed to read file: {str(e)}"})


# -----------------------------------------------------------------------------
# 4. SUGGEST NEXT STEPS — Smart recommendations
# -----------------------------------------------------------------------------

def _suggest_next_steps(results_dir: str, target: str) -> str:
    """Analyze what data exists and suggest which scanner modes to run next."""
    target_dir = os.path.join(results_dir, target)
    
    if not os.path.isdir(target_dir):
        return f"Target '{target}' not found in {results_dir}."
    
    # Check what phases have been completed
    phases = {
        "recon_passive": os.path.exists(os.path.join(target_dir, "recon", "urls.txt")),
        "recon_active": os.path.exists(os.path.join(target_dir, "endpoints", "alive_urls.txt")),
        "port_scan": os.path.exists(os.path.join(target_dir, "recon", "open_ports.txt")),
        "visual_recon": os.path.exists(os.path.join(target_dir, "reports", "web_overview.txt")),
        "osint": os.path.exists(os.path.join(target_dir, "osint")),
        "secrets": os.path.exists(os.path.join(target_dir, "secrets")),
        "vulns_xss": os.path.exists(os.path.join(target_dir, "vulns", "xss.txt")),
        "vulns_ssrf": os.path.exists(os.path.join(target_dir, "vulns", "ssrf.txt")),
        "vulns_sqli": os.path.exists(os.path.join(target_dir, "vulns", "sqli.txt")),
        "vulns_nuclei": os.path.exists(os.path.join(target_dir, "vulns", "nuclei.txt")),
        "cms_detection": os.path.exists(os.path.join(target_dir, "recon", "cms_detection.json")),
        "params": os.path.exists(os.path.join(target_dir, "endpoints", "params_only.txt")),
        "js_files": os.path.exists(os.path.join(target_dir, "endpoints", "js_files.txt")),
    }
    
    # Count file sizes for non-empty checks
    def _has_content(path):
        return os.path.exists(path) and os.path.getsize(path) > 0
    
    sections = []
    sections.append(f"=== SCAN COVERAGE FOR {target} ===\n")
    
    # Phase status table
    sections.append("COMPLETED PHASES:")
    for phase, done in phases.items():
        status = "✅" if done else "❌"
        sections.append(f"  {status} {phase.replace('_', ' ').title()}")
    
    # Recommendations
    recs = []
    
    if not phases["recon_passive"]:
        recs.append("🔴 CRITICAL: Run Mode 0 (Passive Recon) first — no subdomains discovered yet")
    elif not phases["recon_active"]:
        recs.append("🔴 HIGH: Run Mode 1 (Active Recon) — need alive endpoints for vuln scanning")
    
    if phases["recon_active"] and not phases["port_scan"]:
        recs.append("🟡 Run Mode 4 (Port Scan) — discover non-standard services")
    
    if not phases["osint"]:
        recs.append("🟡 Run Mode 6 (OSINT) — find dorks, email security issues, leaked source maps")
    
    if not phases["cms_detection"]:
        recs.append("🟡 Run Mode 7 (CMS Detection) — identify WordPress/Joomla/Drupal for targeted exploits")
    
    if phases["recon_active"] and not phases["secrets"]:
        recs.append("🟡 Run Mode 10 (Secrets Hunter) — find exposed API keys, tokens in JS files")
    
    if phases["recon_active"] and not phases["vulns_xss"]:
        recs.append("🟠 Run Mode 20 (XSS Engine) — test reflected/stored XSS on parameters")
    
    if phases["recon_active"] and not phases["vulns_ssrf"]:
        recs.append("🟠 Run Mode 21 (SSRF Storm) — test for server-side request forgery")
    
    if phases["params"] and not phases["vulns_sqli"]:
        recs.append("🟠 Run Mode 25 (Deep Fuzzing) — SQLi, SSTI, LFI, Command Injection")
    
    if phases["recon_active"]:
        if not os.path.exists(os.path.join(target_dir, "vulns", "cors.txt")):
            recs.append("🟡 Run Mode 31 (CORS Testing) — check for cross-origin misconfigurations")
        if not os.path.exists(os.path.join(target_dir, "vulns", "idor.txt")):
            recs.append("🟡 Run Mode 23 (IDOR Hunter) — test for insecure direct object references")
    
    # Quick scan suggestion
    if not phases["recon_active"]:
        recs.append("\n💡 TIP: Run Mode 80 (Quick Recon) for a fast, automated full reconnaissance")
    elif not phases["vulns_xss"]:
        recs.append("\n💡 TIP: Run Mode 81 (Vulnerability Hunt) for automated XSS/SSRF/SQLi scanning")
    
    sections.append("\n\nRECOMMENDED NEXT STEPS:")
    if recs:
        sections.extend(recs)
    else:
        sections.append("✅ All major scan phases completed! Review findings manually for logic flaws and chained vulnerabilities.")
    
    # Scanner mode reference
    sections.append("""
SCANNER MODE REFERENCE:
  Mode  0 = Passive Recon (subfinder, dnsx)
  Mode  1 = Active Recon (katana, waybackurls, httpx)
  Mode  4 = Port Scan (naabu)
  Mode  6 = OSINT (dorks, SPF/DMARC, emails)
  Mode  7 = CMS Detection (CMSeeK)
  Mode 10 = Secrets Hunter
  Mode 20 = XSS Engine
  Mode 21 = SSRF Storm
  Mode 23 = IDOR Hunter
  Mode 25 = Deep Fuzzing (SQLi, SSTI, LFI)
  Mode 31 = CORS Testing
  Mode 80 = Quick Recon (automated)
  Mode 81 = Vulnerability Hunt (automated)
  
  Usage: ./start.sh then select mode, or:
         docker run ... scanner.sh -d target.com -m 80""")
    
    return "\n".join(sections)


# -----------------------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------------------

def _read_file_preview(filepath: str, max_lines: int = 50) -> str:
    """Read a file and return a line-capped preview. Returns empty string if file is empty/missing."""
    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        return ""
    
    try:
        with open(filepath, 'r', errors='replace') as f:
            lines = f.readlines()
        
        count = len(lines)
        preview = "".join(lines[:max_lines])
        
        if count > max_lines:
            preview += f"\n    ... ({count - max_lines} more lines, {count} total)"
        
        return preview.strip()
    except Exception:
        return ""
