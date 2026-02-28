#!/usr/bin/env python3
"""
REDHAVEN AI — Main CLI Entry Point
====================================
Unified command-line interface for all AI brain capabilities.

Usage:
    # Full AI analysis (correlation + report)
    python3 ai_brain_cli.py analyze /results/target.com
    
    # Smart correlation only
    python3 ai_brain_cli.py correlate /results/target.com
    
    # Generate report only
    python3 ai_brain_cli.py report /results/target.com
    
    # Check AI status
    python3 ai_brain_cli.py status
    
    # Parse and preview findings
    python3 ai_brain_cli.py parse /results/target.com
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pathlib import Path

COLORS = {
    "R": "\033[0;31m", "G": "\033[0;32m", "Y": "\033[1;33m",
    "B": "\033[0;34m", "C": "\033[0;36m", "W": "\033[1;37m",
    "D": "\033[2m", "BOLD": "\033[1m", "RESET": "\033[0m",
    "BR": "\033[1;31m",
}


def print_banner():
    C = COLORS
    print(f"""
{C['BR']}
    ██████╗ ███████╗██████╗ ██╗  ██╗ █████╗ ██╗   ██╗███████╗███╗   ██╗
    ██╔══██╗██╔════╝██╔══██╗██║  ██║██╔══██╗██║   ██║██╔════╝████╗  ██║
    ██████╔╝█████╗  ██║  ██║███████║███████║██║   ██║█████╗  ██╔██╗ ██║
    ██╔══██╗██╔══╝  ██║  ██║██╔══██║██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║
    ██║  ██║███████╗██████╔╝██║  ██║██║  ██║ ╚████╔╝ ███████╗██║ ╚████║
    ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝
{C['RESET']}
    {C['W']}🧠 AI BRAIN v1.0{C['RESET']}  {C['D']}| Intelligent Offensive Analysis{C['RESET']}
""")


def cmd_status():
    """Check AI provider status."""
    from ai_brain.config import load_config
    from ai_brain.llm_client import LLMClient

    config = load_config()
    client = LLMClient(config)
    status = client.get_status()

    print(f"\n{COLORS['C']}  AI BRAIN STATUS{COLORS['RESET']}")
    print(f"  {'─'*40}")
    for k, v in status.items():
        icon = "✓" if v is True else ("✘" if v is False else "•")
        color = COLORS['G'] if v is True else (COLORS['R'] if v is False else COLORS['D'])
        print(f"  {color}{icon}{COLORS['RESET']} {k}: {v}")

    if client.is_available():
        print(f"\n  {COLORS['G']}AI is ready.{COLORS['RESET']}")
    else:
        print(f"\n  {COLORS['R']}AI is NOT available. Check your provider configuration.{COLORS['RESET']}")
        if config.provider == "ollama":
            print(f"  {COLORS['Y']}Hint: Make sure Ollama is running: ollama serve{COLORS['RESET']}")


def cmd_parse(target_dir: str):
    """Parse and preview findings."""
    from ai_brain.finding_parser import FindingParser

    parser = FindingParser(target_dir)
    results = parser.parse_all()
    summary = results.summary_dict()

    print(f"\n{COLORS['C']}  PARSED FINDINGS — {results.target}{COLORS['RESET']}")
    print(f"  {'─'*50}")
    print(f"  Subdomains:   {summary['subdomains_count']}")
    print(f"  Alive URLs:   {summary['alive_urls_count']}")
    print(f"  Endpoints:    {summary['endpoints_count']}")
    print(f"  Parameters:   {summary['parameters_count']}")
    print(f"  Tech Stack:   {', '.join(summary['tech_stack'][:8]) or 'Unknown'}")
    print(f"  Total Findings: {summary['total_findings']}")
    print(f"    Critical:   {summary['critical']}")
    print(f"    High:       {summary['high']}")
    print()

    if summary['findings_by_category']:
        print(f"  {COLORS['W']}Findings by category:{COLORS['RESET']}")
        for cat, count in sorted(summary['findings_by_category'].items(), key=lambda x: x[1], reverse=True):
            print(f"    {count:3d}  {cat}")

    print(f"\n  Files parsed: {len(results.scan_files_found)}")
    print(f"  Files empty:  {len(results.scan_files_empty)}")


def cmd_correlate(target_dir: str):
    """Run AI-powered correlation."""
    from ai_brain.config import load_config
    from ai_brain.smart_correlator import run_hybrid_correlation

    config = load_config()
    run_hybrid_correlation(target_dir, config)


def cmd_report(target_dir: str):
    """Generate AI-powered report."""
    from ai_brain.config import load_config
    from ai_brain.report_generator import ReportGenerator

    config = load_config()
    generator = ReportGenerator(config, target_dir)
    report_path = generator.generate_full_report()
    if report_path:
        print(f"\n{COLORS['G']}  ✓ Report ready: {report_path}{COLORS['RESET']}")


def cmd_analyze(target_dir: str):
    """Full analysis: correlation + report generation."""
    print(f"\n{COLORS['BOLD']}  FULL AI ANALYSIS PIPELINE{COLORS['RESET']}")
    print(f"  {'='*50}\n")

    # Step 1: Correlate
    print(f"  {COLORS['B']}▶ Step 1: Smart Correlation{COLORS['RESET']}")
    cmd_correlate(target_dir)

    # Step 2: Report
    print(f"\n  {COLORS['B']}▶ Step 2: Report Generation{COLORS['RESET']}")
    cmd_report(target_dir)

    print(f"\n{COLORS['G']}  ✓ FULL AI ANALYSIS COMPLETE{COLORS['RESET']}")


def main():
    if len(sys.argv) < 2:
        print_banner()
        print(f"  {COLORS['W']}Commands:{COLORS['RESET']}")
        print(f"    analyze   <dir>   Full analysis (correlate + report)")
        print(f"    correlate <dir>   AI-powered vulnerability correlation")
        print(f"    report    <dir>   Generate narrative report")
        print(f"    parse     <dir>   Preview parsed findings")
        print(f"    status            Check AI provider status")
        print()
        print(f"  {COLORS['W']}Example:{COLORS['RESET']}")
        print(f"    python3 ai_brain_cli.py analyze /results/target.com")
        print()
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == "status":
        cmd_status()
        return

    if len(sys.argv) < 3:
        print(f"{COLORS['R']}[!] Missing target directory.{COLORS['RESET']}")
        print(f"Usage: ai_brain_cli.py {command} <target_directory>")
        sys.exit(1)

    target_dir = sys.argv[2]
    if not Path(target_dir).is_dir():
        print(f"{COLORS['R']}[!] Directory not found: {target_dir}{COLORS['RESET']}")
        sys.exit(1)

    print_banner()

    commands = {
        "analyze": cmd_analyze,
        "correlate": cmd_correlate,
        "report": cmd_report,
        "parse": cmd_parse,
    }

    if command in commands:
        commands[command](target_dir)
    else:
        print(f"{COLORS['R']}[!] Unknown command: {command}{COLORS['RESET']}")
        print(f"Available: {', '.join(commands.keys())}, status")
        sys.exit(1)


if __name__ == "__main__":
    main()
