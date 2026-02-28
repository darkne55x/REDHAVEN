#!/usr/bin/env python3
"""
REDHAVEN AI — Narrative Report Generator
==========================================
Generates HackerOne-quality vulnerability reports using AI.
Transforms raw scan data into professional narratives with
executive summaries, technical details, and remediation advice.

Usage:
    python3 -m ai_brain.report_generator /results/target.com
"""

import json
import sys
import time
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime

from .config import AIConfig, load_config
from .llm_client import LLMClient, Colors
from .finding_parser import FindingParser, ScanResults


# ============================================================================
# Report Prompts
# ============================================================================

REPORT_SYSTEM_PROMPT = """You are a professional security consultant writing a bug bounty report.
Your reports are clear, technical, and convincing. They follow HackerOne best practices.

Report structure:
- Executive summary for non-technical stakeholders
- Technical details for engineers
- Reproduction steps anyone can follow
- Impact assessment tied to business risk
- Remediation recommendations with code examples when applicable

Style:
- Professional but direct tone
- Use markdown formatting
- Include severity ratings (CVSS when applicable)
- Estimate real-world exploitation difficulty
- Reference relevant CWE IDs"""

REPORT_PROMPT_TEMPLATE = """
Generate a professional bug bounty report for the following scan results.

## TARGET INFORMATION
Target: {target}
Scan Date: {scan_date}
Technology Stack: {tech_stack}

## SCAN RESULTS SUMMARY
{findings_context}

## AI ANALYSIS (if available)
{ai_analysis}

## REPORT REQUIREMENTS
Generate a comprehensive report with:

1. **Executive Summary** (3-5 sentences, non-technical)

2. **Scope & Methodology**
   - Tools used: REDHAVEN v1.2.4 + AI Brain
   - What was tested and what wasn't

3. **Findings** (ordered by severity)
   For each finding:
   - Title (format: [SEVERITY] CWE-XXX: Description)
   - Description
   - Steps to Reproduce (with curl commands)
   - Impact
   - Remediation
   - References

4. **Attack Chain Analysis**
   How findings combine for maximum impact

5. **Risk Summary Table**
   | # | Finding | Severity | CVSS | Est. Bounty |

6. **Remediation Priority Matrix**
   What to fix first and why

7. **Total Estimated Bounty**
"""

EXECUTIVE_REPORT_PROMPT = """
Based on these findings, write a 1-page executive summary for non-technical stakeholders:

{findings_summary}

Requirements:
- No technical jargon
- Focus on business impact and risk
- Include a simple risk rating (Low/Medium/High/Critical)
- Recommend immediate actions
- Be concise (max 300 words)
"""


# ============================================================================
# Report Generator
# ============================================================================

class ReportGenerator:
    """Generate AI-powered narrative reports from scan results."""

    def __init__(self, config: AIConfig, target_dir: str):
        self.config = config
        self.target_dir = Path(target_dir)
        self.client = LLMClient(config)
        self.parser = FindingParser(target_dir)

    def generate_full_report(self) -> str:
        """Generate a comprehensive bug bounty report."""
        print(f"\n{Colors.CYAN}{'='*64}{Colors.RESET}")
        print(f"{Colors.CYAN}  REDHAVEN AI — REPORT GENERATOR{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*64}{Colors.RESET}")

        # Parse findings
        print(f"\n{Colors.BLUE}  [1/3] Loading scan data...{Colors.RESET}")
        results = self.parser.parse_all()

        if not results.findings:
            print(f"  {Colors.YELLOW}⚠ No findings to report.{Colors.RESET}")
            return ""

        findings_context = self.parser.to_prompt_context(results, max_items=30)

        # Load AI analysis if exists
        ai_analysis = ""
        ai_report_path = self.target_dir / "reports" / "ai_analysis.md"
        if ai_report_path.exists():
            try:
                ai_analysis = ai_report_path.read_text(encoding='utf-8', errors='ignore')[:3000]
            except Exception:
                pass

        # Generate report
        print(f"\n{Colors.BLUE}  [2/3] Generating report ({self.config.provider})...{Colors.RESET}")
        print(f"  {Colors.DIM}This may take 60-120 seconds...{Colors.RESET}")

        prompt = REPORT_PROMPT_TEMPLATE.format(
            target=results.target,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            tech_stack=", ".join(results.technologies[:10]) or "Unknown",
            findings_context=findings_context,
            ai_analysis=ai_analysis or "Not available (run smart_correlator first)",
        )

        start = time.time()
        report = self.client.analyze(prompt, system_prompt=REPORT_SYSTEM_PROMPT)
        elapsed = time.time() - start

        # Save report
        print(f"\n{Colors.BLUE}  [3/3] Saving report...{Colors.RESET}")
        report_path = self.target_dir / "reports" / "ai_report.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)

        header = (
            f"# REDHAVEN Security Assessment — {results.target}\n\n"
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
            f"**Tool:** REDHAVEN v1.2.4 + AI Brain\n"
            f"**Model:** {self.config.provider}/{self.config.model}\n"
            f"**Findings:** {len(results.findings)} total "
            f"({results.critical_count} critical, {results.high_count} high)\n\n"
            f"---\n\n"
        )

        with open(report_path, 'w') as f:
            f.write(header + report)

        print(f"  {Colors.GREEN}✓{Colors.RESET} Report saved: {report_path} ({elapsed:.1f}s)")

        # Also generate executive summary
        self._generate_executive(results, report_path.parent)

        return str(report_path)

    def _generate_executive(self, results: ScanResults, reports_dir: Path):
        """Generate a short executive summary."""
        try:
            summary = results.summary_dict()
            prompt = EXECUTIVE_REPORT_PROMPT.format(
                findings_summary=json.dumps(summary, indent=2, default=str)
            )
            exec_report = self.client.analyze(prompt, system_prompt=REPORT_SYSTEM_PROMPT)

            exec_path = reports_dir / "ai_executive_summary.md"
            with open(exec_path, 'w') as f:
                f.write(f"# Executive Summary — {results.target}\n\n")
                f.write(exec_report)

            print(f"  {Colors.GREEN}✓{Colors.RESET} Executive summary: {exec_path}")
        except Exception as e:
            print(f"  {Colors.YELLOW}⚠{Colors.RESET} Executive summary generation failed: {e}")

    def generate_finding_report(self, category: str) -> str:
        """Generate a detailed report for a specific finding category."""
        results = self.parser.parse_all()
        findings = results.get_by_category(category)

        if not findings:
            return f"No {category} findings to report."

        details = "\n".join(f"- {f.url or f.raw_data[:120]}" for f in findings[:20])
        prompt = f"""
        Write a detailed bug bounty report for these {category.upper()} findings:
        
        Target: {results.target}
        Tech Stack: {', '.join(results.technologies[:5])}
        
        Findings ({len(findings)} total):
        {details}
        
        Include: Description, Steps to Reproduce (curl), Impact, CVSS score, Remediation.
        """

        return self.client.analyze(prompt, system_prompt=REPORT_SYSTEM_PROMPT)


# ============================================================================
# CLI
# ============================================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: report_generator.py <target_directory>")
        sys.exit(1)

    target_dir = sys.argv[1]
    if not Path(target_dir).is_dir():
        print(f"[!] Directory not found: {target_dir}")
        sys.exit(1)

    config = load_config()
    generator = ReportGenerator(config, target_dir)
    generator.generate_full_report()
