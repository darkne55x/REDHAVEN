#!/usr/bin/env python3
"""
REDHAVEN AI — Smart Correlator
================================
LLM-powered vulnerability correlation engine that replaces the static
if/then chain detection in correlator.py with intelligent analysis.

The Smart Correlator:
1. Loads all findings from a scan
2. Sends them to the LLM with specialized security prompts
3. Returns actionable attack chains, prioritized exploitation plans, 
   and concrete PoC suggestions

Usage:
    python3 -m ai_brain.smart_correlator /results/target.com

    or programmatically:
    from ai_brain.smart_correlator import SmartCorrelator
    correlator = SmartCorrelator(config, "/results/target.com")
    analysis = correlator.run()
"""

import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

from .config import AIConfig, load_config
from .llm_client import LLMClient, Colors
from .finding_parser import FindingParser, ScanResults

# ============================================================================
# System Prompts
# ============================================================================

CORRELATOR_SYSTEM_PROMPT = """You are an elite bug bounty hunter and penetration tester with 10+ years of experience.
You are analyzing the automated scan results from REDHAVEN, an offensive security framework.

Your job is to:
1. Identify REAL, exploitable vulnerabilities (not noise or false positives)
2. Discover multi-stage attack chains that combine findings
3. Prioritize findings by actual exploitability and business impact
4. Generate concrete, step-by-step Proof of Concept (PoC) instructions
5. Suggest additional tests the scanner may have missed

Rules:
- Be PRECISE. Only flag findings you are confident are exploitable.
- Think like an attacker. What would YOU exploit first?
- Consider the tech stack when assessing exploitability.
- Estimate realistic bug bounty payouts based on severity.
- Use technical language. Your audience is a red team operator.
- Output structured analysis, not generic advice."""

CORRELATION_PROMPT_TEMPLATE = """
## SCAN RESULTS TO ANALYZE

{findings_context}

## YOUR ANALYSIS

Provide your analysis in the following structure:

### 1. EXECUTIVE SUMMARY
Brief overview of the target's security posture (2-3 sentences).

### 2. CRITICAL FINDINGS (Immediate Exploitation)
List findings that are ready to exploit NOW, with:
- Vulnerability type and location
- Why you believe it's real (not a false positive)
- Estimated severity (Critical/High/Medium/Low)
- Estimated bounty value

### 3. ATTACK CHAINS
Identify multi-stage attack chains. For each chain:
- Chain name (e.g., "403 Bypass → IDOR → PII Leak")
- Steps to execute
- Combined impact
- Multiplied bounty estimate

### 4. TOP 3 EXPLOITATION PLAN
For the top 3 most impactful findings, provide:
- Step-by-step PoC using curl/Python
- Expected response
- How to maximize impact for the report

### 5. MISSED OPPORTUNITIES
What should the scanner re-test with different parameters?
What manual tests would you add?

### 6. BOUNTY ESTIMATE
Total estimated bounty for all valid findings.
"""

PHASE_ANALYSIS_PROMPT = """
## POST-PHASE ANALYSIS

The following RedHaven module just completed: {phase_name}

Results generated:
{phase_results}

Previous findings context:
{previous_context}

Based on these new results:
1. Are any findings immediately exploitable?
2. Do these results change the attack strategy?
3. What should the NEXT module focus on?
4. Any findings that need deeper investigation?

Be concise. Focus on actionable intelligence only.
"""


# ============================================================================
# Smart Correlator
# ============================================================================

class SmartCorrelator:
    """
    AI-powered vulnerability correlation engine.
    
    Replaces the static chain detection in correlator.py with LLM analysis
    that can understand context, suggest novel chains, and generate PoCs.
    """

    def __init__(self, config: AIConfig, target_dir: str):
        self.config = config
        self.target_dir = Path(target_dir)
        self.client = LLMClient(config)
        self.parser = FindingParser(target_dir, max_findings=config.max_findings_per_prompt)
        self.results: Optional[ScanResults] = None

    def run(self) -> Dict[str, Any]:
        """
        Run full AI correlation analysis on scan results.
        Returns structured analysis with chains, PoCs, and bounty estimates.
        """
        print(f"\n{Colors.CYAN}{'='*64}{Colors.RESET}")
        print(f"{Colors.CYAN}  REDHAVEN AI — SMART CORRELATION ENGINE{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*64}{Colors.RESET}")

        # 1. Parse all findings
        print(f"\n{Colors.BLUE}  [1/4] Parsing scan results...{Colors.RESET}")
        self.results = self.parser.parse_all()
        summary = self.results.summary_dict()

        print(f"  {Colors.GREEN}✓{Colors.RESET} {summary['total_findings']} findings loaded "
              f"({summary['critical']} critical, {summary['high']} high)")
        print(f"  {Colors.GREEN}✓{Colors.RESET} {summary['subdomains_count']} subdomains, "
              f"{summary['alive_urls_count']} alive URLs")
        print(f"  {Colors.GREEN}✓{Colors.RESET} Tech stack: {', '.join(summary['tech_stack'][:5]) or 'Unknown'}")

        if summary['total_findings'] == 0:
            print(f"\n{Colors.YELLOW}  ⚠ No findings to analyze. Run some scan modules first.{Colors.RESET}")
            return {"status": "no_findings", "analysis": None}

        # 2. Generate context for LLM
        print(f"\n{Colors.BLUE}  [2/4] Building analysis context...{Colors.RESET}")
        findings_context = self.parser.to_prompt_context(self.results)
        prompt = CORRELATION_PROMPT_TEMPLATE.format(findings_context=findings_context)

        # 3. Run AI analysis
        print(f"\n{Colors.BLUE}  [3/4] Running AI analysis ({self.config.provider}/{self.config.model})...{Colors.RESET}")
        print(f"  {Colors.DIM}This may take 30-90 seconds depending on model...{Colors.RESET}")

        start_time = time.time()
        analysis = self.client.analyze(prompt, system_prompt=CORRELATOR_SYSTEM_PROMPT)
        elapsed = time.time() - start_time

        print(f"  {Colors.GREEN}✓{Colors.RESET} Analysis complete in {elapsed:.1f}s")

        # 4. Format and save results
        print(f"\n{Colors.BLUE}  [4/4] Saving results...{Colors.RESET}")
        result = {
            "status": "success",
            "target": self.results.target,
            "summary": summary,
            "ai_analysis": analysis,
            "provider": self.config.provider,
            "model": self.config.model,
            "analysis_time_seconds": round(elapsed, 1),
        }

        # Save JSON
        json_path = self.target_dir / "reports" / "ai_correlation.json"
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w') as f:
            json.dump(result, f, indent=2, default=str)

        # Save readable analysis
        md_path = self.target_dir / "reports" / "ai_analysis.md"
        with open(md_path, 'w') as f:
            f.write(f"# REDHAVEN AI Analysis — {self.results.target}\n\n")
            f.write(f"**Analyzed:** {summary['total_findings']} findings | ")
            f.write(f"**Model:** {self.config.provider}/{self.config.model} | ")
            f.write(f"**Time:** {elapsed:.1f}s\n\n")
            f.write("---\n\n")
            f.write(analysis)

        print(f"  {Colors.GREEN}✓{Colors.RESET} JSON:     {json_path}")
        print(f"  {Colors.GREEN}✓{Colors.RESET} Markdown: {md_path}")

        # Print analysis to terminal
        print(f"\n{Colors.CYAN}{'='*64}{Colors.RESET}")
        print(f"{Colors.CYAN}  AI ANALYSIS OUTPUT{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*64}{Colors.RESET}\n")
        print(analysis)
        print(f"\n{Colors.CYAN}{'='*64}{Colors.RESET}")

        return result

    def analyze_phase(self, phase_name: str, phase_results: str,
                      previous_context: str = "") -> str:
        """
        Run a quick AI analysis after a specific phase completes.
        Used for real-time decision making during scans.
        """
        if not self.config.analyze_after_phase:
            return ""

        prompt = PHASE_ANALYSIS_PROMPT.format(
            phase_name=phase_name,
            phase_results=phase_results[:2000],
            previous_context=previous_context[:1000],
        )

        return self.client.analyze(prompt, system_prompt=CORRELATOR_SYSTEM_PROMPT)


# ============================================================================
# Legacy Compatibility — Run the old correlator logic alongside AI
# ============================================================================

def run_hybrid_correlation(target_dir: str, config: Optional[AIConfig] = None):
    """
    Run both the original static correlator AND the AI correlator.
    This provides backward compatibility while adding AI insights.
    """
    if config is None:
        config = load_config()

    # Always run legacy correlator (it's fast and reliable)
    try:
        # Import the original correlator
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from correlator import analyze_chains
        print(f"\n{Colors.BLUE}[*] Running legacy correlation engine...{Colors.RESET}")
        analyze_chains(target_dir)
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Legacy correlator error: {e}{Colors.RESET}")

    # Run AI correlator if enabled
    if config.enabled:
        correlator = SmartCorrelator(config, target_dir)
        return correlator.run()
    else:
        print(f"\n{Colors.DIM}[i] AI analysis disabled in config.{Colors.RESET}")
        return {"status": "disabled"}


# ============================================================================
# CLI Entry Point
# ============================================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: smart_correlator.py <target_directory>")
        print(f"Example: smart_correlator.py /results/target.com")
        sys.exit(1)

    target_dir = sys.argv[1]
    if not Path(target_dir).is_dir():
        print(f"{Colors.RED}[!] Directory not found: {target_dir}{Colors.RESET}")
        sys.exit(1)

    # Load config and run
    config = load_config()
    result = run_hybrid_correlation(target_dir, config)

    if result.get("status") == "success":
        print(f"\n{Colors.GREEN}[✓] REDHAVEN AI analysis complete.{Colors.RESET}")
    elif result.get("status") == "no_findings":
        print(f"\n{Colors.YELLOW}[!] No findings to analyze.{Colors.RESET}")
