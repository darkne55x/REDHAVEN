# REDHAVEN v1.2.4 — Elite Bug Bounty Framework (AI Core v2.0)

![Version](https://img.shields.io/badge/version-1.2.4-red?style=for-the-badge)
![License](https://img.shields.io/badge/license-GPLv3-green?style=for-the-badge)
![Status](https://img.shields.io/badge/status-Elite_Analyst_Edition-black?style=for-the-badge)
![AI Powered](https://img.shields.io/badge/AI-Post--Scan_Analysis-blue?style=for-the-badge)

> **Execution is for scripts. Intelligence is for Analysts.**

REDHAVEN v1.2.4 introduces the **AI Elite Analyst** model. Instead of struggling with tool execution environments, the AI now acts as a high-level security consultant that analyzes the results already collected by the framework. It reads your `/results/` directory, identifies attack chains, finds dorks, and suggests exactly what to test manually to get the bounty.

---

## 🧠 The AI Elite Analyst (New in v1.2.4)

The AI no longer tries to run bash scripts directly. Instead, it leverages its analytical strengths to interpret complex scan data:

1. **Post-Scan Intelligence**: Run your scans with the classic `start.sh` (Mode 80/81). Once done, launch `redhaven-chat.py`.
2. **Result Visualization**: Ask the agent *"What targets do I have?"* or *"Analyze gigared.com"*.
3. **Deep-Dive Analysis**: The AI reads subdomains, open ports, endpoint lists, and vulnerability files. It finds patterns like *"I see an IDOR candidate on /api/user mapping to a 403 bypass on /admin"*.
4. **Actionable Guidance**: The agent tells you exactly which RedHaven mode to run next or which manual PoC to try for maximum impact.

---

## 🚀 Getting Started

### 1. Installation

Clone the repository:

```bash
git clone https://github.com/darkne55/REDHAVEN.git
cd REDHAVEN
```

### 2. Install AI Dependencies

To use the AI Analyst Chat, install the Python requirements:

```bash
pip3 install prompt_toolkit requests pyyaml
pip3 install google-genai  # Required if using Gemini backend
```

### 3. Configure your AI Provider

Edit `config/ai_config.yaml` to set your provider (Ollama for local, or Gemini/OpenAI for speed):

```yaml
ai:
  enabled: true
  provider: "gemini"       # Options: ollama, gemini, openai, deepseek
  model: "gemini-2.0-flash-exp" 
```

---

## 🎮 Workflow

REDHAVEN v1.2.4 separates **Execution** from **Analysis**:

### Phase 1: Execution (The Classic Scanner)
Use the Docker-powered scanner to gather data.
```bash
./start.sh
```
*Run Mode 80 (Quick Recon) or Mode 81 (Vuln Hunt).*

### Phase 2: Analysis (The AI Elite Analyst)
Let the AI find the "needle in the haystack" within your results.
```bash
./redhaven-chat.py
```
*Analyze your findings, find hidden dorks, and plan your manual exploitation.*

---

## ⚡ v1.2.4 Key Features

- **Read-Only Intelligence**: The AI tools (`analyze_target`, `analyze_finding`, `suggest_next_steps`) safely read scan data without environment conflicts.
- **Performance Fixes**: JS analysis (LinkFinder/JSLuice) optimized to avoid hangs on large targets.
- **Improved Recon Filtering**: `clean_targets()` in `recon.sh` now aggressively filters garbage URLs and MIME-type leaks.
- **Elite OSINT**: Shodan/Censys/Google Dorks dynamically linked for one-click discovery.

---

## 📜 License

Educational and authorized bug bounty use only. Respect the target's scope and legal requirements.

---

## 🏆 Acknowledgments

- **[Nelux1](https://github.com/Nelux1)**: Advanced reconnaissance integration.
- **The AI Community**: For the advancements in LLM integration.

**Ready to find critical vulnerabilities? Consult your REDHAVEN AI Analyst now.**
