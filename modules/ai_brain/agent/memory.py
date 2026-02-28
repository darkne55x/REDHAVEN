import os
import json
from datetime import datetime
from typing import Dict, List, Any

class AgentMemory:
    """
    Stores the context of the current engagement for the RedHaven AI Agent.
    This includes discovered targets, running tasks, findings, and chat history.
    """
    def __init__(self, target_domain: str = None):
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.target_domain = target_domain
        
        # State storage
        self.discovered_subdomains: set = set()
        self.discovered_ips: set = set()
        self.open_ports: Dict[str, List[int]] = {}
        self.findings: List[Dict[str, Any]] = []
        
        # Execution history to prevent loops
        self.executed_tools: List[Dict[str, Any]] = []
        
        # Chat history for the LLM context
        self.chat_history: List[Dict[str, str]] = []
        
    def add_message(self, role: str, content: str):
        """Add a message to the chat history (user, assistant, tool)."""
        self.chat_history.append({"role": role, "content": content})
        
    def record_tool_execution(self, tool_name: str, args: dict, result_summary: str):
        """Record that a tool was run to prevent the agent from repeating it pointlessly."""
        self.executed_tools.append({
            "timestamp": datetime.now().isoformat(),
            "tool": tool_name,
            "args": args,
            "result": result_summary
        })
        
    def add_finding(self, severity: str, title: str, description: str):
        self.findings.append({
            "severity": severity,
            "title": title,
            "description": description,
            "timestamp": datetime.now().isoformat()
        })
        
    def add_subdomains(self, subdomains: List[str]):
        self.discovered_subdomains.update(subdomains)
        
    def get_context_summary(self) -> str:
        """Generates a text summary of the current engagement state for the LLM prompt."""
        summary = [
            f"=== ENGAGEMENT CONTEXT ===",
            f"Target Domain: {self.target_domain or 'None set yet'}",
            f"Discovered Subdomains: {len(self.discovered_subdomains)}",
            f"Total Findings Found: {len(self.findings)}",
            f"Tools Executed So Far: {len(self.executed_tools)}"
        ]
        
        if self.executed_tools:
            summary.append("\nRecent Actions:")
            for t in self.executed_tools[-3:]:  # Show last 3
                summary.append(f"- Ran {t['tool']} with args {t['args']}")
                
        if self.findings:
            summary.append("\nTop Findings:")
            # Sort by severity (naively)
            high_findings = [f for f in self.findings if f['severity'] in ['CRITICAL', 'HIGH']]
            for f in high_findings[:5]:
                summary.append(f"- [{f['severity']}] {f['title']}")
                
        return "\n".join(summary)

    def save_state(self, output_dir: str):
        """Save the memory state to disk."""
        os.makedirs(output_dir, exist_ok=True)
        state_file = os.path.join(output_dir, f"agent_memory_{self.session_id}.json")
        
        state = {
            "session_id": self.session_id,
            "target_domain": self.target_domain,
            "discovered_subdomains": list(self.discovered_subdomains),
            "discovered_ips": list(self.discovered_ips),
            "open_ports": self.open_ports,
            "findings": self.findings,
            "executed_tools": self.executed_tools
        }
        
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=2)
            
        return state_file
