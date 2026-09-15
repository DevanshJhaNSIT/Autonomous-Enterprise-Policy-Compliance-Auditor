import re
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from app.agents.state import AgentState

class TriageDecision(BaseModel):
    severity: str = Field(description="Alert severity level: LOW, MEDIUM, HIGH, or CRITICAL")
    iocs: List[str] = Field(description="Extracted Indicators of Compromise (IPs, usernames, hashes, attack types)")
    reasoning: str = Field(description="Reasoning behind triage severity assignment")

def extract_rule_based_iocs(raw_alert: Dict[str, Any]) -> List[str]:
    """Heuristic IoC extractor from alert dictionary values and raw text."""
    iocs = set()
    text = str(raw_alert)
    
    # Extract IPv4 addresses
    ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    for ip in ip_matches:
        if not ip.startswith("127."):
            iocs.add(f"IP:{ip}")
            
    # Extract keys
    for key in ["source_ip", "ip_address", "src_ip"]:
        if key in raw_alert and raw_alert[key]:
            iocs.add(f"IP:{raw_alert[key]}")
            
    for key in ["target_user", "username", "user"]:
        if key in raw_alert and raw_alert[key]:
            iocs.add(f"User:{raw_alert[key]}")
            
    for key in ["event_type", "attack_type"]:
        if key in raw_alert and raw_alert[key]:
            iocs.add(f"Attack:{raw_alert[key]}")
            
    return sorted(list(iocs))

def evaluate_severity_heuristic(raw_alert: Dict[str, Any]) -> str:
    """Classifies alert severity based on rules if LLM is offline or in mock mode."""
    text = str(raw_alert).lower()
    fail_count = raw_alert.get("fail_count", 0)
    
    if "privilege_escalation" in text or "root" in text or "pkexec" in text:
        return "CRITICAL"
    elif "brute_force" in text or fail_count > 10:
        return "HIGH"
    elif "unauthorized" in text or "denied" in text:
        return "MEDIUM"
    return "LOW"

def triage_agent_node(state: AgentState) -> Dict[str, Any]:
    """
    Triage Agent Node:
    Analyzes raw_alert, extracts IoCs, and assigns severity level.
    """
    raw_alert = state.get("raw_alert", {})
    alert_id = state.get("alert_id", "UNKNOWN")

    # Attempt rule-based extraction as standard baseline
    extracted_iocs = extract_rule_based_iocs(raw_alert)
    assigned_severity = evaluate_severity_heuristic(raw_alert)

    return {
        "severity": assigned_severity,
        "iocs": extracted_iocs
    }
