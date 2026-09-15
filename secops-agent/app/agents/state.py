from typing import TypedDict, List, Dict, Any

class AgentState(TypedDict):
    alert_id: str
    raw_alert: Dict[str, Any]
    severity: str
    iocs: List[str]
    investigation_findings: List[str]
    remediation_plan: str
    requires_human_approval: bool
