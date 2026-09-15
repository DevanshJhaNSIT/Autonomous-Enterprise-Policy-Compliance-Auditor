from typing import Dict, Any
from app.agents.state import AgentState

def remediation_agent_node(state: AgentState) -> Dict[str, Any]:
    """
    Remediation Agent Node:
    Generates actionable containment commands, structured markdown incident summary,
    and flags human approval requirement for High/Critical alerts.
    """
    alert_id = state.get("alert_id", "UNKNOWN")
    severity = state.get("severity", "LOW")
    iocs = state.get("iocs", [])
    findings = state.get("investigation_findings", [])
    raw_alert = state.get("raw_alert", {})

    # Extract target IP and user from IoCs or raw_alert
    target_ip = "192.168.1.105"
    target_user = "root"
    for ioc in iocs:
        if ioc.startswith("IP:"):
            target_ip = ioc.replace("IP:", "")
        elif ioc.startswith("User:"):
            target_user = ioc.replace("User:", "")

    # Build containment commands
    containment_commands = [
        f"sudo iptables -A INPUT -s {target_ip} -j DROP",
        f"sudo ufw deny from {target_ip} to any",
        f"sudo usermod -L {target_user}",
        f"sudo pkill -u {target_user}"
    ]

    # Format structured Markdown remediation plan
    plan_md = f"""# Incident Remediation & RCA Report: {alert_id}

## 1. Executive Summary
- **Alert ID**: {alert_id}
- **Assigned Severity**: `{severity}`
- **Event Type**: {raw_alert.get('event_type', 'SECURITY_ALERT')}
- **Target User**: `{target_user}`
- **Attacker IP**: `{target_ip}`

## 2. Extracted IoCs
{"".join([f"- {ioc}\n" for ioc in iocs])}

## 3. Investigation & RAG Findings
{"".join([f"- {finding[:150]}...\n" for finding in findings])}

## 4. Immediate Containment Commands
```bash
{chr(10).join(containment_commands)}
```

## 5. Required Actions
- Lock user account `{target_user}` and inspect active subprocesses.
- Verify perimeter firewall rules.
- Request human-in-the-loop signoff before applying permanent network drop rules.
"""

    requires_approval = severity in ["HIGH", "CRITICAL"]

    return {
        "remediation_plan": plan_md,
        "requires_human_approval": requires_approval
    }
