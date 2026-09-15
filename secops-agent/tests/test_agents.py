import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.agents.state import AgentState
from app.agents.triage_agent import triage_agent_node, evaluate_severity_heuristic, extract_rule_based_iocs
from app.agents.investigation_agent import investigation_agent_node
from app.agents.remediation_agent import remediation_agent_node
from app.agents.graph import secops_graph
from app.rag.vector_store import HybridRetriever

client = TestClient(app)

def test_triage_agent_heuristic():
    alert_critical = {
        "event_type": "PRIVILEGE_ESCALATION",
        "raw_log": "pkexec bash by deploy user",
        "target_user": "root"
    }
    severity = evaluate_severity_heuristic(alert_critical)
    assert severity == "CRITICAL"

    alert_high = {
        "event_type": "SSH_BRUTE_FORCE",
        "fail_count": 50,
        "source_ip": "192.168.1.105"
    }
    iocs = extract_rule_based_iocs(alert_high)
    assert "IP:192.168.1.105" in iocs
    assert evaluate_severity_heuristic(alert_high) == "HIGH"

def test_hybrid_retriever_rrf():
    retriever = HybridRetriever(persist_dir="./data/test_chroma_db")
    docs = [
        {"id": "doc1", "content": "SSH brute force mitigation using iptables drop rules.", "metadata": {"type": "runbook"}},
        {"id": "doc2", "content": "Privilege escalation remediation and pkexec process termination.", "metadata": {"type": "runbook"}},
        {"id": "doc3", "content": "Firewall configuration for outbound egress blocking.", "metadata": {"type": "runbook"}}
    ]
    retriever.add_documents(docs)
    
    results = retriever.hybrid_search("SSH brute force iptables", top_k=2)
    assert len(results) > 0
    assert "rrf_score" in results[0]
    assert results[0]["id"] == "doc1"

def test_remediation_agent_node():
    state: AgentState = {
        "alert_id": "ALT-TEST-01",
        "raw_alert": {"event_type": "SSH_BRUTE_FORCE", "fail_count": 25},
        "severity": "HIGH",
        "iocs": ["IP:192.168.1.105", "User:root"],
        "investigation_findings": ["Runbook matches SSH mitigation"],
        "remediation_plan": "",
        "requires_human_approval": False
    }

    res = remediation_agent_node(state)
    assert res["requires_human_approval"] is True
    assert "iptables -A INPUT -s 192.168.1.105 -j DROP" in res["remediation_plan"]

def test_langgraph_workflow_execution():
    initial_state: AgentState = {
        "alert_id": "ALT-GRAPH-99",
        "raw_alert": {
            "event_type": "PRIVILEGE_ESCALATION",
            "source_ip": "192.168.1.105",
            "target_user": "deploy"
        },
        "severity": "LOW",
        "iocs": [],
        "investigation_findings": [],
        "remediation_plan": "",
        "requires_human_approval": False
    }

    config = {"configurable": {"thread_id": "ALT-GRAPH-99"}}
    output_state = secops_graph.invoke(initial_state, config=config)

    assert output_state["severity"] == "CRITICAL"
    assert output_state["requires_human_approval"] is True
    assert len(output_state["iocs"]) > 0

def test_fastapi_endpoints():
    # Test GET /health
    health_res = client.get("/health")
    assert health_res.status_code == 200
    assert health_res.json()["status"] == "healthy"

    # Test POST /api/v1/triage
    payload = {
        "alert_id": "ALT-API-01",
        "source": "SSH_Auth_Daemon",
        "event_type": "SSH_BRUTE_FORCE",
        "ip_address": "192.168.1.105",
        "username": "root",
        "fail_count": 42
    }
    triage_res = client.post("/api/v1/triage", json=payload)
    assert triage_res.status_code == 200
    data = triage_res.json()
    assert data["alert_id"] == "ALT-API-01"
    assert data["severity"] in ["HIGH", "CRITICAL"]
    assert data["requires_human_approval"] is True
    assert "iptables" in data["remediation_plan"]

    # Test POST /api/v1/approve
    approve_res = client.post("/api/v1/approve", json={"alert_id": "ALT-API-01", "approve": True, "reviewer_notes": "All clean"})
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "CONTAINMENT_EXECUTED"
