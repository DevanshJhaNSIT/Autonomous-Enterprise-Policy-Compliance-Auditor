from typing import Dict, Any, List
from app.agents.state import AgentState
from app.rag.vector_store import HybridRetriever
from app.rag.ingest import ingest_knowledge_base

_retriever = None

def get_retriever() -> HybridRetriever:
    global _retriever
    if _retriever is None:
        _retriever = ingest_knowledge_base()
    return _retriever

def investigation_agent_node(state: AgentState) -> Dict[str, Any]:
    """
    Investigation Agent Node:
    Takes extracted IoCs and raw alert context to query the Hybrid RAG retriever
    for relevant SOC runbooks and matching log evidence.
    """
    iocs = state.get("iocs", [])
    raw_alert = state.get("raw_alert", {})
    alert_id = state.get("alert_id", "")
    
    # Formulate search queries from IoCs and alert description
    query_parts = iocs + [str(raw_alert.get("event_type", "")), str(raw_alert.get("description", ""))]
    query = " ".join([p for p in query_parts if p])
    if not query.strip():
        query = "SSH brute force privilege escalation mitigation"

    retriever = get_retriever()
    matched_docs = retriever.hybrid_search(query, top_k=3)

    findings = []
    for doc in matched_docs:
        meta = doc.get("metadata", {})
        source_name = meta.get("source", "knowledge_base")
        findings.append(f"[{source_name}] {doc['content']}")

    if not findings:
        findings.append("No direct historical match found in runbooks. Follow standard containment protocol.")

    return {
        "investigation_findings": findings
    }
