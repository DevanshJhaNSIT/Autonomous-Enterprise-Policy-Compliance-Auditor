from typing import Dict, Any, Literal
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from app.agents.state import AgentState
from app.agents.triage_agent import triage_agent_node
from app.agents.investigation_agent import investigation_agent_node
from app.agents.remediation_agent import remediation_agent_node

def human_approval_check_node(state: AgentState) -> Dict[str, Any]:
    """
    Human Approval Check Node:
    Verifies if approval is required. In a live system, this node can pause execution.
    """
    return {}

def route_after_remediation(state: AgentState) -> Literal["human_approval_check", "__end__"]:
    """Conditional router based on human approval requirement."""
    if state.get("requires_human_approval", False):
        return "human_approval_check"
    return END

def create_secops_graph():
    """Builds and compiles the SecOps Multi-Agent LangGraph workflow."""
    workflow = StateGraph(AgentState)

    # Add agent nodes
    workflow.add_node("triage", triage_agent_node)
    workflow.add_node("investigation", investigation_agent_node)
    workflow.add_node("remediation", remediation_agent_node)
    workflow.add_node("human_approval_check", human_approval_check_node)

    # Define edges
    workflow.set_entry_point("triage")
    workflow.add_edge("triage", "investigation")
    workflow.add_edge("investigation", "remediation")
    
    workflow.add_conditional_edges(
        "remediation",
        route_after_remediation,
        {
            "human_approval_check": "human_approval_check",
            END: END
        }
    )
    workflow.add_edge("human_approval_check", END)

    # Compile with MemorySaver checkpointer
    checkpointer = MemorySaver()
    app = workflow.compile(checkpointer=checkpointer)
    return app

# Singleton compiled graph app
secops_graph = create_secops_graph()
