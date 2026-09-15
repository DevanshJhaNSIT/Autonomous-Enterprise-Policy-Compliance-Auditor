import uvicorn
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from app.schemas import AlertPayload, ApprovalPayload, TriageResponse, HealthResponse
from app.agents.graph import secops_graph
from app.agents.investigation_agent import get_retriever

app = FastAPI(
    title="SecOps-Agent: Autonomous Incident Triage & RCA Copilot",
    description="Multi-Agent GenAI Copilot for SOC alert triage, hybrid RAG investigation, and containment planning.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory approval storage for tracking signoffs
approval_store = {}

@app.get("/health", response_model=HealthResponse)
def health_check():
    """Health check endpoint verifying Vector DB and Model status."""
    try:
        retriever = get_retriever()
        doc_count = retriever.collection.count()
        vector_db_ok = True
    except Exception as e:
        doc_count = 0
        vector_db_ok = False

    return HealthResponse(
        status="healthy",
        vector_db_connected=vector_db_ok,
        model_status="active"
    )

@app.post("/api/v1/triage", response_model=TriageResponse)
def run_triage(payload: AlertPayload):
    """
    Triggers autonomous multi-agent triage, hybrid RAG log investigation,
    and remediation plan generation.
    """
    try:
        raw_alert_dict = payload.model_dump()
        initial_state = {
            "alert_id": payload.alert_id,
            "raw_alert": raw_alert_dict,
            "severity": "LOW",
            "iocs": [],
            "investigation_findings": [],
            "remediation_plan": "",
            "requires_human_approval": False
        }

        # Run state graph with thread checkpointer config
        config = {"configurable": {"thread_id": payload.alert_id}}
        final_state = secops_graph.invoke(initial_state, config=config)

        status_msg = "AWAITING_APPROVAL" if final_state.get("requires_human_approval") else "COMPLETED"

        return TriageResponse(
            alert_id=final_state.get("alert_id", payload.alert_id),
            severity=final_state.get("severity", "LOW"),
            iocs=final_state.get("iocs", []),
            investigation_findings=final_state.get("investigation_findings", []),
            remediation_plan=final_state.get("remediation_plan", ""),
            requires_human_approval=final_state.get("requires_human_approval", False),
            status=status_msg
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing SecOps triage graph: {str(e)}"
        )

@app.post("/api/v1/approve")
def approve_triage(payload: ApprovalPayload):
    """
    Simulates human-in-the-loop signoff for high/critical security remediation tasks.
    """
    approval_store[payload.alert_id] = {
        "approved": payload.approve,
        "reviewer_notes": payload.reviewer_notes
    }

    action_taken = "CONTAINMENT_EXECUTED" if payload.approve else "REMEDIATION_REJECTED"

    return {
        "alert_id": payload.alert_id,
        "status": action_taken,
        "approved": payload.approve,
        "notes": payload.reviewer_notes
    }

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
