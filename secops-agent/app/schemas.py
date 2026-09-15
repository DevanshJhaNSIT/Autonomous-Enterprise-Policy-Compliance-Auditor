from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class AlertPayload(BaseModel):
    alert_id: str = Field(..., json_schema_extra={"example": "ALT-9901"})
    source: Optional[str] = Field(default="SOC_SIEM", json_schema_extra={"example": "SSH_Auth_Daemon"})
    event_type: str = Field(..., json_schema_extra={"example": "SSH_BRUTE_FORCE"})
    ip_address: Optional[str] = Field(default=None, json_schema_extra={"example": "192.168.1.105"})
    username: Optional[str] = Field(default=None, json_schema_extra={"example": "root"})
    timestamp: Optional[str] = Field(default=None, json_schema_extra={"example": "2026-09-15T22:00:00Z"})
    fail_count: Optional[int] = Field(default=0, json_schema_extra={"example": 42})
    raw_log: Optional[str] = Field(default=None)

class ApprovalPayload(BaseModel):
    alert_id: str = Field(..., json_schema_extra={"example": "ALT-9901"})
    approve: bool = Field(..., json_schema_extra={"example": True})
    reviewer_notes: Optional[str] = Field(default="Approved by SOC Lead analyst", json_schema_extra={"example": "Containment verified"})

class TriageResponse(BaseModel):
    alert_id: str
    severity: str
    iocs: List[str]
    investigation_findings: List[str]
    remediation_plan: str
    requires_human_approval: bool
    status: str

class HealthResponse(BaseModel):
    status: str
    vector_db_connected: bool
    model_status: str
