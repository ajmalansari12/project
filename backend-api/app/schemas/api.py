"""Pydantic request and response schemas for Sentinel-EDR REST API endpoints."""

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.contracts import ComponentAvailability, IncidentStatus, SecurityVerdict


class HealthResponse(BaseModel):
    """API liveness health check response."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(
        default="healthy",
        description="Operational health indicator of the API process.",
    )
    service: str = Field(
        default="sentinel-edr-api",
        description="Canonical service identifier.",
    )
    version: str = Field(
        ...,
        description="Configured application version.",
    )
    timestamp: str = Field(
        ...,
        description="UTC timestamp formatted according to ISO-8601.",
    )


class ComponentStatusMap(BaseModel):
    """Availability states of individual backend subsystems."""

    model_config = ConfigDict(extra="forbid")

    database: ComponentAvailability = Field(
        ...,
        description="Operational availability of the persistent relational database.",
    )
    signature_engine: ComponentAvailability = Field(
        ...,
        description="Operational availability of the SHA-256 and YARA signature engines.",
    )
    ml_engine: ComponentAvailability = Field(
        ...,
        description="Operational availability of the machine-learning inference pipeline.",
    )
    behavioral_monitor: ComponentAvailability = Field(
        ...,
        description="Operational availability of the real-time endpoint behavioral sensor.",
    )
    ai_reporting: ComponentAvailability = Field(
        ...,
        description="Operational availability of the AI forensic explanation service.",
    )


class StatusResponse(BaseModel):
    """System-wide component availability and health overview."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(
        ...,
        description="Overall system status ('operational', 'degraded', 'unavailable').",
    )
    components: ComponentStatusMap = Field(
        ...,
        description="Fine-grained health status mapping per subsystem.",
    )
    timestamp: str = Field(
        ...,
        description="UTC timestamp of the status evaluation formatted as ISO-8601.",
    )


class PaginationMeta(BaseModel):
    """Pagination metadata container adhering to api_spec.md."""

    model_config = ConfigDict(extra="forbid")

    page: int = Field(..., ge=1, description="Current 1-indexed page number.")
    page_size: int = Field(..., ge=1, le=100, description="Items returned per page.")
    total_items: int = Field(..., ge=0, description="Total matching records across all pages.")
    total_pages: int = Field(..., ge=0, description="Total number of available pages.")


class IncidentSummaryResponse(BaseModel):
    """Summary representation of a security incident for collection listing."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(..., description="Unique UUID identifier of the incident.")
    title: str = Field(..., description="Human-readable title describing the security finding.")
    description: Optional[str] = Field(None, description="Detailed incident narrative or summary.")
    incident_type: str = Field(..., description="Classification category of the incident.")
    verdict: SecurityVerdict = Field(..., description="Assigned security classification verdict.")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Normalized risk score (0.0 - 100.0).")
    status: IncidentStatus = Field(..., description="Investigation and handling lifecycle status.")
    file_path: Optional[str] = Field(None, description="Filesystem path associated with the finding.")
    file_hash: Optional[str] = Field(None, description="SHA-256 hash digest of the associated file.")
    process_id: Optional[int] = Field(None, ge=0, description="Process ID associated with the detection.")
    detected_at: str = Field(..., description="UTC ISO-8601 timestamp when detection occurred.")
    created_at: str = Field(..., description="UTC ISO-8601 timestamp when record was persisted.")
    updated_at: str = Field(..., description="UTC ISO-8601 timestamp of last record update.")
    resolved_at: Optional[str] = Field(None, description="UTC ISO-8601 timestamp when incident was resolved.")


class IncidentDetailResponse(IncidentSummaryResponse):
    """Detailed incident response including related entity counts."""

    analysis_job_id: Optional[str] = Field(None, description="Originating analysis job identifier if applicable.")
    evidence_count: int = Field(default=0, ge=0, description="Number of associated detection evidence records.")
    response_action_count: int = Field(default=0, ge=0, description="Number of executed or pending response actions.")


class IncidentListResponse(BaseModel):
    """Paginated response envelope for security incident collections."""

    model_config = ConfigDict(extra="forbid")

    items: List[IncidentSummaryResponse] = Field(..., description="Array of incident summaries on current page.")
    pagination: PaginationMeta = Field(..., description="Pagination metadata for the query.")
