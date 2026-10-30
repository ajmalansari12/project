"""Incident management API endpoints for listing and retrieving security findings."""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.dependencies import get_db_session
from app.models.detection_evidence import DetectionEvidence
from app.models.response_action import ResponseAction
from app.schemas.api import IncidentDetailResponse, IncidentListResponse, IncidentSummaryResponse, PaginationMeta
from app.schemas.contracts import IncidentStatus, SecurityVerdict
from app.services.errors import ValidationError
from app.services.incident_service import get_incident_or_raise, list_incidents

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get(
    "",
    response_model=IncidentListResponse,
    summary="List Security Incidents",
    description="Retrieve a paginated collection of security findings with optional filtering.",
)
def list_security_incidents(
    page: int = Query(default=1, ge=1, description="Page number, starting at 1"),
    page_size: int = Query(default=20, ge=1, le=100, description="Number of records per page (max 100)"),
    verdict: Optional[str] = Query(default=None, description="Filter by security verdict (BENIGN, SUSPICIOUS, MALICIOUS)"),
    status: Optional[str] = Query(default=None, description="Filter by incident status (OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED)"),
    session: Session = Depends(get_db_session),
) -> IncidentListResponse:
    """List security incidents using bounded pagination and deterministic ordering."""
    if verdict is not None and verdict not in {v.value for v in SecurityVerdict}:
        raise ValidationError(f"Invalid verdict '{verdict}'. Allowed: {sorted([v.value for v in SecurityVerdict])}", field="verdict")

    if status is not None and status not in {s.value for s in IncidentStatus}:
        raise ValidationError(f"Invalid status '{status}'. Allowed: {sorted([s.value for s in IncidentStatus])}", field="status")

    paginated = list_incidents(
        session,
        page=page,
        page_size=page_size,
        verdict=verdict,
        status=status,
    )

    items: List[IncidentSummaryResponse] = [
        IncidentSummaryResponse(
            incident_id=inc.incident_id,
            title=inc.title,
            description=inc.description,
            incident_type=inc.incident_type,
            verdict=SecurityVerdict(inc.verdict),
            risk_score=inc.risk_score,
            status=IncidentStatus(inc.status),
            file_path=inc.file_path,
            file_hash=inc.file_hash,
            process_id=inc.process_id,
            detected_at=inc.detected_at,
            created_at=inc.created_at,
            updated_at=inc.updated_at,
            resolved_at=inc.resolved_at,
        )
        for inc in paginated.items
    ]

    pagination = PaginationMeta(
        page=paginated.page,
        page_size=paginated.page_size,
        total_items=paginated.total_items,
        total_pages=paginated.total_pages,
    )

    return IncidentListResponse(items=items, pagination=pagination)


@router.get(
    "/{incident_id}",
    response_model=IncidentDetailResponse,
    summary="Get Incident Details",
    description="Retrieve comprehensive details and associated record counts for a specific incident.",
)
def get_incident_detail(
    incident_id: UUID = Path(..., description="Unique UUID identifier of the incident"),
    session: Session = Depends(get_db_session),
) -> IncidentDetailResponse:
    """Retrieve an incident by primary key along with evidence and response action metrics."""
    incident = get_incident_or_raise(session, str(incident_id))

    evidence_count = (
        session.query(func.count(DetectionEvidence.evidence_id))
        .filter(DetectionEvidence.incident_id == incident.incident_id)
        .scalar()
        or 0
    )
    response_action_count = (
        session.query(func.count(ResponseAction.action_id))
        .filter(ResponseAction.incident_id == incident.incident_id)
        .scalar()
        or 0
    )

    return IncidentDetailResponse(
        incident_id=incident.incident_id,
        analysis_job_id=incident.analysis_job_id,
        title=incident.title,
        description=incident.description,
        incident_type=incident.incident_type,
        verdict=SecurityVerdict(incident.verdict),
        risk_score=incident.risk_score,
        status=IncidentStatus(incident.status),
        file_path=incident.file_path,
        file_hash=incident.file_hash,
        process_id=incident.process_id,
        detected_at=incident.detected_at,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        resolved_at=incident.resolved_at,
        evidence_count=evidence_count,
        response_action_count=response_action_count,
    )
