"""Persistence service for security incidents."""

from typing import Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.analysis_job import AnalysisJob
from app.models.incident import Incident
from app.schemas.contracts import IncidentStatus, SecurityVerdict
from app.services.common import PaginatedResult, paginate_query, utc_now_iso
from app.services.errors import (
    InvalidStateTransitionError,
    PersistenceConflictError,
    PersistenceError,
    ResourceNotFoundError,
    ValidationError,
)

VALID_STATUSES = {s.value for s in IncidentStatus}
VALID_VERDICTS = {v.value for v in SecurityVerdict}

# Valid investigation state transitions
ALLOWED_INCIDENT_TRANSITIONS = {
    IncidentStatus.OPEN.value: {
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.CONTAINED.value,
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
    },
    IncidentStatus.INVESTIGATING.value: {
        IncidentStatus.CONTAINED.value,
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
        IncidentStatus.OPEN.value,
    },
    IncidentStatus.CONTAINED.value: {
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
        IncidentStatus.INVESTIGATING.value,
    },
    IncidentStatus.RESOLVED.value: {
        IncidentStatus.CLOSED.value,
        IncidentStatus.INVESTIGATING.value,  # Reopening
        IncidentStatus.OPEN.value,
    },
    IncidentStatus.CLOSED.value: {
        IncidentStatus.INVESTIGATING.value,  # Reopening
        IncidentStatus.OPEN.value,
    },
}


def create_incident(
    session: Session,
    *,
    title: str,
    incident_type: str,
    verdict: str,
    risk_score: float,
    detected_at: Optional[str] = None,
    incident_id: Optional[str] = None,
    analysis_job_id: Optional[str] = None,
    description: Optional[str] = None,
    status: str = IncidentStatus.OPEN.value,
    file_path: Optional[str] = None,
    file_hash: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Incident:
    """Create and persist a security incident.

    Validates initial risk score, verdict, and status constraints.
    """
    if not title:
        raise ValidationError("title is required.", field="title")
    if not incident_type:
        raise ValidationError("incident_type is required.", field="incident_type")

    if verdict not in VALID_VERDICTS:
        raise ValidationError(f"Invalid verdict '{verdict}'. Allowed: {sorted(VALID_VERDICTS)}", field="verdict")

    if status not in VALID_STATUSES:
        raise ValidationError(f"Invalid status '{status}'. Allowed: {sorted(VALID_STATUSES)}", field="status")

    if risk_score < 0.0 or risk_score > 100.0:
        raise ValidationError("Risk score must be between 0.0 and 100.0.", field="risk_score")

    resolved_id = str(incident_id or uuid4())
    resolved_detected = detected_at or utc_now_iso()
    now = utc_now_iso()

    if analysis_job_id:
        # Verify parent analysis job exists
        parent_job = session.get(AnalysisJob, analysis_job_id)
        if parent_job is None:
            raise ResourceNotFoundError("AnalysisJob", analysis_job_id)

    incident = Incident(
        incident_id=resolved_id,
        analysis_job_id=analysis_job_id,
        title=title,
        description=description,
        incident_type=incident_type,
        verdict=verdict,
        risk_score=risk_score,
        status=status,
        file_path=file_path,
        file_hash=file_hash,
        process_id=process_id,
        detected_at=resolved_detected,
        created_at=now,
        updated_at=now,
        resolved_at=None,
    )

    try:
        session.add(incident)
        session.flush()
    except IntegrityError as exc:
        orig_msg = str(exc.orig) if hasattr(exc, "orig") else str(exc)
        if "UNIQUE" in orig_msg.upper() or "PRIMARY KEY" in orig_msg.upper():
            raise PersistenceConflictError(
                f"Incident with ID '{resolved_id}' already exists.",
                conflict_key="incident_id",
                conflict_value=resolved_id,
            ) from exc
        raise PersistenceError(f"Failed to persist incident: {orig_msg}") from exc

    return incident


def get_incident(session: Session, incident_id: str) -> Optional[Incident]:
    """Retrieve an incident by primary key, or None if not found."""
    return session.get(Incident, str(incident_id))


def get_incident_or_raise(session: Session, incident_id: str) -> Incident:
    """Retrieve an incident by primary key, raising ResourceNotFoundError if missing."""
    incident = get_incident(session, incident_id)
    if incident is None:
        raise ResourceNotFoundError("Incident", incident_id)
    return incident


def get_incident_for_job(session: Session, analysis_job_id: str) -> Optional[Incident]:
    """Retrieve the incident associated with a specific analysis job, or None if not found."""
    stmt = select(Incident).where(Incident.analysis_job_id == str(analysis_job_id))
    return session.scalars(stmt).first()


def list_incidents(
    session: Session,
    page: int = 1,
    page_size: int = 20,
    verdict: Optional[str] = None,
    status: Optional[str] = None,
    file_hash: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> PaginatedResult[Incident]:
    """Retrieve a paginated collection of incidents with optional filters.

    Uses deterministic ordering: detected_at descending, incident_id descending as tie-breaker.
    """
    stmt = select(Incident)

    if verdict:
        stmt = stmt.where(Incident.verdict == verdict)
    if status:
        stmt = stmt.where(Incident.status == status)
    if file_hash:
        stmt = stmt.where(Incident.file_hash == file_hash)
    if start_time:
        stmt = stmt.where(Incident.detected_at >= start_time)
    if end_time:
        stmt = stmt.where(Incident.detected_at <= end_time)

    stmt = stmt.order_by(Incident.detected_at.desc(), Incident.incident_id.desc())
    return paginate_query(session, stmt, page=page, page_size=page_size)


def update_incident_status(
    session: Session,
    incident_id: str,
    new_status: str,
    *,
    verdict: Optional[str] = None,
    risk_score: Optional[float] = None,
    resolved_at: Optional[str] = None,
) -> Incident:
    """Update investigation status for an incident while preserving detection evidence.

    Manages resolution timestamps and enforces valid transitions.
    Allows updating verdict (e.g. to BENIGN for false-positive outcomes) and risk score.
    """
    incident = get_incident_or_raise(session, incident_id)

    if new_status not in VALID_STATUSES:
        raise ValidationError(f"Invalid status '{new_status}'. Allowed: {sorted(VALID_STATUSES)}", field="status")

    if new_status != incident.status:
        allowed = ALLOWED_INCIDENT_TRANSITIONS.get(incident.status, set())
        if new_status not in allowed:
            raise InvalidStateTransitionError("Incident", incident_id, incident.status, new_status)

        incident.status = new_status

    if verdict is not None:
        if verdict not in VALID_VERDICTS:
            raise ValidationError(f"Invalid verdict '{verdict}'. Allowed: {sorted(VALID_VERDICTS)}", field="verdict")
        incident.verdict = verdict

    if risk_score is not None:
        if risk_score < 0.0 or risk_score > 100.0:
            raise ValidationError("Risk score must be between 0.0 and 100.0.", field="risk_score")
        incident.risk_score = risk_score

    now = utc_now_iso()
    if new_status in {IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value}:
        if not incident.resolved_at:
            incident.resolved_at = resolved_at or now
    elif new_status in {IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value}:
        # Reopening clears previous resolution timestamp
        incident.resolved_at = None

    incident.updated_at = now
    session.flush()
    return incident
