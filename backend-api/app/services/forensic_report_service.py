"""Persistence service for AI and heuristic forensic explanation reports."""

from typing import Any, Dict, List, Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.forensic_report import ForensicReport
from app.models.incident import Incident
from app.services.common import PaginatedResult, paginate_query, serialize_json, utc_now_iso
from app.services.errors import (
    InvalidStateTransitionError,
    PersistenceConflictError,
    PersistenceError,
    ResourceNotFoundError,
    ValidationError,
)

VALID_REPORT_STATUSES = {
    "PENDING",
    "GENERATING",
    "COMPLETED",
    "FAILED",
    "UNAVAILABLE",
}

# Allowed transitions for report generation lifecycle
ALLOWED_REPORT_TRANSITIONS = {
    "PENDING": {"GENERATING", "UNAVAILABLE"},
    "GENERATING": {"COMPLETED", "FAILED", "UNAVAILABLE"},
    "FAILED": {"GENERATING"},  # Allow retry
    "COMPLETED": set(),
    "UNAVAILABLE": {"GENERATING"},
}


def create_forensic_report(
    session: Session,
    *,
    incident_id: str,
    provider: str,
    report_id: Optional[str] = None,
    model_name: Optional[str] = None,
    status: str = "PENDING",
    summary: Optional[str] = None,
    findings: Optional[str] = None,
    recommendations: Optional[str] = None,
    technique_mappings: Optional[List[Dict[str, Any]]] = None,
    evidence_references: Optional[List[str]] = None,
    created_at: Optional[str] = None,
) -> ForensicReport:
    """Create and persist a forensic report record associated with an incident.

    Does not trigger external LLM generation or block the detection pipeline.
    """
    if not incident_id:
        raise ValidationError("incident_id is required.", field="incident_id")
    if not provider:
        raise ValidationError("provider is required.", field="provider")

    if status not in VALID_REPORT_STATUSES:
        raise ValidationError(f"Invalid status '{status}'. Allowed: {sorted(VALID_REPORT_STATUSES)}", field="status")

    # Verify parent incident exists
    parent_incident = session.get(Incident, incident_id)
    if parent_incident is None:
        raise ResourceNotFoundError("Incident", incident_id)

    resolved_id = str(report_id or uuid4())
    resolved_created_at = created_at or utc_now_iso()
    now = utc_now_iso()

    report = ForensicReport(
        report_id=resolved_id,
        incident_id=incident_id,
        provider=provider,
        model_name=model_name,
        status=status,
        summary=summary,
        findings=findings,
        recommendations=recommendations,
        technique_mappings_json=serialize_json(technique_mappings),
        evidence_references_json=serialize_json(evidence_references, default_empty="[]") or "[]",
        error_message=None,
        generated_at=None,
        created_at=resolved_created_at,
        updated_at=now,
    )

    try:
        session.add(report)
        session.flush()
    except IntegrityError as exc:
        orig_msg = str(exc.orig) if hasattr(exc, "orig") else str(exc)
        if "UNIQUE" in orig_msg.upper() or "PRIMARY KEY" in orig_msg.upper():
            raise PersistenceConflictError(
                f"Forensic report with ID '{resolved_id}' already exists.",
                conflict_key="report_id",
                conflict_value=resolved_id,
            ) from exc
        raise PersistenceError(f"Failed to persist forensic report: {orig_msg}") from exc

    return report


def get_forensic_report(session: Session, report_id: str) -> Optional[ForensicReport]:
    """Retrieve a forensic report by primary key, or None if not found."""
    return session.get(ForensicReport, str(report_id))


def get_forensic_report_or_raise(session: Session, report_id: str) -> ForensicReport:
    """Retrieve a forensic report by primary key, raising ResourceNotFoundError if missing."""
    report = get_forensic_report(session, report_id)
    if report is None:
        raise ResourceNotFoundError("ForensicReport", report_id)
    return report


def list_reports_for_incident(
    session: Session,
    incident_id: str,
    page: int = 1,
    page_size: int = 20,
) -> PaginatedResult[ForensicReport]:
    """Retrieve a paginated collection of forensic reports for an incident.

    Uses deterministic ordering: created_at descending, report_id descending as tie-breaker.
    """
    stmt = (
        select(ForensicReport)
        .where(ForensicReport.incident_id == incident_id)
        .order_by(ForensicReport.created_at.desc(), ForensicReport.report_id.desc())
    )
    return paginate_query(session, stmt, page=page, page_size=page_size)


def update_forensic_report_status(
    session: Session,
    report_id: str,
    new_status: str,
    *,
    summary: Optional[str] = None,
    findings: Optional[str] = None,
    recommendations: Optional[str] = None,
    technique_mappings: Optional[List[Dict[str, Any]]] = None,
    evidence_references: Optional[List[str]] = None,
    error_message: Optional[str] = None,
    generated_at: Optional[str] = None,
) -> ForensicReport:
    """Update report generation status, findings, and completion timestamps.

    Enforces documented state transitions.
    """
    report = get_forensic_report_or_raise(session, report_id)

    if new_status not in VALID_REPORT_STATUSES:
        raise ValidationError(f"Invalid status '{new_status}'. Allowed: {sorted(VALID_REPORT_STATUSES)}", field="status")

    if new_status != report.status:
        allowed = ALLOWED_REPORT_TRANSITIONS.get(report.status, set())
        if new_status not in allowed:
            raise InvalidStateTransitionError("ForensicReport", report_id, report.status, new_status)

        report.status = new_status

    now = utc_now_iso()
    if new_status == "COMPLETED":
        report.generated_at = generated_at or now

    if summary is not None:
        report.summary = summary
    if findings is not None:
        report.findings = findings
    if recommendations is not None:
        report.recommendations = recommendations
    if technique_mappings is not None:
        report.technique_mappings_json = serialize_json(technique_mappings)
    if evidence_references is not None:
        report.evidence_references_json = serialize_json(evidence_references, default_empty="[]") or "[]"
    if error_message is not None:
        report.error_message = error_message

    report.updated_at = now
    session.flush()
    return report
