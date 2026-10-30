"""Persistence service for detection evidence indicators."""

from typing import Any, Dict, Optional, Union
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.analysis_job import AnalysisJob
from app.models.detection_evidence import DetectionEvidence
from app.models.incident import Incident
from app.schemas.contracts import DetectionEvidence as DetectionEvidenceContract
from app.schemas.contracts import DetectionSeverity
from app.services.common import PaginatedResult, paginate_query, serialize_json, utc_now_iso
from app.services.errors import (
    PersistenceConflictError,
    PersistenceError,
    ResourceNotFoundError,
    ValidationError,
)

VALID_SEVERITIES = {s.value for s in DetectionSeverity}


def create_detection_evidence(
    session: Session,
    evidence_data: Optional[Union[DetectionEvidenceContract, Dict[str, Any]]] = None,
    *,
    evidence_id: Optional[str] = None,
    incident_id: Optional[str] = None,
    analysis_job_id: Optional[str] = None,
    source: Optional[str] = None,
    indicator: Optional[str] = None,
    severity: Optional[Union[str, DetectionSeverity]] = None,
    description: Optional[str] = None,
    observed_value: Optional[str] = None,
    confidence: Optional[float] = None,
    score_contribution: Optional[float] = None,
    details: Optional[Dict[str, Any]] = None,
    observed_at: Optional[str] = None,
) -> DetectionEvidence:
    """Create and persist a detection evidence record for an incident.

    Accepts DetectionEvidence contract, dictionary, or keyword parameters.
    """
    if isinstance(evidence_data, DetectionEvidenceContract):
        d = evidence_data.model_dump()
        res_id = str(d["evidence_id"])
        res_inc_id = str(d["incident_id"])
        res_job_id = str(d["analysis_job_id"]) if d.get("analysis_job_id") else None
        res_source = d["source"]
        res_indicator = d["indicator"]
        res_severity = d["severity"].value if hasattr(d["severity"], "value") else str(d["severity"])
        res_desc = d["description"]
        res_observed_val = d.get("observed_value")
        res_conf = d.get("confidence")
        res_score_contrib = d.get("score_contribution")
        res_details = d.get("details")
        res_observed_at = (
            d["observed_at"].isoformat().replace("+00:00", "Z")
            if hasattr(d["observed_at"], "isoformat")
            else str(d["observed_at"])
        )
    elif isinstance(evidence_data, dict):
        res_id = str(evidence_data.get("evidence_id") or uuid4())
        res_inc_id = str(evidence_data["incident_id"])
        res_job_id = str(evidence_data["analysis_job_id"]) if evidence_data.get("analysis_job_id") else None
        res_source = str(evidence_data["source"])
        res_indicator = str(evidence_data["indicator"])
        sev = evidence_data["severity"]
        res_severity = sev.value if hasattr(sev, "value") else str(sev)
        res_desc = str(evidence_data["description"])
        res_observed_val = evidence_data.get("observed_value")
        res_conf = evidence_data.get("confidence")
        res_score_contrib = evidence_data.get("score_contribution")
        res_details = evidence_data.get("details")
        res_observed_at = str(evidence_data.get("observed_at") or utc_now_iso())
    else:
        if not incident_id:
            raise ValidationError("incident_id is required.", field="incident_id")
        if not source:
            raise ValidationError("source is required.", field="source")
        if not indicator:
            raise ValidationError("indicator is required.", field="indicator")
        if not severity:
            raise ValidationError("severity is required.", field="severity")
        if not description:
            raise ValidationError("description is required.", field="description")

        res_id = str(evidence_id or uuid4())
        res_inc_id = str(incident_id)
        res_job_id = str(analysis_job_id) if analysis_job_id else None
        res_source = str(source)
        res_indicator = str(indicator)
        res_severity = severity.value if hasattr(severity, "value") else str(severity)
        res_desc = str(description)
        res_observed_val = observed_value
        res_conf = confidence
        res_score_contrib = score_contribution
        res_details = details
        res_observed_at = str(observed_at or utc_now_iso())

    if res_severity not in VALID_SEVERITIES:
        raise ValidationError(f"Invalid severity '{res_severity}'. Allowed: {sorted(VALID_SEVERITIES)}", field="severity")

    if res_conf is not None and (res_conf < 0.0 or res_conf > 1.0):
        raise ValidationError("Confidence must be between 0.0 and 1.0.", field="confidence")

    # Verify associated incident exists
    parent_incident = session.get(Incident, res_inc_id)
    if parent_incident is None:
        raise ResourceNotFoundError("Incident", res_inc_id)

    if res_job_id:
        parent_job = session.get(AnalysisJob, res_job_id)
        if parent_job is None:
            raise ResourceNotFoundError("AnalysisJob", res_job_id)

    evidence = DetectionEvidence(
        evidence_id=res_id,
        incident_id=res_inc_id,
        analysis_job_id=res_job_id,
        source=res_source,
        indicator=res_indicator,
        severity=res_severity,
        description=res_desc,
        observed_value=res_observed_val,
        confidence=res_conf,
        score_contribution=res_score_contrib,
        details_json=serialize_json(res_details),
        observed_at=res_observed_at,
        created_at=utc_now_iso(),
    )

    try:
        session.add(evidence)
        session.flush()
    except IntegrityError as exc:
        orig_msg = str(exc.orig) if hasattr(exc, "orig") else str(exc)
        if "UNIQUE" in orig_msg.upper() or "PRIMARY KEY" in orig_msg.upper():
            raise PersistenceConflictError(
                f"Detection evidence with ID '{res_id}' already exists.",
                conflict_key="evidence_id",
                conflict_value=res_id,
            ) from exc
        raise PersistenceError(f"Failed to persist detection evidence: {orig_msg}") from exc

    return evidence


def get_detection_evidence(session: Session, evidence_id: str) -> Optional[DetectionEvidence]:
    """Retrieve detection evidence by primary key, or None if not found."""
    return session.get(DetectionEvidence, str(evidence_id))


def get_detection_evidence_or_raise(session: Session, evidence_id: str) -> DetectionEvidence:
    """Retrieve detection evidence by primary key, raising ResourceNotFoundError if missing."""
    evidence = get_detection_evidence(session, evidence_id)
    if evidence is None:
        raise ResourceNotFoundError("DetectionEvidence", evidence_id)
    return evidence


def list_evidence_for_incident(
    session: Session,
    incident_id: str,
    page: int = 1,
    page_size: int = 20,
    severity: Optional[str] = None,
    source: Optional[str] = None,
) -> PaginatedResult[DetectionEvidence]:
    """Retrieve a paginated collection of evidence records associated with an incident.

    Uses deterministic ordering: observed_at descending, evidence_id descending as tie-breaker.
    """
    stmt = select(DetectionEvidence).where(DetectionEvidence.incident_id == incident_id)

    if severity:
        stmt = stmt.where(DetectionEvidence.severity == severity)
    if source:
        stmt = stmt.where(DetectionEvidence.source == source)

    stmt = stmt.order_by(DetectionEvidence.observed_at.desc(), DetectionEvidence.evidence_id.desc())
    return paginate_query(session, stmt, page=page, page_size=page_size)


def list_evidence_for_job(
    session: Session,
    analysis_job_id: str,
    page: int = 1,
    page_size: int = 20,
) -> PaginatedResult[DetectionEvidence]:
    """Retrieve a paginated collection of evidence records generated by an analysis job.

    Uses deterministic ordering: observed_at descending, evidence_id descending as tie-breaker.
    """
    stmt = select(DetectionEvidence).where(DetectionEvidence.analysis_job_id == analysis_job_id)
    stmt = stmt.order_by(DetectionEvidence.observed_at.desc(), DetectionEvidence.evidence_id.desc())
    return paginate_query(session, stmt, page=page, page_size=page_size)
