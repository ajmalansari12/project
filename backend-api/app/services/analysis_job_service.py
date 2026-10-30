"""Persistence service for analysis job lifecycle tracking."""

from typing import List, Optional
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.analysis_job import AnalysisJob
from app.models.endpoint_event import EndpointEvent
from app.schemas.contracts import AnalysisJobStatus, SecurityVerdict
from app.services.common import PaginatedResult, paginate_query, serialize_json, utc_now_iso
from app.services.errors import (
    InvalidStateTransitionError,
    PersistenceConflictError,
    PersistenceError,
    ResourceNotFoundError,
    ValidationError,
)
from app.services.sha256_service import normalize_sha256

VALID_STATUSES = {s.value for s in AnalysisJobStatus}
VALID_VERDICTS = {v.value for v in SecurityVerdict}

# Documented valid state transitions for analysis jobs
ALLOWED_TRANSITIONS = {
    AnalysisJobStatus.QUEUED.value: {
        AnalysisJobStatus.IN_PROGRESS.value,
        AnalysisJobStatus.FAILED.value,
        AnalysisJobStatus.CANCELLED.value,
    },
    AnalysisJobStatus.IN_PROGRESS.value: {
        AnalysisJobStatus.COMPLETED.value,
        AnalysisJobStatus.FAILED.value,
        AnalysisJobStatus.CANCELLED.value,
    },
    AnalysisJobStatus.COMPLETED.value: set(),
    AnalysisJobStatus.FAILED.value: set(),
    AnalysisJobStatus.CANCELLED.value: set(),
}


def create_analysis_job(
    session: Session,
    *,
    job_id: Optional[str] = None,
    source_event_id: Optional[str] = None,
    file_path: Optional[str] = None,
    file_hash: Optional[str] = None,
    queued_at: Optional[str] = None,
) -> AnalysisJob:
    """Create a new analysis job in the initial QUEUED state."""
    resolved_job_id = str(job_id or uuid4())
    resolved_queued_at = queued_at or utc_now_iso()
    now = utc_now_iso()

    if source_event_id:
        # Verify parent endpoint event exists
        parent_event = session.get(EndpointEvent, source_event_id)
        if parent_event is None:
            raise ResourceNotFoundError("EndpointEvent", source_event_id)

    job = AnalysisJob(
        job_id=resolved_job_id,
        source_event_id=source_event_id,
        file_path=file_path,
        file_hash=file_hash,
        status=AnalysisJobStatus.QUEUED.value,
        verdict=None,
        risk_score=None,
        modules_executed_json="[]",
        modules_skipped_json="[]",
        modules_failed_json="[]",
        queued_at=resolved_queued_at,
        created_at=now,
        updated_at=now,
    )

    try:
        session.add(job)
        session.flush()
    except IntegrityError as exc:
        orig_msg = str(exc.orig) if hasattr(exc, "orig") else str(exc)
        if "UNIQUE" in orig_msg.upper() or "PRIMARY KEY" in orig_msg.upper():
            raise PersistenceConflictError(
                f"Analysis job with ID '{resolved_job_id}' already exists.",
                conflict_key="job_id",
                conflict_value=resolved_job_id,
            ) from exc
        raise PersistenceError(f"Failed to persist analysis job: {orig_msg}") from exc

    return job


def get_analysis_job(session: Session, job_id: str) -> Optional[AnalysisJob]:
    """Retrieve an analysis job by primary key, or None if not found."""
    return session.get(AnalysisJob, str(job_id))


def get_analysis_job_or_raise(session: Session, job_id: str) -> AnalysisJob:
    """Retrieve an analysis job by primary key, raising ResourceNotFoundError if missing."""
    job = get_analysis_job(session, job_id)
    if job is None:
        raise ResourceNotFoundError("AnalysisJob", job_id)
    return job


def list_analysis_jobs(
    session: Session,
    page: int = 1,
    page_size: int = 20,
    status: Optional[str] = None,
    verdict: Optional[str] = None,
    file_hash: Optional[str] = None,
) -> PaginatedResult[AnalysisJob]:
    """Retrieve a paginated collection of analysis jobs with optional filters.

    Uses deterministic ordering: queued_at descending, job_id descending as tie-breaker.
    """
    stmt = select(AnalysisJob)

    if status:
        stmt = stmt.where(AnalysisJob.status == status)
    if verdict:
        stmt = stmt.where(AnalysisJob.verdict == verdict)
    if file_hash:
        stmt = stmt.where(AnalysisJob.file_hash == file_hash)

    stmt = stmt.order_by(AnalysisJob.queued_at.desc(), AnalysisJob.job_id.desc())
    return paginate_query(session, stmt, page=page, page_size=page_size)


def update_analysis_job_status(
    session: Session,
    job_id: str,
    new_status: str,
    *,
    started_at: Optional[str] = None,
    completed_at: Optional[str] = None,
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
) -> AnalysisJob:
    """Update processing lifecycle status and timestamps for an analysis job.

    Enforces documented state transitions.
    """
    job = get_analysis_job_or_raise(session, job_id)

    if new_status not in VALID_STATUSES:
        raise ValidationError(f"Invalid status '{new_status}'. Allowed: {sorted(VALID_STATUSES)}", field="status")

    if new_status != job.status:
        allowed = ALLOWED_TRANSITIONS.get(job.status, set())
        if new_status not in allowed:
            raise InvalidStateTransitionError("AnalysisJob", job_id, job.status, new_status)

        job.status = new_status

    now = utc_now_iso()
    if new_status == AnalysisJobStatus.IN_PROGRESS.value and not job.started_at:
        job.started_at = started_at or now

    if new_status in {
        AnalysisJobStatus.COMPLETED.value,
        AnalysisJobStatus.FAILED.value,
        AnalysisJobStatus.CANCELLED.value,
    }:
        job.completed_at = completed_at or now

    if new_status == AnalysisJobStatus.FAILED.value and job.verdict == SecurityVerdict.BENIGN.value:
        # A failed job must never retain or automatically receive a BENIGN verdict
        job.verdict = None

    if error_code:
        job.error_code = error_code
    if error_message:
        job.error_message = error_message

    job.updated_at = now
    session.flush()
    return job


def record_analysis_job_result(
    session: Session,
    job_id: str,
    *,
    verdict: Optional[str] = None,
    risk_score: Optional[float] = None,
    modules_executed: Optional[List[str]] = None,
    modules_skipped: Optional[List[str]] = None,
    modules_failed: Optional[List[str]] = None,
    completed_at: Optional[str] = None,
    file_hash: Optional[str] = None,
) -> AnalysisJob:
    """Record evaluation results, risk scoring, and module telemetry for an analysis job.

    Enforces that failed jobs are never automatically assigned a BENIGN verdict.
    """
    job = get_analysis_job_or_raise(session, job_id)

    if file_hash is not None:
        job.file_hash = normalize_sha256(file_hash)

    if verdict is not None:
        if verdict not in VALID_VERDICTS:
            raise ValidationError(f"Invalid verdict '{verdict}'. Allowed: {sorted(VALID_VERDICTS)}", field="verdict")
        # Rule: A failed analysis job must not automatically receive the BENIGN verdict
        if job.status == AnalysisJobStatus.FAILED.value and verdict == SecurityVerdict.BENIGN.value:
            raise ValidationError(
                "A failed analysis job cannot be assigned a BENIGN verdict.",
                field="verdict",
            )
        job.verdict = verdict

    if risk_score is not None:
        if risk_score < 0.0 or risk_score > 100.0:
            raise ValidationError("Risk score must be between 0.0 and 100.0.", field="risk_score")
        job.risk_score = risk_score

    if modules_executed is not None:
        job.modules_executed_json = serialize_json(modules_executed, default_empty="[]") or "[]"
    if modules_skipped is not None:
        job.modules_skipped_json = serialize_json(modules_skipped, default_empty="[]") or "[]"
    if modules_failed is not None:
        job.modules_failed_json = serialize_json(modules_failed, default_empty="[]") or "[]"

    now = utc_now_iso()
    if completed_at:
        job.completed_at = completed_at
    job.updated_at = now

    session.flush()
    return job


def claim_analysis_job(
    session: Session,
    job_id: str,
    *,
    started_at: Optional[str] = None,
) -> Optional[AnalysisJob]:
    """Safely and atomically claim a QUEUED analysis job for execution.

    Transitions the job from QUEUED to IN_PROGRESS using an atomic conditional update.
    Returns the claimed AnalysisJob if successfully claimed, or None if the job was
    not in QUEUED state (e.g. already claimed by another worker, cancelled, or missing).
    """
    now = utc_now_iso()
    start_time = started_at or now

    stmt = (
        update(AnalysisJob)
        .where(
            AnalysisJob.job_id == str(job_id),
            AnalysisJob.status == AnalysisJobStatus.QUEUED.value,
        )
        .values(
            status=AnalysisJobStatus.IN_PROGRESS.value,
            started_at=start_time,
            updated_at=now,
        )
    )
    result = session.execute(stmt)
    if result.rowcount == 0:
        return None

    session.flush()
    job = session.get(AnalysisJob, str(job_id))
    if job is not None:
        session.refresh(job)
    return job


def cancel_analysis_job(
    session: Session,
    job_id: str,
    *,
    reason: Optional[str] = None,
) -> AnalysisJob:
    """Cancel an active or queued analysis job following ALLOWED_TRANSITIONS.

    Only jobs currently in QUEUED or IN_PROGRESS status may be cancelled.
    """
    job = get_analysis_job_or_raise(session, job_id)
    if job.status not in (AnalysisJobStatus.QUEUED.value, AnalysisJobStatus.IN_PROGRESS.value):
        raise InvalidStateTransitionError(
            "AnalysisJob",
            job_id,
            job.status,
            AnalysisJobStatus.CANCELLED.value,
        )
    return update_analysis_job_status(
        session,
        job_id,
        AnalysisJobStatus.CANCELLED.value,
        error_message=reason,
    )


def get_pending_queued_job_ids(
    session: Session,
    limit: int = 100,
) -> List[str]:
    """Retrieve job IDs in QUEUED status ordered chronologically by queued_at ASC."""
    stmt = (
        select(AnalysisJob.job_id)
        .where(AnalysisJob.status == AnalysisJobStatus.QUEUED.value)
        .order_by(AnalysisJob.queued_at.asc(), AnalysisJob.job_id.asc())
        .limit(limit)
    )
    return list(session.execute(stmt).scalars().all())


def recover_interrupted_jobs(
    session: Session,
) -> int:
    """Transition orphaned IN_PROGRESS jobs to FAILED on system restart.

    Deployment Invariant:
    This function unconditionally transitions all IN_PROGRESS jobs to FAILED.
    It is supported ONLY under a single-manager deployment model where the
    designated worker manager runs startup recovery during cold boot before
    dispatching work, and where no other worker managers are active concurrently.
    It must not be invoked concurrently by multiple processes without an explicit
    lease or heartbeat mechanism, as doing so would mark another active process's
    jobs as orphaned.

    Under the canonical state machine, an interrupted job cannot safely transition
    backwards to QUEUED. Transitioning to FAILED preserves audit history and records
    an INTERRUPTED_BY_SHUTDOWN error code.
    """
    now = utc_now_iso()
    stmt = (
        update(AnalysisJob)
        .where(AnalysisJob.status == AnalysisJobStatus.IN_PROGRESS.value)
        .values(
            status=AnalysisJobStatus.FAILED.value,
            error_code="INTERRUPTED_BY_SHUTDOWN",
            error_message="Job execution was interrupted by process restart or shutdown.",
            completed_at=now,
            updated_at=now,
        )
    )
    result = session.execute(stmt)
    session.flush()
    return int(result.rowcount)
