"""Append-oriented persistence service for security audit trail logging."""

from typing import Any, Dict, Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.services.common import PaginatedResult, paginate_query, serialize_json, utc_now_iso
from app.services.errors import PersistenceConflictError, PersistenceError, ResourceNotFoundError, ValidationError


def append_audit_log(
    session: Session,
    *,
    actor: str,
    action: str,
    result: str,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    correlation_id: Optional[str] = None,
    audit_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> AuditLog:
    """Append a security or administrative audit record.

    Uses generic entity references without mandatory entity-specific foreign-key columns.
    The service is strictly append-oriented: no update or delete operations are provided.
    """
    if not actor:
        raise ValidationError("actor is required.", field="actor")
    if not action:
        raise ValidationError("action is required.", field="action")
    if not result:
        raise ValidationError("result is required.", field="result")

    resolved_id = str(audit_id or uuid4())
    resolved_timestamp = timestamp or utc_now_iso()

    audit_entry = AuditLog(
        audit_id=resolved_id,
        timestamp=resolved_timestamp,
        actor=actor,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        result=result,
        details_json=serialize_json(details),
        correlation_id=correlation_id,
    )

    try:
        session.add(audit_entry)
        session.flush()
    except IntegrityError as exc:
        orig_msg = str(exc.orig) if hasattr(exc, "orig") else str(exc)
        if "UNIQUE" in orig_msg.upper() or "PRIMARY KEY" in orig_msg.upper():
            raise PersistenceConflictError(
                f"Audit record with ID '{resolved_id}' already exists.",
                conflict_key="audit_id",
                conflict_value=resolved_id,
            ) from exc
        raise PersistenceError(f"Failed to append audit record: {orig_msg}") from exc

    return audit_entry


def get_audit_log(session: Session, audit_id: str) -> Optional[AuditLog]:
    """Retrieve an audit record by primary key, or None if not found."""
    return session.get(AuditLog, str(audit_id))


def get_audit_log_or_raise(session: Session, audit_id: str) -> AuditLog:
    """Retrieve an audit record by primary key, raising ResourceNotFoundError if missing."""
    entry = get_audit_log(session, audit_id)
    if entry is None:
        raise ResourceNotFoundError("AuditLog", audit_id)
    return entry


def list_audit_logs(
    session: Session,
    page: int = 1,
    page_size: int = 20,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    actor: Optional[str] = None,
    action: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> PaginatedResult[AuditLog]:
    """Retrieve a paginated collection of audit logs with optional filters.

    Uses deterministic ordering: timestamp descending, audit_id descending as tie-breaker.
    """
    stmt = select(AuditLog)

    if entity_type:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    if entity_id:
        stmt = stmt.where(AuditLog.entity_id == entity_id)
    if correlation_id:
        stmt = stmt.where(AuditLog.correlation_id == correlation_id)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if start_time:
        stmt = stmt.where(AuditLog.timestamp >= start_time)
    if end_time:
        stmt = stmt.where(AuditLog.timestamp <= end_time)

    stmt = stmt.order_by(AuditLog.timestamp.desc(), AuditLog.audit_id.desc())
    return paginate_query(session, stmt, page=page, page_size=page_size)
