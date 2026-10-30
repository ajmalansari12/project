"""Persistence service for quarantine and restoration tracking metadata."""

import re
from typing import Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.quarantine_record import QuarantineRecord
from app.models.response_action import ResponseAction
from app.services.common import PaginatedResult, paginate_query, utc_now_iso
from app.services.errors import (
    InvalidStateTransitionError,
    PersistenceConflictError,
    PersistenceError,
    ResourceNotFoundError,
    ValidationError,
)

HEX_64_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

VALID_QUARANTINE_STATUSES = {
    "PENDING",
    "QUARANTINED",
    "RESTORING",
    "RESTORED",
    "FAILED",
    "DELETED",
}

# Allowed transitions for quarantine metadata lifecycle
ALLOWED_QUARANTINE_TRANSITIONS = {
    "PENDING": {"QUARANTINED", "FAILED"},
    "QUARANTINED": {"RESTORING", "DELETED"},
    "RESTORING": {"RESTORED", "QUARANTINED", "FAILED"},
    "RESTORED": {"DELETED"},
    "FAILED": set(),
    "DELETED": set(),
}


def create_quarantine_record(
    session: Session,
    *,
    incident_id: str,
    action_id: str,
    original_path: str,
    quarantine_path: str,
    original_sha256: str,
    encryption_algorithm: str,
    nonce: str,
    key_reference: str,
    original_size_bytes: int,
    quarantined_at: Optional[str] = None,
    quarantine_id: Optional[str] = None,
    quarantined_sha256: Optional[str] = None,
    status: str = "PENDING",
) -> QuarantineRecord:
    """Create and persist a quarantine tracking record.

    Stores authenticated-encryption recovery parameters and hash verification metadata.
    Does not perform filesystem operations or store plaintext encryption keys.
    """
    if not incident_id:
        raise ValidationError("incident_id is required.", field="incident_id")
    if not action_id:
        raise ValidationError("action_id is required.", field="action_id")
    if not original_path:
        raise ValidationError("original_path is required.", field="original_path")
    if not quarantine_path:
        raise ValidationError("quarantine_path is required.", field="quarantine_path")
    if not encryption_algorithm:
        raise ValidationError("encryption_algorithm is required.", field="encryption_algorithm")
    if not nonce:
        raise ValidationError("nonce is required.", field="nonce")
    if not key_reference:
        raise ValidationError("key_reference is required.", field="key_reference")

    if original_size_bytes < 0:
        raise ValidationError("original_size_bytes cannot be negative.", field="original_size_bytes")

    if status not in VALID_QUARANTINE_STATUSES:
        raise ValidationError(f"Invalid status '{status}'. Allowed: {sorted(VALID_QUARANTINE_STATUSES)}", field="status")

    if not HEX_64_PATTERN.match(original_sha256):
        raise ValidationError("original_sha256 must be a 64-character hexadecimal digest.", field="original_sha256")

    if quarantined_sha256 and not HEX_64_PATTERN.match(quarantined_sha256):
        raise ValidationError("quarantined_sha256 must be a 64-character hexadecimal digest.", field="quarantined_sha256")

    # Verify incident and action exist
    parent_incident = session.get(Incident, incident_id)
    if parent_incident is None:
        raise ResourceNotFoundError("Incident", incident_id)

    parent_action = session.get(ResponseAction, action_id)
    if parent_action is None:
        raise ResourceNotFoundError("ResponseAction", action_id)

    resolved_id = str(quarantine_id or uuid4())
    resolved_quarantined_at = quarantined_at or utc_now_iso()
    now = utc_now_iso()

    record = QuarantineRecord(
        quarantine_id=resolved_id,
        incident_id=incident_id,
        action_id=action_id,
        original_path=original_path,
        quarantine_path=quarantine_path,
        original_sha256=original_sha256,
        quarantined_sha256=quarantined_sha256,
        encryption_algorithm=encryption_algorithm,
        nonce=nonce,
        key_reference=key_reference,
        original_size_bytes=original_size_bytes,
        status=status,
        restoration_path=None,
        quarantined_at=resolved_quarantined_at,
        restored_at=None,
        created_at=now,
        updated_at=now,
    )

    try:
        session.add(record)
        session.flush()
    except IntegrityError as exc:
        orig_msg = str(exc.orig) if hasattr(exc, "orig") else str(exc)
        if "UNIQUE" in orig_msg.upper() and "QUARANTINE_PATH" in orig_msg.upper():
            raise PersistenceConflictError(
                f"Quarantine object path '{quarantine_path}' is already registered in the database.",
                conflict_key="quarantine_path",
                conflict_value=quarantine_path,
            ) from exc
        if "UNIQUE" in orig_msg.upper() or "PRIMARY KEY" in orig_msg.upper():
            raise PersistenceConflictError(
                f"Quarantine record with ID '{resolved_id}' already exists.",
                conflict_key="quarantine_id",
                conflict_value=resolved_id,
            ) from exc
        raise PersistenceError(f"Failed to persist quarantine record: {orig_msg}") from exc

    return record


def get_quarantine_record(session: Session, quarantine_id: str) -> Optional[QuarantineRecord]:
    """Retrieve a quarantine record by primary key, or None if not found."""
    return session.get(QuarantineRecord, str(quarantine_id))


def get_quarantine_record_or_raise(session: Session, quarantine_id: str) -> QuarantineRecord:
    """Retrieve a quarantine record by primary key, raising ResourceNotFoundError if missing."""
    record = get_quarantine_record(session, quarantine_id)
    if record is None:
        raise ResourceNotFoundError("QuarantineRecord", quarantine_id)
    return record


def list_quarantine_records(
    session: Session,
    page: int = 1,
    page_size: int = 20,
    incident_id: Optional[str] = None,
    status: Optional[str] = None,
) -> PaginatedResult[QuarantineRecord]:
    """Retrieve a paginated collection of quarantine records with optional filters.

    Uses deterministic ordering: quarantined_at descending, quarantine_id descending as tie-breaker.
    """
    stmt = select(QuarantineRecord)

    if incident_id:
        stmt = stmt.where(QuarantineRecord.incident_id == incident_id)
    if status:
        stmt = stmt.where(QuarantineRecord.status == status)

    stmt = stmt.order_by(QuarantineRecord.quarantined_at.desc(), QuarantineRecord.quarantine_id.desc())
    return paginate_query(session, stmt, page=page, page_size=page_size)


def update_quarantine_status(
    session: Session,
    quarantine_id: str,
    new_status: str,
    *,
    restoration_path: Optional[str] = None,
    restored_at: Optional[str] = None,
) -> QuarantineRecord:
    """Update quarantine lifecycle status and record authorized restoration destination metadata.

    Enforces documented state transitions.
    """
    record = get_quarantine_record_or_raise(session, quarantine_id)

    if new_status not in VALID_QUARANTINE_STATUSES:
        raise ValidationError(f"Invalid status '{new_status}'. Allowed: {sorted(VALID_QUARANTINE_STATUSES)}", field="status")

    if new_status != record.status:
        allowed = ALLOWED_QUARANTINE_TRANSITIONS.get(record.status, set())
        if new_status not in allowed:
            raise InvalidStateTransitionError("QuarantineRecord", quarantine_id, record.status, new_status)

        record.status = new_status

    now = utc_now_iso()
    if new_status == "RESTORED":
        record.restored_at = restored_at or now
        if restoration_path:
            record.restoration_path = restoration_path

    record.updated_at = now
    session.flush()
    return record
