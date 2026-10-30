"""Persistence service for incident response action metadata."""

from typing import Any, Dict, Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.schemas.contracts import ResponseActionStatus
from app.services.common import PaginatedResult, paginate_query, serialize_json, utc_now_iso
from app.services.errors import (
    InvalidStateTransitionError,
    PersistenceConflictError,
    PersistenceError,
    ResourceNotFoundError,
    ValidationError,
)

VALID_STATUSES = {s.value for s in ResponseActionStatus}
VALID_MODES = {"DRY_RUN", "ENFORCEMENT"}

# Allowed transitions for response action lifecycle
ALLOWED_ACTION_TRANSITIONS = {
    ResponseActionStatus.PENDING.value: {
        ResponseActionStatus.IN_PROGRESS.value,
        ResponseActionStatus.FAILED.value,
        ResponseActionStatus.CANCELLED.value,
    },
    ResponseActionStatus.IN_PROGRESS.value: {
        ResponseActionStatus.SUCCEEDED.value,
        ResponseActionStatus.FAILED.value,
        ResponseActionStatus.CANCELLED.value,
    },
    ResponseActionStatus.SUCCEEDED.value: set(),
    ResponseActionStatus.FAILED.value: set(),
    ResponseActionStatus.CANCELLED.value: set(),
}


def create_response_action(
    session: Session,
    *,
    incident_id: str,
    action_type: str,
    requested_by: str,
    action_id: Optional[str] = None,
    mode: str = "DRY_RUN",
    status: str = ResponseActionStatus.PENDING.value,
    details: Optional[Dict[str, Any]] = None,
    requested_at: Optional[str] = None,
) -> ResponseAction:
    """Record an action requested or initiated in response to an incident.

    Stores operational metadata only; does not execute file or process operations.
    """
    if not incident_id:
        raise ValidationError("incident_id is required.", field="incident_id")
    if not action_type:
        raise ValidationError("action_type is required.", field="action_type")
    if not requested_by:
        raise ValidationError("requested_by is required.", field="requested_by")

    if mode not in VALID_MODES:
        raise ValidationError(f"Invalid mode '{mode}'. Allowed: {sorted(VALID_MODES)}", field="mode")

    if status not in VALID_STATUSES:
        raise ValidationError(f"Invalid status '{status}'. Allowed: {sorted(VALID_STATUSES)}", field="status")

    # Verify incident exists
    parent_incident = session.get(Incident, incident_id)
    if parent_incident is None:
        raise ResourceNotFoundError("Incident", incident_id)

    resolved_id = str(action_id or uuid4())
    resolved_requested = requested_at or utc_now_iso()

    action = ResponseAction(
        action_id=resolved_id,
        incident_id=incident_id,
        action_type=action_type,
        status=status,
        mode=mode,
        requested_by=requested_by,
        details_json=serialize_json(details),
        error_code=None,
        error_message=None,
        requested_at=resolved_requested,
        started_at=None,
        completed_at=None,
    )

    try:
        session.add(action)
        session.flush()
    except IntegrityError as exc:
        orig_msg = str(exc.orig) if hasattr(exc, "orig") else str(exc)
        if "UNIQUE" in orig_msg.upper() or "PRIMARY KEY" in orig_msg.upper():
            raise PersistenceConflictError(
                f"Response action with ID '{resolved_id}' already exists.",
                conflict_key="action_id",
                conflict_value=resolved_id,
            ) from exc
        raise PersistenceError(f"Failed to persist response action: {orig_msg}") from exc

    return action


def get_response_action(session: Session, action_id: str) -> Optional[ResponseAction]:
    """Retrieve a response action by primary key, or None if not found."""
    return session.get(ResponseAction, str(action_id))


def get_response_action_or_raise(session: Session, action_id: str) -> ResponseAction:
    """Retrieve a response action by primary key, raising ResourceNotFoundError if missing."""
    action = get_response_action(session, action_id)
    if action is None:
        raise ResourceNotFoundError("ResponseAction", action_id)
    return action


def list_response_actions_for_incident(
    session: Session,
    incident_id: str,
    page: int = 1,
    page_size: int = 20,
    status: Optional[str] = None,
    action_type: Optional[str] = None,
) -> PaginatedResult[ResponseAction]:
    """Retrieve a paginated collection of response actions for an incident.

    Uses deterministic ordering: requested_at descending, action_id descending as tie-breaker.
    """
    stmt = select(ResponseAction).where(ResponseAction.incident_id == incident_id)

    if status:
        stmt = stmt.where(ResponseAction.status == status)
    if action_type:
        stmt = stmt.where(ResponseAction.action_type == action_type)

    stmt = stmt.order_by(ResponseAction.requested_at.desc(), ResponseAction.action_id.desc())
    return paginate_query(session, stmt, page=page, page_size=page_size)


def update_response_action_status(
    session: Session,
    action_id: str,
    new_status: str,
    *,
    started_at: Optional[str] = None,
    completed_at: Optional[str] = None,
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
) -> ResponseAction:
    """Update execution status and lifecycle timestamps for a response action.

    Enforces documented state transitions.
    """
    action = get_response_action_or_raise(session, action_id)

    if new_status not in VALID_STATUSES:
        raise ValidationError(f"Invalid status '{new_status}'. Allowed: {sorted(VALID_STATUSES)}", field="status")

    if new_status != action.status:
        allowed = ALLOWED_ACTION_TRANSITIONS.get(action.status, set())
        if new_status not in allowed:
            raise InvalidStateTransitionError("ResponseAction", action_id, action.status, new_status)

        action.status = new_status

    now = utc_now_iso()
    if new_status == ResponseActionStatus.IN_PROGRESS.value and not action.started_at:
        action.started_at = started_at or now

    if new_status in {
        ResponseActionStatus.SUCCEEDED.value,
        ResponseActionStatus.FAILED.value,
        ResponseActionStatus.CANCELLED.value,
    }:
        action.completed_at = completed_at or now

    if error_code:
        action.error_code = error_code
    if error_message:
        action.error_message = error_message

    session.flush()
    return action
