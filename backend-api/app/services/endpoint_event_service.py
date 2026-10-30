"""Persistence service for endpoint telemetry events."""

import re
from typing import Any, Dict, Optional, Union
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.endpoint_event import EndpointEvent
from app.schemas.contracts import EndpointEvent as EndpointEventContract
from app.schemas.contracts import EndpointEventType
from app.services.common import PaginatedResult, paginate_query, serialize_json, utc_now_iso
from app.services.errors import PersistenceConflictError, PersistenceError, ResourceNotFoundError, ValidationError

HEX_64_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
VALID_EVENT_TYPES = {t.value for t in EndpointEventType}


def create_endpoint_event(
    session: Session,
    event_data: Optional[Union[EndpointEventContract, Dict[str, Any]]] = None,
    *,
    event_id: Optional[str] = None,
    event_type: Optional[Union[str, EndpointEventType]] = None,
    timestamp: Optional[str] = None,
    source_component: Optional[str] = None,
    file_path: Optional[str] = None,
    file_hash: Optional[str] = None,
    process_id: Optional[int] = None,
    parent_process_id: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> EndpointEvent:
    """Create and persist a normalized endpoint event.

    Accepts either an EndpointEvent Pydantic contract, a dictionary, or explicit keyword parameters.
    Does not initiate scanning or analysis pipeline execution.
    """
    if isinstance(event_data, EndpointEventContract):
        data_dict = event_data.model_dump()
        resolved_event_id = str(data_dict["event_id"])
        resolved_type = (
            data_dict["event_type"].value
            if hasattr(data_dict["event_type"], "value")
            else str(data_dict["event_type"])
        )
        resolved_timestamp = (
            data_dict["timestamp"].isoformat().replace("+00:00", "Z")
            if hasattr(data_dict["timestamp"], "isoformat")
            else str(data_dict["timestamp"])
        )
        resolved_source = data_dict["source_component"]
        resolved_file_path = data_dict.get("file_path")
        resolved_file_hash = data_dict.get("file_hash")
        resolved_process_id = data_dict.get("process_id")
        resolved_parent_pid = data_dict.get("parent_process_id")
        resolved_metadata = data_dict.get("metadata")
    elif isinstance(event_data, dict):
        resolved_event_id = str(event_data.get("event_id") or uuid4())
        resolved_type = str(event_data["event_type"])
        resolved_timestamp = str(event_data.get("timestamp") or utc_now_iso())
        resolved_source = str(event_data["source_component"])
        resolved_file_path = event_data.get("file_path")
        resolved_file_hash = event_data.get("file_hash")
        resolved_process_id = event_data.get("process_id")
        resolved_parent_pid = event_data.get("parent_process_id")
        resolved_metadata = event_data.get("metadata")
    else:
        if not event_type:
            raise ValidationError("event_type is required.", field="event_type")
        if not source_component:
            raise ValidationError("source_component is required.", field="source_component")

        resolved_event_id = str(event_id or uuid4())
        resolved_type = (
            event_type.value if hasattr(event_type, "value") else str(event_type)
        )
        resolved_timestamp = str(timestamp or utc_now_iso())
        resolved_source = str(source_component)
        resolved_file_path = file_path
        resolved_file_hash = file_hash
        resolved_process_id = process_id
        resolved_parent_pid = parent_process_id
        resolved_metadata = metadata

    if resolved_type not in VALID_EVENT_TYPES:
        raise ValidationError(
            f"Invalid event_type '{resolved_type}'. Allowed: {sorted(VALID_EVENT_TYPES)}",
            field="event_type",
        )

    if resolved_file_hash and not HEX_64_PATTERN.match(resolved_file_hash):
        raise ValidationError(
            "file_hash must be a 64-character hexadecimal SHA-256 digest.",
            field="file_hash",
        )

    if resolved_process_id is not None and resolved_process_id < 0:
        raise ValidationError("process_id cannot be negative.", field="process_id")

    if resolved_parent_pid is not None and resolved_parent_pid < 0:
        raise ValidationError("parent_process_id cannot be negative.", field="parent_process_id")

    event = EndpointEvent(
        event_id=resolved_event_id,
        event_type=resolved_type,
        timestamp=resolved_timestamp,
        source_component=resolved_source,
        file_path=resolved_file_path,
        file_hash=resolved_file_hash,
        process_id=resolved_process_id,
        parent_process_id=resolved_parent_pid,
        metadata_json=serialize_json(resolved_metadata),
        created_at=utc_now_iso(),
    )

    try:
        session.add(event)
        session.flush()
    except IntegrityError as exc:
        orig_msg = str(exc.orig) if hasattr(exc, "orig") else str(exc)
        if "UNIQUE" in orig_msg.upper() or "PRIMARY KEY" in orig_msg.upper():
            raise PersistenceConflictError(
                f"Endpoint event with ID '{resolved_event_id}' already exists.",
                conflict_key="event_id",
                conflict_value=resolved_event_id,
            ) from exc
        raise PersistenceError(f"Failed to persist endpoint event: {orig_msg}") from exc

    return event


def get_endpoint_event(session: Session, event_id: str) -> Optional[EndpointEvent]:
    """Retrieve an endpoint event by primary key, or None if not found."""
    return session.get(EndpointEvent, str(event_id))


def get_endpoint_event_or_raise(session: Session, event_id: str) -> EndpointEvent:
    """Retrieve an endpoint event by primary key, raising ResourceNotFoundError if missing."""
    event = get_endpoint_event(session, event_id)
    if event is None:
        raise ResourceNotFoundError("EndpointEvent", event_id)
    return event


def list_endpoint_events(
    session: Session,
    page: int = 1,
    page_size: int = 20,
    event_type: Optional[str] = None,
    file_hash: Optional[str] = None,
    source_component: Optional[str] = None,
    file_path: Optional[str] = None,
    process_id: Optional[int] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> PaginatedResult[EndpointEvent]:
    """Retrieve a paginated collection of endpoint events with optional filters.

    Uses deterministic ordering: timestamp descending, event_id descending as tie-breaker.
    """
    stmt = select(EndpointEvent)

    if event_type:
        stmt = stmt.where(EndpointEvent.event_type == event_type)
    if file_hash:
        stmt = stmt.where(EndpointEvent.file_hash == file_hash)
    if source_component:
        stmt = stmt.where(EndpointEvent.source_component == source_component)
    if file_path:
        stmt = stmt.where(EndpointEvent.file_path == file_path)
    if process_id is not None:
        stmt = stmt.where(EndpointEvent.process_id == process_id)
    if start_time:
        stmt = stmt.where(EndpointEvent.timestamp >= start_time)
    if end_time:
        stmt = stmt.where(EndpointEvent.timestamp <= end_time)

    stmt = stmt.order_by(EndpointEvent.timestamp.desc(), EndpointEvent.event_id.desc())
    return paginate_query(session, stmt, page=page, page_size=page_size)

