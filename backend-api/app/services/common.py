"""Shared pagination utilities and helpers for Sentinel-EDR persistence services."""

import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Generic, List, Optional, TypeVar

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.services.errors import ValidationError

T = TypeVar("T")


@dataclass(frozen=True)
class PaginatedResult(Generic[T]):
    """Standardized result envelope for paginated collection queries."""

    items: List[T]
    total_items: int
    page: int
    page_size: int
    total_pages: int


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 representation ending in 'Z'."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def serialize_json(data: Optional[Any], default_empty: Optional[str] = None) -> Optional[str]:
    """Serialize structured dict or list to JSON string."""
    if data is None:
        return default_empty
    if isinstance(data, str):
        return data
    return json.dumps(data)


def deserialize_json(json_str: Optional[str], fallback: Optional[Any] = None) -> Any:
    """Safely deserialize JSON string or return fallback."""
    if not json_str:
        return fallback
    try:
        return json.loads(json_str)
    except Exception:
        return fallback


def paginate_query(
    session: Session,
    query: Select,
    page: int = 1,
    page_size: int = 20,
    max_page_size: int = 100,
) -> PaginatedResult[Any]:
    """Execute bounded pagination over a SQLAlchemy select query."""
    if page < 1:
        raise ValidationError("Page number must be greater than or equal to 1.", field="page")
    if page_size < 1:
        raise ValidationError("Page size must be greater than or equal to 1.", field="page_size")

    clamped_page_size = min(page_size, max_page_size)

    # Compute total count efficiently using a subquery without ordering
    count_query = select(func.count()).select_from(query.order_by(None).subquery())
    total_items = session.scalar(count_query) or 0

    total_pages = math.ceil(total_items / clamped_page_size) if total_items > 0 else 0

    offset = (page - 1) * clamped_page_size
    paged_query = query.offset(offset).limit(clamped_page_size)
    items = list(session.scalars(paged_query).all())

    return PaginatedResult(
        items=items,
        total_items=total_items,
        page=page,
        page_size=clamped_page_size,
        total_pages=total_pages,
    )
