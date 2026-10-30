"""FastAPI dependency injection providers for database sessions and request context."""

from typing import Generator
from uuid import uuid4

from fastapi import Request
from sqlalchemy.orm import Session

from app.db.session import get_db


def get_db_session() -> Generator[Session, None, None]:
    """Dependency yielding a scoped SQLAlchemy database session."""
    yield from get_db()


def get_request_id(request: Request) -> str:
    """Extract or generate a unique tracking identifier for the current request."""
    return getattr(request.state, "request_id", None) or str(uuid4())
