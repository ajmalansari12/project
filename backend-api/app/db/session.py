"""Database engine, connection management, and session lifecycle utilities."""

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


def _enable_sqlite_foreign_keys(dbapi_connection: object, connection_record: object) -> None:
    """Enable foreign-key enforcement for SQLite database connections."""
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA foreign_keys = ON;")
    cursor.close()


def create_database_engine(
    database_url: Optional[str] = None,
    echo: bool = False,
    **engine_kwargs: object,
) -> Engine:
    """Create and configure a SQLAlchemy 2.x Engine.

    Ensures parent directories are created for file-backed SQLite paths and
    attaches connection listeners for foreign-key enforcement.
    """
    url = database_url or get_settings().database_url

    # For file-backed SQLite URLs, ensure target directory exists and resolve relative paths to project root
    if url.startswith("sqlite") and not url.endswith(":memory:") and "mode=memory" not in url:
        path_str = url.split("sqlite:///")[-1].split("?")[0]
        if path_str:
            db_path = Path(path_str)
            if not db_path.is_absolute():
                project_root = Path(__file__).resolve().parent.parent.parent.parent
                db_path = (project_root / db_path).resolve()
                url = f"sqlite:///{db_path.as_posix()}"
            db_path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(
        url,
        echo=echo,
        **engine_kwargs,
    )

    if url.startswith("sqlite"):
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)

    return engine


_default_engine: Optional[Engine] = None
_default_session_factory: Optional[sessionmaker[Session]] = None


def get_default_engine() -> Engine:
    """Return the reusable global Engine, initializing it lazily on first call."""
    global _default_engine
    if _default_engine is None:
        _default_engine = create_database_engine()
    return _default_engine


def get_session_factory(engine: Optional[Engine] = None) -> sessionmaker[Session]:
    """Return a configured session factory bound to the given or default engine."""
    if engine is not None:
        return sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=engine,
            expire_on_commit=False,
        )
    global _default_session_factory
    if _default_session_factory is None:
        _default_session_factory = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=get_default_engine(),
            expire_on_commit=False,
        )
    return _default_session_factory


def reset_database_engine() -> None:
    """Dispose and clear cached engine and factory (for tests and teardown)."""
    global _default_engine, _default_session_factory
    if _default_engine is not None:
        _default_engine.dispose()
        _default_engine = None
    _default_session_factory = None


@contextmanager
def db_session_scope(
    session_factory: Optional[sessionmaker[Session]] = None,
) -> Generator[Session, None, None]:
    """Transactional scope around a series of operations."""
    factory = session_factory or get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for yielding database sessions."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()
