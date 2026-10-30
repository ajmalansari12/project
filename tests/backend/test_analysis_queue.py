"""Unit and integration tests for AnalysisQueue in Sentinel-EDR (T010)."""

from typing import Generator
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import db_session_scope
from app.models.analysis_job import AnalysisJob
from app.schemas.contracts import AnalysisJobStatus
from app.services.analysis_job_service import create_analysis_job, get_analysis_job_or_raise
from app.services.analysis_queue import AnalysisQueue
from app.services.analysis_worker import AnalysisWorkerManager


@pytest.fixture
def isolated_db():
    """Create an isolated in-memory SQLite database for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    yield session_factory
    engine.dispose()


@pytest.fixture
def db_session(isolated_db: sessionmaker[Session]) -> Generator[Session, None, None]:
    """Provide a transactional session for test setups."""
    with db_session_scope(isolated_db) as session:
        yield session


def test_queue_initialization_and_capacity():
    """Verify queue initializes with configured bounds and rejects invalid capacities."""
    q = AnalysisQueue(maxsize=10)
    assert q.capacity == 10
    assert q.qsize() == 0
    assert q.is_empty() is True
    assert q.is_full() is False

    with pytest.raises(ValueError, match="Queue maxsize must be positive"):
        AnalysisQueue(maxsize=0)


def test_submit_valid_job_id_and_dispatch(isolated_db: sessionmaker[Session], db_session: Session):
    """Verify valid UUID job IDs can be submitted, dispatched, and retrieved."""
    q = AnalysisQueue(maxsize=5, session_factory=isolated_db)
    job = create_analysis_job(db_session, file_path="C:\\test\\target.bin")
    db_session.commit()

    success = q.submit_job_id(job.job_id)
    assert success is True
    assert q.qsize() == 1
    assert q.is_empty() is False

    pulled_id = q.get_next_job_id(timeout=0.1)
    assert pulled_id == job.job_id
    assert q.is_empty() is True


def test_submit_helper_creates_and_enqueues_job(isolated_db: sessionmaker[Session], db_session: Session):
    """Verify queue.submit creates a persisted QUEUED job and dispatches its notification."""
    q = AnalysisQueue(maxsize=5, session_factory=isolated_db)
    job = q.submit(db_session, file_path="C:\\sample.exe", file_hash="0" * 64)
    db_session.commit()

    assert job.status == AnalysisJobStatus.QUEUED.value
    assert job.file_path == "C:\\sample.exe"
    assert q.qsize() == 1

    queried = get_analysis_job_or_raise(db_session, job.job_id)
    assert queried.status == AnalysisJobStatus.QUEUED.value


def test_queue_capacity_bound_and_backpressure_preserves_work(
    isolated_db: sessionmaker[Session], db_session: Session
):
    """Verify queue saturation rejects in-memory enqueueing but leaves DB job safely QUEUED."""
    q = AnalysisQueue(maxsize=2, session_factory=isolated_db)

    job1 = q.submit(db_session, file_path="C:\\job1.bin")
    job2 = q.submit(db_session, file_path="C:\\job2.bin")
    db_session.commit()

    assert q.is_full() is True

    # Third job exceeds capacity
    job3 = create_analysis_job(db_session, file_path="C:\\job3.bin")
    db_session.commit()

    success = q.submit_job_id(job3.job_id)
    assert success is False  # Saturated, in-memory put rejected
    assert q.qsize() == 2

    # Verify job3 was NOT lost from the database: it remains persisted in QUEUED state
    queried_job3 = get_analysis_job_or_raise(db_session, job3.job_id)
    assert queried_job3.status == AnalysisJobStatus.QUEUED.value


def test_invalid_job_id_rejected():
    """Verify invalid job ID arguments (empty or non-UUID) raise ValueError."""
    q = AnalysisQueue(maxsize=5)

    with pytest.raises(ValueError, match="job_id must be a non-empty string"):
        q.submit_job_id("")

    with pytest.raises(ValueError, match="not a valid UUID format"):
        q.submit_job_id("invalid-uuid-string-12345")


def test_get_next_job_id_timeout_returns_none():
    """Verify get_next_job_id returns None when queue is empty within timeout."""
    q = AnalysisQueue(maxsize=5)
    assert q.get_next_job_id(timeout=0.01) is None


def test_discover_and_enqueue_pending_jobs(
    isolated_db: sessionmaker[Session], db_session: Session
):
    """Verify startup recovery discovers persisted QUEUED jobs and fills queue to capacity."""
    q = AnalysisQueue(maxsize=3, session_factory=isolated_db)

    # Persist 4 queued jobs directly in database
    for i in range(4):
        create_analysis_job(db_session, file_path=f"C:\\pending_{i}.dll")
    db_session.commit()

    assert q.qsize() == 0

    # Discover pending jobs: queue capacity is 3, so 3 should be enqueued
    enqueued = q.discover_and_enqueue_pending_jobs(db_session)
    assert enqueued == 3
    assert q.qsize() == 3
    assert q.is_full() is True


def test_queue_clear_drains_notifications():
    """Verify clear drains all pending notifications."""
    q = AnalysisQueue(maxsize=5)
    for _ in range(3):
        q.submit_job_id(str(uuid.uuid4()))
    assert q.qsize() == 3

    q.clear()
    assert q.is_empty() is True
    assert q.qsize() == 0


def test_worker_manager_disabled_does_not_claim_running(isolated_db: sessionmaker[Session]):
    """Verify disabled worker manager does not start threads or falsely report running."""
    manager = AnalysisWorkerManager(
        session_factory=isolated_db,
        enabled=False,
        worker_count=2,
    )
    assert manager.is_enabled is False
    assert manager.is_running is False

    manager.start()
    assert manager.is_running is False

    manager.stop()
    assert manager.is_running is False


def test_worker_manager_start_and_stop_idempotence(isolated_db: sessionmaker[Session]):
    """Verify start and stop operations can be called repeatedly without errors or thread leaks."""
    manager = AnalysisWorkerManager(
        session_factory=isolated_db,
        enabled=True,
        worker_count=2,
        poll_interval=0.05,
    )
    assert manager.is_running is False

    # First start
    manager.start()
    assert manager.is_running is True

    # Duplicate start: safely guarded
    manager.start()
    assert manager.is_running is True

    # First stop
    manager.stop(timeout=1.0)
    assert manager.is_running is False

    # Duplicate stop: safely guarded
    manager.stop(timeout=1.0)
    assert manager.is_running is False
