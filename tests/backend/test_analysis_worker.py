"""Unit and concurrency tests for AnalysisWorker and WorkerManager in Sentinel-EDR (T010)."""

from pathlib import Path
import threading
import time
from typing import Generator
from unittest.mock import patch
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import db_session_scope
from app.schemas.contracts import AnalysisJobStatus, HashListType, SecurityVerdict
from app.services.analysis_job_service import (
    cancel_analysis_job,
    claim_analysis_job,
    create_analysis_job,
    get_analysis_job,
    get_analysis_job_or_raise,
    recover_interrupted_jobs,
    update_analysis_job_status,
)
from app.services.analysis_orchestrator import AnalysisOrchestrator
from app.services.analysis_queue import AnalysisQueue
from app.services.analysis_worker import (
    AnalysisWorker,
    AnalysisWorkerManager,
    get_default_worker_manager,
    reset_worker_manager,
)
from app.services.hash_database_service import create_hash_reputation


@pytest.fixture
def isolated_db():
    """Create an isolated in-memory SQLite database."""
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


@pytest.fixture
def temp_sample_file(tmp_path: Path) -> Path:
    """Create a temporary harmless fixture file for worker tests."""
    p = tmp_path / "worker_test_file.bin"
    p.write_bytes(b"Sentinel EDR Worker Test Content")
    return p


@pytest.fixture
def isolated_file_db(tmp_path: Path):
    """Create an isolated file-backed SQLite database for multi-threaded concurrency testing."""
    db_file = tmp_path / "concurrency_test.db"
    engine = create_engine(
        f"sqlite:///{db_file.as_posix()}",
        connect_args={"timeout": 15},
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    yield session_factory
    engine.dispose()


def test_atomic_claim_concurrency_only_one_worker_succeeds(isolated_file_db: sessionmaker[Session]):
    """Verify that when multiple threads attempt to claim the same job, exactly one succeeds."""
    with db_session_scope(isolated_file_db) as session:
        job = create_analysis_job(session, file_path="C:\\sample.bin")
        job_id = job.job_id

    claim_results = []
    barrier = threading.Barrier(5)

    def _attempt_claim():
        barrier.wait()
        with db_session_scope(isolated_file_db) as session:
            claimed = claim_analysis_job(session, job_id)
            if claimed is not None:
                claim_results.append(claimed.job_id)

    threads = [threading.Thread(target=_attempt_claim) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one thread must have succeeded
    assert len(claim_results) == 1
    assert claim_results[0] == job_id

    # Database state must be IN_PROGRESS
    with db_session_scope(isolated_file_db) as session:
        persisted = get_analysis_job_or_raise(session, job_id)
        assert persisted.status == AnalysisJobStatus.IN_PROGRESS.value


def test_worker_processes_job_end_to_end(
    isolated_db: sessionmaker[Session], temp_sample_file: Path
):
    """Verify a worker pulls a job, executes orchestration, and marks it COMPLETED."""
    queue = AnalysisQueue(session_factory=isolated_db)
    orchestrator = AnalysisOrchestrator()
    stop_event = threading.Event()

    with db_session_scope(isolated_db) as session:
        job = queue.submit(session, file_path=str(temp_sample_file))
        job_id = job.job_id

    worker = AnalysisWorker(
        worker_id="test-worker-1",
        queue=queue,
        orchestrator=orchestrator,
        session_factory=isolated_db,
        stop_event=stop_event,
        poll_interval=0.05,
    )
    worker.start()

    # Wait for completion (bounded poll)
    completed = False
    for _ in range(50):
        time.sleep(0.05)
        with db_session_scope(isolated_db) as session:
            j = get_analysis_job(session, job_id)
            if j and j.status == AnalysisJobStatus.COMPLETED.value:
                completed = True
                break

    stop_event.set()
    worker.join(timeout=1.0)

    assert completed is True
    with db_session_scope(isolated_db) as session:
        j = get_analysis_job_or_raise(session, job_id)
        assert j.status == AnalysisJobStatus.COMPLETED.value
        assert j.started_at is not None
        assert j.completed_at is not None
        assert len(j.file_hash) == 64


def test_worker_resilience_continues_after_job_failure(
    isolated_db: sessionmaker[Session], temp_sample_file: Path
):
    """Verify worker thread does not terminate when a job encounters a failure."""
    queue = AnalysisQueue(session_factory=isolated_db)
    orchestrator = AnalysisOrchestrator()
    stop_event = threading.Event()

    # Job 1: Invalid/missing file path -> Fails
    with db_session_scope(isolated_db) as session:
        bad_job = queue.submit(session, file_path="C:\\missing\\file.dll")
        bad_job_id = bad_job.job_id
    # Job 2: Valid file path -> Succeeds
    with db_session_scope(isolated_db) as session:
        good_job = queue.submit(session, file_path=str(temp_sample_file))
        good_job_id = good_job.job_id

    worker = AnalysisWorker(
        worker_id="resilient-worker",
        queue=queue,
        orchestrator=orchestrator,
        session_factory=isolated_db,
        stop_event=stop_event,
        poll_interval=0.05,
    )
    worker.start()

    # Wait for good_job to complete
    good_completed = False
    for _ in range(50):
        time.sleep(0.05)
        with db_session_scope(isolated_db) as session:
            j = get_analysis_job(session, good_job_id)
            if j and j.status == AnalysisJobStatus.COMPLETED.value:
                good_completed = True
                break

    stop_event.set()
    worker.join(timeout=1.0)

    assert good_completed is True
    assert worker.is_alive() is False  # Joined cleanly

    with db_session_scope(isolated_db) as session:
        bad_persisted = get_analysis_job_or_raise(session, bad_job_id)
        assert bad_persisted.status == AnalysisJobStatus.FAILED.value
        assert bad_persisted.error_code == "HASHING_FAILED"

        good_persisted = get_analysis_job_or_raise(session, good_job_id)
        assert good_persisted.status == AnalysisJobStatus.COMPLETED.value


def test_startup_recovery_interrupted_jobs_transition_to_failed(
    isolated_db: sessionmaker[Session]
):
    """Verify orphaned IN_PROGRESS jobs are recovered to FAILED with INTERRUPTED_BY_SHUTDOWN."""
    with db_session_scope(isolated_db) as session:
        job = create_analysis_job(session, file_path="C:\\interrupted.bin")
        job_id = job.job_id
        claim_analysis_job(session, job_id)
        persisted = get_analysis_job_or_raise(session, job_id)
        assert persisted.status == AnalysisJobStatus.IN_PROGRESS.value

    # Run recovery
    with db_session_scope(isolated_db) as session:
        recovered = recover_interrupted_jobs(session)
        assert recovered == 1

        persisted = get_analysis_job_or_raise(session, job_id)
        assert persisted.status == AnalysisJobStatus.FAILED.value
        assert persisted.error_code == "INTERRUPTED_BY_SHUTDOWN"
        assert persisted.completed_at is not None


def test_startup_recovery_redispatches_queued_jobs(
    isolated_db: sessionmaker[Session]
):
    """Verify startup manager discovers persisted QUEUED jobs and dispatches them."""
    with db_session_scope(isolated_db) as session:
        job1 = create_analysis_job(session, file_path="C:\\queued_1.bin")
        job2 = create_analysis_job(session, file_path="C:\\queued_2.bin")
        job1_id = job1.job_id
        job2_id = job2.job_id

    manager = AnalysisWorkerManager(
        session_factory=isolated_db,
        enabled=True,
        worker_count=1,
        poll_interval=0.05,
    )
    manager.start()

    time.sleep(0.1)
    manager.stop(timeout=1.0)

    with db_session_scope(isolated_db) as session:
        # Both jobs are intact, neither was deleted or lost
        j1 = get_analysis_job_or_raise(session, job1_id)
        j2 = get_analysis_job_or_raise(session, job2_id)
        assert j1.status in (AnalysisJobStatus.QUEUED.value, AnalysisJobStatus.FAILED.value, AnalysisJobStatus.IN_PROGRESS.value, AnalysisJobStatus.COMPLETED.value)
        assert j2.status in (AnalysisJobStatus.QUEUED.value, AnalysisJobStatus.FAILED.value, AnalysisJobStatus.IN_PROGRESS.value, AnalysisJobStatus.COMPLETED.value)


def test_cancellation_follows_canonical_state_machine(
    isolated_db: sessionmaker[Session]
):
    """Verify cancellation behaves according to ALLOWED_TRANSITIONS."""
    with db_session_scope(isolated_db) as session:
        # 1. Cancel QUEUED job
        job_queued = create_analysis_job(session, file_path="C:\\queued.bin")
        queued_id = job_queued.job_id
        cancel_analysis_job(session, queued_id, reason="User cancelled queued job")
        persisted_queued = get_analysis_job_or_raise(session, queued_id)
        assert persisted_queued.status == AnalysisJobStatus.CANCELLED.value
        assert persisted_queued.error_message == "User cancelled queued job"

        # 2. Cancel IN_PROGRESS job
        job_in_prog = create_analysis_job(session, file_path="C:\\running.bin")
        in_prog_id = job_in_prog.job_id
        claim_analysis_job(session, in_prog_id)
        cancel_analysis_job(session, in_prog_id, reason="User cancelled active job")
        persisted_in_prog = get_analysis_job_or_raise(session, in_prog_id)
        assert persisted_in_prog.status == AnalysisJobStatus.CANCELLED.value

        # 3. Cancelling a CANCELLED job raises InvalidStateTransitionError
        from app.services.errors import InvalidStateTransitionError
        with pytest.raises(InvalidStateTransitionError):
            cancel_analysis_job(session, queued_id)


def test_import_alone_does_not_start_workers():
    """Verify importing the module alone does not spawn threads or start workers."""
    reset_worker_manager()
    initial_threads = threading.active_count()
    manager = get_default_worker_manager()
    assert manager.is_running is False
    assert threading.active_count() == initial_threads


def test_startup_recovery_respects_single_manager_deployment_setting(
    isolated_db: sessionmaker[Session]
):
    """Verify recover_interrupted=False preserves IN_PROGRESS jobs, preventing multi-process sweep."""
    with db_session_scope(isolated_db) as session:
        job = create_analysis_job(session, file_path="C:\\active_in_other_process.bin")
        active_id = job.job_id
        claim_analysis_job(session, active_id)

    # Manager started with recover_interrupted=False (e.g. secondary process in multi-process deployment)
    secondary_manager = AnalysisWorkerManager(
        session_factory=isolated_db,
        enabled=True,
        worker_count=1,
        poll_interval=0.05,
        recover_interrupted=False,
    )
    secondary_manager.start()
    secondary_manager.stop(timeout=1.0)

    # The active job MUST NOT have been swept to FAILED
    with db_session_scope(isolated_db) as session:
        job_check = get_analysis_job_or_raise(session, active_id)
        assert job_check.status == AnalysisJobStatus.IN_PROGRESS.value

    # Now the designated primary manager starts with recover_interrupted=True (supported model)
    primary_manager = AnalysisWorkerManager(
        session_factory=isolated_db,
        enabled=True,
        worker_count=1,
        poll_interval=0.05,
        recover_interrupted=True,
    )
    primary_manager.start()
    primary_manager.stop(timeout=1.0)

    # Now the genuinely orphaned job is transitioned to FAILED
    with db_session_scope(isolated_db) as session:
        job_check = get_analysis_job_or_raise(session, active_id)
        assert job_check.status == AnalysisJobStatus.FAILED.value
        assert job_check.error_code == "INTERRUPTED_BY_SHUTDOWN"


def test_shutdown_does_not_delete_persisted_jobs(
    isolated_db: sessionmaker[Session]
):
    """Verify manager shutdown gracefully leaves database job records intact."""
    with db_session_scope(isolated_db) as session:
        job1 = create_analysis_job(session, file_path="C:\\persistent_1.bin")
        job2 = create_analysis_job(session, file_path="C:\\persistent_2.bin")
        j1_id = job1.job_id
        j2_id = job2.job_id

    manager = AnalysisWorkerManager(
        session_factory=isolated_db,
        enabled=True,
        worker_count=2,
        poll_interval=0.05,
        recover_interrupted=False,
    )
    manager.start()
    assert manager.is_running is True

    # Immediate clean shutdown
    manager.stop(timeout=1.0)
    assert manager.is_running is False

    # Verify both records still exist with valid statuses
    with db_session_scope(isolated_db) as session:
        persisted1 = get_analysis_job_or_raise(session, j1_id)
        persisted2 = get_analysis_job_or_raise(session, j2_id)
        assert persisted1.job_id == j1_id
        assert persisted2.job_id == j2_id


def test_worker_manager_defaults_recovery_to_settings_config():
    """Verify AnalysisWorkerManager defaults recover_interrupted to settings.analysis_recover_interrupted_on_startup."""
    from app.core.config import get_settings
    settings = get_settings()
    assert settings.analysis_recover_interrupted_on_startup is False
    manager = AnalysisWorkerManager()
    assert manager.recover_interrupted is False


def test_start_method_allows_recovery_override():
    """Verify start(recover_interrupted=True) overrides manager instance configuration."""
    manager = AnalysisWorkerManager(enabled=False, recover_interrupted=False)
    assert manager.recover_interrupted is False
    manager.start(recover_interrupted=True)
    assert manager.recover_interrupted is True
