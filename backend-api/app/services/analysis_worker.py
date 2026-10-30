"""Analysis worker and lifecycle management for Sentinel-EDR.

Implements dedicated background worker threads, atomic job claiming, failure isolation,
and a centralized worker manager supporting startup recovery and graceful shutdown.

Supported Deployment Architecture:
- The in-process dispatch queue (AnalysisQueue) is process-local.
- The supported background execution model is a SINGLE active AnalysisWorkerManager process.
- Atomic job claiming (claim_analysis_job) provides multi-thread and multi-worker safety
  against duplicate execution of the same job.
- Unconditional recovery of IN_PROGRESS jobs (recover_interrupted_jobs) is supported ONLY
  during cold startup by the single designated manager before work dispatch. It must not be
  used across multiple active manager processes without distributed leases or heartbeats.
"""

import logging
import threading
from typing import List, Optional

from sqlalchemy import inspect
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.session import db_session_scope, get_session_factory
from app.schemas.contracts import AnalysisJobStatus
from app.services.analysis_job_service import (
    claim_analysis_job,
    recover_interrupted_jobs,
    update_analysis_job_status,
)
from app.services.analysis_orchestrator import AnalysisOrchestrator
from app.services.analysis_queue import AnalysisQueue

logger = logging.getLogger("sentinel.services.analysis_worker")


class AnalysisWorker:
    """Individual background worker thread processing claimed analysis jobs.

    Each job execution is wrapped in an isolated database session and error boundary.
    An unhandled error in a single job never terminates the worker thread.
    """

    def __init__(
        self,
        worker_id: str,
        queue: AnalysisQueue,
        orchestrator: AnalysisOrchestrator,
        session_factory: sessionmaker[Session],
        stop_event: threading.Event,
        *,
        poll_interval: float = 0.5,
    ) -> None:
        """Initialize worker thread.

        Args:
            worker_id: Identifier for logging and diagnostics (e.g. 'worker-1').
            queue: AnalysisQueue instance to pull job notifications from.
            orchestrator: AnalysisOrchestrator instance to execute pipeline stages.
            session_factory: SQLAlchemy sessionmaker used to produce per-job sessions.
            stop_event: Threading event signaled when shutdown is requested.
            poll_interval: Queue poll timeout in seconds.
        """
        self.worker_id = worker_id
        self._queue = queue
        self._orchestrator = orchestrator
        self._session_factory = session_factory
        self._stop_event = stop_event
        self._poll_interval = poll_interval
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Spawn and start the worker thread."""
        self._thread = threading.Thread(
            target=self._run,
            name=f"AnalysisWorker-{self.worker_id}",
            daemon=True,
        )
        self._thread.start()

    def join(self, timeout: Optional[float] = None) -> None:
        """Wait for the worker thread to exit."""
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def is_alive(self) -> bool:
        """Return True if the worker thread is currently active."""
        return bool(self._thread and self._thread.is_alive())

    def _run(self) -> None:
        """Main worker loop pulling and processing jobs."""
        logger.debug("Worker %s started", self.worker_id)
        while not self._stop_event.is_set():
            job_id = self._queue.get_next_job_id(timeout=self._poll_interval)
            if self._stop_event.is_set():
                break
            if job_id is None:
                continue

            self._process_job(job_id)

        logger.debug("Worker %s stopping gracefully", self.worker_id)

    def _process_job(self, job_id: str) -> None:
        """Process an individual job using an isolated database session."""
        try:
            with db_session_scope(self._session_factory) as session:
                # 1. Claim job atomically (transitions QUEUED -> IN_PROGRESS)
                claimed_job = claim_analysis_job(session, job_id)
                if claimed_job is None:
                    # Job was already claimed by another worker, cancelled, or missing
                    logger.debug(
                        "Worker %s skipped job %s: already claimed or not in QUEUED status",
                        self.worker_id,
                        job_id,
                    )
                    return

                logger.info("Job claimed [worker_id=%s, job_id=%s]", self.worker_id, job_id)

                # 2. Execute orchestration stages
                try:
                    self._orchestrator.orchestrate_job(session, job_id)
                except Exception as exc:
                    logger.exception(
                        "Worker %s: orchestration failed with unhandled exception for job %s: %s",
                        self.worker_id,
                        job_id,
                        exc,
                    )
                    try:
                        update_analysis_job_status(
                            session,
                            job_id,
                            AnalysisJobStatus.FAILED.value,
                            error_code="ORCHESTRATION_ERROR",
                            error_message="Unexpected error during analysis orchestration.",
                        )
                    except Exception as status_exc:
                        logger.warning(
                            "Worker %s: could not record FAILED status for job %s: %s",
                            self.worker_id,
                            job_id,
                            status_exc,
                        )
        except Exception as session_exc:
            # Fatal session or DB error outside orchestration
            logger.exception(
                "Worker %s: session error while processing job %s: %s",
                self.worker_id,
                job_id,
                session_exc,
            )


class AnalysisWorkerManager:
    """Manages the lifecycle of analysis worker threads, startup recovery, and shutdown."""

    def __init__(
        self,
        queue: Optional[AnalysisQueue] = None,
        orchestrator: Optional[AnalysisOrchestrator] = None,
        session_factory: Optional[sessionmaker[Session]] = None,
        *,
        worker_count: Optional[int] = None,
        enabled: Optional[bool] = None,
        poll_interval: Optional[float] = None,
        recover_interrupted: Optional[bool] = None,
    ) -> None:
        """Initialize the manager without starting background threads at import time.

        Args:
            queue: Optional custom AnalysisQueue.
            orchestrator: Optional custom AnalysisOrchestrator.
            session_factory: Optional sessionmaker bound to the application DB engine.
            worker_count: Number of concurrent worker threads. Defaults to settings.
            enabled: Explicit flag to enable or disable background processing.
            poll_interval: Queue timeout in seconds for worker loops.
            recover_interrupted: Whether to recover orphaned IN_PROGRESS jobs on startup.
                Defaults to settings.analysis_recover_interrupted_on_startup (False).
                Supported exclusively under the single-manager deployment model.
        """
        settings = get_settings()
        self._enabled = enabled if enabled is not None else settings.analysis_workers_enabled
        self._worker_count = worker_count or settings.analysis_worker_count
        self._poll_interval = poll_interval or settings.analysis_worker_poll_interval_seconds
        self._recover_interrupted = (
            recover_interrupted
            if recover_interrupted is not None
            else settings.analysis_recover_interrupted_on_startup
        )
        self._session_factory = session_factory or get_session_factory()
        self._queue = queue or AnalysisQueue(session_factory=self._session_factory)
        self._orchestrator = orchestrator or AnalysisOrchestrator()

        self._workers: List[AnalysisWorker] = []
        self._stop_event = threading.Event()
        self._is_running = False
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        """Return True if worker threads are currently active."""
        return self._is_running

    @property
    def is_enabled(self) -> bool:
        """Return True if background workers are enabled in configuration."""
        return self._enabled

    @property
    def worker_count(self) -> int:
        """Return the configured number of worker threads."""
        return self._worker_count

    @property
    def recover_interrupted(self) -> bool:
        """Return True if startup recovery of orphaned IN_PROGRESS jobs is enabled."""
        return self._recover_interrupted

    @property
    def queue(self) -> AnalysisQueue:
        """Return the managed AnalysisQueue instance."""
        return self._queue

    @property
    def orchestrator(self) -> AnalysisOrchestrator:
        """Return the managed AnalysisOrchestrator instance."""
        return self._orchestrator

    def start(self, recover_interrupted: Optional[bool] = None) -> None:
        """Start worker threads and perform startup database recovery.

        Safely guarded against duplicate calls (idempotent) and non-blocking if
        database is not yet migrated or inaccessible.

        Args:
            recover_interrupted: Optional override for startup recovery of IN_PROGRESS jobs.
                Defaults to the configured setting (analysis_recover_interrupted_on_startup).
        """
        with self._lock:
            if recover_interrupted is not None:
                self._recover_interrupted = recover_interrupted

            if not self._enabled:
                logger.info("Analysis workers are disabled by configuration; not starting.")
                return

            if self._is_running:
                logger.debug("AnalysisWorkerManager already started; ignoring duplicate call.")
                return

            self._stop_event.clear()
            self._workers.clear()

            # Startup recovery: discover orphaned IN_PROGRESS jobs and pending QUEUED jobs
            self._perform_startup_recovery()

            # Spawn worker threads
            for i in range(self._worker_count):
                worker = AnalysisWorker(
                    worker_id=f"worker-{i+1}",
                    queue=self._queue,
                    orchestrator=self._orchestrator,
                    session_factory=self._session_factory,
                    stop_event=self._stop_event,
                    poll_interval=self._poll_interval,
                )
                worker.start()
                self._workers.append(worker)

            self._is_running = True
            logger.info("Started %d analysis workers successfully", len(self._workers))

    def stop(self, timeout: float = 5.0) -> None:
        """Signal all workers to stop and join active threads within timeout."""
        with self._lock:
            if not self._is_running:
                return

            logger.info("Stopping %d analysis workers...", len(self._workers))
            self._stop_event.set()

            # Wake up any worker threads blocked waiting on queue.get
            for _ in self._workers:
                try:
                    self._queue._queue.put_nowait(None)
                except Exception:
                    pass

            for worker in self._workers:
                worker.join(timeout=timeout)

            self._workers.clear()
            self._is_running = False
            logger.info("Analysis workers stopped cleanly.")

    def _perform_startup_recovery(self) -> None:
        """Safely inspect database on startup to recover interrupted or queued jobs.

        Supported Deployment Model:
        Startup recovery of IN_PROGRESS jobs is supported exclusively under a single-manager
        deployment model. The designated manager executes this recovery during cold boot
        before dispatching work.

        In a multi-manager setup without distributed heartbeats or worker leases,
        recover_interrupted must be disabled (False) to prevent one process from
        marking another active manager's running jobs as orphaned.
        """
        try:
            with db_session_scope(self._session_factory) as session:
                bind = session.get_bind()
                insp = inspect(bind)
                if not insp.has_table("analysis_jobs"):
                    logger.debug("Table 'analysis_jobs' not present; skipping startup recovery.")
                    return

                # Recover interrupted IN_PROGRESS jobs only if enabled under supported deployment model
                if self._recover_interrupted:
                    recovered_count = recover_interrupted_jobs(session)
                    if recovered_count > 0:
                        logger.info(
                            "Startup recovery: transitioned %d orphaned IN_PROGRESS jobs to FAILED "
                            "[supported deployment model: single active manager]",
                            recovered_count,
                        )
                else:
                    logger.debug(
                        "Skipping IN_PROGRESS recovery: recover_interrupted=False (preserves external jobs)"
                    )

                # Rediscover persisted QUEUED jobs
                enqueued = self._queue.discover_and_enqueue_pending_jobs(session)
                if enqueued > 0:
                    logger.info("Startup discovery: enqueued %d persisted QUEUED jobs for dispatch", enqueued)
        except Exception as exc:
            logger.warning(
                "Startup recovery check encountered non-fatal error: %s (skipping recovery)",
                exc,
            )


# ------------------------------------------------------------------------------
# Module-level singletons (lazily initialized, never auto-started on import)
# ------------------------------------------------------------------------------
_default_queue: Optional[AnalysisQueue] = None
_default_manager: Optional[AnalysisWorkerManager] = None
_manager_lock = threading.RLock()


def get_default_analysis_queue() -> AnalysisQueue:
    """Return the application-wide default AnalysisQueue singleton."""
    global _default_queue
    if _default_queue is None:
        with _manager_lock:
            if _default_queue is None:
                _default_queue = AnalysisQueue()
    return _default_queue


def get_default_worker_manager() -> AnalysisWorkerManager:
    """Return the application-wide default AnalysisWorkerManager singleton.

    Does NOT start the worker threads upon creation; start() must be explicitly called.
    """
    global _default_manager
    if _default_manager is None:
        with _manager_lock:
            if _default_manager is None:
                queue = get_default_analysis_queue()
                _default_manager = AnalysisWorkerManager(queue=queue)
    return _default_manager


def reset_worker_manager() -> None:
    """Stop active workers and reset singleton instances (for test isolation)."""
    global _default_manager, _default_queue
    with _manager_lock:
        if _default_manager is not None:
            if _default_manager.is_running:
                _default_manager.stop()
            _default_manager = None
        if _default_queue is not None:
            _default_queue.clear()
            _default_queue = None
