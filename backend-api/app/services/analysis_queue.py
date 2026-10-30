"""Thread-safe bounded dispatch queue for analysis jobs in Sentinel-EDR.

Manages process-local job dispatch notifications to workers, using the persistent
database as the source of truth and enforcing backpressure boundaries.

Deployment Architecture:
The in-memory queue is process-local. Cross-worker synchronization and coordination
are guaranteed through atomic database claiming (claim_analysis_job).
"""

import logging
import queue
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.session import get_session_factory
from app.models.analysis_job import AnalysisJob
from app.services.analysis_job_service import (
    create_analysis_job,
    get_pending_queued_job_ids,
)

logger = logging.getLogger("sentinel.services.analysis_queue")


class AnalysisQueue:
    """Thread-safe bounded in-process dispatch queue for analysis jobs.

    In-memory entries serve as dispatch notifications to available worker threads,
    while persistent database records remain the authoritative state of all jobs.
    """

    def __init__(
        self,
        maxsize: Optional[int] = None,
        *,
        session_factory: Optional[sessionmaker[Session]] = None,
    ) -> None:
        """Initialize the bounded queue.

        Args:
            maxsize: Maximum in-memory capacity. Defaults to settings.analysis_queue_capacity.
            session_factory: Optional SQLAlchemy session factory for DB operations.
        """
        settings = get_settings()
        self._maxsize = maxsize if maxsize is not None else settings.analysis_queue_capacity
        if self._maxsize <= 0:
            raise ValueError(f"Queue maxsize must be positive, got: {self._maxsize}")

        self._queue: queue.Queue[str] = queue.Queue(maxsize=self._maxsize)
        self._session_factory = session_factory or get_session_factory()

    @property
    def capacity(self) -> int:
        """Return the maximum dispatch queue capacity."""
        return self._maxsize

    def qsize(self) -> int:
        """Return the current number of items waiting in the dispatch queue."""
        return self._queue.qsize()

    def is_empty(self) -> bool:
        """Return True if the in-memory dispatch queue is empty."""
        return self._queue.empty()

    def is_full(self) -> bool:
        """Return True if the in-memory dispatch queue is currently full."""
        return self._queue.full()

    def clear(self) -> None:
        """Drain all pending notifications from the in-memory dispatch queue."""
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except queue.Empty:
                break

    def submit_job_id(self, job_id: str) -> bool:
        """Enqueue an existing persisted job ID for worker dispatch.

        Args:
            job_id: Unique identifier of the analysis job (UUID string).

        Returns:
            True if successfully placed in the in-memory queue;
            False if queue is saturated (job remains safely persisted in DB).

        Raises:
            ValueError: If job_id is empty or not a valid UUID string.
        """
        if not job_id or not isinstance(job_id, str):
            raise ValueError("job_id must be a non-empty string.")

        try:
            UUID(job_id)
        except (ValueError, TypeError) as err:
            raise ValueError(f"job_id '{job_id}' is not a valid UUID format.") from err

        try:
            self._queue.put_nowait(job_id)
            logger.info("Job accepted and dispatched to queue [job_id=%s, qsize=%d]", job_id, self.qsize())
            return True
        except queue.Full:
            logger.warning(
                "Queue saturation: analysis dispatch queue is full (capacity=%d); "
                "job %s remains safely persisted in DB and will be claimed via recovery",
                self._maxsize,
                job_id,
            )
            return False

    def submit(
        self,
        session: Session,
        *,
        file_path: Optional[str] = None,
        file_hash: Optional[str] = None,
        source_event_id: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> AnalysisJob:
        """Create a new persisted QUEUED job and dispatch it to the in-memory queue.

        Args:
            session: Active database session for persisting the job.
            file_path: Optional path to the target file.
            file_hash: Optional known SHA-256 hash.
            source_event_id: Optional parent endpoint event UUID.
            job_id: Optional predetermined UUID.

        Returns:
            The newly created and persisted AnalysisJob.
        """
        job = create_analysis_job(
            session,
            job_id=job_id,
            source_event_id=source_event_id,
            file_path=file_path,
            file_hash=file_hash,
        )
        session.flush()

        # Enqueue dispatch notification
        self.submit_job_id(job.job_id)
        return job

    def get_next_job_id(self, timeout: float = 1.0) -> Optional[str]:
        """Pull the next available job ID from the dispatch queue.

        Args:
            timeout: Maximum seconds to wait for a job notification.

        Returns:
            A job_id string, or None if the queue was empty for the timeout duration.
        """
        try:
            job_id = self._queue.get(timeout=timeout)
            self._queue.task_done()
            return job_id
        except queue.Empty:
            return None

    def discover_and_enqueue_pending_jobs(
        self,
        session: Session,
        limit: Optional[int] = None,
    ) -> int:
        """Query persisted QUEUED jobs from database and enqueue undispatched jobs.

        Args:
            session: Database session for querying queued jobs.
            limit: Maximum number of jobs to fetch. Defaults to available queue capacity.

        Returns:
            The number of jobs successfully added to the dispatch queue.
        """
        available_slots = self._maxsize - self.qsize()
        if available_slots <= 0:
            return 0

        max_fetch = min(available_slots, limit or available_slots)
        pending_ids = get_pending_queued_job_ids(session, limit=max_fetch)

        enqueued_count = 0
        for j_id in pending_ids:
            try:
                self._queue.put_nowait(j_id)
                enqueued_count += 1
                logger.info("Job rediscovered during recovery and enqueued [job_id=%s]", j_id)
            except queue.Full:
                break

        return enqueued_count
