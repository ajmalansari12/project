"""SQLAlchemy model for analysis_jobs table."""

from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import CheckConstraint, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.detection_evidence import DetectionEvidence
    from app.models.endpoint_event import EndpointEvent
    from app.models.incident import Incident


class AnalysisJob(Base):
    """Tracks individual analysis jobs across the pipeline lifecycle."""

    __tablename__ = "analysis_jobs"

    job_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_event_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("endpoint_events.event_id", ondelete="RESTRICT"),
        nullable=True,
    )
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    verdict: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    modules_executed_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    modules_skipped_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    modules_failed_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    queued_at: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    completed_at: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    source_event: Mapped[Optional["EndpointEvent"]] = relationship(
        "EndpointEvent",
        back_populates="analysis_jobs",
    )
    incidents: Mapped[List["Incident"]] = relationship(
        "Incident",
        back_populates="analysis_job",
    )
    detection_evidence: Mapped[List["DetectionEvidence"]] = relationship(
        "DetectionEvidence",
        back_populates="analysis_job",
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('QUEUED', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'CANCELLED')",
            name="ck_analysis_jobs_status",
        ),
        CheckConstraint(
            "verdict IS NULL OR verdict IN ('BENIGN', 'SUSPICIOUS', 'MALICIOUS')",
            name="ck_analysis_jobs_verdict",
        ),
        CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0.0 AND risk_score <= 100.0)",
            name="ck_analysis_jobs_risk_score",
        ),
        CheckConstraint(
            "file_hash IS NULL OR (length(file_hash) = 64 AND NOT (file_hash GLOB '*[^0-9a-fA-F]*'))",
            name="ck_analysis_jobs_hash",
        ),
        Index("ix_analysis_jobs_status_queued_at", "status", "queued_at"),
        Index("ix_analysis_jobs_source_event_id", "source_event_id"),
        Index("ix_analysis_jobs_file_hash", "file_hash"),
    )
