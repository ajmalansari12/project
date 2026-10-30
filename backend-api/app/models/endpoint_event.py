"""SQLAlchemy model for endpoint_events table."""

from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import CheckConstraint, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.analysis_job import AnalysisJob


class EndpointEvent(Base):
    """Stores normalized events collected by the endpoint sensor or behavioral monitor."""

    __tablename__ = "endpoint_events"

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[str] = mapped_column(String(32), nullable=False)
    source_component: Mapped[str] = mapped_column(String(128), nullable=False)
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    parent_process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)

    analysis_jobs: Mapped[List["AnalysisJob"]] = relationship(
        "AnalysisJob",
        back_populates="source_event",
    )

    __table_args__ = (
        CheckConstraint(
            "event_type IN ('file_created', 'file_modified', 'file_renamed', 'file_deleted', 'process_observed', 'canary_triggered')",
            name="ck_endpoint_events_type",
        ),
        CheckConstraint(
            "file_hash IS NULL OR (length(file_hash) = 64 AND NOT (file_hash GLOB '*[^0-9a-fA-F]*'))",
            name="ck_endpoint_events_hash",
        ),
        Index("ix_endpoint_events_timestamp", "timestamp"),
        Index("ix_endpoint_events_type_timestamp", "event_type", "timestamp"),
        Index("ix_endpoint_events_file_hash", "file_hash"),
    )
