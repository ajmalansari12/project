"""SQLAlchemy model for incidents table."""

from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import CheckConstraint, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.analysis_job import AnalysisJob
    from app.models.detection_evidence import DetectionEvidence
    from app.models.forensic_report import ForensicReport
    from app.models.quarantine_record import QuarantineRecord
    from app.models.response_action import ResponseAction


class Incident(Base):
    """Stores security findings and incidents presented on the SOC dashboard."""

    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_job_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("analysis_jobs.job_id", ondelete="RESTRICT"),
        nullable=True,
    )
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    incident_type: Mapped[str] = mapped_column(String(64), nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    detected_at: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)
    resolved_at: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    analysis_job: Mapped[Optional["AnalysisJob"]] = relationship(
        "AnalysisJob",
        back_populates="incidents",
    )
    evidence_records: Mapped[List["DetectionEvidence"]] = relationship(
        "DetectionEvidence",
        back_populates="incident",
    )
    response_actions: Mapped[List["ResponseAction"]] = relationship(
        "ResponseAction",
        back_populates="incident",
    )
    quarantine_records: Mapped[List["QuarantineRecord"]] = relationship(
        "QuarantineRecord",
        back_populates="incident",
    )
    forensic_reports: Mapped[List["ForensicReport"]] = relationship(
        "ForensicReport",
        back_populates="incident",
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED')",
            name="ck_incidents_status",
        ),
        CheckConstraint(
            "verdict IN ('BENIGN', 'SUSPICIOUS', 'MALICIOUS')",
            name="ck_incidents_verdict",
        ),
        CheckConstraint(
            "risk_score >= 0.0 AND risk_score <= 100.0",
            name="ck_incidents_risk_score",
        ),
        CheckConstraint(
            "file_hash IS NULL OR (length(file_hash) = 64 AND NOT (file_hash GLOB '*[^0-9a-fA-F]*'))",
            name="ck_incidents_hash",
        ),
        Index("ix_incidents_detected_at", "detected_at"),
        Index("ix_incidents_verdict_detected_at", "verdict", "detected_at"),
        Index("ix_incidents_status_detected_at", "status", "detected_at"),
        Index("ix_incidents_file_hash", "file_hash"),
    )
