"""SQLAlchemy model for detection_evidence table."""

from typing import TYPE_CHECKING, Optional

from sqlalchemy import CheckConstraint, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.analysis_job import AnalysisJob
    from app.models.incident import Incident


class DetectionEvidence(Base):
    """Stores individual indicators and signals supporting an incident detection verdict."""

    __tablename__ = "detection_evidence"

    evidence_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"),
        nullable=False,
    )
    analysis_job_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("analysis_jobs.job_id", ondelete="RESTRICT"),
        nullable=True,
    )
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    indicator: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    observed_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    score_contribution: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    details_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    observed_at: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)

    incident: Mapped["Incident"] = relationship(
        "Incident",
        back_populates="evidence_records",
    )
    analysis_job: Mapped[Optional["AnalysisJob"]] = relationship(
        "AnalysisJob",
        back_populates="detection_evidence",
    )

    __table_args__ = (
        CheckConstraint(
            "severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_detection_evidence_severity",
        ),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)",
            name="ck_detection_evidence_confidence",
        ),
        Index("ix_detection_evidence_incident_observed", "incident_id", "observed_at"),
        Index("ix_detection_evidence_analysis_job_id", "analysis_job_id"),
    )
