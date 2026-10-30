"""SQLAlchemy model for forensic_reports table."""

from typing import TYPE_CHECKING, Optional

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.incident import Incident


class ForensicReport(Base):
    """Stores AI-generated and heuristic forensic explanations for incidents."""

    __tablename__ = "forensic_reports"

    report_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"),
        nullable=False,
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    model_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    findings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommendations: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    technique_mappings_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_references_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    generated_at: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    incident: Mapped["Incident"] = relationship(
        "Incident",
        back_populates="forensic_reports",
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING', 'GENERATING', 'COMPLETED', 'FAILED', 'UNAVAILABLE')",
            name="ck_forensic_reports_status",
        ),
        Index("ix_forensic_reports_incident_created", "incident_id", "created_at"),
    )
