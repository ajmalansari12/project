"""SQLAlchemy model for response_actions table."""

from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.incident import Incident
    from app.models.quarantine_record import QuarantineRecord


class ResponseAction(Base):
    """Stores actions requested or executed in response to a detected security incident."""

    __tablename__ = "response_actions"

    action_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"),
        nullable=False,
    )
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    details_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    requested_at: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    completed_at: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    incident: Mapped["Incident"] = relationship(
        "Incident",
        back_populates="response_actions",
    )
    quarantine_records: Mapped[List["QuarantineRecord"]] = relationship(
        "QuarantineRecord",
        back_populates="response_action",
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING', 'IN_PROGRESS', 'SUCCEEDED', 'FAILED', 'CANCELLED')",
            name="ck_response_actions_status",
        ),
        CheckConstraint(
            "mode IN ('DRY_RUN', 'ENFORCEMENT')",
            name="ck_response_actions_mode",
        ),
        Index("ix_response_actions_incident_requested", "incident_id", "requested_at"),
    )
