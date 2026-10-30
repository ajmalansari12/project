"""SQLAlchemy model for quarantine_records table."""

from typing import TYPE_CHECKING, Optional

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.incident import Incident
    from app.models.response_action import ResponseAction


class QuarantineRecord(Base):
    """Stores metadata tracking quarantined files and safe recovery parameters."""

    __tablename__ = "quarantine_records"

    quarantine_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"),
        nullable=False,
    )
    action_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("response_actions.action_id", ondelete="RESTRICT"),
        nullable=False,
    )
    original_path: Mapped[str] = mapped_column(Text, nullable=False)
    quarantine_path: Mapped[str] = mapped_column(Text, nullable=False)
    original_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    quarantined_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    encryption_algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce: Mapped[str] = mapped_column(Text, nullable=False)
    key_reference: Mapped[str] = mapped_column(String(256), nullable=False)
    original_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    restoration_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    quarantined_at: Mapped[str] = mapped_column(String(32), nullable=False)
    restored_at: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    incident: Mapped["Incident"] = relationship(
        "Incident",
        back_populates="quarantine_records",
    )
    response_action: Mapped["ResponseAction"] = relationship(
        "ResponseAction",
        back_populates="quarantine_records",
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING', 'QUARANTINED', 'RESTORING', 'RESTORED', 'FAILED', 'DELETED')",
            name="ck_quarantine_records_status",
        ),
        CheckConstraint(
            "original_size_bytes >= 0",
            name="ck_quarantine_records_size",
        ),
        CheckConstraint(
            "length(original_sha256) = 64 AND NOT (original_sha256 GLOB '*[^0-9a-fA-F]*')",
            name="ck_quarantine_records_orig_hash",
        ),
        CheckConstraint(
            "quarantined_sha256 IS NULL OR (length(quarantined_sha256) = 64 AND NOT (quarantined_sha256 GLOB '*[^0-9a-fA-F]*'))",
            name="ck_quarantine_records_quar_hash",
        ),
        Index("ix_quarantine_records_incident_id", "incident_id"),
        Index("ix_quarantine_records_status", "status"),
        UniqueConstraint("quarantine_path", name="uq_quarantine_records_path"),
    )
