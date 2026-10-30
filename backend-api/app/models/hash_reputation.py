"""SQLAlchemy model for hash_reputations table."""

from typing import Optional

from sqlalchemy import CheckConstraint, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class HashReputation(Base):
    """Stores known file hashes for allowlists, blocklists, and custom reputation classifications."""

    __tablename__ = "hash_reputations"

    reputation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    file_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    list_type: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(128), nullable=False, default="local")
    metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "verdict IN ('BENIGN', 'SUSPICIOUS', 'MALICIOUS')",
            name="ck_hash_reputations_verdict",
        ),
        CheckConstraint(
            "list_type IN ('ALLOWLIST', 'BLOCKLIST', 'CUSTOM')",
            name="ck_hash_reputations_list_type",
        ),
        CheckConstraint(
            "length(file_hash) = 64 AND NOT (file_hash GLOB '*[^0-9a-f]*')",
            name="ck_hash_reputations_file_hash",
        ),
        UniqueConstraint("file_hash", name="uq_hash_reputations_file_hash"),
        Index("ix_hash_reputations_file_hash", "file_hash"),
        Index("ix_hash_reputations_list_type", "list_type"),
        Index("ix_hash_reputations_verdict", "verdict"),
    )
