"""enforce_lowercase_hash_constraint

Revision ID: 4d18ec32f901
Revises: b92d796755e7
Create Date: 2026-10-29 21:12:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect, text

from app.models.hash_reputation import HashReputation

# revision identifiers, used by Alembic.
revision: str = '4d18ec32f901'
down_revision: Union[str, None] = 'b92d796755e7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = inspect(conn)

    # 1. Inspect existing records in hash_reputations and normalize safely
    if "hash_reputations" in inspector.get_table_names():
        raw_rows = conn.execute(text("SELECT reputation_id, file_hash FROM hash_reputations")).mappings().all()
        seen_hashes = set()
        for row in raw_rows:
            raw_hash = row["file_hash"]
            norm_hash = raw_hash.strip().lower()
            if norm_hash in seen_hashes:
                raise ValueError(
                    f"Cannot apply canonical lowercase constraint: collision detected for '{norm_hash}'"
                )
            seen_hashes.add(norm_hash)
            if raw_hash != norm_hash:
                conn.execute(
                    text("UPDATE hash_reputations SET file_hash = :norm_hash WHERE reputation_id = :rep_id"),
                    {"norm_hash": norm_hash, "rep_id": row["reputation_id"]},
                )

    # 2. Recreate hash_reputations table with the new check constraint enforcing strictly lowercase 0-9a-f
    with op.batch_alter_table(
        "hash_reputations",
        schema=None,
        copy_from=HashReputation.__table__,
        recreate="always",
    ) as batch_op:
        pass


def downgrade() -> None:
    with op.batch_alter_table("hash_reputations", schema=None, recreate="always") as batch_op:
        batch_op.drop_constraint("ck_hash_reputations_ck_hash_reputations_file_hash", type_="check")
        batch_op.create_check_constraint(
            "ck_hash_reputations_ck_hash_reputations_file_hash",
            "length(file_hash) = 64 AND NOT (file_hash GLOB '*[^0-9a-fA-F]*')",
        )
