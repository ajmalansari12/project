"""add_hash_reputations_table

Revision ID: b92d796755e7
Revises: 693501eb898f
Create Date: 2026-10-29 20:55:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'b92d796755e7'
down_revision: Union[str, None] = '693501eb898f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'hash_reputations',
        sa.Column('reputation_id', sa.String(length=36), nullable=False),
        sa.Column('file_hash', sa.String(length=64), nullable=False),
        sa.Column('verdict', sa.String(length=32), nullable=False),
        sa.Column('list_type', sa.String(length=32), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('source', sa.String(length=128), server_default='local', nullable=False),
        sa.Column('metadata_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.String(length=32), nullable=False),
        sa.Column('updated_at', sa.String(length=32), nullable=False),
        sa.CheckConstraint(
            "verdict IN ('BENIGN', 'SUSPICIOUS', 'MALICIOUS')",
            name=op.f('ck_hash_reputations_ck_hash_reputations_verdict'),
        ),
        sa.CheckConstraint(
            "list_type IN ('ALLOWLIST', 'BLOCKLIST', 'CUSTOM')",
            name=op.f('ck_hash_reputations_ck_hash_reputations_list_type'),
        ),
        sa.CheckConstraint(
            "length(file_hash) = 64 AND NOT (file_hash GLOB '*[^0-9a-fA-F]*')",
            name=op.f('ck_hash_reputations_ck_hash_reputations_file_hash'),
        ),
        sa.PrimaryKeyConstraint('reputation_id', name=op.f('pk_hash_reputations')),
        sa.UniqueConstraint('file_hash', name=op.f('uq_hash_reputations_file_hash')),
    )
    with op.batch_alter_table('hash_reputations', schema=None) as batch_op:
        batch_op.create_index('ix_hash_reputations_file_hash', ['file_hash'], unique=False)
        batch_op.create_index('ix_hash_reputations_list_type', ['list_type'], unique=False)
        batch_op.create_index('ix_hash_reputations_verdict', ['verdict'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('hash_reputations', schema=None) as batch_op:
        batch_op.drop_index('ix_hash_reputations_verdict')
        batch_op.drop_index('ix_hash_reputations_list_type')
        batch_op.drop_index('ix_hash_reputations_file_hash')
    op.drop_table('hash_reputations')
