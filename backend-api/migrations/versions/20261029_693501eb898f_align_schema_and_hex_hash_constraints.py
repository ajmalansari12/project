"""align_schema_and_hex_hash_constraints

Revision ID: 693501eb898f
Revises: 30f0d232bc15
Create Date: 2026-10-29 19:25:00.000000

"""
import json
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect, text

from app.models import (
    AnalysisJob,
    AuditLog,
    EndpointEvent,
    Incident,
    QuarantineRecord,
)

# revision identifiers, used by Alembic.
revision: str = '693501eb898f'
down_revision: Union[str, None] = '30f0d232bc15'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = inspect(conn)

    # 1. Defensively migrate audit_logs if old column layout with incident_id/action_id is present
    audit_cols = {c["name"] for c in inspector.get_columns("audit_logs")}
    if "incident_id" in audit_cols or "action_id" in audit_cols or "entity_type" not in audit_cols:
        raw_rows = conn.execute(
            text("SELECT * FROM audit_logs")
        ).mappings().all()
        migrated_rows = []
        for row in raw_rows:
            inc_id = row.get("incident_id")
            act_id = row.get("action_id")
            entity_type = row.get("entity_type")
            entity_id = row.get("entity_id")

            # Canonical entity reference resolution
            if not entity_type and not entity_id:
                if inc_id:
                    entity_type = "incident"
                    entity_id = inc_id
                elif act_id:
                    entity_type = "response_action"
                    entity_id = act_id

            # Parse and merge details_json
            det_val = row.get("details_json")
            details = {}
            if det_val:
                try:
                    details = json.loads(det_val) if isinstance(det_val, str) else det_val
                except Exception:
                    details = {"raw_details": det_val}
            if inc_id and act_id:
                details["associated_action_id"] = act_id

            migrated_rows.append({
                "audit_id": row["audit_id"],
                "timestamp": row["timestamp"],
                "actor": row["actor"],
                "action": row["action"],
                "entity_type": entity_type,
                "entity_id": entity_id,
                "result": row.get("result") or "UNKNOWN",
                "details_json": json.dumps(details) if details else None,
                "correlation_id": row.get("correlation_id"),
            })

        op.drop_table("audit_logs")
        op.create_table(
            "audit_logs",
            sa.Column("audit_id", sa.String(length=36), nullable=False),
            sa.Column("timestamp", sa.String(length=32), nullable=False),
            sa.Column("actor", sa.String(length=128), nullable=False),
            sa.Column("action", sa.String(length=128), nullable=False),
            sa.Column("entity_type", sa.String(length=64), nullable=True),
            sa.Column("entity_id", sa.String(length=64), nullable=True),
            sa.Column("result", sa.String(length=32), nullable=False),
            sa.Column("details_json", sa.Text(), nullable=True),
            sa.Column("correlation_id", sa.String(length=64), nullable=True),
            sa.PrimaryKeyConstraint("audit_id", name=op.f("pk_audit_logs")),
        )
        with op.batch_alter_table("audit_logs", schema=None) as batch_op:
            batch_op.create_index("ix_audit_logs_timestamp", ["timestamp"], unique=False)
            batch_op.create_index("ix_audit_logs_entity", ["entity_type", "entity_id"], unique=False)
            batch_op.create_index("ix_audit_logs_correlation_id", ["correlation_id"], unique=False)

        if migrated_rows:
            conn.execute(
                text(
                    "INSERT INTO audit_logs (audit_id, timestamp, actor, action, entity_type, entity_id, result, details_json, correlation_id) "
                    "VALUES (:audit_id, :timestamp, :actor, :action, :entity_type, :entity_id, :result, :details_json, :correlation_id)"
                ),
                migrated_rows,
            )

    # 2. Update endpoint_events with hex-validated hash constraint using batch copy
    with op.batch_alter_table(
        "endpoint_events",
        schema=None,
        copy_from=EndpointEvent.__table__,
        recreate="always",
    ) as batch_op:
        pass

    # 3. Update analysis_jobs with hex-validated hash constraint using batch copy
    with op.batch_alter_table(
        "analysis_jobs",
        schema=None,
        copy_from=AnalysisJob.__table__,
        recreate="always",
    ) as batch_op:
        pass

    # 4. Update incidents with hex-validated hash constraint using batch copy
    with op.batch_alter_table(
        "incidents",
        schema=None,
        copy_from=Incident.__table__,
        recreate="always",
    ) as batch_op:
        pass

    # 5. Update quarantine_records with hex-validated hash constraints using batch copy
    with op.batch_alter_table(
        "quarantine_records",
        schema=None,
        copy_from=QuarantineRecord.__table__,
        recreate="always",
    ) as batch_op:
        pass


def downgrade() -> None:
    # On downgrade, batch recreate using previous constraint definitions
    conn = op.get_bind()
    with op.batch_alter_table("quarantine_records", schema=None, recreate="always") as batch_op:
        batch_op.drop_constraint("ck_quarantine_records_ck_quarantine_records_orig_hash", type_="check")
        batch_op.drop_constraint("ck_quarantine_records_ck_quarantine_records_quar_hash", type_="check")
        batch_op.create_check_constraint(
            "ck_quarantine_records_ck_quarantine_records_orig_hash",
            "length(original_sha256) = 64",
        )
        batch_op.create_check_constraint(
            "ck_quarantine_records_ck_quarantine_records_quar_hash",
            "quarantined_sha256 IS NULL OR length(quarantined_sha256) = 64",
        )

    with op.batch_alter_table("incidents", schema=None, recreate="always") as batch_op:
        batch_op.drop_constraint("ck_incidents_ck_incidents_hash", type_="check")
        batch_op.create_check_constraint(
            "ck_incidents_ck_incidents_hash",
            "file_hash IS NULL OR length(file_hash) = 64",
        )

    with op.batch_alter_table("analysis_jobs", schema=None, recreate="always") as batch_op:
        batch_op.drop_constraint("ck_analysis_jobs_ck_analysis_jobs_hash", type_="check")
        batch_op.create_check_constraint(
            "ck_analysis_jobs_ck_analysis_jobs_hash",
            "file_hash IS NULL OR length(file_hash) = 64",
        )

    with op.batch_alter_table("endpoint_events", schema=None, recreate="always") as batch_op:
        batch_op.drop_constraint("ck_endpoint_events_ck_endpoint_events_hash", type_="check")
        batch_op.create_check_constraint(
            "ck_endpoint_events_ck_endpoint_events_hash",
            "file_hash IS NULL OR length(file_hash) = 64",
        )
