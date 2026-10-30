"""Automated tests for SQLAlchemy 2.x models, SQLite constraints, and database infrastructure."""

import json
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.base import Base
from app.db.session import create_database_engine, db_session_scope, get_session_factory
from app.models import (
    AnalysisJob,
    AuditLog,
    DetectionEvidence,
    EndpointEvent,
    ForensicReport,
    Incident,
    QuarantineRecord,
    ResponseAction,
)

EXPECTED_TABLES = {
    "endpoint_events",
    "analysis_jobs",
    "incidents",
    "detection_evidence",
    "response_actions",
    "quarantine_records",
    "forensic_reports",
    "audit_logs",
}

REQUIRED_INDEXES = {
    "endpoint_events": [
        ("timestamp",),
        ("event_type", "timestamp"),
        ("file_hash",),
    ],
    "analysis_jobs": [
        ("status", "queued_at"),
        ("source_event_id",),
        ("file_hash",),
    ],
    "incidents": [
        ("detected_at",),
        ("verdict", "detected_at"),
        ("status", "detected_at"),
        ("file_hash",),
    ],
    "detection_evidence": [
        ("incident_id", "observed_at"),
        ("analysis_job_id",),
    ],
    "response_actions": [
        ("incident_id", "requested_at"),
    ],
    "quarantine_records": [
        ("incident_id",),
        ("status",),
    ],
    "forensic_reports": [
        ("incident_id", "created_at"),
    ],
    "audit_logs": [
        ("timestamp",),
        ("entity_type", "entity_id"),
        ("correlation_id",),
    ],
}


@pytest.fixture
def memory_db_engine():
    """Create an isolated in-memory SQLite engine with foreign keys enabled."""
    engine = create_database_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(memory_db_engine):
    """Provide a transactional database session for tests."""
    factory = get_session_factory(memory_db_engine)
    session = factory()
    yield session
    session.close()


# ==============================================================================
# 1. Model & Schema Registration Tests
# ==============================================================================

def test_all_eight_tables_registered_in_metadata() -> None:
    """Verify that all eight tables are declared and registered with Base.metadata."""
    registered_tables = set(Base.metadata.tables.keys())
    assert EXPECTED_TABLES.issubset(registered_tables)
    assert "hash_reputations" in registered_tables


def test_schema_columns_and_nullability(memory_db_engine) -> None:
    """Verify column definitions and nullabilities across tables including audit_logs."""
    inspector = inspect(memory_db_engine)

    # endpoint_events
    cols = {c["name"]: c for c in inspector.get_columns("endpoint_events")}
    assert cols["event_id"]["nullable"] is False
    assert cols["event_type"]["nullable"] is False
    assert cols["file_path"]["nullable"] is True
    assert cols["file_hash"]["nullable"] is True

    # incidents
    inc_cols = {c["name"]: c for c in inspector.get_columns("incidents")}
    assert inc_cols["incident_id"]["nullable"] is False
    assert inc_cols["title"]["nullable"] is False
    assert inc_cols["verdict"]["nullable"] is False
    assert inc_cols["risk_score"]["nullable"] is False

    # audit_logs exact documented fields and nullabilities
    audit_cols = {c["name"]: c for c in inspector.get_columns("audit_logs")}
    expected_audit_fields = {
        "audit_id": False,
        "timestamp": False,
        "actor": False,
        "action": False,
        "entity_type": True,
        "entity_id": True,
        "result": False,
        "details_json": True,
        "correlation_id": True,
    }
    for field_name, expected_nullable in expected_audit_fields.items():
        assert field_name in audit_cols, f"Missing audit_logs column: {field_name}"
        assert audit_cols[field_name]["nullable"] is expected_nullable, (
            f"Expected {field_name} nullable={expected_nullable}, got {audit_cols[field_name]['nullable']}"
        )


def test_audit_logs_generic_entity_references_without_hardcoded_fks(db_session: Session) -> None:
    """Verify audit_logs can reference arbitrary entities without requiring specific foreign-key tables."""
    # 1. Audit log referencing an entity ID that does NOT exist in incidents or response_actions
    non_existent_entity_id = str(uuid4())
    audit1 = AuditLog(
        audit_id=str(uuid4()),
        timestamp="2026-10-29T12:00:00Z",
        actor="system_service",
        action="CONFIG_UPDATE",
        entity_type="system_config",
        entity_id=non_existent_entity_id,
        result="SUCCESS",
        details_json=json.dumps({"key": "alert_threshold", "old": 70, "new": 80}),
        correlation_id=str(uuid4()),
    )
    db_session.add(audit1)
    db_session.commit()

    queried1 = db_session.get(AuditLog, audit1.audit_id)
    assert queried1 is not None
    assert queried1.entity_type == "system_config"
    assert queried1.entity_id == non_existent_entity_id
    assert json.loads(queried1.details_json)["new"] == 80

    # 2. Audit log with NULL entity references
    audit2 = AuditLog(
        audit_id=str(uuid4()),
        timestamp="2026-10-29T12:01:00Z",
        actor="anonymous_service",
        action="HEARTBEAT",
        entity_type=None,
        entity_id=None,
        result="RECORDED",
        details_json=None,
        correlation_id=None,
    )
    db_session.add(audit2)
    db_session.commit()
    assert db_session.get(AuditLog, audit2.audit_id) is not None

    # 3. Omitting required 'result' must fail NOT NULL constraint
    audit_missing_result = AuditLog(
        audit_id=str(uuid4()),
        timestamp="2026-10-29T12:02:00Z",
        actor="analyst",
        action="LOGIN",
        result=None,  # type: ignore - invalid NOT NULL
    )
    db_session.add(audit_missing_result)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_all_required_indexes_match_specification(memory_db_engine) -> None:
    """Verify that every required index combination defined in database_schema.md exists."""
    inspector = inspect(memory_db_engine)
    for table_name, expected_indexes in REQUIRED_INDEXES.items():
        table_indexes = [tuple(ix["column_names"]) for ix in inspector.get_indexes(table_name)]
        for expected_cols in expected_indexes:
            assert expected_cols in table_indexes, (
                f"Missing required index on {table_name}: {expected_cols}. Available: {table_indexes}"
            )


# ==============================================================================
# 2. Connection & Foreign-Key Enforcement Tests
# ==============================================================================

def test_sqlite_foreign_key_enforcement_active(memory_db_engine) -> None:
    """Verify that PRAGMA foreign_keys = ON is active on SQLite connections."""
    with memory_db_engine.connect() as conn:
        result = conn.execute(text("PRAGMA foreign_keys;")).scalar()
        assert result == 1


def test_foreign_key_violation_rejected(db_session: Session) -> None:
    """Verify that inserting a child record referencing a non-existent parent fails."""
    orphan_job = AnalysisJob(
        job_id=str(uuid4()),
        source_event_id=str(uuid4()),  # Non-existent parent event
        status="QUEUED",
        modules_executed_json="[]",
        modules_skipped_json="[]",
        modules_failed_json="[]",
        queued_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    db_session.add(orphan_job)
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_parent_deletion_restricted(db_session: Session) -> None:
    """Verify that parent deletion is restricted when child records exist."""
    incident_id = str(uuid4())
    job_id = str(uuid4())
    evidence_id = str(uuid4())

    job = AnalysisJob(
        job_id=job_id,
        status="QUEUED",
        modules_executed_json="[]",
        modules_skipped_json="[]",
        modules_failed_json="[]",
        queued_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    incident = Incident(
        incident_id=incident_id,
        analysis_job_id=job_id,
        title="Restricted Test Incident",
        incident_type="malware_detection",
        verdict="SUSPICIOUS",
        risk_score=60.0,
        status="OPEN",
        detected_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    evidence = DetectionEvidence(
        evidence_id=evidence_id,
        incident_id=incident_id,
        analysis_job_id=job_id,
        source="yara",
        indicator="rule_test",
        severity="MEDIUM",
        description="Test evidence description",
        confidence=0.8,
        observed_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
    )
    db_session.add(job)
    db_session.add(incident)
    db_session.add(evidence)
    db_session.commit()

    # Attempt to delete parent incident with non-nullable child evidence
    db_session.delete(incident)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # Also test at raw SQL level to verify SQLite PRAGMA foreign_keys = ON rejects direct parent deletion
    event_id = str(uuid4())
    event = EndpointEvent(
        event_id=event_id,
        event_type="file_created",
        timestamp="2026-10-29T12:00:00Z",
        source_component="test",
        created_at="2026-10-29T12:00:00Z",
    )
    job2 = AnalysisJob(
        job_id=str(uuid4()),
        source_event_id=event_id,
        status="QUEUED",
        modules_executed_json="[]",
        modules_skipped_json="[]",
        modules_failed_json="[]",
        queued_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    db_session.add(event)
    db_session.add(job2)
    db_session.commit()

    with pytest.raises(IntegrityError):
        db_session.execute(text("DELETE FROM endpoint_events WHERE event_id = :id"), {"id": event_id})
        db_session.commit()


# ==============================================================================
# 3. Check Constraint Tests
# ==============================================================================

def test_valid_records_insertion_and_query(db_session: Session) -> None:
    """Verify insertion and querying across related records."""
    event_id = str(uuid4())
    job_id = str(uuid4())
    incident_id = str(uuid4())
    action_id = str(uuid4())

    event = EndpointEvent(
        event_id=event_id,
        event_type="file_modified",
        timestamp="2026-10-29T12:00:00Z",
        source_component="fs_monitor",
        created_at="2026-10-29T12:00:00Z",
    )
    job = AnalysisJob(
        job_id=job_id,
        source_event_id=event_id,
        status="COMPLETED",
        verdict="MALICIOUS",
        risk_score=90.0,
        modules_executed_json='["sha256", "yara"]',
        modules_skipped_json="[]",
        modules_failed_json="[]",
        queued_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    incident = Incident(
        incident_id=incident_id,
        analysis_job_id=job_id,
        title="Detected Ransomware Activity",
        incident_type="malware_detection",
        verdict="MALICIOUS",
        risk_score=90.0,
        status="OPEN",
        detected_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    evidence = DetectionEvidence(
        evidence_id=str(uuid4()),
        incident_id=incident_id,
        analysis_job_id=job_id,
        source="yara",
        indicator="rule_ransomware",
        severity="HIGH",
        description="Matched ransomware signature",
        confidence=0.95,
        observed_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
    )
    action = ResponseAction(
        action_id=action_id,
        incident_id=incident_id,
        action_type="QUARANTINE",
        status="SUCCEEDED",
        mode="ENFORCEMENT",
        requested_by="analyst_1",
        requested_at="2026-10-29T12:01:00Z",
    )
    quarantine = QuarantineRecord(
        quarantine_id=str(uuid4()),
        incident_id=incident_id,
        action_id=action_id,
        original_path="C:\\sample.exe",
        quarantine_path="C:\\quarantine\\sample.enc",
        original_sha256="a" * 64,
        encryption_algorithm="AES-256-GCM",
        nonce="nonce_123",
        key_reference="key_v1",
        original_size_bytes=1024,
        status="QUARANTINED",
        quarantined_at="2026-10-29T12:01:05Z",
        created_at="2026-10-29T12:01:05Z",
        updated_at="2026-10-29T12:01:05Z",
    )
    report = ForensicReport(
        report_id=str(uuid4()),
        incident_id=incident_id,
        provider="local_ai",
        status="COMPLETED",
        summary="Analysis confirms ransomware pattern.",
        evidence_references_json="[]",
        created_at="2026-10-29T12:02:00Z",
        updated_at="2026-10-29T12:02:00Z",
    )
    audit = AuditLog(
        audit_id=str(uuid4()),
        timestamp="2026-10-29T12:01:00Z",
        actor="analyst_1",
        action="QUARANTINE_REQUESTED",
        entity_type="incident",
        entity_id=incident_id,
        result="SUCCESS",
    )

    db_session.add_all([event, job, incident, evidence, action, quarantine, report, audit])
    db_session.commit()

    # Query back
    queried_inc = db_session.scalar(select(Incident).where(Incident.incident_id == incident_id))
    assert queried_inc is not None
    assert queried_inc.title == "Detected Ransomware Activity"
    assert len(queried_inc.evidence_records) == 1
    assert len(queried_inc.quarantine_records) == 1


def test_constraint_invalid_risk_score(db_session: Session) -> None:
    """Verify that risk scores > 100 or < 0 are rejected by database check constraints."""
    incident = Incident(
        incident_id=str(uuid4()),
        title="Invalid Score",
        incident_type="test",
        verdict="BENIGN",
        risk_score=150.0,  # Invalid
        status="OPEN",
        detected_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    db_session.add(incident)
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_constraint_invalid_confidence(db_session: Session) -> None:
    """Verify that confidence outside 0.0-1.0 is rejected by check constraints."""
    inc_id = str(uuid4())
    incident = Incident(
        incident_id=inc_id,
        title="Valid Incident",
        incident_type="test",
        verdict="BENIGN",
        risk_score=10.0,
        status="OPEN",
        detected_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    db_session.add(incident)
    db_session.commit()

    evidence = DetectionEvidence(
        evidence_id=str(uuid4()),
        incident_id=inc_id,
        source="test",
        indicator="test",
        severity="LOW",
        description="test",
        confidence=1.5,  # Invalid
        observed_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
    )
    db_session.add(evidence)
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_constraint_negative_file_size(db_session: Session) -> None:
    """Verify that negative file size in quarantine records is rejected."""
    inc_id = str(uuid4())
    act_id = str(uuid4())

    incident = Incident(
        incident_id=inc_id,
        title="Test",
        incident_type="test",
        verdict="BENIGN",
        risk_score=10.0,
        status="OPEN",
        detected_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    action = ResponseAction(
        action_id=act_id,
        incident_id=inc_id,
        action_type="QUARANTINE",
        status="PENDING",
        mode="DRY_RUN",
        requested_by="user",
        requested_at="2026-10-29T12:00:00Z",
    )
    quarantine = QuarantineRecord(
        quarantine_id=str(uuid4()),
        incident_id=inc_id,
        action_id=act_id,
        original_path="C:\\sample.exe",
        quarantine_path="C:\\quar\\sample.enc",
        original_sha256="b" * 64,
        encryption_algorithm="AES-256-GCM",
        nonce="nonce",
        key_reference="ref",
        original_size_bytes=-100,  # Invalid
        status="PENDING",
        quarantined_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    db_session.add_all([incident, action, quarantine])
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_constraint_duplicate_quarantine_path(db_session: Session) -> None:
    """Verify that unique constraint on quarantine_path is enforced."""
    inc_id = str(uuid4())
    act_id = str(uuid4())

    incident = Incident(
        incident_id=inc_id,
        title="Test",
        incident_type="test",
        verdict="BENIGN",
        risk_score=10.0,
        status="OPEN",
        detected_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    action = ResponseAction(
        action_id=act_id,
        incident_id=inc_id,
        action_type="QUARANTINE",
        status="PENDING",
        mode="DRY_RUN",
        requested_by="user",
        requested_at="2026-10-29T12:00:00Z",
    )
    q1 = QuarantineRecord(
        quarantine_id=str(uuid4()),
        incident_id=inc_id,
        action_id=act_id,
        original_path="C:\\file1.exe",
        quarantine_path="C:\\quar\\duplicate.enc",
        original_sha256="c" * 64,
        encryption_algorithm="AES-256-GCM",
        nonce="nonce1",
        key_reference="ref1",
        original_size_bytes=500,
        status="QUARANTINED",
        quarantined_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    q2 = QuarantineRecord(
        quarantine_id=str(uuid4()),
        incident_id=inc_id,
        action_id=act_id,
        original_path="C:\\file2.exe",
        quarantine_path="C:\\quar\\duplicate.enc",  # Duplicate path
        original_sha256="d" * 64,
        encryption_algorithm="AES-256-GCM",
        nonce="nonce2",
        key_reference="ref2",
        original_size_bytes=600,
        status="QUARANTINED",
        quarantined_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    db_session.add_all([incident, action, q1])
    db_session.commit()

    db_session.add(q2)
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_constraint_invalid_hash_length(db_session: Session) -> None:
    """Verify that non-64 length SHA-256 strings violate check constraints."""
    event = EndpointEvent(
        event_id=str(uuid4()),
        event_type="file_created",
        timestamp="2026-10-29T12:00:00Z",
        source_component="sensor",
        file_hash="too_short",
        created_at="2026-10-29T12:00:00Z",
    )
    db_session.add(event)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    event_long = EndpointEvent(
        event_id=str(uuid4()),
        event_type="file_created",
        timestamp="2026-10-29T12:00:00Z",
        source_component="sensor",
        file_hash="a" * 65,
        created_at="2026-10-29T12:00:00Z",
    )
    db_session.add(event_long)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_sha256_hex_validation_rejects_non_hex_characters(db_session: Session) -> None:
    """Verify that 64-character strings with invalid hexadecimal characters fail check constraints."""
    invalid_hex = "0" * 63 + "g"
    whitespace_hex = " " + "0" * 63

    # 1. endpoint_events.file_hash
    event = EndpointEvent(
        event_id=str(uuid4()),
        event_type="file_created",
        timestamp="2026-10-29T12:00:00Z",
        source_component="sensor",
        file_hash=invalid_hex,
        created_at="2026-10-29T12:00:00Z",
    )
    db_session.add(event)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # 2. analysis_jobs.file_hash
    job = AnalysisJob(
        job_id=str(uuid4()),
        status="QUEUED",
        file_hash=whitespace_hex,
        modules_executed_json="[]",
        modules_skipped_json="[]",
        modules_failed_json="[]",
        queued_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    db_session.add(job)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # 3. incidents.file_hash
    inc = Incident(
        incident_id=str(uuid4()),
        title="Invalid Hash Incident",
        incident_type="malware",
        verdict="MALICIOUS",
        risk_score=90.0,
        status="OPEN",
        file_hash=invalid_hex,
        detected_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    db_session.add(inc)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # 4. quarantine_records.original_sha256 (required)
    inc_id = str(uuid4())
    act_id = str(uuid4())
    inc_parent = Incident(
        incident_id=inc_id,
        title="Parent Incident",
        incident_type="malware",
        verdict="MALICIOUS",
        risk_score=85.0,
        status="OPEN",
        detected_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    act_parent = ResponseAction(
        action_id=act_id,
        incident_id=inc_id,
        action_type="QUARANTINE",
        status="SUCCEEDED",
        mode="ENFORCEMENT",
        requested_by="analyst",
        requested_at="2026-10-29T12:00:00Z",
    )
    q_invalid_orig = QuarantineRecord(
        quarantine_id=str(uuid4()),
        incident_id=inc_id,
        action_id=act_id,
        original_path="C:\\test.exe",
        quarantine_path="C:\\quar\\1.enc",
        original_sha256=invalid_hex,
        encryption_algorithm="AES-256-GCM",
        nonce="nonce",
        key_reference="ref",
        original_size_bytes=100,
        status="QUARANTINED",
        quarantined_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    db_session.add_all([inc_parent, act_parent, q_invalid_orig])
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # 5. quarantine_records.quarantined_sha256 (optional)
    q_invalid_quar = QuarantineRecord(
        quarantine_id=str(uuid4()),
        incident_id=inc_id,
        action_id=act_id,
        original_path="C:\\test.exe",
        quarantine_path="C:\\quar\\2.enc",
        original_sha256="a" * 64,
        quarantined_sha256=invalid_hex,
        encryption_algorithm="AES-256-GCM",
        nonce="nonce",
        key_reference="ref",
        original_size_bytes=100,
        status="QUARANTINED",
        quarantined_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    db_session.add_all([inc_parent, act_parent, q_invalid_quar])
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_sha256_optional_null_and_valid_hex_accepted(db_session: Session) -> None:
    """Verify that NULL and valid uppercase/lowercase SHA-256 hashes are accepted."""
    valid_lower = "0123456789abcdef" * 4
    valid_upper = "0123456789ABCDEF" * 4

    ev_lower = EndpointEvent(
        event_id=str(uuid4()),
        event_type="file_created",
        timestamp="2026-10-29T12:00:00Z",
        source_component="sensor",
        file_hash=valid_lower,
        created_at="2026-10-29T12:00:00Z",
    )
    ev_upper = EndpointEvent(
        event_id=str(uuid4()),
        event_type="file_created",
        timestamp="2026-10-29T12:01:00Z",
        source_component="sensor",
        file_hash=valid_upper,
        created_at="2026-10-29T12:01:00Z",
    )
    ev_null = EndpointEvent(
        event_id=str(uuid4()),
        event_type="file_created",
        timestamp="2026-10-29T12:02:00Z",
        source_component="sensor",
        file_hash=None,
        created_at="2026-10-29T12:02:00Z",
    )
    db_session.add_all([ev_lower, ev_upper, ev_null])
    db_session.commit()

    assert db_session.get(EndpointEvent, ev_lower.event_id).file_hash == valid_lower
    assert db_session.get(EndpointEvent, ev_upper.event_id).file_hash == valid_upper
    assert db_session.get(EndpointEvent, ev_null.event_id).file_hash is None


def test_extensible_fields_accept_unrestricted_values(db_session: Session) -> None:
    """Verify that source, provider, and incident_type accept arbitrary extensible strings."""
    inc_id = str(uuid4())
    job_id = str(uuid4())

    job = AnalysisJob(
        job_id=job_id,
        status="COMPLETED",
        verdict="MALICIOUS",
        risk_score=95.0,
        modules_executed_json="[]",
        modules_skipped_json="[]",
        modules_failed_json="[]",
        queued_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    inc = Incident(
        incident_id=inc_id,
        analysis_job_id=job_id,
        title="Novel Finding",
        incident_type="custom_supply_chain_attack",
        verdict="MALICIOUS",
        risk_score=95.0,
        status="OPEN",
        detected_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    evidence = DetectionEvidence(
        evidence_id=str(uuid4()),
        incident_id=inc_id,
        analysis_job_id=job_id,
        source="experimental_quantum_detector",
        indicator="rule_quantum_anomaly",
        severity="HIGH",
        description="Detected novel attack vector",
        observed_at="2026-10-29T12:00:00Z",
        created_at="2026-10-29T12:00:00Z",
    )
    report = ForensicReport(
        report_id=str(uuid4()),
        incident_id=inc_id,
        provider="custom_onprem_neural_llm",
        status="COMPLETED",
        summary="Novel explanation",
        evidence_references_json="[]",
        created_at="2026-10-29T12:00:00Z",
        updated_at="2026-10-29T12:00:00Z",
    )
    db_session.add_all([job, inc, evidence, report])
    db_session.commit()

    assert db_session.get(Incident, inc_id).incident_type == "custom_supply_chain_attack"
    assert db_session.get(DetectionEvidence, evidence.evidence_id).source == "experimental_quantum_detector"
    assert db_session.get(ForensicReport, report.report_id).provider == "custom_onprem_neural_llm"


# ==============================================================================
# 4. Connection, Scope & Configuration Tests
# ==============================================================================

def test_db_session_scope_lifecycle(memory_db_engine) -> None:
    """Verify db_session_scope context manager commits and closes cleanly."""
    factory = get_session_factory(memory_db_engine)
    event_id = str(uuid4())

    with db_session_scope(factory) as session:
        event = EndpointEvent(
            event_id=event_id,
            event_type="file_created",
            timestamp="2026-10-29T12:00:00Z",
            source_component="sensor",
            created_at="2026-10-29T12:00:00Z",
        )
        session.add(event)

    # Query in new session to verify commit
    with db_session_scope(factory) as session:
        queried = session.scalar(select(EndpointEvent).where(EndpointEvent.event_id == event_id))
        assert queried is not None


def test_default_database_url_not_machine_specific() -> None:
    """Verify that default database URL uses project-relative path without machine paths."""
    settings = Settings()
    assert "D:\\" not in settings.database_url
    assert "C:\\" not in settings.database_url
    assert "Ajmal" not in settings.database_url
    assert settings.database_url == "sqlite:///.data/sentinel_edr.db"


def test_alembic_migration_execution() -> None:
    """Verify that Alembic migrations run cleanly against an isolated fresh temporary database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
        tmp_path = Path(tmp_file.name)

    engine = None
    try:
        tmp_url = f"sqlite:///{tmp_path.as_posix()}"
        backend_api_dir = Path(__file__).resolve().parent.parent.parent / "backend-api"
        alembic_ini_path = backend_api_dir / "alembic.ini"

        alembic_cfg = Config(str(alembic_ini_path))
        alembic_cfg.set_main_option("sqlalchemy.url", tmp_url)
        alembic_cfg.set_main_option("script_location", str(backend_api_dir / "migrations"))

        # Run migration upgrade head
        command.upgrade(alembic_cfg, "head")

        # Inspect resulting tables
        engine = create_database_engine(tmp_url)
        inspector = inspect(engine)
        created_tables = set(inspector.get_table_names())
        assert EXPECTED_TABLES.issubset(created_tables)
        assert "alembic_version" in created_tables
    finally:
        if engine is not None:
            engine.dispose()
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except PermissionError:
                pass


def test_corrective_migration_preserves_records_and_updates_schema() -> None:
    """Verify that upgrading from initial 30f0d232bc15 to head preserves data and applies hex checks."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
        tmp_path = Path(tmp_file.name)

    engine = None
    try:
        tmp_url = f"sqlite:///{tmp_path.as_posix()}"
        backend_api_dir = Path(__file__).resolve().parent.parent.parent / "backend-api"
        alembic_ini_path = backend_api_dir / "alembic.ini"

        alembic_cfg = Config(str(alembic_ini_path))
        alembic_cfg.set_main_option("sqlalchemy.url", tmp_url)
        alembic_cfg.set_main_option("script_location", str(backend_api_dir / "migrations"))

        # Step 1: Upgrade to initial revision 30f0d232bc15
        command.upgrade(alembic_cfg, "30f0d232bc15")

        # Step 2: Insert initial records
        engine = create_database_engine(tmp_url)
        ev_id = str(uuid4())
        audit_id = str(uuid4())
        valid_hash = "a" * 64

        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO endpoint_events (event_id, event_type, timestamp, source_component, file_hash, created_at) "
                    "VALUES (:id, 'file_created', '2026-10-29T12:00:00Z', 'sensor', :hash, '2026-10-29T12:00:00Z')"
                ),
                {"id": ev_id, "hash": valid_hash},
            )
            conn.execute(
                text(
                    "INSERT INTO audit_logs (audit_id, timestamp, actor, action, entity_type, entity_id, result, details_json, correlation_id) "
                    "VALUES (:id, '2026-10-29T12:00:00Z', 'admin', 'POLICY_APPLY', 'policy', 'p1', 'SUCCESS', '{\"rule\": 1}', 'c1')"
                ),
                {"id": audit_id},
            )
        engine.dispose()

        # Step 3: Upgrade to head (693501eb898f)
        command.upgrade(alembic_cfg, "head")

        # Step 4: Verify pre-existing data preserved
        engine = create_database_engine(tmp_url)
        with engine.connect() as conn:
            ev_row = conn.execute(
                text("SELECT event_id, file_hash FROM endpoint_events WHERE event_id = :id"),
                {"id": ev_id},
            ).fetchone()
            assert ev_row is not None
            assert ev_row[0] == ev_id
            assert ev_row[1] == valid_hash

            audit_row = conn.execute(
                text("SELECT audit_id, action, result FROM audit_logs WHERE audit_id = :id"),
                {"id": audit_id},
            ).fetchone()
            assert audit_row is not None
            assert audit_row[0] == audit_id
            assert audit_row[2] == "SUCCESS"

            # Step 5: Verify new hex constraint rejects invalid hex hash
            with pytest.raises(IntegrityError):
                conn.execute(
                    text(
                        "INSERT INTO endpoint_events (event_id, event_type, timestamp, source_component, file_hash, created_at) "
                        "VALUES (:id, 'file_created', '2026-10-29T12:00:00Z', 'sensor', :hash, '2026-10-29T12:00:00Z')"
                    ),
                    {"id": str(uuid4()), "hash": "0" * 63 + "g"},
                )
    finally:
        if engine is not None:
            engine.dispose()
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except PermissionError:
                pass


def test_hash_reputations_migration_preserves_records_and_enforces_canonical_lowercase() -> None:
    """Verify that migration 4d18ec32f901 preserves hash_reputations data and enforces strictly lowercase 0-9a-f."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
        tmp_path = Path(tmp_file.name)

    engine = None
    try:
        tmp_url = f"sqlite:///{tmp_path.as_posix()}"
        backend_api_dir = Path(__file__).resolve().parent.parent.parent / "backend-api"
        alembic_ini_path = backend_api_dir / "alembic.ini"

        alembic_cfg = Config(str(alembic_ini_path))
        alembic_cfg.set_main_option("sqlalchemy.url", tmp_url)
        alembic_cfg.set_main_option("script_location", str(backend_api_dir / "migrations"))

        # Step 1: Upgrade to b92d796755e7 (where hash_reputations was initially added)
        command.upgrade(alembic_cfg, "b92d796755e7")

        # Step 2: Insert initial records
        engine = create_database_engine(tmp_url)
        rep_id = str(uuid4())
        initial_hash = "abcdef" + "0" * 58
        now = "2026-10-29T12:00:00Z"

        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO hash_reputations (reputation_id, file_hash, verdict, list_type, description, source, created_at, updated_at) "
                    "VALUES (:id, :file_hash, 'MALICIOUS', 'BLOCKLIST', 'Known threat', 'local_intel', :now, :now)"
                ),
                {"id": rep_id, "file_hash": initial_hash, "now": now},
            )
        engine.dispose()

        # Step 3: Upgrade to head (4d18ec32f901)
        command.upgrade(alembic_cfg, "head")

        # Step 4: Verify pre-existing data preserved
        engine = create_database_engine(tmp_url)
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT reputation_id, file_hash, verdict, list_type, description FROM hash_reputations WHERE reputation_id = :id"),
                {"id": rep_id},
            ).fetchone()
            assert row is not None
            assert row[0] == rep_id
            assert row[1] == initial_hash
            assert row[2] == "MALICIOUS"
            assert row[3] == "BLOCKLIST"
            assert row[4] == "Known threat"

            # Step 5: Verify new constraint rejects direct insert of uppercase hexadecimal characters
            with pytest.raises(IntegrityError):
                conn.execute(
                    text(
                        "INSERT INTO hash_reputations (reputation_id, file_hash, verdict, list_type, source, created_at, updated_at) "
                        "VALUES (:id, :file_hash, 'BENIGN', 'ALLOWLIST', 'test', :now, :now)"
                    ),
                    {"id": str(uuid4()), "file_hash": "A" * 64, "now": now},
                )

            # Step 6: Verify direct insert of valid lowercase hex characters succeeds
            new_id = str(uuid4())
            conn.execute(
                text(
                    "INSERT INTO hash_reputations (reputation_id, file_hash, verdict, list_type, source, created_at, updated_at) "
                    "VALUES (:id, :file_hash, 'BENIGN', 'ALLOWLIST', 'test', :now, :now)"
                ),
                {"id": new_id, "file_hash": "1" * 64, "now": now},
            )
            inserted = conn.execute(
                text("SELECT reputation_id FROM hash_reputations WHERE reputation_id = :id"),
                {"id": new_id},
            ).scalar_one()
            assert inserted == new_id
    finally:
        if engine is not None:
            engine.dispose()
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except PermissionError:
                pass
