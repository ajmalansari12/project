"""Automated unit and integration tests for Sentinel-EDR persistence service layer."""

import json
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

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
from app.schemas.contracts import (
    AnalysisJobStatus,
    DetectionSeverity,
    EndpointEvent as EndpointEventContract,
    EndpointEventType,
    IncidentStatus,
    ResponseActionStatus,
    SecurityVerdict,
)
from app.services import (
    InvalidStateTransitionError,
    PersistenceConflictError,
    PersistenceError,
    ResourceNotFoundError,
    ValidationError,
    append_audit_log,
    create_analysis_job,
    create_detection_evidence,
    create_endpoint_event,
    create_forensic_report,
    create_incident,
    create_quarantine_record,
    create_response_action,
    get_analysis_job,
    get_analysis_job_or_raise,
    get_audit_log,
    get_audit_log_or_raise,
    get_detection_evidence,
    get_detection_evidence_or_raise,
    get_endpoint_event,
    get_endpoint_event_or_raise,
    get_forensic_report,
    get_forensic_report_or_raise,
    get_incident,
    get_incident_or_raise,
    get_quarantine_record,
    get_quarantine_record_or_raise,
    get_response_action,
    get_response_action_or_raise,
    list_analysis_jobs,
    list_audit_logs,
    list_endpoint_events,
    list_evidence_for_incident,
    list_evidence_for_job,
    list_incidents,
    list_quarantine_records,
    list_reports_for_incident,
    list_response_actions_for_incident,
    record_analysis_job_result,
    update_analysis_job_status,
    update_forensic_report_status,
    update_incident_status,
    update_quarantine_status,
    update_response_action_status,
)


@pytest.fixture
def db_engine():
    """Create isolated in-memory SQLite database with foreign keys enabled."""
    engine = create_database_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def session(db_engine):
    """Provide a database session for tests."""
    factory = get_session_factory(db_engine)
    with factory() as sess:
        yield sess


# ==============================================================================
# 1. Basic Persistence Tests (All 8 Entities)
# ==============================================================================

def test_endpoint_event_persistence_contract_and_kwargs(session: Session) -> None:
    """Verify endpoint events can be created via contract or kwargs and retrieved."""
    # Via contract
    contract = EndpointEventContract(
        event_id=uuid4(),
        event_type=EndpointEventType.FILE_CREATED,
        timestamp="2026-10-29T12:00:00Z",
        source_component="fs_monitor",
        file_path="C:\\test\\malware.exe",
        file_hash="0123456789abcdef" * 4,
        process_id=1234,
        parent_process_id=5678,
        metadata={"entropy": 7.92},
    )
    event1 = create_endpoint_event(session, contract)
    session.commit()

    queried1 = get_endpoint_event_or_raise(session, str(contract.event_id))
    assert queried1.event_type == "file_created"
    assert queried1.source_component == "fs_monitor"
    assert queried1.file_hash == "0123456789abcdef" * 4
    assert json.loads(queried1.metadata_json)["entropy"] == 7.92

    # Via kwargs
    event2 = create_endpoint_event(
        session,
        event_type="process_observed",
        source_component="proc_watcher",
        process_id=9999,
    )
    session.commit()

    queried2 = get_endpoint_event_or_raise(session, event2.event_id)
    assert queried2.event_type == "process_observed"
    assert queried2.process_id == 9999


def test_analysis_job_persistence(session: Session) -> None:
    """Verify analysis jobs can be created, updated, and retrieved."""
    job = create_analysis_job(
        session,
        file_path="C:\\sample.dll",
        file_hash="a" * 64,
    )
    session.commit()

    queried = get_analysis_job_or_raise(session, job.job_id)
    assert queried.status == "QUEUED"
    assert queried.file_path == "C:\\sample.dll"
    assert queried.file_hash == "a" * 64

    # Update status to IN_PROGRESS
    update_analysis_job_status(session, job.job_id, "IN_PROGRESS")
    session.commit()
    assert get_analysis_job(session, job.job_id).status == "IN_PROGRESS"
    assert get_analysis_job(session, job.job_id).started_at is not None

    # Record evaluation results and complete
    record_analysis_job_result(
        session,
        job.job_id,
        verdict="MALICIOUS",
        risk_score=88.5,
        modules_executed=["sha256", "yara", "ml_pe"],
        modules_skipped=["canary"],
        modules_failed=[],
    )
    update_analysis_job_status(session, job.job_id, "COMPLETED")
    session.commit()

    completed = get_analysis_job_or_raise(session, job.job_id)
    assert completed.status == "COMPLETED"
    assert completed.verdict == "MALICIOUS"
    assert completed.risk_score == 88.5
    assert json.loads(completed.modules_executed_json) == ["sha256", "yara", "ml_pe"]


def test_incident_persistence(session: Session) -> None:
    """Verify security incidents can be created and updated."""
    inc = create_incident(
        session,
        title="Detected Ransomware Behavior",
        incident_type="ransomware_infection",
        verdict="MALICIOUS",
        risk_score=92.0,
        file_path="C:\\ransomware.exe",
        file_hash="b" * 64,
    )
    session.commit()

    queried = get_incident_or_raise(session, inc.incident_id)
    assert queried.title == "Detected Ransomware Behavior"
    assert queried.verdict == "MALICIOUS"
    assert queried.status == "OPEN"
    assert queried.resolved_at is None

    # Update status to RESOLVED
    update_incident_status(session, inc.incident_id, "RESOLVED")
    session.commit()

    resolved = get_incident_or_raise(session, inc.incident_id)
    assert resolved.status == "RESOLVED"
    assert resolved.resolved_at is not None


def test_detection_evidence_persistence(session: Session) -> None:
    """Verify evidence can be persisted and retrieved for an incident."""
    inc = create_incident(
        session,
        title="Test Incident",
        incident_type="malware",
        verdict="MALICIOUS",
        risk_score=80.0,
    )
    session.commit()

    ev = create_detection_evidence(
        session,
        incident_id=inc.incident_id,
        source="yara",
        indicator="rule_ransomware_strings",
        severity="HIGH",
        description="Matched known ransomware byte sequences.",
        confidence=0.95,
        score_contribution=40.0,
        details={"matched_strings": ["$v1", "$v2"]},
    )
    session.commit()

    queried = get_detection_evidence_or_raise(session, ev.evidence_id)
    assert queried.incident_id == inc.incident_id
    assert queried.source == "yara"
    assert queried.confidence == 0.95
    assert json.loads(queried.details_json)["matched_strings"] == ["$v1", "$v2"]


def test_response_action_persistence(session: Session) -> None:
    """Verify response action metadata creation and status updates."""
    inc = create_incident(
        session,
        title="Test Action Incident",
        incident_type="malware",
        verdict="SUSPICIOUS",
        risk_score=65.0,
    )
    session.commit()

    action = create_response_action(
        session,
        incident_id=inc.incident_id,
        action_type="QUARANTINE",
        requested_by="soc_analyst_1",
        mode="ENFORCEMENT",
        details={"target_path": "C:\\infected.exe"},
    )
    session.commit()

    queried = get_response_action_or_raise(session, action.action_id)
    assert queried.status == "PENDING"
    assert queried.mode == "ENFORCEMENT"
    assert queried.started_at is None

    # Transition PENDING -> IN_PROGRESS -> SUCCEEDED
    update_response_action_status(session, action.action_id, "IN_PROGRESS")
    session.commit()
    assert get_response_action(session, action.action_id).started_at is not None

    update_response_action_status(session, action.action_id, "SUCCEEDED")
    session.commit()
    assert get_response_action(session, action.action_id).completed_at is not None


def test_quarantine_metadata_persistence(session: Session) -> None:
    """Verify quarantine metadata persistence without performing filesystem operations."""
    inc = create_incident(
        session,
        title="Quarantine Test",
        incident_type="malware",
        verdict="MALICIOUS",
        risk_score=90.0,
    )
    action = create_response_action(
        session,
        incident_id=inc.incident_id,
        action_type="QUARANTINE",
        requested_by="system",
        mode="ENFORCEMENT",
    )
    session.commit()

    quar = create_quarantine_record(
        session,
        incident_id=inc.incident_id,
        action_id=action.action_id,
        original_path="C:\\Users\\User\\malware.exe",
        quarantine_path="C:\\Quarantine\\vault\\sample.enc",
        original_sha256="c" * 64,
        encryption_algorithm="AES-256-GCM",
        nonce="nonce_abc123",
        key_reference="key_store_v1_ref",
        original_size_bytes=2048,
        status="QUARANTINED",
    )
    session.commit()

    queried = get_quarantine_record_or_raise(session, quar.quarantine_id)
    assert queried.original_sha256 == "c" * 64
    assert queried.status == "QUARANTINED"
    assert queried.restoration_path is None

    # Transition to RESTORING -> RESTORED
    update_quarantine_status(session, quar.quarantine_id, "RESTORING")
    session.commit()
    assert get_quarantine_record(session, quar.quarantine_id).status == "RESTORING"

    update_quarantine_status(
        session,
        quar.quarantine_id,
        "RESTORED",
        restoration_path="C:\\Restored\\malware.exe",
    )
    session.commit()

    restored = get_quarantine_record_or_raise(session, quar.quarantine_id)
    assert restored.status == "RESTORED"
    assert restored.restoration_path == "C:\\Restored\\malware.exe"
    assert restored.restored_at is not None


def test_forensic_report_persistence(session: Session) -> None:
    """Verify AI forensic explanation report persistence."""
    inc = create_incident(
        session,
        title="Forensic Test",
        incident_type="apt",
        verdict="MALICIOUS",
        risk_score=95.0,
    )
    session.commit()

    report = create_forensic_report(
        session,
        incident_id=inc.incident_id,
        provider="local_heuristic_explainer",
        model_name="rule_explainer_v1",
        status="PENDING",
        evidence_references=["ev-1", "ev-2"],
    )
    session.commit()

    queried = get_forensic_report_or_raise(session, report.report_id)
    assert queried.status == "PENDING"
    assert json.loads(queried.evidence_references_json) == ["ev-1", "ev-2"]

    # Transition PENDING -> GENERATING -> COMPLETED
    update_forensic_report_status(session, report.report_id, "GENERATING")
    session.commit()

    update_forensic_report_status(
        session,
        report.report_id,
        "COMPLETED",
        summary="Analysis confirms ransomware activity.",
        findings="High entropy encrypted files observed.",
        recommendations="Isolate host from local subnet.",
        technique_mappings=[{"technique_id": "T1486", "name": "Data Encrypted for Impact"}],
    )
    session.commit()

    completed = get_forensic_report_or_raise(session, report.report_id)
    assert completed.status == "COMPLETED"
    assert completed.summary == "Analysis confirms ransomware activity."
    assert completed.generated_at is not None
    assert json.loads(completed.technique_mappings_json)[0]["technique_id"] == "T1486"


def test_audit_service_append_only(session: Session) -> None:
    """Verify append-oriented audit logging with generic entity references."""
    entry = append_audit_log(
        session,
        actor="admin_user",
        action="CONFIG_UPDATE",
        result="SUCCESS",
        entity_type="system_policy",
        entity_id="policy-42",
        details={"changed_field": "auto_quarantine", "value": True},
        correlation_id="corr-xyz",
    )
    session.commit()

    queried = get_audit_log_or_raise(session, entry.audit_id)
    assert queried.actor == "admin_user"
    assert queried.action == "CONFIG_UPDATE"
    assert queried.result == "SUCCESS"
    assert queried.entity_type == "system_policy"
    assert queried.entity_id == "policy-42"
    assert json.loads(queried.details_json)["changed_field"] == "auto_quarantine"
    assert json.loads(queried.details_json)["value"] is True


# ==============================================================================
# 2. Relationships and Foreign Key Constraints
# ==============================================================================

def test_evidence_requires_valid_incident(session: Session) -> None:
    """Verify creating detection evidence for a non-existent incident raises ResourceNotFoundError."""
    with pytest.raises(ResourceNotFoundError):
        create_detection_evidence(
            session,
            incident_id=str(uuid4()),  # Non-existent
            source="yara",
            indicator="test",
            severity="LOW",
            description="test",
        )


def test_response_action_requires_valid_incident(session: Session) -> None:
    """Verify creating response action for non-existent incident raises ResourceNotFoundError."""
    with pytest.raises(ResourceNotFoundError):
        create_response_action(
            session,
            incident_id=str(uuid4()),
            action_type="ALERT",
            requested_by="admin",
        )


def test_quarantine_requires_valid_incident_and_action(session: Session) -> None:
    """Verify quarantine metadata requires both valid incident and valid response action."""
    inc = create_incident(session, title="T", incident_type="t", verdict="BENIGN", risk_score=1.0)
    session.commit()

    # Invalid action_id
    with pytest.raises(ResourceNotFoundError):
        create_quarantine_record(
            session,
            incident_id=inc.incident_id,
            action_id=str(uuid4()),
            original_path="C:\\f.exe",
            quarantine_path="C:\\q.enc",
            original_sha256="d" * 64,
            encryption_algorithm="AES-256-GCM",
            nonce="nonce",
            key_reference="ref",
            original_size_bytes=100,
        )


def test_forensic_report_requires_valid_incident(session: Session) -> None:
    """Verify forensic report creation requires existing incident."""
    with pytest.raises(ResourceNotFoundError):
        create_forensic_report(
            session,
            incident_id=str(uuid4()),
            provider="ai",
        )


def test_analysis_job_requires_valid_source_event_if_provided(session: Session) -> None:
    """Verify creating an analysis job with an unknown source_event_id raises ResourceNotFoundError."""
    with pytest.raises(ResourceNotFoundError):
        create_analysis_job(
            session,
            source_event_id=str(uuid4()),
        )


def test_duplicate_quarantine_path_raises_persistence_conflict_error(session: Session) -> None:
    """Verify that registering an existing quarantine path raises PersistenceConflictError."""
    inc = create_incident(session, title="T", incident_type="t", verdict="BENIGN", risk_score=1.0)
    act = create_response_action(session, incident_id=inc.incident_id, action_type="QUARANTINE", requested_by="u")
    session.commit()

    shared_path = "C:\\vault\\duplicate_path.enc"
    create_quarantine_record(
        session,
        incident_id=inc.incident_id,
        action_id=act.action_id,
        original_path="C:\\file1.exe",
        quarantine_path=shared_path,
        original_sha256="e" * 64,
        encryption_algorithm="AES-256-GCM",
        nonce="n1",
        key_reference="k1",
        original_size_bytes=10,
    )
    session.commit()

    with pytest.raises(PersistenceConflictError):
        create_quarantine_record(
            session,
            incident_id=inc.incident_id,
            action_id=act.action_id,
            original_path="C:\\file2.exe",
            quarantine_path=shared_path,
            original_sha256="f" * 64,
            encryption_algorithm="AES-256-GCM",
            nonce="n2",
            key_reference="k2",
            original_size_bytes=20,
        )


def test_audit_logs_support_generic_entity_references_without_foreign_keys(session: Session) -> None:
    """Verify audit records can reference non-existent entity IDs without foreign-key errors."""
    non_existent_id = str(uuid4())
    entry = append_audit_log(
        session,
        actor="system",
        action="PURGE_TEST",
        result="SUCCESS",
        entity_type="ephemeral_cache",
        entity_id=non_existent_id,
    )
    session.commit()

    queried = get_audit_log_or_raise(session, entry.audit_id)
    assert queried.entity_id == non_existent_id


# ==============================================================================
# 3. Query, Filtering, and Pagination Behavior
# ==============================================================================

def test_pagination_empty_results(session: Session) -> None:
    """Verify pagination returns empty items and 0 pages when table is empty."""
    res = list_endpoint_events(session, page=1, page_size=20)
    assert res.items == []
    assert res.total_items == 0
    assert res.total_pages == 0
    assert res.page == 1
    assert res.page_size == 20


def test_pagination_pages_and_limits(session: Session) -> None:
    """Verify multiple pages, page_size clamping, and offset progression."""
    # Insert 15 events
    for i in range(15):
        create_endpoint_event(
            session,
            event_type="file_created",
            source_component="test",
            timestamp=f"2026-10-29T12:{i:02d}:00Z",
        )
    session.commit()

    page1 = list_endpoint_events(session, page=1, page_size=5)
    assert len(page1.items) == 5
    assert page1.total_items == 15
    assert page1.total_pages == 3
    # Check descending order: newest first
    assert page1.items[0].timestamp == "2026-10-29T12:14:00Z"

    page2 = list_endpoint_events(session, page=2, page_size=5)
    assert len(page2.items) == 5
    assert page2.items[0].timestamp == "2026-10-29T12:09:00Z"

    page3 = list_endpoint_events(session, page=3, page_size=5)
    assert len(page3.items) == 5
    assert page3.items[0].timestamp == "2026-10-29T12:04:00Z"

    # Beyond total pages
    page4 = list_endpoint_events(session, page=4, page_size=5)
    assert len(page4.items) == 0
    assert page4.total_pages == 3


def test_pagination_validation_errors(session: Session) -> None:
    """Verify invalid page or page_size inputs raise ValidationError."""
    with pytest.raises(ValidationError):
        list_endpoint_events(session, page=0)
    with pytest.raises(ValidationError):
        list_endpoint_events(session, page=1, page_size=0)


def test_filtering_and_deterministic_ordering(session: Session) -> None:
    """Verify filtering by verdict, status, and deterministic tie-breaker sorting."""
    # Create incidents with same detected_at
    shared_ts = "2026-10-29T12:00:00Z"
    inc1 = create_incident(session, title="A", incident_type="t", verdict="BENIGN", risk_score=10.0, detected_at=shared_ts, incident_id="11111111-0000-0000-0000-000000000000")
    inc2 = create_incident(session, title="B", incident_type="t", verdict="MALICIOUS", risk_score=90.0, detected_at=shared_ts, incident_id="22222222-0000-0000-0000-000000000000")
    inc3 = create_incident(session, title="C", incident_type="t", verdict="MALICIOUS", risk_score=95.0, detected_at="2026-10-29T12:05:00Z", incident_id="33333333-0000-0000-0000-000000000000")
    session.commit()

    # Filter by verdict
    malicious_res = list_incidents(session, verdict="MALICIOUS")
    assert malicious_res.total_items == 2
    assert malicious_res.items[0].incident_id == inc3.incident_id
    assert malicious_res.items[1].incident_id == inc2.incident_id

    # Check tie-breaker ordering when timestamp is identical
    all_res = list_incidents(session, page=1, page_size=10)
    # inc3 (12:05) comes first. Then between inc2 and inc1 (both 12:00), inc2 (id starting with 2) comes before inc1 (id starting with 1)
    assert all_res.items[0].incident_id == inc3.incident_id
    assert all_res.items[1].incident_id == inc2.incident_id
    assert all_res.items[2].incident_id == inc1.incident_id


def test_missing_resource_raises_not_found(session: Session) -> None:
    """Verify that get_*_or_raise functions raise ResourceNotFoundError for non-existent IDs."""
    with pytest.raises(ResourceNotFoundError):
        get_endpoint_event_or_raise(session, str(uuid4()))
    with pytest.raises(ResourceNotFoundError):
        get_analysis_job_or_raise(session, str(uuid4()))
    with pytest.raises(ResourceNotFoundError):
        get_incident_or_raise(session, str(uuid4()))
    with pytest.raises(ResourceNotFoundError):
        get_detection_evidence_or_raise(session, str(uuid4()))
    with pytest.raises(ResourceNotFoundError):
        get_response_action_or_raise(session, str(uuid4()))
    with pytest.raises(ResourceNotFoundError):
        get_quarantine_record_or_raise(session, str(uuid4()))
    with pytest.raises(ResourceNotFoundError):
        get_forensic_report_or_raise(session, str(uuid4()))
    with pytest.raises(ResourceNotFoundError):
        get_audit_log_or_raise(session, str(uuid4()))


# ==============================================================================
# 4. Status and Lifecycle Behavior Tests
# ==============================================================================

def test_failed_analysis_job_cannot_receive_benign_verdict(session: Session) -> None:
    """Verify that a failed analysis job cannot be assigned a BENIGN verdict."""
    job = create_analysis_job(session)
    update_analysis_job_status(session, job.job_id, "IN_PROGRESS")
    update_analysis_job_status(session, job.job_id, "FAILED", error_code="TIMEOUT")
    session.commit()

    with pytest.raises(ValidationError):
        record_analysis_job_result(session, job.job_id, verdict="BENIGN")


def test_invalid_analysis_job_state_transition(session: Session) -> None:
    """Verify illegal transitions (e.g. COMPLETED -> IN_PROGRESS) raise InvalidStateTransitionError."""
    job = create_analysis_job(session)
    update_analysis_job_status(session, job.job_id, "IN_PROGRESS")
    update_analysis_job_status(session, job.job_id, "COMPLETED")
    session.commit()

    with pytest.raises(InvalidStateTransitionError):
        update_analysis_job_status(session, job.job_id, "IN_PROGRESS")


def test_invalid_response_action_state_transition(session: Session) -> None:
    """Verify illegal action transitions (e.g. SUCCEEDED -> IN_PROGRESS) raise InvalidStateTransitionError."""
    inc = create_incident(session, title="T", incident_type="t", verdict="BENIGN", risk_score=0.0)
    act = create_response_action(session, incident_id=inc.incident_id, action_type="ALERT", requested_by="u")
    update_response_action_status(session, act.action_id, "IN_PROGRESS")
    update_response_action_status(session, act.action_id, "SUCCEEDED")
    session.commit()

    with pytest.raises(InvalidStateTransitionError):
        update_response_action_status(session, act.action_id, "IN_PROGRESS")


def test_invalid_quarantine_state_transition(session: Session) -> None:
    """Verify illegal quarantine transitions (e.g. DELETED -> QUARANTINED) raise InvalidStateTransitionError."""
    inc = create_incident(session, title="T", incident_type="t", verdict="BENIGN", risk_score=0.0)
    act = create_response_action(session, incident_id=inc.incident_id, action_type="Q", requested_by="u")
    q = create_quarantine_record(
        session,
        incident_id=inc.incident_id,
        action_id=act.action_id,
        original_path="C:\\a.exe",
        quarantine_path="C:\\vault\\a.enc",
        original_sha256="a" * 64,
        encryption_algorithm="AES-256-GCM",
        nonce="n",
        key_reference="k",
        original_size_bytes=100,
        status="QUARANTINED",
    )
    update_quarantine_status(session, q.quarantine_id, "DELETED")
    session.commit()

    with pytest.raises(InvalidStateTransitionError):
        update_quarantine_status(session, q.quarantine_id, "QUARANTINED")


def test_incident_status_reopen_clears_resolution_timestamp(session: Session) -> None:
    """Verify transitioning to RESOLVED sets resolved_at, and reopening clears it."""
    inc = create_incident(session, title="T", incident_type="t", verdict="MALICIOUS", risk_score=80.0)
    session.commit()
    assert inc.resolved_at is None

    update_incident_status(session, inc.incident_id, "RESOLVED")
    session.commit()
    assert get_incident(session, inc.incident_id).resolved_at is not None

    update_incident_status(session, inc.incident_id, "INVESTIGATING")
    session.commit()
    assert get_incident(session, inc.incident_id).resolved_at is None


# ==============================================================================
# 5. Transaction, Session & Rollback Management
# ==============================================================================

def test_service_does_not_commit_caller_session(session: Session) -> None:
    """Verify that calling create_* flushes without committing the outer transaction."""
    event = create_endpoint_event(
        session,
        event_type="file_created",
        source_component="test",
    )
    # The entity has been assigned, but session is not committed
    assert event.event_id is not None
    assert session.is_active is True

    # Rollback outer transaction
    session.rollback()

    # After rollback, record must not exist
    queried = get_endpoint_event(session, event.event_id)
    assert queried is None


def test_atomic_multi_record_transaction_rollback(db_engine) -> None:
    """Verify that an exception in a multi-step operation rolls back all partial records."""
    factory = get_session_factory(db_engine)

    event_id = str(uuid4())
    inc_id = str(uuid4())

    with pytest.raises(ValueError):
        with db_session_scope(factory) as sess:
            # Step 1: create event
            create_endpoint_event(
                sess,
                event_id=event_id,
                event_type="file_created",
                source_component="test",
            )
            # Step 2: create incident
            create_incident(
                sess,
                incident_id=inc_id,
                title="Partial Incident",
                incident_type="malware",
                verdict="MALICIOUS",
                risk_score=90.0,
            )
            # Step 3: simulate unexpected failure
            raise ValueError("Simulated unexpected failure during workflow")

    # Verify neither record was committed
    with factory() as sess:
        assert get_endpoint_event(sess, event_id) is None
        assert get_incident(sess, inc_id) is None


def test_audit_logs_unaffected_by_unrelated_incident_updates(session: Session) -> None:
    """Verify audit log history remains immutable when incidents are updated."""
    inc = create_incident(session, title="T", incident_type="t", verdict="BENIGN", risk_score=10.0)
    audit = append_audit_log(
        session,
        actor="analyst",
        action="INCIDENT_INVESTIGATED",
        result="SUCCESS",
        entity_type="incident",
        entity_id=inc.incident_id,
    )
    session.commit()

    # Update incident
    update_incident_status(session, inc.incident_id, "CLOSED")
    session.commit()

    # Audit log entry unchanged
    queried_audit = get_audit_log_or_raise(session, audit.audit_id)
    assert queried_audit.entity_id == inc.incident_id
    assert queried_audit.action == "INCIDENT_INVESTIGATED"


# ==============================================================================
# 6. Contract & Status Alignment Verification Tests
# ==============================================================================

def test_analysis_job_status_rejects_running_and_enforces_canonical_statuses(session: Session) -> None:
    """Verify that RUNNING is rejected and canonical IN_PROGRESS is accepted."""
    job = create_analysis_job(session)
    session.commit()

    # RUNNING must be rejected with ValidationError
    with pytest.raises(ValidationError) as exc_info:
        update_analysis_job_status(session, job.job_id, "RUNNING")
    assert "RUNNING" in str(exc_info.value)

    # Transition to IN_PROGRESS succeeds
    update_analysis_job_status(session, job.job_id, "IN_PROGRESS")
    session.commit()
    assert get_analysis_job_or_raise(session, job.job_id).status == "IN_PROGRESS"

    # Transition to FAILED succeeds and clears any pre-existing BENIGN verdict
    record_analysis_job_result(session, job.job_id, verdict="SUSPICIOUS")
    update_analysis_job_status(session, job.job_id, "FAILED", error_code="ERR_CRASH")
    session.commit()
    failed_job = get_analysis_job_or_raise(session, job.job_id)
    assert failed_job.status == "FAILED"
    assert failed_job.error_code == "ERR_CRASH"

    # Assigning BENIGN to a FAILED job must be rejected
    with pytest.raises(ValidationError):
        record_analysis_job_result(session, job.job_id, verdict="BENIGN")

    # Direct QUEUED -> FAILED is allowed (e.g. worker dispatch failure)
    job2 = create_analysis_job(session)
    update_analysis_job_status(session, job2.job_id, "FAILED", error_code="DISPATCH_ERR")
    session.commit()
    assert get_analysis_job_or_raise(session, job2.job_id).status == "FAILED"


def test_incident_status_rejects_false_positive_and_handles_benign_resolution(session: Session) -> None:
    """Verify FALSE_POSITIVE is rejected as status, while BENIGN verdict resolution is supported."""
    inc = create_incident(
        session,
        title="Suspicious Activity",
        incident_type="ransomware",
        verdict="SUSPICIOUS",
        risk_score=70.0,
    )
    # Add evidence to ensure it persists across status changes
    ev = create_detection_evidence(
        session,
        incident_id=inc.incident_id,
        source="yara",
        indicator="rule_entropy",
        severity="HIGH",
        description="High entropy file",
    )
    session.commit()

    # Setting status to FALSE_POSITIVE must raise ValidationError
    with pytest.raises(ValidationError) as exc_info:
        update_incident_status(session, inc.incident_id, "FALSE_POSITIVE")
    assert "FALSE_POSITIVE" in str(exc_info.value)

    # Resolving investigation outcome as false positive: status=RESOLVED, verdict=BENIGN, risk_score=0.0
    update_incident_status(
        session,
        inc.incident_id,
        "RESOLVED",
        verdict="BENIGN",
        risk_score=0.0,
    )
    session.commit()

    resolved_inc = get_incident_or_raise(session, inc.incident_id)
    assert resolved_inc.status == "RESOLVED"
    assert resolved_inc.verdict == "BENIGN"
    assert resolved_inc.risk_score == 0.0
    assert resolved_inc.resolved_at is not None

    # Evidence remains intact and attached
    ev_list = list_evidence_for_incident(session, inc.incident_id)
    assert ev_list.total_items == 1
    assert ev_list.items[0].evidence_id == ev.evidence_id


def test_response_action_status_rejects_completed_and_uses_succeeded(session: Session) -> None:
    """Verify COMPLETED is rejected for response actions and SUCCEEDED is enforced."""
    inc = create_incident(session, title="T", incident_type="malware", verdict="MALICIOUS", risk_score=90.0)
    act = create_response_action(session, incident_id=inc.incident_id, action_type="ALERT", requested_by="auto")
    session.commit()

    # Reject COMPLETED status on response action
    with pytest.raises(ValidationError) as exc_info:
        update_response_action_status(session, act.action_id, "COMPLETED")
    assert "COMPLETED" in str(exc_info.value)

    # Valid lifecycle: PENDING -> IN_PROGRESS -> SUCCEEDED
    update_response_action_status(session, act.action_id, "IN_PROGRESS")
    update_response_action_status(session, act.action_id, "SUCCEEDED")
    session.commit()

    queried = get_response_action_or_raise(session, act.action_id)
    assert queried.status == "SUCCEEDED"
    assert queried.completed_at is not None

    # PENDING -> FAILED is allowed (immediate failure)
    act2 = create_response_action(session, incident_id=inc.incident_id, action_type="ALERT", requested_by="auto")
    update_response_action_status(session, act2.action_id, "FAILED", error_code="POLICY_DENIED")
    session.commit()
    assert get_response_action_or_raise(session, act2.action_id).status == "FAILED"


def test_endpoint_event_validations_and_query_filters(session: Session) -> None:
    """Verify endpoint event validation on hash/type and query filtering across schema columns."""
    # Invalid event_type
    with pytest.raises(ValidationError):
        create_endpoint_event(
            session,
            event_type="invalid_type",
            source_component="test",
        )

    # Invalid file_hash
    with pytest.raises(ValidationError):
        create_endpoint_event(
            session,
            event_type="file_created",
            source_component="test",
            file_hash="not_a_valid_hex_hash",
        )

    # Create several events with distinct properties
    hash1 = "1" * 64
    hash2 = "2" * 64
    ev1 = create_endpoint_event(
        session,
        event_type="file_created",
        source_component="fs_sensor",
        file_path="C:\\test\\doc1.exe",
        file_hash=hash1,
        process_id=101,
        timestamp="2026-10-29T10:00:00Z",
    )
    ev2 = create_endpoint_event(
        session,
        event_type="file_modified",
        source_component="fs_sensor",
        file_path="C:\\test\\doc2.exe",
        file_hash=hash2,
        process_id=102,
        timestamp="2026-10-29T11:00:00Z",
    )
    ev3 = create_endpoint_event(
        session,
        event_type="process_observed",
        source_component="proc_monitor",
        process_id=200,
        timestamp="2026-10-29T12:00:00Z",
    )
    session.commit()

    # Filter by source_component
    fs_events = list_endpoint_events(session, source_component="fs_sensor")
    assert fs_events.total_items == 2

    # Filter by file_path
    path_events = list_endpoint_events(session, file_path="C:\\test\\doc1.exe")
    assert path_events.total_items == 1
    assert path_events.items[0].event_id == ev1.event_id

    # Filter by process_id
    proc_events = list_endpoint_events(session, process_id=200)
    assert proc_events.total_items == 1
    assert proc_events.items[0].event_id == ev3.event_id

    # Filter by file_hash
    hash_events = list_endpoint_events(session, file_hash=hash1)
    assert hash_events.total_items == 1
    assert hash_events.items[0].event_id == ev1.event_id

