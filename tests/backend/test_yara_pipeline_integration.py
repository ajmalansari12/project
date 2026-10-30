"""Integration tests for YARA signature scanner pipeline integration (T011).

Verifies the integration of YaraScanner into AnalysisOrchestrator and worker pipeline:
- Accurate execution on threat fixtures and persistence of DetectionEvidence.
- Clean files with zero matches produce no synthetic evidence.
- Overall AnalysisResult and AnalysisJob verdict and risk_score remain strictly None.
- Distinguishes executed, skipped, and failed YARA states (unready scanner, timeouts, access errors).
- Foreign key integrity with Incident and deterministic idempotency on retry.
"""

from pathlib import Path
import threading
import time
from typing import Generator
from unittest.mock import patch
from uuid import UUID

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import db_session_scope
from app.models.analysis_job import AnalysisJob
from app.models.detection_evidence import DetectionEvidence
from app.models.incident import Incident
from app.schemas.contracts import (
    AnalysisJobStatus,
    AnalysisResult,
    HashListType,
    IncidentStatus,
    SecurityVerdict,
)
from app.services.analysis_job_service import (
    claim_analysis_job,
    create_analysis_job,
    get_analysis_job_or_raise,
)
from app.services.analysis_orchestrator import AnalysisOrchestrator
from app.services.analysis_queue import AnalysisQueue
from app.services.analysis_worker import AnalysisWorker
from app.services.hash_database_service import create_hash_reputation
from app.services.incident_service import create_incident
from app.services.yara_scanner import (
    YaraScanResult,
    YaraScanStatus,
    YaraScanner,
)

FIXTURES_DIR = Path("tests/fixtures/yara").resolve()


@pytest.fixture
def isolated_db():
    """Create an isolated in-memory SQLite database."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    yield session_factory
    engine.dispose()


@pytest.fixture
def db_session(isolated_db: sessionmaker[Session]) -> Generator[Session, None, None]:
    """Provide a transactional session for testing."""
    with db_session_scope(isolated_db) as session:
        yield session


@pytest.fixture
def ready_yara_scanner() -> YaraScanner:
    """Provide a compiled YaraScanner pointing to test fixtures."""
    scanner = YaraScanner(rules_dir=FIXTURES_DIR)
    compiled_count = scanner.load_rules()
    assert compiled_count > 0, "Expected fixture rules to compile"
    assert scanner.is_ready is True
    return scanner


@pytest.fixture
def unready_yara_scanner() -> YaraScanner:
    """Provide an uninitialized YaraScanner without loaded rules."""
    return YaraScanner(rules_dir=FIXTURES_DIR)


@pytest.fixture
def synthetic_alpha_file(tmp_path: Path) -> Path:
    """Fixture file matching SyntheticThreatAlpha."""
    p = tmp_path / "threat_alpha.bin"
    p.write_bytes(b"PREFIX--SENTINEL_EDR_SYNTHETIC_THREAT_PATTERN_ALPHA--SUFFIX")
    return p


@pytest.fixture
def synthetic_multi_match_file(tmp_path: Path) -> Path:
    """Fixture file matching both SyntheticThreatAlpha and SyntheticThreatBeta."""
    p = tmp_path / "threat_multi.bin"
    p.write_bytes(
        b"CONTENT1--SENTINEL_EDR_SYNTHETIC_THREAT_PATTERN_ALPHA--"
        b"CONTENT2--SENTINEL_EDR_SYNTHETIC_THREAT_PATTERN_BETA--CONTENT3"
    )
    return p


@pytest.fixture
def clean_file(tmp_path: Path) -> Path:
    """Fixture file that does not match any test rules."""
    p = tmp_path / "clean_sample.bin"
    p.write_bytes(b"Completely harmless file without any signature markers")
    return p


# ==============================================================================
# Tests
# ==============================================================================

def test_orchestrate_yara_match_persists_evidence_and_preserves_null_verdict(
    db_session: Session,
    ready_yara_scanner: YaraScanner,
    synthetic_alpha_file: Path,
):
    """Verify YARA match executes, persists DetectionEvidence, and preserves top-level verdict=None."""
    orchestrator = AnalysisOrchestrator(
        yara_scanner=ready_yara_scanner,
        yara_enabled=True,
    )

    job = create_analysis_job(db_session, file_path=str(synthetic_alpha_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    # Invariant: Overall AnalysisResult verdict and risk_score remain strictly None in T011
    assert isinstance(result, AnalysisResult)
    assert result.analysis_status == AnalysisJobStatus.COMPLETED
    assert result.verdict is None
    assert result.risk_score is None
    assert result.modules_executed == ["sha256", "hash_reputation", "yara"]
    assert "yara" not in result.modules_skipped
    assert result.modules_failed == []
    assert len(result.evidence_ids) == 1

    # Verify persisted DetectionEvidence record
    evidence_id_str = str(result.evidence_ids[0])
    evidence_record = db_session.get(DetectionEvidence, evidence_id_str)
    assert evidence_record is not None
    assert evidence_record.source == "yara"
    assert evidence_record.indicator == "synthetic_threat:SyntheticThreatAlpha"
    assert evidence_record.severity == "HIGH"
    assert evidence_record.confidence == 1.0
    assert evidence_record.score_contribution is None  # Score contribution deferred to T020
    assert evidence_record.analysis_job_id == job.job_id
    assert "Synthetic test indicator" in evidence_record.description
    assert "1 string match(es)" in evidence_record.observed_value

    # Verify correlated Incident was created to satisfy relational constraint
    incident = db_session.get(Incident, evidence_record.incident_id)
    assert incident is not None
    assert incident.analysis_job_id == job.job_id
    assert incident.incident_type == "SIGNATURE_DETECTION"
    assert "SyntheticThreatAlpha" in incident.description

    # Verify AnalysisJob in database
    persisted_job = get_analysis_job_or_raise(db_session, job.job_id)
    assert persisted_job.status == AnalysisJobStatus.COMPLETED.value
    assert persisted_job.verdict is None
    assert persisted_job.risk_score is None


def test_orchestrate_yara_multi_match_creates_distinct_evidence_records(
    db_session: Session,
    ready_yara_scanner: YaraScanner,
    synthetic_multi_match_file: Path,
):
    """Verify scanning file with multiple matching rules generates distinct evidence for each."""
    orchestrator = AnalysisOrchestrator(
        yara_scanner=ready_yara_scanner,
        yara_enabled=True,
    )

    job = create_analysis_job(db_session, file_path=str(synthetic_multi_match_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    assert result.analysis_status == AnalysisJobStatus.COMPLETED
    assert result.verdict is None
    assert result.risk_score is None
    assert len(result.evidence_ids) == 2

    # Query evidence from database
    evidence_records = db_session.scalars(
        select(DetectionEvidence).where(DetectionEvidence.analysis_job_id == job.job_id)
    ).all()
    assert len(evidence_records) == 2

    indicators = {e.indicator: e for e in evidence_records}
    assert "synthetic_threat:SyntheticThreatAlpha" in indicators
    assert "synthetic_threat:SyntheticThreatBeta" in indicators

    assert indicators["synthetic_threat:SyntheticThreatAlpha"].severity == "HIGH"
    assert indicators["synthetic_threat:SyntheticThreatBeta"].severity == "MEDIUM"

    # Both share the same incident
    incident_ids = {e.incident_id for e in evidence_records}
    assert len(incident_ids) == 1


def test_orchestrate_clean_file_records_yara_executed_with_zero_evidence(
    db_session: Session,
    ready_yara_scanner: YaraScanner,
    clean_file: Path,
):
    """Verify clean file completes YARA stage with is_matched=False and no synthetic evidence."""
    orchestrator = AnalysisOrchestrator(
        yara_scanner=ready_yara_scanner,
        yara_enabled=True,
    )

    job = create_analysis_job(db_session, file_path=str(clean_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    assert result.analysis_status == AnalysisJobStatus.COMPLETED
    assert result.verdict is None
    assert result.risk_score is None
    assert "yara" in result.modules_executed
    assert result.evidence_ids == []

    # Database has no evidence and no synthetic incident
    evidence_count = db_session.scalars(
        select(DetectionEvidence).where(DetectionEvidence.analysis_job_id == job.job_id)
    ).all()
    assert len(evidence_count) == 0

    incidents = db_session.scalars(
        select(Incident).where(Incident.analysis_job_id == job.job_id)
    ).all()
    assert len(incidents) == 0


def test_orchestrate_yara_disabled_skips_stage_and_does_not_scan(
    db_session: Session,
    synthetic_alpha_file: Path,
):
    """Verify orchestrator respects yara_enabled=False by recording yara in modules_skipped."""
    scanner = YaraScanner(rules_dir=FIXTURES_DIR)
    scanner.load_rules()

    orchestrator = AnalysisOrchestrator(
        yara_scanner=scanner,
        yara_enabled=False,
    )

    job = create_analysis_job(db_session, file_path=str(synthetic_alpha_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    with patch.object(scanner, "scan_file") as mock_scan:
        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()
        mock_scan.assert_not_called()

    assert result.analysis_status == AnalysisJobStatus.COMPLETED
    assert "yara" in result.modules_skipped
    assert "yara" not in result.modules_executed
    assert result.evidence_ids == []


def test_orchestrate_unready_scanner_fails_job_with_explicit_error(
    db_session: Session,
    unready_yara_scanner: YaraScanner,
    synthetic_alpha_file: Path,
):
    """Verify attempting to run with uninitialized rules fails the job with YARA_SCANNER_NOT_READY."""
    orchestrator = AnalysisOrchestrator(
        yara_scanner=unready_yara_scanner,
        yara_enabled=True,
    )

    job = create_analysis_job(db_session, file_path=str(synthetic_alpha_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    assert result.analysis_status == AnalysisJobStatus.FAILED
    assert result.verdict is None
    assert "yara" in result.modules_failed
    assert "yara" not in result.modules_executed

    persisted = get_analysis_job_or_raise(db_session, job.job_id)
    assert persisted.status == AnalysisJobStatus.FAILED.value
    assert persisted.error_code == "YARA_SCANNER_NOT_READY"
    assert "not ready" in persisted.error_message


def test_orchestrate_scan_timeout_fails_job_with_safe_code(
    db_session: Session,
    ready_yara_scanner: YaraScanner,
    synthetic_alpha_file: Path,
):
    """Verify scan timeout fails the job with YARA_SCAN_TIMEOUT."""
    orchestrator = AnalysisOrchestrator(
        yara_scanner=ready_yara_scanner,
        yara_enabled=True,
    )

    job = create_analysis_job(db_session, file_path=str(synthetic_alpha_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    timed_out_result = YaraScanResult(
        file_path=str(synthetic_alpha_file),
        status=YaraScanStatus.TIMED_OUT,
        is_matched=False,
        error_message="Scan timed out after 30 seconds",
        timed_out=True,
    )

    with patch.object(ready_yara_scanner, "scan_file", return_value=timed_out_result):
        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

    assert result.analysis_status == AnalysisJobStatus.FAILED
    assert "yara" in result.modules_failed

    persisted = get_analysis_job_or_raise(db_session, job.job_id)
    assert persisted.status == AnalysisJobStatus.FAILED.value
    assert persisted.error_code == "YARA_SCAN_TIMEOUT"


def test_orchestrate_scan_file_access_failure_fails_job(
    db_session: Session,
    ready_yara_scanner: YaraScanner,
    tmp_path: Path,
):
    """Verify file deleted or inaccessible during YARA fails with YARA_FILE_ACCESS_FAILED."""
    target_file = tmp_path / "will_be_missing.bin"
    target_file.write_bytes(b"temp file content")

    orchestrator = AnalysisOrchestrator(
        yara_scanner=ready_yara_scanner,
        yara_enabled=True,
    )

    job = create_analysis_job(db_session, file_path=str(target_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    with patch.object(ready_yara_scanner, "scan_file", side_effect=FileNotFoundError("Target file removed")):
        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

    assert result.analysis_status == AnalysisJobStatus.FAILED
    assert "yara" in result.modules_failed

    persisted = get_analysis_job_or_raise(db_session, job.job_id)
    assert persisted.status == AnalysisJobStatus.FAILED.value
    assert persisted.error_code == "YARA_FILE_ACCESS_FAILED"


def test_orchestrate_file_too_large_fails_job(
    db_session: Session,
    tmp_path: Path,
):
    """Verify file exceeding maximum configured size fails with YARA_FILE_TOO_LARGE."""
    large_file = tmp_path / "oversized.bin"
    large_file.write_bytes(b"A" * 1024)

    scanner = YaraScanner(rules_dir=FIXTURES_DIR, max_file_size=512)
    scanner.load_rules()

    orchestrator = AnalysisOrchestrator(
        yara_scanner=scanner,
        yara_enabled=True,
    )

    job = create_analysis_job(db_session, file_path=str(large_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    assert result.analysis_status == AnalysisJobStatus.FAILED
    assert "yara" in result.modules_failed

    persisted = get_analysis_job_or_raise(db_session, job.job_id)
    assert persisted.status == AnalysisJobStatus.FAILED.value
    assert persisted.error_code == "YARA_FILE_TOO_LARGE"


def test_orchestrate_idempotency_on_retry(
    db_session: Session,
    ready_yara_scanner: YaraScanner,
    synthetic_alpha_file: Path,
):
    """Verify executing orchestration a second time on the same job does not duplicate evidence rows."""
    orchestrator = AnalysisOrchestrator(
        yara_scanner=ready_yara_scanner,
        yara_enabled=True,
    )

    job = create_analysis_job(db_session, file_path=str(synthetic_alpha_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    # First execution
    res1 = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()
    assert len(res1.evidence_ids) == 1

    # Simulate retry by resetting job to IN_PROGRESS
    job.status = AnalysisJobStatus.IN_PROGRESS.value
    db_session.commit()

    # Second execution
    res2 = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()
    assert len(res2.evidence_ids) == 1
    assert res1.evidence_ids == res2.evidence_ids

    # Verify database has exactly 1 evidence row
    all_evidence = db_session.scalars(
        select(DetectionEvidence).where(DetectionEvidence.analysis_job_id == job.job_id)
    ).all()
    assert len(all_evidence) == 1


def test_orchestrate_attaches_evidence_to_existing_incident(
    db_session: Session,
    ready_yara_scanner: YaraScanner,
    synthetic_alpha_file: Path,
):
    """Verify evidence links to an existing pre-created Incident if one is present."""
    orchestrator = AnalysisOrchestrator(
        yara_scanner=ready_yara_scanner,
        yara_enabled=True,
    )

    job = create_analysis_job(db_session, file_path=str(synthetic_alpha_file))
    db_session.commit()

    # Pre-create an incident associated with the job
    existing_inc = create_incident(
        db_session,
        analysis_job_id=job.job_id,
        title="Pre-existing sensor incident",
        incident_type="ENDPOINT_MONITOR",
        verdict=SecurityVerdict.SUSPICIOUS.value,
        risk_score=45.0,
        status=IncidentStatus.INVESTIGATING.value,
    )
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    assert len(result.evidence_ids) == 1
    ev = db_session.get(DetectionEvidence, str(result.evidence_ids[0]))
    assert ev is not None
    assert ev.incident_id == existing_inc.incident_id

    # No second incident was created
    all_incidents = db_session.scalars(
        select(Incident).where(Incident.analysis_job_id == job.job_id)
    ).all()
    assert len(all_incidents) == 1


def test_orchestrate_preserves_hash_reputation_summary_alongside_yara(
    db_session: Session,
    ready_yara_scanner: YaraScanner,
    synthetic_alpha_file: Path,
):
    """Verify hash reputation summary remains preserved in AnalysisResult alongside YARA evidence."""
    from app.services.sha256_service import compute_file_sha256

    file_hash = compute_file_sha256(synthetic_alpha_file)
    create_hash_reputation(
        db_session,
        file_hash=file_hash,
        verdict=SecurityVerdict.MALICIOUS,
        list_type=HashListType.BLOCKLIST,
        description="Known malicious threat",
    )
    db_session.commit()

    orchestrator = AnalysisOrchestrator(
        yara_scanner=ready_yara_scanner,
        yara_enabled=True,
    )

    job = create_analysis_job(db_session, file_path=str(synthetic_alpha_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    assert result.analysis_status == AnalysisJobStatus.COMPLETED
    assert result.verdict is None  # Overall verdict strictly None
    assert result.risk_score is None

    # Both hash_reputation and YARA executed
    assert result.modules_executed == ["sha256", "hash_reputation", "yara"]
    assert result.hash_reputation is not None
    assert result.hash_reputation.is_known is True
    assert result.hash_reputation.verdict == SecurityVerdict.MALICIOUS
    assert result.hash_reputation.list_type == HashListType.BLOCKLIST

    # Evidence persisted
    assert len(result.evidence_ids) == 1


def test_orchestrate_hash_only_job_skips_yara(
    db_session: Session,
    ready_yara_scanner: YaraScanner,
):
    """Verify a job created without file_path skips YARA scanning safely."""
    orchestrator = AnalysisOrchestrator(
        yara_scanner=ready_yara_scanner,
        yara_enabled=True,
    )

    known_hash = "a" * 64
    job = create_analysis_job(db_session, file_hash=known_hash)
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    assert result.analysis_status == AnalysisJobStatus.COMPLETED
    assert "yara" in result.modules_skipped
    assert "yara" not in result.modules_executed
    assert result.evidence_ids == []


def test_worker_dispatches_and_executes_yara_job(
    isolated_db: sessionmaker[Session],
    ready_yara_scanner: YaraScanner,
    synthetic_alpha_file: Path,
):
    """End-to-end test with AnalysisQueue and AnalysisWorker with YARA enabled."""
    queue = AnalysisQueue(session_factory=isolated_db)
    orchestrator = AnalysisOrchestrator(
        yara_scanner=ready_yara_scanner,
        yara_enabled=True,
    )

    with db_session_scope(isolated_db) as session:
        job = create_analysis_job(session, file_path=str(synthetic_alpha_file))
        session.commit()
        job_id = job.job_id
        queue.submit_job_id(job_id)

    stop_event = threading.Event()
    worker = AnalysisWorker(
        worker_id="worker-test-yara",
        queue=queue,
        orchestrator=orchestrator,
        session_factory=isolated_db,
        stop_event=stop_event,
        poll_interval=0.05,
    )
    worker.start()

    # Poll for completion with bounded timeout
    deadline = time.time() + 5.0
    completed = False
    while time.time() < deadline:
        with db_session_scope(isolated_db) as session:
            j = session.get(AnalysisJob, job_id)
            if j and j.status == AnalysisJobStatus.COMPLETED.value:
                completed = True
                break
        time.sleep(0.05)

    stop_event.set()
    worker.join(timeout=2.0)

    assert completed is True, "Analysis job did not complete in worker within deadline"

    # Verify final state in DB
    with db_session_scope(isolated_db) as session:
        j = session.get(AnalysisJob, job_id)
        assert j.status == AnalysisJobStatus.COMPLETED.value
        assert j.verdict is None
        assert j.risk_score is None
        assert "yara" in j.modules_executed_json

        evidence = session.scalars(
            select(DetectionEvidence).where(DetectionEvidence.analysis_job_id == job_id)
        ).all()
        assert len(evidence) == 1
        assert evidence[0].indicator == "synthetic_threat:SyntheticThreatAlpha"


def test_orchestrate_scanner_with_no_rules_fails_job_never_falsely_zero_matches(
    db_session: Session,
    tmp_path: Path,
    synthetic_alpha_file: Path,
):
    """Verify that when no rules are available, scanner state NO_RULES_AVAILABLE fails the job, never falsely zero-match."""
    empty_rules_dir = tmp_path / "empty_rules"
    empty_rules_dir.mkdir()

    scanner = YaraScanner(rules_dir=empty_rules_dir)
    count = scanner.load_rules()
    assert count == 0
    assert scanner.is_ready is False

    orchestrator = AnalysisOrchestrator(
        yara_scanner=scanner,
        yara_enabled=True,
    )

    job = create_analysis_job(db_session, file_path=str(synthetic_alpha_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    # Must fail with YARA_SCANNER_NOT_READY, never completed as clean/zero-match
    assert result.analysis_status == AnalysisJobStatus.FAILED
    assert "yara" in result.modules_failed
    assert "yara" not in result.modules_executed

    persisted = get_analysis_job_or_raise(db_session, job.job_id)
    assert persisted.status == AnalysisJobStatus.FAILED.value
    assert persisted.error_code == "YARA_SCANNER_NOT_READY"


def test_orchestrate_compilation_failure_scanner_fails_job(
    db_session: Session,
    tmp_path: Path,
    synthetic_alpha_file: Path,
):
    """Verify that scanner in COMPILATION_FAILED state fails the job with YARA_SCANNER_NOT_READY."""
    broken_rules_dir = tmp_path / "broken_rules"
    broken_rules_dir.mkdir()
    (broken_rules_dir / "broken.yar").write_text("rule Broken { invalid condition syntax }")

    scanner = YaraScanner(rules_dir=broken_rules_dir)
    try:
        scanner.load_rules()
    except Exception:
        pass
    assert scanner.is_ready is False

    orchestrator = AnalysisOrchestrator(
        yara_scanner=scanner,
        yara_enabled=True,
    )

    job = create_analysis_job(db_session, file_path=str(synthetic_alpha_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    assert result.analysis_status == AnalysisJobStatus.FAILED
    assert "yara" in result.modules_failed
    assert "yara" not in result.modules_executed

    persisted = get_analysis_job_or_raise(db_session, job.job_id)
    assert persisted.status == AnalysisJobStatus.FAILED.value
    assert persisted.error_code == "YARA_SCANNER_NOT_READY"


def test_orchestrate_evidence_persistence_failure_rolls_back_and_leaves_no_partial_evidence(
    db_session: Session,
    ready_yara_scanner: YaraScanner,
    synthetic_multi_match_file: Path,
):
    """Verify that failure during evidence persistence rolls back savepoint and leaves zero partial evidence."""
    from app.services.evidence_service import create_detection_evidence as real_create_evidence

    # 1. Pre-create an unrelated job and evidence record to verify isolation
    unrelated_job = create_analysis_job(db_session, file_hash="b" * 64)
    unrelated_inc = create_incident(
        db_session,
        analysis_job_id=unrelated_job.job_id,
        title="Unrelated incident",
        incident_type="ENDPOINT_MONITOR",
        verdict=SecurityVerdict.SUSPICIOUS.value,
        risk_score=30.0,
        status=IncidentStatus.OPEN.value,
    )
    unrelated_ev = real_create_evidence(
        db_session,
        incident_id=unrelated_inc.incident_id,
        analysis_job_id=unrelated_job.job_id,
        source="unrelated_engine",
        indicator="unrelated_rule",
        severity="LOW",
        description="Pre-existing unrelated evidence",
    )
    db_session.commit()

    # 2. Set up orchestrator for the target job
    orchestrator = AnalysisOrchestrator(
        yara_scanner=ready_yara_scanner,
        yara_enabled=True,
    )

    job = create_analysis_job(db_session, file_path=str(synthetic_multi_match_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    # 3. Simulate failure on the second evidence insertion
    call_count = 0

    def mock_create_evidence(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return real_create_evidence(*args, **kwargs)
        raise RuntimeError("Simulated database failure during second evidence persistence")

    with patch("app.services.analysis_orchestrator.create_detection_evidence", side_effect=mock_create_evidence):
        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

    # 4. Job should fail with EVIDENCE_PERSISTENCE_FAILED
    assert result.analysis_status == AnalysisJobStatus.FAILED
    assert "yara" in result.modules_failed
    assert "yara" not in result.modules_executed

    persisted_job = get_analysis_job_or_raise(db_session, job.job_id)
    assert persisted_job.status == AnalysisJobStatus.FAILED.value
    assert persisted_job.error_code == "EVIDENCE_PERSISTENCE_FAILED"

    # 5. Verify transaction rollback: ZERO evidence records for job.job_id in DB (partial evidence undone)
    target_job_evidence = db_session.scalars(
        select(DetectionEvidence).where(DetectionEvidence.analysis_job_id == job.job_id)
    ).all()
    assert len(target_job_evidence) == 0

    # 6. Verify pre-existing unrelated evidence and incident were preserved intact
    persisted_unrelated_ev = db_session.get(DetectionEvidence, unrelated_ev.evidence_id)
    assert persisted_unrelated_ev is not None
    assert persisted_unrelated_ev.indicator == "unrelated_rule"

