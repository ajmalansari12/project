"""Unit and integration tests for AnalysisOrchestrator in Sentinel-EDR (T010)."""

from pathlib import Path
from typing import Generator
from unittest.mock import patch
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import db_session_scope
from app.schemas.contracts import (
    AnalysisJobStatus,
    AnalysisResult,
    HashListType,
    SecurityVerdict,
)
from app.services.analysis_job_service import (
    claim_analysis_job,
    create_analysis_job,
    get_analysis_job_or_raise,
)
from app.services.analysis_orchestrator import AnalysisOrchestrator
from app.services.hash_database_service import create_hash_reputation


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
def temp_sample_file(tmp_path: Path) -> Path:
    """Create a temporary harmless fixture file for hashing tests."""
    p = tmp_path / "sample_target.bin"
    p.write_bytes(b"Sentinel EDR Safe Test Payload 2026")
    return p


def test_orchestrate_hashing_and_unknown_hash_reputation(
    db_session: Session, temp_sample_file: Path
):
    """Verify clean file hashing succeeds and unknown reputation results in verdict=None, never BENIGN."""
    orchestrator = AnalysisOrchestrator()

    job = create_analysis_job(db_session, file_path=str(temp_sample_file))
    db_session.commit()

    # Claim job so status is IN_PROGRESS
    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    # Orchestrate
    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    assert isinstance(result, AnalysisResult)
    assert result.analysis_status == AnalysisJobStatus.COMPLETED
    assert result.verdict is None  # Overall verdict must remain None in T010
    assert result.risk_score is None
    assert result.modules_executed == ["sha256", "hash_reputation"]
    assert result.modules_failed == []
    assert result.hash_reputation is not None
    assert result.hash_reputation.is_known is False
    assert result.hash_reputation.verdict is None
    assert result.hash_reputation.list_type is None

    # Verify persisted job record
    persisted = get_analysis_job_or_raise(db_session, job.job_id)
    assert persisted.status == AnalysisJobStatus.COMPLETED.value
    assert persisted.verdict is None
    assert persisted.risk_score is None
    assert len(persisted.file_hash) == 64
    assert persisted.file_hash.islower()
    assert result.hash_reputation.file_hash == persisted.file_hash


def test_orchestrate_with_known_malicious_reputation(
    db_session: Session, temp_sample_file: Path
):
    """Verify hash matching a stored MALICIOUS reputation preserves exact stage reputation."""
    orchestrator = AnalysisOrchestrator()

    # Pre-compute hash and insert MALICIOUS reputation in DB
    from app.services.sha256_service import compute_file_sha256
    known_hash = compute_file_sha256(temp_sample_file)

    create_hash_reputation(
        db_session,
        file_hash=known_hash,
        verdict=SecurityVerdict.MALICIOUS,
        list_type=HashListType.BLOCKLIST,
        description="Known test malware indicator",
    )
    job = create_analysis_job(db_session, file_path=str(temp_sample_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    assert result.analysis_status == AnalysisJobStatus.COMPLETED
    assert result.verdict is None  # Overall verdict remains None in T010
    assert result.risk_score is None
    assert result.modules_executed == ["sha256", "hash_reputation"]
    assert result.hash_reputation is not None
    assert result.hash_reputation.is_known is True
    assert result.hash_reputation.verdict == SecurityVerdict.MALICIOUS
    assert result.hash_reputation.list_type == HashListType.BLOCKLIST

    persisted = get_analysis_job_or_raise(db_session, job.job_id)
    assert persisted.verdict is None
    assert persisted.risk_score is None


def test_orchestrate_with_known_suspicious_reputation(
    db_session: Session, temp_sample_file: Path
):
    """Verify hash matching a stored SUSPICIOUS reputation preserves exact stage reputation."""
    orchestrator = AnalysisOrchestrator()
    from app.services.sha256_service import compute_file_sha256
    known_hash = compute_file_sha256(temp_sample_file)

    create_hash_reputation(
        db_session,
        file_hash=known_hash,
        verdict=SecurityVerdict.SUSPICIOUS,
        list_type=HashListType.CUSTOM,
        description="Heuristic test indicator",
    )
    job = create_analysis_job(db_session, file_path=str(temp_sample_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    assert result.analysis_status == AnalysisJobStatus.COMPLETED
    assert result.verdict is None  # Overall verdict remains None in T010
    assert result.risk_score is None
    assert result.modules_executed == ["sha256", "hash_reputation"]
    assert result.hash_reputation is not None
    assert result.hash_reputation.is_known is True
    assert result.hash_reputation.verdict == SecurityVerdict.SUSPICIOUS
    assert result.hash_reputation.list_type == HashListType.CUSTOM

    persisted = get_analysis_job_or_raise(db_session, job.job_id)
    assert persisted.verdict is None
    assert persisted.risk_score is None


def test_orchestrate_with_known_benign_reputation(
    db_session: Session, temp_sample_file: Path
):
    """Verify hash matching an explicit stored BENIGN reputation preserves exact stage reputation."""
    orchestrator = AnalysisOrchestrator()
    from app.services.sha256_service import compute_file_sha256
    known_hash = compute_file_sha256(temp_sample_file)

    create_hash_reputation(
        db_session,
        file_hash=known_hash,
        verdict=SecurityVerdict.BENIGN,
        list_type=HashListType.ALLOWLIST,
        description="Local system benign allowlist entry",
    )
    job = create_analysis_job(db_session, file_path=str(temp_sample_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    assert result.analysis_status == AnalysisJobStatus.COMPLETED
    assert result.verdict is None  # Overall verdict remains None in T010
    assert result.risk_score is None
    assert result.hash_reputation is not None
    assert result.hash_reputation.is_known is True
    assert result.hash_reputation.verdict == SecurityVerdict.BENIGN
    assert result.hash_reputation.list_type == HashListType.ALLOWLIST

    persisted = get_analysis_job_or_raise(db_session, job.job_id)
    assert persisted.verdict is None
    assert persisted.risk_score is None


def test_orchestrate_hashing_failure_transitions_to_failed(db_session: Session):
    """Verify nonexistent file target transitions the job to FAILED with safe diagnostics."""
    orchestrator = AnalysisOrchestrator()

    job = create_analysis_job(db_session, file_path="C:\\nonexistent\\missing_target_file.dll")
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    assert result.analysis_status == AnalysisJobStatus.FAILED
    assert result.verdict is None
    assert result.modules_failed == ["sha256"]

    persisted = get_analysis_job_or_raise(db_session, job.job_id)
    assert persisted.status == AnalysisJobStatus.FAILED.value
    assert persisted.error_code == "HASHING_FAILED"
    assert "FileNotFoundError" in persisted.error_message
    assert persisted.verdict is None


def test_orchestrate_reputation_db_error_transitions_to_failed(
    db_session: Session, temp_sample_file: Path
):
    """Verify reputation lookup DB errors fail the job and are not misrepresented as unknown hash."""
    orchestrator = AnalysisOrchestrator()

    job = create_analysis_job(db_session, file_path=str(temp_sample_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    with patch("app.services.analysis_orchestrator.lookup_hash", side_effect=RuntimeError("Simulated DB fault")):
        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

    assert result.analysis_status == AnalysisJobStatus.FAILED
    assert result.modules_failed == ["hash_reputation"]

    persisted = get_analysis_job_or_raise(db_session, job.job_id)
    assert persisted.status == AnalysisJobStatus.FAILED.value
    assert persisted.error_code == "REPUTATION_LOOKUP_FAILED"
    assert persisted.verdict is None


def test_orchestrator_does_not_invoke_yara_scanner(
    db_session: Session, temp_sample_file: Path
):
    """Verify T009 YaraScanner is strictly not invoked during T010 orchestration."""
    orchestrator = AnalysisOrchestrator()

    job = create_analysis_job(db_session, file_path=str(temp_sample_file))
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    with patch("app.services.yara_scanner.YaraScanner.scan_file") as mock_yara_scan:
        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        mock_yara_scan.assert_not_called()

    assert "yara" not in result.modules_executed
    assert result.analysis_status == AnalysisJobStatus.COMPLETED


def test_orchestrate_cooperative_cancellation_stops_execution(
    db_session: Session, temp_sample_file: Path
):
    """Verify pre-cancelled job is not orchestrated and returns CANCELLED."""
    orchestrator = AnalysisOrchestrator()

    job = create_analysis_job(db_session, file_path=str(temp_sample_file))
    from app.services.analysis_job_service import cancel_analysis_job
    cancel_analysis_job(db_session, job.job_id, reason="User cancelled prior to processing")
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    assert result.analysis_status == AnalysisJobStatus.CANCELLED
    assert result.modules_executed == []


def test_t010_never_calculates_numeric_risk_scores(
    db_session: Session, temp_sample_file: Path
):
    """Verify that under all T010 orchestration paths, risk_score remains strictly None."""
    orchestrator = AnalysisOrchestrator()

    # Case 1: Unknown hash
    job1 = create_analysis_job(db_session, file_path=str(temp_sample_file))
    claim_analysis_job(db_session, job1.job_id)
    res1 = orchestrator.orchestrate_job(db_session, job1.job_id)
    assert res1.risk_score is None

    # Case 2: Known malicious
    from app.services.sha256_service import compute_file_sha256
    file_hash = compute_file_sha256(temp_sample_file)
    create_hash_reputation(
        db_session,
        file_hash=file_hash,
        verdict=SecurityVerdict.MALICIOUS,
        list_type=HashListType.BLOCKLIST,
    )
    job2 = create_analysis_job(db_session, file_path=str(temp_sample_file))
    claim_analysis_job(db_session, job2.job_id)
    res2 = orchestrator.orchestrate_job(db_session, job2.job_id)
    assert res2.verdict is None
    assert res2.hash_reputation is not None
    assert res2.hash_reputation.verdict == SecurityVerdict.MALICIOUS
    assert res2.risk_score is None

    # Case 3: Failed job
    job3 = create_analysis_job(db_session, file_path="C:\\nonexistent\\missing.dll")
    claim_analysis_job(db_session, job3.job_id)
    res3 = orchestrator.orchestrate_job(db_session, job3.job_id)
    assert res3.analysis_status == AnalysisJobStatus.FAILED
    assert res3.risk_score is None
    assert res3.verdict is None


def test_orchestrator_normalizes_uppercase_hash_input_and_emits_lowercase_contract_digest(
    db_session: Session,
):
    """Verify orchestrator accepts uppercase hash input but emits strictly canonical lowercase digest in HashReputationSummary."""
    orchestrator = AnalysisOrchestrator()
    upper_hash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    canonical_lower = upper_hash.lower()

    # Pre-seed hash reputation with canonical lowercase
    create_hash_reputation(
        db_session,
        file_hash=canonical_lower,
        verdict=SecurityVerdict.MALICIOUS,
        list_type=HashListType.BLOCKLIST,
        description="Known test malware indicator",
    )

    # Job created with uppercase hash input (accepted by input normalization)
    job = create_analysis_job(db_session, file_hash=upper_hash)
    db_session.commit()

    claim_analysis_job(db_session, job.job_id)
    db_session.commit()

    result = orchestrator.orchestrate_job(db_session, job.job_id)
    db_session.commit()

    assert result.analysis_status == AnalysisJobStatus.COMPLETED
    assert result.verdict is None  # Overall verdict remains unset in T010
    assert result.risk_score is None  # Risk score remains unset in T010

    # Verify canonical lowercase SHA-256 output in contract
    assert result.hash_reputation is not None
    assert result.hash_reputation.file_hash == canonical_lower
    assert result.hash_reputation.file_hash.islower() is True
    assert result.hash_reputation.is_known is True
    assert result.hash_reputation.verdict == SecurityVerdict.MALICIOUS
    assert result.hash_reputation.list_type == HashListType.BLOCKLIST

    # Persisted DB record is also canonical lowercase
    persisted = get_analysis_job_or_raise(db_session, job.job_id)
    assert persisted.file_hash == canonical_lower
    assert persisted.file_hash.islower() is True
    assert persisted.verdict is None
    assert persisted.risk_score is None
