"""Automated tests for shared Pydantic data contracts and JSON Schema conformance."""

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import jsonschema
import pytest
from pydantic import ValidationError

from app.schemas.contracts import (
    AnalysisJobStatus,
    AnalysisResult,
    ApiErrorDetail,
    ApiErrorResponse,
    ComponentAvailability,
    DetectionEvidence,
    DetectionSeverity,
    EndpointEvent,
    EndpointEventType,
    HashListType,
    HashReputationSummary,
    IncidentStatus,
    ResponseActionStatus,
    SecurityVerdict,
)

SCHEMAS_DIR = Path(__file__).resolve().parent.parent.parent / "shared" / "schemas"


def load_schema(schema_filename: str) -> dict:
    """Load a JSON Schema file from shared/schemas/."""
    schema_path = SCHEMAS_DIR / schema_filename
    assert schema_path.exists(), f"Schema file not found: {schema_path}"
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ==============================================================================
# EndpointEvent Contract Tests
# ==============================================================================

def test_valid_endpoint_event() -> None:
    """Verify that a well-formed EndpointEvent passes validation and schema check."""
    event = EndpointEvent(
        event_id=uuid4(),
        event_type=EndpointEventType.FILE_CREATED,
        timestamp=datetime.now(timezone.utc),
        source_component="sensor_fs_watcher",
        file_path="C:\\Windows\\System32\\test.dll",
        file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        process_id=1234,
        parent_process_id=5678,
        metadata={"action": "write", "size_bytes": 1024},
    )

    data = event.model_dump(mode="json")
    schema = load_schema("endpoint_event.schema.json")
    jsonschema.validate(instance=data, schema=schema)


def test_endpoint_event_optional_metadata_absent() -> None:
    """Verify that optional process and file metadata may be safely omitted."""
    event = EndpointEvent(
        event_id=uuid4(),
        event_type=EndpointEventType.PROCESS_OBSERVED,
        timestamp=datetime.now(timezone.utc),
        source_component="sensor_process_monitor",
    )
    assert event.file_path is None
    assert event.file_hash is None
    assert event.process_id is None
    assert event.parent_process_id is None
    assert event.metadata == {}

    data = event.model_dump(mode="json")
    schema = load_schema("endpoint_event.schema.json")
    jsonschema.validate(instance=data, schema=schema)


def test_endpoint_event_invalid_uuid() -> None:
    """Verify that invalid UUID strings are rejected."""
    with pytest.raises(ValidationError) as exc_info:
        EndpointEvent(
            event_id="not-a-valid-uuid",  # type: ignore[arg-type]
            event_type=EndpointEventType.FILE_CREATED,
            timestamp=datetime.now(timezone.utc),
            source_component="sensor",
        )
    assert "event_id" in str(exc_info.value)


def test_endpoint_event_invalid_event_type() -> None:
    """Verify that unsupported event types are rejected."""
    with pytest.raises(ValidationError) as exc_info:
        EndpointEvent(
            event_id=uuid4(),
            event_type="network_packet_received",  # type: ignore[arg-type]
            timestamp=datetime.now(timezone.utc),
            source_component="sensor",
        )
    assert "event_type" in str(exc_info.value)


def test_endpoint_event_timezone_naive_rejected() -> None:
    """Verify that timezone-naive timestamps are explicitly rejected."""
    naive_dt = datetime(2026, 10, 29, 12, 0, 0)
    with pytest.raises(ValidationError) as exc_info:
        EndpointEvent(
            event_id=uuid4(),
            event_type=EndpointEventType.FILE_CREATED,
            timestamp=naive_dt,
            source_component="sensor",
        )
    assert "timezone-aware" in str(exc_info.value)


def test_endpoint_event_invalid_sha256() -> None:
    """Verify that non-64-character or non-hex hashes are rejected."""
    # Too short
    with pytest.raises(ValidationError):
        EndpointEvent(
            event_id=uuid4(),
            event_type=EndpointEventType.FILE_CREATED,
            timestamp=datetime.now(timezone.utc),
            source_component="sensor",
            file_hash="abcdef",
        )

    # Invalid non-hex characters
    with pytest.raises(ValidationError):
        EndpointEvent(
            event_id=uuid4(),
            event_type=EndpointEventType.FILE_CREATED,
            timestamp=datetime.now(timezone.utc),
            source_component="sensor",
            file_hash="z" * 64,
        )


# ==============================================================================
# DetectionEvidence Contract Tests
# ==============================================================================

def test_valid_detection_evidence() -> None:
    """Verify that valid DetectionEvidence serializes and passes schema validation."""
    evidence = DetectionEvidence(
        evidence_id=uuid4(),
        incident_id=uuid4(),
        source="engine_yara",
        indicator="rule_suspicious_dropper",
        severity=DetectionSeverity.HIGH,
        description="Matched suspicious embedded dropper pattern in .rsrc section.",
        observed_value="FindResourceW",
        confidence=0.92,
        score_contribution=45.0,
        details={"matched_strings": ["dropper_pattern_1"]},
        observed_at=datetime.now(timezone.utc),
        analysis_job_id=uuid4(),
    )

    data = evidence.model_dump(mode="json")
    schema = load_schema("detection_evidence.schema.json")
    jsonschema.validate(instance=data, schema=schema)


def test_detection_evidence_confidence_bounds() -> None:
    """Verify that confidence must remain between 0.0 and 1.0."""
    valid_id = uuid4()
    now = datetime.now(timezone.utc)

    # Below 0.0
    with pytest.raises(ValidationError) as exc_info:
        DetectionEvidence(
            evidence_id=valid_id,
            incident_id=valid_id,
            source="test",
            indicator="test",
            severity=DetectionSeverity.LOW,
            description="test",
            confidence=-0.1,
            observed_at=now,
        )
    assert "confidence" in str(exc_info.value)

    # Above 1.0
    with pytest.raises(ValidationError) as exc_info:
        DetectionEvidence(
            evidence_id=valid_id,
            incident_id=valid_id,
            source="test",
            indicator="test",
            severity=DetectionSeverity.LOW,
            description="test",
            confidence=1.05,
            observed_at=now,
        )
    assert "confidence" in str(exc_info.value)


def test_detection_evidence_invalid_severity() -> None:
    """Verify that unsupported severity values are rejected."""
    with pytest.raises(ValidationError) as exc_info:
        DetectionEvidence(
            evidence_id=uuid4(),
            incident_id=uuid4(),
            source="test",
            indicator="test",
            severity="URGENT",  # type: ignore[arg-type]
            description="test",
            observed_at=datetime.now(timezone.utc),
        )
    assert "severity" in str(exc_info.value)


# ==============================================================================
# AnalysisResult Contract Tests
# ==============================================================================

def test_valid_analysis_result() -> None:
    """Verify that valid AnalysisResult serializes and validates against JSON Schema."""
    result = AnalysisResult(
        job_id=uuid4(),
        analysis_status=AnalysisJobStatus.COMPLETED,
        verdict=SecurityVerdict.MALICIOUS,
        risk_score=88.5,
        modules_executed=["sha256", "yara", "ml_pe"],
        modules_skipped=["canary_monitor"],
        modules_failed=[],
        evidence_ids=[uuid4(), uuid4()],
    )

    data = result.model_dump(mode="json")
    schema = load_schema("analysis_result.schema.json")
    jsonschema.validate(instance=data, schema=schema)


def test_analysis_result_risk_score_bounds() -> None:
    """Verify that risk scores must be between 0.0 and 100.0."""
    job_id = uuid4()

    # Below 0.0
    with pytest.raises(ValidationError) as exc_info:
        AnalysisResult(
            job_id=job_id,
            analysis_status=AnalysisJobStatus.COMPLETED,
            risk_score=-5.0,
        )
    assert "risk_score" in str(exc_info.value)

    # Above 100.0
    with pytest.raises(ValidationError) as exc_info:
        AnalysisResult(
            job_id=job_id,
            analysis_status=AnalysisJobStatus.COMPLETED,
            risk_score=105.0,
        )
    assert "risk_score" in str(exc_info.value)


def test_analysis_result_failed_job_without_verdict() -> None:
    """Verify that failed analysis jobs can omit verdict and risk score without assuming Benign."""
    result = AnalysisResult(
        job_id=uuid4(),
        analysis_status=AnalysisJobStatus.FAILED,
        verdict=None,
        risk_score=None,
        modules_executed=["sha256"],
        modules_skipped=[],
        modules_failed=["ml_pe"],
        evidence_ids=[],
    )
    assert result.verdict is None
    assert result.risk_score is None

    data = result.model_dump(mode="json")
    schema = load_schema("analysis_result.schema.json")
    jsonschema.validate(instance=data, schema=schema)


def test_analysis_result_with_hash_reputation() -> None:
    """Verify that AnalysisResult with HashReputationSummary validates against JSON Schema."""
    result = AnalysisResult(
        job_id=uuid4(),
        analysis_status=AnalysisJobStatus.COMPLETED,
        verdict=None,  # top-level verdict remains None in T010
        risk_score=None,
        modules_executed=["sha256", "hash_reputation"],
        modules_skipped=[],
        modules_failed=[],
        evidence_ids=[],
        hash_reputation=HashReputationSummary(
            file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            is_known=True,
            verdict=SecurityVerdict.MALICIOUS,
            list_type=HashListType.BLOCKLIST,
        ),
    )
    assert result.verdict is None
    assert result.risk_score is None
    assert result.hash_reputation is not None
    assert result.hash_reputation.is_known is True
    assert result.hash_reputation.verdict == SecurityVerdict.MALICIOUS

    data = result.model_dump(mode="json")
    schema = load_schema("analysis_result.schema.json")
    jsonschema.validate(instance=data, schema=schema)


def test_analysis_result_with_unknown_hash_reputation() -> None:
    """Verify that unknown hash reputation with verdict=None conforms to JSON Schema."""
    result = AnalysisResult(
        job_id=uuid4(),
        analysis_status=AnalysisJobStatus.COMPLETED,
        verdict=None,
        risk_score=None,
        modules_executed=["sha256", "hash_reputation"],
        modules_skipped=[],
        modules_failed=[],
        evidence_ids=[],
        hash_reputation=HashReputationSummary(
            file_hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            is_known=False,
            verdict=None,
            list_type=None,
        ),
    )
    assert result.hash_reputation is not None
    assert result.hash_reputation.is_known is False
    assert result.hash_reputation.verdict is None

    data = result.model_dump(mode="json")
    schema = load_schema("analysis_result.schema.json")
    jsonschema.validate(instance=data, schema=schema)


def test_hash_reputation_summary_accepts_valid_lowercase_digest() -> None:
    """Verify that a canonical 64-character lowercase SHA-256 digest is accepted."""
    summary = HashReputationSummary(
        file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        is_known=True,
        verdict=SecurityVerdict.BENIGN,
        list_type=HashListType.ALLOWLIST,
    )
    assert summary.file_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    result = AnalysisResult(
        job_id=uuid4(),
        analysis_status=AnalysisJobStatus.COMPLETED,
        verdict=None,
        risk_score=None,
        modules_executed=["sha256", "hash_reputation"],
        modules_skipped=[],
        modules_failed=[],
        evidence_ids=[],
        hash_reputation=summary,
    )
    schema = load_schema("analysis_result.schema.json")
    jsonschema.validate(instance=result.model_dump(mode="json"), schema=schema)


def test_hash_reputation_summary_rejects_uppercase_digest() -> None:
    """Verify that uppercase SHA-256 output digests are rejected by canonical contracts."""
    upper_hash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"

    # Pydantic contract rejection
    with pytest.raises(ValidationError) as exc_info:
        HashReputationSummary(
            file_hash=upper_hash,
            is_known=True,
        )
    assert "file_hash" in str(exc_info.value)

    # JSON Schema rejection
    schema = load_schema("analysis_result.schema.json")
    raw_payload = {
        "job_id": str(uuid4()),
        "analysis_status": "COMPLETED",
        "verdict": None,
        "risk_score": None,
        "modules_executed": ["sha256", "hash_reputation"],
        "modules_skipped": [],
        "modules_failed": [],
        "evidence_ids": [],
        "hash_reputation": {
            "file_hash": upper_hash,
            "is_known": True,
        },
    }
    with pytest.raises(jsonschema.ValidationError) as schema_exc:
        jsonschema.validate(instance=raw_payload, schema=schema)
    assert "file_hash" in str(schema_exc.value) or "pattern" in str(schema_exc.value)


def test_hash_reputation_summary_rejects_mixed_case_digest() -> None:
    """Verify that mixed-case SHA-256 output digests are rejected by canonical contracts."""
    mixed_hash = "e3b0C44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Pydantic contract rejection
    with pytest.raises(ValidationError) as exc_info:
        HashReputationSummary(
            file_hash=mixed_hash,
            is_known=True,
        )
    assert "file_hash" in str(exc_info.value)

    # JSON Schema rejection
    schema = load_schema("analysis_result.schema.json")
    raw_payload = {
        "job_id": str(uuid4()),
        "analysis_status": "COMPLETED",
        "verdict": None,
        "risk_score": None,
        "modules_executed": ["sha256", "hash_reputation"],
        "modules_skipped": [],
        "modules_failed": [],
        "evidence_ids": [],
        "hash_reputation": {
            "file_hash": mixed_hash,
            "is_known": True,
        },
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=raw_payload, schema=schema)


def test_hash_reputation_summary_rejects_malformed_and_incorrect_size_digest() -> None:
    """Verify that short, long, and non-hex digests are rejected by canonical contracts."""
    invalid_digests = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",   # 63 chars
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8555", # 65 chars
        "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",   # non-hex 'g'
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85z",   # non-hex 'z'
        "not-a-hash",
    ]

    schema = load_schema("analysis_result.schema.json")
    for bad_hash in invalid_digests:
        with pytest.raises(ValidationError):
            HashReputationSummary(file_hash=bad_hash, is_known=False)

        raw_payload = {
            "job_id": str(uuid4()),
            "analysis_status": "COMPLETED",
            "verdict": None,
            "risk_score": None,
            "modules_executed": ["sha256", "hash_reputation"],
            "modules_skipped": [],
            "modules_failed": [],
            "evidence_ids": [],
            "hash_reputation": {
                "file_hash": bad_hash,
                "is_known": False,
            },
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=raw_payload, schema=schema)


# ==============================================================================
# API Error Contract Tests
# ==============================================================================

def test_valid_api_error_response() -> None:
    """Verify that ApiErrorResponse satisfies the envelope contract in api_spec.md."""
    err_resp = ApiErrorResponse(
        error=ApiErrorDetail(
            code="RESOURCE_NOT_FOUND",
            message="The requested incident could not be found.",
            details={"incident_id": "00000000-0000-0000-0000-000000000000"},
            request_id="req-abc-123",
        )
    )

    data = err_resp.model_dump(mode="json")
    assert "error" in data
    assert data["error"]["code"] == "RESOURCE_NOT_FOUND"

    schema = load_schema("api_error.schema.json")
    jsonschema.validate(instance=data, schema=schema)


def test_api_error_empty_code_rejected() -> None:
    """Verify that an empty error code is rejected."""
    with pytest.raises(ValidationError):
        ApiErrorDetail(code="", message="Some error")


# ==============================================================================
# Enum Completeness Tests
# ==============================================================================

def test_enum_values_consistency() -> None:
    """Verify exact values of all required domain enums."""
    assert [v.value for v in SecurityVerdict] == ["BENIGN", "SUSPICIOUS", "MALICIOUS"]
    assert [v.value for v in AnalysisJobStatus] == ["QUEUED", "IN_PROGRESS", "COMPLETED", "FAILED", "CANCELLED"]
    assert [v.value for v in IncidentStatus] == ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]
    assert [v.value for v in ResponseActionStatus] == ["PENDING", "IN_PROGRESS", "SUCCEEDED", "FAILED", "CANCELLED"]
    assert [v.value for v in DetectionSeverity] == ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert [v.value for v in ComponentAvailability] == [
        "available", "unavailable", "degraded", "disabled", "not_initialized", "unknown"
    ]
    assert [v.value for v in EndpointEventType] == [
        "file_created", "file_modified", "file_renamed", "file_deleted", "process_observed", "canary_triggered"
    ]
