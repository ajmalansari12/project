"""Integration tests for Static PE Machine Learning Pipeline Integration (T016).

Verifies the end-to-end integration of PEFeatureExtractor and OnnxInferenceService
into AnalysisOrchestrator and Sentinel-EDR backend architecture:
- Model lifecycle (singleton provider, health status, metadata & checksum verification).
- Feature extraction integration (2,381 canonical float32 features, EMBER v2 schema).
- Real ONNX inference on Design A production artifact (SHA-256 verified, threshold 0.8856).
- Orchestrator Stage 4 execution on eligible PE binaries.
- Benign PE prediction handling (modules_executed, structured summary, no synthetic alert).
- Malicious PE prediction handling (DetectionEvidence persistence, Incident creation/attachment).
- Threshold boundary evaluation (exact operating threshold, perturbations).
- Graceful skipping of non-PE files and disabled ML configurations.
- Robust failure handling (missing model, corrupt model, checksum mismatch, malformed PE,
  file size limits, dimension mismatches, non-finite features, inference execution errors).
- Detection engine coexistence (YARA + ML attached to same Incident).
- Error boundaries & isolation (YARA evidence preserved when ML fails).
- Deterministic idempotency across job replays and retries.
- Transaction savepoint isolation on persistence errors.
- Strict preservation of top-level verdict=None and risk_score=None (deferred to T020).
- Conformance of AnalysisResult with ml_detection to shared JSON Schema.
"""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from typing import Generator, List, Optional
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import jsonschema
import numpy as np
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import Settings, get_settings
from app.db.base import Base
from app.db.session import db_session_scope
from app.models.analysis_job import AnalysisJob
from app.models.detection_evidence import DetectionEvidence
from app.models.incident import Incident
from app.schemas.contracts import (
    AnalysisJobStatus,
    AnalysisResult,
    ComponentAvailability,
    HashListType,
    IncidentStatus,
    MlDetectionSummary,
    SecurityVerdict,
)
from app.schemas.ml_contracts import (
    EMBER_2018_CANONICAL_FEATURE_DIMENSION,
    EMBER_2018_FEATURE_SCHEMA_VERSION,
)
from app.services.analysis_job_service import (
    claim_analysis_job,
    create_analysis_job,
    get_analysis_job_or_raise,
)
from app.services.analysis_orchestrator import AnalysisOrchestrator
from app.services.evidence_service import get_detection_evidence
from app.services.incident_service import create_incident, get_incident_for_job
from app.services.onnx_inference_service import (
    ArtifactHashMismatchError,
    InferenceExecutionError,
    InferenceResult,
    InvalidInputDimensionError,
    InvalidModelMetadataError,
    ModelHealthStatus,
    NonFiniteInputError,
    OnnxArtifactNotFoundError,
    OnnxInferenceService,
    OnnxModelCorruptError,
    get_default_onnx_inference_service,
    reset_default_onnx_inference_service,
)
from app.services.pe_feature_extractor import (
    PEFeatureExtractionResult,
    PEFeatureExtractor,
    extract_pe_features,
    get_default_pe_feature_extractor,
)
from app.services.yara_scanner import (
    YaraRuleMatch,
    YaraScanResult,
    YaraScanStatus,
    YaraScanner,
)

from tests.backend.test_pe_feature_extractor import make_synthetic_pe

SCHEMAS_DIR = Path(__file__).resolve().parent.parent.parent / "shared" / "schemas"
PROD_MODEL_PATH = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2.onnx").resolve()
PROD_METADATA_PATH = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2_onnx_metadata.json").resolve()
EXPECTED_PROD_HASH = "5e3b72ee5f09e8d7d619dcd211c9d815aa16b147d02232589919afa76076ec8e"
EXPECTED_PROD_THRESHOLD = 0.8856


def load_schema(schema_filename: str) -> dict:
    """Load a JSON Schema file from shared/schemas/."""
    schema_path = SCHEMAS_DIR / schema_filename
    assert schema_path.exists(), f"Schema file not found: {schema_path}"
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ==============================================================================
# Fixtures
# ==============================================================================

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
def synthetic_pe32_file(tmp_path: Path) -> Path:
    """Create a temporary valid 32-bit PE file using verified generator."""
    p = tmp_path / "valid_sample_32.exe"
    p.write_bytes(make_synthetic_pe(is_64bit=False))
    return p


@pytest.fixture
def clean_text_file(tmp_path: Path) -> Path:
    """Create a harmless non-PE text file."""
    p = tmp_path / "harmless.txt"
    p.write_bytes(b"This is a plain text file, definitely not an executable binary.")
    return p


@pytest.fixture
def malformed_pe_file(tmp_path: Path) -> Path:
    """Create a truncated malformed PE file with 'MZ' header but corrupted body."""
    p = tmp_path / "corrupt_pe.exe"
    # Starts with MZ magic but truncated before COFF header
    p.write_bytes(b"MZ" + b"\x00" * 40 + b"INVALID_PE_HEADER_DATA_TRUNCATED")
    return p


class MockOnnxInferenceService:
    """Configurable mock for OnnxInferenceService to test deterministic responses."""

    def __init__(
        self,
        *,
        malicious_probability: float = 0.10,
        operating_threshold: float = EXPECTED_PROD_THRESHOLD,
        model_id: str = "sentinel-pe-lightgbm-audit-v2",
        model_version: str = "1.0.0",
        is_loaded: bool = True,
        health_status: ModelHealthStatus = ModelHealthStatus.HEALTHY,
        raise_on_predict: Optional[Exception] = None,
        is_degraded: bool = False,
        degraded_reason: Optional[str] = None,
    ) -> None:
        self.malicious_probability = malicious_probability
        self.operating_threshold = operating_threshold
        self._model_id = model_id
        self._model_version = model_version
        self._is_loaded = is_loaded
        self._health_status = health_status
        self.raise_on_predict = raise_on_predict
        self.is_degraded = is_degraded
        self.degraded_reason = degraded_reason
        self.metadata_path = PROD_METADATA_PATH
        self.model_path = PROD_MODEL_PATH
        self.expected_features = EMBER_2018_CANONICAL_FEATURE_DIMENSION

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded

    @property
    def health_status(self) -> ModelHealthStatus:
        return self._health_status

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def model_version(self) -> str:
        return self._model_version

    @property
    def threshold(self) -> float:
        return self.operating_threshold

    def predict_single(
        self,
        features: np.ndarray,
        threshold: Optional[float] = None,
    ) -> InferenceResult:
        if self.raise_on_predict:
            raise self.raise_on_predict

        th = threshold if threshold is not None else self.operating_threshold
        is_mal = self.malicious_probability >= th
        return InferenceResult(
            malicious_probability=self.malicious_probability,
            benign_probability=1.0 - self.malicious_probability,
            predicted_class="MALICIOUS" if is_mal else "BENIGN",
            predicted_label=1 if is_mal else 0,
            operating_threshold=th,
            model_id=self._model_id,
            model_version=self._model_version,
            inference_duration_ms=0.42,
            is_degraded=self.is_degraded,
            degraded_reason=self.degraded_reason,
        )


# ==============================================================================
# 1. Lifecycle and Model Availability Tests
# ==============================================================================

class TestMlModelLifecycle:
    """Test suite for OnnxInferenceService lifecycle and status reflection."""

    def test_production_model_checksum_and_schema(self):
        """Verify Design A production model artifact matches exact frozen SHA-256 and metadata."""
        assert PROD_MODEL_PATH.is_file(), f"Model artifact missing at {PROD_MODEL_PATH}"
        assert PROD_METADATA_PATH.is_file(), f"Metadata missing at {PROD_METADATA_PATH}"

        hasher = hashlib.sha256()
        with open(PROD_MODEL_PATH, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        computed_hash = hasher.hexdigest().lower()

        assert computed_hash == EXPECTED_PROD_HASH

        with open(PROD_METADATA_PATH, "r", encoding="utf-8") as fm:
            meta = json.load(fm)

        schema = load_schema("model_metadata.schema.json")
        jsonschema.validate(instance=meta, schema=schema)

        assert meta["artifact_hash"].lower() == EXPECTED_PROD_HASH
        assert meta["training_config"]["operating_threshold"] == pytest.approx(EXPECTED_PROD_THRESHOLD, rel=1e-4)

    def test_singleton_provider_lazy_load_and_reset(self):
        """Verify get_default_onnx_inference_service loads singleton and reset clears it."""
        reset_default_onnx_inference_service()
        svc = get_default_onnx_inference_service()
        assert svc is not None
        assert svc.is_loaded
        assert svc.health_status == ModelHealthStatus.HEALTHY
        assert svc.model_id == "sentinel-pe-lightgbm-audit-v2"
        assert svc.threshold == pytest.approx(EXPECTED_PROD_THRESHOLD, rel=1e-4)

        # Calling again returns same cached instance
        svc2 = get_default_onnx_inference_service()
        assert svc2 is svc

        # Resetting clears instance
        reset_default_onnx_inference_service()
        from app.services.onnx_inference_service import _default_inference_service
        assert _default_inference_service is None

    def test_status_route_reflects_ml_engine_states(self, monkeypatch: pytest.MonkeyPatch):
        """Verify /status reports ml_engine states (NOT_INITIALIZED, AVAILABLE, DISABLED)."""
        from app.api.routes.status import _check_ml_engine_availability

        # 1. Uninitialized
        reset_default_onnx_inference_service()
        assert _check_ml_engine_availability() == ComponentAvailability.NOT_INITIALIZED

        # 2. Available when loaded and healthy
        get_default_onnx_inference_service()
        mock_settings_enabled = Settings(ml_enabled=True)
        monkeypatch.setattr("app.core.config.get_settings", lambda: mock_settings_enabled)
        assert _check_ml_engine_availability() == ComponentAvailability.AVAILABLE

        # 3. Disabled when ml_enabled=False
        mock_settings_disabled = Settings(ml_enabled=False)
        monkeypatch.setattr("app.core.config.get_settings", lambda: mock_settings_disabled)
        assert _check_ml_engine_availability() == ComponentAvailability.DISABLED

        reset_default_onnx_inference_service()


# ==============================================================================
# 2. Feature Extraction and ONNX Inference Verification
# ==============================================================================

class TestFeatureExtractionAndInferenceParity:
    """Verify feature extractor output conforms with ONNX input expectations."""

    def test_extract_pe_features_dimensions_and_finite_values(self, synthetic_pe32_file: Path):
        """Verify PEFeatureExtractor produces 2,381 finite float32 values on valid PE."""
        result = extract_pe_features(synthetic_pe32_file)
        assert isinstance(result, PEFeatureExtractionResult)
        assert result.is_pe is True
        assert result.parser_status == "SUCCESS"
        assert len(result.feature_vector.feature_values) == EMBER_2018_CANONICAL_FEATURE_DIMENSION

        arr = np.array(result.feature_vector.feature_values, dtype=np.float32)
        assert arr.shape == (EMBER_2018_CANONICAL_FEATURE_DIMENSION,)
        assert np.all(np.isfinite(arr))

    def test_real_production_model_inference_on_synthetic_pe(self, synthetic_pe32_file: Path):
        """End-to-end integration: extract features from synthetic PE and evaluate via real Design A ONNX model."""
        ext_res = extract_pe_features(synthetic_pe32_file)
        features = ext_res.feature_vector.feature_values

        svc = get_default_onnx_inference_service()
        inf_res = svc.predict_single(features)

        assert isinstance(inf_res, InferenceResult)
        assert 0.0 <= inf_res.malicious_probability <= 1.0
        assert 0.0 <= inf_res.benign_probability <= 1.0
        assert inf_res.benign_probability + inf_res.malicious_probability == pytest.approx(1.0, abs=1e-4)
        assert inf_res.operating_threshold == pytest.approx(EXPECTED_PROD_THRESHOLD, rel=1e-4)
        assert inf_res.predicted_class in ("BENIGN", "MALICIOUS")
        assert inf_res.predicted_label in (0, 1)
        assert inf_res.inference_duration_ms > 0.0
        assert not inf_res.is_degraded


# ==============================================================================
# 3. AnalysisOrchestrator Stage 4 Execution Tests
# ==============================================================================

class TestAnalysisOrchestratorMlExecution:
    """Test suite for orchestrator Stage 4 execution and evidence persistence."""

    def test_orchestrate_malicious_pe_creates_incident_and_persists_evidence(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """When ML predicts MALICIOUS, orchestrator persists DetectionEvidence and attaches to Incident."""
        mock_svc = MockOnnxInferenceService(malicious_probability=0.9650)
        orchestrator = AnalysisOrchestrator(
            ml_service=mock_svc,
            ml_enabled=True,
            yara_enabled=False,
        )

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        # Invariant: verdict and risk_score remain strictly None
        assert result.analysis_status == AnalysisJobStatus.COMPLETED
        assert result.verdict is None
        assert result.risk_score is None
        assert "ml_pe" in result.modules_executed
        assert "ml_pe" not in result.modules_failed
        assert "ml_pe" not in result.modules_skipped
        assert len(result.evidence_ids) == 1

        # Check structured ML detection summary
        assert result.ml_detection is not None
        summary = result.ml_detection
        assert summary.model_id == "sentinel-pe-lightgbm-audit-v2"
        assert summary.model_version == "1.0.0"
        assert summary.artifact_hash == EXPECTED_PROD_HASH
        assert summary.feature_schema == EMBER_2018_FEATURE_SCHEMA_VERSION
        assert summary.malicious_probability == pytest.approx(0.9650, abs=1e-4)
        assert summary.predicted_class == "MALICIOUS"
        assert summary.predicted_label == 1
        assert summary.operating_threshold == pytest.approx(EXPECTED_PROD_THRESHOLD, rel=1e-4)
        assert not summary.is_degraded

        # Verify persisted DetectionEvidence in database
        ev_uuid = result.evidence_ids[0]
        evidence = get_detection_evidence(db_session, str(ev_uuid))
        assert evidence is not None
        assert evidence.source == "ml_pe"
        assert evidence.indicator == "sentinel-pe-lightgbm-audit-v2:1.0.0"
        assert evidence.severity == "HIGH"
        assert evidence.confidence == pytest.approx(0.9650, abs=1e-4)
        assert "P(Malicious)=0.9650" in evidence.observed_value
        assert evidence.score_contribution is None  # Deferred to T020

        # Verify details dictionary fields
        details = json.loads(evidence.details_json)
        assert details["model_id"] == "sentinel-pe-lightgbm-audit-v2"
        assert details["source"] == "MACHINE_LEARNING"
        assert details["detection_source"] == "MACHINE_LEARNING"
        assert details["artifact_hash"] == EXPECTED_PROD_HASH
        assert details["feature_schema"] == "ember_pe_v2"
        assert details["malicious_probability"] == pytest.approx(0.9650, abs=1e-4)
        assert details["predicted_label"] == 1

        # Verify associated Incident exists
        incident = get_incident_for_job(db_session, job.job_id)
        assert incident is not None
        assert incident.incident_id == evidence.incident_id
        assert incident.incident_type == "ML_DETECTION"
        assert incident.status == IncidentStatus.OPEN.value

    def test_orchestrate_benign_pe_produces_no_detection_evidence(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """When ML predicts BENIGN, modules_executed records ml_pe, but no synthetic alert is created."""
        mock_svc = MockOnnxInferenceService(malicious_probability=0.0820)
        orchestrator = AnalysisOrchestrator(
            ml_service=mock_svc,
            ml_enabled=True,
            yara_enabled=False,
        )

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        assert result.analysis_status == AnalysisJobStatus.COMPLETED
        assert result.verdict is None
        assert result.risk_score is None
        assert "ml_pe" in result.modules_executed
        assert len(result.evidence_ids) == 0

        # Structured summary records BENIGN outcome
        assert result.ml_detection is not None
        assert result.ml_detection.predicted_class == "BENIGN"
        assert result.ml_detection.predicted_label == 0
        assert result.ml_detection.malicious_probability == pytest.approx(0.0820, abs=1e-4)

        # No incident was created
        incident = get_incident_for_job(db_session, job.job_id)
        assert incident is None

    def test_orchestrate_threshold_boundary_decisions(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """Test decisions around operating threshold (P >= 0.8856 is MALICIOUS, P < 0.8856 is BENIGN)."""
        th = EXPECTED_PROD_THRESHOLD

        # Case 1: Exactly on threshold
        mock_exact = MockOnnxInferenceService(malicious_probability=th)
        orch1 = AnalysisOrchestrator(ml_service=mock_exact, ml_enabled=True, yara_enabled=False)
        job1 = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job1.job_id)
        db_session.commit()
        res1 = orch1.orchestrate_job(db_session, job1.job_id)
        db_session.commit()
        assert res1.ml_detection.predicted_class == "MALICIOUS"
        assert res1.ml_detection.predicted_label == 1
        assert len(res1.evidence_ids) == 1

        # Case 2: Immediately below threshold (epsilon 1e-5)
        mock_below = MockOnnxInferenceService(malicious_probability=th - 1e-5)
        orch2 = AnalysisOrchestrator(ml_service=mock_below, ml_enabled=True, yara_enabled=False)
        job2 = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job2.job_id)
        db_session.commit()
        res2 = orch2.orchestrate_job(db_session, job2.job_id)
        db_session.commit()
        assert res2.ml_detection.predicted_class == "BENIGN"
        assert res2.ml_detection.predicted_label == 0
        assert len(res2.evidence_ids) == 0

    def test_orchestrate_end_to_end_with_real_production_model(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """End-to-end integration test with the real production Design A ONNX model file."""
        real_svc = get_default_onnx_inference_service()
        orchestrator = AnalysisOrchestrator(
            ml_service=real_svc,
            ml_enabled=True,
            yara_enabled=False,
        )

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        assert result.analysis_status == AnalysisJobStatus.COMPLETED
        assert result.verdict is None
        assert result.risk_score is None
        assert "ml_pe" in result.modules_executed
        assert result.ml_detection is not None
        assert result.ml_detection.model_id == "sentinel-pe-lightgbm-audit-v2"
        assert result.ml_detection.artifact_hash == EXPECTED_PROD_HASH
        assert result.ml_detection.operating_threshold == pytest.approx(EXPECTED_PROD_THRESHOLD, rel=1e-4)


# ==============================================================================
# 4. Graceful Skipping and Non-PE File Handling
# ==============================================================================

class TestSkippedAndEligibilityCases:
    """Test conditions under which ML analysis is skipped without failing the pipeline."""

    def test_non_pe_file_is_gracefully_skipped(
        self,
        db_session: Session,
        clean_text_file: Path,
    ):
        """Harmless non-PE text file is recorded in modules_skipped with non_pe_file reason."""
        mock_svc = MockOnnxInferenceService()
        orchestrator = AnalysisOrchestrator(
            ml_service=mock_svc,
            ml_enabled=True,
            yara_enabled=False,
        )

        job = create_analysis_job(db_session, file_path=str(clean_text_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        assert result.analysis_status == AnalysisJobStatus.COMPLETED
        assert "ml_pe" in result.modules_skipped
        assert "ml_pe" not in result.modules_executed
        assert "ml_pe" not in result.modules_failed
        assert result.ml_detection is None

    def test_ml_disabled_by_configuration_is_skipped(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """When ml_enabled=False, PE binary is skipped cleanly."""
        mock_svc = MockOnnxInferenceService()
        orchestrator = AnalysisOrchestrator(
            ml_service=mock_svc,
            ml_enabled=False,
            yara_enabled=False,
        )

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        assert result.analysis_status == AnalysisJobStatus.COMPLETED
        assert "ml_pe" in result.modules_skipped
        assert result.ml_detection is None

    def test_job_without_file_path_is_skipped(
        self,
        db_session: Session,
    ):
        """Job submitted with only hash and no file_path skips static feature extraction."""
        orchestrator = AnalysisOrchestrator(
            ml_service=MockOnnxInferenceService(),
            ml_enabled=True,
            yara_enabled=False,
        )

        dummy_hash = "a" * 64
        job = create_analysis_job(db_session, file_hash=dummy_hash)
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        assert result.analysis_status == AnalysisJobStatus.COMPLETED
        assert "ml_pe" in result.modules_skipped


# ==============================================================================
# 5. Error Handling and Degraded State Isolation
# ==============================================================================

class TestOrchestratorMlErrorHandling:
    """Test explicit error handling and failure boundaries in ML stage."""

    def test_missing_model_fails_job_with_explicit_code(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """When ONNX model artifact is not found, job fails with ML_MODEL_NOT_FOUND."""
        nonexistent = Path("nonexistent_model.onnx")
        with pytest.raises(OnnxArtifactNotFoundError):
            OnnxInferenceService(nonexistent)

        def _raise_not_found():
            raise OnnxArtifactNotFoundError(f"Model not found at {nonexistent}")

        orchestrator = AnalysisOrchestrator(ml_enabled=True, yara_enabled=False)
        orchestrator._get_ml_service = _raise_not_found

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        assert result.analysis_status == AnalysisJobStatus.FAILED
        assert result.verdict is None  # Invariant: never fabricate BENIGN on failure
        assert "ml_pe" in result.modules_failed

        reloaded = get_analysis_job_or_raise(db_session, job.job_id)
        assert reloaded.status == AnalysisJobStatus.FAILED.value
        assert reloaded.error_code == "ML_MODEL_NOT_FOUND"

    def test_checksum_mismatch_fails_job_with_explicit_code(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """When ONNX model artifact SHA-256 differs from metadata, fails with ML_CHECKSUM_MISMATCH."""
        def _raise_mismatch():
            raise ArtifactHashMismatchError("Model artifact SHA-256 mismatch")

        orchestrator = AnalysisOrchestrator(ml_enabled=True, yara_enabled=False)
        orchestrator._get_ml_service = _raise_mismatch

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        assert result.analysis_status == AnalysisJobStatus.FAILED
        assert "ml_pe" in result.modules_failed
        reloaded = get_analysis_job_or_raise(db_session, job.job_id)
        assert reloaded.error_code == "ML_CHECKSUM_MISMATCH"

    def test_corrupt_model_fails_job(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """When ONNX model or metadata is corrupt, fails with ML_MODEL_CORRUPT."""
        def _raise_corrupt():
            raise OnnxModelCorruptError("Corrupted ONNX file")

        orchestrator = AnalysisOrchestrator(ml_enabled=True, yara_enabled=False)
        orchestrator._get_ml_service = _raise_corrupt

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        assert result.analysis_status == AnalysisJobStatus.FAILED
        assert "ml_pe" in result.modules_failed
        reloaded = get_analysis_job_or_raise(db_session, job.job_id)
        assert reloaded.error_code == "ML_MODEL_CORRUPT"

    def test_malformed_pe_file_fails_job_with_pe_malformed_file(
        self,
        db_session: Session,
        malformed_pe_file: Path,
    ):
        """Binary with MZ header that fails LIEF parsing fails with PE_MALFORMED_FILE."""
        mock_svc = MockOnnxInferenceService()
        orchestrator = AnalysisOrchestrator(
            ml_service=mock_svc,
            ml_enabled=True,
            yara_enabled=False,
        )

        job = create_analysis_job(db_session, file_path=str(malformed_pe_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        assert result.analysis_status == AnalysisJobStatus.FAILED
        assert "ml_pe" in result.modules_failed
        reloaded = get_analysis_job_or_raise(db_session, job.job_id)
        assert reloaded.error_code == "PE_MALFORMED_FILE"

    def test_pe_file_too_large_fails_job(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """File exceeding size ceiling raises PEFileTooLargeError and marks job FAILED."""
        mock_extractor = PEFeatureExtractor(max_file_size_bytes=10)  # Very low 10 bytes limit
        orchestrator = AnalysisOrchestrator(
            pe_extractor=mock_extractor,
            ml_service=MockOnnxInferenceService(),
            ml_enabled=True,
            yara_enabled=False,
        )

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        assert result.analysis_status == AnalysisJobStatus.FAILED
        assert "ml_pe" in result.modules_failed
        reloaded = get_analysis_job_or_raise(db_session, job.job_id)
        assert reloaded.error_code == "PE_FILE_TOO_LARGE"

    def test_invalid_input_dimensions_fails_job(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """Feature vector dimension mismatch raises InvalidInputDimensionError and marks job FAILED."""
        mock_svc = MockOnnxInferenceService(
            raise_on_predict=InvalidInputDimensionError("Expected 2381 features, got 100")
        )
        orchestrator = AnalysisOrchestrator(ml_service=mock_svc, ml_enabled=True, yara_enabled=False)

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        assert result.analysis_status == AnalysisJobStatus.FAILED
        assert "ml_pe" in result.modules_failed
        reloaded = get_analysis_job_or_raise(db_session, job.job_id)
        assert reloaded.error_code == "ML_INVALID_INPUT_DIMENSION"

    def test_non_finite_features_fails_job(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """Non-finite features (NaN / Inf) raise NonFiniteInputError and mark job FAILED."""
        mock_svc = MockOnnxInferenceService(
            raise_on_predict=NonFiniteInputError("Feature vector contains 2 NaNs")
        )
        orchestrator = AnalysisOrchestrator(ml_service=mock_svc, ml_enabled=True, yara_enabled=False)

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        assert result.analysis_status == AnalysisJobStatus.FAILED
        assert "ml_pe" in result.modules_failed
        reloaded = get_analysis_job_or_raise(db_session, job.job_id)
        assert reloaded.error_code == "ML_NON_FINITE_INPUT"

    def test_inference_execution_failure_fails_job(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """Underlying ONNX session execution failure marks job FAILED."""
        mock_svc = MockOnnxInferenceService(
            raise_on_predict=InferenceExecutionError("ONNX Runtime execution error")
        )
        orchestrator = AnalysisOrchestrator(ml_service=mock_svc, ml_enabled=True, yara_enabled=False)

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        assert result.analysis_status == AnalysisJobStatus.FAILED
        assert "ml_pe" in result.modules_failed
        reloaded = get_analysis_job_or_raise(db_session, job.job_id)
        assert reloaded.error_code == "ML_INFERENCE_FAILED"

    def test_degraded_response_fails_job(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """Degraded inference response marks job FAILED without falsely fabricating BENIGN."""
        mock_svc = MockOnnxInferenceService(
            is_degraded=True,
            degraded_reason="Model running in fallback degraded mode",
        )
        orchestrator = AnalysisOrchestrator(ml_service=mock_svc, ml_enabled=True, yara_enabled=False)

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        assert result.analysis_status == AnalysisJobStatus.FAILED
        assert "ml_pe" in result.modules_failed
        reloaded = get_analysis_job_or_raise(db_session, job.job_id)
        assert reloaded.error_code == "ML_INFERENCE_DEGRADED"


# ==============================================================================
# 6. Engine Coexistence, Isolation, and Idempotency
# ==============================================================================

class TestDetectionEngineCoexistenceAndIsolation:
    """Verify YARA and ML engine coexistence, fault isolation, and idempotency."""

    def test_yara_and_ml_both_match_attach_to_single_incident(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """When both YARA and ML detect threats, both evidences attach to the same Incident."""
        # 1. Mock YARA scanner matching a rule
        mock_yara = MagicMock(spec=YaraScanner)
        mock_yara.is_ready = True
        mock_rule = YaraRuleMatch(
            rule_name="ThreatAlpha",
            namespace="sentinel",
            tags=["trojan"],
            metadata={"severity": "HIGH", "description": "Test Trojan Rule"},
            matched_strings=[(0x10, "$a", b"TRIGGER")],
        )
        mock_yara.scan_file.return_value = YaraScanResult(
            file_path=str(synthetic_pe32_file),
            status=YaraScanStatus.COMPLETED,
            is_matched=True,
            matched_rules=[mock_rule],
            matched_rule_names=[mock_rule.rule_name],
            match_count=1,
            scan_duration_ms=1.5,
        )

        # 2. Mock ML service predicting MALICIOUS
        mock_ml = MockOnnxInferenceService(malicious_probability=0.9800)

        orchestrator = AnalysisOrchestrator(
            yara_scanner=mock_yara,
            yara_enabled=True,
            ml_service=mock_ml,
            ml_enabled=True,
        )

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        assert result.analysis_status == AnalysisJobStatus.COMPLETED
        assert "yara" in result.modules_executed
        assert "ml_pe" in result.modules_executed
        assert len(result.evidence_ids) == 2

        # Check evidence records in database
        ev_yara = get_detection_evidence(db_session, str(result.evidence_ids[0]))
        ev_ml = get_detection_evidence(db_session, str(result.evidence_ids[1]))

        assert ev_yara.source == "yara"
        assert ev_ml.source == "ml_pe"
        # Both evidences must point to the EXACT same Incident
        assert ev_yara.incident_id == ev_ml.incident_id

    def test_ml_failure_preserves_committed_yara_evidence(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """When YARA matches in Stage 3, and ML fails in Stage 4, YARA evidence is preserved."""
        mock_yara = MagicMock(spec=YaraScanner)
        mock_yara.is_ready = True
        mock_rule = YaraRuleMatch(
            rule_name="ThreatBeta",
            namespace="sentinel",
            tags=["ransomware"],
            metadata={"severity": "CRITICAL", "description": "Ransomware detection"},
            matched_strings=[(0x20, "$b", b"CRYPTER")],
        )
        mock_yara.scan_file.return_value = YaraScanResult(
            file_path=str(synthetic_pe32_file),
            status=YaraScanStatus.COMPLETED,
            is_matched=True,
            matched_rules=[mock_rule],
            matched_rule_names=[mock_rule.rule_name],
            match_count=1,
            scan_duration_ms=1.2,
        )

        # ML service raises runtime failure
        mock_ml = MockOnnxInferenceService(
            raise_on_predict=InferenceExecutionError("Session crashed")
        )

        orchestrator = AnalysisOrchestrator(
            yara_scanner=mock_yara,
            yara_enabled=True,
            ml_service=mock_ml,
            ml_enabled=True,
        )

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        # Job overall status is FAILED due to Stage 4 ML failure
        assert result.analysis_status == AnalysisJobStatus.FAILED
        assert "yara" in result.modules_executed
        assert "ml_pe" in result.modules_failed

        # YARA evidence remains in evidence_ids and in database!
        assert len(result.evidence_ids) == 1
        ev = get_detection_evidence(db_session, str(result.evidence_ids[0]))
        assert ev is not None
        assert ev.source == "yara"
        assert ev.indicator == "sentinel:ThreatBeta"

    def test_idempotent_evidence_persistence_on_repeated_orchestration(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """Repeated orchestration on same job/file produces identical evidence UUIDs without duplicate DB records."""
        mock_svc = MockOnnxInferenceService(malicious_probability=0.9400)
        orchestrator = AnalysisOrchestrator(
            ml_service=mock_svc,
            ml_enabled=True,
            yara_enabled=False,
        )

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        res1 = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()
        assert len(res1.evidence_ids) == 1
        uuid1 = res1.evidence_ids[0]

        # Reset job status directly to IN_PROGRESS to simulate retry
        job = get_analysis_job_or_raise(db_session, job.job_id)
        job.status = AnalysisJobStatus.IN_PROGRESS.value
        db_session.commit()

        res2 = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()
        assert len(res2.evidence_ids) == 1
        uuid2 = res2.evidence_ids[0]

        assert uuid1 == uuid2

        # Verify only 1 record exists in the database
        stmt = select(DetectionEvidence).where(DetectionEvidence.analysis_job_id == job.job_id)
        all_ev = db_session.execute(stmt).scalars().all()
        assert len(all_ev) == 1


# ==============================================================================
# 7. Schema and Serialization Conformance
# ==============================================================================

class TestSchemaValidation:
    """Verify AnalysisResult with ml_detection conforms to shared JSON Schema."""

    def test_analysis_result_with_ml_detection_validates_json_schema(
        self,
        db_session: Session,
        synthetic_pe32_file: Path,
    ):
        """AnalysisResult contract serializes cleanly and validates against analysis_result.schema.json."""
        mock_svc = MockOnnxInferenceService(malicious_probability=0.9100)
        orchestrator = AnalysisOrchestrator(
            ml_service=mock_svc,
            ml_enabled=True,
            yara_enabled=False,
        )

        job = create_analysis_job(db_session, file_path=str(synthetic_pe32_file))
        db_session.commit()
        claim_analysis_job(db_session, job.job_id)
        db_session.commit()

        result = orchestrator.orchestrate_job(db_session, job.job_id)
        db_session.commit()

        schema = load_schema("analysis_result.schema.json")
        result_dict = result.model_dump(mode="json")
        jsonschema.validate(instance=result_dict, schema=schema)

        # Assert JSON fields
        assert "ml_detection" in result_dict
        ml_d = result_dict["ml_detection"]
        assert ml_d["model_id"] == "sentinel-pe-lightgbm-audit-v2"
        assert ml_d["predicted_class"] == "MALICIOUS"
        assert ml_d["predicted_label"] == 1
        assert ml_d["artifact_hash"] == EXPECTED_PROD_HASH
