"""Tests for ONNX model inference service (T015).

Verifies:
- Session initialization and model health lifecycle.
- Single-sample inference (latency, probabilities, threshold classification).
- Batch inference (latency, throughput, per-sample result consistency).
- Input tensor dimension validation (rejection of shape mismatches and ranks != 1 or 2).
- Non-finite input rejection (NaN, Inf, -Inf).
- Probability output range and consistency (benign + malicious == 1.0 within float tolerance).
- Artifact integrity (SHA-256 mismatch detection and corrupt artifact handling).
- Degraded mode behavior preventing silent BENIGN misclassification.
"""

import json
from pathlib import Path
import pytest
import numpy as np

from app.schemas.ml_contracts import EMBER_2018_CANONICAL_FEATURE_DIMENSION
from app.services.onnx_inference_service import (
    ArtifactHashMismatchError,
    BatchInferenceResult,
    InferenceResult,
    InvalidInputDimensionError,
    InvalidModelMetadataError,
    ModelHealthStatus,
    NonFiniteInputError,
    OnnxArtifactNotFoundError,
    OnnxInferenceService,
    OnnxModelCorruptError,
)


@pytest.fixture
def model_a_path():
    """Path to the primary Design A ONNX model."""
    path = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2.onnx")
    if not path.is_file():
        pytest.skip(f"Model A ONNX artifact not found at {path}")
    return path


@pytest.fixture
def model_b_path():
    """Path to the secondary temporal Design B ONNX model."""
    path = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-temporal.onnx")
    if not path.is_file():
        pytest.skip(f"Model B ONNX artifact not found at {path}")
    return path


class TestOnnxInferenceService:
    """Test suite for OnnxInferenceService."""

    def test_load_model_a_session_and_health_status(self, model_a_path):
        """Model A loads cleanly and reports HEALTHY status with verified threshold."""
        svc = OnnxInferenceService(model_a_path, auto_load=True)
        assert svc.is_loaded
        assert svc.health_status == ModelHealthStatus.HEALTHY
        assert svc.threshold == pytest.approx(0.8856, rel=1e-4)

        health = svc.get_health_status()
        assert health["status"] == "healthy"
        assert health["is_loaded"] is True
        assert health["expected_features"] == EMBER_2018_CANONICAL_FEATURE_DIMENSION

    def test_single_sample_inference(self, model_a_path):
        """Single-sample inference evaluates 2,381 features and produces structured result."""
        svc = OnnxInferenceService(model_a_path, auto_load=True)
        sample = np.zeros(EMBER_2018_CANONICAL_FEATURE_DIMENSION, dtype=np.float32)

        result = svc.predict_single(sample)
        assert isinstance(result, InferenceResult)
        assert 0.0 <= result.malicious_probability <= 1.0
        assert 0.0 <= result.benign_probability <= 1.0
        assert result.benign_probability + result.malicious_probability == pytest.approx(1.0, abs=1e-4)
        assert result.predicted_class in ("BENIGN", "MALICIOUS")
        assert result.predicted_label in (0, 1)
        assert result.operating_threshold == pytest.approx(0.8856, rel=1e-4)
        assert result.inference_duration_ms > 0.0
        assert not result.is_degraded

    def test_batch_inference_consistency(self, model_a_path):
        """Batch inference matches individual single-sample inferences within floating point tolerance."""
        svc = OnnxInferenceService(model_a_path, auto_load=True)
        np.random.seed(42)
        batch_size = 5
        batch_data = np.random.randn(batch_size, EMBER_2018_CANONICAL_FEATURE_DIMENSION).astype(np.float32)

        batch_result = svc.predict_batch(batch_data)
        assert isinstance(batch_result, BatchInferenceResult)
        assert batch_result.sample_count == batch_size
        assert len(batch_result.results) == batch_size
        assert batch_result.total_duration_ms > 0.0
        assert batch_result.throughput_samples_per_sec > 0.0

        for i in range(batch_size):
            single_res = svc.predict_single(batch_data[i])
            batch_sample_res = batch_result.results[i]
            assert batch_sample_res.malicious_probability == pytest.approx(single_res.malicious_probability, abs=1e-5)
            assert batch_sample_res.predicted_class == single_res.predicted_class
            assert batch_sample_res.predicted_label == single_res.predicted_label

    def test_threshold_separation_and_override(self, model_a_path):
        """Threshold logic is distinct from raw probabilities and respects caller overrides."""
        svc = OnnxInferenceService(model_a_path, auto_load=True)
        sample = np.zeros(EMBER_2018_CANONICAL_FEATURE_DIMENSION, dtype=np.float32)

        # Predict with threshold = 0.0 -> must be MALICIOUS
        res_zero = svc.predict_single(sample, threshold=0.0)
        assert res_zero.predicted_class == "MALICIOUS"
        assert res_zero.predicted_label == 1
        assert res_zero.operating_threshold == 0.0

        # Predict with threshold = 1.0 -> must be BENIGN (unless prob == 1.0)
        res_one = svc.predict_single(sample, threshold=1.0)
        assert res_one.predicted_class == "BENIGN"
        assert res_one.predicted_label == 0
        assert res_one.operating_threshold == 1.0

        # Underlying raw probabilities must remain identical regardless of threshold
        assert res_zero.malicious_probability == res_one.malicious_probability

    def test_rejection_of_dimension_mismatch(self, model_a_path):
        """Inputs with feature count != 2,381 or invalid tensor ranks are rejected."""
        svc = OnnxInferenceService(model_a_path, auto_load=True)

        # Under-dimensioned
        too_short = np.zeros(2000, dtype=np.float32)
        with pytest.raises(InvalidInputDimensionError, match="has 2000 dimensions; expected exactly 2381"):
            svc.predict_single(too_short)

        # Over-dimensioned
        too_long = np.zeros(2500, dtype=np.float32)
        with pytest.raises(InvalidInputDimensionError, match="has 2500 dimensions; expected exactly 2381"):
            svc.predict_single(too_long)

        # Invalid rank (3D)
        three_d = np.zeros((2, 2, EMBER_2018_CANONICAL_FEATURE_DIMENSION), dtype=np.float32)
        with pytest.raises(InvalidInputDimensionError, match="Input tensor must be 1D or 2D"):
            svc.predict_batch(three_d)

    def test_rejection_of_non_finite_inputs(self, model_a_path):
        """Feature vectors containing NaN, Inf, or -Inf are rejected with NonFiniteInputError."""
        svc = OnnxInferenceService(model_a_path, auto_load=True)

        # Vector with NaN
        sample_nan = np.zeros(EMBER_2018_CANONICAL_FEATURE_DIMENSION, dtype=np.float32)
        sample_nan[100] = np.nan
        with pytest.raises(NonFiniteInputError, match="contains non-finite values"):
            svc.predict_single(sample_nan)

        # Vector with +Inf
        sample_inf = np.zeros(EMBER_2018_CANONICAL_FEATURE_DIMENSION, dtype=np.float32)
        sample_inf[200] = np.inf
        with pytest.raises(NonFiniteInputError, match="contains non-finite values"):
            svc.predict_single(sample_inf)

        # Vector with -Inf
        sample_neginf = np.zeros(EMBER_2018_CANONICAL_FEATURE_DIMENSION, dtype=np.float32)
        sample_neginf[300] = -np.inf
        with pytest.raises(NonFiniteInputError, match="contains non-finite values"):
            svc.predict_single(sample_neginf)

    def test_missing_model_file_raises_not_found(self, tmp_path):
        """Attempting to load a nonexistent ONNX file raises OnnxArtifactNotFoundError."""
        missing_path = tmp_path / "nonexistent_model.onnx"
        with pytest.raises(OnnxArtifactNotFoundError, match="ONNX model file not found"):
            OnnxInferenceService(missing_path, auto_load=True)

    def test_corrupt_model_file_raises_corrupt_error(self, tmp_path):
        """A corrupt or truncated ONNX file raises OnnxModelCorruptError."""
        corrupt_path = tmp_path / "corrupt_model.onnx"
        corrupt_path.write_bytes(b"NOT_A_VALID_ONNX_FILE_GARBAGE_BYTES")
        with pytest.raises(OnnxModelCorruptError, match="ONNX Runtime failed to load model"):
            OnnxInferenceService(corrupt_path, verify_hash=False, auto_load=True)

    def test_sha256_hash_mismatch_detected(self, model_a_path, tmp_path):
        """A modified ONNX file with non-matching metadata hash raises ArtifactHashMismatchError."""
        # Copy model to tmp
        tampered_onnx = tmp_path / "tampered.onnx"
        tampered_onnx.write_bytes(model_a_path.read_bytes() + b"\x00")  # alter bytes

        tampered_meta = tmp_path / "tampered_metadata.json"
        meta_content = {
            "model_id": "tampered-test",
            "model_version": "1.0.0",
            "artifact_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "training_config": {"operating_threshold": 0.8856},
        }
        tampered_meta.write_text(json.dumps(meta_content))

        with pytest.raises(ArtifactHashMismatchError, match="Model artifact SHA-256 mismatch"):
            OnnxInferenceService(tampered_onnx, metadata_path=tampered_meta, verify_hash=True, auto_load=True)

    def test_degraded_response_never_fabricates_benign_verdict(self, model_a_path):
        """Degraded mode returns explicit error status and negative probabilities, never BENIGN."""
        svc = OnnxInferenceService(model_a_path, auto_load=True)
        degraded = svc.get_degraded_response("Model session crashed or pipeline degraded.")

        assert degraded.is_degraded is True
        assert degraded.predicted_class == "ERROR_DEGRADED"
        assert degraded.predicted_label == -1
        assert degraded.malicious_probability == -1.0
        assert degraded.benign_probability == -1.0
        assert degraded.degraded_reason == "Model session crashed or pipeline degraded."
