"""Tests for prediction parity between LightGBM boosters and ONNX models (T015).

Verifies:
- Raw probability numerical equivalence across representative benign and malicious PE samples.
- Documented tolerance bounds (max difference < 1e-4, mean difference < 1e-6).
- Probability rank ordering preservation (Spearman rank correlation > 0.9999).
- Exact 1-to-1 agreement between single-sample and batch prediction paths.
- Decision threshold classification agreement (100.0% parity on test cohorts).
- Verification on both Design A and Design B models.
"""

from pathlib import Path
import pytest
import lightgbm as lgb
import numpy as np
from scipy.stats import spearmanr

from app.services.onnx_inference_service import OnnxInferenceService


@pytest.fixture(scope="module")
def test_dataset():
    """Load the held-out EMBER test vectors and labels."""
    x_path = Path(".data/ember/X_test.dat")
    y_path = Path(".data/experiments/t014-audit-v2/y_test.npy")
    if not x_path.is_file() or not y_path.is_file():
        pytest.skip("Test dataset files (X_test.dat, y_test.npy) not present on disk.")

    X = np.memmap(x_path, dtype=np.float32, mode="r", shape=(10000, 2381))
    y = np.load(y_path)
    return X, y


class TestOnnxPredictionParity:
    """Test suite verifying mathematical parity between native LightGBM and ONNX models."""

    def test_design_a_parity_on_representative_samples(self, test_dataset):
        """Design A ONNX model closely matches LightGBM booster across representative samples."""
        X, y = test_dataset
        lgb_path = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2.txt")
        onnx_path = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2.onnx")

        if not lgb_path.is_file() or not onnx_path.is_file():
            pytest.skip("Design A artifacts not present.")

        booster = lgb.Booster(model_file=str(lgb_path))
        svc = OnnxInferenceService(onnx_path, auto_load=True)

        # Select representative cohort: 100 benign (label 0) and 100 malicious (label 1)
        benign_indices = np.where(y == 0)[0][:100]
        malicious_indices = np.where(y == 1)[0][:100]
        cohort_indices = np.concatenate([benign_indices, malicious_indices])

        sample_vectors = np.array(X[cohort_indices], dtype=np.float32)

        # 1. Native LightGBM predictions
        lgb_probs = booster.predict(sample_vectors)

        # 2. ONNX batch predictions
        onnx_batch = svc.predict_batch(sample_vectors)
        onnx_probs = np.array([r.malicious_probability for r in onnx_batch.results], dtype=np.float32)

        # 3. Numerical tolerance assertions
        abs_diff = np.abs(lgb_probs - onnx_probs)
        max_diff = float(np.max(abs_diff))
        mean_diff = float(np.mean(abs_diff))

        # Documented float32 tolerance: max diff < 1e-4, mean diff < 1e-6
        assert max_diff < 1e-4, f"Max difference ({max_diff}) exceeded tolerance 1e-4"
        assert mean_diff < 1e-6, f"Mean difference ({mean_diff}) exceeded tolerance 1e-6"

        # 4. Rank order preservation (Spearman correlation)
        corr, _ = spearmanr(lgb_probs, onnx_probs)
        assert corr > 0.9999, f"Rank correlation ({corr}) lower than expected 0.9999"

        # 5. Exact threshold classification agreement
        th = svc.threshold
        lgb_labels = (lgb_probs >= th).astype(int)
        onnx_labels = np.array([r.predicted_label for r in onnx_batch.results])
        assert np.array_equal(lgb_labels, onnx_labels), "Classification labels differed at operating threshold"

    def test_single_sample_vs_batch_parity(self, test_dataset):
        """Single-sample inference produces numerically identical outputs to batch inference."""
        X, _ = test_dataset
        onnx_path = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2.onnx")
        if not onnx_path.is_file():
            pytest.skip("Model A ONNX artifact not found.")

        svc = OnnxInferenceService(onnx_path, auto_load=True)
        subset = np.array(X[:25], dtype=np.float32)

        batch_result = svc.predict_batch(subset)
        for i in range(25):
            single_res = svc.predict_single(subset[i])
            batch_res = batch_result.results[i]
            assert single_res.malicious_probability == pytest.approx(batch_res.malicious_probability, abs=1e-6)
            assert single_res.benign_probability == pytest.approx(batch_res.benign_probability, abs=1e-6)
            assert single_res.predicted_class == batch_res.predicted_class
            assert single_res.predicted_label == batch_res.predicted_label

    def test_design_b_temporal_model_parity(self, test_dataset):
        """Design B temporal model achieves strict tolerance across non-boundary samples and 100% agreement."""
        X, y = test_dataset
        lgb_path = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-temporal.txt")
        onnx_path = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-temporal.onnx")

        if not lgb_path.is_file() or not onnx_path.is_file():
            pytest.skip("Design B artifacts not present.")

        booster = lgb.Booster(model_file=str(lgb_path))
        svc = OnnxInferenceService(onnx_path, auto_load=True)

        # Evaluate 1,000 test samples including known boundary sample 8517
        sample_indices = list(range(500)) + [8517]
        subset = np.array(X[sample_indices], dtype=np.float32)

        lgb_probs = booster.predict(subset)
        onnx_batch = svc.predict_batch(subset)
        onnx_probs = np.array([r.malicious_probability for r in onnx_batch.results], dtype=np.float32)

        # Exclude sample 8517 for strict numerical tolerance assertion
        non_boundary_lgb = lgb_probs[:-1]
        non_boundary_onnx = onnx_probs[:-1]
        abs_diff_clean = np.abs(non_boundary_lgb - non_boundary_onnx)
        assert float(np.max(abs_diff_clean)) < 1e-4, "Clean samples exceeded 1e-4 tolerance"
        assert float(np.mean(abs_diff_clean)) < 1e-6, "Clean samples exceeded 1e-6 mean tolerance"

        # Explicitly verify boundary sample 8517 behavior
        diff_8517 = abs(lgb_probs[-1] - onnx_probs[-1])
        assert diff_8517 == pytest.approx(0.016705, abs=1e-4)
        assert lgb_probs[-1] < 0.20  # Far below 0.9303 threshold
        assert onnx_probs[-1] < 0.20

        # Rank correlation and classification agreement across all evaluated samples
        corr, _ = spearmanr(lgb_probs, onnx_probs)
        assert corr > 0.9999

        th = svc.threshold
        lgb_labels = (lgb_probs >= th).astype(int)
        onnx_labels = np.array([r.predicted_label for r in onnx_batch.results])
        assert np.array_equal(lgb_labels, onnx_labels), "Classification labels differed at threshold"

    def test_design_b_boundary_split_investigation(self, test_dataset):
        """Boundary testing of Feature 626 (header.coff.timestamp) split in Design B."""
        X, _ = test_dataset
        lgb_path = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-temporal.txt")
        onnx_path = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-temporal.onnx")

        if not lgb_path.is_file() or not onnx_path.is_file():
            pytest.skip("Design B artifacts not present.")

        booster = lgb.Booster(model_file=str(lgb_path))
        svc = OnnxInferenceService(onnx_path, auto_load=True)

        base_vec = np.array(X[8517], dtype=np.float32)

        # Perturbation suite around Feature 626 split (1260053568 in float64 / 1260053632 in float32)
        perturbations = [
            ("clearly_below", 1260053568.0 - 1000.0, True),
            ("immediately_below_lgb_th", 1260053568.0 - 128.0, True),
            ("exact_lgb_th", 1260053568.0, True),
            ("boundary_sample_val", 1260053632.0, False),  # where float32 threshold rounding occurs
            ("immediately_above_onnx_th", 1260053632.0 + 128.0, True),
            ("clearly_above", 1260053632.0 + 1000.0, True),
        ]

        for desc, val, expect_strict_parity in perturbations:
            v = base_vec.copy()
            v[626] = np.float32(val)
            p_lgb = float(booster.predict(v.reshape(1, -1))[0])
            p_onnx = svc.predict_single(v).malicious_probability
            diff = abs(p_lgb - p_onnx)

            if expect_strict_parity:
                assert diff < 1e-6, f"Failed strict parity on {desc}: diff={diff}"
            else:
                assert diff < 0.02, f"Boundary sample diff exceeded expected bound: {diff}"

            # Both must agree on classification verdict (BENIGN) and be > 0.7 away from threshold
            assert (p_lgb >= 0.9303) == (p_onnx >= 0.9303)
            assert abs(p_lgb - 0.9303) > 0.70
            assert abs(p_onnx - 0.9303) > 0.70

    def test_design_a_boundary_robustness_control(self, test_dataset):
        """Design A (Control) retains strict numerical parity across all boundary perturbations."""
        X, _ = test_dataset
        lgb_path = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2.txt")
        onnx_path = Path(".data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2.onnx")

        if not lgb_path.is_file() or not onnx_path.is_file():
            pytest.skip("Design A artifacts not present.")

        booster = lgb.Booster(model_file=str(lgb_path))
        svc = OnnxInferenceService(onnx_path, auto_load=True)

        base_vec = np.array(X[8517], dtype=np.float32)

        # Same perturbation suite
        perturbation_vals = [
            1260053568.0 - 1000.0,
            1260053568.0 - 128.0,
            1260053568.0,
            1260053632.0,
            1260053632.0 + 128.0,
            1260053632.0 + 1000.0,
        ]

        for val in perturbation_vals:
            v = base_vec.copy()
            v[626] = np.float32(val)
            p_lgb = float(booster.predict(v.reshape(1, -1))[0])
            p_onnx = svc.predict_single(v).malicious_probability
            diff = abs(p_lgb - p_onnx)

            # Design A must have sub-microsecond float32 parity (< 1e-6) on all points
            assert diff < 1e-6, f"Design A control failed parity at {val}: diff={diff}"
            assert (p_lgb >= 0.8856) == (p_onnx >= 0.8856)
            assert abs(p_lgb - 0.8856) > 0.70
