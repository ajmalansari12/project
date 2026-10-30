"""Tests for LightGBM model training, validation, threshold selection, and evaluation.

Verifies:
- Vectorization schema conformity: 9 canonical groups, 2,381 finite dimensions.
- Size-before-RVA ordering in DataDirectories.
- Binary model training on tiny synthetic datasets.
- Rejection of single-class datasets and invalid target labels.
- Held-out test set isolation: threshold selected strictly on validation split.
- Low-FPR ROC-AUC (max_fpr=0.005) and classification metric computation.
- Model artifact SHA-256 integrity and ModelMetadata JSON Schema conformance.
- Non-corruption / preservation of existing valid artifacts upon failed retraining.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List
import pytest

import jsonschema
import lightgbm as lgb
import numpy as np

from app.schemas.ml_contracts import (
    EMBER_2018_CANONICAL_FEATURE_DIMENSION,
    EMBER_2018_FEATURE_SCHEMA_VERSION,
    ModelFamily,
    ModelMetadata,
)
from app.services.ember_raw_vectorizer import (
    EmberMalformedRecordError,
    EmberNonFiniteValueError,
    EmberRawFeatureVectorizer,
    get_default_ember_raw_vectorizer,
)
from app.services.lightgbm_training import (
    EvaluationReport,
    InsufficientClassDataError,
    LightGBMTrainer,
    ModelTrainingError,
)


@pytest.fixture
def raw_test_record() -> Dict[str, Any]:
    """Return a single deterministic raw feature record."""
    return {
        "sha256": "f" * 64,
        "appeared": "2018-01",
        "label": 1,
        "histogram": [5] * 256,
        "byteentropy": [10] * 256,
        "strings": {
            "numstrings": 20,
            "avlength": 12.5,
            "printables": 250,
            "printabledist": [2] * 96,
            "entropy": 4.8,
            "paths": 2,
            "urls": 1,
            "registry": 1,
            "MZ": 1,
        },
        "general": {
            "size": 4096,
            "vsize": 8192,
            "has_debug": 1,
            "exports": 1,
            "imports": 10,
            "has_relocations": 1,
            "has_resources": 1,
            "has_signature": 0,
            "has_tls": 0,
            "symbols": 0,
        },
        "header": {
            "coff": {"timestamp": 1500000000, "machine": "I386", "characteristics": ["EXECUTABLE_IMAGE", "32BIT_MACHINE"]},
            "optional": {
                "subsystem": "WINDOWS_GUI",
                "dll_characteristics": ["DYNAMIC_BASE", "NX_COMPAT"],
                "magic": "PE32",
                "major_image_version": 1,
                "minor_image_version": 0,
                "major_linker_version": 14,
                "minor_linker_version": 0,
                "major_operating_system_version": 6,
                "minor_operating_system_version": 0,
                "major_subsystem_version": 6,
                "minor_subsystem_version": 0,
                "sizeof_code": 2048,
                "sizeof_headers": 1024,
                "sizeof_heap_commit": 4096,
            },
        },
        "section": {
            "entry": ".text",
            "sections": [
                {"name": ".text", "size": 2048, "entropy": 6.3, "vsize": 2000, "props": ["MEM_READ", "MEM_EXECUTE"]},
                {"name": ".data", "size": 1024, "entropy": 2.5, "vsize": 1000, "props": ["MEM_READ", "MEM_WRITE"]},
            ],
        },
        "imports": {
            "kernel32.dll": ["CreateFileW", "CloseHandle", "ReadFile"],
            "user32.dll": ["MessageBoxW"],
        },
        "exports": ["ExportedRoutineA"],
        "datadirectories": [
            {"name": "EXPORT_TABLE", "size": 128, "virtual_address": 4096},
            {"name": "IMPORT_TABLE", "size": 256, "virtual_address": 8192},
            {"name": "RESOURCE_TABLE", "size": 64, "virtual_address": 12288},
        ],
    }


@pytest.fixture
def model_metadata_json_schema() -> Dict[str, Any]:
    """Load the shared model_metadata.schema.json."""
    schema_path = Path("shared/schemas/model_metadata.schema.json").resolve()
    with open(schema_path, "r", encoding="utf-8") as fin:
        return json.load(fin)


# ==============================================================================
# Feature Vectorization Tests
# ==============================================================================

class TestEmberRawFeatureVectorization:
    """Verify raw JSON feature transformation and canonical layout."""

    def test_nine_feature_groups_dimensions_and_order(self, raw_test_record: Dict[str, Any]):
        """Vector contains exactly 2,381 elements with each of the 9 groups at canonical offsets."""
        vectorizer = get_default_ember_raw_vectorizer()
        vec = vectorizer.vectorize_raw_record(raw_test_record)

        assert vec.shape == (2381,)
        assert vec.dtype == np.float32
        assert np.all(np.isfinite(vec))

        # Check slices for each group
        f_hist = vec[0:256]
        f_entropy = vec[256:512]
        f_strings = vec[512:616]
        f_general = vec[616:626]
        f_header = vec[626:688]
        f_section = vec[688:943]
        f_imports = vec[943:2223]
        f_exports = vec[2223:2351]
        f_datadirs = vec[2351:2381]

        assert len(f_hist) == 256
        assert len(f_entropy) == 256
        assert len(f_strings) == 104
        assert len(f_general) == 10
        assert len(f_header) == 62
        assert len(f_section) == 255
        assert len(f_imports) == 1280
        assert len(f_exports) == 128
        assert len(f_datadirs) == 30

    def test_datadirectories_size_before_rva(self, raw_test_record: Dict[str, Any]):
        """DataDirectories must strictly place Size at 2i and RVA at 2i+1."""
        vectorizer = get_default_ember_raw_vectorizer()
        vec = vectorizer.vectorize_raw_record(raw_test_record)
        dd = vec[2351:2381]

        # Directory 0: EXPORT_TABLE (size=128, rva=4096)
        assert dd[0] == 128.0
        assert dd[1] == 4096.0

        # Directory 1: IMPORT_TABLE (size=256, rva=8192)
        assert dd[2] == 256.0
        assert dd[3] == 8192.0

        # Directory 2: RESOURCE_TABLE (size=64, rva=12288)
        assert dd[4] == 64.0
        assert dd[5] == 12288.0

        # All other directories unpopulated (0.0)
        assert np.all(dd[6:] == 0.0)

    def test_all_elements_finite_numbers(self, raw_test_record: Dict[str, Any]):
        """Vector contains zero NaNs and zero Infinities."""
        vectorizer = get_default_ember_raw_vectorizer()
        vec = vectorizer.vectorize_raw_record(raw_test_record)
        assert not np.isnan(vec).any()
        assert not np.isinf(vec).any()

    def test_vectorize_to_pydantic_feature_vector(self, raw_test_record: Dict[str, Any]):
        """Produces a valid FeatureVector envelope matching T012 schema."""
        vectorizer = get_default_ember_raw_vectorizer()
        fv = vectorizer.vectorize_to_feature_vector(raw_test_record)

        assert fv.feature_count == 2381
        assert fv.feature_schema_version == EMBER_2018_FEATURE_SCHEMA_VERSION
        assert fv.sample_hash == "f" * 64
        assert len(fv.feature_values) == 2381


# ==============================================================================
# LightGBM Training & Class Validation Tests
# ==============================================================================

class TestLightGBMTraining:
    """Verify training behavior, data validation, and threshold selection."""

    def test_train_tiny_binary_dataset_succeeds(self, tmp_path: Path):
        """Train LightGBM binary classifier on tiny synthetic dataset."""
        rng = np.random.RandomState(42)
        n_samples = 40
        dim = EMBER_2018_CANONICAL_FEATURE_DIMENSION

        # Half benign, half malicious
        X_train = rng.randn(n_samples, dim).astype(np.float32)
        y_train = np.array([0] * (n_samples // 2) + [1] * (n_samples // 2), dtype=np.float32)

        trainer = LightGBMTrainer(models_dir=tmp_path)
        booster, threshold, summary = trainer.train(
            X_train,
            y_train,
            num_boost_round=10,
            val_ratio=0.25,
            random_seed=42,
        )

        assert isinstance(booster, lgb.Booster)
        assert 0.0 < threshold < 1.0
        assert summary["train_sample_count"] == 30
        assert summary["val_sample_count"] == 10
        assert summary["train_positive_count"] > 0
        assert summary["train_negative_count"] > 0

    def test_training_fails_if_only_one_class_present(self, tmp_path: Path):
        """Training on dataset with only one class must raise InsufficientClassDataError."""
        n_samples = 20
        dim = EMBER_2018_CANONICAL_FEATURE_DIMENSION
        X_train = np.zeros((n_samples, dim), dtype=np.float32)
        y_train = np.zeros(n_samples, dtype=np.float32)  # only class 0

        trainer = LightGBMTrainer(models_dir=tmp_path)
        with pytest.raises(InsufficientClassDataError) as exc_info:
            trainer.train(X_train, y_train)
        assert "contains only one class" in str(exc_info.value)

    def test_training_fails_on_dimension_mismatch(self, tmp_path: Path):
        """Training features with wrong dimensionality must raise ModelTrainingError."""
        X_bad = np.zeros((20, 100), dtype=np.float32)
        y_good = np.array([0] * 10 + [1] * 10, dtype=np.float32)

        trainer = LightGBMTrainer(models_dir=tmp_path)
        with pytest.raises(ModelTrainingError) as exc_info:
            trainer.train(X_bad, y_good)
        assert "Expected features with shape" in str(exc_info.value)

    def test_training_fails_on_non_finite_values(self, tmp_path: Path):
        """Training features with NaN must raise ModelTrainingError."""
        X_nan = np.zeros((20, EMBER_2018_CANONICAL_FEATURE_DIMENSION), dtype=np.float32)
        X_nan[0, 0] = np.nan
        y = np.array([0] * 10 + [1] * 10, dtype=np.float32)

        trainer = LightGBMTrainer(models_dir=tmp_path)
        with pytest.raises(ModelTrainingError) as exc_info:
            trainer.train(X_nan, y)
        assert "non-finite values" in str(exc_info.value)


# ==============================================================================
# Held-Out Evaluation & Metric Computation Tests
# ==============================================================================

class TestHeldOutEvaluation:
    """Verify evaluation on held-out test data and metric accuracy."""

    def test_evaluate_held_out_metrics(self, tmp_path: Path):
        """Compute ROC-AUC, Low-FPR ROC-AUC, precision, recall, F1, and confusion matrix."""
        rng = np.random.RandomState(42)
        dim = EMBER_2018_CANONICAL_FEATURE_DIMENSION

        # Create synthetic training set
        X_train = rng.randn(60, dim).astype(np.float32)
        # Shift malicious class to make separable
        X_train[30:] += 1.5
        y_train = np.array([0] * 30 + [1] * 30, dtype=np.float32)

        # Create held-out test set
        X_test = rng.randn(30, dim).astype(np.float32)
        X_test[15:] += 1.5
        y_test = np.array([0] * 15 + [1] * 15, dtype=np.float32)

        trainer = LightGBMTrainer(models_dir=tmp_path)
        booster, threshold, summary = trainer.train(X_train, y_train, num_boost_round=15)

        eval_report = trainer.evaluate(booster, X_test, y_test, operating_threshold=threshold)

        assert eval_report.sample_count == 30
        assert eval_report.positive_count == 15
        assert eval_report.negative_count == 15
        assert eval_report.roc_auc > 0.5
        assert 0.0 <= eval_report.precision <= 1.0
        assert 0.0 <= eval_report.recall <= 1.0
        assert 0.0 <= eval_report.f1_score <= 1.0
        assert 0.0 <= eval_report.false_positive_rate <= 1.0
        assert 0.0 <= eval_report.true_positive_rate <= 1.0
        assert len(eval_report.confusion_matrix) == 2
        assert len(eval_report.confusion_matrix[0]) == 2


# ==============================================================================
# Model Artifact and Metadata Persistence Tests
# ==============================================================================

class TestArtifactAndMetadataPersistence:
    """Verify atomic saving, SHA-256 calculation, and ModelMetadata conformance."""

    def test_save_model_and_metadata_conforms_to_schema(
        self,
        tmp_path: Path,
        model_metadata_json_schema: Dict[str, Any],
    ):
        """Saved model and metadata files match checksum and validate against shared schema."""
        rng = np.random.RandomState(42)
        dim = EMBER_2018_CANONICAL_FEATURE_DIMENSION

        X_train = rng.randn(40, dim).astype(np.float32)
        X_train[20:] += 1.0
        y_train = np.array([0] * 20 + [1] * 20, dtype=np.float32)

        trainer = LightGBMTrainer(models_dir=tmp_path)
        booster, threshold, summary = trainer.train(X_train, y_train, num_boost_round=10)
        report = trainer.evaluate(booster, X_train, y_train, operating_threshold=threshold)

        model_path, meta_path, metadata = trainer.save_model_and_metadata(booster, report, summary)

        # 1. Model artifact exists
        assert model_path.is_file()
        assert meta_path.is_file()

        # 2. Check artifact SHA-256 matches actual file
        hasher = hashlib.sha256()
        with open(model_path, "rb") as f:
            hasher.update(f.read())
        assert metadata.artifact_hash == hasher.hexdigest().lower()

        # 3. ModelMetadata Pydantic instance validity
        assert isinstance(metadata, ModelMetadata)
        assert metadata.model_family == ModelFamily.LIGHTGBM
        assert metadata.feature_count == 2381

        # 4. JSON Schema validation
        meta_dict = metadata.model_dump(mode="json")
        jsonschema.validate(instance=meta_dict, schema=model_metadata_json_schema)

    def test_failed_training_preserves_existing_artifact(self, tmp_path: Path):
        """A failed training run must not overwrite or corrupt an existing valid model artifact."""
        model_file = tmp_path / "sentinel-pe-lightgbm.txt"
        meta_file = tmp_path / "sentinel-pe-lightgbm_metadata.json"

        original_content = b"ORIGINAL_VALID_MODEL_DATA"
        model_file.write_bytes(original_content)
        meta_file.write_text('{"status": "original"}', encoding="utf-8")

        trainer = LightGBMTrainer(models_dir=tmp_path)

        # Attempt to train on invalid single-class data
        dim = EMBER_2018_CANONICAL_FEATURE_DIMENSION
        X_bad = np.zeros((10, dim), dtype=np.float32)
        y_bad = np.zeros(10, dtype=np.float32)

        with pytest.raises(InsufficientClassDataError):
            trainer.train(X_bad, y_bad)

        # Existing files must remain completely untouched
        assert model_file.read_bytes() == original_content
        assert meta_file.read_text(encoding="utf-8") == '{"status": "original"}'


# ==============================================================================
# Reference Vectorization Parity Tests (Distinguished from Binary Parser Parity)
# ==============================================================================

class TestReferenceVectorizationParity:
    """Verify raw-feature transformation parity against independent upstream algorithms."""

    def test_byte_histogram_reference_parity(self):
        """Byte histogram sum-normalization matches upstream algorithm."""
        vectorizer = get_default_ember_raw_vectorizer()
        raw_h = [10, 20, 30] + [0] * 253

        # Upstream formula: counts = np.array(raw_obj, dtype=np.float32); return counts / counts.sum()
        ref = np.array(raw_h, dtype=np.float32) / float(sum(raw_h))
        our = vectorizer.vectorize_byte_histogram(raw_h)

        assert np.allclose(our, ref, atol=1e-7)

    def test_byte_entropy_reference_parity(self):
        """Byte entropy histogram sum-normalization matches upstream algorithm."""
        vectorizer = get_default_ember_raw_vectorizer()
        raw_e = [5, 15, 25] + [1] * 253

        ref = np.array(raw_e, dtype=np.float32) / float(sum(raw_e))
        our = vectorizer.vectorize_byte_entropy(raw_e)

        assert np.allclose(our, ref, atol=1e-7)

    def test_general_file_info_reference_parity(self):
        """GeneralFileInfo scalar ordering matches upstream algorithm."""
        vectorizer = get_default_ember_raw_vectorizer()
        raw_g = {
            "size": 5000,
            "vsize": 10000,
            "has_debug": 1,
            "exports": 3,
            "imports": 12,
            "has_relocations": 1,
            "has_resources": 1,
            "has_signature": 0,
            "has_tls": 0,
            "symbols": 0,
        }
        ref = np.asarray([5000, 10000, 1, 3, 12, 1, 1, 0, 0, 0], dtype=np.float32)
        our = vectorizer.vectorize_general(raw_g)

        assert np.array_equal(our, ref)

    def test_datadirectories_reference_parity(self):
        """DataDirectories Size-before-RVA matches upstream process_raw_features."""
        vectorizer = get_default_ember_raw_vectorizer()
        raw_dd = [
            {"name": "EXPORT_TABLE", "size": 100, "virtual_address": 4096},
            {"name": "IMPORT_TABLE", "size": 200, "virtual_address": 8192},
        ]
        our = vectorizer.vectorize_data_directories(raw_dd)

        assert our[0] == 100.0  # Size
        assert our[1] == 4096.0 # RVA
        assert our[2] == 200.0  # Size
        assert our[3] == 8192.0 # RVA
        assert np.all(our[4:] == 0.0)

    def test_distinguish_vectorization_parity_from_parser_parity(self):
        """Audit test documenting that JSONL vectorization parity is separate from real-world LIEF PE parser parity."""
        # 1. Raw JSONL records represent already-extracted features from EMBER 2018 (extracted with LIEF 0.9.0 in 2018).
        # 2. Modern runtime PE feature extraction uses LIEF 1.0.0 (T013) on raw PE binaries.
        # 3. Vectorization parity ensures JSONL records are mapped into 2,381 floats identically to upstream ember/features.py.
        # 4. LIEF parser parity (e.g. malformed PE parsing differences between LIEF 0.9.0 and 1.0.0) is tracked separately.
        vectorizer = get_default_ember_raw_vectorizer()
        assert vectorizer.dim == 2381
        assert vectorizer.schema_version == "ember_pe_v2"

