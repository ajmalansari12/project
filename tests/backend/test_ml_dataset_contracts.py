"""Automated tests for ML dataset, feature vector, and model metadata contracts (T012).

Tests:
- JSON Schema and Pydantic contract conformance for sample records, manifests, feature vectors, and model metadata.
- Canonical lowercase SHA-256 digest validation (^[a-f0-9]{64}$) and rejection of uppercase/malformed hashes.
- Rejection of machine-specific absolute paths, UNC paths, and traversal segments in relative_path.
- Rejection of unexpected properties (strict schema validation).
- Label mapping policy, exclusion of unlabeled samples (-1), and rejection of unknown labels.
- Missing-value policy consistency: JSON-safe null encoding for native_nan, rejection of null for zero_fill/mean_impute.
- Rejection of non-finite float values (NaN, +Inf, -Inf).
- Restriction of model_family to approved 'lightgbm'.
- Manifest sample_count and split_counts reconciliation.
- Dataset quality checks: duplicate sample detection, cross-split data-leakage detection, manifest count checks.
- Non-destructive, deterministic reporting.
"""

from datetime import datetime, timezone
import json
import math
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

from app.schemas.ml_contracts import (
    DEFAULT_CLASS_DEFINITIONS,
    DEFAULT_EMBER_LABEL_MAPPING,
    EMBER_2018_ARCHIVE_NAME,
    EMBER_2018_ARCHIVE_SHA256,
    EMBER_2018_ARCHIVE_URL,
    EMBER_2018_CANONICAL_FEATURE_DIMENSION,
    EMBER_2018_DATASET_NAME,
    EMBER_2018_DATASET_VERSION,
    EMBER_2018_FEATURE_SCHEMA_VERSION,
    EMBER_2018_FEATURE_VERSION,
    EMBER_2018_UPSTREAM_REPOSITORY_URL,
    DatasetManifest,
    DatasetSampleRecord,
    DatasetSplit,
    FeatureVector,
    MissingValueStrategy,
    ModelFamily,
    ModelMetadata,
    ModelMetrics,
    SplitCounts,
    TargetClass,
    TaskType,
    normalize_source_label,
)
from app.services.dataset_validator import DatasetValidationReport, DatasetValidator

SCHEMAS_DIR = Path(__file__).resolve().parent.parent.parent / "shared" / "schemas"


def load_schema(schema_filename: str) -> dict:
    """Load a JSON Schema file from shared/schemas/."""
    schema_path = SCHEMAS_DIR / schema_filename
    assert schema_path.exists(), f"Schema file not found: {schema_path}"
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ==============================================================================
# 1. DatasetSampleRecord Tests
# ==============================================================================

def test_valid_dataset_sample_record_conforms_to_schema() -> None:
    """Verify that a valid DatasetSampleRecord passes Pydantic and JSON Schema validation."""
    sample = DatasetSampleRecord(
        sample_id="ember-sample-001",
        sample_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        dataset_name="ember",
        dataset_version="2018",
        target_label=1,
        split=DatasetSplit.TRAIN,
        feature_schema_version="ember_pe_v1",
        source_record_id="ember-upstream-001",
        source_label=1,
        label_provenance="avclass_consensus",
        relative_path="samples/2018/ember-sample-001.bin",
        collected_at=datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc),
    )

    data = sample.model_dump(mode="json")
    schema = load_schema("dataset_sample_record.schema.json")
    jsonschema.validate(instance=data, schema=schema)

    assert sample.target_label == TargetClass.MALICIOUS
    assert sample.split == DatasetSplit.TRAIN


def test_sample_record_canonical_lowercase_hash_enforced() -> None:
    """Verify that uppercase, mixed-case, and invalid-length digests are rejected."""
    valid_lower = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Uppercase must fail
    with pytest.raises(ValidationError):
        DatasetSampleRecord(
            sample_id="s1",
            sample_hash=valid_lower.upper(),
            dataset_name="ember",
            dataset_version="2018",
            target_label=0,
            split=DatasetSplit.TRAIN,
            feature_schema_version="v1",
        )

    # Mixed-case must fail
    with pytest.raises(ValidationError):
        DatasetSampleRecord(
            sample_id="s1",
            sample_hash=valid_lower[:32].upper() + valid_lower[32:],
            dataset_name="ember",
            dataset_version="2018",
            target_label=0,
            split=DatasetSplit.TRAIN,
            feature_schema_version="v1",
        )

    # Invalid length must fail
    with pytest.raises(ValidationError):
        DatasetSampleRecord(
            sample_id="s1",
            sample_hash="a" * 63,
            dataset_name="ember",
            dataset_version="2018",
            target_label=0,
            split=DatasetSplit.TRAIN,
            feature_schema_version="v1",
        )


def test_sample_record_relative_path_validation_and_schema_agreement() -> None:
    """Verify that Pydantic and JSON Schema consistently accept portable paths and reject invalid paths."""
    schema = load_schema("dataset_sample_record.schema.json")
    base_data = {
        "sample_id": "s1",
        "sample_hash": "a" * 64,
        "dataset_name": "ember",
        "dataset_version": "2018",
        "target_label": 0,
        "split": "train",
        "feature_schema_version": "v1",
    }

    valid_paths = [
        "samples/2018/sample.bin",
        "samples\\2018\\sample.bin",
        "sample.exe",
        "binaries/clean/win32/calc.exe",
        "foo..bar.exe",  # contains '..' as part of filename, not a traversal segment
        None,
    ]

    for p in valid_paths:
        record = DatasetSampleRecord(**base_data, relative_path=p)
        payload = record.model_dump(mode="json")
        jsonschema.validate(instance=payload, schema=schema)

    invalid_paths = [
        # POSIX absolute
        "/etc/passwd",
        "/samples/01.bin",
        # Windows drive-absolute
        "C:\\samples\\01.bin",
        "c:/samples/01.bin",
        "D:\\data\\sample.exe",
        # Windows drive-relative
        "C:sample.exe",
        "d:foo/bar.exe",
        # UNC paths
        "\\\\server\\share\\sample.exe",
        "//server/share/sample.exe",
        # Traversal segments
        "../sample.exe",
        "..\\sample.exe",
        "samples/../sample.exe",
        "samples\\..\\sample.exe",
        "samples/child/..",
        "samples\\child\\..",
        "..",
    ]

    for inv in invalid_paths:
        # Pydantic must reject
        with pytest.raises(ValidationError):
            DatasetSampleRecord(**base_data, relative_path=inv)

        # JSON Schema must reject
        raw_inv = dict(base_data, relative_path=inv)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=raw_inv, schema=schema)


def test_sample_record_rejects_extra_properties() -> None:
    """Verify that unexpected extra properties are rejected by schema and Pydantic."""
    raw_data = {
        "sample_id": "s1",
        "sample_hash": "a" * 64,
        "dataset_name": "ember",
        "dataset_version": "2018",
        "target_label": 0,
        "split": "train",
        "feature_schema_version": "v1",
        "unexpected_raw_bytes": "MZ\x90...",
    }

    # Pydantic extra='forbid'
    with pytest.raises(ValidationError):
        DatasetSampleRecord(**raw_data)

    # JSON Schema additionalProperties: false
    schema = load_schema("dataset_sample_record.schema.json")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=raw_data, schema=schema)


def test_sample_record_enforces_label_integrity_and_rejects_unlabeled() -> None:
    """Verify sample record rejects converting unlabeled (-1) samples to target class 0 or 1."""
    base_data = {
        "sample_id": "s1",
        "sample_hash": "a" * 64,
        "dataset_name": "ember",
        "dataset_version": "2018",
        "split": DatasetSplit.TRAIN,
        "feature_schema_version": "v1",
    }

    # Unlabeled (-1) cannot be silently turned into benign (0)
    with pytest.raises(ValidationError) as exc_info:
        DatasetSampleRecord(**base_data, target_label=0, source_label=-1)
    assert "excluded/unlabeled" in str(exc_info.value)

    # Unlabeled (-1) cannot be turned into malicious (1)
    with pytest.raises(ValidationError) as exc_info:
        DatasetSampleRecord(**base_data, target_label=1, source_label="-1")
    assert "excluded/unlabeled" in str(exc_info.value)

    # Mismatched source and target label rejected
    with pytest.raises(ValidationError) as exc_info:
        DatasetSampleRecord(**base_data, target_label=0, source_label=1)
    assert "does not match normalized source_label" in str(exc_info.value)

    # Unknown source label rejected
    with pytest.raises(ValidationError) as exc_info:
        DatasetSampleRecord(**base_data, target_label=0, source_label=99)
    assert "Unrecognized source label" in str(exc_info.value)

    # Matching source and target labels pass
    s0 = DatasetSampleRecord(**base_data, target_label=0, source_label=0)
    assert s0.target_label == 0

    s1 = DatasetSampleRecord(**base_data, target_label=1, source_label=1)
    assert s1.target_label == 1


# ==============================================================================
# 2. DatasetManifest Tests
# ==============================================================================

def test_valid_dataset_manifest_conforms_to_schema() -> None:
    """Verify that a complete DatasetManifest passes Pydantic and JSON Schema validation."""
    manifest = DatasetManifest(
        manifest_id="manifest-ember-2018-v1",
        dataset_name="ember",
        dataset_version="2018",
        schema_version="1.0.0",
        source="https://github.com/elastic/ember",
        label_mapping=DEFAULT_EMBER_LABEL_MAPPING,
        class_definitions=DEFAULT_CLASS_DEFINITIONS,
        sample_count=1000,
        split_counts=SplitCounts(train=800, validation=100, test=100, unassigned=0),
        excluded_unlabeled_count=200,
        integrity_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        assumptions_and_limitations=["Windows PE executables only", "Excludes .NET binaries"],
        created_at=datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc),
    )

    data = manifest.model_dump(mode="json")
    schema = load_schema("dataset_manifest.schema.json")
    jsonschema.validate(instance=data, schema=schema)

    assert manifest.sample_count == 1000
    assert manifest.split_counts.train == 800
    assert manifest.excluded_unlabeled_count == 200


def test_manifest_sample_and_split_counts_consistency() -> None:
    """Verify manifest enforces sample_count == sum(split_counts)."""
    with pytest.raises(ValidationError) as exc_info:
        DatasetManifest(
            manifest_id="m1",
            dataset_name="ember",
            dataset_version="2018",
            source="src",
            sample_count=1000,
            split_counts=SplitCounts(train=500, validation=100, test=100, unassigned=0),  # sum=700 != 1000
            created_at=datetime.now(timezone.utc),
        )
    assert "Manifest sample_count (1000) must equal the sum of split_counts (700)" in str(exc_info.value)


def test_manifest_missing_required_fields_rejected() -> None:
    """Verify that manifests missing required fields fail validation."""
    with pytest.raises(ValidationError):
        DatasetManifest(
            manifest_id="m1",
            dataset_name="ember",
            # missing dataset_version
            source="src",
            sample_count=10,
            created_at=datetime.now(timezone.utc),
        )


# ==============================================================================
# 3. FeatureVector Tests
# ==============================================================================

def test_valid_feature_vector_zero_fill_conforms_to_schema() -> None:
    """Verify that a valid zero_fill FeatureVector passes Pydantic and JSON Schema validation."""
    vector = FeatureVector(
        sample_id="sample-001",
        sample_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        feature_schema_version="ember_pe_v1",
        feature_values=[0.0, 1.5, -1.0, 42.125],
        feature_count=4,
        missing_value_strategy=MissingValueStrategy.ZERO_FILL,
        extraction_duration_ms=45.2,
        feature_names=["f0", "f1", "f2", "f3"],
    )

    data = vector.model_dump(mode="json")
    schema = load_schema("feature_vector.schema.json")
    jsonschema.validate(instance=data, schema=schema)

    assert vector.feature_count == 4
    assert len(vector.feature_values) == 4
    assert vector.missing_value_strategy == MissingValueStrategy.ZERO_FILL


def test_valid_feature_vector_native_nan_with_nulls_conforms_to_schema() -> None:
    """Verify that native_nan FeatureVector with null elements passes Pydantic and JSON Schema."""
    vector = FeatureVector(
        sample_id="sample-002",
        sample_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        feature_schema_version="ember_pe_v1",
        feature_values=[0.25, None, -3.5, None],
        feature_count=4,
        missing_value_strategy=MissingValueStrategy.NATIVE_NAN,
    )

    data = vector.model_dump(mode="json")
    schema = load_schema("feature_vector.schema.json")
    jsonschema.validate(instance=data, schema=schema)

    assert data["feature_values"] == [0.25, None, -3.5, None]
    assert vector.missing_value_strategy == MissingValueStrategy.NATIVE_NAN


def test_feature_vector_zero_fill_rejects_nulls() -> None:
    """Verify that zero_fill strategy rejects null elements in both Pydantic and JSON Schema."""
    raw = {
        "sample_id": "s1",
        "sample_hash": "a" * 64,
        "feature_schema_version": "v1",
        "feature_values": [1.0, None, 3.0],
        "feature_count": 3,
        "missing_value_strategy": "zero_fill",
    }

    # Pydantic must reject
    with pytest.raises(ValidationError) as exc_info:
        FeatureVector(**raw)
    assert "incompatible with missing_value_strategy 'zero_fill'" in str(exc_info.value)

    # JSON Schema conditional validation must reject
    schema = load_schema("feature_vector.schema.json")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=raw, schema=schema)


def test_feature_vector_mean_impute_rejects_nulls() -> None:
    """Verify that mean_impute strategy rejects null elements in both Pydantic and JSON Schema."""
    raw = {
        "sample_id": "s1",
        "sample_hash": "a" * 64,
        "feature_schema_version": "v1",
        "feature_values": [1.0, None, 3.0],
        "feature_count": 3,
        "missing_value_strategy": "mean_impute",
    }

    # Pydantic must reject
    with pytest.raises(ValidationError) as exc_info:
        FeatureVector(**raw)
    assert "incompatible with missing_value_strategy 'mean_impute'" in str(exc_info.value)

    # JSON Schema conditional validation must reject
    schema = load_schema("feature_vector.schema.json")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=raw, schema=schema)


def test_feature_vector_mismatched_count_rejected() -> None:
    """Verify that feature_count differing from length of feature_values is rejected."""
    with pytest.raises(ValidationError) as exc_info:
        FeatureVector(
            sample_id="s1",
            sample_hash="a" * 64,
            feature_schema_version="v1",
            feature_values=[1.0, 2.0],
            feature_count=3,  # Mismatched
            missing_value_strategy=MissingValueStrategy.ZERO_FILL,
        )
    assert "feature_count (3) does not match" in str(exc_info.value)


def test_feature_vector_rejects_nan_and_inf_floats() -> None:
    """Verify that Python NaN and Infinite float values are rejected in Pydantic."""
    with pytest.raises(ValidationError) as exc_info:
        FeatureVector(
            sample_id="s1",
            sample_hash="a" * 64,
            feature_schema_version="v1",
            feature_values=[1.0, float("nan")],
            feature_count=2,
            missing_value_strategy=MissingValueStrategy.NATIVE_NAN,
        )
    assert "non-finite float" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        FeatureVector(
            sample_id="s1",
            sample_hash="a" * 64,
            feature_schema_version="v1",
            feature_values=[1.0, float("inf")],
            feature_count=2,
            missing_value_strategy=MissingValueStrategy.ZERO_FILL,
        )
    assert "non-finite float" in str(exc_info.value)


# ==============================================================================
# 4. ModelMetadata Tests
# ==============================================================================

def test_model_metadata_un_trained_conforms_to_schema() -> None:
    """Verify ModelMetadata passes validation when no training artifact or metrics exist yet."""
    metadata = ModelMetadata(
        model_id="sentinel-pe-lightgbm",
        model_version="1.0.0",
        model_family=ModelFamily.LIGHTGBM,
        task_type=TaskType.BINARY_CLASSIFICATION,
        dataset_id="ember",
        dataset_version="2018",
        feature_schema_version="ember_pe_v1",
        feature_count=2381,
        label_mapping={"0": "BENIGN", "1": "MALICIOUS"},
        class_order=["BENIGN", "MALICIOUS"],
    )

    assert metadata.artifact_hash is None
    assert metadata.metrics is None
    assert metadata.training_config is None
    assert metadata.model_family == ModelFamily.LIGHTGBM

    data = metadata.model_dump(mode="json")
    schema = load_schema("model_metadata.schema.json")
    jsonschema.validate(instance=data, schema=schema)


def test_model_metadata_trained_with_metrics_conforms_to_schema() -> None:
    """Verify ModelMetadata passes validation when trained with metrics and artifact."""
    metadata = ModelMetadata(
        model_id="sentinel-pe-lightgbm",
        model_version="1.0.0",
        model_family=ModelFamily.LIGHTGBM,
        task_type=TaskType.BINARY_CLASSIFICATION,
        dataset_id="ember",
        dataset_version="2018",
        feature_schema_version="ember_pe_v1",
        feature_count=2381,
        label_mapping={"0": "BENIGN", "1": "MALICIOUS"},
        class_order=["BENIGN", "MALICIOUS"],
        training_config={"learning_rate": 0.05, "num_leaves": 31, "objective": "binary"},
        artifact_format="ONNX",
        artifact_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        metrics=ModelMetrics(
            roc_auc=0.985,
            precision=0.962,
            recall=0.948,
            f1_score=0.955,
            false_positive_rate=0.012,
            evaluation_split="test",
        ),
        created_at=datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc),
        evaluated_at=datetime(2026, 10, 29, 12, 30, 0, tzinfo=timezone.utc),
    )

    data = metadata.model_dump(mode="json")
    schema = load_schema("model_metadata.schema.json")
    jsonschema.validate(instance=data, schema=schema)

    assert metadata.metrics is not None
    assert metadata.metrics.roc_auc == 0.985


def test_model_metadata_rejects_unapproved_model_families() -> None:
    """Verify that unapproved model families (e.g. random_forest, neural_network) are rejected."""
    raw = {
        "model_id": "m1",
        "model_version": "1.0.0",
        "model_family": "random_forest",  # Not authorized
        "task_type": "binary_classification",
        "dataset_id": "ember",
        "dataset_version": "2018",
        "feature_schema_version": "v1",
        "feature_count": 100,
        "label_mapping": {"0": "BENIGN", "1": "MALICIOUS"},
        "class_order": ["BENIGN", "MALICIOUS"],
    }

    # Pydantic must reject
    with pytest.raises(ValidationError):
        ModelMetadata(**raw)

    # JSON Schema must reject
    schema = load_schema("model_metadata.schema.json")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=raw, schema=schema)


# ==============================================================================
# 5. Label Semantics and Normalization Policy Tests
# ==============================================================================

def test_normalize_source_label_policy() -> None:
    """Verify label normalization converts valid labels, excludes unlabeled, and rejects unknown."""
    # 0 -> Benign (0)
    assert normalize_source_label(0) == 0
    assert normalize_source_label("0") == 0

    # 1 -> Malicious (1)
    assert normalize_source_label(1) == 1
    assert normalize_source_label("1") == 1

    # -1 -> Unlabeled / Ambiguous (None, excluded by policy)
    assert normalize_source_label(-1) is None
    assert normalize_source_label("-1") is None

    # Unknown label -> Raises ValueError (never silently converted to benign)
    with pytest.raises(ValueError) as exc_info:
        normalize_source_label(2)
    assert "Unrecognized source label" in str(exc_info.value)

    with pytest.raises(ValueError) as exc_info:
        normalize_source_label("suspicious_heuristic")
    assert "Unrecognized source label" in str(exc_info.value)


# ==============================================================================
# 6. Dataset Quality and Leakage Validation Service Tests
# ==============================================================================

def test_validator_detects_duplicate_sample_digests() -> None:
    """Verify validator detects repeated SHA-256 digests and reports them without dropping records."""
    dup_hash = "a" * 64
    samples = [
        DatasetSampleRecord(
            sample_id="s1",
            sample_hash=dup_hash,
            dataset_name="ember",
            dataset_version="2018",
            target_label=0,
            split=DatasetSplit.TRAIN,
            feature_schema_version="v1",
        ),
        DatasetSampleRecord(
            sample_id="s2",
            sample_hash=dup_hash,  # Duplicate digest
            dataset_name="ember",
            dataset_version="2018",
            target_label=0,
            split=DatasetSplit.TRAIN,
            feature_schema_version="v1",
        ),
        DatasetSampleRecord(
            sample_id="s3",
            sample_hash="b" * 64,
            dataset_name="ember",
            dataset_version="2018",
            target_label=1,
            split=DatasetSplit.TRAIN,
            feature_schema_version="v1",
        ),
    ]

    validator = DatasetValidator()
    report = validator.validate_samples(samples)

    assert report.total_records == 3
    assert report.duplicate_digest_count == 1
    assert dup_hash in report.duplicate_digests
    assert any("Found 1 duplicate SHA-256 digest" in w for w in report.warnings)


def test_validator_detects_cross_split_data_leakage() -> None:
    """Verify validator detects when the same digest appears across train and test splits."""
    leaked_hash = "c" * 64
    samples = [
        DatasetSampleRecord(
            sample_id="train-001",
            sample_hash=leaked_hash,
            dataset_name="ember",
            dataset_version="2018",
            target_label=1,
            split=DatasetSplit.TRAIN,
            feature_schema_version="v1",
        ),
        DatasetSampleRecord(
            sample_id="test-001",
            sample_hash=leaked_hash,  # Data leakage: in both train and test
            dataset_name="ember",
            dataset_version="2018",
            target_label=1,
            split=DatasetSplit.TEST,
            feature_schema_version="v1",
        ),
    ]

    validator = DatasetValidator()
    report = validator.validate_samples(samples)

    assert report.is_valid is False
    assert report.split_overlap_count == 1
    assert len(report.split_overlap_findings) == 1
    finding = report.split_overlap_findings[0]
    assert finding["sample_hash"] == leaked_hash
    assert finding["splits"] == ["test", "train"]
    assert any("Data leakage detected" in err for err in report.errors)


def test_validator_detects_label_mapping_mismatch() -> None:
    """Verify validator detects when raw sample dict contradicts source label policy."""
    raw_samples = [
        {
            "sample_id": "s1",
            "sample_hash": "d" * 64,
            "dataset_name": "ember",
            "dataset_version": "2018",
            "target_label": 0,  # Claims benign
            "source_label": 1,  # But source label was 1 (malicious)
            "split": "train",
            "feature_schema_version": "v1",
        },
    ]

    validator = DatasetValidator()
    report = validator.validate_samples(raw_samples)

    assert report.is_valid is False
    assert any("does not match normalized source_label" in err or "does not match mapped" in err for err in report.errors)


def test_validator_detects_excluded_unlabeled_samples() -> None:
    """Verify validator flags and records excluded unlabeled (-1) samples."""
    raw_samples = [
        {
            "sample_id": "s1",
            "sample_hash": "e" * 64,
            "dataset_name": "ember",
            "dataset_version": "2018",
            "target_label": 0,
            "source_label": -1,  # Unlabeled
            "split": "train",
            "feature_schema_version": "v1",
        },
    ]

    validator = DatasetValidator()
    report = validator.validate_samples(raw_samples)

    assert report.is_valid is False
    assert report.excluded_unlabeled_count == 1
    assert any("excluded/unlabeled" in err for err in report.errors)


def test_validator_matches_manifest_counts_cleanly() -> None:
    """Verify validator passes when samples match manifest counts and splits exactly."""
    samples = [
        DatasetSampleRecord(
            sample_id="tr-1",
            sample_hash="1" * 64,
            dataset_name="ember",
            dataset_version="2018",
            target_label=0,
            source_label=0,
            split=DatasetSplit.TRAIN,
            feature_schema_version="v1",
        ),
        DatasetSampleRecord(
            sample_id="te-1",
            sample_hash="2" * 64,
            dataset_name="ember",
            dataset_version="2018",
            target_label=1,
            source_label=1,
            split=DatasetSplit.TEST,
            feature_schema_version="v1",
        ),
    ]

    manifest = DatasetManifest(
        manifest_id="m1",
        dataset_name="ember",
        dataset_version="2018",
        schema_version="1.0.0",
        source="https://github.com/elastic/ember",
        sample_count=2,
        split_counts=SplitCounts(train=1, validation=0, test=1, unassigned=0),
        excluded_unlabeled_count=50,
        created_at=datetime.now(timezone.utc),
    )

    validator = DatasetValidator()
    report = validator.validate_samples(samples, manifest=manifest)

    assert report.is_valid is True
    assert report.total_records == 2
    assert report.valid_record_count == 2
    assert report.invalid_record_count == 0
    assert report.split_counts["train"] == 1
    assert report.split_counts["test"] == 1
    assert len(report.errors) == 0


def test_validator_empty_collection_handling() -> None:
    """Verify validator handles empty sample collection cleanly."""
    validator = DatasetValidator()
    report = validator.validate_samples([])

    assert report.is_valid is True
    assert report.total_records == 0
    assert len(report.warnings) == 1
    assert "empty" in report.warnings[0]


def test_validator_deterministic_reporting() -> None:
    """Verify that validating the same sample inputs yields identical deterministic outputs."""
    samples = [
        DatasetSampleRecord(
            sample_id="s1",
            sample_hash="a" * 64,
            dataset_name="ember",
            dataset_version="2018",
            target_label=0,
            split=DatasetSplit.TRAIN,
            feature_schema_version="v1",
        ),
        DatasetSampleRecord(
            sample_id="s2",
            sample_hash="b" * 64,
            dataset_name="ember",
            dataset_version="2018",
            target_label=1,
            split=DatasetSplit.TEST,
            feature_schema_version="v1",
        ),
    ]

    validator = DatasetValidator()
    rep1 = validator.validate_samples(samples).to_dict()
    rep2 = validator.validate_samples(samples).to_dict()

    assert rep1 == rep2


# ==============================================================================
# 7. EMBER 2018 (Feature Version 2) Release Verification Tests
# ==============================================================================

def test_ember_2018_release_constants() -> None:
    """Verify official EMBER 2018 v2 release constants and checksum."""
    assert EMBER_2018_DATASET_NAME == "ember"
    assert EMBER_2018_DATASET_VERSION == "2018"
    assert EMBER_2018_FEATURE_VERSION == 2
    assert EMBER_2018_FEATURE_SCHEMA_VERSION == "ember_pe_v2"
    assert EMBER_2018_CANONICAL_FEATURE_DIMENSION == 2381
    assert EMBER_2018_UPSTREAM_REPOSITORY_URL == "https://github.com/elastic/ember"
    assert EMBER_2018_ARCHIVE_NAME == "ember_dataset_2018_2.tar.bz2"
    assert EMBER_2018_ARCHIVE_URL == "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
    assert (
        EMBER_2018_ARCHIVE_SHA256
        == "b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812"
    )
    # Checksum must be canonical lowercase 64-hex string
    import re
    assert re.match(r"^[a-f0-9]{64}$", EMBER_2018_ARCHIVE_SHA256)


def test_ember_2018_canonical_feature_vector_conforms_to_schema() -> None:
    """Verify that a 2381-dimensional feature vector conforms to Pydantic and JSON Schema."""
    values = [0.0] * EMBER_2018_CANONICAL_FEATURE_DIMENSION
    values[0] = 0.12  # byte histogram first entry
    values[256] = 1.45  # byte entropy histogram entry
    values[2380] = 512.0  # data directory entry

    vector = FeatureVector(
        sample_id="ember-2018-sample-001",
        sample_hash="a" * 64,
        feature_schema_version=EMBER_2018_FEATURE_SCHEMA_VERSION,
        feature_values=values,
        feature_count=EMBER_2018_CANONICAL_FEATURE_DIMENSION,
        missing_value_strategy=MissingValueStrategy.ZERO_FILL,
    )

    assert vector.feature_count == 2381
    assert len(vector.feature_values) == 2381

    payload = vector.model_dump(mode="json")
    schema = load_schema("feature_vector.schema.json")
    jsonschema.validate(instance=payload, schema=schema)

