"""Versioned data contracts and schemas for ML dataset preparation and model metadata.

Provides data contracts conforming to language-neutral JSON Schemas in `shared/schemas/`:
- DatasetSampleRecord: Traced and validated sample records with canonical SHA-256.
- DatasetManifest: Versioned dataset metadata, provenance, label mapping, and split counts.
- FeatureVector: Versioned static numerical feature vector envelope.
- ModelMetadata: Specification describing model architecture, training configuration, and metrics.
"""

from datetime import datetime
from enum import Enum
import math
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ==============================================================================
# ML Enums
# ==============================================================================

class DatasetSplit(str, Enum):
    """Partition assignment for ML samples."""
    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"
    UNASSIGNED = "unassigned"


class TargetClass(int, Enum):
    """Normalized binary classification target class indices."""
    BENIGN = 0
    MALICIOUS = 1


class ModelFamily(str, Enum):
    """Approved machine learning frameworks or model families.
    
    Per prd.md §11, trd.md §3.1, and ticket_backlog.md T014/T015, LightGBM is the
    sole approved model family for static PE malware classification.
    """
    LIGHTGBM = "lightgbm"


class TaskType(str, Enum):
    """Analytical task performed by the ML model."""
    BINARY_CLASSIFICATION = "binary_classification"


class MissingValueStrategy(str, Enum):
    """Strategy applied for missing or unextractable feature elements.
    
    - NATIVE_NAN: Missing values are represented as null in JSON (converted to NaN at model loading).
    - ZERO_FILL: Missing values must be imputed with 0.0 before serialization (null forbidden).
    - MEAN_IMPUTE: Missing values must be imputed with precomputed feature means (null forbidden).
    """
    NATIVE_NAN = "native_nan"
    ZERO_FILL = "zero_fill"
    MEAN_IMPUTE = "mean_impute"


# ==============================================================================
# Verified EMBER 2018 (Feature Version 2) Release Constants
# ==============================================================================

EMBER_2018_DATASET_NAME: str = "ember"
EMBER_2018_DATASET_VERSION: str = "2018"
EMBER_2018_FEATURE_VERSION: int = 2
EMBER_2018_FEATURE_SCHEMA_VERSION: str = "ember_pe_v2"
EMBER_2018_CANONICAL_FEATURE_DIMENSION: int = 2381
EMBER_2018_UPSTREAM_REPOSITORY_URL: str = "https://github.com/elastic/ember"
EMBER_2018_ARCHIVE_NAME: str = "ember_dataset_2018_2.tar.bz2"
EMBER_2018_ARCHIVE_URL: str = "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
EMBER_2018_ARCHIVE_SHA256: str = "b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812"


# Documented default label mapping for the EMBER 2018 (Feature Version 2) benchmark dataset.
# Source specification: prd.md §11 establishes EMBER as the initial target public dataset;
# ticket_backlog.md T012 establishes inspecting its feature schema and label conventions.
# Raw labels: 0 -> Benign, 1 -> Malicious, -1 -> Unlabeled / Ambiguous.
# Unlabeled samples are excluded from supervised partitions and never silently converted to 0.
DEFAULT_EMBER_LABEL_MAPPING: Dict[str, Optional[int]] = {
    "0": 0,    # Benign -> Class 0
    "1": 1,    # Malicious -> Class 1
    "-1": None,  # Unlabeled / Ambiguous -> Excluded from supervised training (never converted to 0)
}

DEFAULT_CLASS_DEFINITIONS: Dict[str, str] = {
    "0": "benign",
    "1": "malicious",
}


def normalize_source_label(
    source_label: Union[int, str],
    label_mapping: Optional[Dict[str, Optional[int]]] = None,
) -> Optional[int]:
    """Normalize a raw source dataset label to target binary class (0 or 1) or None if excluded.

    Args:
        source_label: Raw label from source dataset (e.g. 0, 1, -1, '0', '1', '-1').
        label_mapping: Mapping dict of stringified source label to target class or None.
            Defaults to DEFAULT_EMBER_LABEL_MAPPING.

    Returns:
        0 (Benign), 1 (Malicious), or None (explicitly excluded/unlabeled).

    Raises:
        ValueError: If source_label is unrecognized in the mapping.
    """
    mapping = label_mapping if label_mapping is not None else DEFAULT_EMBER_LABEL_MAPPING
    key = str(source_label).strip()

    if key not in mapping:
        raise ValueError(
            f"Unrecognized source label '{source_label}'. "
            f"Allowed source labels according to mapping policy: {sorted(mapping.keys())}"
        )

    return mapping[key]


# ==============================================================================
# Dataset Sample Record
# ==============================================================================

class DatasetSampleRecord(BaseModel):
    """Validated metadata record representing an individual sample in a dataset."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str = Field(
        ...,
        min_length=1,
        description="Stable unique identifier for the sample record.",
    )
    sample_hash: str = Field(
        ...,
        pattern=r"^[a-f0-9]{64}$",
        description="Canonical 64-character lowercase SHA-256 digest.",
    )
    dataset_name: str = Field(
        ...,
        min_length=1,
        description="Name of the originating dataset collection (e.g. 'ember').",
    )
    dataset_version: str = Field(
        ...,
        min_length=1,
        description="Version identifier of the originating dataset (e.g. '2018').",
    )
    target_label: int = Field(
        ...,
        ge=0,
        le=1,
        description="Normalized binary classification target class: 0 for benign, 1 for malicious.",
    )
    split: DatasetSplit = Field(
        default=DatasetSplit.UNASSIGNED,
        description="Partition split assignment for model training and evaluation.",
    )
    feature_schema_version: str = Field(
        ...,
        min_length=1,
        description="Identifier of the feature extraction schema applicable to this sample.",
    )
    source_record_id: Optional[str] = Field(
        default=None,
        description="Optional upstream or external dataset sample identifier.",
    )
    source_label: Optional[Union[int, str]] = Field(
        default=None,
        description="Original raw label from the source dataset prior to normalization.",
    )
    label_provenance: Optional[str] = Field(
        default=None,
        description="Attribution or method used to assign the label (e.g. 'avclass', 'vendor_consensus').",
    )
    relative_path: Optional[str] = Field(
        default=None,
        description="Optional relative path to sample binary within dataset archive (never absolute).",
    )
    collected_at: Optional[datetime] = Field(
        default=None,
        description="Optional ISO 8601 UTC timestamp when the sample was collected.",
    )

    @field_validator("collected_at")
    @classmethod
    def validate_timezone_aware(cls, v: Optional[datetime]) -> Optional[datetime]:
        """Ensure timestamps include explicit timezone information."""
        if v is not None and v.tzinfo is None:
            raise ValueError("collected_at must be timezone-aware (e.g. UTC).")
        return v

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, v: Optional[str]) -> Optional[str]:
        """Reject machine-specific absolute paths, UNC paths, and directory traversal segments."""
        if v is None:
            return None
        clean = v.strip()
        if not clean:
            return clean

        # Reject POSIX absolute paths and forward-slash UNC
        if clean.startswith("/"):
            raise ValueError(f"relative_path cannot be an absolute POSIX or UNC path: '{v}'")

        # Reject Windows backslash UNC or absolute root
        if clean.startswith("\\"):
            raise ValueError(f"relative_path cannot be an absolute Windows or UNC path: '{v}'")

        # Reject Windows drive-absolute or drive-relative paths (e.g., C:\..., c:/..., C:sample.exe)
        if len(clean) >= 2 and clean[0].isalpha() and clean[1] == ":":
            raise ValueError(f"relative_path cannot contain a Windows drive prefix: '{v}'")

        # Reject directory traversal segments (..)
        normalized_segments = clean.replace("\\", "/").split("/")
        if any(segment == ".." for segment in normalized_segments):
            raise ValueError(f"relative_path cannot contain directory traversal segments ('..'): '{v}'")

        return clean

    @model_validator(mode="after")
    def validate_source_label_not_excluded(self) -> "DatasetSampleRecord":
        """Ensure that an excluded/unlabeled source label is never assigned a target class."""
        if self.source_label is not None:
            mapped = normalize_source_label(self.source_label)
            if mapped is None:
                raise ValueError(
                    f"source_label '{self.source_label}' is designated as excluded/unlabeled. "
                    "Unlabeled samples cannot be converted to a target class (0 or 1) in a supervised DatasetSampleRecord."
                )
            if mapped != self.target_label:
                raise ValueError(
                    f"target_label ({self.target_label}) does not match normalized source_label "
                    f"'{self.source_label}' ({mapped})."
                )
        return self


# ==============================================================================
# Dataset Manifest
# ==============================================================================

class SplitCounts(BaseModel):
    """Breakdown of sample counts across dataset splits."""

    model_config = ConfigDict(extra="forbid")

    train: int = Field(default=0, ge=0)
    validation: int = Field(default=0, ge=0)
    test: int = Field(default=0, ge=0)
    unassigned: int = Field(default=0, ge=0)


class DatasetManifest(BaseModel):
    """Manifest defining metadata, provenance, class definitions, and split counts for an ML dataset."""

    model_config = ConfigDict(extra="forbid")

    manifest_id: str = Field(
        ...,
        min_length=1,
        description="Unique identifier for this dataset manifest instance.",
    )
    dataset_name: str = Field(
        ...,
        min_length=1,
        description="Formal dataset collection name (e.g. 'ember').",
    )
    dataset_version: str = Field(
        ...,
        min_length=1,
        description="Version string of the dataset release (e.g. '2018.v2').",
    )
    schema_version: str = Field(
        default="1.0.0",
        min_length=1,
        description="Version of the manifest schema specification.",
    )
    source: str = Field(
        ...,
        min_length=1,
        description="Originating source, reference URL, or publisher of the dataset.",
    )
    label_mapping: Dict[str, Optional[int]] = Field(
        default_factory=lambda: dict(DEFAULT_EMBER_LABEL_MAPPING),
        description="Mapping from stringified source labels to target classes or None (for excluded).",
    )
    class_definitions: Dict[str, str] = Field(
        default_factory=lambda: dict(DEFAULT_CLASS_DEFINITIONS),
        description="Descriptive names for each normalized target class index.",
    )
    sample_count: int = Field(
        ...,
        ge=0,
        description="Total number of retained labeled samples documented in the manifest.",
    )
    split_counts: Optional[SplitCounts] = Field(
        default=None,
        description="Breakdown of retained sample counts across partition splits.",
    )
    excluded_unlabeled_count: Optional[int] = Field(
        default=None,
        ge=0,
        description="Optional count of excluded unlabeled/ambiguous samples from raw source data not included in sample_count or split_counts.",
    )
    integrity_digest: Optional[str] = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
        description="Optional canonical SHA-256 digest of the manifest or archive.",
    )
    assumptions_and_limitations: List[str] = Field(
        default_factory=list,
        description="Explicit assumptions, bias notes, or constraints regarding the dataset.",
    )
    created_at: datetime = Field(
        ...,
        description="ISO 8601 UTC timestamp when this manifest was generated.",
    )

    @field_validator("created_at")
    @classmethod
    def validate_timezone_aware(cls, v: datetime) -> datetime:
        """Ensure timestamps include explicit timezone information."""
        if v.tzinfo is None:
            raise ValueError("created_at must be timezone-aware (e.g. UTC).")
        return v

    @model_validator(mode="after")
    def validate_sample_and_split_counts(self) -> "DatasetManifest":
        """Ensure declared sample_count equals the sum of retained split counts."""
        if self.split_counts is not None:
            split_total = (
                self.split_counts.train
                + self.split_counts.validation
                + self.split_counts.test
                + self.split_counts.unassigned
            )
            if split_total != self.sample_count:
                raise ValueError(
                    f"Manifest sample_count ({self.sample_count}) must equal the sum of split_counts "
                    f"({split_total}). Both describe the retained population of labeled samples."
                )
        return self


# ==============================================================================
# Feature Vector
# ==============================================================================

class FeatureVector(BaseModel):
    """Versioned feature envelope containing ordered static features extracted from an executable."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str = Field(
        ...,
        min_length=1,
        description="Stable identifier of the analyzed sample.",
    )
    sample_hash: str = Field(
        ...,
        pattern=r"^[a-f0-9]{64}$",
        description="Canonical 64-character lowercase SHA-256 digest.",
    )
    feature_schema_version: str = Field(
        ...,
        min_length=1,
        description="Version identifier of the feature extraction schema (e.g. 'ember_pe_v1').",
    )
    feature_values: List[Optional[float]] = Field(
        ...,
        description=(
            "Ordered numerical feature array. Non-null elements must be finite numbers. "
            "Missing elements are represented as null."
        ),
    )
    feature_count: int = Field(
        ...,
        ge=1,
        description="Number of numerical feature values contained in the vector.",
    )
    missing_value_strategy: MissingValueStrategy = Field(
        default=MissingValueStrategy.ZERO_FILL,
        description="Strategy applied for handling unextractable or missing feature elements.",
    )
    extraction_duration_ms: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Optional elapsed duration in milliseconds required to extract features.",
    )
    feature_names: Optional[List[str]] = Field(
        default=None,
        description="Optional list of feature names corresponding 1-to-1 with feature_values.",
    )

    @model_validator(mode="after")
    def validate_vector_integrity(self) -> "FeatureVector":
        """Enforce length consistency, finite numbers, and missing-value strategy compatibility."""
        if len(self.feature_values) != self.feature_count:
            raise ValueError(
                f"feature_count ({self.feature_count}) does not match length of feature_values "
                f"({len(self.feature_values)})."
            )

        for i, val in enumerate(self.feature_values):
            if val is None:
                if self.missing_value_strategy != MissingValueStrategy.NATIVE_NAN:
                    raise ValueError(
                        f"feature_values contains null (None) at index {i}, which is incompatible with "
                        f"missing_value_strategy '{self.missing_value_strategy.value}'. "
                        "Null feature values are only permitted under 'native_nan' policy."
                    )
            else:
                if math.isnan(val) or math.isinf(val):
                    raise ValueError(
                        f"feature_values contains non-finite float at index {i}: {val}. "
                        "Numeric features must be finite numbers. Represent missing values as null (None) "
                        "under the 'native_nan' strategy."
                    )

        if self.feature_names is not None and len(self.feature_names) != self.feature_count:
            raise ValueError(
                f"feature_names length ({len(self.feature_names)}) does not match feature_count "
                f"({self.feature_count})."
            )

        return self


# ==============================================================================
# Model Metadata
# ==============================================================================

class ModelMetrics(BaseModel):
    """Evaluation performance metrics measured on a held-out split."""

    model_config = ConfigDict(extra="allow")

    roc_auc: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    precision: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    recall: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    f1_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    false_positive_rate: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    evaluation_split: Optional[str] = Field(default=None, pattern=r"^(test|validation)$")


class ModelMetadata(BaseModel):
    """Specification describing ML model architecture, training configuration, and metrics."""

    model_config = ConfigDict(extra="forbid")

    model_id: str = Field(
        ...,
        min_length=1,
        description="Unique identifier for model family or deployment (e.g. 'sentinel-pe-lightgbm').",
    )
    model_version: str = Field(
        ...,
        min_length=1,
        description="Semantic version of the model artifact (e.g. '1.0.0').",
    )
    model_family: ModelFamily = Field(
        default=ModelFamily.LIGHTGBM,
        description="Approved machine learning framework (LightGBM per prd.md §11 and trd.md §3.1).",
    )
    task_type: TaskType = Field(
        default=TaskType.BINARY_CLASSIFICATION,
        description="Specific analytical task performed by the model.",
    )
    dataset_id: str = Field(
        ...,
        min_length=1,
        description="Identifier of dataset used for training (e.g. 'ember').",
    )
    dataset_version: str = Field(
        ...,
        min_length=1,
        description="Version of training dataset (e.g. '2018').",
    )
    feature_schema_version: str = Field(
        ...,
        min_length=1,
        description="Feature schema version required by model.",
    )
    feature_count: int = Field(
        ...,
        ge=1,
        description="Exact input dimension expected by the model.",
    )
    label_mapping: Dict[str, str] = Field(
        default_factory=lambda: {"0": "BENIGN", "1": "MALICIOUS"},
        description="Mapping from class index string to semantic label name.",
    )
    class_order: List[str] = Field(
        default_factory=lambda: ["BENIGN", "MALICIOUS"],
        min_length=2,
        description="Ordered array of class labels corresponding to model output probabilities.",
    )
    training_config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional hyperparameters and training configuration settings.",
    )
    artifact_format: Optional[str] = Field(
        default=None,
        description="Storage format of serialized model artifact ('ONNX', 'LightGBM_Binary', etc.).",
    )
    artifact_hash: Optional[str] = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
        description="Canonical lowercase SHA-256 digest of compiled model artifact file.",
    )
    metrics: Optional[ModelMetrics] = Field(
        default=None,
        description="Evaluation performance metrics measured on reserved test split.",
    )
    created_at: Optional[datetime] = Field(
        default=None,
        description="ISO 8601 UTC timestamp when model was registered.",
    )
    evaluated_at: Optional[datetime] = Field(
        default=None,
        description="ISO 8601 UTC timestamp when evaluation metrics were recorded.",
    )

    @field_validator("created_at", "evaluated_at")
    @classmethod
    def validate_timezone_aware(cls, v: Optional[datetime]) -> Optional[datetime]:
        """Ensure timestamps include explicit timezone information."""
        if v is not None and v.tzinfo is None:
            raise ValueError("Timestamp must be timezone-aware (e.g. UTC).")
        return v
