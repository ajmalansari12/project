"""Dataset quality, integrity, and data-leakage validation service for Sentinel-EDR.

Implements reusable validation checks for dataset manifests and sample records:
- Duplicate sample digest detection.
- Cross-split data leakage detection (same sample digest appearing across splits).
- Source-to-target label mapping consistency and missing/unmapped label checks.
- Manifest sample and split count verification.
- Structured, auditable validation reporting without mutating or deleting records.
"""

from collections import defaultdict
from dataclasses import dataclass, field
import logging
from typing import Any, Dict, List, Optional, Sequence, Set, Union

from pydantic import ValidationError

from app.schemas.ml_contracts import (
    DEFAULT_EMBER_LABEL_MAPPING,
    DatasetManifest,
    DatasetSampleRecord,
    DatasetSplit,
    normalize_source_label,
)

logger = logging.getLogger("sentinel.services.dataset_validator")


@dataclass
class DatasetValidationReport:
    """Structured report summarizing dataset quality, consistency, and leakage findings."""

    is_valid: bool
    total_records: int
    valid_record_count: int
    invalid_record_count: int
    duplicate_digest_count: int
    duplicate_digests: List[str] = field(default_factory=list)
    missing_label_count: int = 0
    excluded_unlabeled_count: int = 0
    split_counts: Dict[str, int] = field(default_factory=dict)
    split_overlap_count: int = 0
    split_overlap_findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to serializable dictionary representation."""
        return {
            "is_valid": self.is_valid,
            "total_records": self.total_records,
            "valid_record_count": self.valid_record_count,
            "invalid_record_count": self.invalid_record_count,
            "duplicate_digest_count": self.duplicate_digest_count,
            "duplicate_digests": list(self.duplicate_digests),
            "missing_label_count": self.missing_label_count,
            "excluded_unlabeled_count": self.excluded_unlabeled_count,
            "split_counts": dict(self.split_counts),
            "split_overlap_count": self.split_overlap_count,
            "split_overlap_findings": list(self.split_overlap_findings),
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


class DatasetValidator:
    """Thread-safe validator for ML dataset manifests and sample records."""

    def __init__(
        self,
        *,
        default_label_mapping: Optional[Dict[str, Optional[int]]] = None,
    ) -> None:
        """Initialize validator with optional default label mapping."""
        self._default_label_mapping = (
            default_label_mapping if default_label_mapping is not None else DEFAULT_EMBER_LABEL_MAPPING
        )

    def validate_manifest(
        self,
        manifest_data: Union[DatasetManifest, Dict[str, Any]],
    ) -> DatasetValidationReport:
        """Validate a dataset manifest structure and integrity.

        Args:
            manifest_data: DatasetManifest instance or raw dictionary.

        Returns:
            DatasetValidationReport indicating validity and any schema or logical errors.
        """
        errors: List[str] = []
        warnings: List[str] = []

        manifest: Optional[DatasetManifest] = None
        if isinstance(manifest_data, DatasetManifest):
            manifest = manifest_data
        elif isinstance(manifest_data, dict):
            try:
                manifest = DatasetManifest(**manifest_data)
            except ValidationError as exc:
                errors.append(f"Manifest schema validation failed: {exc}")
                return DatasetValidationReport(
                    is_valid=False,
                    total_records=1,
                    valid_record_count=0,
                    invalid_record_count=1,
                    duplicate_digest_count=0,
                    errors=errors,
                    warnings=warnings,
                )
        else:
            errors.append(f"Expected DatasetManifest or dict, got {type(manifest_data).__name__}")
            return DatasetValidationReport(
                is_valid=False,
                total_records=1,
                valid_record_count=0,
                invalid_record_count=1,
                duplicate_digest_count=0,
                errors=errors,
                warnings=warnings,
            )

        # Logical validations on parsed manifest
        split_counts_dict: Dict[str, int] = {}
        if manifest.split_counts:
            split_counts_dict = {
                "train": manifest.split_counts.train,
                "validation": manifest.split_counts.validation,
                "test": manifest.split_counts.test,
                "unassigned": manifest.split_counts.unassigned,
            }
            total_split_sum = sum(split_counts_dict.values())
            if total_split_sum != manifest.sample_count:
                errors.append(
                    f"Sum of split counts ({total_split_sum}) does not match declared "
                    f"sample_count ({manifest.sample_count}). Both must describe retained labeled samples."
                )

        if not manifest.label_mapping:
            errors.append("Manifest label_mapping is empty.")

        if not manifest.class_definitions:
            errors.append("Manifest class_definitions is empty.")

        # Ensure both classes 0 and 1 are defined
        if "0" not in manifest.class_definitions or "1" not in manifest.class_definitions:
            warnings.append(
                f"Binary classification expects definitions for '0' and '1'. Found: {list(manifest.class_definitions.keys())}"
            )

        is_valid = len(errors) == 0
        return DatasetValidationReport(
            is_valid=is_valid,
            total_records=1,
            valid_record_count=1 if is_valid else 0,
            invalid_record_count=0 if is_valid else 1,
            duplicate_digest_count=0,
            excluded_unlabeled_count=manifest.excluded_unlabeled_count or 0,
            split_counts=split_counts_dict,
            errors=errors,
            warnings=warnings,
        )

    def validate_samples(
        self,
        samples: Sequence[Union[DatasetSampleRecord, Dict[str, Any]]],
        manifest: Optional[Union[DatasetManifest, Dict[str, Any]]] = None,
    ) -> DatasetValidationReport:
        """Validate an iterable collection of dataset sample records.

        Performs:
        1. Sample schema validation and canonical lowercase SHA-256 checks.
        2. Duplicate digest detection across samples.
        3. Split assignment tracking and cross-split data-leakage detection.
        4. Label mapping validation against manifest or default policy.
        5. Manifest count comparison if manifest is provided.

        Args:
            samples: Sequence of DatasetSampleRecord instances or sample dicts.
            manifest: Optional parent DatasetManifest to validate against.

        Returns:
            DatasetValidationReport with exhaustive diagnostic findings.
        """
        total = len(samples)
        if total == 0:
            return DatasetValidationReport(
                is_valid=True,
                total_records=0,
                valid_record_count=0,
                invalid_record_count=0,
                duplicate_digest_count=0,
                split_counts={"train": 0, "validation": 0, "test": 0, "unassigned": 0},
                warnings=["Dataset sample collection is empty."],
            )

        errors: List[str] = []
        warnings: List[str] = []

        # Parse manifest if provided
        active_manifest: Optional[DatasetManifest] = None
        label_mapping = self._default_label_mapping

        if manifest:
            if isinstance(manifest, DatasetManifest):
                active_manifest = manifest
            elif isinstance(manifest, dict):
                try:
                    active_manifest = DatasetManifest(**manifest)
                except ValidationError as exc:
                    errors.append(f"Parent manifest failed validation: {exc}")

            if active_manifest and active_manifest.label_mapping:
                label_mapping = active_manifest.label_mapping

        parsed_records: List[DatasetSampleRecord] = []
        invalid_record_count = 0
        excluded_unlabeled_count = 0

        # 1. Parse and validate individual sample records
        for i, item in enumerate(samples):
            if isinstance(item, DatasetSampleRecord):
                parsed_records.append(item)
            elif isinstance(item, dict):
                try:
                    record = DatasetSampleRecord(**item)
                    parsed_records.append(record)
                except ValidationError as exc:
                    invalid_record_count += 1
                    err_msg = str(exc)
                    if "excluded/unlabeled" in err_msg or "'-1'" in err_msg:
                        excluded_unlabeled_count += 1
                    errors.append(f"Sample at index {i} failed validation: {exc}")
            else:
                invalid_record_count += 1
                errors.append(f"Sample at index {i} has invalid type: {type(item).__name__}")

        # 2. Check for duplicate SHA-256 sample digests
        digest_to_sample_ids: Dict[str, List[str]] = defaultdict(list)
        digest_to_splits: Dict[str, Set[str]] = defaultdict(set)
        split_counts: Dict[str, int] = defaultdict(int)
        missing_label_count = 0

        for r in parsed_records:
            digest_to_sample_ids[r.sample_hash].append(r.sample_id)
            digest_to_splits[r.sample_hash].add(r.split.value)
            split_counts[r.split.value] += 1

            # Validate target label
            if r.target_label not in (0, 1):
                invalid_record_count += 1
                errors.append(f"Sample '{r.sample_id}' has invalid target_label {r.target_label}; must be 0 or 1.")

            # Validate label against mapping if source label exists
            if r.source_label is not None:
                try:
                    expected_class = normalize_source_label(r.source_label, label_mapping)
                    if expected_class is None:
                        excluded_unlabeled_count += 1
                        errors.append(
                            f"Sample '{r.sample_id}' has source label '{r.source_label}' which is designated "
                            "as excluded/unlabeled by the label mapping policy. Unlabeled records cannot be assigned "
                            f"target_label={r.target_label} or retained in supervised dataset partitions."
                        )
                    elif expected_class != r.target_label:
                        errors.append(
                            f"Sample '{r.sample_id}' target_label ({r.target_label}) does not match "
                            f"mapped source_label '{r.source_label}' ({expected_class})."
                        )
                except ValueError as err:
                    missing_label_count += 1
                    errors.append(f"Sample '{r.sample_id}' label mapping error: {err}")

        # Evaluate duplicate digests
        duplicate_digests: List[str] = [h for h, ids in digest_to_sample_ids.items() if len(ids) > 1]
        duplicate_count = len(duplicate_digests)

        if duplicate_count > 0:
            warnings.append(
                f"Found {duplicate_count} duplicate SHA-256 digest(s) across {sum(len(digest_to_sample_ids[h]) for h in duplicate_digests)} sample records."
            )

        # 3. Check for cross-split data leakage (sample digest in multiple splits)
        split_overlap_findings: List[Dict[str, Any]] = []
        for h, splits in digest_to_splits.items():
            partitioned_splits = {s for s in splits if s != DatasetSplit.UNASSIGNED.value}
            if len(partitioned_splits) > 1:
                finding = {
                    "sample_hash": h,
                    "splits": sorted(partitioned_splits),
                    "sample_ids": digest_to_sample_ids[h],
                }
                split_overlap_findings.append(finding)
                errors.append(
                    f"Data leakage detected for digest {h}: sample appears in multiple splits {sorted(partitioned_splits)}."
                )

        split_overlap_count = len(split_overlap_findings)

        # 4. Compare with manifest if provided
        if active_manifest:
            if active_manifest.sample_count != total:
                errors.append(
                    f"Sample count ({total}) does not match manifest sample_count ({active_manifest.sample_count})."
                )

            if active_manifest.split_counts:
                for split_name in ("train", "validation", "test", "unassigned"):
                    expected = getattr(active_manifest.split_counts, split_name, 0)
                    actual = split_counts[split_name]
                    if expected != actual:
                        errors.append(
                            f"Split '{split_name}' sample count ({actual}) does not match manifest split_counts ({expected})."
                        )

        is_valid = (len(errors) == 0) and (invalid_record_count == 0)

        # Ensure standard keys present in split_counts
        for split_key in ("train", "validation", "test", "unassigned"):
            split_counts.setdefault(split_key, 0)

        return DatasetValidationReport(
            is_valid=is_valid,
            total_records=total,
            valid_record_count=len(parsed_records) - invalid_record_count if is_valid else max(0, len(parsed_records) - invalid_record_count),
            invalid_record_count=invalid_record_count,
            duplicate_digest_count=duplicate_count,
            duplicate_digests=sorted(duplicate_digests),
            missing_label_count=missing_label_count,
            excluded_unlabeled_count=excluded_unlabeled_count,
            split_counts=dict(split_counts),
            split_overlap_count=split_overlap_count,
            split_overlap_findings=split_overlap_findings,
            errors=errors,
            warnings=warnings,
        )
