"""Ember dataset acquisition, safe extraction, validation, and streaming service.

Handles:
- Safe streaming download of the official EMBER 2018 Feature Version 2 archive.
- SHA-256 checksum verification against the published upstream digest.
- Path-traversal-safe extraction of .tar.bz2 archives.
- Incremental JSONL streaming with malformed record tracking.
- Label normalization and exclusion of unlabeled (-1) samples per T012 policy.
- Duplicate SHA-256 digest detection and cross-split data-leakage auditing.
- Dataset manifest generation conforming to T012 schemas.
- Chunked, resource-aware vectorization to disk-backed memory-mapped arrays.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import tarfile
from typing import Any, Callable, Dict, Generator, List, Optional, Sequence, Set, Tuple, Union

import httpx
import numpy as np

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
    SplitCounts,
    normalize_source_label,
)
from app.services.dataset_validator import DatasetValidator
from app.services.ember_raw_vectorizer import EmberRawFeatureVectorizer, get_default_ember_raw_vectorizer

logger = logging.getLogger("sentinel.services.ember_dataset")


class EmberDatasetError(Exception):
    """Base exception for EMBER dataset operations."""


class EmberChecksumMismatchError(EmberDatasetError):
    """Raised when downloaded archive checksum does not match published digest."""


class EmberArchiveSecurityError(EmberDatasetError):
    """Raised when an archive member attempts path traversal or unsafe extraction."""


class EmberDatasetNotFoundError(EmberDatasetError):
    """Raised when expected dataset shards are missing."""


@dataclass
class IngestionSummary:
    """Summary of raw JSONL ingestion, filtering, and split counts."""

    total_records_read: int = 0
    labeled_records_retained: int = 0
    unlabeled_records_excluded: int = 0
    malformed_records_count: int = 0
    malformed_records: List[Dict[str, Any]] = field(default_factory=list)
    train_records_count: int = 0
    test_records_count: int = 0
    duplicate_digest_count: int = 0
    duplicate_digests: List[str] = field(default_factory=list)
    cross_split_leakage_count: int = 0
    cross_split_leakage_digests: List[str] = field(default_factory=list)
    manifest_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to serializable dictionary."""
        return {
            "total_records_read": self.total_records_read,
            "labeled_records_retained": self.labeled_records_retained,
            "unlabeled_records_excluded": self.unlabeled_records_excluded,
            "malformed_records_count": self.malformed_records_count,
            "train_records_count": self.train_records_count,
            "test_records_count": self.test_records_count,
            "duplicate_digest_count": self.duplicate_digest_count,
            "cross_split_leakage_count": self.cross_split_leakage_count,
            "manifest_path": self.manifest_path,
        }


class EmberDatasetService:
    """Service for managing the EMBER 2018 (Feature Version 2) dataset pipeline."""

    def __init__(
        self,
        dataset_dir: Union[str, Path] = ".data/ember",
        *,
        archive_url: str = EMBER_2018_ARCHIVE_URL,
        expected_sha256: str = EMBER_2018_ARCHIVE_SHA256,
        vectorizer: Optional[EmberRawFeatureVectorizer] = None,
    ) -> None:
        self.dataset_dir = Path(dataset_dir).resolve()
        self.archive_url = archive_url
        self.expected_sha256 = expected_sha256.lower()
        self.vectorizer = vectorizer or get_default_ember_raw_vectorizer()
        self.validator = DatasetValidator()

    @property
    def archive_path(self) -> Path:
        """Path to the downloaded archive file."""
        return self.dataset_dir / EMBER_2018_ARCHIVE_NAME

    # --------------------------------------------------------------------------
    # 1. Download & Checksum Verification
    # --------------------------------------------------------------------------
    def verify_archive_checksum(self, archive_file: Optional[Path] = None) -> bool:
        """Verify the SHA-256 checksum of an archive file against the expected digest."""
        target = archive_file or self.archive_path
        if not target.is_file():
            return False

        hasher = hashlib.sha256()
        with open(target, "rb") as fin:
            for chunk in iter(lambda: fin.read(1024 * 1024), b""):
                hasher.update(chunk)

        computed = hasher.hexdigest().lower()
        return computed == self.expected_sha256

    def download_archive(
        self,
        *,
        force: bool = False,
        chunk_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Path:
        """Stream download the EMBER archive with incremental SHA-256 verification.

        Downloads to a temporary '.part' file, verifies checksum upon completion,
        and atomically renames to the canonical archive path.
        """
        self.dataset_dir.mkdir(parents=True, exist_ok=True)
        canonical_path = self.archive_path

        if canonical_path.is_file() and not force:
            if self.verify_archive_checksum(canonical_path):
                logger.info("Validated EMBER archive already exists: %s", canonical_path)
                return canonical_path
            logger.warning("Existing archive failed checksum; re-downloading: %s", canonical_path)
            canonical_path.unlink()

        part_path = self.dataset_dir / f"{EMBER_2018_ARCHIVE_NAME}.part"
        if part_path.is_file():
            part_path.unlink()

        logger.info("Initiating streaming download from %s", self.archive_url)
        hasher = hashlib.sha256()
        bytes_downloaded = 0

        try:
            with httpx.stream("GET", self.archive_url, follow_redirects=True, timeout=120.0) as resp:
                resp.raise_for_status()
                total_bytes = int(resp.headers.get("content-length", 0))

                with open(part_path, "wb") as fout:
                    for chunk in resp.iter_bytes(chunk_size=1024 * 1024):
                        if chunk:
                            fout.write(chunk)
                            hasher.update(chunk)
                            bytes_downloaded += len(chunk)
                            if chunk_callback:
                                chunk_callback(bytes_downloaded, total_bytes)

            computed_sha256 = hasher.hexdigest().lower()
            if computed_sha256 != self.expected_sha256:
                if part_path.is_file():
                    part_path.unlink()
                raise EmberChecksumMismatchError(
                    f"Checksum mismatch for downloaded archive. "
                    f"Expected: {self.expected_sha256}, got: {computed_sha256}"
                )

            # Atomic rename after verified checksum
            part_path.replace(canonical_path)
            logger.info("Successfully downloaded and verified EMBER archive: %s", canonical_path)
            return canonical_path

        except Exception as exc:
            if part_path.is_file():
                part_path.unlink()
            raise EmberDatasetError(f"Failed to download EMBER archive: {exc}") from exc

    # --------------------------------------------------------------------------
    # 2. Safe Archive Extraction
    # --------------------------------------------------------------------------
    def extract_archive(
        self,
        archive_file: Optional[Path] = None,
        dest_dir: Optional[Path] = None,
        *,
        force: bool = False,
    ) -> Path:
        """Safely extract the tar.bz2 archive, rejecting path traversal attempts."""
        archive = archive_file or self.archive_path
        out_dir = dest_dir or self.dataset_dir

        if not archive.is_file():
            raise EmberDatasetNotFoundError(f"Archive file not found: {archive}")

        out_dir.mkdir(parents=True, exist_ok=True)
        resolved_out_dir = out_dir.resolve()

        # Check if already extracted
        test_shard = out_dir / "test_features.jsonl"
        train_shard = out_dir / "train_features_0.jsonl"
        if not force and test_shard.is_file() and train_shard.is_file():
            logger.info("Extracted EMBER JSONL shards already exist in %s", out_dir)
            return out_dir

        logger.info("Extracting %s into %s", archive, out_dir)
        with tarfile.open(archive, "r:bz2") as tar:
            # Single-pass streaming audit and extraction
            for member in tar:
                name = member.name.replace("\\", "/")
                # Reject absolute paths or Windows drive letters
                if name.startswith("/") or (len(name) >= 2 and name[0].isalpha() and name[1] == ":"):
                    raise EmberArchiveSecurityError(f"Unsafe absolute path in archive: '{member.name}'")

                # Reject path traversal segments
                segments = name.split("/")
                if ".." in segments:
                    raise EmberArchiveSecurityError(f"Path traversal detected in archive member: '{member.name}'")

                # Resolve target path and verify it stays inside out_dir
                target_path = (resolved_out_dir / member.name).resolve()
                try:
                    target_path.relative_to(resolved_out_dir)
                except ValueError as err:
                    raise EmberArchiveSecurityError(
                        f"Archive member extracts outside destination directory: '{member.name}'"
                    ) from err

                # Reject symlinks/hardlinks targeting outside destination
                if member.issym() or member.islnk():
                    link_target = (resolved_out_dir / member.linkname).resolve()
                    try:
                        link_target.relative_to(resolved_out_dir)
                    except ValueError as err:
                        raise EmberArchiveSecurityError(
                            f"Unsafe link in archive pointing outside destination: '{member.name}' -> '{member.linkname}'"
                        ) from err

                # Extract single member safely
                if hasattr(tarfile, "data_filter"):
                    tar.extract(member, path=resolved_out_dir, filter="data")
                else:
                    tar.extract(member, path=resolved_out_dir)

                if member.isfile():
                    logger.info("Extracted member: %s (%.1f MB)", member.name, member.size / (1024 * 1024))

        # Check if files were extracted into a nested subfolder (e.g. ember2018/)
        nested_dir = resolved_out_dir / "ember2018"
        if nested_dir.is_dir() and not (resolved_out_dir / "test_features.jsonl").is_file():
            for item in nested_dir.iterdir():
                dest_file = resolved_out_dir / item.name
                if not dest_file.exists():
                    item.rename(dest_file)

        logger.info("Extraction complete. Destination: %s", out_dir)
        return out_dir

    # --------------------------------------------------------------------------
    # 3. JSONL Shard Discovery & Streaming
    # --------------------------------------------------------------------------
    def discover_shards(self, data_dir: Optional[Path] = None) -> Tuple[List[Path], Path]:
        """Discover training shards (train_features_*.jsonl) and test shard (test_features.jsonl)."""
        target_dir = data_dir or self.dataset_dir

        # Check in target_dir or nested ember2018/
        candidates = [target_dir, target_dir / "ember2018"]
        train_shards: List[Path] = []
        test_shard: Optional[Path] = None

        for c in candidates:
            if c.is_dir():
                found_train = sorted(c.glob("train_features_*.jsonl"))
                found_test = c / "test_features.jsonl"
                if found_train and found_test.is_file():
                    train_shards = found_train
                    test_shard = found_test
                    break

        if not train_shards or test_shard is None or not test_shard.is_file():
            raise EmberDatasetNotFoundError(
                f"Could not find valid EMBER shards in {target_dir} or {target_dir / 'ember2018'}. "
                "Ensure train_features_*.jsonl and test_features.jsonl exist."
            )

        return train_shards, test_shard

    def stream_jsonl(
        self,
        file_path: Path,
    ) -> Generator[Tuple[int, Optional[Dict[str, Any]], Optional[str]], None, None]:
        """Stream raw JSON records line by line from a JSONL file.

        Yields:
            (line_number, parsed_record_dict or None, error_message or None)
        """
        with open(file_path, "r", encoding="utf-8") as fin:
            for line_idx, line in enumerate(fin, start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                try:
                    record = json.loads(clean_line)
                    yield (line_idx, record, None)
                except json.JSONDecodeError as err:
                    yield (line_idx, None, f"JSONDecodeError on line {line_idx}: {err}")

    # --------------------------------------------------------------------------
    # 4. Ingestion, Manifest Creation & Quality Validation
    # --------------------------------------------------------------------------
    def inspect_and_build_manifest(
        self,
        data_dir: Optional[Path] = None,
        *,
        output_manifest_path: Optional[Path] = None,
    ) -> Tuple[DatasetManifest, IngestionSummary]:
        """Inspect all dataset shards, enforce label policy, detect duplicates/leakage, and produce manifest."""
        train_shards, test_shard = self.discover_shards(data_dir)
        summary = IngestionSummary()

        train_digests: Set[str] = set()
        test_digests: Set[str] = set()
        all_digests: Dict[str, List[str]] = {}

        # 1. Process training shards
        for shard in train_shards:
            for line_no, record, err in self.stream_jsonl(shard):
                summary.total_records_read += 1
                if err or record is None:
                    summary.malformed_records_count += 1
                    summary.malformed_records.append({
                        "file": shard.name,
                        "line": line_no,
                        "error": err,
                    })
                    continue

                raw_label = record.get("label")
                mapped = normalize_source_label(raw_label)
                if mapped is None:
                    # -1 unlabeled record -> excluded
                    summary.unlabeled_records_excluded += 1
                    continue

                sha = record.get("sha256", "").lower()
                if not sha or len(sha) != 64:
                    summary.malformed_records_count += 1
                    continue

                summary.labeled_records_retained += 1
                summary.train_records_count += 1
                train_digests.add(sha)
                all_digests.setdefault(sha, []).append(f"train:{shard.name}:{line_no}")

        # 2. Process test shard
        for line_no, record, err in self.stream_jsonl(test_shard):
            summary.total_records_read += 1
            if err or record is None:
                summary.malformed_records_count += 1
                summary.malformed_records.append({
                    "file": test_shard.name,
                    "line": line_no,
                    "error": err,
                })
                continue

            raw_label = record.get("label")
            mapped = normalize_source_label(raw_label)
            if mapped is None:
                summary.unlabeled_records_excluded += 1
                continue

            sha = record.get("sha256", "").lower()
            if not sha or len(sha) != 64:
                summary.malformed_records_count += 1
                continue

            summary.labeled_records_retained += 1
            summary.test_records_count += 1
            test_digests.add(sha)
            all_digests.setdefault(sha, []).append(f"test:{test_shard.name}:{line_no}")

        # 3. Detect duplicates and cross-split leakage
        duplicate_digests = [h for h, locs in all_digests.items() if len(locs) > 1]
        summary.duplicate_digest_count = len(duplicate_digests)
        summary.duplicate_digests = sorted(duplicate_digests)

        overlap = train_digests.intersection(test_digests)
        summary.cross_split_leakage_count = len(overlap)
        summary.cross_split_leakage_digests = sorted(list(overlap))

        # 4. Build DatasetManifest
        manifest_path = output_manifest_path or (self.dataset_dir / "dataset_manifest.json")
        manifest = DatasetManifest(
            manifest_id=f"ember-2018-v2-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            dataset_name=EMBER_2018_DATASET_NAME,
            dataset_version=f"{EMBER_2018_DATASET_VERSION}.v{EMBER_2018_FEATURE_VERSION}",
            schema_version="1.0.0",
            source=EMBER_2018_UPSTREAM_REPOSITORY_URL,
            label_mapping=dict(DEFAULT_EMBER_LABEL_MAPPING),
            class_definitions=dict(DEFAULT_CLASS_DEFINITIONS),
            sample_count=summary.labeled_records_retained,
            split_counts=SplitCounts(
                train=summary.train_records_count,
                validation=0,
                test=summary.test_records_count,
                unassigned=0,
            ),
            excluded_unlabeled_count=summary.unlabeled_records_excluded,
            integrity_digest=self.expected_sha256,
            assumptions_and_limitations=[
                "Samples collected through 2018; subject to temporal concept drift on post-2018 evasions.",
                "Unlabeled samples (-1) are strictly excluded from supervised training and evaluation.",
                "Feature vectorization conforms to ember_pe_v2 (2,381 dimensions) with Size-before-RVA in DataDirectories.",
            ],
            created_at=datetime.now(timezone.utc),
        )

        with open(manifest_path, "w", encoding="utf-8") as fout:
            json.dump(manifest.model_dump(mode="json"), fout, indent=2)

        summary.manifest_path = str(manifest_path)
        return manifest, summary

    # --------------------------------------------------------------------------
    # 5. Resource-Aware Vectorization to Memory-Mapped Arrays
    # --------------------------------------------------------------------------
    def vectorize_records_to_memmap(
        self,
        records_generator: Generator[Tuple[int, Optional[Dict[str, Any]], Optional[str]], None, None],
        x_memmap_path: Path,
        y_memmap_path: Path,
        *,
        max_samples: Optional[int] = None,
        stratified: bool = False,
        class_counts_out: Optional[Dict[int, int]] = None,
        chunk_size: int = 5000,
    ) -> Tuple[int, int]:
        """Stream raw JSON records, vectorize in chunks, and write directly into memmapped arrays.

        Args:
            records_generator: Generator yielding (line_idx, record, err).
            x_memmap_path: Path to write X array (float32, shape=(N, 2381)).
            y_memmap_path: Path to write y array (float32, shape=(N,)).
            max_samples: Optional cap on retained labeled samples (for bounded/subset testing).
            stratified: If True and max_samples is set, balances classes 0 and 1 equally.
            class_counts_out: Optional dict updated in-place with per-class retained counts.
            chunk_size: Processing batch size before flushing to disk.

        Returns:
            Tuple of (total_retained_samples, total_excluded_unlabeled).
        """
        dim = self.vectorizer.dim
        x_memmap_path.parent.mkdir(parents=True, exist_ok=True)
        y_memmap_path.parent.mkdir(parents=True, exist_ok=True)

        # Temporary buffer for chunked writes
        x_buf: List[np.ndarray] = []
        y_buf: List[float] = []

        # We first accumulate into a temporary raw binary or sized memmap
        temp_x_file = x_memmap_path.with_suffix(".tmp")
        temp_y_file = y_memmap_path.with_suffix(".tmp")

        retained = 0
        excluded = 0
        class_counts: Dict[int, int] = {0: 0, 1: 0}
        per_class_limit = (max_samples // 2) if (stratified and max_samples is not None) else None

        with open(temp_x_file, "wb") as fx, open(temp_y_file, "wb") as fy:
            for line_no, record, err in records_generator:
                if err or record is None:
                    continue

                raw_label = record.get("label")
                target_label = normalize_source_label(raw_label)
                if target_label is None:
                    excluded += 1
                    continue

                # In stratified mode, enforce balanced class limit
                if per_class_limit is not None and class_counts[target_label] >= per_class_limit:
                    continue

                # Vectorize raw record
                vec = self.vectorizer.vectorize_raw_record(record)
                x_buf.append(vec)
                y_buf.append(float(target_label))
                retained += 1
                class_counts[target_label] += 1

                if len(x_buf) >= chunk_size:
                    chunk_x = np.vstack(x_buf).astype(np.float32)
                    chunk_y = np.array(y_buf, dtype=np.float32)
                    fx.write(chunk_x.tobytes())
                    fy.write(chunk_y.tobytes())
                    x_buf.clear()
                    y_buf.clear()

                if max_samples is not None and retained >= max_samples:
                    break

            if x_buf:
                chunk_x = np.vstack(x_buf).astype(np.float32)
                chunk_y = np.array(y_buf, dtype=np.float32)
                fx.write(chunk_x.tobytes())
                fy.write(chunk_y.tobytes())
                x_buf.clear()
                y_buf.clear()

        if class_counts_out is not None:
            class_counts_out.update(class_counts)

        # Atomic move to final destination
        if temp_x_file.exists():
            if x_memmap_path.exists():
                x_memmap_path.unlink()
            temp_x_file.replace(x_memmap_path)

        if temp_y_file.exists():
            if y_memmap_path.exists():
                y_memmap_path.unlink()
            temp_y_file.replace(y_memmap_path)

        return retained, excluded

    def load_memmap_features(
        self,
        x_memmap_path: Path,
        y_memmap_path: Path,
        n_samples: int,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Load memory-mapped feature and label arrays in read-only mode."""
        dim = self.vectorizer.dim
        X = np.memmap(x_memmap_path, dtype=np.float32, mode="r", shape=(n_samples, dim))
        y = np.memmap(y_memmap_path, dtype=np.float32, mode="r", shape=(n_samples,))
        return X, y
