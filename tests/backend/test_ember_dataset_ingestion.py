"""Tests for EMBER dataset acquisition, safe extraction, streaming, and validation.

Verifies:
- Checksum verification and corrupted archive detection.
- Path-traversal security during archive extraction.
- Incremental JSONL streaming with malformed record handling.
- Label policy enforcement: 0->0, 1->1, -1 excluded.
- Duplicate digest and cross-split leakage detection.
- Dataset manifest generation and contract validation.
- Memory-mapped array streaming vectorization.
"""

from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tarfile
from typing import Any, Dict, List
import pytest

import jsonschema
import numpy as np

from app.schemas.ml_contracts import (
    EMBER_2018_CANONICAL_FEATURE_DIMENSION,
    DatasetManifest,
    normalize_source_label,
)
from app.services.ember_dataset_service import (
    EmberArchiveSecurityError,
    EmberChecksumMismatchError,
    EmberDatasetNotFoundError,
    EmberDatasetService,
    IngestionSummary,
)
from app.services.ember_raw_vectorizer import EmberRawFeatureVectorizer


@pytest.fixture
def synthetic_raw_sample() -> Dict[str, Any]:
    """Return a single valid synthetic raw feature record."""
    return {
        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "appeared": "2018-05",
        "label": 1,
        "avclass": "trojan",
        "histogram": [1] * 256,
        "byteentropy": [2] * 256,
        "strings": {
            "numstrings": 10,
            "avlength": 15.0,
            "printables": 150,
            "printabledist": [1] * 96,
            "entropy": 5.0,
            "paths": 1,
            "urls": 1,
            "registry": 0,
            "MZ": 1,
        },
        "general": {
            "size": 2048,
            "vsize": 4096,
            "has_debug": 1,
            "exports": 0,
            "imports": 5,
            "has_relocations": 1,
            "has_resources": 0,
            "has_signature": 0,
            "has_tls": 0,
            "symbols": 0,
        },
        "header": {
            "coff": {"timestamp": 1520000000, "machine": "I386", "characteristics": ["EXECUTABLE_IMAGE"]},
            "optional": {
                "subsystem": "WINDOWS_GUI",
                "dll_characteristics": ["DYNAMIC_BASE"],
                "magic": "PE32",
                "major_image_version": 1,
                "minor_image_version": 0,
                "major_linker_version": 14,
                "minor_linker_version": 0,
                "major_operating_system_version": 6,
                "minor_operating_system_version": 0,
                "major_subsystem_version": 6,
                "minor_subsystem_version": 0,
                "sizeof_code": 1024,
                "sizeof_headers": 512,
                "sizeof_heap_commit": 4096,
            },
        },
        "section": {
            "entry": ".text",
            "sections": [
                {"name": ".text", "size": 1024, "entropy": 6.0, "vsize": 1000, "props": ["MEM_READ", "MEM_EXECUTE"]},
            ],
        },
        "imports": {"kernel32.dll": ["ExitProcess", "GetProcAddress"]},
        "exports": [],
        "datadirectories": [
            {"name": "EXPORT_TABLE", "size": 0, "virtual_address": 0},
            {"name": "IMPORT_TABLE", "size": 128, "virtual_address": 2048},
        ],
    }


@pytest.fixture
def manifest_json_schema() -> Dict[str, Any]:
    """Load the shared dataset_manifest.schema.json."""
    schema_path = Path("shared/schemas/dataset_manifest.schema.json").resolve()
    with open(schema_path, "r", encoding="utf-8") as fin:
        return json.load(fin)


# ==============================================================================
# Archive Checksum & Download Verification Tests
# ==============================================================================

class TestArchiveChecksumAndIntegrity:
    """Verify archive hashing, verification, and corruption detection."""

    def test_checksum_verification_success(self, tmp_path: Path):
        """Valid archive file matching expected SHA-256 returns True."""
        content = b"EMBER 2018 V2 ARCHIVE TEST BYTES"
        expected_hash = hashlib.sha256(content).hexdigest()

        archive_file = tmp_path / "test_archive.tar.bz2"
        archive_file.write_bytes(content)

        service = EmberDatasetService(dataset_dir=tmp_path, expected_sha256=expected_hash)
        assert service.verify_archive_checksum(archive_file) is True

    def test_checksum_verification_failure_on_corrupt_file(self, tmp_path: Path):
        """Corrupt archive file with different checksum returns False."""
        archive_file = tmp_path / "corrupt_archive.tar.bz2"
        archive_file.write_bytes(b"CORRUPTED CONTENT")

        service = EmberDatasetService(dataset_dir=tmp_path, expected_sha256="a" * 64)
        assert service.verify_archive_checksum(archive_file) is False

    def test_verify_archive_checksum_missing_file_returns_false(self, tmp_path: Path):
        """Nonexistent archive file returns False without raising unhandled error."""
        missing = tmp_path / "nonexistent.tar.bz2"
        service = EmberDatasetService(dataset_dir=tmp_path, expected_sha256="b" * 64)
        assert service.verify_archive_checksum(missing) is False


# ==============================================================================
# Safe Archive Extraction Tests
# ==============================================================================

class TestSafeArchiveExtraction:
    """Verify path traversal rejection and safe member extraction."""

    def test_reject_path_traversal_archive(self, tmp_path: Path):
        """Archive containing '..' path traversal segments must raise EmberArchiveSecurityError."""
        archive_path = tmp_path / "evil_traversal.tar.bz2"

        with tarfile.open(archive_path, "w:bz2") as tar:
            data = b"malicious payload"
            ti = tarfile.TarInfo(name="../escape_root.txt")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

        service = EmberDatasetService(dataset_dir=tmp_path)
        with pytest.raises(EmberArchiveSecurityError) as exc_info:
            service.extract_archive(archive_path, tmp_path / "extracted")
        assert "Path traversal detected" in str(exc_info.value)

    def test_reject_absolute_path_archive(self, tmp_path: Path):
        """Archive containing absolute POSIX path must raise EmberArchiveSecurityError."""
        archive_path = tmp_path / "evil_absolute.tar.bz2"

        with tarfile.open(archive_path, "w:bz2") as tar:
            data = b"malicious payload"
            ti = tarfile.TarInfo(name="/etc/cron.d/malicious")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

        service = EmberDatasetService(dataset_dir=tmp_path)
        with pytest.raises(EmberArchiveSecurityError) as exc_info:
            service.extract_archive(archive_path, tmp_path / "extracted")
        assert "Unsafe absolute path" in str(exc_info.value)

    def test_extract_safe_archive(self, tmp_path: Path):
        """Safe archive members are extracted successfully inside destination."""
        archive_path = tmp_path / "safe.tar.bz2"
        dest_dir = tmp_path / "extracted"

        with tarfile.open(archive_path, "w:bz2") as tar:
            data = b'{"label": 0}\n'
            ti = tarfile.TarInfo(name="train_features_0.jsonl")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

            ti2 = tarfile.TarInfo(name="test_features.jsonl")
            ti2.size = len(data)
            tar.addfile(ti2, io.BytesIO(data))

        service = EmberDatasetService(dataset_dir=tmp_path)
        service.extract_archive(archive_path, dest_dir)

        assert (dest_dir / "train_features_0.jsonl").is_file()
        assert (dest_dir / "test_features.jsonl").is_file()


# ==============================================================================
# JSONL Streaming & Malformed Record Tests
# ==============================================================================

class TestJsonlStreamingAndErrorHandling:
    """Verify streaming line-by-line reading and error tracking."""

    def test_stream_valid_and_malformed_lines(self, tmp_path: Path):
        """Stream JSONL yielding valid records and tracking line numbers for malformed lines."""
        jsonl_path = tmp_path / "test.jsonl"
        lines = [
            '{"sha256": "abc", "label": 0}\n',
            'THIS IS INVALID JSON LINE\n',
            '\n',  # empty line
            '{"sha256": "def", "label": 1}\n',
        ]
        jsonl_path.write_text("".join(lines), encoding="utf-8")

        service = EmberDatasetService(dataset_dir=tmp_path)
        items = list(service.stream_jsonl(jsonl_path))

        assert len(items) == 3  # empty line skipped
        # Line 1: valid
        assert items[0][0] == 1
        assert items[0][1]["sha256"] == "abc"
        assert items[0][2] is None

        # Line 2: malformed
        assert items[1][0] == 2
        assert items[1][1] is None
        assert "JSONDecodeError" in items[1][2]

        # Line 4 (after empty line): valid
        assert items[2][0] == 4
        assert items[2][1]["sha256"] == "def"
        assert items[2][2] is None


# ==============================================================================
# Label Policy & Exclusion Tests
# ==============================================================================

class TestLabelNormalizationAndExclusion:
    """Verify strict EMBER label policy (0->BENIGN, 1->MALICIOUS, -1->Excluded)."""

    def test_benign_label_normalization(self):
        assert normalize_source_label(0) == 0
        assert normalize_source_label("0") == 0

    def test_malicious_label_normalization(self):
        assert normalize_source_label(1) == 1
        assert normalize_source_label("1") == 1

    def test_unlabeled_exclusion(self):
        """Unlabeled samples (-1) return None and are never converted to 0."""
        assert normalize_source_label(-1) is None
        assert normalize_source_label("-1") is None

    def test_unsupported_label_raises_value_error(self):
        with pytest.raises(ValueError):
            normalize_source_label(2)
        with pytest.raises(ValueError):
            normalize_source_label("SUSPICIOUS")


# ==============================================================================
# Duplicate Digest and Cross-Split Leakage Tests
# ==============================================================================

class TestDuplicateAndLeakageDetection:
    """Verify duplicate SHA-256 detection and cross-split leakage identification."""

    def test_duplicate_and_leakage_detection(self, tmp_path: Path, synthetic_raw_sample: Dict[str, Any]):
        """Detect intra-split duplicates and cross-split overlap."""
        sha_train_dup = "1" * 64
        sha_leaked = "2" * 64
        sha_unique_test = "3" * 64

        sample1 = dict(synthetic_raw_sample, sha256=sha_train_dup, label=0)
        sample2 = dict(synthetic_raw_sample, sha256=sha_train_dup, label=0)
        sample3 = dict(synthetic_raw_sample, sha256=sha_leaked, label=1)

        train_file = tmp_path / "train_features_0.jsonl"
        with open(train_file, "w", encoding="utf-8") as f:
            for s in [sample1, sample2, sample3]:
                f.write(json.dumps(s) + "\n")

        # Test shard contains leaked sample and unique test sample
        sample4 = dict(synthetic_raw_sample, sha256=sha_leaked, label=1)
        sample5 = dict(synthetic_raw_sample, sha256=sha_unique_test, label=0)
        sample6 = dict(synthetic_raw_sample, sha256="4" * 64, label=-1)  # excluded unlabeled

        test_file = tmp_path / "test_features.jsonl"
        with open(test_file, "w", encoding="utf-8") as f:
            for s in [sample4, sample5, sample6]:
                f.write(json.dumps(s) + "\n")

        service = EmberDatasetService(dataset_dir=tmp_path)
        manifest, summary = service.inspect_and_build_manifest(tmp_path)

        # Check duplicate
        assert summary.duplicate_digest_count >= 1
        assert sha_train_dup in summary.duplicate_digests

        # Check cross-split leakage
        assert summary.cross_split_leakage_count == 1
        assert sha_leaked in summary.cross_split_leakage_digests

        # Check unlabeled exclusion
        assert summary.unlabeled_records_excluded == 1
        assert summary.total_records_read == 6
        assert summary.labeled_records_retained == 5


# ==============================================================================
# Dataset Manifest Conformance Tests
# ==============================================================================

class TestManifestGenerationAndConformance:
    """Verify generated manifest conforms to Pydantic and JSON Schema contracts."""

    def test_manifest_conforms_to_schema(
        self,
        tmp_path: Path,
        synthetic_raw_sample: Dict[str, Any],
        manifest_json_schema: Dict[str, Any],
    ):
        """Manifest produced by inspect_and_build_manifest validates against shared JSON Schema."""
        train_file = tmp_path / "train_features_0.jsonl"
        test_file = tmp_path / "test_features.jsonl"

        s_train = dict(synthetic_raw_sample, sha256="a" * 64, label=0)
        s_test = dict(synthetic_raw_sample, sha256="b" * 64, label=1)
        s_unlabeled = dict(synthetic_raw_sample, sha256="c" * 64, label=-1)

        with open(train_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(s_train) + "\n")
            f.write(json.dumps(s_unlabeled) + "\n")

        with open(test_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(s_test) + "\n")

        service = EmberDatasetService(dataset_dir=tmp_path)
        manifest, summary = service.inspect_and_build_manifest(tmp_path)

        # Validate with Pydantic
        assert isinstance(manifest, DatasetManifest)
        assert manifest.sample_count == 2
        assert manifest.split_counts.train == 1
        assert manifest.split_counts.test == 1
        assert manifest.excluded_unlabeled_count == 1

        # Validate against shared JSON Schema
        manifest_dict = manifest.model_dump(mode="json")
        jsonschema.validate(instance=manifest_dict, schema=manifest_json_schema)


# ==============================================================================
# Memory-Mapped Vectorization Tests
# ==============================================================================

class TestMemmapVectorization:
    """Verify streaming vectorization to disk-backed memmap arrays."""

    def test_vectorize_records_to_memmap(self, tmp_path: Path, synthetic_raw_sample: Dict[str, Any]):
        """Vectorize stream of JSON records and verify memory-mapped array contents."""
        service = EmberDatasetService(dataset_dir=tmp_path)
        x_path = tmp_path / "X_train.dat"
        y_path = tmp_path / "y_train.dat"

        sample_benign = dict(synthetic_raw_sample, sha256="1" * 64, label=0)
        sample_malicious = dict(synthetic_raw_sample, sha256="2" * 64, label=1)
        sample_unlabeled = dict(synthetic_raw_sample, sha256="3" * 64, label=-1)

        def records_gen():
            yield (1, sample_benign, None)
            yield (2, sample_unlabeled, None)
            yield (3, sample_malicious, None)

        retained, excluded = service.vectorize_records_to_memmap(records_gen(), x_path, y_path)

        assert retained == 2
        assert excluded == 1
        assert x_path.is_file()
        assert y_path.is_file()

        # Load back with load_memmap_features
        X, y = service.load_memmap_features(x_path, y_path, retained)

        assert X.shape == (2, EMBER_2018_CANONICAL_FEATURE_DIMENSION)
        assert y.shape == (2,)
        assert y[0] == 0.0
        assert y[1] == 1.0
        assert np.all(np.isfinite(X))
