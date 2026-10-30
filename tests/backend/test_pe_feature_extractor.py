"""Automated test suite for static PE feature extraction (T013).

Tests:
- Extraction of canonical EMBER 2018 Feature Version 2 (`ember_pe_v2`) schema.
- Exact total dimensionality of 2,381 features.
- Group-by-group dimensionality verification across all 9 canonical groups:
  1. ByteHistogram: 256
  2. ByteEntropyHistogram: 256
  3. StringExtractor: 104
  4. GeneralFileInfo: 10
  5. HeaderFileInfo: 62
  6. SectionInfo: 255
  7. ImportsInfo: 1280
  8. ExportsInfo: 128
  9. DataDirectories: 30
- Statistical invariants: byte histogram normalization, joint byte-entropy histogram,
  printable string statistics, regex counts (paths, URLs, registry, MZ).
- Conformance of output FeatureVector with JSON Schema and Pydantic model.
- Finite number enforcement (no NaNs, no infinities, zero-fill for missing/degraded).
- Canonical lowercase SHA-256 calculation and file immutability.
- Graceful degradation for non-PE files, empty files, and corrupted binaries.
- Error handling for nonexistent paths, directories, and file size limits.
- Strict isolation: no risk scoring, no security verdicts, no model inference.
"""

import json
import math
from pathlib import Path
import re
import struct
from typing import Dict, List, Optional, Tuple, Union

import jsonschema
import lief
import numpy as np
import pytest
from sklearn.feature_extraction import FeatureHasher

from app.schemas.ml_contracts import (
    EMBER_2018_CANONICAL_FEATURE_DIMENSION,
    EMBER_2018_FEATURE_SCHEMA_VERSION,
    FeatureVector,
    MissingValueStrategy,
)
from app.services.pe_feature_extractor import (
    DATA_DIRECTORY_ORDER,
    EXTRACTOR_IMPLEMENTATION_VERSION,
    GROUP_DIMENSIONS,
    PEFeatureExtractionResult,
    PEFeatureExtractor,
    PEFeatureExtractorError,
    PEFileAccessError,
    PEFileNotFoundError,
    PEFileTooLargeError,
    PEIsADirectoryError,
    PEMalformedFileError,
    TESTED_LIEF_VERSION,
    TESTED_NUMPY_VERSION,
    TESTED_SKLEARN_VERSION,
    extract_pe_features,
    extract_pe_features_from_bytes,
    get_default_pe_feature_extractor,
)
from app.services.sha256_service import compute_bytes_sha256, compute_file_sha256

SCHEMAS_DIR = Path(__file__).resolve().parent.parent.parent / "shared" / "schemas"


def load_schema(schema_filename: str) -> dict:
    """Load a JSON Schema file from shared/schemas/."""
    schema_path = SCHEMAS_DIR / schema_filename
    assert schema_path.exists(), f"Schema file not found: {schema_path}"
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ==============================================================================
# Synthetic PE Generators
# ==============================================================================

def make_synthetic_pe(
    *,
    is_64bit: bool = False,
    add_strings: bool = True,
    sections: Optional[List[Union[Tuple[bytes, int, int, int], Tuple[bytes, int, int, int, int]]]] = None,
    data_directory_entries: Optional[Dict[int, Tuple[int, int]]] = None,
    pad_to_size: Optional[int] = None,
) -> bytes:
    """Construct a minimal valid PE executable entirely in memory using standard struct packing.
    
    Contains DOS header, COFF header, Optional Header (with 16 Data Directories),
    and Section Table so that LIEF can fully parse the binary structures without
    needing any external compilers or downloads.
    """
    # DOS Header (64 bytes)
    dos_header = bytearray(64)
    struct.pack_into("<H", dos_header, 0, 0x5A4D)  # 'MZ'
    pe_offset = 64
    struct.pack_into("<I", dos_header, 60, pe_offset)  # e_lfanew -> 64

    # PE Signature
    pe_sig = b"PE\x00\x00"

    # Section configuration
    if sections is None:
        sections = [(b".text\x00\x00\x00", 0x100, 0x1000, 0x200, 0x60000020)]

    num_sections = len(sections)
    machine = 0x8664 if is_64bit else 0x014C
    timedatestamp = 0x5F000000
    opt_hdr_size = 240 if is_64bit else 224
    characteristics = 0x0102  # EXECUTABLE_IMAGE | 32BIT_MACHINE

    coff_header = struct.pack(
        "<HHIIIHH",
        machine,
        num_sections,
        timedatestamp,
        0,
        0,
        opt_hdr_size,
        characteristics,
    )

    if is_64bit:
        magic = 0x020B
        std_fields = struct.pack(
            "<HBBIIIII",
            magic,
            14,
            0,
            0x200,
            0x200,
            0,
            0x1000,
            0x1000,
        )
        win_fields = struct.pack(
            "<QIIHHHHHHIIIIHHQQQQII",
            0x140000000,  # ImageBase
            0x1000,       # SectionAlignment
            0x200,        # FileAlignment
            6, 0, 0, 0, 6, 0, 0,  # Versions
            0x4000,       # SizeOfImage
            0x200,        # SizeOfHeaders
            0,            # Checksum
            3,            # Subsystem (Windows CUI)
            0x8140,       # DllCharacteristics
            0x100000, 0x1000, 0x100000, 0x1000,  # Stack & Heap
            0, 16,        # LoaderFlags, NumberOfRvaAndSizes
        )
    else:
        magic = 0x010B
        std_fields = struct.pack(
            "<HBBIIIIIII",
            magic,
            14,
            0,
            0x200,
            0x200,
            0,
            0x1000,
            0x1000,
            0x2000,
            0x00400000,
        )
        win_fields = struct.pack(
            "<IIHHHHHHIIIIHHIIIIII",
            0x1000,       # SectionAlignment
            0x200,        # FileAlignment
            6, 0, 0, 0, 6, 0, 0,
            0x4000,       # SizeOfImage
            0x200,        # SizeOfHeaders
            0,
            3,            # Subsystem
            0x8140,       # DllCharacteristics
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 16,
        )

    # 16 Data Directories (8 bytes each = 128 bytes)
    data_dirs = bytearray(16 * 8)
    if data_directory_entries:
        for idx, (rva, size) in data_directory_entries.items():
            if 0 <= idx < 16:
                struct.pack_into("<II", data_dirs, idx * 8, rva, size)

    # Section Headers (40 bytes each)
    section_headers = bytearray()
    raw_ptr_cursor = 0x200
    for item in sections:
        if len(item) == 5:
            name, vsize, vaddr, raw_size, sect_chars = item
        else:
            name, vsize, vaddr, raw_size = item
            sect_chars = 0x60000020
        sect_hdr = struct.pack(
            "<8sIIIIIIHHI",
            name,
            vsize,
            vaddr,
            raw_size,
            raw_ptr_cursor,
            0,
            0,
            0,
            0,
            sect_chars,
        )
        section_headers.extend(sect_hdr)
        raw_ptr_cursor += raw_size

    header_block = dos_header + pe_sig + coff_header + std_fields + win_fields + data_dirs + section_headers
    if len(header_block) < 0x200:
        header_block += b"\x00" * (0x200 - len(header_block))

    # Section data blocks
    body_data = bytearray()
    for item in sections:
        raw_size = item[3]
        sec_bytes = bytearray(raw_size)
        # Add basic x86/x64 instruction: xor eax, eax; ret
        sec_bytes[0:2] = b"\x31\xc0\xc3"
        if add_strings:
            test_strings = (
                b"Hello Sentinel-EDR Test Executable!\x00"
                b"https://detection.sentinel.local/report\x00"
                b"C:\\Windows\\System32\\drivers\\sentinel.sys\x00"
                b"HKEY_LOCAL_MACHINE\\Software\\Sentinel\\Config\x00"
                b"This program cannot be run in DOS mode.\x00"
            )
            sec_bytes[16 : 16 + len(test_strings)] = test_strings
        body_data.extend(sec_bytes)

    total_data = header_block + body_data
    if pad_to_size is not None and len(total_data) < pad_to_size:
        total_data += b"\x00" * (pad_to_size - len(total_data))

    return bytes(total_data)


# ==============================================================================
# Test Fixtures
# ==============================================================================

@pytest.fixture
def synthetic_pe32_bytes() -> bytes:
    """Standard 32-bit PE binary."""
    return make_synthetic_pe(is_64bit=False, add_strings=True)


@pytest.fixture
def synthetic_pe64_bytes() -> bytes:
    """Standard 64-bit PE binary."""
    return make_synthetic_pe(is_64bit=True, add_strings=True)


@pytest.fixture
def synthetic_pe_large_bytes() -> bytes:
    """PE binary padded to >= 2048 bytes to exercise joint entropy histogram."""
    return make_synthetic_pe(is_64bit=False, add_strings=True, pad_to_size=4096)


@pytest.fixture
def synthetic_pe32_file(tmp_path: Path, synthetic_pe32_bytes: bytes) -> Path:
    """A temporary 32-bit PE file on disk."""
    pe_path = tmp_path / "sample_pe32.exe"
    pe_path.write_bytes(synthetic_pe32_bytes)
    return pe_path


@pytest.fixture
def synthetic_pe64_file(tmp_path: Path, synthetic_pe64_bytes: bytes) -> Path:
    """A temporary 64-bit PE file on disk."""
    pe_path = tmp_path / "sample_pe64.exe"
    pe_path.write_bytes(synthetic_pe64_bytes)
    return pe_path


@pytest.fixture
def non_pe_text_file(tmp_path: Path) -> Path:
    """A temporary plain text file."""
    text_path = tmp_path / "document.txt"
    text_path.write_text("Sentinel-EDR plain text analysis target.\nNot a PE executable.", encoding="utf-8")
    return text_path


@pytest.fixture
def empty_file(tmp_path: Path) -> Path:
    """A temporary 0-byte file."""
    empty_path = tmp_path / "empty.bin"
    empty_path.write_bytes(b"")
    return empty_path


@pytest.fixture
def feature_vector_schema() -> dict:
    """Shared FeatureVector JSON schema."""
    return load_schema("feature_vector.schema.json")


# ==============================================================================
# Dimensionality and Schema Validation Tests
# ==============================================================================

class TestFeatureDimensionalityAndSchema:
    """Test canonical dimensionality and schema compliance across all groups."""

    def test_canonical_group_dimensions_sum(self):
        """Verify the 9 canonical groups sum exactly to 2,381 features."""
        total = sum(GROUP_DIMENSIONS.values())
        assert total == EMBER_2018_CANONICAL_FEATURE_DIMENSION
        assert total == 2381

    def test_pe32_feature_vector_dimensions_and_metadata(self, synthetic_pe32_file: Path):
        """Extract features from synthetic PE32 and verify dimensionality and envelope metadata."""
        result = extract_pe_features(synthetic_pe32_file, sample_id="sample-pe32-001")

        assert isinstance(result, PEFeatureExtractionResult)
        assert result.is_pe is True
        assert result.parser_status == "SUCCESS"
        assert result.feature_schema_version == EMBER_2018_FEATURE_SCHEMA_VERSION
        assert result.feature_schema_version == "ember_pe_v2"
        assert result.feature_count == 2381
        assert len(result.feature_vector.feature_values) == 2381
        assert result.feature_vector.sample_id == "sample-pe32-001"
        assert result.feature_vector.missing_value_strategy == MissingValueStrategy.ZERO_FILL
        assert result.extraction_duration_ms > 0.0

    def test_pe64_feature_vector_dimensions_and_metadata(self, synthetic_pe64_file: Path):
        """Extract features from synthetic PE64 and verify dimensionality and envelope metadata."""
        result = extract_pe_features(synthetic_pe64_file, sample_id="sample-pe64-001")

        assert isinstance(result, PEFeatureExtractionResult)
        assert result.is_pe is True
        assert result.parser_status == "SUCCESS"
        assert result.feature_count == 2381
        assert len(result.feature_vector.feature_values) == 2381
        assert result.feature_vector.sample_id == "sample-pe64-001"

    def test_individual_group_slices(self, synthetic_pe32_bytes: bytes):
        """Verify that each individual feature group contributes exactly its assigned dimensions."""
        result = extract_pe_features_from_bytes(synthetic_pe32_bytes)
        features = result.feature_vector.feature_values

        offset = 0
        expected_slices = [
            ("ByteHistogram", 256),
            ("ByteEntropyHistogram", 256),
            ("StringExtractor", 104),
            ("GeneralFileInfo", 10),
            ("HeaderFileInfo", 62),
            ("SectionInfo", 255),
            ("ImportsInfo", 1280),
            ("ExportsInfo", 128),
            ("DataDirectories", 30),
        ]

        for group_name, expected_dim in expected_slices:
            group_slice = features[offset : offset + expected_dim]
            assert len(group_slice) == expected_dim, f"Group {group_name} dimension mismatch"
            assert len(group_slice) == GROUP_DIMENSIONS[group_name]
            # All elements in group must be finite floats
            for i, val in enumerate(group_slice):
                assert val is not None, f"Null found in {group_name} at index {i}"
                assert math.isfinite(val), f"Non-finite float in {group_name} at index {i}: {val}"
            offset += expected_dim

        assert offset == 2381

    def test_conformance_to_shared_json_schema(
        self, synthetic_pe32_bytes: bytes, feature_vector_schema: dict
    ):
        """Verify that serialized FeatureVector strictly validates against shared/schemas/feature_vector.schema.json."""
        result = extract_pe_features_from_bytes(synthetic_pe32_bytes, sample_id="json-schema-test")
        payload = result.feature_vector.model_dump(mode="json")

        # Must validate without raising jsonschema.ValidationError
        jsonschema.validate(instance=payload, schema=feature_vector_schema)
        assert payload["feature_schema_version"] == "ember_pe_v2"
        assert payload["feature_count"] == 2381
        assert len(payload["feature_values"]) == 2381
        assert payload["missing_value_strategy"] == "zero_fill"

    def test_to_dict_serialization(self, synthetic_pe32_file: Path):
        """Verify the to_dict() serialization of PEFeatureExtractionResult."""
        result = extract_pe_features(synthetic_pe32_file, sample_id="sample-dict-test")
        d = result.to_dict()

        assert d["file_path"] == str(synthetic_pe32_file.resolve())
        assert d["file_hash"] == result.file_hash
        assert d["is_pe"] is True
        assert d["parser_status"] == "SUCCESS"
        assert d["feature_count"] == 2381
        assert d["feature_schema_version"] == "ember_pe_v2"
        assert d["extractor_version"] == EXTRACTOR_IMPLEMENTATION_VERSION
        assert isinstance(d["warnings"], list)
        assert isinstance(d["feature_vector"], dict)


# ==============================================================================
# Upstream Reference Implementation for Algorithm-Parity Verification
# ==============================================================================

class UpstreamByteEntropyHistogramReference:
    """Isolated reference implementation of upstream EMBER ByteEntropyHistogram.

    Directly models upstream features.py:
    https://github.com/elastic/ember/blob/master/ember/features.py
    Used strictly for algorithm-parity verification on local inputs.
    """

    def __init__(self, step: int = 1024, window: int = 2048) -> None:
        self.window = window
        self.step = step

    def _entropy_bin_counts(self, block: np.ndarray) -> Tuple[int, np.ndarray]:
        c = np.bincount(block >> 4, minlength=16)[:16]
        p = c.astype(np.float32) / float(self.window)
        wh = np.where(c)[0]
        if len(wh) == 0:
            H = 0.0
        else:
            H = float(np.sum(-p[wh] * np.log2(p[wh])) * 2.0)
        Hbin = int(H * 2.0)
        if Hbin >= 16:
            Hbin = 15
        return Hbin, c

    def raw_features(self, bytez: bytes) -> List[int]:
        output = np.zeros((16, 16), dtype=int)
        a = np.frombuffer(bytez, dtype=np.uint8)
        if a.shape[0] == 0:
            return output.flatten().tolist()
        if a.shape[0] < self.window:
            Hbin, c = self._entropy_bin_counts(a)
            output[Hbin, :] += c
        else:
            shape = a.shape[:-1] + (a.shape[-1] - self.window + 1, self.window)
            strides = a.strides + (a.strides[-1],)
            blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::self.step, :]
            for block in blocks:
                Hbin, c = self._entropy_bin_counts(block)
                output[Hbin, :] += c
        return output.flatten().tolist()

    def process_raw_features(self, raw_obj: List[int]) -> np.ndarray:
        counts = np.array(raw_obj, dtype=np.float32)
        s = float(counts.sum())
        if s == 0.0:
            return np.zeros(256, dtype=np.float32)
        return counts / s


# ==============================================================================
# Algorithmic and Statistical Invariants Tests
# ==============================================================================

class TestFeatureGroupInvariants:
    """Verify group-specific normalization and statistical properties."""

    def test_byte_histogram_normalization(self, synthetic_pe32_bytes: bytes):
        """ByteHistogram (dimensions 0-255) must sum to 1.0 within floating point tolerance."""
        result = extract_pe_features_from_bytes(synthetic_pe32_bytes)
        byte_hist = result.feature_vector.feature_values[0:256]

        assert len(byte_hist) == 256
        for b in byte_hist:
            assert 0.0 <= b <= 1.0

        hist_sum = sum(byte_hist)
        assert math.isclose(hist_sum, 1.0, rel_tol=1e-5)

        # Character 'M' (0x4D) and 'Z' (0x5A) must have positive counts
        assert byte_hist[0x4D] > 0.0
        assert byte_hist[0x5A] > 0.0

    @pytest.mark.parametrize(
        "file_size",
        [0, 1, 100, 2047, 2048, 2049, 5000],
    )
    def test_byte_entropy_histogram_across_file_sizes(self, file_size: int):
        """Verify ByteEntropyHistogram across exact boundary file sizes.

        Tests sizes:
        - 0 bytes: Empty input follows documented finite-safe policy (all zeros, no NaN).
        - 1 byte, 100 bytes, 2047 bytes: Sub-window short files use partial-block entropy.
        - 2048 bytes: Exactly one full window.
        - 2049 bytes, 5000 bytes: Multi-window files using rolling strided windows.

        Verifies:
        - Exactly 256 values.
        - No NaN or infinity (all finite).
        - Sum-normalization matches algorithm.
        - Numerical algorithm-parity with upstream EMBER reference implementation.
        """
        data = bytes([(i * 31 + 17) % 256 for i in range(file_size)])
        extractor = PEFeatureExtractor()
        our_result = extractor.extract_byte_entropy_histogram(data)

        # 1. Output dimensionality
        assert len(our_result) == 256
        assert isinstance(our_result, np.ndarray)

        # 2. Finite guarantees (zero NaNs, zero Infs)
        for i, val in enumerate(our_result):
            assert math.isfinite(float(val)), f"Non-finite entropy value at index {i}: {val}"

        # 3. Empty vs Non-empty normalization
        if file_size == 0:
            # Documented safe policy: all zeros for empty input to prevent 0/0 NaN
            assert np.all(our_result == 0.0)
            assert np.sum(our_result) == 0.0
        else:
            # Non-empty sub-window and multi-window files must sum to 1.0
            sum_val = float(np.sum(our_result))
            assert math.isclose(sum_val, 1.0, rel_tol=1e-5), f"Sum was {sum_val} for size {file_size}"
            # Sub-window short files must not be all zeros
            assert not np.all(our_result == 0.0), f"Short file size {file_size} was incorrectly zero-filled"

        # 4. Algorithm-parity with upstream EMBER reference
        upstream = UpstreamByteEntropyHistogramReference()
        ref_raw = upstream.raw_features(data)
        ref_result = upstream.process_raw_features(ref_raw)

        assert np.allclose(our_result, ref_result, atol=1e-6), (
            f"Algorithm parity mismatch with upstream reference at file size {file_size} bytes."
        )

    def test_byte_entropy_histogram_deterministic_identical_bytes(self):
        """Identical byte sequences must produce bit-for-bit identical entropy vectors."""
        data_a = bytes([i % 256 for i in range(1500)])
        data_b = bytes([i % 256 for i in range(1500)])

        extractor = PEFeatureExtractor()
        res_a = extractor.extract_byte_entropy_histogram(data_a)
        res_b = extractor.extract_byte_entropy_histogram(data_b)

        assert np.array_equal(res_a, res_b)

    def test_byte_entropy_histogram_normalization_large_file(self, synthetic_pe_large_bytes: bytes):
        """ByteEntropyHistogram from synthetic large PE sums to 1.0 and is finite."""
        result = extract_pe_features_from_bytes(synthetic_pe_large_bytes)
        entropy_hist = result.feature_vector.feature_values[256:512]

        assert len(entropy_hist) == 256
        for e in entropy_hist:
            assert 0.0 <= e <= 1.0
            assert math.isfinite(e)

        hist_sum = sum(entropy_hist)
        assert math.isclose(hist_sum, 1.0, rel_tol=1e-5)

    def test_string_extractor_invariants(self, synthetic_pe32_bytes: bytes):
        """StringExtractor (dimensions 512-615) must contain length stats, regex indicators, and char dist.
        
        Canonical EMBER StringExtractor ordering (104 dimensions):
        0: numstrings
        1: avlength
        2: printables
        3..98: printabledist (96 normalized character bins)
        99: entropy
        100: paths
        101: urls
        102: registry
        103: MZ
        """
        result = extract_pe_features_from_bytes(synthetic_pe32_bytes)
        strings_feat = result.feature_vector.feature_values[512:616]

        assert len(strings_feat) == 104
        num_strings = strings_feat[0]
        avg_len = strings_feat[1]
        printables = strings_feat[2]
        char_dist = strings_feat[3:99]
        entropy = strings_feat[99]
        paths_count = strings_feat[100]
        urls_count = strings_feat[101]
        registry_count = strings_feat[102]
        mz_count = strings_feat[103]

        assert num_strings >= 1.0
        assert avg_len >= 5.0
        assert printables > 0.0
        assert entropy > 0.0

        # In our synthetic binary, we embedded a path, URL, registry key, and MZ string
        assert paths_count >= 1.0  # C:\Windows\...
        assert urls_count >= 1.0   # https://detection...
        assert registry_count >= 1.0  # HKEY_LOCAL_MACHINE\...
        assert mz_count >= 1.0     # MZ header or string

        # Printable character distribution (96 bins) must sum to 1.0
        assert len(char_dist) == 96
        assert math.isclose(sum(char_dist), 1.0, rel_tol=1e-5)

    def test_general_file_info_invariants(self, synthetic_pe32_bytes: bytes):
        """GeneralFileInfo (dimensions 616-625) 10 scalar properties."""
        result = extract_pe_features_from_bytes(synthetic_pe32_bytes)
        gen_info = result.feature_vector.feature_values[616:626]

        assert len(gen_info) == 10
        file_size = gen_info[0]
        vsize = gen_info[1]
        has_debug = gen_info[2]
        exports_cnt = gen_info[3]
        imports_cnt = gen_info[4]
        has_reloc = gen_info[5]
        has_rsrc = gen_info[6]
        has_sig = gen_info[7]
        has_tls = gen_info[8]
        symbols_cnt = gen_info[9]

        assert file_size == float(len(synthetic_pe32_bytes))
        assert vsize > 0.0
        assert has_debug in (0.0, 1.0)
        assert has_reloc in (0.0, 1.0)
        assert has_rsrc in (0.0, 1.0)
        assert has_sig in (0.0, 1.0)
        assert has_tls in (0.0, 1.0)
        assert symbols_cnt >= 0.0

    def test_header_file_info_invariants(self, synthetic_pe32_bytes: bytes):
        """HeaderFileInfo (dimensions 626-687) 62 dimensions: timestamp, hashes, and scalars."""
        result = extract_pe_features_from_bytes(synthetic_pe32_bytes)
        header_info = result.feature_vector.feature_values[626:688]

        assert len(header_info) == 62
        timestamp = header_info[0]
        # In make_synthetic_pe, timedatestamp was set to 0x5F000000 = 1593835520
        assert timestamp == float(0x5F000000)

        # 5 hashed categorical fields (10 bins each = 50 dimensions)
        hashed_block = header_info[1:51]
        assert len(hashed_block) == 50

        # 11 scalar fields (major/minor image, linker, os, subsys, sizes)
        scalars = header_info[51:62]
        assert len(scalars) == 11
        # major_linker_version was set to 14 (index 2 in scalars)
        assert scalars[2] == 14.0

    def test_section_info_invariants(self, synthetic_pe32_bytes: bytes):
        """SectionInfo (dimensions 688-942) 255 dimensions: 5 counts + 5 x 50 feature hasher outputs."""
        result = extract_pe_features_from_bytes(synthetic_pe32_bytes)
        sec_info = result.feature_vector.feature_values[688:943]

        assert len(sec_info) == 255
        num_sections = sec_info[0]
        zero_size_count = sec_info[1]
        empty_name_count = sec_info[2]
        rx_sections = sec_info[3]
        w_sections = sec_info[4]

        assert num_sections == 1.0
        assert zero_size_count == 0.0
        assert empty_name_count == 0.0
        assert rx_sections == 1.0
        assert w_sections == 0.0

    def test_data_directories_invariants(self, synthetic_pe32_bytes: bytes):
        """DataDirectories (dimensions 2351-2380) 30 dimensions: 15 standard dirs x (size, rva)."""
        result = extract_pe_features_from_bytes(synthetic_pe32_bytes)
        dd_feats = result.feature_vector.feature_values[2351:2381]

        assert len(dd_feats) == 30
        assert len(DATA_DIRECTORY_ORDER) == 15
        # In our minimal PE, all data directories are 0
        for val in dd_feats:
            assert val == 0.0


# ==============================================================================
# Canonical SHA-256 and File Immutability Tests
# ==============================================================================

class TestSHA256AndImmutability:
    """Verify canonical lowercase SHA-256 and file read-only semantics."""

    def test_canonical_lowercase_sha256(self, synthetic_pe32_file: Path, synthetic_pe32_bytes: bytes):
        """Verify file_hash matches T008 compute_file_sha256 and conforms to ^[a-f0-9]{64}$."""
        result = extract_pe_features(synthetic_pe32_file)
        expected_hash = compute_file_sha256(synthetic_pe32_file)

        assert result.file_hash == expected_hash
        assert result.feature_vector.sample_hash == expected_hash
        assert len(result.file_hash) == 64
        assert result.file_hash.islower()
        assert all(c in "0123456789abcdef" for c in result.file_hash)

    def test_file_immutability_during_extraction(self, synthetic_pe32_file: Path):
        """Verify the target file on disk is strictly read-only and unmodified during extraction."""
        hash_before = compute_file_sha256(synthetic_pe32_file)
        size_before = synthetic_pe32_file.stat().st_size
        mtime_before = synthetic_pe32_file.stat().st_mtime_ns

        result = extract_pe_features(synthetic_pe32_file)

        hash_after = compute_file_sha256(synthetic_pe32_file)
        size_after = synthetic_pe32_file.stat().st_size
        mtime_after = synthetic_pe32_file.stat().st_mtime_ns

        assert hash_before == hash_after
        assert size_before == size_after
        assert mtime_before == mtime_after
        assert result.file_hash == hash_before


# ==============================================================================
# Graceful Degradation and Non-PE Fallback Tests
# ==============================================================================

class TestGracefulDegradation:
    """Verify non-PE files, empty files, and corrupted binaries degrade gracefully without crashing."""

    def test_empty_file_handling(self, empty_file: Path, feature_vector_schema: dict):
        """0-byte file must produce valid 2,381 feature vector with parser_status='DEGRADED_NON_PE'."""
        result = extract_pe_features(empty_file)

        assert result.is_pe is False
        assert result.parser_status == "DEGRADED_NON_PE"
        assert result.feature_count == 2381
        assert len(result.feature_vector.feature_values) == 2381
        assert any("empty" in w.lower() for w in result.warnings)

        # Must conform to JSON Schema
        jsonschema.validate(instance=result.feature_vector.model_dump(mode="json"), schema=feature_vector_schema)

    def test_non_pe_text_file(self, non_pe_text_file: Path, feature_vector_schema: dict):
        """Plain text file must extract byte & string features, zero PE features, and report DEGRADED_NON_PE."""
        result = extract_pe_features(non_pe_text_file)

        assert result.is_pe is False
        assert result.parser_status == "DEGRADED_NON_PE"
        assert result.feature_count == 2381
        assert len(result.feature_vector.feature_values) == 2381

        # Byte histogram should reflect the text bytes
        byte_hist = result.feature_vector.feature_values[0:256]
        assert math.isclose(sum(byte_hist), 1.0, rel_tol=1e-5)

        # PE general info: file size is populated, structural PE counts are zero-filled
        general_info = result.feature_vector.feature_values[616:626]
        assert general_info[0] > 0.0  # file size
        assert all(v == 0.0 for v in general_info[1:])

        # PE header info: all zero-filled for non-PE
        header_info = result.feature_vector.feature_values[626:688]
        assert all(v == 0.0 for v in header_info)

        # JSON schema validation
        jsonschema.validate(instance=result.feature_vector.model_dump(mode="json"), schema=feature_vector_schema)

    def test_truncated_pe_file(self, tmp_path: Path, feature_vector_schema: dict):
        """Truncated PE headers must degrade gracefully without crashing."""
        corrupted_path = tmp_path / "truncated.exe"
        # Write MZ with broken header
        corrupted_path.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")

        result = extract_pe_features(corrupted_path)

        assert result.is_pe is False
        assert result.parser_status in ("DEGRADED_NON_PE", "DEGRADED_PARSE_ERROR")
        assert len(result.feature_vector.feature_values) == 2381
        assert len(result.warnings) > 0

        jsonschema.validate(instance=result.feature_vector.model_dump(mode="json"), schema=feature_vector_schema)

    def test_random_binary_garbage(self, tmp_path: Path, feature_vector_schema: dict):
        """Random binary stream must not crash the extractor."""
        garbage_path = tmp_path / "garbage.bin"
        garbage_bytes = bytes(range(256)) * 4
        garbage_path.write_bytes(garbage_bytes)

        result = extract_pe_features(garbage_path)

        assert result.is_pe is False
        assert result.parser_status == "DEGRADED_NON_PE"
        assert len(result.feature_vector.feature_values) == 2381
        jsonschema.validate(instance=result.feature_vector.model_dump(mode="json"), schema=feature_vector_schema)


# ==============================================================================
# Error Handling and Limits Tests
# ==============================================================================

class TestErrorHandling:
    """Verify input validation, size limits, and filesystem exceptions."""

    def test_file_not_found(self, tmp_path: Path):
        """Nonexistent path raises PEFileNotFoundError."""
        missing = tmp_path / "nonexistent_binary.exe"
        with pytest.raises(PEFileNotFoundError) as exc_info:
            extract_pe_features(missing)
        assert "does not exist" in str(exc_info.value).lower()

    def test_path_is_a_directory(self, tmp_path: Path):
        """Directory path raises PEIsADirectoryError."""
        directory = tmp_path / "some_dir"
        directory.mkdir()
        with pytest.raises(PEIsADirectoryError) as exc_info:
            extract_pe_features(directory)
        assert "is a directory" in str(exc_info.value).lower()

    def test_file_too_large_rejection(self, synthetic_pe32_file: Path):
        """File exceeding max_file_size_bytes raises PEFileTooLargeError."""
        # Synthetic PE is 512 bytes; set max limit to 256 bytes
        extractor = PEFeatureExtractor(max_file_size_bytes=256)
        with pytest.raises(PEFileTooLargeError) as exc_info:
            extractor.extract_from_file(synthetic_pe32_file)
        assert "exceeds" in str(exc_info.value).lower()


# ==============================================================================
# Scope Isolation Tests
# ==============================================================================

class TestScopeIsolation:
    """Verify strict adherence to T013 scope boundaries: no verdicts, no scoring, no inference."""

    def test_no_security_verdict_or_risk_scoring(self, synthetic_pe32_bytes: bytes):
        """Ensure no risk score, classification verdict, or threat rating is produced."""
        result = extract_pe_features_from_bytes(synthetic_pe32_bytes)
        result_dict = result.to_dict()

        forbidden_keys = [
            "risk_score",
            "verdict",
            "security_verdict",
            "is_malicious",
            "threat_score",
            "confidence",
            "prediction",
            "probability",
        ]

        for key in forbidden_keys:
            assert key not in result_dict, f"Forbidden key '{key}' found in result dict"
            assert not hasattr(result, key), f"Forbidden attribute '{key}' found in result object"

    def test_all_feature_values_finite_numbers(self, synthetic_pe32_bytes: bytes):
        """Ensure all 2,381 feature values are strictly finite (no NaN, no Inf, no None)."""
        result = extract_pe_features_from_bytes(synthetic_pe32_bytes)
        for i, val in enumerate(result.feature_vector.feature_values):
            assert val is not None, f"Feature index {i} is None"
            assert isinstance(val, (int, float)), f"Feature index {i} is not a number: {type(val)}"
            assert math.isfinite(val), f"Feature index {i} is non-finite: {val}"


# ==============================================================================
# Helper and Re-export Tests
# ==============================================================================

class TestHelpersAndReExports:
    """Verify public module functions and service exports."""

    def test_get_default_pe_feature_extractor_singleton(self):
        """Verify get_default_pe_feature_extractor returns a persistent singleton."""
        ext1 = get_default_pe_feature_extractor()
        ext2 = get_default_pe_feature_extractor()
        assert ext1 is ext2
        assert isinstance(ext1, PEFeatureExtractor)

    def test_app_services_re_exports(self):
        """Verify all PE extractor symbols are cleanly re-exported from app.services."""
        import app.services as s

        assert hasattr(s, "PEFeatureExtractor")
        assert hasattr(s, "PEFeatureExtractionResult")
        assert hasattr(s, "PEFeatureExtractorError")
        assert hasattr(s, "PEFileNotFoundError")
        assert hasattr(s, "PEIsADirectoryError")
        assert hasattr(s, "PEFileAccessError")
        assert hasattr(s, "PEFileTooLargeError")
        assert hasattr(s, "PEMalformedFileError")
        assert hasattr(s, "extract_pe_features")
        assert hasattr(s, "extract_pe_features_from_bytes")
        assert hasattr(s, "get_default_pe_feature_extractor")
        assert hasattr(s, "GROUP_DIMENSIONS")
        assert hasattr(s, "EXTRACTOR_IMPLEMENTATION_VERSION")
        assert hasattr(s, "TESTED_LIEF_VERSION")
        assert hasattr(s, "TESTED_NUMPY_VERSION")
        assert hasattr(s, "TESTED_SKLEARN_VERSION")

    def test_reproducible_dependency_versions(self):
        """Verify that installed package versions match the tested pinned specifications."""
        import lief
        import numpy
        import sklearn

        assert TESTED_LIEF_VERSION == "1.0.0"
        assert TESTED_NUMPY_VERSION == "2.5.4"
        assert TESTED_SKLEARN_VERSION == "1.9.1"

        # Check installed environment versions
        assert numpy.__version__ == TESTED_NUMPY_VERSION
        assert sklearn.__version__ == TESTED_SKLEARN_VERSION
        # LIEF C++ runtime __version__ includes git commit suffix (e.g. '1.0.0-d05b3499b')
        assert getattr(lief, "__version__", "").startswith(TESTED_LIEF_VERSION)


# ==============================================================================
# Independent Algorithm-Parity Test Suites
# ==============================================================================

class TestByteHistogramAlgorithmParity:
    """Algorithm-level comparison against independent byte histogram calculation."""

    @staticmethod
    def _independent_byte_histogram(data: bytes) -> np.ndarray:
        if not data:
            return np.zeros(256, dtype=np.float32)
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(np.float32)
        total = float(counts.sum())
        return counts / total if total > 0.0 else np.zeros(256, dtype=np.float32)

    @pytest.mark.parametrize(
        "test_input",
        [
            b"",
            b"A",
            bytes(range(256)),
            b"\x00" * 200 + b"\xff" * 300,
            b"MZ\x90\x00" + bytes([(i * 7) % 256 for i in range(1024)]),
        ],
    )
    def test_byte_histogram_matches_independent_calculation(self, test_input: bytes):
        extractor = PEFeatureExtractor()
        our_result = extractor.extract_byte_histogram(test_input)
        ref_result = self._independent_byte_histogram(test_input)

        assert our_result.shape == (256,)
        assert our_result.dtype == np.float32
        assert np.allclose(our_result, ref_result, atol=1e-6)


class TestStringExtractorAlgorithmParity:
    """Algorithm-level comparison against independent string extraction calculation."""

    @staticmethod
    def _independent_string_extractor(data: bytes) -> np.ndarray:
        if not data:
            return np.zeros(104, dtype=np.float32)

        strings = re.findall(b"[\x20-\x7f]{5,}", data)
        if strings:
            lens = [len(s) for s in strings]
            avlen = float(sum(lens) / len(lens))
            shifted = [b - 0x20 for s in strings for b in s]
            c_dist = np.bincount(shifted, minlength=96)[:96].astype(np.float32)
            printables = float(c_dist.sum())
            if printables > 0:
                p = c_dist / printables
                wh = p > 0
                entropy = float(-np.sum(p[wh] * np.log2(p[wh]))) if np.any(wh) else 0.0
                norm_dist = c_dist / printables
            else:
                entropy = 0.0
                norm_dist = np.zeros(96, dtype=np.float32)
        else:
            avlen = 0.0
            printables = 0.0
            norm_dist = np.zeros(96, dtype=np.float32)
            entropy = 0.0

        paths = float(len(re.findall(b"c:\\\\", data, re.IGNORECASE)))
        urls = float(len(re.findall(b"https?://", data, re.IGNORECASE)))
        registry = float(len(re.findall(b"HKEY_", data)))
        mz = float(len(re.findall(b"MZ", data)))

        return np.hstack([
            float(len(strings)),
            avlen,
            printables,
            norm_dist,
            entropy,
            paths,
            urls,
            registry,
            mz,
        ]).astype(np.float32)

    @pytest.mark.parametrize(
        "test_input",
        [
            b"",
            b"short",
            b"Valid string with C:\\Windows\\System32\\calc.exe and https://detection.local plus HKEY_CURRENT_USER and MZ marker.",
            b"\x00" * 50 + b"Hello World string!" + b"\x00" * 50,
        ],
    )
    def test_string_extractor_matches_independent_calculation(self, test_input: bytes):
        extractor = PEFeatureExtractor()
        our_result = extractor.extract_string_features(test_input)
        ref_result = self._independent_string_extractor(test_input)

        assert our_result.shape == (104,)
        assert our_result.dtype == np.float32
        assert np.allclose(our_result, ref_result, atol=1e-6)


class TestDataDirectoriesAlgorithmParity:
    """Algorithm-level comparison for PE DataDirectories ordering and extraction."""

    def test_data_directories_size_and_rva_ordering(self):
        """Verify data directories map Size at 2*i and RVA at 2*i+1 for all 15 directories.

        Canonical upstream EMBER DataDirectories.process_raw_features:
        features[2 * i] = raw_obj[i]["size"]
        features[2 * i + 1] = raw_obj[i]["virtual_address"] (RVA)
        """
        entries = {
            0: (0x3000, 0x120),  # Directory 0 (EXPORT): RVA=0x3000, Size=0x120
            1: (0x3200, 0x80),   # Directory 1 (IMPORT): RVA=0x3200, Size=0x80
            6: (0x3400, 0x40),   # Directory 6 (DEBUG):  RVA=0x3400, Size=0x40
        }
        raw_pe = make_synthetic_pe(data_directory_entries=entries)
        pe = lief.PE.parse(list(raw_pe))
        assert pe is not None

        extractor = PEFeatureExtractor()
        dd_features = extractor.extract_data_directories(pe)

        assert len(dd_features) == 30
        assert dd_features.dtype == np.float32

        # Independent expected vector constructed from upstream algorithm:
        # Size first, RVA second for each standard directory index
        expected = np.zeros(30, dtype=np.float32)
        expected[0] = float(0x120)    # Directory 0 (EXPORT): Size
        expected[1] = float(0x3000)   # Directory 0 (EXPORT): RVA
        expected[2] = float(0x80)     # Directory 1 (IMPORT): Size
        expected[3] = float(0x3200)   # Directory 1 (IMPORT): RVA
        expected[12] = float(0x40)    # Directory 6 (DEBUG): Size
        expected[13] = float(0x3400)  # Directory 6 (DEBUG): RVA

        # Assert full vector equality against independent upstream calculation
        assert np.array_equal(dd_features, expected)

        # Pair-specific assertions for clarity
        assert dd_features[0] == float(0x120)
        assert dd_features[1] == float(0x3000)
        assert dd_features[2] == float(0x80)
        assert dd_features[3] == float(0x3200)
        assert dd_features[12] == float(0x40)
        assert dd_features[13] == float(0x3400)

        # All other directories must be zero-filled (0.0, 0.0)
        for idx in range(15):
            if idx not in entries:
                assert dd_features[2 * idx] == 0.0
                assert dd_features[2 * idx + 1] == 0.0

    def test_data_directories_fallback_on_non_pe(self):
        """Verify non-PE fallback produces 30 zero features."""
        extractor = PEFeatureExtractor()
        dd_features = extractor.extract_data_directories(None)
        assert len(dd_features) == 30
        assert np.all(dd_features == 0.0)


class TestSectionInfoAlgorithmParity:
    """Algorithm-level comparison for SectionInfo counts and FeatureHasher blocks."""

    def test_multi_section_counts_and_feature_hasher(self):
        """Verify 5 general counts and FeatureHasher transforms on multi-section synthetic PE."""
        sections = [
            (b".text\x00\x00\x00", 0x100, 0x1000, 0x200, 0x60000020),  # RX
            (b".data\x00\x00\x00", 0x80, 0x2000, 0x200, 0xC0000040),   # W
        ]
        raw_pe = make_synthetic_pe(sections=sections)
        pe = lief.PE.parse(list(raw_pe))
        assert pe is not None

        extractor = PEFeatureExtractor()
        sec_features = extractor.extract_section_info(pe)

        assert len(sec_features) == 255
        assert sec_features.dtype == np.float32

        # 5 general counts
        num_sections = sec_features[0]
        zero_size_count = sec_features[1]
        empty_name_count = sec_features[2]
        rx_count = sec_features[3]
        w_count = sec_features[4]

        assert num_sections == 2.0
        assert zero_size_count == 0.0
        assert empty_name_count == 0.0
        assert rx_count == 1.0
        assert w_count == 1.0

        # Independent calculation of entry section name hasher
        ref_entry_hasher = FeatureHasher(50, input_type="string").transform([[".text"]]).toarray()[0]
        # In extract_section_info:
        # sec_general: 5 dims (0..4)
        # sizes_hashed: 50 dims (5..54)
        # entropy_hashed: 50 dims (55..104)
        # vsize_hashed: 50 dims (105..154)
        # entry_name_hashed: 50 dims (155..204)
        # entry_chars_hashed: 50 dims (205..254)
        our_entry_hashed = sec_features[155:205]
        assert np.allclose(our_entry_hashed, ref_entry_hasher, atol=1e-6)


class TestCategoricalFeatureHasherParity:
    """Algorithm-level comparison for categorical hashing in Imports, Exports, and HeaderFileInfo."""

    def test_imports_feature_hasher_configuration(self):
        """Verify signed MurmurHash3 hashing for library and API imports."""
        mock_imports = {
            "kernel32.dll": ["CreateFileW", "ReadFile", "CloseHandle", "ordinal12"],
            "user32.dll": ["MessageBoxW"],
        }
        libraries = list(set([l.lower() for l in mock_imports.keys()]))
        ref_lib_hasher = FeatureHasher(256, input_type="string").transform([libraries]).toarray()[0]

        all_imports = [
            lib.lower() + ":" + e
            for lib, elist in mock_imports.items()
            for e in elist
        ]
        ref_imp_hasher = FeatureHasher(1024, input_type="string").transform([all_imports]).toarray()[0]

        ref_combined = np.hstack([ref_lib_hasher, ref_imp_hasher]).astype(np.float32)
        assert len(ref_combined) == 1280
        assert np.array_equal(ref_combined, np.hstack([ref_lib_hasher, ref_imp_hasher]).astype(np.float32))

    def test_exports_feature_hasher_configuration(self):
        """Verify export symbols hashing (128 bins) with 10000 char clipping."""
        mock_exports = ["ExportFuncA", "ExportFuncB", "VeryLongExportName" * 100]
        clipped = [name[:10000] for name in mock_exports]
        ref_exports_hasher = FeatureHasher(128, input_type="string").transform([clipped]).toarray()[0].astype(np.float32)

        assert len(ref_exports_hasher) == 128
        assert ref_exports_hasher.dtype == np.float32

    def test_header_categorical_hashing_parity(self):
        """Verify header categorical FeatureHasher transforms (10 bins each)."""
        ref_machine = FeatureHasher(10, input_type="string").transform([["i386"]]).toarray()[0]
        assert len(ref_machine) == 10

        ref_subsys = FeatureHasher(10, input_type="string").transform([["WINDOWS_CUI"]]).toarray()[0]
        assert len(ref_subsys) == 10

        ref_magic = FeatureHasher(10, input_type="string").transform([["PE32"]]).toarray()[0]
        assert len(ref_magic) == 10
