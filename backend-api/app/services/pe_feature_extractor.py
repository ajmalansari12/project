"""Static PE feature extraction service for Sentinel-EDR (T013).

Extracts the 2,381-dimensional numerical feature representation defined by the
EMBER 2018 Feature Version 2 (`ember_pe_v2`) specification.

Attribution & Upstream Specification:
Derived from and compatible with the EMBER (Elastic Malware Benchmark for Empowering
Researchers) Feature Version 2 specification:
https://github.com/elastic/ember
Original EMBER implementation: Copyright (c) 2018-2019 Elastic / Endgame,
licensed under the Apache License, Version 2.0.

Feature Groups and Canonical Ordering (Total: 2,381 dimensions):
1. ByteHistogram (256)
2. ByteEntropyHistogram (256)
3. StringExtractor (104)
4. GeneralFileInfo (10)
5. HeaderFileInfo (62)
6. SectionInfo (255)
7. ImportsInfo (1,280)
8. ExportsInfo (128)
9. DataDirectories (30)

Parity & Verification Status:
- Structural Conformity: Verified (2,381 dimensions, valid T012 JSON Schema & Pydantic contracts).
- Algorithm Parity: Verified for ByteHistogram, ByteEntropyHistogram (including sub-window partial
  blocks), StringExtractor, and DataDirectories against independent reference calculations.
  Empty-file input follows documented finite-safe zero fallback to prevent 0/0 NaN division.
- Parser-Dependent Boundaries: Structural PE groups (GeneralFileInfo, HeaderFileInfo, SectionInfo,
  ImportsInfo, ExportsInfo) implement canonical EMBER FeatureHasher parameters and PE mappings;
  behavior on diverse real-world binaries is subject to LIEF 1.0.0 parsing and validated in T014.
- Full Dataset Parity: Deferred to T014 (requires ingesting external dataset reference vectors).

All features are extracted statically without executing the target file.
"""

from dataclasses import dataclass, field
import hashlib
import logging
import math
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import lief
import numpy as np
from sklearn.feature_extraction import FeatureHasher

from app.core.config import get_settings
from app.schemas.ml_contracts import (
    EMBER_2018_CANONICAL_FEATURE_DIMENSION,
    EMBER_2018_FEATURE_SCHEMA_VERSION,
    FeatureVector,
    MissingValueStrategy,
)
from app.services.sha256_service import compute_file_sha256, normalize_sha256

logger = logging.getLogger("sentinel.services.pe_feature_extractor")

# Current extraction implementation version
EXTRACTOR_IMPLEMENTATION_VERSION = "1.0.0"

# Tested and verified dependency versions for reproduction & audit
TESTED_LIEF_VERSION = "1.0.0"
TESTED_NUMPY_VERSION = "2.5.4"
TESTED_SKLEARN_VERSION = "1.9.1"

# Canonical EMBER 2018 Feature Version 2 dimensions
GROUP_DIMENSIONS: Dict[str, int] = {
    "ByteHistogram": 256,
    "ByteEntropyHistogram": 256,
    "StringExtractor": 104,
    "GeneralFileInfo": 10,
    "HeaderFileInfo": 62,
    "SectionInfo": 255,
    "ImportsInfo": 1280,
    "ExportsInfo": 128,
    "DataDirectories": 30,
}

# The 15 standard PE Data Directory names in canonical order
DATA_DIRECTORY_ORDER: List[str] = [
    "EXPORT_TABLE",
    "IMPORT_TABLE",
    "RESOURCE_TABLE",
    "EXCEPTION_TABLE",
    "CERTIFICATE_TABLE",
    "BASE_RELOCATION_TABLE",
    "DEBUG",
    "ARCHITECTURE",
    "GLOBAL_PTR",
    "TLS_TABLE",
    "LOAD_CONFIG_TABLE",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT_DESCRIPTOR",
    "CLR_RUNTIME_HEADER",
]


# ==============================================================================
# Service Exceptions
# ==============================================================================

class PEFeatureExtractorError(Exception):
    """Base exception for all PE feature extraction errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class PEFileNotFoundError(PEFeatureExtractorError):
    """Raised when the specified file path does not exist."""


class PEIsADirectoryError(PEFeatureExtractorError):
    """Raised when the target path is a directory rather than a regular file."""


class PEFileAccessError(PEFeatureExtractorError):
    """Raised when an OS or I/O error prevents accessing or reading the file."""


class PEFileTooLargeError(PEFeatureExtractorError):
    """Raised when file size exceeds the configured maximum allowable limit."""


class PEMalformedFileError(PEFeatureExtractorError):
    """Raised when critical file corruption prevents feature extraction."""


# ==============================================================================
# Result Container
# ==============================================================================

@dataclass
class PEFeatureExtractionResult:
    """Validated result container for static PE feature extraction."""

    file_path: Optional[str]
    file_hash: str
    feature_vector: FeatureVector
    is_pe: bool
    parser_status: str  # "SUCCESS", "DEGRADED_NON_PE", "DEGRADED_PARSE_ERROR"
    warnings: List[str] = field(default_factory=list)
    extraction_duration_ms: float = 0.0
    lief_version: str = field(default_factory=lambda: getattr(lief, "__version__", "unknown"))
    extractor_version: str = EXTRACTOR_IMPLEMENTATION_VERSION
    feature_schema_version: str = EMBER_2018_FEATURE_SCHEMA_VERSION
    feature_count: int = EMBER_2018_CANONICAL_FEATURE_DIMENSION

    def to_dict(self) -> Dict[str, Any]:
        """Serialize result to a dictionary."""
        return {
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "feature_vector": self.feature_vector.model_dump(mode="json"),
            "is_pe": self.is_pe,
            "parser_status": self.parser_status,
            "warnings": list(self.warnings),
            "extraction_duration_ms": self.extraction_duration_ms,
            "lief_version": self.lief_version,
            "extractor_version": self.extractor_version,
            "feature_schema_version": self.feature_schema_version,
            "feature_count": self.feature_count,
        }


# ==============================================================================
# PE Feature Extractor Service
# ==============================================================================

class PEFeatureExtractor:
    """Thread-safe static PE feature extractor implementing the EMBER v2 schema."""

    def __init__(self, *, max_file_size_bytes: Optional[int] = None) -> None:
        """Initialize extractor with optional file size ceiling.

        Args:
            max_file_size_bytes: Maximum allowed file size in bytes. Defaults to app settings.
        """
        settings = get_settings()
        self.max_file_size_bytes = (
            max_file_size_bytes
            if max_file_size_bytes is not None
            else getattr(settings, "pe_max_file_size_bytes", 104857600)
        )

        # Precompiled regex patterns for StringExtractor
        self._re_allstrings = re.compile(b"[\x20-\x7f]{5,}")
        self._re_paths = re.compile(b"C:\\\\", re.IGNORECASE)
        self._re_urls = re.compile(b"https?://", re.IGNORECASE)
        self._re_registry = re.compile(b"HKEY_", re.IGNORECASE)
        self._re_mz = re.compile(b"MZ")

    # --------------------------------------------------------------------------
    # 1. ByteHistogram (256 dimensions)
    # --------------------------------------------------------------------------
    def extract_byte_histogram(self, bytez: bytes) -> np.ndarray:
        """Extract normalized 256-bin byte frequency histogram."""
        if not bytez:
            return np.zeros(256, dtype=np.float32)

        counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)[:256].astype(np.float32)
        total = counts.sum()
        return counts / total if total > 0 else np.zeros(256, dtype=np.float32)

    # --------------------------------------------------------------------------
    # 2. ByteEntropyHistogram (256 dimensions)
    # --------------------------------------------------------------------------
    def _entropy_bin_counts(self, block: np.ndarray, window_size: int = 2048) -> Tuple[int, np.ndarray]:
        """Compute entropy bin index and 16-bin coarse histogram for a byte window."""
        c = np.bincount(block >> 4, minlength=16)[:16]
        p = c.astype(np.float32) / float(window_size)
        wh = np.where(c)[0]
        if len(wh) == 0:
            return 0, c

        h = float(np.sum(-p[wh] * np.log2(p[wh])) * 2.0)
        h_bin = int(h * 2.0)
        if h_bin >= 16:
            h_bin = 15
        return h_bin, c

    def extract_byte_entropy_histogram(
        self,
        bytez: bytes,
        *,
        step: int = 1024,
        window: int = 2048,
    ) -> np.ndarray:
        """Extract 16x16 joint byte-entropy histogram flattened to 256 dimensions.

        Conforms strictly to the upstream EMBER ByteEntropyHistogram algorithm:
        - For non-empty files shorter than window (len < 2048), the available bytes
          are processed as a partial block using p = c / window. The local entropy H
          and coarse bin Hbin = min(int(2H), 15) are calculated, and output[Hbin, :] += c.
        - For files >= window (len >= 2048), a sliding window with the configured step
          (default 1024) computes entropy across strided blocks.
        - The resulting 256-bin matrix is flattened and normalized by its sum (sum to 1.0).
        - Safe deviation: For empty input (0 bytes), an all-zero vector is returned to
          prevent 0/0 NaN division, ensuring finite float guarantees across all inputs.
        """
        if not bytez:
            return np.zeros(256, dtype=np.float32)

        output = np.zeros((16, 16), dtype=np.float32)
        a = np.frombuffer(bytez, dtype=np.uint8)

        if a.shape[0] < window:
            h_bin, c = self._entropy_bin_counts(a, window_size=window)
            output[h_bin, :] += c
        else:
            shape = a.shape[:-1] + (a.shape[-1] - window + 1, window)
            strides = a.strides + (a.strides[-1],)
            blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::step, :]
            for block in blocks:
                h_bin, c = self._entropy_bin_counts(block, window_size=window)
                output[h_bin, :] += c

        sum_out = output.sum()
        if sum_out > 0:
            return (output.flatten() / sum_out).astype(np.float32)
        return np.zeros(256, dtype=np.float32)

    # --------------------------------------------------------------------------
    # 3. StringExtractor (104 dimensions)
    # --------------------------------------------------------------------------
    def extract_string_features(self, bytez: bytes) -> np.ndarray:
        """Extract statistical features from printable string sequences (dim=104)."""
        if not bytez:
            return np.zeros(104, dtype=np.float32)

        allstrings = self._re_allstrings.findall(bytez)
        if allstrings:
            str_lens = [len(s) for s in allstrings]
            avlen = float(sum(str_lens) / len(str_lens))
            as_shifted = [b - 0x20 for b in b"".join(allstrings)]
            c_dist = np.bincount(as_shifted, minlength=96)[:96].astype(np.float32)
            printables = float(c_dist.sum())

            if printables > 0:
                p_probs = c_dist / printables
                nonzero_p = p_probs[p_probs > 0]
                entropy = float(-np.sum(nonzero_p * np.log2(nonzero_p))) if len(nonzero_p) > 0 else 0.0
            else:
                entropy = 0.0
        else:
            avlen = 0.0
            printables = 0.0
            c_dist = np.zeros(96, dtype=np.float32)
            entropy = 0.0

        hist_div = printables if printables > 0 else 1.0
        normalized_dist = c_dist / hist_div

        paths_count = float(len(self._re_paths.findall(bytez)))
        urls_count = float(len(self._re_urls.findall(bytez)))
        registry_count = float(len(self._re_registry.findall(bytez)))
        mz_count = float(len(self._re_mz.findall(bytez)))

        return np.hstack([
            float(len(allstrings)),
            avlen,
            printables,
            normalized_dist,  # 96
            entropy,
            paths_count,
            urls_count,
            registry_count,
            mz_count,
        ]).astype(np.float32)

    # --------------------------------------------------------------------------
    # 4. GeneralFileInfo (10 dimensions)
    # --------------------------------------------------------------------------
    def extract_general_file_info(
        self,
        bytez: bytes,
        lief_binary: Optional[Any],
    ) -> np.ndarray:
        """Extract general PE structural counts and flags (dim=10)."""
        file_size = float(len(bytez))
        if lief_binary is None:
            return np.asarray([file_size, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], dtype=np.float32)

        vsize = float(getattr(lief_binary, "virtual_size", 0))
        has_debug = float(int(bool(getattr(lief_binary, "has_debug", False))))
        exports = float(len(getattr(lief_binary, "exported_functions", [])))
        imports = float(len(getattr(lief_binary, "imported_functions", [])))
        has_reloc = float(int(bool(getattr(lief_binary, "has_relocations", False))))
        has_resources = float(int(bool(getattr(lief_binary, "has_resources", False))))
        has_signatures = float(int(bool(
            getattr(lief_binary, "has_signatures", getattr(lief_binary, "has_signature", False))
        )))
        has_tls = float(int(bool(getattr(lief_binary, "has_tls", False))))
        symbols = float(len(getattr(lief_binary, "symbols", [])))

        return np.asarray([
            file_size,
            vsize,
            has_debug,
            exports,
            imports,
            has_reloc,
            has_resources,
            has_signatures,
            has_tls,
            symbols,
        ], dtype=np.float32)

    # --------------------------------------------------------------------------
    # 5. HeaderFileInfo (62 dimensions)
    # --------------------------------------------------------------------------
    def extract_header_file_info(self, lief_binary: Optional[Any]) -> np.ndarray:
        """Extract COFF and Optional Header metadata features (dim=62)."""
        if lief_binary is None:
            return np.zeros(62, dtype=np.float32)

        hdr = getattr(lief_binary, "header", None)
        opt = getattr(lief_binary, "optional_header", None)

        timestamp = float(getattr(hdr, "time_date_stamps", 0)) if hdr else 0.0
        machine = str(getattr(hdr, "machine", "")).split(".")[-1] if hdr else ""
        coff_chars = [str(c).split(".")[-1] for c in getattr(hdr, "characteristics_list", [])] if hdr else []

        subsystem = str(getattr(opt, "subsystem", "")).split(".")[-1] if opt else ""
        dll_chars = [str(c).split(".")[-1] for c in getattr(opt, "dll_characteristics_lists", [])] if opt else []
        magic = str(getattr(opt, "magic", "")).split(".")[-1] if opt else ""

        scalars = np.asarray([
            float(getattr(opt, "major_image_version", 0)) if opt else 0.0,
            float(getattr(opt, "minor_image_version", 0)) if opt else 0.0,
            float(getattr(opt, "major_linker_version", 0)) if opt else 0.0,
            float(getattr(opt, "minor_linker_version", 0)) if opt else 0.0,
            float(getattr(opt, "major_operating_system_version", 0)) if opt else 0.0,
            float(getattr(opt, "minor_operating_system_version", 0)) if opt else 0.0,
            float(getattr(opt, "major_subsystem_version", 0)) if opt else 0.0,
            float(getattr(opt, "minor_subsystem_version", 0)) if opt else 0.0,
            float(getattr(opt, "sizeof_code", 0)) if opt else 0.0,
            float(getattr(opt, "sizeof_headers", 0)) if opt else 0.0,
            float(getattr(opt, "sizeof_heap_commit", 0)) if opt else 0.0,
        ], dtype=np.float32)

        return np.hstack([
            timestamp,
            FeatureHasher(10, input_type="string").transform([[machine]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([coff_chars]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([[subsystem]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([dll_chars]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([[magic]]).toarray()[0],
            scalars,
        ]).astype(np.float32)

    # --------------------------------------------------------------------------
    # 6. SectionInfo (255 dimensions)
    # --------------------------------------------------------------------------
    def extract_section_info(self, lief_binary: Optional[Any]) -> np.ndarray:
        """Extract PE section characteristics, sizes, entropies, and hashed properties (dim=255)."""
        if lief_binary is None or not hasattr(lief_binary, "sections"):
            return np.zeros(255, dtype=np.float32)

        sections = []
        for s in lief_binary.sections:
            props = [str(c).split(".")[-1] for c in getattr(s, "characteristics_lists", [])]
            sections.append({
                "name": str(s.name) if s.name else "",
                "size": float(s.size),
                "entropy": float(s.entropy),
                "vsize": float(s.virtual_size),
                "props": props,
            })

        # Determine entry point section name
        entry_name = ""
        try:
            entrypoint = getattr(lief_binary, "entrypoint", 0)
            imagebase = getattr(lief_binary, "imagebase", 0)
            rva = entrypoint - imagebase if entrypoint > imagebase else entrypoint
            entry_sec = lief_binary.section_from_rva(rva)
            if entry_sec and entry_sec.name:
                entry_name = str(entry_sec.name)
        except Exception:
            entry_name = ""

        # Fallback to first executable section if entrypoint was not resolved
        if not entry_name:
            for s in sections:
                if "MEM_EXECUTE" in s["props"]:
                    entry_name = s["name"]
                    break

        sec_general = np.asarray([
            float(len(sections)),
            float(sum(1 for s in sections if s["size"] == 0)),
            float(sum(1 for s in sections if s["name"] == "")),
            float(sum(1 for s in sections if "MEM_READ" in s["props"] and "MEM_EXECUTE" in s["props"])),
            float(sum(1 for s in sections if "MEM_WRITE" in s["props"])),
        ], dtype=np.float32)

        entry_chars = [p for s in sections for p in s["props"] if s["name"] == entry_name]

        return np.hstack([
            sec_general,
            FeatureHasher(50, input_type="pair").transform([[(s["name"], s["size"]) for s in sections]]).toarray()[0],
            FeatureHasher(50, input_type="pair").transform([[(s["name"], s["entropy"]) for s in sections]]).toarray()[0],
            FeatureHasher(50, input_type="pair").transform([[(s["name"], s["vsize"]) for s in sections]]).toarray()[0],
            FeatureHasher(50, input_type="string").transform([[entry_name]]).toarray()[0],
            FeatureHasher(50, input_type="string").transform([entry_chars]).toarray()[0],
        ]).astype(np.float32)

    # --------------------------------------------------------------------------
    # 7. ImportsInfo (1,280 dimensions)
    # --------------------------------------------------------------------------
    def extract_imports_info(self, lief_binary: Optional[Any]) -> np.ndarray:
        """Extract hashed dynamic import libraries (256) and import functions (1024) (dim=1280)."""
        if lief_binary is None or not hasattr(lief_binary, "imports"):
            return np.hstack([
                FeatureHasher(256, input_type="string").transform([[]]).toarray()[0],
                FeatureHasher(1024, input_type="string").transform([[]]).toarray()[0],
            ]).astype(np.float32)

        raw_imports: Dict[str, List[str]] = {}
        for imp in lief_binary.imports:
            lib_name = str(imp.name) if getattr(imp, "name", None) else ""
            entries = []
            for e in getattr(imp, "entries", []):
                if getattr(e, "is_ordinal", False):
                    entries.append(f"ordinal{e.ordinal}")
                elif getattr(e, "name", None):
                    entries.append(str(e.name))
            if lib_name:
                raw_imports[lib_name] = entries

        libraries = list(set([l.lower() for l in raw_imports.keys()]))
        lib_hashed = FeatureHasher(256, input_type="string").transform([libraries]).toarray()[0]

        all_imports = [
            lib.lower() + ":" + e
            for lib, elist in raw_imports.items()
            for e in elist
        ]
        imp_hashed = FeatureHasher(1024, input_type="string").transform([all_imports]).toarray()[0]

        return np.hstack([lib_hashed, imp_hashed]).astype(np.float32)

    # --------------------------------------------------------------------------
    # 8. ExportsInfo (128 dimensions)
    # --------------------------------------------------------------------------
    def extract_exports_info(self, lief_binary: Optional[Any]) -> np.ndarray:
        """Extract hashed export function symbol names (dim=128)."""
        if lief_binary is None or not hasattr(lief_binary, "exported_functions"):
            return FeatureHasher(128, input_type="string").transform([[]]).toarray()[0].astype(np.float32)

        raw_exports = []
        for exp in lief_binary.exported_functions:
            name = exp.name if hasattr(exp, "name") else str(exp)
            if name:
                raw_exports.append(name[:10000])

        return FeatureHasher(128, input_type="string").transform([raw_exports]).toarray()[0].astype(np.float32)

    # --------------------------------------------------------------------------
    # 9. DataDirectories (30 dimensions)
    # --------------------------------------------------------------------------
    def extract_data_directories(self, lief_binary: Optional[Any]) -> np.ndarray:
        """Extract size and virtual address (RVA) features for the first 15 standard PE data directories (dim=30).

        Upstream EMBER DataDirectories.process_raw_features appends:
        1. size
        2. virtual_address (RVA)
        for each of the 15 standard data directories in canonical order:
        features[2 * i] = size
        features[2 * i + 1] = virtual_address (RVA)
        """
        output = np.zeros(30, dtype=np.float32)
        if lief_binary is None or not hasattr(lief_binary, "data_directories"):
            return output

        dirs = list(lief_binary.data_directories)
        for i in range(15):
            if i < len(dirs):
                output[2 * i] = float(dirs[i].size)
                output[2 * i + 1] = float(dirs[i].rva)

        return output

    # --------------------------------------------------------------------------
    # Vector Assembly & Validation
    # --------------------------------------------------------------------------
    def assemble_feature_vector(
        self,
        bytez: bytes,
        lief_binary: Optional[Any],
    ) -> np.ndarray:
        """Assemble and concatenate all 9 feature groups in canonical order (dim=2381)."""
        f1 = self.extract_byte_histogram(bytez)
        f2 = self.extract_byte_entropy_histogram(bytez)
        f3 = self.extract_string_features(bytez)
        f4 = self.extract_general_file_info(bytez, lief_binary)
        f5 = self.extract_header_file_info(lief_binary)
        f6 = self.extract_section_info(lief_binary)
        f7 = self.extract_imports_info(lief_binary)
        f8 = self.extract_exports_info(lief_binary)
        f9 = self.extract_data_directories(lief_binary)

        total_vec = np.hstack([f1, f2, f3, f4, f5, f6, f7, f8, f9])
        if total_vec.shape[0] != EMBER_2018_CANONICAL_FEATURE_DIMENSION:
            raise PEFeatureExtractorError(
                f"Assembled feature vector dimension ({total_vec.shape[0]}) does not match "
                f"expected EMBER v2 dimension ({EMBER_2018_CANONICAL_FEATURE_DIMENSION})."
            )

        return total_vec.astype(np.float32)

    # --------------------------------------------------------------------------
    # Primary Public Operations
    # --------------------------------------------------------------------------
    def extract_from_bytes(
        self,
        data: bytes,
        *,
        sample_id: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> PEFeatureExtractionResult:
        """Extract EMBER v2 feature vector directly from in-memory byte buffer.

        Args:
            data: Raw binary byte contents.
            sample_id: Optional sample identifier (defaults to computed SHA-256).
            file_path: Optional original file path string for provenance.

        Returns:
            PEFeatureExtractionResult containing validated FeatureVector.
        """
        start_time = time.perf_counter()
        warnings: List[str] = []

        if len(data) > self.max_file_size_bytes:
            raise PEFileTooLargeError(
                f"Byte buffer size ({len(data)} bytes) exceeds configured limit ({self.max_file_size_bytes} bytes)."
            )

        if len(data) == 0:
            warnings.append("Target data is empty (0 bytes); features populated with zero fallback.")

        file_hash = hashlib.sha256(data).hexdigest().lower()
        active_sample_id = sample_id or file_hash

        # Parse PE structures via LIEF
        lief_binary = None
        is_pe = False
        parser_status = "SUCCESS"

        try:
            lief_binary = lief.PE.parse(list(data))
            if lief_binary is not None:
                is_pe = True
            else:
                parser_status = "DEGRADED_NON_PE"
                warnings.append(
                    "Target data is not a valid PE binary; structural PE features populated "
                    "with default zeros per EMBER fallback convention."
                )
        except Exception as exc:
            logger.warning(f"LIEF parser exception during PE parsing: {exc}")
            lief_binary = None
            parser_status = "DEGRADED_PARSE_ERROR"
            warnings.append(f"LIEF parser exception during PE extraction: {exc}")

        # Assemble feature vector
        vector_np = self.assemble_feature_vector(data, lief_binary)

        # Enforce finite float invariant
        float_values: List[float] = []
        for i, val in enumerate(vector_np):
            f_val = float(val)
            if math.isnan(f_val) or math.isinf(f_val):
                raise PEFeatureExtractorError(
                    f"Extracted feature at index {i} is non-finite ({f_val}). "
                    "EMBER feature vectors must contain only finite float values."
                )
            float_values.append(f_val)

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Construct validated T012 FeatureVector
        feature_vector = FeatureVector(
            sample_id=active_sample_id,
            sample_hash=file_hash,
            feature_schema_version=EMBER_2018_FEATURE_SCHEMA_VERSION,
            feature_values=float_values,
            feature_count=EMBER_2018_CANONICAL_FEATURE_DIMENSION,
            missing_value_strategy=MissingValueStrategy.ZERO_FILL,
            extraction_duration_ms=round(duration_ms, 2),
        )

        return PEFeatureExtractionResult(
            file_path=file_path,
            file_hash=file_hash,
            feature_vector=feature_vector,
            is_pe=is_pe,
            parser_status=parser_status,
            warnings=warnings,
            extraction_duration_ms=round(duration_ms, 2),
            lief_version=getattr(lief, "__version__", "unknown"),
            extractor_version=EXTRACTOR_IMPLEMENTATION_VERSION,
            feature_schema_version=EMBER_2018_FEATURE_SCHEMA_VERSION,
            feature_count=EMBER_2018_CANONICAL_FEATURE_DIMENSION,
        )

    def extract_from_file(
        self,
        file_path: Union[str, Path],
        *,
        sample_id: Optional[str] = None,
    ) -> PEFeatureExtractionResult:
        """Extract EMBER v2 feature vector from an explicitly supplied file path.

        Args:
            file_path: Path to target executable file.
            sample_id: Optional sample identifier (defaults to computed SHA-256).

        Returns:
            PEFeatureExtractionResult containing validated FeatureVector.

        Raises:
            PEFileNotFoundError: If target file does not exist.
            PEIsADirectoryError: If target path is a directory.
            PEFileTooLargeError: If file exceeds maximum size ceiling.
            PEFileAccessError: If file cannot be accessed or read.
        """
        path = Path(file_path).resolve()
        str_path = str(path)

        if not path.exists():
            raise PEFileNotFoundError(f"Target file does not exist: '{str_path}'")

        if path.is_dir():
            raise PEIsADirectoryError(f"Target path is a directory, not a regular file: '{str_path}'")

        # Check file size prior to reading into memory
        try:
            st = path.stat()
            file_size = st.st_size
        except OSError as err:
            raise PEFileAccessError(f"Failed to access file metadata for '{str_path}': {err}") from err

        if file_size > self.max_file_size_bytes:
            raise PEFileTooLargeError(
                f"File size ({file_size} bytes) exceeds configured maximum allowable limit "
                f"({self.max_file_size_bytes} bytes): '{str_path}'"
            )

        # Compute authoritative SHA-256 digest via T008 service
        authoritative_hash = compute_file_sha256(path)

        # Read binary contents
        try:
            with open(path, "rb") as f:
                bytez = f.read()
        except OSError as err:
            raise PEFileAccessError(f"Failed to read file contents for '{str_path}': {err}") from err

        # Verify size after reading to detect concurrent truncation or file growth
        if len(bytez) > self.max_file_size_bytes:
            raise PEFileTooLargeError(
                f"File size ({len(bytez)} bytes) exceeded limit after reading: '{str_path}'"
            )

        # Verify in-memory digest against pre-read file digest to detect concurrent file mutation
        in_memory_hash = hashlib.sha256(bytez).hexdigest().lower()
        if in_memory_hash != authoritative_hash:
            raise PEFileAccessError(
                f"File was concurrently modified during extraction: digest mismatch between "
                f"stream hash ({authoritative_hash}) and buffer hash ({in_memory_hash}) for '{str_path}'."
            )

        return self.extract_from_bytes(
            bytez,
            sample_id=sample_id,
            file_path=str_path,
        )


# ==============================================================================
# Functional Helpers
# ==============================================================================

_DEFAULT_EXTRACTOR: Optional[PEFeatureExtractor] = None


def get_default_pe_feature_extractor() -> PEFeatureExtractor:
    """Return a shared singleton instance of PEFeatureExtractor."""
    global _DEFAULT_EXTRACTOR
    if _DEFAULT_EXTRACTOR is None:
        _DEFAULT_EXTRACTOR = PEFeatureExtractor()
    return _DEFAULT_EXTRACTOR


def extract_pe_features(
    file_path: Union[str, Path],
    *,
    max_file_size_bytes: Optional[int] = None,
    sample_id: Optional[str] = None,
) -> PEFeatureExtractionResult:
    """Extract EMBER v2 feature vector from a file path using default configuration.

    Args:
        file_path: Absolute or relative file path to analyze.
        max_file_size_bytes: Optional size ceiling override.
        sample_id: Optional unique sample record identifier.

    Returns:
        PEFeatureExtractionResult conforming to T012 contracts.
    """
    if max_file_size_bytes is not None:
        extractor = PEFeatureExtractor(max_file_size_bytes=max_file_size_bytes)
    else:
        extractor = get_default_pe_feature_extractor()
    return extractor.extract_from_file(file_path, sample_id=sample_id)


def extract_pe_features_from_bytes(
    data: bytes,
    *,
    sample_id: Optional[str] = None,
) -> PEFeatureExtractionResult:
    """Extract EMBER v2 feature vector directly from raw in-memory bytes.

    Args:
        data: Raw binary byte string.
        sample_id: Optional unique sample record identifier.

    Returns:
        PEFeatureExtractionResult conforming to T012 contracts.
    """
    extractor = get_default_pe_feature_extractor()
    return extractor.extract_from_bytes(data, sample_id=sample_id)
