"""Raw feature vectorization service for EMBER 2018 (Feature Version 2) JSONL records.

Converts parsed raw feature dictionaries from the official EMBER JSONL dataset shards
(e.g. train_features_*.jsonl, test_features.jsonl) into validated 2,381-dimensional
numerical feature vectors conforming to the 'ember_pe_v2' schema and T012 data contracts.

Preserves the canonical 9 feature groups in exact order:
1. ByteHistogram (256 dims)
2. ByteEntropyHistogram (256 dims)
3. StringExtractor (104 dims)
4. GeneralFileInfo (10 dims)
5. HeaderFileInfo (62 dims)
6. SectionInfo (255 dims)
7. ImportsInfo (1,280 dims)
8. ExportsInfo (128 dims)
9. DataDirectories (30 dims, Size-before-RVA)
Total: 2,381 dimensions.
"""

from dataclasses import dataclass
import logging
import math
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np
from sklearn.feature_extraction import FeatureHasher

from app.schemas.ml_contracts import (
    EMBER_2018_CANONICAL_FEATURE_DIMENSION,
    EMBER_2018_FEATURE_SCHEMA_VERSION,
    FeatureVector,
    MissingValueStrategy,
)

logger = logging.getLogger("sentinel.services.ember_raw_vectorizer")


# Canonical feature group dimensions
GROUP_DIMENSIONS: Dict[str, int] = {
    "histogram": 256,
    "byteentropy": 256,
    "strings": 104,
    "general": 10,
    "header": 62,
    "section": 255,
    "imports": 1280,
    "exports": 128,
    "datadirectories": 30,
}

CANONICAL_FEATURE_ORDER: List[str] = [
    "histogram",
    "byteentropy",
    "strings",
    "general",
    "header",
    "section",
    "imports",
    "exports",
    "datadirectories",
]

# Standard 15 PE data directories in canonical EMBER ordering
CANONICAL_DATA_DIRECTORIES: List[str] = [
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


class EmberVectorizerError(Exception):
    """Base exception for raw feature vectorization errors."""


class EmberMalformedRecordError(EmberVectorizerError):
    """Raised when a raw record is missing required fields or has incompatible structure."""


class EmberNonFiniteValueError(EmberVectorizerError):
    """Raised when non-finite numbers (NaN or Inf) are produced during vectorization."""


class EmberRawFeatureVectorizer:
    """Transforms EMBER raw-feature JSON objects into canonical 2,381-dimensional feature vectors."""

    def __init__(self, *, missing_value_strategy: MissingValueStrategy = MissingValueStrategy.ZERO_FILL) -> None:
        self.missing_value_strategy = missing_value_strategy
        self.dim = EMBER_2018_CANONICAL_FEATURE_DIMENSION
        self.schema_version = EMBER_2018_FEATURE_SCHEMA_VERSION

    # --------------------------------------------------------------------------
    # 1. ByteHistogram (256 dimensions)
    # --------------------------------------------------------------------------
    def vectorize_byte_histogram(self, raw_histogram: Optional[Sequence[Any]]) -> np.ndarray:
        """Process 256-bin raw byte histogram counts with sum normalization."""
        if not raw_histogram or len(raw_histogram) != 256:
            return np.zeros(256, dtype=np.float32)

        counts = np.asarray(raw_histogram, dtype=np.float32)
        total = float(np.sum(counts))
        if total > 0.0:
            return counts / total
        return np.zeros(256, dtype=np.float32)

    # --------------------------------------------------------------------------
    # 2. ByteEntropyHistogram (256 dimensions)
    # --------------------------------------------------------------------------
    def vectorize_byte_entropy(self, raw_byteentropy: Optional[Sequence[Any]]) -> np.ndarray:
        """Process 256-bin (16x16) 2D byte/entropy histogram counts with sum normalization."""
        if not raw_byteentropy or len(raw_byteentropy) != 256:
            return np.zeros(256, dtype=np.float32)

        counts = np.asarray(raw_byteentropy, dtype=np.float32)
        total = float(np.sum(counts))
        if total > 0.0:
            return counts / total
        return np.zeros(256, dtype=np.float32)

    # --------------------------------------------------------------------------
    # 3. StringExtractor (104 dimensions)
    # --------------------------------------------------------------------------
    def vectorize_strings(self, raw_strings: Optional[Dict[str, Any]]) -> np.ndarray:
        """Process string extraction statistics, printable distribution, and regex indicators."""
        if not raw_strings or not isinstance(raw_strings, dict):
            return np.zeros(104, dtype=np.float32)

        numstrings = float(raw_strings.get("numstrings", 0.0))
        avlength = float(raw_strings.get("avlength", 0.0))
        printables = float(raw_strings.get("printables", 0.0))

        raw_dist = raw_strings.get("printabledist", [])
        if len(raw_dist) != 96:
            dist_arr = np.zeros(96, dtype=np.float32)
        else:
            dist_arr = np.asarray(raw_dist, dtype=np.float32)

        hist_divisor = printables if printables > 0.0 else 1.0
        normalized_dist = dist_arr / hist_divisor

        entropy = float(raw_strings.get("entropy", 0.0))
        paths = float(raw_strings.get("paths", 0.0))
        urls = float(raw_strings.get("urls", 0.0))
        registry = float(raw_strings.get("registry", 0.0))
        mz = float(raw_strings.get("MZ", 0.0))

        return np.hstack([
            numstrings,
            avlength,
            printables,
            normalized_dist,
            entropy,
            paths,
            urls,
            registry,
            mz,
        ]).astype(np.float32)

    # --------------------------------------------------------------------------
    # 4. GeneralFileInfo (10 dimensions)
    # --------------------------------------------------------------------------
    def vectorize_general(self, raw_general: Optional[Dict[str, Any]]) -> np.ndarray:
        """Process 10 scalar general file properties."""
        if not raw_general or not isinstance(raw_general, dict):
            return np.zeros(10, dtype=np.float32)

        # Accommodate both has_signature and has_signatures key variants
        has_sig = raw_general.get("has_signature")
        if has_sig is None:
            has_sig = raw_general.get("has_signatures", 0)

        return np.asarray([
            float(raw_general.get("size", 0)),
            float(raw_general.get("vsize", 0)),
            float(raw_general.get("has_debug", 0)),
            float(raw_general.get("exports", 0)),
            float(raw_general.get("imports", 0)),
            float(raw_general.get("has_relocations", 0)),
            float(raw_general.get("has_resources", 0)),
            float(has_sig),
            float(raw_general.get("has_tls", 0)),
            float(raw_general.get("symbols", 0)),
        ], dtype=np.float32)

    # --------------------------------------------------------------------------
    # 5. HeaderFileInfo (62 dimensions)
    # --------------------------------------------------------------------------
    def vectorize_header(self, raw_header: Optional[Dict[str, Any]]) -> np.ndarray:
        """Process COFF header, optional header, and categorical hashed fields."""
        if not raw_header or not isinstance(raw_header, dict):
            return np.zeros(62, dtype=np.float32)

        coff = raw_header.get("coff", {})
        optional = raw_header.get("optional", {})

        timestamp = float(coff.get("timestamp", 0.0))
        machine = str(coff.get("machine", ""))
        characteristics = [str(c) for c in coff.get("characteristics", [])]

        subsystem = str(optional.get("subsystem", ""))
        dll_characteristics = [str(c) for c in optional.get("dll_characteristics", [])]
        magic = str(optional.get("magic", ""))

        machine_hashed = FeatureHasher(10, input_type="string").transform([[machine]]).toarray()[0]
        chars_hashed = FeatureHasher(10, input_type="string").transform([characteristics]).toarray()[0]
        subsys_hashed = FeatureHasher(10, input_type="string").transform([[subsystem]]).toarray()[0]
        dll_chars_hashed = FeatureHasher(10, input_type="string").transform([dll_characteristics]).toarray()[0]
        magic_hashed = FeatureHasher(10, input_type="string").transform([[magic]]).toarray()[0]

        scalars = [
            float(optional.get("major_image_version", 0)),
            float(optional.get("minor_image_version", 0)),
            float(optional.get("major_linker_version", 0)),
            float(optional.get("minor_linker_version", 0)),
            float(optional.get("major_operating_system_version", 0)),
            float(optional.get("minor_operating_system_version", 0)),
            float(optional.get("major_subsystem_version", 0)),
            float(optional.get("minor_subsystem_version", 0)),
            float(optional.get("sizeof_code", 0)),
            float(optional.get("sizeof_headers", 0)),
            float(optional.get("sizeof_heap_commit", 0)),
        ]

        return np.hstack([
            timestamp,
            machine_hashed,
            chars_hashed,
            subsys_hashed,
            dll_chars_hashed,
            magic_hashed,
            scalars,
        ]).astype(np.float32)

    # --------------------------------------------------------------------------
    # 6. SectionInfo (255 dimensions)
    # --------------------------------------------------------------------------
    def vectorize_section(self, raw_section: Optional[Dict[str, Any]]) -> np.ndarray:
        """Process section metrics, entry characteristics, and pair/string FeatureHasher blocks."""
        if not raw_section or not isinstance(raw_section, dict):
            return np.zeros(255, dtype=np.float32)

        sections = raw_section.get("sections", [])
        entry_section = str(raw_section.get("entry", ""))

        general = [
            float(len(sections)),
            float(sum(1 for s in sections if s.get("size", 0) == 0)),
            float(sum(1 for s in sections if not s.get("name", ""))),
            float(sum(1 for s in sections if "MEM_READ" in s.get("props", []) and "MEM_EXECUTE" in s.get("props", []))),
            float(sum(1 for s in sections if "MEM_WRITE" in s.get("props", []))),
        ]

        section_sizes = [(str(s.get("name", "")), float(s.get("size", 0.0))) for s in sections]
        sizes_hashed = FeatureHasher(50, input_type="pair").transform([section_sizes]).toarray()[0]

        section_entropy = [(str(s.get("name", "")), float(s.get("entropy", 0.0))) for s in sections]
        entropy_hashed = FeatureHasher(50, input_type="pair").transform([section_entropy]).toarray()[0]

        section_vsize = [(str(s.get("name", "")), float(s.get("vsize", 0.0))) for s in sections]
        vsize_hashed = FeatureHasher(50, input_type="pair").transform([section_vsize]).toarray()[0]

        # In modern scikit-learn (1.9.1), wrap single string in [[item]]
        entry_name_hashed = FeatureHasher(50, input_type="string").transform([[entry_section]]).toarray()[0]

        entry_chars = [str(p) for s in sections for p in s.get("props", []) if s.get("name") == entry_section]
        chars_hashed = FeatureHasher(50, input_type="string").transform([entry_chars]).toarray()[0]

        return np.hstack([
            general,
            sizes_hashed,
            entropy_hashed,
            vsize_hashed,
            entry_name_hashed,
            chars_hashed,
        ]).astype(np.float32)

    # --------------------------------------------------------------------------
    # 7. ImportsInfo (1,280 dimensions)
    # --------------------------------------------------------------------------
    def vectorize_imports(self, raw_imports: Optional[Dict[str, Any]]) -> np.ndarray:
        """Process unique library names (256 bins) and qualified import symbols (1024 bins)."""
        if not raw_imports or not isinstance(raw_imports, dict):
            lib_hashed = FeatureHasher(256, input_type="string").transform([[]]).toarray()[0]
            imp_hashed = FeatureHasher(1024, input_type="string").transform([[]]).toarray()[0]
            return np.hstack([lib_hashed, imp_hashed]).astype(np.float32)

        libraries = list(set([str(lib).lower() for lib in raw_imports.keys()]))
        lib_hashed = FeatureHasher(256, input_type="string").transform([libraries]).toarray()[0]

        all_imports: List[str] = []
        for lib, funcs in raw_imports.items():
            lib_lower = str(lib).lower()
            if isinstance(funcs, list):
                for f in funcs:
                    all_imports.append(f"{lib_lower}:{f}")

        imp_hashed = FeatureHasher(1024, input_type="string").transform([all_imports]).toarray()[0]
        return np.hstack([lib_hashed, imp_hashed]).astype(np.float32)

    # --------------------------------------------------------------------------
    # 8. ExportsInfo (128 dimensions)
    # --------------------------------------------------------------------------
    def vectorize_exports(self, raw_exports: Optional[Sequence[Any]]) -> np.ndarray:
        """Process clipped export function symbol names (128 bins)."""
        if not raw_exports:
            return FeatureHasher(128, input_type="string").transform([[]]).toarray()[0].astype(np.float32)

        clipped = [str(name)[:10000] for name in raw_exports if name]
        return FeatureHasher(128, input_type="string").transform([clipped]).toarray()[0].astype(np.float32)

    # --------------------------------------------------------------------------
    # 9. DataDirectories (30 dimensions) — Size first (2*i), RVA second (2*i + 1)
    # --------------------------------------------------------------------------
    def vectorize_data_directories(self, raw_data_dirs: Optional[Sequence[Any]]) -> np.ndarray:
        """Extract size and virtual address (RVA) for the 15 canonical PE data directories.

        Canonical EMBER ordering:
        features[2 * i] = size
        features[2 * i + 1] = virtual_address (RVA)
        """
        output = np.zeros(30, dtype=np.float32)
        if not raw_data_dirs or not isinstance(raw_data_dirs, (list, tuple)):
            return output

        for i in range(15):
            if i < len(raw_data_dirs):
                item = raw_data_dirs[i]
                if isinstance(item, dict):
                    output[2 * i] = float(item.get("size", 0.0))
                    # Handle both virtual_address and rva keys
                    va = item.get("virtual_address")
                    if va is None:
                        va = item.get("rva", 0.0)
                    output[2 * i + 1] = float(va)

        return output

    # --------------------------------------------------------------------------
    # Full Vector Assembly
    # --------------------------------------------------------------------------
    def vectorize_raw_record(self, raw_record: Dict[str, Any]) -> np.ndarray:
        """Assemble all 9 feature groups from a raw JSON feature record into a 2,381-dim vector.

        Args:
            raw_record: Parsed JSON dictionary corresponding to an EMBER raw record.

        Returns:
            1D numpy array of exactly 2,381 float32 values.

        Raises:
            EmberMalformedRecordError: If record is not a dictionary.
            EmberNonFiniteValueError: If any extracted element is NaN or Inf.
        """
        if not isinstance(raw_record, dict):
            raise EmberMalformedRecordError(f"Expected dict for raw_record, got {type(raw_record).__name__}")

        f1 = self.vectorize_byte_histogram(raw_record.get("histogram"))
        f2 = self.vectorize_byte_entropy(raw_record.get("byteentropy"))
        f3 = self.vectorize_strings(raw_record.get("strings"))
        f4 = self.vectorize_general(raw_record.get("general"))
        f5 = self.vectorize_header(raw_record.get("header"))
        f6 = self.vectorize_section(raw_record.get("section"))
        f7 = self.vectorize_imports(raw_record.get("imports"))
        f8 = self.vectorize_exports(raw_record.get("exports"))
        f9 = self.vectorize_data_directories(raw_record.get("datadirectories"))

        total_vec = np.hstack([f1, f2, f3, f4, f5, f6, f7, f8, f9]).astype(np.float32)

        if total_vec.shape != (self.dim,):
            raise EmberMalformedRecordError(
                f"Assembled vector has shape {total_vec.shape}, expected ({self.dim},)"
            )

        # Enforce finite numbers invariant (no NaNs, no Infs)
        if not np.all(np.isfinite(total_vec)):
            non_finite_indices = np.where(~np.isfinite(total_vec))[0]
            raise EmberNonFiniteValueError(
                f"Vector contains {len(non_finite_indices)} non-finite values at indices: {non_finite_indices[:10].tolist()}"
            )

        return total_vec

    def vectorize_to_feature_vector(
        self,
        raw_record: Dict[str, Any],
        *,
        sample_id: Optional[str] = None,
        sample_hash: Optional[str] = None,
    ) -> FeatureVector:
        """Vectorize a raw record into a validated Pydantic FeatureVector envelope."""
        vec = self.vectorize_raw_record(raw_record)
        digest = sample_hash or raw_record.get("sha256")
        if not digest or not isinstance(digest, str) or len(digest) != 64:
            raise EmberMalformedRecordError("Missing or invalid canonical SHA-256 in raw_record.")

        sid = sample_id or raw_record.get("sha256", "unknown-sample")

        return FeatureVector(
            sample_id=sid,
            sample_hash=digest.lower(),
            feature_schema_version=self.schema_version,
            feature_values=vec.tolist(),
            feature_count=self.dim,
            missing_value_strategy=self.missing_value_strategy,
        )


_DEFAULT_VECTORIZER: Optional[EmberRawFeatureVectorizer] = None


def get_default_ember_raw_vectorizer() -> EmberRawFeatureVectorizer:
    """Return singleton instance of EmberRawFeatureVectorizer."""
    global _DEFAULT_VECTORIZER
    if _DEFAULT_VECTORIZER is None:
        _DEFAULT_VECTORIZER = EmberRawFeatureVectorizer()
    return _DEFAULT_VECTORIZER
