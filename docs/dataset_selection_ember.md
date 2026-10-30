# Dataset Selection & Specification: EMBER 2018 (Feature Version 2)

**Project:** Sentinel-EDR  
**Milestone:** Static PE Malware Classification Pipeline (Epic D)  
**Ticket:** T012 — Dataset and Model Schema Preparation  
**Status:** Documented / Selected for T013 & T014  

---

## 1. Overview & Upstream Source

Sentinel-EDR targets the **EMBER** (Elastic Malware Benchmark for Empowering Researchers) benchmark dataset for training and evaluating its static PE classifier, as established in:
- `prd.md` §11 ("Data and Model Evaluation")
- `trd.md` §3.1 ("Core Backend & Detection Logic")
- `implementation_plan.md` §8 ("Phase 4 — Static Feature Extraction and Machine Learning")
- `ticket_backlog.md` Ticket T012

Following review of upstream releases at https://github.com/elastic/ember, Sentinel-EDR officially selects **EMBER 2018, Feature Version 2**.

### Upstream Release Details

- **Dataset Collection Name:** `ember`
- **Release Identifier:** `2018`
- **Feature Version:** `2`
- **Canonical Feature Schema Identifier:** `ember_pe_v2`
- **Official Upstream Repository:** [https://github.com/elastic/ember](https://github.com/elastic/ember)
- **Official Archive Filename:** `ember_dataset_2018_2.tar.bz2`
- **Official Download URL:** `https://ember.elastic.co/ember_dataset_2018_2.tar.bz2`
- **Published Upstream Archive SHA-256 Checksum:**  
  `b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812`

> **Note on Digest Distinction:**  
> The checksum above is the cryptographic SHA-256 digest of the compressed upstream source archive file (`ember_dataset_2018_2.tar.bz2`). It must strictly be distinguished from any future integrity digests computed over extracted sample records or locally generated dataset manifests.

---

## 2. Canonical Feature Schema (Feature Version 2)

Upstream EMBER Feature Version 2 extracts structural, byte-level, and metadata properties from Windows Portable Executable (PE) files without execution, producing a vector of **2,381 numerical features**.

### Feature Group Breakdown (2,381 Total Dimensions)

| Group Index | Feature Group Name | Dimensionality | Description |
| :---: | :--- | :---: | :--- |
| 1 | **ByteHistogram** | 256 | Normalized distribution of raw byte values (0–255) across the entire executable. |
| 2 | **ByteEntropyHistogram** | 256 | Joint 2D distribution (16x16) of byte values and local entropy, measuring byte-level randomness and compressed/encrypted regions. |
| 3 | **StringExtractor** | 104 | Statistics of printable ASCII and UTF-8 strings: count, average length, printable character histogram, entropy, paths (`C:\`), URLs (`http`), registry keys (`HKEY_`), and PE marker counts (`MZ`). |
| 4 | **GeneralFileInfo** | 10 | High-level PE scalar properties: file size, virtual size, exported function count, imported function count, has debug, has relocations, has resources, has signature, has TLS, and symbol table count. |
| 5 | **HeaderFileInfo** | 62 | COFF header properties (machine architecture, timestamp, characteristics) and Optional Header properties (magic, subsystem, DLL characteristics, stack/heap reserve sizes). |
| 6 | **SectionInfo** | 255 | Information on PE sections: entry point section properties, total section count, section sizes, entropy distributions, characteristics flags, and hashed section names. |
| 7 | **ImportsInfo** | 1,280 | 2D hashed representation (hashing trick) of imported dynamic libraries (DLLs) and specific API functions invoked by the binary. |
| 8 | **ExportsInfo** | 128 | Hashed representations of exported symbol names. |
| 9 | **DataDirectories** | 30 | Size and Relative Virtual Address (RVA) pairs for the first 15 standard PE Data Directories (Export, Import, Resource, Exception, Certificate/Security, Base Relocation, Debug, Architecture, Global Ptr, TLS, Load Config, Bound Import, IAT, Delay Import, COM Descriptor). |
| **Total** | | **2,381** | **Exact Canonical Input Dimension for `ember_pe_v2`** |

---

## 3. Label Semantics & Supervised Training Policy

### Source Dataset Labels

Raw EMBER records contain three label classifications:
- `0`: Benign Windows PE executable.
- `1`: Malicious Windows PE executable (confirmed via VirusTotal AVClass family consensus).
- `-1`: Unlabeled / ambiguous sample (samples collected without AVClass consensus or without definitive ground truth).

### Sentinel-EDR Target Class Mapping

Sentinel-EDR enforces binary supervised classification via `DEFAULT_EMBER_LABEL_MAPPING`:
- Source `"0"` or `0` $\rightarrow$ Target class `0` (`BENIGN`)
- Source `"1"` or `1` $\rightarrow$ Target class `1` (`MALICIOUS`)
- Source `"-1"` or `-1` $\rightarrow$ `None` (`EXCLUDE_UNLABELED`)

### Supervised Integrity Rules:
1. **Zero Silent Poisoning:** Unlabeled samples (`-1`) are strictly excluded from supervised training and evaluation splits. They must **never** be silently converted to `0` (`BENIGN`) or `1` (`MALICIOUS`).
2. **Contract Rejection:** Any attempt to instantiate a supervised `DatasetSampleRecord` with `source_label="-1"` or assign it a target label raises an explicit `ValidationError`.
3. **Unsupported Label Rejection:** Any unrecognized label value (e.g. `2`, `"suspicious"`, `"unknown"`) raises an explicit `ValueError`.

---

## 4. Feature Extraction & Compatibility Constraints (T013)

Ticket T013 implements the static PE feature extractor corresponding to this schema. The following engineering constraints and algorithm specifications are enforced:

1. **Extraction Library Alignment & Reproducible Dependencies:**
   - **LIEF:** `lief==1.0.0` (official stable release on PyPI, CPython stable ABI `cp312-abi3-win_amd64`, runtime version `1.0.0-d05b3499b`).
   - **NumPy:** `numpy==2.5.4` (exact tested release).
   - **scikit-learn:** `scikit-learn==1.9.1` (exact tested release for `FeatureHasher` MurmurHash3 parity).
   - Dependencies are pinned in `requirements.txt` to ensure reproducible extraction across environments.

2. **ByteEntropyHistogram Algorithm & Short-File Behavior:**
   - Upstream EMBER `ByteEntropyHistogram` uses a window size of 2,048 bytes and step of 1,024 bytes.
   - **Non-Empty Short Files (< 2,048 bytes):** The available bytes are processed as a partial block. The coarse 16-bin histogram $c$ is computed via `block >> 4`, local probabilities are scaled by the full window size ($p = c / 2048$), the local entropy $H = 2 \sum -p \log_2(p)$ is computed, the coarse bin $Hbin = \min(\lfloor 2H \rfloor, 15)$ is selected, and counts are added to `output[Hbin, :] += c`. The flattened 256-element array is sum-normalized ($counts / \sum counts$) to sum to 1.0.
   - **Multi-Window Files (>= 2,048 bytes):** A rolling strided window computes local entropy across 2,048-byte blocks with a 1,024-byte step, accumulating into `output[Hbin, :] += c`, followed by sum-normalization.
   - **Documented Safe Empty-File Policy:** For empty inputs (0 bytes), an all-zero 256-dimensional vector is returned. This is an explicit, safe deviation from upstream EMBER (which performs $0.0 / 0.0$ producing an array of NaNs) to guarantee finite float values across all inputs.

3. **Missing-Value Policy:** Per T012 contracts, the static feature extractor emits `missing_value_strategy="zero_fill"`. Extracted features must strictly contain finite float numbers (zero NaNs, zero infinities, zero nulls).

4. **Safe Parsing:** Malformed, truncated, or non-PE binaries are handled safely without process crash, code execution, or memory corruption, producing valid 2,381 feature vectors with `parser_status="DEGRADED_NON_PE"`.

---

## 5. Parity Levels & Numerical Verification Boundaries

Sentinel-EDR strictly distinguishes three distinct tiers of verification:

1. **Structural Conformity (Verified in T013):**
   - The feature vector contains all 9 canonical groups in the exact order specified by EMBER Feature Version 2, totaling exactly 2,381 dimensions.
   - Data contracts strictly validate against `shared/schemas/feature_vector.schema.json` and Pydantic `FeatureVector`.

2. **Algorithm Parity (Audited by Feature Group):**
   - Verified for groups where mathematical and regex-based algorithms can be evaluated against independent reference calculations on local synthetic inputs without parser ambiguity.
   - For LIEF-dependent groups, structural mapping and FeatureHasher parameterization are verified, but parser-dependent behavior across diverse real-world compilers remains unvalidated until reference vectors are ingested.

3. **Full Dataset Parity (Deferred to T014):**
   - Numerical comparison of extracted vectors against upstream pre-extracted `.jsonl` / vectorized files from the official `ember_dataset_2018_2.tar.bz2` release across real-world malware and benign binaries.
   - Because downloading external dataset archives is prohibited in T013, full dataset parity is deferred to T014 where dataset partitions are formally ingested and benchmarked.

### Feature-Group-by-Feature-Group Parity Audit

| Group Index | Group Name | Dims | Evidence Classification | Verification Details & Parser Boundaries |
|:---:|---|:---:|---|---|
| 1 | **ByteHistogram** | 256 | **Algorithm-level comparison verified** | Evaluated against independent reference calculation (`bincount / total_bytes`) on empty, single-byte, uniform, skewed, and PE inputs. Bit-for-bit identical ($0.0$ difference). |
| 2 | **ByteEntropyHistogram** | 256 | **Algorithm-level comparison verified** | Evaluated against upstream EMBER reference across $0$, $1$, $100$, $2047$, $2048$, $2049$, and $5000$ bytes. Sub-window partial blocks and rolling strided windows match upstream bit-for-bit. Empty input follows documented finite-safe zero policy. |
| 3 | **StringExtractor** | 104 | **Algorithm-level comparison verified** | Evaluated against independent regex and statistical calculation: length metrics, 96-bin printable ASCII distribution, entropy, and regex counts (`c:\\`, `https?://`, `HKEY_`, `MZ`). Bit-for-bit identical. |
| 4 | **GeneralFileInfo** | 10 | **Parser-dependent behavior not yet validated** | Scalar fields (`size`, `vsize`, `has_debug`, `exports`, `imports`, `has_relocations`, `has_resources`, `has_signatures`, `has_tls`, `symbols`) conform structurally and match synthetic PE headers. LIEF 1.0.0 vs LIEF 0.9.0 parsing of malformed/packed PE files requires reference vector validation. |
| 5 | **HeaderFileInfo** | 62 | **Parser-dependent behavior not yet validated** | Categorical FeatureHasher configuration (10 bins each for machine, subsystem, characteristics, dll_characteristics, magic) and 11 scalars verified on synthetic PE fixtures. LIEF enum string representations (e.g. `MACHINE_TYPES.AMD64` vs `AMD64`) require reference vector validation. |
| 6 | **SectionInfo** | 255 | **Parser-dependent behavior not yet validated** | 5 general section metrics and 5x50 FeatureHasher blocks (sizes, entropies, vsizes, entry name, entry props) verified on multi-section PE fixtures. Entry section resolution on obfuscated PE headers and LIEF section characteristics string format require reference vector validation. |
| 7 | **ImportsInfo** | 1,280 | **Parser-dependent behavior not yet validated** | FeatureHasher 256 (unique libraries) and FeatureHasher 1024 (`lib:func` / `lib:ordinal123`) verified with independent hasher. LIEF 1.0.0 import ordinal string representation and parsing of corrupted import tables require reference vector validation. |
| 8 | **ExportsInfo** | 128 | **Parser-dependent behavior not yet validated** | FeatureHasher 128 with 10,000-character clipping verified with independent hasher. LIEF 1.0.0 export table parsing on complex binaries requires reference vector validation. |
| 9 | **DataDirectories** | 30 | **Algorithm-level comparison verified** | 15 standard directories with Size at $2i$ and Virtual Address (RVA) at $2i+1$ verified against synthetic PE fixtures with configured non-zero entries (Export, Import, Debug) and non-PE fallback (all zeros). |

---

## 6. Known Limitations of the EMBER 2018 Release

1. **Temporal & Concept Drift:** The samples in EMBER 2018 were collected through 2018. Adversary tactics, evasion techniques (e.g. novel packing algorithms, API hashing variants, indirect syscalls, and .NET loader wrappers) have evolved significantly since 2018.
2. **Compiler & Toolchain Evolution:** Modern compilers (Visual Studio 2022+, modern Rust/Go toolchains) produce different section layouts, import tables, and entropy signatures compared to 2018-era compilers.
3. **Deployment Role in Sentinel-EDR:** The model trained on EMBER 2018 serves as a reproducible baseline static detector. In production, Sentinel-EDR mitigates temporal drift by combining static ML inference with:
   - Authoritative SHA-256 local hash reputation (T008).
   - High-confidence YARA rule signature detection (T009/T011).
   - Real-time process and system telemetry monitoring (Epic E).
   - Planned retraining capabilities using newer telemetry or dataset extensions.

---

## 7. Provenance & Non-Fabrication Commitment

In accordance with T012 acceptance criteria:
- **No Data Fabrication:** Observed sample counts, train/test split totals, class balance figures, and local manifest integrity digests will **not** be recorded or assumed until the archive is formally acquired, verified, and extracted in subsequent workflow steps.
- **Reproducible Reference:** Downstream tasks (T013 PE feature extractor and T014 LightGBM training) must reference this document and `backend-api/app/schemas/ml_contracts.py` as the canonical source of truth for the EMBER 2018 v2 schema.
