# T015 — ONNX Export and Inference Report

**Ticket:** T015 — ONNX Export and Inference  
**Epic:** Machine Learning Engine  
**Status:** DONE  
**Verified Models:**
- Design A (Primary): `sentinel-pe-lightgbm-audit-v2.onnx` (Random Stratified 80/20, Threshold: `0.8856`)
- Design B (Secondary): `sentinel-pe-lightgbm-temporal.onnx` (Temporal Validation Split, Threshold: `0.9303`)

---

## 1. Executive Summary

This report documents the design, export procedure, prediction parity verification, inference service architecture, and performance benchmarking for Ticket **T015 (ONNX Export and Inference)**.

The verified LightGBM PE malware classification boosters trained during T014 have been compiled into optimized ONNX computation graphs. The ONNX models preserve the canonical 2,381-feature input schema (`ember_pe_v2`), enforce float32 dynamic batch dimensions, match the original LightGBM booster predictions with near-exact numerical precision (maximum difference on test data $\le 2.23 \times 10^{-7}$ for Design A), achieve 100.00% binary classification parity across all 10,000 held-out test executables, and deliver sub-millisecond inference latency (0.038 ms per sample, >130,000 samples/sec in batch mode).

---

## 2. Converter Choice and Dependency Architecture

### Environment & Compatibility Matrix:
- **Operating System:** Windows 11 (AMD64)
- **Python Runtime:** Python 3.13.6
- **Tree Booster Engine:** LightGBM 4.7.0
- **Feature Vector Array:** NumPy 2.5.4

### Selected ONNX Dependencies:
| Dependency | Version | Purpose |
|---|---|---|
| `onnxruntime` | `1.31.1` | Optimized C++ cross-platform inference runtime |
| `onnx` | `1.23.2` | ONNX protobuf specification, checker, and graph definition |
| `onnxmltools` | `1.16.0` | LightGBM-to-ONNX tree converter (`convert_lightgbm`) |
| `skl2onnx` | `1.20.0` | Supporting scikit-learn / tree conversion utilities |
| `protobuf` | `7.36.2` | Graph serialization protocol |
| `flatbuffers` | `25.12.19` | Fast memory buffers |
| `ml_dtypes` | `0.6.0` | Machine learning numerical types |

All dependencies are explicitly pinned in [`requirements.txt`](file:///D:/project/requirements.txt).

### Converter Technical Nuances & Fixes:
1. **Target Operator Set (Opset 15):** The maximum supported operator set for ONNX-ML tree ensemble conversions on `onnx 1.23.2` and `onnxmltools 1.16.0` is opset 15 (`ai.onnx.ml`).
2. **Probability Output Tensor (`zipmap=False`):** By default, ONNX-ML converts probabilities into a sequence of dictionaries (`seq(map(int64, tensor(float)))`). Passing `zipmap=False` compiles probabilities directly into a contiguous 2D float32 tensor of shape `[None, 2]`, maximizing cache efficiency and throughput.
3. **Dynamic Batch Parameter on Label Output:** `onnxmltools` defaults the output shape of `label` to fixed `[1]`. During dynamic batch evaluation in ONNX Runtime, this causes shape-mismatch warnings. The export service explicitly clears `dim_value` and sets `dim_param = "None"` on `label`, allowing variable batch sizes ($N$) without warnings.

---

## 3. ONNX Model Export Service

The export service is implemented in [`backend-api/app/services/onnx_export_service.py`](file:///D:/project/backend-api/app/services/onnx_export_service.py) via `OnnxModelExporter`.

### Export Process:
1. **Booster Validation:** Loads booster and strictly checks `booster.num_feature() == 2381`.
2. **Graph Conversion:** Converts booster to ONNX with `initial_types=[('features', FloatTensorType([None, 2381]))]`, `target_opset=15`, `zipmap=False`.
3. **Dynamic Batch Shape Adjustment:** Sets dynamic batch dimension on `label` output.
4. **Graph & Session Validation:** Runs `onnx.checker.check_model` and executes a dummy inference pass through `ort.InferenceSession`.
5. **Atomic Persistence:** Writes ONNX bytes to temporary file, computes canonical SHA-256 digest, and atomically places it at target path.
6. **Metadata Conformance:** Generates and atomically persists ModelMetadata JSON conforming to [`shared/schemas/model_metadata.schema.json`](file:///D:/project/shared/schemas/model_metadata.schema.json).

### Exported Artifact Inventory:

| Model Design | Model Artifact Path | File Size | SHA-256 Digest | Metadata Path |
|---|---|---:|---|---|
| **Design A (Primary)** | [`.data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2.onnx`](file:///D:/project/.data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2.onnx) | 469,989 bytes | `5e3b72ee5f09e8d7d619dcd211c9d815aa16b147d02232589919afa76076ec8e` | [`.data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2_onnx_metadata.json`](file:///D:/project/.data/experiments/t014-audit-v2/sentinel-pe-lightgbm-audit-v2_onnx_metadata.json) |
| **Design B (Temporal)** | [`.data/experiments/t014-audit-v2/sentinel-pe-lightgbm-temporal.onnx`](file:///D:/project/.data/experiments/t014-audit-v2/sentinel-pe-lightgbm-temporal.onnx) | 469,919 bytes | `c59ecd989e0d1dd204f0bcaca3f147ac770336cbebfeb9a7dcb0d871c1f28b12` | [`.data/experiments/t014-audit-v2/sentinel-pe-lightgbm-temporal_onnx_metadata.json`](file:///D:/project/.data/experiments/t014-audit-v2/sentinel-pe-lightgbm-temporal_onnx_metadata.json) |

All original baseline LightGBM boosters and text metadata files are strictly preserved.

---

## 4. Input and Output Contracts

### Input Tensor Contract:
- **Node Name:** `features`
- **Data Type:** `tensor(float)` (32-bit floating point)
- **Rank / Dimensions:** 2D tensor `[None, 2381]` (variable batch size $N$, exactly 2,381 static PE features conforming to `ember_pe_v2`).
- **Validation Rules:**
  - 1D inputs `(2381,)` are automatically reshaped to `(1, 2381)`.
  - Feature counts $\ne 2381$ raise `InvalidInputDimensionError`.
  - Tensors with rank $\ne 1$ or $2$ raise `InvalidInputDimensionError`.
  - Vectors containing `NaN`, `+Inf`, or `-Inf` raise `NonFiniteInputError`.

### Output Tensor Contract:
- **Probabilities Tensor (`probabilities`):**
  - Shape: `[None, 2]`
  - Data Type: `tensor(float)` (values bounded in $[0.0, 1.0]$)
  - Column 0: Benign class probability
  - Column 1: Malicious class probability
- **Label Tensor (`label`):**
  - Shape: `[None]`
  - Data Type: `tensor(int64)`
  - Value: Argmax predicted class index (0 for Benign, 1 for Malicious)

---

## 5. Operating Threshold Determination and Separation

In accordance with safety requirements, raw probability inference is kept strictly separate from threshold classification decisions:
- **Raw Inference:** Produces continuous probabilities $P(\text{Malicious} \mid X) \in [0.0, 1.0]$.
- **Decision Logic:** Compares $P(\text{Malicious}) \ge \theta_{\text{operating}}$:
  - If $\ge \theta$: verdict is `"MALICIOUS"`, predicted label is `1`.
  - If $< \theta$: verdict is `"BENIGN"`, predicted label is `0`.
- **Threshold Assignment:**
  - **Design A:** $\theta = 0.8856$ (selected strictly on validation to enforce validation $\text{FPR} \le 0.005$).
  - **Design B:** $\theta = 0.9303$ (selected strictly on temporal validation to enforce validation $\text{FPR} \le 0.005$).
- Callers may override the threshold for specific policy requirements without altering model weights.

---

## 6. Prediction Parity Verification & Boundary Split Investigation

Prediction parity was measured against the official held-out test partition (10,000 real PE binaries: 5,000 benign, 5,000 malicious) comparing native `lightgbm.Booster.predict()` with `OnnxInferenceService.predict_batch()`.

### Measurement Results:

| Metric | Design A (Primary) | Design B (Temporal) | Documented Acceptance Tolerance |
|---|---:|---:|---|
| **Test Dataset Size ($N$)** | 10,000 | 10,000 | Held-out EMBER test set |
| **Max Absolute Probability Difference** | **$2.23 \times 10^{-7}$** | $1.67 \times 10^{-2}$ (1 boundary sample) | $< 1.0 \times 10^{-4}$ (Production standard) |
| **Clean Non-Boundary Max Difference** | **$2.23 \times 10^{-7}$** | **$1.80 \times 10^{-7}$** (9,999 samples) | $< 1.0 \times 10^{-4}$ |
| **Mean Absolute Probability Difference** | **$3.28 \times 10^{-8}$** | **$1.71 \times 10^{-6}$** | $< 1.0 \times 10^{-5}$ |
| **99th Percentile Difference** | **$1.06 \times 10^{-7}$** | **$1.11 \times 10^{-7}$** | $< 1.0 \times 10^{-4}$ |
| **Spearman Rank Correlation** | **$> 0.99999$** | **$> 0.99999$** | $> 0.9999$ |
| **Single-Sample vs. Batch Parity** | **Identical** | **Identical** | Exact float equality within $10^{-6}$ |
| **Test Classification Agreement** | **10,000 / 10,000 (100.00%)** | **10,000 / 10,000 (100.00%)** | 100.0% binary decision agreement |

### Investigation of Design B Probability Discrepancy ($1.67 \times 10^{-2}$):
A thorough audit of the single outlier sample at index **8517** revealed the exact mechanical origin of the difference:
1. **Affected Sample & Feature:**
   - Sample index in held-out test set: `8517` (Ground truth label: `0` / Benign).
   - Affected feature: Feature `626` (`header.coff.timestamp`, seconds since UNIX epoch).
   - Exact sample feature value: `1260053632.0` (`0x1.2c6b920000000p+30`, corresponding to Dec 5, 2009).
2. **Affected Trees and Split Thresholds:**
   - Both **Tree 29** and **Tree 97** in Design B split on Feature 626 with threshold `th = 1260053568.0000002` (`0x1.2c6b910000001p+30`).
   - In LightGBM (internal 64-bit float math): $1260053632.0 > 1260053568.0000002 \implies \text{BRANCH\_RIGHT}$.
     - Tree 29 produces leaf score `+0.05986852`.
     - Tree 97 produces leaf score `+0.04236733`.
     - Cumulative LightGBM logit: `-1.77298724` $\implies P(\text{Malicious}) = \mathbf{0.14517123}$.
3. **ONNX Protobuf Float32 Quantization:**
   - In ONNX specification for `TreeEnsembleClassifier`, node threshold attributes are serialized as 32-bit floats (`nodes_values: float`).
   - In IEEE 754 float32, numbers around $1.26 \times 10^9$ have 64-unit step quantization ($2^{30} \times 2^{-24} = 64$).
   - The double-precision split threshold `1260053568.0000002` rounds up to `1260053632.0` in 32-bit float.
   - When evaluating `sample[8517, 626] == 1260053632.0`:
     $\text{sample\_val} \le \text{onnx\_th} \implies 1260053632.0 \le 1260053632.0$ evaluates as **`True`** ($\text{BRANCH\_LEFT}$).
     - Tree 29 produces leaf score `-0.03960622`.
     - Tree 97 produces leaf score `+0.00023976`.
     - Cumulative ONNX logit: `-1.91461955` $\implies P(\text{Malicious}) = \mathbf{0.12846607}$.
   - Absolute probability difference: $|0.14517123 - 0.12846607| = \mathbf{0.01670516}$.
4. **Safety & Classification Impact:**
   - Operating threshold for Design B is `0.9303`.
   - Distance from threshold in LightGBM: $|0.145171 - 0.9303| = \mathbf{0.7851}$.
   - Distance from threshold in ONNX: $|0.128466 - 0.9303| = \mathbf{0.8018}$.
   - Both probabilities are deep within the BENIGN region ($>0.78$ margin from threshold). Zero classification error occurs.
   - Across the remaining 9,999 test binaries, maximum difference is $\le 1.80 \times 10^{-7}$.

### Targeted Boundary Testing Suite:
Perturbations of Feature 626 were tested around the split threshold:

| Condition | Feature 626 Value | LightGBM Prob | ONNX Prob | Abs Difference | Classification | Agreement |
|---|---:|---:|---:|---:|---|---|
| **Clearly Below** ($th - 1000$) | $1260052568.0$ | $0.128466$ | $0.128466$ | $4.86 \times 10^{-8}$ | BENIGN | **MATCH** |
| **Below LGB Threshold** ($th - 128$) | $1260053440.0$ | $0.128466$ | $0.128466$ | $4.86 \times 10^{-8}$ | BENIGN | **MATCH** |
| **Exact LGB Threshold** ($th$) | $1260053568.0$ | $0.128466$ | $0.128466$ | $4.86 \times 10^{-8}$ | BENIGN | **MATCH** |
| **Original Sample** (ONNX $th$) | $1260053632.0$ | $0.145171$ | $0.128466$ | $1.67 \times 10^{-2}$ | BENIGN | **MATCH** |
| **Above ONNX Threshold** ($th + 128$) | $1260053760.0$ | $0.145171$ | $0.145171$ | $6.44 \times 10^{-8}$ | BENIGN | **MATCH** |
| **Clearly Above** ($th + 1000$) | $1260054632.0$ | $0.145171$ | $0.145171$ | $6.44 \times 10^{-8}$ | BENIGN | **MATCH** |

### Design A Control Verification:
Under the identical boundary perturbation suite, Design A (`sentinel-pe-lightgbm-audit-v2.onnx`) exhibits **zero split boundary collisions**:
- Maximum probability difference: $\mathbf{4.40 \times 10^{-8}}$ across all points.
- 100.0% classification agreement at operating threshold `0.8856`.
- Confirmed production readiness for Design A. Design B remains designated as an experimental research model.

---

## 7. Inference Performance Benchmarks

Benchmarks were executed on the test partition using Windows 11 x64 on an Intel 12-core host (`intra_op_num_threads=1` for low jitter).

### 1. Model Loading Latency:
- **Design A:** Average: **13.19 ms** (min: 11.86 ms, max: 15.39 ms)
- **Design B:** Average: **13.56 ms** (min: 12.16 ms, max: 15.37 ms)

### 2. Single-Sample Inference Latency (500 distinct PE binaries):
- **Average Latency:** **0.0378 ms** (37.8 microseconds)
- **Median Latency:** **0.0352 ms**
- **P95 Latency:** **0.0533 ms**
- **P99 Latency:** **0.1003 ms**
- **Single-Sample Throughput:** **~26,450 samples / second**

### 3. Batch Inference Latency & Throughput:

| Batch Size | Total Latency (avg) | Total Latency (median) | P95 Latency | Per-Sample Latency | Throughput |
|---|---:|---:|---:|---:|---:|
| **1** | 0.030 ms | 0.028 ms | 0.038 ms | 0.0303 ms | 32,992 samples/sec |
| **10** | 0.087 ms | 0.085 ms | 0.106 ms | 0.0087 ms | 114,345 samples/sec |
| **50** | 0.401 ms | 0.396 ms | 0.429 ms | 0.0080 ms | 124,587 samples/sec |
| **100** | 0.755 ms | 0.753 ms | 0.787 ms | 0.0075 ms | 132,465 samples/sec |
| **500** | 3.944 ms | 3.899 ms | 4.638 ms | 0.0079 ms | 126,766 samples/sec |

---

## 8. Failure Modes and Degraded-Mode Handling

The inference service provides clear error handling and degraded-mode guarantees:

| Failure Condition | Exception Raised | System / Orchestrator Action |
|---|---|---|
| **Missing Model File** | `OnnxArtifactNotFoundError` | Health status marked `UNAVAILABLE`; fails fast during initialization. |
| **Corrupt / Truncated Model** | `OnnxModelCorruptError` | Health status marked `UNAVAILABLE`; session init aborted. |
| **SHA-256 Digest Mismatch** | `ArtifactHashMismatchError` | Prevents executing tampered or out-of-sync model artifacts. |
| **Missing Runtime Library** | `RuntimeDependencyError` | Clear diagnostic message instructing pip install. |
| **Feature Count $\ne 2,381$** | `InvalidInputDimensionError` | Rejects vector immediately with dimension details. |
| **NaN / Inf in Features** | `NonFiniteInputError` | Identifies count of NaNs/Infs; rejects corrupt feature vectors. |
| **Runtime Execution Failure** | `InferenceExecutionError` | Captures ONNX Runtime error without process crash. |
| **Degraded Pipeline Escalation** | `get_degraded_response()` | Returns `predicted_class="ERROR_DEGRADED"`, `is_degraded=True`, `malicious_prob=-1.0`. **Never silently fabricates a BENIGN verdict.** |

---

## 9. Test Suite Verification

Three test suites were implemented (23 automated unit and parity tests):
1. [`tests/backend/test_onnx_export.py`](file:///D:/project/tests/backend/test_onnx_export.py): 8 tests covering conversion, dynamic batching, atomic writing, rollback on failure, schema conformance.
2. [`tests/backend/test_onnx_inference.py`](file:///D:/project/tests/backend/test_onnx_inference.py): 10 tests covering loading, single/batch inference, threshold separation, dimension errors, non-finite values, corrupt artifacts, SHA mismatches, degraded mode.
3. [`tests/backend/test_onnx_parity.py`](file:///D:/project/tests/backend/test_onnx_parity.py): 5 tests verifying numerical parity, rank correlations, 100% test classification agreement, targeted boundary testing of Feature 626 split on Design B, and Design A boundary robustness control.

### Full Regression Suite:
```powershell
Set-Location D:\project
.\.venv\Scripts\python.exe -m pytest tests\backend -vv -s --tb=short --durations=20
```
- **Passed:** **332 / 332** tests.
- **Failures:** **0**.
- **Warnings:** 1 benign Starlette deprecation warning (`starlette.testclient`).

---

## 10. Conclusion and Backlog Status

- **Primary Model (Design A):** Fully verified and approved for production use. Retains max error $< 10^{-4}$ ($2.23 \times 10^{-7}$), 100% classification agreement, verified SHA-256 (`5e3b72ee5f09e8d7d619dcd211c9d815aa16b147d02232589919afa76076ec8e`), and operating threshold of `0.8856`.
- **Secondary Model (Design B):** Boundary discrepancy fully documented and understood as IEEE 754 float32 quantization of large UNIX timestamps ($1.26 \times 10^9$) in tree split thresholds. Designated as an experimental model.
- **Ticket T015 Acceptance Criteria:** All satisfied.
- **Ticket Backlog:** Marked **`DONE`** in [`ticket_backlog.md`](file:///D:/project/ticket_backlog.md).
- **Next Ticket:** T016 remains in `BACKLOG`. T016 is not started.
