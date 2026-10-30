# Sentinel-EDR

Sentinel-EDR is a hybrid Endpoint Detection and Response (EDR) platform combining signature-based detection, static PE machine learning, runtime behavioral monitoring, composite risk scoring, secure quarantine, and AI-assisted forensic explanations.

---

## Backend Development Setup

The backend service is built with Python 3.13 and FastAPI, following a modular architecture.

### 1. Prerequisites

- **Operating System:** Windows 10/11 (x64)
- **Python:** 3.13+ with `venv` module support
- **Git:** Version 2.40+

### 2. Environment Setup

From the repository root (`D:\project`), create and activate a Python virtual environment:

```powershell
# Create the virtual environment
python -m venv .venv

# Activate the virtual environment in Windows PowerShell
.\.venv\Scripts\Activate.ps1

# (Optional) If script execution is restricted in your PowerShell session:
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

### 3. Install Dependencies

Install the foundational backend dependencies into the active virtual environment:

```powershell
python -m pip install -r requirements.txt
```

Core dependencies in `requirements.txt`:
- `fastapi` — REST API framework
- `uvicorn[standard]` — ASGI server runtime
- `pydantic-settings` — Validated configuration management
- `SQLAlchemy` — Database ORM (Phase 2)
- `alembic` — Database schema migration tool
- `pytest` — Automated test framework
- `httpx` — HTTP client for API testing
- `yara-python` — Official Python bindings for YARA signature scanning
- `lief` — Static PE parsing and section extraction
- `lightgbm` — Gradient boosted decision tree engine
- `onnxruntime` — High-performance C++ ONNX inference engine (T015)
- `onnxmltools` & `onnx` — Model conversion and schema validation (T015)

### 4. Configuration

The application loads configuration from environment variables or a local `.env` file with safe defaults. To customize settings:

```powershell
Copy-Item .env.example .env
```

Review and adjust variables in `.env` as needed:
- `DATABASE_URL`: Connection string for SQLite (default: `sqlite:///.data/sentinel_edr.db`). Relative SQLite paths are automatically anchored to the repository root.
- Do not commit `.env` or `.data/` to source control.

### 5. Database Setup and Migrations

Sentinel-EDR uses SQLite 3 with SQLAlchemy 2.x and Alembic for schema migrations. Relational integrity is enforced at connection time using `PRAGMA foreign_keys = ON;`.

To apply all pending database migrations:

```powershell
Set-Location D:\project\backend-api
..\.venv\Scripts\alembic.exe upgrade head
```

To inspect the currently applied migration revision:

```powershell
Set-Location D:\project\backend-api
..\.venv\Scripts\alembic.exe current
```

### 6. Running the Backend Server

Start the local development server using Uvicorn from the `backend-api` directory:

```powershell
Set-Location D:\project\backend-api
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Alternatively, from the repository root:

```powershell
Set-Location D:\project
$env:PYTHONPATH = "backend-api"
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- **Base URL:** `http://127.0.0.1:8000`
- **Interactive API Documentation (Swagger UI):** `http://127.0.0.1:8000/docs`
- **OpenAPI Schema (JSON):** `http://127.0.0.1:8000/openapi.json`

#### Implemented Foundation Endpoints:
- `GET /api/v1/health` — API liveness status
- `GET /api/v1/status` — Real-time backend subsystem and database availability
- `GET /api/v1/incidents` — Paginated retrieval of security incidents with bounded filtering
- `GET /api/v1/incidents/{incident_id}` — Detailed incident view with evidence and action metrics

### 7. YARA Signature Scanner and Rule Configuration

Sentinel-EDR includes a standalone YARA scanning service powered by `yara-python` integrated into the analysis orchestration pipeline:

- **Pipeline Activation:** Configurable via `YARA_ENABLED` (default: `false`). When enabled, the application lifespan compiles configured rules at startup, and `AnalysisOrchestrator` invokes YARA as Stage 3 of file analysis.
- **Rules Directory:** Configurable via `YARA_RULES_DIR` (default: `rules/yara`). The scanner discovers supported `.yar` and `.yara` files with deterministic ordering and stable namespaces.
- **Scan Timeout:** Configurable via `YARA_SCAN_TIMEOUT_SECONDS` (default: 30 seconds). Timed-out scans are reported explicitly with `TIMED_OUT` status and fail the job with `YARA_SCAN_TIMEOUT` (never fabricated as completed no-match results).
- **Max File Size:** Configurable via `YARA_MAX_FILE_SIZE_BYTES` (default: 100 MB).

To test the standalone YARA scanner and the integrated analysis pipeline:

```powershell
Set-Location D:\project
python -m pytest tests\backend\test_yara_scanner.py tests\backend\test_yara_pipeline_integration.py -v
```

### 8. Analysis Queue, Workers, and Orchestration

Sentinel-EDR provides a multi-threaded analysis queue and orchestration service for managing background analysis pipelines:

- **Process-Local Bounded Queue:** The in-memory dispatch queue is strictly process-local with configurable capacity via `ANALYSIS_QUEUE_CAPACITY` (default: 100). Persisted database records serve as the authoritative state, with backpressure preventing silent job loss during queue saturation.
- **Supported Deployment Model:** The supported background execution architecture is a **single active `AnalysisWorkerManager` process** when `ANALYSIS_WORKERS_ENABLED=true`.
- **Atomic Job Claiming vs. Orphaned Recovery:**
  - *Atomic Claiming (`claim_analysis_job`):* Concurrency-safe conditional updates (`status='QUEUED'` -> `'IN_PROGRESS'`) prevent multiple workers or threads from processing the same job.
  - *Orphaned Recovery (`recover_interrupted_jobs`):* Controlled by `ANALYSIS_RECOVER_INTERRUPTED_ON_STARTUP` (default: `false`). When enabled for a designated single manager process, cold startup transitions un-resumable `IN_PROGRESS` jobs to `FAILED` (`INTERRUPTED_BY_SHUTDOWN`). When disabled, `IN_PROGRESS` jobs are left untouched while eligible `QUEUED` jobs are safely discovered and dispatched.
- **Orchestration Pipeline Stages (T011):**
  1. Computes canonical lowercase SHA-256 digests via memory-bounded streaming.
  2. Queries the local hash reputation database. The exact local reputation (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`, or unknown `is_known=False`) is preserved in the structured `hash_reputation` summary field. Unknown hashes remain neutral (`is_known=False`, `verdict=None`) and are never fabricated as benign.
  3. YARA signature scanning (when `YARA_ENABLED=true` and target file path is available). Matching rules generate persisted, idempotent `DetectionEvidence` records linked to the job and incident, preserving rule metadata and match details. A clean scan with zero matches produces no synthetic evidence. Unready scanner, timeouts, or file access errors transition the job to `FAILED` with explicit error codes.
  4. The top-level overall analysis `verdict` and `risk_score` on `AnalysisResult` and `AnalysisJob` remain strictly `None` throughout T011, as individual engine stages do not constitute a composite multi-engine verdict. Multi-engine verdict synthesis and risk scoring belong strictly to T020 (Verdict Aggregation).

To run the queue, worker, orchestrator, and pipeline integration tests:

```powershell
Set-Location D:\project
python -m pytest tests\backend\test_analysis_queue.py tests\backend\test_analysis_orchestrator.py tests\backend\test_analysis_worker.py tests\backend\test_yara_pipeline_integration.py -v
```

### 9. Machine Learning Dataset and Model Schema Foundation (T012)

Sentinel-EDR defines versioned, language-neutral data contracts for the PE static machine learning pipeline (Epic D):

- **Selected Benchmark Dataset Release:** Verified and documented in [`docs/dataset_selection_ember.md`](docs/dataset_selection_ember.md):
  - **Dataset & Release:** `ember` / `2018` (Feature Version 2)
  - **Canonical Feature Schema:** `ember_pe_v2` (2,381 numerical dimensions)
  - **Upstream Repository:** `https://github.com/elastic/ember`
  - **Official Archive:** `ember_dataset_2018_2.tar.bz2` (`https://ember.elastic.co/ember_dataset_2018_2.tar.bz2`)
  - **Published Upstream SHA-256 Checksum:** `b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812`
- **Shared JSON Schemas:** Defined under `shared/schemas/`:
  - `dataset_sample_record.schema.json` — Traced dataset sample records enforcing canonical lowercase SHA-256 (`^[a-f0-9]{64}$`), split assignment, portable relative paths, and provenance metadata.
  - `dataset_manifest.schema.json` — Versioned dataset collection metadata, class definitions, excluded unlabeled counts, and split integrity reconciliation (`sample_count == sum(split_counts)`).
  - `feature_vector.schema.json` — Extracted numerical PE feature vector envelope with missing-value handling strategy (`native_nan` with JSON-safe `null`, `zero_fill`, `mean_impute`).
  - `model_metadata.schema.json` — Model specification for LightGBM/ONNX artifacts, input dimensions (2,381), evaluation metrics, and class ordering.
- **Dataset Validation Service (`DatasetValidator`):** Implements non-destructive quality checks detecting duplicate sample digests, cross-split data leakage, and label mapping inconsistencies.
- **Target Label Semantics:** Binary target classes `0` (`BENIGN`) and `1` (`MALICIOUS`). EMBER source label `-1` (unlabeled/ambiguous) is excluded by policy (`EXCLUDE_UNLABELED`) and never converted to benign.

To run the ML dataset contract and validation tests:

```powershell
Set-Location D:\project
python -m pytest tests\backend\test_ml_dataset_contracts.py -v
```

### 10. Static PE Feature Extraction Service (T013)

Sentinel-EDR provides a standalone static PE feature extraction service in `backend-api/app/services/pe_feature_extractor.py` implementing the `ember_pe_v2` schema (2,381 dimensions) for binary executables:
- **Canonical Ordering:** Preserves all 9 feature groups in exact EMBER v2 sequence: ByteHistogram (256), ByteEntropyHistogram (256), StringExtractor (104), GeneralFileInfo (10), HeaderFileInfo (62), SectionInfo (255), ImportsInfo (1,280), ExportsInfo (128), DataDirectories (30, with Size-before-RVA ordering).
- **Graceful Degradation:** Malformed, truncated, or non-PE binaries parse safely without crashes, yielding zero-filled vectors with `parser_status="DEGRADED_NON_PE"`.
- **Pinned Dependencies:** `lief==1.0.0`, `numpy==2.5.4`, `scikit-learn==1.9.1`.

To run the PE feature extraction test suite:

```powershell
Set-Location D:\project
python -m pytest tests\backend\test_pe_feature_extractor.py -v
```

### 11. LightGBM Model Training and Evaluation Workflow (T014)

Sentinel-EDR provides a reproducible training, validation, threshold-selection, and evaluation workflow for LightGBM static malware classifiers:

- **Authoritative Dataset Release:**
  - **Dataset:** EMBER 2018 (Feature Version 2, schema `ember_pe_v2`, 2,381 dimensions)
  - **Official Archive:** `https://ember.elastic.co/ember_dataset_2018_2.tar.bz2` (1.696 GB compressed)
  - **Published SHA-256 Checksum:** `b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812`
  - **Configurable Directories:** `EMBER_DATASET_DIR` (default `.data/ember`) and `ML_MODELS_DIR` (default `.data/models`).
- **Binary Label Policy:** Strict T012 label mapping: `0` -> `BENIGN`, `1` -> `MALICIOUS`, `-1` -> Excluded (`excluded_unlabeled_count`). Unlabeled records are strictly omitted from supervised fitting and evaluation.
- **Resource-Aware Streaming & Memmaps:**
  - Disk-backed memory-mapped arrays (`X_train.dat`, `y_train.dat`, `X_test.dat`, `y_test.dat`) enable processing large JSONL shards without exceeding host RAM boundaries.
  - Optional `--subset-size <N>` flag supports deterministic, bounded experiments in resource-constrained environments. Subset experiments are explicitly flagged in `ModelMetadata.training_config["is_subset_experiment"] = true`.
- **Validation-Only Operating Threshold Determination:**
  - The official held-out test partition (`test_features.jsonl`) is strictly preserved and never used for parameter tuning, early stopping, or threshold selection.
  - The operating threshold is determined strictly on the validation partition (targeting low false-positive rate $\le 0.005$) and frozen before evaluating on the held-out test set.
- **Output Artifacts and Metadata:**
  - Native LightGBM text model: `.data/models/sentinel-pe-lightgbm.txt`
  - Validated ModelMetadata JSON: `.data/models/sentinel-pe-lightgbm_metadata.json` (conforms to `model_metadata.schema.json` with computed artifact SHA-256, hyperparameter settings, and test metrics).
- **Raw-Feature Vectorization Parity vs. LIEF Parser Parity:**
  - *Raw-Feature Vectorization Parity:* The transformations from JSONL records to 2,381-dimensional float32 vectors match upstream `ember/features.py` bit-for-bit (verified across all 9 groups in `test_lightgbm_training.py`).
  - *Parser-Dependent Limitation:* Upstream EMBER 2018 raw features were generated using LIEF 0.9.0 in 2018. Minor parser discrepancies between LIEF 0.9.0 and modern LIEF 1.0.0 on heavily packed or corrupted binaries are inherent to toolchain evolution and tracked separately from vectorization parity.

#### Running Training and Ingestion via CLI:

```powershell
Set-Location D:\project

# View CLI options
.\.venv\Scripts\python.exe scripts/train_lightgbm.py --help

# Run training workflow on configured data directory
.\.venv\Scripts\python.exe scripts/train_lightgbm.py --data-dir .data/ember --models-dir .data/models

# Optional: Download and extract upstream archive if missing
.\.venv\Scripts\python.exe scripts/train_lightgbm.py --download --extract --subset-size 5000
```

To run the dataset ingestion and LightGBM training automated test suites:

```powershell
Set-Location D:\project
.\.venv\Scripts\python.exe -m pytest tests\backend\test_ember_dataset_ingestion.py tests\backend\test_lightgbm_training.py -v
```

### 12. ONNX Model Export and Inference Service (T015)

Sentinel-EDR compiles trained LightGBM tree boosters into optimized ONNX computation graphs for high-throughput, cross-platform inference:
- **Production Artifact:** Design A (`sentinel-pe-lightgbm-audit-v2.onnx`, SHA-256: `5e3b72ee5f09e8d7d619dcd211c9d815aa16b147d02232589919afa76076ec8e`).
- **Feature Contract:** Preserves 2,381 float32 features adhering to `ember_pe_v2`. Input tensors are verified for dimensional conformity, rank, and finite values (`NaN`/`Inf` checks).
- **Prediction Parity:** 100.00% binary classification agreement with native LightGBM on 10,000 held-out test executables with sub-millisecond execution latency.

To run the ONNX export, inference, and numerical parity test suites:

```powershell
Set-Location D:\project
.\.venv\Scripts\python.exe -m pytest tests\backend\test_onnx_export.py tests\backend\test_onnx_inference.py tests\backend\test_onnx_parity.py -v
```

### 13. Machine Learning Pipeline Integration (T016)

Sentinel-EDR integrates static PE feature extraction and ONNX machine learning inference into the core analysis orchestrator (`AnalysisOrchestrator`) and background worker pipeline:
- **Execution Pipeline (4 Stages):**
  1. File SHA-256 digest computation (streaming).
  2. Local hash reputation query (preserves stored reputation or neutral unknown).
  3. YARA signature scanning (when `YARA_ENABLED=true`).
  4. Static PE feature extraction and ONNX ML inference (`ml_pe`, when `ML_ENABLED=true`).
- **PE Validation & Non-PE Handling:** Target executables are inspected for the DOS `MZ` magic header. Non-PE files (scripts, plain text, documents) are gracefully skipped without failure (`modules_skipped.append("ml_pe")`). Corrupted or truncated PE files trigger explicit `PE_MALFORMED_FILE` failure.
- **Evidence Persistence:** Successful classifications persist structured, idempotent `DetectionEvidence` records (`source="ml_pe"`) linked to the job and correlated Incident using deterministic UUIDv5 identifiers.
- **Fault Isolation:** Failure during the ML stage preserves prior Hash and YARA evidence. Unanalyzed or failed files are never marked as benign.
- **Scope Boundary:** Composite risk scoring and top-level verdict aggregation strictly remain deferred to T020 (`verdict=None`, `risk_score=None`).

To run the ML pipeline integration test suite:

```powershell
Set-Location D:\project
.\.venv\Scripts\python.exe -m pytest tests\backend\test_ml_pipeline_integration.py -v
```

### 14. Running Automated Tests

Run the backend test suite from the repository root:

```powershell
Set-Location D:\project
python -m pytest tests\backend -v
```

To run tests with quiet output:

```powershell
python -m pytest tests\backend -q
```


---

## Frontend Development Setup

The frontend Security Operations Center (SOC) dashboard is built with React 18, TypeScript, Vite, and Tailwind CSS.

### 1. Prerequisites

- **Node.js:** v20+ (tested with `v26.13.0`)
- **npm:** v10+ (tested with `11.20.0`)
- **Directory:** `dashboard-ui/`

### 2. Install Dependencies

From the `dashboard-ui` directory, install frontend dependencies:

```powershell
Set-Location D:\project\dashboard-ui
npm install
```

Core dependencies in `dashboard-ui/package.json`:
- `react`, `react-dom` — UI framework
- `vite`, `@vitejs/plugin-react` — Fast bundler & development server
- `tailwindcss`, `postcss`, `autoprefixer` — Utility-first styling
- `typescript` — Static type checking
- `vitest`, `@testing-library/react`, `jsdom` — Component test suite
- `eslint`, `typescript-eslint` — Code quality and style linting

### 3. Running the Development Server

Start the local Vite development server:

```powershell
Set-Location D:\project\dashboard-ui
npm run dev
```

The console is accessible locally at `http://127.0.0.1:3000`.

### 4. Quality Checks and Testing

Run the following checks from `dashboard-ui/`:

- **Code Linting:**
  ```powershell
  npm run lint
  ```
- **TypeScript Type Checking:**
  ```powershell
  npm run typecheck
  ```
- **Automated Component Tests:**
  ```powershell
  npm run test
  ```
- **Production Build:**
  ```powershell
  npm run build
  ```
