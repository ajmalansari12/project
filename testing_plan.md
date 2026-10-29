# Sentinel-EDR
## Testing Plan

**Project:** Sentinel-EDR — Hybrid Real-Time Endpoint Detection and Response System  
**Document Version:** 1.0  
**Status:** Initial Draft  
**Related Documents:** `prd.md`, `trd.md`, `implementation_plan.md`, `architecture.md`, `database_schema.md`, `api_spec.md`, `ticket_backlog.md`

---

## 1. Purpose

This document defines the testing strategy for Sentinel-EDR.

Testing will verify that individual modules work correctly, integrated components communicate through their documented interfaces, security-sensitive operations behave safely, and the complete application meets its functional requirements.

Google Antigravity must use this document when implementing tickets and must not mark a ticket complete until its required tests have been executed and verified.

Testing must use harmless fixtures, mocked dependencies, and controlled behavioral simulations. Live malware is not required for the initial development or demonstration.

## 2. Testing Objectives

The testing process must:

1. Verify that each implemented component behaves according to its requirements.
2. Validate shared schemas, API contracts, and database constraints.
3. Verify the signature-detection and static ML pipelines.
4. Test behavioral detection using controlled simulations.
5. Confirm that risk scoring and verdict generation are deterministic.
6. Verify quarantine, restoration, integrity checks, and authorization controls.
7. Confirm that incidents and evidence persist correctly.
8. Verify the REST API, WebSocket events, and SOC dashboard.
9. Test failures, unavailable dependencies, and recovery behavior.
10. Measure ML classification performance and system latency.
11. Prevent regressions as new tickets are implemented.
12. Ensure documented capabilities correspond to tested behavior.

## 3. Testing Principles

- **Test incrementally:** Write and run tests alongside each implementation ticket.
- **Automate repeatable checks:** Prefer automated tests for deterministic behavior.
- **Isolate dependencies:** Mock external providers, OS-specific behavior, and destructive operations where appropriate.
- **Use safe fixtures:** Generate harmless test files instead of using live malware.
- **Test failure paths:** Verify how the system behaves when components fail.
- **Preserve evidence:** Store relevant test results and evaluation measurements.
- **Avoid unsupported claims:** A passing unit test does not prove that the complete system prevents malware execution.
- **Verify actual results:** Do not claim tests passed without executing them.
- **Keep tests reproducible:** Record relevant software versions, configurations, and dataset splits.
- **Test security boundaries:** Validate authorization, path handling, encryption, and restoration behavior.

## 4. Testing Technology

| Area | Preferred Tool |
|---|---|
| Backend unit and integration tests | pytest |
| API testing | FastAPI TestClient or HTTPX |
| Database tests | SQLite test database and SQLAlchemy |
| Mocking | pytest fixtures and mocking utilities |
| Frontend unit tests | Vitest |
| Frontend component tests | React Testing Library |
| Frontend browser tests | Playwright, if introduced by an approved ticket |
| Code quality | Python linting and formatting tools selected during setup |
| Frontend type validation | TypeScript compiler |
| ML evaluation | scikit-learn metrics and appropriate evaluation utilities |
| Performance measurement | Python timing and profiling utilities |

The implementation must use one consistent test configuration and avoid adding redundant testing frameworks without a documented reason.

## 5. Test Categories

### 5.1 Unit Testing

Unit tests verify individual functions and components in isolation.

Examples include:

- SHA-256 calculations.
- Hash-list matching.
- YARA result interpretation.
- PE feature extraction.
- ML input validation.
- Risk-score calculations.
- Verdict thresholds.
- Configuration validation.
- API request validation.
- Quarantine path validation.
- Incident serialization.

Unit tests should be fast, deterministic, and independent of external services.

### 5.2 Integration Testing

Integration tests verify communication between components.

Examples include:

- Sensor events entering the analysis queue.
- The orchestrator invoking the signature engine.
- PE features being passed to ONNX inference.
- Detection evidence entering the scoring engine.
- Incidents being saved to SQLite.
- The response engine updating quarantine records.
- FastAPI retrieving persisted incidents.
- WebSocket events being delivered to connected clients.

### 5.3 System and End-to-End Testing

System tests verify complete workflows across multiple components.

The initial end-to-end workflow must demonstrate:

1. A harmless test file is detected in a monitored directory.
2. The file enters the analysis queue.
3. Applicable signature checks are performed.
4. Eligible PE files undergo the configured static ML analysis.
5. Available behavioral evidence is considered.
6. The risk-scoring engine produces the expected result.
7. The incident and evidence are persisted.
8. The dashboard displays the incident.
9. A controlled response operation can be tested.
10. The incident status reflects the actual outcome.

Unavailable optional components must be reported accurately rather than simulated as successful operations.

### 5.4 Security Testing

Security tests verify that unsafe or unauthorized operations are rejected.

Testing must cover:

- Invalid input and malformed files.
- Path traversal attempts.
- Unauthorized quarantine and restoration requests.
- Invalid destination paths.
- Attempts to overwrite existing files without authorization.
- Invalid or missing encryption metadata.
- Corrupted quarantine artifacts.
- Invalid API payloads.
- Exposed secrets in application logs.
- Malformed AI-provider responses.
- Incomplete or interrupted response operations.

All destructive-action tests must use mocks, dry-run behavior, or disposable test artifacts.

### 5.5 Regression Testing

Regression tests ensure that changes introduced by new tickets do not break previously completed functionality.

The regression suite must cover relevant completed features, including:

- Shared data contracts.
- Database persistence.
- Signature scanning.
- ML inference.
- Risk scoring.
- Incident APIs.
- Response authorization.
- Quarantine and restoration.
- Dashboard integration.
- WebSocket event handling.

Each ticket must add or update regression tests for the behavior it changes.

### 5.6 Performance Testing

Performance tests measure resource consumption and latency under representative workloads.

The test suite must measure:

- SHA-256 hashing time.
- Signature scanning duration.
- PE feature extraction duration.
- ML inference latency.
- Queue waiting time.
- End-to-end analysis duration.
- WebSocket event-delivery latency.
- CPU and memory consumption where practical.

Performance targets must remain separate from achieved results until measurements have been collected.

## 6. Test Directory Structure

The initial test directory should use the following organization:

```text
tests/
├── conftest.py
├── unit/
│   ├── test_config.py
│   ├── test_hashing.py
│   ├── test_signature_engine.py
│   ├── test_feature_extractor.py
│   ├── test_ml_inference.py
│   ├── test_risk_scoring.py
│   ├── test_quarantine.py
│   └── test_event_schema.py
├── integration/
│   ├── test_database.py
│   ├── test_analysis_pipeline.py
│   ├── test_behavioral_monitor.py
│   ├── test_response_engine.py
│   ├── test_api.py
│   └── test_websocket.py
├── security/
│   ├── test_path_validation.py
│   ├── test_authorization.py
│   ├── test_quarantine_integrity.py
│   └── test_input_validation.py
├── frontend/
│   ├── components/
│   ├── pages/
│   └── api/
├── e2e/
│   └── test_incident_workflow.py
├── fixtures/
│   ├── benign_files/
│   ├── synthetic_pe/
│   └── simulations/
└── performance/
    ├── benchmark_hashing.py
    ├── benchmark_features.py
    ├── benchmark_inference.py
    └── benchmark_pipeline.py
```

This is the proposed structure, not a requirement to create every file immediately. Files must be introduced through their relevant implementation tickets.

The final test structure must remain consistent with the repository and the organization defined in `trd.md`.

## 7. Safe Test Data and Fixtures

Testing must not depend on executing live malware.

### 7.1 Benign Files

Use harmless files to test:

- File creation and modification events.
- File hashing.
- Queue processing.
- File access errors.
- Database persistence.
- Dashboard updates.

### 7.2 Signature Test Fixtures

Create a dedicated YARA rule for a known test marker and a harmless file that matches it.

Verify that:

- The expected rule matches.
- The associated evidence is recorded.
- A different file without the marker does not produce the same match.
- The system handles unavailable rulesets correctly.

Test blocklist matching using explicitly configured synthetic hashes or hashes of designated harmless fixtures.

### 7.3 ML Test Fixtures

Use the documented public dataset for training and evaluation.

For integration tests, use:

- Valid feature vectors matching the model schema.
- Saved model artifacts where appropriate.
- Synthetic or benign PE fixtures for parser validation.
- Mocked inference outputs for deterministic scoring tests.

A model's output on a benign file must not be assumed to represent ground-truth malware classification.

### 7.4 Behavioral Simulations

Use controlled scripts to simulate harmless filesystem events, such as modifying multiple designated test files or modifying a dedicated canary file.

Simulations must:

- Operate only in designated test directories.
- Avoid modifying unrelated user data.
- Avoid destructive encryption or file-deletion behavior.
- Produce deterministic expected events where possible.
- Clearly identify simulated activity in testing reports.

### 7.5 Test Environment Isolation

Tests must not:

- Execute live malware.
- Modify operating-system files.
- Terminate arbitrary processes.
- Quarantine arbitrary user files.
- Use production encryption keys.
- Require administrator privileges unnecessarily.
- Depend on real AI-provider credentials for routine automated testing.

Tests that require particular operating-system facilities must use suitable mocks or run in an explicitly configured test environment.

## 8. Module-Level Test Requirements

### 8.1 Endpoint Sensor

**Required tests:**

- Detect a new file in a monitored directory.
- Detect supported modifications and rename events.
- Handle inaccessible directories.
- Handle files that are still being written.
- Handle duplicate filesystem events.
- Handle shutdown and restart.
- Represent unavailable process metadata correctly.

**Expected result:** Supported events are normalized and delivered without crashing the application.

The tests must not imply that a directory watcher prevents execution.

### 8.2 Signature Detection Engine

**Required tests:**

- Correct SHA-256 calculation.
- Blocklist match.
- Allowlist match.
- YARA rule match.
- YARA non-match.
- Invalid rule handling.
- Unreadable file handling.
- Cache behavior.
- Hash-list loading failures.

**Expected result:** The engine returns structured evidence or an explicit processing error.

### 8.3 Static ML Engine

**Required tests:**

- Supported PE parsing.
- Malformed PE handling.
- Feature-schema validation.
- Feature-order validation.
- Missing model handling.
- Inference output validation.
- Model-version reporting.
- Feature extraction timing.
- Inference timing.

**Expected result:** The engine returns a valid model result only when the selected model and its feature schema are available and compatible.

### 8.4 Behavioral Monitor

**Required tests:**

- Process metadata collection where supported.
- Suspicious relationship-rule matching.
- Canary-file modification detection.
- File activity threshold evaluation.
- Missing process metadata.
- Monitoring errors.
- False-positive handling using ordinary test activity.

**Expected result:** Behavioral alerts include the rule and observations supporting the detection.

### 8.5 Risk Scoring Engine

**Required tests:**

- Minimum and maximum possible scores.
- YARA-only evidence.
- ML-only evidence.
- Combined evidence.
- Entropy normalization.
- Behavioral evidence.
- Missing evidence.
- Configurable weights.
- Threshold-boundary behavior.
- High-confidence policy overrides.
- Invalid configuration.

**Expected result:** Scores and verdicts are deterministic for identical inputs and configuration.

The scoring tests must verify the actual configured policy rather than assume the initial thresholds are optimal.

### 8.6 Response Engine and Quarantine

**Required tests:**

- Dry-run quarantine request.
- Authorized quarantine of a disposable test file.
- Unauthorized quarantine rejection.
- Encryption and decryption.
- Integrity verification.
- Restoration to a permitted destination.
- Existing destination handling.
- Invalid path rejection.
- Invalid encryption metadata.
- Interrupted operation handling.
- Audit record creation.

**Expected result:** A response is reported as successful only when the operation has been completed and verified according to policy.

### 8.7 Database and Incident Service

**Required tests:**

- Database initialization.
- Record creation and retrieval.
- Foreign-key enforcement.
- Invalid enum and field values.
- Transaction rollback.
- Persistence across restarts.
- Pagination and filtering.
- Migration behavior.
- Database failure handling.

**Expected result:** Data remains consistent and failures are explicitly represented.

### 8.8 FastAPI Backend

**Required tests:**

- Health and status endpoints.
- Incident list and detail endpoints.
- Evidence retrieval.
- Analysis-job status retrieval.
- Invalid request handling.
- Missing-resource behavior.
- Incident status transitions.
- Authorization checks.
- Quarantine requests.
- Restoration requests.
- Forensic-report endpoints.
- Database failures.

**Expected result:** All implemented endpoints conform to `api_spec.md`.

### 8.9 WebSocket Communication

**Required tests:**

- Successful local connection.
- Correct event envelope.
- Event delivery after successful persistence.
- Client disconnection.
- Reconnection behavior.
- Malformed messages where applicable.
- Duplicate event handling.
- Sensitive-data exclusion.

**Expected result:** Connected clients receive supported events, and the REST API remains the source of truth for persisted state.

### 8.10 SOC Dashboard

**Required tests:**

- Dashboard rendering.
- Incident-list retrieval.
- Incident filtering.
- Incident-detail rendering.
- Risk score and verdict display.
- Loading and empty states.
- Backend error handling.
- WebSocket updates.
- Reconnection behavior.
- Quarantine action-state display.
- Forensic-report rendering.
- TypeScript compilation and production build.

**Expected result:** The dashboard displays actual API data and accurately represents loading, failure, and response-action states.

### 8.11 AI Forensic Reporting

**Required tests:**

- Valid report generation using a mocked or configured provider.
- Malformed provider responses.
- Provider timeout.
- Missing credentials.
- Unavailable provider.
- Evidence reference validation.
- Report persistence.
- Failure-state reporting.
- Attempts to generate unauthorized actions through report content.

**Expected result:** AI output remains advisory, and report-generation failure does not block core detection or incident persistence.

## 9. Risk-Scoring Test Matrix

The following cases must be tested against the implemented scoring policy.

| Test case | Evidence | Expected verification |
|---|---|---|
| RSK-01 | All scoring inputs are zero | Score is 0 |
| RSK-02 | All normalized inputs are one | Score is 100 |
| RSK-03 | YARA evidence only | Contribution follows configured YARA weight |
| RSK-04 | ML evidence only | Contribution follows configured ML weight |
| RSK-05 | Entropy input below normalization threshold | Entropy penalty follows the documented formula |
| RSK-06 | Multiple detection signals | Contributions combine according to configured weights |
| RSK-07 | Score immediately below 35 | Benign verdict under initial thresholds |
| RSK-08 | Score exactly 35 | Suspicious verdict under initial thresholds |
| RSK-09 | Score immediately below 70 | Suspicious verdict under initial thresholds |
| RSK-10 | Score exactly 70 | Malicious verdict under initial thresholds |
| RSK-11 | Canary policy override | Configured high-priority policy is applied |
| RSK-12 | Invalid weights or missing evidence | Configuration or evidence policy is enforced |

These tests verify implementation consistency. They do not establish that the scoring model achieves acceptable real-world detection performance.

## 10. API Test Matrix

| Test ID | Scenario | Expected result |
|---|---|---|
| API-01 | API health check | Successful response when API is available |
| API-02 | Component status query | Actual component availability reported |
| API-03 | Incident list query | Correct paginated results |
| API-04 | Unknown incident ID | `404 Not Found` |
| API-05 | Invalid pagination values | Validation error |
| API-06 | Unsupported verdict filter | Validation error |
| API-07 | Valid incident status update | Status changes and audit record is created |
| API-08 | Invalid incident status transition | Conflict or documented validation error |
| API-09 | Unauthorized quarantine request | Request rejected |
| API-10 | Accepted dry-run quarantine | Request accepted, with pending or actual state accurately represented |
| API-11 | Invalid restoration destination | Request rejected |
| API-12 | AI provider unavailable | Clear unavailable or failed report status |
| API-13 | Database unavailable | Documented service error without fabricated success |
| API-14 | WebSocket event | Event follows the documented envelope |

The final expected status codes must match the implemented contract in `api_spec.md`.

## 11. Quarantine and Recovery Test Matrix

| Test ID | Scenario | Expected result |
|---|---|---|
| QTN-01 | Quarantine in dry-run mode | No actual file isolation is claimed |
| QTN-02 | Authorized quarantine of test file | Encrypted object and metadata are created |
| QTN-03 | Unauthorized quarantine request | Request rejected |
| QTN-04 | Corrupted encrypted object | Integrity or decryption failure reported |
| QTN-05 | Invalid key reference | Operation fails safely |
| QTN-06 | Successful restoration | Restored content matches the original hash |
| QTN-07 | Destination already exists | No silent overwrite |
| QTN-08 | Invalid destination path | Request rejected |
| QTN-09 | Interrupted quarantine | State reflects incomplete operation |
| QTN-10 | Failed restoration | Recovery metadata and quarantined object are retained when possible |

All actual quarantine and restoration tests must use designated disposable test artifacts.

## 12. Machine Learning Evaluation Plan

Model evaluation must be separate from routine software testing.

### 12.1 Required Metrics

Calculate the following where applicable:

- ROC-AUC.
- Precision.
- Recall.
- F1-score.
- False-positive rate.
- Confusion matrix.
- Feature extraction duration.
- ONNX inference latency.
- End-to-end analysis latency.

### 12.2 Dataset and Split Requirements

- Record the selected dataset version.
- Document the feature schema.
- Document preprocessing and label conventions.
- Separate training, validation, and test data appropriately.
- Do not select final thresholds using the test split.
- Avoid data leakage between training and evaluation.
- Record the model artifact version and experiment configuration.

### 12.3 False-Positive Evaluation

False-positive rate must be calculated from the relevant confusion-matrix counts:

\[
\mathrm{FPR} =
\frac{\mathrm{FP}}{\mathrm{FP}+\mathrm{TN}}
\]

where FP represents benign samples incorrectly classified as malicious and TN represents benign samples correctly classified as benign.

If the denominator is zero, report the metric as undefined rather than inventing a value.

### 12.4 Model Acceptance

The initial targets proposed in `prd.md`, including ROC-AUC above 0.98 and false-positive rate below 1%, are research goals rather than guaranteed outcomes.

The final report must record measured results and explain any differences between goals and observations.

A model must not be considered successful solely because its accuracy is high on an imbalanced dataset.

## 13. Performance Benchmark Plan

Benchmark the following stages independently:

1. SHA-256 hashing.
2. YARA scanning.
3. PE feature extraction.
4. ONNX inference.
5. Queue waiting time.
6. End-to-end analysis.
7. WebSocket event delivery.

### 13.1 Representative File Sizes

Where supported by the test pipeline, use:

- 1 KB.
- 1 MB.
- 10 MB.
- 50 MB.

A file size alone does not establish that a file is a valid PE executable. Use appropriate fixtures for each benchmark stage.

### 13.2 Benchmark Procedure

For every experiment:

1. Record the test environment.
2. Record the file or fixture characteristics.
3. Record the relevant configuration and model version.
4. Run an initial warm-up where applicable.
5. Execute repeated measurements.
6. Report sample count, median, and high-percentile latency where practical.
7. Record errors and failed runs.
8. Separate feature extraction time from inference time.
9. Compare Python inference and ONNX inference only when equivalent feature preparation and model behavior are used.
10. Record the results in the project evaluation report.

The sub-20-millisecond inference target applies only to the inference stage unless the complete pipeline is independently measured and shown to satisfy it.

## 14. Ticket-Based Testing Workflow

Every implementation ticket must include its required verification.

When working on a ticket, Antigravity must:

1. Read the ticket and relevant project documents.
2. Inspect existing tests and implementation.
3. Identify the required unit, integration, security, or frontend tests.
4. Implement the scoped changes.
5. Add or update tests.
6. Run the relevant test commands.
7. Inspect failures and investigate regressions.
8. Report the actual commands executed.
9. Report passed, failed, skipped, and blocked tests accurately.
10. List any remaining limitations.

A ticket must not be marked `DONE` if its acceptance criteria require passing tests that remain unexecuted or failing.

A test may be marked blocked when the required environment or dependency is unavailable, but the blocker must be documented and the ticket must not be reported as fully verified.

## 15. Continuous Regression Testing

At minimum, the following checks must be run at the appropriate stages:

### Backend

- Python test suite.
- Backend linting and formatting checks.
- API contract tests.
- Database and migration tests.

### Frontend

- TypeScript type checking.
- Frontend component tests.
- Linting and formatting checks.
- Production build.

### Integrated System

- Detection-pipeline integration tests.
- Incident persistence tests.
- API and WebSocket integration tests.
- Quarantine and restoration safety tests.
- End-to-end smoke tests.

The exact commands must be established in the repository's setup and development documentation. Antigravity must use the actual scripts and dependency versions present in the project rather than assuming that a command exists.

## 16. Test Results and Evidence

Relevant test results should be stored in an organized location, such as:

```text
reports/
├── test-results/
├── model-evaluation/
├── performance/
└── security/
```

These directories should be created only when needed by implementation tickets.

Test evidence should include:

- Ticket identifier.
- Date and environment.
- Test command.
- Result summary.
- Failures and relevant error details.
- Model or configuration version, when applicable.
- Links or references to supporting logs and reports.

Do not store secrets, encryption keys, sensitive user data, or unnecessary executable contents in test reports.

## 17. Testing Exit Criteria

A ticket passes testing when:

- Its required acceptance criteria are satisfied.
- Relevant automated tests have run successfully.
- Relevant regressions have been checked.
- Any blocked or skipped tests are disclosed.
- Security-sensitive behavior has been verified where applicable.
- Documentation reflects the tested functionality.

The integrated project passes final testing when:

- The documented end-to-end workflow works using safe test artifacts.
- Signature and ML components produce recorded results.
- Behavioral simulations trigger their expected alerts.
- Risk scores and verdicts follow the implemented policy.
- Incidents and evidence persist correctly.
- The API and dashboard function together.
- Response operations respect authorization and recovery requirements.
- AI reporting failures do not block the core pipeline.
- Performance and model-evaluation measurements are reproducible.
- Known limitations are documented.

---

**End of Testing Plan**