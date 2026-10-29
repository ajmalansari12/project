# Sentinel-EDR
## Ticket Backlog

**Project:** Sentinel-EDR — Hybrid Real-Time Endpoint Detection and Response System  
**Document Version:** 1.0  
**Status:** Initial Backlog  
**Development Environment:** Google Antigravity  
**Related Documents:** `prd.md`, `trd.md`, `implementation_plan.md`, `architecture.md`, `database_schema.md`, `api_spec.md`

---

## 1. Purpose

This document defines the development backlog for Sentinel-EDR.

Every implementation task must be tracked as an individual ticket with a unique identifier, clear scope, dependencies, acceptance criteria, and required tests.

Google Antigravity must implement only the ticket currently assigned. It must not attempt to implement the entire backlog in one operation.

This backlog defines the intended implementation sequence. Ticket status must reflect the actual state of the repository and must be updated as work progresses.

## 2. Ticket Rules

### Ticket Identifiers

Tickets use sequential identifiers:

`T001`, `T002`, `T003`, and so on.

Each identifier is permanent and must never be reused.

### Priority Levels

- **P0 — Critical:** Required for the foundational system or a core security boundary.
- **P1 — High:** Required for the initial working product.
- **P2 — Normal:** Important supporting capability or evaluation work.

### Ticket Statuses

- `BACKLOG` — Not started.
- `READY` — Dependencies satisfied and ready for implementation.
- `IN_PROGRESS` — Currently being implemented.
- `BLOCKED` — Cannot proceed because of an unresolved dependency.
- `IN_REVIEW` — Implementation completed and awaiting verification.
- `DONE` — Acceptance criteria and required verification passed.

### Definition of Ticket Completion

A ticket may be marked `DONE` only when:

1. Its acceptance criteria are satisfied.
2. The required implementation exists in the repository.
3. Relevant tests have been executed.
4. Test results have been inspected.
5. No known critical regression introduced by the ticket remains unresolved.
6. Required documentation has been updated.
7. Any incomplete work is explicitly identified.

Generating code alone does not constitute ticket completion.

---

# 3. Epic A — Project Foundation

## T001 — Repository Inspection and Project Baseline

**Priority:** P0  
**Status:** BACKLOG  
**Dependencies:** None

**Objective:** Inspect the repository and establish the starting point for development.

**Scope:**
- Inspect existing files, dependencies, and directory structure.
- Read the project documentation.
- Identify inconsistencies or conflicting requirements.
- Check available Python, Node.js, npm, and Git tooling.
- Identify existing functionality that must be preserved.
- Report blockers before modifying the project.

**Acceptance criteria:**
- The existing repository is inspected.
- Existing functionality and missing components are documented.
- The technology stack is compared against `trd.md`.
- No unnecessary files or dependencies are created.
- A clear implementation baseline is established.

**Out of scope:** Implementing application features.

## T002 — Backend Environment and Application Scaffold

**Priority:** P0  
**Status:** BACKLOG  
**Dependencies:** T001

**Objective:** Establish the Python backend environment and application entry point.

**Scope:**
- Configure the Python environment and dependencies.
- Create the backend package structure.
- Add the FastAPI application.
- Add basic configuration loading.
- Configure `.env.example` and `.gitignore` where needed.
- Add structured logging.
- Add basic backend test infrastructure.

**Acceptance criteria:**
- The backend starts using documented commands.
- Configuration validation works.
- Logs are generated without exposing secrets.
- Backend tests can run.
- Dependency definitions are reproducible.

## T003 — Frontend Environment and Application Scaffold

**Priority:** P0  
**Status:** BACKLOG  
**Dependencies:** T001

**Objective:** Establish the React dashboard development environment.

**Scope:**
- Configure React, TypeScript, Vite, and Tailwind CSS.
- Create the initial frontend structure.
- Configure linting and frontend tests.
- Establish reusable layout and styling conventions.
- Add a basic application entry point.

**Acceptance criteria:**
- The frontend starts using documented commands.
- The production build succeeds.
- TypeScript compilation succeeds.
- Frontend tests can run.
- No backend secrets are included in browser code.

## T004 — Shared Contracts and Configuration

**Priority:** P0  
**Status:** BACKLOG  
**Dependencies:** T002, T003

**Objective:** Establish shared application terminology and validated data contracts.

**Scope:**
- Define event types and event identifiers.
- Define analysis-job states.
- Define security verdicts and incident statuses.
- Define shared detection-evidence models.
- Define timestamps and error representations.
- Define the configuration schema.
- Establish consistent corresponding types in the Python and TypeScript applications.

**Acceptance criteria:**
- Shared Python schemas are validated.
- Corresponding TypeScript types reflect the public API contract.
- Enum values are consistent across the applications.
- Invalid configuration and invalid payloads produce clear errors.
- No unnecessary duplicate schema implementations are introduced.

---

# 4. Epic B — Database and Backend Foundation

## T005 — SQLite and SQLAlchemy Schema

**Priority:** P0  
**Status:** BACKLOG  
**Dependencies:** T002, T004

**Objective:** Implement the database schema defined in `database_schema.md`.

**Scope:**
- Create SQLAlchemy models for all eight defined entities.
- Implement primary keys and foreign-key relationships.
- Add required constraints and indexes.
- Enable SQLite foreign-key enforcement.
- Configure database initialization and schema-version management.
- Establish a controlled migration approach.

**Acceptance criteria:**
- All eight tables are implemented.
- Relationships and required constraints are validated.
- Foreign-key enforcement is active.
- Relevant indexes are created.
- Database initialization is reproducible.
- Existing data is not silently discarded by schema changes.

## T006 — Persistence Services and Database Tests

**Priority:** P0  
**Status:** BACKLOG  
**Dependencies:** T005

**Objective:** Implement controlled database access through application services.

**Scope:**
- Implement incident persistence.
- Implement analysis-job persistence.
- Implement evidence persistence.
- Implement response-action and quarantine metadata persistence.
- Implement forensic-report and audit-record persistence.
- Add transaction handling and database error management.

**Acceptance criteria:**
- Records can be created and retrieved through service interfaces.
- Foreign-key relationships behave as documented.
- Data persists across application restarts.
- Database errors are handled explicitly.
- Automated tests cover persistence and relationships.
- Business logic does not depend directly on database implementation details.

## T007 — Health, Status, and Incident API Foundation

**Priority:** P0  
**Status:** BACKLOG  
**Dependencies:** T002, T006

**Objective:** Implement the first backend API endpoints.

**Scope:**
- Implement `GET /api/v1/health`.
- Implement `GET /api/v1/status`.
- Establish standard error responses.
- Configure request validation.
- Add initial incident retrieval endpoints where their dependencies are satisfied.
- Verify generated OpenAPI documentation.

**Acceptance criteria:**
- Health status reflects actual API availability.
- Component status is not hardcoded to report success.
- Errors use the documented response format.
- Database failures are handled appropriately.
- API tests cover successful requests and relevant error cases.

---

# 5. Epic C — Signature Detection and Analysis

## T008 — SHA-256 and Hash Database Service

**Priority:** P0  
**Status:** BACKLOG  
**Dependencies:** T004

**Objective:** Implement file hashing and local hash-list matching.

**Scope:**
- Calculate SHA-256 using chunked file reading.
- Implement configurable local allowlists and blocklists.
- Validate hash-list entries.
- Normalize hash-match results into detection evidence.
- Handle unreadable or changing files.

**Acceptance criteria:**
- Hashes match known benign test fixtures.
- Hash-list matches return the expected result.
- Invalid entries are rejected or reported according to the documented policy.
- File-reading errors are visible.
- Failed hashing is never interpreted automatically as proof that a file is benign.

## T009 — YARA Signature Scanner

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T008

**Objective:** Integrate signature-rule scanning.

**Scope:**
- Select and configure a compatible YARA implementation.
- Implement rule loading and validation.
- Scan eligible test files.
- Record matched rule identifiers and severity.
- Handle unavailable or invalid rule collections.

**Acceptance criteria:**
- A harmless file matching a dedicated test rule produces the expected evidence.
- A file that does not match the test rules produces no fabricated match.
- Invalid rulesets produce clear errors.
- Rule identifiers are preserved in detection evidence.
- Tests do not require live malware.

## T010 — Analysis Queue and Orchestrator

**Priority:** P0  
**Status:** BACKLOG  
**Dependencies:** T004, T006, T008

**Objective:** Coordinate analysis jobs and detection-service execution.

**Scope:**
- Implement analysis-job creation and status management.
- Add bounded job scheduling and configurable concurrency.
- Connect the orchestrator to SHA-256 and hash-list matching.
- Record completed, failed, and skipped stages.
- Handle duplicate jobs and interrupted processing where practical.

**Acceptance criteria:**
- Analysis jobs follow the documented lifecycle.
- Duplicate events are handled appropriately.
- Hash results flow into structured analysis results.
- Failed stages remain distinguishable from successful stages.
- Queue and worker errors do not silently produce benign verdicts.

## T011 — YARA Integration with the Analysis Pipeline

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T009, T010

**Objective:** Integrate signature scanning into the orchestrated analysis workflow.

**Scope:**
- Invoke the signature scanner through the orchestrator.
- Merge hash and YARA results into structured evidence.
- Apply the documented analysis-stage policy.
- Persist relevant evidence.
- Record stage timings and errors.

**Acceptance criteria:**
- Signature results are associated with the correct analysis job.
- Matched rules appear in persisted evidence.
- Stage failures are recorded.
- The analysis result accurately identifies executed and skipped modules.
- Integration tests cover both match and non-match cases.

---

# 6. Epic D — Machine Learning Engine

## T012 — Dataset and Model Schema Preparation

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T002

**Objective:** Establish the reproducible ML dataset and feature-schema requirements.

**Scope:**
- Select and document the intended EMBER dataset version.
- Inspect its feature schema and label conventions.
- Document dataset preparation and split strategy.
- Define the feature schema used by the selected model.
- Record reproducibility requirements.

**Acceptance criteria:**
- The selected dataset version is documented.
- Feature and label definitions are understood.
- Training and evaluation splits are defined.
- The planned model schema is documented.
- No model performance results are claimed before experiments are run.

## T013 — PE Feature Extraction

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T012

**Objective:** Implement the feature extractor required by the selected ML model.

**Scope:**
- Validate PE file inputs.
- Integrate LIEF where appropriate.
- Extract the features required by the selected model.
- Calculate section entropy.
- Handle malformed, unsupported, and truncated files.
- Validate feature order and types.

**Acceptance criteria:**
- Supported fixtures produce valid feature vectors.
- Extracted features conform to the selected model schema.
- Malformed files are handled safely.
- Feature extraction duration can be measured.
- Files are analyzed without executing them.

## T014 — LightGBM Training and Evaluation

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T012, T013

**Objective:** Train and evaluate a reproducible static malware classifier.

**Scope:**
- Implement the training workflow.
- Apply the documented preprocessing and feature schema.
- Train the selected LightGBM model.
- Evaluate it on the reserved test split.
- Record model metadata and experiment configuration.

**Acceptance criteria:**
- Training can be reproduced using documented instructions.
- Evaluation uses a held-out test set.
- ROC-AUC, precision, recall, F1-score, and false-positive rate are reported where applicable.
- Training configuration and model version are recorded.
- Actual results are reported without substituting target values for measurements.

## T015 — ONNX Export and Inference

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T014

**Objective:** Implement inference through a compatible ONNX model.

**Scope:**
- Export the selected trained model when supported.
- Validate ONNX input and output schemas.
- Implement model loading and inference.
- Record inference latency.
- Handle missing, incompatible, or corrupt model artifacts.

**Acceptance criteria:**
- Model input dimensions and feature order are validated.
- Inference returns a documented score and interpretation.
- Unsupported or missing models produce explicit errors.
- Inference timing is measured independently of feature extraction.
- Automated tests cover successful inference and model failures.

## T016 — ML Integration with the Analysis Pipeline

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T011, T013, T015

**Objective:** Integrate static feature extraction and inference into analysis orchestration.

**Scope:**
- Invoke ML analysis when required.
- Merge the ML output with existing evidence.
- Record model version and relevant timings.
- Handle skipped and failed inference stages.
- Persist structured analysis results.

**Acceptance criteria:**
- Eligible PE files enter the ML analysis stage.
- Model outputs are associated with the correct job.
- Failed inference does not become a benign verdict.
- The complete feature-extraction and inference path is tested.
- Detection evidence remains available for scoring and investigation.

---

# 7. Epic E — Endpoint and Behavioral Monitoring

## T017 — Filesystem Sensor

**Priority:** P0  
**Status:** BACKLOG  
**Dependencies:** T010

**Objective:** Implement filesystem event monitoring for configured Windows directories.

**Scope:**
- Configure monitored directories.
- Observe supported file events.
- Normalize events to the shared schema.
- Handle repeated, incomplete, renamed, or inaccessible files.
- Submit events to the analysis orchestrator.

**Acceptance criteria:**
- A harmless test file generates a normalized event.
- Supported event types are mapped correctly.
- Monitoring errors are visible.
- Duplicate events are managed appropriately.
- The sensor does not claim universal execution interception or prevention.

## T018 — Process Metadata and Behavioral Monitor

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T017

**Objective:** Implement basic supported process and behavioral monitoring.

**Scope:**
- Collect available process metadata.
- Record parent-child relationships when available.
- Implement configurable suspicious process-relationship rules.
- Monitor supported file modification patterns.
- Normalize behavioral findings as detection evidence.

**Acceptance criteria:**
- Test process relationships generate the expected results.
- Missing process metadata is represented accurately.
- Behavioral findings include supporting observations.
- Routine test activity does not automatically become a malicious verdict.
- Monitoring remains within documented operating-system capabilities.

## T019 — Canary Monitoring and Safe Simulations

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T018

**Objective:** Implement canary-file monitoring and harmless behavioral demonstrations.

**Scope:**
- Create decoy files in a dedicated test location.
- Monitor their supported modification events.
- Produce high-priority behavioral evidence when a canary rule is triggered.
- Create harmless simulation fixtures.
- Add tests for expected and unexpected events.

**Acceptance criteria:**
- A designated canary modification produces the configured alert.
- Test artifacts and monitoring paths are clearly isolated.
- No live malware is required.
- Canary evidence is associated with the relevant incident or event.
- Destructive response actions remain disabled unless separately authorized.

---

# 8. Epic F — Risk Scoring and Response

## T020 — Composite Risk Scoring Engine

**Priority:** P0  
**Status:** BACKLOG  
**Dependencies:** T011, T016

**Objective:** Implement the risk score and verdict policy defined in `prd.md`.

**Scope:**
- Implement input normalization.
- Apply configurable scoring weights and thresholds.
- Implement the composite score.
- Handle missing or unavailable evidence explicitly.
- Support documented high-confidence policy overrides.
- Return score contributions and explanation metadata.

**Acceptance criteria:**
- Scores remain between 0 and 100.
- Identical inputs and configuration produce deterministic results.
- All verdict boundaries are tested.
- Evidence contributions are preserved.
- Missing evidence is not silently converted into benign evidence.
- Thresholds and weights are configurable.

## T021 — Controlled Quarantine and Restoration

**Priority:** P0  
**Status:** BACKLOG  
**Dependencies:** T006, T020

**Objective:** Implement secure quarantine and recovery for designated test artifacts.

**Scope:**
- Implement alert-only and dry-run modes.
- Define response authorization boundaries.
- Implement protected quarantine storage.
- Encrypt quarantined contents using authenticated encryption.
- Store recovery metadata and required key references.
- Implement integrity-checked restoration.
- Record response outcomes and errors.

**Acceptance criteria:**
- Dry-run behavior is distinguishable from actual enforcement.
- Quarantine works on designated disposable test files.
- Restored file contents match the original SHA-256.
- Encryption keys are not stored as unprotected plaintext.
- Invalid paths and unauthorized operations are rejected.
- Interrupted operations are recoverable or explicitly marked as unresolved.
- Automatic destructive response is not enabled by default.

---

# 9. Epic G — API and Dashboard Integration

## T022 — Incident and Evidence API

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T006, T007, T011, T020

**Objective:** Implement the documented incident and evidence retrieval contracts.

**Scope:**
- Implement incident listing and filtering.
- Implement incident-detail retrieval.
- Implement evidence retrieval.
- Implement analysis-job status endpoints.
- Implement incident status updates.
- Add pagination and validation.

**Acceptance criteria:**
- Responses conform to `api_spec.md`.
- Data comes from persisted records.
- Invalid filters and unknown resources return documented errors.
- Pagination is deterministic.
- API tests cover success and failure cases.

## T023 — Response, Quarantine, and Forensic APIs

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T021, T022

**Objective:** Expose documented response and quarantine operations safely.

**Scope:**
- Implement response-action history.
- Implement quarantine record listing and details.
- Implement authorized quarantine requests.
- Implement authorized restoration requests.
- Implement forensic-report endpoints when the reporting service is available.
- Apply API authorization and validation.

**Acceptance criteria:**
- Security-sensitive actions are protected.
- Request acceptance is distinct from execution success.
- Quarantine and restoration states reflect actual outcomes.
- Unauthorized requests are rejected.
- API contracts match `api_spec.md`.

## T024 — WebSocket Event Delivery

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T007, T022

**Objective:** Implement real-time event delivery to the dashboard.

**Scope:**
- Implement the documented WebSocket endpoint.
- Define event envelopes.
- Publish relevant persisted incident and response updates.
- Handle client disconnections and connection errors.
- Establish frontend reconnection requirements.

**Acceptance criteria:**
- The WebSocket accepts valid development connections.
- Published events follow the documented envelope.
- Events reflect actual application activity.
- Sensitive information is not broadcast.
- REST remains the source of truth after reconnecting.
- Event delivery limitations are documented.

## T025 — SOC Dashboard Overview and Incident Investigation

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T003, T004, T022

**Objective:** Implement the core security operations dashboard.

**Scope:**
- Create dashboard navigation and layout.
- Display incident statistics from actual API data.
- Build the incident list and filters.
- Build incident details and detection evidence views.
- Display verdicts, scores, timestamps, and processing information.
- Handle loading, empty, and error states.

**Acceptance criteria:**
- The dashboard retrieves persisted backend data.
- Incident details show their associated evidence.
- Statistics are not hardcoded as real activity.
- API errors are shown clearly.
- The interface is responsive.
- The frontend production build succeeds.

## T026 — Dashboard Live Updates and Quarantine Management

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T021, T023, T024, T025

**Objective:** Complete real-time updates and controlled response interfaces.

**Scope:**
- Connect the dashboard to the WebSocket endpoint.
- Implement safe reconnection behavior.
- Refresh current state after reconnecting.
- Display response-action history.
- Build quarantine-management views.
- Provide authorized quarantine and restoration workflows.

**Acceptance criteria:**
- New persisted incidents appear through live updates.
- Reconnection does not leave the dashboard permanently stale.
- Response statuses reflect backend results.
- Dry-run actions are clearly labeled.
- Unauthorized actions are not enabled in the UI.
- The interface handles backend unavailability.

---

# 10. Epic H — AI, Integration, and Evaluation

## T027 — AI Forensic Reporting Service

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T022

**Objective:** Generate evidence-based explanations for security incidents.

**Scope:**
- Define the report input and output schemas.
- Integrate the supported AI provider or Antigravity MCP interface.
- Generate incident summaries and recommendations.
- Preserve evidence references.
- Handle provider timeouts and invalid output.
- Persist report status and results.

**Acceptance criteria:**
- A test incident can generate a report when the provider is available.
- Reports distinguish observed facts from interpretations.
- Report failures are visible.
- AI output cannot directly execute system commands or destructive actions.
- Core detection and incident persistence continue when AI is unavailable.

## T028 — Forensic Reports in the Dashboard

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T023, T025, T027

**Objective:** Display incident explanations in the SOC dashboard.

**Scope:**
- Add report summaries and detailed views.
- Display report-generation status.
- Display evidence references and recommendations.
- Support authorized report-generation requests.
- Handle unavailable providers and failed report generation.

**Acceptance criteria:**
- Reports are displayed from actual backend responses.
- Pending, failed, completed, and unavailable states are distinct.
- Unsupported AI claims are not presented as verified facts.
- Report generation does not block incident investigation.
- Frontend tests cover normal and error states.

## T029 — End-to-End Integration and Security Hardening

**Priority:** P0  
**Status:** BACKLOG  
**Dependencies:** T016, T019, T020, T021, T023, T024, T026

**Objective:** Verify complete system workflows and address integration defects.

**Scope:**
- Test event-to-analysis processing.
- Test signature and ML integration.
- Test behavioral evidence and scoring.
- Test incident persistence and live delivery.
- Test response authorization and quarantine recovery.
- Review input validation, secret handling, and path safety.
- Run regression tests.
- Correct confirmed defects.

**Acceptance criteria:**
- Core workflows operate end to end using safe test fixtures.
- No failed analysis is silently recorded as benign.
- Incidents and evidence persist correctly.
- Response actions report their actual outcomes.
- Quarantine restoration verifies integrity.
- Security-sensitive endpoints enforce their defined restrictions.
- Critical regressions introduced during development are resolved.

## T030 — ML and System Performance Evaluation

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T014, T015, T016, T029

**Objective:** Produce reproducible ML and system performance measurements.

**Scope:**
- Evaluate the held-out ML test split.
- Calculate classification metrics.
- Benchmark feature extraction and model inference.
- Measure end-to-end analysis duration.
- Measure representative file sizes.
- Record environment and benchmark settings.
- Identify bottlenecks and document limitations.

**Acceptance criteria:**
- ROC-AUC, precision, recall, F1-score, and false-positive rate are reported where applicable.
- Feature extraction, inference, queue delay, and end-to-end duration are measured separately.
- Benchmark conditions are documented.
- Results are reproducible.
- Performance goals are distinguished from achieved measurements.
- No unsupported accuracy or latency claims remain in project documentation.

## T031 — Final Documentation and Demonstration Readiness

**Priority:** P1  
**Status:** BACKLOG  
**Dependencies:** T029, T030

**Objective:** Prepare a reproducible final demonstration and verify that documentation matches the implementation.

**Scope:**
- Review installation and configuration instructions.
- Update the README with actual capabilities.
- Document known limitations.
- Prepare a demonstration using safe test artifacts.
- Verify the end-to-end workflow.
- Document evaluation results.
- Record remaining non-critical issues.

**Acceptance criteria:**
- The application can be installed and launched using documented instructions.
- The demo uses safe test artifacts and clearly labeled simulations.
- Documentation accurately represents implemented functionality.
- Evaluation results match actual test outputs.
- Known limitations are disclosed.
- No feature is described as complete without verification.

---

# 11. Dependency Overview

The intended major implementation sequence is:

```text
T001
 ├── T002 ── T004 ── T005 ── T006 ── T007
 │                                  │
 │                                  └── T022
 │
 ├── T003 ───────────────────────────── T025
 │
 ├── T008 ── T009 ── T011
 │      │             ▲
 │      └── T010 ─────┘
 │
 ├── T012 ── T013 ── T014 ── T015 ── T016
 │
 └── T017 ── T018 ── T019
                         │
T011 + T016 ── T020 ── T021
                         │
T022 ── T023 ── T024
  │          │      │
  └── T025 ──┴──────┴── T026
       │
T022 ── T027 ── T028
                    │
Core tickets ───────┴── T029 ── T030 ── T031
```

This diagram is a high-level guide. The explicit dependency list in each ticket takes precedence.

## 12. Initial Execution Rules

When beginning implementation:

1. Start with `T001`.
2. Inspect the actual repository before modifying files.
3. Complete the foundation tickets in dependency order.
4. Mark a ticket `DONE` only after verification.
5. Update this backlog as ticket states change.
6. Generate a detailed Antigravity prompt for the selected ticket rather than feeding the entire backlog as an implementation request.
7. Do not start dependent tickets when required interfaces are missing.
8. If a ticket exposes an architectural conflict, document the issue before changing the established design.
9. Do not implement unrequested features simply because they appear in a future ticket.
10. Keep automated tests passing as the codebase grows.

## 13. Current Project State

At the time this backlog is created:

- The project documentation is being established.
- Implementation status has not yet been verified against the repository.
- All tickets begin in `BACKLOG`.
- No ticket may be assumed complete solely because it appears in this document.

After repository inspection, ticket statuses must be updated based on actual evidence.

---

**End of Ticket Backlog**