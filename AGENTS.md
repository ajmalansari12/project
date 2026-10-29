# Sentinel-EDR
## Agent Instructions

These instructions govern all AI-assisted development work performed on Sentinel-EDR using Google Antigravity.

**Project:** Hybrid Real-Time Endpoint Detection and Response System  
**Instruction File:** `AGENTS.md`  
**Scope:** Entire repository

---

## 1. Project Context

Sentinel-EDR is a Windows-focused endpoint security project combining:

- Filesystem event monitoring and endpoint telemetry.
- SHA-256 hashing and YARA-based signature detection.
- PE executable feature extraction.
- LightGBM model training and ONNX Runtime inference.
- Runtime behavioral monitoring and canary-file detection.
- Composite threat scoring and verdict generation.
- Controlled response operations and secure quarantine.
- FastAPI REST endpoints and WebSocket events.
- SQLite persistence through SQLAlchemy.
- A React, TypeScript, Vite, and Tailwind CSS SOC dashboard.
- Optional AI-assisted forensic reporting.

The project is being developed incrementally through explicit implementation tickets.

The objective is to build a working, testable, maintainable system—not merely generate code or create the appearance of completed functionality.

## 2. Mandatory Development Rules

Follow these rules for every ticket.

1. Work only on the ticket explicitly assigned by the user.
2. Inspect the existing codebase before making changes.
3. Read relevant project documents before implementation.
4. Preserve working functionality unless the assigned ticket requires a change.
5. Follow existing architecture, naming conventions, and shared interfaces.
6. Implement only the scope required by the current ticket.
7. Write or update tests for implemented behavior.
8. Execute relevant tests and inspect their results.
9. Report actual implementation progress honestly.
10. Update documentation when an approved change affects existing requirements or interfaces.
11. Never claim that code, tests, or integrations work without verification.
12. Never silently introduce a new framework, major dependency, or architectural pattern.

**Do not implement multiple future tickets merely because their dependencies or specifications are available.**

## 3. Documentation Hierarchy

Before starting work, consult the documents relevant to the assigned ticket.

| Document | Purpose |
|---|---|
| `prd.md` | Defines product requirements and scope |
| `trd.md` | Defines technologies, implementation constraints, and technical requirements |
| `implementation_plan.md` | Defines implementation phases and their dependencies |
| `architecture.md` | Defines component responsibilities and system boundaries |
| `database_schema.md` | Defines database entities, relationships, and constraints |
| `api_spec.md` | Defines REST and WebSocket contracts |
| `ticket_backlog.md` | Defines tickets, dependencies, and completion criteria |
| `testing_plan.md` | Defines verification and evaluation requirements |
| `AGENTS.md` | Defines mandatory development and agent behavior |

Use `README.md` and other existing documentation for setup details and additional context.

If requirements conflict, do not silently invent a resolution. Identify the conflict, explain the impact, and propose the smallest reasonable change before modifying the established contract.

An explicitly approved change takes precedence over the superseded requirement and must be documented.

## 4. Ticket Execution Workflow

For each assigned ticket, follow this sequence.

### Step 1 — Understand

Read the complete ticket and identify:

- Its objective and scope.
- Dependencies and prerequisite tickets.
- Relevant architectural requirements.
- Required source files or interfaces.
- Acceptance criteria.
- Required tests.
- Explicitly excluded work.

### Step 2 — Inspect

Inspect the actual repository.

Determine:

- Which required components already exist.
- Which components are incomplete or missing.
- Which tests are available.
- Which commands are configured for development and testing.
- Whether the change could break an existing interface.

Do not recreate working files or implementations unnecessarily.

### Step 3 — Plan

Identify the smallest implementation that satisfies the acceptance criteria.

Reuse existing services, schemas, utilities, and dependencies where appropriate.

Do not expand the scope into unrelated refactoring or future-ticket functionality.

### Step 4 — Implement

Implement the assigned ticket while preserving the established architecture.

Separate responsibilities appropriately, including:

- API routes.
- Business logic.
- Database access.
- Detection algorithms.
- Risk scoring.
- Response operations.
- Frontend presentation.

Do not introduce unnecessary abstractions or duplicate implementations.

### Step 5 — Test

Write or update tests relevant to the ticket.

Run the actual configured test commands and inspect failures. Fix defects introduced by the changes before declaring the ticket complete.

Do not suppress test failures, weaken assertions, or remove tests merely to obtain a passing result.

### Step 6 — Review

Review the changes for:

- Scope violations.
- Regressions.
- Interface incompatibilities.
- Security problems.
- Unnecessary dependencies.
- Hardcoded paths or secrets.
- Missing error handling.
- Missing or misleading documentation.

### Step 7 — Report

Provide a completion report containing:

1. Ticket ID and title.
2. Summary of the implementation.
3. Important files created or modified.
4. Tests actually executed and their results.
5. Acceptance criteria satisfied or outstanding.
6. Blockers, limitations, or follow-up work.

Update ticket status only when the repository provides sufficient evidence for the change.

A ticket may be marked `DONE` only when its acceptance criteria and required verification are satisfied.

## 5. Coding Standards

### Python

- Use clear, descriptive names.
- Use type hints for functions and important interfaces.
- Prefer small, focused functions.
- Separate business logic from persistence and API handling.
- Handle exceptions explicitly at appropriate boundaries.
- Use structured logging instead of scattered debug prints.
- Avoid global mutable state where practical.
- Centralize configuration instead of scattering constants throughout the code.
- Use pathlib or another appropriate path-handling interface for filesystem operations.
- Keep security-sensitive behavior independently testable.

### TypeScript and React

- Use TypeScript for application code.
- Keep shared frontend types consistent with backend API contracts.
- Use reusable components where they improve maintainability.
- Separate API access from presentation logic.
- Handle loading, empty, error, and disconnected states.
- Avoid unnecessary dependencies and oversized components.
- Do not hardcode real incident statistics or fabricate endpoint telemetry.
- Do not place backend credentials or secret keys in frontend code.

### General

- Follow the repository's existing formatting and naming conventions.
- Add comments when they clarify non-obvious decisions.
- Avoid dead code and unused dependencies.
- Do not create duplicate configuration mechanisms.
- Keep changes focused and reviewable.
- Prefer deterministic behavior and reproducible tests.

## 6. Architecture and Integration Rules

Maintain the separation of responsibilities defined in `architecture.md`.

### Endpoint Sensor

Collect supported filesystem events and endpoint metadata. Do not claim that a directory watcher provides universal process-creation interception or prevents executable launch.

### Signature Engine

Implement hashing, hash-list matching, and signature scanning. Return structured evidence rather than independently implementing the final composite risk decision.

### ML Engine

Keep feature extraction and model inference separate.

Validate the feature schema, feature order, input types, and model outputs. Never execute inspected files to classify them.

### Behavioral Monitor

Collect supported runtime evidence and apply configurable detection rules. Do not treat every individual suspicious observation as definitive malware proof without an explicit policy.

### Risk Scoring Engine

Calculate the documented composite score from normalized inputs. Keep weights, thresholds, and policy overrides configurable.

Do not scatter separate threat-scoring implementations across modules.

### Response Engine

Execute only actions permitted by the response policy. A model prediction must not directly trigger unrestricted destructive operations.

### Database and Backend

Use the documented persistence and API interfaces. Keep business logic independent of database implementation details.

### AI Forensic Reporting

Treat AI output as advisory, untrusted content. It must not independently execute system commands, authorize destructive operations, or override response policies.

### Frontend

Use documented REST and WebSocket contracts. Persisted backend data is the source of truth for incidents.

## 7. Cybersecurity Safety Requirements

These rules are mandatory throughout development.

1. Use harmless files, synthetic fixtures, mocked data, and controlled behavioral simulations for routine tests.
2. Do not download, execute, or distribute live malware as part of ordinary implementation or automated testing.
3. Do not modify unrelated user files or operating-system files during tests.
4. Do not terminate arbitrary processes.
5. Do not enable destructive actions by default.
6. Do not perform quarantine or restoration on arbitrary files during development.
7. Test actual quarantine and recovery using designated disposable artifacts.
8. Use authenticated encryption for quarantined file contents.
9. Never store encryption keys as unprotected plaintext alongside encrypted objects.
10. Validate source and destination paths on the backend.
11. Restrict security-sensitive operations through explicit authorization and policy checks.
12. Keep secrets out of source control, logs, API responses, and browser code.
13. Use least-privilege execution whenever practical.
14. Do not claim complete endpoint protection, universal malware detection, or execution prevention without implementation evidence.
15. Clearly distinguish simulated events from actual collected telemetry.

The first implementation should favor monitoring, evidence collection, and alert-only response before introducing enforcement.

## 8. Error Handling and Reliability

Every component must handle predictable failures explicitly.

Examples include:

- Inaccessible files.
- Invalid or unsupported executable formats.
- Malformed YARA rules.
- Missing ML models.
- Feature-schema mismatches.
- Database failures.
- Full analysis queues.
- Interrupted response operations.
- Failed integrity checks.
- Unavailable AI providers.
- WebSocket disconnections.
- Invalid API requests.

Do not silently swallow exceptions.

Do not fabricate a successful operation when a component is unavailable.

**A failed or incomplete analysis must never be silently classified as `BENIGN`.**

Represent processing status, security verdict, and response-action status as separate concepts.

When partial analysis is possible, preserve the available evidence and record which components failed, were skipped, or were unavailable.

## 9. Database and API Contract Rules

- Follow `database_schema.md` for data relationships and persistence requirements.
- Follow `api_spec.md` for endpoint paths and public response contracts.
- Use validated request and response models.
- Do not expose SQLAlchemy objects directly as public API responses.
- Enable and test SQLite foreign-key enforcement.
- Use controlled schema migrations.
- Never silently drop or recreate existing data during schema changes.
- Apply consistent pagination and error handling.
- Record security-sensitive actions and their actual outcomes.
- Publish events describing successful persistence only after the relevant operation succeeds.
- Treat WebSocket delivery as transient; persisted REST data remains authoritative.

Changes to shared schemas or public API contracts must include the required tests and documentation updates.

## 10. Machine Learning Rules

- Document the chosen dataset version and feature schema.
- Keep training, validation, and test data appropriately separated.
- Avoid data leakage.
- Validate compatibility between the feature extractor and model artifact.
- Preserve the model version used for inference.
- Record actual performance metrics.
- Measure feature extraction, inference, and end-to-end latency separately.
- Do not hardcode expected model outputs as actual predictions.
- Do not claim that a proposed ROC-AUC or latency target has been achieved without measurements.
- Handle unavailable models and invalid inference outputs explicitly.

A model that loads successfully is not necessarily an accurate or operationally valid malware detector.

## 11. Dependency and Configuration Rules

Before introducing a dependency:

1. Check whether the repository already contains a suitable implementation.
2. Verify that the dependency is compatible with the existing environment.
3. Confirm that it is required by the assigned ticket.
4. Prefer the smallest appropriate dependency set.
5. Update the relevant dependency manifest.
6. Add tests for the new functionality.
7. Document relevant setup changes.

Do not introduce Redis, PostgreSQL, container orchestration, kernel drivers, or additional infrastructure unless an approved ticket requires them.

Never hardcode API credentials, encryption keys, user-specific absolute paths, or production secrets.

Use `.env.example` for documented non-secret configuration placeholders.

## 12. Testing and Verification Rules

Follow `testing_plan.md`.

For every ticket:

- Add or update relevant unit tests.
- Add integration tests when component interactions change.
- Add security tests when trust boundaries or response operations change.
- Run relevant regression tests.
- Run the configured frontend type checks and build when frontend code changes.
- Inspect the actual output rather than relying solely on an exit-status summary.
- Disclose tests that could not be executed.

Never:

- Claim tests passed without running them.
- Disable failing tests to conceal a defect.
- Remove validation merely to make tests pass.
- Treat mocked integration behavior as proof that a real external integration works.
- Treat a successful application startup as proof that all components work.

If the environment prevents verification, report the blocker and keep the ticket in an appropriate non-complete state.

## 13. Scope Control

When implementing a ticket, do not:

- Implement future tickets without authorization.
- Perform unrelated repository-wide refactoring.
- Replace an existing architecture without approval.
- Add placeholder features that appear operational but do not work.
- Populate dashboards with fabricated real-world statistics.
- invent detection results.
- Add unnecessary frameworks or alternative implementations.
- Change public interfaces without updating their contracts.
- Mark future capabilities as implemented merely because code scaffolding exists.

If a prerequisite is missing, identify the dependency and explain the smallest required next step.

If an unavoidable design change is discovered, document the issue and request or follow the applicable approval process before proceeding beyond the assigned scope.

## 14. Documentation Maintenance

Update documentation when a ticket changes:

- Product requirements.
- Architecture or component boundaries.
- Database models or relationships.
- API request or response contracts.
- Configuration options.
- Dependencies or installation instructions.
- Security restrictions.
- Testing requirements.
- Measured performance or ML evaluation results.

Do not rewrite unrelated documents unnecessarily.

Keep `ticket_backlog.md` aligned with actual ticket progress.

Record approved technical decisions in the appropriate project documentation.

## 15. Definition of Done

A ticket is complete only when all applicable conditions are satisfied:

- Its scope is implemented.
- Its acceptance criteria are verified.
- Relevant tests pass.
- Existing behavior has not suffered an unresolved critical regression.
- Security requirements are satisfied.
- Required interfaces are compatible.
- Documentation is updated where necessary.
- Remaining limitations are disclosed.
- The completion report accurately describes the work.

A generated file, scaffold, mock, or placeholder is not equivalent to a completed feature.

## 16. Final Instruction

**Always work on the single ticket assigned by the user.**

Read the requirements, inspect the existing repository, make the smallest complete implementation, test it, review it, and report the actual result.

Preserve existing functionality, respect security boundaries, and do not fabricate implementation progress or test evidence.

When a ticket is verified, report its result so that the user can decide whether to proceed to the next ticket.

---

**End of AGENTS.md**