# Sentinel-EDR
## Implementation Plan

**Project:** Sentinel-EDR — Hybrid Real-Time Endpoint Detection and Response System  
**Document Version:** 1.0  
**Status:** Initial Draft  
**Related Documents:** `prd.md`, `trd.md`

---

## 1. Purpose

This document defines the implementation sequence for Sentinel-EDR.

The system will be developed incrementally using Google Antigravity. Work will be organized into small implementation tickets, with each ticket defining a specific objective, scope, dependencies, and acceptance criteria.

The implementation must prioritize a working, testable foundation before introducing advanced detection, automated response, or AI integration.

Antigravity must follow this plan unless a documented technical issue requires an approved change.

## 2. Implementation Principles

1. Implement one ticket at a time.
2. Inspect the existing codebase before making changes.
3. Read the relevant project documents before starting a ticket.
4. Verify dependencies before implementing a feature.
5. Avoid implementing features outside the current ticket's scope.
6. Write tests alongside implementation.
7. Run relevant tests before reporting completion.
8. Do not replace working implementations without justification.
9. Update documentation when an approved architectural or interface change is made.
10. Never claim that a feature or test is complete without verification.
11. Use harmless test artifacts and simulated behavior during development.
12. Keep monitoring, detection, scoring, and response execution as separate responsibilities.

## 3. Overall Implementation Strategy

Development will follow this sequence:

**Project foundation → Shared contracts → Backend foundation → Database → Signature detection → ML engine → Behavioral monitoring → Risk scoring → Response and quarantine → API integration → Dashboard → AI reporting → System testing and evaluation.**

Each phase depends on the successful completion of the preceding requirements.

A later phase may be developed in parallel only when its required interfaces have been defined and its dependencies are stable.

---

## 4. Phase 0 — Project Inspection and Environment Setup

### Objective

Establish the development environment and confirm that the project can be developed and tested locally.

### Tasks

- Inspect the existing repository and project documents.
- Confirm the operating system and installed development tools.
- Set up the Python virtual environment.
- Set up the React, TypeScript, Vite, and Tailwind CSS environment.
- Create the initial source directory structure.
- Establish `.gitignore` and `.env.example`.
- Add dependency manifests and development commands.
- Configure basic logging and test execution.
- Document setup instructions.

### Deliverables

- Working backend environment.
- Working frontend environment.
- Initial repository structure.
- Basic test infrastructure.
- Reproducible development setup.

### Exit Criteria

- The backend starts successfully.
- The frontend starts successfully.
- Python and frontend tests can execute.
- No secrets are committed.
- Setup instructions are documented.

---

## 5. Phase 1 — Application Foundation and Shared Contracts

### Objective

Establish the shared interfaces that allow modules to be developed independently.

### Tasks

- Define shared event types.
- Define analysis job states.
- Define threat verdicts and incident statuses.
- Define common identifiers and timestamp conventions.
- Define structured detection evidence.
- Define normalized error representations.
- Implement configuration loading and validation.
- Establish structured logging.
- Define service interfaces for detection, scoring, persistence, and response.
- Add unit tests for shared contracts and configuration.

### Deliverables

- Shared event schema.
- Shared enums and data models.
- Configuration foundation.
- Logging foundation.
- Tested component interfaces.

### Exit Criteria

- Data contracts are documented and validated.
- Invalid configuration produces a clear error.
- Common types are not unnecessarily duplicated across modules.
- Tests cover shared schemas and validation.

---

## 6. Phase 2 — Backend Foundation and Incident Database

### Objective

Build the backend application skeleton and establish persistent incident storage.

### Tasks

- Create the FastAPI application.
- Implement startup and shutdown lifecycle management.
- Add health and service-status endpoints.
- Configure SQLAlchemy with SQLite.
- Define the initial database models.
- Implement database initialization and schema-version management.
- Add incident and detection-evidence storage.
- Add incident retrieval and pagination.
- Add initial API request and response models.
- Implement database error handling.
- Add backend unit and integration tests.

### Deliverables

- Running FastAPI application.
- SQLite database.
- Initial persistence layer.
- Incident storage services.
- Tested health and incident endpoints.

### Exit Criteria

- The application starts without errors.
- Database records persist across restarts.
- Incidents can be created and retrieved.
- Invalid requests return appropriate errors.
- Database operations are separated from route handlers.

---

## 7. Phase 3 — Signature Detection Engine

### Objective

Implement the first working detection component using hashes and signature rules.

### Tasks

- Implement chunked SHA-256 hashing.
- Create a configurable local hash allowlist and blocklist.
- Define the precedence of hash matches and other detection evidence.
- Integrate YARA-compatible signature scanning.
- Implement rule loading and validation.
- Normalize hash and YARA results into shared detection evidence.
- Record matching rule identifiers and severity.
- Add analysis-result caching where appropriate.
- Handle malformed files, inaccessible files, and unavailable rulesets.
- Add unit and integration tests using harmless fixtures.

### Deliverables

- SHA-256 service.
- Hash-list matching service.
- YARA scanning service.
- Structured signature evidence.
- Tested signature pipeline.

### Exit Criteria

- Known test hashes produce the expected results.
- YARA test rules produce the expected matches.
- Signature evidence includes the relevant identifiers.
- Failed scans are not reported as benign.
- Tests do not require live malware.

---

## 8. Phase 4 — Static Feature Extraction and Machine Learning

### Objective

Build a reproducible static executable classification pipeline.

### Tasks

- Select and document the EMBER dataset version and feature schema.
- Implement PE file validation.
- Implement static feature extraction using LIEF where appropriate.
- Calculate section entropy