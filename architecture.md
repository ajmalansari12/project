# Sentinel-EDR
## System Architecture Document

**Project:** Sentinel-EDR — Hybrid Real-Time Endpoint Detection and Response System  
**Document Version:** 1.0  
**Status:** Initial Draft  
**Related Documents:** `prd.md`, `trd.md`, `implementation_plan.md`

---

## 1. Purpose

This document defines the architecture of Sentinel-EDR, including its main components, responsibilities, communication paths, data flow, and architectural constraints.

It serves as the architectural reference for Google Antigravity during ticket-based development.

All implementation tickets must follow the boundaries defined in this document. Changes to the architecture must be justified, tested, and reflected in the relevant documentation.

## 2. Architectural Overview

Sentinel-EDR will use a modular, event-driven architecture.

The initial version will run locally on Windows and consist of a Python-based endpoint and detection system, a FastAPI backend, an SQLite database, and a React-based SOC dashboard.

Detection, risk scoring, response execution, and AI reporting will remain separate responsibilities.

The architecture will support incremental implementation, allowing each component to be tested independently before full integration.

### 2.1 Architectural Components

The system consists of the following components:

1. Endpoint Sensor
2. Analysis Queue and Orchestrator
3. Signature Detection Engine
4. Static Feature Extraction and ML Engine
5. Behavioral Monitoring Engine
6. Risk Scoring Engine
7. Response and Quarantine Engine
8. Incident Storage
9. FastAPI Backend
10. AI Forensic Reporting Service
11. React SOC Dashboard

## 3. High-Level Architecture Diagram

```text
┌───────────────────────────────────────────────┐
│                WINDOWS ENDPOINT               │
│                                               │
│  ┌───────────────────┐  ┌──────────────────┐  │
│  │ Endpoint Sensor   │  │ Behavioral       │  │
│  │                   │  │ Monitor          │  │
│  │ File Events       │  │ Process Metadata │  │
│  │ Directory Watch   │  │ Canary Events    │  │
│  └─────────┬─────────┘  └────────┬─────────┘  │
│            │                     │            │
│            └──────────┬──────────┘            │
│                       ▼                       │
│             ┌──────────────────┐              │
│             │ Analysis Queue   │              │
│             │ & Orchestrator   │              │
│             └─────────┬────────┘              │
│                       ▼                       │
│  ┌─────────────────────────────────────────┐  │
│  │             DETECTION LAYER             │  │
│  │                                         │  │
│  │  SHA-256 │ Hash Lists │ YARA             │  │
│  │  PE Feature Extraction │ ONNX Inference  │  │
│  │  Behavioral Evidence                    │  │
│  └────────────────────┬────────────────────┘  │
│                       ▼                       │
│             ┌──────────────────┐              │
│             │ Risk Scoring     │              │
│             │ Engine           │              │
│             └─────────┬────────┘              │
│                       ▼                       │
│             ┌──────────────────┐              │
│             │ Response Engine  │              │
│             │ Alerts/Quarantine│              │
│             └──────────────────┘              │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│                  BACKEND LAYER                │
│                                               │
│  ┌─────────────────┐   ┌──────────────────┐  │
│  │ FastAPI REST API│   │ WebSocket Events │  │
│  └────────┬────────┘   └────────┬─────────┘  │
│           │                     │            │
│           ▼                     │            │
│  ┌─────────────────┐            │            │
│  │ Incident Service│            │            │
│  └────────┬────────┘            │            │
│           ▼                     │            │
│  ┌─────────────────┐            │            │
│  │ SQLite Database │◄───────────┘            │
│  └─────────────────┘                         │
│                                               │
│  ┌─────────────────────────────────────────┐  │
│  │ AI Forensic Reporting Service           │  │
│  │ Evidence → Explanation → Recommendations│  │
│  └─────────────────────────────────────────┘  │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│                  FRONTEND LAYER               │
│                                               │
│  React + TypeScript + Vite + Tailwind CSS     │
│                                               │
│  Overview │ Alerts │ Incidents │ Quarantine   │
│                 Forensic Reports              │
└───────────────────────────────────────────────┘
```

**Diagram note:** This is a logical architecture. It does not require every component to run as a separate operating-system process. The initial implementation should favor a simple local deployment with well-defined internal interfaces.

## 4. Component Responsibilities and Boundaries

### 4.1 Endpoint Sensor

**Responsibility:** Observe filesystem events and collect available endpoint metadata.

Responsibilities include:

- Monitoring configured directories.
- Normalizing file events.
- Identifying files eligible for analysis.
- Collecting available process information.
- Submitting events to the orchestrator.
- Logging monitoring errors.

The sensor must not implement its own separate threat-scoring algorithm or duplicate signature-scanning logic.

A directory watcher must not be represented as a mechanism that prevents executable launch.

### 4.2 Analysis Queue and Orchestrator

**Responsibility:** Coordinate the analysis lifecycle.

Responsibilities include:

- Accepting normalized events.
- Creating analysis jobs.
- Managing job status.
- Avoiding unnecessary duplicate analysis.
- Scheduling detection components.
- Collecting detection results.
- Recording processing failures and duration.

The orchestrator coordinates services but must not contain the implementation details of the signature engine, ML model, or quarantine system.

### 4.3 Signature Detection Engine

**Responsibility:** Identify matches against known hashes and configured signature rules.

Responsibilities include:

- SHA-256 calculation.
- Hash allowlist and blocklist lookups.
- YARA rule evaluation.
- Match severity interpretation.
- Structured evidence generation.

The component returns evidence and detection status. The risk scoring engine determines the final composite score.

### 4.4 Static ML Engine

**Responsibility:** Extract executable features and classify supported PE files.

Responsibilities include:

- File-format validation.
- PE feature extraction.
- Section entropy calculation.
- Model loading and ONNX inference.
- Model-input validation.
- Inference timing and error reporting.

The ML engine must not execute inspected files. It must not terminate processes, quarantine files, or independently authorize response actions.

### 4.5 Behavioral Monitoring Engine

**Responsibility:** Identify suspicious runtime observations.

Responsibilities include:

- Supported process metadata collection.
- Parent-child relationship analysis.
- Configurable behavioral rules.
- Canary-file event detection.
- File activity monitoring.
- Behavioral evidence generation.

The behavioral monitor must not automatically equate every suspicious observation with a confirmed malware infection.

### 4.6 Risk Scoring Engine

**Responsibility:** Convert available detection evidence into a composite score and verdict.

Responsibilities include:

- Normalizing scoring inputs.
- Applying configurable weights.
- Applying verdict thresholds.
- Handling high-confidence detection policies.
- Producing score contributions and explanations.

It must remain deterministic for identical inputs and configuration.

### 4.7 Response and Quarantine Engine

**Responsibility:** Execute authorized responses to security incidents.

Responsibilities include:

- Alert-only and dry-run modes.
- Response policy evaluation.
- Controlled quarantine.
- Authenticated encryption.
- Integrity verification.
- File restoration.
- Response auditing.

The response engine must not be invoked directly by the ML model or AI agent. It must receive an authorized action request through the documented response interface.

### 4.8 Incident Service and Database

**Responsibility:** Persist incidents, evidence, processing states, and response history.

Responsibilities include:

- Creating and updating incident records.
- Persisting structured detection evidence.
- Recording response actions.
- Retrieving incidents for the API.
- Handling database failures.

SQLite is the initial persistence technology. The service must isolate database access from detection logic and frontend concerns.

### 4.9 FastAPI Backend

**Responsibility:** Expose validated interfaces to the frontend and authorized application clients.

Responsibilities include:

- REST endpoints.
- Request and response validation.
- Incident retrieval.
- Service-status endpoints.
- Authorized quarantine-management requests.
- WebSocket event publication.

The API must not duplicate detection algorithms or directly manipulate database files outside the persistence layer.

### 4.10 AI Forensic Reporting Service

**Responsibility:** Explain a detection using the evidence collected by Sentinel-EDR.

Responsibilities include:

- Accepting structured incident evidence.
- Generating a human-readable explanation.
- Describing observed indicators.
- Suggesting investigation and remediation actions.
- Reporting provider failures.

AI output is advisory. It must never independently execute commands, authorize process termination, or initiate destructive file operations.

### 4.11 React SOC Dashboard

**Responsibility:** Display incidents, alerts, telemetry, response history, and forensic explanations.

Responsibilities include:

- Retrieving information through documented APIs.
- Displaying verdicts and supporting evidence.
- Showing live event updates.
- Managing loading and error states.
- Initiating authorized user actions through the API.

The frontend must not directly access the SQLite database, invoke Python internals, or contain secrets.

## 5. Core Data Flow

### 5.1 File Analysis Flow

The file-analysis workflow must follow this sequence:

1. The endpoint sensor observes a relevant filesystem event.
2. The sensor normalizes the event.
3. The orchestrator validates the event and creates an analysis job.
4. The signature engine calculates the SHA-256 hash.
5. The signature engine evaluates applicable hash lists and YARA rules.
6. If further analysis is required, the orchestrator invokes static feature extraction and ML inference.
7. Available behavioral evidence is associated with the relevant event or incident.
8. The risk scoring engine evaluates the collected evidence.
9. The incident service stores the result.
10. The response engine applies the configured response policy.
11. The backend publishes relevant updates.
12. The dashboard displays the incident.
13. The AI reporting service may generate an asynchronous forensic explanation.

The orchestrator must record which analysis stages completed, were skipped, were unavailable, or failed.

### 5.2 Detection Pipeline Flow

```text
File Event
    |
    v
Validate File and Event
    |
    v
Calculate SHA-256
    |
    v
Check Hash Lists
    |
    v
Evaluate YARA Rules
    |
    v
Additional Analysis Required?
    |
    +---- Yes ---> Extract PE Features
    |                    |
    |                    v
    |               ONNX Inference
    |                    |
    +--------------------+
                         |
                         v
                Collect Available
                Behavioral Evidence
                         |
                         v
                  Calculate Score
                         |
                         v
                  Assign Verdict
                         |
                         v
                Persist Incident
                         |
                         v
                Apply Response Policy
```

A definitive signature result may short-circuit unnecessary analysis only when the applicable policy permits it. The system must still preserve high-priority behavioral evidence and enforce any explicit override rules.

### 5.3 Incident Reporting Flow

```text
Detection Evidence
        |
        v
Incident Service
        |
        +------> SQLite Persistence
        |
        +------> WebSocket Event
        |              |
        |              v
        |         SOC Dashboard
        |
        +------> AI Reporting Service
                       |
                       v
               Forensic Explanation
                       |
                       v
               Incident Detail View
```

AI report generation must not block the primary detection and incident-persistence workflow.

## 6. Detection and Response Separation

Sentinel-EDR must keep these four operations distinct:

**Detection:** Collect facts and identify suspicious indicators.

**Scoring:** Combine evidence into a normalized risk score and verdict.

**Response:** Apply the configured policy to decide whether to alert, isolate, or take another authorized action.

**Explanation:** Summarize evidence and provide recommendations.

This separation prevents a classification result or generated explanation from automatically becoming a destructive operating-system action.

The ML probability is one input into the composite risk score, not a complete security decision by itself.

## 7. Shared Data Contracts

All internal modules must use documented, consistent data contracts.

### 7.1 Endpoint Event

A normalized endpoint event should include fields equivalent to:

```json
{
  "event_id": "unique-event-id",
  "event_type": "file_created",
  "timestamp": "UTC ISO-8601 timestamp",
  "source_component": "endpoint-sensor",
  "file_path": "monitored-file-path",
  "process_id": null,
  "parent_process_id": null,
  "metadata": {}
}
```

Field values are illustrative. An unavailable process identifier must be represented as unavailable rather than invented.

### 7.2 Detection Evidence

```json
{
  "evidence_id": "unique-evidence-id",
  "incident_id": "incident-id",
  "source": "signature-engine",
  "indicator": "sha256_match",
  "severity": "high",
  "description": "Configured blocklist match",
  "details": {},
  "timestamp": "UTC ISO-8601 timestamp"
}
```

Evidence must distinguish observed values from calculated or inferred values.

### 7.3 Analysis Result

```json
{
  "job_id": "unique-job-id",
  "analysis_status": "completed",
  "verdict": "suspicious",
  "risk_score": 52.5,
  "modules_executed": [
    "signature-engine",
    "ml-engine"
  ],
  "modules_skipped": [],
  "modules_failed": [],
  "evidence_ids": []
}
```

The sample demonstrates the structure only. Actual verdict values and processing states must use the shared types defined by the project.

Processing status and security verdict must remain separate fields.

The canonical shared models must be implemented and maintained in the location designated by `trd.md` and `api_spec.md`.

## 8. Database Boundary

All persistent application data must be accessed through the incident and persistence services.

The database will initially store the following logical entities:

- Security incidents.
- Detection evidence.
- Analysis jobs.
- Response actions.
- Quarantine metadata.
- AI forensic reports.
- Relevant audit records.

The final table structure, keys, relationships, and constraints will be defined in `database_schema.md`.

File contents must not be embedded in incident records by default. Quarantined file storage must remain separate from ordinary incident metadata.

## 9. API and Frontend Boundary

The frontend and backend must communicate through documented HTTP and WebSocket interfaces.

The frontend may request:

- Health and service status.
- Incident listings and details.
- Supported telemetry and statistics.
- Quarantine metadata.
- Authorized quarantine and restoration actions.
- Forensic reports.

The frontend must not:

- Read or modify database files directly.
- Import backend implementation modules.
- Perform security decisions independently.
- Assume that a requested response action succeeded before the backend confirms the result.
- Treat WebSocket events as the only durable record of incidents.

After reconnection, the frontend must be able to retrieve current persisted state through the REST API.

## 10. Error Handling and Partial Availability

Each component must report failures through a consistent error representation.

Examples include:

- File inaccessible.
- File format unsupported.
- YARA rules unavailable.
- ML model unavailable.
- Feature extraction failed.
- Database operation failed.
- WebSocket disconnected.
- AI provider unavailable.
- Quarantine operation failed.

These states must not be silently translated into a benign security verdict.

Where appropriate, a partial analysis result may be retained alongside the failed component's status. The final policy must clearly identify whether the verdict is complete or based on incomplete evidence.

The application should continue to provide core detection, incident storage, and alerting when the optional AI reporting service is unavailable.

## 11. Security Boundaries

The architecture must enforce the following restrictions:

1. The ML engine cannot independently perform destructive actions.
2. The AI service cannot execute arbitrary system commands.
3. The dashboard cannot bypass backend authorization.
4. The API cannot expose unrestricted file paths or file operations.
5. Quarantine storage must be protected from unauthorized access.
6. Encryption keys must not be stored as unprotected plaintext beside encrypted files.
7. Components must not require administrator privileges unless a documented capability genuinely needs them.
8. External model outputs, threat-intelligence data, and AI-generated content must be validated.
9. Response actions must produce audit records.
10. Destructive actions must remain disabled or simulated until explicitly implemented, tested, and authorized.

The initial local application should bind to localhost by default.

## 12. Deployment Architecture

### 12.1 Initial Development Deployment

The initial system will use a local development deployment:

- Python environment for backend and detection services.
- SQLite database stored locally.
- React/Vite development server for the dashboard.
- Local configuration for monitored directories, models, rules, and quarantine storage.

The project does not require Redis, PostgreSQL, Kubernetes, or a distributed service deployment for its first working version.

### 12.2 Process Boundaries

Components may be packaged into separate modules while running within a shared application process during early development.

A separate endpoint service, backend process, or other OS-level process may be introduced when required by permissions, lifecycle, reliability, or platform constraints.

Such separation must be accompanied by documented communication contracts and appropriate integration tests.

### 12.3 Future Deployment

Multi-endpoint management, remote deployment, privileged sensor services, and additional operating system support are future architectural extensions. They must not be treated as existing capabilities.

## 13. Architectural Decisions

The following decisions apply to the initial version.

| ID | Decision | Reason |
|---|---|---|
| ADR-001 | Use a modular architecture | Allows independent implementation and testing |
| ADR-002 | Start with Windows PE analysis | Keeps the initial scope manageable |
| ADR-003 | Use SQLite initially | Simplifies local development and persistence |
| ADR-004 | Use FastAPI for backend interfaces | Provides typed API contracts and WebSocket support |
| ADR-005 | Use React and TypeScript for the dashboard | Separates UI development from detection logic |
| ADR-006 | Keep scoring independent from response | Prevents model output from directly authorizing destructive actions |
| ADR-007 | Keep AI reporting asynchronous and optional | Preserves core detection when AI services are unavailable |
| ADR-008 | Introduce response actions incrementally | Enables safe testing and recovery before enforcement |
| ADR-009 | Use documented shared data contracts | Reduces integration failures between Antigravity-generated modules |
| ADR-010 | Validate the ML feature schema explicitly | Prevents incorrect inference caused by incompatible model inputs |

Changes to these decisions must be documented and approved before implementation deviates from them.

## 14. Architectural Rules for Antigravity

During ticket implementation, Antigravity must:

1. Read this document and relevant ticket requirements before making changes.
2. Inspect existing modules before creating new ones.
3. Reuse existing shared models and services where appropriate.
4. Avoid unnecessary duplicate implementations.
5. Keep component interfaces explicit and testable.
6. Avoid circular imports and hidden cross-module dependencies.
7. Separate API routes, business logic, persistence, and security operations.
8. Keep the frontend independent of Python implementation details.
9. Avoid introducing unapproved dependencies or architectural patterns.
10. Preserve existing working functionality unless the ticket explicitly changes it.
11. Add or update tests for interface and behavior changes.
12. Document approved architectural changes.
13. Report incomplete interfaces or unavailable platform capabilities honestly.
14. Never mark unimplemented functionality as complete.

## 15. Definition of Architectural Completion

The architecture will be considered successfully implemented when:

- Component responsibilities are reflected in the codebase.
- Shared data contracts are implemented and validated.
- The analysis pipeline passes events and evidence between components correctly.
- Detection, scoring, response, and explanation remain separate.
- Incidents persist independently of dashboard connections.
- The frontend uses documented API contracts.
- Optional AI functionality does not block core detection.
- Errors and partial-analysis states are represented explicitly.
- Quarantine and restoration operate within defined security boundaries.
- Automated integration tests verify the principal component interactions.

---

**End of System Architecture Document**