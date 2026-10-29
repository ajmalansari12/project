# Sentinel-EDR
## API Specification

**Project:** Sentinel-EDR — Hybrid Real-Time Endpoint Detection and Response System  
**Document Version:** 1.0  
**Status:** Initial Draft  
**API Framework:** FastAPI  
**API Style:** REST + WebSockets  
**Base Path:** `/api/v1`  
**Related Documents:** `prd.md`, `trd.md`, `implementation_plan.md`, `architecture.md`, `database_schema.md`

---

## 1. Purpose

This document defines the API contract between the Sentinel-EDR backend and its frontend dashboard.

It specifies available endpoints, request and response formats, query parameters, HTTP status codes, WebSocket event messages, validation requirements, and authorization rules.

Google Antigravity must follow these contracts when implementing API routes, service integrations, and frontend API clients.

The API must use shared data models and consistent terminology. Backend and frontend implementations must not independently invent incompatible field names, status values, or response formats.

## 2. General API Standards

### 2.1 Base URL

The local development API will use:

`http://127.0.0.1:8000/api/v1`

The actual host and port must be configurable.

All endpoint paths in this document are relative to `/api/v1`, unless explicitly stated otherwise.

### 2.2 Content Type

JSON request and response bodies must use:

`Content-Type: application/json`

WebSocket messages must use JSON text messages.

### 2.3 Naming Conventions

- Use `snake_case` for JSON field names.
- Use UUID strings for application-generated identifiers.
- Use ISO 8601 timestamps in UTC.
- Represent unavailable optional values as `null`.
- Use uppercase enum values for verdicts and processing states.
- Use consistent pagination parameters across collection endpoints.

### 2.4 API Versioning

All application REST routes must be grouped beneath `/api/v1`.

Breaking changes to published request or response contracts require a documented change and an appropriate versioning decision.

### 2.5 OpenAPI Documentation

FastAPI's OpenAPI documentation must reflect the implemented API.

The interactive API documentation must be available through the configured development URL, using FastAPI's standard documentation route unless deliberately changed.

The implementation must not document endpoints as functional when they are only placeholders.

---

## 3. Common Data Models

The following models define the public API contract. They are not intended to expose SQLAlchemy ORM objects directly.

### 3.1 Health Response

```json
{
  "status": "healthy",
  "service": "sentinel-edr-api",
  "version": "1.0.0",
  "timestamp": "2026-10-29T10:00:00Z"
}
```

`status` indicates API availability. The timestamp is illustrative.

### 3.2 Service Status Response

```json
{
  "status": "degraded",
  "components": {
    "database": "available",
    "signature_engine": "available",
    "ml_engine": "unavailable",
    "behavioral_monitor": "available",
    "ai_reporting": "unavailable"
  },
  "timestamp": "2026-10-29T10:00:00Z"
}
```

Component states must represent actual health checks or observed availability. They must not be hardcoded to report success.

Suggested component states are:

- `available`
- `unavailable`
- `degraded`
- `disabled`
- `not_initialized`
- `unknown`

The overall status must reflect the application’s actual operational condition.

### 3.3 Security Verdict

Allowed values:

- `BENIGN`
- `SUSPICIOUS`
- `MALICIOUS`

A verdict describes the security classification, not whether processing completed successfully.

### 3.4 Processing Status

Allowed analysis-job statuses:

- `QUEUED`
- `IN_PROGRESS`
- `COMPLETED`
- `FAILED`
- `CANCELLED`

### 3.5 Incident Status

Allowed incident statuses:

- `OPEN`
- `INVESTIGATING`
- `CONTAINED`
- `RESOLVED`
- `CLOSED`

### 3.6 Response Action Status

Allowed response action statuses:

- `PENDING`
- `IN_PROGRESS`
- `SUCCEEDED`
- `FAILED`
- `CANCELLED`

### 3.7 Standard Error Response

All API errors must use a consistent response structure.

```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "The requested incident was not found.",
    "details": {},
    "request_id": "request-uuid"
  }
}
```

Requirements:

- `code` must be a stable, machine-readable error identifier.
- `message` must be safe to display to users.
- `details` may include field-validation information that does not expose sensitive internal data.
- `request_id` should identify the request for troubleshooting.
- Unexpected exceptions must not expose stack traces, secrets, or internal filesystem details in production-like responses.

---

## 4. Health and System Status Endpoints

### 4.1 Check API Health

**Endpoint:** `GET /health`

**Purpose:** Check whether the API process is responsive.

**Authentication:** Not required for the initial local-only application.

**Success response:** `200 OK`

```json
{
  "status": "healthy",
  "service": "sentinel-edr-api",
  "version": "1.0.0",
  "timestamp": "2026-10-29T10:00:00Z"
}
```

This endpoint must not claim that every detection component is healthy merely because the API process responds.

### 4.2 Get Component Status

**Endpoint:** `GET /status`

**Purpose:** Retrieve the availability of core and optional components.

**Success response:** `200 OK`

Returns the Service Status Response defined in Section 3.2.

The response must distinguish mandatory services from optional capabilities. An unavailable AI provider, for example, must not automatically mean that the core API is unavailable.

---

## 5. Incident Endpoints

### 5.1 List Incidents

**Endpoint:** `GET /incidents`

**Purpose:** Retrieve security incidents for the SOC dashboard.

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `page` | Integer | No | Page number, starting at 1 |
| `page_size` | Integer | No | Number of records, maximum 100 |
| `verdict` | String | No | Filter by security verdict |
| `status` | String | No | Filter by incident status |
| `search` | String | No | Search supported incident fields |
| `file_hash` | String | No | Filter by SHA-256 hash |
| `from_time` | ISO 8601 | No | Inclusive starting timestamp |
| `to_time` | ISO 8601 | No | Inclusive ending timestamp |
| `sort_by` | String | No | Supported sorting field |
| `order` | String | No | `asc` or `desc` |

Default behavior:

- `page = 1`
- `page_size = 20`
- `order = desc`
- Default sort field: `detected_at`

Only documented sort fields may be accepted. SQL expressions or arbitrary database field names must not be accepted from query parameters.

**Success response:** `200 OK`

```json
{
  "items": [
    {
      "incident_id": "incident-uuid",
      "title": "Suspicious executable detected",
      "description": "The file triggered multiple detection indicators.",
      "incident_type": "FILE_DETECTION",
      "verdict": "SUSPICIOUS",
      "risk_score": 52.5,
      "status": "OPEN",
      "file_path": "C:\\Users\\Example\\Downloads\\sample.exe",
      "file_hash": null,
      "process_id": null,
      "detected_at": "2026-10-29T10:00:00Z",
      "created_at": "2026-10-29T10:00:00Z",
      "updated_at": "2026-10-29T10:00:00Z",
      "resolved_at": null
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_items": 1,
    "total_pages": 1
  }
}
```

The example uses illustrative data and does not represent a real detection.

### 5.2 Get Incident Details

**Endpoint:** `GET /incidents/{incident_id}`

**Purpose:** Retrieve one incident and its main detection information.

**Success response:** `200 OK`

```json
{
  "incident_id": "incident-uuid",
  "analysis_job_id": "job-uuid",
  "title": "Suspicious executable detected",
  "description": "The file triggered multiple detection indicators.",
  "incident_type": "FILE_DETECTION",
  "verdict": "SUSPICIOUS",
  "risk_score": 52.5,
  "status": "OPEN",
  "file_path": "C:\\Users\\Example\\Downloads\\sample.exe",
  "file_hash": null,
  "process_id": null,
  "detected_at": "2026-10-29T10:00:00Z",
  "created_at": "2026-10-29T10:00:00Z",
  "updated_at": "2026-10-29T10:00:00Z",
  "resolved_at": null,
  "evidence_count": 2,
  "response_action_count": 0
}
```

The detail endpoint may return additional documented metadata but must not return unrestricted file contents, encryption keys, or sensitive internal configuration.

**Possible errors:**

- `404 Not Found` — Incident does not exist.
- `422 Unprocessable Entity` — Invalid identifier format, where identifier validation is enforced.

### 5.3 Update Incident Status

**Endpoint:** `PATCH /incidents/{incident_id}/status`

**Purpose:** Update an incident's investigation status.

**Request body:**

```json
{
  "status": "INVESTIGATING"
}
```

Allowed values are the statuses defined in Section 3.5.

**Success response:** `200 OK`

```json
{
  "incident_id": "incident-uuid",
  "status": "INVESTIGATING",
  "updated_at": "2026-10-29T10:05:00Z"
}
```

Requirements:

- Validate allowed status transitions.
- Record the change in the audit log.
- Set `resolved_at` when the incident is actually resolved, according to the defined lifecycle.
- Preserve the original detection timestamp.
- Do not allow status updates to change the recorded detection evidence.
- Do not treat closing an incident as permission to delete or restore a quarantined file.

---

## 6. Detection Evidence Endpoints

### 6.1 List Evidence for an Incident

**Endpoint:** `GET /incidents/{incident_id}/evidence`

**Purpose:** Retrieve supporting indicators for an incident.

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `page` | Integer | No | Page number |
| `page_size` | Integer | No | Maximum 100 |
| `source` | String | No | Filter by detection component |
| `severity` | String | No | Filter by severity |

**Success response:** `200 OK`

```json
{
  "items": [
    {
      "evidence_id": "evidence-uuid",
      "incident_id": "incident-uuid",
      "analysis_job_id": "job-uuid",
      "source": "signature_engine",
      "indicator": "yara_match",
      "severity": "HIGH",
      "description": "A configured detection rule matched the file.",
      "observed_value": "example_test_rule",
      "confidence": null,
      "score_contribution": 25.0,
      "details": {
        "rule_id": "example_test_rule"
      },
      "observed_at": "2026-10-29T10:00:00Z",
      "created_at": "2026-10-29T10:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_items": 1,
    "total_pages": 1
  }
}
```

Requirements:

- Verify that the incident exists before returning evidence.
- Return evidence associated with the requested incident.
- Preserve the distinction between observed values and interpreted findings.
- Validate `confidence` when present.
- Represent arbitrary structured evidence as JSON rather than exposing internal database serialization.
- Do not return complete executable contents.

---

## 7. Analysis Job Endpoints

### 7.1 List Analysis Jobs

**Endpoint:** `GET /analysis-jobs`

**Purpose:** Retrieve analysis-job status for diagnostic and monitoring interfaces.

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `page` | Integer | No | Page number |
| `page_size` | Integer | No | Maximum 100 |
| `status` | String | No | Filter by processing status |
| `verdict` | String | No | Filter by verdict |
| `file_hash` | String | No | Filter by file hash |

**Success response:** `200 OK`

```json
{
  "items": [
    {
      "job_id": "job-uuid",
      "source_event_id": "event-uuid",
      "status": "COMPLETED",
      "verdict": "SUSPICIOUS",
      "risk_score": 52.5,
      "modules_executed": [
        "signature_engine",
        "ml_engine"
      ],
      "modules_skipped": [],
      "modules_failed": [],
      "error_code": null,
      "queued_at": "2026-10-29T10:00:00Z",
      "started_at": "2026-10-29T10:00:00Z",
      "completed_at": "2026-10-29T10:00:01Z"
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_items": 1,
    "total_pages": 1
  }
}
```

### 7.2 Get Analysis Job Details

**Endpoint:** `GET /analysis-jobs/{job_id}`

**Purpose:** Retrieve the full recorded processing status of an analysis job.

**Success response:** `200 OK`

The response must contain the job fields defined in `database_schema.md`, along with documented derived timing information where available.

Requirements:

- A failed job must not be represented as a completed benign result.
- The response must identify failed or unavailable modules.
- Detailed error responses must not expose secrets or unsafe internal information.
- The endpoint must not rerun the analysis simply because the job is retrieved.

---

## 8. Response Action Endpoints

Response operations are security-sensitive. They must remain disabled or restricted until an authorization mechanism and a valid response policy are implemented.

### 8.1 List Incident Response Actions

**Endpoint:** `GET /incidents/{incident_id}/response-actions`

**Purpose:** Retrieve the recorded response history for an incident.

**Success response:** `200 OK`

```json
{
  "items": [
    {
      "action_id": "action-uuid",
      "incident_id": "incident-uuid",
      "action_type": "QUARANTINE",
      "status": "SUCCEEDED",
      "mode": "DRY_RUN",
      "requested_by": "local_operator",
      "requested_at": "2026-10-29T10:05:00Z",
      "started_at": "2026-10-29T10:05:00Z",
      "completed_at": "2026-10-29T10:05:01Z",
      "error_code": null,
      "error_message": null
    }
  ]
}
```

The example is illustrative. An actual dry-run action must not be described as an actual file quarantine.

### 8.2 Request a Quarantine Operation

**Endpoint:** `POST /incidents/{incident_id}/response-actions/quarantine`

**Purpose:** Request a controlled quarantine operation for the file associated with an incident.

**Request body:**

```json
{
  "mode": "DRY_RUN",
  "reason": "Controlled project test",
  "confirmation": true
}
```

`mode` must be one of:

- `DRY_RUN`
- `ENFORCEMENT`

`confirmation` is an explicit confirmation field; it does not replace authentication or authorization.

**Successful accepted response:** `202 Accepted`

```json
{
  "action_id": "action-uuid",
  "incident_id": "incident-uuid",
  "action_type": "QUARANTINE",
  "status": "PENDING",
  "mode": "DRY_RUN",
  "message": "The quarantine request has been accepted for processing."
}
```

Requirements:

- Validate the incident and associated file metadata.
- Enforce response authorization and the configured policy.
- Default to `DRY_RUN` during development.
- Do not accept an arbitrary source file path from the frontend as sufficient authorization.
- Record the action before reporting successful completion.
- Return `202 Accepted` only when the request has actually been accepted for processing.
- Use `403 Forbidden` when an authenticated actor is not authorized.
- Use `409 Conflict` when the resource or current state does not permit the requested operation.
- Return actual execution status through the response-action API or a subsequent event.

The initial MVP must not enable enforcement mode until quarantine encryption, restoration, authorization, and failure recovery have been tested.

### 8.3 List Quarantine Records

**Endpoint:** `GET /quarantine`

**Purpose:** Retrieve quarantined-object metadata for authorized management interfaces.

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `page` | Integer | No | Page number |
| `page_size` | Integer | No | Maximum 100 |
| `status` | String | No | Filter by quarantine status |
| `incident_id` | String | No | Filter by incident |

**Success response:** `200 OK`

```json
{
  "items": [
    {
      "quarantine_id": "quarantine-uuid",
      "incident_id": "incident-uuid",
      "action_id": "action-uuid",
      "original_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "original_size_bytes": 4096,
      "encryption_algorithm": "AES-256-GCM",
      "status": "QUARANTINED",
      "quarantined_at": "2026-10-29T10:05:00Z",
      "restored_at": null
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_items": 1,
    "total_pages": 1
  }
}
```

Requirements:

- Do not expose encryption keys or their secret material.
- Do not expose unrestricted physical paths unless explicitly necessary and authorized.
- Retrieve file metadata from the database rather than trusting frontend-supplied metadata.
- Distinguish quarantined objects from objects merely scheduled for quarantine.

### 8.4 Get Quarantine Record Details

**Endpoint:** `GET /quarantine/{quarantine_id}`

**Purpose:** Retrieve the status and recovery metadata for a quarantine record.

**Success response:** `200 OK`

Return the documented quarantine metadata, including the original hash, size, lifecycle status, and available restoration information.

Do not return secret encryption keys or decrypted file contents.

### 8.5 Request Restoration

**Endpoint:** `POST /quarantine/{quarantine_id}/restore`

**Purpose:** Request authorized restoration of a quarantined artifact.

**Request body:**

```json
{
  "destination_path": "C:\\Users\\Example\\Restored\\sample.exe",
  "confirmation": true,
  "reason": "Authorized recovery test"
}
```

The destination path must be validated by the backend. This example is illustrative and must not be treated as a recommended restoration location for suspicious files.

**Successful accepted response:** `202 Accepted`

```json
{
  "action_id": "action-uuid",
  "quarantine_id": "quarantine-uuid",
  "status": "PENDING",
  "message": "The restoration request has been accepted for processing."
}
```

Requirements:

- Require authentication and authorization before enabling the operation.
- Allow restoration only from a valid quarantine state.
- Validate and safely handle the destination.
- Avoid overwriting an existing file silently.
- Verify the recovered content against the original SHA-256.
- Mark the record as restored only after the operation is verified.
- Record failures and retain recoverable quarantine data whenever possible.
- Do not execute the restored file automatically.

---

## 9. Forensic Report Endpoints

### 9.1 List Reports for an Incident

**Endpoint:** `GET /incidents/{incident_id}/forensic-reports`

**Purpose:** Retrieve forensic report metadata and available reports for an incident.

**Success response:** `200 OK`

```json
{
  "items": [
    {
      "report_id": "report-uuid",
      "incident_id": "incident-uuid",
      "provider": "configured_ai_provider",
      "model_name": null,
      "status": "COMPLETED",
      "summary": "Multiple indicators contributed to a suspicious classification.",
      "findings": "The recorded evidence includes configured signature and static-analysis results.",
      "recommendations": "Review the evidence and validate the file's origin.",
      "technique_mappings": [],
      "evidence_references": [
        "evidence-uuid"
      ],
      "generated_at": "2026-10-29T10:10:00Z",
      "created_at": "2026-10-29T10:10:00Z",
      "updated_at": "2026-10-29T10:10:00Z"
    }
  ]
}
```

Illustrative content must not be displayed as an actual AI-generated report.

### 9.2 Get a Forensic Report

**Endpoint:** `GET /forensic-reports/{report_id}`

**Purpose:** Retrieve the complete recorded report.

**Success response:** `200 OK`

The response must contain the report fields defined in `database_schema.md`.

Requirements:

- Preserve the distinction between evidence and AI-generated interpretation.
- Include valid evidence references when present.
- Handle pending, failed, and unavailable report statuses.
- Do not generate a new report merely because an existing report is retrieved.
- Avoid exposing external provider credentials or sensitive information included in internal prompts.

### 9.3 Request Report Generation

**Endpoint:** `POST /incidents/{incident_id}/forensic-reports`

**Purpose:** Request asynchronous forensic report generation.

**Request body:**

```json
{
  "regenerate": false
}
```

**Successful accepted response:** `202 Accepted`

```json
{
  "report_id": "report-uuid",
  "incident_id": "incident-uuid",
  "status": "PENDING",
  "message": "The report-generation request has been accepted."
}
```

Requirements:

- Verify that the incident exists.
- Supply structured incident evidence to the reporting service.
- Enforce configured limits on repeated requests.
- Treat report generation as an optional capability.
- Do not block detection or incident persistence while waiting for an AI provider.
- Validate the report before storing or returning it.
- Do not allow report contents to trigger security operations automatically.

---

## 10. Dashboard Statistics Endpoint

### Get Dashboard Overview

**Endpoint:** `GET /dashboard/overview`

**Purpose:** Return summary statistics for the SOC dashboard.

**Success response:** `200 OK`

```json
{
  "generated_at": "2026-10-29T10:00:00Z",
  "statistics": {
    "total_incidents": 24,
    "open_incidents": 5,
    "benign": 12,
    "suspicious": 7,
    "malicious": 5
  },
  "pipeline": {
    "queued_jobs": 0,
    "in_progress_jobs": 1,
    "failed_jobs": 0
  },
  "recent_activity": []
}
```

All numerical values and activity entries must be computed from actual persisted data.

The example values must never be hardcoded as real production statistics.

Requirements:

- Return a consistent response when the database contains no incidents.
- Use documented time windows for any time-dependent statistics.
- Distinguish incident counts from analysis-job counts.
- Avoid expensive unbounded queries for dashboard summaries.
- Clearly distinguish unavailable telemetry from a genuine count of zero.

---

## 11. WebSocket Event API

### 11.1 Connection Endpoint

**Endpoint:** `WS /api/v1/ws/events`

Development connection example:

`ws://127.0.0.1:8000/api/v1/ws/events`

The configured host must match the backend deployment.

### 11.2 Purpose

The WebSocket connection delivers relevant live system events to connected dashboard clients.

It supplements the REST API. It does not replace persistent incident storage.

### 11.3 Event Envelope

All server-to-client messages must follow a consistent envelope.

```json
{
  "event_id": "event-uuid",
  "event_type": "incident.created",
  "timestamp": "2026-10-29T10:00:00Z",
  "data": {
    "incident_id": "incident-uuid",
    "verdict": "SUSPICIOUS",
    "risk_score": 52.5
  }
}
```

### 11.4 Supported Event Types

The initial event vocabulary should include:

| Event type | Purpose |
|---|---|
| `connection.ready` | Confirms the WebSocket connection is established |
| `connection.error` | Reports a non-sensitive connection-level error |
| `endpoint.event_received` | Indicates a normalized endpoint event was received |
| `analysis.started` | Indicates an analysis job started |
| `analysis.completed` | Indicates analysis completed |
| `analysis.failed` | Indicates analysis failed |
| `incident.created` | Indicates a new incident was persisted |
| `incident.updated` | Indicates incident metadata or status changed |
| `response_action.updated` | Indicates a response action changed state |
| `quarantine.updated` | Indicates a quarantine record changed state |
| `forensic_report.updated` | Indicates a forensic report changed state |
| `system.status_changed` | Indicates a component status changed |

Only events that actually occur may be published. Unsupported event types must not be fabricated to satisfy a frontend display requirement.

### 11.5 Connection Behavior

- The server must accept and manage WebSocket connections safely.
- Connection lifecycle and disconnection must be logged appropriately.
- The frontend must reconnect after temporary disconnection with a bounded retry policy.
- The frontend must retrieve current persisted state through REST after reconnection.
- The server must avoid broadcasting sensitive configuration, secrets, encryption metadata, or unrestricted file contents.
- Duplicate event delivery must be tolerated by the frontend.
- Clients must not assume every event will be delivered exactly once.
- A database failure must not be concealed by emitting an event that claims the affected record was persisted successfully.

### 11.6 Event Persistence

Events representing completed database operations should be published only after the relevant persistence operation succeeds.

Where reliable event publication is required, the architecture may introduce a durable event-outbox mechanism as a later enhancement. The initial version must document the delivery limitations of in-memory broadcasting.

The dashboard must use REST queries as the source of truth for persisted state.

---

## 12. HTTP Status Codes

The implementation must use consistent HTTP status codes.

| Code | Meaning | Typical use |
|---|---|---|
| `200 OK` | Request succeeded | Read or update an existing resource |
| `201 Created` | Resource created synchronously | Successful synchronous resource creation |
| `202 Accepted` | Request accepted for asynchronous processing | Quarantine request or forensic report generation |
| `204 No Content` | Request succeeded without a response body | Successful operation where a response body is unnecessary |
| `400 Bad Request` | Invalid request | Malformed request or invalid parameter combination |
| `401 Unauthorized` | Authentication is missing or invalid | Protected resource access |
| `403 Forbidden` | Request is not authorized | Restricted security operation |
| `404 Not Found` | Resource not found | Unknown incident, job, or quarantine record |
| `409 Conflict` | Request conflicts with resource state | Invalid state transition or incompatible response action |
| `413 Content Too Large` | Request or upload exceeds the configured limit | Applicable only if upload functionality is implemented |
| `422 Unprocessable Entity` | Request validation failed | Invalid field values or schema |
| `429 Too Many Requests` | Rate limit exceeded | Protected or rate-limited operations |
| `500 Internal Server Error` | Unexpected server failure | Unhandled internal error |
| `503 Service Unavailable` | Required service unavailable | A required component cannot process the request |

An endpoint must return a status code only when its corresponding condition is satisfied.

In particular, `202 Accepted` does not mean that the requested operation has already succeeded.

---

## 13. Error Codes

Use stable error codes across the API.

| Error code | Meaning |
|---|---|
| `VALIDATION_ERROR` | Request input failed validation |
| `RESOURCE_NOT_FOUND` | Requested resource does not exist |
| `INVALID_STATE_TRANSITION` | Requested state change is not permitted |
| `ANALYSIS_UNAVAILABLE` | Required analysis capability is unavailable |
| `ANALYSIS_FAILED` | Analysis could not complete |
| `MODEL_UNAVAILABLE` | Required ML model is unavailable |
| `SIGNATURE_ENGINE_UNAVAILABLE` | Signature scanning is unavailable |
| `DATABASE_UNAVAILABLE` | Database operation could not be completed |
| `UNAUTHORIZED` | Authentication is required or invalid |
| `FORBIDDEN` | The action is not authorized |
| `QUARANTINE_FAILED` | Quarantine operation failed |
| `RESTORATION_FAILED` | Restoration operation failed |
| `INTEGRITY_CHECK_FAILED` | Integrity validation failed |
| `AI_PROVIDER_UNAVAILABLE` | AI reporting service is unavailable |
| `RATE_LIMIT_EXCEEDED` | Request limit has been exceeded |
| `INTERNAL_ERROR` | Unexpected internal failure |

The API may introduce additional codes through documented changes.

Error messages must not expose raw stack traces, credentials, secrets, or sensitive filesystem content.

---

## 14. Authentication and Authorization

### 14.1 Initial Local Development

The initial development API must bind to localhost by default.

Health checks may remain unauthenticated. All security-sensitive operations must be restricted.

The following operations must require authorization before enforcement mode is enabled:

- Quarantine.
- File restoration.
- Process termination.
- Response-policy changes.
- Other actions capable of changing endpoint state.

### 14.2 Enforcement Operations

Until a suitable authentication and authorization mechanism is implemented and tested:

- Enforcement endpoints must remain disabled or restricted to safe dry-run behavior.
- A request body's `confirmation` field must not be treated as authentication.
- The system must not trust a frontend button or hidden UI element as an authorization control.
- Any actual response action must be validated by the backend.
- Unauthorized attempts must be rejected and recorded where appropriate.

### 14.3 Future Remote Access

If the application later supports remote clients, it must introduce a documented authentication mechanism, authorization rules, secure transport, and appropriate origin restrictions before allowing access to security-sensitive operations.

Secrets must not be embedded in the React application or committed to source control.

### 14.4 CORS

During development, CORS must permit only configured frontend origins.

The implementation must not use unrestricted cross-origin access as a substitute for authentication or authorization.

### 14.5 WebSocket Authorization

The WebSocket endpoint must follow the application's connection-access policy.

If authentication becomes required, it must be validated during connection establishment or through another documented secure mechanism. Secrets must not be exposed in URLs or logged connection metadata.

---

## 15. Request Validation and Security Requirements

The API must:

1. Validate all incoming request bodies using typed Pydantic models.
2. Validate UUID and hash formats where required.
3. Apply bounds to pagination parameters.
4. Reject invalid enum values.
5. Restrict sorting and filtering to documented fields.
6. Validate all filesystem paths on the backend.
7. Prevent path traversal in quarantine and restoration workflows.
8. Avoid exposing arbitrary file reads through query parameters.
9. Never accept frontend-supplied risk scores as authoritative security results.
10. Avoid exposing encryption keys or unprotected secrets.
11. Sanitize error responses.
12. Separate request validation from business logic.
13. Record security-sensitive actions and their actual outcomes.
14. Treat data received from AI providers and external threat feeds as untrusted.

File monitoring and scanning APIs must not provide a general-purpose remote command-execution interface.

---

## 16. Pagination and Filtering Standards

All collection endpoints must use consistent pagination conventions.

### Request

`GET /incidents?page=1&page_size=20&order=desc`

### Response

```json
{
  "items": [],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_items": 0,
    "total_pages": 0
  }
}
```

Requirements:

- Default page size: 20.
- Maximum page size: 100.
- Page numbers start at 1.
- Invalid negative values must be rejected.
- Empty results must return an empty array.
- Sorting must use documented fields.
- Filtering must be applied before pagination.
- All collection results must have deterministic ordering, including a stable secondary key when necessary.

Endpoints that return a single resource or a small fixed status response do not require pagination.

---

## 17. Implementation and Testing Requirements

Google Antigravity must implement the API in incremental tickets.

### Backend Implementation

- Define Pydantic request and response schemas.
- Keep route handlers thin.
- Delegate business logic to service classes or functions.
- Use the persistence layer defined by `database_schema.md`.
- Ensure transactions are handled correctly.
- Normalize errors consistently.
- Avoid direct SQLAlchemy model serialization.
- Add API tests for success, validation, missing resources, and failed dependencies.

### Frontend Integration

- Define TypeScript types corresponding to API contracts.
- Use a centralized API client.
- Handle loading, error, empty, and disconnected states.
- Use REST for current persisted state.
- Use WebSockets for live updates.
- Avoid assuming that a requested security action succeeded before receiving confirmation.
- Keep backend credentials and secrets out of browser code.

### Automated Testing

Tests must verify:

- Health and service-status endpoints.
- Incident listing, filtering, and pagination.
- Incident-detail retrieval.
- Evidence retrieval.
- Analysis-job status retrieval.
- Incident status transitions.
- Response-action validation and authorization.
- Quarantine and restoration error handling.
- Forensic report creation and retrieval.
- WebSocket connection and event envelopes.
- Database failure behavior.
- Invalid inputs and unknown resources.
- Consistency between the documented contract and actual responses.

All destructive-action tests must use mocks, dry-run behavior, or disposable test artifacts.

---

## 18. Definition of API Completion

The API implementation will be considered complete when:

1. All implemented endpoints follow the documented paths and schemas.
2. Request validation rejects invalid inputs.
3. REST responses use consistent structures.
4. Pagination and filtering work correctly.
5. Incident and evidence data comes from persistent storage.
6. Processing errors are distinguishable from benign verdicts.
7. WebSocket messages follow the documented event envelope.
8. The frontend can retrieve current state and consume live updates.
9. Authorization protects security-sensitive operations.
10. Quarantine and restoration requests report their actual execution states.
11. AI reporting failures do not block core incident operations.
12. Automated API tests pass.
13. FastAPI's generated OpenAPI documentation matches the implemented contract.
14. No endpoint claims functionality that has not been implemented and verified.

---

**End of API Specification**