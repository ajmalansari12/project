# Sentinel-EDR
## Database Schema

**Project:** Sentinel-EDR — Hybrid Real-Time Endpoint Detection and Response System  
**Document Version:** 1.0  
**Status:** Initial Draft  
**Database:** SQLite  
**ORM:** SQLAlchemy  
**Related Documents:** `prd.md`, `trd.md`, `implementation_plan.md`, `architecture.md`

---

## 1. Purpose

This document defines the database schema for Sentinel-EDR.

The database will persist endpoint events, analysis jobs, security incidents, detection evidence, response actions, quarantine metadata, AI forensic reports, and audit records.

The schema must support reliable incident investigation, reproducible detection results, safe quarantine and restoration, and dashboard queries.

Google Antigravity must implement this schema consistently across database models, application services, API responses, and automated tests.

Any schema changes must be documented and implemented through a controlled migration process.

## 2. Database Design Principles

1. Use SQLite for the initial local implementation.
2. Use SQLAlchemy for database access.
3. Use UUID strings for application-generated primary keys.
4. Store timestamps in UTC using a consistent ISO 8601 representation.
5. Use foreign keys to maintain referential integrity.
6. Store structured supplementary data as JSON-serialized text when appropriate.
7. Keep quarantined file contents outside the database.
8. Never store encryption keys as unprotected plaintext.
9. Store detection evidence separately from incident summaries.
10. Distinguish processing status from security verdict.
11. Preserve response and restoration history for auditing.
12. Use database transactions for operations that require multiple related records to remain consistent.
13. Add indexes for frequently queried fields.
14. Avoid unnecessary duplication of incident evidence and metadata.
15. Do not silently discard existing records when changing the schema.

## 3. Database Entities

The initial schema contains eight primary tables.

| Table | Purpose |
|---|---|
| `endpoint_events` | Stores normalized filesystem and endpoint events |
| `analysis_jobs` | Tracks the lifecycle and results of analysis jobs |
| `incidents` | Stores security incidents and their final or provisional verdicts |
| `detection_evidence` | Records individual detection signals and supporting details |
| `response_actions` | Records alerts, quarantine requests, restoration requests, and other response operations |
| `quarantine_records` | Stores quarantine metadata and recovery information |
| `forensic_reports` | Stores AI-generated incident explanations |
| `audit_logs` | Records security-sensitive actions and important system operations |

## 4. Entity Relationship Diagram

```text
┌──────────────────────┐
│   endpoint_events    │
│                      │
│ PK event_id          │
│ event_type           │
│ timestamp            │
│ file_path            │
└──────────┬───────────┘
           │
           │ One event can generate multiple jobs
           ▼
┌──────────────────────┐
│     analysis_jobs    │
│                      │
│ PK job_id            │
│ FK source_event_id   │
│ status               │
│ verdict              │
│ risk_score           │
└──────────┬───────────┘
           │
           │ One job may generate incidents
           ▼
┌──────────────────────┐
│      incidents       │
│                      │
│ PK incident_id       │
│ FK analysis_job_id   │
│ verdict              │
│ risk_score           │
│ status               │
└──────┬─────┬─────┬───┘
       │     │     │
       ▼     ▼     ▼
  evidence  response  forensic
  records   actions   reports
               │
               ▼
       quarantine records

┌──────────────────────┐
│      audit_logs      │
│                      │
│ PK audit_id          │
│ action               │
│ entity_type          │
│ entity_id            │
└──────────────────────┘
```

**Relationship rules:**

- An endpoint event may generate one or more analysis jobs.
- An analysis job may produce one or more incidents if the processing workflow identifies separate incidents.
- An incident may have multiple evidence records, response actions, quarantine records, and forensic reports.
- A response action may be associated with a quarantine record.
- Audit records may reference an incident or another entity.
- Audit logs must remain useful even when an optional entity reference is unavailable.

The diagram represents the logical relationships. SQLAlchemy models and foreign keys must implement the exact constraints specified below.

## 5. Table: `endpoint_events`

### Purpose

Stores normalized events collected by the endpoint sensor or behavioral monitor.

### Fields

| Field | Type | Constraints | Description |
|---|---|---|---|
| `event_id` | TEXT | Primary key | Unique event identifier |
| `event_type` | TEXT | Not null | Type of observed event |
| `timestamp` | TEXT | Not null | Time the event occurred, in UTC |
| `source_component` | TEXT | Not null | Component that generated the event |
| `file_path` | TEXT | Nullable | Relevant file path |
| `file_hash` | TEXT | Nullable | SHA-256 hash, when available |
| `process_id` | INTEGER | Nullable | Relevant process ID |
| `parent_process_id` | INTEGER | Nullable | Parent process ID, when available |
| `metadata_json` | TEXT | Nullable | Additional normalized event metadata |
| `created_at` | TEXT | Not null | Time the record was persisted |

### Requirements

- Generate event IDs in the application.
- Support event types such as `file_created`, `file_modified`, `file_renamed`, `file_deleted`, `process_observed`, and `canary_triggered`.
- Allow events that do not contain a file path or process ID.
- Store event metadata as valid JSON when supplied.
- Treat filesystem paths as observed metadata, not as trusted instructions.
- Avoid storing unrestricted file contents.
- Preserve enough information to investigate why an event generated an analysis job.

The event vocabulary may be extended through controlled changes.

## 6. Table: `analysis_jobs`

### Purpose

Tracks individual analysis jobs from scheduling through completion, failure, or cancellation.

### Fields

| Field | Type | Constraints | Description |
|---|---|---|---|
| `job_id` | TEXT | Primary key | Unique analysis job identifier |
| `source_event_id` | TEXT | Foreign key, nullable | Source endpoint event |
| `file_path` | TEXT | Nullable | File being analyzed |
| `file_hash` | TEXT | Nullable | SHA-256 hash, when available |
| `status` | TEXT | Not null | Processing status |
| `verdict` | TEXT | Nullable | Resulting security verdict |
| `risk_score` | REAL | Nullable, 0–100 | Calculated risk score |
| `modules_executed_json` | TEXT | Not null | Analysis modules that ran |
| `modules_skipped_json` | TEXT | Not null | Analysis modules skipped |
| `modules_failed_json` | TEXT | Not null | Analysis modules that failed |
| `error_code` | TEXT | Nullable | Machine-readable processing error |
| `error_message` | TEXT | Nullable | Sanitized error description |
| `queued_at` | TEXT | Not null | Job creation time |
| `started_at` | TEXT | Nullable | Processing start time |
| `completed_at` | TEXT | Nullable | Processing completion time |
| `created_at` | TEXT | Not null | Record creation time |
| `updated_at` | TEXT | Not null | Last update time |

### Allowed processing states

- `QUEUED`
- `IN_PROGRESS`
- `COMPLETED`
- `FAILED`
- `CANCELLED`

### Allowed verdicts

- `BENIGN`
- `SUSPICIOUS`
- `MALICIOUS`

A verdict may be null when the job has not produced a valid security decision.

### Requirements

- Processing status and verdict must remain separate.
- A failed analysis job must not automatically receive the `BENIGN` verdict.
- Risk scores must be within the range 0–100 when present.
- Module execution details must be valid JSON arrays.
- Record timestamps must reflect the actual processing lifecycle.
- The source event foreign key must reference `endpoint_events.event_id`.
- Failed and incomplete analysis must remain distinguishable from successful analysis.

## 7. Table: `incidents`

### Purpose

Stores security incidents that are visible to the SOC dashboard.

An incident represents a security finding requiring tracking, investigation, or response.

### Fields

| Field | Type | Constraints | Description |
|---|---|---|---|
| `incident_id` | TEXT | Primary key | Unique incident identifier |
| `analysis_job_id` | TEXT | Foreign key, nullable | Associated analysis job |
| `title` | TEXT | Not null | Human-readable incident title |
| `description` | TEXT | Nullable | Incident summary |
| `incident_type` | TEXT | Not null | Type of security finding |
| `verdict` | TEXT | Not null | Current security classification |
| `risk_score` | REAL | Not null, 0–100 | Composite risk score |
| `status` | TEXT | Not null | Investigation status |
| `file_path` | TEXT | Nullable | Associated file path |
| `file_hash` | TEXT | Nullable | Associated SHA-256 hash |
| `process_id` | INTEGER | Nullable | Associated process ID |
| `detected_at` | TEXT | Not null | Time the incident was detected |
| `created_at` | TEXT | Not null | Record creation time |
| `updated_at` | TEXT | Not null | Last update time |
| `resolved_at` | TEXT | Nullable | Incident resolution time |

### Allowed incident statuses

- `OPEN`
- `INVESTIGATING`
- `CONTAINED`
- `RESOLVED`
- `CLOSED`

### Requirements

- An incident must have a valid verdict and risk score.
- Incident status must not be used to represent analysis-job status.
- Incident updates must preserve the original detection time.
- Resolution timestamps must be populated only when the incident is actually resolved.
- An incident may exist without an associated analysis job for certain behavioral detections.
- The incident record must summarize the finding without replacing detailed evidence records.
- Repeated events must not create uncontrolled duplicate incidents. Deduplication rules must be implemented at the application-service level.

The incident lifecycle is independent of whether an AI forensic report has been generated.

## 8. Table: `detection_evidence`

### Purpose

Stores individual signals supporting a detection or incident verdict.

Examples include a hash-list match, a YARA rule match, an ML probability, a high-entropy section, or a suspicious process relationship.

### Fields

| Field | Type | Constraints | Description |
|---|---|---|---|
| `evidence_id` | TEXT | Primary key | Unique evidence identifier |
| `incident_id` | TEXT | Foreign key, not null | Associated incident |
| `analysis_job_id` | TEXT | Foreign key, nullable | Associated analysis job |
| `source` | TEXT | Not null | Source detection component |
| `indicator` | TEXT | Not null | Indicator identifier |
| `severity` | TEXT | Not null | Indicator severity |
| `description` | TEXT | Not null | Human-readable explanation |
| `observed_value` | TEXT | Nullable | Observed or calculated value |
| `confidence` | REAL | Nullable, 0–1 | Confidence where defined |
| `score_contribution` | REAL | Nullable | Contribution to risk scoring |
| `details_json` | TEXT | Nullable | Additional structured evidence |
| `observed_at` | TEXT | Not null | Time the evidence was observed |
| `created_at` | TEXT | Not null | Time the evidence was persisted |

### Suggested severity values

- `INFO`
- `LOW`
- `MEDIUM`
- `HIGH`
- `CRITICAL`

### Requirements

- Evidence records must be associated with an incident.
- The analysis-job reference may be null for standalone behavioral findings.
- The evidence source must identify the component that produced it.
- Confidence, if provided, must be between 0 and 1.
- Evidence must distinguish measured values from interpretations.
- Store structured evidence as JSON where needed.
- Do not store full executable contents in this table.
- Preserve the specific YARA rule identifier, matched hash, ML result, or behavioral rule that supports the finding.
- The scoring service must be able to retrieve the evidence used to calculate a score.

## 9. Table: `response_actions`

### Purpose

Stores actions requested or performed in response to an incident.

Examples include creating an alert, performing a dry-run quarantine, quarantining a test file, or restoring a quarantined object.

### Fields

| Field | Type | Constraints | Description |
|---|---|---|---|
| `action_id` | TEXT | Primary key | Unique response-action identifier |
| `incident_id` | TEXT | Foreign key, not null | Associated incident |
| `action_type` | TEXT | Not null | Type of response |
| `status` | TEXT | Not null | Execution status |
| `mode` | TEXT | Not null | Dry-run or actual execution |
| `requested_by` | TEXT | Not null | Origin of the request |
| `details_json` | TEXT | Nullable | Action parameters and sanitized details |
| `error_code` | TEXT | Nullable | Machine-readable failure code |
| `error_message` | TEXT | Nullable | Sanitized failure description |
| `requested_at` | TEXT | Not null | Request time |
| `started_at` | TEXT | Nullable | Execution start time |
| `completed_at` | TEXT | Nullable | Execution completion time |

### Suggested action types

- `ALERT`
- `QUARANTINE`
- `RESTORE`
- `TERMINATE_PROCESS`
- `POLICY_CHANGE`

### Allowed execution statuses

- `PENDING`
- `IN_PROGRESS`
- `SUCCEEDED`
- `FAILED`
- `CANCELLED`

### Allowed modes

- `DRY_RUN`
- `ENFORCEMENT`

### Requirements

- Response requests must be validated against the configured response policy.
- A requested action must not be reported as successful before execution is confirmed.
- Failed response actions must retain their error information.
- Destructive actions must be authorized.
- The `requested_by` field must identify the initiating actor or service.
- The action record must not store secrets or encryption keys.
- A successful action must have appropriate completion metadata.
- Process termination must be treated as a separate capability, not as an automatic consequence of an ML prediction.

## 10. Table: `quarantine_records`

### Purpose

Stores metadata necessary to track quarantined files and support safe restoration.

The actual quarantined file contents must be stored separately in the protected quarantine directory.

### Fields

| Field | Type | Constraints | Description |
|---|---|---|---|
| `quarantine_id` | TEXT | Primary key | Unique quarantine record identifier |
| `incident_id` | TEXT | Foreign key, not null | Associated incident |
| `action_id` | TEXT | Foreign key, not null | Quarantine response action |
| `original_path` | TEXT | Not null | Original file path |
| `quarantine_path` | TEXT | Not null, unique | Stored quarantine-object path |
| `original_sha256` | TEXT | Not null | Original file hash |
| `quarantined_sha256` | TEXT | Nullable | Hash of the stored encrypted object, if applicable |
| `encryption_algorithm` | TEXT | Not null | Encryption algorithm identifier |
| `nonce` | TEXT | Not null | Nonce required for authenticated decryption |
| `key_reference` | TEXT | Not null | Reference to securely managed key material |
| `original_size_bytes` | INTEGER | Not null | Original file size |
| `status` | TEXT | Not null | Quarantine lifecycle status |
| `restoration_path` | TEXT | Nullable | Authorized restoration destination |
| `quarantined_at` | TEXT | Not null | Quarantine time |
| `restored_at` | TEXT | Nullable | Restoration time |
| `created_at` | TEXT | Not null | Record creation time |
| `updated_at` | TEXT | Not null | Last update time |

### Allowed quarantine statuses

- `PENDING`
- `QUARANTINED`
- `RESTORING`
- `RESTORED`
- `FAILED`
- `DELETED`

`DELETED` must be reserved for an explicitly authorized lifecycle operation. It must not be used as the default result of quarantine.

### Requirements

- The original SHA-256 must be recorded before or during a successful quarantine transaction.
- The stored encrypted object must be integrity-checked.
- AES-GCM or another approved authenticated-encryption implementation must be used.
- The nonce must be stored as metadata and handled according to the selected encryption implementation.
- `key_reference` must identify the approved key-management mechanism. It must not contain the plaintext encryption key.
- The database must not contain unprotected encryption keys.
- Restoration must verify the recovered content against the original SHA-256.
- Restoration paths must be validated and must not silently overwrite existing files.
- A failed quarantine operation must not leave the application claiming that the file was safely quarantined.
- Database and filesystem operations must use a recoverable workflow because SQLite transactions cannot atomically commit filesystem changes.
- Partial operations must be detected and reconciled.
- Only authorized operations may transition a record into a terminal lifecycle state.

## 11. Table: `forensic_reports`

### Purpose

Stores forensic explanations generated from incident evidence.

### Fields

| Field | Type | Constraints | Description |
|---|---|---|---|
| `report_id` | TEXT | Primary key | Unique forensic report identifier |
| `incident_id` | TEXT | Foreign key, not null | Associated incident |
| `provider` | TEXT | Not null | AI provider or local reporting engine |
| `model_name` | TEXT | Nullable | Model identifier when available |
| `status` | TEXT | Not null | Report-generation status |
| `summary` | TEXT | Nullable | Short incident summary |
| `findings` | TEXT | Nullable | Detailed findings |
| `recommendations` | TEXT | Nullable | Suggested investigation and remediation actions |
| `technique_mappings_json` | TEXT | Nullable | Supported MITRE ATT&CK mappings |
| `evidence_references_json` | TEXT | Not null | Evidence identifiers used in the report |
| `error_message` | TEXT | Nullable | Sanitized generation failure |
| `generated_at` | TEXT | Nullable | Report generation time |
| `created_at` | TEXT | Not null | Record creation time |
| `updated_at` | TEXT | Not null | Last update time |

### Allowed report statuses

- `PENDING`
- `GENERATING`
- `COMPLETED`
- `FAILED`
- `UNAVAILABLE`

### Requirements

- Reports must reference an existing incident.
- Report status must identify whether generation succeeded.
- Failed generation must not be represented as a completed report.
- Evidence references must point to actual evidence identifiers when supplied.
- AI-generated interpretations must remain distinguishable from observed evidence.
- MITRE ATT&CK mappings must be included only when supported by the incident evidence.
- Provider credentials and secrets must never be stored in report records.
- The report-generation workflow must not block the primary detection pipeline.

Multiple report records may exist for an incident when reports are regenerated or produced by different providers.

## 12. Table: `audit_logs`

### Purpose

Records important system operations and security-sensitive actions.

### Fields

| Field | Type | Constraints | Description |
|---|---|---|---|
| `audit_id` | TEXT | Primary key | Unique audit-record identifier |
| `timestamp` | TEXT | Not null | Event time in UTC |
| `actor` | TEXT | Not null | User or system component initiating the action |
| `action` | TEXT | Not null | Operation performed or attempted |
| `entity_type` | TEXT | Nullable | Type of related entity |
| `entity_id` | TEXT | Nullable | Identifier of related entity |
| `result` | TEXT | Not null | Outcome of the operation |
| `details_json` | TEXT | Nullable | Sanitized structured metadata |
| `correlation_id` | TEXT | Nullable | Related event, job, or request identifier |

### Audit-worthy operations

- Quarantine requests.
- Successful and failed restoration attempts.
- Process termination requests.
- Response-policy changes.
- Security configuration changes.
- Unauthorized response attempts.
- Sensitive administrative actions.
- Important application-security failures.

### Requirements

- Record the actual result of the operation.
- Preserve failed and rejected sensitive actions.
- Avoid storing credentials, plaintext encryption keys, or unrestricted file contents.
- Use correlation identifiers where available.
- Restrict access to audit records.
- Do not allow ordinary application operations to silently rewrite the recorded outcome of a completed security action.
- Treat audit-log immutability as a future hardening requirement unless a separate protected logging mechanism is implemented.

## 13. Relationships and Foreign Keys

The following relationships must be implemented:

| Parent table | Child table | Relationship |
|---|---|---|
| `endpoint_events` | `analysis_jobs` | One-to-many |
| `analysis_jobs` | `incidents` | One-to-many |
| `incidents` | `detection_evidence` | One-to-many |
| `analysis_jobs` | `detection_evidence` | One-to-many, optional association |
| `incidents` | `response_actions` | One-to-many |
| `incidents` | `quarantine_records` | One-to-many |
| `response_actions` | `quarantine_records` | One-to-many or one-to-one according to the final response workflow |
| `incidents` | `forensic_reports` | One-to-many |

`audit_logs` uses optional entity references rather than mandatory foreign keys to every possible entity type.

### Deletion Policy

- Do not cascade-delete incident history when an endpoint event is removed.
- Do not cascade-delete audit records when a related entity is removed.
- Prefer retaining security records and using an explicitly authorized retention process.
- Quarantined objects must not be deleted merely because an incident is closed.
- Any retention or purge functionality must be implemented through a separate, explicitly authorized operation.

## 14. Indexes

The following indexes should be created.

| Table | Index | Purpose |
|---|---|---|
| `endpoint_events` | `timestamp` | Retrieve recent endpoint events |
| `endpoint_events` | `event_type`, `timestamp` | Filter events by type and time |
| `endpoint_events` | `file_hash` | Look up events associated with a hash |
| `analysis_jobs` | `status`, `queued_at` | Find queued and active jobs |
| `analysis_jobs` | `source_event_id` | Retrieve jobs generated from an event |
| `analysis_jobs` | `file_hash` | Find prior analysis of a file hash |
| `incidents` | `detected_at` | Sort incidents by detection time |
| `incidents` | `verdict`, `detected_at` | Filter and sort by verdict |
| `incidents` | `status`, `detected_at` | Find open and unresolved incidents |
| `incidents` | `file_hash` | Find related incidents |
| `detection_evidence` | `incident_id`, `observed_at` | Retrieve incident evidence |
| `detection_evidence` | `analysis_job_id` | Retrieve evidence by job |
| `response_actions` | `incident_id`, `requested_at` | Retrieve action history |
| `quarantine_records` | `incident_id` | Retrieve quarantined objects for an incident |
| `quarantine_records` | `status` | Find objects requiring recovery or review |
| `forensic_reports` | `incident_id`, `created_at` | Retrieve reports by incident |
| `audit_logs` | `timestamp` | Retrieve recent audit entries |
| `audit_logs` | `entity_type`, `entity_id` | Retrieve audit history for an entity |
| `audit_logs` | `correlation_id` | Trace related operations |

Antigravity must add indexes through the database initialization or migration mechanism and verify that the relevant queries use the intended indexes when performance warrants it.

## 15. Data Validation and Constraints

The implementation must enforce the following validation rules:

- Primary keys must be unique.
- Required fields must not be null.
- Foreign keys must reference valid records.
- Risk scores must be within 0–100.
- Confidence values must be within 0–1.
- File sizes must not be negative.
- Required JSON fields must contain valid JSON.
- Enum-like status fields must use approved values.
- SHA-256 values must be validated as 64 hexadecimal characters when a full hash is required.
- Timestamps must use a consistent UTC representation.
- IDs must be generated by the application and must not depend on user-provided values.
- Quarantine paths must be unique in the database.
- File paths and metadata must not be treated as safe merely because they are stored in valid database records.

SQLite foreign-key enforcement must be enabled for application connections.

Database constraints must be supplemented with application-level validation where appropriate.

## 16. SQLAlchemy Implementation Requirements

### ORM Design

- Use SQLAlchemy declarative models.
- Use explicit field types and nullability.
- Define primary and foreign keys in the model.
- Define relationships where they improve clarity and maintainability.
- Keep database models separate from API response schemas.
- Avoid placing detection or response business logic inside ORM models.
- Use transactions for logically related updates.
- Avoid keeping long-running database transactions open during ML inference or AI report generation.

### Serialization

- Serialize structured JSON fields consistently.
- Validate JSON before persistence.
- Keep serialization and deserialization logic centralized.
- Return typed API responses instead of raw ORM objects.

### Migrations

- Establish a controlled schema-versioning and migration process.
- Never silently drop or recreate the database when application models change.
- Test migrations against a disposable copy of existing data.
- Preserve incident and quarantine metadata during schema upgrades.
- Document any migration that is not backward-compatible.

The specific migration tooling must be selected consistently during implementation. The initial implementation must not introduce competing database migration mechanisms.

## 17. Transaction and Recovery Requirements

Database and filesystem changes cannot always be completed as one atomic transaction.

For example, quarantining a file may involve:

1. Creating a response-action record.
2. Validating the source file and its hash.
3. Encrypting and writing the quarantine object.
4. Verifying the stored artifact.
5. Updating the quarantine record.
6. Completing the response-action record.

The implementation must track intermediate states and recover from interruptions.

If an operation fails, the database must reflect the failure or unresolved state rather than report a successful quarantine.

Restoration must verify the decrypted data against the original hash before marking the object as restored.

The same principle applies to incident creation and asynchronous forensic reporting: a temporary failure must remain visible and must not silently erase the evidence already collected.

## 18. Data Retention and Privacy

- Retain incident evidence for investigation according to the configured retention policy.
- Avoid storing unnecessary executable contents or sensitive document data.
- Keep quarantine objects in protected external storage.
- Store only the metadata needed for safe restoration.
- Exclude secrets from logs and forensic-report inputs.
- Avoid exposing unrestricted filesystem paths through public API responses.
- Require explicit authorization for purge operations.
- Do not implement automatic data deletion until its retention policy and recovery implications have been documented.

## 19. Database Completion Criteria

The database implementation is considered complete when:

1. All eight tables are implemented.
2. Primary keys, foreign keys, relationships, and required constraints are defined.
3. The SQLite database initializes reproducibly.
4. Foreign-key enforcement is active.
5. The relevant indexes are created.
6. Incidents and evidence persist across application restarts.
7. Analysis-job states are stored correctly.
8. Response actions and quarantine metadata are associated with incidents.
9. Quarantined file contents remain outside the database.
10. Forensic reports and audit records can be stored and retrieved.
11. Database errors are handled without silently losing completed operation records.
12. Automated tests cover persistence, relationships, validation, and failure handling.
13. Schema changes can be applied without silently discarding existing data.

---

**End of Database Schema Document**