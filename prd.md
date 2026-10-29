# Sentinel-EDR
## Product Requirements Document (PRD)

**Project Name:** Sentinel-EDR  
**Full Name:** Hybrid Real-Time Endpoint Detection and Response System  
**Document Version:** 1.0  
**Status:** Initial Draft

---

## 1. Product Overview

Sentinel-EDR is a hybrid Endpoint Detection and Response (EDR) system designed to detect, analyze, monitor, and respond to potential malware threats on a computer.

The system combines signature-based detection, static machine learning, runtime behavioral monitoring, automated threat scoring, secure quarantine, and AI-generated forensic explanations in a unified security platform.

A web-based Security Operations Center (SOC) dashboard will allow users to monitor system activity, review security alerts, examine detection evidence, and manage incidents.

The project will initially focus on a Windows-based prototype, with an architecture that allows additional operating system support in the future.

## 2. Problem Statement

Traditional antivirus systems that rely primarily on known signatures may fail to identify previously unseen or modified malware. Static machine learning models can identify suspicious executable structures but may generate false positives or fail to detect behavior that becomes apparent only during execution.

Security tools also frequently present technical alerts without sufficient explanations for users to understand why an object was flagged.

Sentinel-EDR aims to address these limitations by combining multiple detection methods, collecting runtime evidence, assigning explainable risk scores, and presenting actionable incident reports through a centralized dashboard.

## 3. Product Objectives

The primary objectives are:

1. Detect known threats using cryptographic hashes and YARA rules.
2. Analyze unknown Windows executable files using static feature extraction and machine learning.
3. Monitor selected filesystem and process activities for suspicious behavior.
4. Calculate a composite risk score using evidence from multiple detection layers.
5. Generate alerts and support controlled quarantine and recovery workflows.
6. Present security events and system telemetry through a real-time dashboard.
7. Generate human-readable forensic reports using an AI agent.
8. Evaluate detection quality, false-positive rates, and processing latency through reproducible experiments.

## 4. Target Users

### 4.1 Security Analyst
Reviews security alerts, investigates suspicious files, examines process activity, and manages incidents.

### 4.2 System Administrator
Monitors endpoint activity, reviews system health, and manages security settings.

### 4.3 Student or Researcher
Uses the platform to study malware detection, machine learning, behavioral heuristics, and explainable cybersecurity systems.

## 5. Scope of the Product

### 5.1 Included in the Initial Version

- Windows PE executable analysis.
- SHA-256 hashing and local hash allowlist/blocklist.
- YARA-based signature scanning.
- Static executable feature extraction.
- LightGBM classification with ONNX Runtime inference.
- File activity monitoring in configured directories.
- Basic process information and parent-child relationship monitoring.
- Safe behavioral simulation and canary-file detection.
- Composite risk scoring and configurable verdict thresholds.
- Incident storage using SQLite.
- FastAPI backend.
- WebSocket-based live event delivery.
- React and Tailwind CSS SOC dashboard.
- Controlled quarantine and restoration of test artifacts.
- AI-assisted forensic explanations.
- Automated tests and performance evaluation.

### 5.2 Future Enhancements

The following capabilities may be considered after the initial version is stable:

- Linux endpoint support.
- Advanced operating-system-level execution prevention.
- eBPF-based telemetry.
- Windows kernel or filesystem filter integrations.
- Additional malware families and behavioral detection rules.
- Multi-endpoint centralized management.
- Role-based access control for multiple analysts.
- Advanced threat intelligence integrations.

Future enhancements must not be treated as implemented features until their tickets have been completed and verified.

## 6. Core Product Modules

### Module 1: Endpoint Sensor

**Purpose:** Collect endpoint file and process activity.

Requirements:

- Monitor configured directories for file creation and modification.
- Identify files requiring analysis.
- Collect available process metadata.
- Record process identifiers and parent-process information where supported.
- Submit events to an asynchronous analysis queue.
- Avoid repeatedly processing unchanged files unnecessarily.
- Support clean shutdown and error logging.

The initial directory watcher is a monitoring mechanism. It must not be represented as an operating-system execution interception mechanism unless actual enforcement has been implemented and tested.

### Module 2: Signature Detection Engine

**Purpose:** Detect known malicious files and match known-safe objects.

Requirements:

- Calculate SHA-256 file hashes.
- Compare hashes against a local blocklist and allowlist.
- Scan eligible files with YARA rules.
- Record matched rules and supporting evidence.
- Support configurable rules and hash databases.
- Cache appropriate analysis results.
- Prevent unsupported or failed scans from being incorrectly reported as clean.

### Module 3: Static Machine Learning Engine

**Purpose:** Classify eligible Windows PE files using extracted structural features.

Requirements:

- Parse PE files and validate input format.
- Extract the features required by the selected model.
- Calculate section entropy and collect relevant structural metadata.
- Load a trained LightGBM model exported to ONNX format.
- Return a malware probability or model score.
- Record model version, inference duration, and errors.
- Handle malformed files and unsupported formats safely.

The feature extractor and inference pipeline must use a consistent, documented feature schema.

### Module 4: Behavioral Monitor

**Purpose:** Identify suspicious runtime activity that static analysis may not reveal.

Requirements:

- Monitor configured file modification and rename events.
- Track available process activity.
- Detect suspicious parent-child process relationships using configurable rules.
- Create decoy canary files in a controlled test environment.
- Generate high-priority alerts when canary activity is detected.
- Detect configurable patterns of rapid file modification.
- Record the observations supporting each behavioral alert.

A single behavioral indicator must not automatically be treated as definitive proof of malware unless the detection policy explicitly justifies that action.

### Module 5: Response Engine

**Purpose:** Convert detection results into consistent security decisions and response actions.

Requirements:

- Combine signature, machine learning, static heuristic, and behavioral evidence.
- Calculate a composite risk score from 0 to 100.
- Assign the verdict Benign, Suspicious, or Malicious.
- Create incident records for relevant detections.
- Support alerting, investigation, and controlled quarantine.
- Preserve file metadata and hashes.
- Support authorized restoration of quarantined files.
- Record response actions and errors in an audit trail.
- Prevent unauthorized access to quarantine contents.

Destructive actions must be introduced incrementally. The initial implementation should support safe simulation and controlled test artifacts before enabling automated process termination or quarantine of arbitrary files.

### Module 6: AI Forensic Analyst

**Purpose:** Explain the evidence behind security incidents.

Requirements:

- Accept structured detection evidence from the backend.
- Summarize matched signatures and suspicious executable characteristics.
- Explain relevant runtime observations.
- Provide possible MITRE ATT&CK technique mappings when supported by the evidence.
- Recommend investigation and remediation steps.
- Clearly distinguish observed facts from AI-generated interpretations.
- Handle unavailable AI services and malformed responses gracefully.

The AI agent must not independently execute arbitrary system commands or perform unrestricted destructive actions.

### Module 7: SOC Dashboard

**Purpose:** Provide a centralized interface for monitoring and investigating security events.

Requirements:

- Display overall system status and event statistics.
- Show recent security alerts.
- Display threat classifications and risk scores.
- Present the evidence associated with individual incidents.
- Show scan and inference latency.
- Display process and behavioral events when available.
- Manage quarantine records and authorized restoration actions.
- Display AI-generated forensic reports.
- Receive live events from the backend.
- Show loading, empty, error, and disconnected states appropriately.

The interface must distinguish real collected telemetry from simulated demonstration data.

## 7. Threat Scoring Requirements

The initial risk scoring model will use four evidence categories:

- YARA rule severity.
- Static machine learning probability.
- Normalized maximum executable-section entropy.
- Runtime behavioral anomaly score.

The initial proposed equation is:

\[
S_{\text{total}} =
100 \times
\left(
0.25I_{\text{YARA}}
+ 0.40P_{\text{ML}}
+ 0.15\hat{E}_{\text{norm}}
+ 0.20B_{\text{runtime}}
\right)
\]

Where:

- \(I_{\text{YARA}}\) is the normalized YARA severity score.
- \(P_{\text{ML}}\) is the model output normalized to a value between 0 and 1.
- \(\hat{E}_{\text{norm}}\) is the normalized maximum section entropy penalty.
- \(B_{\text{runtime}}\) is the behavioral anomaly score.

Each component must be normalized to the range 0–1 before calculating the composite score.

### Initial Decision Thresholds

| Risk score | Verdict | Initial action |
|---|---|---|
| Below 35 | Benign | Allow and record according to policy |
| 35 to below 70 | Suspicious | Alert and continue monitoring |
| 70 to 100 | Malicious | High-priority alert and controlled response |

These are initial configuration values, not validated detection boundaries. The thresholds and weights must be evaluated against test data before production-like enforcement is considered.

A high-confidence behavioral event, such as a canary-file modification, may trigger a separate high-priority policy.

## 8. Functional Requirements

The system must:

**FR-01:** Detect file events in configured monitoring locations.

**FR-02:** Calculate SHA-256 hashes for eligible files.

**FR-03:** Match hashes against configured local allowlists and blocklists.

**FR-04:** Scan eligible files using configured YARA rules.

**FR-05:** Extract supported executable features and run ML inference.

**FR-06:** Record detection evidence and processing errors.

**FR-07:** Monitor supported runtime behavioral indicators.

**FR-08:** Calculate a composite threat risk score.

**FR-09:** Generate consistent security verdicts.

**FR-10:** Store incidents and response actions.

**FR-11:** Deliver relevant events to the dashboard in real time.

**FR-12:** Generate AI-assisted forensic summaries.

**FR-13:** Support controlled quarantine and restoration workflows.

**FR-14:** Provide tests for detection logic, scoring, API contracts, and response operations.

**FR-15:** Measure model performance and system processing latency.

## 9. Non-Functional Requirements

### Performance
- Design the analysis pipeline to minimize avoidable delays.
- Measure latency separately for hashing, signature scanning, feature extraction, model inference, and total processing.
- Establish benchmark targets through repeatable experiments.
- Avoid claiming real-time prevention until the enforcement path has been implemented and measured.

### Reliability
- Recover gracefully from unsupported files and component failures.
- Prevent duplicate event processing where practical.
- Record failures without silently classifying failed analysis as benign.
- Preserve incident records across application restarts.

### Security
- Validate file paths and API inputs.
- Restrict access to quarantine operations.
- Store secrets outside source control.
- Use authenticated encryption for quarantined file contents.
- Record sensitive response actions in an audit log.
- Use least-privilege execution wherever possible.

### Maintainability
- Use modular components with defined interfaces.
- Keep configuration separate from application logic.
- Use clear naming, type hints, and structured logging.
- Provide automated tests for critical components.

### Usability
- Provide clear verdicts and explanations.
- Display timestamps and relevant evidence with each incident.
- Make errors and unavailable services visible.
- Distinguish alerts, warnings, simulated events, and completed response actions.

## 10. Technology Stack

| Layer | Technology |
|---|---|
| Primary development environment | Google Antigravity |
| Endpoint and detection services | Python |
| File monitoring | Python watcher and supported OS event interfaces |
| Hashing | SHA-256 |
| Signature scanning | YARA |
| Executable parsing | LIEF |
| Machine learning | LightGBM |
| Model inference | ONNX Runtime |
| Backend API | FastAPI |
| Live event transport | WebSockets |
| Initial database | SQLite |
| Frontend | React with TypeScript |
| Styling | Tailwind CSS |
| AI integration | Google Antigravity agent and supported MCP integration |
| Automated testing | pytest and frontend testing tools appropriate to the chosen stack |

Additional infrastructure such as Redis, PostgreSQL, or a dedicated kernel-level sensor must be introduced only when justified by the implementation requirements.

## 11. Data and Model Evaluation

The ML component will use an appropriate public dataset, initially targeting EMBER, subject to confirmation of the selected dataset version and feature schema.

Evaluation must include:

- ROC-AUC.
- Precision and recall.
- F1-score.
- False-positive rate.
- Confusion matrix.
- Feature extraction duration.
- Model inference latency.
- End-to-end scanning latency.

The dataset split, preprocessing pipeline, feature definitions, and evaluation procedure must be documented to ensure reproducibility.

Performance goals will be finalized after the first working benchmark. Expected performance must never be presented as an experimentally achieved result.

## 12. Safety and Operating Constraints

- Initial development and demonstrations must use benign files and safe simulations.
- Do not execute unknown or live malware on the primary development computer.
- Begin with monitoring and alert-only behavior.
- Test quarantine and restoration using designated disposable artifacts.
- Require explicit authorization for destructive response operations during development.
- Ensure that false positives can be investigated and recovered from.
- Do not report file-execution prevention unless the underlying operating-system control has been implemented and verified.
- Treat external threat intelligence and AI-generated output as untrusted inputs.

## 13. Definition of Product Success

The initial project will be considered functionally successful when:

1. A monitored test file enters the analysis pipeline.
2. The signature engine returns a reproducible result.
3. An eligible PE file can be analyzed using the configured ML model.
4. Safe behavioral simulations produce the expected alerts.
5. The scoring engine produces a verdict consistent with configured rules.
6. Incidents are persisted and visible in the dashboard.
7. Live event updates work correctly.
8. The AI component can produce an evidence-grounded incident summary or report its unavailability clearly.
9. A designated test artifact can be quarantined and restored through the controlled workflow.
10. Automated tests pass and evaluation results can be reproduced.

Each capability must be demonstrated and tested before being marked complete.

## 14. Project Development Approach

Sentinel-EDR will be developed through small, verifiable implementation tickets in Google Antigravity.

The development process will follow these principles:

- Each ticket must have a clear objective and defined acceptance criteria.
- Dependencies between tickets must be respected.
- Modules must follow the contracts documented in the technical specifications.
- Existing tests must continue to pass after changes.
- Every completed ticket must include implementation evidence and relevant test results.
- Architecture and requirements changes must be reflected in the appropriate documentation.
- Features must not be marked complete merely because code has been generated.

The Product Requirements Document defines what Sentinel-EDR should accomplish. Technical implementation details, ticket sequencing, API contracts, and database design will be maintained in their respective project documents.

---

**End of PRD**